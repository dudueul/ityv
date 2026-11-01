//! Resume after a power loss (PROTOCOL.md §7.3 재개, §7.8; ADR-0021;
//! VC-069): the rebuilt box equals the box that wrote the journal, the
//! attested waiting area decides what happens to the papers left (the
//! four cases), and every broken or inconsistent journal is refused.
// Integration-test crate: outside the TCB. Tests express "this must hold"
// with unwrap/expect/panic/indexing and small arithmetic on test sizes,
// so these lints are relaxed for this file only (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::many_single_char_names
)]

mod common;

use common::{
    MemJournal, MemStaging, MockModule, SEED, STYLE_SMALL, World, build_position, cast_one,
    challenge_one, interpretation, mocks, ports, run_visit, signer, tb, visit_end, visit_work,
    work, world,
};
use ityv_crypto::object_hash;
use ityv_cunit::boxstate::{BATCH_WORK_LEN, CLOSE_WORK_LEN, CloseInputs, OpenBox};
use ityv_cunit::config::Profile;
use ityv_cunit::error::Invariant;
use ityv_cunit::link::{
    JournalEntry, JournalKind, MAX_JOURNAL_ENTRY_LEN, SCHEMA_JOURNAL_ENTRY, visit_digest,
};
use ityv_cunit::port::{JournalItem, JournalSource};
use ityv_cunit::rules::{PaperAction, ResumeCase, ResumePlan, WaitingArea, close_verdict};
use ityv_cunit::visit::{Decision, VisitWork};
use ityv_cunit::{Error, JournalError, ResumeInputs};
use ityv_encoding::{
    BatchAttest, Hash512, ModuleCounter, ModuleCounters, ModuleId, SCHEMA_BATCH_ATTEST,
    SCHEMA_VERSION_1, TimeBucket, decode_object, encode_object,
};
use ityv_ledger::merkle::sorted_set_root;

const PACKAGE_ROOM: usize = 64 * 1024;

const EMPTY: WaitingArea = WaitingArea {
    papers: 0,
    front_imprinted: false,
    sticker_printed: false,
};

const fn area(papers: u8, front_imprinted: bool) -> WaitingArea {
    WaitingArea {
        papers,
        front_imprinted,
        sticker_printed: false,
    }
}

fn entry(bytes: &[u8]) -> JournalEntry<'_> {
    decode_object(SCHEMA_JOURNAL_ENTRY, SCHEMA_VERSION_1, bytes).unwrap()
}

fn kinds(j: &MemJournal) -> std::vec::Vec<JournalKind> {
    j.entries.iter().map(|e| entry(e).kind()).collect()
}

/// Resumes from a copy of `j`, appending to `j` itself, with fresh
/// modules (they issued nothing the journal does not show).
fn resume_at(
    w: &World,
    j: &mut MemJournal,
    waiting_area: WaitingArea,
    opened: u64,
    at: u64,
) -> Result<(OpenBox<'static>, ResumePlan), Error> {
    resume_with(w, &mut mocks(w), j, waiting_area, opened, at)
}

/// Resumes from a copy of `j`, appending to `j` itself, asking the
/// modules `m`.
fn resume_with(
    w: &World,
    m: &mut [MockModule],
    j: &mut MemJournal,
    waiting_area: WaitingArea,
    opened: u64,
    at: u64,
) -> Result<(OpenBox<'static>, ResumePlan), Error> {
    let copy = MemJournal {
        entries: j.entries.clone(),
        packages: j.packages.clone(),
        ..MemJournal::default()
    };
    let mut package = std::vec![0u8; PACKAGE_ROOM];
    OpenBox::resume(
        w.config,
        &mut copy.reader(),
        j,
        &mut ports(m),
        &ResumeInputs {
            opened: tb(opened),
            waiting_area,
            time_bucket: tb(at),
        },
        &mut package,
    )
}

fn resume(
    w: &World,
    j: &mut MemJournal,
    waiting_area: WaitingArea,
    at: u64,
) -> Result<(OpenBox<'static>, ResumePlan), Error> {
    resume_at(w, j, waiting_area, 1, at)
}

fn close(
    w: &World,
    b: &mut OpenBox<'static>,
    m: &mut [MockModule],
    j: &mut MemJournal,
    at: u64,
) -> Result<std::vec::Vec<u8>, Error> {
    let head = j.head();
    let mut out = std::vec![0u8; BATCH_WORK_LEN];
    b.close_batch(&head, &mut ports(m), signer(w), j, tb(at), &mut out)
        .map(<[u8]>::to_vec)
}

/// `true` if every module's mark equals records + challenges +
/// quarantines (the counter invariant of the close, VC-038).
fn counters_balance(b: &OpenBox<'_>) -> bool {
    let totals = b.totals();
    let inputs = CloseInputs {
        paper: totals.records,
        without_record: 0,
        spoiled_envelopes: totals.challenged + totals.quarantined,
        envelopes: None,
        fallback_declared: false,
        record_set_root: Hash512::ZERO,
        seal_digest: Hash512::ZERO,
    };
    !close_verdict(&b.close_facts(&inputs)).contains(Invariant::ModuleCounters)
}

/// Everything observable about a box.
fn assert_same(live: &OpenBox<'_>, resumed: &OpenBox<'_>) {
    assert_eq!(live.journal_head(), resumed.journal_head());
    assert_eq!(live.totals(), resumed.totals());
    assert_eq!(live.module_counters(), resumed.module_counters());
    assert_eq!(live.batch_records(), resumed.batch_records());
    assert_eq!(live.batch_index(), resumed.batch_index());
    assert_eq!(live.paper_incidents(), resumed.paper_incidents());
    for at in [1, 2, 3, 4, 5, 6] {
        assert_eq!(live.batch_due(tb(at)), resumed.batch_due(tb(at)), "{at}");
    }
    assert!(!resumed.has_visit_open());
    assert!(!resumed.is_faulted());
}

fn papers(plan: &ResumePlan) -> std::vec::Vec<PaperAction> {
    plan.papers[..usize::from(plan.paper_count)].to_vec()
}

/// Binds `options.len()` small-style positions, ends and decides the
/// visit (`checks` bit i = check position i), then imprints the first
/// `imprints` cast positions and opens the checked ones before them, and
/// drops the visit state (the machine stops). Returns the codes.
fn decided_visit(
    w: &World,
    b: &mut OpenBox<'static>,
    m: &mut [MockModule],
    j: &mut MemJournal,
    options: &[u16],
    checks: u8,
    processed: u8,
) -> std::vec::Vec<Hash512> {
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    let codes = bind_all(w, b, m, j, &mut staging, &mut visit, options);
    let ready = b
        .end_visit(&visit_end(b"E-2026", options.len() as u8), &mut visit)
        .unwrap();
    let mut package = std::vec![0u8; 300_000];
    let mut decided = ready
        .decide(
            b,
            Decision::from_checks(checks),
            j,
            &mut staging,
            &mut package,
            tb(2),
        )
        .unwrap();
    for _ in 0..processed {
        match decided.current(b).unwrap().1 {
            ityv_cunit::Choice::Cast => decided.imprinted(b, j, tb(2)).unwrap(),
            ityv_cunit::Choice::Check => {
                let mut out = std::vec![0u8; 8192];
                decided.open_challenge(b, signer(w), &mut out).unwrap();
            }
        }
    }
    codes
}

fn bind_all(
    w: &World,
    b: &mut OpenBox<'static>,
    m: &mut [MockModule],
    j: &mut MemJournal,
    staging: &mut MemStaging,
    visit: &mut VisitWork,
    options: &[u16],
) -> std::vec::Vec<Hash512> {
    options
        .iter()
        .map(|&option| {
            *build_position(w, b, m, j, staging, visit, (STYLE_SMALL, option)).tracking_code()
        })
        .collect()
}

#[test]
fn an_empty_journal_resumes_a_fresh_box() {
    let w = world(Profile::InPerson, false);
    let mut j = MemJournal::default();
    let (resumed, plan) = resume(&w, &mut j, EMPTY, 1).unwrap();
    assert_eq!(plan.case, ResumeCase::Nothing);
    assert_same(&OpenBox::open(w.config, tb(1)), &resumed);
    assert!(j.entries.is_empty());
}

/// One step of a live box.
type Step = fn(&World, &mut OpenBox<'static>, &mut [MockModule], &mut MemJournal);

#[test]
fn the_resumed_box_equals_the_live_box_after_every_visit_kind() {
    let w = world(Profile::InPerson, false);
    let mut live = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let steps: [(&str, Step); 6] = [
        ("cast", |w, b, m, j| {
            cast_one(w, b, m, j, 2);
        }),
        ("check", |w, b, m, j| challenge_one(w, b, m, j, 2)),
        ("mixed visit", |w, b, m, j| {
            run_visit(
                w,
                b,
                m,
                j,
                &[(STYLE_SMALL, 1), (STYLE_SMALL, 2), (STYLE_SMALL, 3)],
                0b010,
                3,
            );
        }),
        ("batch", |w, b, m, j| {
            close(w, b, m, j, 3).unwrap();
        }),
        ("abandoned before the decision", |w, b, m, j| {
            let mut staging = MemStaging::default();
            let mut visit = visit_work();
            bind_all(w, b, m, j, &mut staging, &mut visit, &[1, 2]);
            b.abandon_visit(j, tb(3)).unwrap();
        }),
        ("imprint failed", |w, b, m, j| {
            let mut staging = MemStaging::default();
            let mut visit = visit_work();
            bind_all(w, b, m, j, &mut staging, &mut visit, &[1, 2]);
            let ready = b.end_visit(&visit_end(b"E-2026", 2), &mut visit).unwrap();
            let mut package = std::vec![0u8; 300_000];
            let mut decided = ready
                .decide(b, Decision::CAST_ALL, j, &mut staging, &mut package, tb(3))
                .unwrap();
            decided.imprint_failed(b, j, tb(3)).unwrap();
            decided.imprinted(b, j, tb(3)).unwrap();
            decided.finish_positions(b).unwrap().finish(b).unwrap();
        }),
    ];
    for (name, step) in steps {
        step(&w, &mut live, &mut m, &mut j);
        let entries = j.entries.len();
        // the live modules: every counter they issued is in the journal
        let (resumed, plan) = resume_with(&w, &mut m, &mut j, EMPTY, 1, 4).unwrap();
        assert_eq!(plan.case, ResumeCase::Nothing, "{name}");
        assert_same(&live, &resumed);
        assert_eq!(j.entries.len(), entries, "{name}: nothing appended");
    }
    // the resumed box carries on: the modules (which kept their state)
    // sign the next batch over the restored ranges
    let (mut resumed, _) = resume(&w, &mut j, EMPTY, 4).unwrap();
    let next = cast_one(&w, &mut resumed, &mut m, &mut j, 5);
    let attest = close(&w, &mut resumed, &mut m, &mut j, 5).unwrap();
    let parsed: BatchAttest<'_> =
        decode_object(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, &attest).unwrap();
    assert!(parsed.body().module_refusals().is_empty());
    assert_eq!(parsed.body().record_count(), 2);
    assert_ne!(
        parsed.body().records_root(),
        &sorted_set_root(&[next]).unwrap()
    );
    assert_eq!(resumed.totals().quarantined, 3);
}

#[test]
fn case_1_bound_positions_are_quarantined_by_record_and_the_counters_stay_exact() {
    let w = world(Profile::InPerson, false);
    let mut live = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    cast_one(&w, &mut live, &mut m, &mut j, 2);
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    let codes = bind_all(
        &w,
        &mut live,
        &mut m,
        &mut j,
        &mut staging,
        &mut visit,
        &[1, 2],
    );
    // the machine stops before the decision: the bound entries are in the
    // journal, two papers wait
    assert_eq!(kinds(&j)[4..], [JournalKind::Bound; 2]);
    let (mut resumed, plan) = resume_with(&w, &mut m, &mut j, area(2, false), 1, 3).unwrap();
    assert_eq!(plan.case, ResumeCase::BeforeDecision);
    assert_eq!(papers(&plan), [PaperAction::Quarantine; 2]);
    assert_eq!(
        (
            plan.quarantine[..2].to_vec(),
            plan.unjournaled,
            plan.incident
        ),
        ([true, true].to_vec(), 0, false)
    );
    assert_eq!(
        kinds(&j)[6..],
        [JournalKind::Quarantine, JournalKind::Quarantine]
    );
    for (i, code) in codes.iter().enumerate() {
        let q = entry(&j.entries[6 + i]);
        assert_eq!(q.record_hash(), code);
        assert_eq!(
            q.module_counters(),
            entry(&j.entries[4 + i]).module_counters()
        );
    }
    assert_eq!(resumed.totals().quarantined, 2);
    // every consumed counter is accounted for: one record, two quarantines
    assert_eq!(resumed.module_counters(), &[3, 3, 3, 3, 3]);
    assert!(counters_balance(&resumed));
    // and the modules' next counters are accepted
    cast_one(&w, &mut resumed, &mut m, &mut j, 3);
    assert_eq!(resumed.module_counters(), &[4, 4, 4, 4, 4]);
}

#[test]
fn case_1_the_ballot_in_flight_is_found_by_asking_the_modules() {
    let w = world(Profile::InPerson, false);
    let mut live = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    let codes = bind_all(
        &w,
        &mut live,
        &mut m,
        &mut j,
        &mut staging,
        &mut visit,
        &[1],
    );
    // the second ballot is issued, then the machine stops before its bound
    // entry; a third paper waits behind it
    let mut area_ = work();
    let ballot = live
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 2), &mut area_)
        .unwrap();
    ballot.issue(&mut live, &mut ports(&mut m), &SEED).unwrap();
    assert_eq!(kinds(&j), [JournalKind::Bound]);
    let saved = MemJournal {
        entries: j.entries.clone(),
        packages: j.packages.clone(),
        ..MemJournal::default()
    };
    let (mut resumed, plan) = resume_with(&w, &mut m, &mut j, area(3, false), 1, 3).unwrap();
    assert_eq!(
        papers(&plan),
        [
            PaperAction::Quarantine,
            PaperAction::Quarantine,
            PaperAction::Return
        ]
    );
    assert_eq!(
        (plan.quarantine[0], plan.unjournaled, plan.incident),
        (true, 1, false)
    );
    assert_eq!(
        kinds(&j)[1..],
        [JournalKind::Quarantine, JournalKind::Quarantine]
    );
    assert_eq!(entry(&j.entries[1]).record_hash(), &codes[0]);
    let lost = entry(&j.entries[2]);
    assert_eq!(lost.record_hash(), &Hash512::ZERO);
    assert_eq!(lost.module_counters().len(), 5);
    assert!(lost.module_counters().iter().all(|c| c.counter == 2));
    assert_eq!(resumed.module_counters(), &[2, 2, 2, 2, 2]);
    assert_eq!(resumed.totals().quarantined, 2);
    assert!(counters_balance(&resumed));
    cast_one(&w, &mut resumed, &mut m, &mut j, 3);
    // a module that refused an earlier batch cannot answer: nothing is
    // assumed for it, and its next issue is a gap (README)
    let mut j = saved;
    let mut m2 = mocks(&w);
    for (fresh, used) in m2.iter_mut().zip(&m) {
        fresh.pending = used.pending.clone();
    }
    for module in &mut m2 {
        module.pending.retain(|&c| c <= 2);
    }
    m2[0].refuse_batches = true;
    let (resumed, plan) = resume_with(&w, &mut m2, &mut j, area(3, false), 1, 3).unwrap();
    assert_eq!(plan.unjournaled, 1);
    assert_eq!(entry(&j.entries[2]).module_counters().len(), 4);
    assert_eq!(resumed.module_counters(), &[1, 2, 2, 2, 2]);
}

#[test]
fn case_1_a_decision_lost_before_its_fsync_leaves_the_bound_positions() {
    let w = world(Profile::InPerson, false);
    let mut live = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    let codes = bind_all(
        &w,
        &mut live,
        &mut m,
        &mut j,
        &mut staging,
        &mut visit,
        &[1, 2, 3],
    );
    let ready = live
        .end_visit(&visit_end(b"E-2026", 3), &mut visit)
        .unwrap();
    let mut package = std::vec![0u8; 300_000];
    j.fail_after = Some(3); // the three decision entries, then the decision fails
    assert!(
        ready
            .decide(
                &mut live,
                Decision::CAST_ALL,
                &mut j,
                &mut staging,
                &mut package,
                tb(2)
            )
            .is_err()
    );
    assert_eq!(j.unsynced, 3);
    j.lose_unsynced();
    j.fail_after = None;
    assert_eq!(
        kinds(&j),
        [JournalKind::Bound; 3],
        "the deferred entries died with the power, the bound ones stay"
    );
    let (resumed, plan) = resume(&w, &mut j, area(3, false), 3).unwrap();
    assert_eq!(
        (plan.case, plan.unjournaled),
        (ResumeCase::BeforeDecision, 0)
    );
    let named: std::vec::Vec<Hash512> = j.entries[3..]
        .iter()
        .map(|e| *entry(e).record_hash())
        .collect();
    assert_eq!(named, codes);
    assert_eq!(resumed.totals().quarantined, 3);
    assert_eq!(resumed.module_counters(), &[3, 3, 3, 3, 3]);
}

#[test]
fn case_1_positions_without_their_decision_are_quarantined_by_record_hash() {
    let w = world(Profile::InPerson, false);
    let mut live = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    let codes = bind_all(
        &w,
        &mut live,
        &mut m,
        &mut j,
        &mut staging,
        &mut visit,
        &[1, 2],
    );
    let ready = live
        .end_visit(&visit_end(b"E-2026", 2), &mut visit)
        .unwrap();
    let mut package = std::vec![0u8; 300_000];
    j.fail_after = Some(2); // the host's deferred writes happened to land
    assert!(
        ready
            .decide(
                &mut live,
                Decision::from_checks(0b10),
                &mut j,
                &mut staging,
                &mut package,
                tb(2)
            )
            .is_err()
    );
    j.fail_after = None;
    assert_eq!(
        kinds(&j),
        [
            JournalKind::Bound,
            JournalKind::Bound,
            JournalKind::Record,
            JournalKind::Challenge
        ]
    );
    // three papers: the two positions and one that consumed nothing
    let (resumed, plan) = resume(&w, &mut j, area(3, false), 3).unwrap();
    assert_eq!(plan.case, ResumeCase::BeforeDecision);
    assert_eq!(
        (plan.quarantine[0], plan.quarantine[1], plan.unjournaled),
        (true, true, 0)
    );
    assert_eq!(papers(&plan)[2], PaperAction::Return);
    assert_eq!(
        kinds(&j)[4..],
        [JournalKind::Quarantine, JournalKind::Quarantine]
    );
    assert_eq!(entry(&j.entries[4]).record_hash(), &codes[0]);
    assert_eq!(entry(&j.entries[5]).record_hash(), &codes[1]);
    assert_eq!(
        (
            resumed.totals().records,
            resumed.totals().challenged,
            resumed.totals().quarantined
        ),
        (0, 0, 2)
    );
    assert_eq!(resumed.batch_records(), 0);
    // the journal resumes again to the same box
    let (again, plan) = resume(&w, &mut j, EMPTY, 3).unwrap();
    assert_eq!(plan.case, ResumeCase::Nothing);
    assert_same(&resumed, &again);
}

#[test]
fn case_2_the_remaining_positions_are_settled_as_decided() {
    let w = world(Profile::InPerson, false);
    // cast, check, cast; the first imprinted; the machine stops at the check
    let mut live = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let codes = decided_visit(&w, &mut live, &mut m, &mut j, &[1, 2, 3], 0b010, 1);
    let mut base = MemJournal {
        entries: j.entries.clone(),
        packages: j.packages.clone(),
        ..MemJournal::default()
    };
    let (resumed, plan) = resume(&w, &mut base, area(2, false), 3).unwrap();
    assert_eq!(plan.case, ResumeCase::AfterDecision);
    assert_eq!(
        papers(&plan),
        [PaperAction::SpoilChute, PaperAction::Quarantine]
    );
    assert_eq!(entry(base.entries.last().unwrap()).record_hash(), &codes[2]);
    assert_eq!(
        (
            resumed.totals().records,
            resumed.totals().challenged,
            resumed.totals().quarantined
        ),
        (1, 1, 1)
    );
    assert_eq!(resumed.totals().visits, 1);
    // the last paper was printed but its entry is missing: journal it, drop
    let mut base = MemJournal {
        entries: j.entries.clone(),
        packages: j.packages.clone(),
        ..MemJournal::default()
    };
    let (resumed, plan) = resume(&w, &mut base, area(1, true), 3).unwrap();
    assert_eq!(
        (plan.case, plan.imprint),
        (ResumeCase::AfterDecision, Some(2))
    );
    assert_eq!(papers(&plan), [PaperAction::Drop]);
    let last = entry(base.entries.last().unwrap());
    assert_eq!(
        (last.kind(), last.record_hash()),
        (JournalKind::Imprinted, &codes[2])
    );
    assert_eq!(resumed.totals().records, 2);
    // its entry was durable already: it only drops
    let mut live = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    decided_visit(&w, &mut live, &mut m, &mut j, &[1, 2, 3], 0b010, 3);
    let entries = j.entries.len();
    let (resumed, plan) = resume(&w, &mut j, area(1, true), 3).unwrap();
    assert_eq!(
        (plan.case, plan.imprint, papers(&plan)),
        (
            ResumeCase::AfterDecision,
            None,
            [PaperAction::Drop].to_vec()
        )
    );
    assert_eq!(j.entries.len(), entries);
    assert_eq!(resumed.totals().records, 2);
    // a resumed box takes the next visit
    let mut resumed = resumed;
    cast_one(&w, &mut resumed, &mut m, &mut j, 4);
    assert_eq!(resumed.totals().visits, 2);
}

#[test]
fn case_3_a_missing_sticker_entry_quarantines_the_visits_cast_records() {
    let w = world(Profile::Absentee, false);
    let mut live = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let codes = decided_visit(&w, &mut live, &mut m, &mut j, &[1, 2, 3], 0b010, 3);
    let (resumed, plan) = resume(&w, &mut j, EMPTY, 3).unwrap();
    assert_eq!(plan.case, ResumeCase::LabelMissing);
    assert!(plan.return_tray);
    let tail: std::vec::Vec<Hash512> = j.entries[j.entries.len() - 2..]
        .iter()
        .map(|e| *entry(e).record_hash())
        .collect();
    assert_eq!(tail, [codes[0], codes[2]]);
    assert_eq!(
        (
            resumed.totals().records,
            resumed.totals().quarantined,
            resumed.totals().visits
        ),
        (0, 2, 0)
    );
    // with a paper still waiting the labels are lost as well
    let mut live = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    decided_visit(&w, &mut live, &mut m, &mut j, &[1, 2], 0, 1);
    let (resumed, plan) = resume(&w, &mut j, area(1, true), 3).unwrap();
    assert_eq!(plan.case, ResumeCase::AfterDecision);
    assert_eq!(
        (plan.imprint, papers(&plan), plan.return_tray),
        (None, [PaperAction::Quarantine].to_vec(), true)
    );
    assert_eq!(
        (resumed.totals().records, resumed.totals().quarantined),
        (0, 2)
    );
    // a printed sticker entry ends the visit
    let mut live = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    run_visit(&w, &mut live, &mut m, &mut j, &[(STYLE_SMALL, 1)], 0, 2);
    let (resumed, plan) = resume(&w, &mut j, EMPTY, 3).unwrap();
    assert_eq!(plan.case, ResumeCase::Nothing);
    assert_same(&live, &resumed);
}

/// Out of district a finished visit owes nothing (its sticker entry is
/// there, or nothing of it was cast), so the next visit counts no incident;
/// a decided visit whose sticker entry is missing when the next visit
/// starts counts one, and its record stays cast.
#[test]
fn only_a_visit_still_owing_its_sticker_counts_an_incident() {
    let w = world(Profile::Absentee, false);
    let mut live = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    cast_one(&w, &mut live, &mut m, &mut j, 2);
    challenge_one(&w, &mut live, &mut m, &mut j, 2);
    cast_one(&w, &mut live, &mut m, &mut j, 2);
    let (resumed, plan) = resume(&w, &mut j, EMPTY, 3).unwrap();
    assert_eq!(plan.case, ResumeCase::Nothing);
    assert_same(&live, &resumed);
    assert_eq!(resumed.paper_incidents(), 0);
    let s = specs(&j);
    assert_eq!(s[4].kind, JournalKind::LabelPrinted);
    let mut x = s.clone();
    x.remove(4);
    let mut gap = chain(&x);
    let (resumed, plan) = resume(&w, &mut gap, EMPTY, 3).unwrap();
    assert_eq!(plan.case, ResumeCase::Nothing);
    assert_eq!(resumed.paper_incidents(), 1);
    assert_eq!((resumed.totals().records, resumed.totals().visits), (2, 2));
}

#[test]
fn case_4_papers_that_do_not_fit_are_an_incident_the_close_reports() {
    let w = world(Profile::InPerson, false);
    let mut live = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    // cast, cast: the first imprinted, then both papers are gone
    let codes = decided_visit(&w, &mut live, &mut m, &mut j, &[1, 2], 0, 1);
    let entries = j.entries.len();
    let (mut resumed, plan) = resume(&w, &mut j, EMPTY, 3).unwrap();
    assert_eq!((plan.case, plan.incident), (ResumeCase::Inconsistent, true));
    assert_eq!(j.entries.len(), entries, "nothing journaled");
    assert_eq!(resumed.paper_incidents(), 1);
    // the box goes on; a later resume recounts the incident from the
    // journal when another visit follows the one left open
    let next = cast_one(&w, &mut resumed, &mut m, &mut j, 4);
    let (again, plan) = resume(&w, &mut j, EMPTY, 4).unwrap();
    assert_eq!(plan.case, ResumeCase::Nothing);
    assert_eq!(again.paper_incidents(), 1);
    assert_same(&resumed, &again);
    // and the close reports it
    let mut resumed = again;
    close(&w, &mut resumed, &mut m, &mut j, 4).unwrap();
    let mut all = std::vec![codes[0], codes[1], next];
    all.sort_by_key(|h| h.0);
    let inputs = CloseInputs {
        paper: 3,
        without_record: 0,
        spoiled_envelopes: 0,
        envelopes: None,
        fallback_declared: false,
        record_set_root: sorted_set_root(&all).unwrap(),
        seal_digest: Hash512::ZERO,
    };
    let verdict = close_verdict(&resumed.close_facts(&inputs));
    assert!(verdict.contains(Invariant::PaperIncidents));
    let mut out = std::vec![0u8; CLOSE_WORK_LEN];
    let closed = resumed
        .prepare_close(&inputs, signer(&w), &mut j, tb(4), &mut out)
        .unwrap();
    assert!(closed.verdict.contains(Invariant::PaperIncidents));
}

#[test]
fn the_resume_entries_need_a_durable_write_and_time() {
    let w = world(Profile::InPerson, false);
    let mut live = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    decided_visit(&w, &mut live, &mut m, &mut j, &[1], 0, 0);
    let copy = MemJournal {
        entries: j.entries.clone(),
        packages: j.packages.clone(),
        ..MemJournal::default()
    };
    let mut sink = MemJournal {
        fail: true,
        ..MemJournal::default()
    };
    let mut package = std::vec![0u8; PACKAGE_ROOM];
    let inputs = |at: u64| ResumeInputs {
        opened: tb(1),
        waiting_area: area(1, true),
        time_bucket: tb(at),
    };
    assert_eq!(
        OpenBox::resume(
            w.config,
            &mut copy.reader(),
            &mut sink,
            &mut ports(&mut mocks(&w)),
            &inputs(3),
            &mut package
        )
        .unwrap_err(),
        Error::Journal(JournalError::NotDurable)
    );
    sink.fail = false;
    assert_eq!(
        OpenBox::resume(
            w.config,
            &mut copy.reader(),
            &mut sink,
            &mut ports(&mut mocks(&w)),
            &inputs(1),
            &mut package
        )
        .unwrap_err(),
        Error::TimeRegression
    );
    let (_, plan) = OpenBox::resume(
        w.config,
        &mut copy.reader(),
        &mut sink,
        &mut ports(&mut mocks(&w)),
        &inputs(3),
        &mut package,
    )
    .unwrap();
    assert_eq!(plan.imprint, Some(0));
    assert_eq!(kinds(&sink), [JournalKind::Imprinted]);
}

#[test]
fn a_scan_count_is_due_right_after_resume() {
    let w = world(Profile::InPerson, false);
    let mut live = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    cast_one(&w, &mut live, &mut m, &mut j, 2);
    assert!(!live.scan_count_due(tb(2)));
    let (mut resumed, _) = resume(&w, &mut j, EMPTY, 2).unwrap();
    assert!(resumed.scan_count_due(tb(2)));
    let mut out = std::vec![0u8; 512];
    resumed.scan_count_body(tb(2), &mut out).unwrap();
    assert!(!resumed.scan_count_due(tb(2)));
}

#[test]
fn a_closed_box_does_not_resume() {
    let w = world(Profile::InPerson, false);
    let mut live = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let code = cast_one(&w, &mut live, &mut m, &mut j, 2);
    close(&w, &mut live, &mut m, &mut j, 2).unwrap();
    let inputs = CloseInputs {
        paper: 1,
        without_record: 0,
        spoiled_envelopes: 0,
        envelopes: None,
        fallback_declared: false,
        record_set_root: sorted_set_root(&[code]).unwrap(),
        seal_digest: Hash512::ZERO,
    };
    let mut out = std::vec![0u8; CLOSE_WORK_LEN];
    live.prepare_close(&inputs, signer(&w), &mut j, tb(2), &mut out)
        .unwrap();
    assert_eq!(resume(&w, &mut j, EMPTY, 2).unwrap_err(), Error::BoxClosed);
}

#[test]
fn a_source_failure_is_reported_as_such() {
    let w = world(Profile::InPerson, false);
    let mut live = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    cast_one(&w, &mut live, &mut m, &mut j, 2);
    let mut reader = j.reader();
    reader.fail_at = Some(1);
    let mut sink = MemJournal::default();
    let mut package = std::vec![0u8; PACKAGE_ROOM];
    let err = OpenBox::resume(
        w.config,
        &mut reader,
        &mut sink,
        &mut ports(&mut mocks(&w)),
        &ResumeInputs {
            opened: tb(1),
            waiting_area: EMPTY,
            time_bucket: tb(2),
        },
        &mut package,
    )
    .unwrap_err();
    assert_eq!(err, Error::Journal(JournalError::Unreadable));
}

/// A source that reports lengths larger than the buffers it filled.
struct Overlong {
    entry_len: usize,
    package_len: Option<usize>,
    done: bool,
}

impl JournalSource for Overlong {
    fn next_item(
        &mut self,
        _entry: &mut [u8],
        _package: &mut [u8],
    ) -> Result<Option<JournalItem>, JournalError> {
        if self.done {
            return Ok(None);
        }
        self.done = true;
        Ok(Some(JournalItem {
            entry_len: self.entry_len,
            package_len: self.package_len,
        }))
    }
}

#[test]
fn lengths_beyond_the_buffers_are_corrupt() {
    let w = world(Profile::InPerson, false);
    let mut package = std::vec![0u8; 16];
    for (entry_len, package_len) in [(MAX_JOURNAL_ENTRY_LEN + 1, None), (100, Some(17))] {
        let mut source = Overlong {
            entry_len,
            package_len,
            done: false,
        };
        let err = OpenBox::resume(
            w.config,
            &mut source,
            &mut MemJournal::default(),
            &mut ports(&mut mocks(&w)),
            &ResumeInputs {
                opened: tb(1),
                waiting_area: EMPTY,
                time_bucket: tb(1),
            },
            &mut package,
        )
        .unwrap_err();
        assert_eq!(err, Error::JournalCorrupt, "{entry_len} {package_len:?}");
    }
}

// --- crafted journals -------------------------------------------------------

/// One journal entry as the tests write it.
#[derive(Clone, Debug)]
struct Spec {
    kind: JournalKind,
    record_hash: Hash512,
    package: Option<std::vec::Vec<u8>>,
    /// Overrides the share-package hash derived from `package`.
    package_hash: Option<Hash512>,
    counters: std::vec::Vec<(std::vec::Vec<u8>, u64)>,
    bucket: u64,
}

fn specs(j: &MemJournal) -> std::vec::Vec<Spec> {
    j.entries
        .iter()
        .zip(&j.packages)
        .map(|(bytes, package)| {
            let e = entry(bytes);
            Spec {
                kind: e.kind(),
                record_hash: *e.record_hash(),
                package: package.clone(),
                package_hash: None,
                counters: e
                    .module_counters()
                    .iter()
                    .map(|c| (c.module_id.as_bytes().to_vec(), c.counter))
                    .collect(),
                bucket: e.time_bucket().get(),
            }
        })
        .collect()
}

/// Writes `specs` as a correctly chained journal.
fn chain(specs: &[Spec]) -> MemJournal {
    let mut j = MemJournal::default();
    let mut head = Hash512::ZERO;
    for spec in specs {
        let list: std::vec::Vec<ModuleCounter<'_>> = spec
            .counters
            .iter()
            .map(|(id, counter)| ModuleCounter {
                module_id: ModuleId::new(id).unwrap(),
                counter: *counter,
            })
            .collect();
        let package_hash = spec
            .package_hash
            .unwrap_or_else(|| spec.package.as_deref().map_or(Hash512::ZERO, object_hash));
        let value = JournalEntry::new(
            head,
            spec.kind,
            spec.record_hash,
            package_hash,
            ModuleCounters::new(&list).unwrap(),
            TimeBucket::new(spec.bucket),
        );
        let mut buf = std::vec![0u8; MAX_JOURNAL_ENTRY_LEN];
        let len = encode_object(SCHEMA_JOURNAL_ENTRY, SCHEMA_VERSION_1, &value, &mut buf).unwrap();
        buf.truncate(len);
        head = object_hash(&buf);
        j.entries.push(buf);
        j.packages.push(spec.package.clone());
    }
    j
}

/// A live in-person journal (marks end at 6; `N` bound, `R` record, `C`
/// challenge, `D` decision, `I` imprint, `B` batch close, `Q` quarantine):
///
/// | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 | 17 | 18 | 19 |
/// |---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
/// | N1 | N2 | N3 | R1 | C2 | R3 | D | I1 | I3 | B | N4 | R4 | D | I4 | N5 | R5 | D | Q5 | N6 | Q6 |
fn sample() -> (World, std::vec::Vec<Spec>) {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    run_visit(
        &w,
        &mut b,
        &mut m,
        &mut j,
        &[(STYLE_SMALL, 1), (STYLE_SMALL, 2), (STYLE_SMALL, 3)],
        0b010,
        2,
    );
    close(&w, &mut b, &mut m, &mut j, 3).unwrap();
    cast_one(&w, &mut b, &mut m, &mut j, 3);
    let mut staging = MemStaging::default();
    let mut visit = visit_work();
    bind_all(&w, &mut b, &mut m, &mut j, &mut staging, &mut visit, &[1]);
    let ready = b.end_visit(&visit_end(b"E-2026", 1), &mut visit).unwrap();
    let mut package = std::vec![0u8; 300_000];
    let mut decided = ready
        .decide(
            &mut b,
            Decision::CAST_ALL,
            &mut j,
            &mut staging,
            &mut package,
            tb(3),
        )
        .unwrap();
    decided.imprint_failed(&mut b, &mut j, tb(3)).unwrap();
    decided
        .finish_positions(&mut b)
        .unwrap()
        .finish(&mut b)
        .unwrap();
    let mut visit = visit_work();
    bind_all(&w, &mut b, &mut m, &mut j, &mut staging, &mut visit, &[1]);
    b.abandon_visit(&mut j, tb(3)).unwrap();
    let s = specs(&j);
    (w, s)
}

fn corrupt(w: &World, specs: &[Spec]) -> Error {
    let mut j = chain(specs);
    resume(w, &mut j, EMPTY, 9).unwrap_err()
}

/// A decision entry naming `positions` (kind, record hash).
fn decision(positions: &[(JournalKind, Hash512)], bucket: u64) -> Spec {
    let pairs: std::vec::Vec<(u8, Hash512)> =
        positions.iter().map(|(k, h)| (k.code(), *h)).collect();
    Spec {
        kind: JournalKind::VisitDecision,
        record_hash: visit_digest(&pairs),
        package: None,
        package_hash: None,
        counters: std::vec::Vec::new(),
        bucket,
    }
}

/// The modules of the sample's configuration.
const IDS: [&[u8]; 5] = [b"mod-a", b"mod-c", b"mod-j", b"mod-p1", b"mod-p2"];

/// An entry of `kind` naming `record` with every module at `counter`.
fn entry_spec(kind: JournalKind, record: Hash512, counter: u64) -> Spec {
    Spec {
        kind,
        record_hash: record,
        package: (kind == JournalKind::Record).then(|| std::vec![counter as u8]),
        package_hash: None,
        counters: IDS.iter().map(|id| (id.to_vec(), counter)).collect(),
        bucket: 1,
    }
}

/// The same entry as a quarantine (no package).
fn quarantine_of(spec: &Spec) -> Spec {
    Spec {
        kind: JournalKind::Quarantine,
        package: None,
        ..spec.clone()
    }
}

#[test]
fn the_sample_journal_resumes_when_rechained() {
    use JournalKind::{
        BatchClose as B, Bound as N, Challenge as C, Imprinted as I, Quarantine as Q, Record as R,
        VisitDecision as D,
    };
    let (w, s) = sample();
    let kinds: std::vec::Vec<JournalKind> = s.iter().map(|x| x.kind).collect();
    assert_eq!(
        kinds,
        [N, N, N, R, C, R, D, I, I, B, N, R, D, I, N, R, D, Q, N, Q]
    );
    let mut j = chain(&s);
    let (resumed, plan) = resume(&w, &mut j, EMPTY, 9).unwrap();
    assert_eq!(plan.case, ResumeCase::Nothing);
    assert_eq!(resumed.totals().records, 3);
    assert_eq!(resumed.totals().quarantined, 2);
    assert_eq!(resumed.totals().challenged, 1);
    assert_eq!(resumed.totals().attested, 2);
    assert_eq!(resumed.totals().visits, 2);
    assert_eq!(resumed.module_counters(), &[6, 6, 6, 6, 6]);
    assert_eq!(resumed.paper_incidents(), 0);
    assert!(counters_balance(&resumed));
    // the decision digest covers the positions' decision entries in order
    assert_eq!(
        s[6].record_hash,
        decision(
            &[
                (R, s[3].record_hash),
                (C, s[4].record_hash),
                (R, s[5].record_hash)
            ],
            2
        )
        .record_hash
    );
    // each decision entry and the abandoned position's quarantine name and
    // repeat a bound entry
    for (bound, named) in [(0, 3), (1, 4), (2, 5), (10, 11), (14, 15), (18, 19)] {
        assert_eq!(s[named].record_hash, s[bound].record_hash);
        assert_eq!(s[named].counters, s[bound].counters);
    }
}

#[test]
fn a_broken_or_undecodable_entry_is_refused() {
    let (w, s) = sample();
    let good = chain(&s);
    let copy = || MemJournal {
        entries: good.entries.clone(),
        packages: good.packages.clone(),
        ..MemJournal::default()
    };
    // a flipped byte inside the imprint entry breaks its chain link, its
    // record hash or its package hash
    for at in [16, 40, 100, 200] {
        let mut j = copy();
        j.entries[7][at] ^= 1;
        assert_eq!(
            resume(&w, &mut j, EMPTY, 9).unwrap_err(),
            Error::JournalCorrupt,
            "byte {at}"
        );
    }
    // a missing entry breaks the chain
    let mut j = copy();
    j.entries.remove(1);
    j.packages.remove(1);
    assert_eq!(
        resume(&w, &mut j, EMPTY, 9).unwrap_err(),
        Error::JournalCorrupt
    );
    // a truncated entry does not decode
    let mut j = copy();
    j.entries[0].pop();
    assert_eq!(
        resume(&w, &mut j, EMPTY, 9).unwrap_err(),
        Error::JournalCorrupt
    );
}

#[test]
fn share_packages_must_sit_exactly_after_records_and_match() {
    let (w, s) = sample();
    let original = object_hash(s[3].package.as_ref().unwrap());
    let mut x = s.clone();
    x[3].package.as_mut().unwrap()[0] ^= 1;
    x[3].package_hash = Some(original);
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "altered package");
    let mut x = s.clone();
    x[3].package = None;
    x[3].package_hash = Some(original);
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "missing package");
    for (at, what) in [
        (4, "package on a challenge"),
        (0, "package on a bound entry"),
    ] {
        let mut x = s.clone();
        x[at].package = Some(std::vec![1, 2, 3]);
        assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "{what}");
    }
    let mut x = s.clone();
    x[4].package_hash = Some(Hash512([1; 64]));
    assert_eq!(
        corrupt(&w, &x),
        Error::JournalCorrupt,
        "hash without package"
    );
}

#[test]
fn time_must_not_run_backwards_in_the_journal() {
    let (w, s) = sample();
    let mut x = s.clone();
    x[10].bucket = 2; // after the batch close at bucket 3
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt);
    let mut j = chain(&s);
    assert_eq!(
        resume_at(&w, &mut j, EMPTY, 3, 9).unwrap_err(),
        Error::JournalCorrupt,
        "entries before the box opened"
    );
}

#[test]
fn counters_must_follow_each_module_mark() {
    let (w, s) = sample();
    let mut x = s.clone();
    x[2].counters[0].1 = 5; // bound entry: gap (mark 2)
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "bound gap");
    let mut x = s.clone();
    x[1].counters[4].1 = 1; // bound entry: replay (mark 1)
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "bound replay");
    let mut x = s.clone();
    x[5].counters[0].1 = 4; // a decision entry repeats its bound entry
    assert_eq!(
        corrupt(&w, &x),
        Error::JournalCorrupt,
        "decision entry with other counters"
    );
    let mut x = s.clone();
    x[0].counters.clear();
    x[3].counters.clear();
    assert_eq!(
        corrupt(&w, &x),
        Error::JournalCorrupt,
        "bound without counters"
    );
    let mut x = s.clone();
    x[0].counters[3].0 = b"mod-q".to_vec(); // unknown module
    x[0].counters.sort();
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "unknown module");
    // a quarantine without record consumes the counters after the marks
    let unrecorded = |counter: u64| Spec {
        bucket: 4,
        ..entry_spec(JournalKind::Quarantine, Hash512::ZERO, counter)
    };
    let mut x = s.clone();
    x.push(unrecorded(9));
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "unrecorded gap");
    let mut x = s.clone();
    x.push(unrecorded(7));
    let mut j = chain(&x);
    let (resumed, _) = resume(&w, &mut j, EMPTY, 9).unwrap();
    assert_eq!(resumed.module_counters(), &[7, 7, 7, 7, 7]);
    assert_eq!(resumed.totals().quarantined, 3);
}

#[test]
fn a_decision_must_close_its_positions_with_their_digest() {
    let (w, s) = sample();
    let mut x = s.clone();
    x[6].record_hash = Hash512([7; 64]);
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "wrong digest");
    let mut x = s.clone();
    x[6].counters = s[5].counters.clone();
    assert_eq!(
        corrupt(&w, &x),
        Error::JournalCorrupt,
        "a decision with counters"
    );
    let mut x = s.clone();
    x[6].record_hash = decision(
        &[
            (JournalKind::Record, s[3].record_hash),
            (JournalKind::Challenge, s[4].record_hash),
        ],
        2,
    )
    .record_hash;
    assert_eq!(
        corrupt(&w, &x),
        Error::JournalCorrupt,
        "a digest over fewer positions"
    );
    // a decision before every position has its decision entry
    let mut x = s[..5].to_vec();
    x.push(s[6].clone());
    assert_eq!(
        corrupt(&w, &x),
        Error::JournalCorrupt,
        "a position without its decision entry"
    );
    // decision entries in another order than the bound positions
    let mut x = s.clone();
    x.swap(3, 5);
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "out of order");
    // a decision entry without a bound position, or a bound entry after
    // the decision entries began
    let x = [s[3].clone()];
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "nothing bound");
    let later = |spec: Spec| Spec { bucket: 4, ..spec };
    let mut x = s[..4].to_vec();
    x.push(later(entry_spec(JournalKind::Bound, Hash512([9; 64]), 4)));
    assert_eq!(
        corrupt(&w, &x),
        Error::JournalCorrupt,
        "bound after a decision entry"
    );
    let mut x = s[..3].to_vec();
    x.push(quarantine_of(&s[0]));
    x.push(later(entry_spec(JournalKind::Bound, Hash512([9; 64]), 4)));
    assert_eq!(
        corrupt(&w, &x),
        Error::JournalCorrupt,
        "bound after a quarantine"
    );
    let mut x = s[..6].to_vec();
    x.push(later(entry_spec(JournalKind::Record, Hash512([9; 64]), 3)));
    assert_eq!(
        corrupt(&w, &x),
        Error::JournalCorrupt,
        "more decision entries than positions"
    );
    // even one that names nothing and repeats no counter
    let mut x = s[..6].to_vec();
    x.push(Spec {
        counters: std::vec::Vec::new(),
        ..later(entry_spec(JournalKind::Challenge, Hash512::ZERO, 0))
    });
    assert_eq!(
        corrupt(&w, &x),
        Error::JournalCorrupt,
        "an empty decision entry beyond the positions"
    );
    // a second decision, or one with no position
    let mut x = s[..9].to_vec();
    x.push(s[6].clone());
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "second decision");
    let x = [decision(&[], 1)];
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "no position");
    // an undecided visit cannot be followed by anything but its own entries
    let mut x = s[..2].to_vec();
    x.push(s[9].clone());
    assert_eq!(
        corrupt(&w, &x),
        Error::JournalCorrupt,
        "batch after undecided positions"
    );
    let mut x = s[..2].to_vec();
    x.push(entry_spec(JournalKind::Quarantine, Hash512::ZERO, 3));
    assert_eq!(
        corrupt(&w, &x),
        Error::JournalCorrupt,
        "unrecorded quarantine"
    );
    // a position may not repeat inside its visit, and a visit holds eight
    let mut x = s[..1].to_vec();
    x.push(Spec {
        counters: s[1].counters.clone(),
        ..s[0].clone()
    });
    assert_eq!(
        corrupt(&w, &x),
        Error::JournalCorrupt,
        "the same record twice"
    );
    let x = [entry_spec(JournalKind::Bound, Hash512::ZERO, 1)];
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "no record hash");
    let position = |n: u64| entry_spec(JournalKind::Bound, Hash512([n as u8; 64]), n);
    let eight: std::vec::Vec<Spec> = (1..=8).map(position).collect();
    let mut j = chain(&eight);
    let (_, plan) = resume(&w, &mut j, area(8, false), 1).unwrap();
    assert_eq!(plan.case, ResumeCase::BeforeDecision);
    assert_eq!(plan.quarantine, [true; 8]);
    let nine: std::vec::Vec<Spec> = (1..=9).map(position).collect();
    assert_eq!(corrupt(&w, &nine), Error::JournalCorrupt, "nine positions");
}

#[test]
fn an_imprint_must_name_the_next_cast_position() {
    let (w, s) = sample();
    // the third position imprinted before the first
    let mut x = s.clone();
    x.swap(7, 8);
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "out of order");
    let mut x = s.clone();
    x[7].counters[1].1 = 3;
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "other counters");
    let mut x = s.clone();
    x[7].record_hash = s[4].record_hash;
    x[7].counters = s[4].counters.clone();
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "a checked position");
    let mut x = s[..8].to_vec();
    x.push(s[7].clone());
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "twice");
    let mut x = s[..6].to_vec();
    x.push(s[7].clone());
    assert_eq!(
        corrupt(&w, &x),
        Error::JournalCorrupt,
        "before the decision"
    );
    let x = [s[7].clone()];
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "no visit");
}

#[test]
fn a_quarantine_naming_a_record_must_fit_its_visit() {
    let (w, s) = sample();
    let mut x = s.clone();
    x[17].record_hash = s[11].record_hash; // a record of an earlier visit
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "other visit");
    let mut x = s.clone();
    x[17].counters[0].1 = 4;
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "other counters");
    let mut x = s.clone();
    x[17].counters.pop();
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "fewer counters");
    // in person an imprinted record stays cast
    let mut x = s[..8].to_vec();
    x.push(quarantine_of(&s[7]));
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "after its imprint");
    // a checked position is never quarantined after the decision
    let mut x = s[..7].to_vec();
    x.push(quarantine_of(&s[4]));
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "a checked position");
    // twice
    let mut x = s[..18].to_vec();
    x.push(s[17].clone());
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "twice");
    // nothing to name
    let x = [s[17].clone()];
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "no visit");
    // an undecided position quarantined twice
    let mut x = s[..2].to_vec();
    x.push(quarantine_of(&s[0]));
    x.push(quarantine_of(&s[0]));
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "undecided twice");
    // no decision entry after a quarantine of its positions
    let mut x = s[..3].to_vec();
    x.push(quarantine_of(&s[0]));
    x.push(s[3].clone());
    assert_eq!(
        corrupt(&w, &x),
        Error::JournalCorrupt,
        "decided after quarantine"
    );
    // an abandoned visit: every bound position named, then the ballot in
    // flight without record
    let mut x = s[..2].to_vec();
    x.push(quarantine_of(&s[0]));
    x.push(quarantine_of(&s[1]));
    x.push(entry_spec(JournalKind::Quarantine, Hash512::ZERO, 3));
    let mut j = chain(&x);
    let (resumed, _) = resume(&w, &mut j, EMPTY, 9).unwrap();
    assert_eq!(resumed.totals().quarantined, 3);
    assert_eq!(resumed.module_counters(), &[3, 3, 3, 3, 3]);
    let mut x = s[..2].to_vec();
    x.push(quarantine_of(&s[0]));
    x.push(entry_spec(JournalKind::Quarantine, Hash512::ZERO, 3));
    assert_eq!(
        corrupt(&w, &x),
        Error::JournalCorrupt,
        "a position left unnamed"
    );
}

#[test]
fn a_sticker_entry_must_close_an_out_of_district_visit() {
    let w = world(Profile::Absentee, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    run_visit(
        &w,
        &mut b,
        &mut m,
        &mut j,
        &[(STYLE_SMALL, 1), (STYLE_SMALL, 2)],
        0,
        2,
    );
    // N N R R D I I L
    let s = specs(&j);
    assert_eq!(s[7].kind, JournalKind::LabelPrinted);
    assert_eq!(s[7].record_hash, s[4].record_hash);
    let mut good = chain(&s);
    assert!(resume(&w, &mut good, EMPTY, 9).is_ok());
    let mut x = s.clone();
    x[7].record_hash = Hash512([1; 64]);
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "wrong digest");
    let mut x = s.clone();
    x[7].counters = s[0].counters.clone();
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "with counters");
    let mut x = s[..6].to_vec();
    x.push(s[7].clone());
    assert_eq!(
        corrupt(&w, &x),
        Error::JournalCorrupt,
        "before every imprint"
    );
    let mut x = s.clone();
    x.push(s[7].clone());
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "twice");
    // after the sticker the cast records stay cast
    let mut x = s.clone();
    x.push(quarantine_of(&s[5]));
    assert_eq!(
        corrupt(&w, &x),
        Error::JournalCorrupt,
        "quarantined after the sticker"
    );
    // in person there is no sticker
    let (wp, sp) = sample();
    let mut x = sp[..9].to_vec();
    x.push(Spec {
        kind: JournalKind::LabelPrinted,
        record_hash: sp[6].record_hash,
        package: None,
        package_hash: None,
        counters: std::vec::Vec::new(),
        bucket: 2,
    });
    assert_eq!(corrupt(&wp, &x), Error::JournalCorrupt, "in person");
}

#[test]
fn a_batch_close_must_match_the_replayed_batch() {
    let (w, s) = sample();
    let mut x = s.clone();
    x[9].record_hash = Hash512([5; 64]);
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "root");
    let mut x = s.clone();
    x[9].counters.pop();
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "missing module");
    let mut x = s.clone();
    x[9].counters[1].1 = 2;
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "counter below mark");
    // a second batch close right after the first closes an empty batch
    let mut x = s[..10].to_vec();
    x.push(s[9].clone());
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "empty batch");
}

#[test]
fn a_box_close_must_name_the_marks_and_end_the_journal() {
    let (w, s) = sample();
    let close_entry = Spec {
        kind: JournalKind::BoxClose,
        record_hash: Hash512([3; 64]),
        package: None,
        package_hash: None,
        counters: s[19].counters.clone(),
        bucket: 4,
    };
    let mut x = s.clone();
    x.push(Spec {
        counters: s[0].counters.clone(),
        ..close_entry.clone()
    });
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "stale counters");
    let mut x = s.clone();
    let mut partial = close_entry.clone();
    partial.counters.truncate(4);
    x.push(partial);
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt, "missing module");
    let mut full = s.clone();
    full.push(close_entry);
    assert_eq!(corrupt(&w, &full), Error::BoxClosed, "a valid close");
    full.push(full[0].clone());
    assert_eq!(
        corrupt(&w, &full),
        Error::JournalCorrupt,
        "entry after close"
    );
}

#[test]
fn a_sixty_fifth_unbatched_record_is_corrupt() {
    let w = world(Profile::InPerson, false);
    let visit = |n: u64| {
        let record = entry_spec(JournalKind::Record, Hash512([n as u8; 64]), n);
        let bound = Spec {
            kind: JournalKind::Bound,
            package: None,
            ..record.clone()
        };
        let decided = decision(&[(JournalKind::Record, record.record_hash)], 1);
        let imprint = Spec {
            kind: JournalKind::Imprinted,
            package: None,
            ..record.clone()
        };
        [bound, record, decided, imprint]
    };
    let x: std::vec::Vec<Spec> = (1..=64).flat_map(visit).collect();
    let mut j = chain(&x);
    let (resumed, _) = resume(&w, &mut j, EMPTY, 1).unwrap();
    assert_eq!(resumed.batch_records(), 64);
    assert_eq!(resumed.paper_incidents(), 0);
    let x: std::vec::Vec<Spec> = (1..=65).flat_map(visit).collect();
    assert_eq!(corrupt(&w, &x), Error::JournalCorrupt);
}
