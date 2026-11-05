//! The voter roll (PROTOCOL.md §6.1, §6.2, §14 6; ADR-0033, ADR-0040;
//! VC-107..111): source extracts, the freeze as their merge, custody
//! receipts and the custody quorum, amendments with their sources, and
//! contested check-ins, all signed with real hybrid signatures under the
//! keys the genesis registers (`tests/common/roll.rs`). Every refusal of
//! the stage, the quorum's number and both branches, the pseudonym root,
//! a disagreeing receipt, the entry count the merge allows, the roll at
//! the poll close and an amendment after it, a precinct without its
//! extract, the entry commitment and its inclusion proof.
// Integration tests: outside the TCB. Assertions use unwrap/expect, so these
// lints are relaxed for this file only (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::arithmetic_side_effects
)]

mod common;
mod world;

use common::roll::{
    self, APPEAL, C_INT, C_IVC, C_JUD, C_PA, CONFIRMING, DEATHS, DISQ, GU, IVC, NEC, OVERSEAS,
    SNAPSHOT, Who, by, merged, residents, snapshot, sources, state, witnessed,
};
use common::{election, leak, module_signing, object, sign_seeded, unit_signing};
use ityv_crypto::object_hash;
use ityv_encoding::{
    ContestedCheckin, ContestedMessage, ElectionId, EventRole, Hash512, ModuleId,
    ParticipationModuleSig, RollAmendmentReason, RollSourceKind, RollState,
    SCHEMA_CONTESTED_CHECKIN, SCHEMA_PARTICIPATION_SET, SCHEMA_SIGNED_GENESIS, SCHEMA_VERSION_1,
    StationId, StationKind, Token192, UnitId,
};
use ityv_ledger::{Accumulator, inclusion_proof};
use ityv_state::{HoldReason, HoldSet};
use ityv_verify::{
    ContestedFinding, RollEvent, RollInput, RollRefusal, RollStage, authorize_ledger, build_index,
    roll_entry_commitment, roll_entry_included, verify_boxes, verify_participation, verify_records,
    verify_roll,
};

use world::{Book, World, amend, election_world, group, participation, world};

use RollEvent::{Amendment, Extract, Freeze, Receipt};
use RollRefusal as R;

/// The roll stage over `book`, with `contested` supplied.
fn run_with(book: &Book, contested: &[&'static [u8]]) -> RollStage<'static> {
    let g = book.world.genesis;
    let index = leak(build_index(g, book.ledger.bytes(), &book.ledger.events));
    assert!(index.ledger_holds().is_empty(), "{:?}", index.findings());
    let authority = leak(authorize_ledger(g, index));
    let boxes = leak(verify_boxes(g, index, authority));
    let records = leak(verify_records(g, index, boxes));
    let participation = leak(verify_participation(g, index, boxes, records));
    let input = RollInput {
        contested: common::leak_slice(contested.to_vec()),
    };
    verify_roll(g, index, participation, &input)
}

fn run(book: &Book) -> RollStage<'static> {
    run_with(book, &[])
}

fn ev(body: &'static [u8], who: &[Who]) -> &'static [u8] {
    witnessed(body, who, None)
}

/// A book of the world with `events`.
fn book_of(world: &'static World, events: &[&'static [u8]]) -> Book {
    let mut book = Book::new(world);
    for e in events {
        book.w(e);
    }
    book
}

/// The refusals of `stage`, as (frame, event, refusal).
fn refused(stage: &RollStage<'_>) -> Vec<(u64, RollEvent, RollRefusal)> {
    stage
        .refused()
        .iter()
        .map(|r| (r.seq.get(), r.event, r.refusal))
        .collect()
}

fn only(reason: HoldReason) -> HoldSet {
    HoldSet::empty().with(reason)
}

/// ST-1's resident extract and the snapshot, as events, and their bodies.
fn sources_of_st1() -> ([&'static [u8]; 2], [&'static [u8]; 2]) {
    let bodies = [residents(b"ST-1", 0x10), snapshot()];
    (
        bodies,
        [ev(bodies[0], &[by(GU)]), ev(bodies[1], &[by(SNAPSHOT)])],
    )
}

/// The freeze of the merge of `bodies` (`merged(0x40, bodies)`).
fn freeze_of(bodies: &[&'static [u8]]) -> &'static [u8] {
    roll::freeze(merged(0x40, bodies), sources(bodies))
}

/// `custodian`'s receipt agreeing with the freeze `body` over `bodies`.
fn agreeing(
    custodian: &'static [u8],
    body: &'static [u8],
    bodies: &[&'static [u8]],
    pseudonyms: bool,
) -> &'static [u8] {
    let r = roll::receipt(
        custodian,
        body,
        merged(0x40, bodies),
        Some(sources(bodies).0),
        pseudonyms,
    );
    ev(r, &[by(custodian)])
}

#[test]
fn a_merged_roll_confirmed_by_three_custodians_takes_effect() {
    let mut book = Book::new(world());
    for (schema, e) in roll::standard(&[b"ST-1"]) {
        book.push(schema, e);
    }
    let stage = run(&book);
    assert_eq!(stage.holds(), HoldSet::empty(), "{:?}", stage.refused());
    assert!(stage.refused().is_empty());
    assert!(stage.mismatches().is_empty());
    assert_eq!(stage.extracts().len(), 2);
    assert_eq!(stage.extracts()[0].kind, RollSourceKind::Residents);
    assert_eq!(
        stage.extracts()[0].precinct,
        Some(StationId::new(b"ST-1").unwrap())
    );
    assert_eq!(stage.extracts()[1].kind, RollSourceKind::Snapshot);
    let freeze = stage.freeze().unwrap();
    assert!(freeze.effective);
    assert!(freeze.pseudonym_confirmed);
    assert_eq!(
        freeze
            .custodians
            .iter()
            .map(ityv_encoding::AuthorityId::as_bytes)
            .collect::<Vec<_>>(),
        [C_JUD, C_INT, C_IVC]
    );
    assert!(stage.complete());
    assert_eq!(
        stage.roll(),
        Some(&merged(0x40, &[residents(b"ST-1", 0x10), snapshot()]))
    );
    assert_eq!(stage.contested_frames(), 0);
    // Other lists (deaths, disqualifications, overseas voters) join the
    // merge when their sources sign them.
    let (bodies, events) = sources_of_st1();
    let lists = [
        roll::extract(DEATHS, RollSourceKind::Deaths, None, 0x21),
        roll::extract(DISQ, RollSourceKind::Disqualifications, None, 0x22),
        roll::extract(OVERSEAS, RollSourceKind::Overseas, None, 0x23),
    ];
    let all: Vec<&'static [u8]> = bodies.iter().chain(&lists).copied().collect();
    let body = freeze_of(&all);
    let mut list = events.to_vec();
    list.push(ev(lists[0], &[by(DEATHS)]));
    list.push(ev(lists[1], &[by(DISQ)]));
    list.push(ev(lists[2], &[by(OVERSEAS)]));
    list.push(ev(body, &[NEC, IVC]));
    for (i, c) in [C_JUD, C_INT, C_PA].iter().enumerate() {
        list.push(agreeing(c, body, &all, i == 1));
    }
    let stage = run(&book_of(world(), &list));
    assert_eq!(stage.holds(), HoldSet::empty(), "{:?}", stage.refused());
    assert_eq!(stage.extracts().len(), 5);
    assert!(stage.complete());
}

#[test]
fn the_quorum_needs_three_custodians_with_both_branches_and_the_pseudonym_root() {
    let (bodies, events) = sources_of_st1();
    let body = freeze_of(&bodies);
    let with = |receipts: &[(&'static [u8], bool)]| {
        let mut list = events.to_vec();
        list.push(ev(body, &[NEC, IVC]));
        for (c, p) in receipts {
            list.push(agreeing(c, body, &bodies, *p));
        }
        run(&book_of(world(), &list))
    };
    for receipts in [
        // Two custodians.
        &[(C_JUD, true), (C_INT, false)][..],
        // No Ministry of the Interior.
        &[(C_JUD, true), (C_IVC, false), (C_PA, false)],
        // No court administration.
        &[(C_INT, true), (C_IVC, false), (C_PA, false)],
        // No custodian gave the pseudonym root (VC-109).
        &[(C_JUD, false), (C_INT, false), (C_IVC, false)],
        // None at all.
        &[],
    ] {
        let stage = with(receipts);
        assert_eq!(stage.holds(), HoldSet::empty());
        let freeze = stage.freeze().unwrap();
        assert!(!freeze.effective, "{receipts:?}");
        assert!(!stage.complete());
        assert_eq!(stage.roll(), None);
    }
    // Any custodian may give the pseudonym root; four count as well.
    let stage = with(&[(C_JUD, false), (C_INT, false), (C_PA, true), (C_IVC, false)]);
    assert!(stage.freeze().unwrap().effective);
    assert!(stage.complete());
    // No freeze at all: nothing took effect.
    let stage = run(&book_of(world(), &events));
    assert!(stage.freeze().is_none());
    assert!(!stage.complete());
    assert_eq!(stage.holds(), HoldSet::empty());
}

#[test]
fn every_extract_that_cannot_be_taken_is_listed_and_holds() {
    let (bodies, events) = sources_of_st1();
    let deaths = roll::extract(DEATHS, RollSourceKind::Deaths, None, 0x2B);
    let body = freeze_of(&[bodies[0], bodies[1], deaths]);
    // An unknown source, a source of another function, a signer who is
    // not the source named, a signature under another key.
    let nobody = roll::extract(b"R-NOBODY", RollSourceKind::Deaths, None, 0x24);
    let deaths_by_gu = roll::extract(GU, RollSourceKind::Deaths, None, 0x25);
    let gu_body = residents(b"ST-1", 0x26);
    let (gu, role, org, _) = by(GU);
    let deaths_key = by(DEATHS).3;
    let early = residents(b"ST-2", 0x27);
    let unknown = residents(b"ST-9", 0x28);
    let list = [
        ev(
            nobody,
            &[(b"R-NOBODY", EventRole::RollSource, b"X", deaths_key)],
        ),
        ev(deaths_by_gu, &[by(GU)]),
        ev(gu_body, &[by(DEATHS)]),
        ev(gu_body, &[(gu, role, org, deaths_key)]),
        ev(early, &[by(GU)]),
        ev(unknown, &[by(GU)]),
        events[0],
        witnessed(bodies[0], &[by(GU)], Some(7)),
        ev(residents(b"ST-1", 0x29), &[by(GU)]),
        events[1],
        // One list per kind and source: another list of deaths conflicts.
        ev(deaths, &[by(DEATHS)]),
        ev(
            roll::extract(DEATHS, RollSourceKind::Deaths, None, 0x2C),
            &[by(DEATHS)],
        ),
        ev(body, &[NEC, IVC]),
        ev(
            roll::extract(DEATHS, RollSourceKind::Deaths, None, 0x2A),
            &[by(DEATHS)],
        ),
    ];
    let stage = run(&book_of(world(), &list));
    assert_eq!(
        refused(&stage),
        [
            (3, Extract, R::Authority),
            (4, Extract, R::Authority),
            (5, Extract, R::Authority),
            (6, Extract, R::Signature),
            (7, Extract, R::Precinct),
            (8, Extract, R::Precinct),
            (10, Extract, R::Repeated),
            (11, Extract, R::Conflict),
            (14, Extract, R::Conflict),
            (16, Extract, R::AfterFreeze),
        ]
    );
    assert_eq!(stage.holds(), only(HoldReason::RollEventRefused));
    // The freeze merged the three extracts taken.
    assert_eq!(stage.extracts().len(), 3);
    assert!(stage.freeze().is_some());
}

#[test]
fn a_freeze_must_merge_the_extracts_taken_before_it() {
    let (bodies, events) = sources_of_st1();
    let body = freeze_of(&bodies);
    let case = |list: &[&'static [u8]]| run(&book_of(world(), list));
    // Without the precinct's extract, without the snapshot.
    for missing in [0, 1] {
        let kept = bodies[1 - missing];
        let stage = case(&[events[1 - missing], ev(freeze_of(&[kept]), &[NEC, IVC])]);
        assert_eq!(refused(&stage), [(4, Freeze, R::Incomplete)]);
        assert!(stage.freeze().is_none());
    }
    // A count or a root that is not the merge's.
    let (root, count) = sources(&bodies);
    for (r, c) in [(root, count + 1), (sources(&bodies[..1]).0, count)] {
        let stage = case(&[
            events[0],
            events[1],
            ev(roll::freeze(state(0x40), (r, c)), &[NEC, IVC]),
        ]);
        assert_eq!(refused(&stage), [(5, Freeze, R::Sources)]);
    }
    // The commission's signature under the committee's key.
    let stage = case(&[
        events[0],
        events[1],
        ev(
            body,
            &[
                (b"nec", EventRole::Commission, b"NEC", common::COMMITTEE),
                IVC,
            ],
        ),
    ]);
    assert_eq!(refused(&stage), [(5, Freeze, R::Signature)]);
    // Twice, and another freeze; a refused freeze leaves room for one.
    let other = roll::freeze(state(0x41), sources(&bodies));
    let stage = case(&[
        events[0],
        events[1],
        ev(freeze_of(&[bodies[0]]), &[NEC, IVC]),
        ev(body, &[NEC, IVC]),
        witnessed(body, &[NEC, IVC], Some(9)),
        ev(other, &[NEC, IVC]),
    ]);
    assert_eq!(
        refused(&stage),
        [
            (5, Freeze, R::Sources),
            (7, Freeze, R::Repeated),
            (8, Freeze, R::Conflict)
        ]
    );
    assert_eq!(stage.freeze().unwrap().hash, object_hash(body));
    assert_eq!(stage.holds(), only(HoldReason::RollEventRefused));
}

#[test]
fn a_freeze_counts_the_residents_within_what_the_other_lists_remove_or_add() {
    // The review's I-d: ST-1's residents (1,016 entries) and the snapshot
    // (1,048, the national cross-check, not a count of the roll); 10
    // deaths, 7 disqualifications and 5 overseas entries.
    let (bodies, events) = sources_of_st1();
    let lists = [
        (
            DEATHS,
            roll::listing(DEATHS, RollSourceKind::Deaths, None, 0x21, 10),
        ),
        (
            DISQ,
            roll::listing(DISQ, RollSourceKind::Disqualifications, None, 0x22, 7),
        ),
        (
            OVERSEAS,
            roll::listing(OVERSEAS, RollSourceKind::Overseas, None, 0x23, 5),
        ),
    ];
    let case = |taken: &[(&'static [u8], &'static [u8])], entries: u64| {
        let mut all = bodies.to_vec();
        all.extend(taken.iter().map(|(_, b)| *b));
        let mut list = events.to_vec();
        list.extend(taken.iter().map(|(who, b)| ev(b, &[by(who)])));
        let s = RollState {
            entry_count: entries,
            ..state(0x40)
        };
        list.push(ev(roll::freeze(s, sources(&all)), &[NEC, IVC]));
        let stage = run(&book_of(world(), &list));
        assert_eq!(stage.freeze().is_some(), stage.refused().is_empty());
        refused(&stage)
    };
    // At least 1,016 - (10 + 7 + 5) = 994, at most 1,016 + 5 = 1,021.
    for entries in [994, 1_016, 1_021] {
        assert_eq!(case(&lists, entries), [], "{entries}");
    }
    for entries in [993, 1_022, 1_016 + 1_048, 0, u64::MAX] {
        assert_eq!(case(&lists, entries), [(8, Freeze, R::Count)], "{entries}");
    }
    // Without the lists, the residents' sum exactly.
    assert_eq!(case(&[], 1_016), []);
    for entries in [1_015, 1_017] {
        assert_eq!(case(&[], entries), [(5, Freeze, R::Count)], "{entries}");
    }
    // Removals only lower the floor; only the overseas list raises the
    // ceiling.
    assert_eq!(case(&lists[..2], 999), []);
    assert_eq!(case(&lists[..2], 1_017), [(7, Freeze, R::Count)]);
    assert_eq!(case(&lists[2..], 1_021), []);
    assert_eq!(case(&lists[2..], 1_011), []);
    assert_eq!(case(&lists[2..], 1_010), [(6, Freeze, R::Count)]);
    // A refused freeze holds and leaves room for one.
    let stage = run(&book_of(
        world(),
        &[
            events[0],
            events[1],
            ev(
                roll::freeze(
                    RollState {
                        entry_count: 1_017,
                        ..state(0x40)
                    },
                    sources(&bodies),
                ),
                &[NEC, IVC],
            ),
            ev(freeze_of(&bodies), &[NEC, IVC]),
        ],
    ));
    assert_eq!(refused(&stage), [(5, Freeze, R::Count)]);
    assert_eq!(
        stage.freeze().unwrap().hash,
        object_hash(freeze_of(&bodies))
    );
    assert_eq!(stage.holds(), only(HoldReason::RollEventRefused));
}

#[test]
fn a_receipt_answers_a_state_taken_before_it_once_per_custodian() {
    let (bodies, events) = sources_of_st1();
    let body = freeze_of(&bodies);
    let root = sources(&bodies).0;
    let s = merged(0x40, &bodies);
    let r = |custodian, subject: &'static [u8], sources_root, p| {
        roll::receipt(custodian, subject, s, sources_root, p)
    };
    let jud = r(C_JUD, body, Some(root), true);
    let (jud_id, jud_role, jud_org, _) = by(C_JUD);
    let list = [
        // Before the freeze.
        witnessed(jud, &[by(C_JUD)], Some(21)),
        events[0],
        events[1],
        ev(body, &[NEC, IVC]),
        // Of an extract, without the freeze's sources root.
        ev(r(C_JUD, bodies[0], Some(root), true), &[by(C_JUD)]),
        ev(r(C_INT, body, None, false), &[by(C_INT)]),
        // A source as custodian, an unknown custodian, another key.
        ev(
            r(GU, body, Some(root), false),
            &[(GU, EventRole::RollCustodian, b"JONGNO-GU", by(GU).3)],
        ),
        ev(
            r(b"R-NOBODY", body, Some(root), false),
            &[(b"R-NOBODY", EventRole::RollCustodian, b"X", by(C_PA).3)],
        ),
        ev(jud, &[(jud_id, jud_role, jud_org, by(C_PA).3)]),
        // Taken, again, another answer.
        ev(jud, &[by(C_JUD)]),
        witnessed(jud, &[by(C_JUD)], Some(11)),
        ev(r(C_JUD, body, Some(root), false), &[by(C_JUD)]),
        ev(r(C_INT, body, Some(root), false), &[by(C_INT)]),
        ev(r(C_IVC, body, Some(root), false), &[by(C_IVC)]),
    ];
    let stage = run(&book_of(world(), &list));
    assert_eq!(
        refused(&stage),
        [
            (3, Receipt, R::Subject),
            (7, Receipt, R::Subject),
            (8, Receipt, R::Subject),
            (9, Receipt, R::Authority),
            (10, Receipt, R::Authority),
            (11, Receipt, R::Signature),
            (13, Receipt, R::Repeated),
            (14, Receipt, R::Conflict),
        ]
    );
    assert_eq!(stage.holds(), only(HoldReason::RollEventRefused));
    let freeze = stage.freeze().unwrap();
    assert!(freeze.effective);
    assert_eq!(freeze.custodians.len(), 3);
}

#[test]
fn a_receipt_that_disagrees_is_a_custody_mismatch_and_does_not_count() {
    let (bodies, events) = sources_of_st1();
    let body = freeze_of(&bodies);
    let root = sources(&bodies).0;
    let good = merged(0x40, &bodies);
    let mut variants = Vec::new();
    let mut s = good;
    s.entries_root = Hash512([0x99; 64]);
    variants.push((s, Some(root), false));
    let mut s = good;
    s.entry_count += 1;
    variants.push((s, Some(root), false));
    let mut s = good;
    s.counts_hash = Hash512([0x98; 64]);
    variants.push((s, Some(root), false));
    variants.push((good, Some(Hash512([0x97; 64])), false));
    let mut s = good;
    s.pseudonym_root = Hash512([0x96; 64]);
    variants.push((s, Some(root), true));
    for (s, sources_root, p) in variants {
        let list = [
            events[0],
            events[1],
            ev(body, &[NEC, IVC]),
            agreeing(C_JUD, body, &bodies, true),
            agreeing(C_INT, body, &bodies, false),
            ev(roll::receipt(C_IVC, body, s, sources_root, p), &[by(C_IVC)]),
        ];
        let stage = run(&book_of(world(), &list));
        assert!(stage.refused().is_empty());
        assert_eq!(stage.mismatches().len(), 1);
        let m = stage.mismatches()[0];
        assert_eq!(m.seq.get(), 8);
        assert_eq!(m.custodian.as_bytes(), C_IVC);
        assert_eq!(m.subject, object_hash(body));
        assert_eq!(stage.holds(), only(HoldReason::RollCustodyMismatch));
        assert!(!stage.freeze().unwrap().effective);
        assert!(!stage.complete());
    }
}

#[test]
fn amendments_chain_from_the_freeze_with_their_source_and_fresh_receipts() {
    let (bodies, events) = sources_of_st1();
    let body = freeze_of(&bodies);
    let after = state(0x50);
    let death = roll::amendment(1, body, RollAmendmentReason::Death, DEATHS, after);
    let appeal = roll::amendment(
        2,
        death,
        RollAmendmentReason::AppealDecision,
        APPEAL,
        state(0x60),
    );
    let receipts = |subject: &'static [u8], s| {
        [C_JUD, C_INT, C_IVC]
            .iter()
            .enumerate()
            .map(|(i, c)| ev(roll::receipt(c, subject, s, None, i == 0), &[by(c)]))
            .collect::<Vec<_>>()
    };
    let mut list = events.to_vec();
    list.push(ev(body, &[NEC, IVC]));
    for (i, c) in [C_JUD, C_INT, C_IVC].iter().enumerate() {
        list.push(agreeing(c, body, &bodies, i == 0));
    }
    let three = |b| ev(b, &[NEC, IVC, by(DEATHS)]);
    list.push(three(death));
    // Without fresh receipts the roll waits; with them it is the new one.
    let stage = run(&book_of(world(), &list));
    assert_eq!(stage.holds(), HoldSet::empty(), "{:?}", stage.refused());
    assert_eq!(stage.amendments().len(), 1);
    assert!(!stage.amendments()[0].custody.effective);
    assert!(!stage.complete());
    list.extend(receipts(death, after));
    let stage = run(&book_of(world(), &list));
    assert!(stage.complete());
    assert_eq!(stage.roll(), Some(&after));
    assert_eq!(stage.amendments_for(RollAmendmentReason::Death), 1);
    assert_eq!(stage.amendments_for(RollAmendmentReason::AppealDecision), 0);
    let a = &stage.amendments()[0];
    assert_eq!((a.number, a.reason), (1, RollAmendmentReason::Death));
    assert_eq!(a.authority.as_bytes(), DEATHS);
    // A second amendment chained to the first, with its own receipts.
    let mut full = list.clone();
    full.push(ev(appeal, &[NEC, IVC, by(APPEAL)]));
    full.extend(receipts(appeal, state(0x60)));
    let stage = run(&book_of(world(), &full));
    assert!(stage.complete(), "{:?}", stage.refused());
    assert_eq!(stage.roll(), Some(&state(0x60)));
    // Every refusal of an amendment.
    let wrong_previous = roll::amendment(1, bodies[0], RollAmendmentReason::Death, DEATHS, after);
    let second_first = roll::amendment(2, body, RollAmendmentReason::Death, DEATHS, after);
    let by_gu = roll::amendment(1, body, RollAmendmentReason::Death, GU, after);
    let nobody = roll::amendment(1, body, RollAmendmentReason::Death, b"R-NOBODY", after);
    let other = roll::amendment(1, body, RollAmendmentReason::Overseas, OVERSEAS, after);
    let (d_id, d_role, d_org, _) = by(DEATHS);
    let early = [witnessed(death, &[NEC, IVC, by(DEATHS)], Some(23))];
    let mut list = early.to_vec();
    list.extend(events);
    list.push(ev(body, &[NEC, IVC]));
    list.extend([
        three(wrong_previous),
        three(second_first),
        ev(by_gu, &[NEC, IVC, by(GU)]),
        ev(
            nobody,
            &[
                NEC,
                IVC,
                (b"R-NOBODY", EventRole::RollSource, b"X", by(DEATHS).3),
            ],
        ),
        ev(death, &[NEC, IVC, (d_id, d_role, d_org, by(GU).3)]),
        three(death),
        witnessed(death, &[NEC, IVC, by(DEATHS)], Some(13)),
        ev(other, &[NEC, IVC, by(OVERSEAS)]),
    ]);
    let stage = run(&book_of(world(), &list));
    assert_eq!(
        refused(&stage),
        [
            (3, Amendment, R::Chain),
            (7, Amendment, R::Chain),
            (8, Amendment, R::Chain),
            (9, Amendment, R::Authority),
            (10, Amendment, R::Authority),
            (11, Amendment, R::Signature),
            (13, Amendment, R::Repeated),
            (14, Amendment, R::Conflict),
        ]
    );
    assert_eq!(stage.amendments().len(), 1);
    assert_eq!(stage.holds(), only(HoldReason::RollEventRefused));
}

#[test]
fn an_amendment_after_the_poll_close_is_recorded_and_holds_and_the_roll_is_the_close_s() {
    // The review's I-d: the individual check (VC-110) compares with the
    // roll in force when voting closed, which the first participation set
    // of an election-day station marks on the ledger.
    let (bodies, events) = sources_of_st1();
    let body = freeze_of(&bodies);
    let frozen = merged(0x40, &bodies);
    let death = roll::amendment(1, body, RollAmendmentReason::Death, DEATHS, state(0x50));
    let mut base = events.to_vec();
    base.push(ev(body, &[NEC, IVC]));
    for (i, c) in CONFIRMING.iter().enumerate() {
        base.push(agreeing(c, body, &bodies, i == 0));
    }
    let amendment = |book: &mut Book, receipts: bool| {
        let seq = book.w(ev(death, &[NEC, IVC, by(DEATHS)]));
        if receipts {
            for (i, c) in CONFIRMING.iter().enumerate() {
                let r = roll::receipt(c, death, state(0x50), None, i == 0);
                book.w(ev(r, &[by(c)]));
            }
        }
        seq
    };
    // No participation set: the close is not known and every amendment
    // counts.
    let mut book = book_of(election_world(), &base);
    amendment(&mut book, true);
    let stage = run(&book);
    assert_eq!(stage.poll_close(), None);
    assert_eq!(stage.roll(), Some(&state(0x50)));
    assert_eq!(stage.holds(), HoldSet::empty());
    // Before the close: the roll is the amended one.
    let mut book = book_of(election_world(), &base);
    amendment(&mut book, true);
    let close = book.push(SCHEMA_PARTICIPATION_SET, participation(3));
    let stage = run(&book);
    assert_eq!(stage.poll_close().map(ityv_encoding::Seq::get), Some(close));
    assert!(stage.late_amendments().is_empty());
    assert_eq!(stage.roll(), Some(&state(0x50)));
    assert!(stage.complete());
    assert_eq!(stage.holds(), HoldSet::empty());
    // After the close: recorded and confirmed, but the roll stays the
    // freeze's and the ledger holds.
    for receipts in [true, false] {
        let mut book = book_of(election_world(), &base);
        let close = book.push(SCHEMA_PARTICIPATION_SET, participation(3));
        let late = amendment(&mut book, receipts);
        let stage = run(&book);
        assert_eq!(stage.poll_close().map(ityv_encoding::Seq::get), Some(close));
        assert_eq!(
            stage
                .late_amendments()
                .iter()
                .map(|s| s.get())
                .collect::<Vec<_>>(),
            [late]
        );
        assert_eq!(stage.amendments().len(), 1);
        assert_eq!(stage.amendments()[0].custody.effective, receipts);
        assert!(stage.refused().is_empty());
        assert_eq!(stage.roll(), Some(&frozen));
        assert_eq!(stage.complete(), receipts);
        assert_eq!(stage.holds(), only(HoldReason::RollIncomplete));
    }
}

#[test]
fn a_precinct_the_genesis_adds_after_the_freeze_has_no_extract_and_holds() {
    // The review's I-d: the freeze checks the stations of the state in
    // force; an amendment that makes ST-2 an election-day station after it
    // leaves ST-2 without an extract, which no later extract can supply.
    let (world, genesis_amendment) = leak(amend(|d| {
        d.stations[1] = common::station(
            b"ST-2",
            StationKind::ElectionDay,
            common::checkin_unit(2, b"U-2A", &[b"M-U2A-P1", b"M-U2A-P2"]),
            common::checkin_unit(3, b"U-2B", &[b"M-U2B-P1", b"M-U2B-P2"]),
            &[b"BOX-3"],
            &[],
        );
    }));
    let mut book = Book::new(world);
    for (schema, e) in roll::standard(&[b"ST-1"]) {
        book.push(schema, e);
    }
    book.push(SCHEMA_SIGNED_GENESIS, genesis_amendment);
    let late = book.w(ev(residents(b"ST-2", 0x11), &[by(GU)]));
    let stage = run(&book);
    assert!(stage.freeze().unwrap().effective);
    assert_eq!(refused(&stage), [(late, Extract, R::AfterFreeze)]);
    assert_eq!(stage.missing_extracts(), [StationId::new(b"ST-2").unwrap()]);
    assert!(!stage.complete());
    assert_eq!(
        stage.holds(),
        HoldSet::empty()
            .with(HoldReason::RollEventRefused)
            .with(HoldReason::RollIncomplete)
    );
    // The same genesis amended before the freeze: the freeze needs ST-2's
    // extract, and with it nothing is missing.
    let mut book = Book::new(world);
    book.push(SCHEMA_SIGNED_GENESIS, genesis_amendment);
    for (schema, e) in roll::standard(&[b"ST-1", b"ST-2"]) {
        book.push(schema, e);
    }
    let stage = run(&book);
    assert!(stage.missing_extracts().is_empty());
    assert!(stage.complete(), "{:?}", stage.refused());
    assert_eq!(stage.holds(), HoldSet::empty());
    // No freeze yet: nothing is missing until there is one.
    let mut book = Book::new(world);
    book.push(SCHEMA_SIGNED_GENESIS, genesis_amendment);
    let stage = run(&book);
    assert!(stage.missing_extracts().is_empty());
    assert_eq!(stage.holds(), HoldSet::empty());
}

/// A contested check-in at ST-1 of `pseudonym`, signed by unit `unit`
/// (key number `unit_key`) and the modules `modules` (id, key number),
/// with an envelope label of its own (`pseudonym ^ 0x4C`).
fn contested(
    election_id: ElectionId<'static>,
    station: &'static [u8],
    unit: &'static [u8],
    unit_key: u16,
    modules: &[(&'static [u8], u16)],
    pseudonym: u8,
) -> &'static [u8] {
    let message = group(&ContestedMessage {
        election_id,
        station_id: StationId::new(station).unwrap(),
        unit_id: UnitId::new(unit).unwrap(),
        pseudonym: leak([pseudonym; 64]),
        envelope_label: Token192([pseudonym ^ 0x4C; 24]),
    });
    signed_checkin(message, unit_key, modules, 0)
}

/// The check-in of `message` signed by unit key `unit_key` and the
/// modules `modules`, the hedged signatures' randomness drawn from `seed`.
fn signed_checkin(
    message: &'static [u8],
    unit_key: u16,
    modules: &[(&'static [u8], u16)],
    seed: u64,
) -> &'static [u8] {
    let sigs: Vec<ParticipationModuleSig<'static>> = modules
        .iter()
        .map(|&(m, key)| ParticipationModuleSig {
            module_id: ModuleId::new(m).unwrap(),
            sig: sign_seeded(module_signing(key), b"contested-checkin", message, seed),
        })
        .collect();
    object(
        SCHEMA_CONTESTED_CHECKIN,
        SCHEMA_VERSION_1,
        &ContestedCheckin::new(
            message,
            sign_seeded(unit_signing(unit_key), b"contested-checkin", message, seed),
            &sigs,
        )
        .unwrap(),
    )
}

/// A check-in at ST-1 by U-1A of `pseudonym` with envelope label `label`,
/// signatures drawn from `seed` (another seed: the same message signed
/// again, another object).
fn labelled(pseudonym: u8, label: u8, seed: u64) -> &'static [u8] {
    let message = group(&ContestedMessage {
        election_id: election(),
        station_id: StationId::new(b"ST-1").unwrap(),
        unit_id: UnitId::new(b"U-1A").unwrap(),
        pseudonym: leak([pseudonym; 64]),
        envelope_label: Token192([label; 24]),
    });
    signed_checkin(message, 0, &MODULES, seed)
}

const MODULES: [(&[u8], u16); 2] = [(b"M-U1A-P1", 8), (b"M-U1A-P2", 9)];

#[test]
fn contested_checkins_are_counted_in_public_and_checked_with_access() {
    let world = election_world();
    let good = |p| contested(election(), b"ST-1", b"U-1A", 0, &MODULES, p);
    let absent = good(9);
    let twice = good(2);
    let spare = contested(
        election(),
        b"ST-1",
        b"U-1B",
        1,
        &[(b"M-U1B-P1", 10), (b"M-U1B-P2", 11)],
        8,
    );
    let invalid = [
        // Another election, a station the genesis lacks, a unit of no
        // state signing under another key, the modules out of order, one
        // party missing, a module of another unit.
        contested(
            ElectionId::new(b"E-OTHER").unwrap(),
            b"ST-1",
            b"U-1A",
            0,
            &MODULES,
            7,
        ),
        contested(election(), b"ST-9", b"U-1A", 0, &MODULES, 7),
        contested(election(), b"ST-1", b"U-1A", 1, &MODULES, 7),
        contested(
            election(),
            b"ST-1",
            b"U-1A",
            0,
            &[MODULES[1], MODULES[0]],
            7,
        ),
        contested(election(), b"ST-1", b"U-1A", 0, &MODULES[..1], 7),
        contested(
            election(),
            b"ST-1",
            b"U-1A",
            0,
            &[(b"M-U1B-P1", 10), MODULES[1]],
            7,
        ),
    ];
    let mut book = Book::new(world);
    for c in [absent, twice, spare].iter().chain(&invalid) {
        book.push(SCHEMA_CONTESTED_CHECKIN, c);
    }
    // A frame whose body is no check-in at all.
    let garbage: &'static [u8] = leak([0x5Au8; 40]);
    book.push(SCHEMA_CONTESTED_CHECKIN, garbage);
    // What a verifier with access supplies is restricted: its `Debug` shows
    // the number of bodies only.
    let supplied = [absent, spare];
    let input = RollInput {
        contested: &supplied,
    };
    assert_eq!(std::format!("{input:?}"), "RollInput { contested: 2 }");
    // The public verifier counts the frames and holds nothing.
    let stage = run(&book);
    assert_eq!(stage.contested_frames(), 10);
    assert!(stage.contested().is_empty());
    assert_eq!(stage.holds(), HoldSet::empty());
    // Before ST-1's participation set: undetermined.
    let stage = run_with(&book, &[absent, spare]);
    assert_eq!(
        stage
            .contested()
            .iter()
            .map(|c| c.finding)
            .collect::<Vec<_>>(),
        [
            ContestedFinding::Undetermined,
            ContestedFinding::Undetermined
        ]
    );
    assert_eq!(stage.holds(), HoldSet::empty());
    // With every station's set: absent, or counted at ST-1.
    book.push(SCHEMA_PARTICIPATION_SET, participation(3));
    let mut supplied = std::vec![absent, twice, spare];
    supplied.extend(invalid);
    supplied.push(garbage);
    let off_ledger = good(6);
    supplied.push(off_ledger);
    let stage = run_with(&book, &supplied);
    let st1 = StationId::new(b"ST-1").unwrap();
    let findings: Vec<ContestedFinding<'_>> = stage.contested().iter().map(|c| c.finding).collect();
    // Seven of the ten frames have no body that verifies, so a pseudonym
    // found in no set is not yet absent: one of those could be another
    // check-in of it.
    let mut expected = std::vec![
        ContestedFinding::Undetermined,
        ContestedFinding::Elsewhere(st1),
        ContestedFinding::Undetermined,
    ];
    expected.extend([ContestedFinding::Invalid; 7]);
    expected.push(ContestedFinding::NotOnLedger);
    assert_eq!(findings, expected);
    assert_eq!(
        stage.contested()[0].seq.map(ityv_encoding::Seq::get),
        Some(3)
    );
    assert_eq!(stage.contested()[0].station, Some(st1));
    assert_eq!(stage.contested()[9].station, None);
    assert_eq!(stage.contested()[10].seq, None);
    assert_eq!(stage.holds(), only(HoldReason::ContestedCheckinInvalid));
    // A body not on the ledger alone holds nothing.
    let stage = run_with(&book, &[off_ledger, absent]);
    assert_eq!(stage.holds(), HoldSet::empty());
    // Pseudonyms below, between and above the set's are absent.
    let mut book = Book::new(world);
    book.push(SCHEMA_PARTICIPATION_SET, participation(3));
    let probes: Vec<&'static [u8]> = [0u8, 4, 1, 3]
        .iter()
        .map(|p| contested(election(), b"ST-1", b"U-1A", 0, &MODULES, *p))
        .collect();
    for c in &probes {
        book.push(SCHEMA_CONTESTED_CHECKIN, c);
    }
    let stage = run_with(&book, &probes);
    assert_eq!(
        stage
            .contested()
            .iter()
            .map(|c| c.finding)
            .collect::<Vec<_>>(),
        [
            ContestedFinding::Absent,
            ContestedFinding::Absent,
            ContestedFinding::Elsewhere(st1),
            ContestedFinding::Elsewhere(st1),
        ]
    );
}

#[test]
fn a_pseudonym_or_an_envelope_label_in_two_check_ins_excludes_them_all() {
    // The second review's proof of concept: one voter (pseudonym 9, in no
    // participation set) with three contested check-ins: two envelopes,
    // and the first one's message signed again (hedged signatures make it
    // another object). Each was `Absent`, so countable, with no hold. Now
    // both envelopes are excluded and reported, without a hold (as for a
    // pseudonym found in a participation set).
    let st1 = StationId::new(b"ST-1").unwrap();
    let mut book = Book::new(election_world());
    book.push(SCHEMA_PARTICIPATION_SET, participation(3));
    let first = labelled(9, 0x4C, 1);
    let second_envelope = labelled(9, 0x4D, 1);
    let resigned = labelled(9, 0x4C, 2);
    assert_ne!(first, resigned, "fresh signatures give a new object");
    let mut frames = Vec::new();
    for c in [first, second_envelope, resigned] {
        frames.push(book.push(SCHEMA_CONTESTED_CHECKIN, c));
    }
    let first_seq = ityv_encoding::Seq::new(frames[0]).unwrap();
    let stage = run_with(&book, &[resigned, second_envelope, first]);
    let findings: Vec<ContestedFinding<'_>> = stage.contested().iter().map(|c| c.finding).collect();
    assert_eq!(stage.contested_frames(), 3);
    assert_eq!(
        findings,
        [
            ContestedFinding::Copy(first_seq),
            ContestedFinding::Repeated,
            ContestedFinding::Repeated,
        ]
    );
    assert_eq!(stage.holds(), HoldSet::empty());
    // The copy is counted once: two messages at ST-1.
    assert_eq!(stage.contested_counts(), [(st1, 2)]);

    // One envelope and its re-signed copy: one countable check-in, no
    // hold.
    let mut book = Book::new(election_world());
    book.push(SCHEMA_PARTICIPATION_SET, participation(3));
    for c in [first, resigned] {
        book.push(SCHEMA_CONTESTED_CHECKIN, c);
    }
    let stage = run_with(&book, &[first, resigned, first]);
    let findings: Vec<ContestedFinding<'_>> = stage.contested().iter().map(|c| c.finding).collect();
    assert_eq!(
        findings,
        [
            ContestedFinding::Absent,
            ContestedFinding::Copy(first_seq),
            ContestedFinding::Copy(first_seq),
        ]
    );
    assert_eq!(stage.holds(), HoldSet::empty());
    assert_eq!(stage.contested_counts(), [(st1, 1)]);

    // One envelope label under two pseudonyms: both excluded, even the one
    // whose pseudonym is in a set, and the ledger holds (a device or
    // insider fault); a third check-in of its own label is untouched.
    let mut book = Book::new(election_world());
    book.push(SCHEMA_PARTICIPATION_SET, participation(3));
    let a = labelled(9, 0x4C, 1);
    let b = labelled(2, 0x4C, 1);
    let c = labelled(8, 0x4E, 1);
    for x in [a, b, c] {
        book.push(SCHEMA_CONTESTED_CHECKIN, x);
    }
    let stage = run_with(&book, &[a, b, c]);
    let findings: Vec<ContestedFinding<'_>> = stage.contested().iter().map(|c| c.finding).collect();
    assert_eq!(
        findings,
        [
            ContestedFinding::LabelReused,
            ContestedFinding::LabelReused,
            ContestedFinding::Absent,
        ]
    );
    assert_eq!(stage.holds(), only(HoldReason::ContestedLabelReused));
    assert_eq!(stage.contested_counts(), [(st1, 3)]);
    // A pseudonym repeated and found elsewhere is repeated: both
    // envelopes are excluded either way, without a hold.
    let mut book = Book::new(election_world());
    book.push(SCHEMA_PARTICIPATION_SET, participation(3));
    let a = labelled(2, 0x50, 1);
    let b = labelled(2, 0x51, 1);
    for x in [a, b] {
        book.push(SCHEMA_CONTESTED_CHECKIN, x);
    }
    let stage = run_with(&book, &[a, b]);
    assert!(
        stage
            .contested()
            .iter()
            .all(|c| c.finding == ContestedFinding::Repeated)
    );
    assert_eq!(stage.holds(), HoldSet::empty());
    // The public verifier sees frames only, and holds nothing.
    assert_eq!(run(&book).holds(), HoldSet::empty());
}

/// A check-in of `pseudonym` with envelope label `label` at `station` by
/// `unit` (key number `unit_key`) and the modules `modules`, signatures
/// drawn from `seed`.
fn checkin_at(
    station: &'static [u8],
    unit: &'static [u8],
    unit_key: u16,
    modules: &[(&'static [u8], u16)],
    (pseudonym, label): (u8, u8),
    seed: u64,
) -> &'static [u8] {
    let message = group(&ContestedMessage {
        election_id: election(),
        station_id: StationId::new(station).unwrap(),
        unit_id: UnitId::new(unit).unwrap(),
        pseudonym: leak([pseudonym; 64]),
        envelope_label: Token192([label; 24]),
    });
    signed_checkin(message, unit_key, modules, seed)
}

const ST2_MODULES: [(&[u8], u16); 2] = [(b"M-U2A-P1", 12), (b"M-U2A-P2", 13)];
const SPARE_MODULES: [(&[u8], u16); 2] = [(b"M-U1B-P1", 10), (b"M-U1B-P2", 11)];

fn findings_of(stage: &RollStage<'static>) -> Vec<ContestedFinding<'static>> {
    stage.contested().iter().map(|c| c.finding).collect()
}

#[test]
fn a_check_in_is_absent_only_against_every_contested_frame_s_body() {
    // The final review's F1: pseudonym 9 (in no set) has two envelopes on
    // the ledger. A verifier given one body (one district's) saw `Absent`,
    // countable, with no hold.
    let mut book = Book::new(election_world());
    book.push(SCHEMA_PARTICIPATION_SET, participation(3));
    let first = labelled(9, 0x4C, 1);
    let second = labelled(9, 0x4D, 1);
    book.push(SCHEMA_CONTESTED_CHECKIN, first);
    book.push(SCHEMA_CONTESTED_CHECKIN, second);
    let both = run_with(&book, &[first, second]);
    assert_eq!(
        findings_of(&both),
        [ContestedFinding::Repeated, ContestedFinding::Repeated]
    );
    assert_eq!(both.holds(), HoldSet::empty());
    for supplied in [first, second] {
        let one = run_with(&book, &[supplied]);
        assert_eq!(one.contested_frames(), 2);
        assert_eq!(findings_of(&one), [ContestedFinding::Undetermined]);
        assert_eq!(one.holds(), HoldSet::empty());
    }
    // Another voter's envelope beside it: undetermined until every frame's
    // body is in, then absent.
    let mut book = Book::new(election_world());
    book.push(SCHEMA_PARTICIPATION_SET, participation(3));
    let other = labelled(8, 0x4E, 1);
    for c in [first, other] {
        book.push(SCHEMA_CONTESTED_CHECKIN, c);
    }
    assert_eq!(
        findings_of(&run_with(&book, &[first])),
        [ContestedFinding::Undetermined]
    );
    assert_eq!(
        findings_of(&run_with(&book, &[first, other])),
        [ContestedFinding::Absent, ContestedFinding::Absent]
    );
    // A copy covers its own frame; a body of the frame that does not
    // verify does not.
    let resigned = labelled(9, 0x4C, 2);
    let mut book = Book::new(election_world());
    book.push(SCHEMA_PARTICIPATION_SET, participation(3));
    let first_seq = ityv_encoding::Seq::new(book.push(SCHEMA_CONTESTED_CHECKIN, first)).unwrap();
    book.push(SCHEMA_CONTESTED_CHECKIN, resigned);
    assert_eq!(
        findings_of(&run_with(&book, &[first, resigned])),
        [ContestedFinding::Absent, ContestedFinding::Copy(first_seq)]
    );
    assert_eq!(
        findings_of(&run_with(&book, &[first])),
        [ContestedFinding::Undetermined]
    );
    let foreign = contested(
        ElectionId::new(b"E-OTHER").unwrap(),
        b"ST-1",
        b"U-1A",
        0,
        &MODULES,
        8,
    );
    let mut book = Book::new(election_world());
    book.push(SCHEMA_PARTICIPATION_SET, participation(3));
    for c in [first, foreign] {
        book.push(SCHEMA_CONTESTED_CHECKIN, c);
    }
    let stage = run_with(&book, &[first, foreign]);
    assert_eq!(
        findings_of(&stage),
        [ContestedFinding::Undetermined, ContestedFinding::Invalid]
    );
    assert_eq!(stage.holds(), only(HoldReason::ContestedCheckinInvalid));
}

#[test]
fn a_check_in_is_its_whole_message_and_a_shared_label_holds() {
    // The final review's F3: the same (pseudonym, label) signed at ST-1 and
    // at ST-2 by their units was a silent copy; ST-2's check-in vanished
    // from the per-station count. Now they are two messages sharing a
    // label: both excluded, and the ledger holds.
    let st1 = StationId::new(b"ST-1").unwrap();
    let st2 = StationId::new(b"ST-2").unwrap();
    let at_st1 = checkin_at(b"ST-1", b"U-1A", 0, &MODULES, (9, 0x4C), 1);
    let at_st2 = checkin_at(b"ST-2", b"U-2A", 2, &ST2_MODULES, (9, 0x4C), 1);
    let mut book = Book::new(world());
    for c in [at_st1, at_st2] {
        book.push(SCHEMA_CONTESTED_CHECKIN, c);
    }
    let stage = run_with(&book, &[at_st1, at_st2]);
    assert_eq!(
        findings_of(&stage),
        [ContestedFinding::LabelReused, ContestedFinding::LabelReused]
    );
    assert_eq!(stage.holds(), only(HoldReason::ContestedLabelReused));
    assert_eq!(stage.contested_counts(), [(st1, 1), (st2, 1)]);
    // At one station by the unit in service and the spare: two messages.
    let spare = checkin_at(b"ST-1", b"U-1B", 1, &SPARE_MODULES, (9, 0x4C), 1);
    let mut book = Book::new(world());
    for c in [at_st1, spare] {
        book.push(SCHEMA_CONTESTED_CHECKIN, c);
    }
    let stage = run_with(&book, &[at_st1, spare]);
    assert_eq!(
        findings_of(&stage),
        [ContestedFinding::LabelReused, ContestedFinding::LabelReused]
    );
    assert_eq!(stage.contested_counts(), [(st1, 2)]);
    // One pseudonym under two labels at two stations: the voter contested
    // twice, excluded and reported without a hold, each station counting
    // its own.
    let other_label = checkin_at(b"ST-2", b"U-2A", 2, &ST2_MODULES, (9, 0x4D), 1);
    let mut book = Book::new(world());
    for c in [at_st1, other_label] {
        book.push(SCHEMA_CONTESTED_CHECKIN, c);
    }
    let stage = run_with(&book, &[at_st1, other_label]);
    assert_eq!(
        findings_of(&stage),
        [ContestedFinding::Repeated, ContestedFinding::Repeated]
    );
    assert_eq!(stage.holds(), HoldSet::empty());
    assert_eq!(stage.contested_counts(), [(st1, 1), (st2, 1)]);
    // A label shared and a pseudonym repeated: the label wins and holds,
    // and the pseudonym's other envelope is repeated.
    let third = checkin_at(b"ST-2", b"U-2A", 2, &ST2_MODULES, (7, 0x4D), 1);
    let mut book = Book::new(world());
    for c in [at_st1, other_label, third] {
        book.push(SCHEMA_CONTESTED_CHECKIN, c);
    }
    let stage = run_with(&book, &[at_st1, other_label, third]);
    assert_eq!(
        findings_of(&stage),
        [
            ContestedFinding::Repeated,
            ContestedFinding::LabelReused,
            ContestedFinding::LabelReused,
        ]
    );
    assert_eq!(stage.holds(), only(HoldReason::ContestedLabelReused));
}

#[test]
fn a_check_in_whose_pseudonym_is_in_its_own_station_s_set_is_excluded() {
    // The final review's F2 (legal): the code excludes a pseudonym found in
    // any station's set, the contesting station's own included; the
    // statute now says so (`LEGAL_ANNEX.md` §44-5 ②).
    let mut book = Book::new(election_world());
    book.push(SCHEMA_PARTICIPATION_SET, participation(3));
    let c = labelled(2, 0x60, 1);
    book.push(SCHEMA_CONTESTED_CHECKIN, c);
    let stage = run_with(&book, &[c]);
    assert_eq!(stage.contested()[0].station, StationId::new(b"ST-1"));
    assert_eq!(
        findings_of(&stage),
        [ContestedFinding::Elsewhere(
            StationId::new(b"ST-1").unwrap()
        )]
    );
    assert_eq!(stage.holds(), HoldSet::empty());
}

#[test]
fn an_entry_commitment_is_salted_and_proved_against_the_root() {
    // C = SHA3-512("ityv:roll:v1" ‖ 0x00 ‖ salt ‖ entry), computed outside
    // this code base (Python hashlib.sha3_512).
    let salt = [0x5Au8; 32];
    let c = roll_entry_commitment(&salt, b"entry-1");
    assert_eq!(c, Hash512(EXPECTED_COMMITMENT));
    assert_ne!(roll_entry_commitment(&[0x5B; 32], b"entry-1"), c);
    assert_ne!(roll_entry_commitment(&salt, b"entry-2"), c);
    // A root over three commitments in ascending order.
    let mut leaves: Vec<Hash512> = (0u8..3)
        .map(|i| roll_entry_commitment(&[i; 32], b"entry"))
        .collect();
    leaves.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    let root = ityv_ledger::sorted_set_root(&leaves).unwrap();
    let mut acc = Accumulator::empty();
    for l in &leaves {
        acc.push(l).unwrap();
    }
    assert_eq!(acc.root(), root);
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = inclusion_proof(&leaves.as_slice(), 3, i as u64).unwrap();
        assert!(roll_entry_included(&root, 3, i as u64, leaf, &proof));
        assert!(!roll_entry_included(
            &root,
            3,
            (i as u64 + 1) % 3,
            leaf,
            &proof
        ));
        assert!(!roll_entry_included(
            &Hash512([1; 64]),
            3,
            i as u64,
            leaf,
            &proof
        ));
        assert!(!roll_entry_included(&root, 3, 3, leaf, &proof));
    }
}

/// `SHA3-512(b"ityv:roll:v1" + b"\x00" + b"\x5a" * 32 + b"entry-1")`.
const EXPECTED_COMMITMENT: [u8; 64] = [
    0x94, 0x4f, 0xce, 0xf9, 0xab, 0xb5, 0x06, 0xa1, 0x58, 0xb7, 0x69, 0xa6, 0x4f, 0xec, 0x4a, 0x61,
    0x76, 0xd5, 0x5a, 0xaa, 0x7c, 0xdb, 0x7a, 0xc1, 0xcc, 0xfc, 0x0c, 0x58, 0x71, 0xf2, 0xdb, 0xde,
    0x08, 0x8f, 0xc4, 0x59, 0x4d, 0xde, 0x70, 0x4b, 0xe5, 0x0c, 0x77, 0xcb, 0xda, 0x79, 0x13, 0xee,
    0xfa, 0x30, 0x6b, 0x72, 0xa8, 0x3e, 0xee, 0x82, 0x8d, 0x6f, 0xce, 0x93, 0xd0, 0xf4, 0x9b, 0x04,
];

#[test]
fn a_roll_event_of_another_election_is_the_index_s_to_refuse() {
    let body = object(
        ityv_encoding::SCHEMA_ROLL_SOURCE_EXTRACT_BODY,
        SCHEMA_VERSION_1,
        &ityv_encoding::RollSourceExtractBody::new(&ityv_encoding::RollSourceExtractParts {
            election_id: ElectionId::new(b"E-OTHER").unwrap(),
            authority_id: ityv_encoding::AuthorityId::new(GU).unwrap(),
            kind: RollSourceKind::Residents,
            precinct: Some(StationId::new(b"ST-1").unwrap()),
            reference_day: ityv_encoding::Day::new(1),
            entry_count: 1,
            entries_root: Hash512([0x31; 64]),
        })
        .unwrap(),
    );
    let book = book_of(world(), &[ev(body, &[by(GU)])]);
    let g = book.world.genesis;
    let index = build_index(g, book.ledger.bytes(), &book.ledger.events);
    assert_eq!(index.findings().len(), 1);
    assert_eq!(
        index.findings()[0].kind,
        ityv_verify::FindingKind::OtherElection
    );
    assert!(index.ledger_holds().contains(HoldReason::LedgerUnchecked));
}
