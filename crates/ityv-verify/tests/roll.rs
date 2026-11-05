//! The voter roll (PROTOCOL.md §6.1, §6.2, §14 6; ADR-0033, ADR-0040;
//! VC-107..111): source extracts, the freeze as their merge, custody
//! receipts and the custody quorum, amendments with their sources, and
//! contested check-ins, all signed with real hybrid signatures under the
//! keys the genesis registers (`tests/common/roll.rs`). Every refusal of
//! the stage, the quorum's number and both branches, the pseudonym root,
//! a disagreeing receipt, the entry commitment and its inclusion proof.
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
    self, APPEAL, C_INT, C_IVC, C_JUD, C_PA, DEATHS, GU, IVC, NEC, OVERSEAS, SNAPSHOT, Who, by,
    residents, snapshot, sources, state, witnessed,
};
use common::{election, leak, module_signing, object, sign, unit_signing};
use ityv_crypto::object_hash;
use ityv_encoding::{
    ContestedCheckin, ContestedMessage, ElectionId, EventRole, Hash512, ModuleId,
    ParticipationModuleSig, RollAmendmentReason, RollSourceKind, SCHEMA_CONTESTED_CHECKIN,
    SCHEMA_PARTICIPATION_SET, SCHEMA_VERSION_1, StationId, Token192, UnitId,
};
use ityv_ledger::{Accumulator, inclusion_proof};
use ityv_state::{HoldReason, HoldSet};
use ityv_verify::{
    ContestedFinding, RollEvent, RollInput, RollRefusal, RollStage, authorize_ledger, build_index,
    roll_entry_commitment, roll_entry_included, verify_boxes, verify_participation, verify_records,
    verify_roll,
};

use world::{Book, World, election_world, group, participation, world};

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

/// The freeze of `state(0x40)` over `bodies`.
fn freeze_of(bodies: &[&'static [u8]]) -> &'static [u8] {
    roll::freeze(state(0x40), sources(bodies))
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
        state(0x40),
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
    assert_eq!(stage.roll(), Some(&state(0x40)));
    assert_eq!(stage.contested_frames(), 0);
    // Other lists (deaths, disqualifications, overseas voters) join the
    // merge when their sources sign them.
    let (bodies, events) = sources_of_st1();
    let lists = [
        roll::extract(DEATHS, RollSourceKind::Deaths, None, 0x21),
        roll::extract(
            common::roll::DISQ,
            RollSourceKind::Disqualifications,
            None,
            0x22,
        ),
        roll::extract(OVERSEAS, RollSourceKind::Overseas, None, 0x23),
    ];
    let all: Vec<&'static [u8]> = bodies.iter().chain(&lists).copied().collect();
    let body = freeze_of(&all);
    let mut list = events.to_vec();
    list.push(ev(lists[0], &[by(DEATHS)]));
    list.push(ev(lists[1], &[by(common::roll::DISQ)]));
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
fn a_receipt_answers_a_state_taken_before_it_once_per_custodian() {
    let (bodies, events) = sources_of_st1();
    let body = freeze_of(&bodies);
    let root = sources(&bodies).0;
    let s = state(0x40);
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
    let good = state(0x40);
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

/// A contested check-in at ST-1 of `pseudonym`, signed by unit `unit`
/// (key number `unit_key`) and the modules `modules` (id, key number).
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
        envelope_label: Token192([0x4C; 24]),
    });
    let sigs: Vec<ParticipationModuleSig<'static>> = modules
        .iter()
        .map(|&(m, key)| ParticipationModuleSig {
            module_id: ModuleId::new(m).unwrap(),
            sig: sign(module_signing(key), b"contested-checkin", message),
        })
        .collect();
    object(
        SCHEMA_CONTESTED_CHECKIN,
        SCHEMA_VERSION_1,
        &ContestedCheckin::new(
            message,
            sign(unit_signing(unit_key), b"contested-checkin", message),
            &sigs,
        )
        .unwrap(),
    )
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
    let mut expected = std::vec![
        ContestedFinding::Absent,
        ContestedFinding::Elsewhere(st1),
        ContestedFinding::Absent,
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
