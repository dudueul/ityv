//! The tally stage (PROTOCOL.md §10.6, §11, §14 7; VC-024, VC-042..044,
//! VC-057, VC-063, VC-075, VC-099): receipt resolutions, legal tally
//! effects, tally scopes against the recomputation, aggregate openings
//! against the sum of real commitments, paper counts per reporting unit,
//! and the report reaching `CRYPTO_TALLY_VERIFIED`. Every record carries a
//! real OR proof over commitments made from known secrets, every opening
//! opens their real sum, and every signature is a real hybrid signature
//! under a key the genesis registers.
// Integration tests: outside the TCB. Assertions use unwrap/expect, so these
// lints are relaxed for this file only (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::struct_field_names,
    clippy::type_complexity
)]

mod common;
mod world;

use std::vec::Vec;

use common::{ROSTER_BASE, object};
use ityv_crypto::{Scalar, object_hash};
use ityv_encoding::{
    BatchAttest, BoxId, ChamberCode, CloseCounts, DisputeType, EventRole, ExclusionReason, Hash512,
    QuorumSigned, ReceiptOutcome, SCHEMA_BATCH_ATTEST, SCHEMA_BOX_CLOSE, SCHEMA_CAST_RECORD,
    SCHEMA_MODULE_PROVISIONED, SCHEMA_PARTICIPATION_SET, SCHEMA_PARTY_KEY_CEREMONY,
    SCHEMA_QUORUM_SIGNED, SCHEMA_SIGNED_GENESIS, SCHEMA_VERSION_1, SCHEMA_WITNESSED_EVENT,
    SchemaId, Seq, TallyEffect, TimeBucket, WitnessedEvent,
};
use ityv_encoding::{
    LateBatchCloseBody, LateBatchCloseParts, LateBatchReason, SCHEMA_CHALLENGE_OPENING,
    SCHEMA_LATE_BATCH_CLOSE_BODY,
};
use ityv_state::{HoldReason, HoldSet, Publication, Status};
use ityv_verify::{
    ExpectedExclusion, OpeningOutcome, Publications, Report, ScopeProblem, TallyEvent,
    TallyRefusal, build_index, verify_ledger,
};

use world::*;

// ---------------------------------------------------------------------
// A clean unit.

#[test]
fn a_clean_unit_is_tallied_and_agrees_with_its_paper() {
    let mut book = Book::new(world());
    let casts = box1(&mut book);
    let (at, opened_at) = tally1(
        &mut book,
        &casts,
        &spec(STYLE1, RU1, &codes(&casts)),
        &[1, 1, 1, 0, 0],
        0,
    );
    let stage = book.run();
    assert!(stage.refused().is_empty(), "{:?}", stage.refused());
    let u = unit1(&stage);
    assert_eq!(u.included, sorted(&codes(&casts)));
    assert_eq!(u.included_root, Some(root(&codes(&casts))));
    assert!(u.exclusions.is_empty());
    assert_eq!(u.scope, Some(Seq::new(at).unwrap()));
    assert!(u.scope_problems.is_empty(), "{:?}", u.scope_problems);
    assert_eq!(u.chunks, 1);
    assert_eq!(u.openings.len(), 1);
    assert_eq!(u.openings[0].seq.get(), opened_at);
    assert_eq!(u.openings[0].outcome, OpeningOutcome::Verified);
    // BLANK, five candidates, UNREADABLE.
    assert_eq!(u.counts, Some(std::vec![0, 1, 1, 1, 0, 0, 0]));
    assert_eq!(u.paper.map(Seq::get), Some(opened_at + 1));
    assert!(u.comparison.unwrap().agrees());
    assert_eq!(u.holds, HoldSet::empty());
    assert!(u.complete());
    assert!(u.passed());
    // The out-of-district unit has nothing yet: incomplete, not held.
    let u2 = stage.unit(STYLE2, RU2).unwrap();
    assert!(!u2.complete());
    assert!(!u2.passed());
    assert_eq!(u2.chunks, 2);
    assert_eq!(stage.holds(), HoldSet::empty());
    assert!(!stage.complete());
    assert!(!stage.passed());
    assert_eq!(stage.units().len(), 2);
    assert!(stage.unit(STYLE1, RU2).is_none());
}

#[test]
fn the_index_scopes_the_tally_events_to_the_election() {
    let mut book = Book::new(world());
    let casts = box1(&mut book);
    tally1(
        &mut book,
        &casts,
        &spec(STYLE1, RU1, &codes(&casts)),
        &[1, 1, 1, 0, 0],
        0,
    );
    book.q(resolution(B3, &[], READY));
    let g = world().genesis;
    let index = build_index(g, book.ledger.bytes(), &book.ledger.events);
    assert!(index.findings().is_empty(), "{:?}", index.findings());
    let election: Vec<SchemaId> = index
        .events()
        .iter()
        .filter(|e| e.scope == ityv_verify::Scope::Election)
        .map(|e| e.schema)
        .collect();
    let quorum = election
        .iter()
        .filter(|s| **s == SCHEMA_QUORUM_SIGNED)
        .count();
    assert_eq!(quorum, 3);
    assert!(election.contains(&SCHEMA_WITNESSED_EVENT));
}

// ---------------------------------------------------------------------
// The scope.

#[test]
fn a_scope_with_a_wrong_count_root_or_no_record_count_is_a_mismatch() {
    let casts_codes = |book: &mut Book| codes(&box1(book));
    let cases: [(fn(&mut ScopeSpec), &[ScopeProblem]); 3] = [
        (|s| s.count = Some(2), &[ScopeProblem::IncludedCount]),
        (
            |s| s.root = Some(Hash512([0x77; 64])),
            &[ScopeProblem::IncludedRoot],
        ),
        (|s| s.no_record = 1, &[ScopeProblem::NoRecordCount]),
    ];
    for (change, problems) in cases {
        let mut book = Book::new(world());
        let c = casts_codes(&mut book);
        let mut s = spec(STYLE1, RU1, &c);
        change(&mut s);
        book.q(scope(scope_body(&s)));
        let stage = book.run();
        let u = unit1(&stage);
        assert_eq!(u.scope_problems, problems);
        assert_eq!(u.holds, only(HoldReason::TallyScopeMismatch));
        assert!(!u.passed());
        assert!(stage.holds().contains(HoldReason::TallyScopeMismatch));
    }
    // A record left out of the included set.
    let mut book = Book::new(world());
    let c = casts_codes(&mut book);
    book.q(scope(scope_body(&spec(STYLE1, RU1, &c[..2]))));
    let u = unit1(&book.run());
    assert_eq!(
        u.scope_problems,
        [ScopeProblem::IncludedCount, ScopeProblem::IncludedRoot]
    );
}

/// BOX-1 with a cast record (option 1) attested, a test ballot and a cast
/// record (option 0, BLANK) in no batch, and one ballot without a record:
/// the test ballot is `TEST_BALLOT` (first of §11.1, though also
/// unattested), the other `UNATTESTED`.
fn mixed(book: &mut Book) -> (Cast, Cast, Cast, Hash512) {
    let kept = cast(B1, 1, 1);
    let test = cast_styled(B1, 2, 4, b"TEST-1", 7);
    let late = cast(B1, 3, 0);
    book.w(opened(B1));
    for c in [kept, test, late] {
        book.push(SCHEMA_CAST_RECORD, c.event);
    }
    book.push(SCHEMA_BATCH_ATTEST, batch(B1, 0, 1, 1, &[kept.code]));
    let closed = close(B1, 3, 1, 1, &[kept.code, test.code, late.code]);
    book.push(SCHEMA_BOX_CLOSE, closed);
    book.checkpoint();
    (kept, test, late, object_hash(closed))
}

#[test]
fn an_exclusion_cites_the_first_reason_and_its_basis() {
    let mut book = Book::new(world());
    let (kept, test, late, closed) = mixed(&mut book);
    let mut s = spec(STYLE1, RU1, &[kept.code]);
    s.no_record = 1;
    s.exclusions = std::vec![
        exclusion(
            test.code,
            ExclusionReason::TestBallot,
            object_hash(test.event)
        ),
        exclusion(late.code, ExclusionReason::Unattested, closed),
    ];
    let good = s.clone();
    tally1(&mut book, &[kept], &s, &[2, 0, 0, 0, 0], 2);
    let stage = book.run();
    let u = unit1(&stage);
    assert!(u.scope_problems.is_empty(), "{:?}", u.scope_problems);
    let mut expected = std::vec![
        ExpectedExclusion {
            record_hash: test.code,
            reason: ExclusionReason::TestBallot,
            basis: Some(object_hash(test.event)),
        },
        ExpectedExclusion {
            record_hash: late.code,
            reason: ExclusionReason::Unattested,
            basis: Some(closed),
        },
    ];
    expected.sort_by(|a, b| a.record_hash.as_bytes().cmp(b.record_hash.as_bytes()));
    assert_eq!(u.exclusions, expected);
    assert_eq!(u.no_record_count, 1);
    // Both excluded ballots are in the box: the paper counts them.
    assert_eq!(u.excluded_with_paper, 2);
    // Paper: candidate 1 twice (the emergency ballot), the blank and test
    // ballots invalid: 2 + 2 = D + B + U + F + X = 1 + 0 + 0 + 1 + 2.
    assert_eq!(u.counts, Some(std::vec![0, 1, 0, 0, 0, 0, 0]));
    assert!(u.comparison.unwrap().agrees(), "{:?}", u.comparison);
    assert!(u.passed(), "{u:?}");

    // A later reason of §11.1 for the test ballot, a basis that is not
    // the event, a record missing, a record the verifier includes.
    let cases: [(
        fn(&mut ScopeSpec, Cast, Cast, Cast),
        fn(Cast, Cast, Cast) -> ScopeProblem,
    ); 4] = [
        (
            |s, _, _, _| s.exclusions[0].reason = ExclusionReason::Unattested,
            |_, test, _| ScopeProblem::Reason(test.code),
        ),
        (
            |s, _, _, late| s.exclusions[1].basis = object_hash(late.event),
            |_, _, late| ScopeProblem::Basis(late.code),
        ),
        (
            |s, _, _, _| {
                s.exclusions.remove(1);
            },
            |_, _, late| ScopeProblem::Missing(late.code),
        ),
        (
            |s, kept, _, _| {
                s.exclusions.push(exclusion(
                    kept.code,
                    ExclusionReason::Unattested,
                    Hash512([1; 64]),
                ));
            },
            |kept, _, _| ScopeProblem::Unexpected(kept.code),
        ),
    ];
    for (change, problem) in cases {
        let mut book = Book::new(world());
        let (kept, test, late, _) = mixed(&mut book);
        let mut s = good.clone();
        change(&mut s, kept, test, late);
        book.q(scope(scope_body(&s)));
        let u = unit1(&book.run());
        assert_eq!(u.scope_problems, [problem(kept, test, late)]);
        assert_eq!(u.holds, only(HoldReason::TallyScopeMismatch));
    }
}

#[test]
fn a_challenged_record_cites_its_challenge_opening() {
    let mut book = Book::new(world());
    let kept = cast(B1, 1, 1);
    let opened_one = cast(B1, 2, 3);
    book.w(opened(B1));
    book.push(SCHEMA_CAST_RECORD, kept.event);
    book.push(SCHEMA_CAST_RECORD, opened_one.event);
    let shown = challenge(B1, &opened_one);
    book.push(SCHEMA_CHALLENGE_OPENING, shown);
    book.push(SCHEMA_BATCH_ATTEST, batch(B1, 0, 1, 1, &[kept.code]));
    let counts = CloseCounts {
        paper: 1,
        records: 1,
        attested: 1,
        without_record: 0,
        challenged: 1,
        quarantined: 0,
        visits: 1,
        envelopes: 0,
        stickers: 0,
        spoil_envelopes: 1,
    };
    book.push(
        SCHEMA_BOX_CLOSE,
        close_full(B1, counts, 2, &[kept.code], Some(b"box-close")),
    );
    book.checkpoint();
    let mut s = spec(STYLE1, RU1, &[kept.code]);
    s.exclusions = std::vec![exclusion(
        opened_one.code,
        ExclusionReason::ChallengedSpoiled,
        object_hash(shown)
    )];
    tally1(&mut book, &[kept], &s, &[1, 0, 0, 0, 0], 0);
    let stage = book.run();
    let u = unit1(&stage);
    assert_eq!(
        u.exclusions,
        [ExpectedExclusion {
            record_hash: opened_one.code,
            reason: ExclusionReason::ChallengedSpoiled,
            basis: Some(object_hash(shown)),
        }]
    );
    // The spoiled ballot is not in the box: nothing to count on paper.
    assert_eq!(u.excluded_with_paper, 0);
    assert!(u.passed(), "{u:?}");
}

#[test]
fn a_scope_before_its_time_is_refused() {
    // BOX-1 still open.
    let mut book = Book::new(world());
    book.w(opened(B1));
    let early = book.q(scope(scope_body(&spec(STYLE1, RU1, &[]))));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [(early, TallyEvent::Scope, TallyRefusal::Premature)]
    );
    assert_eq!(unit1(&stage).scope, None);
    assert_eq!(unit1(&stage).holds, only(HoldReason::TallyScopeRefused));
    assert_eq!(stage.holds(), only(HoldReason::TallyScopeRefused));

    // The witnesses' time is past the window, but the box's close is in a
    // later frame than the scope.
    let mut book = Book::new(world());
    book.w(opened(B1));
    let c = cast(B1, 1, 1);
    book.push(SCHEMA_CAST_RECORD, c.event);
    book.push(SCHEMA_BATCH_ATTEST, batch(B1, 0, 1, 1, &[c.code]));
    book.checkpoint();
    let before_close = book.q(scope(scope_body(&spec(STYLE1, RU1, &[c.code]))));
    book.push(SCHEMA_BOX_CLOSE, close(B1, 1, 1, 0, &[c.code]));
    assert_eq!(
        refused(&book.run()),
        [(before_close, TallyEvent::Scope, TallyRefusal::Premature)]
    );

    // Within the late-close window by the witnesses' time, though the
    // trustees date the scope after it; then after it: the second is
    // taken.
    let mut book = Book::new(world());
    let casts = box1_closed(&mut book);
    book.checkpoint_at(CLOSE_BUCKET + 96);
    let mut s = spec(STYLE1, RU1, &codes(&casts));
    s.bucket = READY + 50;
    let early = book.q(scope(scope_body(&s)));
    book.checkpoint();
    let (at, _) = tally1(
        &mut book,
        &casts,
        &spec(STYLE1, RU1, &codes(&casts)),
        &[1, 1, 1, 0, 0],
        0,
    );
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [(early, TallyEvent::Scope, TallyRefusal::Premature)]
    );
    let u = unit1(&stage);
    assert_eq!(u.scope.map(Seq::get), Some(at));
    assert!(u.counts.is_some());
    assert_eq!(u.holds, only(HoldReason::TallyScopeRefused));
    assert!(!u.passed());
    assert!(!stage.passed());

    // A second scope after one was taken: the same body under other
    // signature bytes, and another body (a conflict, never silently
    // "already has one").
    let mut book = Book::new(world());
    let casts = box1(&mut book);
    let s = spec(STYLE1, RU1, &codes(&casts));
    let body = scope_body(&s);
    book.q(scope(body));
    let again = book.q(quorum_seeded(body, b"tally-scope", &QUORUM, Some(9)));
    let other = book.q(scope(scope_body(&ScopeSpec {
        bucket: READY + 5,
        ..s
    })));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [
            (again, TallyEvent::Scope, TallyRefusal::Repeated),
            (other, TallyEvent::Scope, TallyRefusal::Conflict),
        ]
    );
    assert_eq!(unit1(&stage).holds, only(HoldReason::TallyScopeRefused));
}

#[test]
fn a_scope_of_no_unit_of_the_genesis_is_refused() {
    let mut book = Book::new(world());
    box1(&mut book);
    let other = book.q(scope(scope_body(&spec(STYLE1, RU2, &[]))));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [(other, TallyEvent::Scope, TallyRefusal::Subject)]
    );
    // Held, though no unit names it.
    assert_eq!(stage.holds(), only(HoldReason::TallyScopeRefused));
    assert_eq!(unit1(&stage).holds, HoldSet::empty());
}

/// The late batch close naming the batch `batch_event` (PROTOCOL.md
/// §7.2.1), signed by the clerks and observers.
fn late_batch_close(batch_event: &'static [u8], bucket: u64) -> &'static [u8] {
    let b: BatchAttest<'static> =
        ityv_encoding::decode_object(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, batch_event).unwrap();
    let body = LateBatchCloseBody::new(&LateBatchCloseParts {
        election_id: common::election(),
        box_id: BoxId::new(b"BOX-1").unwrap(),
        batch_body_hash: object_hash(b.body_bytes()),
        reason: LateBatchReason::DeviceRestart,
        time_bucket: TimeBucket::new(bucket),
    })
    .unwrap();
    witnessed(
        object(SCHEMA_LATE_BATCH_CLOSE_BODY, SCHEMA_VERSION_1, &body),
        &PEOPLE,
    )
}

#[test]
fn a_late_close_after_a_scope_of_its_style_is_refused() {
    let mut book = Book::new(world());
    let (kept, test, late, closed) = mixed(&mut book);
    let mut s = spec(STYLE1, RU1, &[kept.code]);
    s.no_record = 1;
    s.exclusions = std::vec![
        exclusion(
            test.code,
            ExclusionReason::TestBallot,
            object_hash(test.event)
        ),
        exclusion(late.code, ExclusionReason::Unattested, closed),
    ];
    // Before the scope a late batch close would still attest (within
    // the window it declares); after it, the scope has fixed UNATTESTED.
    let at = book.q(scope(scope_body(&s)));
    let late_batch = batch_at(B1, 1, 2, 3, &[test.code, late.code], CLOSE_BUCKET + 5);
    let batch_seq = book.push(SCHEMA_BATCH_ATTEST, late_batch);
    let late_close = book.w(late_batch_close(late_batch, CLOSE_BUCKET + 5));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [
            (batch_seq, TallyEvent::LateClose, TallyRefusal::AfterScope),
            (late_close, TallyEvent::LateClose, TallyRefusal::AfterScope),
        ]
    );
    let u = unit1(&stage);
    assert_eq!(u.scope.map(Seq::get), Some(at));
    assert!(u.holds.contains(HoldReason::LateCloseAfterScope));
    assert!(stage.holds().contains(HoldReason::LateCloseAfterScope));
    // The record stage took the late batch: the scope no longer agrees.
    assert!(u.holds.contains(HoldReason::TallyScopeMismatch));
    // The late batch close before the scope, its batch after it: the
    // pair is completed after the scope, and the batch's frame is refused.
    let mut book = Book::new(world());
    let (kept, test, late, closed) = mixed(&mut book);
    let late_batch = batch_at(B1, 1, 2, 3, &[test.code, late.code], CLOSE_BUCKET + 5);
    book.w(late_batch_close(late_batch, CLOSE_BUCKET + 5));
    let mut s = spec(STYLE1, RU1, &[kept.code]);
    s.no_record = 1;
    s.exclusions = std::vec![
        exclusion(
            test.code,
            ExclusionReason::TestBallot,
            object_hash(test.event)
        ),
        exclusion(late.code, ExclusionReason::Unattested, closed),
    ];
    book.q(scope(scope_body(&s)));
    let batch_after = book.push(SCHEMA_BATCH_ATTEST, late_batch);
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [(batch_after, TallyEvent::LateClose, TallyRefusal::AfterScope)]
    );
    assert!(
        unit1(&stage)
            .holds
            .contains(HoldReason::LateCloseAfterScope)
    );

    // A scope of another style does not refuse BOX-1's late closes.
    let mut book = Book::new(world());
    mixed(&mut book);
    box3(&mut book, &[1]);
    let late_batch = batch_at(B1, 1, 2, 3, &[test.code, late.code], CLOSE_BUCKET + 5);
    book.q(scope(scope_body(&spec(STYLE2, RU2, &[]))));
    book.push(SCHEMA_BATCH_ATTEST, late_batch);
    book.w(late_batch_close(late_batch, CLOSE_BUCKET + 5));
    let stage = book.run();
    assert!(
        stage
            .refused()
            .iter()
            .all(|r| r.event != TallyEvent::LateClose),
        "{:?}",
        stage.refused()
    );

    // A late box close replacing a manual close, after the scope.
    let mut book = Book::new(world());
    let casts = std::vec![cast(B1, 1, 1)];
    book.w(opened(B1));
    book.push(SCHEMA_CAST_RECORD, casts[0].event);
    book.push(SCHEMA_BATCH_ATTEST, batch(B1, 0, 1, 1, &codes(&casts)));
    book.push(
        SCHEMA_BOX_CLOSE,
        close_as(B1, (1, 1, 0), &codes(&casts), None),
    );
    book.checkpoint();
    let at = book.q(scope(scope_body(&spec(STYLE1, RU1, &codes(&casts)))));
    let late_close = book.push(
        SCHEMA_BOX_CLOSE,
        close_as(B1, (1, 1, 0), &codes(&casts), Some(b"late-box-close")),
    );
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [(late_close, TallyEvent::LateClose, TallyRefusal::AfterScope)]
    );
    assert_eq!(unit1(&stage).scope.map(Seq::get), Some(at));
}

// ---------------------------------------------------------------------
// The quorum and the capability.

#[test]
fn a_forged_or_insufficient_quorum_is_refused() {
    let mut book = Book::new(world());
    let casts = box1(&mut book);
    let body = scope_body(&spec(STYLE1, RU1, &codes(&casts)));
    // Two of J, A, C, N.
    let short = book.q(quorum(
        body,
        b"tally-scope",
        &[(b"T-A", 5), (b"T-J", 4), (b"T-P1-1", 0), (b"T-P2-1", 2)],
    ));
    // No P2 member.
    let no_party = book.q(quorum(
        body,
        b"tally-scope",
        &[(b"T-A", 5), (b"T-C", 6), (b"T-J", 4), (b"T-P1-1", 0)],
    ));
    // T-C's signature by another key.
    let forged = book.q(quorum(
        body,
        b"tally-scope",
        &[
            (b"T-A", 5),
            (b"T-C", 7),
            (b"T-J", 4),
            (b"T-P1-1", 0),
            (b"T-P2-1", 2),
        ],
    ));
    // A signer who is not a trustee.
    let stranger = book.q(quorum(
        body,
        b"tally-scope",
        &[
            (b"T-A", 5),
            (b"T-C", 6),
            (b"T-J", 4),
            (b"T-P1-1", 0),
            (b"T-P2-1", 2),
            (b"T-X", 7),
        ],
    ));
    // The opening's purpose on a scope.
    let purpose = book.q(quorum(body, b"aggregate-opening", &QUORUM));
    let taken = book.q(scope(body));
    book.checkpoint();
    let obody = opening_body(STYLE1, RU1, body, 0, sums(&casts, 0));
    let weak = book.q(quorum(
        obody,
        b"aggregate-opening",
        &[(b"T-A", 5), (b"T-P1-1", 0), (b"T-P2-1", 2)],
    ));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [
            (short, TallyEvent::Scope, TallyRefusal::Signature),
            (no_party, TallyEvent::Scope, TallyRefusal::Signature),
            (forged, TallyEvent::Scope, TallyRefusal::Signature),
            (stranger, TallyEvent::Scope, TallyRefusal::Signature),
            (purpose, TallyEvent::Scope, TallyRefusal::Signature),
            (weak, TallyEvent::Opening, TallyRefusal::Signature),
        ]
    );
    let u = unit1(&stage);
    assert_eq!(u.scope.map(Seq::get), Some(taken));
    assert!(u.openings.is_empty());
    assert_eq!(
        stage.holds(),
        HoldSet::empty()
            .with(HoldReason::TallyScopeRefused)
            .with(HoldReason::AggregateRefused)
    );
}

#[test]
fn a_tally_without_crypto_tally_aid_is_refused() {
    let mut book = Book::new(world_without_aid());
    let casts = box1(&mut book);
    let body = scope_body(&spec(STYLE1, RU1, &codes(&casts)));
    let at = book.q(scope(body));
    book.checkpoint();
    let opened_at = book.q(opening(opening_body(STYLE1, RU1, body, 0, sums(&casts, 0))));
    let receipt = book.q(resolution(B3, &[], READY));
    assert_eq!(
        refused(&book.run()),
        [
            (at, TallyEvent::Scope, TallyRefusal::Capability),
            (opened_at, TallyEvent::Opening, TallyRefusal::Capability),
            (receipt, TallyEvent::Receipt, TallyRefusal::Capability),
        ]
    );
}

// ---------------------------------------------------------------------
// The opening.

#[test]
fn an_opening_before_a_checkpoint_covers_its_scope_is_refused() {
    let mut book = Book::new(world());
    let casts = box1(&mut book);
    let body = scope_body(&spec(STYLE1, RU1, &codes(&casts)));
    // A checkpoint that does not reach the scope's frame.
    book.checkpoint();
    book.q(scope(body));
    let sums0 = sums(&casts, 0);
    let early = book.q(opening(opening_at(STYLE1, RU1, body, 0, sums0, READY + 2)));
    book.checkpoint();
    let taken_body = opening_at(STYLE1, RU1, body, 0, sums0, READY + 3);
    let taken = book.q(opening(taken_body));
    let again = book.q(quorum_seeded(
        taken_body,
        b"aggregate-opening",
        &QUORUM,
        Some(9),
    ));
    let other = book.q(opening(opening_at(STYLE1, RU1, body, 0, sums0, READY + 4)));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [
            (early, TallyEvent::Opening, TallyRefusal::Premature),
            (again, TallyEvent::Opening, TallyRefusal::Repeated),
            (other, TallyEvent::Opening, TallyRefusal::Conflict),
        ]
    );
    let u = unit1(&stage);
    assert_eq!(u.openings.len(), 1);
    assert_eq!(u.openings[0].seq.get(), taken);
    assert_eq!(u.holds, only(HoldReason::AggregateRefused));
}

#[test]
fn an_opening_must_name_the_scope_taken_and_a_chunk_of_the_style() {
    let mut book = Book::new(world());
    let casts = box1(&mut book);
    let s = spec(STYLE1, RU1, &codes(&casts));
    let body = scope_body(&s);
    let sums0 = sums(&casts, 0);
    // Before its scope (premature: no checkpoint before it can cover a
    // later frame), for a scope not taken, for chunk 1 of a one-chunk
    // style, for a unit of no box.
    let none = book.q(opening(opening_body(STYLE1, RU1, body, 0, sums0)));
    book.q(scope(body));
    book.checkpoint();
    let other = scope_body(&ScopeSpec {
        bucket: READY + 9,
        ..s
    });
    let wrong = book.q(opening(opening_body(STYLE1, RU1, other, 0, sums0)));
    let chunk = book.q(opening(opening_body(STYLE1, RU1, body, 1, sums0)));
    let unit = book.q(opening(opening_body(STYLE1, RU2, body, 0, sums0)));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [
            (none, TallyEvent::Opening, TallyRefusal::Premature),
            (wrong, TallyEvent::Opening, TallyRefusal::NoScope),
            (chunk, TallyEvent::Opening, TallyRefusal::Subject),
            (unit, TallyEvent::Opening, TallyRefusal::Subject),
        ]
    );
    assert!(unit1(&stage).openings.is_empty());
}

#[test]
fn an_opening_with_a_wrong_sum_does_not_open() {
    let one = Scalar::from_u64(1);
    let cases: [fn((Scalar, Scalar, Scalar), Scalar) -> (Scalar, Scalar, Scalar); 3] = [
        |(t, r, s), one| (t.add(&one), r, s),
        |(t, r, s), one| (t, r.add(&one), s),
        |(t, r, s), one| (t, r, s.add(&one)),
    ];
    for change in cases {
        let mut book = Book::new(world());
        let casts = box1(&mut book);
        let body = scope_body(&spec(STYLE1, RU1, &codes(&casts)));
        book.q(scope(body));
        book.checkpoint();
        book.q(opening(opening_body(
            STYLE1,
            RU1,
            body,
            0,
            change(sums(&casts, 0), one),
        )));
        book.w(paper(STYLE1, RU1, &[1, 1, 1, 0, 0], 0));
        let stage = book.run();
        assert!(stage.refused().is_empty(), "{:?}", stage.refused());
        let u = unit1(&stage);
        assert_eq!(u.openings[0].outcome, OpeningOutcome::Equation);
        assert_eq!(u.counts, None);
        assert_eq!(u.comparison, None);
        assert_eq!(u.holds, only(HoldReason::AggregateMismatch));
        assert!(u.complete());
        assert!(!u.passed());
    }
    // The sums of only two of the three records.
    let mut book = Book::new(world());
    let casts = box1(&mut book);
    let body = scope_body(&spec(STYLE1, RU1, &codes(&casts)));
    book.q(scope(body));
    book.checkpoint();
    book.q(opening(opening_body(
        STYLE1,
        RU1,
        body,
        0,
        sums(&casts[..2], 0),
    )));
    let u = unit1(&book.run());
    assert_eq!(u.openings[0].outcome, OpeningOutcome::Equation);
}

#[test]
fn every_chunk_must_open_before_the_counts() {
    // Unit 2 has two chunks: BOX-3, all three records received.
    let mut book = Book::new(world());
    let casts = box3(&mut book, &[1, 9, 10]);
    let all = codes(&casts);
    book.q(resolution(
        B3,
        &all.iter()
            .map(|c| (*c, ReceiptOutcome::Received))
            .collect::<Vec<_>>(),
        CLOSE_BUCKET + 20,
    ));
    let body = scope_body(&spec(STYLE2, RU2, &all));
    book.q(scope(body));
    book.checkpoint();
    book.q(opening(opening_body(STYLE2, RU2, body, 1, sums(&casts, 1))));
    // The unreadable mark is invalid on paper.
    book.w(paper(STYLE2, RU2, &[1, 0, 0, 0, 0, 0, 0, 0, 1], 1));
    let stage = book.run();
    let u = stage.unit(STYLE2, RU2).unwrap();
    assert!(u.scope_problems.is_empty(), "{:?}", u.scope_problems);
    assert_eq!(u.openings.len(), 1);
    assert!(!u.complete());
    assert_eq!(u.counts, None);
    assert_eq!(u.holds, HoldSet::empty());
    // Chunk 0 then: options 0..=8, then 9 and 10 in chunk 1.
    book.q(opening(opening_body(STYLE2, RU2, body, 0, sums(&casts, 0))));
    let stage = book.run();
    let u = stage.unit(STYLE2, RU2).unwrap();
    assert_eq!(u.counts, Some(std::vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1]));
    assert!(u.comparison.unwrap().agrees());
    assert!(u.passed(), "{u:?}");
}

// ---------------------------------------------------------------------
// The paper count.

#[test]
fn paper_below_the_machine_or_with_other_totals_holds_the_unit() {
    let cases: [(&[u64], u64, Option<u16>, bool); 4] = [
        // Candidate 2 below the machine's one vote; totals still equal.
        (&[2, 0, 1, 0, 0], 0, Some(2), true),
        // One invalid ballot more than the machine accounts for.
        (&[1, 1, 1, 0, 0], 1, None, false),
        // A vote for candidate 5 the machine has not.
        (&[1, 1, 1, 0, 1], 0, None, false),
        // Both.
        (&[0, 1, 1, 0, 0], 0, Some(1), false),
    ];
    for (votes, invalid, below, totals) in cases {
        let mut book = Book::new(world());
        let casts = box1(&mut book);
        let body = scope_body(&spec(STYLE1, RU1, &codes(&casts)));
        book.q(scope(body));
        book.checkpoint();
        book.q(opening(opening_body(STYLE1, RU1, body, 0, sums(&casts, 0))));
        book.w(paper(STYLE1, RU1, votes, invalid));
        let u = unit1(&book.run());
        let c = u.comparison.unwrap();
        assert_eq!(c.first_below, below, "{votes:?}");
        assert_eq!(c.totals_agree, totals, "{votes:?}");
        assert_eq!(u.holds, only(HoldReason::PaperCountMismatch));
        assert!(!u.passed());
    }
}

#[test]
fn a_paper_count_follows_the_amended_commission_and_takes_an_earlier_key() {
    let (world, amendment) = amended_world();
    let mut book = Book::new(world);
    let casts = box1(&mut book);
    book.push(SCHEMA_SIGNED_GENESIS, amendment);
    book.checkpoint();
    let body = scope_body(&spec(STYLE1, RU1, &codes(&casts)));
    book.q(scope(body));
    book.checkpoint();
    book.q(opening(opening_body(STYLE1, RU1, body, 0, sums(&casts, 0))));
    // obs-a signs under the key of the genesis, which the amendment
    // replaced; the chair of NEC-D no longer reports RU-1.
    let old_obs_a = (
        &b"obs-a"[..],
        EventRole::Observer,
        &b"PARTY-A"[..],
        ROSTER_BASE + 2,
    );
    let former = book.w(paper_by(
        STYLE1,
        RU1,
        &[1, 1, 1, 0, 0],
        0,
        &[PAPER_SIGNERS[0], old_obs_a, PAPER_SIGNERS[2]],
    ));
    let taken = book.w(paper_by(
        STYLE1,
        RU1,
        &[1, 1, 1, 0, 0],
        0,
        &[
            (b"chair-x", EventRole::Chair, b"NEC-X", ROSTER_BASE + 31),
            old_obs_a,
            PAPER_SIGNERS[2],
        ],
    ));
    // A key no state gave obs-a.
    let stranger = book.w(paper_by(
        STYLE1,
        RU1,
        &[1, 1, 1, 0, 0],
        1,
        &[
            (b"chair-x", EventRole::Chair, b"NEC-X", ROSTER_BASE + 31),
            (b"obs-a", EventRole::Observer, b"PARTY-A", ROSTER_BASE + 41),
            PAPER_SIGNERS[2],
        ],
    ));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [
            (former, TallyEvent::Paper, TallyRefusal::Signature),
            (stranger, TallyEvent::Paper, TallyRefusal::Signature),
        ]
    );
    let u = unit1(&stage);
    assert_eq!(u.paper.map(Seq::get), Some(taken));
    assert!(u.comparison.unwrap().agrees());
}

#[test]
fn a_paper_count_must_be_signed_by_the_chair_and_name_the_style() {
    let mut book = Book::new(world());
    let casts = box1(&mut book);
    let body = scope_body(&spec(STYLE1, RU1, &codes(&casts)));
    book.q(scope(body));
    book.checkpoint();
    book.q(opening(opening_body(STYLE1, RU1, body, 0, sums(&casts, 0))));
    // The chair's signature by an observer's key; a clerk for the chair
    // (the envelope admits only the chair and observers, so the clerk
    // signs in the chair role); the chair of a commission the unit does
    // not name, filing first; four candidates; a unit of no box; a second,
    // different report after the one taken (a conflict).
    let forged = book.w(paper_by(
        STYLE1,
        RU1,
        &[1, 1, 1, 0, 0],
        0,
        &[
            (b"chair", EventRole::Chair, b"NEC-D", ROSTER_BASE + 2),
            PAPER_SIGNERS[1],
            PAPER_SIGNERS[2],
        ],
    ));
    let clerk = book.w(paper_by(
        STYLE1,
        RU1,
        &[1, 1, 1, 0, 0],
        0,
        &[
            (b"clerk-1", EventRole::Chair, b"ORG-ST", ROSTER_BASE),
            PAPER_SIGNERS[1],
            PAPER_SIGNERS[2],
        ],
    ));
    let elsewhere = book.w(paper_by(
        STYLE1,
        RU1,
        &[1, 1, 1, 0, 0],
        0,
        &[
            (b"chair-x", EventRole::Chair, b"NEC-X", ROSTER_BASE + 31),
            PAPER_SIGNERS[1],
            PAPER_SIGNERS[2],
        ],
    ));
    let short = book.w(paper(STYLE1, RU1, &[1, 1, 1, 0], 0));
    let nowhere = book.w(paper(STYLE1, RU2, &[1, 1, 1, 0, 0], 0));
    let taken_event = paper(STYLE1, RU1, &[1, 1, 1, 0, 0], 0);
    let taken = book.w(taken_event);
    let taken_body = ityv_encoding::decode_object::<WitnessedEvent<'_>>(
        SCHEMA_WITNESSED_EVENT,
        ityv_encoding::SCHEMA_VERSION_WITNESSED,
        taken_event,
    )
    .unwrap()
    .body_bytes();
    let resigned = book.w(witnessed_seeded(taken_body, &PAPER_SIGNERS, Some(9)));
    let again = book.w(paper(STYLE1, RU1, &[1, 1, 1, 0, 0], 1));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [
            (forged, TallyEvent::Paper, TallyRefusal::Signature),
            (clerk, TallyEvent::Paper, TallyRefusal::Signature),
            (elsewhere, TallyEvent::Paper, TallyRefusal::Signature),
            (short, TallyEvent::Paper, TallyRefusal::Subject),
            (nowhere, TallyEvent::Paper, TallyRefusal::Subject),
            (resigned, TallyEvent::Paper, TallyRefusal::Repeated),
            (again, TallyEvent::Paper, TallyRefusal::Conflict),
        ]
    );
    let u = unit1(&stage);
    assert_eq!(u.paper.map(Seq::get), Some(taken));
    assert!(u.comparison.unwrap().agrees());
    assert_eq!(u.holds, only(HoldReason::PaperCountRefused));
}

// ---------------------------------------------------------------------
// Out-of-district records: receipts and the law.

/// BOX-3 opened with one record per option of `options`, all attested,
/// closed.
fn box3(book: &mut Book, options: &[u16]) -> Vec<Cast> {
    let casts: Vec<Cast> = options
        .iter()
        .enumerate()
        .map(|(i, o)| cast(B3, i as u64 + 1, *o))
        .collect();
    book.w(opened(B3));
    for c in &casts {
        book.push(SCHEMA_CAST_RECORD, c.event);
    }
    let all = codes(&casts);
    let n = all.len() as u64;
    book.push(SCHEMA_BATCH_ATTEST, batch(B3, 0, 1, n, &all));
    book.push(SCHEMA_BOX_CLOSE, close(B3, n, n, 0, &all));
    book.checkpoint();
    casts
}

#[test]
fn a_legal_exclude_decision_applies_to_a_damaged_record() {
    let mut book = Book::new(world());
    // Received (option 1), damaged (option 9), not received (option 10).
    let casts = box3(&mut book, &[1, 9, 10]);
    let (received, damaged, lost) = (casts[0], casts[1], casts[2]);
    let receipt = resolution(
        B3,
        &[
            (received.code, ReceiptOutcome::Received),
            (damaged.code, ReceiptOutcome::Damaged),
            (lost.code, ReceiptOutcome::NotReceived),
        ],
        CLOSE_BUCKET + 20,
    );
    book.q(receipt);
    let (filed, filed_event) = filing(DisputeType::Postal, B3, damaged.code, 1);
    book.w(filed_event);
    book.disputes.push(filed);
    let mut s = spec(STYLE2, RU2, &[received.code]);
    // Before the decision, the scope waits for the law (VC-099).
    let early = book.q(scope(scope_body(&s)));
    let decided = decision(filed, TallyEffect::Exclude);
    book.w(decided);
    s.exclusions = std::vec![
        exclusion(
            damaged.code,
            ExclusionReason::LegalExcluded,
            object_hash(decided)
        ),
        exclusion(
            lost.code,
            ExclusionReason::CastNotReceived,
            object_hash(receipt)
        ),
    ];
    s.bucket = READY + 4;
    let body = scope_body(&s);
    book.q(scope(body));
    book.checkpoint();
    for j in 0..2 {
        book.q(opening(opening_body(
            STYLE2,
            RU2,
            body,
            j,
            sums(&[received], j),
        )));
    }
    book.w(paper(STYLE2, RU2, &[1, 0, 0, 0, 0, 0, 0, 0, 0], 0));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [(early, TallyEvent::Scope, TallyRefusal::Premature)]
    );
    let u = stage.unit(STYLE2, RU2).unwrap();
    assert!(u.scope_problems.is_empty(), "{:?}", u.scope_problems);
    assert_eq!(u.included, [received.code]);
    assert_eq!(u.counts, Some(std::vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    // Neither excluded ballot is counted on paper.
    assert_eq!(u.excluded_with_paper, 0);
    assert!(u.comparison.unwrap().agrees());
    assert!(u.complete());
    // The premature scope holds the unit.
    assert_eq!(u.holds, only(HoldReason::TallyScopeRefused));
    assert_eq!(stage.holds(), only(HoldReason::TallyScopeRefused));
}

#[test]
fn a_legal_include_decision_counts_the_record() {
    let mut book = Book::new(world());
    let casts = box3(&mut book, &[1, 9]);
    let (received, wrong) = (casts[0], casts[1]);
    book.q(resolution(
        B3,
        &[
            (received.code, ReceiptOutcome::Received),
            (wrong.code, ReceiptOutcome::WrongDistrict),
        ],
        CLOSE_BUCKET + 20,
    ));
    let (filed, filed_event) = filing(DisputeType::Postal, B3, wrong.code, 1);
    book.w(filed_event);
    book.disputes.push(filed);
    book.w(decision(filed, TallyEffect::Include));
    let body = scope_body(&spec(STYLE2, RU2, &[received.code, wrong.code]));
    book.q(scope(body));
    book.checkpoint();
    for j in 0..2 {
        book.q(opening(opening_body(STYLE2, RU2, body, j, sums(&casts, j))));
    }
    book.w(paper(STYLE2, RU2, &[1, 0, 0, 0, 0, 0, 0, 0, 1], 0));
    let stage = book.run();
    assert!(stage.refused().is_empty(), "{:?}", stage.refused());
    let u = stage.unit(STYLE2, RU2).unwrap();
    assert!(u.passed(), "{u:?}");
    assert_eq!(u.counts.as_ref().unwrap()[9], 1);
}

#[test]
fn a_record_the_law_includes_but_no_batch_attests_is_counted_on_paper() {
    // Received and attested (option 1); damaged, included by the law, but
    // in no batch (option 2): UNATTESTED in the scope, its ballot on paper.
    let mut book = Book::new(world());
    let received = cast(B3, 1, 1);
    let damaged = cast(B3, 2, 2);
    book.w(opened(B3));
    book.push(SCHEMA_CAST_RECORD, received.event);
    book.push(SCHEMA_CAST_RECORD, damaged.event);
    book.push(SCHEMA_BATCH_ATTEST, batch(B3, 0, 1, 1, &[received.code]));
    let closed = close(B3, 2, 1, 0, &[received.code, damaged.code]);
    book.push(SCHEMA_BOX_CLOSE, closed);
    book.checkpoint();
    book.q(resolution(
        B3,
        &[
            (received.code, ReceiptOutcome::Received),
            (damaged.code, ReceiptOutcome::Damaged),
        ],
        CLOSE_BUCKET + 20,
    ));
    let (filed, filed_event) = filing(DisputeType::Postal, B3, damaged.code, 1);
    book.w(filed_event);
    book.disputes.push(filed);
    book.w(decision(filed, TallyEffect::Include));
    let mut s = spec(STYLE2, RU2, &[received.code]);
    s.exclusions = std::vec![exclusion(
        damaged.code,
        ExclusionReason::Unattested,
        object_hash(closed)
    )];
    let body = scope_body(&s);
    book.q(scope(body));
    book.checkpoint();
    for j in 0..2 {
        book.q(opening(opening_body(
            STYLE2,
            RU2,
            body,
            j,
            sums(&[received], j),
        )));
    }
    book.w(paper(STYLE2, RU2, &[1, 1, 0, 0, 0, 0, 0, 0, 0], 0));
    let stage = book.run();
    let u = stage.unit(STYLE2, RU2).unwrap();
    assert!(u.scope_problems.is_empty(), "{:?}", u.scope_problems);
    assert_eq!(u.excluded_with_paper, 1);
    assert!(u.comparison.unwrap().agrees(), "{:?}", u.comparison);
    assert_eq!(u.holds, HoldSet::empty());
}

#[test]
fn a_scope_waits_for_the_receipts_and_a_late_one_is_excluded() {
    let mut book = Book::new(world());
    let casts = box3(&mut book, &[1, 2]);
    let (on_time, late) = (casts[0], casts[1]);
    let mut s = spec(STYLE2, RU2, &[on_time.code]);
    let early = book.q(scope(scope_body(&s)));
    let receipt = resolution(
        B3,
        &[
            (on_time.code, ReceiptOutcome::Received),
            (late.code, ReceiptOutcome::Late),
        ],
        READY,
    );
    book.q(receipt);
    s.exclusions = std::vec![exclusion(
        late.code,
        ExclusionReason::ReceivedLate,
        object_hash(receipt)
    )];
    s.bucket = READY + 1;
    book.q(scope(scope_body(&s)));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [(early, TallyEvent::Scope, TallyRefusal::Premature)]
    );
    let u = stage.unit(STYLE2, RU2).unwrap();
    assert!(u.scope.is_some());
    assert!(u.scope_problems.is_empty(), "{:?}", u.scope_problems);
}

#[test]
fn a_receipt_resolution_must_resolve_exactly_a_closed_out_of_district_box() {
    let mut book = Book::new(world());
    book.w(opened(B3));
    let c1 = cast(B3, 1, 1);
    let c2 = cast(B3, 2, 2);
    book.push(SCHEMA_CAST_RECORD, c1.event);
    book.push(SCHEMA_CAST_RECORD, c2.event);
    let both = [
        (c1.code, ReceiptOutcome::Received),
        (c2.code, ReceiptOutcome::Received),
    ];
    // Before the close.
    let open = book.q(resolution(B3, &both, CLOSE_BUCKET));
    book.push(SCHEMA_BATCH_ATTEST, batch(B3, 0, 1, 2, &[c1.code, c2.code]));
    book.push(SCHEMA_BOX_CLOSE, close(B3, 2, 2, 0, &[c1.code, c2.code]));
    book.w(opened(B1));
    // An in-person box; one record missing; a record of no box.
    let in_person = book.q(resolution(B1, &[], READY));
    let missing = book.q(resolution(B3, &both[..1], READY));
    let extra = book.q(resolution(
        B3,
        &[
            both[0],
            both[1],
            (Hash512([0x99; 64]), ReceiptOutcome::Late),
        ],
        READY,
    ));
    let taken_event = resolution(B3, &both, READY);
    let taken = book.q(taken_event);
    let taken_body = ityv_encoding::decode_object::<QuorumSigned<'_>>(
        SCHEMA_QUORUM_SIGNED,
        ityv_encoding::SCHEMA_VERSION_QUORUM_SIGNED,
        taken_event,
    )
    .unwrap()
    .body_bytes();
    let same = book.q(quorum_seeded(
        taken_body,
        b"receipt-resolution",
        &QUORUM,
        Some(9),
    ));
    let again = book.q(resolution(B3, &both, READY + 1));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [
            (open, TallyEvent::Receipt, TallyRefusal::Premature),
            (in_person, TallyEvent::Receipt, TallyRefusal::Subject),
            (missing, TallyEvent::Receipt, TallyRefusal::Entries),
            (extra, TallyEvent::Receipt, TallyRefusal::Entries),
            (same, TallyEvent::Receipt, TallyRefusal::Repeated),
            (again, TallyEvent::Receipt, TallyRefusal::Conflict),
        ]
    );
    assert!(taken > extra);
    assert_eq!(stage.holds(), only(HoldReason::ReceiptResolutionRefused));
    // A forged quorum.
    let mut book = Book::new(world());
    book.w(opened(B3));
    book.push(SCHEMA_CAST_RECORD, c1.event);
    book.push(SCHEMA_BATCH_ATTEST, batch(B3, 0, 1, 1, &[c1.code]));
    book.push(SCHEMA_BOX_CLOSE, close(B3, 1, 1, 0, &[c1.code]));
    let body = ityv_encoding::decode_object::<QuorumSigned<'_>>(
        SCHEMA_QUORUM_SIGNED,
        ityv_encoding::SCHEMA_VERSION_QUORUM_SIGNED,
        resolution(B3, &both[..1], READY),
    )
    .unwrap()
    .body_bytes();
    let forged = book.q(quorum(
        body,
        b"receipt-resolution",
        &[(b"T-A", 5), (b"T-J", 4), (b"T-P1-1", 0), (b"T-P2-1", 2)],
    ));
    assert_eq!(
        refused(&book.run()),
        [(forged, TallyEvent::Receipt, TallyRefusal::Signature)]
    );
}

#[test]
fn a_tally_effect_that_cannot_apply_is_refused() {
    let mut book = Book::new(world());
    let casts = box3(&mut book, &[1, 2]);
    let (received, damaged) = (casts[0], casts[1]);
    // A decision on a damaged record before the resolution that finds it
    // damaged.
    let (early_filed, early_event) = filing(DisputeType::Postal, B3, damaged.code, 1);
    book.w(early_event);
    let before = book.w(decision(early_filed, TallyEffect::Exclude));
    book.q(resolution(
        B3,
        &[
            (received.code, ReceiptOutcome::Received),
            (damaged.code, ReceiptOutcome::Damaged),
        ],
        CLOSE_BUCKET + 20,
    ));
    // A decision on a record received normally; on a custody dispute; on a
    // record of no box; the first that applies; a second on the same
    // record.
    let (normal, normal_event) = filing(DisputeType::Postal, B3, received.code, 2);
    book.w(normal_event);
    let on_received = book.w(decision(normal, TallyEffect::Exclude));
    let (custody, custody_event) = filing(DisputeType::Custody, B3, damaged.code, 3);
    book.w(custody_event);
    let on_custody = book.w(decision(custody, TallyEffect::Exclude));
    let (stray, stray_event) = filing(DisputeType::Postal, B3, Hash512([0x42; 64]), 4);
    book.w(stray_event);
    let on_stray = book.w(decision(stray, TallyEffect::Include));
    let (filed, filed_event) = filing(DisputeType::Postal, B3, damaged.code, 5);
    book.w(filed_event);
    // A decision without effect changes nothing and is not refused.
    book.w(decision(filed, TallyEffect::NoEffect));
    book.w(decision(filed, TallyEffect::Include));
    let second = book.w(decision(filed, TallyEffect::Exclude));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [
            (before, TallyEvent::Decision, TallyRefusal::Effect),
            (on_received, TallyEvent::Decision, TallyRefusal::Effect),
            (on_custody, TallyEvent::Decision, TallyRefusal::Effect),
            (on_stray, TallyEvent::Decision, TallyRefusal::Effect),
            (second, TallyEvent::Decision, TallyRefusal::Effect),
        ]
    );
    assert_eq!(stage.holds(), only(HoldReason::TallyEffectRefused));
    // The include applied: both records are in the recomputed scope.
    let u = stage.unit(STYLE2, RU2).unwrap();
    assert_eq!(u.included, sorted(&[received.code, damaged.code]));
    assert!(u.exclusions.is_empty());
}

#[test]
fn a_clean_election_reaches_crypto_tally_verified() {
    let world = election_world();
    let mut book = Book::new(world);
    for chamber in [ChamberCode::P1, ChamberCode::P2] {
        book.push(SCHEMA_PARTY_KEY_CEREMONY, ceremony(chamber));
    }
    for m in ELECTION_MODULES {
        book.push(SCHEMA_MODULE_PROVISIONED, provisioning(m));
    }
    let casts = box1(&mut book);
    for (schema, event) in station_record(3) {
        book.push(schema, event);
    }
    book.push(SCHEMA_PARTICIPATION_SET, participation(3));
    tally1(
        &mut book,
        &casts,
        &spec(STYLE1, RU1, &codes(&casts)),
        &[1, 1, 1, 0, 0],
        0,
    );
    book.checkpoint();
    let anchored = Publications {
        anchors: Publication::Satisfied,
        board: Publication::Pending,
    };
    let report = verify_ledger(
        world.genesis,
        book.ledger.bytes(),
        &book.ledger.events,
        anchored,
    );
    assert!(report.participation().complete());
    assert!(report.tally().complete());
    assert!(report.tally().passed(), "{:?}", report.tally());
    assert_eq!(report.tally().holds(), HoldSet::empty());
    assert_eq!(
        report.status().holds(),
        HoldSet::empty(),
        "{:?}",
        report.status()
    );
    assert_eq!(report.status().status(), Status::CryptoTallyVerified);

    // A refused event that names no unit holds the ledger though the unit
    // passed.
    let unit_passed = |r: &ityv_verify::Report<'_>| r.tally().unit(STYLE1, RU1).unwrap().passed();
    book.q(scope(scope_body(&spec(STYLE1, RU2, &[]))));
    book.checkpoint();
    let report = verify_ledger(
        world.genesis,
        book.ledger.bytes(),
        &book.ledger.events,
        anchored,
    );
    assert!(unit_passed(&report));
    assert!(report.tally().complete());
    assert!(!report.tally().passed());
    assert_eq!(report.status().status(), Status::HoldReview);
    assert!(
        report
            .status()
            .holds()
            .contains(HoldReason::TallyScopeRefused)
    );

    // Without the paper count the tally step is not run.
    let mut book = Book::new(world);
    for chamber in [ChamberCode::P1, ChamberCode::P2] {
        book.push(SCHEMA_PARTY_KEY_CEREMONY, ceremony(chamber));
    }
    for m in ELECTION_MODULES {
        book.push(SCHEMA_MODULE_PROVISIONED, provisioning(m));
    }
    let casts = box1(&mut book);
    for (schema, event) in station_record(3) {
        book.push(schema, event);
    }
    book.push(SCHEMA_PARTICIPATION_SET, participation(3));
    let body = scope_body(&spec(STYLE1, RU1, &codes(&casts)));
    book.q(scope(body));
    book.checkpoint();
    book.q(opening(opening_body(STYLE1, RU1, body, 0, sums(&casts, 0))));
    book.checkpoint();
    let report = verify_ledger(
        world.genesis,
        book.ledger.bytes(),
        &book.ledger.events,
        anchored,
    );
    assert!(!report.tally().complete());
    assert_eq!(report.status().status(), Status::SourceCompletenessChecked);

    // A paper count that does not agree holds the ledger.
    book.w(paper(STYLE1, RU1, &[1, 1, 1, 0, 0], 1));
    book.checkpoint();
    let report = verify_ledger(
        world.genesis,
        book.ledger.bytes(),
        &book.ledger.events,
        anchored,
    );
    assert_eq!(report.status().status(), Status::HoldReview);
    assert!(
        report
            .status()
            .holds()
            .contains(HoldReason::PaperCountMismatch)
    );
}

/// The whole two-unit ledger, with unit RU-2's opening and paper count
/// when asked.
fn two_unit_ledger(opening2: bool, paper2: bool) -> Report<'static> {
    let world = two_unit_world();
    let mut book = Book::new(world);
    for chamber in [ChamberCode::P1, ChamberCode::P2] {
        book.push(SCHEMA_PARTY_KEY_CEREMONY, ceremony(chamber));
    }
    for m in TWO_UNIT_MODULES {
        book.push(SCHEMA_MODULE_PROVISIONED, provisioning(m));
    }
    let casts1 = box1_closed(&mut book);
    let casts2 = std::vec![cast(B2, 1, 1), cast(B2, 2, 4)];
    book.w(opened(B2));
    for c in &casts2 {
        book.push(SCHEMA_CAST_RECORD, c.event);
    }
    book.push(SCHEMA_BATCH_ATTEST, batch(B2, 0, 1, 2, &codes(&casts2)));
    book.push(SCHEMA_BOX_CLOSE, close(B2, 2, 2, 0, &codes(&casts2)));
    for (schema, event) in station_record_of(&[(B1, 3), (B2, 2)]) {
        book.push(schema, event);
    }
    book.push(SCHEMA_PARTICIPATION_SET, participation(5));
    book.checkpoint();
    tally1(
        &mut book,
        &casts1,
        &spec(STYLE1, RU1, &codes(&casts1)),
        &[1, 1, 1, 0, 0],
        0,
    );
    let body = scope_body(&spec(STYLE1, RU2, &codes(&casts2)));
    book.q(scope(body));
    book.checkpoint();
    if opening2 {
        book.q(opening(opening_body(
            STYLE1,
            RU2,
            body,
            0,
            sums(&casts2, 0),
        )));
    }
    if paper2 {
        book.w(paper(STYLE1, RU2, &[1, 0, 0, 1, 0], 0));
    }
    book.checkpoint();
    verify_ledger(
        world.genesis,
        book.ledger.bytes(),
        &book.ledger.events,
        Publications {
            anchors: Publication::Satisfied,
            board: Publication::Pending,
        },
    )
}

#[test]
fn every_unit_must_be_tallied_for_crypto_tally_verified() {
    let report = two_unit_ledger(true, true);
    assert_eq!(report.tally().units().len(), 2);
    assert!(report.tally().passed(), "{:?}", report.tally());
    assert_eq!(
        report.status().holds(),
        HoldSet::empty(),
        "{:?}",
        report.status()
    );
    assert_eq!(report.status().status(), Status::CryptoTallyVerified);
    // RU-2 without its opening, or without its paper count: RU-1 alone
    // passing is not enough, and nothing is held.
    for (opening2, paper2) in [(false, true), (true, false)] {
        let report = two_unit_ledger(opening2, paper2);
        assert!(report.tally().unit(STYLE1, RU1).unwrap().passed());
        assert!(!report.tally().unit(STYLE1, RU2).unwrap().complete());
        assert!(!report.tally().passed());
        assert_eq!(report.status().holds(), HoldSet::empty());
        assert_eq!(report.status().status(), Status::SourceCompletenessChecked);
    }
}
