//! The tally (ENCODING.md §8.61–§8.65): `TallyScopeBody` (0x0043),
//! `AggregateOpeningBody` (0x0044), `ReceiptResolutionBody` (0x0047), the
//! trustee-quorum envelope `QuorumSigned` (0x0045) and
//! `PaperCountReportBody` (0x0046) in a `WitnessedEvent`. Round trips, the constructors' rules (the same as the
//! decoders'), the signer roles of a paper count report, and the bounds the
//! golden vectors in `vectors.rs` do not reach. Signatures are patterned
//! bytes.
// Integration-test crate: outside the TCB. Test code expresses "this must
// hold" with unwrap/expect/panic/indexing and does small arithmetic on test
// sizes, so those restriction lints are relaxed for this file only
// (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]

mod common;

use common::encode_to_vec;
use ityv_encoding::{
    AggregateOpeningBody, AggregateOpeningParts, BallotStyleId, BoxId, Decode, EXCLUSION_LEN,
    ElectionId, Encode, ErrorKind, EventRole, EventSig, ExclusionEntry, ExclusionReason,
    Exclusions, HEADER_LEN, HYBRID_SIG_LEN, Hash512, MAX_CANDIDATES, MAX_EXCLUSIONS,
    MAX_QUORUM_BODY_LEN, MAX_QUORUM_SIGS, MAX_RECEIPT_ENTRIES, MAX_TALLY_COUNT, OrgId,
    PURPOSE_AGGREGATE_OPENING, PURPOSE_PAPER_COUNT, PURPOSE_RECEIPT_RESOLUTION,
    PURPOSE_TALLY_SCOPE, PaperCountParts, PaperCountReportBody, PaperVotes, QuorumKind, QuorumSig,
    QuorumSigned, RECEIPT_ENTRY_LEN, Reader, ReceiptEntries, ReceiptEntry, ReceiptOutcome,
    ReceiptResolutionBody, ReceiptResolutionParts, ReportingUnitId, SCHEMA_AGGREGATE_OPENING_BODY,
    SCHEMA_PAPER_COUNT_REPORT_BODY, SCHEMA_QUORUM_SIGNED, SCHEMA_RECEIPT_RESOLUTION_BODY,
    SCHEMA_TALLY_SCOPE_BODY, SCHEMA_VERSION_1, SCHEMA_WITNESSED_EVENT, Scalar32, SchemaId,
    SignerId, TallyScopeBody, TallyScopeParts, TimeBucket, TrusteeId, WITNESSED_BODY_SCHEMAS,
    WitnessedEvent, Writer, decode_object, purpose_of, roles_satisfied,
};
use ityv_encoding::{MAX_QUORUM_MESSAGE_LEN, write_quorum_message};
use proptest::prelude::*;
use std::vec::Vec;

static SIG_A: [u8; HYBRID_SIG_LEN] = [0xA1; HYBRID_SIG_LEN];
static SIG_B: [u8; HYBRID_SIG_LEN] = [0xB2; HYBRID_SIG_LEN];
static SIG_C: [u8; HYBRID_SIG_LEN] = [0xC3; HYBRID_SIG_LEN];

/// The largest identifier: 64 bytes.
const LONG: &[u8; 64] = b"0123456789012345678901234567890123456789012345678901234567890123";

fn e() -> ElectionId<'static> {
    ElectionId::new(b"KR-2030-PRES").unwrap()
}

fn style() -> BallotStyleId<'static> {
    BallotStyleId::new(b"S-11-0001").unwrap()
}

fn unit() -> ReportingUnitId<'static> {
    ReportingUnitId::new(b"RU-11-01").unwrap()
}

fn leak(v: Vec<u8>) -> &'static [u8] {
    Vec::leak(v)
}

fn entry(fill: u8, reason: ExclusionReason) -> ExclusionEntry {
    ExclusionEntry {
        record_hash: Hash512([fill; 64]),
        reason,
        basis: Hash512([fill.wrapping_add(1); 64]),
    }
}

fn entries(list: &[ExclusionEntry]) -> &'static [u8] {
    let mut out = std::vec![0u8; list.len() * EXCLUSION_LEN];
    let mut w = Writer::new(&mut out);
    for e in list {
        e.encode(&mut w).unwrap();
    }
    assert_eq!(w.finish(), out.len());
    leak(out)
}

fn scope_parts(exclusions: Exclusions<'static>) -> TallyScopeParts<'static> {
    TallyScopeParts {
        election_id: e(),
        ballot_style_id: style(),
        reporting_unit_id: unit(),
        included_count: 3,
        included_root: Hash512([0x30; 64]),
        no_record_count: 2,
        exclusions,
        time_bucket: TimeBucket::new(2_000),
    }
}

fn opening_parts(chunk: u8) -> AggregateOpeningParts<'static> {
    AggregateOpeningParts {
        election_id: e(),
        ballot_style_id: style(),
        reporting_unit_id: unit(),
        scope_hash: Hash512([0x50; 64]),
        chunk,
        packed_sum: Scalar32([1; 32]),
        rand_sum: Scalar32([2; 32]),
        id_sum: Scalar32([3; 32]),
        time_bucket: TimeBucket::new(2_100),
    }
}

fn paper_parts(votes: &[u64]) -> PaperCountParts<'static> {
    PaperCountParts {
        election_id: e(),
        reporting_unit_id: unit(),
        ballot_style_id: style(),
        votes: PaperVotes::new(votes).unwrap(),
        invalid: 4,
        time_bucket: TimeBucket::new(2_200),
    }
}

fn kind_of<'a, T: Decode<'a> + core::fmt::Debug>(
    schema: SchemaId,
    bytes: &'a [u8],
) -> (ErrorKind, usize) {
    let err = decode_object::<T>(schema, ityv_encoding::schema_version(schema), bytes).unwrap_err();
    (err.kind(), err.offset())
}

fn sig(id: &'static [u8], s: &'static [u8; HYBRID_SIG_LEN]) -> QuorumSig<'static> {
    QuorumSig {
        trustee_id: TrusteeId::new(id).unwrap(),
        sig: s,
    }
}

#[test]
fn purposes_and_reason_codes() {
    assert_eq!(PURPOSE_TALLY_SCOPE, b"tally-scope");
    assert_eq!(PURPOSE_AGGREGATE_OPENING, b"aggregate-opening");
    assert_eq!(PURPOSE_PAPER_COUNT, b"paper-count");
    assert_eq!(QuorumKind::TallyScope.purpose(), PURPOSE_TALLY_SCOPE);
    assert_eq!(
        QuorumKind::AggregateOpening.purpose(),
        PURPOSE_AGGREGATE_OPENING
    );
    assert_eq!(MAX_TALLY_COUNT, (1 << 26) - 1);
    let names = [
        "TEST_BALLOT",
        "CHALLENGED_SPOILED",
        "QUARANTINED",
        "CAST_NOT_RECEIVED",
        "RECEIVED_LATE",
        "LEGAL_EXCLUDED",
        "SHARE_MISSING",
        "UNATTESTED",
    ];
    for (i, reason) in ExclusionReason::ALL.iter().enumerate() {
        let code = u8::try_from(i + 1).unwrap();
        assert_eq!(reason.code(), code);
        assert_eq!(ExclusionReason::from_code(code), Some(*reason));
        assert_eq!(reason.name(), names[i]);
    }
    for code in [0u8, 9, 255] {
        assert_eq!(ExclusionReason::from_code(code), None);
    }
    // The codes follow PROTOCOL.md §11.1, so the first reason is the least.
    assert!(ExclusionReason::TestBallot < ExclusionReason::Unattested);
}

#[test]
fn exclusions_are_whole_canonical_and_ascending() {
    assert!(Exclusions::EMPTY.is_empty());
    assert_eq!(Exclusions::EMPTY.len(), 0);
    assert_eq!(Exclusions::new(&[]), Some(Exclusions::EMPTY));
    let list = [
        entry(0x10, ExclusionReason::TestBallot),
        entry(0x20, ExclusionReason::Unattested),
    ];
    let bytes = entries(&list);
    let ex = Exclusions::new(bytes).unwrap();
    assert_eq!(ex.len(), 2);
    assert!(!ex.is_empty());
    assert_eq!(ex.as_bytes(), bytes);
    assert_eq!(ex.iter().collect::<Vec<_>>(), list);
    // A partial entry, the wrong order, a repeat, a bad reason, no basis.
    assert_eq!(Exclusions::new(&bytes[..=EXCLUSION_LEN]), None);
    assert_eq!(Exclusions::new(entries(&[list[1], list[0]])), None);
    assert_eq!(Exclusions::new(entries(&[list[0], list[0]])), None);
    let mut bad = bytes.to_vec();
    bad[64] = 9;
    assert_eq!(Exclusions::new(leak(bad)), None);
    let mut none = bytes.to_vec();
    none[65..129].fill(0);
    assert_eq!(Exclusions::new(leak(none)), None);
    // Each entry alone round-trips.
    let mut buf = [0u8; EXCLUSION_LEN];
    list[0].encode(&mut Writer::new(&mut buf)).unwrap();
    assert_eq!(list[0].encoded_len(), EXCLUSION_LEN);
    let mut r = Reader::new(&buf);
    assert_eq!(ExclusionEntry::decode(&mut r).unwrap(), list[0]);
    r.finish().unwrap();
}

#[test]
fn tally_scope_round_trips_and_bounds_its_counts() {
    let ex = Exclusions::new(entries(&[
        entry(0x10, ExclusionReason::ChallengedSpoiled),
        entry(0x11, ExclusionReason::LegalExcluded),
        entry(0x40, ExclusionReason::ShareMissing),
    ]))
    .unwrap();
    let body = TallyScopeBody::new(&scope_parts(ex)).unwrap();
    let bytes = encode_to_vec(SCHEMA_TALLY_SCOPE_BODY, SCHEMA_VERSION_1, &body);
    let back: TallyScopeBody<'_> =
        decode_object(SCHEMA_TALLY_SCOPE_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(back, body);
    assert_eq!(back.parts().exclusions.len(), 3);
    assert_eq!(bytes.len(), HEADER_LEN + body.encoded_len());
    for (included, no_record) in [(MAX_TALLY_COUNT + 1, 0), (0, MAX_TALLY_COUNT + 1)] {
        let parts = TallyScopeParts {
            included_count: included,
            no_record_count: no_record,
            ..scope_parts(Exclusions::EMPTY)
        };
        let err = TallyScopeBody::new(&parts).unwrap_err();
        assert_eq!((err.kind(), err.offset()), (ErrorKind::ValueOutOfRange, 0));
    }
    let top = TallyScopeParts {
        included_count: MAX_TALLY_COUNT,
        no_record_count: MAX_TALLY_COUNT,
        ..scope_parts(Exclusions::EMPTY)
    };
    assert!(TallyScopeBody::new(&top).is_ok());
}

#[test]
fn the_largest_scope_is_the_longest_quorum_body() {
    let id = |b: &'static [u8]| {
        (
            BallotStyleId::new(b).unwrap(),
            ReportingUnitId::new(b).unwrap(),
        )
    };
    let mut all = std::vec![0u8; MAX_EXCLUSIONS * EXCLUSION_LEN];
    for (i, chunk) in all.chunks_exact_mut(EXCLUSION_LEN).enumerate() {
        chunk[..4].copy_from_slice(&u32::try_from(i).unwrap().to_be_bytes());
        chunk[64] = ExclusionReason::Unattested.code();
        chunk[65..].fill(0x77);
    }
    let all = leak(all);
    let ex = Exclusions::new(all).unwrap();
    assert_eq!(ex.len(), MAX_EXCLUSIONS);
    let (s, u) = id(LONG);
    let body = TallyScopeBody::new(&TallyScopeParts {
        election_id: ElectionId::new(LONG).unwrap(),
        ballot_style_id: s,
        reporting_unit_id: u,
        exclusions: ex,
        ..scope_parts(Exclusions::EMPTY)
    })
    .unwrap();
    let bytes = leak(encode_to_vec(
        SCHEMA_TALLY_SCOPE_BODY,
        SCHEMA_VERSION_1,
        &body,
    ));
    assert_eq!(bytes.len(), MAX_QUORUM_BODY_LEN);
    let event = QuorumSigned::new(bytes, &[sig(b"T-A", &SIG_A)]).unwrap();
    assert_eq!(event.kind(), QuorumKind::TallyScope);
    // One more exclusion does not fit.
    let mut more = all.to_vec();
    more.extend_from_slice(&all[..EXCLUSION_LEN]);
    assert_eq!(Exclusions::new(leak(more)), None);
    // A body one byte longer than the bound is refused as a body.
    let mut long = bytes.to_vec();
    long.push(0);
    let err = QuorumSigned::new(leak(long), &[sig(b"T-A", &SIG_A)]).unwrap_err();
    assert_eq!((err.kind(), err.offset()), (ErrorKind::LengthExceedsMax, 0));
}

#[test]
fn aggregate_opening_round_trips_and_checks_its_fields() {
    for chunk in [0u8, 7] {
        let body = AggregateOpeningBody::new(&opening_parts(chunk)).unwrap();
        let bytes = encode_to_vec(SCHEMA_AGGREGATE_OPENING_BODY, SCHEMA_VERSION_1, &body);
        let back: AggregateOpeningBody<'_> =
            decode_object(SCHEMA_AGGREGATE_OPENING_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        assert_eq!(back, body);
        assert_eq!(back.parts().chunk, chunk);
        assert_eq!(bytes.len(), HEADER_LEN + body.encoded_len());
    }
    let err = AggregateOpeningBody::new(&opening_parts(8)).unwrap_err();
    assert_eq!((err.kind(), err.offset()), (ErrorKind::ValueOutOfRange, 0));
    let parts = AggregateOpeningParts {
        scope_hash: Hash512::ZERO,
        ..opening_parts(0)
    };
    let err = AggregateOpeningBody::new(&parts).unwrap_err();
    assert_eq!(
        (err.kind(), err.offset()),
        (ErrorKind::InvalidPreviousHash, 0)
    );
}

fn opening_bytes() -> &'static [u8] {
    let body = AggregateOpeningBody::new(&opening_parts(1)).unwrap();
    leak(encode_to_vec(
        SCHEMA_AGGREGATE_OPENING_BODY,
        SCHEMA_VERSION_1,
        &body,
    ))
}

fn scope_bytes() -> &'static [u8] {
    let body = TallyScopeBody::new(&scope_parts(Exclusions::EMPTY)).unwrap();
    leak(encode_to_vec(
        SCHEMA_TALLY_SCOPE_BODY,
        SCHEMA_VERSION_1,
        &body,
    ))
}

fn paper_bytes(votes: &[u64]) -> &'static [u8] {
    let body = PaperCountReportBody::new(&paper_parts(votes)).unwrap();
    leak(encode_to_vec(
        SCHEMA_PAPER_COUNT_REPORT_BODY,
        SCHEMA_VERSION_1,
        &body,
    ))
}

#[test]
fn a_quorum_event_carries_either_body_with_ascending_trustees() {
    let sigs = [
        sig(b"T-A", &SIG_A),
        sig(b"T-J", &SIG_B),
        sig(b"T-P1", &SIG_C),
    ];
    for (body, kind) in [
        (scope_bytes(), QuorumKind::TallyScope),
        (opening_bytes(), QuorumKind::AggregateOpening),
        (receipt_bytes(), QuorumKind::ReceiptResolution),
    ] {
        let event = QuorumSigned::new(body, &sigs).unwrap();
        assert_eq!(event.kind(), kind);
        assert_eq!(event.purpose(), kind.purpose());
        assert_eq!(event.body_bytes(), body);
        assert_eq!(event.sig_count(), 3);
        assert_eq!(event.sigs().collect::<Vec<_>>(), sigs);
        assert_eq!(
            event.tally_scope().is_some(),
            kind == QuorumKind::TallyScope
        );
        assert_eq!(
            event.aggregate_opening().is_some(),
            kind == QuorumKind::AggregateOpening
        );
        assert_eq!(
            event.receipt_resolution().is_some(),
            kind == QuorumKind::ReceiptResolution
        );
        let bytes = encode_to_vec(SCHEMA_QUORUM_SIGNED, SCHEMA_VERSION_1, &event);
        assert_eq!(bytes.len(), HEADER_LEN + event.encoded_len());
        let back: QuorumSigned<'_> =
            decode_object(SCHEMA_QUORUM_SIGNED, SCHEMA_VERSION_1, &bytes).unwrap();
        assert_eq!(back, event);
    }
    let scope = QuorumSigned::new(scope_bytes(), &sigs).unwrap();
    assert_eq!(
        scope.tally_scope().unwrap().parts(),
        &scope_parts(Exclusions::EMPTY)
    );
    let opening = QuorumSigned::new(opening_bytes(), &sigs).unwrap();
    assert_eq!(
        opening.aggregate_opening().unwrap().parts(),
        &opening_parts(1)
    );
    // No signature, the wrong order, a repeat, too many.
    let refused = |s: &[QuorumSig<'static>]| {
        let err = QuorumSigned::new(opening_bytes(), s).unwrap_err();
        (err.kind(), err.offset())
    };
    let invariant = (ErrorKind::InvariantViolation, 0);
    assert_eq!(refused(&[]), invariant);
    assert_eq!(refused(&[sigs[1], sigs[0]]), invariant);
    assert_eq!(refused(&[sigs[0], sigs[0]]), invariant);
    let ids: Vec<&'static [u8]> = (0..=MAX_QUORUM_SIGS)
        .map(|i| leak(std::format!("T-{i:03}").into_bytes()))
        .collect();
    let many: Vec<QuorumSig<'static>> = ids.iter().map(|id| sig(id, &SIG_A)).collect();
    assert_eq!(refused(&many), invariant);
    assert!(QuorumSigned::new(opening_bytes(), &many[..MAX_QUORUM_SIGS]).is_ok());
    // A body of another schema.
    let err = QuorumSigned::new(paper_bytes(&[1]), &sigs).unwrap_err();
    assert_eq!((err.kind(), err.offset()), (ErrorKind::SchemaMismatch, 4));
    // The decoder reports a short body at its place in the envelope.
    let event = QuorumSigned::new(opening_bytes(), &sigs[..1]).unwrap();
    let mut bytes = encode_to_vec(SCHEMA_QUORUM_SIGNED, SCHEMA_VERSION_1, &event);
    let end = bytes.len();
    bytes.truncate(end - 1);
    let n = u32::try_from(bytes.len() - HEADER_LEN).unwrap();
    bytes[12..16].copy_from_slice(&n.to_be_bytes());
    assert_eq!(
        kind_of::<QuorumSigned<'_>>(SCHEMA_QUORUM_SIGNED, &bytes).0,
        ErrorKind::UnexpectedEnd
    );
}

#[test]
fn paper_votes_and_report_round_trip_and_bound_their_counts() {
    assert_eq!(PaperVotes::new(&[]), None);
    assert_eq!(PaperVotes::new(&[0; MAX_CANDIDATES + 1]), None);
    assert_eq!(PaperVotes::new(&[MAX_TALLY_COUNT + 1]), None);
    let full = PaperVotes::new(&[MAX_TALLY_COUNT; MAX_CANDIDATES]).unwrap();
    assert_eq!(full.len(), MAX_CANDIDATES);
    let votes = PaperVotes::new(&[120, 75, 3]).unwrap();
    assert_eq!(votes.as_slice(), [120, 75, 3]);
    assert_eq!(votes.len(), 3);
    assert!(!votes.is_empty());
    let body = PaperCountReportBody::new(&paper_parts(&[120, 75, 3])).unwrap();
    let bytes = encode_to_vec(SCHEMA_PAPER_COUNT_REPORT_BODY, SCHEMA_VERSION_1, &body);
    assert_eq!(bytes.len(), HEADER_LEN + body.encoded_len());
    let back: PaperCountReportBody<'_> =
        decode_object(SCHEMA_PAPER_COUNT_REPORT_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(back, body);
    assert_eq!(back.parts().votes.as_slice(), [120, 75, 3]);
    let parts = PaperCountParts {
        invalid: MAX_TALLY_COUNT + 1,
        ..paper_parts(&[1])
    };
    let err = PaperCountReportBody::new(&parts).unwrap_err();
    assert_eq!((err.kind(), err.offset()), (ErrorKind::ValueOutOfRange, 0));
    let parts = PaperCountParts {
        invalid: MAX_TALLY_COUNT,
        ..paper_parts(&[1])
    };
    assert!(PaperCountReportBody::new(&parts).is_ok());
}

fn esig(
    id: &'static [u8],
    role: EventRole,
    org: &'static [u8],
    s: &'static [u8; HYBRID_SIG_LEN],
) -> EventSig<'static> {
    EventSig {
        signer_id: SignerId::new(id).unwrap(),
        role,
        org_id: OrgId::new(org).unwrap(),
        sig: s,
    }
}

#[test]
fn a_paper_count_report_is_signed_by_the_chair_and_two_observer_orgs() {
    assert!(WITNESSED_BODY_SCHEMAS.contains(&SCHEMA_PAPER_COUNT_REPORT_BODY));
    assert_eq!(
        purpose_of(SCHEMA_PAPER_COUNT_REPORT_BODY),
        Some(PURPOSE_PAPER_COUNT)
    );
    assert_eq!(EventRole::from_code(9), Some(EventRole::Chair));
    assert_eq!(EventRole::Chair.code(), 9);
    let chair = esig(b"chair-11", EventRole::Chair, b"NEC-11", &SIG_A);
    let obs_a = esig(b"obs-a", EventRole::Observer, b"PARTY-A", &SIG_B);
    let obs_b = esig(b"obs-b", EventRole::Observer, b"PARTY-B", &SIG_C);
    let obs_a2 = esig(b"obs-c", EventRole::Observer, b"PARTY-A", &SIG_C);
    let chair2 = esig(b"chair-12", EventRole::Chair, b"NEC-12", &SIG_B);
    let clerk = esig(b"clerk-1", EventRole::Clerk, b"NEC-11", &SIG_B);
    let ok = |sigs: &[EventSig<'static>]| {
        roles_satisfied(SCHEMA_PAPER_COUNT_REPORT_BODY, || sigs.iter().copied())
    };
    assert!(ok(&[chair, obs_a, obs_b]));
    assert!(ok(&[chair, obs_a, obs_a2, obs_b]));
    assert!(!ok(&[obs_a, obs_b]), "no chair");
    assert!(!ok(&[chair, chair2, obs_a, obs_b]), "two chairs");
    assert!(!ok(&[chair, obs_a, obs_a2]), "one organisation");
    assert!(!ok(&[chair, clerk, obs_a, obs_b]), "a clerk");
    // The chair takes part in no other event.
    for schema in WITNESSED_BODY_SCHEMAS {
        if schema != SCHEMA_PAPER_COUNT_REPORT_BODY {
            assert!(!roles_satisfied(schema, || [chair, obs_a, obs_b].into_iter()));
        }
    }
    let body = paper_bytes(&[5, 2]);
    let event = WitnessedEvent::new(body, &[chair, obs_a, obs_b]).unwrap();
    assert_eq!(event.purpose(), PURPOSE_PAPER_COUNT);
    assert_eq!(event.body_schema(), SCHEMA_PAPER_COUNT_REPORT_BODY);
    let bytes = encode_to_vec(
        SCHEMA_WITNESSED_EVENT,
        ityv_encoding::SCHEMA_VERSION_WITNESSED,
        &event,
    );
    let back: WitnessedEvent<'_> = decode_object(
        SCHEMA_WITNESSED_EVENT,
        ityv_encoding::SCHEMA_VERSION_WITNESSED,
        &bytes,
    )
    .unwrap();
    assert_eq!(back, event);
    let parsed: PaperCountReportBody<'_> = back.body(SCHEMA_PAPER_COUNT_REPORT_BODY).unwrap();
    assert_eq!(parsed.parts().votes.as_slice(), [5, 2]);
    assert!(WitnessedEvent::new(body, &[obs_a, obs_b]).is_err());
}

fn receipt_entries(list: &[(u8, ReceiptOutcome)]) -> &'static [u8] {
    let mut out = std::vec![0u8; list.len() * RECEIPT_ENTRY_LEN];
    let mut w = Writer::new(&mut out);
    for (fill, outcome) in list {
        ReceiptEntry {
            record_hash: Hash512([*fill; 64]),
            outcome: *outcome,
        }
        .encode(&mut w)
        .unwrap();
    }
    assert_eq!(w.finish(), out.len());
    leak(out)
}

fn receipt_parts(entries: &'static [u8]) -> ReceiptResolutionParts<'static> {
    ReceiptResolutionParts {
        election_id: e(),
        box_id: BoxId::new(b"BOX-OUT-1").unwrap(),
        entries: ReceiptEntries::new(entries).unwrap(),
        time_bucket: TimeBucket::new(1_900),
    }
}

fn receipt_bytes() -> &'static [u8] {
    let all = receipt_entries(&[
        (0x10, ReceiptOutcome::Received),
        (0x20, ReceiptOutcome::Damaged),
        (0x30, ReceiptOutcome::Late),
        (0x40, ReceiptOutcome::WrongDistrict),
        (0x50, ReceiptOutcome::NotReceived),
    ]);
    let body = ReceiptResolutionBody::new(&receipt_parts(all));
    leak(encode_to_vec(
        SCHEMA_RECEIPT_RESOLUTION_BODY,
        SCHEMA_VERSION_1,
        &body,
    ))
}

#[test]
fn receipt_outcomes_have_the_codes_of_the_resolution() {
    assert_eq!(PURPOSE_RECEIPT_RESOLUTION, b"receipt-resolution");
    assert_eq!(
        QuorumKind::ReceiptResolution.purpose(),
        PURPOSE_RECEIPT_RESOLUTION
    );
    let all = [
        ReceiptOutcome::Received,
        ReceiptOutcome::Damaged,
        ReceiptOutcome::Late,
        ReceiptOutcome::WrongDistrict,
        ReceiptOutcome::NotReceived,
    ];
    for (i, o) in all.iter().enumerate() {
        assert_eq!(usize::from(o.code()), i + 1);
        assert_eq!(ReceiptOutcome::from_code(o.code()), Some(*o));
    }
    assert_eq!(ReceiptOutcome::from_code(0), None);
    assert_eq!(ReceiptOutcome::from_code(6), None);
    assert_eq!(RECEIPT_ENTRY_LEN, 65);
    assert_eq!(MAX_RECEIPT_ENTRIES, 65_536);
}

#[test]
fn a_receipt_resolution_round_trips_and_lists_each_record_once_in_order() {
    let bytes = receipt_bytes();
    let body: ReceiptResolutionBody<'_> =
        decode_object(SCHEMA_RECEIPT_RESOLUTION_BODY, SCHEMA_VERSION_1, bytes).unwrap();
    assert_eq!(bytes.len(), HEADER_LEN + body.encoded_len());
    let entries = body.parts().entries;
    assert_eq!(entries.len(), 5);
    assert!(!entries.is_empty());
    let outcomes: Vec<(u8, ReceiptOutcome)> = entries
        .iter()
        .map(|e| (e.record_hash.0[0], e.outcome))
        .collect();
    assert_eq!(
        outcomes,
        std::vec![
            (0x10, ReceiptOutcome::Received),
            (0x20, ReceiptOutcome::Damaged),
            (0x30, ReceiptOutcome::Late),
            (0x40, ReceiptOutcome::WrongDistrict),
            (0x50, ReceiptOutcome::NotReceived),
        ]
    );
    // No entry at all is a resolution of an empty box.
    let empty = ReceiptResolutionBody::new(&receipt_parts(leak(Vec::new())));
    assert!(empty.parts().entries.is_empty());
    assert_eq!(empty.parts().entries.len(), 0);
    let bytes = encode_to_vec(SCHEMA_RECEIPT_RESOLUTION_BODY, SCHEMA_VERSION_1, &empty);
    let back: ReceiptResolutionBody<'_> =
        decode_object(SCHEMA_RECEIPT_RESOLUTION_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(back, empty);

    // The entry list's own rules.
    let two = receipt_entries(&[
        (0x10, ReceiptOutcome::Received),
        (0x20, ReceiptOutcome::Late),
    ]);
    assert!(ReceiptEntries::new(two).is_some());
    assert!(ReceiptEntries::new(&two[..=RECEIPT_ENTRY_LEN]).is_none());
    let mut bad = two.to_vec();
    bad[64] = 6;
    assert!(ReceiptEntries::new(leak(bad)).is_none());
    let twice = receipt_entries(&[
        (0x10, ReceiptOutcome::Received),
        (0x10, ReceiptOutcome::Late),
    ]);
    assert!(ReceiptEntries::new(twice).is_none());
    let reversed = receipt_entries(&[
        (0x20, ReceiptOutcome::Received),
        (0x10, ReceiptOutcome::Late),
    ]);
    assert!(ReceiptEntries::new(reversed).is_none());
    let too_many = leak(std::vec![0u8; (MAX_RECEIPT_ENTRIES + 1) * RECEIPT_ENTRY_LEN]);
    assert!(ReceiptEntries::new(too_many).is_none());
    // The largest list is accepted (ascending record hashes).
    let mut most = std::vec![0u8; MAX_RECEIPT_ENTRIES * RECEIPT_ENTRY_LEN];
    for (i, chunk) in most.chunks_exact_mut(RECEIPT_ENTRY_LEN).enumerate() {
        chunk[60..64].copy_from_slice(&u32::try_from(i).unwrap().to_be_bytes());
        chunk[64] = 1;
    }
    let most = ReceiptEntries::new(leak(most)).unwrap();
    assert_eq!(most.len(), MAX_RECEIPT_ENTRIES);
}

#[test]
fn a_receipt_resolution_decoder_reports_each_rule_where_it_breaks() {
    let bytes = receipt_bytes();
    // Offsets: header 16, election 4 + 12, box 4 + 9, count 4.
    let first = HEADER_LEN + 16 + 13 + 4;
    let second = first + RECEIPT_ENTRY_LEN;
    let mut b = bytes.to_vec();
    b[first + 64] = 0;
    assert_eq!(
        kind_of::<ReceiptResolutionBody<'_>>(SCHEMA_RECEIPT_RESOLUTION_BODY, &b),
        (ErrorKind::ValueOutOfRange, first + 64)
    );
    let mut b = bytes.to_vec();
    b[second..second + 64].fill(0x10);
    assert_eq!(
        kind_of::<ReceiptResolutionBody<'_>>(SCHEMA_RECEIPT_RESOLUTION_BODY, &b),
        (ErrorKind::Duplicate, second)
    );
    let mut b = bytes.to_vec();
    b[second..second + 64].fill(0x01);
    assert_eq!(
        kind_of::<ReceiptResolutionBody<'_>>(SCHEMA_RECEIPT_RESOLUTION_BODY, &b),
        (ErrorKind::NotSorted, second)
    );
    let mut b = bytes.to_vec();
    b[first - 4..first].copy_from_slice(&65_537u32.to_be_bytes());
    assert_eq!(
        kind_of::<ReceiptResolutionBody<'_>>(SCHEMA_RECEIPT_RESOLUTION_BODY, &b).0,
        ErrorKind::CountExceedsMax
    );
    // Inside a quorum envelope the error is rebased to the envelope.
    let sigs = [sig(b"T-A", &SIG_A)];
    let event = QuorumSigned::new(bytes, &sigs).unwrap();
    let mut wrapped = encode_to_vec(SCHEMA_QUORUM_SIGNED, SCHEMA_VERSION_1, &event);
    wrapped[HEADER_LEN + 4 + first + 64] = 9;
    assert_eq!(
        kind_of::<QuorumSigned<'_>>(SCHEMA_QUORUM_SIGNED, &wrapped),
        (ErrorKind::ValueOutOfRange, HEADER_LEN + 4 + first + 64)
    );
}

/// `n` exclusions, ascending by record hash, with reasons and bases drawn
/// from `seeds`.
fn drawn_exclusions(seeds: &[(u8, u8)]) -> &'static [u8] {
    let list: Vec<ExclusionEntry> = seeds
        .iter()
        .enumerate()
        .map(|(i, (reason, basis))| {
            let mut record = [0u8; 64];
            record[..4].copy_from_slice(&u32::try_from(i).unwrap().to_be_bytes());
            ExclusionEntry {
                record_hash: Hash512(record),
                reason: ExclusionReason::ALL[usize::from(*reason) % 8],
                basis: Hash512([basis.saturating_add(1); 64]),
            }
        })
        .collect();
    entries(&list)
}

proptest! {
    /// Every valid tally scope survives an object round trip.
    #[test]
    fn tally_scope_round_trip(
        included in 0..=MAX_TALLY_COUNT,
        no_record in 0..=MAX_TALLY_COUNT,
        root in any::<[u8; 32]>(),
        seeds in prop::collection::vec((any::<u8>(), any::<u8>()), 0..12),
        bucket in any::<u64>(),
    ) {
        let mut r = [0u8; 64];
        r[..32].copy_from_slice(&root);
        let parts = TallyScopeParts {
            included_count: included,
            included_root: Hash512(r),
            no_record_count: no_record,
            exclusions: Exclusions::new(drawn_exclusions(&seeds)).unwrap(),
            time_bucket: TimeBucket::new(bucket),
            ..scope_parts(Exclusions::EMPTY)
        };
        let body = TallyScopeBody::new(&parts).unwrap();
        let bytes = encode_to_vec(SCHEMA_TALLY_SCOPE_BODY, SCHEMA_VERSION_1, &body);
        prop_assert_eq!(bytes.len(), HEADER_LEN + body.encoded_len());
        let back: TallyScopeBody<'_> =
            decode_object(SCHEMA_TALLY_SCOPE_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back.parts(), &parts);
        prop_assert_eq!(back.parts().exclusions.len(), seeds.len());
    }

    /// Every valid aggregate opening survives a round trip.
    #[test]
    fn aggregate_opening_round_trip(
        chunk in 0u8..8,
        t in any::<[u8; 32]>(),
        r in any::<[u8; 32]>(),
        s in any::<[u8; 32]>(),
        scope in 1u8..=255,
        bucket in any::<u64>(),
    ) {
        let parts = AggregateOpeningParts {
            scope_hash: Hash512([scope; 64]),
            packed_sum: Scalar32(t),
            rand_sum: Scalar32(r),
            id_sum: Scalar32(s),
            time_bucket: TimeBucket::new(bucket),
            ..opening_parts(chunk)
        };
        let body = AggregateOpeningBody::new(&parts).unwrap();
        let bytes = encode_to_vec(SCHEMA_AGGREGATE_OPENING_BODY, SCHEMA_VERSION_1, &body);
        let back: AggregateOpeningBody<'_> =
            decode_object(SCHEMA_AGGREGATE_OPENING_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back.parts(), &parts);
    }

    /// Every valid receipt resolution survives a round trip.
    #[test]
    fn receipt_resolution_round_trip(
        outcomes in prop::collection::vec(1u8..=5, 0..16),
        bucket in any::<u64>(),
    ) {
        let list: Vec<(u8, ReceiptOutcome)> = outcomes
            .iter()
            .enumerate()
            .map(|(i, o)| (u8::try_from(i).unwrap(), ReceiptOutcome::from_code(*o).unwrap()))
            .collect();
        let parts = ReceiptResolutionParts {
            time_bucket: TimeBucket::new(bucket),
            ..receipt_parts(receipt_entries(&list))
        };
        let body = ReceiptResolutionBody::new(&parts);
        let bytes = encode_to_vec(SCHEMA_RECEIPT_RESOLUTION_BODY, SCHEMA_VERSION_1, &body);
        let back: ReceiptResolutionBody<'_> =
            decode_object(SCHEMA_RECEIPT_RESOLUTION_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back.parts(), &parts);
        let decoded: Vec<ReceiptOutcome> = back.parts().entries.iter().map(|e| e.outcome).collect();
        let drawn: Vec<ReceiptOutcome> = list.iter().map(|(_, o)| *o).collect();
        prop_assert_eq!(decoded, drawn);
    }

    /// Every valid paper count report survives a round trip.
    #[test]
    fn paper_count_round_trip(
        votes in prop::collection::vec(0..=MAX_TALLY_COUNT, 1..=MAX_CANDIDATES),
        invalid in 0..=MAX_TALLY_COUNT,
        bucket in any::<u64>(),
    ) {
        let parts = PaperCountParts {
            invalid,
            time_bucket: TimeBucket::new(bucket),
            ..paper_parts(&votes)
        };
        let body = PaperCountReportBody::new(&parts).unwrap();
        let bytes = encode_to_vec(SCHEMA_PAPER_COUNT_REPORT_BODY, SCHEMA_VERSION_1, &body);
        let back: PaperCountReportBody<'_> =
            decode_object(SCHEMA_PAPER_COUNT_REPORT_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back.parts(), &parts);
        prop_assert_eq!(back.parts().votes.as_slice(), votes.as_slice());
    }

    /// Every valid quorum envelope, of any of its three bodies and one to
    /// 64 ascending trustees, survives a round trip, and its quorum
    /// message names exactly its trustees after the body hash.
    #[test]
    fn quorum_signed_round_trip(
        which in 0u8..3,
        trustees in 1usize..=MAX_QUORUM_SIGS,
    ) {
        let body = match which {
            0 => scope_bytes(),
            1 => opening_bytes(),
            _ => receipt_bytes(),
        };
        let names: Vec<&'static [u8]> = (0..trustees)
            .map(|i| leak(std::format!("T-{i:02}").into_bytes()))
            .collect();
        let sigs: Vec<QuorumSig<'static>> = names.iter().map(|n| sig(n, &SIG_A)).collect();
        let event = QuorumSigned::new(body, &sigs).unwrap();
        let bytes = encode_to_vec(SCHEMA_QUORUM_SIGNED, SCHEMA_VERSION_1, &event);
        let back: QuorumSigned<'_> =
            decode_object(SCHEMA_QUORUM_SIGNED, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back, event);
        let hash = Hash512([0x5A; 64]);
        let mut from_event = std::vec![0u8; MAX_QUORUM_MESSAGE_LEN];
        let mut w = Writer::new(&mut from_event);
        back.write_message(&hash, &mut w).unwrap();
        let n = w.finish();
        let ids: Vec<TrusteeId<'static>> =
            names.iter().map(|n| TrusteeId::new(n).unwrap()).collect();
        let mut from_list = std::vec![0u8; MAX_QUORUM_MESSAGE_LEN];
        let mut w = Writer::new(&mut from_list);
        write_quorum_message(&hash, &ids, &mut w).unwrap();
        prop_assert_eq!(w.finish(), n);
        prop_assert_eq!(&from_event[..n], &from_list[..n]);
        prop_assert_eq!(&from_event[..64], hash.as_bytes().as_slice());
        let count = u32::try_from(trustees).unwrap().to_be_bytes();
        prop_assert_eq!(&from_event[64..68], count.as_slice());
    }
}

#[test]
fn the_quorum_message_needs_ascending_trustees_and_fits_the_bound() {
    let hash = Hash512([0x5A; 64]);
    let mut buf = std::vec![0u8; MAX_QUORUM_MESSAGE_LEN];
    let a = TrusteeId::new(b"T-A").unwrap();
    let b = TrusteeId::new(b"T-B").unwrap();
    for bad in [&[][..], &[b, a][..], &[a, a][..]] {
        let mut w = Writer::new(&mut buf);
        assert_eq!(
            write_quorum_message(&hash, bad, &mut w).unwrap_err().kind(),
            ErrorKind::InvariantViolation
        );
    }
    let too_many: Vec<TrusteeId<'static>> = (0..=MAX_QUORUM_SIGS)
        .map(|i| TrusteeId::new(leak(std::format!("T-{i:02}").into_bytes())).unwrap())
        .collect();
    let mut w = Writer::new(&mut buf);
    assert!(write_quorum_message(&hash, &too_many, &mut w).is_err());
    // The longest message: 64 trustees of 64-byte identifiers.
    let longest: Vec<TrusteeId<'static>> = (0..MAX_QUORUM_SIGS)
        .map(|i| {
            let mut id = std::format!("{i:02}").into_bytes();
            id.resize(64, b'x');
            TrusteeId::new(leak(id)).unwrap()
        })
        .collect();
    let mut w = Writer::new(&mut buf);
    write_quorum_message(&hash, &longest, &mut w).unwrap();
    assert_eq!(w.finish(), MAX_QUORUM_MESSAGE_LEN);
}
