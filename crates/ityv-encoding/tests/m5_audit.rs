//! The paper audit (ENCODING.md §8.66–§8.72): `AuditManifestFreezeBody`
//! (0x0048), `AuditSeedBody` (0x000D), the restricted `SampleOpeningBody`
//! (0x0049), `SampleOpeningRefBody` (0x004A) in a `QuorumSigned`,
//! `SampleComparisonBody` (0x004B), `AuditFindingBody` (0x004C) and
//! `HandCountReportBody` (0x004D) in a `WitnessedEvent`. Round trips, the
//! constructors' rules (the same as the decoders'), every decoder rule at
//! its offset, the signer roles of each audit body, the secrecy of the
//! opening, and property tests. Signatures are patterned bytes.
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

use common::{encode_to_vec, ident_len};
use ityv_encoding::{
    AuditCommitBody, AuditCommitParts, AuditFindingBody, AuditFindingParts, AuditFreezeParts,
    AuditManifestFreezeBody, AuditRound, AuditRounds, AuditSeedBody, AuditSeedParts, BallotStyleId,
    BoxId, ComparisonCode, Decode, ElectionId, Encode, ErrorKind, EventRole, EventSig, HEADER_LEN,
    HYBRID_SIG_LEN, HandCountReportBody, Hash512, MAX_AUDIT_ROUNDS, MAX_CANDIDATES,
    MAX_RISK_LIMIT_PPM, MAX_TALLY_COUNT, OrgId, PURPOSE_AUDIT_COMMIT, PURPOSE_AUDIT_FINDING,
    PURPOSE_AUDIT_FREEZE, PURPOSE_AUDIT_SEED, PURPOSE_HAND_COUNT, PURPOSE_SAMPLE_COMPARISON,
    PURPOSE_SAMPLE_OPENING, PaperCountParts, PaperVotes, QuorumKind, QuorumSig, QuorumSigned,
    Reader, ReportingUnitId, SCHEMA_AUDIT_COMMIT_BODY, SCHEMA_AUDIT_FINDING_BODY,
    SCHEMA_AUDIT_FREEZE_BODY, SCHEMA_AUDIT_SEED_BODY, SCHEMA_HAND_COUNT_REPORT_BODY,
    SCHEMA_PAPER_COUNT_REPORT_BODY, SCHEMA_QUORUM_SIGNED, SCHEMA_SAMPLE_COMPARISON_BODY,
    SCHEMA_SAMPLE_OPENING_BODY, SCHEMA_SAMPLE_OPENING_REF_BODY, SCHEMA_VERSION_1,
    SCHEMA_VERSION_QUORUM_SIGNED, SCHEMA_VERSION_WITNESSED, SCHEMA_WITNESSED_EVENT,
    SampleComparisonBody, SampleComparisonParts, SampleOpeningBody, SampleOpeningParts,
    SampleOpeningRefBody, SampleOpeningRefParts, Scalar32, Scalars, SchemaId, SignerId, TimeBucket,
    Token192, TrusteeId, WITNESSED_BODY_SCHEMAS, WitnessedEvent, decode_object, purpose_of,
    roles_satisfied, schema_version,
};
use proptest::prelude::*;
use std::vec::Vec;

static SIG_A: [u8; HYBRID_SIG_LEN] = [0xA1; HYBRID_SIG_LEN];
static SIG_B: [u8; HYBRID_SIG_LEN] = [0xB2; HYBRID_SIG_LEN];
static SIG_C: [u8; HYBRID_SIG_LEN] = [0xC3; HYBRID_SIG_LEN];
static SIG_D: [u8; HYBRID_SIG_LEN] = [0xD4; HYBRID_SIG_LEN];
static SIG_E: [u8; HYBRID_SIG_LEN] = [0xE5; HYBRID_SIG_LEN];

fn e() -> ElectionId<'static> {
    ElectionId::new(b"KR-2030-PRES").unwrap()
}

fn style() -> BallotStyleId<'static> {
    BallotStyleId::new(b"S-11-0001").unwrap()
}

fn device() -> BoxId<'static> {
    BoxId::new(b"BOX-11-0042").unwrap()
}

fn h(fill: u8) -> Hash512 {
    Hash512([fill; 64])
}

fn round(sample_size: u64, threshold: u32) -> AuditRound {
    AuditRound {
        sample_size,
        threshold,
    }
}

fn rounds() -> AuditRounds {
    AuditRounds::new(&[round(10, 0), round(40, 2)]).unwrap()
}

fn freeze_parts() -> AuditFreezeParts<'static> {
    AuditFreezeParts {
        election_id: e(),
        ballot_style_id: style(),
        frame_count: 1_000,
        frame_root: h(0x10),
        rule_hash: h(0x11),
        risk_limit_ppm: 10_000,
        beacon_source: h(0x12),
        beacon_round: 4_242,
        rounds: rounds(),
        time_bucket: TimeBucket::new(3_000),
    }
}

fn seed_parts() -> AuditSeedParts<'static> {
    AuditSeedParts {
        election_id: e(),
        dice_hash: h(0x20),
        beacon_round: 4_242,
        beacon_value: h(0x21),
        checkpoint_hash: h(0x22),
        seed: h(0x23),
        time_bucket: TimeBucket::new(3_010),
    }
}

fn commit_parts() -> AuditCommitParts<'static> {
    AuditCommitParts {
        election_id: e(),
        dice_hash: h(0x20),
        beacon_source: h(0x24),
        beacon_round: 4_242,
        freezes_root: h(0x25),
        time_bucket: TimeBucket::new(3_005),
    }
}

fn rand(n: usize) -> Scalars<8> {
    let list: Vec<Scalar32> = (0..n)
        .map(|i| Scalar32([u8::try_from(i).unwrap() + 1; 32]))
        .collect();
    Scalars::new(&list).unwrap()
}

fn ref_parts() -> SampleOpeningRefParts<'static> {
    SampleOpeningRefParts {
        election_id: e(),
        ballot_style_id: style(),
        record_hash: h(0x30),
        opening_hash: h(0x31),
    }
}

fn comparison_parts(code: ComparisonCode) -> SampleComparisonParts<'static> {
    SampleComparisonParts {
        election_id: e(),
        ballot_style_id: style(),
        record_hash: h(0x30),
        opening_hash: h(0x31),
        device_id: device(),
        code,
        transfer_mark: false,
    }
}

fn finding_parts() -> AuditFindingParts<'static> {
    AuditFindingParts {
        election_id: e(),
        ballot_style_id: style(),
        device_id: device(),
        finding_hash: h(0x40),
        time_bucket: TimeBucket::new(3_100),
    }
}

fn hand_parts(votes: &[u64]) -> PaperCountParts<'static> {
    PaperCountParts {
        election_id: e(),
        reporting_unit_id: ReportingUnitId::new(b"RU-11-01").unwrap(),
        ballot_style_id: style(),
        votes: PaperVotes::new(votes).unwrap(),
        invalid: 3,
        time_bucket: TimeBucket::new(3_200),
    }
}

fn kind_of<'a, T: Decode<'a> + core::fmt::Debug>(
    schema: SchemaId,
    bytes: &'a [u8],
) -> (ErrorKind, usize) {
    let err = decode_object::<T>(schema, schema_version(schema), bytes).unwrap_err();
    (err.kind(), err.offset())
}

fn leak(v: Vec<u8>) -> &'static [u8] {
    Vec::leak(v)
}

fn freeze_bytes(p: &AuditFreezeParts<'_>) -> Vec<u8> {
    let body = AuditManifestFreezeBody::new(p).unwrap();
    let bytes = encode_to_vec(SCHEMA_AUDIT_FREEZE_BODY, SCHEMA_VERSION_1, &body);
    assert_eq!(bytes.len(), HEADER_LEN + body.encoded_len());
    bytes
}

// Offsets of the freeze: header 16, election 4 + 12, style 4 + 9.
const FRAME_COUNT_AT: usize = HEADER_LEN + 16 + 13;
const RULE_AT: usize = FRAME_COUNT_AT + 8 + 64;
const RISK_AT: usize = RULE_AT + 64;
const BEACON_AT: usize = RISK_AT + 4;
const ROUNDS_AT: usize = BEACON_AT + 64 + 8;
const FIRST_ROUND_AT: usize = ROUNDS_AT + 4;
const SECOND_ROUND_AT: usize = FIRST_ROUND_AT + 12;

#[test]
fn purposes_codes_and_versions() {
    assert_eq!(PURPOSE_AUDIT_FREEZE, b"audit-freeze");
    assert_eq!(PURPOSE_AUDIT_SEED, b"audit-seed");
    assert_eq!(PURPOSE_AUDIT_COMMIT, b"audit-commit");
    assert_eq!(PURPOSE_SAMPLE_OPENING, b"sample-opening");
    assert_eq!(PURPOSE_SAMPLE_COMPARISON, b"sample-comparison");
    assert_eq!(PURPOSE_AUDIT_FINDING, b"audit-finding");
    assert_eq!(PURPOSE_HAND_COUNT, b"hand-count");
    for (schema, purpose) in [
        (SCHEMA_AUDIT_SEED_BODY, PURPOSE_AUDIT_SEED),
        (SCHEMA_AUDIT_COMMIT_BODY, PURPOSE_AUDIT_COMMIT),
        (SCHEMA_AUDIT_FREEZE_BODY, PURPOSE_AUDIT_FREEZE),
        (SCHEMA_SAMPLE_COMPARISON_BODY, PURPOSE_SAMPLE_COMPARISON),
        (SCHEMA_AUDIT_FINDING_BODY, PURPOSE_AUDIT_FINDING),
        (SCHEMA_HAND_COUNT_REPORT_BODY, PURPOSE_HAND_COUNT),
    ] {
        assert!(WITNESSED_BODY_SCHEMAS.contains(&schema));
        assert_eq!(purpose_of(schema), Some(purpose));
    }
    // The restricted opening and its public reference are not witnessed
    // bodies; the reference is the trustees' (`QuorumSigned`).
    for schema in [SCHEMA_SAMPLE_OPENING_BODY, SCHEMA_SAMPLE_OPENING_REF_BODY] {
        assert!(!WITNESSED_BODY_SCHEMAS.contains(&schema));
        assert_eq!(purpose_of(schema), None);
    }
    assert_eq!(QuorumKind::SampleOpening.purpose(), PURPOSE_SAMPLE_OPENING);
    assert_eq!(SCHEMA_AUDIT_SEED_BODY.get(), 0x000D);
    assert_eq!(SCHEMA_AUDIT_FREEZE_BODY.get(), 0x0048);
    assert_eq!(SCHEMA_SAMPLE_OPENING_BODY.get(), 0x0049);
    assert_eq!(SCHEMA_SAMPLE_OPENING_REF_BODY.get(), 0x004A);
    assert_eq!(SCHEMA_SAMPLE_COMPARISON_BODY.get(), 0x004B);
    assert_eq!(SCHEMA_AUDIT_FINDING_BODY.get(), 0x004C);
    assert_eq!(SCHEMA_HAND_COUNT_REPORT_BODY.get(), 0x004D);
    assert_eq!(SCHEMA_AUDIT_COMMIT_BODY.get(), 0x004E);
    for schema in [
        SCHEMA_AUDIT_COMMIT_BODY,
        SCHEMA_AUDIT_SEED_BODY,
        SCHEMA_AUDIT_FREEZE_BODY,
        SCHEMA_SAMPLE_OPENING_BODY,
        SCHEMA_SAMPLE_OPENING_REF_BODY,
        SCHEMA_SAMPLE_COMPARISON_BODY,
        SCHEMA_AUDIT_FINDING_BODY,
        SCHEMA_HAND_COUNT_REPORT_BODY,
    ] {
        assert_eq!(schema_version(schema), SCHEMA_VERSION_1);
    }
    for code in 0u8..=255 {
        match ComparisonCode::from_code(code) {
            Some(c) => assert_eq!(c.code(), code),
            None => assert!(code > 6),
        }
    }
    for (index, c) in ComparisonCode::ALL.iter().enumerate() {
        assert_eq!(usize::from(c.code()), index);
    }
    assert_eq!(EventRole::from_code(10), Some(EventRole::Auditor));
    assert_eq!(EventRole::Auditor.code(), 10);
    assert_eq!(MAX_AUDIT_ROUNDS, 8);
    assert_eq!(MAX_RISK_LIMIT_PPM, 999_999);
}

#[test]
fn rounds_ascend_in_size_and_never_lower_the_threshold() {
    let ok = AuditRounds::new(&[round(1, 0), round(2, 0), round(MAX_TALLY_COUNT, 7)]).unwrap();
    assert_eq!(ok.count(), 3);
    assert_eq!(ok.as_slice().len(), 3);
    assert_eq!(ok.get(0), Some(round(1, 0)));
    assert_eq!(ok.get(2), Some(round(MAX_TALLY_COUNT, 7)));
    assert_eq!(ok.get(3), None);
    let eight: Vec<AuditRound> = (1..=8).map(|i| round(i, 0)).collect();
    assert_eq!(AuditRounds::new(&eight).unwrap().count(), 8);
    let nine: Vec<AuditRound> = (1..=9).map(|i| round(i, 0)).collect();
    assert_eq!(AuditRounds::new(&nine), None);
    assert_eq!(AuditRounds::new(&[]), None);
    assert_eq!(AuditRounds::new(&[round(0, 0)]), None);
    assert_eq!(AuditRounds::new(&[round(MAX_TALLY_COUNT + 1, 0)]), None);
    assert_eq!(AuditRounds::new(&[round(5, 0), round(5, 0)]), None);
    assert_eq!(AuditRounds::new(&[round(5, 0), round(4, 0)]), None);
    assert_eq!(AuditRounds::new(&[round(5, 2), round(6, 1)]), None);
    assert!(AuditRounds::new(&[round(5, 2), round(6, 2)]).is_some());
    // A threshold below the size: a round every sample passes rules
    // nothing.
    assert!(AuditRounds::new(&[round(5, 4)]).is_some());
    assert_eq!(AuditRounds::new(&[round(5, 5)]), None);
    assert_eq!(AuditRounds::new(&[round(1, 1)]), None);
    assert_eq!(AuditRounds::new(&[round(5, 0), round(6, u32::MAX)]), None);
    let top = u32::try_from(MAX_TALLY_COUNT - 1).unwrap();
    assert!(AuditRounds::new(&[round(5, 0), round(MAX_TALLY_COUNT, top)]).is_some());
    // A rule that fails at the second round fails as a whole.
    assert_eq!(AuditRounds::new(&[round(5, 0), round(0, 0)]), None);
}

#[test]
fn a_freeze_round_trips_and_decodes_each_rule_where_it_breaks() {
    let parts = freeze_parts();
    let bytes = freeze_bytes(&parts);
    let back: AuditManifestFreezeBody<'_> =
        decode_object(SCHEMA_AUDIT_FREEZE_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(back.parts(), &parts);
    assert_eq!(back.parts().rounds.as_slice(), rounds().as_slice());
    // The largest frame and risk limit, the smallest risk limit.
    for (count, risk) in [(MAX_TALLY_COUNT, MAX_RISK_LIMIT_PPM), (0, 1)] {
        let p = AuditFreezeParts {
            frame_count: count,
            risk_limit_ppm: risk,
            ..parts
        };
        let b = freeze_bytes(&p);
        let back: AuditManifestFreezeBody<'_> =
            decode_object(SCHEMA_AUDIT_FREEZE_BODY, SCHEMA_VERSION_1, &b).unwrap();
        assert_eq!(back.parts(), &p);
    }
    // The constructor's rules.
    let bad = |p: AuditFreezeParts<'static>| AuditManifestFreezeBody::new(&p).unwrap_err();
    for p in [
        AuditFreezeParts {
            frame_count: MAX_TALLY_COUNT + 1,
            ..parts
        },
        AuditFreezeParts {
            risk_limit_ppm: 0,
            ..parts
        },
        AuditFreezeParts {
            risk_limit_ppm: MAX_RISK_LIMIT_PPM + 1,
            ..parts
        },
    ] {
        let err = bad(p);
        assert_eq!((err.kind(), err.offset()), (ErrorKind::ValueOutOfRange, 0));
    }
    for p in [
        AuditFreezeParts {
            rule_hash: Hash512::ZERO,
            ..parts
        },
        AuditFreezeParts {
            beacon_source: Hash512::ZERO,
            ..parts
        },
    ] {
        let err = bad(p);
        assert_eq!(
            (err.kind(), err.offset()),
            (ErrorKind::InvalidPreviousHash, 0)
        );
    }
    // The decoder's, each at its offset.
    let at = |b: &[u8]| kind_of::<AuditManifestFreezeBody<'_>>(SCHEMA_AUDIT_FREEZE_BODY, b);
    let mut b = bytes.clone();
    b[FRAME_COUNT_AT..FRAME_COUNT_AT + 8].copy_from_slice(&(MAX_TALLY_COUNT + 1).to_be_bytes());
    assert_eq!(at(&b), (ErrorKind::ValueOutOfRange, FRAME_COUNT_AT));
    let mut b = bytes.clone();
    b[RULE_AT..RULE_AT + 64].fill(0);
    assert_eq!(at(&b), (ErrorKind::InvalidPreviousHash, RULE_AT));
    for risk in [0u32, MAX_RISK_LIMIT_PPM + 1] {
        let mut b = bytes.clone();
        b[RISK_AT..RISK_AT + 4].copy_from_slice(&risk.to_be_bytes());
        assert_eq!(at(&b), (ErrorKind::ValueOutOfRange, RISK_AT));
    }
    let mut b = bytes.clone();
    b[RISK_AT..RISK_AT + 4].copy_from_slice(&MAX_RISK_LIMIT_PPM.to_be_bytes());
    assert!(
        decode_object::<AuditManifestFreezeBody<'_>>(
            SCHEMA_AUDIT_FREEZE_BODY,
            SCHEMA_VERSION_1,
            &b
        )
        .is_ok()
    );
    let mut b = bytes.clone();
    b[BEACON_AT..BEACON_AT + 64].fill(0);
    assert_eq!(at(&b), (ErrorKind::InvalidPreviousHash, BEACON_AT));
    let mut b = bytes.clone();
    b[ROUNDS_AT..ROUNDS_AT + 4].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(at(&b), (ErrorKind::InvariantViolation, ROUNDS_AT));
    let mut b = bytes.clone();
    b[ROUNDS_AT..ROUNDS_AT + 4].copy_from_slice(&9u32.to_be_bytes());
    assert_eq!(at(&b).0, ErrorKind::CountExceedsMax);
    let mut b = bytes.clone();
    b[FIRST_ROUND_AT..FIRST_ROUND_AT + 8].copy_from_slice(&0u64.to_be_bytes());
    assert_eq!(at(&b), (ErrorKind::ValueOutOfRange, FIRST_ROUND_AT));
    let mut b = bytes.clone();
    b[FIRST_ROUND_AT..FIRST_ROUND_AT + 8].copy_from_slice(&(MAX_TALLY_COUNT + 1).to_be_bytes());
    assert_eq!(at(&b), (ErrorKind::ValueOutOfRange, FIRST_ROUND_AT));
    let mut b = bytes.clone();
    b[SECOND_ROUND_AT..SECOND_ROUND_AT + 8].copy_from_slice(&10u64.to_be_bytes());
    assert_eq!(at(&b), (ErrorKind::Duplicate, SECOND_ROUND_AT));
    let mut b = bytes.clone();
    b[SECOND_ROUND_AT..SECOND_ROUND_AT + 8].copy_from_slice(&9u64.to_be_bytes());
    assert_eq!(at(&b), (ErrorKind::NotSorted, SECOND_ROUND_AT));
    let mut b = bytes.clone();
    // The first round's threshold not below its size.
    b[FIRST_ROUND_AT + 8..FIRST_ROUND_AT + 12].copy_from_slice(&10u32.to_be_bytes());
    assert_eq!(at(&b), (ErrorKind::ValueOutOfRange, FIRST_ROUND_AT));
    let mut b = bytes.clone();
    // The first round's threshold above the second's.
    b[FIRST_ROUND_AT + 8..FIRST_ROUND_AT + 12].copy_from_slice(&3u32.to_be_bytes());
    assert_eq!(at(&b), (ErrorKind::InvariantViolation, SECOND_ROUND_AT));
    let mut b = bytes.clone();
    b.truncate(b.len() - 1);
    let n = u32::try_from(b.len() - HEADER_LEN).unwrap();
    b[12..16].copy_from_slice(&n.to_be_bytes());
    assert_eq!(at(&b).0, ErrorKind::UnexpectedEnd);
}

#[test]
fn a_seed_round_trips_and_needs_its_dice_and_checkpoint() {
    let parts = seed_parts();
    let body = AuditSeedBody::new(&parts).unwrap();
    let bytes = encode_to_vec(SCHEMA_AUDIT_SEED_BODY, SCHEMA_VERSION_1, &body);
    assert_eq!(bytes.len(), HEADER_LEN + body.encoded_len());
    let back: AuditSeedBody<'_> =
        decode_object(SCHEMA_AUDIT_SEED_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(back.parts(), &parts);
    for p in [
        AuditSeedParts {
            dice_hash: Hash512::ZERO,
            ..parts
        },
        AuditSeedParts {
            checkpoint_hash: Hash512::ZERO,
            ..parts
        },
    ] {
        let err = AuditSeedBody::new(&p).unwrap_err();
        assert_eq!(
            (err.kind(), err.offset()),
            (ErrorKind::InvalidPreviousHash, 0)
        );
    }
    // A zero beacon value or seed is a value like any other.
    let p = AuditSeedParts {
        beacon_value: Hash512::ZERO,
        seed: Hash512::ZERO,
        ..parts
    };
    assert!(AuditSeedBody::new(&p).is_ok());
    let dice_at = HEADER_LEN + 16;
    let checkpoint_at = dice_at + 64 + 8 + 64;
    let at = |b: &[u8]| kind_of::<AuditSeedBody<'_>>(SCHEMA_AUDIT_SEED_BODY, b);
    let mut b = bytes.clone();
    b[dice_at..dice_at + 64].fill(0);
    assert_eq!(at(&b), (ErrorKind::InvalidPreviousHash, dice_at));
    let mut b = bytes;
    b[checkpoint_at..checkpoint_at + 64].fill(0);
    assert_eq!(at(&b), (ErrorKind::InvalidPreviousHash, checkpoint_at));
}

#[test]
fn a_commit_round_trips_and_needs_its_dice_beacon_and_freezes() {
    let parts = commit_parts();
    let body = AuditCommitBody::new(&parts).unwrap();
    let bytes = encode_to_vec(SCHEMA_AUDIT_COMMIT_BODY, SCHEMA_VERSION_1, &body);
    assert_eq!(bytes.len(), HEADER_LEN + body.encoded_len());
    let back: AuditCommitBody<'_> =
        decode_object(SCHEMA_AUDIT_COMMIT_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(back.parts(), &parts);
    for p in [
        AuditCommitParts {
            dice_hash: Hash512::ZERO,
            ..parts
        },
        AuditCommitParts {
            beacon_source: Hash512::ZERO,
            ..parts
        },
        AuditCommitParts {
            freezes_root: Hash512::ZERO,
            ..parts
        },
    ] {
        let err = AuditCommitBody::new(&p).unwrap_err();
        assert_eq!(
            (err.kind(), err.offset()),
            (ErrorKind::InvalidPreviousHash, 0)
        );
    }
    let dice_at = HEADER_LEN + 16;
    let source_at = dice_at + 64;
    let freezes_at = source_at + 64 + 8;
    let at = |b: &[u8]| kind_of::<AuditCommitBody<'_>>(SCHEMA_AUDIT_COMMIT_BODY, b);
    for place in [dice_at, source_at, freezes_at] {
        let mut b = bytes.clone();
        b[place..place + 64].fill(0);
        assert_eq!(at(&b), (ErrorKind::InvalidPreviousHash, place));
    }
    let mut b = bytes;
    b.truncate(b.len() - 1);
    let n = u32::try_from(b.len() - HEADER_LEN).unwrap();
    b[12..16].copy_from_slice(&n.to_be_bytes());
    assert_eq!(at(&b).0, ErrorKind::UnexpectedEnd);
}

#[test]
fn a_sample_opening_round_trips_and_keeps_its_secret() {
    let r = rand(2);
    let parts = SampleOpeningParts {
        election_id: e(),
        ballot_style_id: style(),
        record_hash: h(0x30),
        option_index: 63,
        cast_id: Token192([0x77; 24]),
        rand: &r,
    };
    let body = SampleOpeningBody::new(&parts).unwrap();
    assert_eq!(body.election_id(), e());
    assert_eq!(body.ballot_style_id(), style());
    assert_eq!(body.record_hash(), &h(0x30));
    assert_eq!(body.option_index(), 63);
    assert_eq!(body.cast_id(), &Token192([0x77; 24]));
    assert_eq!(body.rand().as_slice(), r.as_slice());
    let bytes = encode_to_vec(SCHEMA_SAMPLE_OPENING_BODY, SCHEMA_VERSION_1, &body);
    assert_eq!(bytes.len(), HEADER_LEN + body.encoded_len());
    let back: SampleOpeningBody<'_> =
        decode_object(SCHEMA_SAMPLE_OPENING_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(back, body);
    // The parts' Debug shows neither the option nor the cast id: two parts
    // that differ only there print alike.
    let r2 = rand(2);
    let other = SampleOpeningParts {
        option_index: 5,
        cast_id: Token192([0x78; 24]),
        rand: &r2,
        ..parts
    };
    let text = std::format!("{parts:?}");
    assert_eq!(text, std::format!("{other:?}"));
    assert!(
        text.contains("record_hash") && text.contains("scalars: 2"),
        "{text}"
    );
    assert!(!text.contains("option_index") && !text.contains("cast_id") && !text.contains("119"));
    // Debug shows the public fields only.
    let shown = std::format!("{back:?}");
    assert!(shown.contains("record_hash"));
    assert!(!shown.contains("option_index"));
    assert!(!shown.contains("cast_id"));
    assert!(!shown.contains("rand"));
    // The constructor's and the decoder's rules.
    let empty = rand(0);
    assert!(
        SampleOpeningBody::new(&SampleOpeningParts {
            rand: &empty,
            ..parts
        })
        .is_none()
    );
    assert!(
        SampleOpeningBody::new(&SampleOpeningParts {
            option_index: 64,
            ..parts
        })
        .is_none()
    );
    let index_at = HEADER_LEN + 16 + 13 + 64;
    let rand_at = index_at + 2 + 24;
    let at = |b: &[u8]| kind_of::<SampleOpeningBody<'_>>(SCHEMA_SAMPLE_OPENING_BODY, b);
    let mut b = bytes.clone();
    b[index_at..index_at + 2].copy_from_slice(&64u16.to_be_bytes());
    assert_eq!(at(&b), (ErrorKind::ValueOutOfRange, index_at));
    let mut b = bytes.clone();
    b[rand_at..rand_at + 4].copy_from_slice(&0u32.to_be_bytes());
    b.truncate(rand_at + 4);
    let n = u32::try_from(b.len() - HEADER_LEN).unwrap();
    b[12..16].copy_from_slice(&n.to_be_bytes());
    assert_eq!(at(&b), (ErrorKind::ValueOutOfRange, rand_at));
    let mut b = bytes.clone();
    b[rand_at..rand_at + 4].copy_from_slice(&9u32.to_be_bytes());
    assert_eq!(at(&b).0, ErrorKind::CountExceedsMax);
}

#[test]
fn a_sample_opening_is_wiped_when_dropped() {
    use zeroize::Zeroize;
    let r = rand(3);
    let mut body = SampleOpeningBody::new(&SampleOpeningParts {
        election_id: e(),
        ballot_style_id: style(),
        record_hash: h(0x30),
        option_index: 5,
        cast_id: Token192([0x77; 24]),
        rand: &r,
    })
    .unwrap();
    body.zeroize();
    assert_eq!(body.option_index(), 0);
    assert_eq!(body.cast_id(), &Token192([0; 24]));
    assert_eq!(body.rand().count(), 0);
    // The public fields stay.
    assert_eq!(body.record_hash(), &h(0x30));
}

#[test]
fn a_sample_opening_reference_rides_in_a_quorum_envelope() {
    let parts = ref_parts();
    let body = SampleOpeningRefBody::new(&parts).unwrap();
    let bytes = encode_to_vec(SCHEMA_SAMPLE_OPENING_REF_BODY, SCHEMA_VERSION_1, &body);
    assert_eq!(bytes.len(), HEADER_LEN + body.encoded_len());
    let back: SampleOpeningRefBody<'_> =
        decode_object(SCHEMA_SAMPLE_OPENING_REF_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(back.parts(), &parts);
    let err = SampleOpeningRefBody::new(&SampleOpeningRefParts {
        opening_hash: Hash512::ZERO,
        ..parts
    })
    .unwrap_err();
    assert_eq!(
        (err.kind(), err.offset()),
        (ErrorKind::InvalidPreviousHash, 0)
    );
    let opening_at = HEADER_LEN + 16 + 13 + 64;
    let mut b = bytes.clone();
    b[opening_at..opening_at + 64].fill(0);
    assert_eq!(
        kind_of::<SampleOpeningRefBody<'_>>(SCHEMA_SAMPLE_OPENING_REF_BODY, &b),
        (ErrorKind::InvalidPreviousHash, opening_at)
    );
    // In the trustees' envelope (version 2).
    let body_bytes = leak(bytes);
    let sigs = [
        QuorumSig {
            trustee_id: TrusteeId::new(b"T-A").unwrap(),
            sig: &SIG_A,
        },
        QuorumSig {
            trustee_id: TrusteeId::new(b"T-J").unwrap(),
            sig: &SIG_B,
        },
    ];
    let event = QuorumSigned::new(body_bytes, &sigs).unwrap();
    assert_eq!(event.kind(), QuorumKind::SampleOpening);
    assert_eq!(event.purpose(), PURPOSE_SAMPLE_OPENING);
    assert_eq!(event.sample_opening_ref().unwrap().parts(), &parts);
    assert!(event.tally_scope().is_none());
    assert!(event.aggregate_opening().is_none());
    assert!(event.receipt_resolution().is_none());
    let wrapped = encode_to_vec(SCHEMA_QUORUM_SIGNED, SCHEMA_VERSION_QUORUM_SIGNED, &event);
    let back: QuorumSigned<'_> =
        decode_object(SCHEMA_QUORUM_SIGNED, SCHEMA_VERSION_QUORUM_SIGNED, &wrapped).unwrap();
    assert_eq!(back, event);
    // A zero opening hash inside the envelope is reported at its place.
    let mut b = wrapped.clone();
    b[HEADER_LEN + 4 + opening_at..HEADER_LEN + 4 + opening_at + 64].fill(0);
    assert_eq!(
        kind_of::<QuorumSigned<'_>>(SCHEMA_QUORUM_SIGNED, &b),
        (ErrorKind::InvalidPreviousHash, HEADER_LEN + 4 + opening_at)
    );
    // Version 1 of the envelope is not read.
    assert_eq!(
        decode_object::<QuorumSigned<'_>>(SCHEMA_QUORUM_SIGNED, SCHEMA_VERSION_1, &wrapped)
            .unwrap_err()
            .kind(),
        ErrorKind::UnsupportedVersion
    );
    // The restricted body itself is no quorum body: a frame of it on the
    // public ledger does not decode as a trustee event.
    let r = rand(1);
    let secret = SampleOpeningBody::new(&SampleOpeningParts {
        election_id: e(),
        ballot_style_id: style(),
        record_hash: h(0x30),
        option_index: 1,
        cast_id: Token192([0x77; 24]),
        rand: &r,
    })
    .unwrap();
    let secret = leak(encode_to_vec(
        SCHEMA_SAMPLE_OPENING_BODY,
        SCHEMA_VERSION_1,
        &secret,
    ));
    let err = QuorumSigned::new(secret, &sigs).unwrap_err();
    assert_eq!((err.kind(), err.offset()), (ErrorKind::SchemaMismatch, 4));
}

#[test]
fn a_comparison_round_trips_every_code_and_mark() {
    for code in ComparisonCode::ALL {
        for mark in [false, true] {
            let parts = SampleComparisonParts {
                transfer_mark: mark,
                ..comparison_parts(code)
            };
            let body = SampleComparisonBody::new(&parts).unwrap();
            let bytes = encode_to_vec(SCHEMA_SAMPLE_COMPARISON_BODY, SCHEMA_VERSION_1, &body);
            assert_eq!(bytes.len(), HEADER_LEN + body.encoded_len());
            let back: SampleComparisonBody<'_> =
                decode_object(SCHEMA_SAMPLE_COMPARISON_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
            assert_eq!(back.parts(), &parts);
        }
    }
    let parts = comparison_parts(ComparisonCode::Match);
    let err = SampleComparisonBody::new(&SampleComparisonParts {
        opening_hash: Hash512::ZERO,
        ..parts
    })
    .unwrap_err();
    assert_eq!(
        (err.kind(), err.offset()),
        (ErrorKind::InvalidPreviousHash, 0)
    );
    let bytes = encode_to_vec(
        SCHEMA_SAMPLE_COMPARISON_BODY,
        SCHEMA_VERSION_1,
        &SampleComparisonBody::new(&parts).unwrap(),
    );
    let opening_at = HEADER_LEN + 16 + 13 + 64;
    let code_at = opening_at + 64 + ident_len(b"BOX-11-0042");
    let at = |b: &[u8]| kind_of::<SampleComparisonBody<'_>>(SCHEMA_SAMPLE_COMPARISON_BODY, b);
    let mut b = bytes.clone();
    b[opening_at..opening_at + 64].fill(0);
    assert_eq!(at(&b), (ErrorKind::InvalidPreviousHash, opening_at));
    let mut b = bytes.clone();
    b[code_at] = 7;
    assert_eq!(at(&b), (ErrorKind::ValueOutOfRange, code_at));
    let mut b = bytes;
    b[code_at + 1] = 2;
    assert_eq!(at(&b), (ErrorKind::InvalidBool, code_at + 1));
}

#[test]
fn a_finding_and_a_hand_count_round_trip() {
    let parts = finding_parts();
    let body = AuditFindingBody::new(&parts).unwrap();
    let bytes = encode_to_vec(SCHEMA_AUDIT_FINDING_BODY, SCHEMA_VERSION_1, &body);
    assert_eq!(bytes.len(), HEADER_LEN + body.encoded_len());
    let back: AuditFindingBody<'_> =
        decode_object(SCHEMA_AUDIT_FINDING_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(back.parts(), &parts);
    let err = AuditFindingBody::new(&AuditFindingParts {
        finding_hash: Hash512::ZERO,
        ..parts
    })
    .unwrap_err();
    assert_eq!(
        (err.kind(), err.offset()),
        (ErrorKind::InvalidPreviousHash, 0)
    );
    let finding_at = HEADER_LEN + 16 + 13 + ident_len(b"BOX-11-0042");
    let mut b = bytes;
    b[finding_at..finding_at + 64].fill(0);
    assert_eq!(
        kind_of::<AuditFindingBody<'_>>(SCHEMA_AUDIT_FINDING_BODY, &b),
        (ErrorKind::InvalidPreviousHash, finding_at)
    );

    // The hand count has the paper count's fields and rules, under its own
    // schema.
    let parts = hand_parts(&[120, 75, 3]);
    let body = HandCountReportBody::new(&parts).unwrap();
    let bytes = encode_to_vec(SCHEMA_HAND_COUNT_REPORT_BODY, SCHEMA_VERSION_1, &body);
    assert_eq!(bytes.len(), HEADER_LEN + body.encoded_len());
    let back: HandCountReportBody<'_> =
        decode_object(SCHEMA_HAND_COUNT_REPORT_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(back.parts(), &parts);
    assert_eq!(
        decode_object::<HandCountReportBody<'_>>(
            SCHEMA_PAPER_COUNT_REPORT_BODY,
            SCHEMA_VERSION_1,
            &bytes
        )
        .unwrap_err()
        .kind(),
        ErrorKind::SchemaMismatch
    );
    let err = HandCountReportBody::new(&PaperCountParts {
        invalid: MAX_TALLY_COUNT + 1,
        ..parts
    })
    .unwrap_err();
    assert_eq!((err.kind(), err.offset()), (ErrorKind::ValueOutOfRange, 0));
    assert!(
        HandCountReportBody::new(&PaperCountParts {
            invalid: MAX_TALLY_COUNT,
            ..parts
        })
        .is_ok()
    );
    let votes_at = HEADER_LEN + 16 + 12 + 13;
    let at = |b: &[u8]| kind_of::<HandCountReportBody<'_>>(SCHEMA_HAND_COUNT_REPORT_BODY, b);
    let mut b = bytes.clone();
    b[votes_at + 4..votes_at + 12].copy_from_slice(&(MAX_TALLY_COUNT + 1).to_be_bytes());
    assert_eq!(at(&b), (ErrorKind::ValueOutOfRange, votes_at + 4));
    let mut b = bytes[..votes_at].to_vec();
    b.extend_from_slice(&0u32.to_be_bytes());
    b.extend_from_slice(&[0u8; 16]);
    let n = u32::try_from(b.len() - HEADER_LEN).unwrap();
    b[12..16].copy_from_slice(&n.to_be_bytes());
    assert_eq!(at(&b), (ErrorKind::InvariantViolation, votes_at));
}

fn esig(
    id: &'static [u8],
    role: EventRole,
    o: &'static [u8],
    s: &'static [u8; HYBRID_SIG_LEN],
) -> EventSig<'static> {
    EventSig {
        signer_id: SignerId::new(id).unwrap(),
        role,
        org_id: OrgId::new(o).unwrap(),
        sig: s,
    }
}

#[test]
fn each_audit_body_has_its_signers() {
    let committee = esig(b"committee", EventRole::Committee, b"IVC", &SIG_A);
    let obs_a = esig(b"obs-a", EventRole::Observer, b"PARTY-A", &SIG_B);
    let obs_b = esig(b"obs-b", EventRole::Observer, b"PARTY-B", &SIG_C);
    let obs_a2 = esig(b"obs-c", EventRole::Observer, b"PARTY-A", &SIG_C);
    let aud_1 = esig(b"aud-1", EventRole::Auditor, b"AUDIT-A", &SIG_D);
    let aud_2 = esig(b"aud-2", EventRole::Auditor, b"AUDIT-B", &SIG_E);
    let aud_1b = esig(b"aud-3", EventRole::Auditor, b"AUDIT-A", &SIG_E);
    let chair = esig(b"chair", EventRole::Chair, b"NEC-11", &SIG_A);
    let clerk = esig(b"clerk", EventRole::Clerk, b"NEC-11", &SIG_A);
    let commission = esig(b"commission", EventRole::Commission, b"NEC", &SIG_A);
    let ok = |schema: SchemaId, sigs: &[EventSig<'static>]| {
        roles_satisfied(schema, || sigs.iter().copied())
    };
    for schema in [
        SCHEMA_AUDIT_FREEZE_BODY,
        SCHEMA_AUDIT_COMMIT_BODY,
        SCHEMA_AUDIT_SEED_BODY,
    ] {
        assert!(ok(schema, &[committee, obs_a, obs_b]));
        assert!(ok(schema, &[committee, obs_a, obs_a2, obs_b]));
        assert!(!ok(schema, &[obs_a, obs_b]), "no committee");
        assert!(!ok(schema, &[committee, obs_a, obs_a2]), "one organisation");
        assert!(!ok(schema, &[commission, obs_a, obs_b]), "the commission");
        assert!(!ok(schema, &[committee, aud_1, obs_a, obs_b]), "an auditor");
        assert!(!ok(schema, &[committee, clerk, obs_a, obs_b]), "a clerk");
    }
    for schema in [SCHEMA_SAMPLE_COMPARISON_BODY, SCHEMA_AUDIT_FINDING_BODY] {
        assert!(ok(schema, &[aud_1, aud_2, obs_a, obs_b]));
        assert!(ok(schema, &[aud_1, aud_1b, aud_2, obs_a, obs_a2, obs_b]));
        assert!(
            !ok(schema, &[aud_1, aud_1b, obs_a, obs_b]),
            "one auditor org"
        );
        assert!(
            !ok(schema, &[aud_1, aud_2, obs_a, obs_a2]),
            "one observer org"
        );
        assert!(!ok(schema, &[aud_1, aud_2]), "no observer");
        assert!(!ok(schema, &[obs_a, obs_b]), "no auditor");
        for other in [committee, chair, clerk, commission] {
            assert!(!ok(schema, &[aud_1, aud_2, obs_a, obs_b, other]));
        }
    }
    assert!(ok(SCHEMA_HAND_COUNT_REPORT_BODY, &[chair, obs_a, obs_b]));
    assert!(!ok(SCHEMA_HAND_COUNT_REPORT_BODY, &[obs_a, obs_b]));
    assert!(!ok(
        SCHEMA_HAND_COUNT_REPORT_BODY,
        &[chair, aud_1, obs_a, obs_b]
    ));
    // The auditor signs nothing else.
    for schema in WITNESSED_BODY_SCHEMAS {
        if schema != SCHEMA_SAMPLE_COMPARISON_BODY && schema != SCHEMA_AUDIT_FINDING_BODY {
            assert!(!roles_satisfied(schema, || [aud_1, aud_2, obs_a, obs_b].into_iter()));
        }
    }
    // A comparison in its envelope round trips.
    let body = leak(encode_to_vec(
        SCHEMA_SAMPLE_COMPARISON_BODY,
        SCHEMA_VERSION_1,
        &SampleComparisonBody::new(&comparison_parts(ComparisonCode::BlankValid)).unwrap(),
    ));
    let event = WitnessedEvent::new(body, &[aud_1, aud_2, obs_a, obs_b]).unwrap();
    assert_eq!(event.purpose(), PURPOSE_SAMPLE_COMPARISON);
    let bytes = encode_to_vec(SCHEMA_WITNESSED_EVENT, SCHEMA_VERSION_WITNESSED, &event);
    let back: WitnessedEvent<'_> =
        decode_object(SCHEMA_WITNESSED_EVENT, SCHEMA_VERSION_WITNESSED, &bytes).unwrap();
    assert_eq!(back, event);
    assert_eq!(
        back.body::<SampleComparisonBody<'_>>(SCHEMA_SAMPLE_COMPARISON_BODY)
            .unwrap()
            .parts()
            .code,
        ComparisonCode::BlankValid
    );
    // A body error inside the envelope is reported at its place.
    let mut b = bytes;
    let code_at = HEADER_LEN + 16 + 13 + 64 + 64 + ident_len(b"BOX-11-0042");
    b[HEADER_LEN + 4 + code_at] = 9;
    assert_eq!(
        kind_of::<WitnessedEvent<'_>>(SCHEMA_WITNESSED_EVENT, &b),
        (ErrorKind::ValueOutOfRange, HEADER_LEN + 4 + code_at)
    );
    // Every audit body validates in the envelope.
    let freeze = leak(freeze_bytes(&freeze_parts()));
    assert!(WitnessedEvent::new(freeze, &[committee, obs_a, obs_b]).is_ok());
    let seed = leak(encode_to_vec(
        SCHEMA_AUDIT_SEED_BODY,
        SCHEMA_VERSION_1,
        &AuditSeedBody::new(&seed_parts()).unwrap(),
    ));
    assert!(WitnessedEvent::new(seed, &[committee, obs_a, obs_b]).is_ok());
    let finding = leak(encode_to_vec(
        SCHEMA_AUDIT_FINDING_BODY,
        SCHEMA_VERSION_1,
        &AuditFindingBody::new(&finding_parts()).unwrap(),
    ));
    assert!(WitnessedEvent::new(finding, &[aud_1, aud_2, obs_a, obs_b]).is_ok());
    let hand = leak(encode_to_vec(
        SCHEMA_HAND_COUNT_REPORT_BODY,
        SCHEMA_VERSION_1,
        &HandCountReportBody::new(&hand_parts(&[1, 2])).unwrap(),
    ));
    assert!(WitnessedEvent::new(hand, &[chair, obs_a, obs_b]).is_ok());
    let mut broken = freeze.to_vec();
    broken[RULE_AT..RULE_AT + 64].fill(0);
    let err = WitnessedEvent::new(leak(broken), &[committee, obs_a, obs_b]).unwrap_err();
    assert_eq!(
        (err.kind(), err.offset()),
        (ErrorKind::InvalidPreviousHash, RULE_AT)
    );
}

#[test]
fn rounds_decode_alone() {
    let r = rounds();
    let mut buf = std::vec![0u8; r.encoded_len()];
    r.encode(&mut ityv_encoding::Writer::new(&mut buf)).unwrap();
    assert_eq!(buf.len(), 4 + 2 * 12);
    let back = AuditRounds::decode(&mut Reader::new(&buf)).unwrap();
    assert_eq!(back, r);
}

fn ident_strategy() -> impl Strategy<Value = Vec<u8>> {
    common::ident_bytes(64)
}

proptest! {
    /// Every valid freeze survives a round trip.
    #[test]
    fn freeze_round_trip(
        style_id in ident_strategy(),
        count in 0..=MAX_TALLY_COUNT,
        root in common::hash64(),
        risk in 1..=MAX_RISK_LIMIT_PPM,
        beacon_round in any::<u64>(),
        sizes in prop::collection::btree_set(1..=MAX_TALLY_COUNT, 1..=MAX_AUDIT_ROUNDS),
        threshold in 0u32..1_000,
        bucket in any::<u64>(),
    ) {
        let list: Vec<AuditRound> = sizes
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let below = u32::try_from(*s - 1).unwrap_or(u32::MAX);
                round(*s, (threshold + u32::try_from(i).unwrap()).min(below))
            })
            .collect();
        let parts = AuditFreezeParts {
            ballot_style_id: BallotStyleId::new(leak(style_id)).unwrap(),
            frame_count: count,
            frame_root: Hash512(root),
            risk_limit_ppm: risk,
            beacon_round,
            rounds: AuditRounds::new(&list).unwrap(),
            time_bucket: TimeBucket::new(bucket),
            ..freeze_parts()
        };
        let bytes = freeze_bytes(&parts);
        let back: AuditManifestFreezeBody<'_> =
            decode_object(SCHEMA_AUDIT_FREEZE_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back.parts(), &parts);
        prop_assert_eq!(back.parts().rounds.as_slice(), list.as_slice());
    }

    /// Every valid seed survives a round trip.
    #[test]
    fn seed_round_trip(
        dice in 1u8..=255,
        value in common::hash64(),
        seed in common::hash64(),
        beacon_round in any::<u64>(),
        bucket in any::<u64>(),
    ) {
        let parts = AuditSeedParts {
            dice_hash: h(dice),
            beacon_round,
            beacon_value: Hash512(value),
            seed: Hash512(seed),
            time_bucket: TimeBucket::new(bucket),
            ..seed_parts()
        };
        let body = AuditSeedBody::new(&parts).unwrap();
        let bytes = encode_to_vec(SCHEMA_AUDIT_SEED_BODY, SCHEMA_VERSION_1, &body);
        let back: AuditSeedBody<'_> =
            decode_object(SCHEMA_AUDIT_SEED_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back.parts(), &parts);
    }

    /// Every valid commit survives a round trip.
    #[test]
    fn commit_round_trip(
        dice in 1u8..=255,
        source in 1u8..=255,
        freezes in 1u8..=255,
        beacon_round in any::<u64>(),
        bucket in any::<u64>(),
    ) {
        let parts = AuditCommitParts {
            dice_hash: h(dice),
            beacon_source: h(source),
            beacon_round,
            freezes_root: h(freezes),
            time_bucket: TimeBucket::new(bucket),
            ..commit_parts()
        };
        let body = AuditCommitBody::new(&parts).unwrap();
        let bytes = encode_to_vec(SCHEMA_AUDIT_COMMIT_BODY, SCHEMA_VERSION_1, &body);
        let back: AuditCommitBody<'_> =
            decode_object(SCHEMA_AUDIT_COMMIT_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back.parts(), &parts);
    }

    /// Every valid opening survives a round trip.
    #[test]
    fn sample_opening_round_trip(
        option in 0u16..=63,
        cid in any::<[u8; 24]>(),
        chunks in 1usize..=8,
        record in common::hash64(),
    ) {
        let r = rand(chunks);
        let parts = SampleOpeningParts {
            election_id: e(),
            ballot_style_id: style(),
            record_hash: Hash512(record),
            option_index: option,
            cast_id: Token192(cid),
            rand: &r,
        };
        let body = SampleOpeningBody::new(&parts).unwrap();
        let bytes = encode_to_vec(SCHEMA_SAMPLE_OPENING_BODY, SCHEMA_VERSION_1, &body);
        let back: SampleOpeningBody<'_> =
            decode_object(SCHEMA_SAMPLE_OPENING_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back, body);
    }

    /// Every valid comparison, reference and finding survives a round trip.
    #[test]
    fn per_record_round_trips(
        code in 0u8..=6,
        mark in any::<bool>(),
        record in common::hash64(),
        opening in 1u8..=255,
        device_id in ident_strategy(),
        bucket in any::<u64>(),
    ) {
        let device_id = BoxId::new(leak(device_id)).unwrap();
        let parts = SampleComparisonParts {
            record_hash: Hash512(record),
            opening_hash: h(opening),
            device_id,
            code: ComparisonCode::from_code(code).unwrap(),
            transfer_mark: mark,
            ..comparison_parts(ComparisonCode::Match)
        };
        let body = SampleComparisonBody::new(&parts).unwrap();
        let bytes = encode_to_vec(SCHEMA_SAMPLE_COMPARISON_BODY, SCHEMA_VERSION_1, &body);
        let back: SampleComparisonBody<'_> =
            decode_object(SCHEMA_SAMPLE_COMPARISON_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back.parts(), &parts);
        let parts = SampleOpeningRefParts {
            record_hash: Hash512(record),
            opening_hash: h(opening),
            ..ref_parts()
        };
        let body = SampleOpeningRefBody::new(&parts).unwrap();
        let bytes = encode_to_vec(SCHEMA_SAMPLE_OPENING_REF_BODY, SCHEMA_VERSION_1, &body);
        let back: SampleOpeningRefBody<'_> =
            decode_object(SCHEMA_SAMPLE_OPENING_REF_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back.parts(), &parts);
        let parts = AuditFindingParts {
            device_id,
            finding_hash: h(opening),
            time_bucket: TimeBucket::new(bucket),
            ..finding_parts()
        };
        let body = AuditFindingBody::new(&parts).unwrap();
        let bytes = encode_to_vec(SCHEMA_AUDIT_FINDING_BODY, SCHEMA_VERSION_1, &body);
        let back: AuditFindingBody<'_> =
            decode_object(SCHEMA_AUDIT_FINDING_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back.parts(), &parts);
    }

    /// Every valid hand count survives a round trip.
    #[test]
    fn hand_count_round_trip(
        votes in prop::collection::vec(0..=MAX_TALLY_COUNT, 1..=MAX_CANDIDATES),
        invalid in 0..=MAX_TALLY_COUNT,
        bucket in any::<u64>(),
    ) {
        let parts = PaperCountParts {
            invalid,
            time_bucket: TimeBucket::new(bucket),
            ..hand_parts(&votes)
        };
        let body = HandCountReportBody::new(&parts).unwrap();
        let bytes = encode_to_vec(SCHEMA_HAND_COUNT_REPORT_BODY, SCHEMA_VERSION_1, &body);
        let back: HandCountReportBody<'_> =
            decode_object(SCHEMA_HAND_COUNT_REPORT_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back.parts(), &parts);
    }
}
