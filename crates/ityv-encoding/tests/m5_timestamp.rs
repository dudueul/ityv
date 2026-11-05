//! External timestamps (ENCODING.md §8.74, §8.75; ADR-0034, ADR-0039): the
//! genesis entry `TimestampAuthorityEntry` (0x0050, set 12) and the ledger
//! event `TimestampRecord` (0x004F). Round trips, the constructors' rules
//! (the same as the decoders'), every decoder rule at its offset, the
//! published vector files, the target schemas (VC-117) and property tests.
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

use common::{Vector, check_file, encode_to_vec, ident_len, render, self_check};
use ityv_encoding::{
    AuthorityId, Decode, ElectionId, Encode, EntrySet, ErrorKind, GenesisEntry, HEADER_LEN,
    Hash512, MAX_PIN_LEN, MAX_POLICY_ACCURACY_MS, MAX_TIMESTAMP_TOKEN_LEN, MAX_TSA_PINS, OrgId,
    PolicyAccuracy, SCHEMA_TIMESTAMP_AUTHORITY_ENTRY, SCHEMA_TIMESTAMP_RECORD, SCHEMA_VERSION_1,
    SchemaId, TIMESTAMP_TARGET_SCHEMAS, TimestampAuthorityEntry, TimestampAuthorityKind,
    TimestampPins, TimestampRecord, TimestampRecordParts, decode_object, schema_version,
    timestamp_target_allowed,
};
use proptest::prelude::*;
use std::vec::Vec;

fn e() -> ElectionId<'static> {
    ElectionId::new(b"KR-2030-PRES").unwrap()
}

fn tsa() -> AuthorityId<'static> {
    AuthorityId::new(b"TSA-GPKI-1").unwrap()
}

fn operator() -> OrgId<'static> {
    OrgId::new(b"MOIS-GPKI").unwrap()
}

fn patterned(seed: u8) -> Hash512 {
    common::patterned64(seed)
}

static PIN_A: [u8; 48] = [0x01; 48];
static PIN_B: [u8; 60] = [0x02; 60];

fn pins() -> TimestampPins<'static> {
    TimestampPins::new(&[&PIN_A, &PIN_B]).unwrap()
}

fn entry() -> TimestampAuthorityEntry<'static> {
    TimestampAuthorityEntry {
        tsa_id: tsa(),
        operator: operator(),
        kind: TimestampAuthorityKind::Government,
        policy_accuracy: PolicyAccuracy::from_millis(500).unwrap(),
        pins: pins(),
    }
}

static TOKEN: [u8; 32] = [0x30; 32];

fn record_parts() -> TimestampRecordParts<'static> {
    TimestampRecordParts {
        election_id: e(),
        target_schema: SchemaId::new(0x0010),
        target_hash: patterned(0x40),
        authority_id: tsa(),
        token: Some(&TOKEN),
    }
}

fn record() -> TimestampRecord<'static> {
    TimestampRecord::new(&record_parts()).unwrap()
}

fn round_trip<'a, T: Encode + Decode<'a> + PartialEq + core::fmt::Debug>(
    schema: SchemaId,
    value: &T,
    buf: &'a mut Vec<u8>,
) -> T {
    *buf = encode_to_vec(schema, SCHEMA_VERSION_1, value);
    let back: T = decode_object(schema, SCHEMA_VERSION_1, buf).unwrap();
    back
}

fn kind_at<'a, T: Decode<'a>>(schema: SchemaId, bytes: &'a [u8]) -> (ErrorKind, usize) {
    let e = decode_object::<T>(schema, SCHEMA_VERSION_1, bytes)
        .map(drop)
        .unwrap_err();
    (e.kind(), e.offset())
}

fn fix_len(v: &mut [u8]) {
    let body_len = u32::try_from(v.len() - HEADER_LEN).unwrap();
    v[12..16].copy_from_slice(&body_len.to_be_bytes());
}

#[test]
fn both_schemas_are_version_1_and_registered() {
    assert_eq!(schema_version(SCHEMA_TIMESTAMP_RECORD), 1);
    assert_eq!(schema_version(SCHEMA_TIMESTAMP_AUTHORITY_ENTRY), 1);
    assert_eq!(SCHEMA_TIMESTAMP_RECORD.get(), 0x004F);
    assert_eq!(SCHEMA_TIMESTAMP_AUTHORITY_ENTRY.get(), 0x0050);
    assert_eq!(
        EntrySet::TimestampAuthorities.schema(),
        Some(SCHEMA_TIMESTAMP_AUTHORITY_ENTRY)
    );
    assert_eq!(EntrySet::TimestampAuthorities.code(), 12);
    assert_eq!(EntrySet::TimestampAuthorities.index(), 11);
    assert!(!EntrySet::TimestampAuthorities.amendable());
    assert_eq!(EntrySet::TimestampAuthorities.version(), 1);
    assert_eq!(EntrySet::ALL.last(), Some(&EntrySet::TimestampAuthorities));
    assert_eq!(
        <TimestampAuthorityEntry<'_> as GenesisEntry<'_>>::SET,
        EntrySet::TimestampAuthorities
    );
}

#[test]
fn an_authority_round_trips_and_is_keyed_by_its_id() {
    let entry = entry();
    let mut buf = Vec::new();
    assert_eq!(
        round_trip(SCHEMA_TIMESTAMP_AUTHORITY_ENTRY, &entry, &mut buf),
        entry
    );
    assert_eq!(entry.key(), b"TSA-GPKI-1");
    assert_eq!(entry.pins.len(), 2);
    assert!(!entry.pins.is_empty());
    assert_eq!(
        entry.pins.iter().collect::<Vec<_>>(),
        [PIN_A.as_slice(), PIN_B.as_slice()]
    );
    assert_eq!(
        buf.len(),
        HEADER_LEN
            + ident_len(b"TSA-GPKI-1")
            + ident_len(b"MOIS-GPKI")
            + 1
            + 4
            + 4
            + 4
            + 48
            + 4
            + 60
    );
    for kind in [
        TimestampAuthorityKind::Government,
        TimestampAuthorityKind::NonGovernment,
    ] {
        let other = TimestampAuthorityEntry { kind, ..entry };
        let mut buf = Vec::new();
        assert_eq!(
            round_trip(SCHEMA_TIMESTAMP_AUTHORITY_ENTRY, &other, &mut buf),
            other
        );
    }
}

#[test]
fn pins_and_accuracy_follow_their_rules() {
    assert_eq!(
        PolicyAccuracy::from_millis(MAX_POLICY_ACCURACY_MS).map(PolicyAccuracy::millis),
        Some(3_600_000)
    );
    assert_eq!(
        PolicyAccuracy::from_millis(MAX_POLICY_ACCURACY_MS + 1),
        None
    );
    assert_eq!(
        PolicyAccuracy::from_millis(0).map(PolicyAccuracy::millis),
        Some(0)
    );
    assert!(TimestampPins::new(&[]).is_none());
    assert!(TimestampPins::new(&[&[]]).is_none());
    assert!(TimestampPins::new(&[&PIN_B, &PIN_A]).is_none());
    assert!(TimestampPins::new(&[&PIN_A, &PIN_A]).is_none());
    let long = std::vec![0x01u8; MAX_PIN_LEN + 1];
    assert!(TimestampPins::new(&[&long]).is_none());
    let longest = std::vec![0x01u8; MAX_PIN_LEN];
    assert_eq!(TimestampPins::new(&[&longest]).map(|p| p.len()), Some(1));
    let four: [&[u8]; 4] = [&[1], &[2], &[3], &[4]];
    assert_eq!(TimestampPins::new(&four).map(|p| p.len()), Some(4));
    let five: [&[u8]; 5] = [&[1], &[2], &[3], &[4], &[5]];
    assert!(TimestampPins::new(&five).is_none());
    assert_eq!(MAX_TSA_PINS, 4);
}

#[test]
fn a_record_round_trips_with_and_without_a_token() {
    let record = record();
    let mut buf = Vec::new();
    assert_eq!(
        round_trip(SCHEMA_TIMESTAMP_RECORD, &record, &mut buf),
        record
    );
    assert_eq!(record.parts(), &record_parts());
    assert_eq!(
        buf.len(),
        HEADER_LEN + ident_len(b"KR-2030-PRES") + 4 + 64 + ident_len(b"TSA-GPKI-1") + 1 + 4 + 32
    );
    let unanswered = TimestampRecord::new(&TimestampRecordParts {
        token: None,
        ..record_parts()
    })
    .unwrap();
    let mut buf = Vec::new();
    assert_eq!(
        round_trip(SCHEMA_TIMESTAMP_RECORD, &unanswered, &mut buf),
        unanswered
    );
    for target in TIMESTAMP_TARGET_SCHEMAS {
        let r = TimestampRecord::new(&TimestampRecordParts {
            target_schema: target,
            ..record_parts()
        })
        .unwrap();
        let mut buf = Vec::new();
        assert_eq!(round_trip(SCHEMA_TIMESTAMP_RECORD, &r, &mut buf), r);
    }
    let longest = std::vec![0x30u8; MAX_TIMESTAMP_TOKEN_LEN];
    let r = TimestampRecord::new(&TimestampRecordParts {
        token: Some(&longest),
        ..record_parts()
    })
    .unwrap();
    let mut buf = Vec::new();
    assert_eq!(round_trip(SCHEMA_TIMESTAMP_RECORD, &r, &mut buf), r);
}

#[test]
fn a_record_stamps_only_checkpoints_genesis_and_witnessed_events() {
    // VC-117: never a cast record (0x0016), a check-in counter (0x0009) or a
    // progress tick (0x0031), nor anything else.
    for raw in 0u32..=0x0200 {
        let schema = SchemaId::new(raw);
        let expected = matches!(raw, 0x0010 | 0x0028 | 0x0033);
        assert_eq!(timestamp_target_allowed(schema), expected, "{raw:#06x}");
        let built = TimestampRecord::new(&TimestampRecordParts {
            target_schema: schema,
            ..record_parts()
        });
        assert_eq!(built.is_ok(), expected, "{raw:#06x}");
    }
    assert!(!timestamp_target_allowed(SchemaId::new(u32::MAX)));
    let zero = TimestampRecord::new(&TimestampRecordParts {
        target_hash: Hash512::ZERO,
        ..record_parts()
    });
    assert!(zero.is_err());
    let empty = TimestampRecord::new(&TimestampRecordParts {
        token: Some(&[]),
        ..record_parts()
    });
    assert!(empty.is_err());
    let long = std::vec![0x30u8; MAX_TIMESTAMP_TOKEN_LEN + 1];
    let long = TimestampRecord::new(&TimestampRecordParts {
        token: Some(&long),
        ..record_parts()
    });
    assert!(long.is_err());
}

fn valid(label: &'static str, bytes: Vec<u8>) -> Vector {
    Vector {
        label,
        bytes,
        expected: None,
    }
}

fn invalid(label: &'static str, bytes: Vec<u8>, kind: &'static str, offset: usize) -> Vector {
    Vector {
        label,
        bytes,
        expected: Some((kind, offset)),
    }
}

fn authority_vectors() -> Vec<Vector> {
    let bytes = encode_to_vec(SCHEMA_TIMESTAMP_AUTHORITY_ENTRY, SCHEMA_VERSION_1, &entry());
    let kind_at = HEADER_LEN + ident_len(b"TSA-GPKI-1") + ident_len(b"MOIS-GPKI");
    let accuracy_at = kind_at + 1;
    let pins_at = accuracy_at + 4;
    let first_pin = pins_at + 4;
    let second_pin = first_pin + 4 + PIN_A.len();
    let mut v = std::vec![valid("government, two pins", bytes.clone())];
    let other = TimestampAuthorityEntry {
        kind: TimestampAuthorityKind::NonGovernment,
        policy_accuracy: PolicyAccuracy::from_millis(MAX_POLICY_ACCURACY_MS).unwrap(),
        pins: TimestampPins::new(&[&PIN_A]).unwrap(),
        ..entry()
    };
    v.push(valid(
        "non-government, one pin, one hour",
        encode_to_vec(SCHEMA_TIMESTAMP_AUTHORITY_ENTRY, SCHEMA_VERSION_1, &other),
    ));
    let mut b = bytes.clone();
    b[kind_at] = 3;
    v.push(invalid("kind 3", b, "ValueOutOfRange", kind_at));
    let mut b = bytes.clone();
    b[kind_at] = 0;
    v.push(invalid("kind 0", b, "ValueOutOfRange", kind_at));
    let mut b = bytes.clone();
    b[accuracy_at..accuracy_at + 4].copy_from_slice(&(MAX_POLICY_ACCURACY_MS + 1).to_be_bytes());
    v.push(invalid(
        "accuracy above an hour",
        b,
        "ValueOutOfRange",
        accuracy_at,
    ));
    // No pin: the count is zero and the pins are gone.
    let mut b = bytes[..pins_at].to_vec();
    b.extend_from_slice(&0u32.to_be_bytes());
    fix_len(&mut b);
    v.push(invalid("no pin", b, "InvariantViolation", pins_at));
    let mut b = bytes.clone();
    b[pins_at..pins_at + 4].copy_from_slice(&5u32.to_be_bytes());
    v.push(invalid("five pins", b, "CountExceedsMax", pins_at));
    // The pins swapped: out of order.
    let mut b = bytes[..first_pin].to_vec();
    b.extend_from_slice(&u32::try_from(PIN_B.len()).unwrap().to_be_bytes());
    b.extend_from_slice(&PIN_B);
    b.extend_from_slice(&u32::try_from(PIN_A.len()).unwrap().to_be_bytes());
    b.extend_from_slice(&PIN_A);
    fix_len(&mut b);
    let swapped_second = first_pin + 4 + PIN_B.len();
    v.push(invalid("pins out of order", b, "NotSorted", swapped_second));
    // The first pin twice.
    let mut b = bytes[..first_pin].to_vec();
    for _ in 0..2 {
        b.extend_from_slice(&u32::try_from(PIN_A.len()).unwrap().to_be_bytes());
        b.extend_from_slice(&PIN_A);
    }
    fix_len(&mut b);
    v.push(invalid("pin repeated", b, "Duplicate", second_pin));
    // An empty first pin.
    let mut b = bytes[..first_pin].to_vec();
    b.extend_from_slice(&0u32.to_be_bytes());
    b.extend_from_slice(&u32::try_from(PIN_B.len()).unwrap().to_be_bytes());
    b.extend_from_slice(&PIN_B);
    fix_len(&mut b);
    v.push(invalid("empty pin", b, "InvariantViolation", first_pin));
    let mut b = bytes.clone();
    b[first_pin..first_pin + 4]
        .copy_from_slice(&u32::try_from(MAX_PIN_LEN + 1).unwrap().to_be_bytes());
    v.push(invalid("pin too long", b, "LengthExceedsMax", first_pin));
    v
}

fn record_vectors() -> Vec<Vector> {
    let bytes = encode_to_vec(SCHEMA_TIMESTAMP_RECORD, SCHEMA_VERSION_1, &record());
    let schema_at = HEADER_LEN + ident_len(b"KR-2030-PRES");
    let hash_at = schema_at + 4;
    let authority_at = hash_at + 64;
    let token_at = authority_at + ident_len(b"TSA-GPKI-1");
    let mut v = std::vec![valid("token over a checkpoint", bytes.clone())];
    let unanswered = TimestampRecord::new(&TimestampRecordParts {
        target_schema: SchemaId::new(0x0033),
        token: None,
        ..record_parts()
    })
    .unwrap();
    v.push(valid(
        "no answer for a genesis",
        encode_to_vec(SCHEMA_TIMESTAMP_RECORD, SCHEMA_VERSION_1, &unanswered),
    ));
    let mut b = bytes.clone();
    b[schema_at..schema_at + 4].copy_from_slice(&0x0016u32.to_be_bytes());
    v.push(invalid("a cast record", b, "ValueOutOfRange", schema_at));
    let mut b = bytes.clone();
    b[schema_at..schema_at + 4].copy_from_slice(&0x0031u32.to_be_bytes());
    v.push(invalid("a progress tick", b, "ValueOutOfRange", schema_at));
    let mut b = bytes.clone();
    b[schema_at..schema_at + 4].copy_from_slice(&0x0009u32.to_be_bytes());
    v.push(invalid(
        "a check-in counter",
        b,
        "ValueOutOfRange",
        schema_at,
    ));
    let mut b = bytes.clone();
    b[hash_at..hash_at + 64].fill(0);
    v.push(invalid("no target", b, "InvalidPreviousHash", hash_at));
    let mut b = bytes.clone();
    b[token_at] = 2;
    v.push(invalid("presence 2", b, "InvalidPresenceTag", token_at));
    let mut b = bytes[..=token_at].to_vec();
    b.extend_from_slice(&0u32.to_be_bytes());
    fix_len(&mut b);
    v.push(invalid(
        "empty token",
        b,
        "InvariantViolation",
        token_at + 1,
    ));
    let mut b = bytes.clone();
    b[token_at + 1..token_at + 5].copy_from_slice(
        &u32::try_from(MAX_TIMESTAMP_TOKEN_LEN + 1)
            .unwrap()
            .to_be_bytes(),
    );
    v.push(invalid(
        "token too long",
        b,
        "LengthExceedsMax",
        token_at + 1,
    ));
    v
}

#[test]
fn authority_vectors_are_current_and_self_consistent() {
    let content = render(
        "TimestampAuthorityEntry",
        SCHEMA_TIMESTAMP_AUTHORITY_ENTRY,
        &authority_vectors(),
    );
    check_file("timestamp_authority_entry.txt", &content);
    self_check(&content, |b| {
        let v: TimestampAuthorityEntry<'_> =
            decode_object(SCHEMA_TIMESTAMP_AUTHORITY_ENTRY, SCHEMA_VERSION_1, b)?;
        Ok(encode_to_vec(
            SCHEMA_TIMESTAMP_AUTHORITY_ENTRY,
            SCHEMA_VERSION_1,
            &v,
        ))
    });
}

#[test]
fn record_vectors_are_current_and_self_consistent() {
    let content = render(
        "TimestampRecord",
        SCHEMA_TIMESTAMP_RECORD,
        &record_vectors(),
    );
    check_file("timestamp_record.txt", &content);
    self_check(&content, |b| {
        let v: TimestampRecord<'_> = decode_object(SCHEMA_TIMESTAMP_RECORD, SCHEMA_VERSION_1, b)?;
        Ok(encode_to_vec(SCHEMA_TIMESTAMP_RECORD, SCHEMA_VERSION_1, &v))
    });
}

#[test]
fn an_entry_is_not_a_record_and_the_reverse() {
    let entry = encode_to_vec(SCHEMA_TIMESTAMP_AUTHORITY_ENTRY, SCHEMA_VERSION_1, &entry());
    assert_eq!(
        kind_at::<TimestampRecord<'_>>(SCHEMA_TIMESTAMP_RECORD, &entry).0,
        ErrorKind::SchemaMismatch
    );
    let record = encode_to_vec(SCHEMA_TIMESTAMP_RECORD, SCHEMA_VERSION_1, &record());
    assert_eq!(
        kind_at::<TimestampAuthorityEntry<'_>>(SCHEMA_TIMESTAMP_AUTHORITY_ENTRY, &record).0,
        ErrorKind::SchemaMismatch
    );
}

fn ident_strategy() -> impl Strategy<Value = Vec<u8>> {
    common::ident_bytes(64)
}

proptest! {
    #[test]
    fn authority_entries_round_trip(
        id in ident_strategy(),
        op in ident_strategy(),
        government in any::<bool>(),
        millis in 0u32..=MAX_POLICY_ACCURACY_MS,
        raw in prop::collection::btree_set(prop::collection::vec(any::<u8>(), 1..80), 1..=4),
    ) {
        let raw: Vec<Vec<u8>> = raw.into_iter().collect();
        let refs: Vec<&[u8]> = raw.iter().map(Vec::as_slice).collect();
        let entry = TimestampAuthorityEntry {
            tsa_id: AuthorityId::new(&id).unwrap(),
            operator: OrgId::new(&op).unwrap(),
            kind: if government {
                TimestampAuthorityKind::Government
            } else {
                TimestampAuthorityKind::NonGovernment
            },
            policy_accuracy: PolicyAccuracy::from_millis(millis).unwrap(),
            pins: TimestampPins::new(&refs).unwrap(),
        };
        let bytes = encode_to_vec(SCHEMA_TIMESTAMP_AUTHORITY_ENTRY, SCHEMA_VERSION_1, &entry);
        let back: TimestampAuthorityEntry<'_> =
            decode_object(SCHEMA_TIMESTAMP_AUTHORITY_ENTRY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back, entry);
        prop_assert_eq!(
            encode_to_vec(SCHEMA_TIMESTAMP_AUTHORITY_ENTRY, SCHEMA_VERSION_1, &back),
            bytes
        );
    }

    #[test]
    fn records_round_trip(
        id in ident_strategy(),
        target in 0usize..3,
        hash in common::hash64(),
        token in prop::option::of(prop::collection::vec(any::<u8>(), 1..200)),
    ) {
        prop_assume!(hash.iter().any(|b| *b != 0));
        let record = TimestampRecord::new(&TimestampRecordParts {
            election_id: e(),
            target_schema: TIMESTAMP_TARGET_SCHEMAS[target],
            target_hash: Hash512(hash),
            authority_id: AuthorityId::new(&id).unwrap(),
            token: token.as_deref(),
        })
        .unwrap();
        let bytes = encode_to_vec(SCHEMA_TIMESTAMP_RECORD, SCHEMA_VERSION_1, &record);
        let back: TimestampRecord<'_> =
            decode_object(SCHEMA_TIMESTAMP_RECORD, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back, record);
        prop_assert_eq!(encode_to_vec(SCHEMA_TIMESTAMP_RECORD, SCHEMA_VERSION_1, &back), bytes);
    }

    #[test]
    fn decoding_arbitrary_record_bytes_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        let _ = decode_object::<TimestampRecord<'_>>(SCHEMA_TIMESTAMP_RECORD, SCHEMA_VERSION_1, &bytes);
        let _ = decode_object::<TimestampAuthorityEntry<'_>>(
            SCHEMA_TIMESTAMP_AUTHORITY_ENTRY,
            SCHEMA_VERSION_1,
            &bytes,
        );
    }
}
