//! Construction, invariant and round-trip tests for the three exemplar
//! schemas.
// Integration-test crate: outside the TCB. Test code expresses "this must
// hold" with unwrap/expect/panic/indexing and does small arithmetic on test
// sizes, so those restriction lints are relaxed for this file only. No TCB
// crate may do this (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
)]

mod common;

use common::encode_to_vec;
use ityv_encoding::{
    CheckpointBody, CheckpointParts, Day, ElectionId, Encode as _, ErrorKind, Hash512, KeysetId,
    LedgerFrame, LedgerId, LegalAuthorizationBody, MAX_SCOPES, SCHEMA_CHECKPOINT_BODY,
    SCHEMA_LEDGER_FRAME, SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, SchemaId, Scope, ScopeSet,
    Seq, TimeBucket, TreeSize, decode_object,
};

fn parts(seq: u64, previous: Hash512) -> CheckpointParts<'static> {
    CheckpointParts {
        election_id: ElectionId::new(b"KR-2030-PRES").unwrap(),
        ledger_id: LedgerId::new(b"L1").unwrap(),
        keyset_id: KeysetId::new(b"K1").unwrap(),
        checkpoint_seq: Seq::new(seq).unwrap(),
        tree_size: TreeSize::new(12_345),
        root_hash: Hash512([1; 64]),
        previous_checkpoint_hash: previous,
        box_close_root: Hash512([2; 64]),
        dispute_root: Hash512([3; 64]),
        genesis_hash: Hash512([4; 64]),
        time_bucket: TimeBucket::new(99),
    }
}

#[test]
fn ledger_frame_round_trip_and_length() {
    let frame = LedgerFrame::new(
        ElectionId::new(b"E").unwrap(),
        Seq::new(7).unwrap(),
        Hash512([5; 64]),
        SchemaId::new(0x0005),
        Hash512([6; 64]),
    );
    assert_eq!(frame.encoded_len(), 5 + 8 + 64 + 4 + 64);
    let bytes = encode_to_vec(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &frame);
    let decoded: LedgerFrame<'_> =
        decode_object(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(decoded, frame);
    assert_eq!(decoded.seq().get(), 7);
    assert_eq!(decoded.event_schema_id().get(), 5);
    assert_eq!(decoded.prev_hash(), &Hash512([5; 64]));
    assert_eq!(decoded.event_hash(), &Hash512([6; 64]));
    assert_eq!(decoded.election_id().as_bytes(), b"E");
}

#[test]
fn ledger_frame_rejects_zero_seq_at_field_offset() {
    let frame = LedgerFrame::new(
        ElectionId::new(b"E").unwrap(),
        Seq::new(7).unwrap(),
        Hash512::ZERO,
        SchemaId::new(1),
        Hash512::ZERO,
    );
    let mut bytes = encode_to_vec(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &frame);
    // header 16 + ident (4 + 1) = 21 is where seq starts.
    bytes[21..29].copy_from_slice(&[0; 8]);
    let e = decode_object::<LedgerFrame<'_>>(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &bytes)
        .unwrap_err();
    assert_eq!((e.kind(), e.offset()), (ErrorKind::ValueOutOfRange, 21));
}

#[test]
fn scope_codes_are_exactly_one_to_nine() {
    for code in 0u8..=255 {
        let scope = Scope::from_code(code);
        assert_eq!(scope.is_some(), (1..=9).contains(&code), "code {code}");
        if let Some(s) = scope {
            assert_eq!(s.code(), code);
        }
    }
    assert_eq!(Scope::ALL.len(), 9);
    assert!(Scope::ALL.windows(2).all(|w| w[0].code() < w[1].code()));
}

#[test]
fn scope_set_is_canonical_regardless_of_insertion_order() {
    let a = ScopeSet::from_slice(&[Scope::VoterCode, Scope::Rla, Scope::Rla, Scope::PublicBoard]);
    let b = ScopeSet::from_slice(&[Scope::PublicBoard, Scope::Rla, Scope::VoterCode]);
    assert_eq!(a, b);
    assert_eq!(a.len(), 3);
    assert!(!a.is_empty());
    assert!(ScopeSet::empty().is_empty());
    let codes: std::vec::Vec<u8> = a.iter().map(Scope::code).collect();
    assert_eq!(codes, std::vec![1, 5, 9]);
    assert!(a.contains(Scope::Rla));
    assert!(!a.contains(Scope::TrusteeBody));
    assert_eq!(a.encoded_len(), 4 + 3);
}

fn authorization(
    scopes: ScopeSet,
    from: u64,
    until: u64,
) -> Option<LegalAuthorizationBody<'static>> {
    LegalAuthorizationBody::new(
        ElectionId::new(b"KR-2030-PRES").unwrap(),
        scopes,
        Hash512([0x5a; 64]),
        Day::new(from),
        Day::new(until),
    )
}

#[test]
fn authorization_round_trip_and_invariants() {
    let body = authorization(
        ScopeSet::from_slice(&[Scope::PublicBoard, Scope::TrusteeBody]),
        10,
        20,
    )
    .unwrap();
    assert_eq!(body.encoded_len(), (4 + 12) + (4 + 2) + 64 + 8 + 8);
    let bytes = encode_to_vec(SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, &body);
    let decoded: LegalAuthorizationBody<'_> =
        decode_object(SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(decoded, body);
    assert_eq!(decoded.effective_from_day().get(), 10);
    assert_eq!(decoded.effective_until_day().get(), 20);
    assert_eq!(decoded.statute_refs_hash(), &Hash512([0x5a; 64]));
    assert!(decoded.scopes().contains(Scope::TrusteeBody));

    assert!(
        authorization(ScopeSet::empty(), 5, 5).is_some(),
        "equal days are allowed"
    );
    assert!(
        authorization(ScopeSet::empty(), 6, 5).is_none(),
        "until before from is rejected"
    );
}

#[test]
fn authorization_decoding_rejects_bad_scope_arrays_and_day_order() {
    let body = authorization(
        ScopeSet::from_slice(&[Scope::BallotMark, Scope::Rla]),
        10,
        20,
    )
    .unwrap();
    let base = encode_to_vec(SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, &body);
    // header 16 + ident (4 + 12) = 32 is where the scopes count starts; codes at 36, 37.
    let decode = |b: &[u8]| {
        decode_object::<LegalAuthorizationBody<'_>>(SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, b)
            .map(|_| ())
    };

    let mut unknown = base.clone();
    unknown[37] = 10;
    let e = decode(&unknown).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (ErrorKind::InvalidScopeCode, 37));

    let mut zero = base.clone();
    zero[36] = 0;
    let e = decode(&zero).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (ErrorKind::InvalidScopeCode, 36));

    let mut duplicate = base.clone();
    duplicate[37] = 3;
    let e = decode(&duplicate).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (ErrorKind::Duplicate, 37));

    let mut unsorted = base.clone();
    unsorted[36] = 5;
    unsorted[37] = 3;
    let e = decode(&unsorted).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (ErrorKind::NotSorted, 37));

    let mut too_many = base.clone();
    too_many[32..36].copy_from_slice(&(u32::try_from(MAX_SCOPES).unwrap() + 1).to_be_bytes());
    let e = decode(&too_many).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (ErrorKind::CountExceedsMax, 32));

    // Days: from at 38 + 64 = 102, until at 110.
    let mut reversed = base.clone();
    reversed[102..110].copy_from_slice(&21u64.to_be_bytes());
    let e = decode(&reversed).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (ErrorKind::ValueOutOfRange, 110));
}

#[test]
fn checkpoint_invariant_links_previous_hash_and_seq() {
    assert!(CheckpointBody::new(&parts(1, Hash512::ZERO)).is_some());
    assert!(CheckpointBody::new(&parts(2, Hash512([9; 64]))).is_some());
    assert!(
        CheckpointBody::new(&parts(1, Hash512([9; 64]))).is_none(),
        "first must be zero"
    );
    assert!(
        CheckpointBody::new(&parts(2, Hash512::ZERO)).is_none(),
        "later must be non-zero"
    );
}

#[test]
fn checkpoint_round_trip_and_rejection_offsets() {
    let body = CheckpointBody::new(&parts(2, Hash512([9; 64]))).unwrap();
    assert_eq!(
        body.encoded_len(),
        (4 + 12) + (4 + 2) + (4 + 2) + 8 + 8 + 64 * 5 + 8
    );
    let bytes = encode_to_vec(SCHEMA_CHECKPOINT_BODY, SCHEMA_VERSION_1, &body);
    let decoded: CheckpointBody<'_> =
        decode_object(SCHEMA_CHECKPOINT_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(decoded, body);
    assert_eq!(decoded.parts().tree_size.get(), 12_345);

    // Offsets: header 16, election 16, ledger 6, keyset 6 -> seq at 44,
    // tree_size 52, root 60, previous 124.
    let mut zero_previous = bytes.clone();
    zero_previous[124..188].copy_from_slice(&[0; 64]);
    let e = decode_object::<CheckpointBody<'_>>(
        SCHEMA_CHECKPOINT_BODY,
        SCHEMA_VERSION_1,
        &zero_previous,
    )
    .unwrap_err();
    assert_eq!(
        (e.kind(), e.offset()),
        (ErrorKind::InvalidPreviousHash, 124)
    );

    let mut zero_seq = bytes.clone();
    zero_seq[44..52].copy_from_slice(&[0; 8]);
    let e =
        decode_object::<CheckpointBody<'_>>(SCHEMA_CHECKPOINT_BODY, SCHEMA_VERSION_1, &zero_seq)
            .unwrap_err();
    assert_eq!((e.kind(), e.offset()), (ErrorKind::ValueOutOfRange, 44));
}
