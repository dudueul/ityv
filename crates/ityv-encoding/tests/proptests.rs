//! Property-based tests (verification ladder V1): round trips, canonicity
//! under single-byte mutation, and rejection of every proper prefix, for all
//! primitives and the three exemplar schemas.
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

use common::{encode_to_vec, hash64, ident_bytes, nonzero_u64};
use ityv_encoding::{
    CheckpointBody, CheckpointParts, Day, Decode, ElectionId, Encode, Hash512, KeysetId,
    LedgerFrame, LedgerId, LegalAuthorizationBody, Reader, SCHEMA_CHECKPOINT_BODY,
    SCHEMA_LEDGER_FRAME, SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, SchemaId, Scope, ScopeSet,
    Seq, TimeBucket, TreeSize, Writer, decode_object,
};
use proptest::prelude::*;

/// Byte masks applied to each position: lowest bit, highest bit, all bits.
const MASKS: [u8; 3] = [0x01, 0x80, 0xff];

/// Checks canonicity of one object encoding: every single-byte mutation is
/// either rejected or decodes to a *different* value whose canonical
/// encoding is exactly the mutated bytes. Every proper prefix is rejected.
macro_rules! check_canonical {
    ($ty:ty, $schema:expr, $bytes:expr) => {{
        let bytes: &[u8] = $bytes;
        let original: $ty = decode_object($schema, SCHEMA_VERSION_1, bytes).unwrap();
        for i in 0..bytes.len() {
            for mask in MASKS {
                let mut mutated = bytes.to_vec();
                mutated[i] ^= mask;
                let outcome: Result<$ty, _> = decode_object($schema, SCHEMA_VERSION_1, &mutated);
                if let Ok(other) = outcome {
                    prop_assert_ne!(
                        other,
                        original,
                        "mutation at {} decoded to the same value",
                        i
                    );
                    let re = encode_to_vec($schema, SCHEMA_VERSION_1, &other);
                    prop_assert_eq!(re, mutated, "re-encoding differs after mutation at {}", i);
                }
            }
        }
        for k in 0..bytes.len() {
            let prefix: Result<$ty, _> = decode_object($schema, SCHEMA_VERSION_1, &bytes[..k]);
            prop_assert!(prefix.is_err(), "proper prefix of length {} decoded", k);
        }
    }};
}

fn scope_set() -> impl Strategy<Value = ScopeSet> {
    prop::collection::vec(prop::sample::select(Scope::ALL.to_vec()), 0..=9)
        .prop_map(|v| ScopeSet::from_slice(&v))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn u64_round_trip(v in any::<u64>()) {
        let mut buf = [0u8; 8];
        let mut w = Writer::new(&mut buf);
        v.encode(&mut w).unwrap();
        prop_assert_eq!(w.finish(), 8);
        let mut r = Reader::new(&buf);
        prop_assert_eq!(u64::decode(&mut r).unwrap(), v);
        prop_assert!(r.finish().is_ok());
    }

    #[test]
    fn u32_u16_u8_round_trip(a in any::<u32>(), b in any::<u16>(), c in any::<u8>()) {
        let mut buf = [0u8; 7];
        let mut w = Writer::new(&mut buf);
        a.encode(&mut w).unwrap();
        b.encode(&mut w).unwrap();
        c.encode(&mut w).unwrap();
        let mut r = Reader::new(&buf);
        prop_assert_eq!(u32::decode(&mut r).unwrap(), a);
        prop_assert_eq!(u16::decode(&mut r).unwrap(), b);
        prop_assert_eq!(u8::decode(&mut r).unwrap(), c);
        prop_assert!(r.finish().is_ok());
    }

    #[test]
    fn bool_byte_strictness(byte in any::<u8>()) {
        let buf = [byte];
        let mut r = Reader::new(&buf);
        let decoded = bool::decode(&mut r);
        prop_assert_eq!(decoded.is_ok(), byte <= 1);
    }

    #[test]
    fn ident_round_trip(id in ident_bytes(64)) {
        let ident = ElectionId::new(&id).unwrap();
        let mut buf = [0u8; 68];
        let mut w = Writer::new(&mut buf);
        ident.encode(&mut w).unwrap();
        let len = w.finish();
        prop_assert_eq!(len, id.len() + 4);
        let mut r = Reader::new(&buf[..len]);
        prop_assert_eq!(ElectionId::decode(&mut r).unwrap(), ident);
        prop_assert!(r.finish().is_ok());
    }

    #[test]
    fn ident_rejects_any_byte_outside_alphabet(id in ident_bytes(8), pos in 0usize..8, bad in any::<u8>()) {
        prop_assume!(!ityv_encoding::Ident::is_valid_byte(bad));
        let mut id = id;
        let pos = pos % id.len();
        id[pos] = bad;
        prop_assert!(ElectionId::new(&id).is_none());
    }

    #[test]
    fn hash_round_trip(h in hash64()) {
        let value = Hash512(h);
        let mut buf = [0u8; 64];
        let mut w = Writer::new(&mut buf);
        value.encode(&mut w).unwrap();
        prop_assert_eq!(buf, h);
        let mut r = Reader::new(&buf);
        prop_assert_eq!(Hash512::decode(&mut r).unwrap(), value);
    }

    #[test]
    fn option_round_trip(v in proptest::option::of(any::<u64>())) {
        let mut buf = [0u8; 9];
        let mut w = Writer::new(&mut buf);
        v.encode(&mut w).unwrap();
        let len = w.finish();
        let mut r = Reader::new(&buf[..len]);
        prop_assert_eq!(Option::<u64>::decode(&mut r).unwrap(), v);
        prop_assert!(r.finish().is_ok());
    }

    #[test]
    fn ledger_frame_round_trip_and_canonicity(
        id in ident_bytes(64), seq in nonzero_u64(), prev in hash64(), schema in any::<u32>(), event in hash64()
    ) {
        let frame = LedgerFrame::new(
            ElectionId::new(&id).unwrap(),
            Seq::new(seq).unwrap(),
            Hash512(prev),
            SchemaId::new(schema),
            Hash512(event),
        );
        let bytes = encode_to_vec(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &frame);
        let decoded: LedgerFrame<'_> = decode_object(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(decoded, frame);
        prop_assert_eq!(encode_to_vec(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &decoded), bytes.clone());
        check_canonical!(LedgerFrame<'_>, SCHEMA_LEDGER_FRAME, &bytes);
    }

    #[test]
    fn authorization_round_trip_and_canonicity(
        id in ident_bytes(64), scopes in scope_set(), statute in hash64(), from in any::<u64>(), span in 0u64..1_000_000
    ) {
        let until = from.saturating_add(span);
        let body = LegalAuthorizationBody::new(
            ElectionId::new(&id).unwrap(), scopes, Hash512(statute), Day::new(from), Day::new(until),
        ).unwrap();
        let bytes = encode_to_vec(SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, &body);
        let decoded: LegalAuthorizationBody<'_> =
            decode_object(SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(decoded, body);
        check_canonical!(LegalAuthorizationBody<'_>, SCHEMA_LEGAL_AUTHORIZATION, &bytes);
    }

    #[test]
    fn checkpoint_round_trip_and_canonicity(
        election in ident_bytes(16), ledger in ident_bytes(16), keyset in ident_bytes(16),
        seq in nonzero_u64(), tree in any::<u64>(), root in hash64(), prev in hash64(),
        boxes in hash64(), disputes in hash64(), genesis in hash64(), bucket in any::<u64>()
    ) {
        let checkpoint_seq = Seq::new(seq).unwrap();
        // Honour the invariant: first checkpoint has a zero predecessor.
        let previous = if checkpoint_seq.is_first() { Hash512::ZERO } else {
            let mut p = prev; if Hash512(p).is_zero() { p[0] = 1; } Hash512(p)
        };
        let body = CheckpointBody::new(&CheckpointParts {
            election_id: ElectionId::new(&election).unwrap(),
            ledger_id: LedgerId::new(&ledger).unwrap(),
            keyset_id: KeysetId::new(&keyset).unwrap(),
            checkpoint_seq,
            tree_size: TreeSize::new(tree),
            root_hash: Hash512(root),
            previous_checkpoint_hash: previous,
            box_close_root: Hash512(boxes),
            dispute_root: Hash512(disputes),
            genesis_hash: Hash512(genesis),
            time_bucket: TimeBucket::new(bucket),
        }).unwrap();
        let bytes = encode_to_vec(SCHEMA_CHECKPOINT_BODY, SCHEMA_VERSION_1, &body);
        let decoded: CheckpointBody<'_> = decode_object(SCHEMA_CHECKPOINT_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(decoded, body);
        check_canonical!(CheckpointBody<'_>, SCHEMA_CHECKPOINT_BODY, &bytes);
    }

    #[test]
    fn arbitrary_bytes_never_panic_the_decoders(bytes in prop::collection::vec(any::<u8>(), 0..300)) {
        let _ = decode_object::<LedgerFrame<'_>>(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &bytes);
        let _ = decode_object::<LegalAuthorizationBody<'_>>(SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, &bytes);
        let _ = decode_object::<CheckpointBody<'_>>(SCHEMA_CHECKPOINT_BODY, SCHEMA_VERSION_1, &bytes);
        let mut r = Reader::new(&bytes);
        let _ = r.read_ident(64);
        let _ = r.read_bytes(64);
        let _ = r.read_count(16);
        let _ = r.read_bool();
        let _ = r.finish();
    }
}
