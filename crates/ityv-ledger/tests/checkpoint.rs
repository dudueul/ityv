//! `SignedCheckpoint` encoding, successor validation, and the witness
//! signing state machine.
// Integration-test crate: outside the TCB (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::missing_panics_doc
)]

mod common;

use common::{
    body_object, body_parts, decode_body, decode_signed, leaf_input, leaves, object_to_vec,
    roster_entries, signed_checkpoint_object, witnesses,
};
use ityv_crypto::{PURPOSE_CHECKPOINT, sign_hybrid};
use ityv_encoding::{Encode, ErrorKind, Hash512, Ident, Seq};
use ityv_ledger::{
    ConsistencyProof, EMPTY_ROOT, Error, Root, SCHEMA_SIGNED_CHECKPOINT, SignedCheckpoint,
    SignedCheckpointParts, WitnessMemory, WitnessSignatureEntry, consistency_proof, root_of_leaves,
    sorted_set_root, validate_successor,
};

const GENESIS: Hash512 = Hash512([7; 64]);

#[test]
fn signed_checkpoint_round_trips_in_identifier_order() {
    let ws = witnesses(3);
    let body = body_object(&body_parts(
        1,
        0,
        EMPTY_ROOT,
        Hash512::ZERO,
        EMPTY_ROOT,
        EMPTY_ROOT,
        GENESIS,
        1,
    ));
    let bytes = signed_checkpoint_object(&ws, &[0, 1, 2], &body);
    let signed = decode_signed(&bytes);
    assert_eq!(signed.body_bytes(), body.as_slice());
    assert_eq!(signed.body().parts().checkpoint_seq, Seq::FIRST);
    assert_eq!(signed.signature_count(), 3);
    assert_eq!(signed.body_hash(), ityv_crypto::object_hash(&body));
    let ids: std::vec::Vec<_> = signed
        .signatures()
        .map(|s| std::string::String::from_utf8(s.witness_id().as_bytes().to_vec()).unwrap())
        .collect();
    assert_eq!(ids, ["W00", "W01", "W02"]);
    for (i, entry) in signed.signatures().enumerate() {
        let key = ws[i].key.verifying_key();
        let signed_by =
            ityv_crypto::verify_hybrid(&key, &PURPOSE_CHECKPOINT, &body, entry.signature())
                .unwrap();
        assert_eq!(signed_by.get().object(), body.as_slice());
    }
    // Re-encoding the decoded object reproduces the bytes exactly.
    let again = object_to_vec(SCHEMA_SIGNED_CHECKPOINT, &signed);
    assert_eq!(again, bytes);
    assert_eq!(signed.encoded_len() + 16, bytes.len());
}

#[test]
fn signed_checkpoint_rejects_unsorted_duplicate_and_bad_bodies() {
    let ws = witnesses(2);
    let body = body_object(&body_parts(
        1,
        0,
        EMPTY_ROOT,
        Hash512::ZERO,
        EMPTY_ROOT,
        EMPTY_ROOT,
        GENESIS,
        1,
    ));
    let mut r = common::rng(1);
    let s0 = sign_hybrid(&ws[0].key, &PURPOSE_CHECKPOINT, &body, &mut r).unwrap();
    let s1 = sign_hybrid(&ws[1].key, &PURPOSE_CHECKPOINT, &body, &mut r).unwrap();
    let e0 = WitnessSignatureEntry {
        witness_id: Ident::new(b"W00", 64).unwrap(),
        signature: &s0,
    };
    let e1 = WitnessSignatureEntry {
        witness_id: Ident::new(b"W01", 64).unwrap(),
        signature: &s1,
    };
    assert_eq!(
        SignedCheckpointParts::new(&body, &[e1, e0]).unwrap_err(),
        Error::NotSorted
    );
    assert_eq!(
        SignedCheckpointParts::new(&body, &[e0, e0]).unwrap_err(),
        Error::Duplicate
    );
    assert!(matches!(
        SignedCheckpointParts::new(b"junk", &[e0]).unwrap_err(),
        Error::Encoding(_)
    ));
    // Encoded objects with the same defects are rejected at decode.
    let ordered = [e0, e1];
    let good = SignedCheckpointParts::new(&body, &ordered).unwrap();
    let bytes = object_to_vec(SCHEMA_SIGNED_CHECKPOINT, &good);
    let signed_len = bytes.len();
    // Swap the two entries: decode must report NotSorted at the second id.
    let entry_len = 4 + 3 + 4691;
    let entries_start = 16 + 4 + body.len() + 4;
    let mut swapped = bytes.clone();
    let (a, b) = (entries_start, entries_start + entry_len);
    let first = swapped[a..a + entry_len].to_vec();
    let second = swapped[b..b + entry_len].to_vec();
    swapped[a..a + entry_len].copy_from_slice(&second);
    swapped[b..b + entry_len].copy_from_slice(&first);
    let err =
        ityv_encoding::decode_object::<SignedCheckpoint<'_>>(SCHEMA_SIGNED_CHECKPOINT, 1, &swapped)
            .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NotSorted);
    assert_eq!(err.offset(), b);
    let mut dup = bytes.clone();
    dup[b..b + entry_len].copy_from_slice(&first);
    let err =
        ityv_encoding::decode_object::<SignedCheckpoint<'_>>(SCHEMA_SIGNED_CHECKPOINT, 1, &dup)
            .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Duplicate);
    // A body that is not a checkpoint object: the inner error offset is
    // reported relative to the whole object (header 16 + length prefix 4).
    let mut bad_body = bytes.clone();
    bad_body[16 + 4] ^= 0xff;
    let err = ityv_encoding::decode_object::<SignedCheckpoint<'_>>(
        SCHEMA_SIGNED_CHECKPOINT,
        1,
        &bad_body,
    )
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::BadMagic);
    assert_eq!(err.offset(), 20);
    // A truncated signature.
    let truncated = &bytes[..signed_len - 1];
    assert!(
        ityv_encoding::decode_object::<SignedCheckpoint<'_>>(
            SCHEMA_SIGNED_CHECKPOINT,
            1,
            truncated
        )
        .is_err()
    );
    // Zero signatures is a well-formed (if useless) object.
    let none = SignedCheckpointParts::new(&body, &[]).unwrap();
    let bytes = object_to_vec(SCHEMA_SIGNED_CHECKPOINT, &none);
    assert_eq!(decode_signed(&bytes).signature_count(), 0);
    let _ = roster_entries(&ws);
}

#[test]
fn successor_validation_checks_every_field() {
    let ls = leaves(4);
    let r2 = root_of_leaves(&ls.as_slice(), 2).unwrap();
    let r4 = root_of_leaves(&ls.as_slice(), 4).unwrap();
    let first_bytes = body_object(&body_parts(
        1,
        2,
        r2,
        Hash512::ZERO,
        EMPTY_ROOT,
        EMPTY_ROOT,
        GENESIS,
        1,
    ));
    let first = decode_body(&first_bytes);
    let first_hash = ityv_crypto::object_hash(&first_bytes);
    let genesis_ok = validate_successor(None, &first, &GENESIS).unwrap();
    assert!(genesis_ok.get().prev().is_none());
    assert_eq!(
        validate_successor(None, &first, &Hash512([8; 64])).unwrap_err(),
        Error::GenesisMismatch
    );
    let second_bytes = body_object(&body_parts(
        2, 4, r4, first_hash, EMPTY_ROOT, EMPTY_ROOT, GENESIS, 2,
    ));
    let second = decode_body(&second_bytes);
    assert_eq!(
        validate_successor(None, &second, &GENESIS).unwrap_err(),
        Error::SequenceGap
    );
    let ok = validate_successor(Some((&first, &first_hash)), &second, &GENESIS).unwrap();
    assert_eq!(ok.get().body().parts().checkpoint_seq.get(), 2);
    assert!(ok.get().prev().is_some());
    // An equal tree size is allowed (no new frames since the last one).
    let same_size = body_object(&body_parts(
        2, 2, r2, first_hash, EMPTY_ROOT, EMPTY_ROOT, GENESIS, 2,
    ));
    let same_size = decode_body(&same_size);
    let ok = validate_successor(Some((&first, &first_hash)), &same_size, &GENESIS).unwrap();
    assert_eq!(ok.get().body().parts().tree_size.get(), 2);
    // Gap.
    let third_bytes = body_object(&body_parts(
        3, 4, r4, first_hash, EMPTY_ROOT, EMPTY_ROOT, GENESIS, 2,
    ));
    let third = decode_body(&third_bytes);
    assert_eq!(
        validate_successor(Some((&first, &first_hash)), &third, &GENESIS).unwrap_err(),
        Error::SequenceGap
    );
    // Wrong previous hash.
    let wrong_prev = body_object(&body_parts(
        2,
        4,
        r4,
        Hash512([1; 64]),
        EMPTY_ROOT,
        EMPTY_ROOT,
        GENESIS,
        2,
    ));
    let wrong_prev = decode_body(&wrong_prev);
    assert_eq!(
        validate_successor(Some((&first, &first_hash)), &wrong_prev, &GENESIS).unwrap_err(),
        Error::PreviousHashMismatch
    );
    // Shrinking tree.
    let shrink = body_object(&body_parts(
        2, 1, r2, first_hash, EMPTY_ROOT, EMPTY_ROOT, GENESIS, 2,
    ));
    let shrink = decode_body(&shrink);
    assert_eq!(
        validate_successor(Some((&first, &first_hash)), &shrink, &GENESIS).unwrap_err(),
        Error::TreeShrank
    );
    // Different genesis in the body.
    let other_genesis = body_object(&body_parts(
        2,
        4,
        r4,
        first_hash,
        EMPTY_ROOT,
        EMPTY_ROOT,
        Hash512([8; 64]),
        2,
    ));
    let other_genesis = decode_body(&other_genesis);
    assert_eq!(
        validate_successor(Some((&first, &first_hash)), &other_genesis, &GENESIS).unwrap_err(),
        Error::GenesisMismatch
    );
    // Different ledger id.
    let mut parts = body_parts(2, 4, r4, first_hash, EMPTY_ROOT, EMPTY_ROOT, GENESIS, 2);
    parts.ledger_id = ityv_encoding::LedgerId::new(b"LEDGER-OTHER").unwrap();
    let other_ledger = body_object(&parts);
    let other_ledger = decode_body(&other_ledger);
    assert_eq!(
        validate_successor(Some((&first, &first_hash)), &other_ledger, &GENESIS).unwrap_err(),
        Error::LedgerMismatch
    );
    let mut parts = body_parts(2, 4, r4, first_hash, EMPTY_ROOT, EMPTY_ROOT, GENESIS, 2);
    parts.election_id = ityv_encoding::ElectionId::new(b"KR-2030-OTHER").unwrap();
    let other_election = body_object(&parts);
    let other_election = decode_body(&other_election);
    assert_eq!(
        validate_successor(Some((&first, &first_hash)), &other_election, &GENESIS).unwrap_err(),
        Error::ElectionMismatch
    );
}

/// Runs `may_sign` on a memory and asserts that it fails with `expected`,
/// returning the memory, which must be unchanged.
fn refuse(
    memory: WitnessMemory,
    body: &[u8],
    proof: &ConsistencyProof,
    close: &[Hash512],
    disputes: &[Hash512],
    genesis: &Hash512,
    expected: &Error,
) -> WitnessMemory {
    let before = WitnessMemory::from_last(memory.last().copied());
    let (result, memory) = memory.may_sign(body, proof, close, disputes, genesis);
    assert_eq!(result.unwrap_err(), *expected);
    assert_eq!(memory, before, "a refused body leaves the memory unchanged");
    memory
}

#[test]
#[allow(clippy::too_many_lines)]
fn witness_memory_signs_a_chain_and_refuses_every_deviation() {
    let ls = leaves(8);
    let r3 = root_of_leaves(&ls.as_slice(), 3).unwrap();
    let r6 = root_of_leaves(&ls.as_slice(), 6).unwrap();
    let r8 = root_of_leaves(&ls.as_slice(), 8).unwrap();
    let close_set = [leaf_input(11), leaf_input(12)];
    let close_root = sorted_set_root(&close_set).unwrap();
    let memory = WitnessMemory::fresh();
    assert!(memory.last().is_none());

    // Checkpoint 1 over 3 leaves, no previous. A first checkpoint needs an
    // empty consistency proof.
    let b1 = body_object(&body_parts(
        1,
        3,
        r3,
        Hash512::ZERO,
        EMPTY_ROOT,
        EMPTY_ROOT,
        GENESIS,
        1,
    ));
    let p36 = consistency_proof(&ls.as_slice(), 3, 6).unwrap();
    let memory = refuse(memory, &b1, &p36, &[], &[], &GENESIS, &Error::ProofInvalid);
    let (t1, memory) = memory.may_sign(&b1, &ConsistencyProof::EMPTY, &[], &[], &GENESIS);
    let t1 = t1.unwrap();
    assert_eq!(t1.get().body_bytes(), b1.as_slice());
    assert_eq!(*t1.get().body_hash(), ityv_crypto::object_hash(&b1));
    assert_eq!(t1.get().consistency(), &ConsistencyProof::EMPTY);
    assert!(t1.get().box_close_hashes().is_empty());
    assert!(t1.get().dispute_hashes().is_empty());
    assert_eq!(*t1.get().genesis_hash(), GENESIS);
    let last = memory.last().unwrap();
    assert_eq!(last.seq().get(), 1);
    assert_eq!(last.tree_size().get(), 3);
    assert_eq!(*last.root_hash(), r3);
    let h1 = *last.body_hash();
    let ids1 = *last.ids_hash();

    // The memory survives persistence as a complete object.
    let mut buf = [0u8; 16 + 208];
    let used = memory.to_object(&mut buf).unwrap();
    assert_eq!(used, 16 + 208);
    let back = WitnessMemory::from_object(&buf[..used]).unwrap();
    assert_eq!(back, memory);

    // Two bodies at one sequence number can never both yield tokens: the
    // memory that produced t1 is gone, and the advanced memory refuses seq 1.
    let b1_other = body_object(&body_parts(
        1,
        3,
        r3,
        Hash512::ZERO,
        EMPTY_ROOT,
        EMPTY_ROOT,
        GENESIS,
        2,
    ));
    let memory = refuse(
        memory,
        &b1_other,
        &ConsistencyProof::EMPTY,
        &[],
        &[],
        &GENESIS,
        &Error::SequenceGap,
    );

    // Checkpoint 2 over 6 leaves with a box-close set.
    let b2 = body_object(&body_parts(
        2, 6, r6, h1, close_root, EMPTY_ROOT, GENESIS, 2,
    ));
    // A fork at the same sequence number (different tree) is not consistent
    // with the signed prefix of 3 leaves.
    let mut forked = ls.clone();
    forked[1] = leaf_input(99);
    let rf6 = root_of_leaves(&forked.as_slice(), 6).unwrap();
    let forked_proof = consistency_proof(&forked.as_slice(), 3, 6).unwrap();
    let b2_fork = body_object(&body_parts(
        2, 6, rf6, h1, close_root, EMPTY_ROOT, GENESIS, 2,
    ));
    let memory = refuse(
        memory,
        &b2_fork,
        &forked_proof,
        &close_set,
        &[],
        &GENESIS,
        &Error::ProofInvalid,
    );
    let (t2, memory) = memory.may_sign(&b2, &p36, &close_set, &[], &GENESIS);
    let t2 = t2.unwrap();
    assert_eq!(t2.get().box_close_hashes(), &close_set[..]);
    let memory = refuse(
        memory,
        &b2,
        &p36,
        &close_set,
        &[],
        &GENESIS,
        &Error::SequenceGap,
    );
    assert_eq!(*memory.last().unwrap().ids_hash(), ids1);
    let h2 = *memory.last().unwrap().body_hash();

    // Deviations for checkpoint 3.
    let p68 = consistency_proof(&ls.as_slice(), 6, 8).unwrap();
    let good3 = body_object(&body_parts(
        3, 8, r8, h2, close_root, EMPTY_ROOT, GENESIS, 3,
    ));
    // Skipping a sequence number.
    let skip = body_object(&body_parts(
        4, 8, r8, h2, close_root, EMPTY_ROOT, GENESIS, 3,
    ));
    let memory = refuse(
        memory,
        &skip,
        &p68,
        &close_set,
        &[],
        &GENESIS,
        &Error::SequenceGap,
    );
    // Wrong previous hash.
    let wrong_prev = body_object(&body_parts(
        3, 8, r8, h1, close_root, EMPTY_ROOT, GENESIS, 3,
    ));
    let memory = refuse(
        memory,
        &wrong_prev,
        &p68,
        &close_set,
        &[],
        &GENESIS,
        &Error::PreviousHashMismatch,
    );
    // A changed ledger identifier.
    let mut parts = body_parts(3, 8, r8, h2, close_root, EMPTY_ROOT, GENESIS, 3);
    parts.ledger_id = ityv_encoding::LedgerId::new(b"LEDGER-OTHER").unwrap();
    let other_ledger = body_object(&parts);
    let memory = refuse(
        memory,
        &other_ledger,
        &p68,
        &close_set,
        &[],
        &GENESIS,
        &Error::LedgerMismatch,
    );
    let mut parts = body_parts(3, 8, r8, h2, close_root, EMPTY_ROOT, GENESIS, 3);
    parts.keyset_id = ityv_encoding::KeysetId::new(b"KEYSET-OTHER").unwrap();
    let other_keyset = body_object(&parts);
    let memory = refuse(
        memory,
        &other_keyset,
        &p68,
        &close_set,
        &[],
        &GENESIS,
        &Error::LedgerMismatch,
    );
    let mut parts = body_parts(3, 8, r8, h2, close_root, EMPTY_ROOT, GENESIS, 3);
    parts.election_id = ityv_encoding::ElectionId::new(b"KR-2030-OTHER").unwrap();
    let other_election = body_object(&parts);
    let memory = refuse(
        memory,
        &other_election,
        &p68,
        &close_set,
        &[],
        &GENESIS,
        &Error::LedgerMismatch,
    );
    // Shrinking tree.
    let shrink = body_object(&body_parts(
        3, 3, r3, h2, close_root, EMPTY_ROOT, GENESIS, 3,
    ));
    let memory = refuse(
        memory,
        &shrink,
        &ConsistencyProof::EMPTY,
        &close_set,
        &[],
        &GENESIS,
        &Error::TreeShrank,
    );
    // Wrong genesis.
    let memory = refuse(
        memory,
        &good3,
        &p68,
        &close_set,
        &[],
        &Hash512([8; 64]),
        &Error::GenesisMismatch,
    );
    // Wrong box-close root (set differs) and wrong dispute root.
    let memory = refuse(
        memory,
        &good3,
        &p68,
        &[leaf_input(11)],
        &[],
        &GENESIS,
        &Error::RootMismatch(Root::BoxClose),
    );
    let memory = refuse(
        memory,
        &good3,
        &p68,
        &close_set,
        &[leaf_input(1)],
        &GENESIS,
        &Error::RootMismatch(Root::Dispute),
    );
    // Unsorted set input is rejected before any comparison.
    let memory = refuse(
        memory,
        &good3,
        &p68,
        &[leaf_input(12), leaf_input(11)],
        &[],
        &GENESIS,
        &Error::NotSorted,
    );
    // Invalid consistency proof.
    let memory = refuse(
        memory,
        &good3,
        &p36,
        &close_set,
        &[],
        &GENESIS,
        &Error::ProofInvalid,
    );
    // Not a body at all.
    let (junk, memory) = memory.may_sign(b"junk", &p68, &close_set, &[], &GENESIS);
    assert!(matches!(junk.unwrap_err(), Error::Encoding(_)));
    // The good one.
    let (t3, memory) = memory.may_sign(&good3, &p68, &close_set, &[], &GENESIS);
    let t3 = t3.unwrap();
    assert_eq!(t3.get().body().parts().checkpoint_seq.get(), 3);
    assert_eq!(memory.last().unwrap().seq().get(), 3);
    // Equal tree size with an empty proof is allowed (no new frames).
    let h3 = *memory.last().unwrap().body_hash();
    let same = body_object(&body_parts(
        4, 8, r8, h3, close_root, EMPTY_ROOT, GENESIS, 4,
    ));
    let (t4, memory) = memory.may_sign(&same, &ConsistencyProof::EMPTY, &close_set, &[], &GENESIS);
    assert_eq!(t4.unwrap().get().body().parts().checkpoint_seq.get(), 4);
    // A persisted memory rebuilt from parts behaves the same.
    let rebuilt = WitnessMemory::from_last(memory.last().copied());
    assert_eq!(rebuilt, memory);
}

#[test]
fn witness_memory_object_rejects_garbage_and_inconsistent_fields() {
    let mut buf = [0u8; 16 + 208];
    let used = WitnessMemory::fresh().to_object(&mut buf).unwrap();
    assert_eq!(used, 224);
    assert_eq!(
        WitnessMemory::from_object(&buf).unwrap(),
        WitnessMemory::fresh()
    );
    assert_eq!(&buf[..4], b"ITYV");
    assert_eq!(&buf[4..8], &0x0011u32.to_be_bytes());
    // Garbage, wrong schema, truncation.
    assert!(matches!(
        WitnessMemory::from_object(b"not an object").unwrap_err(),
        Error::Encoding(e) if e.kind() == ErrorKind::BadMagic
    ));
    let mut wrong_schema = buf;
    wrong_schema[7] = 0x10;
    assert!(matches!(
        WitnessMemory::from_object(&wrong_schema).unwrap_err(),
        Error::Encoding(e) if e.kind() == ErrorKind::SchemaMismatch
    ));
    assert!(WitnessMemory::from_object(&buf[..223]).is_err());
    // last_seq 0 with a non-zero field.
    let mut inconsistent = buf;
    inconsistent[16 + 16 + 5] = 1;
    assert!(matches!(
        WitnessMemory::from_object(&inconsistent).unwrap_err(),
        Error::Encoding(e) if e.kind() == ErrorKind::InvariantViolation && e.offset() == 16
    ));
    // tree_size above the capacity.
    let mut huge = buf;
    huge[16 + 7] = 1;
    huge[16 + 8] = 1;
    assert!(matches!(
        WitnessMemory::from_object(&huge).unwrap_err(),
        Error::Encoding(e) if e.kind() == ErrorKind::ValueOutOfRange && e.offset() == 24
    ));
    // A signed memory round-trips and is not equal to a fresh one.
    let last = {
        let body = body_object(&body_parts(
            1,
            0,
            EMPTY_ROOT,
            Hash512::ZERO,
            EMPTY_ROOT,
            EMPTY_ROOT,
            GENESIS,
            1,
        ));
        let (token, memory) =
            WitnessMemory::fresh().may_sign(&body, &ConsistencyProof::EMPTY, &[], &[], &GENESIS);
        let _ = token.unwrap();
        memory
    };
    let used = last.to_object(&mut buf).unwrap();
    let back = WitnessMemory::from_object(&buf[..used]).unwrap();
    assert_eq!(back, last);
    assert_ne!(back, WitnessMemory::fresh());
    assert_eq!(back.last().unwrap().seq().get(), 1);
}
