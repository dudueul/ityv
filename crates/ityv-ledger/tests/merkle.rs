//! Merkle tree behaviour: shape arithmetic, accumulator, proofs and their
//! rejections, sorted-set roots, encodings.
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

use common::{decode_exact, encode_to_vec, leaf_input, leaves};
use ityv_encoding::{ErrorKind, Hash512};
use ityv_ledger::{
    Accumulator, ConsistencyProof, EMPTY_ROOT, Error, InclusionProof, MAX_CONSISTENCY_PATH,
    MAX_DEPTH, MAX_INCLUSION_PATH, MAX_TREE_SIZE, check_sorted, consistency_proof, depth_for_size,
    inclusion_proof, leaf_hash, node_hash, root_of_leaves, sorted_set_root, split_point,
    verify_consistency, verify_inclusion,
};

#[test]
fn split_point_is_largest_power_of_two_below() {
    assert_eq!(split_point(0), None);
    assert_eq!(split_point(1), None);
    assert_eq!(split_point(2), Some(1));
    assert_eq!(split_point(3), Some(2));
    assert_eq!(split_point(4), Some(2));
    assert_eq!(split_point(5), Some(4));
    assert_eq!(split_point(8), Some(4));
    assert_eq!(split_point(9), Some(8));
    assert_eq!(split_point(MAX_TREE_SIZE), Some(MAX_TREE_SIZE / 2));
    assert_eq!(split_point(MAX_TREE_SIZE + 1), Some(MAX_TREE_SIZE));
    assert_eq!(split_point(u64::MAX), Some(1 << 63));
}

#[test]
fn depth_bound_holds_up_to_the_capacity() {
    assert_eq!(depth_for_size(0), 0);
    assert_eq!(depth_for_size(1), 0);
    assert_eq!(depth_for_size(2), 1);
    assert_eq!(depth_for_size(3), 2);
    assert_eq!(depth_for_size(4), 2);
    assert_eq!(depth_for_size(5), 3);
    assert_eq!(depth_for_size(MAX_TREE_SIZE), MAX_DEPTH as u32);
    assert_eq!(depth_for_size(MAX_TREE_SIZE + 1), MAX_DEPTH as u32 + 1);
    assert_eq!(MAX_INCLUSION_PATH, MAX_DEPTH);
    assert_eq!(MAX_CONSISTENCY_PATH, MAX_DEPTH + 1);
}

#[test]
fn hashes_use_the_rfc_prefixes_and_differ_by_role() {
    let a = leaf_input(1);
    let l = leaf_hash(&a);
    assert_ne!(l, a);
    assert_ne!(node_hash(&l, &l), l);
    assert_ne!(
        node_hash(&l, &leaf_hash(&leaf_input(2))),
        node_hash(&leaf_hash(&leaf_input(2)), &l)
    );
    assert_eq!(root_of_leaves(&[].as_slice(), 0).unwrap(), EMPTY_ROOT);
    assert_eq!(root_of_leaves(&[a].as_slice(), 1).unwrap(), l);
}

#[test]
fn accumulator_matches_full_recomputation_for_every_prefix() {
    let ls = leaves(70);
    let mut acc = Accumulator::new();
    assert_eq!(acc.root(), EMPTY_ROOT);
    for n in 1..=ls.len() {
        acc.push(&ls[n - 1]).unwrap();
        assert_eq!(acc.size(), n as u64);
        assert_eq!(acc.peaks().len(), (n as u64).count_ones() as usize);
        assert_eq!(
            acc.root(),
            root_of_leaves(&ls.as_slice(), n as u64).unwrap(),
            "n={n}"
        );
    }
    let restored = Accumulator::from_parts(acc.size(), acc.peaks()).unwrap();
    assert_eq!(restored, acc);
    assert!(Accumulator::from_parts(3, acc.peaks()).is_none());
    assert!(Accumulator::from_parts(MAX_TREE_SIZE + 1, &[]).is_none());
}

#[test]
fn accumulator_refuses_to_exceed_the_capacity() {
    let mut acc = Accumulator::from_parts(MAX_TREE_SIZE, &[leaf_input(9)]).unwrap();
    assert_eq!(acc.push(&leaf_input(1)), Err(Error::TreeFull));
    assert_eq!(acc.size(), MAX_TREE_SIZE);
    let mut almost = Accumulator::from_parts(MAX_TREE_SIZE - 1, &leaves(40)).unwrap();
    almost.push(&leaf_input(1)).unwrap();
    assert_eq!(almost.size(), MAX_TREE_SIZE);
    assert_eq!(almost.peaks().len(), 1);
}

#[test]
fn accumulator_round_trips_and_rejects_bad_peak_counts() {
    let ls = leaves(11);
    let mut acc = Accumulator::new();
    for l in &ls {
        acc.push(l).unwrap();
    }
    let bytes = encode_to_vec(&acc);
    assert_eq!(bytes.len(), 8 + 4 + 3 * 64);
    let back: Accumulator = decode_exact(&bytes).unwrap();
    assert_eq!(back, acc);
    let mut wrong = bytes.clone();
    wrong[7] = 12;
    let err = decode_exact::<Accumulator>(&wrong).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvariantViolation);
    assert_eq!(err.offset(), 8);
    let mut huge = bytes.clone();
    huge[0] = 1;
    let err = decode_exact::<Accumulator>(&huge).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ValueOutOfRange);
    assert_eq!(err.offset(), 0);
}

#[test]
fn inclusion_proofs_verify_and_detect_every_tampering() {
    let ls = leaves(13);
    let root = root_of_leaves(&ls.as_slice(), 13).unwrap();
    for m in 0..13u64 {
        let proof = inclusion_proof(&ls.as_slice(), 13, m).unwrap();
        let leaf = ls[m as usize];
        let ok = verify_inclusion(&root, 13, m, &leaf, &proof).unwrap();
        assert_eq!(ok.get().tree_size(), 13);
        assert_eq!(*ok.get().leaf_input(), leaf);
        // Wrong index, wrong leaf, wrong size, wrong root.
        let other = (m + 1) % 13;
        assert_eq!(
            verify_inclusion(&root, 13, other, &leaf, &proof).unwrap_err(),
            Error::ProofInvalid
        );
        let wrong_leaf = leaf_input(200);
        assert_eq!(
            verify_inclusion(&root, 13, m, &wrong_leaf, &proof).unwrap_err(),
            Error::ProofInvalid
        );
        // The same proof against the 12-leaf tree (its own root and size).
        let root12 = root_of_leaves(&ls.as_slice(), 12).unwrap();
        assert_eq!(
            verify_inclusion(&root12, 12, m, &leaf, &proof).unwrap_err(),
            if m < 12 {
                Error::ProofInvalid
            } else {
                Error::IndexOutOfRange
            }
        );
        let wrong_root = Hash512([3; 64]);
        assert_eq!(
            verify_inclusion(&wrong_root, 13, m, &leaf, &proof).unwrap_err(),
            Error::ProofInvalid
        );
        // Truncated and extended paths.
        let hashes = proof.hashes();
        if let Some((_, rest)) = hashes.split_last() {
            let shorter = InclusionProof::from_hashes(rest).unwrap();
            assert_eq!(
                verify_inclusion(&root, 13, m, &leaf, &shorter).unwrap_err(),
                Error::ProofInvalid
            );
        }
        let mut longer = hashes.to_vec();
        longer.push(Hash512([5; 64]));
        let longer = InclusionProof::from_hashes(&longer).unwrap();
        assert_eq!(
            verify_inclusion(&root, 13, m, &leaf, &longer).unwrap_err(),
            Error::ProofInvalid
        );
    }
    assert_eq!(
        inclusion_proof(&ls.as_slice(), 13, 13).unwrap_err(),
        Error::IndexOutOfRange
    );
    assert_eq!(
        verify_inclusion(
            &root,
            13,
            13,
            &ls[0],
            &InclusionProof::from_hashes(&[]).unwrap()
        )
        .unwrap_err(),
        Error::IndexOutOfRange
    );
    assert_eq!(
        verify_inclusion(
            &root,
            MAX_TREE_SIZE + 1,
            0,
            &ls[0],
            &InclusionProof::from_hashes(&[]).unwrap()
        )
        .unwrap_err(),
        Error::Capacity
    );
}

#[test]
fn single_leaf_tree_has_empty_inclusion_proof() {
    let ls = leaves(1);
    let root = root_of_leaves(&ls.as_slice(), 1).unwrap();
    let proof = inclusion_proof(&ls.as_slice(), 1, 0).unwrap();
    assert!(proof.hashes().is_empty());
    let included = verify_inclusion(&root, 1, 0, &ls[0], &proof).unwrap();
    assert_eq!(included.get().index(), 0);
}

#[test]
fn consistency_proofs_verify_and_reject_forks() {
    let ls = leaves(20);
    for old in 0..=20u64 {
        for new in old..=20u64 {
            let proof = consistency_proof(&ls.as_slice(), old, new).unwrap();
            let old_root = root_of_leaves(&ls.as_slice(), old).unwrap();
            let new_root = root_of_leaves(&ls.as_slice(), new).unwrap();
            let consistent = verify_consistency(old, &old_root, new, &new_root, &proof)
                .unwrap_or_else(|e| panic!("old={old} new={new}: {e}"));
            assert_eq!(consistent.get().old_size(), old);
            if old == 0 || old == new {
                assert!(proof.hashes().is_empty());
            }
            // A forked old tree (different leaf at position old − 1).
            if old > 0 {
                let mut forked = ls.clone();
                forked[(old - 1) as usize] = leaf_input(250);
                let forked_root = root_of_leaves(&forked.as_slice(), old).unwrap();
                assert_eq!(
                    verify_consistency(old, &forked_root, new, &new_root, &proof).unwrap_err(),
                    Error::ProofInvalid,
                    "old={old} new={new}"
                );
            }
            // Wrong new root. From the empty tree nothing constrains the
            // new root (an empty proof is all there is), so only old > 0 is
            // checked here.
            let wrong = Hash512([9; 64]);
            if old > 0 {
                assert_eq!(
                    verify_consistency(old, &old_root, new, &wrong, &proof).unwrap_err(),
                    Error::ProofInvalid
                );
            }
        }
    }
    assert_eq!(
        consistency_proof(&ls.as_slice(), 5, 4).unwrap_err(),
        Error::SizeMismatch
    );
    let r5 = root_of_leaves(&ls.as_slice(), 5).unwrap();
    assert_eq!(
        verify_consistency(5, &r5, 4, &r5, &ConsistencyProof::EMPTY).unwrap_err(),
        Error::SizeMismatch
    );
    // Equal sizes need equal roots and an empty proof.
    let non_empty = consistency_proof(&ls.as_slice(), 3, 5).unwrap();
    assert_eq!(
        verify_consistency(5, &r5, 5, &r5, &non_empty).unwrap_err(),
        Error::ProofInvalid
    );
    // From the empty tree the old root must be the empty root.
    let r1 = root_of_leaves(&ls.as_slice(), 1).unwrap();
    assert_eq!(
        verify_consistency(0, &r1, 5, &r5, &ConsistencyProof::EMPTY).unwrap_err(),
        Error::ProofInvalid
    );
}

#[test]
fn proofs_round_trip_through_their_encodings() {
    let ls = leaves(9);
    let incl = inclusion_proof(&ls.as_slice(), 9, 4).unwrap();
    let bytes = encode_to_vec(&incl);
    assert_eq!(bytes.len(), 4 + incl.hashes().len() * 64);
    let back: InclusionProof = decode_exact(&bytes).unwrap();
    assert_eq!(back, incl);
    let cons = consistency_proof(&ls.as_slice(), 3, 9).unwrap();
    let bytes = encode_to_vec(&cons);
    let back: ConsistencyProof = decode_exact(&bytes).unwrap();
    assert_eq!(back, cons);
    // Too many hashes are rejected at the count.
    let too_many = std::vec![Hash512::ZERO; MAX_INCLUSION_PATH + 1];
    assert!(InclusionProof::from_hashes(&too_many).is_none());
    let mut bytes = encode_to_vec(&InclusionProof::from_hashes(&[]).unwrap());
    bytes[3] = 41;
    let err = decode_exact::<InclusionProof>(&bytes).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::CountExceedsMax);
}

#[test]
fn sorted_set_roots_require_strict_order() {
    let one = leaf_input(1);
    let two = leaf_input(2);
    let three = leaf_input(3);
    assert_eq!(sorted_set_root(&[]).unwrap(), EMPTY_ROOT);
    assert_eq!(sorted_set_root(&[one]).unwrap(), leaf_hash(&one));
    let all = sorted_set_root(&[one, two, three]).unwrap();
    assert_eq!(
        all,
        root_of_leaves(&[one, two, three].as_slice(), 3).unwrap()
    );
    assert_eq!(
        sorted_set_root(&[two, one, three]).unwrap_err(),
        Error::NotSorted
    );
    assert_eq!(
        sorted_set_root(&[one, one, three]).unwrap_err(),
        Error::Duplicate
    );
    assert_eq!(check_sorted(&[one, two, three]), Ok(()));
    assert_eq!(check_sorted(&[three, two]), Err(Error::NotSorted));
    // Order is bytewise, so the first differing byte decides.
    let mut late_byte = Hash512([0; 64]);
    late_byte.0[63] = 1;
    let mut first_byte = Hash512([0; 64]);
    first_byte.0[0] = 1;
    assert_eq!(check_sorted(&[late_byte, first_byte]), Ok(()));
    assert_eq!(
        check_sorted(&[first_byte, late_byte]),
        Err(Error::NotSorted)
    );
}

#[test]
fn errors_display_distinctly() {
    let errors = [
        Error::TreeFull,
        Error::Capacity,
        Error::SizeMismatch,
        Error::IndexOutOfRange,
        Error::LeafUnavailable,
        Error::ProofLength,
        Error::ProofInvalid,
        Error::NotSorted,
        Error::Duplicate,
        Error::SequenceGap,
        Error::PreviousHashMismatch,
        Error::ElectionMismatch,
        Error::LedgerMismatch,
        Error::TreeShrank,
        Error::GenesisMismatch,
        Error::RootMismatch(ityv_ledger::Root::Ledger),
        Error::RootMismatch(ityv_ledger::Root::BoxClose),
        Error::TornTail { offset: 3 },
        Error::CorruptRecord { offset: 3 },
        Error::Record {
            offset: 3,
            inner: ityv_encoding::Error::new(ErrorKind::BadMagic, 0),
        },
        Error::UnknownWitness { index: 2 },
        Error::InvalidSignature { index: 2 },
        Error::QuorumShort { have: 8, need: 9 },
        Error::DiversityShort {
            dimension: ityv_ledger::Dimension::Regions,
            have: 2,
            need: 3,
        },
        Error::ProfileInvalid,
        Error::RosterInvalid,
        Error::Overflow,
        Error::Breach(ityv_ledger::Breach::BoardUnpublished),
        Error::Encoding(ityv_encoding::Error::new(ErrorKind::BadMagic, 0)),
        Error::Crypto(ityv_crypto::Error::SignatureInvalid),
    ];
    let texts: std::collections::BTreeSet<std::string::String> =
        errors.iter().map(|e| std::format!("{e}")).collect();
    assert_eq!(texts.len(), errors.len());
    let from_enc: Error = ityv_encoding::Error::new(ErrorKind::BadMagic, 0).into();
    assert!(matches!(from_enc, Error::Encoding(_)));
    let from_crypto: Error = ityv_crypto::Error::SignatureInvalid.into();
    assert!(matches!(from_crypto, Error::Crypto(_)));
}
