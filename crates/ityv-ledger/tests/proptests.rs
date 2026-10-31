//! Property tests over random trees, chains and objects.
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

use common::{decode_exact, encode_to_vec, frame_chain, random_leaves};
use ityv_encoding::Hash512;
use ityv_ledger::{
    Accumulator, ChainState, ConsistencyProof, Error, FrameStream, InclusionProof,
    consistency_proof, inclusion_proof, root_of_leaves, sorted_set_root, verify_consistency,
    verify_inclusion, write_record,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn inclusion_proofs_hold_for_every_leaf(seed in any::<u64>(), n in 1usize..=1024) {
        let ls = random_leaves(seed, n);
        let root = root_of_leaves(&ls.as_slice(), n as u64).unwrap();
        let picks = [0usize, n / 2, n - 1, (seed as usize) % n];
        for &m in &picks {
            let proof = inclusion_proof(&ls.as_slice(), n as u64, m as u64).unwrap();
            prop_assert!(proof.hashes().len() <= 10);
            let included = verify_inclusion(&root, n as u64, m as u64, &ls[m], &proof).unwrap();
            prop_assert_eq!(included.get().index(), m as u64);
            if n > 1 {
                let wrong = (m + 1) % n;
                prop_assert_eq!(
                    verify_inclusion(&root, n as u64, wrong as u64, &ls[m], &proof).unwrap_err(),
                    Error::ProofInvalid
                );
                prop_assert_eq!(
                    verify_inclusion(&root, n as u64, m as u64, &ls[wrong], &proof).unwrap_err(),
                    Error::ProofInvalid
                );
            }
            let bytes = encode_to_vec(&proof);
            let back: InclusionProof = decode_exact(&bytes).unwrap();
            prop_assert_eq!(back, proof);
        }
    }

    #[test]
    fn consistency_proofs_hold_between_random_sizes(seed in any::<u64>(), new in 1usize..=512, pick in any::<u64>()) {
        let ls = random_leaves(seed, new);
        let old = (pick % (new as u64 + 1)) as usize;
        let proof = consistency_proof(&ls.as_slice(), old as u64, new as u64).unwrap();
        let old_root = root_of_leaves(&ls.as_slice(), old as u64).unwrap();
        let new_root = root_of_leaves(&ls.as_slice(), new as u64).unwrap();
        let consistent =
            verify_consistency(old as u64, &old_root, new as u64, &new_root, &proof).unwrap();
        prop_assert_eq!(consistent.get().new_size(), new as u64);
        if old > 0 {
            let mut forked = ls.clone();
            forked[old - 1] = Hash512([0xAB; 64]);
            let forked_root = root_of_leaves(&forked.as_slice(), old as u64).unwrap();
            prop_assert_eq!(
                verify_consistency(old as u64, &forked_root, new as u64, &new_root, &proof).unwrap_err(),
                Error::ProofInvalid
            );
        }
        let bytes = encode_to_vec(&proof);
        let back: ConsistencyProof = decode_exact(&bytes).unwrap();
        prop_assert_eq!(back, proof);
    }

    #[test]
    fn accumulator_equals_recomputation(seed in any::<u64>(), n in 0usize..=300) {
        let ls = random_leaves(seed, n);
        let mut acc = Accumulator::new();
        for (i, l) in ls.iter().enumerate() {
            acc.push(l).unwrap();
            prop_assert_eq!(acc.root(), root_of_leaves(&ls.as_slice(), i as u64 + 1).unwrap());
        }
        let bytes = encode_to_vec(&acc);
        let back: Accumulator = decode_exact(&bytes).unwrap();
        prop_assert_eq!(back, acc);
    }

    #[test]
    fn sorted_sets_accept_sorted_and_reject_unsorted(seed in any::<u64>(), n in 2usize..=50) {
        let mut ls = random_leaves(seed, n);
        ls.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        ls.dedup();
        let root = sorted_set_root(&ls).unwrap();
        prop_assert_eq!(root, root_of_leaves(&ls.as_slice(), ls.len() as u64).unwrap());
        if ls.len() >= 2 {
            let mut swapped = ls.clone();
            swapped.swap(0, 1);
            prop_assert_eq!(sorted_set_root(&swapped).unwrap_err(), Error::NotSorted);
            let mut dup = ls.clone();
            dup[1] = dup[0];
            prop_assert_eq!(sorted_set_root(&dup).unwrap_err(), Error::Duplicate);
        }
    }

    #[test]
    fn frame_streams_replay_and_truncate_cleanly(n in 1usize..=12, cut in any::<usize>()) {
        let chain = frame_chain(n);
        let mut stream = std::vec![0u8; n * 300];
        let mut w = ityv_encoding::Writer::new(&mut stream);
        for f in &chain {
            write_record(&mut w, f).unwrap();
        }
        let used = w.finish();
        stream.truncate(used);
        let mut state = ChainState::new();
        for r in FrameStream::new(&stream) {
            let r = r.unwrap();
            state.append(r.bytes()).unwrap();
        }
        prop_assert_eq!(state.head().unwrap().seq().get(), n as u64);
        let cut = cut % stream.len();
        let mut s = FrameStream::new(&stream[..cut]);
        let mut complete = 0usize;
        let mut torn = None;
        for r in s.by_ref() {
            match r {
                Ok(_) => complete += 1,
                Err(e) => torn = Some(e),
            }
        }
        // Either the cut is on a boundary (no torn tail) or the torn tail
        // starts at the record the cut falls into.
        let mut offset = 0usize;
        let mut boundary = cut == 0;
        let mut expected_complete = 0usize;
        for f in &chain {
            let next = offset + 4 + f.len();
            if next <= cut { expected_complete += 1; }
            if next == cut { boundary = true; }
            offset = next;
        }
        prop_assert_eq!(complete, expected_complete);
        if boundary {
            prop_assert!(torn.is_none());
        } else {
            let start = {
                let mut o = 0usize;
                for f in &chain { let next = o + 4 + f.len(); if cut < next { break; } o = next; }
                o
            };
            prop_assert_eq!(torn, Some(Error::TornTail { offset: start }));
        }
    }
}
