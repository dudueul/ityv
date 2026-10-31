//! Kani bounded model-checking harnesses (verification ladder V2).
//!
//! Compiled only under `cargo kani`, as `crate::proofs` via a `#[path]`
//! attribute in `src/lib.rs`. Each harness states one property of the
//! crate's pure algorithms: the RFC 9162 shape arithmetic, the inclusion
//! and consistency proof algorithms (generation and verification agree, a
//! wrong index is refused), the accumulator against full recomputation,
//! the sorted-set order check, the quorum profile rule, the deadline
//! arithmetic, and the stream parser on short inputs.
//!
//! The tree harnesses run the generic algorithms with a cheap stand-in
//! node function ([`MockNodes`]) so that what is explored is the tree
//! algorithm, not SHA3-512; the round-trip properties hold for any
//! deterministic node function. The harness that needs distinct hashes
//! uses concrete leaves whose stand-in hashes are checked to be distinct.
//! SHA3-512 itself is covered by the known-answer vectors.
//!
//! Kani additionally checks every harness for panics, overflow and
//! out-of-bounds access on all explored inputs, which is the mechanical
//! form of the crate's "no panics" promise for these functions.
//!
//! Run with `cargo kani -p ityv-ledger` from the workspace root.
// Harness file: outside the TCB and outside `src/` (CONSTITUTION.md §1.1).
// A harness states expected values with plain indexing, `as` casts and
// unchecked arithmetic on bounded symbolic inputs, and Kani itself reports
// any panic or overflow in them, so these restriction lints are relaxed for
// this file only.
#![allow(
    clippy::unreachable,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::missing_panics_doc,
    clippy::unwrap_used
)]

use ityv_encoding::{Hash512, TimeBucket};

use crate::frame::FrameStream;
use crate::merkle::{
    Accumulator, MAX_DEPTH, MAX_TREE_SIZE, NodeHasher, check_sorted, consistency_proof_with,
    depth_for_size, inclusion_proof_with, range_root, sorted_set_root_with, split_point,
    verify_consistency_with, verify_inclusion_with,
};
use crate::policy::{MAX_WITNESSES, QuorumProfile};
use crate::publication::{
    ANCHOR_WINDOW, BOARD_WINDOW, REQUIRED_ANCHORS, Status, anchor_deadline, board_deadline,
    check_anchor,
};

/// A cheap node function for the tree algorithms. Only the first eight
/// bytes of a hash carry information (one `u64` lane); the rest stay zero.
/// That keeps the symbolic state small while every tree-shape decision is
/// still exercised.
struct MockNodes;

fn lane(h: &Hash512) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&h.0[..8]);
    u64::from_le_bytes(bytes)
}

fn from_lane(v: u64) -> Hash512 {
    let mut out = [0u8; 64];
    out[..8].copy_from_slice(&v.to_le_bytes());
    Hash512(out)
}

impl NodeHasher for MockNodes {
    fn empty(&self) -> Hash512 {
        from_lane(0xEEEE_EEEE_EEEE_EEEE)
    }

    fn leaf(&self, input: &Hash512) -> Hash512 {
        from_lane(lane(input).rotate_left(1) ^ 0x0101_0101_0101_0101)
    }

    fn node(&self, left: &Hash512, right: &Hash512) -> Hash512 {
        // Asymmetric in its two inputs (rotations 5 and 17 differ by a
        // non-multiple of 8, and the left lane is added once more), so the
        // order of children is visible in the result.
        let l = lane(left);
        let r = lane(right);
        from_lane((l.rotate_left(5) ^ r.rotate_left(17)).wrapping_add(l ^ 0x5A5A_5A5A_5A5A_5A5A))
    }
}

/// A hash whose first eight bytes are symbolic and whose other bytes are
/// zero.
fn any_hash() -> Hash512 {
    from_lane(kani::any())
}

/// `split_point(n)` is a power of two, below `n`, and at least `n / 2`.
#[kani::proof]
fn split_point_is_the_largest_power_of_two_below() {
    let n: u64 = kani::any();
    kani::assume(n >= 2);
    let k = split_point(n).unwrap();
    assert!(k.is_power_of_two());
    assert!(k < n);
    assert!(k.checked_mul(2).map_or(true, |twice| twice >= n));
    assert!(split_point(0).is_none());
    assert!(split_point(1).is_none());
}

/// Every size up to the capacity has depth at most `MAX_DEPTH`, and the
/// depth is the bit length of `n − 1`.
#[kani::proof]
fn depth_is_bounded_by_the_capacity() {
    let n: u64 = kani::any();
    kani::assume(n <= MAX_TREE_SIZE);
    let d = depth_for_size(n);
    assert!(d as usize <= MAX_DEPTH);
    if n >= 2 {
        assert_eq!(d, 64 - (n - 1).leading_zeros());
    } else {
        assert_eq!(d, 0);
    }
}

/// For every tree of at most four symbolic leaves and every index, the
/// generated inclusion proof verifies against the tree root. Sizes and
/// indices are enumerated concretely (so array indices stay concrete for
/// the solver); the leaf values are symbolic.
#[kani::proof]
#[kani::unwind(70)]
fn inclusion_proof_round_trips_for_small_trees() {
    let leaves = [any_hash(), any_hash(), any_hash(), any_hash()];
    for size in 1..=4u64 {
        let slice: &[Hash512] = &leaves[..size as usize];
        let root = range_root(&MockNodes, &slice, 0, size).unwrap();
        for index in 0..size {
            let proof = inclusion_proof_with(&MockNodes, &slice, size, index).unwrap();
            let leaf = leaves[index as usize];
            let included =
                verify_inclusion_with(&MockNodes, &root, size, index, &leaf, &proof).unwrap();
            assert_eq!(included.get().index(), index);
            // RFC 9162 paths are at most the depth (PATH(2, D[3]) has one element).
            assert!(proof.hashes().len() as u32 <= depth_for_size(size));
        }
    }
}

/// With concrete distinct leaves, a proof for one index never verifies
/// for another index of the same tree, nor with another leaf.
#[kani::proof]
#[kani::unwind(70)]
fn inclusion_proof_refuses_a_wrong_index() {
    // Non-periodic lanes: a byte-repeated lane is invariant under rotation
    // by multiples of 8, which would hide the order of children.
    let leaves = [
        from_lane(0x0123_4567_89ab_cdef),
        from_lane(0xfedc_ba98_7654_3210),
        from_lane(0x0f1e_2d3c_4b5a_6978),
        from_lane(0x8796_a5b4_c3d2_e1f0),
    ];
    for size in 2..=4u64 {
        let slice: &[Hash512] = &leaves[..size as usize];
        let root = range_root(&MockNodes, &slice, 0, size).unwrap();
        for index in 0..size {
            let proof = inclusion_proof_with(&MockNodes, &slice, size, index).unwrap();
            let leaf = leaves[index as usize];
            for wrong in 0..size {
                if wrong == index {
                    continue;
                }
                assert!(
                    verify_inclusion_with(&MockNodes, &root, size, wrong, &leaf, &proof).is_err()
                );
                let other = leaves[wrong as usize];
                assert!(
                    verify_inclusion_with(&MockNodes, &root, size, index, &other, &proof).is_err()
                );
            }
        }
    }
}

/// For all `old <= new <= 4` over symbolic leaves, the generated
/// consistency proof verifies between the two roots.
#[kani::proof]
#[kani::unwind(70)]
fn consistency_proof_round_trips_for_small_trees() {
    let leaves = [any_hash(), any_hash(), any_hash(), any_hash()];
    for new in 0..=4u64 {
        let slice: &[Hash512] = &leaves[..new as usize];
        let new_root = range_root(&MockNodes, &slice, 0, new).unwrap();
        for old in 0..=new {
            let proof = consistency_proof_with(&MockNodes, &slice, old, new).unwrap();
            let old_root = range_root(&MockNodes, &slice, 0, old).unwrap();
            let consistent =
                verify_consistency_with(&MockNodes, old, &old_root, new, &new_root, &proof)
                    .unwrap();
            assert_eq!(consistent.get().new_size(), new);
            if old == 0 || old == new {
                assert!(proof.hashes().is_empty());
            }
        }
    }
}

/// Pushing leaves one by one yields the same root as the full
/// recomputation, for every prefix of four symbolic leaves.
#[kani::proof]
#[kani::unwind(70)]
fn accumulator_matches_full_recomputation() {
    let leaves = [any_hash(), any_hash(), any_hash(), any_hash()];
    let mut acc = Accumulator::empty();
    assert_eq!(acc.root_with(&MockNodes), MockNodes.empty());
    for n in 1..=4u64 {
        acc.push_with(&MockNodes, &leaves[n as usize - 1]).unwrap();
        let slice: &[Hash512] = &leaves[..n as usize];
        assert_eq!(
            acc.root_with(&MockNodes),
            range_root(&MockNodes, &slice, 0, n).unwrap()
        );
        assert_eq!(acc.size(), n);
        assert_eq!(acc.peaks().len(), n.count_ones() as usize);
    }
}

/// `check_sorted` accepts exactly the strictly ascending triples, and the
/// sorted-set root of an accepted triple equals the range root.
#[kani::proof]
#[kani::unwind(70)]
fn sorted_set_check_is_strict_ascending() {
    let a = any_hash();
    let b = any_hash();
    let c = any_hash();
    let set = [a, b, c];
    let expected = a.as_bytes() < b.as_bytes() && b.as_bytes() < c.as_bytes();
    assert_eq!(check_sorted(&set).is_ok(), expected);
    if expected {
        let slice: &[Hash512] = &set;
        assert_eq!(
            sorted_set_root_with(&MockNodes, &set).unwrap(),
            range_root(&MockNodes, &slice, 0, 3).unwrap()
        );
    } else {
        assert!(sorted_set_root_with(&MockNodes, &set).is_err());
    }
}

/// The quorum profile rule equals its arithmetic definition on every
/// `(witnesses, quorum, byzantine_max)`.
#[kani::proof]
fn quorum_profile_rule_matches_its_definition() {
    let n: u8 = kani::any();
    let q: u8 = kani::any();
    let f: u8 = kani::any();
    let expected = q >= 1
        && q <= n
        && (n as usize) <= MAX_WITNESSES
        && 2 * (q as u32) > (n as u32) + (f as u32);
    assert_eq!(QuorumProfile::is_valid(n, q, f), expected);
    assert_eq!(QuorumProfile::new(n, q, f).is_some(), expected);
    if let Some(p) = QuorumProfile::new(n, q, f) {
        assert!(p.quorum_intersection() as u32 > f as u32);
    }
}

/// Deadline arithmetic never panics and overflows exactly at the top of
/// the bucket range; the anchor check counts receipts correctly.
#[kani::proof]
#[kani::unwind(8)]
fn deadlines_are_total_and_exact() {
    let bucket: u64 = kani::any();
    let anchor = anchor_deadline(TimeBucket::new(bucket));
    assert_eq!(anchor.is_ok(), bucket.checked_add(ANCHOR_WINDOW).is_some());
    if let Ok(d) = anchor {
        assert_eq!(d.get(), bucket + ANCHOR_WINDOW);
    }
    let board = board_deadline(TimeBucket::new(bucket));
    assert_eq!(board.is_ok(), bucket.checked_add(BOARD_WINDOW).is_some());
    let r1: u64 = kani::any();
    let r2: u64 = kani::any();
    let r3: u64 = kani::any();
    let now: u64 = kani::any();
    kani::assume(bucket <= u64::MAX - ANCHOR_WINDOW);
    let receipts = [
        TimeBucket::new(r1),
        TimeBucket::new(r2),
        TimeBucket::new(r3),
    ];
    let deadline = bucket + ANCHOR_WINDOW;
    let timely = (r1 <= deadline) as usize + (r2 <= deadline) as usize + (r3 <= deadline) as usize;
    let result = check_anchor(TimeBucket::new(bucket), &receipts, TimeBucket::new(now));
    if timely >= REQUIRED_ANCHORS {
        assert_eq!(result.unwrap(), Status::Satisfied);
    } else if now > deadline {
        assert!(result.is_err());
    } else {
        assert_eq!(result.unwrap(), Status::Pending);
    }
}

/// The stream parser never panics on a short arbitrary input and reports a
/// torn tail or a corrupt record at offset 0.
#[kani::proof]
#[kani::unwind(10)]
fn stream_parser_is_total_on_short_inputs() {
    let bytes: [u8; 8] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 8);
    let mut stream = FrameStream::new(&bytes[..len]);
    match stream.next_record() {
        None => assert_eq!(len, 0),
        Some(Err(crate::error::Error::TornTail { offset })) => assert_eq!(offset, 0),
        Some(Err(crate::error::Error::CorruptRecord { offset })) => assert_eq!(offset, 0),
        Some(_) => unreachable!("a record needs at least the minimum frame length"),
    }
    assert!(stream.next_record().is_none());
}
