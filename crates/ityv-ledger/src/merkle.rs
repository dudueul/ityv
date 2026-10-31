//! The ledger Merkle tree (PROTOCOL.md §5.3, ADR-0016 §2).
//!
//! Tree shape and proof algorithms are those of RFC 9162 §2.1: the left
//! subtree of `n` leaves holds the largest power of two strictly smaller than
//! `n`. Hashing is SHA3-512 with the RFC's prefixes:
//!
//! | node | input |
//! |---|---|
//! | leaf | `SHA3-512(0x00 ‖ leaf_input)` |
//! | interior | `SHA3-512(0x01 ‖ left ‖ right)` |
//! | empty tree | `SHA3-512("")` ([`EMPTY_ROOT`]) |
//!
//! A leaf input is a frame hash (ledger tree) or an event hash (sorted-set
//! trees for `box_close_root` and `dispute_root`).
//!
//! The tree holds at most 2^40 leaves, so an inclusion path has at most
//! [`MAX_DEPTH`] hashes, a consistency path at most [`MAX_DEPTH`] + 1, and the
//! incremental [`Accumulator`] keeps at most [`MAX_DEPTH`] peaks. Nothing here
//! allocates.
//!
//! Proof *generation* reads leaves through a [`Leaves`] accessor and hashes
//! O(n) leaves per proof; it is a reference implementation for verifiers and
//! small tools. Proof *verification* is O(log n) with fixed memory and is the
//! part every witness and mirror runs.

use ityv_encoding::{Decode, Encode, Error as EncodingError, ErrorKind, Hash512, Reader, Writer};

use crate::error::Error;
use crate::verified::Verified;

/// Maximum tree depth: the tree holds at most 2^40 leaves.
pub const MAX_DEPTH: usize = 40;
/// Maximum number of leaves.
pub const MAX_TREE_SIZE: u64 = 1 << MAX_DEPTH;
/// Maximum length of an inclusion path.
pub const MAX_INCLUSION_PATH: usize = MAX_DEPTH;
/// Maximum length of a consistency path.
pub const MAX_CONSISTENCY_PATH: usize = MAX_DEPTH + 1;

/// `SHA3-512("")`: the root of the empty tree (RFC 9162 §2.1.1).
pub const EMPTY_ROOT: Hash512 = Hash512([
    0xa6, 0x9f, 0x73, 0xcc, 0xa2, 0x3a, 0x9a, 0xc5, 0xc8, 0xb5, 0x67, 0xdc, 0x18, 0x5a, 0x75, 0x6e,
    0x97, 0xc9, 0x82, 0x16, 0x4f, 0xe2, 0x58, 0x59, 0xe0, 0xd1, 0xdc, 0xc1, 0x47, 0x5c, 0x80, 0xa6,
    0x15, 0xb2, 0x12, 0x3a, 0xf1, 0xf5, 0xf9, 0x4c, 0x11, 0xe3, 0xe9, 0x40, 0x2c, 0x3a, 0xc5, 0x58,
    0xf5, 0x00, 0x19, 0x9d, 0x95, 0xb6, 0xd3, 0xe3, 0x01, 0x75, 0x85, 0x86, 0x28, 0x1d, 0xcd, 0x26,
]);

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

// ---------------------------------------------------------------------------
// Node hashing, generic so the Kani harnesses can swap in a cheap function.
// ---------------------------------------------------------------------------

/// How leaves and interior nodes are hashed. The production implementation
/// is SHA3-512 with the RFC 9162 prefixes; harnesses use a cheap stand-in to
/// check the tree algorithms independently of the hash function.
pub(crate) trait NodeHasher {
    /// Root of the empty tree.
    fn empty(&self) -> Hash512;
    /// Hash of a leaf.
    fn leaf(&self, input: &Hash512) -> Hash512;
    /// Hash of an interior node.
    fn node(&self, left: &Hash512, right: &Hash512) -> Hash512;
}

/// SHA3-512 node hashing (PROTOCOL.md §5.3).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Sha3Nodes;

impl NodeHasher for Sha3Nodes {
    fn empty(&self) -> Hash512 {
        EMPTY_ROOT
    }

    fn leaf(&self, input: &Hash512) -> Hash512 {
        let mut hasher = ityv_crypto::Sha3Hasher::new();
        hasher.absorb(&[LEAF_PREFIX]);
        hasher.absorb(input.as_bytes());
        Hash512(hasher.finish())
    }

    fn node(&self, left: &Hash512, right: &Hash512) -> Hash512 {
        let mut hasher = ityv_crypto::Sha3Hasher::new();
        hasher.absorb(&[NODE_PREFIX]);
        hasher.absorb(left.as_bytes());
        hasher.absorb(right.as_bytes());
        Hash512(hasher.finish())
    }
}

/// `SHA3-512(0x00 ‖ input)`.
#[must_use]
pub fn leaf_hash(input: &Hash512) -> Hash512 {
    Sha3Nodes.leaf(input)
}

/// `SHA3-512(0x01 ‖ left ‖ right)`.
#[must_use]
pub fn node_hash(left: &Hash512, right: &Hash512) -> Hash512 {
    Sha3Nodes.node(left, right)
}

// ---------------------------------------------------------------------------
// Shape arithmetic
// ---------------------------------------------------------------------------

/// The largest power of two strictly smaller than `n`, for `n >= 2`
/// (RFC 9162 §2.1.1's `k`). Returns `None` for `n < 2`.
#[must_use]
pub const fn split_point(n: u64) -> Option<u64> {
    if n < 2 {
        return None;
    }
    // `n - 1 >= 1`, so `checked_ilog2` is `Some`, and the result is below 64.
    match n.checked_sub(1) {
        Some(m) => match m.checked_ilog2() {
            Some(p) => 1u64.checked_shl(p),
            None => None,
        },
        None => None,
    }
}

/// Number of levels an inclusion path for a tree of `n` leaves can have:
/// `⌈log2 n⌉` for `n >= 1`, 0 for `n <= 1`. At most [`MAX_DEPTH`] for any
/// size up to [`MAX_TREE_SIZE`].
#[must_use]
pub const fn depth_for_size(n: u64) -> u32 {
    if n < 2 {
        return 0;
    }
    match n.checked_sub(1) {
        Some(m) => match m.checked_ilog2() {
            // ⌈log2 n⌉ = ⌊log2 (n − 1)⌋ + 1 for n >= 2.
            Some(p) => p.saturating_add(1),
            None => 0,
        },
        None => 0,
    }
}

const fn is_power_of_two(n: u64) -> bool {
    n != 0 && n & n.wrapping_sub(1) == 0
}

const fn lsb_set(n: u64) -> bool {
    n & 1 == 1
}

// ---------------------------------------------------------------------------
// Leaf access
// ---------------------------------------------------------------------------

/// Read access to the leaf inputs of a tree, for proof generation.
///
/// `leaf(i)` returns the input of leaf `i` (a frame or event hash, not yet
/// prefixed), or `None` if the source cannot supply it.
pub trait Leaves {
    /// The input of leaf `index`.
    fn leaf(&self, index: u64) -> Option<Hash512>;
}

impl Leaves for &[Hash512] {
    fn leaf(&self, index: u64) -> Option<Hash512> {
        let i = usize::try_from(index).ok()?;
        self.get(i).copied()
    }
}

impl<F: Fn(u64) -> Option<Hash512>> Leaves for F {
    fn leaf(&self, index: u64) -> Option<Hash512> {
        self(index)
    }
}

// ---------------------------------------------------------------------------
// Accumulator
// ---------------------------------------------------------------------------

/// An incremental Merkle tree head: the perfect-subtree peaks of a tree of
/// `size` leaves, largest first. Pushing a leaf is O(log n) and the root is
/// bagged from the peaks right to left, which equals RFC 9162's `MTH`.
///
/// Encoding: `size: u64` ‖ `peaks: Array<Hash512, 40>` with exactly
/// `popcount(size)` elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accumulator {
    peaks: [Hash512; MAX_DEPTH],
    len: usize,
    size: u64,
}

impl Default for Accumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl Accumulator {
    /// The empty tree.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            peaks: [Hash512::ZERO; MAX_DEPTH],
            len: 0,
            size: 0,
        }
    }

    /// Rebuilds an accumulator from persisted peaks. Returns `None` if the
    /// number of peaks is not `popcount(size)` or the size exceeds the bound.
    #[must_use]
    pub fn from_parts(size: u64, peaks: &[Hash512]) -> Option<Self> {
        if size > MAX_TREE_SIZE || peaks.len() != popcount(size) {
            return None;
        }
        let mut out = Self::new();
        for (slot, peak) in out.peaks.iter_mut().zip(peaks) {
            *slot = *peak;
        }
        out.len = peaks.len();
        out.size = size;
        Some(out)
    }

    /// Number of leaves.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// The peaks, largest subtree first.
    #[must_use]
    pub fn peaks(&self) -> &[Hash512] {
        self.peaks.get(..self.len).unwrap_or(&[])
    }

    /// Appends a leaf.
    ///
    /// # Errors
    /// [`Error::TreeFull`] once the tree holds [`MAX_TREE_SIZE`] leaves.
    pub fn push(&mut self, input: &Hash512) -> Result<(), Error> {
        self.push_with(&Sha3Nodes, input)
    }

    pub(crate) fn push_with<H: NodeHasher>(&mut self, h: &H, input: &Hash512) -> Result<(), Error> {
        if self.size >= MAX_TREE_SIZE {
            return Err(Error::TreeFull);
        }
        let mut node = h.leaf(input);
        let mut size = self.size;
        // Each trailing one bit of `size` is a peak that merges with the new
        // node, smallest first.
        while lsb_set(size) {
            let top = self.len.checked_sub(1).ok_or(Error::Capacity)?;
            let peak = self.peaks.get_mut(top).ok_or(Error::Capacity)?;
            node = h.node(peak, &node);
            // Unused slots stay zero so that two accumulators of the same
            // tree compare equal and encode identically.
            *peak = Hash512::ZERO;
            self.len = top;
            size = size.wrapping_shr(1);
        }
        let slot = self.peaks.get_mut(self.len).ok_or(Error::Capacity)?;
        *slot = node;
        self.len = self.len.checked_add(1).ok_or(Error::Capacity)?;
        self.size = self.size.checked_add(1).ok_or(Error::TreeFull)?;
        Ok(())
    }

    /// The Merkle root of the leaves pushed so far.
    #[must_use]
    pub fn root(&self) -> Hash512 {
        self.root_with(&Sha3Nodes)
    }

    pub(crate) fn root_with<H: NodeHasher>(&self, h: &H) -> Hash512 {
        let peaks = self.peaks();
        match peaks.split_last() {
            None => h.empty(),
            Some((last, rest)) => rest
                .iter()
                .rev()
                .fold(*last, |acc, peak| h.node(peak, &acc)),
        }
    }
}

const fn popcount(n: u64) -> usize {
    // `count_ones` is at most 64, which fits every `usize`.
    n.count_ones() as usize
}

impl Encode for Accumulator {
    fn encoded_len(&self) -> usize {
        8usize.saturating_add(ityv_encoding::encoded_len_of_slice(self.peaks()))
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        w.write_u64(self.size)?;
        ityv_encoding::encode_slice(w, self.peaks(), MAX_DEPTH)
    }
}

impl<'a> Decode<'a> for Accumulator {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        let size_at = r.position();
        let size = r.read_u64()?;
        if size > MAX_TREE_SIZE {
            return Err(EncodingError::new(ErrorKind::ValueOutOfRange, size_at));
        }
        let count_at = r.position();
        let count = r.read_count(MAX_DEPTH)?;
        if count != popcount(size) {
            return Err(EncodingError::new(ErrorKind::InvariantViolation, count_at));
        }
        let mut out = Self::new();
        for slot in out.peaks.iter_mut().take(count) {
            *slot = Hash512::decode(r)?;
        }
        out.len = count;
        out.size = size;
        Ok(out)
    }
}

/// The root of a tree given its leaf inputs.
///
/// # Errors
/// [`Error::Capacity`] if `size` exceeds [`MAX_TREE_SIZE`],
/// [`Error::LeafUnavailable`] if the accessor returns `None`.
pub fn root_of_leaves(leaves: &dyn Leaves, size: u64) -> Result<Hash512, Error> {
    range_root(&Sha3Nodes, leaves, 0, size)
}

/// `MTH(D[lo:hi])`.
pub(crate) fn range_root<H: NodeHasher>(
    h: &H,
    leaves: &dyn Leaves,
    lo: u64,
    hi: u64,
) -> Result<Hash512, Error> {
    if hi < lo || hi.checked_sub(lo).is_none_or(|n| n > MAX_TREE_SIZE) {
        return Err(Error::Capacity);
    }
    let mut acc = Accumulator::new();
    let mut i = lo;
    while i < hi {
        let input = leaves.leaf(i).ok_or(Error::LeafUnavailable)?;
        acc.push_with(h, &input)?;
        i = i.checked_add(1).ok_or(Error::Capacity)?;
    }
    Ok(acc.root_with(h))
}

// ---------------------------------------------------------------------------
// Proofs
// ---------------------------------------------------------------------------

/// A fixed-capacity list of hashes, the storage behind both proof types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Path<const N: usize> {
    hashes: [Hash512; N],
    len: usize,
}

impl<const N: usize> Path<N> {
    const fn empty() -> Self {
        Self {
            hashes: [Hash512::ZERO; N],
            len: 0,
        }
    }

    fn from_slice(hashes: &[Hash512]) -> Option<Self> {
        if hashes.len() > N {
            return None;
        }
        let mut out = Self::empty();
        for (slot, h) in out.hashes.iter_mut().zip(hashes) {
            *slot = *h;
        }
        out.len = hashes.len();
        Some(out)
    }

    fn as_slice(&self) -> &[Hash512] {
        self.hashes.get(..self.len).unwrap_or(&[])
    }

    fn push(&mut self, h: Hash512) -> Result<(), Error> {
        let slot = self.hashes.get_mut(self.len).ok_or(Error::Capacity)?;
        *slot = h;
        self.len = self.len.checked_add(1).ok_or(Error::Capacity)?;
        Ok(())
    }

    /// Reverses the order in place (generation collects top-down, proofs
    /// are bottom-up).
    fn reverse(&mut self) {
        if let Some(used) = self.hashes.get_mut(..self.len) {
            used.reverse();
        }
    }

    fn encode_to(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        ityv_encoding::encode_slice(w, self.as_slice(), N)
    }

    fn decode_from(r: &mut Reader<'_>) -> Result<Self, EncodingError> {
        let count = r.read_count(N)?;
        let mut out = Self::empty();
        for slot in out.hashes.iter_mut().take(count) {
            *slot = Hash512::decode(r)?;
        }
        out.len = count;
        Ok(out)
    }
}

/// An inclusion path (RFC 9162 §2.1.3), bottom-up sibling hashes.
/// Encoding: `Array<Hash512, 40>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InclusionProof {
    path: Path<MAX_INCLUSION_PATH>,
}

impl InclusionProof {
    /// Builds a proof from its hashes, bottom-up. Returns `None` if there are
    /// more than [`MAX_INCLUSION_PATH`].
    #[must_use]
    pub fn from_hashes(hashes: &[Hash512]) -> Option<Self> {
        Path::from_slice(hashes).map(|path| Self { path })
    }

    /// The sibling hashes, bottom-up.
    #[must_use]
    pub fn hashes(&self) -> &[Hash512] {
        self.path.as_slice()
    }
}

impl Encode for InclusionProof {
    fn encoded_len(&self) -> usize {
        ityv_encoding::encoded_len_of_slice(self.hashes())
    }
    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        self.path.encode_to(w)
    }
}

impl<'a> Decode<'a> for InclusionProof {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        Ok(Self {
            path: Path::decode_from(r)?,
        })
    }
}

/// A consistency path (RFC 9162 §2.1.4). Encoding: `Array<Hash512, 41>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsistencyProof {
    path: Path<MAX_CONSISTENCY_PATH>,
}

impl ConsistencyProof {
    /// The empty proof, valid between equal sizes and from the empty tree.
    pub const EMPTY: Self = Self {
        path: Path::empty(),
    };

    /// Builds a proof from its hashes. Returns `None` if there are more than
    /// [`MAX_CONSISTENCY_PATH`].
    #[must_use]
    pub fn from_hashes(hashes: &[Hash512]) -> Option<Self> {
        Path::from_slice(hashes).map(|path| Self { path })
    }

    /// The hashes of the proof.
    #[must_use]
    pub fn hashes(&self) -> &[Hash512] {
        self.path.as_slice()
    }
}

impl Encode for ConsistencyProof {
    fn encoded_len(&self) -> usize {
        ityv_encoding::encoded_len_of_slice(self.hashes())
    }
    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        self.path.encode_to(w)
    }
}

impl<'a> Decode<'a> for ConsistencyProof {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        Ok(Self {
            path: Path::decode_from(r)?,
        })
    }
}

/// What [`verify_inclusion`] verified.
#[derive(Debug, Clone, Copy)]
pub struct Included<'a> {
    root: &'a Hash512,
    tree_size: u64,
    index: u64,
    leaf_input: &'a Hash512,
    proof: &'a InclusionProof,
}

impl<'a> Included<'a> {
    /// The root the leaf is included under.
    #[must_use]
    pub const fn root(&self) -> &'a Hash512 {
        self.root
    }
    /// The tree size.
    #[must_use]
    pub const fn tree_size(&self) -> u64 {
        self.tree_size
    }
    /// The leaf index.
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }
    /// The leaf input.
    #[must_use]
    pub const fn leaf_input(&self) -> &'a Hash512 {
        self.leaf_input
    }
    /// The proof.
    #[must_use]
    pub const fn proof(&self) -> &'a InclusionProof {
        self.proof
    }
}

/// What [`verify_consistency`] verified.
#[derive(Debug, Clone, Copy)]
pub struct Consistent<'a> {
    old_size: u64,
    old_root: &'a Hash512,
    new_size: u64,
    new_root: &'a Hash512,
    proof: &'a ConsistencyProof,
}

impl<'a> Consistent<'a> {
    /// The older tree size.
    #[must_use]
    pub const fn old_size(&self) -> u64 {
        self.old_size
    }
    /// The older root.
    #[must_use]
    pub const fn old_root(&self) -> &'a Hash512 {
        self.old_root
    }
    /// The newer tree size.
    #[must_use]
    pub const fn new_size(&self) -> u64 {
        self.new_size
    }
    /// The newer root.
    #[must_use]
    pub const fn new_root(&self) -> &'a Hash512 {
        self.new_root
    }
    /// The proof.
    #[must_use]
    pub const fn proof(&self) -> &'a ConsistencyProof {
        self.proof
    }
}

/// Generates the inclusion path of leaf `index` in a tree of `size` leaves.
///
/// # Errors
/// [`Error::IndexOutOfRange`], [`Error::Capacity`], [`Error::LeafUnavailable`].
pub fn inclusion_proof(
    leaves: &dyn Leaves,
    size: u64,
    index: u64,
) -> Result<InclusionProof, Error> {
    inclusion_proof_with(&Sha3Nodes, leaves, size, index)
}

pub(crate) fn inclusion_proof_with<H: NodeHasher>(
    h: &H,
    leaves: &dyn Leaves,
    size: u64,
    index: u64,
) -> Result<InclusionProof, Error> {
    if size > MAX_TREE_SIZE {
        return Err(Error::Capacity);
    }
    if index >= size {
        return Err(Error::IndexOutOfRange);
    }
    let mut path: Path<MAX_INCLUSION_PATH> = Path::empty();
    let mut lo = 0u64;
    let mut n = size;
    let mut m = index;
    // PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n])   if m < k
    //              = PATH(m − k, D[k:n]) : MTH(D[0:k])  otherwise
    // Collected top-down, then reversed to the bottom-up order.
    while let Some(k) = split_point(n) {
        let mid = lo.checked_add(k).ok_or(Error::Capacity)?;
        let hi = lo.checked_add(n).ok_or(Error::Capacity)?;
        if m < k {
            path.push(range_root(h, leaves, mid, hi)?)?;
            n = k;
        } else {
            path.push(range_root(h, leaves, lo, mid)?)?;
            lo = mid;
            m = m.checked_sub(k).ok_or(Error::IndexOutOfRange)?;
            n = n.checked_sub(k).ok_or(Error::Capacity)?;
        }
    }
    path.reverse();
    Ok(InclusionProof { path })
}

/// Verifies that `leaf_input` is leaf `index` of the tree of `tree_size`
/// leaves whose root is `root` (RFC 9162 §2.1.3.2).
///
/// # Errors
/// [`Error::IndexOutOfRange`], [`Error::Capacity`], [`Error::ProofInvalid`].
pub fn verify_inclusion<'a>(
    root: &'a Hash512,
    tree_size: u64,
    index: u64,
    leaf_input: &'a Hash512,
    proof: &'a InclusionProof,
) -> Result<Verified<Included<'a>>, Error> {
    verify_inclusion_with(&Sha3Nodes, root, tree_size, index, leaf_input, proof)
}

pub(crate) fn verify_inclusion_with<'a, H: NodeHasher>(
    h: &H,
    root: &'a Hash512,
    tree_size: u64,
    index: u64,
    leaf_input: &'a Hash512,
    proof: &'a InclusionProof,
) -> Result<Verified<Included<'a>>, Error> {
    if tree_size > MAX_TREE_SIZE {
        return Err(Error::Capacity);
    }
    if index >= tree_size {
        return Err(Error::IndexOutOfRange);
    }
    let mut fnode = index;
    let mut snode = tree_size.wrapping_sub(1);
    let mut r = h.leaf(leaf_input);
    for p in proof.hashes() {
        if snode == 0 {
            return Err(Error::ProofInvalid);
        }
        if lsb_set(fnode) || fnode == snode {
            r = h.node(p, &r);
            if !lsb_set(fnode) {
                while !lsb_set(fnode) && fnode != 0 {
                    fnode = fnode.wrapping_shr(1);
                    snode = snode.wrapping_shr(1);
                }
            }
        } else {
            r = h.node(&r, p);
        }
        fnode = fnode.wrapping_shr(1);
        snode = snode.wrapping_shr(1);
    }
    if snode == 0 && r == *root {
        Ok(Verified::new(Included {
            root,
            tree_size,
            index,
            leaf_input,
            proof,
        }))
    } else {
        Err(Error::ProofInvalid)
    }
}

/// Generates the consistency path from the tree of `old_size` leaves to the
/// tree of `new_size` leaves over the same leaf sequence.
///
/// # Errors
/// [`Error::SizeMismatch`] if `old_size > new_size`, [`Error::Capacity`],
/// [`Error::LeafUnavailable`].
pub fn consistency_proof(
    leaves: &dyn Leaves,
    old_size: u64,
    new_size: u64,
) -> Result<ConsistencyProof, Error> {
    consistency_proof_with(&Sha3Nodes, leaves, old_size, new_size)
}

pub(crate) fn consistency_proof_with<H: NodeHasher>(
    h: &H,
    leaves: &dyn Leaves,
    old_size: u64,
    new_size: u64,
) -> Result<ConsistencyProof, Error> {
    if new_size > MAX_TREE_SIZE {
        return Err(Error::Capacity);
    }
    if old_size > new_size {
        return Err(Error::SizeMismatch);
    }
    if old_size == 0 || old_size == new_size {
        return Ok(ConsistencyProof::EMPTY);
    }
    let mut path: Path<MAX_CONSISTENCY_PATH> = Path::empty();
    let mut lo = 0u64;
    let mut m = old_size;
    let mut n = new_size;
    let mut complete = true;
    // SUBPROOF(m, D[m], true) = {}; SUBPROOF(m, D[m], false) = {MTH(D[m])}
    // SUBPROOF(m, D[n], b) = SUBPROOF(m, D[0:k], b) : MTH(D[k:n])        if m <= k
    //                      = SUBPROOF(m − k, D[k:n], false) : MTH(D[0:k])  otherwise
    while m < n {
        let k = split_point(n).ok_or(Error::SizeMismatch)?;
        let mid = lo.checked_add(k).ok_or(Error::Capacity)?;
        let hi = lo.checked_add(n).ok_or(Error::Capacity)?;
        if m <= k {
            path.push(range_root(h, leaves, mid, hi)?)?;
            n = k;
        } else {
            path.push(range_root(h, leaves, lo, mid)?)?;
            lo = mid;
            m = m.checked_sub(k).ok_or(Error::SizeMismatch)?;
            n = n.checked_sub(k).ok_or(Error::SizeMismatch)?;
            complete = false;
        }
    }
    if !complete {
        let hi = lo.checked_add(m).ok_or(Error::Capacity)?;
        path.push(range_root(h, leaves, lo, hi)?)?;
    }
    path.reverse();
    Ok(ConsistencyProof { path })
}

/// Verifies that the tree of `new_size` leaves with root `new_root` extends
/// the tree of `old_size` leaves with root `old_root` (RFC 9162 §2.1.4.2).
///
/// `old_size == new_size` requires equal roots and an empty proof;
/// `old_size == 0` requires an empty proof and accepts any newer tree.
///
/// # Errors
/// [`Error::SizeMismatch`], [`Error::Capacity`], [`Error::ProofInvalid`].
pub fn verify_consistency<'a>(
    old_size: u64,
    old_root: &'a Hash512,
    new_size: u64,
    new_root: &'a Hash512,
    proof: &'a ConsistencyProof,
) -> Result<Verified<Consistent<'a>>, Error> {
    verify_consistency_with(&Sha3Nodes, old_size, old_root, new_size, new_root, proof)
}

pub(crate) fn verify_consistency_with<'a, H: NodeHasher>(
    h: &H,
    old_size: u64,
    old_root: &'a Hash512,
    new_size: u64,
    new_root: &'a Hash512,
    proof: &'a ConsistencyProof,
) -> Result<Verified<Consistent<'a>>, Error> {
    if new_size > MAX_TREE_SIZE {
        return Err(Error::Capacity);
    }
    if old_size > new_size {
        return Err(Error::SizeMismatch);
    }
    let token = Consistent {
        old_size,
        old_root,
        new_size,
        new_root,
        proof,
    };
    let hashes = proof.hashes();
    if old_size == new_size {
        return if hashes.is_empty() && old_root == new_root {
            Ok(Verified::new(token))
        } else {
            Err(Error::ProofInvalid)
        };
    }
    if old_size == 0 {
        return if hashes.is_empty() && *old_root == h.empty() {
            Ok(Verified::new(token))
        } else {
            Err(Error::ProofInvalid)
        };
    }
    let (first, rest) = hashes.split_first().ok_or(Error::ProofInvalid)?;
    // If `first` is a power of two, `old_root` is prepended to the path.
    let (mut fr, mut sr, tail) = if is_power_of_two(old_size) {
        (*old_root, *old_root, hashes)
    } else {
        (*first, *first, rest)
    };
    let mut fnode = old_size.wrapping_sub(1);
    let mut snode = new_size.wrapping_sub(1);
    while lsb_set(fnode) {
        fnode = fnode.wrapping_shr(1);
        snode = snode.wrapping_shr(1);
    }
    for c in tail {
        if snode == 0 {
            return Err(Error::ProofInvalid);
        }
        if lsb_set(fnode) || fnode == snode {
            fr = h.node(c, &fr);
            sr = h.node(c, &sr);
            if !lsb_set(fnode) {
                while !lsb_set(fnode) && fnode != 0 {
                    fnode = fnode.wrapping_shr(1);
                    snode = snode.wrapping_shr(1);
                }
            }
        } else {
            sr = h.node(&sr, c);
        }
        fnode = fnode.wrapping_shr(1);
        snode = snode.wrapping_shr(1);
    }
    if snode == 0 && fr == *old_root && sr == *new_root {
        Ok(Verified::new(token))
    } else {
        Err(Error::ProofInvalid)
    }
}

// ---------------------------------------------------------------------------
// Sorted-set trees
// ---------------------------------------------------------------------------

/// Checks that `hashes` is strictly ascending in byte order.
///
/// # Errors
/// [`Error::NotSorted`] or [`Error::Duplicate`] at the first violation.
pub fn check_sorted(hashes: &[Hash512]) -> Result<(), Error> {
    for pair in hashes.windows(2) {
        if let [prev, cur] = pair {
            match prev.as_bytes().cmp(cur.as_bytes()) {
                core::cmp::Ordering::Less => {}
                core::cmp::Ordering::Equal => return Err(Error::Duplicate),
                core::cmp::Ordering::Greater => return Err(Error::NotSorted),
            }
        }
    }
    Ok(())
}

/// The root of the sorted-set tree over `hashes` (the `box_close_root` and
/// `dispute_root` rule, ADR-0016 §2): the hashes must be strictly ascending
/// in byte order, the empty set has root [`EMPTY_ROOT`].
///
/// # Errors
/// [`Error::NotSorted`], [`Error::Duplicate`], [`Error::Capacity`].
pub fn sorted_set_root(hashes: &[Hash512]) -> Result<Hash512, Error> {
    sorted_set_root_with(&Sha3Nodes, hashes)
}

pub(crate) fn sorted_set_root_with<H: NodeHasher>(
    h: &H,
    hashes: &[Hash512],
) -> Result<Hash512, Error> {
    check_sorted(hashes)?;
    let size = u64::try_from(hashes.len()).map_err(|_| Error::Capacity)?;
    range_root(h, &hashes, 0, size)
}
