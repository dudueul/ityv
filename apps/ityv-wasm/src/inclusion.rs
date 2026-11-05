//! Inclusion of every record's frame in the first verified checkpoint
//! that covers it, carried in the report itself (so an answer can never
//! belong to another bundle).
//!
//! The paths are generated here from the frame hashes (RFC 9162 §2.1.3.1
//! shape, every subtree root computed once), which is untrusted helper
//! work: each path is then checked by `ityv_ledger::verify_inclusion`
//! against the checkpoint's root, and only that check decides
//! `included`.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use ityv_encoding::Hash512;
use ityv_ledger::{InclusionProof, leaf_hash, node_hash, split_point, verify_inclusion};

/// The ledger tree over the frame hashes, with memoised subtree roots.
pub(crate) struct Tree<'h> {
    leaves: &'h [Hash512],
    memo: BTreeMap<(u64, u64), Hash512>,
}

impl<'h> Tree<'h> {
    pub(crate) const fn new(leaves: &'h [Hash512]) -> Self {
        Self {
            leaves,
            memo: BTreeMap::new(),
        }
    }

    /// The root of leaves `lo..hi` (`hi > lo`), or `None` past the leaves.
    fn root(&mut self, lo: u64, hi: u64) -> Option<Hash512> {
        if let Some(h) = self.memo.get(&(lo, hi)) {
            return Some(*h);
        }
        let n = hi.checked_sub(lo)?;
        let h = if n == 1 {
            let i = usize::try_from(lo).ok()?;
            leaf_hash(self.leaves.get(i)?)
        } else {
            let k = split_point(n)?;
            let mid = lo.checked_add(k)?;
            let left = self.root(lo, mid)?;
            let right = self.root(mid, hi)?;
            node_hash(&left, &right)
        };
        self.memo.insert((lo, hi), h);
        Some(h)
    }

    /// The inclusion path of leaf `index` in the tree of `size` leaves,
    /// bottom-up.
    fn path(&mut self, size: u64, index: u64) -> Option<Vec<Hash512>> {
        if index >= size {
            return None;
        }
        let mut out = Vec::new();
        let (mut lo, mut n, mut m) = (0u64, size, index);
        while let Some(k) = split_point(n) {
            let mid = lo.checked_add(k)?;
            let hi = lo.checked_add(n)?;
            if m < k {
                out.push(self.root(mid, hi)?);
                n = k;
            } else {
                out.push(self.root(lo, mid)?);
                lo = mid;
                m = m.checked_sub(k)?;
                n = n.checked_sub(k)?;
            }
        }
        out.reverse();
        Some(out)
    }

    /// Whether frame `seq` (from 1) is in the tree of `size` leaves with
    /// root `root`, as `ityv_ledger::verify_inclusion` decides, and the
    /// length of the path it checked.
    pub(crate) fn included(&mut self, root: &Hash512, size: u64, seq: u64) -> (bool, usize) {
        let Some(index) = seq.checked_sub(1) else {
            return (false, 0);
        };
        let Some(leaf) = usize::try_from(index)
            .ok()
            .and_then(|i| self.leaves.get(i))
            .copied()
        else {
            return (false, 0);
        };
        let Some(path) = self.path(size, index) else {
            return (false, 0);
        };
        let Some(proof) = InclusionProof::from_hashes(&path) else {
            return (false, path.len());
        };
        (
            verify_inclusion(root, size, index, &leaf, &proof).is_ok(),
            path.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::Tree;
    use ityv_encoding::Hash512;
    use ityv_ledger::root_of_leaves;

    #[test]
    fn every_leaf_of_every_size_is_included_and_no_other() {
        let leaves: Vec<Hash512> = (0u8..23).map(|i| Hash512([i; 64])).collect();
        let mut tree = Tree::new(&leaves);
        for size in 1..=23u64 {
            let root = root_of_leaves(&leaves.as_slice(), size).unwrap_or(Hash512::ZERO);
            for seq in 1..=size {
                assert!(tree.included(&root, size, seq).0, "size {size} seq {seq}");
            }
            assert!(!tree.included(&root, size, size + 1).0);
            assert!(!tree.included(&root, size, 0).0);
            assert!(!tree.included(&Hash512([0xEE; 64]), size, 1).0);
        }
    }
}
