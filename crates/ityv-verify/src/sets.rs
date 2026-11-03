//! One genesis entry set, decoded and checked whole (ADR-0028 decision 2,
//! VC-104): every entry is the canonical object of the set's schema, the
//! set is strictly ascending by key, and the count and root recomputed
//! from the entries' object hashes are the body's.

use alloc::vec::Vec;
use core::cmp::Ordering;

use ityv_crypto::hash::object_hash;
use ityv_encoding::schema_version;
use ityv_encoding::{EntrySet, GenesisEntry, Hash512, SetCommitment, decode_object};
use ityv_ledger::{Accumulator, InclusionProof, MAX_DEPTH, leaf_hash, node_hash, sorted_set_root};

use crate::error::{Error, Rule};

/// The rule broken by `next` following `previous` in a set that must be
/// strictly ascending, if any: equal is a duplicate, smaller is out of
/// order.
pub(crate) fn successor(previous: &[u8], next: &[u8]) -> Option<Rule> {
    match previous.cmp(next) {
        Ordering::Less => None,
        Ordering::Equal => Some(Rule::Duplicate),
        Ordering::Greater => Some(Rule::NotSorted),
    }
}

/// One entry with the bytes it was decoded from.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Item<'a, T> {
    pub(crate) value: T,
    pub(crate) bytes: &'a [u8],
}

/// A whole entry set whose order, count and root were checked.
#[derive(Debug, Clone)]
pub(crate) struct Set<'a, T> {
    items: Vec<Item<'a, T>>,
    /// The tree, bottom up: the leaf hashes, then each level of node
    /// hashes, an odd last node carried up unchanged (the same tree as
    /// RFC 9162's recursive split). A proof reads one hash per level.
    levels: Vec<Vec<Hash512>>,
}

/// The levels of the tree over `leaf_inputs`: one for an empty or
/// one-leaf set, `depth + 1` otherwise.
fn levels_of(leaf_inputs: &[Hash512]) -> Vec<Vec<Hash512>> {
    let mut levels = Vec::new();
    let mut level: Vec<Hash512> = leaf_inputs.iter().map(leaf_hash).collect();
    // A tree has at most `MAX_DEPTH + 1` levels. The bound keeps the loop
    // finite whatever its exit test says (CONSTITUTION.md §1: no unbounded
    // work in the TCB).
    for _ in 0..MAX_DEPTH {
        if level.len() <= 1 {
            break;
        }
        let next = level
            .chunks(2)
            .filter_map(|pair| match pair {
                [left, right] => Some(node_hash(left, right)),
                [odd] => Some(*odd),
                _ => None,
            })
            .collect();
        levels.push(level);
        level = next;
    }
    levels.push(level);
    levels
}

/// The inclusion path of leaf `index` read from `levels`, bottom up.
fn path(levels: &[Vec<Hash512>], index: usize) -> Option<InclusionProof> {
    let mut hashes = Vec::new();
    let mut i = index;
    for level in levels {
        // A node without a sibling (the odd last one) is carried up and
        // adds nothing to the path.
        if let Some(sibling) = level.get(i ^ 1) {
            hashes.push(*sibling);
        }
        i >>= 1;
    }
    InclusionProof::from_hashes(&hashes)
}

fn count_of(len: usize) -> Option<u64> {
    u64::try_from(len).ok()
}

impl<'a, T: GenesisEntry<'a>> Set<'a, T> {
    /// Decodes `entries` as `T`'s set and checks them against
    /// `commitment`.
    ///
    /// # Errors
    /// [`Rule::Decode`] for an entry that is not a canonical object of the
    /// set's schema, [`Rule::NotSorted`] or [`Rule::Duplicate`] at the
    /// first entry out of order, [`Rule::Count`] and [`Rule::Root`] for a
    /// commitment the entries do not give.
    pub(crate) fn parse(
        state: u64,
        entries: &[&'a [u8]],
        commitment: &SetCommitment,
    ) -> Result<Self, Error> {
        let set = T::SET;
        let schema = set.schema().ok_or(Error::set(state, set, Rule::Decode))?;
        let mut items: Vec<Item<'a, T>> = Vec::with_capacity(entries.len());
        let mut leaves: Vec<Hash512> = Vec::with_capacity(entries.len());
        let mut tree = Accumulator::empty();
        for (index, &bytes) in entries.iter().enumerate() {
            let at = |rule| Error::entry(state, set, index, rule);
            let value: T = decode_object(schema, schema_version(schema), bytes)
                .map_err(|_| at(Rule::Decode))?;
            if let Some(rule) = items
                .last()
                .and_then(|previous| successor(previous.value.key(), value.key()))
            {
                return Err(at(rule));
            }
            let hash = object_hash(bytes);
            tree.push(&hash).map_err(|_| at(Rule::Count))?;
            leaves.push(hash);
            items.push(Item { value, bytes });
        }
        if count_of(items.len()) != Some(commitment.count) {
            return Err(Error::set(state, set, Rule::Count));
        }
        if tree.root() != commitment.root {
            return Err(Error::set(state, set, Rule::Root));
        }
        Ok(Self {
            items,
            levels: levels_of(&leaves),
        })
    }

    /// The entries in key order.
    pub(crate) fn items(&self) -> &[Item<'a, T>] {
        &self.items
    }

    /// The position of the entry with `key`, if any.
    pub(crate) fn position(&self, key: &[u8]) -> Option<usize> {
        self.items
            .binary_search_by(|item| item.value.key().cmp(key))
            .ok()
    }

    /// The entry with `key`, if any.
    pub(crate) fn find(&self, key: &[u8]) -> Option<&T> {
        self.position(key)
            .and_then(|i| self.items.get(i))
            .map(|item| &item.value)
    }

    /// The bytes, position and inclusion proof of the entry with `key`,
    /// in `O(log n)`. The proof is checked again when `ityv-state` proves
    /// the entry against the genesis root.
    pub(crate) fn proof(&self, key: &[u8]) -> Option<(&'a [u8], u64, InclusionProof)> {
        let i = self.position(key)?;
        let item = self.items.get(i)?;
        Some((item.bytes, count_of(i)?, path(&self.levels, i)?))
    }
}

/// The appointment set: bare event hashes, strictly ascending, committed
/// by their sorted-set root (ADR-0028 decision 2).
#[derive(Debug, Clone)]
pub(crate) struct Appointments {
    hashes: Vec<Hash512>,
}

impl Appointments {
    /// Checks `hashes` against `commitment`.
    ///
    /// # Errors
    /// [`Rule::NotSorted`], [`Rule::Duplicate`], [`Rule::Count`],
    /// [`Rule::Root`].
    pub(crate) fn parse(
        state: u64,
        hashes: &[Hash512],
        commitment: &SetCommitment,
    ) -> Result<Self, Error> {
        let set = EntrySet::Appointments;
        for (index, pair) in hashes.windows(2).enumerate() {
            if let [a, b] = pair
                && let Some(rule) = successor(a.as_bytes(), b.as_bytes())
            {
                // The second hash of the pair is the one out of place.
                return Err(Error::entry(state, set, index.saturating_add(1), rule));
            }
        }
        if count_of(hashes.len()) != Some(commitment.count) {
            return Err(Error::set(state, set, Rule::Count));
        }
        let root = sorted_set_root(hashes).map_err(|_| Error::set(state, set, Rule::Count))?;
        if root != commitment.root {
            return Err(Error::set(state, set, Rule::Root));
        }
        Ok(Self {
            hashes: hashes.to_vec(),
        })
    }

    /// Whether `hash` is an appointment of this state.
    pub(crate) fn contains(&self, hash: &Hash512) -> bool {
        self.hashes
            .binary_search_by(|h| h.as_bytes().cmp(hash.as_bytes()))
            .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use ityv_encoding::Hash512;
    use ityv_ledger::{depth_for_size, inclusion_proof, root_of_leaves};

    use super::{levels_of, path};

    /// The levels give the reference tree's depth, root and proofs for
    /// every size up to 70 and every leaf; the empty set has one empty
    /// level.
    #[test]
    fn levels_match_the_reference_tree() {
        assert_eq!(levels_of(&[]), [Vec::<Hash512>::new()]);
        for n in 1..=70usize {
            let leaves: Vec<Hash512> = (0..n)
                .map(|i| Hash512([u8::try_from(i).unwrap(); 64]))
                .collect();
            let size = u64::try_from(n).unwrap();
            let levels = levels_of(&leaves);
            let depth = usize::try_from(depth_for_size(size)).unwrap();
            assert_eq!(levels.len(), depth + 1);
            assert_eq!(
                levels.last().unwrap()[0],
                root_of_leaves(&leaves.as_slice(), size).unwrap()
            );
            for i in 0..n {
                let index = u64::try_from(i).unwrap();
                let expected = inclusion_proof(&leaves.as_slice(), size, index).unwrap();
                assert_eq!(path(&levels, i).unwrap().hashes(), expected.hashes());
            }
        }
    }
}
