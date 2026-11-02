//! One genesis entry set, decoded and checked whole (ADR-0028 decision 2,
//! VC-104): every entry is the canonical object of the set's schema, the
//! set is strictly ascending by key, and the count and root recomputed
//! from the entries' object hashes are the body's.

use alloc::vec::Vec;
use core::cmp::Ordering;

use ityv_crypto::hash::object_hash;
use ityv_encoding::{
    EntrySet, GenesisEntry, Hash512, SCHEMA_VERSION_1, SetCommitment, decode_object,
};
use ityv_ledger::{Accumulator, InclusionProof, inclusion_proof, sorted_set_root};

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
    leaves: Vec<Hash512>,
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
        let mut leaves = Vec::with_capacity(entries.len());
        let mut tree = Accumulator::empty();
        for (index, &bytes) in entries.iter().enumerate() {
            let at = |rule| Error::entry(state, set, index, rule);
            let value: T =
                decode_object(schema, SCHEMA_VERSION_1, bytes).map_err(|_| at(Rule::Decode))?;
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
        Ok(Self { items, leaves })
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

    /// The bytes, position and inclusion proof of the entry with `key`.
    pub(crate) fn proof(&self, key: &[u8]) -> Option<(&'a [u8], u64, InclusionProof)> {
        let i = self.position(key)?;
        let item = self.items.get(i)?;
        let size = count_of(self.leaves.len())?;
        let index = count_of(i)?;
        let proof = inclusion_proof(&self.leaves.as_slice(), size, index).ok()?;
        Some((item.bytes, index, proof))
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
