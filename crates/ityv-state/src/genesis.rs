//! The pinned genesis and its entries (ADR-0028; PROTOCOL.md §4; VC-005,
//! VC-104, VC-105).
//!
//! Everything this crate takes from the genesis comes through here:
//!
//! 1. [`Pinned::new`] accepts a `SignedGenesis` only if the object hash of
//!    its `GenesisBody` is the pin the caller was given out of band
//!    (VC-005).
//! 2. [`Pinned::seal`] checks the signatures: the election commission's and
//!    the committee's under the keys the body names, and at least `q`
//!    witnesses from the witness set, each with a verification token, of
//!    the required organisations, providers and regions, no two signers
//!    sharing a key half (VC-104).
//! 3. [`Genesis::entry`] decodes one entry object and checks its inclusion
//!    proof against the root its set has now. The resulting [`Entry`] is
//!    the only way to hand a box, station, roster signer, route, policy or
//!    module to a state machine.
//! 4. [`Genesis::amend`] applies a `GenesisAmendment` with the next
//!    number, chained to the previous body, signed like the genesis
//!    (VC-105). It replaces the amendable set commitments; entries proved
//!    earlier stay valid for what they signed before (§4.3).
//!
//! What it does not prove: that a set is sorted and free of duplicate
//! keys, that the sets agree with each other (every box's station exists,
//! every unit's module is registered, and so on), or that every roster
//! entry's appointment is in the appointment set. An inclusion proof shows
//! one entry, not the absence of another; those checks need every entry
//! and belong to the full verifier (`ityv-verify`, VC-104).

use ityv_crypto::hash::object_hash;
use ityv_crypto::{HybridSigned, Verified};
use ityv_encoding::{
    ENTRY_SET_COUNT, ElectionId, GenesisBody, GenesisEntry, Hash512, MAX_GENESIS_WITNESSES,
    SCHEMA_VERSION_1, SetCommitment, SignedGenesis, WitnessRosterEntry, decode_object,
};
use ityv_ledger::{InclusionProof, verify_inclusion};

use crate::error::Error;
use crate::sig::{Key, check_pairs};

/// Signers of a genesis or amendment: the commission, the committee and
/// at most 64 witnesses.
const MAX_GENESIS_SIGNERS: usize = 66;

const _: () = assert!(MAX_GENESIS_SIGNERS == MAX_GENESIS_WITNESSES + 2);

/// A genesis entry whose inclusion in its set was proved against a pinned,
/// signed genesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry<T> {
    value: T,
    hash: Hash512,
    index: u64,
}

impl<T> Entry<T> {
    /// The entry.
    #[must_use]
    pub const fn get(&self) -> &T {
        &self.value
    }

    /// The entry object's hash (its leaf input).
    #[must_use]
    pub const fn hash(&self) -> &Hash512 {
        &self.hash
    }

    /// The entry's position in its set.
    #[must_use]
    pub const fn index(&self) -> u64 {
        self.index
    }

    /// An entry without a proof, for unit tests and Kani harnesses only.
    #[cfg(any(test, kani))]
    pub(crate) const fn unproved(value: T) -> Self {
        Self {
            value,
            hash: Hash512([0; 64]),
            index: 0,
        }
    }
}

/// Decodes `bytes` as an entry of `T`'s set and checks its inclusion proof
/// against `sets`.
fn prove<'a, T: GenesisEntry<'a>>(
    sets: &[SetCommitment; ENTRY_SET_COUNT],
    bytes: &'a [u8],
    index: u64,
    proof: &InclusionProof,
) -> Result<Entry<T>, Error> {
    let schema = T::SET.schema().ok_or(Error::Decode)?;
    let value: T = decode_object(schema, SCHEMA_VERSION_1, bytes).map_err(|_| Error::Decode)?;
    let set = sets.get(T::SET.index()).ok_or(Error::Decode)?;
    let hash = object_hash(bytes);
    let included = verify_inclusion(&set.root, set.count, index, &hash, proof)
        .map_err(|_| Error::NotIncluded)?;
    Ok(Entry {
        value,
        hash,
        index: included.get().index(),
    })
}

/// Number of distinct values among `values`.
fn distinct<'v>(values: impl Iterator<Item = &'v [u8]>) -> usize {
    let mut seen: [Option<&[u8]>; MAX_GENESIS_WITNESSES] = [None; MAX_GENESIS_WITNESSES];
    let mut count = 0usize;
    for v in values {
        if !seen.iter().take(count).flatten().any(|s| *s == v) {
            if let Some(slot) = seen.get_mut(count) {
                *slot = Some(v);
            }
            count = count.saturating_add(1);
        }
    }
    count
}

/// Checks the signatures of a genesis or amendment against `body`'s keys
/// and quorum (VC-104, VC-105).
fn check_seal(
    signed: &SignedGenesis<'_>,
    body: &GenesisBody<'_>,
    tokens: &[Verified<HybridSigned<'_>>],
    witnesses: &[Entry<WitnessRosterEntry<'_>>],
) -> Result<(), Error> {
    let count = signed.witness_count();
    let named = witnesses.len() == count
        && signed
            .witness_sigs()
            .zip(witnesses)
            .all(|(s, w)| s.witness_id.as_bytes() == w.get().witness_id.as_bytes());
    if !named {
        return Err(Error::NotRegistered);
    }
    let q = body.quorum();
    let entries = || witnesses.iter().map(Entry::get);
    let diverse = distinct(entries().map(|w| w.org_id.as_bytes())) >= usize::from(q.min_orgs)
        && distinct(entries().map(|w| w.provider.as_bytes())) >= usize::from(q.min_providers)
        && distinct(entries().map(|w| w.region.as_bytes())) >= usize::from(q.min_regions);
    if count < usize::from(q.quorum) || !diverse {
        return Err(Error::SignersShort);
    }
    let authorities = [
        (signed.commission_sig(), body.commission_key()),
        (signed.committee_sig(), body.committee_key()),
    ];
    let pairs = authorities.into_iter().map(Ok).chain(
        signed
            .witness_sigs()
            .zip(witnesses)
            .map(|(s, w)| Ok((s.sig, w.get().key))),
    );
    check_pairs::<MAX_GENESIS_SIGNERS, _>(
        signed.body_bytes(),
        signed.purpose(),
        tokens,
        count.saturating_add(2),
        pairs,
    )
}

/// A genesis whose body hash is the pin, not yet checked for signatures.
#[derive(Debug, Clone, Copy)]
pub struct Pinned<'a> {
    signed: &'a SignedGenesis<'a>,
    body: GenesisBody<'a>,
    hash: Hash512,
}

impl<'a> Pinned<'a> {
    /// Accepts `signed` if it carries a genesis body whose object hash is
    /// `pin` (VC-005). The pin must come from outside the source of the
    /// genesis: the gazette, the committee's site, the designated public
    /// verifiers, print.
    ///
    /// # Errors
    /// [`Error::Mismatch`] for an amendment, [`Error::Pin`] for another
    /// hash.
    pub fn new(pin: &Hash512, signed: &'a SignedGenesis<'a>) -> Result<Self, Error> {
        let body = signed.genesis().ok_or(Error::Mismatch)?;
        let hash = object_hash(signed.body_bytes());
        if hash != *pin {
            return Err(Error::Pin);
        }
        Ok(Self { signed, body, hash })
    }

    /// Proves one witness entry, for [`Self::seal`].
    ///
    /// # Errors
    /// As [`Genesis::entry`].
    pub fn witness(
        &self,
        bytes: &'a [u8],
        index: u64,
        proof: &InclusionProof,
    ) -> Result<Entry<WitnessRosterEntry<'a>>, Error> {
        prove(self.body.sets(), bytes, index, proof)
    }

    /// Checks the signatures. `tokens` are the verification tokens of the
    /// commission's, the committee's and each witness's signature, in that
    /// order; `witnesses` are the entries of the signing witnesses, in the
    /// order of their signatures.
    ///
    /// # Errors
    /// [`Error::NotRegistered`] if the witness entries do not name the
    /// signing witnesses one to one, [`Error::SignersShort`] for fewer than
    /// `q` witnesses or too little diversity, and the errors of
    /// [`crate::sig::check_event`] for the tokens.
    pub fn seal(
        self,
        tokens: &[Verified<HybridSigned<'_>>],
        witnesses: &[Entry<WitnessRosterEntry<'_>>],
    ) -> Result<Genesis<'a>, Error> {
        check_seal(self.signed, &self.body, tokens, witnesses)?;
        Ok(Genesis {
            body: self.body,
            hash: self.hash,
            sets: *self.body.sets(),
            release_manifest_hash: *self.body.release_manifest_hash(),
            seq: 0,
            head: self.hash,
        })
    }
}

/// A pinned genesis with its signatures checked, and the amendments
/// applied to it so far.
#[derive(Debug, Clone, Copy)]
pub struct Genesis<'a> {
    body: GenesisBody<'a>,
    hash: Hash512,
    sets: [SetCommitment; ENTRY_SET_COUNT],
    release_manifest_hash: Hash512,
    seq: u64,
    head: Hash512,
}

impl<'a> Genesis<'a> {
    /// Proves one entry of `T`'s set against the set's current root.
    ///
    /// # Errors
    /// [`Error::Decode`] if `bytes` is not a complete object of the set's
    /// schema, [`Error::NotIncluded`] if the proof does not lead to the
    /// root.
    pub fn entry<T: GenesisEntry<'a>>(
        &self,
        bytes: &'a [u8],
        index: u64,
        proof: &InclusionProof,
    ) -> Result<Entry<T>, Error> {
        prove(&self.sets, bytes, index, proof)
    }

    /// Applies the next amendment (PROTOCOL.md §4.3, VC-105). `tokens` and
    /// `witnesses` are as for [`Pinned::seal`]; the witness entries are
    /// proved with [`Self::entry`].
    ///
    /// # Errors
    /// [`Error::Mismatch`] for a genesis body, another election, a number
    /// other than the next, or a previous hash other than the last body's;
    /// the errors of [`Pinned::seal`].
    pub fn amend(
        &self,
        signed: &SignedGenesis<'_>,
        tokens: &[Verified<HybridSigned<'_>>],
        witnesses: &[Entry<WitnessRosterEntry<'_>>],
    ) -> Result<Self, Error> {
        let amendment = signed.amendment().ok_or(Error::Mismatch)?;
        let p = amendment.parts();
        let next = self.seq.checked_add(1).ok_or(Error::Overflow)?;
        if p.election_id.as_bytes() != self.body.election_id().as_bytes()
            || p.seq != next
            || p.previous_hash != self.head
        {
            return Err(Error::Mismatch);
        }
        check_seal(signed, &self.body, tokens, witnesses)?;
        let mut sets = self.sets;
        for (slot, new) in sets.iter_mut().zip(p.sets) {
            *slot = new;
        }
        Ok(Self {
            sets,
            release_manifest_hash: p.release_manifest_hash,
            seq: next,
            head: object_hash(signed.body_bytes()),
            ..*self
        })
    }

    /// The genesis body.
    #[must_use]
    pub const fn body(&self) -> &GenesisBody<'a> {
        &self.body
    }

    /// The election.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.body.election_id()
    }

    /// The genesis hash (the pin).
    #[must_use]
    pub const fn hash(&self) -> &Hash512 {
        &self.hash
    }

    /// The hash of the last body applied (the genesis, or the last
    /// amendment).
    #[must_use]
    pub const fn head(&self) -> &Hash512 {
        &self.head
    }

    /// Amendments applied.
    #[must_use]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    /// The current set commitments, in `EntrySet` order.
    #[must_use]
    pub const fn sets(&self) -> &[SetCommitment; ENTRY_SET_COUNT] {
        &self.sets
    }

    /// The release manifest in force.
    #[must_use]
    pub const fn release_manifest_hash(&self) -> &Hash512 {
        &self.release_manifest_hash
    }

    /// The election commission's key.
    #[must_use]
    pub const fn commission_key(&self) -> &'a Key {
        self.body.commission_key()
    }

    /// The Independent Verification Committee's key.
    #[must_use]
    pub const fn committee_key(&self) -> &'a Key {
        self.body.committee_key()
    }
}
