//! Checkpoints (PROTOCOL.md §5.4, ENCODING.md §8.4, ADR-0016 §4–5): the
//! `SignedCheckpoint` object, successor validation, and the witness's
//! signing state machine.
//!
//! # `SignedCheckpoint` byte layout (schema `0x0010`, version 1)
//!
//! | order | field | type |
//! |---|---|---|
//! | 1 | `body` | `Bytes<4096>`: the complete encoded `CheckpointBody` object, header included |
//! | 2 | `signatures` | `Array<entry, 64>`, entries ascending by `witness_id`, no duplicates |
//!
//! An entry is `witness_id: Ident<64>` (`u32` length ‖ bytes) ‖
//! `signature: [u8; 4691]` (a `HybridSignature`, `mldsa87[4627] ‖ ed25519[64]`),
//! and each signature is the hybrid signature of the `body` bytes under
//! purpose `checkpoint`. Decoding re-decodes `body` as a `CheckpointBody`
//! and applies every rule of ENCODING.md §8.3 to it; the quorum, roster and
//! diversity checks are [`crate::policy`]'s.
//!
//! # Witness rule
//!
//! [`WitnessMemory::may_sign`] is `HonestSign` of
//! `docs/models/LedgerWitness.tla`: a witness signs body `b` only if
//! `b.checkpoint_seq` is the next sequence number after the last body it
//! signed and `b` extends that body's tree (the consistency proof), and
//! never two bodies at one sequence number (the memory advances when a
//! token is consumed). The remaining VC-012 conditions (previous hash,
//! genesis, recomputed set roots) are checked in the same call.

use ityv_encoding::{
    CheckpointBody, Decode, Encode, Error as EncodingError, ErrorKind, Hash512, Ident, Reader,
    SCHEMA_CHECKPOINT_BODY, SCHEMA_VERSION_1, SchemaId, Seq, TreeSize, Writer, decode_object,
};

use crate::error::{Error, Root};
use crate::merkle::{ConsistencyProof, sorted_set_root, verify_consistency};
use crate::verified::Verified;

/// `SignedCheckpoint` (ENCODING.md §6, `0x0010`).
pub const SCHEMA_SIGNED_CHECKPOINT: SchemaId = SchemaId::new(0x0010);
/// Maximum length of the embedded `CheckpointBody` object bytes.
pub const MAX_BODY_LEN: usize = 4096;
/// Maximum number of witness signatures on one checkpoint.
pub const MAX_SIGNATURES: usize = 64;
/// Maximum length of a witness identifier.
pub const MAX_WITNESS_ID_LEN: usize = 64;
/// Length of one hybrid signature.
pub const SIGNATURE_LEN: usize = ityv_crypto::HybridSignature::ENCODED_LEN;

/// One witness signature as supplied to the encoder.
#[derive(Debug, Clone, Copy)]
pub struct WitnessSignatureEntry<'a> {
    /// The witness identifier from the genesis roster.
    pub witness_id: Ident<'a>,
    /// The witness's hybrid signature over the body bytes.
    pub signature: &'a ityv_crypto::HybridSignature,
}

/// A witness signature read back from an encoded object.
#[derive(Debug, Clone)]
pub struct WitnessSignatureRef<'a> {
    witness_id: Ident<'a>,
    signature: ityv_crypto::HybridSignature,
}

impl<'a> WitnessSignatureRef<'a> {
    /// The witness identifier.
    #[must_use]
    pub const fn witness_id(&self) -> Ident<'a> {
        self.witness_id
    }

    /// The signature.
    #[must_use]
    pub const fn signature(&self) -> &ityv_crypto::HybridSignature {
        &self.signature
    }
}

/// The inputs to encode a `SignedCheckpoint`: the body object bytes and the
/// witness signatures, which must already be ascending by identifier.
#[derive(Debug, Clone, Copy)]
pub struct SignedCheckpointParts<'a> {
    body_bytes: &'a [u8],
    entries: &'a [WitnessSignatureEntry<'a>],
}

impl<'a> SignedCheckpointParts<'a> {
    /// Checks the structural rules and builds the parts.
    ///
    /// # Errors
    /// [`Error::Encoding`] if `body_bytes` is not a canonical `CheckpointBody`
    /// object or is too long, [`Error::Capacity`] for more than
    /// [`MAX_SIGNATURES`] entries, [`Error::NotSorted`] or [`Error::Duplicate`]
    /// for identifiers out of order, [`Error::RosterInvalid`] for an
    /// identifier longer than [`MAX_WITNESS_ID_LEN`].
    pub fn new(
        body_bytes: &'a [u8],
        entries: &'a [WitnessSignatureEntry<'a>],
    ) -> Result<Self, Error> {
        if body_bytes.len() > MAX_BODY_LEN {
            return Err(Error::Encoding(EncodingError::new(
                ErrorKind::LengthExceedsMax,
                0,
            )));
        }
        let _: CheckpointBody<'a> =
            decode_object(SCHEMA_CHECKPOINT_BODY, SCHEMA_VERSION_1, body_bytes)?;
        if entries.len() > MAX_SIGNATURES {
            return Err(Error::Capacity);
        }
        let mut previous: Option<&[u8]> = None;
        for entry in entries {
            let id = entry.witness_id.as_bytes();
            if id.len() > MAX_WITNESS_ID_LEN {
                return Err(Error::RosterInvalid);
            }
            if let Some(prev) = previous {
                match prev.cmp(id) {
                    core::cmp::Ordering::Less => {}
                    core::cmp::Ordering::Equal => return Err(Error::Duplicate),
                    core::cmp::Ordering::Greater => return Err(Error::NotSorted),
                }
            }
            previous = Some(id);
        }
        Ok(Self {
            body_bytes,
            entries,
        })
    }

    /// The body object bytes.
    #[must_use]
    pub const fn body_bytes(&self) -> &'a [u8] {
        self.body_bytes
    }

    /// The signature entries.
    #[must_use]
    pub const fn entries(&self) -> &'a [WitnessSignatureEntry<'a>] {
        self.entries
    }
}

fn entry_len(id: &Ident<'_>) -> usize {
    id.byte_len()
        .saturating_add(4)
        .saturating_add(SIGNATURE_LEN)
}

impl Encode for SignedCheckpointParts<'_> {
    fn encoded_len(&self) -> usize {
        let entries = self.entries.iter().fold(4usize, |acc, e| {
            acc.saturating_add(entry_len(&e.witness_id))
        });
        self.body_bytes
            .len()
            .saturating_add(4)
            .saturating_add(entries)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        w.write_bytes(self.body_bytes, MAX_BODY_LEN)?;
        w.write_count(self.entries.len(), MAX_SIGNATURES)?;
        for entry in self.entries {
            w.write_ident(&entry.witness_id, MAX_WITNESS_ID_LEN)?;
            entry.signature.encode(w)?;
        }
        Ok(())
    }
}

/// One signature entry of a decoded object: the identifier and the raw
/// signature bytes, both borrowed from the object.
#[derive(Debug, Clone, Copy)]
struct EntryRef<'a> {
    witness_id: Ident<'a>,
    signature: &'a [u8; SIGNATURE_LEN],
}

/// A decoded `SignedCheckpoint`. Decoding proves only that the bytes are
/// well formed; validity against the roster and the quorum is
/// [`crate::policy::evaluate`]'s result.
#[derive(Debug, Clone, Copy)]
pub struct SignedCheckpoint<'a> {
    body_bytes: &'a [u8],
    body: CheckpointBody<'a>,
    entries: [Option<EntryRef<'a>>; MAX_SIGNATURES],
    count: usize,
}

impl<'a> SignedCheckpoint<'a> {
    /// The body object bytes (what every witness signed).
    #[must_use]
    pub const fn body_bytes(&self) -> &'a [u8] {
        self.body_bytes
    }

    /// The decoded body.
    #[must_use]
    pub const fn body(&self) -> &CheckpointBody<'a> {
        &self.body
    }

    /// Object hash of the body bytes: what the next checkpoint's
    /// `previous_checkpoint_hash` must equal.
    #[must_use]
    pub fn body_hash(&self) -> Hash512 {
        ityv_crypto::object_hash(self.body_bytes)
    }

    /// Number of signature entries.
    #[must_use]
    pub const fn signature_count(&self) -> usize {
        self.count
    }

    /// The signature entries in order, decoded on demand.
    #[must_use]
    pub fn signatures(&self) -> Signatures<'a> {
        Signatures {
            entries: self.entries,
            next: 0,
            count: self.count,
        }
    }
}

/// Iterator over the signature entries of a [`SignedCheckpoint`].
#[derive(Debug)]
pub struct Signatures<'a> {
    entries: [Option<EntryRef<'a>>; MAX_SIGNATURES],
    next: usize,
    count: usize,
}

impl<'a> Iterator for Signatures<'a> {
    type Item = WitnessSignatureRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.count {
            return None;
        }
        let entry = (*self.entries.get(self.next)?)?;
        self.next = self.next.saturating_add(1);
        let mut reader = Reader::new(entry.signature);
        // A fixed-width signature has no invalid encodings; the error path
        // would only end the iteration early.
        let signature = ityv_crypto::HybridSignature::decode(&mut reader).ok()?;
        Some(WitnessSignatureRef {
            witness_id: entry.witness_id,
            signature,
        })
    }
}

impl Encode for SignedCheckpoint<'_> {
    fn encoded_len(&self) -> usize {
        let entries = self
            .entries
            .iter()
            .take(self.count)
            .flatten()
            .fold(4usize, |acc, e| {
                acc.saturating_add(entry_len(&e.witness_id))
            });
        self.body_bytes
            .len()
            .saturating_add(4)
            .saturating_add(entries)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        w.write_bytes(self.body_bytes, MAX_BODY_LEN)?;
        w.write_count(self.count, MAX_SIGNATURES)?;
        for entry in self.entries.iter().take(self.count).flatten() {
            w.write_ident(&entry.witness_id, MAX_WITNESS_ID_LEN)?;
            w.write_array(entry.signature)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for SignedCheckpoint<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        let body_at = r.position();
        let body_bytes = r.read_bytes(MAX_BODY_LEN)?;
        let body: CheckpointBody<'a> =
            decode_object(SCHEMA_CHECKPOINT_BODY, SCHEMA_VERSION_1, body_bytes).map_err(
                |inner| {
                    // Report the inner offset relative to the whole object.
                    let offset = body_at
                        .checked_add(4)
                        .and_then(|p| p.checked_add(inner.offset()))
                        .unwrap_or(body_at);
                    EncodingError::new(inner.kind(), offset)
                },
            )?;
        let count = r.read_count(MAX_SIGNATURES)?;
        let mut entries: [Option<EntryRef<'a>>; MAX_SIGNATURES] = [None; MAX_SIGNATURES];
        let mut previous: Option<&[u8]> = None;
        for slot in entries.iter_mut().take(count) {
            let id_at = r.position();
            let witness_id = r.read_ident(MAX_WITNESS_ID_LEN)?;
            Reader::check_ascending(previous, witness_id.as_bytes(), id_at)?;
            previous = Some(witness_id.as_bytes());
            let sig_at = r.position();
            let raw = r.take(SIGNATURE_LEN)?;
            let signature: &'a [u8; SIGNATURE_LEN] = raw
                .try_into()
                .map_err(|_| EncodingError::new(ErrorKind::UnexpectedEnd, sig_at))?;
            *slot = Some(EntryRef {
                witness_id,
                signature,
            });
        }
        Ok(Self {
            body_bytes,
            body,
            entries,
            count,
        })
    }
}

/// What [`validate_successor`] verified.
#[derive(Debug, Clone, Copy)]
pub struct Successor<'a> {
    prev: Option<(&'a CheckpointBody<'a>, &'a Hash512)>,
    body: &'a CheckpointBody<'a>,
    genesis_hash: &'a Hash512,
}

impl<'a> Successor<'a> {
    /// The previous body and its hash, if any.
    #[must_use]
    pub const fn prev(&self) -> Option<(&'a CheckpointBody<'a>, &'a Hash512)> {
        self.prev
    }
    /// The validated body.
    #[must_use]
    pub const fn body(&self) -> &'a CheckpointBody<'a> {
        self.body
    }
    /// The genesis hash both are bound to.
    #[must_use]
    pub const fn genesis_hash(&self) -> &'a Hash512 {
        self.genesis_hash
    }
}

/// Checks that `body` validly follows `prev` (the previous body and the
/// object hash of its bytes): `checkpoint_seq` is `prev + 1` (or 1 with an
/// all-zero previous hash when there is no predecessor),
/// `previous_checkpoint_hash` equals the previous body hash, `tree_size`
/// does not decrease, the election, ledger and key-set identifiers are
/// unchanged, and `genesis_hash` equals the expected genesis.
///
/// # Errors
/// [`Error::SequenceGap`], [`Error::PreviousHashMismatch`],
/// [`Error::TreeShrank`], [`Error::ElectionMismatch`],
/// [`Error::LedgerMismatch`], [`Error::GenesisMismatch`].
pub fn validate_successor<'a>(
    prev: Option<(&'a CheckpointBody<'a>, &'a Hash512)>,
    body: &'a CheckpointBody<'a>,
    genesis_hash: &'a Hash512,
) -> Result<Verified<Successor<'a>>, Error> {
    let parts = body.parts();
    if parts.genesis_hash != *genesis_hash {
        return Err(Error::GenesisMismatch);
    }
    match prev {
        None => {
            if !parts.checkpoint_seq.is_first() {
                return Err(Error::SequenceGap);
            }
            if !parts.previous_checkpoint_hash.is_zero() {
                return Err(Error::PreviousHashMismatch);
            }
        }
        Some((prev_body, prev_hash)) => {
            let p = prev_body.parts();
            let expected = p
                .checkpoint_seq
                .get()
                .checked_add(1)
                .ok_or(Error::SequenceGap)?;
            if parts.checkpoint_seq.get() != expected {
                return Err(Error::SequenceGap);
            }
            if parts.previous_checkpoint_hash != *prev_hash {
                return Err(Error::PreviousHashMismatch);
            }
            if parts.tree_size < p.tree_size {
                return Err(Error::TreeShrank);
            }
            if parts.election_id != p.election_id {
                return Err(Error::ElectionMismatch);
            }
            if parts.ledger_id != p.ledger_id || parts.keyset_id != p.keyset_id {
                return Err(Error::LedgerMismatch);
            }
            if p.genesis_hash != *genesis_hash {
                return Err(Error::GenesisMismatch);
            }
        }
    }
    Ok(Verified::new(Successor {
        prev,
        body,
        genesis_hash,
    }))
}

/// The last checkpoint a witness signed.
///
/// Encoding: `seq: u64` ‖ `tree_size: u64` ‖ `root_hash: Hash512` ‖
/// `body_hash: Hash512`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LastSigned {
    seq: Seq,
    tree_size: TreeSize,
    root_hash: Hash512,
    body_hash: Hash512,
}

impl LastSigned {
    /// The sequence number.
    #[must_use]
    pub const fn seq(&self) -> Seq {
        self.seq
    }
    /// The tree size.
    #[must_use]
    pub const fn tree_size(&self) -> TreeSize {
        self.tree_size
    }
    /// The ledger root.
    #[must_use]
    pub const fn root_hash(&self) -> &Hash512 {
        &self.root_hash
    }
    /// The object hash of the body bytes.
    #[must_use]
    pub const fn body_hash(&self) -> &Hash512 {
        &self.body_hash
    }
}

impl Encode for LastSigned {
    fn encoded_len(&self) -> usize {
        8 + 8 + 64 + 64
    }
    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        self.seq.encode(w)?;
        self.tree_size.encode(w)?;
        self.root_hash.encode(w)?;
        self.body_hash.encode(w)
    }
}

impl<'a> Decode<'a> for LastSigned {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        Ok(Self {
            seq: Seq::decode(r)?,
            tree_size: TreeSize::decode(r)?,
            root_hash: Hash512::decode(r)?,
            body_hash: Hash512::decode(r)?,
        })
    }
}

/// A witness's persistent memory of what it last signed (ADR-0016 §4).
///
/// Encoding: `Option<LastSigned>`. The host must persist the memory before
/// releasing a signature; a witness that signs and then loses its memory
/// could be induced to sign a fork at the same sequence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct WitnessMemory {
    last: Option<LastSigned>,
}

/// What [`WitnessMemory::may_sign`] verified: a body this witness may sign.
#[derive(Debug, Clone, Copy)]
pub struct Signable<'a> {
    body: CheckpointBody<'a>,
    body_bytes: &'a [u8],
    body_hash: Hash512,
}

impl<'a> Signable<'a> {
    /// The decoded body.
    #[must_use]
    pub const fn body(&self) -> &CheckpointBody<'a> {
        &self.body
    }
    /// The body bytes to sign under purpose `checkpoint`.
    #[must_use]
    pub const fn body_bytes(&self) -> &'a [u8] {
        self.body_bytes
    }
    /// The object hash of the body bytes.
    #[must_use]
    pub const fn body_hash(&self) -> &Hash512 {
        &self.body_hash
    }
}

impl WitnessMemory {
    /// A witness that has signed nothing yet.
    #[must_use]
    pub const fn new() -> Self {
        Self { last: None }
    }

    /// Rebuilds a memory from a persisted record.
    #[must_use]
    pub const fn from_last(last: Option<LastSigned>) -> Self {
        Self { last }
    }

    /// The last signed checkpoint, if any.
    #[must_use]
    pub const fn last(&self) -> Option<&LastSigned> {
        self.last.as_ref()
    }

    /// Decides whether this witness may sign the checkpoint body in
    /// `body_bytes` (VC-012, VC-013; `HonestSign` in the TLA+ model):
    ///
    /// 1. `checkpoint_seq` is the last signed sequence plus one (1 if none);
    /// 2. `previous_checkpoint_hash` is the hash of the last signed body
    ///    (all zeros if none);
    /// 3. `tree_size` does not decrease and `consistency` proves that the
    ///    body's tree extends the last signed tree (from the empty tree if
    ///    none, which requires an empty proof);
    /// 4. `genesis_hash` equals `genesis_hash`;
    /// 5. `box_close_root` and `dispute_root` equal the sorted-set roots of
    ///    `box_close_hashes` and `dispute_hashes`.
    ///
    /// # Errors
    /// [`Error::Encoding`], [`Error::SequenceGap`],
    /// [`Error::PreviousHashMismatch`], [`Error::TreeShrank`],
    /// [`Error::ProofInvalid`], [`Error::GenesisMismatch`],
    /// [`Error::RootMismatch`], [`Error::NotSorted`], [`Error::Duplicate`].
    pub fn may_sign<'a>(
        &self,
        body_bytes: &'a [u8],
        consistency: &ConsistencyProof,
        box_close_hashes: &[Hash512],
        dispute_hashes: &[Hash512],
        genesis_hash: &Hash512,
    ) -> Result<Verified<Signable<'a>>, Error> {
        let body: CheckpointBody<'a> =
            decode_object(SCHEMA_CHECKPOINT_BODY, SCHEMA_VERSION_1, body_bytes)?;
        let parts = body.parts();
        let (expected_seq, expected_prev, old_size, old_root) = match &self.last {
            None => (1u64, Hash512::ZERO, 0u64, crate::merkle::EMPTY_ROOT),
            Some(last) => (
                last.seq.get().checked_add(1).ok_or(Error::SequenceGap)?,
                last.body_hash,
                last.tree_size.get(),
                last.root_hash,
            ),
        };
        if parts.checkpoint_seq.get() != expected_seq {
            return Err(Error::SequenceGap);
        }
        if parts.previous_checkpoint_hash != expected_prev {
            return Err(Error::PreviousHashMismatch);
        }
        if parts.tree_size.get() < old_size {
            return Err(Error::TreeShrank);
        }
        let _consistent = verify_consistency(
            old_size,
            &old_root,
            parts.tree_size.get(),
            &parts.root_hash,
            consistency,
        )?;
        if parts.genesis_hash != *genesis_hash {
            return Err(Error::GenesisMismatch);
        }
        if sorted_set_root(box_close_hashes)? != parts.box_close_root {
            return Err(Error::RootMismatch(Root::BoxClose));
        }
        if sorted_set_root(dispute_hashes)? != parts.dispute_root {
            return Err(Error::RootMismatch(Root::Dispute));
        }
        Ok(Verified::new(Signable {
            body,
            body_bytes,
            body_hash: ityv_crypto::object_hash(body_bytes),
        }))
    }

    /// Records that the witness signed the body in `token`. The result must
    /// be persisted before the signature leaves the witness.
    pub fn advance(&mut self, token: &Verified<Signable<'_>>) {
        let signable = token.get();
        let parts = signable.body.parts();
        self.last = Some(LastSigned {
            seq: parts.checkpoint_seq,
            tree_size: parts.tree_size,
            root_hash: parts.root_hash,
            body_hash: signable.body_hash,
        });
    }
}

impl Encode for WitnessMemory {
    fn encoded_len(&self) -> usize {
        self.last.encoded_len()
    }
    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        self.last.encode(w)
    }
}

impl<'a> Decode<'a> for WitnessMemory {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        Ok(Self {
            last: Option::decode(r)?,
        })
    }
}
