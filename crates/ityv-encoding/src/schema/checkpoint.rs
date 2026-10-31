//! `CheckpointBody` (schema `0x0004`, version 1): the witness-signed statement
//! about a ledger prefix.
//!
//! Field order: `election_id`, `ledger_id`, `keyset_id`, `checkpoint_seq`,
//! `tree_size`, `root_hash`, `previous_checkpoint_hash`, `box_close_root`,
//! `dispute_root`, `genesis_hash`, `time_bucket`.
//!
//! Invariant: `previous_checkpoint_hash` is all zeros if and only if
//! `checkpoint_seq == 1`.

use crate::codec::{Decode, Encode};
use crate::error::{Error, Kind};
use crate::primitives::{ElectionId, Hash512, KeysetId, LedgerId, Seq, TimeBucket, TreeSize};
use crate::reader::Reader;
use crate::writer::Writer;

/// Unvalidated inputs for [`CheckpointBody::new`].
///
/// This is the only place raw fields are assembled; the constructor checks
/// the cross-field invariant and the result is immutable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckpointParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The ledger being checkpointed.
    pub ledger_id: LedgerId<'a>,
    /// The witness key set whose signatures are expected.
    pub keyset_id: KeysetId<'a>,
    /// One-based checkpoint sequence number.
    pub checkpoint_seq: Seq,
    /// Number of ledger leaves covered.
    pub tree_size: TreeSize,
    /// Merkle root over the covered leaves.
    pub root_hash: Hash512,
    /// Hash of the previous checkpoint body, or all zeros for the first.
    pub previous_checkpoint_hash: Hash512,
    /// Root over the signed box-close envelopes.
    pub box_close_root: Hash512,
    /// Root over the open dispute events.
    pub dispute_root: Hash512,
    /// Hash of the genesis this checkpoint is bound to.
    pub genesis_hash: Hash512,
    /// Coarse time bucket of the checkpoint proposal.
    pub time_bucket: TimeBucket,
}

/// A validated checkpoint body.
///
/// A decoded body proves only that the bytes are well formed. Whether the
/// quorum signed it, whether the root matches the ledger, and whether the
/// previous hash chains to an externally pinned checkpoint are checked by the
/// ledger and witness verifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckpointBody<'a> {
    parts: CheckpointParts<'a>,
}

impl<'a> CheckpointBody<'a> {
    /// Validates the cross-field invariant and builds the body.
    ///
    /// Returns `None` unless `previous_checkpoint_hash.is_zero()` equals
    /// `checkpoint_seq.is_first()`.
    #[must_use]
    pub fn new(parts: &CheckpointParts<'a>) -> Option<Self> {
        if parts.previous_checkpoint_hash.is_zero() == parts.checkpoint_seq.is_first() {
            Some(Self { parts: *parts })
        } else {
            None
        }
    }

    /// The validated fields.
    #[must_use]
    pub const fn parts(&self) -> &CheckpointParts<'a> {
        &self.parts
    }
}

impl Encode for CheckpointBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.ledger_id.encoded_len())
            .saturating_add(p.keyset_id.encoded_len())
            .saturating_add(p.checkpoint_seq.encoded_len())
            .saturating_add(p.tree_size.encoded_len())
            .saturating_add(p.root_hash.encoded_len())
            .saturating_add(p.previous_checkpoint_hash.encoded_len())
            .saturating_add(p.box_close_root.encoded_len())
            .saturating_add(p.dispute_root.encoded_len())
            .saturating_add(p.genesis_hash.encoded_len())
            .saturating_add(p.time_bucket.encoded_len())
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.ledger_id.encode(w)?;
        p.keyset_id.encode(w)?;
        p.checkpoint_seq.encode(w)?;
        p.tree_size.encode(w)?;
        p.root_hash.encode(w)?;
        p.previous_checkpoint_hash.encode(w)?;
        p.box_close_root.encode(w)?;
        p.dispute_root.encode(w)?;
        p.genesis_hash.encode(w)?;
        p.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for CheckpointBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let ledger_id = LedgerId::decode(r)?;
        let keyset_id = KeysetId::decode(r)?;
        let checkpoint_seq = Seq::decode(r)?;
        let tree_size = TreeSize::decode(r)?;
        let root_hash = Hash512::decode(r)?;
        let previous_at = r.position();
        let previous_checkpoint_hash = Hash512::decode(r)?;
        let box_close_root = Hash512::decode(r)?;
        let dispute_root = Hash512::decode(r)?;
        let genesis_hash = Hash512::decode(r)?;
        let time_bucket = TimeBucket::decode(r)?;
        Self::new(&CheckpointParts {
            election_id,
            ledger_id,
            keyset_id,
            checkpoint_seq,
            tree_size,
            root_hash,
            previous_checkpoint_hash,
            box_close_root,
            dispute_root,
            genesis_hash,
            time_bucket,
        })
        .ok_or_else(|| Error::new(Kind::InvalidPreviousHash, previous_at))
    }
}
