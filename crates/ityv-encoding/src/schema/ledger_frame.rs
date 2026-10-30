//! `LedgerFrame` (schema `0x0001`, version 1): the header of one evidence
//! ledger frame.
//!
//! Field order: `election_id`, `seq`, `prev_hash`, `event_schema_id`,
//! `event_hash`.

use crate::codec::{Decode, Encode};
use crate::error::Error;
use crate::primitives::{ElectionId, Hash512, SchemaId, Seq};
use crate::reader::Reader;
use crate::writer::Writer;

/// One frame of the append-only evidence ledger.
///
/// This object commits to the frame's position (`seq`), its predecessor
/// (`prev_hash`), and the event it carries (`event_schema_id`,
/// `event_hash`). It does **not** prove that the event's content is true,
/// nor that the chain it belongs to was witnessed; those are the ledger and
/// checkpoint verifiers' jobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LedgerFrame<'a> {
    election_id: ElectionId<'a>,
    seq: Seq,
    prev_hash: Hash512,
    event_schema_id: SchemaId,
    event_hash: Hash512,
}

impl<'a> LedgerFrame<'a> {
    /// Builds a frame. All invariants are carried by the field types.
    #[must_use]
    pub const fn new(
        election_id: ElectionId<'a>,
        seq: Seq,
        prev_hash: Hash512,
        event_schema_id: SchemaId,
        event_hash: Hash512,
    ) -> Self {
        Self {
            election_id,
            seq,
            prev_hash,
            event_schema_id,
            event_hash,
        }
    }

    /// The election this frame belongs to.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.election_id
    }

    /// The one-based position of this frame in the ledger.
    #[must_use]
    pub const fn seq(&self) -> Seq {
        self.seq
    }

    /// Hash of the previous frame, or all zeros for the first frame.
    #[must_use]
    pub const fn prev_hash(&self) -> &Hash512 {
        &self.prev_hash
    }

    /// Schema of the event carried by this frame.
    #[must_use]
    pub const fn event_schema_id(&self) -> SchemaId {
        self.event_schema_id
    }

    /// Hash of the canonical encoding of the carried event.
    #[must_use]
    pub const fn event_hash(&self) -> &Hash512 {
        &self.event_hash
    }
}

impl Encode for LedgerFrame<'_> {
    fn encoded_len(&self) -> usize {
        self.election_id
            .encoded_len()
            .saturating_add(self.seq.encoded_len())
            .saturating_add(self.prev_hash.encoded_len())
            .saturating_add(self.event_schema_id.encoded_len())
            .saturating_add(self.event_hash.encoded_len())
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.election_id.encode(w)?;
        self.seq.encode(w)?;
        self.prev_hash.encode(w)?;
        self.event_schema_id.encode(w)?;
        self.event_hash.encode(w)
    }
}

impl<'a> Decode<'a> for LedgerFrame<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let seq = Seq::decode(r)?;
        let prev_hash = Hash512::decode(r)?;
        let event_schema_id = SchemaId::decode(r)?;
        let event_hash = Hash512::decode(r)?;
        Ok(Self::new(
            election_id,
            seq,
            prev_hash,
            event_schema_id,
            event_hash,
        ))
    }
}
