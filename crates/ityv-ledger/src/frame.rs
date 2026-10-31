//! Frame chain rules and the on-disk frame stream (PROTOCOL.md §5.1,
//! ADR-0016 §3).
//!
//! A ledger is an append-only sequence of `LedgerFrame` objects. Frame `i`
//! carries `seq = i` (one-based) and `prev_hash` = the object hash of frame
//! `i − 1` (all zeros for the first frame). The frame hash is the leaf input
//! of the ledger Merkle tree.
//!
//! On disk the ledger is a stream of records `u32_be len ‖ frame object`.
//! A truncated last record is a torn tail: it is reported with its offset
//! and never repaired; every record before it stays valid (VC-010).
//!
//! This module does not store anything and does not know about closing or
//! event contents; it decides only whether bytes form a valid next frame.

use ityv_encoding::{
    Decode, ElectionId, Encode, Error as EncodingError, HEADER_LEN, Hash512, LedgerFrame, Reader,
    SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, SchemaId, Seq, Writer, decode_object,
};

use crate::error::Error;
use crate::merkle::Accumulator;
use crate::verified::Verified;

/// Smallest possible frame object: header plus a one-byte election id.
pub const MIN_FRAME_LEN: usize = HEADER_LEN + 4 + 1 + 8 + 64 + 4 + 64;
/// Largest possible frame object: header plus a 64-byte election id.
pub const MAX_FRAME_LEN: usize = HEADER_LEN + 4 + 64 + 8 + 64 + 4 + 64;
/// Length of the record length prefix.
pub const RECORD_PREFIX_LEN: usize = 4;

/// The head of a validated chain: the last frame's position and hash.
///
/// Encoding: `election_id: Ident<64>` ‖ `seq: u64` ‖ `hash: Hash512`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChainHead<'a> {
    election_id: ElectionId<'a>,
    seq: Seq,
    hash: Hash512,
}

impl<'a> ChainHead<'a> {
    /// Rebuilds a head from persisted fields.
    #[must_use]
    pub const fn from_parts(election_id: ElectionId<'a>, seq: Seq, hash: Hash512) -> Self {
        Self {
            election_id,
            seq,
            hash,
        }
    }

    /// The election.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.election_id
    }

    /// Sequence number of the last frame.
    #[must_use]
    pub const fn seq(&self) -> Seq {
        self.seq
    }

    /// Object hash of the last frame.
    #[must_use]
    pub const fn hash(&self) -> &Hash512 {
        &self.hash
    }
}

impl Encode for ChainHead<'_> {
    fn encoded_len(&self) -> usize {
        self.election_id
            .encoded_len()
            .saturating_add(8)
            .saturating_add(64)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        self.election_id.encode(w)?;
        self.seq.encode(w)?;
        self.hash.encode(w)
    }
}

impl<'a> Decode<'a> for ChainHead<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        Ok(Self {
            election_id: ElectionId::decode(r)?,
            seq: Seq::decode(r)?,
            hash: Hash512::decode(r)?,
        })
    }
}

/// What [`link`] verified: a frame that validly follows the head with
/// sequence `prev_seq` and hash `prev_hash` (none and all zeros for the
/// first frame).
#[derive(Debug, Clone, Copy)]
pub struct Linked<'a> {
    prev_seq: Option<Seq>,
    prev_hash: Hash512,
    frame: LedgerFrame<'a>,
    bytes: &'a [u8],
    hash: Hash512,
}

impl<'a> Linked<'a> {
    /// Sequence number of the predecessor, if any.
    #[must_use]
    pub const fn prev_seq(&self) -> Option<Seq> {
        self.prev_seq
    }

    /// Hash of the predecessor (all zeros for the first frame).
    #[must_use]
    pub const fn prev_hash(&self) -> &Hash512 {
        &self.prev_hash
    }

    /// The decoded frame.
    #[must_use]
    pub const fn frame(&self) -> &LedgerFrame<'a> {
        &self.frame
    }

    /// The frame's canonical bytes.
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The frame's object hash: the chain hash and the Merkle leaf input.
    #[must_use]
    pub const fn hash(&self) -> &Hash512 {
        &self.hash
    }

    /// The head of the chain after this frame.
    #[must_use]
    pub const fn head(&self) -> ChainHead<'a> {
        ChainHead {
            election_id: self.frame.election_id(),
            seq: self.frame.seq(),
            hash: self.hash,
        }
    }
}

/// Decodes `frame_bytes` as a `LedgerFrame` object and checks that it is the
/// valid successor of `prev`: `seq` is `prev.seq + 1` (or 1 with an all-zero
/// `prev_hash` when there is no predecessor), `prev_hash` is `prev.hash`,
/// and the election identifier is unchanged.
///
/// # Errors
/// [`Error::Encoding`] if the bytes are not a canonical frame object,
/// [`Error::SequenceGap`], [`Error::PreviousHashMismatch`],
/// [`Error::ElectionMismatch`].
pub fn link<'a>(
    prev: Option<&ChainHead<'_>>,
    frame_bytes: &'a [u8],
) -> Result<Verified<Linked<'a>>, Error> {
    let frame: LedgerFrame<'a> = decode_object(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, frame_bytes)?;
    match prev {
        None => {
            if !frame.seq().is_first() {
                return Err(Error::SequenceGap);
            }
            if !frame.prev_hash().is_zero() {
                return Err(Error::PreviousHashMismatch);
            }
        }
        Some(head) => {
            let expected = head.seq.get().checked_add(1).ok_or(Error::SequenceGap)?;
            if frame.seq().get() != expected {
                return Err(Error::SequenceGap);
            }
            if *frame.prev_hash() != head.hash {
                return Err(Error::PreviousHashMismatch);
            }
            if frame.election_id() != head.election_id {
                return Err(Error::ElectionMismatch);
            }
        }
    }
    let hash = ityv_crypto::object_hash(frame_bytes);
    Ok(Verified::new(Linked {
        prev_seq: prev.map(|h| h.seq),
        prev_hash: prev.map_or(Hash512::ZERO, |h| h.hash),
        frame,
        bytes: frame_bytes,
        hash,
    }))
}

/// Builds the frame that follows `prev` for an event.
///
/// # Errors
/// [`Error::ElectionMismatch`] if `election_id` differs from the head's,
/// [`Error::SequenceGap`] if the sequence number cannot be incremented.
pub fn next_frame<'a>(
    prev: Option<&ChainHead<'a>>,
    election_id: ElectionId<'a>,
    event_schema_id: SchemaId,
    event_hash: Hash512,
) -> Result<LedgerFrame<'a>, Error> {
    let (seq, prev_hash) = match prev {
        None => (Seq::FIRST, Hash512::ZERO),
        Some(head) => {
            if head.election_id != election_id {
                return Err(Error::ElectionMismatch);
            }
            let next = head.seq.get().checked_add(1).ok_or(Error::SequenceGap)?;
            (Seq::new(next).ok_or(Error::SequenceGap)?, head.hash)
        }
    };
    Ok(LedgerFrame::new(
        election_id,
        seq,
        prev_hash,
        event_schema_id,
        event_hash,
    ))
}

/// The chain head and the Merkle accumulator together: the state a writer or
/// a replaying verifier carries from frame to frame.
///
/// Encoding: `head: Option<ChainHead>` ‖ `accumulator: Accumulator`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainState<'a> {
    head: Option<ChainHead<'a>>,
    accumulator: Accumulator,
}

impl<'a> ChainState<'a> {
    /// The empty ledger.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            head: None,
            accumulator: Accumulator::empty(),
        }
    }

    /// Rebuilds a state from persisted parts. Returns `None` if the head's
    /// sequence number and the accumulator's size disagree.
    #[must_use]
    pub fn from_parts(head: Option<ChainHead<'a>>, accumulator: &Accumulator) -> Option<Self> {
        let expected = head.map_or(0, |h| h.seq.get());
        if accumulator.size() != expected {
            return None;
        }
        Some(Self {
            head,
            accumulator: *accumulator,
        })
    }

    /// The current head.
    #[must_use]
    pub const fn head(&self) -> Option<&ChainHead<'a>> {
        self.head.as_ref()
    }

    /// The accumulator over every frame hash so far.
    #[must_use]
    pub const fn accumulator(&self) -> &Accumulator {
        &self.accumulator
    }

    /// Links `frame_bytes` to the head, appends its hash to the tree and
    /// advances the head. On error nothing changes.
    ///
    /// # Errors
    /// Any error of [`link`], or [`Error::TreeFull`].
    pub fn append(&mut self, frame_bytes: &'a [u8]) -> Result<Hash512, Error> {
        let linked = link(self.head.as_ref(), frame_bytes)?;
        let linked = linked.into_inner();
        let mut accumulator = self.accumulator;
        accumulator.push(linked.hash())?;
        let hash = *linked.hash();
        self.head = Some(linked.head());
        self.accumulator = accumulator;
        Ok(hash)
    }
}

impl Encode for ChainState<'_> {
    fn encoded_len(&self) -> usize {
        self.head
            .encoded_len()
            .saturating_add(self.accumulator.encoded_len())
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        self.head.encode(w)?;
        self.accumulator.encode(w)
    }
}

impl<'a> Decode<'a> for ChainState<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        let at = r.position();
        let head: Option<ChainHead<'a>> = Option::decode(r)?;
        let accumulator = Accumulator::decode(r)?;
        Self::from_parts(head, &accumulator)
            .ok_or_else(|| EncodingError::new(ityv_encoding::ErrorKind::InvariantViolation, at))
    }
}

/// One record of the frame stream.
#[derive(Debug, Clone, Copy)]
pub struct Record<'a> {
    offset: usize,
    bytes: &'a [u8],
    frame: LedgerFrame<'a>,
}

impl<'a> Record<'a> {
    /// Offset of the record (its length prefix) in the stream.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// The frame object bytes, without the length prefix.
    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The decoded frame.
    #[must_use]
    pub const fn frame(&self) -> &LedgerFrame<'a> {
        &self.frame
    }
}

/// A parser over the on-disk stream `u32_be len ‖ frame object`, one record
/// at a time. After an error the stream yields nothing further; the error's
/// offset tells the host where the valid prefix ends.
#[derive(Debug)]
pub struct FrameStream<'a> {
    bytes: &'a [u8],
    pos: usize,
    stopped: bool,
}

impl<'a> FrameStream<'a> {
    /// Starts parsing at the beginning of `bytes`.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: 0,
            stopped: false,
        }
    }

    /// Offset of the next record, or of the first byte after the last
    /// record once the stream is exhausted.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Parses the next record.
    ///
    /// Returns `None` exactly at a record boundary at the end of the bytes.
    ///
    /// # Errors
    /// [`Error::TornTail`] if the bytes end inside a record,
    /// [`Error::CorruptRecord`] if a length prefix is impossible,
    /// [`Error::Record`] if the record is not a canonical frame object.
    pub fn next_record(&mut self) -> Option<Result<Record<'a>, Error>> {
        if self.stopped || self.pos >= self.bytes.len() {
            return None;
        }
        let result = self.parse_at(self.pos);
        match result {
            Ok((record, next)) => {
                self.pos = next;
                Some(Ok(record))
            }
            Err(err) => {
                self.stopped = true;
                Some(Err(err))
            }
        }
    }

    fn parse_at(&self, offset: usize) -> Result<(Record<'a>, usize), Error> {
        let rest = self.bytes.get(offset..).unwrap_or(&[]);
        let (prefix, after_prefix) = rest
            .split_first_chunk::<RECORD_PREFIX_LEN>()
            .ok_or(Error::TornTail { offset })?;
        let len = usize::try_from(u32::from_be_bytes(*prefix))
            .map_err(|_| Error::CorruptRecord { offset })?;
        if !(MIN_FRAME_LEN..=MAX_FRAME_LEN).contains(&len) {
            return Err(Error::CorruptRecord { offset });
        }
        let (bytes, _) = after_prefix
            .split_at_checked(len)
            .ok_or(Error::TornTail { offset })?;
        let frame: LedgerFrame<'a> = decode_object(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, bytes)
            .map_err(|inner| Error::Record { offset, inner })?;
        let next = offset
            .checked_add(RECORD_PREFIX_LEN)
            .and_then(|p| p.checked_add(len))
            .ok_or(Error::CorruptRecord { offset })?;
        Ok((
            Record {
                offset,
                bytes,
                frame,
            },
            next,
        ))
    }
}

impl<'a> Iterator for FrameStream<'a> {
    type Item = Result<Record<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_record()
    }
}

/// Writes one stream record (`u32_be len ‖ frame_bytes`).
///
/// # Errors
/// [`Error::CorruptRecord`] with offset 0 if `frame_bytes` is not a
/// possible frame length, or an encoding error if `out` is too small.
pub fn write_record(w: &mut Writer<'_>, frame_bytes: &[u8]) -> Result<(), Error> {
    let len = frame_bytes.len();
    if !(MIN_FRAME_LEN..=MAX_FRAME_LEN).contains(&len) {
        return Err(Error::CorruptRecord { offset: 0 });
    }
    let raw = u32::try_from(len).map_err(|_| Error::CorruptRecord { offset: 0 })?;
    w.write_u32(raw)?;
    w.write_slice(frame_bytes)?;
    Ok(())
}

/// Classification of a frame that arrives for a sequence number the ledger
/// already holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resend {
    /// The same bytes: the resend is idempotent and changes nothing.
    Identical,
    /// Different bytes for the same position: both are preserved and the
    /// conflict is reported (VC-010, behaviour rows 051 and 053).
    Conflict,
}

/// Compares an incoming frame with the frame already stored at its position.
#[must_use]
pub fn classify_resend(existing: &[u8], incoming: &[u8]) -> Resend {
    if existing == incoming {
        Resend::Identical
    } else {
        Resend::Conflict
    }
}
