//! The ledger of a scenario: a plan of steps, then the frame stream with
//! witness checkpoints over it.
//!
//! A scenario is a list of [`Step`]s. Most are events; checkpoints are
//! steps too, signed when the plan is laid down because their roots
//! depend on every frame before them. An attack is a change to the list
//! (an event removed, repeated, moved, replaced) or a step kind that
//! produces a deliberately wrong frame.

use ityv_crypto::object_hash;
use ityv_encoding::{
    CheckpointBody, CheckpointParts, Hash512, KeysetId, LedgerFrame, LedgerId, SCHEMA_BOX_CLOSE,
    SCHEMA_CHECKPOINT_BODY, SCHEMA_LEDGER_FRAME, SchemaId, Seq, TimeBucket, TreeSize,
};
use ityv_ledger::{
    SCHEMA_SIGNED_CHECKPOINT, SignedCheckpointParts, WitnessSignatureEntry, root_of_leaves,
    sorted_set_root,
};

use crate::election::{Election, SIGNERS, WITNESS_IDS};
use crate::util::{hybrid_variant, leak_slice, object, text};

/// One step of a scenario's ledger.
#[derive(Debug, Clone)]
pub enum Step {
    /// A frame carrying `event` as `schema`; the event is published as
    /// `published` (normally the same bytes). `filed` is the filing hash
    /// of a dispute this event opens.
    Event {
        /// The frame's schema.
        schema: SchemaId,
        /// The event the frame names.
        event: &'static [u8],
        /// The bytes published beside the ledger (a mirror's copy).
        published: Option<&'static [u8]>,
        /// The filing body hash, if this event files a dispute.
        filed: Option<Hash512>,
    },
    /// A witness checkpoint over every frame so far, in time bucket
    /// `bucket`.
    Checkpoint {
        /// The witnesses' time bucket.
        bucket: u64,
    },
    /// A second checkpoint under the previous checkpoint's sequence
    /// number over fewer frames: a rollback the witnesses signed (a fork
    /// of the checkpoint chain).
    ForkCheckpoint {
        /// The witnesses' time bucket.
        bucket: u64,
        /// Frames dropped from the previous checkpoint's tree.
        dropped: u64,
    },
}

impl Step {
    /// An ordinary event step.
    #[must_use]
    pub const fn event(schema: SchemaId, event: &'static [u8]) -> Self {
        Self::Event {
            schema,
            event,
            published: None,
            filed: None,
        }
    }

    /// The event of an event step.
    #[must_use]
    pub const fn event_bytes(&self) -> Option<&'static [u8]> {
        match self {
            Self::Event { event, .. } => Some(event),
            Self::Checkpoint { .. } | Self::ForkCheckpoint { .. } => None,
        }
    }
}

/// A laid-down ledger: the frame stream and the published events.
#[derive(Debug, Clone)]
pub struct Ledger {
    /// The frame stream (`u32_be` length ‖ frame, repeated).
    pub frames: Vec<u8>,
    /// The event objects published beside it, in frame order.
    pub events: Vec<&'static [u8]>,
    /// The last checkpoint's time bucket, if any.
    pub last_checkpoint_bucket: Option<u64>,
    /// The last checkpoint's body hash (what an audit seed names as its
    /// binding checkpoint), if any.
    pub last_checkpoint_hash: Option<Hash512>,
    /// Frames.
    pub size: u64,
}

struct Book<'e> {
    election: &'e Election,
    stream: Vec<u8>,
    prev: Hash512,
    frames: Vec<Hash512>,
    closes: Vec<Hash512>,
    disputes: Vec<Hash512>,
    events: Vec<&'static [u8]>,
    last: Option<(u64, Hash512, u64)>,
    previous: Option<(u64, Hash512)>,
    bucket: Option<u64>,
}

impl Book<'_> {
    fn push(&mut self, schema: SchemaId, event: &'static [u8], published: &'static [u8]) {
        let seq = self.frames.len() as u64 + 1;
        let frame = LedgerFrame::new(
            self.election.election_id(),
            Seq::new(seq).unwrap(),
            self.prev,
            schema,
            object_hash(event),
        );
        let bytes = object(SCHEMA_LEDGER_FRAME, &frame);
        let hash = object_hash(bytes);
        self.prev = hash;
        self.stream
            .extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
        self.stream.extend_from_slice(bytes);
        self.frames.push(hash);
        self.events.push(published);
        if schema == SCHEMA_BOX_CLOSE {
            self.closes.push(object_hash(event));
        }
    }

    /// The checkpoint numbered `seq` after `previous` over the first
    /// `size` frames.
    fn checkpoint(&mut self, seq: u64, previous: Hash512, size: u64, bucket: u64, variant: u64) {
        let e = self.election;
        let mut closes = self.closes.clone();
        closes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let mut disputes = self.disputes.clone();
        disputes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let body = CheckpointBody::new(&CheckpointParts {
            election_id: e.election_id(),
            ledger_id: LedgerId::new(text(&format!("L-{}", e.eid))).unwrap(),
            keyset_id: KeysetId::new(b"K-1").unwrap(),
            checkpoint_seq: Seq::new(seq).unwrap(),
            tree_size: TreeSize::new(size),
            root_hash: root_of_leaves(&self.frames.as_slice(), size).unwrap(),
            previous_checkpoint_hash: previous,
            box_close_root: sorted_set_root(&closes).unwrap(),
            dispute_root: sorted_set_root(&disputes).unwrap(),
            genesis_hash: e.pin,
            time_bucket: TimeBucket::new(bucket),
        })
        .unwrap();
        let body = object(SCHEMA_CHECKPOINT_BODY, &body);
        let entries: Vec<WitnessSignatureEntry<'static>> = SIGNERS
            .iter()
            .map(|&i| WitnessSignatureEntry {
                witness_id: ityv_encoding::Ident::new(text(WITNESS_IDS[i]), 64).unwrap(),
                signature: hybrid_variant(&e.witness(i), b"checkpoint", body, variant),
            })
            .collect();
        let signed = SignedCheckpointParts::new(body, leak_slice(entries)).unwrap();
        let event = object(SCHEMA_SIGNED_CHECKPOINT, &signed);
        self.previous = self.last.map(|(s, h, _)| (s, h));
        self.last = Some((seq, object_hash(body), size));
        self.bucket = Some(bucket);
        self.push(SCHEMA_SIGNED_CHECKPOINT, event, event);
    }
}

/// Lays down `steps` over `election`'s genesis: the frame stream and the
/// events, every checkpoint signed by the witness quorum.
#[must_use]
pub fn lay_down(election: &Election, steps: &[Step]) -> Ledger {
    let mut book = Book {
        election,
        stream: Vec::new(),
        prev: Hash512::ZERO,
        frames: Vec::new(),
        closes: Vec::new(),
        disputes: Vec::new(),
        events: Vec::new(),
        last: None,
        previous: None,
        bucket: None,
    };
    for step in steps {
        match step {
            Step::Event {
                schema,
                event,
                published,
                filed,
            } => {
                book.push(*schema, event, published.unwrap_or(event));
                if let Some(f) = filed {
                    book.disputes.push(*f);
                }
            }
            Step::Checkpoint { bucket } => {
                let (seq, previous) = book
                    .last
                    .map_or((1, Hash512::ZERO), |(seq, hash, _)| (seq + 1, hash));
                let size = book.frames.len() as u64;
                book.checkpoint(seq, previous, size, *bucket, 0);
            }
            Step::ForkCheckpoint { bucket, dropped } => {
                let (seq, _, size) = book.last.unwrap();
                let previous = book.previous.map_or(Hash512::ZERO, |(_, h)| h);
                book.checkpoint(seq, previous, size - dropped, *bucket, 1);
            }
        }
    }
    Ledger {
        size: book.frames.len() as u64,
        frames: book.stream,
        events: book.events,
        last_checkpoint_bucket: book.bucket,
        last_checkpoint_hash: book.last.map(|(_, h, _)| h),
    }
}
