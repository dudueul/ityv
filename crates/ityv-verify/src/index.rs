//! The ledger index (PROTOCOL.md §5.1, §14 3; VC-010, VC-039, VC-101).
//!
//! [`build_index`] reads the frame stream of one election against a
//! [`VerifiedGenesis`] and the event objects published beside it. For
//! each frame in order it:
//!
//! 1. parses the record and links it to the chain (`ityv-ledger`: `seq`
//!    one more than the last, `prev_hash` the last frame's hash, the
//!    genesis's election). A torn tail is isolated and not read (VC-010);
//!    a corrupt record or a broken link ends the index there, because the
//!    frames after it are not provably part of this ledger;
//! 2. finds the event whose object hash is the frame's `event_hash` and
//!    decodes it as the canonical object of the frame's
//!    `event_schema_id`, which must be a ledger event this verifier knows;
//! 3. works out whom the event concerns: a box, a station (all its
//!    boxes), or the whole election, and refuses a box or station the
//!    genesis does not have, a genesis or amendment whose body the
//!    verified genesis did not apply, and a legal authorization other than
//!    the one the genesis pins;
//! 4. refuses an event already carried by an earlier frame: the later
//!    frame is invalid (VC-101);
//! 5. refuses a record of a box (cast record, challenge opening, batch
//!    attestation) in a frame after the first frame carrying that box's
//!    close: the record is invalid (VC-039, VC-101).
//!
//! A refused frame is not indexed. It becomes a [`Finding`] and puts what
//! it concerns under `HOLD_REVIEW`: its box, every box of its station, or
//! the whole ledger. Nothing is dropped silently, and nothing stops the
//! index except a break in the chain itself.
//!
//! What the index does not prove: that a signature on an event is valid,
//! that an event follows the rules of its own state machine, that the
//! ledger is the one the witnesses signed (the checkpoint chain, stage
//! 2), or that it is complete (the box stage, stage 4). Those stages read
//! the index.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use ityv_crypto::hash::object_hash;
use ityv_encoding::{
    BatchAttest, BoxClose, BoxId, BoxOpenedBody, BoxUnitSwapBody, CastRecord, ChallengeOpening,
    CheckinUnitSwapBody, CustodyHandoffBody, Decode, DeviceAttestation, DisputeEventBody,
    FallbackBody, Hash512, ImprintAuditBody, IssuanceCountBody, LateBatchCloseBody,
    LegalAuthorizationBody, LegalDecisionRefBody, ObserverCountAttestBody, ProgressBody,
    ProgressCheckBody, ProgressTick, SCHEMA_BATCH_ATTEST, SCHEMA_BOX_CLOSE, SCHEMA_BOX_OPENED_BODY,
    SCHEMA_BOX_UNIT_SWAP_BODY, SCHEMA_CAST_RECORD, SCHEMA_CHALLENGE_OPENING,
    SCHEMA_CHECKIN_UNIT_SWAP_BODY, SCHEMA_CUSTODY_HANDOFF_BODY, SCHEMA_DEVICE_ATTESTATION,
    SCHEMA_DISPUTE_EVENT_BODY, SCHEMA_FALLBACK_BODY, SCHEMA_IMPRINT_AUDIT_BODY,
    SCHEMA_ISSUANCE_COUNT_BODY, SCHEMA_LATE_BATCH_CLOSE_BODY, SCHEMA_LEGAL_AUTHORIZATION,
    SCHEMA_LEGAL_DECISION_REF_BODY, SCHEMA_OBSERVER_COUNT_ATTEST_BODY, SCHEMA_PROGRESS_CHECK_BODY,
    SCHEMA_PROGRESS_TICK, SCHEMA_SCAN_COUNT_ATTEST, SCHEMA_SEAL_CHANGE_BODY, SCHEMA_SIGNED_GENESIS,
    SCHEMA_VERSION_1, SCHEMA_WITNESSED_EVENT, ScanCountAttest, SchemaId, SealChangeBody, Seq,
    SignedGenesis, StationId, WitnessedEvent, decode_object,
};
use ityv_ledger::{
    ChainHead, ChainState, Error as LedgerError, FrameStream, Record, SCHEMA_SIGNED_CHECKPOINT,
    SignedCheckpoint,
};
use ityv_state::{HoldReason, HoldSet};

use crate::genesis::VerifiedGenesis;

/// Whom a ledger event concerns, for holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope<'a> {
    /// One box.
    Box(BoxId<'a>),
    /// One station: every box the genesis lists for it.
    Station(StationId<'a>),
    /// The whole election.
    Election,
}

/// What is wrong with a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindingKind {
    /// The stream ends inside a record: the torn tail is isolated and not
    /// read (VC-010). Not a hold by itself; the frames before it stand.
    TornTail,
    /// A record is not a canonical frame, or a frame does not extend the
    /// chain (sequence, previous hash, election). The index ends here.
    ChainBroken,
    /// No event with the frame's `event_hash` was supplied.
    EventMissing,
    /// The event is not the canonical object of the frame's schema, or the
    /// schema is not a ledger event this verifier knows.
    EventInvalid,
    /// The event names a box or station the genesis does not have.
    UnknownSubject,
    /// The event is a genesis or amendment whose body the verified genesis
    /// did not apply, or a legal authorization other than the one the
    /// genesis pins.
    NotPinned,
    /// The event was already carried by the frame `first` (VC-101).
    Replayed {
        /// The frame that first carried the event.
        first: Seq,
    },
    /// A record of a box in a frame after the frame `close` that carried
    /// the box's close (VC-039, VC-101).
    AfterClose {
        /// The frame of the box's first close.
        close: Seq,
    },
}

/// A frame the index refused, or the end of the readable stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Finding<'a> {
    /// The frame's sequence number, when the record could be read.
    pub seq: Option<Seq>,
    /// The byte offset of the record in the stream.
    pub offset: usize,
    /// The event hash the frame names, when the record could be read.
    pub event_hash: Option<Hash512>,
    /// Whom the finding puts under review.
    pub scope: Scope<'a>,
    /// What is wrong.
    pub kind: FindingKind,
}

/// The coarse kind of an event, for the index's own rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Role {
    /// A record of the box: invalid after the box's close.
    Record,
    /// The box's close.
    Close,
    /// A signed genesis or amendment, with the hash of the body it signs:
    /// it must be a body the verified genesis applied.
    Pinned(Hash512),
    /// A legal authorization, with its object hash: it must be the one the
    /// genesis pins.
    Authorization(Hash512),
    /// Anything else.
    Other,
}

/// An event the index accepted, with the frame that carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexedEvent<'a> {
    /// The frame's sequence number.
    pub seq: Seq,
    /// The frame's hash (the leaf input of the ledger tree).
    pub frame_hash: Hash512,
    /// The event's schema.
    pub schema: SchemaId,
    /// The event's object hash.
    pub hash: Hash512,
    /// The event object's bytes, a canonical object of `schema`.
    pub bytes: &'a [u8],
    /// Whom the event concerns.
    pub scope: Scope<'a>,
}

/// The ledger read against a verified genesis.
#[derive(Debug, Clone)]
pub struct LedgerIndex<'a> {
    events: Vec<IndexedEvent<'a>>,
    findings: Vec<Finding<'a>>,
    boxes: BTreeMap<&'a [u8], HoldSet>,
    ledger: HoldSet,
    chain: ChainState<'a>,
}

impl<'a> LedgerIndex<'a> {
    /// The accepted events, in frame order.
    #[must_use]
    pub fn events(&self) -> &[IndexedEvent<'a>] {
        &self.events
    }

    /// The accepted events that concern box `box_id` directly, in frame
    /// order.
    pub fn box_events<'s>(
        &'s self,
        box_id: &'s [u8],
    ) -> impl Iterator<Item = &'s IndexedEvent<'a>> + 's {
        self.events
            .iter()
            .filter(move |e| matches!(e.scope, Scope::Box(b) if b.as_bytes() == box_id))
    }

    /// The refused frames and the end of the stream, in stream order.
    #[must_use]
    pub fn findings(&self) -> &[Finding<'a>] {
        &self.findings
    }

    /// The hold reasons the index puts on box `box_id` (empty if none).
    #[must_use]
    pub fn box_holds(&self, box_id: &[u8]) -> HoldSet {
        self.boxes.get(box_id).copied().unwrap_or(HoldSet::empty())
    }

    /// The hold reasons the index puts on the whole ledger.
    #[must_use]
    pub const fn ledger_holds(&self) -> HoldSet {
        self.ledger
    }

    /// The head of the indexed chain, if any frame was read.
    #[must_use]
    pub const fn head(&self) -> Option<&ChainHead<'a>> {
        self.chain.head()
    }

    /// The number of frames in the chain (refused frames included: they
    /// are in the chain, only their events are not indexed).
    #[must_use]
    pub const fn tree_size(&self) -> u64 {
        self.chain.accumulator().size()
    }

    /// The root of the ledger tree over every frame read.
    #[must_use]
    pub fn root(&self) -> Hash512 {
        self.chain.accumulator().root()
    }

    fn hold(&mut self, genesis: &VerifiedGenesis<'a>, scope: Scope<'a>, reason: HoldReason) {
        match scope {
            Scope::Box(b) => {
                let set = self.boxes.entry(b.as_bytes()).or_insert(HoldSet::empty());
                *set = set.with(reason);
            }
            Scope::Station(s) => match genesis.station(s.as_bytes()) {
                Some(station) => {
                    for b in station.boxes() {
                        let set = self.boxes.entry(b.as_bytes()).or_insert(HoldSet::empty());
                        *set = set.with(reason);
                    }
                }
                None => self.ledger = self.ledger.with(reason),
            },
            Scope::Election => self.ledger = self.ledger.with(reason),
        }
    }

    fn refuse(&mut self, genesis: &VerifiedGenesis<'a>, finding: Finding<'a>, reason: HoldReason) {
        self.hold(genesis, finding.scope, reason);
        self.findings.push(finding);
    }
}

fn decode<'a, T: Decode<'a>>(schema: SchemaId, bytes: &'a [u8]) -> Option<T> {
    decode_object(schema, SCHEMA_VERSION_1, bytes).ok()
}

/// The scope of a witnessed event, from its body.
fn witnessed_scope<'a>(event: &WitnessedEvent<'a>) -> Option<Scope<'a>> {
    let schema = event.body_schema();
    let scope = if schema == SCHEMA_CUSTODY_HANDOFF_BODY {
        Scope::Box(
            event
                .body::<CustodyHandoffBody<'a>>(schema)
                .ok()?
                .parts()
                .box_id,
        )
    } else if schema == SCHEMA_DISPUTE_EVENT_BODY {
        match event
            .body::<DisputeEventBody<'a>>(schema)
            .ok()?
            .parts()
            .box_id
        {
            Some(b) => Scope::Box(b),
            None => Scope::Election,
        }
    } else if schema == SCHEMA_LEGAL_DECISION_REF_BODY {
        event.body::<LegalDecisionRefBody<'a>>(schema).ok()?;
        Scope::Election
    } else if schema == SCHEMA_BOX_OPENED_BODY {
        Scope::Box(event.body::<BoxOpenedBody<'a>>(schema).ok()?.parts().box_id)
    } else if schema == SCHEMA_FALLBACK_BODY {
        Scope::Box(event.body::<FallbackBody<'a>>(schema).ok()?.parts().box_id)
    } else if schema == SCHEMA_ISSUANCE_COUNT_BODY {
        Scope::Station(
            event
                .body::<IssuanceCountBody<'a>>(schema)
                .ok()?
                .parts()
                .station_id,
        )
    } else if schema == SCHEMA_IMPRINT_AUDIT_BODY {
        Scope::Box(
            event
                .body::<ImprintAuditBody<'a>>(schema)
                .ok()?
                .parts()
                .box_id,
        )
    } else if schema == SCHEMA_SEAL_CHANGE_BODY {
        Scope::Box(
            event
                .body::<SealChangeBody<'a>>(schema)
                .ok()?
                .parts()
                .box_id,
        )
    } else if schema == SCHEMA_LATE_BATCH_CLOSE_BODY {
        Scope::Box(
            event
                .body::<LateBatchCloseBody<'a>>(schema)
                .ok()?
                .parts()
                .box_id,
        )
    } else if schema == SCHEMA_PROGRESS_CHECK_BODY {
        Scope::Station(
            event
                .body::<ProgressCheckBody<'a>>(schema)
                .ok()?
                .parts()
                .station_id,
        )
    } else if schema == SCHEMA_OBSERVER_COUNT_ATTEST_BODY {
        Scope::Station(
            event
                .body::<ObserverCountAttestBody<'a>>(schema)
                .ok()?
                .parts()
                .station_id,
        )
    } else if schema == SCHEMA_CHECKIN_UNIT_SWAP_BODY {
        Scope::Station(
            event
                .body::<CheckinUnitSwapBody<'a>>(schema)
                .ok()?
                .parts()
                .station_id,
        )
    } else if schema == SCHEMA_BOX_UNIT_SWAP_BODY {
        Scope::Box(
            event
                .body::<BoxUnitSwapBody<'a>>(schema)
                .ok()?
                .parts()
                .box_id,
        )
    } else {
        return None;
    };
    Some(scope)
}

/// Decodes `bytes` as the ledger event of `schema` and returns whom it
/// concerns and its role; `None` if it is not one.
fn classify<'a>(
    genesis: &VerifiedGenesis<'a>,
    schema: SchemaId,
    bytes: &'a [u8],
) -> Option<(Scope<'a>, Role)> {
    let found = if schema == SCHEMA_CAST_RECORD {
        (
            Scope::Box(decode::<CastRecord<'a>>(schema, bytes)?.body().box_id()),
            Role::Record,
        )
    } else if schema == SCHEMA_CHALLENGE_OPENING {
        let c = decode::<ChallengeOpening<'a>>(schema, bytes)?;
        (Scope::Box(c.body().box_id()), Role::Record)
    } else if schema == SCHEMA_BATCH_ATTEST {
        let b = decode::<BatchAttest<'a>>(schema, bytes)?;
        (Scope::Box(b.body().box_id()), Role::Record)
    } else if schema == SCHEMA_BOX_CLOSE {
        (
            Scope::Box(decode::<BoxClose<'a>>(schema, bytes)?.body().box_id()),
            Role::Close,
        )
    } else if schema == SCHEMA_SCAN_COUNT_ATTEST {
        let s = decode::<ScanCountAttest<'a>>(schema, bytes)?;
        (Scope::Box(s.body().box_id()), Role::Other)
    } else if schema == SCHEMA_PROGRESS_TICK {
        let scope = match decode::<ProgressTick<'a>>(schema, bytes)?.body() {
            ProgressBody::Box(b) => Scope::Box(b.parts().box_id),
            ProgressBody::Checkin(c) => Scope::Station(c.parts().station_id),
        };
        (scope, Role::Other)
    } else if schema == SCHEMA_DEVICE_ATTESTATION {
        let a = decode::<DeviceAttestation<'a>>(schema, bytes)?;
        (
            device_scope(genesis, a.body().device_id().as_bytes()),
            Role::Other,
        )
    } else if schema == SCHEMA_WITNESSED_EVENT {
        let w = decode::<WitnessedEvent<'a>>(schema, bytes)?;
        (witnessed_scope(&w)?, Role::Other)
    } else if schema == SCHEMA_SIGNED_GENESIS {
        let signed = decode::<SignedGenesis<'a>>(schema, bytes)?;
        (
            Scope::Election,
            Role::Pinned(object_hash(signed.body_bytes())),
        )
    } else if schema == SCHEMA_SIGNED_CHECKPOINT {
        decode::<SignedCheckpoint<'a>>(schema, bytes)?;
        (Scope::Election, Role::Other)
    } else if schema == SCHEMA_LEGAL_AUTHORIZATION {
        decode::<LegalAuthorizationBody<'a>>(schema, bytes)?;
        (Scope::Election, Role::Authorization(object_hash(bytes)))
    } else {
        return None;
    };
    Some(found)
}

/// The scope of an attesting device: its box, its station's check-in
/// unit, or the election for a module or gateway. Device identifiers are
/// distinct within a genesis state, so at most one applies.
fn device_scope<'a>(genesis: &VerifiedGenesis<'a>, device_id: &[u8]) -> Scope<'a> {
    if let Some(b) = genesis.expected_box(device_id) {
        return Scope::Box(b.box_id);
    }
    genesis
        .unit_station(device_id)
        .map_or(Scope::Election, Scope::Station)
}

/// Whether the genesis has the box or station `scope` names.
fn known(genesis: &VerifiedGenesis<'_>, scope: &Scope<'_>) -> bool {
    match scope {
        Scope::Box(b) => genesis.expected_box(b.as_bytes()).is_some(),
        Scope::Station(s) => genesis.station(s.as_bytes()).is_some(),
        Scope::Election => true,
    }
}

/// The running state of [`build_index`].
struct Builder<'g, 'a> {
    genesis: &'g VerifiedGenesis<'a>,
    supply: BTreeMap<[u8; 64], &'a [u8]>,
    seen: BTreeMap<[u8; 64], Seq>,
    closed: BTreeMap<&'a [u8], Seq>,
    index: LedgerIndex<'a>,
}

impl<'a> Builder<'_, 'a> {
    /// Handles a record the stream could not parse. The stream stops.
    fn unreadable(&mut self, e: LedgerError, position: usize) {
        let (offset, kind) = if let LedgerError::TornTail { offset } = e {
            (offset, FindingKind::TornTail)
        } else if let LedgerError::CorruptRecord { offset } | LedgerError::Record { offset, .. } = e
        {
            (offset, FindingKind::ChainBroken)
        } else {
            (position, FindingKind::ChainBroken)
        };
        let finding = Finding {
            seq: None,
            offset,
            event_hash: None,
            scope: Scope::Election,
            kind,
        };
        if kind == FindingKind::TornTail {
            self.index.findings.push(finding);
        } else {
            self.index
                .refuse(self.genesis, finding, HoldReason::LedgerUnchecked);
        }
    }

    /// Indexes one record. Returns `false` if the chain broke and the
    /// index must stop.
    fn record(&mut self, record: &Record<'a>) -> bool {
        let frame = *record.frame();
        let mut finding = Finding {
            seq: Some(frame.seq()),
            offset: record.offset(),
            event_hash: Some(*frame.event_hash()),
            scope: Scope::Election,
            kind: FindingKind::ChainBroken,
        };
        let ours = frame.election_id().as_bytes() == self.genesis.election_id().as_bytes();
        let linked = if ours {
            self.index.chain.append(record.bytes()).ok()
        } else {
            None
        };
        let Some(frame_hash) = linked else {
            self.index
                .refuse(self.genesis, finding, HoldReason::LedgerUnchecked);
            return false;
        };
        let hash = *frame.event_hash();
        let schema = frame.event_schema_id();
        let refusal = match self.supply.get(hash.as_bytes()).copied() {
            None => Err((FindingKind::EventMissing, HoldReason::LedgerUnchecked)),
            Some(bytes) => match classify(self.genesis, schema, bytes) {
                None => Err((FindingKind::EventInvalid, HoldReason::LedgerUnchecked)),
                Some((scope, role)) => {
                    finding.scope = scope;
                    self.admit(frame.seq(), &hash, scope, role)
                        .map(|()| IndexedEvent {
                            seq: frame.seq(),
                            frame_hash,
                            schema,
                            hash,
                            bytes,
                            scope,
                        })
                }
            },
        };
        match refusal {
            Ok(event) => self.index.events.push(event),
            Err((kind, reason)) => {
                if kind == FindingKind::UnknownSubject {
                    finding.scope = Scope::Election;
                }
                finding.kind = kind;
                self.index.refuse(self.genesis, finding, reason);
            }
        }
        true
    }

    /// Applies the subject, replay and after-close rules to an event that
    /// decoded.
    fn admit(
        &mut self,
        seq: Seq,
        hash: &Hash512,
        scope: Scope<'a>,
        role: Role,
    ) -> Result<(), (FindingKind, HoldReason)> {
        if !known(self.genesis, &scope) {
            return Err((FindingKind::UnknownSubject, HoldReason::LedgerUnchecked));
        }
        let pinned = match role {
            Role::Pinned(body) => self.genesis.is_applied_body(&body),
            Role::Authorization(hash) => {
                hash == *self.genesis.genesis().body().legal_authorization_hash()
            }
            Role::Record | Role::Close | Role::Other => true,
        };
        if !pinned {
            return Err((FindingKind::NotPinned, HoldReason::LedgerUnchecked));
        }
        if let Some(first) = self.seen.get(hash.as_bytes()).copied() {
            return Err((FindingKind::Replayed { first }, HoldReason::EventReplayed));
        }
        self.seen.insert(hash.0, seq);
        if let Scope::Box(b) = scope {
            match (role, self.closed.get(b.as_bytes()).copied()) {
                (Role::Record, Some(close)) => {
                    return Err((
                        FindingKind::AfterClose { close },
                        HoldReason::RecordAfterClose,
                    ));
                }
                (Role::Close, None) => {
                    self.closed.insert(b.as_bytes(), seq);
                }
                (
                    Role::Record
                    | Role::Close
                    | Role::Pinned(_)
                    | Role::Authorization(_)
                    | Role::Other,
                    _,
                ) => {}
            }
        }
        Ok(())
    }
}

/// Reads the frame stream `frames` against `genesis`, with `events` the
/// event objects published beside it (in any order; duplicates in the
/// supply are harmless, a duplicate on the ledger is not).
#[must_use]
pub fn build_index<'a>(
    genesis: &VerifiedGenesis<'a>,
    frames: &'a [u8],
    events: &[&'a [u8]],
) -> LedgerIndex<'a> {
    let mut builder = Builder {
        genesis,
        supply: events
            .iter()
            .map(|bytes| (object_hash(bytes).0, *bytes))
            .collect(),
        seen: BTreeMap::new(),
        closed: BTreeMap::new(),
        index: LedgerIndex {
            events: Vec::new(),
            findings: Vec::new(),
            boxes: BTreeMap::new(),
            ledger: HoldSet::empty(),
            chain: ChainState::empty(),
        },
    };
    let mut stream = FrameStream::new(frames);
    while let Some(next) = stream.next_record() {
        match next {
            Ok(record) => {
                if !builder.record(&record) {
                    break;
                }
            }
            Err(e) => {
                builder.unreadable(e, stream.position());
                break;
            }
        }
    }
    builder.index
}
