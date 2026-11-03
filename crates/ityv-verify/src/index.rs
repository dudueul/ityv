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
//! 2. keeps a frame of a restricted or sealed event by its hash alone
//!    ([`OPAQUE_SCHEMAS`]); otherwise finds the event whose object hash
//!    is the frame's `event_hash` and decodes it as the canonical object
//!    of the frame's `event_schema_id`, which must be a ledger event this
//!    verifier knows;
//! 3. refuses an event that names another election; works out whom the
//!    event concerns: a box, a station (all its boxes), or the whole
//!    election, and refuses a box or station no state of the genesis has,
//!    a genesis or amendment whose body the verified genesis did not
//!    apply, and a signed legal authorization (`0x0042`) whose body is
//!    not the one the genesis pins;
//! 4. refuses an event already carried by an earlier frame: the later
//!    frame is invalid (VC-101);
//! 5. refuses a record of a box (cast record, challenge opening) in a
//!    frame after the first frame carrying that box's close: the record is
//!    invalid (VC-039, VC-101). A batch attestation after the close is a
//!    late batch close (§7.2.1, VC-100), which the box stage judges with
//!    its `LateBatchClose`.
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
    ElectionId, FallbackBody, Hash512, ImprintAuditBody, IssuanceCountBody, LateBatchCloseBody,
    LegalDecisionRefBody, ModuleProvisioned, ObserverCountAttestBody, PaperCountReportBody,
    ParticipationSet, PartyKeyCeremony, ProgressBody, ProgressCheckBody, ProgressTick,
    QuorumSigned, SCHEMA_BATCH_ATTEST, SCHEMA_BOX_CLOSE, SCHEMA_BOX_OPENED_BODY,
    SCHEMA_BOX_UNIT_SWAP_BODY, SCHEMA_CAST_RECORD, SCHEMA_CHALLENGE_OPENING,
    SCHEMA_CHECKIN_UNIT_SWAP_BODY, SCHEMA_CUSTODY_HANDOFF_BODY, SCHEMA_DEVICE_ATTESTATION,
    SCHEMA_DISPUTE_EVENT_BODY, SCHEMA_FALLBACK_BODY, SCHEMA_IMPRINT_AUDIT_BODY,
    SCHEMA_ISSUANCE_COUNT_BODY, SCHEMA_LATE_BATCH_CLOSE_BODY, SCHEMA_LEGAL_DECISION_REF_BODY,
    SCHEMA_MODULE_PROVISIONED, SCHEMA_OBSERVER_COUNT_ATTEST_BODY, SCHEMA_PAPER_COUNT_REPORT_BODY,
    SCHEMA_PARTICIPATION_SET, SCHEMA_PARTY_KEY_CEREMONY, SCHEMA_PROGRESS_CHECK_BODY,
    SCHEMA_PROGRESS_TICK, SCHEMA_QUORUM_SIGNED, SCHEMA_SCAN_COUNT_ATTEST, SCHEMA_SEAL_CHANGE_BODY,
    SCHEMA_SHARE_PACKAGE, SCHEMA_SIGNED_GENESIS, SCHEMA_SIGNED_LEGAL_AUTHORIZATION,
    SCHEMA_VERSION_1, SCHEMA_WITNESSED_EVENT, ScanCountAttest, SchemaId, SealChangeBody, Seq,
    SignedGenesis, SignedLegalAuthorization, StationId, WitnessedEvent, decode_object,
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

/// Ledger event schemas whose bodies are not public (PROTOCOL.md §5.2,
/// §12.3): the public ledger carries their frames and event hashes, and
/// only restricted or sealed verifiers hold the bodies. The index keeps
/// such a frame by its hash (replays still count) and asks for no body:
/// `CheckinCounter` (0x0009, restricted) and `SharePackage` (0x000B,
/// sealed). Restricted events without a schema yet (`SampleOpening`) join
/// the list when they get one.
pub const OPAQUE_SCHEMAS: [SchemaId; 2] = [SchemaId::new(0x0009), SCHEMA_SHARE_PACKAGE];

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
    /// The event names an election other than the genesis's.
    OtherElection,
    /// The event names a box or station no state of the genesis has.
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
    /// A record of a box (cast record, challenge opening) in a frame after
    /// the frame `close` that carried the box's close (VC-039, VC-101).
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
    /// A record of the box (a cast record or challenge opening): invalid
    /// after the box's close.
    Record,
    /// The box's close.
    Close,
    /// A signed genesis or amendment, with the hash of the body it signs:
    /// it must be a body the verified genesis applied.
    Pinned(Hash512),
    /// A legal authorization, with its object hash: it must be the one the
    /// genesis pins.
    Authorization(Hash512),
    /// A frame of a restricted or sealed event: the body is not public.
    Opaque,
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
    /// The event object's bytes, a canonical object of `schema`; `None`
    /// for a frame of a restricted or sealed event, whose body the public
    /// ledger does not carry ([`OPAQUE_SCHEMAS`]).
    pub bytes: Option<&'a [u8]>,
    /// Whom the event concerns.
    pub scope: Scope<'a>,
}

/// The ledger read against a verified genesis.
#[derive(Debug, Clone)]
pub struct LedgerIndex<'a> {
    events: Vec<IndexedEvent<'a>>,
    by_box: BTreeMap<&'a [u8], Vec<usize>>,
    by_station: BTreeMap<&'a [u8], Vec<usize>>,
    findings: Vec<Finding<'a>>,
    boxes: BTreeMap<&'a [u8], HoldSet>,
    ledger: HoldSet,
    chain: ChainState<'a>,
    frame_hashes: Vec<Hash512>,
    /// The frame of the first accepted `SignedGenesis` of each state (0 is
    /// the genesis), `None` where the ledger has none.
    state_frames: Vec<Option<Seq>>,
}

impl<'a> LedgerIndex<'a> {
    /// The accepted events, in frame order.
    #[must_use]
    pub fn events(&self) -> &[IndexedEvent<'a>] {
        &self.events
    }

    /// The accepted events that concern box `box_id` directly, in frame
    /// order, without reading the whole ledger again.
    pub fn box_events<'s>(
        &'s self,
        box_id: &[u8],
    ) -> impl Iterator<Item = &'s IndexedEvent<'a>> + 's {
        self.by_box
            .get(box_id)
            .into_iter()
            .flatten()
            .filter_map(|&i| self.events.get(i))
    }

    /// The boxes that have accepted events, in identifier order.
    pub fn boxes_with_events(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.by_box.keys().copied()
    }

    /// The accepted events that concern station `station_id` as a whole
    /// (not one of its boxes), in frame order.
    pub fn station_events<'s>(
        &'s self,
        station_id: &[u8],
    ) -> impl Iterator<Item = &'s IndexedEvent<'a>> + 's {
        self.by_station
            .get(station_id)
            .into_iter()
            .flatten()
            .filter_map(|&i| self.events.get(i))
    }

    /// The refused frames and the end of the stream, in stream order.
    #[must_use]
    pub fn findings(&self) -> &[Finding<'a>] {
        &self.findings
    }

    /// The hold reasons that apply to box `box_id`: the index's holds on
    /// the box, its station, and the whole ledger (empty if none).
    #[must_use]
    pub fn box_holds(&self, box_id: &[u8]) -> HoldSet {
        self.boxes
            .get(box_id)
            .copied()
            .unwrap_or(HoldSet::empty())
            .union(self.ledger)
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

    /// The hash of every frame in the chain, in order (`frame_hashes()[i]`
    /// is the frame with `seq = i + 1`), refused frames included: the
    /// leaves of the ledger tree.
    #[must_use]
    pub fn frame_hashes(&self) -> &[Hash512] {
        &self.frame_hashes
    }

    /// The frame that carries each amendment the verifier applied, in
    /// amendment order (the first is amendment 1), as far as the ledger
    /// carries them in order. An amendment applies from its frame on.
    #[must_use]
    pub fn amendment_frames(&self) -> Vec<Seq> {
        let mut out: Vec<Seq> = Vec::new();
        for frame in self.state_frames.iter().skip(1) {
            match frame {
                Some(seq) if out.last().is_none_or(|last| last.get() < seq.get()) => {
                    out.push(*seq);
                }
                Some(_) | None => break,
            }
        }
        out
    }

    /// The genesis state in force at frame `seq`: the number of amendments
    /// whose frames come before it.
    #[must_use]
    pub fn state_at(&self, seq: Seq) -> usize {
        self.amendment_frames()
            .iter()
            .take_while(|f| f.get() < seq.get())
            .count()
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

    fn push(&mut self, event: IndexedEvent<'a>) {
        let at = self.events.len();
        match event.scope {
            Scope::Box(b) => self.by_box.entry(b.as_bytes()).or_default().push(at),
            Scope::Station(s) => self.by_station.entry(s.as_bytes()).or_default().push(at),
            Scope::Election => {}
        }
        self.events.push(event);
    }

    fn refuse(&mut self, genesis: &VerifiedGenesis<'a>, finding: Finding<'a>, reason: HoldReason) {
        self.hold(genesis, finding.scope, reason);
        self.findings.push(finding);
    }
}

fn decode<'a, T: Decode<'a>>(schema: SchemaId, bytes: &'a [u8]) -> Option<T> {
    decode_object(schema, SCHEMA_VERSION_1, bytes).ok()
}

/// Whom a witnessed event concerns, and its election, from its body.
#[allow(clippy::too_many_lines)] // One branch per witnessed body schema.
fn witnessed<'a>(event: &WitnessedEvent<'a>) -> Option<(Scope<'a>, ElectionId<'a>)> {
    let s = event.body_schema();
    let found = if s == SCHEMA_CUSTODY_HANDOFF_BODY {
        let b = event.body::<CustodyHandoffBody<'a>>(s).ok()?;
        (Scope::Box(b.parts().box_id), b.parts().election_id)
    } else if s == SCHEMA_DISPUTE_EVENT_BODY {
        let b = event.body::<DisputeEventBody<'a>>(s).ok()?;
        let scope = b.parts().box_id.map_or(Scope::Election, Scope::Box);
        (scope, b.parts().election_id)
    } else if s == SCHEMA_LEGAL_DECISION_REF_BODY {
        let b = event.body::<LegalDecisionRefBody<'a>>(s).ok()?;
        (Scope::Election, b.parts().election_id)
    } else if s == SCHEMA_BOX_OPENED_BODY {
        let b = event.body::<BoxOpenedBody<'a>>(s).ok()?;
        (Scope::Box(b.parts().box_id), b.parts().election_id)
    } else if s == SCHEMA_FALLBACK_BODY {
        let b = event.body::<FallbackBody<'a>>(s).ok()?;
        (Scope::Box(b.parts().box_id), b.parts().election_id)
    } else if s == SCHEMA_ISSUANCE_COUNT_BODY {
        let b = event.body::<IssuanceCountBody<'a>>(s).ok()?;
        (Scope::Station(b.parts().station_id), b.parts().election_id)
    } else if s == SCHEMA_IMPRINT_AUDIT_BODY {
        let b = event.body::<ImprintAuditBody<'a>>(s).ok()?;
        (Scope::Box(b.parts().box_id), b.parts().election_id)
    } else if s == SCHEMA_SEAL_CHANGE_BODY {
        let b = event.body::<SealChangeBody<'a>>(s).ok()?;
        (Scope::Box(b.parts().box_id), b.parts().election_id)
    } else if s == SCHEMA_LATE_BATCH_CLOSE_BODY {
        let b = event.body::<LateBatchCloseBody<'a>>(s).ok()?;
        (Scope::Box(b.parts().box_id), b.parts().election_id)
    } else if s == SCHEMA_PROGRESS_CHECK_BODY {
        let b = event.body::<ProgressCheckBody<'a>>(s).ok()?;
        (Scope::Station(b.parts().station_id), b.parts().election_id)
    } else if s == SCHEMA_OBSERVER_COUNT_ATTEST_BODY {
        let b = event.body::<ObserverCountAttestBody<'a>>(s).ok()?;
        (Scope::Station(b.parts().station_id), b.parts().election_id)
    } else if s == SCHEMA_CHECKIN_UNIT_SWAP_BODY {
        let b = event.body::<CheckinUnitSwapBody<'a>>(s).ok()?;
        (Scope::Station(b.parts().station_id), b.parts().election_id)
    } else if s == SCHEMA_BOX_UNIT_SWAP_BODY {
        let b = event.body::<BoxUnitSwapBody<'a>>(s).ok()?;
        (Scope::Box(b.parts().box_id), b.parts().election_id)
    } else if s == SCHEMA_PAPER_COUNT_REPORT_BODY {
        // A reporting unit's report: the tally stage reads it with the
        // unit's scopes and openings.
        let b = event.body::<PaperCountReportBody<'a>>(s).ok()?;
        (Scope::Election, b.parts().election_id)
    } else {
        return None;
    };
    Some(found)
}

/// What the index learns from an event that decoded.
#[derive(Debug, Clone, Copy)]
struct Classified<'a> {
    scope: Scope<'a>,
    role: Role,
    /// The election the event names (`None` for an opaque frame).
    election: Option<ElectionId<'a>>,
}

impl<'a> Classified<'a> {
    const fn new(scope: Scope<'a>, role: Role, election: ElectionId<'a>) -> Self {
        Self {
            scope,
            role,
            election: Some(election),
        }
    }
}

/// Decodes `bytes` as the ledger event of `schema`; `None` if it is not
/// one.
fn classify<'a>(
    genesis: &VerifiedGenesis<'a>,
    schema: SchemaId,
    bytes: &'a [u8],
) -> Option<Classified<'a>> {
    let found = if schema == SCHEMA_CAST_RECORD {
        let r = decode::<CastRecord<'a>>(schema, bytes)?;
        Classified::new(
            Scope::Box(r.body().box_id()),
            Role::Record,
            r.body().election_id(),
        )
    } else if schema == SCHEMA_CHALLENGE_OPENING {
        let c = decode::<ChallengeOpening<'a>>(schema, bytes)?;
        Classified::new(
            Scope::Box(c.body().box_id()),
            Role::Record,
            c.body().election_id(),
        )
    } else if schema == SCHEMA_BATCH_ATTEST {
        // Not a record for the after-close rule: a late batch close is a
        // batch attestation after the box's close (PROTOCOL.md §7.2.1,
        // VC-100), judged by the box stage with its `LateBatchClose`.
        let b = decode::<BatchAttest<'a>>(schema, bytes)?;
        Classified::new(
            Scope::Box(b.body().box_id()),
            Role::Other,
            b.body().election_id(),
        )
    } else if schema == SCHEMA_BOX_CLOSE {
        let c = decode::<BoxClose<'a>>(schema, bytes)?;
        Classified::new(
            Scope::Box(c.body().box_id()),
            Role::Close,
            c.body().election_id(),
        )
    } else if schema == SCHEMA_SCAN_COUNT_ATTEST {
        let a = decode::<ScanCountAttest<'a>>(schema, bytes)?;
        Classified::new(
            Scope::Box(a.body().box_id()),
            Role::Other,
            a.body().election_id(),
        )
    } else if schema == SCHEMA_PROGRESS_TICK {
        match *decode::<ProgressTick<'a>>(schema, bytes)?.body() {
            ProgressBody::Box(b) => Classified::new(
                Scope::Box(b.parts().box_id),
                Role::Other,
                b.parts().election_id,
            ),
            ProgressBody::Checkin(c) => Classified::new(
                Scope::Station(c.parts().station_id),
                Role::Other,
                c.parts().election_id,
            ),
        }
    } else if schema == SCHEMA_DEVICE_ATTESTATION {
        let a = decode::<DeviceAttestation<'a>>(schema, bytes)?;
        let scope = device_scope(genesis, a.body().device_id().as_bytes());
        Classified::new(scope, Role::Other, a.body().election_id())
    } else if schema == SCHEMA_WITNESSED_EVENT {
        let (scope, election) = witnessed(&decode::<WitnessedEvent<'a>>(schema, bytes)?)?;
        Classified::new(scope, Role::Other, election)
    } else if schema == SCHEMA_PARTICIPATION_SET {
        let p = decode::<ParticipationSet<'a>>(schema, bytes)?;
        Classified::new(Scope::Station(p.station_id()), Role::Other, p.election_id())
    } else if schema == SCHEMA_MODULE_PROVISIONED {
        // The election, not the module's device: the record is made
        // before the election and may come before the amendment that adds
        // its device, where a box's stage would refuse it. The
        // participation stage reads every record.
        let m = decode::<ModuleProvisioned<'a>>(schema, bytes)?;
        Classified::new(Scope::Election, Role::Other, m.parts().election_id)
    } else if schema == SCHEMA_PARTY_KEY_CEREMONY {
        let c = decode::<PartyKeyCeremony<'a>>(schema, bytes)?;
        Classified::new(Scope::Election, Role::Other, c.message().election_id())
    } else if schema == SCHEMA_SIGNED_GENESIS {
        let signed = decode::<SignedGenesis<'a>>(schema, bytes)?;
        let election = match (signed.genesis(), signed.amendment()) {
            (Some(g), _) => g.election_id(),
            (None, Some(a)) => a.parts().election_id,
            (None, None) => return None,
        };
        let role = Role::Pinned(object_hash(signed.body_bytes()));
        Classified::new(Scope::Election, role, election)
    } else if schema == SCHEMA_SIGNED_CHECKPOINT {
        let c = decode::<SignedCheckpoint<'a>>(schema, bytes)?;
        Classified::new(Scope::Election, Role::Other, c.body().parts().election_id)
    } else if schema == SCHEMA_QUORUM_SIGNED {
        // A tally scope or aggregate opening of a ballot style and
        // reporting unit, or the receipt resolution of an out-of-district
        // box: the tally stage reads every one.
        let q = decode::<QuorumSigned<'a>>(schema, bytes)?;
        let election = match (
            q.tally_scope(),
            q.aggregate_opening(),
            q.receipt_resolution(),
        ) {
            (Some(t), _, _) => t.parts().election_id,
            (None, Some(o), _) => o.parts().election_id,
            (None, None, Some(r)) => r.parts().election_id,
            (None, None, None) => return None,
        };
        Classified::new(Scope::Election, Role::Other, election)
    } else if schema == SCHEMA_SIGNED_LEGAL_AUTHORIZATION {
        let a = decode::<SignedLegalAuthorization<'a>>(schema, bytes)?;
        Classified::new(
            Scope::Election,
            Role::Authorization(object_hash(a.body_bytes())),
            a.body().election_id(),
        )
    } else {
        return None;
    };
    Some(found)
}

/// The scope of an attesting device: its box, its station's check-in
/// unit, or the election for a module or gateway. Device identifiers are
/// distinct within a genesis state, so at most one applies; a unit is
/// found in any state of the genesis.
fn device_scope<'a>(genesis: &VerifiedGenesis<'a>, device_id: &[u8]) -> Scope<'a> {
    if let Some(b) = genesis.expected_box(device_id) {
        return Scope::Box(b.box_id);
    }
    genesis
        .unit_station(device_id)
        .map_or(Scope::Election, Scope::Station)
}

/// Whether some state of the genesis has the box or station `scope`
/// names.
fn known(genesis: &VerifiedGenesis<'_>, scope: &Scope<'_>) -> bool {
    match scope {
        Scope::Box(b) => genesis.knows_box(b.as_bytes()),
        Scope::Station(s) => genesis.knows_station(s.as_bytes()),
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
        self.index.frame_hashes.push(frame_hash);
        let hash = *frame.event_hash();
        let schema = frame.event_schema_id();
        let found = if OPAQUE_SCHEMAS.contains(&schema) {
            // The public ledger carries the frame, not the body.
            Ok((
                None,
                Classified {
                    scope: Scope::Election,
                    role: Role::Opaque,
                    election: None,
                },
            ))
        } else {
            match self.supply.get(hash.as_bytes()).copied() {
                None => Err((FindingKind::EventMissing, HoldReason::LedgerUnchecked)),
                Some(bytes) => classify(self.genesis, schema, bytes)
                    .map(|c| (Some(bytes), c))
                    .ok_or((FindingKind::EventInvalid, HoldReason::LedgerUnchecked)),
            }
        };
        let accepted = found.and_then(|(bytes, c)| {
            finding.scope = c.scope;
            self.admit(frame.seq(), &hash, &c).map(|()| IndexedEvent {
                seq: frame.seq(),
                frame_hash,
                schema,
                hash,
                bytes,
                scope: c.scope,
            })
        });
        match accepted {
            Ok(event) => self.index.push(event),
            Err((kind, reason)) => {
                if matches!(
                    kind,
                    FindingKind::UnknownSubject | FindingKind::OtherElection
                ) {
                    finding.scope = Scope::Election;
                }
                finding.kind = kind;
                self.index.refuse(self.genesis, finding, reason);
            }
        }
        true
    }

    /// Applies the election, subject, pin, replay and after-close rules to
    /// an event that decoded.
    fn admit(
        &mut self,
        seq: Seq,
        hash: &Hash512,
        c: &Classified<'a>,
    ) -> Result<(), (FindingKind, HoldReason)> {
        if c.election
            .is_some_and(|e| e.as_bytes() != self.genesis.election_id().as_bytes())
        {
            return Err((FindingKind::OtherElection, HoldReason::LedgerUnchecked));
        }
        if !known(self.genesis, &c.scope) {
            return Err((FindingKind::UnknownSubject, HoldReason::LedgerUnchecked));
        }
        let pinned = match c.role {
            Role::Pinned(body) => {
                let state = self
                    .genesis
                    .anchors()
                    .iter()
                    .position(|a| a.head() == &body);
                if let Some(slot) = state.and_then(|k| self.index.state_frames.get_mut(k))
                    && slot.is_none()
                {
                    *slot = Some(seq);
                }
                state.is_some()
            }
            Role::Authorization(hash) => {
                hash == *self.genesis.genesis().body().legal_authorization_hash()
            }
            Role::Record | Role::Close | Role::Opaque | Role::Other => true,
        };
        if !pinned {
            return Err((FindingKind::NotPinned, HoldReason::LedgerUnchecked));
        }
        if let Some(first) = self.seen.get(hash.as_bytes()).copied() {
            return Err((FindingKind::Replayed { first }, HoldReason::EventReplayed));
        }
        self.seen.insert(hash.0, seq);
        if let Scope::Box(b) = c.scope {
            match (c.role, self.closed.get(b.as_bytes()).copied()) {
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
                    | Role::Opaque
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
            by_box: BTreeMap::new(),
            by_station: BTreeMap::new(),
            findings: Vec::new(),
            boxes: BTreeMap::new(),
            ledger: HoldSet::empty(),
            chain: ChainState::empty(),
            frame_hashes: Vec::new(),
            state_frames: alloc::vec![None; genesis.state_count()],
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
    let mut index = builder.index;
    // Every applied amendment must be on the ledger, in order.
    let carried = index.amendment_frames().len();
    if carried.saturating_add(1) != genesis.state_count() {
        index.ledger = index.ledger.with(HoldReason::AmendmentMissing);
    }
    index
}
