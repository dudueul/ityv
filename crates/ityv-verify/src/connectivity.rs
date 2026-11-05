//! The connectivity stage (PROTOCOL.md §5.8, §14 11; ADR-0022, ADR-0041;
//! VC-077..080, VC-083).
//!
//! [`verify_connectivity`] reads what the public verifier can check of
//! the declared, audited connections:
//!
//! 1. **The manifest (VC-077).** The genesis pins a per-class connection
//!    policy (`ConnectivityManifest`, version 2). Every device class has
//!    an entry; the TCB classes (interpretation unit, commitment unit,
//!    check-in unit, chamber module) have no inbound port and no radio;
//!    the election-day identity terminal has no connection; only the
//!    early-voting identity terminal (on the election line, during early
//!    voting, to a party outside the system), the gateway and the central
//!    systems have two-way ports; a tap only sends; only the early-voting
//!    identity terminal looks up the roll; the commitment unit and the
//!    check-in unit each have exactly one frame link, send-only, optical,
//!    to the gateway, for the box's opening to its close, carrying public
//!    objects (and, for the commitment unit, sealed share packages) and
//!    never check-in counters; no other class sends frames. A broken rule
//!    is listed and holds the whole ledger (`ConnectivityManifest`): a
//!    declared inbound path concerns every device of its class, so every
//!    box (ADR-0022 decision 11).
//! 2. **Sessions (VC-080).** Each station's `UplinkSession`s in ledger
//!    order: the gateway the genesis registers for the station (in some
//!    state up to the session's frame) signed the body, every observer is
//!    a registered observer of the station whose capture statement
//!    verifies, the number follows the station's last session and the
//!    previous hash is that session body's, the window comes after the
//!    previous one, no session follows a final one, every listed link is a
//!    link of the station's devices, every link with frames has its frame
//!    log in an earlier frame, and no log of the session is left unlisted.
//!    Then, per link, the chain recomputed over the log's frame headers
//!    from the previous head must give the session's head (only then are
//!    the log's frames taken), and the counts of normal and catch-up
//!    frames, the stream end and (once every session is read) the missing
//!    slots must be the log's. A log that no session takes once it could
//!    no longer be taken is refused too. Every refusal and disagreement
//!    holds the station (`UplinkSessionRefused`).
//! 3. **Frames (VC-078).** Per link, over every frame taken: the device's
//!    frame key signed the frame's header; a normal frame's number is
//!    below the manifest's frames per slot and any other's below its
//!    catch-up count; a slot holds frames of one kind group; every frame
//!    lies in its session's window; no frame precedes the slot of the
//!    box's first opening (the station's first, for a check-in unit); no
//!    normal or catch-up frame of a box follows the slot after its first
//!    close's time bucket; nothing but resends follows a close resend and
//!    nothing but witnessed resends follows a witnessed resend; the stream
//!    starts at 0 and each frame starts where the previous ended, or later
//!    across a missing slot; the payload root rebuilt from the published
//!    data leaves and the zero leaf is the signed one (the padding proof);
//!    and every data chunk whose bytes are all public ledger objects gives
//!    the published leaf. A frame that breaks a rule is listed and holds
//!    the device's box, or every box of the station for a check-in unit
//!    (`UplinkFrameInvalid`).
//! 4. **Objects (VC-079).** Per link, over every object listed: a kind the
//!    device may send and the manifest lets it carry (never a check-in
//!    counter or a contested check-in); objects in stream order without
//!    overlap, each starting in the stream received by its session; the
//!    received bytes covered by objects except where frames were lost; a
//!    public object of the ledger with the ledger's length; cast records
//!    only in runs right after a batch attestation, in strictly ascending
//!    record hash; a share package only right after the record that names
//!    it; and, once the gateway sent its final session, every fully
//!    received object a frame of the ledger names (a sealed share package
//!    through the ledger's record right before it). A break is listed and
//!    holds like a frame (`UplinkObjectInvalid`).
//! 5. **Inclusion (VC-080).** Once a station's gateway sent its final
//!    session, every accepted cast record, batch attestation, challenge
//!    opening, progress tick and participation set of the station must be
//!    an object of its device's link (a box's scanner in any genesis state;
//!    the station's check-in units) that lies wholly in received frames.
//!    Otherwise it is listed and holds its box or station
//!    (`UplinkObjectOutside`).
//! 6. **Incidents (VC-083).** A `ConnectivityIncident` signed by two
//!    clerks and observers of two organisations, or by the committee and
//!    observers of two organisations, all registered on the roster
//!    (`ityv_state::check_incident_signers`), whose box (if any) is a box
//!    of its station, holds the box, every box of the station, or the
//!    whole ledger (`ConnectivityIncident`); a commitment unit involved
//!    lists its boxes for a full comparison, with whether the audit stage
//!    compared every record. Otherwise it is refused and holds the ledger
//!    (`ConnectivityIncidentRefused`). The verifier never lifts the hold:
//!    the paper is the legal result of those boxes.
//!
//! The stage is complete ([`ConnectivityStage::complete`]) when every
//! station of the genesis's last state has a final session taken: the
//! status ladder needs it for `SOURCE_COMPLETENESS_CHECKED` (ADR-0041
//! decision 10).
//!
//! What this stage does not prove: that the manifest is the hardware
//! (teardown samples and radio checks, VC-082); the sealed bytes and the
//! fill inside a data chunk that holds them (taps, VC-081:
//! [`crate::compare_capture`]); when a device closed a batch or sent a
//! tick (only the order and unit are visible); the carrier's records
//! ([`crate::compare_carrier`]); anything about the paper.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;

use ityv_crypto::uplink::{chain_next, chain_start, chunk_leaf, link_id, payload_root};
use ityv_crypto::{
    Purpose, RecordPurpose, RecordSignature, RecordVerifyingKey, object_hash, verify_record,
};
use ityv_encoding::{
    BoxClose, BoxId, BoxOpenedBody, CARRY_CHECKIN, CARRY_PUBLIC, CARRY_ROLL, CARRY_SEALED,
    CHUNK_LEN, CaptureMessage, CastRecord, ConnectivityIncidentBody, ConnectivityIncidentParts,
    ConnectivityManifest, DeviceClass, Direction, Encode, EventRole, FrameEntry, FrameKind,
    GatewayId, HEADER_LEN, Hash512, LogLeaves, ManifestEntry, Medium, PURPOSE_UPLINK_CAPTURE,
    PURPOSE_UPLINK_SESSION, RosterRole, SCHEMA_BATCH_ATTEST, SCHEMA_BOX_CLOSE,
    SCHEMA_BOX_OPENED_BODY, SCHEMA_CAST_RECORD, SCHEMA_CHALLENGE_OPENING,
    SCHEMA_CONNECTIVITY_INCIDENT_BODY, SCHEMA_OBSERVER_COUNT_ATTEST_BODY, SCHEMA_PARTICIPATION_SET,
    SCHEMA_PROGRESS_TICK, SCHEMA_SHARE_PACKAGE, SCHEMA_UPLINK_FRAME_HEADER,
    SCHEMA_UPLINK_FRAME_LOG, SCHEMA_UPLINK_SESSION, SCHEMA_VERSION_1, SCHEMA_WITNESSED_EVENT,
    Schedule, SchemaId, Seq, StationEntry, StationId, StreamObject, UnitId, UplinkFrameHeader,
    UplinkFrameLog, UplinkSession, WitnessedEvent, decode_object, encode_object, schema_version,
};
use ityv_state::{HoldReason, HoldSet, RosterEntry, Signed, check_incident_signers};

use crate::audit::AuditStage;
use crate::genesis::VerifiedGenesis;
use crate::index::{LedgerIndex, Scope};
use crate::progress::bucket_slots;
use crate::sigs::Material;

// ---------------------------------------------------------------------------
// Report types.

/// A rule of the manifest (VC-077) an entry or class breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ManifestProblem {
    /// The class has no entry.
    Uncovered,
    /// A TCB device's port receives (direction other than none or
    /// send-only).
    TcbInbound,
    /// A TCB device's port is wireless.
    TcbWireless,
    /// The election-day identity terminal has a connection.
    TerminalConnected,
    /// A two-way port of a class that may not have one, or the early-voting
    /// terminal's two-way port not on the election line, during early
    /// voting, to a party outside the system.
    TwoWay,
    /// A tap that does not only send.
    TapNotSendOnly,
    /// A roll lookup on a class other than the early-voting terminal.
    RollLookup,
    /// The commitment unit or check-in unit has no frame link, or more
    /// than one.
    FrameLinkCount,
    /// A frame link that is not send-only, optical, to the gateway, for the
    /// box's opening to its close.
    FrameLinkShape,
    /// A frame link that may carry what its device may not send: a
    /// check-in counter (VC-084), anything but public objects (and sealed
    /// packages for the commitment unit).
    FrameLinkCarries,
    /// A class other than the commitment unit and check-in unit sends
    /// frames.
    FramesElsewhere,
}

/// A manifest rule broken by one entry (or one class, for
/// [`ManifestProblem::Uncovered`] and [`ManifestProblem::FrameLinkCount`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ManifestFinding<'a> {
    /// The class.
    pub class: DeviceClass,
    /// The port, when one entry breaks the rule.
    pub port: Option<&'a [u8]>,
    /// The rule.
    pub problem: ManifestProblem,
}

/// The device a link belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkDevice<'a> {
    /// A box's scanner (its commitment unit).
    Box(BoxId<'a>),
    /// A check-in unit.
    Unit(UnitId<'a>),
}

/// Why a session, a frame log or a link's record was not taken (VC-080).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionProblem {
    /// The gateway is not one the genesis registers for the station, or
    /// its signature does not verify under that gateway's key.
    Gateway,
    /// An observer is not a registered observer of the station's
    /// organisation, or the capture statement does not verify.
    Observer,
    /// The session's number is not the next of the station.
    Order,
    /// The previous hash is not the previous session body's.
    Previous,
    /// The window does not come after the previous session's.
    Window,
    /// A session after the station's final one.
    AfterFinal,
    /// A listed link is not a link of the station's devices.
    Link,
    /// A link with frames has no frame log before the session.
    LogMissing,
    /// A frame log of the session names a link the session does not
    /// list, or another gateway.
    LogUnlisted,
    /// A second frame log of one session and link.
    LogRepeated,
    /// A frame log no session takes, and none can any more.
    LogDangling,
    /// The chain recomputed over the log is not the session's head: the
    /// log's frames are not taken.
    ChainHead,
    /// The session's normal-frame count is not the log's.
    Frames,
    /// The session's catch-up count is not the log's.
    CatchupFrames,
    /// The session's stream end is not the end of the last frame received.
    StreamEnd,
    /// The session's missing slots are not the slots of its window in which
    /// the link fell short of its shape.
    MissingSlots,
    /// The link fell short of its shape in a slot no session covers.
    UndeclaredGap,
}

/// A session refused, or a disagreement between a taken session and its
/// logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionFinding {
    /// The frame of the session (or of the log, for a log problem).
    pub seq: Seq,
    /// The session's number.
    pub session_index: u32,
    /// The link, for a per-link disagreement.
    pub link: Option<Hash512>,
    /// What is wrong.
    pub problem: SessionProblem,
}

/// A session taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionReport {
    /// Its frame.
    pub seq: Seq,
    /// Its number.
    pub session_index: u32,
    /// Its first slot.
    pub start_slot: u64,
    /// Its last slot.
    pub end_slot: u64,
    /// Whether it is the gateway's final session.
    pub is_final: bool,
    /// How many observers signed a capture statement.
    pub observers: usize,
    /// Bytes on the outer line, as the gateway declares them.
    pub wan_bytes: u64,
    /// Links listed.
    pub links: usize,
}

/// A rule of VC-078 or VC-079 a link breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LinkProblem {
    /// The frame's signature is not the device's frame key over its header.
    Signature,
    /// The number is beyond the slot's count (or the manifest declares no
    /// frame link for the device's class).
    Index,
    /// The slot holds frames of two kind groups.
    Shape,
    /// The frame lies outside its session's window.
    Window,
    /// The frame comes before the box's (or station's) first opening.
    BeforeOpening,
    /// A normal or catch-up frame after the box's close.
    AfterClose,
    /// A normal or catch-up frame after a close resend, or another kind
    /// after a witnessed resend.
    KindOrder,
    /// The stream offset goes back, or skips without a missing slot.
    Offset,
    /// The payload root the data leaves and zero fill give is not the
    /// signed one: a chunk after the data is not zero.
    Fill,
    /// A chunk whose bytes are public ledger objects gives another leaf.
    Chunk,
    /// An object of a kind the device may not send or the manifest does
    /// not let it carry.
    Kind,
    /// An object that starts before the previous one ends.
    Overlap,
    /// An object listed before its first byte was received.
    Early,
    /// Received bytes that belong to no object.
    NotObject,
    /// A public object whose length is not the ledger's.
    Length,
    /// A cast record outside a run right after a batch attestation, or not
    /// above the previous record of its run.
    Batch,
    /// A share package not right after the record that names it.
    Package,
    /// A fully received object no ledger frame names, once the gateway
    /// closed (a share package: no record on the ledger right before it
    /// names it).
    NotOnLedger,
}

impl LinkProblem {
    /// The hold the problem puts on the device's boxes.
    #[must_use]
    pub const fn hold(self) -> HoldReason {
        match self {
            Self::Signature
            | Self::Index
            | Self::Shape
            | Self::Window
            | Self::BeforeOpening
            | Self::AfterClose
            | Self::KindOrder
            | Self::Offset
            | Self::Fill
            | Self::Chunk => HoldReason::UplinkFrameInvalid,
            Self::Kind
            | Self::Overlap
            | Self::Early
            | Self::NotObject
            | Self::Length
            | Self::Batch
            | Self::Package
            | Self::NotOnLedger => HoldReason::UplinkObjectInvalid,
        }
    }
}

/// A frame or object of a link that breaks a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinkFinding {
    /// The frame of the log that lists it.
    pub seq: Seq,
    /// The slot, for a frame.
    pub slot: Option<u64>,
    /// The frame's number in its slot, for a frame.
    pub index: Option<u16>,
    /// The stream offset of the frame or object.
    pub stream_offset: u64,
    /// The object's hash, for an object.
    pub object: Option<Hash512>,
    /// What is wrong.
    pub problem: LinkProblem,
}

/// What the stage found on one link.
#[derive(Debug, Clone)]
pub struct LinkReport<'a> {
    /// The link.
    pub link_id_hash: Hash512,
    /// Its device.
    pub device: LinkDevice<'a>,
    /// Normal frames taken.
    pub frames: u64,
    /// Catch-up and resend frames taken.
    pub catchup_frames: u64,
    /// Frames that carry data.
    pub data_frames: u64,
    /// Slots between the first and last frame in which the link fell short
    /// of its shape.
    pub missing_slots: u64,
    /// The first and last slot of a normal, catch-up or close-resend frame.
    pub slots: Option<(u64, u64)>,
    /// The end of the stream received.
    pub stream_end: u64,
    /// Objects listed.
    pub objects: u64,
    /// Data chunks recomputed from public ledger objects.
    pub checked_chunks: u64,
    /// Data chunks the public cannot recompute (sealed bytes, objects not
    /// on the ledger, lost starts): the taps' to check.
    pub opaque_chunks: u64,
    /// Device events of the ledger found inside received frames.
    pub included: u64,
    /// What breaks a rule, in stream order.
    pub findings: Vec<LinkFinding>,
}

/// A device event of the ledger that lies in no received frame of its
/// device's link (VC-080).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OutsideEvent<'a> {
    /// Its frame.
    pub seq: Seq,
    /// Its schema.
    pub schema: SchemaId,
    /// Its object hash.
    pub hash: Hash512,
    /// Whom it concerns.
    pub scope: Scope<'a>,
}

/// What the stage found for one station.
#[derive(Debug, Clone)]
pub struct StationUplink<'a> {
    /// The station.
    pub station_id: StationId<'a>,
    /// Its gateway in the genesis's last state.
    pub gateway_id: Option<GatewayId<'a>>,
    /// The sessions taken, in ledger order.
    pub sessions: Vec<SessionReport>,
    /// The frame of the final session taken, if any.
    pub final_session: Option<Seq>,
    /// Sessions refused, logs refused and disagreements, in ledger order.
    pub findings: Vec<SessionFinding>,
    /// Frame logs that wait for their session.
    pub pending_logs: usize,
    /// Its links with frames taken.
    pub links: Vec<LinkReport<'a>>,
    /// Device events outside every received frame (judged once the final
    /// session is taken).
    pub outside: Vec<OutsideEvent<'a>>,
    /// The holds on every box of the station from this stage.
    pub holds: HoldSet,
}

/// Why an incident was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IncidentProblem {
    /// The signers are not two clerks and observers of two organisations,
    /// or the committee and observers of two organisations, on the roster.
    Signers,
    /// The box is not a box of the station.
    Subject,
}

/// A connectivity incident on the ledger (VC-083).
#[derive(Debug, Clone)]
pub struct IncidentReport<'a> {
    /// Its frame.
    pub seq: Seq,
    /// Its fields.
    pub parts: ConnectivityIncidentParts<'a>,
    /// Why it was refused, if it was.
    pub refused: Option<IncidentProblem>,
    /// The boxes whose electronic layer it holds (every box for an
    /// incident of the election).
    pub boxes: Vec<BoxId<'a>>,
    /// For an incident that involves a commitment unit: each box to compare
    /// in full (§12.5), with whether the audit stage compared every record.
    pub full_comparison: Vec<(BoxId<'a>, bool)>,
}

/// The connectivity stage.
#[derive(Debug, Clone)]
pub struct ConnectivityStage<'a> {
    manifest: Vec<ManifestFinding<'a>>,
    stations: Vec<StationUplink<'a>>,
    incidents: Vec<IncidentReport<'a>>,
    boxes: BTreeMap<&'a [u8], HoldSet>,
    ledger: HoldSet,
}

impl<'a> ConnectivityStage<'a> {
    /// The manifest's broken rules.
    #[must_use]
    pub fn manifest_findings(&self) -> &[ManifestFinding<'a>] {
        &self.manifest
    }

    /// One entry per station of the genesis's last state, in station
    /// order, then one per other station with sessions.
    #[must_use]
    pub fn stations(&self) -> &[StationUplink<'a>] {
        &self.stations
    }

    /// The entry of station `station_id`.
    #[must_use]
    pub fn station(&self, station_id: &[u8]) -> Option<&StationUplink<'a>> {
        self.stations
            .iter()
            .find(|s| s.station_id.as_bytes() == station_id)
    }

    /// The incidents, in ledger order.
    #[must_use]
    pub fn incidents(&self) -> &[IncidentReport<'a>] {
        &self.incidents
    }

    /// Whether every station of the genesis's last state has its gateway's
    /// final session taken (ADR-0041 decision 10).
    #[must_use]
    pub fn complete(&self) -> bool {
        self.stations
            .iter()
            .filter(|s| s.gateway_id.is_some())
            .all(|s| s.final_session.is_some())
    }

    /// The stage's holds on box `box_id` (with the ledger's).
    #[must_use]
    pub fn box_holds(&self, box_id: &[u8]) -> HoldSet {
        self.boxes
            .get(box_id)
            .copied()
            .unwrap_or(HoldSet::empty())
            .union(self.ledger)
    }

    /// The stage's holds on the whole ledger, not on one box: a manifest
    /// that breaks a rule, an incident of the whole election, a refused
    /// incident, a hold on a station the genesis's last state does not
    /// have.
    #[must_use]
    pub const fn ledger_holds(&self) -> HoldSet {
        self.ledger
    }

    /// Every hold of the stage.
    #[must_use]
    pub fn holds(&self) -> HoldSet {
        self.boxes
            .values()
            .fold(self.ledger, |acc, h| acc.union(*h))
    }
}

// ---------------------------------------------------------------------------
// The manifest (VC-077).

fn manifest_findings<'a>(manifest: &ConnectivityManifest<'a>) -> Vec<ManifestFinding<'a>> {
    let mut out = Vec::new();
    let entries: Vec<ManifestEntry<'a>> = manifest.entries().iter().collect();
    for class in DeviceClass::ALL {
        if !entries.iter().any(|e| e.device_class == *class) {
            out.push(ManifestFinding {
                class: *class,
                port: None,
                problem: ManifestProblem::Uncovered,
            });
        }
    }
    for e in &entries {
        for problem in entry_problems(e) {
            out.push(ManifestFinding {
                class: e.device_class,
                port: Some(e.port.as_bytes()),
                problem,
            });
        }
    }
    for class in [DeviceClass::CommitmentUnit, DeviceClass::CheckinUnit] {
        let links = entries
            .iter()
            .filter(|e| e.device_class == class && e.sends_frames())
            .count();
        if links != 1 {
            out.push(ManifestFinding {
                class,
                port: None,
                problem: ManifestProblem::FrameLinkCount,
            });
        }
    }
    out
}

/// What a commitment unit's frame link may carry: public objects and
/// sealed share packages (ADR-0041 decision 7), the bits `CARRY_PUBLIC`
/// and `CARRY_SEALED`. A literal, as `ityv_encoding::CARRIES_MASK` is: the
/// two bits are disjoint, so in an expression of them `|` and `^` give the
/// same set. The unit tests tie the literal to the two names.
const SCANNER_CARRIES: u32 = 0b11;

/// The rules one entry breaks.
fn entry_problems(e: &ManifestEntry<'_>) -> Vec<ManifestProblem> {
    let mut out = Vec::new();
    let class = e.device_class;
    let two_way = e.direction == Direction::Both;
    if class.is_tcb() && !matches!(e.direction, Direction::None | Direction::OutOnly) {
        out.push(ManifestProblem::TcbInbound);
    }
    if class.is_tcb() && e.medium == Medium::Wireless {
        out.push(ManifestProblem::TcbWireless);
    }
    if class == DeviceClass::IdTerminalElectionDay && e.direction != Direction::None {
        out.push(ManifestProblem::TerminalConnected);
    }
    let two_way_allowed = match class {
        DeviceClass::IdTerminalEarlyVoting => {
            e.medium == Medium::ElectionLine
                && e.schedule == Schedule::EarlyVoting
                && e.peer_class.is_none()
        }
        DeviceClass::Gateway
        | DeviceClass::LedgerCollector
        | DeviceClass::BoardPublisher
        | DeviceClass::Witness
        | DeviceClass::TrusteeReceiver => true,
        DeviceClass::InterpretationUnit
        | DeviceClass::CommitmentUnit
        | DeviceClass::CheckinUnit
        | DeviceClass::ChamberModule
        | DeviceClass::IdTerminalElectionDay
        | DeviceClass::Tap
        | DeviceClass::ReceiptReader
        | DeviceClass::ImprintReader
        | DeviceClass::Printer => false,
    };
    if two_way && !two_way_allowed {
        out.push(ManifestProblem::TwoWay);
    }
    if class == DeviceClass::Tap && e.direction != Direction::OutOnly {
        out.push(ManifestProblem::TapNotSendOnly);
    }
    if e.carries & CARRY_ROLL != 0 && class != DeviceClass::IdTerminalEarlyVoting {
        out.push(ManifestProblem::RollLookup);
    }
    if e.sends_frames() {
        let allowed = match class {
            DeviceClass::CommitmentUnit => SCANNER_CARRIES,
            DeviceClass::CheckinUnit => CARRY_PUBLIC,
            DeviceClass::InterpretationUnit
            | DeviceClass::ChamberModule
            | DeviceClass::IdTerminalElectionDay
            | DeviceClass::IdTerminalEarlyVoting
            | DeviceClass::Gateway
            | DeviceClass::Tap
            | DeviceClass::LedgerCollector
            | DeviceClass::BoardPublisher
            | DeviceClass::Witness
            | DeviceClass::TrusteeReceiver
            | DeviceClass::ReceiptReader
            | DeviceClass::ImprintReader
            | DeviceClass::Printer => {
                out.push(ManifestProblem::FramesElsewhere);
                0
            }
        };
        let shaped = e.direction == Direction::OutOnly
            && e.medium == Medium::OpticalTransmit
            && e.peer_class == Some(DeviceClass::Gateway)
            && e.schedule == Schedule::BoxOpenToClose;
        if allowed != 0 && !shaped {
            out.push(ManifestProblem::FrameLinkShape);
        }
        if allowed != 0 && (e.carries & !allowed != 0 || e.carries & CARRY_CHECKIN != 0) {
            out.push(ManifestProblem::FrameLinkCarries);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Links and devices.

/// A link the genesis registers: its device, station and frame key.
#[derive(Debug, Clone, Copy)]
struct LinkInfo<'a> {
    device: LinkDevice<'a>,
    station: StationId<'a>,
    frame_key: &'a [u8; ityv_encoding::FRAME_KEY_LEN],
}

impl LinkInfo<'_> {
    const fn class(&self) -> DeviceClass {
        match self.device {
            LinkDevice::Box(_) => DeviceClass::CommitmentUnit,
            LinkDevice::Unit(_) => DeviceClass::CheckinUnit,
        }
    }
}

/// Every link of every genesis state, by link hash (the earliest state
/// that has it).
fn links<'a>(genesis: &VerifiedGenesis<'a>) -> BTreeMap<[u8; 64], LinkInfo<'a>> {
    let mut out = BTreeMap::new();
    for state in 0..genesis.state_count() {
        for b in genesis.boxes_at(state) {
            out.entry(link_id(b.frame_key).0).or_insert(LinkInfo {
                device: LinkDevice::Box(b.box_id),
                station: b.station_id,
                frame_key: b.frame_key,
            });
        }
        for s in genesis.stations_at(state) {
            for unit in [s.primary(), s.spare()] {
                out.entry(link_id(unit.frame_key).0).or_insert(LinkInfo {
                    device: LinkDevice::Unit(unit.unit_id),
                    station: s.station_id(),
                    frame_key: unit.frame_key,
                });
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The stage's work.

/// One frame taken from a log, with its leaves.
#[derive(Debug, Clone, Copy)]
struct Frame<'a> {
    log: Seq,
    window: (u64, u64),
    entry: FrameEntry<'a>,
    leaves: LogLeaves<'a>,
}

/// One object listed by a taken log.
#[derive(Debug, Clone, Copy)]
struct Listed {
    log: Seq,
    /// The stream end once the session that lists it was read.
    received_by: u64,
    object: StreamObject,
}

/// What one link accumulates over the sessions.
#[derive(Debug, Clone)]
struct LinkWork<'a> {
    info: LinkInfo<'a>,
    head: Hash512,
    stream_end: u64,
    frames: Vec<Frame<'a>>,
    objects: Vec<Listed>,
}

/// A session's declared missing slots per link, for the check after every
/// session is read.
#[derive(Debug, Clone, Copy)]
struct Declared {
    session_index: u32,
    link: [u8; 64],
    missing: u32,
}

/// What one station accumulates.
#[derive(Debug, Clone)]
struct StationWork<'a> {
    station_id: StationId<'a>,
    /// The last session taken: number, body hash, last slot.
    last: Option<(u32, Hash512, u64)>,
    final_session: Option<Seq>,
    sessions: Vec<SessionReport>,
    findings: Vec<SessionFinding>,
    declared: Vec<Declared>,
}

impl<'a> StationWork<'a> {
    const fn new(station_id: StationId<'a>) -> Self {
        Self {
            station_id,
            last: None,
            final_session: None,
            sessions: Vec::new(),
            findings: Vec::new(),
            declared: Vec::new(),
        }
    }

    fn find(&mut self, seq: Seq, index: u32, link: Option<Hash512>, problem: SessionProblem) {
        self.findings.push(SessionFinding {
            seq,
            session_index: index,
            link,
            problem,
        });
    }
}

type LogKey<'a> = (&'a [u8], u32, [u8; 64]);

struct Work<'g, 'a> {
    genesis: &'g VerifiedGenesis<'a>,
    index: &'g LedgerIndex<'a>,
    links: BTreeMap<[u8; 64], LinkInfo<'a>>,
    per_link: BTreeMap<[u8; 64], LinkWork<'a>>,
    stations: BTreeMap<&'a [u8], StationWork<'a>>,
    logs: BTreeMap<LogKey<'a>, (Seq, UplinkFrameLog<'a>)>,
}

/// The encoded header object of `header`, and its object hash.
fn header_hash(header: &ityv_encoding::UplinkFrameHeaderParts) -> Option<(Hash512, [u8; 167])> {
    let h = UplinkFrameHeader::new(header).ok()?;
    let mut buf = [0u8; 167];
    let len = encode_object(SCHEMA_UPLINK_FRAME_HEADER, SCHEMA_VERSION_1, &h, &mut buf).ok()?;
    let bytes = buf.get(..len)?;
    Some((object_hash(bytes), buf))
}

/// The head after `frames` from `head`, or `None` if a header cannot be
/// built.
fn chain_over<'a>(
    head: Hash512,
    link: &Hash512,
    frames: impl Iterator<Item = FrameEntry<'a>>,
) -> Option<Hash512> {
    let mut h = head;
    for f in frames {
        let (hash, _) = header_hash(&f.header(*link))?;
        h = chain_next(&h, &hash);
    }
    Some(h)
}

impl<'a> Work<'_, 'a> {
    fn station(&mut self, station_id: StationId<'a>) -> &mut StationWork<'a> {
        self.stations
            .entry(station_id.as_bytes())
            .or_insert_with(|| StationWork::new(station_id))
    }

    /// The key of the gateway `gateway` of `station` in some state up to
    /// `state` whose signature over `body` verifies.
    fn gateway_signed(
        &self,
        state: usize,
        session: &UplinkSession<'a>,
        gateway: GatewayId<'_>,
        station: &[u8],
    ) -> bool {
        let Some(purpose) = Purpose::new(PURPOSE_UPLINK_SESSION) else {
            return false;
        };
        (0..=state).any(|k| {
            self.genesis.station_at(k, station).is_some_and(|s| {
                let g = s.gateway();
                g.gateway_id.as_bytes() == gateway.as_bytes()
                    && Material::new(core::iter::once((session.gateway_sig(), g.key)))
                        .is_some_and(|m| m.verify(&purpose, session.body_bytes()).is_some())
            })
        })
    }

    /// Whether every observer of `session` is an observer of the station's
    /// organisation registered in some state up to `state` whose capture
    /// statement verifies.
    fn observers_signed(&self, state: usize, session: &UplinkSession<'a>, station: &[u8]) -> bool {
        let Some(purpose) = Purpose::new(PURPOSE_UPLINK_CAPTURE) else {
            return false;
        };
        let body_hash = object_hash(session.body_bytes());
        session.observers().all(|o| {
            let message = CaptureMessage {
                body_hash,
                observer_id: o.observer_id,
                capture_hash: o.capture_hash,
            };
            let mut bytes = vec![0u8; message.encoded_len()];
            let mut w = ityv_encoding::Writer::new(&mut bytes);
            if message.encode(&mut w).is_err() {
                return false;
            }
            (0..=state).any(|k| {
                self.genesis.roster_at(k).iter().any(|r| {
                    let r = r.get();
                    r.signer_id.as_bytes() == o.observer_id.as_bytes()
                        && r.role == RosterRole::Observer
                        && r.org_id.as_bytes() == o.org_id.as_bytes()
                        && r.station_id.is_some_and(|s| s.as_bytes() == station)
                        && Material::new(core::iter::once((o.sig, r.key)))
                            .is_some_and(|m| m.verify(&purpose, &bytes).is_some())
                })
            })
        })
    }

    /// Reads one session in ledger order.
    #[allow(clippy::too_many_lines)] // The acceptance rules, then the per-link records, in order.
    fn session(&mut self, seq: Seq, session: &UplinkSession<'a>) {
        let p = *session.body().parts();
        let station = p.station_id;
        let state = self.index.state_at(seq);
        let index = p.session_index;
        let keys: Vec<LogKey<'a>> = self
            .logs
            .keys()
            .filter(|(s, i, _)| *s == station.as_bytes() && *i == index)
            .copied()
            .collect();
        let refusal = {
            let st = self.stations.get(station.as_bytes());
            let last = st.and_then(|s| s.last);
            let expected = last.map_or(Some(1), |(i, _, _)| i.checked_add(1));
            let previous = last.map_or(Hash512::ZERO, |(_, h, _)| h);
            if !self.gateway_signed(state, session, p.gateway_id, station.as_bytes()) {
                Some(SessionProblem::Gateway)
            } else if !self.observers_signed(state, session, station.as_bytes()) {
                Some(SessionProblem::Observer)
            } else if st.is_some_and(|s| s.final_session.is_some()) {
                Some(SessionProblem::AfterFinal)
            } else if expected != Some(index) {
                Some(SessionProblem::Order)
            } else if p.previous_session_hash != previous {
                Some(SessionProblem::Previous)
            } else if last.is_some_and(|(_, _, end)| p.start_slot <= end) {
                Some(SessionProblem::Window)
            } else if p.links.iter().any(|l| {
                self.links
                    .get(&l.link_id_hash.0)
                    .is_none_or(|i| i.station.as_bytes() != station.as_bytes())
            }) {
                Some(SessionProblem::Link)
            } else if p.links.iter().any(|l| {
                l.frames.saturating_add(l.catchup_frames) > 0
                    && !keys.iter().any(|k| k.2 == l.link_id_hash.0)
            }) {
                Some(SessionProblem::LogMissing)
            } else if keys.iter().any(|k| {
                let listed = p.links.iter().any(|l| l.link_id_hash.0 == k.2);
                let gateway = self.logs.get(k).is_some_and(|(_, log)| {
                    log.parts().gateway_id.as_bytes() == p.gateway_id.as_bytes()
                });
                !listed || !gateway
            }) {
                Some(SessionProblem::LogUnlisted)
            } else {
                None
            }
        };
        let logs: Vec<(Seq, UplinkFrameLog<'a>)> =
            keys.iter().filter_map(|k| self.logs.remove(k)).collect();
        if let Some(problem) = refusal {
            self.station(station).find(seq, index, None, problem);
            return;
        }
        let window = (p.start_slot, p.end_slot);
        let mut findings = Vec::new();
        let mut declared = Vec::new();
        for l in p.links.iter() {
            let link = l.link_id_hash;
            let log = logs
                .iter()
                .find(|(_, log)| log.parts().link_id_hash == link)
                .copied();
            let Some(info) = self.links.get(&link.0).copied() else {
                continue;
            };
            let work = self.per_link.entry(link.0).or_insert_with(|| LinkWork {
                info,
                head: chain_start(&link),
                stream_end: 0,
                frames: Vec::new(),
                objects: Vec::new(),
            });
            declared.push(Declared {
                session_index: index,
                link: link.0,
                missing: l.missing_slots,
            });
            let frames: Vec<FrameEntry<'a>> = log
                .map(|(_, lg)| lg.parts().frames.iter().collect())
                .unwrap_or_default();
            let head = chain_over(work.head, &link, frames.iter().copied());
            if head != Some(l.chain_head) {
                findings.push((Some(link), SessionProblem::ChainHead));
                continue;
            }
            let normal = u64::try_from(
                frames
                    .iter()
                    .filter(|f| f.kind == FrameKind::Normal)
                    .count(),
            )
            .unwrap_or(u64::MAX);
            let other = u64::try_from(frames.len())
                .unwrap_or(u64::MAX)
                .saturating_sub(normal);
            let end = frames.last().map_or(work.stream_end, |f| {
                f.stream_offset.saturating_add(u64::from(f.payload_len))
            });
            if normal != l.frames {
                findings.push((Some(link), SessionProblem::Frames));
            }
            if other != l.catchup_frames {
                findings.push((Some(link), SessionProblem::CatchupFrames));
            }
            if end != l.stream_end {
                findings.push((Some(link), SessionProblem::StreamEnd));
            }
            work.head = l.chain_head;
            work.stream_end = end;
            if let Some((log_seq, lg)) = log {
                let parts = lg.parts();
                let mut leaves = parts.leaves.as_bytes();
                for f in parts.frames.iter() {
                    let n = f.payload_len;
                    let take = ityv_encoding::data_chunks(n).saturating_mul(64);
                    let (mine, rest) = leaves.split_at_checked(take).unwrap_or((&[], &[]));
                    leaves = rest;
                    work.frames.push(Frame {
                        log: log_seq,
                        window,
                        entry: f,
                        leaves: LogLeaves::new(mine).unwrap_or(LogLeaves::EMPTY),
                    });
                }
                for o in parts.objects.iter() {
                    work.objects.push(Listed {
                        log: log_seq,
                        received_by: end,
                        object: o,
                    });
                }
            }
        }
        let st = self.station(station);
        for (link, problem) in findings {
            st.find(seq, index, link, problem);
        }
        st.declared.extend(declared);
        st.last = Some((index, object_hash(session.body_bytes()), p.end_slot));
        if p.is_final {
            st.final_session = Some(seq);
        }
        st.sessions.push(SessionReport {
            seq,
            session_index: index,
            start_slot: p.start_slot,
            end_slot: p.end_slot,
            is_final: p.is_final,
            observers: session.observers().count(),
            wan_bytes: p.wan_bytes,
            links: p.links.len(),
        });
    }
}

// ---------------------------------------------------------------------------
// One link's frames and objects.

/// What a link's judgement needs from the rest of the ledger.
struct LinkContext<'c, 'a> {
    entry: Option<ManifestEntry<'a>>,
    opening: Option<u64>,
    close: Option<u64>,
    /// Public ledger objects by hash: schema and bytes.
    public: &'c BTreeMap<[u8; 64], (SchemaId, &'a [u8])>,
    /// Every event hash a ledger frame names.
    on_ledger: &'c BTreeSet<[u8; 64]>,
    closed: bool,
}

/// The received ranges of a link: merged `[start, end)` of every frame
/// whose signature verified.
fn received_ranges(frames: &[(Frame<'_>, bool)]) -> Vec<(u64, u64)> {
    let mut ranges: Vec<(u64, u64)> = frames
        .iter()
        .filter(|(f, valid)| *valid && f.entry.payload_len > 0)
        .map(|(f, _)| {
            let start = f.entry.stream_offset;
            (start, start.saturating_add(u64::from(f.entry.payload_len)))
        })
        .collect();
    ranges.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (start, end) in ranges {
        match out.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out
}

/// The slots of `[a, b]` no window covers (windows do not overlap).
fn uncovered(windows: &[(u64, u64)], a: u64, b: u64) -> u64 {
    let Some(span) = b.checked_sub(a).and_then(|d| d.checked_add(1)) else {
        return 0;
    };
    let covered = windows.iter().fold(0u64, |acc, (start, end)| {
        let lo = a.max(*start);
        let hi = b.min(*end);
        let overlap = hi
            .checked_sub(lo)
            .and_then(|d| d.checked_add(1))
            .unwrap_or(0);
        acc.saturating_add(overlap)
    });
    span.saturating_sub(covered)
}

/// Whether `[start, end)` lies wholly in `ranges`.
fn covered(ranges: &[(u64, u64)], start: u64, end: u64) -> bool {
    start >= end || ranges.iter().any(|(a, b)| *a <= start && end <= *b)
}

/// The data-chunk leaf of `frame`'s chunk `j` recomputed from public
/// objects, or `None` if a byte of it is not public.
fn public_leaf(
    frame: &FrameEntry<'_>,
    j: usize,
    objects: &[Listed],
    public: &BTreeMap<[u8; 64], (SchemaId, &[u8])>,
) -> Option<Hash512> {
    let offset_in = u64::try_from(j.checked_mul(CHUNK_LEN)?).ok()?;
    let start = frame.stream_offset.checked_add(offset_in)?;
    let data_end = frame
        .stream_offset
        .checked_add(u64::from(frame.payload_len))?;
    let end = start
        .checked_add(u64::try_from(CHUNK_LEN).ok()?)?
        .min(data_end);
    let mut chunk = Vec::with_capacity(CHUNK_LEN);
    let mut at = start;
    let first = objects.partition_point(|l| l.object.stream_offset <= start);
    let mut i = first.checked_sub(1)?;
    while at < end {
        let l = objects.get(i)?;
        let o = &l.object;
        let o_end = o.end()?;
        if o.stream_offset > at || o_end <= at {
            return None;
        }
        let (schema, bytes) = public.get(&o.object_hash.0)?;
        if *schema != o.schema || u64::try_from(bytes.len()).ok() != Some(u64::from(o.len)) {
            return None;
        }
        let from = usize::try_from(at.checked_sub(o.stream_offset)?).ok()?;
        let to = usize::try_from(end.min(o_end).checked_sub(o.stream_offset)?).ok()?;
        chunk.extend_from_slice(bytes.get(from..to)?);
        at = end.min(o_end);
        i = i.checked_add(1)?;
    }
    Some(chunk_leaf(&chunk))
}

/// The schemas a device of `class` may send, and the `carries` bit each
/// needs.
fn allowed(class: DeviceClass, schema: SchemaId) -> Option<u32> {
    let s = schema.get();
    match class {
        DeviceClass::CommitmentUnit if s == SCHEMA_SHARE_PACKAGE.get() => Some(CARRY_SEALED),
        DeviceClass::CommitmentUnit
            if [
                SCHEMA_CAST_RECORD,
                SCHEMA_BATCH_ATTEST,
                SCHEMA_CHALLENGE_OPENING,
                SCHEMA_PROGRESS_TICK,
            ]
            .contains(&schema) =>
        {
            Some(CARRY_PUBLIC)
        }
        DeviceClass::CheckinUnit
            if [
                SCHEMA_PROGRESS_TICK,
                SCHEMA_PARTICIPATION_SET,
                SCHEMA_WITNESSED_EVENT,
            ]
            .contains(&schema) =>
        {
            Some(CARRY_PUBLIC)
        }
        DeviceClass::CommitmentUnit
        | DeviceClass::CheckinUnit
        | DeviceClass::InterpretationUnit
        | DeviceClass::ChamberModule
        | DeviceClass::IdTerminalElectionDay
        | DeviceClass::IdTerminalEarlyVoting
        | DeviceClass::Gateway
        | DeviceClass::Tap
        | DeviceClass::LedgerCollector
        | DeviceClass::BoardPublisher
        | DeviceClass::Witness
        | DeviceClass::TrusteeReceiver
        | DeviceClass::ReceiptReader
        | DeviceClass::ImprintReader
        | DeviceClass::Printer => None,
    }
}

/// Whether a check-in unit's witnessed object is an observer count (the
/// only witnessed body it carries); `true` when its bytes are not known.
fn witnessed_ok(bytes: Option<&[u8]>) -> bool {
    bytes.is_none_or(|b| {
        decode_object::<WitnessedEvent<'_>>(
            SCHEMA_WITNESSED_EVENT,
            schema_version(SCHEMA_WITNESSED_EVENT),
            b,
        )
        .is_ok_and(|e| e.body_schema() == SCHEMA_OBSERVER_COUNT_ATTEST_BODY)
    })
}

/// The frame rules of one link (VC-078): the per-frame findings, whether
/// each frame's signature verified, and the slots that fell short.
#[allow(clippy::too_many_lines)] // One rule after another, as the module docs list them.
fn judge_frames(
    work: &LinkWork<'_>,
    ctx: &LinkContext<'_, '_>,
    windows: &[(u64, u64)],
    report: &mut LinkReport<'_>,
) -> (Vec<bool>, BTreeSet<u64>, u64) {
    let key = RecordVerifyingKey::from_bytes(*work.info.frame_key).ok();
    let link = link_id(work.info.frame_key);
    let (normal, catchup) = ctx
        .entry
        .map_or((0, 0), |e| (e.frames_per_slot, e.catchup_frames_per_slot));
    let mut valid = Vec::with_capacity(work.frames.len());
    let finding = |f: &Frame<'_>, problem| LinkFinding {
        seq: f.log,
        slot: Some(f.entry.slot),
        index: Some(f.entry.index),
        stream_offset: f.entry.stream_offset,
        object: None,
        problem,
    };
    // Signatures, numbers, windows, opening and close, padding proofs.
    let mut slots: BTreeMap<u64, (bool, bool, BTreeSet<u16>)> = BTreeMap::new();
    let mut reached = 0u8;
    for f in &work.frames {
        let e = &f.entry;
        let header = e.header(link);
        let signed = key.as_ref().is_some_and(|k| {
            header_hash(&header).is_some_and(|(_, buf)| {
                buf.get(..HEADER_LEN.saturating_add(151))
                    .is_some_and(|obj| {
                        verify_record(
                            k,
                            RecordPurpose::UplinkFrame,
                            obj,
                            &RecordSignature::from_bytes(*e.frame_sig),
                        )
                        .is_ok()
                    })
            })
        });
        valid.push(signed);
        if !signed {
            report.findings.push(finding(f, LinkProblem::Signature));
        }
        if e.kind.uses_catchup() {
            report.catchup_frames = report.catchup_frames.saturating_add(1);
        } else {
            report.frames = report.frames.saturating_add(1);
        }
        if e.payload_len > 0 {
            report.data_frames = report.data_frames.saturating_add(1);
        }
        let limit = if e.kind.uses_catchup() {
            catchup
        } else {
            normal
        };
        if e.index >= limit {
            report.findings.push(finding(f, LinkProblem::Index));
        }
        if e.slot < f.window.0 || e.slot > f.window.1 {
            report.findings.push(finding(f, LinkProblem::Window));
        }
        if ctx.opening.is_none_or(|open| e.slot < open) {
            report.findings.push(finding(f, LinkProblem::BeforeOpening));
        }
        let continuing = matches!(e.kind, FrameKind::Normal | FrameKind::CatchUp);
        if continuing && ctx.close.is_some_and(|close| e.slot > close) {
            report.findings.push(finding(f, LinkProblem::AfterClose));
        }
        // Nothing but resends after a close resend, nothing but witnessed
        // resends after a witnessed resend.
        let rank = match e.kind {
            FrameKind::Normal | FrameKind::CatchUp => 0u8,
            FrameKind::CloseResend => 1,
            FrameKind::WitnessedResend => 2,
        };
        if rank < reached {
            report.findings.push(finding(f, LinkProblem::KindOrder));
        }
        reached = reached.max(rank);
        let root = payload_root(f.leaves.iter());
        if root != Some(e.payload_root) {
            report.findings.push(finding(f, LinkProblem::Fill));
        }
        let group = slots.entry(e.slot).or_insert_with(|| {
            (
                e.kind.uses_catchup(),
                e.kind == FrameKind::WitnessedResend,
                BTreeSet::new(),
            )
        });
        if group.0 != e.kind.uses_catchup() || group.1 != (e.kind == FrameKind::WitnessedResend) {
            report.findings.push(finding(f, LinkProblem::Shape));
        }
        group.2.insert(e.index);
    }
    // The slots that fell short of their shape, between the first and last
    // slot of a frame that is not a witnessed resend.
    let span: Vec<u64> = work
        .frames
        .iter()
        .filter(|f| f.entry.kind != FrameKind::WitnessedResend)
        .map(|f| f.entry.slot)
        .collect();
    let first = span.iter().min().copied();
    let last = span.iter().max().copied();
    report.slots = first.zip(last);
    // Each window holds at most six slots, so this walks a bounded number
    // of slots whatever the frames claim.
    let mut short = BTreeSet::new();
    let mut gap = 0u64;
    if let (Some(a), Some(b)) = (first, last) {
        for (start, end) in windows {
            for s in a.max(*start)..=b.min(*end) {
                // A slot is whole when it holds every number of its shape;
                // a number beyond the shape is an `Index` finding, not a
                // gap.
                let full = slots.get(&s).is_some_and(|(cu, _, indices)| {
                    let want = if *cu { catchup } else { normal };
                    indices.range(..want).count() == usize::from(want)
                });
                if !full {
                    short.insert(s);
                }
            }
        }
        gap = uncovered(windows, a, b);
    }
    report.missing_slots = u64::try_from(short.len())
        .unwrap_or(u64::MAX)
        .saturating_add(gap);
    // Stream offsets: from 0, each frame where the previous ended, or later
    // across a slot that fell short or that no window covers.
    let mut expected: Option<(u64, u64)> = None;
    for f in &work.frames {
        let e = &f.entry;
        let ok = match expected {
            None => e.stream_offset == 0,
            Some((end, slot)) => match e.stream_offset.cmp(&end) {
                Ordering::Equal => true,
                Ordering::Greater => {
                    slot <= e.slot
                        && (short.range(slot..=e.slot).next().is_some()
                            || uncovered(windows, slot, e.slot) > 0)
                }
                Ordering::Less => false,
            },
        };
        if !ok {
            report.findings.push(finding(f, LinkProblem::Offset));
        }
        expected = Some((
            e.stream_offset.saturating_add(u64::from(e.payload_len)),
            e.slot,
        ));
    }
    (valid, short, gap)
}

/// The object rules of one link (VC-079), and the chunk checks.
#[allow(clippy::too_many_lines)] // One rule after another, as the module docs list them.
fn judge_objects(
    work: &LinkWork<'_>,
    ctx: &LinkContext<'_, '_>,
    valid: &[bool],
    report: &mut LinkReport<'_>,
) -> Vec<(u64, u64)> {
    let paired: Vec<(Frame<'_>, bool)> = work
        .frames
        .iter()
        .copied()
        .zip(valid.iter().copied())
        .collect();
    let received = received_ranges(&paired);
    let received_end = received.last().map_or(0, |r| r.1);
    let class = work.info.class();
    let carries = ctx.entry.map_or(0, |e| e.carries);
    report.objects = u64::try_from(work.objects.len()).unwrap_or(u64::MAX);
    let finding = |l: &Listed, problem| LinkFinding {
        seq: l.log,
        slot: None,
        index: None,
        stream_offset: l.object.stream_offset,
        object: Some(l.object.object_hash),
        problem,
    };
    let mut pos = 0u64;
    let mut group = false;
    let mut last_record: Option<[u8; 64]> = None;
    let mut previous: Option<(SchemaId, Option<Hash512>)> = None;
    for l in &work.objects {
        let o = &l.object;
        let end = o.end().unwrap_or(u64::MAX);
        let bytes = ctx.public.get(&o.object_hash.0).copied();
        let bytes_of_schema = bytes.filter(|(s, _)| *s == o.schema).map(|(_, b)| b);
        // Kind.
        let needs = allowed(class, o.schema);
        let kind_ok = needs.is_some_and(|bit| carries & bit != 0)
            && (o.schema != SCHEMA_WITNESSED_EVENT || witnessed_ok(bytes_of_schema));
        if !kind_ok {
            report.findings.push(finding(l, LinkProblem::Kind));
        }
        // Order, listing and tiling.
        if o.stream_offset < pos {
            report.findings.push(finding(l, LinkProblem::Overlap));
        } else if o.stream_offset > pos && covered(&received, pos, o.stream_offset) {
            report.findings.push(finding(l, LinkProblem::NotObject));
        }
        if o.stream_offset >= l.received_by {
            report.findings.push(finding(l, LinkProblem::Early));
        }
        pos = pos.max(end);
        // Length.
        if bytes_of_schema.is_some_and(|b| u64::try_from(b.len()).ok() != Some(u64::from(o.len))) {
            report.findings.push(finding(l, LinkProblem::Length));
        }
        // Batches and packages.
        let schema = o.schema;
        // A share package the record right before it names: sealed, so not
        // on the ledger itself, but named by the record that is.
        let named = schema == SCHEMA_SHARE_PACKAGE
            && previous.is_some_and(|(s, package)| {
                s == SCHEMA_CAST_RECORD && package == Some(o.object_hash)
            });
        if schema == SCHEMA_BATCH_ATTEST {
            group = true;
            last_record = None;
        } else if schema == SCHEMA_CAST_RECORD {
            if !group || last_record.is_some_and(|r| r >= o.object_hash.0) {
                report.findings.push(finding(l, LinkProblem::Batch));
            }
            last_record = Some(o.object_hash.0);
        } else if schema == SCHEMA_SHARE_PACKAGE {
            let follows = previous.is_some_and(|(s, package)| {
                s == SCHEMA_CAST_RECORD && package.is_none_or(|p| p == o.object_hash)
            });
            if !follows {
                report.findings.push(finding(l, LinkProblem::Package));
            }
        } else {
            group = false;
            last_record = None;
        }
        let package = if schema == SCHEMA_CAST_RECORD {
            bytes_of_schema.and_then(|b| {
                decode_object::<CastRecord<'_>>(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, b)
                    .ok()
                    .map(|r| *r.body().share_package_hash())
            })
        } else {
            None
        };
        previous = Some((schema, package));
        // On the ledger, once the gateway closed (a share package through
        // the record that names it).
        if ctx.closed
            && covered(&received, o.stream_offset, end)
            && !ctx.on_ledger.contains(&o.object_hash.0)
            && !named
        {
            report.findings.push(finding(l, LinkProblem::NotOnLedger));
        }
    }
    if ctx.closed
        && pos < received_end
        && covered(&received, pos, received_end)
        && let Some(l) = work.objects.last()
    {
        report.findings.push(finding(l, LinkProblem::NotObject));
    }
    // Chunks.
    for (f, ok) in &paired {
        if !ok {
            continue;
        }
        for (j, leaf) in f.leaves.iter().enumerate() {
            match public_leaf(&f.entry, j, &work.objects, ctx.public) {
                Some(mine) => {
                    report.checked_chunks = report.checked_chunks.saturating_add(1);
                    if mine != leaf {
                        report.findings.push(LinkFinding {
                            seq: f.log,
                            slot: Some(f.entry.slot),
                            index: Some(f.entry.index),
                            stream_offset: f.entry.stream_offset,
                            object: None,
                            problem: LinkProblem::Chunk,
                        });
                    }
                }
                None => report.opaque_chunks = report.opaque_chunks.saturating_add(1),
            }
        }
    }
    received
}

// ---------------------------------------------------------------------------
// The stage.

/// The first slot of the first `BoxOpened` of `box_id`, if any.
pub(crate) fn opening_slot(index: &LedgerIndex<'_>, box_id: &[u8]) -> Option<u64> {
    index.box_events(box_id).find_map(|e| {
        if e.schema != SCHEMA_WITNESSED_EVENT {
            return None;
        }
        let w = decode_object::<WitnessedEvent<'_>>(
            SCHEMA_WITNESSED_EVENT,
            schema_version(SCHEMA_WITNESSED_EVENT),
            e.bytes?,
        )
        .ok()?;
        let b = w.body::<BoxOpenedBody<'_>>(SCHEMA_BOX_OPENED_BODY).ok()?;
        bucket_slots(b.parts().time_bucket).map(|(first, _)| first)
    })
}

/// The slot after the last slot of the first `BoxClose` of `box_id`: the
/// latest a normal or catch-up frame may be sent (the closing progress
/// tick's slot, ADR-0027).
pub(crate) fn close_slot(index: &LedgerIndex<'_>, box_id: &[u8]) -> Option<u64> {
    index.box_events(box_id).find_map(|e| {
        if e.schema != SCHEMA_BOX_CLOSE {
            return None;
        }
        let c = decode_object::<BoxClose<'_>>(SCHEMA_BOX_CLOSE, SCHEMA_VERSION_1, e.bytes?).ok()?;
        bucket_slots(c.body().time_bucket()).and_then(|(_, last)| last.checked_add(1))
    })
}

/// The device events whose inclusion the stage checks (VC-080).
const DEVICE_EVENTS: [SchemaId; 5] = [
    SCHEMA_CAST_RECORD,
    SCHEMA_BATCH_ATTEST,
    SCHEMA_CHALLENGE_OPENING,
    SCHEMA_PROGRESS_TICK,
    SCHEMA_PARTICIPATION_SET,
];

/// Adds `reason` to every box `scope` concerns.
fn hold<'a>(
    genesis: &VerifiedGenesis<'a>,
    boxes: &mut BTreeMap<&'a [u8], HoldSet>,
    ledger: &mut HoldSet,
    scope: Scope<'a>,
    reason: HoldReason,
) {
    let mut add = |b: &'a [u8]| {
        let set = boxes.entry(b).or_insert(HoldSet::empty());
        *set = set.with(reason);
    };
    match scope {
        Scope::Box(b) => add(b.as_bytes()),
        Scope::Station(s) => match genesis.station(s.as_bytes()) {
            Some(station) => station.boxes().for_each(|b| add(b.as_bytes())),
            None => *ledger = ledger.with(reason),
        },
        Scope::Election => *ledger = ledger.with(reason),
    }
}

/// Whether the audit stage compared every record of `box_id`: some style
/// audits it and every style that does compared all its records.
fn fully_compared(audit: &AuditStage<'_>, box_id: &[u8]) -> bool {
    let devices: Vec<_> = audit
        .styles()
        .iter()
        .flat_map(|s| s.devices.iter())
        .filter(|d| d.box_id.as_bytes() == box_id)
        .collect();
    !devices.is_empty() && devices.iter().all(|d| d.compared == d.records)
}

/// Reads one incident (VC-083).
fn incident<'a>(
    genesis: &VerifiedGenesis<'a>,
    index: &LedgerIndex<'a>,
    audit: &AuditStage<'a>,
    seq: Seq,
    event: &WitnessedEvent<'a>,
) -> Option<IncidentReport<'a>> {
    let body = event
        .body::<ConnectivityIncidentBody<'a>>(SCHEMA_CONNECTIVITY_INCIDENT_BODY)
        .ok()?;
    let parts = *body.parts();
    let state = index.state_at(seq);
    let signed = people_signed(genesis, state, event);
    // The box is at that station (in some state). The index already
    // refuses an event naming a station or box no state has (§14 3), and
    // the decoder a box without its station.
    let subject_ok = match (parts.station_id, parts.box_id) {
        (Some(s), Some(b)) => (0..genesis.state_count()).any(|k| {
            genesis
                .expected_box_at(k, b.as_bytes())
                .is_some_and(|x| x.station_id.as_bytes() == s.as_bytes())
        }),
        (Some(_) | None, None) | (None, Some(_)) => true,
    };
    let refused = if !signed {
        Some(IncidentProblem::Signers)
    } else if !subject_ok {
        Some(IncidentProblem::Subject)
    } else {
        None
    };
    let boxes: Vec<BoxId<'a>> = match (parts.box_id, parts.station_id) {
        (Some(b), _) => vec![b],
        (None, Some(s)) => genesis
            .station(s.as_bytes())
            .map(|st| st.boxes().collect())
            .unwrap_or_default(),
        (None, None) => genesis.boxes().map(|b| b.box_id).collect(),
    };
    let full_comparison = if refused.is_none() && parts.commitment_unit {
        boxes
            .iter()
            .map(|b| (*b, fully_compared(audit, b.as_bytes())))
            .collect()
    } else {
        Vec::new()
    };
    Some(IncidentReport {
        seq,
        parts,
        refused,
        boxes: if refused.is_none() { boxes } else { Vec::new() },
        full_comparison,
    })
}

/// Whether the people of `event` are registered and their signatures
/// verify: the committee under the genesis key, every clerk and observer
/// under a key the roster of `state` or an earlier state registers for
/// that signer, role and organisation (`ityv_state::check_incident_signers`).
fn people_signed(genesis: &VerifiedGenesis<'_>, state: usize, event: &WitnessedEvent<'_>) -> bool {
    let Some(purpose) = Purpose::new(event.purpose()) else {
        return false;
    };
    let rosters: Vec<Vec<RosterEntry<'_>>> = (0..=state).map(|k| genesis.roster_at(k)).collect();
    let Some(in_force) = rosters.last() else {
        return false;
    };
    let committee = genesis.genesis().committee_key();
    let mut keys: Vec<RosterEntry<'_>> = Vec::new();
    let mut pairs = Vec::new();
    for s in event.sigs() {
        if s.role == EventRole::Committee {
            pairs.push((s.sig, committee));
            continue;
        }
        let found = rosters.iter().rev().flatten().find(|r| {
            r.get().signer_id.as_bytes() == s.signer_id.as_bytes()
                && Material::new(core::iter::once((s.sig, r.get().key)))
                    .is_some_and(|m| m.verify(&purpose, event.body_bytes()).is_some())
        });
        let Some(entry) = found else {
            return false;
        };
        keys.push(*entry);
        pairs.push((s.sig, entry.get().key));
    }
    let Some(material) = Material::new(pairs.into_iter()) else {
        return false;
    };
    let Some(tokens) = material.verify(&purpose, event.body_bytes()) else {
        return false;
    };
    check_incident_signers(
        &Signed {
            event,
            tokens: &tokens,
        },
        in_force,
        &keys,
        committee,
    )
    .is_ok()
}

/// Runs the connectivity stage over `index` against `genesis`, with the
/// audit stage for the full comparisons an incident calls for.
#[must_use]
#[allow(clippy::too_many_lines)] // The stage's steps in order, as the module docs list them.
pub fn verify_connectivity<'a>(
    genesis: &VerifiedGenesis<'a>,
    index: &LedgerIndex<'a>,
    audit: &AuditStage<'a>,
) -> ConnectivityStage<'a> {
    let manifest = genesis.manifest();
    let manifest_problems = manifest_findings(manifest);
    let mut ledger = HoldSet::empty().with_if(
        !manifest_problems.is_empty(),
        HoldReason::ConnectivityManifest,
    );
    let mut boxes: BTreeMap<&'a [u8], HoldSet> = BTreeMap::new();
    let mut work = Work {
        genesis,
        index,
        links: links(genesis),
        per_link: BTreeMap::new(),
        stations: BTreeMap::new(),
        logs: BTreeMap::new(),
    };
    let mut incidents = Vec::new();
    let mut refused_logs: Vec<(StationId<'a>, Seq, u32, SessionProblem)> = Vec::new();
    for e in index.events() {
        let Some(bytes) = e.bytes else {
            continue;
        };
        if e.schema == SCHEMA_UPLINK_FRAME_LOG {
            let Ok(log) = decode_object::<UplinkFrameLog<'a>>(
                SCHEMA_UPLINK_FRAME_LOG,
                SCHEMA_VERSION_1,
                bytes,
            ) else {
                continue;
            };
            let p = log.parts();
            let key = (p.station_id.as_bytes(), p.session_index, p.link_id_hash.0);
            let taken = work
                .stations
                .get(p.station_id.as_bytes())
                .and_then(|s| s.last)
                .is_some_and(|(i, _, _)| p.session_index <= i);
            if taken || work.logs.contains_key(&key) {
                let problem = if taken {
                    SessionProblem::LogDangling
                } else {
                    SessionProblem::LogRepeated
                };
                refused_logs.push((p.station_id, e.seq, p.session_index, problem));
            } else {
                work.logs.insert(key, (e.seq, log));
            }
        } else if e.schema == SCHEMA_UPLINK_SESSION {
            if let Ok(s) = decode_object::<UplinkSession<'a>>(
                SCHEMA_UPLINK_SESSION,
                schema_version(SCHEMA_UPLINK_SESSION),
                bytes,
            ) {
                work.session(e.seq, &s);
            }
        } else if e.schema == SCHEMA_WITNESSED_EVENT {
            let Ok(w) = decode_object::<WitnessedEvent<'a>>(
                SCHEMA_WITNESSED_EVENT,
                schema_version(SCHEMA_WITNESSED_EVENT),
                bytes,
            ) else {
                continue;
            };
            if w.body_schema() == SCHEMA_CONNECTIVITY_INCIDENT_BODY
                && let Some(report) = incident(genesis, index, audit, e.seq, &w)
            {
                incidents.push(report);
            }
        }
    }
    for (station, seq, i, problem) in refused_logs {
        work.station(station).find(seq, i, None, problem);
    }
    // Logs no session can take any more.
    let dangling: Vec<(LogKey<'a>, Seq, StationId<'a>)> = work
        .logs
        .iter()
        .filter(|((s, i, _), _)| {
            work.stations.get(s).is_some_and(|st| {
                st.final_session.is_some() || st.last.is_some_and(|(n, _, _)| *i <= n)
            })
        })
        .map(|(k, (seq, log))| (*k, *seq, log.parts().station_id))
        .collect();
    for (k, seq, station) in dangling {
        work.logs.remove(&k);
        work.station(station)
            .find(seq, k.1, None, SessionProblem::LogDangling);
    }

    // The ledger's public objects and every hash a frame names.
    let mut public: BTreeMap<[u8; 64], (SchemaId, &'a [u8])> = BTreeMap::new();
    let mut on_ledger: BTreeSet<[u8; 64]> = BTreeSet::new();
    for e in index.events() {
        on_ledger.insert(e.hash.0);
        if let Some(b) = e.bytes {
            public.insert(e.hash.0, (e.schema, b));
        }
    }
    for f in index.findings() {
        if let Some(h) = f.event_hash {
            on_ledger.insert(h.0);
        }
    }

    // Every station of the last state, then any other with sessions.
    let mut order: Vec<StationId<'a>> = genesis.stations().map(StationEntry::station_id).collect();
    for s in work.stations.values() {
        if !order
            .iter()
            .any(|o| o.as_bytes() == s.station_id.as_bytes())
        {
            order.push(s.station_id);
        }
    }
    let mut stations = Vec::with_capacity(order.len());
    for station_id in order {
        let st = work
            .stations
            .remove(station_id.as_bytes())
            .unwrap_or_else(|| StationWork::new(station_id));
        let closed = st.final_session.is_some();
        let mut findings = st.findings;
        let mut links_out = Vec::new();
        let mut station_holds = HoldSet::empty();
        // Links of the station, by link hash.
        let station_links: Vec<([u8; 64], LinkWork<'a>)> = work
            .per_link
            .iter()
            .filter(|(_, w)| w.info.station.as_bytes() == station_id.as_bytes())
            .map(|(k, w)| (*k, w.clone()))
            .collect();
        let mut received_by_link: BTreeMap<[u8; 64], Vec<(u64, u64)>> = BTreeMap::new();
        let windows: Vec<(u64, u64)> = st
            .sessions
            .iter()
            .map(|s| (s.start_slot, s.end_slot))
            .collect();
        for (key, lw) in &station_links {
            let (opening, close) = match lw.info.device {
                LinkDevice::Box(b) => (
                    opening_slot(index, b.as_bytes()),
                    close_slot(index, b.as_bytes()),
                ),
                LinkDevice::Unit(_) => (
                    genesis.station(station_id.as_bytes()).and_then(|s| {
                        s.boxes()
                            .filter_map(|b| opening_slot(index, b.as_bytes()))
                            .min()
                    }),
                    None,
                ),
            };
            let ctx = LinkContext {
                entry: manifest.frame_link(lw.info.class()),
                opening,
                close,
                public: &public,
                on_ledger: &on_ledger,
                closed,
            };
            let mut report = LinkReport {
                link_id_hash: Hash512(*key),
                device: lw.info.device,
                frames: 0,
                catchup_frames: 0,
                data_frames: 0,
                missing_slots: 0,
                slots: None,
                stream_end: lw.stream_end,
                objects: 0,
                checked_chunks: 0,
                opaque_chunks: 0,
                included: 0,
                findings: Vec::new(),
            };
            let (valid, short, gap) = judge_frames(lw, &ctx, &windows, &mut report);
            let received = judge_objects(lw, &ctx, &valid, &mut report);
            // Missing slots against every session's declaration (none when
            // the session does not list the link).
            for session in &st.sessions {
                let declared = st
                    .declared
                    .iter()
                    .find(|d| d.link == *key && d.session_index == session.session_index)
                    .map_or(0, |d| d.missing);
                let counted = if session.start_slot <= session.end_slot {
                    short.range(session.start_slot..=session.end_slot).count()
                } else {
                    0
                };
                if u64::try_from(counted).ok() != Some(u64::from(declared)) {
                    findings.push(SessionFinding {
                        seq: session.seq,
                        session_index: session.session_index,
                        link: Some(Hash512(*key)),
                        problem: SessionProblem::MissingSlots,
                    });
                }
            }
            if let (true, Some(last)) = (gap > 0, st.sessions.last()) {
                findings.push(SessionFinding {
                    seq: last.seq,
                    session_index: last.session_index,
                    link: Some(Hash512(*key)),
                    problem: SessionProblem::UndeclaredGap,
                });
            }
            let scope = match lw.info.device {
                LinkDevice::Box(b) => Scope::Box(b),
                LinkDevice::Unit(_) => Scope::Station(station_id),
            };
            for f in &report.findings {
                hold(genesis, &mut boxes, &mut ledger, scope, f.problem.hold());
            }
            received_by_link.insert(*key, received);
            links_out.push(report);
        }
        if !findings.is_empty() {
            station_holds = station_holds.with(HoldReason::UplinkSessionRefused);
            hold(
                genesis,
                &mut boxes,
                &mut ledger,
                Scope::Station(station_id),
                HoldReason::UplinkSessionRefused,
            );
        }
        // Inclusion, once the gateway closed.
        let mut outside = Vec::new();
        if closed {
            let device_events = index
                .station_events(station_id.as_bytes())
                .chain(
                    genesis
                        .station(station_id.as_bytes())
                        .into_iter()
                        .flat_map(StationEntry::boxes)
                        .flat_map(|b| index.box_events(b.as_bytes())),
                )
                .filter(|e| DEVICE_EVENTS.contains(&e.schema));
            for e in device_events {
                let mine = |info: &LinkInfo<'_>| match (e.scope, info.device) {
                    (Scope::Box(b), LinkDevice::Box(d)) => b.as_bytes() == d.as_bytes(),
                    (Scope::Station(_), LinkDevice::Unit(_)) => true,
                    (Scope::Box(_), LinkDevice::Unit(_))
                    | (Scope::Station(_), LinkDevice::Box(_))
                    | (Scope::Election, _) => false,
                };
                let found = station_links.iter().find(|(key, lw)| {
                    mine(&lw.info)
                        && lw.objects.iter().any(|l| {
                            l.object.object_hash == e.hash
                                && l.object.schema == e.schema
                                && l.object.end().is_some_and(|end| {
                                    received_by_link
                                        .get(key)
                                        .is_some_and(|r| covered(r, l.object.stream_offset, end))
                                })
                        })
                });
                if let Some((key, _)) = found {
                    if let Some(r) = links_out.iter_mut().find(|r| r.link_id_hash.0 == *key) {
                        r.included = r.included.saturating_add(1);
                    }
                } else {
                    outside.push(OutsideEvent {
                        seq: e.seq,
                        schema: e.schema,
                        hash: e.hash,
                        scope: e.scope,
                    });
                    hold(
                        genesis,
                        &mut boxes,
                        &mut ledger,
                        e.scope,
                        HoldReason::UplinkObjectOutside,
                    );
                }
            }
        }
        for r in &links_out {
            for f in &r.findings {
                station_holds = station_holds.with(f.problem.hold());
            }
        }
        if !outside.is_empty() {
            station_holds = station_holds.with(HoldReason::UplinkObjectOutside);
        }
        let pending_logs = work
            .logs
            .keys()
            .filter(|(s, _, _)| *s == station_id.as_bytes())
            .count();
        findings.sort_by_key(|f| f.seq.get());
        stations.push(StationUplink {
            station_id,
            gateway_id: genesis
                .station(station_id.as_bytes())
                .map(|s| s.gateway().gateway_id),
            sessions: st.sessions,
            final_session: st.final_session,
            findings,
            pending_logs,
            links: links_out,
            outside,
            holds: station_holds,
        });
    }
    for i in &incidents {
        let reason = if i.refused.is_some() {
            ledger = ledger.with(HoldReason::ConnectivityIncidentRefused);
            continue;
        } else {
            HoldReason::ConnectivityIncident
        };
        let scope = match (i.parts.box_id, i.parts.station_id) {
            (Some(b), _) => Scope::Box(b),
            (None, Some(s)) => Scope::Station(s),
            (None, None) => Scope::Election,
        };
        hold(genesis, &mut boxes, &mut ledger, scope, reason);
    }
    ConnectivityStage {
        manifest: manifest_problems,
        stations,
        incidents,
        boxes,
        ledger,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use ityv_encoding::{
        CARRY_LEDGER, CARRY_LINK, CARRY_SESSION, ElectionId, Ident, ManifestEntries,
    };

    use DeviceClass as C;
    use Direction as D;
    use ManifestProblem as P;
    use Medium as M;
    use Schedule as S;

    fn entry(
        class: DeviceClass,
        direction: Direction,
        medium: Medium,
        peer: Option<DeviceClass>,
        schedule: Schedule,
        frames: u16,
        carries: u32,
    ) -> ManifestEntry<'static> {
        ManifestEntry {
            device_class: class,
            port: Ident::new(b"port", 32).unwrap(),
            direction,
            medium,
            peer_class: peer,
            counterpart: Ident::new(b"declared", 64).unwrap(),
            schedule,
            frames_per_slot: frames,
            catchup_frames_per_slot: frames,
            carries,
        }
    }

    /// A connection that is no connection.
    fn none(class: DeviceClass) -> ManifestEntry<'static> {
        entry(class, D::None, M::None, None, S::Unused, 0, 0)
    }

    /// A frame link of the declared shape.
    fn link(class: DeviceClass, carries: u32) -> ManifestEntry<'static> {
        entry(
            class,
            D::OutOnly,
            M::OpticalTransmit,
            Some(C::Gateway),
            S::BoxOpenToClose,
            4,
            carries,
        )
    }

    #[test]
    fn a_tcb_device_neither_receives_nor_radiates() {
        for class in [
            C::InterpretationUnit,
            C::CommitmentUnit,
            C::CheckinUnit,
            C::ChamberModule,
        ] {
            assert!(entry_problems(&none(class)).is_empty());
            let out = entry(class, D::OutOnly, M::Optocoupler, None, S::Always, 0, 0);
            assert!(entry_problems(&out).is_empty());
            let inbound = entry(class, D::InOnly, M::Optocoupler, None, S::Always, 0, 0);
            assert_eq!(entry_problems(&inbound), [P::TcbInbound]);
            let both = entry(class, D::Both, M::Optocoupler, None, S::Always, 0, 0);
            assert_eq!(entry_problems(&both), [P::TcbInbound, P::TwoWay]);
            let radio = entry(class, D::OutOnly, M::Wireless, None, S::Always, 0, 0);
            assert_eq!(entry_problems(&radio), [P::TcbWireless]);
        }
        // Another class may receive, and radiate.
        let printer = entry(C::Printer, D::InOnly, M::Wireless, None, S::Always, 0, 0);
        assert!(entry_problems(&printer).is_empty());
    }

    #[test]
    fn two_way_ports_only_where_the_manifest_allows_them() {
        // The election-day terminal has no connection at all.
        assert!(entry_problems(&none(C::IdTerminalElectionDay)).is_empty());
        let out = entry(
            C::IdTerminalElectionDay,
            D::OutOnly,
            M::Optocoupler,
            None,
            S::Always,
            0,
            0,
        );
        assert_eq!(entry_problems(&out), [P::TerminalConnected]);
        let both = entry(
            C::IdTerminalElectionDay,
            D::Both,
            M::ElectionLine,
            None,
            S::EarlyVoting,
            0,
            0,
        );
        assert_eq!(entry_problems(&both), [P::TerminalConnected, P::TwoWay]);
        // The early-voting terminal: on the election line, during early
        // voting, to a party outside the system.
        let roll = entry(
            C::IdTerminalEarlyVoting,
            D::Both,
            M::ElectionLine,
            None,
            S::EarlyVoting,
            0,
            CARRY_ROLL,
        );
        assert!(entry_problems(&roll).is_empty());
        for wrong in [
            entry(
                C::IdTerminalEarlyVoting,
                D::Both,
                M::Ethernet,
                None,
                S::EarlyVoting,
                0,
                0,
            ),
            entry(
                C::IdTerminalEarlyVoting,
                D::Both,
                M::ElectionLine,
                None,
                S::Always,
                0,
                0,
            ),
            entry(
                C::IdTerminalEarlyVoting,
                D::Both,
                M::ElectionLine,
                Some(C::Gateway),
                S::EarlyVoting,
                0,
                0,
            ),
        ] {
            assert_eq!(entry_problems(&wrong), [P::TwoWay]);
        }
        for class in [
            C::Gateway,
            C::LedgerCollector,
            C::BoardPublisher,
            C::Witness,
            C::TrusteeReceiver,
        ] {
            let both = entry(
                class,
                D::Both,
                M::OpticalLine,
                None,
                S::Always,
                0,
                CARRY_LEDGER | CARRY_SESSION | CARRY_LINK,
            );
            assert!(entry_problems(&both).is_empty(), "{class:?}");
        }
        for class in [C::ReceiptReader, C::ImprintReader, C::Printer] {
            let both = entry(class, D::Both, M::Ethernet, None, S::Always, 0, 0);
            assert_eq!(entry_problems(&both), [P::TwoWay], "{class:?}");
        }
    }

    #[test]
    fn a_tap_only_sends_and_only_the_early_voting_terminal_looks_up_the_roll() {
        let tap = entry(
            C::Tap,
            D::OutOnly,
            M::Ethernet,
            None,
            S::BoxOpenToClose,
            0,
            CARRY_PUBLIC,
        );
        assert!(entry_problems(&tap).is_empty());
        assert_eq!(entry_problems(&none(C::Tap)), [P::TapNotSendOnly]);
        let both = entry(C::Tap, D::Both, M::Ethernet, None, S::BoxOpenToClose, 0, 0);
        assert_eq!(entry_problems(&both), [P::TwoWay, P::TapNotSendOnly]);
        let gateway = entry(
            C::Gateway,
            D::Both,
            M::OpticalLine,
            None,
            S::Always,
            0,
            CARRY_ROLL,
        );
        assert_eq!(entry_problems(&gateway), [P::RollLookup]);
    }

    #[test]
    fn the_scanner_carries_public_objects_and_sealed_packages() {
        assert_eq!(SCANNER_CARRIES, CARRY_PUBLIC | CARRY_SEALED);
    }

    #[test]
    fn a_frame_link_has_its_shape_and_carries_what_its_device_may_send() {
        assert!(entry_problems(&link(C::CommitmentUnit, CARRY_PUBLIC | CARRY_SEALED)).is_empty());
        assert!(entry_problems(&link(C::CheckinUnit, CARRY_PUBLIC)).is_empty());
        // Sealed packages from the check-in unit; check-in counters from
        // either; anything else.
        assert_eq!(
            entry_problems(&link(C::CheckinUnit, CARRY_PUBLIC | CARRY_SEALED)),
            [P::FrameLinkCarries]
        );
        for class in [C::CommitmentUnit, C::CheckinUnit] {
            assert_eq!(
                entry_problems(&link(class, CARRY_PUBLIC | CARRY_CHECKIN)),
                [P::FrameLinkCarries]
            );
            assert_eq!(
                entry_problems(&link(class, CARRY_PUBLIC | CARRY_LEDGER)),
                [P::FrameLinkCarries]
            );
        }
        // Each part of the shape.
        let mut e = link(C::CommitmentUnit, CARRY_PUBLIC);
        e.direction = D::None;
        assert_eq!(entry_problems(&e), [P::FrameLinkShape]);
        let mut e = link(C::CommitmentUnit, CARRY_PUBLIC);
        e.medium = M::Optocoupler;
        assert_eq!(entry_problems(&e), [P::FrameLinkShape]);
        let mut e = link(C::CommitmentUnit, CARRY_PUBLIC);
        e.peer_class = Some(C::Tap);
        assert_eq!(entry_problems(&e), [P::FrameLinkShape]);
        let mut e = link(C::CommitmentUnit, CARRY_PUBLIC);
        e.peer_class = None;
        assert_eq!(entry_problems(&e), [P::FrameLinkShape]);
        let mut e = link(C::CommitmentUnit, CARRY_PUBLIC);
        e.schedule = S::Always;
        assert_eq!(entry_problems(&e), [P::FrameLinkShape]);
        // No other class sends frames: the shape and carriage are not
        // judged for it.
        for class in DeviceClass::ALL
            .iter()
            .filter(|c| !matches!(c, C::CommitmentUnit | C::CheckinUnit))
        {
            let mut e = link(*class, CARRY_LEDGER);
            if class.is_tcb() || *class == C::IdTerminalElectionDay {
                e.direction = D::None;
            }
            let problems = entry_problems(&e);
            assert!(problems.contains(&P::FramesElsewhere), "{class:?}");
            assert!(!problems.contains(&P::FrameLinkShape), "{class:?}");
            assert!(!problems.contains(&P::FrameLinkCarries), "{class:?}");
        }
    }

    fn manifest(entries: &[ManifestEntry<'static>]) -> ConnectivityManifest<'static> {
        let mut entries = entries.to_vec();
        entries.sort_by(|a, b| a.key().cmp(&b.key()));
        let mut bytes = Vec::new();
        for e in &entries {
            let mut buf = vec![0u8; e.encoded_len()];
            e.encode(&mut ityv_encoding::Writer::new(&mut buf)).unwrap();
            bytes.extend_from_slice(&buf);
        }
        let bytes: &'static [u8] = alloc::boxed::Box::leak(bytes.into_boxed_slice());
        ConnectivityManifest::new(
            ElectionId::new(b"E").unwrap(),
            ManifestEntries::new(bytes).unwrap(),
        )
    }

    #[test]
    fn the_manifest_covers_every_class_with_one_frame_link_each() {
        let mut entries: Vec<ManifestEntry<'static>> =
            DeviceClass::ALL.iter().map(|c| none(*c)).collect();
        entries.push({
            let mut e = link(C::CommitmentUnit, CARRY_PUBLIC);
            e.port = Ident::new(b"uplink", 32).unwrap();
            e
        });
        entries.push({
            let mut e = link(C::CheckinUnit, CARRY_PUBLIC);
            e.port = Ident::new(b"uplink", 32).unwrap();
            e
        });
        let tap = entries
            .iter()
            .position(|e| e.device_class == C::Tap)
            .unwrap();
        entries[tap].direction = D::OutOnly;
        assert!(manifest_findings(&manifest(&entries)).is_empty());

        // A class left out; a second frame link; none.
        let mut fewer = entries.clone();
        fewer.retain(|e| e.device_class != C::Witness);
        assert_eq!(
            manifest_findings(&manifest(&fewer)),
            [ManifestFinding {
                class: C::Witness,
                port: None,
                problem: P::Uncovered
            }]
        );
        let mut more = entries.clone();
        more.push({
            let mut e = link(C::CheckinUnit, CARRY_PUBLIC);
            e.port = Ident::new(b"uplink-2", 32).unwrap();
            e
        });
        assert_eq!(
            manifest_findings(&manifest(&more)),
            [ManifestFinding {
                class: C::CheckinUnit,
                port: None,
                problem: P::FrameLinkCount
            }]
        );
        let mut without = entries;
        without.retain(|e| !(e.device_class == C::CommitmentUnit && e.sends_frames()));
        assert_eq!(
            manifest_findings(&manifest(&without)),
            [ManifestFinding {
                class: C::CommitmentUnit,
                port: None,
                problem: P::FrameLinkCount
            }]
        );
    }

    #[test]
    fn slots_no_window_covers() {
        assert_eq!(uncovered(&[], 5, 4), 0);
        assert_eq!(uncovered(&[], 5, 5), 1);
        assert_eq!(uncovered(&[], 5, 9), 5);
        assert_eq!(uncovered(&[(0, 20)], 5, 9), 0);
        assert_eq!(uncovered(&[(6, 7)], 5, 9), 3);
        assert_eq!(uncovered(&[(0, 5), (9, 12)], 5, 9), 3);
        assert_eq!(uncovered(&[(10, 12)], 5, 9), 5);
        assert_eq!(uncovered(&[(0, 4)], 5, 9), 5);
        assert_eq!(uncovered(&[], 0, u64::MAX), 0);
    }

    #[test]
    fn a_span_lies_wholly_in_the_received_ranges() {
        let ranges = [(0, 10), (20, 30)];
        assert!(covered(&ranges, 0, 10));
        assert!(covered(&ranges, 22, 25));
        assert!(covered(&ranges, 15, 15));
        assert!(covered(&[], 7, 3));
        assert!(!covered(&ranges, 5, 21));
        assert!(!covered(&ranges, 10, 11));
        assert!(!covered(&[], 0, 1));
    }

    #[test]
    fn a_device_sends_its_own_kinds() {
        assert_eq!(
            allowed(C::CommitmentUnit, SCHEMA_SHARE_PACKAGE),
            Some(CARRY_SEALED)
        );
        assert_eq!(
            allowed(C::CommitmentUnit, SCHEMA_CAST_RECORD),
            Some(CARRY_PUBLIC)
        );
        assert_eq!(
            allowed(C::CommitmentUnit, SCHEMA_PROGRESS_TICK),
            Some(CARRY_PUBLIC)
        );
        assert_eq!(allowed(C::CommitmentUnit, SCHEMA_PARTICIPATION_SET), None);
        assert_eq!(
            allowed(C::CheckinUnit, SCHEMA_PARTICIPATION_SET),
            Some(CARRY_PUBLIC)
        );
        assert_eq!(
            allowed(C::CheckinUnit, SCHEMA_WITNESSED_EVENT),
            Some(CARRY_PUBLIC)
        );
        assert_eq!(allowed(C::CheckinUnit, SCHEMA_SHARE_PACKAGE), None);
        assert_eq!(allowed(C::CheckinUnit, SchemaId::new(0x0009)), None);
        assert_eq!(allowed(C::Gateway, SCHEMA_PROGRESS_TICK), None);
        // Witnessed bytes not known are not judged; others must decode.
        assert!(witnessed_ok(None));
        assert!(!witnessed_ok(Some(b"not an object")));
    }
}
