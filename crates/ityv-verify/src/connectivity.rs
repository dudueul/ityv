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
//!    frame key signed the frame's header, which carries the hash of the
//!    frame's own object list; a normal frame's number is below the
//!    manifest's frames per slot and any other's below its catch-up count;
//!    a slot holds frames of one kind group; every frame lies in its
//!    session's window; no frame precedes the slot of the box's first
//!    opening (the station's first, for a check-in unit); no normal or
//!    catch-up frame of a box follows the slot after its first close's
//!    time bucket; no frame of a device a swap took out of service
//!    follows the swap's slot, none of one a swap brought in precedes it,
//!    and (once the gateway closed) none comes from one no swap brought
//!    in; a catch-up group comes only after a slot of the span fell short
//!    (the first slot of a link a swap brought in counts as one), after a
//!    whole catch-up group of full frames, or in the close slot; a close
//!    resend only from the close slot (or the slot after, when the close
//!    slot's frames went untaken) for the slots the stream before it needs
//!    at the catch-up shape; a witnessed resend only after the close, in
//!    no more slots than its bytes need at the catch-up shape and its
//!    slots that fell short. The close is the box's (the station's last,
//!    for a check-in unit), laid, or while it is not as the device's
//!    frames state it (its first close resend); while neither says, the
//!    kinds' slots wait.
//!    Nothing but resends follows a close resend and nothing but
//!    witnessed resends follows a witnessed resend; the
//!    payload root rebuilt from the published data leaves and the zero
//!    leaf is the signed one (the padding proof); and the stream starts at
//!    0 and each frame starts where the previous ended, or later only
//!    across positions (slot, number) no frame was taken in, by at most a
//!    full payload each. The positions run over the slots the device must
//!    send in: from the opening for a link that is its device's from the
//!    start or that an amendment laid before the opening brought in, from
//!    the slot of the swap that brought it in for one swapped in (for a
//!    box's frame key, the first `BoxUnitSwap` laid in a state that
//!    carries it), to the close for one in service at the
//!    end (to the slot before the swap that took it out, or its last
//!    frame), and over its witnessed resends' slots from the first of the
//!    session that took the first of them; a slot with frames taken has
//!    its group's count of positions, one without the catch-up count. A
//!    frame that breaks a rule is listed and holds the device's box, or
//!    every box of the station for a check-in unit
//!    (`UplinkFrameInvalid`).
//! 4. **Objects (VC-079).** Per link, over every frame whose signature
//!    verified: its list tiles its data (the first entry starts at or
//!    before the data and reaches into it, each next one where the one
//!    before ends, or at the frame's next 4,096-byte boundary around a
//!    share package with the bytes between zero fill, the last reaches the
//!    data's end; no list without data and no data without a list); two
//!    frames list the same object at one position, and what one frame
//!    carries out the next carries in; a kind the device may send and the
//!    manifest lets it carry (never a check-in counter or a contested
//!    check-in); a public ledger event of the link's own box or station;
//!    no hash the ledger names under another schema; a public object of
//!    the ledger with the ledger's length; each object listed no more
//!    often than its kind allows (a batch's objects twice in normal and
//!    catch-up frames, anything else once; once in the close resend; in
//!    witnessed resends once, and again after each listing there not
//!    received whole); cast records only in runs of their batch as the
//!    record stage takes it: after an attestation, that batch's records
//!    one after another in hash order from the first, to the last where
//!    nothing was lost; after bytes not received, one stretch of one
//!    batch's records; in each group (normal and catch-up frames, the
//!    close resend, each run of witnessed slots) batches first sent in
//!    batch-index order, in normal and catch-up frames a batch first
//!    received after one of a higher index only where each such one was
//!    first received in the slot before, after a loss there; the close
//!    resend the box's batches again in batch-index order from the first,
//!    skipping one or stopping early only where something was lost, and
//!    nothing else; a witnessed resend (once the gateway closed) only what
//!    normal, catch-up and close-resend frames did not bring whole;
//!    nothing before its time (a batch before the first slot of its time
//!    bucket, a tick before its slot or after a later tick in its group);
//!    a share package right after the record that names it (when that
//!    record is known; never first in the stream) and no longer than the
//!    election allows; and, once the
//!    gateway sent its final session, every listed object, received whole
//!    or not, a frame of the ledger names under its schema (a share
//!    package through an accepted record of its box). Every data chunk
//!    that holds no package byte is recomputed from the ledger's objects
//!    and the zero fill, in a frame whose list tiles its data. A break is
//!    listed and holds like a frame (`UplinkObjectInvalid`).
//! 5. **Inclusion (VC-080).** Once a station's gateway sent its final
//!    session, every accepted cast record, batch attestation, challenge
//!    opening, progress tick and participation set of the station must be
//!    listed by a received frame of its device's link (a box's scanner in
//!    any genesis state; the station's check-in units), received whole,
//!    and every chunk that holds bytes of it recomputed and matched.
//!    Otherwise it is listed and holds its box or station
//!    (`UplinkObjectOutside`).
//! 6. **Incidents (VC-083).** A `ConnectivityIncident` signed by two
//!    clerks and observers of two organisations, or by the committee and
//!    observers of two organisations, all registered on the roster
//!    (`ityv_state::check_incident_signers`), whose box (if any) is a box
//!    of its station, whose clerks are registered at that station and
//!    which names a station unless the committee signed it, holds the
//!    box, every box of the station, or the whole ledger
//!    (`ConnectivityIncident`); a commitment unit involved
//!    lists its boxes for a full comparison, with whether the audit stage
//!    compared every record. Otherwise it is refused and holds the ledger
//!    (`ConnectivityIncidentRefused`). The verifier never lifts the hold:
//!    the paper is the legal result of those boxes.
//!
//! No hold waits on an event not laid yet (a ledger read mid-day): until
//! the gateway sent its final session, a record the ledger has in no
//! batch, an object not on the ledger, a link no swap brought in, the
//! slots of a window before a link's start the ledger does not give yet
//! and after its last frame, a run's shape while a challenge opening may
//! be missing (bytes lost, or an opening listed and not laid), and the
//! station's opening and close while a box's opening is not laid are not
//! judged; the kinds' slots wait for the close as above.
//!
//! The stage is complete ([`ConnectivityStage::complete`]) when every
//! station of the genesis's last state has a final session taken: the
//! status ladder needs it for `SOURCE_COMPLETENESS_CHECKED` (ADR-0041
//! decision 10).
//!
//! What this stage does not prove: that the manifest is the hardware
//! (teardown samples and radio checks, VC-082); the sealed bytes and the
//! fill after them in a package's last chunk (taps, VC-081:
//! [`crate::compare_capture`]); how much of a frame a device fills; how
//! long after its time bucket or slot a device sent a batch or a tick
//! (only the earliest and the order are checked); where a run starts
//! again after a position no frame was taken in; the carrier's records
//! ([`crate::compare_carrier`]); anything about the paper.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;

use ityv_crypto::uplink::{
    chain_next, chain_start, chunk_leaf, link_id, objects_hash, payload_root,
};
use ityv_crypto::{
    Purpose, RecordPurpose, RecordSignature, RecordVerifyingKey, object_hash, verify_record,
};
use ityv_encoding::{
    BatchAttest, BoxClose, BoxId, BoxOpenedBody, BoxUnitSwapBody, CARRY_CHECKIN, CARRY_PUBLIC,
    CARRY_ROLL, CARRY_SEALED, CHUNK_LEN, CaptureMessage, CastRecord, CheckinUnitSwapBody,
    ConnectivityIncidentBody, ConnectivityIncidentParts, ConnectivityManifest, DeviceClass,
    Direction, Encode, EventRole, FRAME_HEADER_LEN, FrameEntry, FrameKind, FrameObjects, GatewayId,
    HEADER_LEN, Hash512, LogLeaves, LoggedFrame, MAX_PAYLOAD_LEN, ManifestEntry, Medium,
    PURPOSE_UPLINK_CAPTURE, PURPOSE_UPLINK_SESSION, ProgressBody, ProgressTick, RosterRole,
    SCHEMA_BATCH_ATTEST, SCHEMA_BOX_CLOSE, SCHEMA_BOX_OPENED_BODY, SCHEMA_BOX_UNIT_SWAP_BODY,
    SCHEMA_CAST_RECORD, SCHEMA_CHALLENGE_OPENING, SCHEMA_CHECKIN_UNIT_SWAP_BODY,
    SCHEMA_CONNECTIVITY_INCIDENT_BODY, SCHEMA_OBSERVER_COUNT_ATTEST_BODY, SCHEMA_PARTICIPATION_SET,
    SCHEMA_PROGRESS_TICK, SCHEMA_SHARE_PACKAGE, SCHEMA_UPLINK_FRAME_HEADER,
    SCHEMA_UPLINK_FRAME_LOG, SCHEMA_UPLINK_SESSION, SCHEMA_VERSION_1, SCHEMA_WITNESSED_EVENT,
    Schedule, SchemaId, Seq, StationEntry, StationId, StreamObject, UnitId, UplinkFrameHeader,
    UplinkFrameLog, UplinkSession, WitnessedEvent, decode_object, encode_object, max_package_len,
    schema_version,
};
use ityv_state::{HoldReason, HoldSet, RecordStatus, RosterEntry, Signed, check_incident_signers};

use crate::audit::AuditStage;
use crate::genesis::VerifiedGenesis;
use crate::index::{LedgerIndex, Scope};
use crate::progress::bucket_slots;
use crate::records::RecordStage;
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
    /// A frame of a device a swap took out of service, after the swap's
    /// slot.
    AfterSwap,
    /// A frame of a device swapped in, before the slot of the swap that
    /// took it into service, or of one no swap took into service (judged
    /// once the gateway closed).
    BeforeSwap,
    /// A frame of a kind its slot may not hold: a catch-up frame outside
    /// the close slot that neither a slot that fell short right before it
    /// nor a whole catch-up group of full frames right before it explains;
    /// a close resend before the close slot, past the slots the stream
    /// before it needs at the catch-up shape, or starting after a close
    /// slot taken whole; a witnessed resend before the close slot is past
    /// or in more slots than its bytes need and its slots that fell short;
    /// a normal or catch-up frame after a close resend, or another kind
    /// after a witnessed resend.
    KindOrder,
    /// The stream offset goes back, or skips ahead where no position
    /// between the frame and the one before it went untaken, or by more
    /// than a full payload per untaken position.
    Offset,
    /// The payload root the data leaves and zero fill give is not the
    /// signed one: a chunk after the data is not zero.
    Fill,
    /// A chunk whose bytes are public ledger objects gives another leaf.
    Chunk,
    /// An object of a kind the device may not send or the manifest does
    /// not let it carry.
    Kind,
    /// Two frames list different objects at one stream position: the
    /// object a frame carries out is not the one the next carries in, or
    /// one frame's object overlaps another's.
    Overlap,
    /// A frame's object list does not tile its data: a data byte no entry
    /// covers (other than the zero fill around a share package), an entry
    /// outside the data, or a frame with data that lists nothing.
    NotObject,
    /// A share package that does not start on a chunk boundary of its
    /// frame, or an object after a package that does not.
    Alignment,
    /// A ledger event of another box or station than the link's device.
    Foreign,
    /// An entry whose hash the ledger names under another schema (a share
    /// package's hash under any schema but a package's, or a package
    /// listed under the hash of a ledger event).
    Schema,
    /// An object listed more often than its kind allows: a batch's
    /// attestation, record or package more than twice in normal and
    /// catch-up frames, any other object more than once; anything more
    /// than once in the close resend; in witnessed resends, more than once
    /// plus once for each earlier listing there not received whole.
    Repeat,
    /// An object sent before its time or out of its order: a batch's
    /// attestation or record in a slot before the first its time bucket
    /// overlaps, a progress tick before its own slot or, within one group
    /// (normal and catch-up frames, the close resend, a run of witnessed
    /// slots), after a tick of a later slot.
    Time,
    /// A resend of what the protocol does not resend: in the close resend
    /// anything but the box's batches, a batch out of their order or
    /// skipped where nothing was lost, a close resend that stops before
    /// the last batch where nothing was lost after it; in a witnessed
    /// resend (once the gateway closed) a batch received whole before, or
    /// any other object received whole before.
    Resend,
    /// A public object whose length is not the ledger's.
    Length,
    /// A cast record that is not where its batch puts it: a run after a
    /// batch attestation holds that batch's records (as the record stage
    /// takes them) one after another in hash order from the first, and
    /// ends, where nothing was lost, at the last; after bytes not
    /// received, a run is one stretch of one batch's records; a record no
    /// batch has (other than a challenged one, judged once the gateway
    /// closed) or outside every run; within a group, a batch first sent
    /// after one of a higher index (in normal and catch-up frames, unless
    /// each such one was first sent in the slot before after a loss in
    /// that slot). Until the gateway closed, while a challenge opening may
    /// be missing (bytes lost, or an opening listed and not laid), a run's
    /// skipped members, early end and records outside every run wait.
    Batch,
    /// A share package not right after the record that names it (or the
    /// first object of the stream), or longer than the election allows.
    Package,
    /// An object a received frame lists that no ledger frame names, once
    /// the gateway closed (a share package: no accepted record of the box
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
            | Self::AfterSwap
            | Self::BeforeSwap
            | Self::KindOrder
            | Self::Offset
            | Self::Fill
            | Self::Chunk => HoldReason::UplinkFrameInvalid,
            Self::Kind
            | Self::Overlap
            | Self::NotObject
            | Self::Alignment
            | Self::Foreign
            | Self::Schema
            | Self::Repeat
            | Self::Time
            | Self::Resend
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
    /// on the ledger): the taps' to check.
    pub opaque_chunks: u64,
    /// Device events of the ledger received whole, every chunk of them
    /// recomputed.
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
    /// A clerk is not registered at the station the incident names, or an
    /// incident of the whole election is not signed by the committee.
    Scope,
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
    /// Whether the link is its device's in the last state: the box's frame
    /// key, or the station's in-service unit. It must send to the close.
    current: bool,
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
/// that has it; a frame key names one device in every state, ADR-0041
/// decision 2), with whether it is its device's in the last state.
fn links<'a>(genesis: &VerifiedGenesis<'a>) -> BTreeMap<[u8; 64], LinkInfo<'a>> {
    let mut out: BTreeMap<[u8; 64], LinkInfo<'a>> = BTreeMap::new();
    let last = genesis.state_count().saturating_sub(1);
    for state in 0..genesis.state_count() {
        for b in genesis.boxes_at(state) {
            let info = out.entry(link_id(b.frame_key).0).or_insert(LinkInfo {
                device: LinkDevice::Box(b.box_id),
                station: b.station_id,
                frame_key: b.frame_key,
                current: false,
            });
            info.current |= state == last;
        }
        for s in genesis.stations_at(state) {
            for (unit, in_service) in [(s.primary(), true), (s.spare(), false)] {
                let info = out.entry(link_id(unit.frame_key).0).or_insert(LinkInfo {
                    device: LinkDevice::Unit(unit.unit_id),
                    station: s.station_id(),
                    frame_key: unit.frame_key,
                    current: false,
                });
                info.current |= state == last && in_service;
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The stage's work.

/// One frame taken from a log, with its leaves and its object list.
#[derive(Debug, Clone, Copy)]
struct Frame<'a> {
    log: Seq,
    window: (u64, u64),
    entry: FrameEntry<'a>,
    leaves: LogLeaves<'a>,
    objects: FrameObjects<'a>,
}

/// What one link accumulates over the sessions.
#[derive(Debug, Clone)]
struct LinkWork<'a> {
    info: LinkInfo<'a>,
    head: Hash512,
    stream_end: u64,
    frames: Vec<Frame<'a>>,
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
    /// The missing slots each session declares, by link and session
    /// number; `None` where the session's record of the link was refused
    /// (its frames are not taken, so its count is not compared).
    declared: BTreeMap<([u8; 64], u32), Option<u32>>,
}

impl<'a> StationWork<'a> {
    const fn new(station_id: StationId<'a>) -> Self {
        Self {
            station_id,
            last: None,
            final_session: None,
            sessions: Vec::new(),
            findings: Vec::new(),
            declared: BTreeMap::new(),
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

/// The logs of `station`'s session `index`, by key.
fn session_keys<'a>(
    logs: &BTreeMap<LogKey<'a>, (Seq, UplinkFrameLog<'a>)>,
    station: &'a [u8],
    index: u32,
) -> Vec<LogKey<'a>> {
    logs.range((station, index, [0u8; 64])..=(station, index, [0xFF; 64]))
        .map(|(k, _)| *k)
        .collect()
}

/// Every genesis state's roster, proved once, with each signer's entries.
struct Rosters<'a> {
    states: Vec<Vec<RosterEntry<'a>>>,
    by_signer: Vec<BTreeMap<&'a [u8], Vec<usize>>>,
}

impl<'a> Rosters<'a> {
    fn new(genesis: &VerifiedGenesis<'a>) -> Self {
        let states: Vec<Vec<RosterEntry<'a>>> = (0..genesis.state_count())
            .map(|k| genesis.roster_at(k))
            .collect();
        let by_signer = states
            .iter()
            .map(|roster| {
                let mut map: BTreeMap<&'a [u8], Vec<usize>> = BTreeMap::new();
                for (i, r) in roster.iter().enumerate() {
                    map.entry(r.get().signer_id.as_bytes()).or_default().push(i);
                }
                map
            })
            .collect();
        Self { states, by_signer }
    }

    /// The entries of signer `id` in state `state`.
    fn signer<'s>(&'s self, state: usize, id: &[u8]) -> impl Iterator<Item = &'s RosterEntry<'a>> {
        let roster = self.states.get(state);
        self.by_signer
            .get(state)
            .and_then(|m| m.get(id))
            .into_iter()
            .flatten()
            .filter_map(move |i| roster.and_then(|r| r.get(*i)))
    }
}

struct Work<'g, 'a> {
    genesis: &'g VerifiedGenesis<'a>,
    index: &'g LedgerIndex<'a>,
    rosters: &'g Rosters<'a>,
    links: BTreeMap<[u8; 64], LinkInfo<'a>>,
    per_link: BTreeMap<[u8; 64], LinkWork<'a>>,
    stations: BTreeMap<&'a [u8], StationWork<'a>>,
    logs: BTreeMap<LogKey<'a>, (Seq, UplinkFrameLog<'a>)>,
}

/// The length of an encoded frame header object.
const HEADER_OBJECT_LEN: usize = HEADER_LEN + FRAME_HEADER_LEN;

/// The encoded header object of `header`, and its object hash.
fn header_hash(
    header: &ityv_encoding::UplinkFrameHeaderParts,
) -> Option<(Hash512, [u8; HEADER_OBJECT_LEN])> {
    let h = UplinkFrameHeader::new(header).ok()?;
    let mut buf = [0u8; HEADER_OBJECT_LEN];
    let len = encode_object(SCHEMA_UPLINK_FRAME_HEADER, SCHEMA_VERSION_1, &h, &mut buf).ok()?;
    let bytes = buf.get(..len)?;
    Some((object_hash(bytes), buf))
}

/// The header of frame `entry` listing `objects` on link `link`.
fn frame_header(
    link: Hash512,
    entry: &FrameEntry<'_>,
    objects: &FrameObjects<'_>,
) -> ityv_encoding::UplinkFrameHeaderParts {
    entry.header(link, objects_hash(objects.as_bytes()))
}

/// The head after `frames` from `head`, or `None` if a header cannot be
/// built.
fn chain_over<'a>(
    head: Hash512,
    link: &Hash512,
    frames: impl Iterator<Item = LoggedFrame<'a>>,
) -> Option<Hash512> {
    let mut h = head;
    for f in frames {
        let (hash, _) = header_hash(&frame_header(*link, &f.entry, &f.objects))?;
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
                self.rosters.signer(k, o.observer_id.as_bytes()).any(|r| {
                    let r = r.get();
                    r.role == RosterRole::Observer
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
        let keys = session_keys(&self.logs, station.as_bytes(), index);
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
            });
            declared.push(((link.0, index), Some(l.missing_slots)));
            let frames: Vec<LoggedFrame<'a>> = log
                .map(|(_, lg)| lg.frames_with().collect())
                .unwrap_or_default();
            let head = chain_over(work.head, &link, frames.iter().copied());
            if head != Some(l.chain_head) {
                findings.push((Some(link), SessionProblem::ChainHead));
                if let Some(d) = declared.last_mut() {
                    d.1 = None;
                }
                continue;
            }
            let normal = u64::try_from(
                frames
                    .iter()
                    .filter(|f| f.entry.kind == FrameKind::Normal)
                    .count(),
            )
            .unwrap_or(u64::MAX);
            let other = u64::try_from(frames.len())
                .unwrap_or(u64::MAX)
                .saturating_sub(normal);
            let end = frames.last().map_or(work.stream_end, |f| {
                f.entry
                    .stream_offset
                    .saturating_add(u64::from(f.entry.payload_len))
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
            if let Some((log_seq, _)) = log {
                work.frames.extend(frames.iter().map(|f| Frame {
                    log: log_seq,
                    window,
                    entry: f.entry,
                    leaves: f.leaves,
                    objects: f.objects,
                }));
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

/// Where a link's span ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpanEnd {
    /// At this slot, or at its last frame if later: the box's close slot
    /// (the station's last, for a check-in unit), or while it is open the
    /// last slot of the station's last session.
    To(Option<u64>),
    /// A swap took the device out of service at this slot: it sends to
    /// the slot before, and no frame of it may follow the swap's slot.
    Swap(u64),
    /// At its last frame.
    LastFrame,
}

/// A batch as the record stage took it (ADR-0041 decision 6).
#[derive(Debug, Clone, Default)]
struct BatchRun {
    /// Its member records' object hashes, ascending.
    records: Vec<[u8; 64]>,
    /// Its batch index.
    index: u32,
    /// The first slot its time bucket overlaps: none of its objects goes
    /// out before.
    first_slot: Option<u64>,
}

/// A box's batches as the record stage took them.
#[derive(Debug, Clone, Default)]
struct Batches {
    /// Each batch, by the object hash of its attestation.
    by_hash: BTreeMap<[u8; 64], BatchRun>,
    /// The batch of each member record, by the record's object hash.
    of_record: BTreeMap<[u8; 64], [u8; 64]>,
    /// The share package each member record names, and the record of each
    /// such package.
    package_of: BTreeMap<[u8; 64], [u8; 64]>,
    record_of: BTreeMap<[u8; 64], [u8; 64]>,
    /// The records the device opened for a challenge: no batch has them.
    challenged: BTreeSet<[u8; 64]>,
}

impl Batches {
    /// The batch an object belongs to, by its attestation's hash: an
    /// attestation's own, a record's, a package's through its record.
    fn of(&self, schema: SchemaId, hash: &[u8; 64]) -> Option<(&[u8; 64], &BatchRun)> {
        let b = if schema == SCHEMA_BATCH_ATTEST {
            Some(hash)
        } else if schema == SCHEMA_CAST_RECORD {
            self.of_record.get(hash)
        } else if schema == SCHEMA_SHARE_PACKAGE {
            self.record_of.get(hash).and_then(|r| self.of_record.get(r))
        } else {
            None
        }?;
        self.by_hash.get_key_value(b)
    }

    /// Whether `schema` is a batch's: an attestation, a record or a share
    /// package.
    fn batch_object(schema: SchemaId) -> bool {
        [
            SCHEMA_BATCH_ATTEST,
            SCHEMA_CAST_RECORD,
            SCHEMA_SHARE_PACKAGE,
        ]
        .contains(&schema)
    }
}

/// The order of batches and ticks within one group of a link's listings
/// (normal and catch-up frames; the close resend; one run of witnessed
/// slots).
#[derive(Debug, Clone, Default)]
struct Order {
    /// Each batch first sent, by index: the slot, and whether a loss in
    /// that slot came before it.
    first: BTreeMap<u32, (u64, bool)>,
    /// The slot of the latest tick sent.
    latest_tick: Option<u64>,
}

/// What comes before a stream's first object: no record (a share package
/// may not open the stream).
const STREAM_START: SchemaId = SCHEMA_UPLINK_FRAME_HEADER;

/// What a link's judgement needs from the rest of the ledger.
struct LinkContext<'c, 'a> {
    entry: Option<ManifestEntry<'a>>,
    /// The first slot of the box's first opening (the station's first,
    /// for a check-in unit).
    opening: Option<u64>,
    /// The box's close slot: no normal or catch-up frame after it (none
    /// for a check-in unit).
    close: Option<u64>,
    /// The slot the device closes in, where it uses its catch-up shape and
    /// after which a witnessed resend may come: the box's close slot (the
    /// station's last, for a check-in unit); while the close is not laid,
    /// the slot the device's own frames close in.
    closing: Option<u64>,
    /// The first slot the device must send in: the box's opening (the
    /// station's first) for a link in service from the opening, the slot
    /// of the swap that took it into service for one swapped in.
    start: Option<u64>,
    /// Whether `start` is the ledger's (its opening or swap is laid, or
    /// the gateway closed); otherwise the span starts at the first frame
    /// and the first frame's offset is not judged yet.
    start_known: bool,
    /// The slot of the swap that took the link into service: no frame of
    /// it may come before (`BeforeSwap`).
    swapped_in: Option<u64>,
    /// A link swapped in by no swap on the ledger once the gateway closed:
    /// every frame of it is `BeforeSwap`.
    never_brought: bool,
    /// Where the slots it must send in end.
    end: SpanEnd,
    /// Public ledger objects by hash: schema and bytes.
    public: &'c BTreeMap<[u8; 64], (SchemaId, &'a [u8])>,
    /// Every event a ledger frame names: hash and schema.
    on_ledger: &'c BTreeSet<([u8; 64], u32)>,
    /// Whom each accepted public event concerns, by hash.
    scopes: &'c BTreeMap<[u8; 64], Scope<'a>>,
    /// The share packages the box's accepted cast records name.
    packages: &'c BTreeSet<[u8; 64]>,
    /// The box's batches.
    batches: &'c Batches,
    /// The longest share package the election allows.
    package_len: u64,
    closed: bool,
}

impl LinkContext<'_, '_> {
    /// Whether a ledger frame names `hash` under a schema other than
    /// `schema` (a share package the box's records name counts as one).
    fn other_schema(&self, hash: &[u8; 64], schema: SchemaId) -> bool {
        let package = self.packages.contains(hash) && schema != SCHEMA_SHARE_PACKAGE;
        package
            || self
                .on_ledger
                .range((*hash, 0)..=(*hash, u32::MAX))
                .any(|(_, s)| *s != schema.get())
    }
}

/// The received ranges of a link: merged `[start, end)` of every frame
/// given (a frame without data gives an empty range, which covers
/// nothing).
fn received_ranges(frames: &[&Frame<'_>]) -> Vec<(u64, u64)> {
    let mut ranges: Vec<(u64, u64)> = frames
        .iter()
        .map(|f| {
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
        acc.saturating_add(overlap(Some((*start, *end)), a, b))
    });
    span.saturating_sub(covered)
}

/// The slots of `[a, b]` in `range` (inclusive), if any.
fn overlap(range: Option<(u64, u64)>, a: u64, b: u64) -> u64 {
    range.map_or(0, |(lo, hi)| {
        let lo = a.max(lo);
        let hi = b.min(hi);
        hi.checked_sub(lo)
            .and_then(|d| d.checked_add(1))
            .unwrap_or(0)
    })
}

/// Whether `[start, end)` lies wholly in `ranges` (sorted, merged).
fn covered(ranges: &[(u64, u64)], start: u64, end: u64) -> bool {
    if start >= end {
        return true;
    }
    let after = ranges.partition_point(|(a, _)| *a <= start);
    after
        .checked_sub(1)
        .and_then(|i| ranges.get(i))
        .is_some_and(|(_, b)| end <= *b)
}

/// How a frame's object list tiles its data (ADR-0041 decisions 3 and 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tiling {
    /// The first rule broken, with the stream offset where: data no entry
    /// covers or an entry outside the data ([`LinkProblem::NotObject`]),
    /// or a share package off its chunk boundary
    /// ([`LinkProblem::Alignment`]).
    pub(crate) problem: Option<(LinkProblem, u64)>,
    /// The fill around share packages, as stream ranges: bytes that are
    /// no object and must be zero.
    pub(crate) fill: Vec<(u64, u64)>,
}

/// Where an object right after `previous` starts in a frame whose data
/// start at `start`: right at its end, or at the frame's next chunk
/// boundary when either is a share package.
fn next_start(start: u64, previous_end: u64, aligned: bool) -> Option<u64> {
    if !aligned {
        return Some(previous_end);
    }
    let into = previous_end.checked_sub(start)?;
    let chunk = u64::try_from(CHUNK_LEN).ok()?;
    let up = into.div_ceil(chunk).checked_mul(chunk)?;
    start.checked_add(up)
}

/// The tiling of a frame whose `payload_len` data bytes start at
/// `stream_offset` by its list `objects`: the first entry starts at or
/// before the data and reaches into them; each next one starts where the
/// one before ends, or at the frame's next 4,096-byte boundary when either
/// is a share package (the bytes between are fill); the last reaches the
/// data's end or past it. A frame without data lists nothing.
pub(crate) fn tiling(stream_offset: u64, payload_len: u32, objects: &FrameObjects<'_>) -> Tiling {
    let mut out = Tiling {
        problem: None,
        fill: Vec::new(),
    };
    let start = stream_offset;
    let Some(end) = start.checked_add(u64::from(payload_len)) else {
        out.problem = Some((LinkProblem::NotObject, start));
        return out;
    };
    let mut list = objects.iter();
    let Some(first) = list.next() else {
        if payload_len > 0 {
            out.problem = Some((LinkProblem::NotObject, start));
        }
        return out;
    };
    let reaches = |o: &StreamObject| o.stream_offset < end && o.end().is_some_and(|e| e > start);
    if first.stream_offset > start || !reaches(&first) {
        out.problem = Some((LinkProblem::NotObject, start.min(first.stream_offset)));
        return out;
    }
    let mut previous = first;
    for o in list {
        let aligned = previous.schema == SCHEMA_SHARE_PACKAGE || o.schema == SCHEMA_SHARE_PACKAGE;
        let previous_end = previous.end().unwrap_or(u64::MAX);
        let expected = next_start(start, previous_end, aligned);
        if Some(o.stream_offset) != expected {
            let problem = if aligned {
                LinkProblem::Alignment
            } else {
                LinkProblem::NotObject
            };
            out.problem = Some((problem, o.stream_offset));
            return out;
        }
        if !reaches(&o) {
            out.problem = Some((LinkProblem::NotObject, o.stream_offset));
            return out;
        }
        if o.stream_offset > previous_end {
            out.fill.push((previous_end, o.stream_offset));
        }
        previous = o;
    }
    if previous.end().is_some_and(|e| e < end) {
        out.problem = Some((LinkProblem::NotObject, previous.end().unwrap_or(u64::MAX)));
    }
    out
}

/// The leaf of the chunk of stream bytes `[lo, hi)` recomputed from the
/// public objects of `objects` that overlap it (zeros between them), or
/// `None` if a byte belongs to a share package or an object whose bytes
/// the ledger does not show.
fn public_leaf(
    lo: u64,
    hi: u64,
    objects: &[StreamObject],
    public: &BTreeMap<[u8; 64], (SchemaId, &[u8])>,
) -> Option<Hash512> {
    let mut chunk = [0u8; CHUNK_LEN];
    for o in objects {
        let o_end = o.end()?;
        if o_end <= lo || o.stream_offset >= hi {
            continue;
        }
        if o.schema == SCHEMA_SHARE_PACKAGE {
            return None;
        }
        let (schema, bytes) = public.get(&o.object_hash.0)?;
        if *schema != o.schema || u64::try_from(bytes.len()).ok() != Some(u64::from(o.len)) {
            return None;
        }
        let from = lo.max(o.stream_offset);
        let to = hi.min(o_end);
        let src = bytes.get(
            usize::try_from(from.checked_sub(o.stream_offset)?).ok()?
                ..usize::try_from(to.checked_sub(o.stream_offset)?).ok()?,
        )?;
        let at = usize::try_from(from.checked_sub(lo)?).ok()?;
        chunk
            .get_mut(at..at.checked_add(src.len())?)?
            .copy_from_slice(src);
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

/// Whether an event that concerns `scope` is the link's device's: its
/// box for a scanner, its station for a check-in unit.
fn mine(scope: Scope<'_>, info: &LinkInfo<'_>) -> bool {
    match (scope, info.device) {
        (Scope::Box(b), LinkDevice::Box(d)) => b.as_bytes() == d.as_bytes(),
        (Scope::Station(s), LinkDevice::Unit(_)) => s.as_bytes() == info.station.as_bytes(),
        (Scope::Box(_), LinkDevice::Unit(_))
        | (Scope::Station(_), LinkDevice::Box(_))
        | (Scope::Election, _) => false,
    }
}

/// The slots of a link's frames: per slot, whether it is a catch-up
/// group, whether a witnessed one, and its numbers.
type SlotGroups = BTreeMap<u64, (bool, bool, BTreeSet<u16>)>;

/// Where a link must send frames: its shape, the slots from its opening
/// to its close, and the slots of its witnessed resends.
#[derive(Debug, Clone, Copy)]
struct Shape {
    normal: u16,
    catchup: u16,
    span: Option<(u64, u64)>,
    witnessed: Option<(u64, u64)>,
}

impl Shape {
    /// The slots of `[a, b]` the device must send in.
    fn slots(&self, a: u64, b: u64) -> u64 {
        if a > b {
            return 0;
        }
        // Where the two meet (an empty meeting overlaps nothing).
        let both = self
            .span
            .zip(self.witnessed)
            .map(|((p, q), (r, s))| (p.max(r), q.min(s)));
        overlap(self.span, a, b)
            .saturating_add(overlap(self.witnessed, a, b))
            .saturating_sub(overlap(both, a, b))
    }

    /// The numbers of slot `slot` the device must send: its group's count
    /// when frames of it were taken, at most the catch-up count when none
    /// was; none outside the slots it must send in.
    fn count(&self, groups: &SlotGroups, slot: u64) -> u64 {
        if self.slots(slot, slot) == 0 {
            return 0;
        }
        let n = match groups.get(&slot) {
            Some((false, _, _)) => self.normal,
            Some((true, _, _)) | None => self.catchup,
        };
        u64::from(n)
    }

    /// The positions strictly between frame `previous` (or the start) and
    /// frame `current`, (slot, number), that no frame took: the slots
    /// between them took none.
    fn absent(
        &self,
        groups: &SlotGroups,
        previous: Option<(u64, u16)>,
        current: (u64, u16),
    ) -> u64 {
        let (s2, i2) = current;
        let last = self.count(groups, s2).min(u64::from(i2));
        let catchup = u64::from(self.catchup);
        match previous {
            None => {
                let lo = [self.span, self.witnessed]
                    .iter()
                    .flatten()
                    .map(|(a, _)| *a)
                    .min()
                    .unwrap_or(s2);
                let before = s2
                    .checked_sub(1)
                    .map_or(0, |b| self.slots(lo, b))
                    .saturating_mul(catchup);
                before.saturating_add(last)
            }
            Some((s1, i1)) => match s1.cmp(&s2) {
                Ordering::Equal => last.saturating_sub(u64::from(i1).saturating_add(1)),
                Ordering::Less => {
                    let first = self
                        .count(groups, s1)
                        .saturating_sub(u64::from(i1).saturating_add(1));
                    let between = match (s1.checked_add(1), s2.checked_sub(1)) {
                        (Some(a), Some(b)) => self.slots(a, b).saturating_mul(catchup),
                        _ => 0,
                    };
                    first.saturating_add(between).saturating_add(last)
                }
                Ordering::Greater => 0,
            },
        }
    }
}

/// What the frame rules of one link give the object rules and the
/// session checks.
struct FrameJudgement {
    /// Whether each frame's signature verified.
    valid: Vec<bool>,
    /// The slots it must send in that a window covers and that fell short.
    short: BTreeSet<u64>,
    /// The slots it must send in that no window covers.
    gap: u64,
    /// The run of consecutive witnessed slots each witnessed slot is in,
    /// counted from 0.
    witnessed_run: BTreeMap<u64, u32>,
    /// Whether every position after its last frame was taken: its stream
    /// ends where the device's did.
    whole_end: bool,
}

/// Whether a slot's frames hold every number of their group's shape.
fn full(group: Option<&(bool, bool, BTreeSet<u16>)>, normal: u16, catchup: u16) -> bool {
    group.is_some_and(|(cu, _, indices)| {
        let want = if *cu { catchup } else { normal };
        indices.range(..want).count() == usize::from(want)
    })
}

/// Merges two inclusive slot ranges that overlap or touch into one.
fn ranges_of(a: Option<(u64, u64)>, b: Option<(u64, u64)>) -> Vec<(u64, u64)> {
    let mut v: Vec<(u64, u64)> = [a, b].into_iter().flatten().collect();
    v.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (lo, hi) in v {
        match out.last_mut() {
            Some(last) if lo <= last.1.saturating_add(1) => last.1 = last.1.max(hi),
            _ => out.push((lo, hi)),
        }
    }
    out
}

/// What a link's frames hold, slot by slot: the kind group and numbers
/// ([`SlotGroups`]), and whether every frame of the slot is a catch-up
/// frame carrying a full payload (a backlog may remain after it).
struct SlotFacts {
    groups: SlotGroups,
    /// Per slot: every frame a catch-up frame, and every one full.
    backlog: BTreeMap<u64, (bool, bool)>,
}

impl SlotFacts {
    fn of<'f>(frames: impl Iterator<Item = &'f Frame<'f>>) -> Self {
        let mut groups: SlotGroups = BTreeMap::new();
        let mut backlog: BTreeMap<u64, (bool, bool)> = BTreeMap::new();
        let most = u32::try_from(MAX_PAYLOAD_LEN).unwrap_or(u32::MAX);
        for f in frames {
            let e = &f.entry;
            groups
                .entry(e.slot)
                .or_insert_with(|| {
                    (
                        e.kind.uses_catchup(),
                        e.kind == FrameKind::WitnessedResend,
                        BTreeSet::new(),
                    )
                })
                .2
                .insert(e.index);
            let b = backlog.entry(e.slot).or_insert((true, true));
            b.0 &= e.kind == FrameKind::CatchUp;
            b.1 &= e.payload_len == most;
        }
        Self { groups, backlog }
    }

    /// Whether a catch-up group in `slot` is explained: the slot before it,
    /// one the link must send in from `start`, fell short (a position
    /// went untaken), or was a catch-up group taken whole with every frame
    /// full (a backlog may remain).
    fn explained(&self, slot: u64, start: Option<u64>, normal: u16, catchup: u16) -> bool {
        let Some(p) = slot.checked_sub(1) else {
            return false;
        };
        let group = self.groups.get(&p);
        let whole = full(group, normal, catchup);
        let short = start.is_some_and(|a| p >= a) && !whole;
        let continued = whole && self.backlog.get(&p).is_some_and(|(k, f)| *k && *f);
        short || continued
    }
}

/// The slot a device's own frames say it closed in: its first close
/// resend (PROTOCOL.md §5.8 item 3). A catch-up group says nothing until
/// the close is known: it may follow a slot that fell short.
fn close_statement(frames: &[Frame<'_>]) -> Option<u64> {
    frames
        .iter()
        .find(|f| f.entry.kind == FrameKind::CloseResend)
        .map(|f| f.entry.slot)
}

/// The frame rules of one link (VC-078): the per-frame findings, whether
/// each frame's signature verified, the slots that fell short, and the
/// slots of the span no window covers.
#[allow(clippy::too_many_lines)] // One rule after another, as the module docs list them.
fn judge_frames(
    work: &LinkWork<'_>,
    ctx: &LinkContext<'_, '_>,
    windows: &[(u64, u64)],
    report: &mut LinkReport<'_>,
) -> FrameJudgement {
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
    // Signatures, numbers, windows, opening, close and swaps, padding
    // proofs.
    let mut reached = 0u8;
    let mut shapes: BTreeMap<u64, u8> = BTreeMap::new();
    // Whether each frame kept the order of kinds (the kinds' slots are
    // judged below, once the span is known).
    let mut in_order = Vec::with_capacity(work.frames.len());
    for f in &work.frames {
        let e = &f.entry;
        let header = frame_header(link, e, &f.objects);
        let signed = key.as_ref().is_some_and(|k| {
            header_hash(&header).is_some_and(|(_, obj)| {
                verify_record(
                    k,
                    RecordPurpose::UplinkFrame,
                    &obj,
                    &RecordSignature::from_bytes(*e.frame_sig),
                )
                .is_ok()
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
        // Before the opening: judged once the opening is laid, or once the
        // gateway closed without one.
        if ctx.opening.map_or(ctx.closed, |open| e.slot < open) {
            report.findings.push(finding(f, LinkProblem::BeforeOpening));
        }
        let continuing = matches!(e.kind, FrameKind::Normal | FrameKind::CatchUp);
        if continuing && ctx.close.is_some_and(|close| e.slot > close) {
            report.findings.push(finding(f, LinkProblem::AfterClose));
        }
        if let SpanEnd::Swap(at) = ctx.end
            && e.slot > at
        {
            report.findings.push(finding(f, LinkProblem::AfterSwap));
        }
        if ctx.never_brought || ctx.swapped_in.is_some_and(|at| e.slot < at) {
            report.findings.push(finding(f, LinkProblem::BeforeSwap));
        }
        // Nothing but resends after a close resend, nothing but witnessed
        // resends after a witnessed resend.
        let rank = match e.kind {
            FrameKind::Normal | FrameKind::CatchUp => 0u8,
            FrameKind::CloseResend => 1,
            FrameKind::WitnessedResend => 2,
        };
        in_order.push(rank >= reached);
        if rank < reached {
            report.findings.push(finding(f, LinkProblem::KindOrder));
        }
        reached = reached.max(rank);
        let root = payload_root(f.leaves.iter());
        if root != Some(e.payload_root) {
            report.findings.push(finding(f, LinkProblem::Fill));
        }
        // The slot's kind group: normal; catch-up and close resend;
        // witnessed resend.
        let shape = match e.kind {
            FrameKind::Normal => 0u8,
            FrameKind::CatchUp | FrameKind::CloseResend => 1,
            FrameKind::WitnessedResend => 2,
        };
        if *shapes.entry(e.slot).or_insert(shape) != shape {
            report.findings.push(finding(f, LinkProblem::Shape));
        }
    }
    let facts = SlotFacts::of(work.frames.iter());
    let slots = &facts.groups;
    // The slots the device must send in: from its start (the first frame's
    // slot when none is known) to its end, or to the last frame that is
    // not a witnessed resend if later; and from the first slot of the
    // session that took its first witnessed resend to its last witnessed
    // resend. A link with no frame (a spare never used) has no span.
    let sent: Vec<u64> = work
        .frames
        .iter()
        .filter(|f| f.entry.kind != FrameKind::WitnessedResend)
        .map(|f| f.entry.slot)
        .collect();
    let first = sent.iter().min().copied();
    let last = sent.iter().max().copied();
    report.slots = first.zip(last);
    let span_start = ctx.start.or(first);
    let span_end = last.map(|b| match ctx.end {
        SpanEnd::To(Some(a)) => a.max(b),
        SpanEnd::To(None) | SpanEnd::LastFrame => b,
        SpanEnd::Swap(at) => at.saturating_sub(1).max(b),
    });
    let witnessed: Vec<&Frame<'_>> = work
        .frames
        .iter()
        .filter(|f| f.entry.kind == FrameKind::WitnessedResend)
        .collect();
    let witnessed_first = witnessed.first().map(|f| f.window.0.min(f.entry.slot));
    let witnessed_last = witnessed.iter().map(|f| f.entry.slot).max();
    let shape = Shape {
        normal,
        catchup,
        span: span_start.zip(span_end).filter(|(a, b)| a <= b),
        witnessed: witnessed_first.zip(witnessed_last),
    };
    // The kinds' slots (PROTOCOL.md §5.8 items 3–4). A catch-up group only
    // in the close slot, after a slot that fell short, or after a whole
    // catch-up group of full frames; a close resend only from the close
    // slot (or, when its frames there went untaken, the slot after) for
    // the slots what came before it needs at the catch-up shape; a
    // witnessed resend only after the close, in no more slots than its
    // bytes need at the catch-up shape and the slots of it that fell
    // short. While the close is unknown (not laid, not stated by the
    // device's frames) and the gateway has not closed, these wait.
    let per_slot = u64::from(catchup)
        .saturating_mul(u64::try_from(MAX_PAYLOAD_LEN).unwrap_or(u64::MAX))
        .max(1);
    let decided = ctx.closing.is_some() || ctx.closed;
    // A link a swap brought in may open with a catch-up group: its first
    // slot follows the slots its device could not send in while the
    // transmitter it replaced was out.
    let explain_from = span_start.map(|a| {
        if ctx.swapped_in.is_some() {
            a.saturating_sub(1)
        } else {
            a
        }
    });
    let first_resend = work
        .frames
        .iter()
        .find(|f| f.entry.kind == FrameKind::CloseResend);
    let resend_slots = first_resend
        .map_or(0, |f| f.entry.stream_offset)
        .div_ceil(per_slot);
    // A close resend that starts after the close slot: only when the close
    // slot's own frames went untaken.
    let resend_start_ok = |c: u64| {
        first_resend.is_none_or(|f| f.entry.slot <= c || !full(slots.get(&c), normal, catchup))
    };
    let witnessed_bytes = witnessed.first().zip(witnessed.last()).map_or(0, |(a, z)| {
        z.entry
            .stream_offset
            .saturating_add(u64::from(z.entry.payload_len))
            .saturating_sub(a.entry.stream_offset)
    });
    let witnessed_slots = shape.witnessed.map_or(0, |(a, z)| {
        let whole = slots
            .range(a..=z)
            .filter(|(_, g)| full(Some(*g), normal, catchup))
            .count();
        z.saturating_sub(a)
            .saturating_add(1)
            .saturating_sub(u64::try_from(whole).unwrap_or(u64::MAX))
            .saturating_add(witnessed_bytes.div_ceil(per_slot))
    });
    for (f, ordered) in work.frames.iter().zip(&in_order) {
        let s = f.entry.slot;
        let c = ctx.closing;
        let ok = match f.entry.kind {
            FrameKind::Normal => true,
            FrameKind::CatchUp => {
                c == Some(s) || facts.explained(s, explain_from, normal, catchup) || !decided
            }
            FrameKind::CloseResend => {
                c.is_some_and(|c| {
                    c <= s && s <= c.saturating_add(resend_slots) && resend_start_ok(c)
                }) || !decided
            }
            FrameKind::WitnessedResend => {
                let within = witnessed_first.is_some_and(|w| s.saturating_sub(w) < witnessed_slots);
                c.is_some_and(|c| s > c && within) || !decided
            }
        };
        if *ordered && !ok {
            report.findings.push(finding(f, LinkProblem::KindOrder));
        }
    }
    // Each window holds at most six slots, so this walks a bounded number
    // of slots whatever the frames claim.
    let mut short = BTreeSet::new();
    let mut gap = 0u64;
    for (a, b) in ranges_of(shape.span, shape.witnessed) {
        for (start, end) in windows {
            for s in a.max(*start)..=b.min(*end) {
                // A slot is whole when it holds every number of its shape;
                // a number beyond the shape is an `Index` finding, not a
                // gap.
                if !full(slots.get(&s), normal, catchup) {
                    short.insert(s);
                }
            }
        }
        // Slots after the last session taken may still come, until the
        // gateway's final session.
        let reported = if ctx.closed {
            Some(b)
        } else {
            windows.last().map(|w| w.1.min(b))
        };
        gap = gap.saturating_add(reported.map_or(0, |b| uncovered(windows, a, b)));
    }
    report.missing_slots = u64::try_from(short.len())
        .unwrap_or(u64::MAX)
        .saturating_add(gap);
    // Stream offsets: from 0, each frame where the previous ended, or later
    // only across positions no frame took, by at most a full payload each.
    // While the link's start is not the ledger's, the first frame's offset
    // waits (the positions before it are not known yet).
    let most = u64::try_from(MAX_PAYLOAD_LEN).unwrap_or(u64::MAX);
    let mut previous: Option<(u64, u16, u64)> = None;
    for f in &work.frames {
        let e = &f.entry;
        let end = previous.map_or(0, |p| p.2);
        let ok = match e.stream_offset.cmp(&end) {
            Ordering::Equal => true,
            Ordering::Less => false,
            // A skip of at least one byte needs at least one untaken
            // position, and at most a payload for each.
            Ordering::Greater => {
                let absent = shape.absent(slots, previous.map(|p| (p.0, p.1)), (e.slot, e.index));
                (previous.is_none() && !ctx.start_known)
                    || e.stream_offset.saturating_sub(end) <= absent.saturating_mul(most)
            }
        };
        if !ok {
            report.findings.push(finding(f, LinkProblem::Offset));
        }
        previous = Some((
            e.slot,
            e.index,
            e.stream_offset.saturating_add(u64::from(e.payload_len)),
        ));
    }
    // Whether a position after the last frame went untaken.
    let beyond = [shape.span, shape.witnessed]
        .iter()
        .flatten()
        .map(|(_, b)| *b)
        .max()
        .and_then(|b| b.checked_add(1));
    let whole_end = match (previous, beyond) {
        (Some((s, i, _)), Some(after)) => shape.absent(slots, Some((s, i)), (after, 0)) == 0,
        _ => true,
    };
    // The runs of consecutive witnessed slots.
    let mut witnessed_run = BTreeMap::new();
    let mut run = 0u32;
    let mut previous_slot: Option<u64> = None;
    for (s, (_, w, _)) in slots {
        if *w {
            if previous_slot.is_some_and(|p| p.checked_add(1) != Some(*s)) {
                run = run.saturating_add(1);
            }
            witnessed_run.insert(*s, run);
            previous_slot = Some(*s);
        }
    }
    FrameJudgement {
        valid,
        short,
        gap,
        witnessed_run,
        whole_end,
    }
}

/// One object a frame lists, as the stage tracks it.
#[derive(Debug, Clone, Copy)]
struct Listed {
    object: StreamObject,
    /// The log of the first frame that lists it.
    log: Seq,
    /// The slot and kind of the first frame that lists it.
    slot: u64,
    kind: FrameKind,
    /// Whether every chunk of every frame that holds bytes of it was
    /// recomputed and matched.
    verified: bool,
}

/// Where the walk over a link's objects is, for the batch rule.
#[derive(Debug, Clone, Copy)]
enum Walk<'r> {
    /// Outside every run.
    Outside,
    /// Right after bytes not received: a run may go on from anywhere.
    AfterLoss,
    /// In a run: the batch's records in hash order (when the ledger has
    /// the batch), the position of the last record taken, and its hash.
    Run {
        list: Option<&'r [[u8; 64]]>,
        at: Option<usize>,
        last: Option<[u8; 64]>,
    },
}

impl Walk<'_> {
    /// Whether a run that ends here with nothing lost ends at its batch's
    /// last record (or is no run, or its batch is not known).
    fn complete(&self) -> bool {
        match self {
            Self::Run {
                list: Some(list),
                at,
                ..
            } => at.map_or(list.is_empty(), |a| a.checked_add(1) == Some(list.len())),
            Self::Run { list: None, .. } | Self::Outside | Self::AfterLoss => true,
        }
    }
}

/// How often an object may be listed in normal and catch-up frames: a
/// batch's attestation, records and packages twice (the closed slot and
/// the next, PROTOCOL.md §5.8 item 4), anything else once.
fn listings(schema: SchemaId) -> u32 {
    if [
        SCHEMA_BATCH_ATTEST,
        SCHEMA_CAST_RECORD,
        SCHEMA_SHARE_PACKAGE,
    ]
    .contains(&schema)
    {
        2
    } else {
        1
    }
}

/// The slot of a progress tick, from its bytes.
fn tick_slot(bytes: &[u8]) -> Option<u64> {
    let t =
        decode_object::<ProgressTick<'_>>(SCHEMA_PROGRESS_TICK, SCHEMA_VERSION_1, bytes).ok()?;
    Some(match *t.body() {
        ProgressBody::Box(b) => b.parts().slot,
        ProgressBody::Checkin(c) => c.parts().slot,
    })
}

/// The object rules of one link (VC-079) over its frames whose signature
/// verified, and the chunk checks; returns the objects included: received
/// whole, every chunk of them recomputed and matched (by schema and hash).
#[allow(clippy::too_many_lines)] // One rule after another, as the module docs list them.
fn judge_objects(
    work: &LinkWork<'_>,
    ctx: &LinkContext<'_, '_>,
    judged: &FrameJudgement,
    report: &mut LinkReport<'_>,
) -> BTreeSet<(u32, [u8; 64])> {
    let frames: Vec<&Frame<'_>> = work
        .frames
        .iter()
        .zip(&judged.valid)
        .filter(|(_, ok)| **ok)
        .map(|(f, _)| f)
        .collect();
    let received = received_ranges(&frames);
    let frame_finding = |f: &Frame<'_>, at: u64, problem| LinkFinding {
        seq: f.log,
        slot: Some(f.entry.slot),
        index: Some(f.entry.index),
        stream_offset: at,
        object: None,
        problem,
    };
    // Each frame's tiling; every object once, by where it starts; what one
    // frame carries out is what the next carries in.
    let mut listed: BTreeMap<u64, Listed> = BTreeMap::new();
    let mut previous_data: Option<&Frame<'_>> = None;
    // The frames whose list does not tile their data: their chunks are not
    // recomputed.
    let mut untiled: BTreeSet<(u64, u16)> = BTreeSet::new();
    for f in &frames {
        let e = &f.entry;
        if let Some((problem, at)) = tiling(e.stream_offset, e.payload_len, &f.objects).problem {
            report.findings.push(frame_finding(f, at, problem));
            untiled.insert((e.slot, e.index));
        }
        for o in f.objects.iter() {
            let first = listed.entry(o.stream_offset).or_insert(Listed {
                object: o,
                log: f.log,
                slot: e.slot,
                kind: e.kind,
                verified: true,
            });
            if first.object != o {
                report
                    .findings
                    .push(frame_finding(f, o.stream_offset, LinkProblem::Overlap));
            }
        }
        if e.payload_len == 0 {
            continue;
        }
        if let Some(p) = previous_data {
            let carried = p.objects.iter().last();
            let next = f.objects.iter().next();
            // Where they start: what they list there is compared above.
            let agrees = match (carried, next) {
                (Some(c), Some(n)) => {
                    let c_end = c.end().unwrap_or(u64::MAX);
                    if c_end > e.stream_offset {
                        n.stream_offset == c.stream_offset
                    } else {
                        n.stream_offset >= c_end
                    }
                }
                (None, _) | (_, None) => true,
            };
            if !agrees {
                report
                    .findings
                    .push(frame_finding(f, e.stream_offset, LinkProblem::Overlap));
            }
        }
        previous_data = Some(f);
    }
    report.objects = u64::try_from(listed.len()).unwrap_or(u64::MAX);
    let class = work.info.class();
    let carries = ctx.entry.map_or(0, |e| e.carries);
    let finding = |l: &Listed, problem| LinkFinding {
        seq: l.log,
        slot: None,
        index: None,
        stream_offset: l.object.stream_offset,
        object: Some(l.object.object_hash),
        problem,
    };
    let batches = ctx.batches;
    // What was received whole in normal, catch-up and close-resend frames:
    // a witnessed resend carries only what is still missing.
    let whole02: BTreeSet<(u32, [u8; 64])> = listed
        .values()
        .filter(|l| l.kind != FrameKind::WitnessedResend)
        .filter(|l| {
            l.object
                .end()
                .is_some_and(|end| covered(&received, l.object.stream_offset, end))
        })
        .map(|l| (l.object.schema.get(), l.object.object_hash.0))
        .collect();
    let batch_whole = |b: &[u8; 64], run: &BatchRun| {
        whole02.contains(&(SCHEMA_BATCH_ATTEST.get(), *b))
            && run.records.iter().all(|r| {
                whole02.contains(&(SCHEMA_CAST_RECORD.get(), *r))
                    && batches
                        .package_of
                        .get(r)
                        .is_none_or(|p| whole02.contains(&(SCHEMA_SHARE_PACKAGE.get(), *p)))
            })
    };
    // The batches a close resend sends again: every one of the box closed
    // by then, in batch-index order.
    let resent: Vec<u32> = {
        let mut v: Vec<u32> = batches
            .by_hash
            .values()
            .filter(|b| {
                ctx.closing
                    .is_none_or(|c| b.first_slot.is_none_or(|first| first <= c))
            })
            .map(|b| b.index)
            .collect();
        v.sort_unstable();
        v
    };
    // Until the gateway closed, a batch member may be a record the device
    // opened for a challenge whose opening the ledger does not have yet
    // (lost on the link, or listed and not laid): the record stage counts
    // it a member until then, and the device sends it outside every run
    // (PROTOCOL.md §8 item 3). While that may be, a run may skip members
    // or end early and a record may go outside every run: the close
    // decides.
    let gap = received.len() > 1 || received.first().is_some_and(|(a, _)| *a > 0);
    let unlaid_opening = listed.values().any(|l| {
        l.object.schema == SCHEMA_CHALLENGE_OPENING
            && !ctx
                .on_ledger
                .contains(&(l.object.object_hash.0, SCHEMA_CHALLENGE_OPENING.get()))
    });
    let unsettled = !ctx.closed && (gap || unlaid_opening);
    let mut walk = Walk::Outside;
    // What came right before: at the stream's start no record, after a
    // loss nothing known.
    let mut previous: Option<(SchemaId, Option<Hash512>)> = Some((STREAM_START, None));
    let mut previous_end: Option<u64> = None;
    // Listings per object in normal and catch-up frames and in the close
    // resend; the objects a witnessed resend already carried whole.
    let mut counts: BTreeMap<(u32, [u8; 64]), [u32; 2]> = BTreeMap::new();
    let mut witnessed_whole: BTreeSet<(u32, [u8; 64])> = BTreeSet::new();
    // The order of batches and ticks in each group: normal and catch-up
    // frames, the close resend, each run of witnessed slots.
    let mut orders: BTreeMap<u32, Order> = BTreeMap::new();
    // The slot of the last loss seen.
    let mut loss_slot: Option<u64> = None;
    // The close resend: the last batch it sent, and its last listing.
    let mut resend_batch: Option<u32> = None;
    let mut resend_last: Option<&Listed> = None;
    for l in listed.values() {
        let o = &l.object;
        let hash = o.object_hash;
        let schema = o.schema;
        let bytes = ctx
            .public
            .get(&hash.0)
            .filter(|(s, _)| *s == schema)
            .map(|(_, b)| *b);
        // Kind, length, whose, schema.
        let kind_ok = allowed(class, schema).is_some_and(|bit| carries & bit != 0)
            && (schema != SCHEMA_WITNESSED_EVENT || witnessed_ok(bytes));
        if !kind_ok {
            report.findings.push(finding(l, LinkProblem::Kind));
        }
        if bytes.is_some_and(|b| u64::try_from(b.len()).ok() != Some(u64::from(o.len))) {
            report.findings.push(finding(l, LinkProblem::Length));
        }
        let package = schema == SCHEMA_SHARE_PACKAGE;
        // A share package is judged by the records that name it: the
        // sealed frames the index keeps by hash say nothing of its box.
        if !package
            && ctx
                .scopes
                .get(&hash.0)
                .is_some_and(|scope| !mine(*scope, &work.info))
        {
            report.findings.push(finding(l, LinkProblem::Foreign));
        }
        let mislabeled = ctx.other_schema(&hash.0, schema);
        if mislabeled {
            report.findings.push(finding(l, LinkProblem::Schema));
        }
        // Across bytes not received the objects between are not known: what
        // follows may go on a run whose start was lost.
        let continuous = match previous_end {
            None => o.stream_offset == 0,
            Some(end) => end >= o.stream_offset || covered(&received, end, o.stream_offset),
        };
        if !continuous {
            loss_slot = Some(l.slot);
        }
        let whole = o
            .end()
            .is_some_and(|end| covered(&received, o.stream_offset, end));
        let key = (schema.get(), hash.0);
        // Its group, and how often it is listed there: a batch's objects
        // twice in normal and catch-up frames (the closed slot and the
        // next), anything else once; once in the close resend; in a
        // witnessed resend again only after a listing of it there that
        // was not received whole.
        let group = match l.kind {
            FrameKind::Normal | FrameKind::CatchUp => 0u32,
            FrameKind::CloseResend => 1,
            FrameKind::WitnessedResend => judged
                .witnessed_run
                .get(&l.slot)
                .map_or(2, |r| r.saturating_add(2)),
        };
        let repeated = match l.kind {
            FrameKind::Normal | FrameKind::CatchUp | FrameKind::CloseResend => {
                let i = usize::from(l.kind == FrameKind::CloseResend);
                let count = counts.entry(key).or_insert([0; 2]);
                let most = if i == 0 { listings(schema) } else { 1 };
                count.get_mut(i).is_some_and(|n| {
                    *n = n.saturating_add(1);
                    *n > most
                })
            }
            FrameKind::WitnessedResend => {
                let again = witnessed_whole.contains(&key);
                if whole {
                    witnessed_whole.insert(key);
                }
                again
            }
        };
        if repeated {
            report.findings.push(finding(l, LinkProblem::Repeat));
        }
        // Its batch, and when it may go out.
        let batch = batches.of(schema, &hash.0);
        let order = orders.entry(group).or_default();
        if let Some((b_hash, b)) = batch {
            if b.first_slot.is_some_and(|first| l.slot < first) && schema != SCHEMA_SHARE_PACKAGE {
                report.findings.push(finding(l, LinkProblem::Time));
            }
            // A batch first sent after one of a higher index: in normal and
            // catch-up frames only where each such one was first sent in
            // the slot before, after a loss there that may have held this
            // one's first copy (the second copy follows in the next slot);
            // in a resend never.
            if !order.first.contains_key(&b.index) {
                let tolerated = group == 0;
                let fine = order.first.range(b.index..).all(|(_, (slot, after_loss))| {
                    tolerated && slot.checked_add(1) == Some(l.slot) && *after_loss
                });
                if !fine {
                    report.findings.push(finding(l, LinkProblem::Batch));
                }
                order
                    .first
                    .insert(b.index, (l.slot, loss_slot == Some(l.slot)));
            }
            // What a resend carries.
            match l.kind {
                FrameKind::CloseResend => {
                    if resend_batch != Some(b.index) {
                        let next = match resend_batch {
                            None => resent.first().copied(),
                            Some(p) => resent.iter().find(|i| **i > p).copied(),
                        };
                        if next != Some(b.index) && continuous {
                            report.findings.push(finding(l, LinkProblem::Resend));
                        }
                        resend_batch = Some(b.index);
                    }
                }
                FrameKind::WitnessedResend if ctx.closed && batch_whole(b_hash, b) => {
                    report.findings.push(finding(l, LinkProblem::Resend));
                }
                FrameKind::Normal | FrameKind::CatchUp | FrameKind::WitnessedResend => {}
            }
        } else if !Batches::batch_object(schema) {
            // Anything but a batch's objects: never in the close resend,
            // in a witnessed resend only when not yet received whole.
            let again = match l.kind {
                FrameKind::CloseResend => true,
                FrameKind::WitnessedResend => ctx.closed && whole02.contains(&key),
                FrameKind::Normal | FrameKind::CatchUp => false,
            };
            if again {
                report.findings.push(finding(l, LinkProblem::Resend));
            }
        }
        // The close resend sends every batch to the last, where nothing was
        // lost after it.
        if l.kind == FrameKind::CloseResend {
            resend_last = Some(l);
        } else if l.kind == FrameKind::WitnessedResend
            && let Some(last) = resend_last.take()
            && continuous
            && ctx.closed
            && resend_batch != resent.last().copied()
        {
            report.findings.push(finding(last, LinkProblem::Resend));
        }
        if schema == SCHEMA_PROGRESS_TICK
            && let Some(slot) = bytes.and_then(tick_slot)
        {
            let behind = order.latest_tick.is_some_and(|t| slot < t);
            if l.slot < slot || behind {
                report.findings.push(finding(l, LinkProblem::Time));
            }
            order.latest_tick = order.latest_tick.max(Some(slot));
        }
        // Batches and packages.
        if !continuous {
            walk = Walk::AfterLoss;
            previous = None;
        }
        let record = schema == SCHEMA_CAST_RECORD && !batches.challenged.contains(&hash.0);
        if schema == SCHEMA_BATCH_ATTEST {
            if !walk.complete() && !unsettled {
                report.findings.push(finding(l, LinkProblem::Batch));
            }
            // A batch the record stage did not take holds no record.
            let list = batches.by_hash.get(&hash.0).map_or_else(
                || {
                    ctx.on_ledger
                        .contains(&(hash.0, SCHEMA_BATCH_ATTEST.get()))
                        .then_some(&[][..])
                },
                |b| Some(b.records.as_slice()),
            );
            walk = Walk::Run {
                list,
                at: None,
                last: None,
            };
        } else if record {
            // A record the ledger does not have yet is judged by hash order
            // alone, and one it has in no batch only once the gateway
            // closed: its batch may not be laid yet.
            let known = ctx.on_ledger.contains(&(hash.0, SCHEMA_CAST_RECORD.get()));
            let its_list = batches
                .of_record
                .get(&hash.0)
                .and_then(|b| batches.by_hash.get(b))
                .map(|b| b.records.as_slice());
            walk = match walk {
                Walk::Run {
                    list: Some(list),
                    at,
                    last,
                } if !known => Walk::Run {
                    list: Some(list),
                    at,
                    last,
                },
                Walk::Run { list, at, last } => {
                    let (ok, at) = match list {
                        Some(list) => {
                            let next = at.map_or(0, |a| a.saturating_add(1));
                            let here = list.binary_search(&hash.0).ok();
                            let fits = if unsettled {
                                here.is_some_and(|h| h >= next)
                            } else {
                                here == Some(next)
                            };
                            (fits, here.or(at))
                        }
                        None => (last.is_none_or(|r| r < hash.0), None),
                    };
                    if ok {
                        Walk::Run {
                            list,
                            at,
                            last: Some(hash.0),
                        }
                    } else if unsettled {
                        // Perhaps a challenged record after the run.
                        Walk::Outside
                    } else {
                        report.findings.push(finding(l, LinkProblem::Batch));
                        Walk::Run {
                            list,
                            at,
                            last: Some(hash.0),
                        }
                    }
                }
                // After a loss, one stretch of one batch's records.
                Walk::AfterLoss => match its_list {
                    Some(list) => Walk::Run {
                        list: Some(list),
                        at: list.binary_search(&hash.0).ok(),
                        last: Some(hash.0),
                    },
                    None if known && ctx.closed => {
                        report.findings.push(finding(l, LinkProblem::Batch));
                        Walk::Outside
                    }
                    None => Walk::Run {
                        list: None,
                        at: None,
                        last: Some(hash.0),
                    },
                },
                Walk::Outside => {
                    if !unsettled {
                        report.findings.push(finding(l, LinkProblem::Batch));
                    }
                    Walk::Outside
                }
            };
        } else if package {
            // Right after the record that names it (when that record is
            // known), and no longer than the election allows.
            let follows = previous
                .is_none_or(|(s, p)| s == SCHEMA_CAST_RECORD && p.is_none_or(|p| p == hash));
            if !follows || u64::from(o.len) > ctx.package_len {
                report.findings.push(finding(l, LinkProblem::Package));
            }
        } else {
            if !walk.complete() && !unsettled {
                report.findings.push(finding(l, LinkProblem::Batch));
            }
            walk = Walk::Outside;
        }
        let its_package = if schema == SCHEMA_CAST_RECORD {
            bytes.and_then(|b| {
                decode_object::<CastRecord<'_>>(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, b)
                    .ok()
                    .map(|r| *r.body().share_package_hash())
            })
        } else {
            None
        };
        previous = Some((schema, its_package));
        previous_end = o.end();
        // On the ledger, once the gateway closed: a frame of the ledger
        // names it under its schema (a share package: an accepted record of
        // the box names it).
        let named = if package {
            ctx.packages.contains(&hash.0)
        } else {
            ctx.on_ledger.contains(&(hash.0, schema.get()))
        };
        if ctx.closed && !named && !mislabeled {
            report.findings.push(finding(l, LinkProblem::NotOnLedger));
        }
    }
    // A run the stream ends in, where the device's stream ends and its
    // last object was received whole, ends at its batch's last record.
    let stream_end = frames
        .iter()
        .map(|f| {
            f.entry
                .stream_offset
                .saturating_add(u64::from(f.entry.payload_len))
        })
        .max();
    let whole_end = ctx.closed
        && judged.whole_end
        && listed.values().next_back().is_some_and(|l| {
            l.object.end() == stream_end
                && stream_end.is_some_and(|end| covered(&received, l.object.stream_offset, end))
        });
    if whole_end
        && !walk.complete()
        && let Some(l) = listed.values().next_back()
    {
        report.findings.push(finding(l, LinkProblem::Batch));
    }
    // A close resend the stream ends in stops at the box's last batch.
    if whole_end
        && let Some(last) = resend_last
        && resend_batch != resent.last().copied()
    {
        report.findings.push(finding(last, LinkProblem::Resend));
    }
    // Chunks: every data chunk whose bytes are all public objects (and the
    // zero fill around packages) is recomputed, in a frame whose list tiles
    // its data; an object counts as checked when every chunk that holds
    // bytes of it was.
    for f in &frames {
        let objects: Vec<StreamObject> = f.objects.iter().collect();
        let tiled = !untiled.contains(&(f.entry.slot, f.entry.index));
        let mut from = 0usize;
        for (j, leaf) in f.leaves.iter().enumerate() {
            let chunk = u64::try_from(CHUNK_LEN).unwrap_or(u64::MAX);
            let into = u64::try_from(j).unwrap_or(u64::MAX).saturating_mul(chunk);
            let lo = f.entry.stream_offset.saturating_add(into);
            let data_end = f
                .entry
                .stream_offset
                .saturating_add(u64::from(f.entry.payload_len));
            let hi = lo.saturating_add(chunk).min(data_end);
            let mine = if tiled {
                public_leaf(lo, hi, &objects, ctx.public)
            } else {
                None
            };
            let ok = if let Some(mine) = mine {
                report.checked_chunks = report.checked_chunks.saturating_add(1);
                if mine != leaf {
                    report
                        .findings
                        .push(frame_finding(f, lo, LinkProblem::Chunk));
                }
                mine == leaf
            } else {
                report.opaque_chunks = report.opaque_chunks.saturating_add(1);
                false
            };
            // The objects before `from` end before this chunk.
            while objects
                .get(from)
                .is_some_and(|o| o.end().is_some_and(|end| end <= lo))
            {
                from = from.saturating_add(1);
            }
            if !ok {
                for o in objects
                    .iter()
                    .skip(from)
                    .take_while(|o| o.stream_offset < hi)
                {
                    if let Some(l) = listed.get_mut(&o.stream_offset) {
                        l.verified = false;
                    }
                }
            }
        }
    }
    listed
        .values()
        .filter(|l| {
            l.verified
                && l.object
                    .end()
                    .is_some_and(|end| covered(&received, l.object.stream_offset, end))
        })
        .map(|l| (l.object.schema.get(), l.object.object_hash.0))
        .collect()
}

// ---------------------------------------------------------------------------
// The stage.

/// The first slot of the first `BoxOpened` of `box_id`, if any.
pub(crate) fn opening_slot(index: &LedgerIndex<'_>, box_id: &[u8]) -> Option<u64> {
    opening_of(index, box_id).map(|(_, slot)| slot)
}

/// The first `BoxOpened` of `box_id`: its frame and first slot.
fn opening_of(index: &LedgerIndex<'_>, box_id: &[u8]) -> Option<(Seq, u64)> {
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
        bucket_slots(b.parts().time_bucket).map(|(first, _)| (e.seq, first))
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

/// The slot of each `BoxUnitSwap` of `box_id`, in ledger order.
fn box_swaps(index: &LedgerIndex<'_>, box_id: &[u8]) -> Vec<(Seq, u64)> {
    index
        .box_events(box_id)
        .filter_map(|e| {
            if e.schema != SCHEMA_WITNESSED_EVENT {
                return None;
            }
            let w = decode_object::<WitnessedEvent<'_>>(
                SCHEMA_WITNESSED_EVENT,
                schema_version(SCHEMA_WITNESSED_EVENT),
                e.bytes?,
            )
            .ok()?;
            w.body::<BoxUnitSwapBody<'_>>(SCHEMA_BOX_UNIT_SWAP_BODY)
                .ok()
                .map(|b| (e.seq, b.parts().at_slot))
        })
        .collect()
}

/// The slots of the station's first `CheckinUnitSwap` that brought `unit`
/// into service (none for a unit in service from the start) and of the
/// first that took it out after that. A spare is used once (VC-106): a
/// unit taken out is not counted back in.
fn unit_swaps(
    index: &LedgerIndex<'_>,
    station_id: &[u8],
    unit: &[u8],
    original: bool,
) -> (Option<u64>, Option<u64>) {
    // Each swap of the station: the failed unit, the spare, the slot.
    let mut swaps: Vec<(&[u8], &[u8], u64)> = Vec::new();
    for e in index.station_events(station_id) {
        let Some(w) = e
            .bytes
            .filter(|_| e.schema == SCHEMA_WITNESSED_EVENT)
            .and_then(|b| {
                decode_object::<WitnessedEvent<'_>>(
                    SCHEMA_WITNESSED_EVENT,
                    schema_version(SCHEMA_WITNESSED_EVENT),
                    b,
                )
                .ok()
            })
        else {
            continue;
        };
        if let Ok(swap) = w.body::<CheckinUnitSwapBody<'_>>(SCHEMA_CHECKIN_UNIT_SWAP_BODY) {
            let p = swap.parts();
            swaps.push((p.failed_unit.as_bytes(), p.spare_unit.as_bytes(), p.at_slot));
        }
    }
    let brought = if original {
        None
    } else {
        swaps
            .iter()
            .find(|(_, spare, _)| *spare == unit)
            .map(|(_, _, at)| *at)
    };
    let taken = swaps
        .iter()
        .find(|(failed, _, at)| *failed == unit && brought.is_none_or(|b| *at >= b))
        .map(|(_, _, at)| *at);
    (brought, taken)
}

/// How a link came into service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Intro {
    /// At the opening: in the first state that has its device, or brought
    /// by an amendment laid before the opening.
    Opening,
    /// At the slot of the swap laid in a state that carries it.
    Swap(u64),
    /// Not known: an amendment laid after the opening (or not laid) and no
    /// swap that carries it.
    Unknown,
}

/// Whether the amendment that created genesis state `state` (none for the
/// genesis) is laid before frame `before`.
fn amended_before(index: &LedgerIndex<'_>, state: usize, before: Option<Seq>) -> bool {
    state
        .checked_sub(1)
        .and_then(|k| index.amendment_frames().get(k).copied())
        .zip(before)
        .is_some_and(|(a, b)| a.get() < b.get())
}

/// The links of `box_id`'s frame keys in the order the genesis states
/// bring them, each with how it came into service: the box's first key and
/// a key an amendment laid before the opening at the opening (`opened`,
/// the frame of the box's first `BoxOpened`); another at the first
/// `BoxUnitSwap` laid in a state that carries it (ADR-0041 decision 5).
fn box_keys(
    genesis: &VerifiedGenesis<'_>,
    index: &LedgerIndex<'_>,
    box_id: &[u8],
    opened: Option<Seq>,
) -> Vec<([u8; 64], Intro)> {
    let swaps = box_swaps(index, box_id);
    let mut out: Vec<([u8; 64], Intro)> = Vec::new();
    for state in 0..genesis.state_count() {
        let Some(b) = genesis.expected_box_at(state, box_id) else {
            continue;
        };
        let l = link_id(b.frame_key).0;
        if out.iter().any(|(k, _)| *k == l) {
            continue;
        }
        let intro = if out.is_empty() || amended_before(index, state, opened) {
            Intro::Opening
        } else {
            swaps
                .iter()
                .find(|(seq, _)| {
                    genesis
                        .expected_box_at(index.state_at(*seq), box_id)
                        .is_some_and(|x| link_id(x.frame_key).0 == l)
                })
                .map_or(Intro::Unknown, |(_, at)| Intro::Swap(*at))
        };
        out.push((l, intro));
    }
    out
}

/// Whether check-in unit `unit` of `station_id` is in service from the
/// station's opening (`opened`, the frame of its first `BoxOpened`): the
/// in-service unit of the first state that has the station, or of a state
/// an amendment laid before the opening created.
fn unit_from_opening(
    genesis: &VerifiedGenesis<'_>,
    index: &LedgerIndex<'_>,
    station_id: &[u8],
    unit: &[u8],
    opened: Option<Seq>,
) -> bool {
    let mut first = true;
    for state in 0..genesis.state_count() {
        let Some(s) = genesis.station_at(state, station_id) else {
            continue;
        };
        if s.primary().unit_id.as_bytes() == unit && (first || amended_before(index, state, opened))
        {
            return true;
        }
        first = false;
    }
    false
}

/// Where a link's span starts and whether the ledger says so.
struct Start {
    slot: Option<u64>,
    known: bool,
    swapped_in: Option<u64>,
    never_brought: bool,
}

/// The start of a link that came into service as `intro` says, with the
/// opening `opening` and whether the gateway `closed`. A link of unknown
/// start waits, while the gateway has not closed, at its first frame.
fn start_of(intro: Intro, opening: Option<u64>, closed: bool) -> Start {
    match intro {
        Intro::Opening => Start {
            slot: opening,
            known: opening.is_some() || closed,
            swapped_in: None,
            never_brought: false,
        },
        Intro::Swap(at) => Start {
            slot: Some(at),
            known: true,
            swapped_in: Some(at),
            never_brought: false,
        },
        Intro::Unknown => Start {
            slot: opening.filter(|_| closed),
            known: closed,
            swapped_in: None,
            never_brought: closed,
        },
    }
}

/// A box's batches as the record stage took them, with the first slot of
/// each one's time bucket, and its challenged records.
fn batches_of(index: &LedgerIndex<'_>, records: &RecordStage<'_>, box_id: &[u8]) -> Batches {
    let mut out = Batches::default();
    let Some(report) = records.report(box_id) else {
        return out;
    };
    let events = index.events();
    let at = |seq: Seq| {
        events
            .binary_search_by_key(&seq.get(), |e| e.seq.get())
            .ok()
            .and_then(|i| events.get(i))
    };
    for m in &report.members {
        let Some(e) = at(m.seq) else {
            continue;
        };
        let body = e.bytes.and_then(|b| {
            decode_object::<BatchAttest<'_>>(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, b).ok()
        });
        let mut list: Vec<[u8; 64]> = m
            .records
            .iter()
            .filter_map(|s| at(*s))
            .map(|r| r.hash.0)
            .collect();
        list.sort_unstable();
        for r in &list {
            out.of_record.insert(*r, e.hash.0);
        }
        for r in m.records.iter().filter_map(|s| at(*s)) {
            if let Some(p) = r.bytes.and_then(|b| {
                decode_object::<CastRecord<'_>>(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, b)
                    .ok()
                    .map(|c| c.body().share_package_hash().0)
            }) {
                out.package_of.insert(r.hash.0, p);
                out.record_of.insert(p, r.hash.0);
            }
        }
        out.by_hash.insert(
            e.hash.0,
            BatchRun {
                records: list,
                index: body.as_ref().map_or(0, |b| b.body().batch_index()),
                first_slot: body
                    .as_ref()
                    .and_then(|b| bucket_slots(b.body().time_bucket()))
                    .map(|(first, _)| first),
            },
        );
    }
    for r in &report.records {
        if r.state.status() == RecordStatus::ChallengedSpoiled
            && let Some(e) = at(r.seq)
        {
            out.challenged.insert(e.hash.0);
        }
    }
    out
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

/// Per box the audit stage audits, whether it compared every record: some
/// style audits the box and every style that does compared all its
/// records.
fn fully_compared<'a>(audit: &AuditStage<'a>) -> BTreeMap<&'a [u8], bool> {
    let mut out: BTreeMap<&'a [u8], bool> = BTreeMap::new();
    for d in audit.styles().iter().flat_map(|s| s.devices.iter()) {
        let all = out.entry(d.box_id.as_bytes()).or_insert(true);
        *all = *all && d.compared == d.records;
    }
    out
}

/// Reads one incident (VC-083).
fn incident<'a>(
    genesis: &VerifiedGenesis<'a>,
    index: &LedgerIndex<'a>,
    rosters: &Rosters<'a>,
    compared: &BTreeMap<&'a [u8], bool>,
    seq: Seq,
    event: &WitnessedEvent<'a>,
) -> Option<IncidentReport<'a>> {
    let body = event
        .body::<ConnectivityIncidentBody<'a>>(SCHEMA_CONNECTIVITY_INCIDENT_BODY)
        .ok()?;
    let parts = *body.parts();
    let state = index.state_at(seq);
    let signers = people_signed(genesis, rosters, state, event);
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
    // Clerks sign on site, at the station the incident names; the whole
    // election is the committee's to name (the envelope never mixes the
    // committee with clerks).
    let scope_ok = signers.as_ref().is_some_and(|s| match parts.station_id {
        Some(station) => s
            .clerk_stations
            .iter()
            .all(|c| c.is_some_and(|c| c.as_bytes() == station.as_bytes())),
        None => s.committee,
    });
    let refused = if signers.is_none() {
        Some(IncidentProblem::Signers)
    } else if !subject_ok {
        Some(IncidentProblem::Subject)
    } else if !scope_ok {
        Some(IncidentProblem::Scope)
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
            .map(|b| (*b, compared.get(b.as_bytes()).copied().unwrap_or(false)))
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

/// Who signed an incident whose people are registered.
struct Signers<'a> {
    /// Whether the committee signed.
    committee: bool,
    /// The station each clerk is registered at.
    clerk_stations: Vec<Option<StationId<'a>>>,
}

/// The people of `event` if they are registered and their signatures
/// verify: the committee under the genesis key, every clerk and observer
/// under a key the roster of `state` or an earlier state registers for
/// that signer, role and organisation (`ityv_state::check_incident_signers`).
fn people_signed<'a>(
    genesis: &VerifiedGenesis<'a>,
    rosters: &Rosters<'a>,
    state: usize,
    event: &WitnessedEvent<'_>,
) -> Option<Signers<'a>> {
    let purpose = Purpose::new(event.purpose())?;
    let in_force = rosters.states.get(state)?;
    let committee = genesis.genesis().committee_key();
    let mut keys: Vec<RosterEntry<'a>> = Vec::new();
    let mut pairs = Vec::new();
    let mut out = Signers {
        committee: false,
        clerk_stations: Vec::new(),
    };
    for s in event.sigs() {
        if s.role == EventRole::Committee {
            out.committee = true;
            pairs.push((s.sig, committee));
            continue;
        }
        let entry = *(0..=state)
            .rev()
            .flat_map(|k| rosters.signer(k, s.signer_id.as_bytes()))
            .find(|r| {
                Material::new(core::iter::once((s.sig, r.get().key)))
                    .is_some_and(|m| m.verify(&purpose, event.body_bytes()).is_some())
            })?;
        if s.role == EventRole::Clerk {
            // The roster entry in force names the clerk's station.
            let station = rosters
                .signer(state, s.signer_id.as_bytes())
                .map(ityv_state::Entry::get)
                .find(|r| r.role == RosterRole::Clerk)
                .and_then(|r| r.station_id);
            out.clerk_stations.push(station);
        }
        keys.push(entry);
        pairs.push((s.sig, entry.get().key));
    }
    let material = Material::new(pairs.into_iter())?;
    let tokens = material.verify(&purpose, event.body_bytes())?;
    check_incident_signers(
        &Signed {
            event,
            tokens: &tokens,
        },
        in_force,
        &keys,
        committee,
    )
    .ok()?;
    Some(out)
}

/// Runs the connectivity stage over `index` against `genesis`, with the
/// record stage for each box's batches and the audit stage for the full
/// comparisons an incident calls for.
#[must_use]
#[allow(clippy::too_many_lines)] // The stage's steps in order, as the module docs list them.
pub fn verify_connectivity<'a>(
    genesis: &VerifiedGenesis<'a>,
    index: &LedgerIndex<'a>,
    records: &RecordStage<'a>,
    audit: &AuditStage<'a>,
) -> ConnectivityStage<'a> {
    let manifest = genesis.manifest();
    let manifest_problems = manifest_findings(manifest);
    let mut ledger = HoldSet::empty().with_if(
        !manifest_problems.is_empty(),
        HoldReason::ConnectivityManifest,
    );
    let mut boxes: BTreeMap<&'a [u8], HoldSet> = BTreeMap::new();
    let rosters = Rosters::new(genesis);
    let mut work = Work {
        genesis,
        index,
        rosters: &rosters,
        links: links(genesis),
        per_link: BTreeMap::new(),
        stations: BTreeMap::new(),
        logs: BTreeMap::new(),
    };
    let compared = fully_compared(audit);
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
                && let Some(report) = incident(genesis, index, &rosters, &compared, e.seq, &w)
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

    // The ledger's public objects and whom each concerns (a sealed frame's
    // scope says nothing of its box), and every hash and schema a frame
    // names.
    let mut public: BTreeMap<[u8; 64], (SchemaId, &'a [u8])> = BTreeMap::new();
    let mut scopes: BTreeMap<[u8; 64], Scope<'a>> = BTreeMap::new();
    let mut on_ledger: BTreeSet<([u8; 64], u32)> = BTreeSet::new();
    for e in index.events() {
        on_ledger.insert((e.hash.0, e.schema.get()));
        if let Some(b) = e.bytes {
            scopes.entry(e.hash.0).or_insert(e.scope);
            public.insert(e.hash.0, (e.schema, b));
        }
    }
    for f in index.findings() {
        if let (Some(h), Some(s)) = (f.event_hash, f.event_schema) {
            on_ledger.insert((h.0, s.get()));
        }
    }
    let members = genesis.trustees().count();
    let package_len = u64::try_from(max_package_len(members)).unwrap_or(u64::MAX);
    let no_packages = BTreeSet::new();

    // Every station of the last state, then any other with sessions.
    let mut order: Vec<StationId<'a>> = genesis.stations().map(StationEntry::station_id).collect();
    let listed: BTreeSet<&[u8]> = order.iter().map(StationId::as_bytes).collect();
    for s in work.stations.values() {
        if !listed.contains(s.station_id.as_bytes()) {
            order.push(s.station_id);
        }
    }
    // Each station's links, by link hash.
    let mut by_station: BTreeMap<&'a [u8], Vec<([u8; 64], LinkWork<'a>)>> = BTreeMap::new();
    for (k, w) in core::mem::take(&mut work.per_link) {
        by_station
            .entry(w.info.station.as_bytes())
            .or_default()
            .push((k, w));
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
        let station_links = by_station.remove(station_id.as_bytes()).unwrap_or_default();
        let mut included: BTreeMap<[u8; 64], BTreeSet<(u32, [u8; 64])>> = BTreeMap::new();
        let windows: Vec<(u64, u64)> = st
            .sessions
            .iter()
            .map(|s| (s.start_slot, s.end_slot))
            .collect();
        let last_window = windows.last().map(|w| w.1);
        let station_boxes: Vec<&'a [u8]> = genesis
            .station(station_id.as_bytes())
            .map(|s| s.boxes().map(|b| b.as_bytes()).collect())
            .unwrap_or_default();
        // Each opened box: its first `BoxOpened`'s frame and slot, and its
        // close slot, laid or (while it is not) as its device's frames
        // state it.
        let close_of = |b: &[u8]| {
            close_slot(index, b).or_else(|| {
                station_links
                    .iter()
                    .filter(
                        |(_, lw)| matches!(lw.info.device, LinkDevice::Box(x) if x.as_bytes() == b),
                    )
                    .filter_map(|(_, lw)| close_statement(&lw.frames))
                    .max()
            })
        };
        let opened: Vec<(&'a [u8], Seq, u64)> = station_boxes
            .iter()
            .filter_map(|b| opening_of(index, b).map(|(seq, slot)| (*b, seq, slot)))
            .collect();
        // Until the gateway closed, a box whose opening is not laid yet may
        // still open: the station's opening and last close wait for every
        // box (once it closed, a box that never opened counts for neither).
        let every_box = closed || opened.len() == station_boxes.len();
        let station_opening = opened
            .iter()
            .map(|(_, _, s)| *s)
            .min()
            .filter(|_| every_box);
        let station_opened = opened
            .iter()
            .map(|(_, q, _)| *q)
            .min_by_key(|q| q.get())
            .filter(|_| every_box);
        // The station's last close once every opened box closed.
        let box_closes: Vec<Option<u64>> = opened.iter().map(|(b, _, _)| close_of(b)).collect();
        let last_close = if every_box && box_closes.iter().all(Option::is_some) {
            box_closes.iter().flatten().max().copied()
        } else {
            None
        };
        let no_batches = Batches::default();
        for (key, lw) in &station_links {
            let mut packages = BTreeSet::new();
            let mut batches = None;
            let (opening, close, closing, start, end) = match lw.info.device {
                LinkDevice::Box(b) => {
                    for e in index.box_events(b.as_bytes()) {
                        if e.schema == SCHEMA_CAST_RECORD
                            && let Some(r) = e.bytes.and_then(|bytes| {
                                decode_object::<CastRecord<'_>>(
                                    SCHEMA_CAST_RECORD,
                                    SCHEMA_VERSION_1,
                                    bytes,
                                )
                                .ok()
                            })
                        {
                            packages.insert(r.body().share_package_hash().0);
                        }
                    }
                    batches = Some(batches_of(index, records, b.as_bytes()));
                    let close = close_slot(index, b.as_bytes());
                    let first = opening_of(index, b.as_bytes());
                    let opening = first.map(|(_, slot)| slot);
                    let closing = opening.and(close_of(b.as_bytes()));
                    // Each frame key from the event that brought it in to
                    // the one that brought in the next.
                    let keys = box_keys(genesis, index, b.as_bytes(), first.map(|(seq, _)| seq));
                    let k = keys.iter().position(|(l, _)| l == key).unwrap_or(0);
                    let intro = keys.get(k).map_or(Intro::Opening, |(_, i)| *i);
                    let end = match keys.get(k.saturating_add(1)) {
                        Some((_, Intro::Swap(at))) => SpanEnd::Swap(*at),
                        Some((_, Intro::Opening)) => {
                            opening.map_or(SpanEnd::LastFrame, SpanEnd::Swap)
                        }
                        None if lw.info.current => SpanEnd::To(closing.or(last_window)),
                        Some((_, Intro::Unknown)) | None => SpanEnd::LastFrame,
                    };
                    (
                        opening,
                        close,
                        closing,
                        start_of(intro, opening, closed),
                        end,
                    )
                }
                LinkDevice::Unit(u) => {
                    // The station's last close once every opened box closed,
                    // its last session's last slot while one is open; from
                    // and to the swaps that bring the unit in and take it
                    // out.
                    let from_opening = unit_from_opening(
                        genesis,
                        index,
                        station_id.as_bytes(),
                        u.as_bytes(),
                        station_opened,
                    );
                    let (brought, taken) =
                        unit_swaps(index, station_id.as_bytes(), u.as_bytes(), from_opening);
                    let intro = if from_opening {
                        Intro::Opening
                    } else {
                        brought.map_or(Intro::Unknown, Intro::Swap)
                    };
                    let end = match taken {
                        Some(at) => SpanEnd::Swap(at),
                        None if lw.info.current || brought.is_some() => {
                            SpanEnd::To(last_close.or(last_window))
                        }
                        None => SpanEnd::LastFrame,
                    };
                    (
                        station_opening,
                        None,
                        last_close,
                        start_of(intro, station_opening, closed),
                        end,
                    )
                }
            };
            let batches = batches.unwrap_or_default();
            let ctx = LinkContext {
                entry: manifest.frame_link(lw.info.class()),
                opening,
                close,
                closing,
                start: start.slot,
                start_known: start.known,
                swapped_in: start.swapped_in,
                never_brought: start.never_brought,
                end,
                public: &public,
                on_ledger: &on_ledger,
                scopes: &scopes,
                packages: if packages.is_empty() {
                    &no_packages
                } else {
                    &packages
                },
                batches: if batches.by_hash.is_empty() && batches.challenged.is_empty() {
                    &no_batches
                } else {
                    &batches
                },
                package_len,
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
            let judged = judge_frames(lw, &ctx, &windows, &mut report);
            included.insert(*key, judge_objects(lw, &ctx, &judged, &mut report));
            let (short, gap) = (judged.short, judged.gap);
            let first_frame = report.slots.map(|(a, _)| a);
            let last_frame = report.slots.map(|(_, b)| b);
            // Missing slots against every session's declaration (none when
            // the session does not list the link). While the link's start
            // is not the ledger's (its opening or swap not laid yet), the
            // slots of a window before its first frame may be its own and
            // lost: the session may count them too. While the gateway has
            // not closed, a swap that ends the link may not be laid yet:
            // the session need not count its slots after its last frame.
            for session in &st.sessions {
                let Some(declared) = st
                    .declared
                    .get(&(*key, session.session_index))
                    .copied()
                    .unwrap_or(Some(0))
                else {
                    continue;
                };
                let counted = if session.start_slot <= session.end_slot {
                    short.range(session.start_slot..=session.end_slot).count()
                } else {
                    0
                };
                let counted = u64::try_from(counted).unwrap_or(u64::MAX);
                let unknown = match first_frame {
                    Some(f) if !ctx.start_known => f.saturating_sub(session.start_slot).min(
                        session
                            .end_slot
                            .saturating_sub(session.start_slot)
                            .saturating_add(1),
                    ),
                    _ => 0,
                };
                let trailing = match last_frame {
                    Some(b) if !closed => {
                        let from = session.start_slot.max(b.saturating_add(1));
                        if from <= session.end_slot {
                            short.range(from..=session.end_slot).count()
                        } else {
                            0
                        }
                    }
                    _ => 0,
                };
                let trailing = u64::try_from(trailing).unwrap_or(u64::MAX);
                let declared = u64::from(declared);
                if declared < counted.saturating_sub(trailing)
                    || declared > counted.saturating_add(unknown)
                {
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
                .chain(station_boxes.iter().flat_map(|b| index.box_events(b)))
                .filter(|e| DEVICE_EVENTS.contains(&e.schema));
            for e in device_events {
                let wanted = (e.schema.get(), e.hash.0);
                let found = station_links.iter().find(|(key, lw)| {
                    mine(e.scope, &lw.info)
                        && included.get(key).is_some_and(|set| set.contains(&wanted))
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
            .range((station_id.as_bytes(), 0, [0u8; 64])..)
            .take_while(|((s, _, _), _)| *s == station_id.as_bytes())
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
        let ranges = [(0, 10), (20, 30), (40, 50)];
        assert!(covered(&ranges, 0, 10));
        assert!(covered(&ranges, 22, 25));
        assert!(covered(&ranges, 40, 50));
        assert!(covered(&ranges, 15, 15));
        assert!(covered(&[], 7, 3));
        assert!(!covered(&ranges, 5, 21));
        assert!(!covered(&ranges, 10, 11));
        assert!(!covered(&ranges, 45, 51));
        assert!(!covered(&ranges, 35, 36));
        assert!(!covered(&[], 0, 1));
        assert_eq!(overlap(None, 0, 9), 0);
        assert_eq!(overlap(Some((5, 7)), 0, 9), 3);
        assert_eq!(overlap(Some((5, 7)), 6, 6), 1);
        assert_eq!(overlap(Some((5, 7)), 8, 9), 0);
    }

    fn object(schema: SchemaId, offset: u64, len: u32) -> StreamObject {
        StreamObject {
            schema,
            object_hash: Hash512([1; 64]),
            stream_offset: offset,
            len,
        }
    }

    fn list(objects: &[StreamObject]) -> FrameObjects<'static> {
        let mut bytes = std::vec::Vec::new();
        for o in objects {
            let mut buf = std::vec![0u8; 80];
            o.encode(&mut ityv_encoding::Writer::new(&mut buf)).unwrap();
            bytes.extend_from_slice(&buf);
        }
        FrameObjects::new(std::boxed::Box::leak(bytes.into_boxed_slice())).unwrap()
    }

    #[test]
    fn a_list_tiles_its_frames_data() {
        use LinkProblem as L;
        let r = SCHEMA_CAST_RECORD;
        let p = SCHEMA_SHARE_PACKAGE;
        let problem =
            |start, len, objects: &[StreamObject]| tiling(start, len, &list(objects)).problem;
        // Carried in, packages on chunk boundaries of the frame, carried out.
        let frame = [
            object(r, 900, 1200),
            object(p, 1000 + 4096, 100),
            object(r, 1000 + 8192, 50),
            object(p, 1000 + 12_288, 5000),
        ];
        let t = tiling(1000, 13_000, &list(&frame));
        assert_eq!(t.problem, None);
        assert_eq!(
            t.fill,
            [
                (2100, 1000 + 4096),
                (1000 + 4196, 1000 + 8192),
                (1000 + 8242, 1000 + 12_288)
            ]
        );
        // No data, no list; data, no list; a list without data.
        assert_eq!(problem(5, 0, &[]), None);
        assert_eq!(problem(5, 10, &[]), Some((L::NotObject, 5)));
        assert_eq!(problem(5, 0, &[object(r, 5, 16)]), Some((L::NotObject, 5)));
        // The first entry starts after the data or ends before it.
        assert_eq!(
            problem(100, 50, &[object(r, 101, 49)]),
            Some((L::NotObject, 100))
        );
        assert_eq!(
            problem(100, 50, &[object(r, 50, 50)]),
            Some((L::NotObject, 50))
        );
        // A gap, an entry past the data's end, a tail no entry covers.
        assert_eq!(
            problem(0, 100, &[object(r, 0, 40), object(r, 41, 59)]),
            Some((L::NotObject, 41))
        );
        assert_eq!(
            problem(0, 40, &[object(r, 0, 40), object(r, 40, 16)]),
            Some((L::NotObject, 40))
        );
        assert_eq!(
            problem(0, 100, &[object(r, 0, 99)]),
            Some((L::NotObject, 99))
        );
        assert_eq!(problem(0, 100, &[object(r, 0, 100)]), None);
        // Objects end to end leave no fill.
        let t = tiling(0, 300, &list(&[object(r, 0, 100), object(r, 100, 200)]));
        assert_eq!((t.problem, t.fill.len()), (None, 0));
        assert_eq!(problem(0, 100, &[object(r, 0, 101)]), None);
        // A package right after a record, or a record right after a
        // package, off the boundary.
        assert_eq!(
            problem(0, 5000, &[object(r, 0, 100), object(p, 100, 4900)]),
            Some((L::Alignment, 100))
        );
        assert_eq!(
            problem(0, 5000, &[object(p, 0, 100), object(r, 100, 4900)]),
            Some((L::Alignment, 100))
        );
        assert_eq!(
            problem(0, 5000, &[object(p, 0, 100), object(r, 4096, 904)]),
            None
        );
        // A package carried in at the frame's start needs no boundary; one
        // that ends where the data end needs none after it.
        assert_eq!(problem(10, 90, &[object(p, 0, 100)]), None);
        assert_eq!(
            problem(0, 100, &[object(r, 0, 60), object(p, 4096, 40)]),
            Some((L::NotObject, 4096))
        );
        // A frame past the end of the stream.
        assert_eq!(problem(u64::MAX, 2, &[]), Some((L::NotObject, u64::MAX)));
        assert_eq!(next_start(1000, 1000, true), Some(1000));
        assert_eq!(next_start(1000, 1001, true), Some(1000 + 4096));
        assert_eq!(next_start(1000, 1000 + 4096, true), Some(1000 + 4096));
        assert_eq!(next_start(1000, 1001, false), Some(1001));
        assert_eq!(next_start(1000, 999, true), None);
    }

    #[test]
    fn a_skip_needs_positions_no_frame_took() {
        let mut groups: SlotGroups = BTreeMap::new();
        groups.insert(10, (false, false, BTreeSet::from([0])));
        groups.insert(12, (true, false, BTreeSet::from([0, 1])));
        groups.insert(30, (true, true, BTreeSet::from([1])));
        let shape = Shape {
            normal: 2,
            catchup: 5,
            span: Some((10, 20)),
            witnessed: Some((30, 31)),
        };
        // Slots the device must send in.
        assert_eq!(shape.slots(10, 20), 11);
        assert_eq!(shape.slots(5, 9), 0);
        assert_eq!(shape.slots(19, 32), 2 + 2);
        assert_eq!(shape.slots(21, 20), 0);
        // Their counts: the group's shape, the catch-up count for a slot
        // with no frame, none outside.
        assert_eq!(shape.count(&groups, 10), 2);
        assert_eq!(shape.count(&groups, 12), 5);
        assert_eq!(shape.count(&groups, 11), 5);
        assert_eq!(shape.count(&groups, 25), 0);
        // Before the first frame: the slots from the start, then the
        // numbers before it.
        assert_eq!(shape.absent(&groups, None, (10, 0)), 0);
        assert_eq!(shape.absent(&groups, None, (10, 1)), 1);
        assert_eq!(shape.absent(&groups, None, (12, 1)), 2 * 5 + 1);
        // In one slot: the numbers strictly between.
        assert_eq!(shape.absent(&groups, Some((12, 0)), (12, 1)), 0);
        assert_eq!(shape.absent(&groups, Some((12, 0)), (12, 4)), 3);
        assert_eq!(shape.absent(&groups, Some((12, 3)), (12, 9)), 1);
        // Across slots: the rest of the first, the slots between, the
        // numbers before the last.
        assert_eq!(shape.absent(&groups, Some((10, 0)), (12, 0)), 1 + 5);
        assert_eq!(shape.absent(&groups, Some((10, 1)), (11, 0)), 0);
        assert_eq!(shape.absent(&groups, Some((12, 4)), (30, 0)), 8 * 5);
        assert_eq!(shape.absent(&groups, Some((20, 0)), (30, 1)), 4 + 1);
        // Going back takes no position.
        assert_eq!(shape.absent(&groups, Some((12, 0)), (10, 1)), 0);
        // Slots in both ranges count once.
        let both = Shape {
            witnessed: Some((18, 25)),
            ..shape
        };
        assert_eq!(both.slots(10, 25), 11 + 8 - 3);
        assert_eq!(both.slots(19, 19), 1);
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
