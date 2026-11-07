//! Connectivity: the manifest, uplink frames, gateway sessions and frame
//! logs, and connectivity incidents (ADR-0022, ADR-0041; PROTOCOL.md §5.8;
//! ENCODING.md §8.21–§8.24, §8.82–§8.84).
//!
//! * [`ConnectivityManifest`] (schema `0x001C`, version 2): the per-class
//!   connection policy the genesis pins by hash. One entry per device class
//!   and port; the instances are the genesis's device entries, which carry
//!   each device's frame key (ADR-0041 decisions 1 and 2).
//! * [`UplinkFrameHeader`] (schema `0x0057`): what a frame's signature and
//!   the gateway's chain cover: the frame's fields, the root of its
//!   payload's chunk tree and the hash of its object list (ADR-0041
//!   decision 3).
//! * [`UplinkFrame`] (schema `0x001D`, version 2): the 1,048,576-byte wire
//!   frame: its fields, its object list (every object that overlaps its
//!   data, at most [`MAX_FRAME_OBJECTS`]), its payload and its signature.
//!   Not a ledger event; tap observers capture it.
//! * [`UplinkSessionBody`] and [`UplinkSession`] (schemas `0x001E`,
//!   `0x001F`, version 2): a gateway's signed record of up to six slots.
//! * [`UplinkFrameLog`] (schema `0x0058`): the frames of one link in one
//!   session, their data-chunk leaves and each frame's object list.
//! * [`ConnectivityIncidentBody`] (schema `0x0059`, a witnessed body).
//!
//! This crate checks form only. The one-way rules of the manifest, the
//! signatures, the chains, the slot shapes and the stream are the
//! verifier's (`ityv-verify`'s connectivity stage).
//!
//! Versions 1 of `0x001C`–`0x001F` were specification drafts that were
//! never encoded.

use core::cmp::Ordering;

use crate::codec::{Decode, Encode};
use crate::envelope::decode as decode_object;
use crate::error::{Error, Kind};
use crate::primitives::{
    BoxId, ElectionId, GatewayId, Hash512, Ident, OrgId, SchemaId, SignerId, StationId,
};
use crate::reader::Reader;
use crate::schema::genesis::read_nonzero_hash;
use crate::schema::util::{ED25519_SIG_LEN, HYBRID_SIG_LEN, read_fixed};
use crate::schema::{SCHEMA_UPLINK_SESSION_BODY, SCHEMA_VERSION_UPLINK};
use crate::writer::Writer;

/// The fixed body length of an uplink frame (ADR-0022 decision 4).
pub const FRAME_BODY_LEN: usize = 1_048_576;

/// The most objects one frame lists: every object that overlaps its data,
/// the one carried in from the frame before and the one carried out to the
/// frame after included. A device stops filling a frame at this bound.
pub const MAX_FRAME_OBJECTS: usize = 1024;

/// The object list region of a wire frame: [`MAX_FRAME_OBJECTS`] entries
/// of [`OBJECT_ENTRY_LEN`] bytes, the unused ones zero.
pub const FRAME_OBJECTS_LEN: usize = MAX_FRAME_OBJECTS * OBJECT_ENTRY_LEN;

/// The payload of an uplink frame: the body less the header fields (87
/// bytes), the object count (2 bytes), the object list region (81,920
/// bytes) and the signature (64 bytes).
pub const MAX_PAYLOAD_LEN: usize = 966_503;

/// The length of one chunk of the payload tree.
pub const CHUNK_LEN: usize = 4096;

/// The chunks of the payload tree: the payload zero-extended to
/// [`FRAME_BODY_LEN`] bytes, in [`CHUNK_LEN`]-byte chunks.
pub const PAYLOAD_CHUNKS: usize = 256;

/// The length of an uplink slot, in minutes, counted from the election
/// epoch day.
pub const SLOT_MINUTES: u64 = 10;

/// The most frames a link may send in one slot, normal or catch-up.
pub const MAX_FRAMES_PER_SLOT: u16 = 64;

/// The most slots one session covers: an hour.
pub const MAX_SESSION_SLOTS: u64 = 6;

/// The most entries a manifest lists.
pub const MAX_MANIFEST_ENTRIES: usize = 256;

/// The longest port name.
pub const MAX_PORT_LEN: usize = 32;

/// The length of a frame key (Ed25519).
pub const FRAME_KEY_LEN: usize = 32;

/// The most links one session lists.
pub const MAX_SESSION_LINKS: usize = 16;

/// The longest embedded session body.
pub const MAX_SESSION_BODY_LEN: usize = 4096;

/// The most observer capture signatures on one session.
pub const MAX_CAPTURE_SIGS: usize = 4;

/// The most frames one log lists: six slots of
/// [`MAX_FRAMES_PER_SLOT`].
pub const MAX_LOG_FRAMES: usize = 384;

/// The most data-chunk leaves one log carries.
pub const MAX_LOG_LEAVES: usize = MAX_LOG_FRAMES * PAYLOAD_CHUNKS;

/// The most object entries one log carries: every frame's list.
pub const MAX_LOG_OBJECTS: usize = MAX_LOG_FRAMES * MAX_FRAME_OBJECTS;

/// The encoded length of one frame entry of a log.
pub const FRAME_ENTRY_LEN: usize = 153;

/// The encoded length of a frame header's body.
pub const FRAME_HEADER_LEN: usize = 215;

/// The encoded length of one object entry of a log.
pub const OBJECT_ENTRY_LEN: usize = 80;

/// The encoded length of one link entry of a session body.
pub const SESSION_LINK_LEN: usize = 156;

/// The shortest object: its header (ENCODING.md §3).
pub const MIN_OBJECT_LEN: u32 = 16;

/// Signature purpose of an uplink frame (Ed25519 only).
pub const PURPOSE_UPLINK_FRAME: &[u8] = b"uplink-frame";

/// Signature purpose of a gateway session.
pub const PURPOSE_UPLINK_SESSION: &[u8] = b"uplink-session";

/// Signature purpose of an observer's capture statement.
pub const PURPOSE_UPLINK_CAPTURE: &[u8] = b"uplink-capture";

/// Signature purpose of a connectivity incident.
pub const PURPOSE_CONNECTIVITY_INCIDENT: &[u8] = b"connectivity-incident";

/// The `carries` bit of public ledger objects of the device (records,
/// batch attestations, challenge openings, progress ticks, participation
/// sets, observer counts).
pub const CARRY_PUBLIC: u32 = 1;
/// The `carries` bit of sealed share packages.
pub const CARRY_SEALED: u32 = 1 << 1;
/// The `carries` bit of check-in counters (restricted; never on a frame
/// link, VC-084).
pub const CARRY_CHECKIN: u32 = 1 << 2;
/// The `carries` bit of device link objects.
pub const CARRY_LINK: u32 = 1 << 3;
/// The `carries` bit of checkpoints and the ledger.
pub const CARRY_LEDGER: u32 = 1 << 4;
/// The `carries` bit of roll lookups (personal data).
pub const CARRY_ROLL: u32 = 1 << 5;
/// The `carries` bit of session records.
pub const CARRY_SESSION: u32 = 1 << 6;
/// Every defined `carries` bit.
pub const CARRIES_MASK: u32 = 0x7F;

macro_rules! code_enum {
    (
        $(#[$meta:meta])*
        $name:ident { $( $(#[$vmeta:meta])* $variant:ident = $code:literal ),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[repr(u8)]
        pub enum $name {
            $( $(#[$vmeta])* $variant = $code ),+
        }

        impl $name {
            /// Every value, in code order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The wire code.
            #[must_use]
            pub const fn code(self) -> u8 {
                self as u8
            }

            /// Returns the value with wire code `code`, if defined.
            #[must_use]
            pub const fn from_code(code: u8) -> Option<Self> {
                match code {
                    $( $code => Some(Self::$variant), )+
                    _ => None,
                }
            }
        }
    };
}

code_enum! {
    /// A kind of device or system the manifest declares ports for
    /// (ENCODING.md §8.21).
    DeviceClass {
        /// The interpretation unit (해석 유닛).
        InterpretationUnit = 1,
        /// The commitment unit and the scanner's outer port.
        CommitmentUnit = 2,
        /// The check-in unit (카운터·가명 유닛).
        CheckinUnit = 3,
        /// A chamber module.
        ChamberModule = 4,
        /// An election-day identity terminal.
        IdTerminalElectionDay = 5,
        /// An early-voting identity terminal.
        IdTerminalEarlyVoting = 6,
        /// The station gateway.
        Gateway = 7,
        /// An observation tap.
        Tap = 8,
        /// The ledger collection server.
        LedgerCollector = 9,
        /// The public board server.
        BoardPublisher = 10,
        /// A witness.
        Witness = 11,
        /// A trustee's receiving system.
        TrusteeReceiver = 12,
        /// A receipt label reader.
        ReceiptReader = 13,
        /// An imprint reader.
        ImprintReader = 14,
        /// A printer (imprinter, slip, label).
        Printer = 15,
    }
}

impl DeviceClass {
    /// Whether the class is a TCB device that must have no inbound path
    /// and no radio (PROTOCOL.md §5.8 item 1).
    #[must_use]
    pub const fn is_tcb(self) -> bool {
        matches!(
            self,
            Self::InterpretationUnit
                | Self::CommitmentUnit
                | Self::CheckinUnit
                | Self::ChamberModule
        )
    }
}

code_enum! {
    /// The direction of a port.
    Direction {
        /// None: sealed or not fitted.
        None = 0,
        /// Out only: no receiving element.
        OutOnly = 1,
        /// In only.
        InOnly = 2,
        /// Both ways.
        Both = 3,
    }
}

code_enum! {
    /// The medium of a port.
    Medium {
        /// None.
        None = 0,
        /// An optical transmitter with no receiver.
        OpticalTransmit = 1,
        /// An optocoupler inside the device.
        Optocoupler = 2,
        /// Wired Ethernet.
        Ethernet = 3,
        /// An optical line.
        OpticalLine = 4,
        /// The election's dedicated line (the integrated roll).
        ElectionLine = 5,
        /// A direct on-site link under witnesses.
        OnSiteDirect = 6,
        /// Wireless.
        Wireless = 7,
    }
}

code_enum! {
    /// When a port is used.
    Schedule {
        /// Not used.
        Unused = 0,
        /// From the box's opening to its close processing.
        BoxOpenToClose = 1,
        /// During early voting.
        EarlyVoting = 2,
        /// Always.
        Always = 3,
        /// Only during a witnessed procedure.
        Witnessed = 4,
    }
}

code_enum! {
    /// The kind of an uplink frame.
    FrameKind {
        /// A normal frame of the fixed schedule.
        Normal = 0,
        /// A catch-up frame after a recorded loss.
        CatchUp = 1,
        /// The resend of the whole box at close.
        CloseResend = 2,
        /// A witnessed resend at the counting centre.
        WitnessedResend = 3,
    }
}

impl FrameKind {
    /// Whether a frame of this kind is numbered below the catch-up count
    /// (every kind but [`Self::Normal`]).
    #[must_use]
    pub const fn uses_catchup(self) -> bool {
        !matches!(self, Self::Normal)
    }
}

code_enum! {
    /// What a connectivity incident records (ADR-0041 decision 11).
    IncidentKind {
        /// A connection the manifest does not declare.
        UndeclaredConnection = 1,
        /// An inbound path or a radio on a TCB device.
        InboundOrRadio = 2,
        /// A frame off its schedule or size.
        FrameOffSchedule = 3,
        /// Bytes that are not canonical objects.
        NonCanonicalBytes = 4,
        /// A capture that disagrees with the published chain.
        CaptureMismatch = 5,
        /// A carrier record that disagrees with the sessions.
        CarrierMismatch = 6,
        /// The roll lookup line connected outside its declared window.
        RollLineOutsideWindow = 7,
        /// A transmission nobody can explain.
        UnexplainedTransmission = 8,
        /// A teardown finding.
        TeardownFinding = 9,
        /// A radio check finding.
        RadioCheckFinding = 10,
    }
}

fn read_code<T>(r: &mut Reader<'_>, from: impl Fn(u8) -> Option<T>) -> Result<T, Error> {
    let at = r.position();
    from(r.read_u8()?).ok_or_else(|| Error::new(Kind::ValueOutOfRange, at))
}

fn invalid(at: usize) -> Error {
    Error::new(Kind::InvariantViolation, at)
}

fn ident_len(id: &Ident<'_>) -> usize {
    id.byte_len().saturating_add(4)
}

// ---------------------------------------------------------------------------
// 0x001C ConnectivityManifest

/// One port of one device class (ENCODING.md §8.21).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ManifestEntry<'a> {
    /// The device class.
    pub device_class: DeviceClass,
    /// The port's name (at most [`MAX_PORT_LEN`] bytes).
    pub port: Ident<'a>,
    /// Its direction.
    pub direction: Direction,
    /// Its medium.
    pub medium: Medium,
    /// The class at the other end, or `None` for a party outside the
    /// system (named in `counterpart`).
    pub peer_class: Option<DeviceClass>,
    /// The other end, for people.
    pub counterpart: Ident<'a>,
    /// When it is used.
    pub schedule: Schedule,
    /// Normal frames per slot (0 for a port that sends no frames).
    pub frames_per_slot: u16,
    /// Catch-up frames per slot (0 for a port that sends no frames).
    pub catchup_frames_per_slot: u16,
    /// What it carries, as `CARRY_*` bits.
    pub carries: u32,
}

impl ManifestEntry<'_> {
    /// Whether the entry declares a frame link.
    #[must_use]
    pub const fn sends_frames(&self) -> bool {
        self.frames_per_slot > 0
    }

    /// The entry's key: its class and port.
    #[must_use]
    pub fn key(&self) -> (u8, &[u8]) {
        (self.device_class.code(), self.port.as_bytes())
    }

    /// Whether the frame counts are in form: none, or
    /// `1 ≤ frames ≤ catch-up ≤ 64`.
    #[must_use]
    pub const fn counts_valid(&self) -> bool {
        if self.frames_per_slot == 0 {
            self.catchup_frames_per_slot == 0
        } else {
            self.frames_per_slot <= self.catchup_frames_per_slot
                && self.catchup_frames_per_slot <= MAX_FRAMES_PER_SLOT
        }
    }
}

/// The fixed-width fields of a manifest entry: class, direction, medium,
/// peer class and schedule (one byte each), the two frame counts (two
/// each) and `carries` (four).
const ENTRY_FIXED_LEN: usize = 13;

impl Encode for ManifestEntry<'_> {
    fn encoded_len(&self) -> usize {
        ident_len(&self.port)
            .saturating_add(ident_len(&self.counterpart))
            .saturating_add(ENTRY_FIXED_LEN)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_u8(self.device_class.code())?;
        w.write_ident(&self.port, MAX_PORT_LEN)?;
        w.write_u8(self.direction.code())?;
        w.write_u8(self.medium.code())?;
        w.write_u8(self.peer_class.map_or(0, DeviceClass::code))?;
        w.write_ident(&self.counterpart, crate::primitives::IDENT_MAX_STANDARD)?;
        w.write_u8(self.schedule.code())?;
        w.write_u16(self.frames_per_slot)?;
        w.write_u16(self.catchup_frames_per_slot)?;
        w.write_u32(self.carries)
    }
}

impl<'a> Decode<'a> for ManifestEntry<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let device_class = read_code(r, DeviceClass::from_code)?;
        let port = r.read_ident(MAX_PORT_LEN)?;
        let direction = read_code(r, Direction::from_code)?;
        let medium = read_code(r, Medium::from_code)?;
        let peer_at = r.position();
        let peer = r.read_u8()?;
        let peer_class = if peer == 0 {
            None
        } else {
            Some(
                DeviceClass::from_code(peer)
                    .ok_or_else(|| Error::new(Kind::ValueOutOfRange, peer_at))?,
            )
        };
        let counterpart = r.read_ident(crate::primitives::IDENT_MAX_STANDARD)?;
        let schedule = read_code(r, Schedule::from_code)?;
        let frames_at = r.position();
        let frames_per_slot = r.read_u16()?;
        let catchup_frames_per_slot = r.read_u16()?;
        let carries_at = r.position();
        let carries = r.read_u32()?;
        let entry = Self {
            device_class,
            port,
            direction,
            medium,
            peer_class,
            counterpart,
            schedule,
            frames_per_slot,
            catchup_frames_per_slot,
            carries,
        };
        if !entry.counts_valid() {
            return Err(Error::new(Kind::ValueOutOfRange, frames_at));
        }
        if carries & !CARRIES_MASK != 0 {
            return Err(Error::new(Kind::ValueOutOfRange, carries_at));
        }
        Ok(entry)
    }
}

/// The manifest's entries, borrowed as their encoded bytes: one to
/// [`MAX_MANIFEST_ENTRIES`] canonical entries strictly ascending by class,
/// then port bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ManifestEntries<'a> {
    bytes: &'a [u8],
    count: u16,
}

impl<'a> ManifestEntries<'a> {
    /// The entries encoded in `bytes` (without the count prefix). `None`
    /// unless they are one to [`MAX_MANIFEST_ENTRIES`] canonical entries in
    /// strictly ascending key order with nothing left over.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        let mut count = 0usize;
        let mut previous: Option<ManifestEntry<'a>> = None;
        while !r.is_empty() {
            let entry = ManifestEntry::decode(&mut r).ok()?;
            if previous.is_some_and(|p| p.key() >= entry.key()) {
                return None;
            }
            previous = Some(entry);
            count = count.checked_add(1)?;
        }
        if count == 0 || count > MAX_MANIFEST_ENTRIES {
            return None;
        }
        Some(Self {
            bytes,
            count: u16::try_from(count).ok()?,
        })
    }

    /// The encoded entries.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.count)
    }

    /// Always `false`: a manifest has at least one entry.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The entries in key order.
    pub fn iter(&self) -> impl Iterator<Item = ManifestEntry<'a>> + use<'a> {
        let mut r = Reader::new(self.bytes);
        core::iter::from_fn(move || {
            if r.is_empty() {
                None
            } else {
                ManifestEntry::decode(&mut r).ok()
            }
        })
    }
}

/// The connectivity manifest (schema `0x001C`, version 2; ADR-0041
/// decision 1).
///
/// Rules: one to 256 entries strictly ascending by (class, port)
/// (`NotSorted`, `Duplicate`, `InvariantViolation` for none,
/// `CountExceedsMax`); every code in range and the peer class 0 or a class
/// (`ValueOutOfRange`); the frame counts none or `1 ≤ frames ≤ catch-up ≤
/// 64`, and no undefined `carries` bit (`ValueOutOfRange`). The one-way
/// rules and the coverage of every class (VC-077) are the verifier's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectivityManifest<'a> {
    election_id: ElectionId<'a>,
    entries: ManifestEntries<'a>,
}

impl<'a> ConnectivityManifest<'a> {
    /// Builds the manifest.
    #[must_use]
    pub const fn new(election_id: ElectionId<'a>, entries: ManifestEntries<'a>) -> Self {
        Self {
            election_id,
            entries,
        }
    }

    /// The election.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.election_id
    }

    /// The entries.
    #[must_use]
    pub const fn entries(&self) -> &ManifestEntries<'a> {
        &self.entries
    }

    /// The entry of `class` that sends frames, if exactly one does.
    #[must_use]
    pub fn frame_link(&self, class: DeviceClass) -> Option<ManifestEntry<'a>> {
        let mut found = None;
        for e in self.entries.iter() {
            if e.device_class == class && e.sends_frames() {
                if found.is_some() {
                    return None;
                }
                found = Some(e);
            }
        }
        found
    }
}

impl Encode for ConnectivityManifest<'_> {
    fn encoded_len(&self) -> usize {
        self.election_id
            .encoded_len()
            .saturating_add(4)
            .saturating_add(self.entries.bytes.len())
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.election_id.encode(w)?;
        w.write_count(self.entries.len(), MAX_MANIFEST_ENTRIES)?;
        w.write_slice(self.entries.bytes)
    }
}

impl<'a> Decode<'a> for ConnectivityManifest<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let count_at = r.position();
        let count = r.read_count(MAX_MANIFEST_ENTRIES)?;
        if count == 0 {
            return Err(invalid(count_at));
        }
        let start = r.position();
        let mut previous: Option<ManifestEntry<'a>> = None;
        for _ in 0..count {
            let at = r.position();
            let entry = ManifestEntry::decode(r)?;
            if let Some(p) = previous {
                match p.key().cmp(&entry.key()) {
                    Ordering::Less => {}
                    Ordering::Equal => return Err(Error::new(Kind::Duplicate, at)),
                    Ordering::Greater => return Err(Error::new(Kind::NotSorted, at)),
                }
            }
            previous = Some(entry);
        }
        let bytes = r.consumed_from(start)?;
        Ok(Self {
            election_id,
            entries: ManifestEntries {
                bytes,
                count: u16::try_from(count)
                    .map_err(|_| Error::new(Kind::CountExceedsMax, count_at))?,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// 0x0057 UplinkFrameHeader

/// The fields of a frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UplinkFrameHeaderParts {
    /// The link: `SHA3-512("ityv:link:v1" ‖ 0x00 ‖ frame_key)`.
    pub link_id_hash: Hash512,
    /// The 10-minute slot since the election epoch day.
    pub slot: u64,
    /// The frame's number in its slot.
    pub index: u16,
    /// Its kind.
    pub kind: FrameKind,
    /// Where its payload starts in the link's byte stream.
    pub stream_offset: u64,
    /// How many payload bytes are data (the rest are zero).
    pub payload_len: u32,
    /// The root of the payload's chunk tree (ADR-0041 decision 3).
    pub payload_root: Hash512,
    /// The hash of the frame's object list
    /// (`ityv_crypto::uplink::objects_hash` of its encoded entries).
    pub objects_hash: Hash512,
}

impl UplinkFrameHeaderParts {
    /// Whether the fields are in form: an index below
    /// [`MAX_FRAMES_PER_SLOT`] and a payload length at most
    /// [`MAX_PAYLOAD_LEN`].
    #[must_use]
    pub fn valid(&self) -> bool {
        self.index < MAX_FRAMES_PER_SLOT
            && usize::try_from(self.payload_len).is_ok_and(|n| n <= MAX_PAYLOAD_LEN)
    }

    /// The number of chunks that hold data: `⌈payload_len / 4096⌉`.
    #[must_use]
    pub fn data_chunks(&self) -> usize {
        data_chunks(self.payload_len)
    }
}

/// `⌈len / 4096⌉`.
#[must_use]
pub fn data_chunks(len: u32) -> usize {
    let n = usize::try_from(len).unwrap_or(usize::MAX);
    n.div_ceil(CHUNK_LEN)
}

/// An uplink frame's header (schema `0x0057`): what the device signs and
/// the gateway chains.
///
/// Rules: the kind in range, the index below 64 and the payload length at
/// most [`MAX_PAYLOAD_LEN`] (`ValueOutOfRange`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UplinkFrameHeader {
    parts: UplinkFrameHeaderParts,
}

impl UplinkFrameHeader {
    /// Builds the header.
    ///
    /// # Errors
    /// `ValueOutOfRange` at 0 if a field is out of range.
    pub fn new(parts: &UplinkFrameHeaderParts) -> Result<Self, Error> {
        if parts.valid() {
            Ok(Self { parts: *parts })
        } else {
            Err(Error::new(Kind::ValueOutOfRange, 0))
        }
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &UplinkFrameHeaderParts {
        &self.parts
    }
}

fn write_frame_fields(w: &mut Writer<'_>, p: &UplinkFrameHeaderParts) -> Result<(), Error> {
    p.link_id_hash.encode(w)?;
    write_position(w, p)
}

/// Writes slot, index, kind, stream offset and payload length.
fn write_position(w: &mut Writer<'_>, p: &UplinkFrameHeaderParts) -> Result<(), Error> {
    w.write_u64(p.slot)?;
    w.write_u16(p.index)?;
    w.write_u8(p.kind.code())?;
    w.write_u64(p.stream_offset)?;
    w.write_u32(p.payload_len)
}

/// Reads slot, index, kind, stream offset and payload length, with
/// `link_id_hash` and a zero root and object hash.
fn read_position(
    r: &mut Reader<'_>,
    link_id_hash: Hash512,
) -> Result<UplinkFrameHeaderParts, Error> {
    let slot = r.read_u64()?;
    let index_at = r.position();
    let index = r.read_u16()?;
    if index >= MAX_FRAMES_PER_SLOT {
        return Err(Error::new(Kind::ValueOutOfRange, index_at));
    }
    let kind = read_code(r, FrameKind::from_code)?;
    let stream_offset = r.read_u64()?;
    let len_at = r.position();
    let payload_len = r.read_u32()?;
    if !usize::try_from(payload_len).is_ok_and(|n| n <= MAX_PAYLOAD_LEN) {
        return Err(Error::new(Kind::ValueOutOfRange, len_at));
    }
    Ok(UplinkFrameHeaderParts {
        link_id_hash,
        slot,
        index,
        kind,
        stream_offset,
        payload_len,
        payload_root: Hash512::ZERO,
        objects_hash: Hash512::ZERO,
    })
}

impl Encode for UplinkFrameHeader {
    fn encoded_len(&self) -> usize {
        FRAME_HEADER_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        write_frame_fields(w, &self.parts)?;
        self.parts.payload_root.encode(w)?;
        self.parts.objects_hash.encode(w)
    }
}

impl<'a> Decode<'a> for UplinkFrameHeader {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let link_id_hash = Hash512::decode(r)?;
        let mut parts = read_position(r, link_id_hash)?;
        parts.payload_root = Hash512::decode(r)?;
        parts.objects_hash = Hash512::decode(r)?;
        Ok(Self { parts })
    }
}

// ---------------------------------------------------------------------------
// 0x001D UplinkFrame

/// An uplink frame on the wire (schema `0x001D`, version 2): the header
/// fields, the object count and the 81,920-byte object list region, the
/// 966,503-byte payload and the device's signature over the frame's
/// [`UplinkFrameHeader`] (purpose `uplink-frame`), whose `objects_hash` is
/// the hash of the listed entries.
///
/// Rules: the header fields as [`UplinkFrameHeader`] (`ValueOutOfRange`);
/// at most [`MAX_FRAME_OBJECTS`] objects (`ValueOutOfRange` at the count),
/// listed as [`FrameObjects`] requires; every byte of the region after the
/// listed entries is zero, and every payload byte from `payload_len` on is
/// zero (`InvariantViolation` at the first that is not).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UplinkFrame<'a> {
    parts: UplinkFrameHeaderParts,
    objects: FrameObjects<'a>,
    payload: &'a [u8; MAX_PAYLOAD_LEN],
    frame_sig: &'a [u8; ED25519_SIG_LEN],
}

/// The offset of the first nonzero byte at or after `from` in `payload`.
fn first_nonzero(payload: &[u8], from: usize) -> Option<usize> {
    let tail = payload.get(from..)?;
    let at = tail.iter().position(|b| *b != 0)?;
    from.checked_add(at)
}

impl<'a> UplinkFrame<'a> {
    /// Builds a frame. The header's `payload_root` and `objects_hash` are
    /// ignored (the wire frame does not carry them; the receiver computes
    /// them).
    ///
    /// # Errors
    /// `ValueOutOfRange` at 0 for a header field out of range,
    /// `InvariantViolation` at 0 if a byte after `payload_len` is not zero.
    pub fn new(
        parts: &UplinkFrameHeaderParts,
        objects: FrameObjects<'a>,
        payload: &'a [u8; MAX_PAYLOAD_LEN],
        frame_sig: &'a [u8; ED25519_SIG_LEN],
    ) -> Result<Self, Error> {
        if !parts.valid() {
            return Err(Error::new(Kind::ValueOutOfRange, 0));
        }
        let len = usize::try_from(parts.payload_len).map_err(|_| invalid(0))?;
        if first_nonzero(payload, len).is_some() {
            return Err(invalid(0));
        }
        let mut parts = *parts;
        parts.payload_root = Hash512::ZERO;
        parts.objects_hash = Hash512::ZERO;
        Ok(Self {
            parts,
            objects,
            payload,
            frame_sig,
        })
    }

    /// The header fields, with a zero `payload_root` and `objects_hash`.
    #[must_use]
    pub const fn fields(&self) -> &UplinkFrameHeaderParts {
        &self.parts
    }

    /// The object list.
    #[must_use]
    pub const fn objects(&self) -> FrameObjects<'a> {
        self.objects
    }

    /// The whole payload.
    #[must_use]
    pub const fn payload(&self) -> &'a [u8; MAX_PAYLOAD_LEN] {
        self.payload
    }

    /// The data bytes: the first `payload_len` of the payload.
    #[must_use]
    pub fn data(&self) -> &'a [u8] {
        let len = usize::try_from(self.parts.payload_len).unwrap_or(0);
        self.payload.get(..len).unwrap_or(&[])
    }

    /// The device's signature.
    #[must_use]
    pub const fn frame_sig(&self) -> &'a [u8; ED25519_SIG_LEN] {
        self.frame_sig
    }
}

impl Encode for UplinkFrame<'_> {
    fn encoded_len(&self) -> usize {
        FRAME_BODY_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        write_frame_fields(w, &self.parts)?;
        let count = self.objects.len();
        w.write_u16(u16::try_from(count).map_err(|_| Error::new(Kind::CountExceedsMax, 0))?)?;
        w.write_slice(self.objects.bytes)?;
        for _ in count..MAX_FRAME_OBJECTS {
            w.write_array(&[0u8; OBJECT_ENTRY_LEN])?;
        }
        w.write_array(self.payload)?;
        w.write_array(self.frame_sig)
    }
}

impl<'a> Decode<'a> for UplinkFrame<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let link_id_hash = Hash512::decode(r)?;
        let parts = read_position(r, link_id_hash)?;
        let objects = read_object_region(r)?;
        let payload_at = r.position();
        let payload = read_fixed::<MAX_PAYLOAD_LEN>(r)?;
        let len = usize::try_from(parts.payload_len).map_err(|_| invalid(payload_at))?;
        if let Some(at) = first_nonzero(payload, len) {
            return Err(invalid(payload_at.saturating_add(at)));
        }
        Ok(Self {
            parts,
            objects,
            payload,
            frame_sig: read_fixed::<ED25519_SIG_LEN>(r)?,
        })
    }
}

/// Reads a wire frame's object count and region: the listed entries as
/// [`FrameObjects`] requires, then zeros to the region's end.
fn read_object_region<'a>(r: &mut Reader<'a>) -> Result<FrameObjects<'a>, Error> {
    let count_at = r.position();
    let count = usize::from(r.read_u16()?);
    if count > MAX_FRAME_OBJECTS {
        return Err(Error::new(Kind::ValueOutOfRange, count_at));
    }
    let start = r.position();
    read_frame_objects(r, count)?;
    let objects = FrameObjects {
        bytes: r.consumed_from(start)?,
    };
    let rest_at = r.position();
    let used = objects.bytes.len();
    let rest = r.take(FRAME_OBJECTS_LEN.saturating_sub(used))?;
    if let Some(at) = first_nonzero(rest, 0) {
        return Err(invalid(rest_at.saturating_add(at)));
    }
    Ok(objects)
}

// ---------------------------------------------------------------------------
// 0x001E UplinkSessionBody

/// One link of a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionLink {
    /// The link.
    pub link_id_hash: Hash512,
    /// Normal frames received in the session.
    pub frames: u64,
    /// Catch-up, close-resend and witnessed-resend frames received.
    pub catchup_frames: u64,
    /// Slots of the session in which the link sent fewer frames than its
    /// shape.
    pub missing_slots: u32,
    /// The end of the stream received so far: the last frame's
    /// `stream_offset + payload_len`.
    pub stream_end: u64,
    /// The link's chain head after the session's frames.
    pub chain_head: Hash512,
}

impl Encode for SessionLink {
    fn encoded_len(&self) -> usize {
        SESSION_LINK_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.link_id_hash.encode(w)?;
        w.write_u64(self.frames)?;
        w.write_u64(self.catchup_frames)?;
        w.write_u32(self.missing_slots)?;
        w.write_u64(self.stream_end)?;
        self.chain_head.encode(w)
    }
}

impl<'a> Decode<'a> for SessionLink {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            link_id_hash: Hash512::decode(r)?,
            frames: r.read_u64()?,
            catchup_frames: r.read_u64()?,
            missing_slots: r.read_u32()?,
            stream_end: r.read_u64()?,
            chain_head: Hash512::decode(r)?,
        })
    }
}

/// A fixed-width view: `bytes` holds whole entries of `N` bytes.
fn fixed_count<const N: usize>(bytes: &[u8]) -> usize {
    bytes.len().checked_div(N).unwrap_or(0)
}

/// The links of a session, borrowed as [`SESSION_LINK_LEN`]-byte entries
/// strictly ascending by link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionLinks<'a> {
    bytes: &'a [u8],
}

impl<'a> SessionLinks<'a> {
    /// No link.
    pub const EMPTY: SessionLinks<'static> = SessionLinks { bytes: &[] };

    /// The links encoded in `bytes`. `None` unless whole entries, at most
    /// [`MAX_SESSION_LINKS`], strictly ascending by link.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        let count = fixed_count::<SESSION_LINK_LEN>(bytes);
        if bytes.len().checked_rem(SESSION_LINK_LEN) != Some(0) || count > MAX_SESSION_LINKS {
            return None;
        }
        let mut r = Reader::new(bytes);
        read_links(&mut r, count).ok()?;
        Some(Self { bytes })
    }

    /// The encoded entries.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The number of links.
    #[must_use]
    pub fn len(&self) -> usize {
        fixed_count::<SESSION_LINK_LEN>(self.bytes)
    }

    /// Whether there is none.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The links in order.
    pub fn iter(&self) -> impl Iterator<Item = SessionLink> + use<'a> {
        self.bytes.chunks_exact(SESSION_LINK_LEN).filter_map(|c| {
            let mut r = Reader::new(c);
            SessionLink::decode(&mut r).ok()
        })
    }
}

fn read_links(r: &mut Reader<'_>, count: usize) -> Result<(), Error> {
    let mut previous: Option<Hash512> = None;
    for _ in 0..count {
        let at = r.position();
        let link = SessionLink::decode(r)?;
        Reader::check_ascending(
            previous.as_ref().map(|h| h.as_bytes().as_slice()),
            link.link_id_hash.as_bytes(),
            at,
        )?;
        previous = Some(link.link_id_hash);
    }
    Ok(())
}

/// The fields of a session body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UplinkSessionParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The station.
    pub station_id: StationId<'a>,
    /// The station's gateway.
    pub gateway_id: GatewayId<'a>,
    /// The session's number for the gateway, from 1.
    pub session_index: u32,
    /// Whether this is the gateway's last session.
    pub is_final: bool,
    /// The first slot it covers.
    pub start_slot: u64,
    /// The last slot it covers (at most five after the first).
    pub end_slot: u64,
    /// Its links.
    pub links: SessionLinks<'a>,
    /// Bytes the gateway sent on its outer line during the session.
    pub wan_bytes: u64,
    /// Object hash of the previous session body (zero for the first).
    pub previous_session_hash: Hash512,
}

/// A gateway session body (schema `0x001E`, version 2).
///
/// Rules: the session number is at least 1 and the previous hash zero
/// exactly for the first (`ValueOutOfRange`, `InvalidPreviousHash`); the
/// window `start ≤ end ≤ start + 5` (`InvariantViolation`); at most 16
/// links strictly ascending (`CountExceedsMax`, `NotSorted`, `Duplicate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UplinkSessionBody<'a> {
    parts: UplinkSessionParts<'a>,
}

fn window_valid(start: u64, end: u64) -> bool {
    end.checked_sub(start)
        .is_some_and(|span| span < MAX_SESSION_SLOTS)
}

impl<'a> UplinkSessionBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// The rule violated, at offset 0.
    pub fn new(parts: &UplinkSessionParts<'a>) -> Result<Self, Error> {
        if parts.session_index == 0 {
            return Err(Error::new(Kind::ValueOutOfRange, 0));
        }
        if (parts.session_index == 1) != parts.previous_session_hash.is_zero() {
            return Err(Error::new(Kind::InvalidPreviousHash, 0));
        }
        if !window_valid(parts.start_slot, parts.end_slot) {
            return Err(invalid(0));
        }
        Ok(Self { parts: *parts })
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &UplinkSessionParts<'a> {
        &self.parts
    }
}

impl Encode for UplinkSessionBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.station_id.encoded_len())
            .saturating_add(p.gateway_id.encoded_len())
            .saturating_add(4 + 1 + 8 + 8 + 4)
            .saturating_add(p.links.bytes.len())
            .saturating_add(8 + 64)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.station_id.encode(w)?;
        p.gateway_id.encode(w)?;
        w.write_u32(p.session_index)?;
        w.write_bool(p.is_final)?;
        w.write_u64(p.start_slot)?;
        w.write_u64(p.end_slot)?;
        w.write_count(p.links.len(), MAX_SESSION_LINKS)?;
        w.write_slice(p.links.bytes)?;
        w.write_u64(p.wan_bytes)?;
        p.previous_session_hash.encode(w)
    }
}

impl<'a> Decode<'a> for UplinkSessionBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let station_id = StationId::decode(r)?;
        let gateway_id = GatewayId::decode(r)?;
        let index_at = r.position();
        let session_index = r.read_u32()?;
        if session_index == 0 {
            return Err(Error::new(Kind::ValueOutOfRange, index_at));
        }
        let is_final = r.read_bool()?;
        let start_slot = r.read_u64()?;
        let end_at = r.position();
        let end_slot = r.read_u64()?;
        if !window_valid(start_slot, end_slot) {
            return Err(invalid(end_at));
        }
        let count = r.read_count(MAX_SESSION_LINKS)?;
        let start = r.position();
        read_links(r, count)?;
        let links = SessionLinks {
            bytes: r.consumed_from(start)?,
        };
        let wan_bytes = r.read_u64()?;
        let previous_at = r.position();
        let previous_session_hash = Hash512::decode(r)?;
        if (session_index == 1) != previous_session_hash.is_zero() {
            return Err(Error::new(Kind::InvalidPreviousHash, previous_at));
        }
        Ok(Self {
            parts: UplinkSessionParts {
                election_id,
                station_id,
                gateway_id,
                session_index,
                is_final,
                start_slot,
                end_slot,
                links,
                wan_bytes,
                previous_session_hash,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// 0x001F UplinkSession

/// One observer's capture statement on a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CaptureSig<'a> {
    /// The observer, as on the roster.
    pub observer_id: SignerId<'a>,
    /// The observer's organisation.
    pub org_id: OrgId<'a>,
    /// `SHA3-512("ityv:capture:v1" ‖ 0x00 ‖ capture file)`.
    pub capture_hash: Hash512,
    /// The observer's hybrid signature over the [`CaptureMessage`].
    pub sig: &'a [u8; HYBRID_SIG_LEN],
}

/// What an observer signs (purpose `uplink-capture`), as a header-less
/// field group: the session body's object hash, the observer and the
/// capture's hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CaptureMessage<'a> {
    /// The session body's object hash.
    pub body_hash: Hash512,
    /// The observer.
    pub observer_id: SignerId<'a>,
    /// The capture's hash.
    pub capture_hash: Hash512,
}

impl Encode for CaptureMessage<'_> {
    fn encoded_len(&self) -> usize {
        self.observer_id.encoded_len().saturating_add(128)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.body_hash.encode(w)?;
        self.observer_id.encode(w)?;
        self.capture_hash.encode(w)
    }
}

/// A gateway session (schema `0x001F`, version 2): the body object bytes,
/// the gateway's hybrid signature over them (purpose `uplink-session`) and
/// up to four observers' capture statements.
///
/// Rules: the body is a canonical `UplinkSessionBody` of at most 4,096
/// bytes (its own errors, rebased); at most four observer entries strictly
/// ascending by observer (`CountExceedsMax`, `NotSorted`, `Duplicate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UplinkSession<'a> {
    body_bytes: &'a [u8],
    body: UplinkSessionBody<'a>,
    gateway_sig: &'a [u8; HYBRID_SIG_LEN],
    observers: [Option<CaptureSig<'a>>; MAX_CAPTURE_SIGS],
    observer_count: u8,
}

impl<'a> UplinkSession<'a> {
    /// Builds a session from the encoded body.
    ///
    /// # Errors
    /// The body's decoding error, `LengthExceedsMax` at 0 for a long body,
    /// `InvariantViolation` at 0 for more than four observers or observers
    /// out of order.
    pub fn new(
        body_bytes: &'a [u8],
        gateway_sig: &'a [u8; HYBRID_SIG_LEN],
        observers: &[CaptureSig<'a>],
    ) -> Result<Self, Error> {
        if body_bytes.len() > MAX_SESSION_BODY_LEN {
            return Err(Error::new(Kind::LengthExceedsMax, 0));
        }
        let body = decode_object(
            SCHEMA_UPLINK_SESSION_BODY,
            SCHEMA_VERSION_UPLINK,
            body_bytes,
        )?;
        let ordered = observers.windows(2).all(|w| match w {
            [a, b] => a.observer_id.as_bytes() < b.observer_id.as_bytes(),
            _ => true,
        });
        if observers.len() > MAX_CAPTURE_SIGS || !ordered {
            return Err(invalid(0));
        }
        let mut slots = [None; MAX_CAPTURE_SIGS];
        for (slot, o) in slots.iter_mut().zip(observers) {
            *slot = Some(*o);
        }
        Ok(Self {
            body_bytes,
            body,
            gateway_sig,
            observers: slots,
            observer_count: u8::try_from(observers.len()).map_err(|_| invalid(0))?,
        })
    }

    /// The body object bytes (what the gateway signed).
    #[must_use]
    pub const fn body_bytes(&self) -> &'a [u8] {
        self.body_bytes
    }

    /// The decoded body.
    #[must_use]
    pub const fn body(&self) -> &UplinkSessionBody<'a> {
        &self.body
    }

    /// The gateway's signature.
    #[must_use]
    pub const fn gateway_sig(&self) -> &'a [u8; HYBRID_SIG_LEN] {
        self.gateway_sig
    }

    /// The observers' capture statements, ascending by observer.
    pub fn observers(&self) -> impl Iterator<Item = CaptureSig<'a>> + '_ {
        self.observers
            .iter()
            .take(usize::from(self.observer_count))
            .flatten()
            .copied()
    }
}

impl Encode for UplinkSession<'_> {
    fn encoded_len(&self) -> usize {
        let observers = self.observers().fold(4usize, |acc, o| {
            acc.saturating_add(o.observer_id.encoded_len())
                .saturating_add(o.org_id.encoded_len())
                .saturating_add(64)
                .saturating_add(HYBRID_SIG_LEN)
        });
        self.body_bytes
            .len()
            .saturating_add(4)
            .saturating_add(HYBRID_SIG_LEN)
            .saturating_add(observers)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_bytes(self.body_bytes, MAX_SESSION_BODY_LEN)?;
        w.write_array(self.gateway_sig)?;
        w.write_count(usize::from(self.observer_count), MAX_CAPTURE_SIGS)?;
        for o in self.observers() {
            o.observer_id.encode(w)?;
            o.org_id.encode(w)?;
            o.capture_hash.encode(w)?;
            w.write_array(o.sig)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for UplinkSession<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let at = r.position();
        let body_bytes = r.read_bytes(MAX_SESSION_BODY_LEN)?;
        let body = decode_object(
            SCHEMA_UPLINK_SESSION_BODY,
            SCHEMA_VERSION_UPLINK,
            body_bytes,
        )
        .map_err(|inner| {
            let offset = at
                .checked_add(4)
                .and_then(|p| p.checked_add(inner.offset()))
                .unwrap_or(at);
            Error::new(inner.kind(), offset)
        })?;
        let gateway_sig = read_fixed::<HYBRID_SIG_LEN>(r)?;
        let count_at = r.position();
        let count = r.read_count(MAX_CAPTURE_SIGS)?;
        let mut observers = [None; MAX_CAPTURE_SIGS];
        let mut previous: Option<&[u8]> = None;
        for slot in observers.iter_mut().take(count) {
            let entry_at = r.position();
            let observer_id = SignerId::decode(r)?;
            Reader::check_ascending(previous, observer_id.as_bytes(), entry_at)?;
            previous = Some(observer_id.as_bytes());
            *slot = Some(CaptureSig {
                observer_id,
                org_id: OrgId::decode(r)?,
                capture_hash: Hash512::decode(r)?,
                sig: read_fixed::<HYBRID_SIG_LEN>(r)?,
            });
        }
        Ok(Self {
            body_bytes,
            body,
            gateway_sig,
            observers,
            observer_count: u8::try_from(count)
                .map_err(|_| Error::new(Kind::CountExceedsMax, count_at))?,
        })
    }
}

// ---------------------------------------------------------------------------
// 0x0058 UplinkFrameLog

/// One frame of a log: its header fields (the link is the log's), the
/// number of objects it lists, its payload root and the device's
/// signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FrameEntry<'a> {
    /// The slot.
    pub slot: u64,
    /// The number in the slot.
    pub index: u16,
    /// The kind.
    pub kind: FrameKind,
    /// Where the payload starts in the link's stream.
    pub stream_offset: u64,
    /// How many payload bytes are data.
    pub payload_len: u32,
    /// How many objects the frame lists (at most [`MAX_FRAME_OBJECTS`]).
    pub object_count: u16,
    /// The root of the payload's chunk tree, as the device signed it.
    pub payload_root: Hash512,
    /// The device's signature over the frame's header.
    pub frame_sig: &'a [u8; ED25519_SIG_LEN],
}

impl FrameEntry<'_> {
    /// The frame's header under `link_id_hash`, with `objects_hash` the
    /// hash of its object list.
    #[must_use]
    pub const fn header(
        &self,
        link_id_hash: Hash512,
        objects_hash: Hash512,
    ) -> UplinkFrameHeaderParts {
        UplinkFrameHeaderParts {
            link_id_hash,
            slot: self.slot,
            index: self.index,
            kind: self.kind,
            stream_offset: self.stream_offset,
            payload_len: self.payload_len,
            payload_root: self.payload_root,
            objects_hash,
        }
    }
}

impl Encode for FrameEntry<'_> {
    fn encoded_len(&self) -> usize {
        FRAME_ENTRY_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        write_position(w, &self.header(Hash512::ZERO, Hash512::ZERO))?;
        w.write_u16(self.object_count)?;
        self.payload_root.encode(w)?;
        w.write_array(self.frame_sig)
    }
}

impl<'a> Decode<'a> for FrameEntry<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let p = read_position(r, Hash512::ZERO)?;
        let count_at = r.position();
        let object_count = r.read_u16()?;
        if usize::from(object_count) > MAX_FRAME_OBJECTS {
            return Err(Error::new(Kind::ValueOutOfRange, count_at));
        }
        Ok(Self {
            slot: p.slot,
            index: p.index,
            kind: p.kind,
            stream_offset: p.stream_offset,
            payload_len: p.payload_len,
            object_count,
            payload_root: Hash512::decode(r)?,
            frame_sig: read_fixed::<ED25519_SIG_LEN>(r)?,
        })
    }
}

/// The frames of a log, borrowed as [`FRAME_ENTRY_LEN`]-byte entries,
/// strictly ascending by (slot, index).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LogFrames<'a> {
    bytes: &'a [u8],
}

/// Reads `count` frame entries; returns their data chunks and listed
/// objects.
fn read_frames(r: &mut Reader<'_>, count: usize) -> Result<(u64, u64), Error> {
    let mut previous: Option<(u64, u16)> = None;
    let mut chunks = 0u64;
    let mut objects = 0u64;
    for _ in 0..count {
        let at = r.position();
        let f = FrameEntry::decode(r)?;
        if let Some(p) = previous {
            match p.cmp(&(f.slot, f.index)) {
                Ordering::Less => {}
                Ordering::Equal => return Err(Error::new(Kind::Duplicate, at)),
                Ordering::Greater => return Err(Error::new(Kind::NotSorted, at)),
            }
        }
        previous = Some((f.slot, f.index));
        let n = u64::try_from(data_chunks(f.payload_len))
            .map_err(|_| Error::new(Kind::ArithmeticOverflow, at))?;
        chunks = chunks
            .checked_add(n)
            .ok_or_else(|| Error::new(Kind::ArithmeticOverflow, at))?;
        objects = objects
            .checked_add(u64::from(f.object_count))
            .ok_or_else(|| Error::new(Kind::ArithmeticOverflow, at))?;
    }
    Ok((chunks, objects))
}

impl<'a> LogFrames<'a> {
    /// The frames encoded in `bytes`. `None` unless one to
    /// [`MAX_LOG_FRAMES`] whole entries strictly ascending by (slot,
    /// index).
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        let count = fixed_count::<FRAME_ENTRY_LEN>(bytes);
        if bytes.len().checked_rem(FRAME_ENTRY_LEN) != Some(0)
            || count == 0
            || count > MAX_LOG_FRAMES
        {
            return None;
        }
        let mut r = Reader::new(bytes);
        read_frames(&mut r, count).ok()?;
        Some(Self { bytes })
    }

    /// The encoded entries.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The number of frames.
    #[must_use]
    pub fn len(&self) -> usize {
        fixed_count::<FRAME_ENTRY_LEN>(self.bytes)
    }

    /// Always `false`: a log has at least one frame.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The data chunks of every frame: `Σ ⌈payload_len / 4096⌉`.
    #[must_use]
    pub fn data_chunks(&self) -> usize {
        self.iter().fold(0usize, |acc, f| {
            acc.saturating_add(data_chunks(f.payload_len))
        })
    }

    /// The objects every frame lists: `Σ object_count`.
    #[must_use]
    pub fn objects(&self) -> usize {
        self.iter().fold(0usize, |acc, f| {
            acc.saturating_add(usize::from(f.object_count))
        })
    }

    /// The frames in order.
    pub fn iter(&self) -> impl Iterator<Item = FrameEntry<'a>> + use<'a> {
        self.bytes.chunks_exact(FRAME_ENTRY_LEN).filter_map(|c| {
            let mut r = Reader::new(c);
            FrameEntry::decode(&mut r).ok()
        })
    }
}

/// The data-chunk leaves of a log, borrowed as 64-byte hashes: each
/// frame's `⌈payload_len / 4096⌉` leaves, frame after frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LogLeaves<'a> {
    bytes: &'a [u8],
}

impl<'a> LogLeaves<'a> {
    /// No leaf.
    pub const EMPTY: LogLeaves<'static> = LogLeaves { bytes: &[] };

    /// The leaves in `bytes`. `None` unless whole hashes, at most
    /// [`MAX_LOG_LEAVES`].
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        let whole = bytes.len().checked_rem(64) == Some(0);
        (whole && fixed_count::<64>(bytes) <= MAX_LOG_LEAVES).then_some(Self { bytes })
    }

    /// The encoded leaves.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The number of leaves.
    #[must_use]
    pub fn len(&self) -> usize {
        fixed_count::<64>(self.bytes)
    }

    /// Whether there is none.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The leaves in order.
    pub fn iter(&self) -> impl Iterator<Item = Hash512> + use<'a> {
        self.bytes.chunks_exact(64).filter_map(|c| {
            let mut r = Reader::new(c);
            Hash512::decode(&mut r).ok()
        })
    }
}

/// One object of a link's stream: its schema, object hash, where it starts
/// and how long it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StreamObject {
    /// The object's schema, as its header names it.
    pub schema: SchemaId,
    /// Its object hash (ENCODING.md §4).
    pub object_hash: Hash512,
    /// Where it starts in the link's stream.
    pub stream_offset: u64,
    /// Its length, header included.
    pub len: u32,
}

impl StreamObject {
    /// Where it ends (exclusive), if that fits.
    #[must_use]
    pub fn end(&self) -> Option<u64> {
        self.stream_offset.checked_add(u64::from(self.len))
    }
}

impl Encode for StreamObject {
    fn encoded_len(&self) -> usize {
        OBJECT_ENTRY_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.schema.encode(w)?;
        self.object_hash.encode(w)?;
        w.write_u64(self.stream_offset)?;
        w.write_u32(self.len)
    }
}

impl<'a> Decode<'a> for StreamObject {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let schema = SchemaId::decode(r)?;
        let object_hash = Hash512::decode(r)?;
        let stream_offset = r.read_u64()?;
        let len_at = r.position();
        let len = r.read_u32()?;
        if len < MIN_OBJECT_LEN {
            return Err(Error::new(Kind::ValueOutOfRange, len_at));
        }
        Ok(Self {
            schema,
            object_hash,
            stream_offset,
            len,
        })
    }
}

/// Reads `count` entries of one frame's object list: each in form (at
/// least 16 bytes long, `ValueOutOfRange`; its end within `u64`,
/// `ValueOutOfRange`) and starting at or after the end of the one before
/// (`InvariantViolation`).
fn read_frame_objects(r: &mut Reader<'_>, count: usize) -> Result<(), Error> {
    let mut previous_end: Option<u64> = None;
    for _ in 0..count {
        let at = r.position();
        let o = StreamObject::decode(r)?;
        if previous_end.is_some_and(|end| o.stream_offset < end) {
            return Err(invalid(at));
        }
        previous_end = Some(
            o.end()
                .ok_or_else(|| Error::new(Kind::ValueOutOfRange, at))?,
        );
    }
    Ok(())
}

/// One frame's object list (ADR-0041 decision 3), borrowed as
/// [`OBJECT_ENTRY_LEN`]-byte entries in stream order, none overlapping the
/// one before: every object that overlaps the frame's data, the one
/// carried in from the frame before and the one carried out to the frame
/// after included. Whether the list tiles the frame's data is the
/// verifier's rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FrameObjects<'a> {
    bytes: &'a [u8],
}

impl<'a> FrameObjects<'a> {
    /// No object.
    pub const EMPTY: FrameObjects<'static> = FrameObjects { bytes: &[] };

    /// The list in `bytes`. `None` unless whole entries, at most
    /// [`MAX_FRAME_OBJECTS`], each at least 16 bytes long and starting at
    /// or after the end of the one before.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        let count = fixed_count::<OBJECT_ENTRY_LEN>(bytes);
        if bytes.len().checked_rem(OBJECT_ENTRY_LEN) != Some(0) || count > MAX_FRAME_OBJECTS {
            return None;
        }
        let mut r = Reader::new(bytes);
        read_frame_objects(&mut r, count).ok()?;
        Some(Self { bytes })
    }

    /// The encoded entries.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The number of objects.
    #[must_use]
    pub fn len(&self) -> usize {
        fixed_count::<OBJECT_ENTRY_LEN>(self.bytes)
    }

    /// Whether there is none.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The objects in stream order.
    pub fn iter(&self) -> impl Iterator<Item = StreamObject> + use<'a> {
        self.bytes.chunks_exact(OBJECT_ENTRY_LEN).filter_map(|c| {
            let mut r = Reader::new(c);
            StreamObject::decode(&mut r).ok()
        })
    }
}

/// The object lists of a log's frames, one after another, borrowed as
/// [`OBJECT_ENTRY_LEN`]-byte entries. An object carried from one frame to
/// the next is in both lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LogObjects<'a> {
    bytes: &'a [u8],
}

impl<'a> LogObjects<'a> {
    /// No object.
    pub const EMPTY: LogObjects<'static> = LogObjects { bytes: &[] };

    /// The entries in `bytes`. `None` unless whole entries, at most
    /// [`MAX_LOG_OBJECTS`], each at least 16 bytes long with its end
    /// within `u64`. How they divide into frames is the log's.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        let count = fixed_count::<OBJECT_ENTRY_LEN>(bytes);
        if bytes.len().checked_rem(OBJECT_ENTRY_LEN) != Some(0) || count > MAX_LOG_OBJECTS {
            return None;
        }
        let in_form = bytes.chunks_exact(OBJECT_ENTRY_LEN).all(|c| {
            let mut r = Reader::new(c);
            StreamObject::decode(&mut r).is_ok_and(|o| o.end().is_some())
        });
        in_form.then_some(Self { bytes })
    }

    /// The encoded entries.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        fixed_count::<OBJECT_ENTRY_LEN>(self.bytes)
    }

    /// Whether there is none.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// One frame of a log with its data-chunk leaves and its object list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LoggedFrame<'a> {
    /// The frame.
    pub entry: FrameEntry<'a>,
    /// Its `⌈payload_len / 4096⌉` data-chunk leaves.
    pub leaves: LogLeaves<'a>,
    /// Its `object_count` objects.
    pub objects: FrameObjects<'a>,
}

/// The fields of a frame log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UplinkFrameLogParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The station.
    pub station_id: StationId<'a>,
    /// The station's gateway.
    pub gateway_id: GatewayId<'a>,
    /// The session the frames belong to.
    pub session_index: u32,
    /// The link.
    pub link_id_hash: Hash512,
    /// The frames received, in order.
    pub frames: LogFrames<'a>,
    /// The leaves of every data chunk of the frames, in frame order.
    pub leaves: LogLeaves<'a>,
    /// Every frame's object list, in frame order.
    pub objects: LogObjects<'a>,
}

/// A frame log (schema `0x0058`, a ledger event without a signature of its
/// own: the session's chain head covers its frames).
///
/// Rules: the session number is at least 1 (`ValueOutOfRange`); one to 384
/// frames strictly ascending by (slot, index), each in form, listing at
/// most [`MAX_FRAME_OBJECTS`] objects (`InvariantViolation` for none,
/// `CountExceedsMax`, `NotSorted`, `Duplicate`, `ValueOutOfRange`); exactly
/// `Σ ⌈payload_len / 4096⌉` leaves (`InvariantViolation` at the leaf
/// count); exactly `Σ object_count` object entries (`InvariantViolation` at
/// the object count), each frame's list as [`FrameObjects`] requires
/// (`ValueOutOfRange`, `InvariantViolation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UplinkFrameLog<'a> {
    parts: UplinkFrameLogParts<'a>,
}

impl<'a> UplinkFrameLog<'a> {
    /// Builds the log.
    ///
    /// # Errors
    /// `ValueOutOfRange` at 0 for session 0, `InvariantViolation` at 0 if
    /// the leaves or the objects do not match the frames.
    pub fn new(parts: &UplinkFrameLogParts<'a>) -> Result<Self, Error> {
        if parts.session_index == 0 {
            return Err(Error::new(Kind::ValueOutOfRange, 0));
        }
        if parts.leaves.len() != parts.frames.data_chunks()
            || parts.objects.len() != parts.frames.objects()
        {
            return Err(invalid(0));
        }
        let log = Self { parts: *parts };
        let lists_ok = log
            .frames_with()
            .all(|f| FrameObjects::new(f.objects.bytes).is_some());
        if lists_ok { Ok(log) } else { Err(invalid(0)) }
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &UplinkFrameLogParts<'a> {
        &self.parts
    }

    /// Each frame with its leaves and its object list, in order.
    pub fn frames_with(&self) -> impl Iterator<Item = LoggedFrame<'a>> + use<'a> {
        let mut leaves = self.parts.leaves.bytes;
        let mut objects = self.parts.objects.bytes;
        self.parts.frames.iter().map(move |entry| {
            let n = data_chunks(entry.payload_len).saturating_mul(64);
            let (mine, rest) = leaves.split_at_checked(n).unwrap_or((leaves, &[]));
            leaves = rest;
            let m = usize::from(entry.object_count).saturating_mul(OBJECT_ENTRY_LEN);
            let (listed, rest) = objects.split_at_checked(m).unwrap_or((objects, &[]));
            objects = rest;
            LoggedFrame {
                entry,
                leaves: LogLeaves { bytes: mine },
                objects: FrameObjects { bytes: listed },
            }
        })
    }
}

impl Encode for UplinkFrameLog<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.station_id.encoded_len())
            .saturating_add(p.gateway_id.encoded_len())
            .saturating_add(4 + 64 + 12)
            .saturating_add(p.frames.bytes.len())
            .saturating_add(p.leaves.bytes.len())
            .saturating_add(p.objects.bytes.len())
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.station_id.encode(w)?;
        p.gateway_id.encode(w)?;
        w.write_u32(p.session_index)?;
        p.link_id_hash.encode(w)?;
        w.write_count(p.frames.len(), MAX_LOG_FRAMES)?;
        w.write_slice(p.frames.bytes)?;
        w.write_count(p.leaves.len(), MAX_LOG_LEAVES)?;
        w.write_slice(p.leaves.bytes)?;
        w.write_count(p.objects.len(), MAX_LOG_OBJECTS)?;
        w.write_slice(p.objects.bytes)
    }
}

impl<'a> Decode<'a> for UplinkFrameLog<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let station_id = StationId::decode(r)?;
        let gateway_id = GatewayId::decode(r)?;
        let index_at = r.position();
        let session_index = r.read_u32()?;
        if session_index == 0 {
            return Err(Error::new(Kind::ValueOutOfRange, index_at));
        }
        let link_id_hash = Hash512::decode(r)?;
        let frames_at = r.position();
        let frame_count = r.read_count(MAX_LOG_FRAMES)?;
        if frame_count == 0 {
            return Err(invalid(frames_at));
        }
        let start = r.position();
        let (chunks, listed) = read_frames(r, frame_count)?;
        let frames = LogFrames {
            bytes: r.consumed_from(start)?,
        };
        let leaves_at = r.position();
        let leaf_count = r.read_count(MAX_LOG_LEAVES)?;
        if u64::try_from(leaf_count).ok() != Some(chunks) {
            return Err(invalid(leaves_at));
        }
        let length = leaf_count
            .checked_mul(64)
            .ok_or_else(|| Error::new(Kind::ArithmeticOverflow, leaves_at))?;
        let leaves = LogLeaves {
            bytes: r.take(length)?,
        };
        let objects_at = r.position();
        let object_count = r.read_count(MAX_LOG_OBJECTS)?;
        if u64::try_from(object_count).ok() != Some(listed) {
            return Err(invalid(objects_at));
        }
        let start = r.position();
        for f in frames.iter() {
            read_frame_objects(r, usize::from(f.object_count))?;
        }
        let objects = LogObjects {
            bytes: r.consumed_from(start)?,
        };
        Ok(Self {
            parts: UplinkFrameLogParts {
                election_id,
                station_id,
                gateway_id,
                session_index,
                link_id_hash,
                frames,
                leaves,
                objects,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// 0x0059 ConnectivityIncidentBody

/// The fields of a connectivity incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectivityIncidentParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The station, or `None` for the whole election.
    pub station_id: Option<StationId<'a>>,
    /// The box, or `None` for the whole station; requires the station.
    pub box_id: Option<BoxId<'a>>,
    /// What was found.
    pub kind: IncidentKind,
    /// The first slot of the affected interval.
    pub from_slot: u64,
    /// The last slot of the affected interval.
    pub to_slot: u64,
    /// Whether a commitment unit is involved: its records are compared
    /// with the paper in full (PROTOCOL.md §12.5).
    pub commitment_unit: bool,
    /// Hash of the evidence document.
    pub evidence_hash: Hash512,
}

/// A connectivity incident (schema `0x0059`, a witnessed body; ADR-0041
/// decision 11, VC-083).
///
/// Rules: the kind in range (`ValueOutOfRange`); a box only with a station
/// and `from_slot ≤ to_slot` (`InvariantViolation`); a nonzero evidence
/// hash (`InvalidPreviousHash`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectivityIncidentBody<'a> {
    parts: ConnectivityIncidentParts<'a>,
}

impl<'a> ConnectivityIncidentBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// The rule violated, at offset 0.
    pub fn new(parts: &ConnectivityIncidentParts<'a>) -> Result<Self, Error> {
        if (parts.box_id.is_some() && parts.station_id.is_none()) || parts.from_slot > parts.to_slot
        {
            return Err(invalid(0));
        }
        if parts.evidence_hash.is_zero() {
            return Err(Error::new(Kind::InvalidPreviousHash, 0));
        }
        Ok(Self { parts: *parts })
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &ConnectivityIncidentParts<'a> {
        &self.parts
    }
}

impl Encode for ConnectivityIncidentBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.station_id.encoded_len())
            .saturating_add(p.box_id.encoded_len())
            .saturating_add(1 + 8 + 8 + 1 + 64)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.station_id.encode(w)?;
        p.box_id.encode(w)?;
        w.write_u8(p.kind.code())?;
        w.write_u64(p.from_slot)?;
        w.write_u64(p.to_slot)?;
        w.write_bool(p.commitment_unit)?;
        p.evidence_hash.encode(w)
    }
}

impl<'a> Decode<'a> for ConnectivityIncidentBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let station_id = Option::<StationId<'a>>::decode(r)?;
        let box_at = r.position();
        let box_id = Option::<BoxId<'a>>::decode(r)?;
        if box_id.is_some() && station_id.is_none() {
            return Err(invalid(box_at));
        }
        let kind = read_code(r, IncidentKind::from_code)?;
        let from_slot = r.read_u64()?;
        let to_at = r.position();
        let to_slot = r.read_u64()?;
        if from_slot > to_slot {
            return Err(invalid(to_at));
        }
        let commitment_unit = r.read_bool()?;
        Ok(Self {
            parts: ConnectivityIncidentParts {
                election_id,
                station_id,
                box_id,
                kind,
                from_slot,
                to_slot,
                commitment_unit,
                evidence_hash: read_nonzero_hash(r)?,
            },
        })
    }
}
