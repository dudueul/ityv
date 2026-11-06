//! The connectivity side of a simulated election (ADR-0022, ADR-0041): the
//! manifest the genesis pins, and the gateway's frame logs and sessions
//! over the device events the ledger carries.
//!
//! Every scanner and check-in unit sends its manifest's normal frames in
//! every slot from its station's opening to the slot after its box's close
//! (the unit to the station's last box). The objects a device made since
//! the gateway's previous session go into the frames of the last slot the
//! device sends in within the session's window: first its ticks and
//! openings (the unit's observer counts and participation set), then, from
//! a frame of their own, its closed batches (an attestation, then its
//! records by record hash, each followed by its sealed share package). A
//! record no batch attestation has taken is never sent: the device sends
//! records only in closed batches (PROTOCOL.md §5.8 item 4). Each frame
//! lists every object that overlaps its data and signs the list's hash
//! with its header; a share package, and the object after one, start on a
//! 4,096-byte boundary of the frame, with zero fill between (ADR-0041
//! decision 3). The scanner's last slot (its closing tick's) is a catch-up
//! slot: what is left, then the close resend of every batch it sent.
//! The gateway closes a session at each window of six slots from the
//! station's opening ([`Window`], a step of the plan); the last is final,
//! after the station's participation set, and the station's two observers
//! sign a capture statement on it. Their capture's hash is fixture data:
//! the simulator writes no capture file.
//!
//! A scenario changes what a device or the gateway did with a [`Fault`] on
//! a window.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::OnceLock;

use ityv_crypto::uplink::{
    chain_next, chain_start, chunk_leaf, link_id, objects_hash, payload_root,
};
use ityv_crypto::{RecordPurpose, object_hash};
use ityv_encoding::{
    BatchAttest, CARRY_LEDGER, CARRY_PUBLIC, CARRY_ROLL, CARRY_SEALED, CARRY_SESSION, CHUNK_LEN,
    CaptureMessage, CaptureSig, CastRecord, ChallengeOpening, ConnectivityManifest, DeviceClass,
    Direction, ElectionId, Encode, FRAME_HEADER_LEN, FrameEntry, FrameKind, GatewayId, HEADER_LEN,
    Hash512, Ident, LogFrames, LogLeaves, LogObjects, MAX_PAYLOAD_LEN, ManifestEntries,
    ManifestEntry, Medium, ObjectHeader, ObserverCountAttestBody, OrgId, PAYLOAD_CHUNKS,
    ParticipationSet, ProgressBody, ProgressTick, Reader, SCHEMA_BATCH_ATTEST, SCHEMA_CAST_RECORD,
    SCHEMA_CHALLENGE_OPENING, SCHEMA_CONNECTIVITY_MANIFEST, SCHEMA_OBSERVER_COUNT_ATTEST_BODY,
    SCHEMA_PARTICIPATION_SET, SCHEMA_PROGRESS_TICK, SCHEMA_SHARE_PACKAGE,
    SCHEMA_UPLINK_FRAME_HEADER, SCHEMA_UPLINK_FRAME_LOG, SCHEMA_UPLINK_SESSION,
    SCHEMA_UPLINK_SESSION_BODY, SCHEMA_VERSION_1, SCHEMA_WITNESSED_EVENT, Schedule, SchemaId,
    SessionLink, SessionLinks, SignerId, StationId, StreamObject, UplinkFrameHeader,
    UplinkFrameHeaderParts, UplinkFrameLog, UplinkFrameLogParts, UplinkSession, UplinkSessionBody,
    UplinkSessionParts, WitnessedEvent, Writer, decode_object, encode_object, schema_version,
};

use crate::election::Election;
use crate::util::{group, hash_of, leak_slice, object, record_sig, share_package, sign, text};

/// Normal and catch-up frames per slot of a scanner (the reference values,
/// ADR-0022).
pub const SCANNER_FRAMES: (u16, u16) = (16, 64);
/// Normal and catch-up frames per slot of a check-in unit.
pub const UNIT_FRAMES: (u16, u16) = (4, 64);

/// A device that sends frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Device {
    /// A box's scanner (its commitment unit), by box index.
    Box(usize),
    /// A station's check-in unit in service, by station index.
    Unit(usize),
}

/// What a scenario changes in one session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The gateway leaves the first frame of `slot` out of its log and its
    /// chain and declares no slot missing (a hidden frame).
    Hide {
        /// The device.
        device: Device,
        /// The slot.
        slot: u64,
    },
    /// Frame `index` of `slot` was lost on the line; the gateway declares
    /// the slot missing. What it carried arrives only if the device sends
    /// it again (a batch in the close resend).
    Lose {
        /// The device.
        device: Device,
        /// The slot.
        slot: u64,
        /// The frame's number in the slot.
        index: u16,
    },
    /// The device sends 3,000 bytes that are no object (listing none) in
    /// the first frame of `slot`, nothing in the next slot, and goes on a
    /// byte past them; the gateway declares the silent slot missing.
    Covert {
        /// The device.
        device: Device,
        /// The slot.
        slot: u64,
    },
    /// The gateway logs the first frame of `slot` with a list of its own
    /// (its first object under another hash) and chains that header.
    Relist {
        /// The device.
        device: Device,
        /// The slot.
        slot: u64,
    },
    /// The gateway puts in place of the last frame of `slot` one it signed
    /// itself (an injected frame).
    Inject {
        /// The device.
        device: Device,
        /// The slot.
        slot: u64,
    },
    /// The device's last frame of `slot` has a nonzero byte after its data.
    Fill {
        /// The device.
        device: Device,
        /// The slot.
        slot: u64,
    },
    /// The device sends one normal frame more in `slot` than the manifest
    /// allows.
    Extra {
        /// The device.
        device: Device,
        /// The slot.
        slot: u64,
    },
    /// The device keeps sending normal frames in the slot after its last.
    AfterClose {
        /// The device.
        device: Device,
    },
    /// The device sends the records of each batch in descending record
    /// hash.
    Unordered {
        /// The device.
        device: Device,
    },
    /// The device event whose object hash this is never travels its link:
    /// it reaches the ledger by another path. (On any window: it applies to
    /// the whole ledger.)
    Withhold {
        /// The event's object hash.
        event: Hash512,
    },
}

impl Fault {
    /// The event a [`Fault::Withhold`] keeps off its link.
    #[must_use]
    pub const fn withheld(&self) -> Option<Hash512> {
        match self {
            Self::Withhold { event } => Some(*event),
            Self::Hide { .. }
            | Self::Lose { .. }
            | Self::Covert { .. }
            | Self::Relist { .. }
            | Self::Inject { .. }
            | Self::Fill { .. }
            | Self::Extra { .. }
            | Self::AfterClose { .. }
            | Self::Unordered { .. } => None,
        }
    }
}

/// One session of a station's gateway: its window, whether it is the last,
/// and what a scenario changed in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Window {
    /// The station.
    pub station: usize,
    /// The first slot.
    pub start: u64,
    /// The last slot.
    pub end: u64,
    /// Whether this is the gateway's final session.
    pub is_final: bool,
    /// What a scenario changed.
    pub faults: Vec<Fault>,
}

/// The windows of six slots that cover `first` to `last`.
#[must_use]
pub fn windows(first: u64, last: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut start = first;
    while start <= last {
        out.push((start, start + 5));
        start += 6;
    }
    out
}

fn ident(bytes: &'static [u8], max: usize) -> Ident<'static> {
    Ident::new(bytes, max).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn entry(
    class: DeviceClass,
    port: &'static [u8],
    direction: Direction,
    medium: Medium,
    peer: Option<DeviceClass>,
    counterpart: &'static [u8],
    schedule: Schedule,
    frames: (u16, u16),
    carries: u32,
) -> ManifestEntry<'static> {
    ManifestEntry {
        device_class: class,
        port: ident(port, 32),
        direction,
        medium,
        peer_class: peer,
        counterpart: ident(counterpart, 64),
        schedule,
        frames_per_slot: frames.0,
        catchup_frames_per_slot: frames.1,
        carries,
    }
}

/// The connectivity manifest of a simulated election: every device class
/// declared, the two frame links, the one-way rules kept. With `two_way`
/// the scanner's frame link receives as well (an attack on VC-077).
#[must_use]
pub fn manifest(election_id: ElectionId<'static>, two_way: bool) -> &'static [u8] {
    use DeviceClass as C;
    use Direction as D;
    use Medium as M;
    use Schedule as S;
    let none = |class, port: &'static [u8]| {
        entry(
            class,
            port,
            D::None,
            M::None,
            None,
            b"none",
            S::Unused,
            (0, 0),
            0,
        )
    };
    let mut entries = vec![
        entry(
            C::InterpretationUnit,
            b"optocoupler",
            D::OutOnly,
            M::Optocoupler,
            Some(C::CommitmentUnit),
            b"commitment-unit",
            S::BoxOpenToClose,
            (0, 0),
            ityv_encoding::CARRY_LINK,
        ),
        entry(
            C::CommitmentUnit,
            b"uplink",
            if two_way { D::Both } else { D::OutOnly },
            M::OpticalTransmit,
            Some(C::Gateway),
            b"station-gateway",
            S::BoxOpenToClose,
            SCANNER_FRAMES,
            CARRY_PUBLIC | CARRY_SEALED,
        ),
        entry(
            C::CheckinUnit,
            b"uplink",
            D::OutOnly,
            M::OpticalTransmit,
            Some(C::Gateway),
            b"station-gateway",
            S::BoxOpenToClose,
            UNIT_FRAMES,
            CARRY_PUBLIC,
        ),
        none(C::ChamberModule, b"bus"),
        none(C::IdTerminalElectionDay, b"none"),
        entry(
            C::IdTerminalEarlyVoting,
            b"roll-line",
            D::Both,
            M::ElectionLine,
            None,
            b"unified-voter-roll",
            S::EarlyVoting,
            (0, 0),
            CARRY_ROLL,
        ),
        entry(
            C::Gateway,
            b"wan",
            D::Both,
            M::OpticalLine,
            Some(C::LedgerCollector),
            b"ledger-collector",
            S::Always,
            (0, 0),
            CARRY_PUBLIC | CARRY_SEALED | CARRY_SESSION,
        ),
        entry(
            C::Tap,
            b"monitor",
            D::OutOnly,
            M::Ethernet,
            None,
            b"observer-recorder",
            S::BoxOpenToClose,
            (0, 0),
            CARRY_PUBLIC | CARRY_SEALED,
        ),
        entry(
            C::LedgerCollector,
            b"net",
            D::Both,
            M::OpticalLine,
            None,
            b"mirrors",
            S::Always,
            (0, 0),
            CARRY_LEDGER,
        ),
        entry(
            C::BoardPublisher,
            b"net",
            D::Both,
            M::OpticalLine,
            None,
            b"public",
            S::Always,
            (0, 0),
            CARRY_LEDGER,
        ),
        entry(
            C::Witness,
            b"net",
            D::Both,
            M::OpticalLine,
            Some(C::LedgerCollector),
            b"ledger-collector",
            S::Always,
            (0, 0),
            CARRY_LEDGER,
        ),
        entry(
            C::TrusteeReceiver,
            b"hsm",
            D::InOnly,
            M::OnSiteDirect,
            None,
            b"trustee-hsm",
            S::Witnessed,
            (0, 0),
            CARRY_SEALED,
        ),
        none(C::ReceiptReader, b"none"),
        none(C::ImprintReader, b"none"),
        none(C::Printer, b"none"),
    ];
    entries.sort_by(|a, b| a.key().cmp(&b.key()));
    let mut bytes = Vec::new();
    for e in &entries {
        bytes.extend_from_slice(group(e));
    }
    let entries = ManifestEntries::new(leak_slice(bytes)).unwrap();
    object(
        SCHEMA_CONNECTIVITY_MANIFEST,
        &ConnectivityManifest::new(election_id, entries),
    )
}

/// The payload root of a frame without data.
fn empty_root() -> Hash512 {
    static ROOT: OnceLock<Hash512> = OnceLock::new();
    *ROOT.get_or_init(|| payload_root([]).unwrap())
}

/// The encoded header object of `parts`, and its object hash.
fn header(parts: &UplinkFrameHeaderParts) -> ([u8; HEADER_LEN + FRAME_HEADER_LEN], Hash512) {
    let mut buf = [0u8; HEADER_LEN + FRAME_HEADER_LEN];
    let h = UplinkFrameHeader::new(parts).unwrap();
    let n = encode_object(SCHEMA_UPLINK_FRAME_HEADER, SCHEMA_VERSION_1, &h, &mut buf).unwrap();
    assert_eq!(n, buf.len());
    let hash = object_hash(&buf);
    (buf, hash)
}

/// The schema an object's header names.
fn schema_of(object: &[u8]) -> Option<SchemaId> {
    ObjectHeader::read(&mut Reader::new(object))
        .ok()
        .map(|h| h.schema_id())
}

/// An object partly sent: the rest goes first into the next frame.
#[derive(Debug, Clone, Copy)]
struct Carry {
    object: &'static [u8],
    sent: usize,
    entry: StreamObject,
}

/// What one link has sent and holds.
#[derive(Debug, Clone)]
struct Link {
    /// Its frame key's label.
    label: String,
    /// Its link identifier.
    id: Hash512,
    /// The gateway's chain head over the frames it logged.
    head: Hash512,
    /// Where the device's next byte goes in its stream.
    offset: u64,
    /// The end of the last frame the gateway logged.
    received: u64,
    /// The object the last frame carried out, if any.
    carry: Option<Carry>,
    /// Whether the last object placed was a share package (the next starts
    /// on a chunk boundary of its frame).
    after_package: bool,
    /// Objects made and not yet sent other than batches, in transmission
    /// order (ticks, openings, the unit's counts and participation set).
    pending: Vec<&'static [u8]>,
    /// Closed batches not yet sent: each attestation, then its records by
    /// record hash, each followed by its share package.
    batches: Vec<&'static [u8]>,
    /// Every batch object sent, for the close resend.
    sent_batches: Vec<&'static [u8]>,
    /// Records no batch attestation has taken yet.
    unbatched: Vec<&'static [u8]>,
    /// Every object seen (a replayed event is sent once).
    seen: BTreeSet<[u8; 64]>,
}

impl Link {
    /// One frame's data and list from `queue` (front first), at most
    /// `capacity` bytes: the object carried in first; each share package,
    /// and the object after one, on a chunk boundary of the frame, with
    /// zero fill between; an object that does not fit is carried out.
    fn fill(
        &mut self,
        queue: &mut VecDeque<&'static [u8]>,
        capacity: usize,
    ) -> (Vec<u8>, Vec<StreamObject>) {
        let start = self.offset;
        let mut data: Vec<u8> = Vec::new();
        let mut list: Vec<StreamObject> = Vec::new();
        if let Some(c) = self.carry.take() {
            let rest = &c.object[c.sent..];
            let take = rest.len().min(capacity);
            data.extend_from_slice(&rest[..take]);
            list.push(c.entry);
            if take < rest.len() {
                self.carry = Some(Carry {
                    sent: c.sent + take,
                    ..c
                });
            }
        }
        while self.carry.is_none() {
            let Some(&o) = queue.front() else {
                break;
            };
            let package = schema_of(o) == Some(SCHEMA_SHARE_PACKAGE);
            let at = if self.after_package || package {
                data.len().div_ceil(CHUNK_LEN) * CHUNK_LEN
            } else {
                data.len()
            };
            if at >= capacity {
                break;
            }
            data.resize(at, 0);
            let entry = StreamObject {
                schema: schema_of(o).unwrap(),
                object_hash: object_hash(o),
                stream_offset: start + at as u64,
                len: o.len() as u32,
            };
            list.push(entry);
            let take = o.len().min(capacity - at);
            data.extend_from_slice(&o[..take]);
            if take < o.len() {
                self.carry = Some(Carry {
                    object: o,
                    sent: take,
                    entry,
                });
            }
            self.after_package = package;
            queue.pop_front();
        }
        self.offset += data.len() as u64;
        (data, list)
    }
}

/// The station gateways of an election as the ledger is laid down.
pub(crate) struct Gateways<'e> {
    e: &'e Election,
    links: BTreeMap<Device, Link>,
    /// Per station: the last session's number and body hash.
    sessions: Vec<(u32, Hash512)>,
    /// Device events that never travel their link ([`Fault::Withhold`]).
    withheld: BTreeSet<[u8; 64]>,
}

/// The share package `record` names: the stand-in of its box and
/// commitments ([`crate::util::share_package`]).
fn package_of(record: &'static [u8]) -> &'static [u8] {
    let r = decode_object::<CastRecord<'_>>(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, record).unwrap();
    let body = r.body();
    let points: Vec<u8> = body
        .commitments()
        .as_slice()
        .iter()
        .flat_map(|p| p.0)
        .collect();
    let package = share_package(body.box_id().as_bytes(), &points);
    assert_eq!(object_hash(package), *body.share_package_hash());
    package
}

/// The encoded entries of `list`.
fn list_bytes(list: &[StreamObject]) -> Vec<u8> {
    list.iter().flat_map(|o| group(o).iter().copied()).collect()
}

/// A frame's kind: `closing` its catch-up group's `kind`, else normal.
fn kind_of(closing: bool, kind: FrameKind) -> FrameKind {
    if closing { kind } else { FrameKind::Normal }
}

/// What a gateway that relists an object logs for `list`: its first
/// entry under another hash.
fn relisted(list: &[StreamObject]) -> Vec<StreamObject> {
    let mut out = list.to_vec();
    if let Some(first) = out.first_mut() {
        first.object_hash.0[0] ^= 1;
    }
    out
}

/// Reverses the records of each batch in `batches` (each with its share
/// package after it): records out of record-hash order.
fn reverse_records(batches: &mut [&'static [u8]]) {
    let mut i = 0;
    while i < batches.len() {
        if schema_of(batches[i]) == Some(SCHEMA_CAST_RECORD) {
            let end = (i..batches.len())
                .find(|j| schema_of(batches[*j]) == Some(SCHEMA_BATCH_ATTEST))
                .unwrap_or(batches.len());
            let pairs: Vec<&'static [u8]> =
                batches[i..end].chunks(2).rev().flatten().copied().collect();
            batches[i..end].copy_from_slice(&pairs);
            i = end;
        } else {
            i += 1;
        }
    }
}

impl<'e> Gateways<'e> {
    /// The gateways of `e`, with the events `withheld` kept off every link.
    pub(crate) fn new(e: &'e Election, withheld: BTreeSet<[u8; 64]>) -> Self {
        let mut links = BTreeMap::new();
        let mut add = |d: Device| {
            let label = e.frame_label(d);
            let link = link_id(e.frame_key(d));
            links.insert(
                d,
                Link {
                    label,
                    id: link,
                    head: chain_start(&link),
                    offset: 0,
                    received: 0,
                    carry: None,
                    after_package: false,
                    pending: Vec::new(),
                    batches: Vec::new(),
                    sent_batches: Vec::new(),
                    unbatched: Vec::new(),
                    seen: BTreeSet::new(),
                },
            );
        };
        for b in 0..e.boxes.len() {
            add(Device::Box(b));
        }
        for s in 0..e.stations.len() {
            add(Device::Unit(s));
        }
        Self {
            e,
            links,
            sessions: vec![(0, Hash512::ZERO); e.stations.len()],
            withheld,
        }
    }

    /// The device whose link carries `event`, if it is a device event.
    fn device_of(&self, event: &'static [u8]) -> Option<Device> {
        let schema = schema_of(event)?;
        let v = schema_version(schema);
        let box_of = |id: &[u8]| {
            self.e
                .boxes
                .iter()
                .position(|b| b.id.as_bytes() == id)
                .map(Device::Box)
        };
        let unit_of = |id: &[u8]| {
            self.e
                .stations
                .iter()
                .position(|s| s.id.as_bytes() == id)
                .map(Device::Unit)
        };
        if schema == SCHEMA_CAST_RECORD {
            box_of(
                decode_object::<CastRecord<'_>>(schema, v, event)
                    .ok()?
                    .body()
                    .box_id()
                    .as_bytes(),
            )
        } else if schema == SCHEMA_BATCH_ATTEST {
            box_of(
                decode_object::<BatchAttest<'_>>(schema, v, event)
                    .ok()?
                    .body()
                    .box_id()
                    .as_bytes(),
            )
        } else if schema == SCHEMA_CHALLENGE_OPENING {
            box_of(
                decode_object::<ChallengeOpening<'_>>(schema, v, event)
                    .ok()?
                    .body()
                    .box_id()
                    .as_bytes(),
            )
        } else if schema == SCHEMA_PROGRESS_TICK {
            match *decode_object::<ProgressTick<'_>>(schema, v, event)
                .ok()?
                .body()
            {
                ProgressBody::Box(b) => box_of(b.parts().box_id.as_bytes()),
                ProgressBody::Checkin(c) => unit_of(c.parts().station_id.as_bytes()),
            }
        } else if schema == SCHEMA_PARTICIPATION_SET {
            unit_of(
                decode_object::<ParticipationSet<'_>>(schema, v, event)
                    .ok()?
                    .station_id()
                    .as_bytes(),
            )
        } else if schema == SCHEMA_WITNESSED_EVENT {
            let w = decode_object::<WitnessedEvent<'_>>(schema, v, event).ok()?;
            let body = w
                .body::<ObserverCountAttestBody<'_>>(SCHEMA_OBSERVER_COUNT_ATTEST_BODY)
                .ok()?;
            unit_of(body.parts().station_id.as_bytes())
        } else {
            None
        }
    }

    /// Takes in one event of the ledger: a device event joins its link's
    /// stream (a record waits for the batch attestation that takes it, then
    /// travels in the batch with its share package).
    pub(crate) fn observe(&mut self, event: &'static [u8]) {
        let Some(device) = self.device_of(event) else {
            return;
        };
        let hash = object_hash(event).0;
        if self.withheld.contains(&hash) {
            return;
        }
        let link = self.links.get_mut(&device).unwrap();
        if !link.seen.insert(hash) {
            return;
        }
        match schema_of(event) {
            Some(s) if s == SCHEMA_CAST_RECORD => link.unbatched.push(event),
            Some(s) if s == SCHEMA_BATCH_ATTEST => {
                let n = decode_object::<BatchAttest<'_>>(s, schema_version(s), event)
                    .map_or(0, |b| usize::from(b.body().record_count()));
                // The batch takes the counters after the previous one's:
                // the oldest records no batch has taken.
                let take = n.min(link.unbatched.len());
                let mut records: Vec<&'static [u8]> = link.unbatched.drain(..take).collect();
                records.sort_by_key(|r| object_hash(r).0);
                link.batches.push(event);
                for r in records {
                    link.batches.push(r);
                    link.batches.push(package_of(r));
                }
            }
            _ => link.pending.push(event),
        }
    }

    /// The frame logs and the session of window `w`, in ledger order.
    #[allow(clippy::too_many_lines)] // Each link's frames, then the session.
    pub(crate) fn session(&mut self, w: &Window) -> Vec<(SchemaId, &'static [u8])> {
        let e = self.e;
        let s = w.station;
        let station = StationId::new(text(e.stations[s].id)).unwrap();
        let gateway = e.gateway_id(s);
        let (previous_index, previous) = self.sessions[s];
        let index = previous_index + 1;
        let mut devices: Vec<Device> = e.stations[s]
            .boxes
            .iter()
            .map(|b| Device::Box(*b))
            .collect();
        devices.push(Device::Unit(s));
        let mut out = Vec::new();
        let mut entries: Vec<SessionLink> = Vec::new();
        let mut wan = 0u64;
        for d in devices {
            let (first, last) = e.link_slots(d);
            let after = w.faults.contains(&Fault::AfterClose { device: d });
            let lo = w.start.max(first);
            let hi = w.end.min(if after { last + 1 } else { last });
            if lo > hi {
                continue;
            }
            let (fps, catchup) = match d {
                Device::Box(_) => SCANNER_FRAMES,
                Device::Unit(_) => UNIT_FRAMES,
            };
            let gateway_label = e.gateway_label(s);
            let unordered = w.faults.contains(&Fault::Unordered { device: d });
            let link = self.links.get_mut(&d).unwrap();
            // The objects of the window, in transmission order: the others,
            // then the closed batches (a batch starts a frame of its own).
            let mut others: VecDeque<&'static [u8]> = std::mem::take(&mut link.pending).into();
            let mut batches: Vec<&'static [u8]> = std::mem::take(&mut link.batches);
            if unordered {
                reverse_records(&mut batches);
            }
            link.sent_batches.extend(batches.iter().copied());
            let mut batches: VecDeque<&'static [u8]> = batches.into();
            let mut resend: VecDeque<&'static [u8]> = VecDeque::new();
            let data_slot = hi.min(last);
            let mut frames: Vec<u8> = Vec::new();
            let mut leaves: Vec<u8> = Vec::new();
            let mut lists: Vec<u8> = Vec::new();
            let (mut normal, mut other, mut short) = (0u64, 0u64, 0u32);
            let hide = |slot| w.faults.contains(&Fault::Hide { device: d, slot });
            let mut head = link.head;
            let mut silent = false;
            for slot in lo..=hi {
                // The scanner's close slot is a catch-up slot: what is left
                // (catch-up frames), then the close resend of every batch it
                // sent (close-resend frames).
                let closing = matches!(d, Device::Box(_)) && slot == last;
                if closing {
                    resend = link.sent_batches.iter().copied().collect();
                }
                let shape = if closing { catchup } else { fps };
                let extra = w.faults.contains(&Fault::Extra { device: d, slot });
                let covert = w.faults.contains(&Fault::Covert { device: d, slot });
                let mut logged = 0u16;
                for i in 0..shape + u16::from(extra) {
                    if silent {
                        break;
                    }
                    let (kind, data, list) = if covert && i == 0 {
                        // Bytes that are no object, listing none.
                        link.offset += 3000;
                        (FrameKind::Normal, vec![0xC5u8; 3000], Vec::new())
                    } else if slot != data_slot {
                        (FrameKind::Normal, Vec::new(), Vec::new())
                    } else if link.carry.is_some() || !others.is_empty() {
                        let (data, list) = link.fill(&mut others, MAX_PAYLOAD_LEN);
                        (kind_of(closing, FrameKind::CatchUp), data, list)
                    } else if !batches.is_empty() {
                        let (data, list) = link.fill(&mut batches, MAX_PAYLOAD_LEN);
                        (kind_of(closing, FrameKind::CatchUp), data, list)
                    } else {
                        let (data, list) = link.fill(&mut resend, MAX_PAYLOAD_LEN);
                        (kind_of(closing, FrameKind::CloseResend), data, list)
                    };
                    let take = data.len();
                    let stream_offset = link.offset - take as u64;
                    let last_frame = i + 1 == shape;
                    let fill = last_frame && w.faults.contains(&Fault::Fill { device: d, slot });
                    let data_leaves: Vec<Hash512> =
                        data.chunks(CHUNK_LEN).map(chunk_leaf).collect();
                    let root = if fill {
                        // A nonzero byte 100 bytes past the data.
                        let mut leaves_all: Vec<Hash512> = data_leaves.clone();
                        let at = take + 100;
                        let j = at / CHUNK_LEN;
                        while leaves_all.len() <= j {
                            leaves_all.push(chunk_leaf(&[]));
                        }
                        let mut c = vec![0u8; CHUNK_LEN];
                        let from = j * CHUNK_LEN;
                        if from < take {
                            c[..take - from].copy_from_slice(&data[from..take]);
                        }
                        c[at - from] = 1;
                        leaves_all[j] = chunk_leaf(&c);
                        assert!(leaves_all.len() <= PAYLOAD_CHUNKS);
                        payload_root(leaves_all).unwrap()
                    } else if data_leaves.is_empty() {
                        empty_root()
                    } else {
                        payload_root(data_leaves.iter().copied()).unwrap()
                    };
                    let parts = UplinkFrameHeaderParts {
                        link_id_hash: link.id,
                        slot,
                        index: i,
                        kind,
                        stream_offset,
                        payload_len: take as u32,
                        payload_root: root,
                        objects_hash: objects_hash(&list_bytes(&list)),
                    };
                    let (obj, _) = header(&parts);
                    let injected =
                        last_frame && w.faults.contains(&Fault::Inject { device: d, slot });
                    let sig = if injected {
                        record_sig(&gateway_label, RecordPurpose::UplinkFrame, &obj)
                    } else {
                        record_sig(&link.label, RecordPurpose::UplinkFrame, &obj)
                    };
                    let lost = (i == 0 && hide(slot))
                        || w.faults.contains(&Fault::Lose {
                            device: d,
                            slot,
                            index: i,
                        });
                    if lost {
                        continue;
                    }
                    // The gateway logs the list the device signed, or one it
                    // made up ([`Fault::Relist`]), and chains what it logs.
                    let list = if i == 0 && w.faults.contains(&Fault::Relist { device: d, slot }) {
                        relisted(&list)
                    } else {
                        list
                    };
                    let parts = UplinkFrameHeaderParts {
                        objects_hash: objects_hash(&list_bytes(&list)),
                        ..parts
                    };
                    let (_, hash) = header(&parts);
                    head = chain_next(&head, &hash);
                    let entry = FrameEntry {
                        slot,
                        index: i,
                        kind,
                        stream_offset,
                        payload_len: take as u32,
                        object_count: list.len() as u16,
                        payload_root: root,
                        frame_sig: sig,
                    };
                    frames.extend_from_slice(group(&entry));
                    for l in &data_leaves {
                        leaves.extend_from_slice(l.as_bytes());
                    }
                    lists.extend_from_slice(&list_bytes(&list));
                    link.received = stream_offset + take as u64;
                    if kind == FrameKind::Normal {
                        normal += 1;
                    } else {
                        other += 1;
                    }
                    if i < shape {
                        logged += 1;
                    }
                }
                if logged < shape && !hide(slot) {
                    short += 1;
                }
                // After covert bytes the device sends nothing in the next
                // slot, then starts a byte past them.
                if silent {
                    link.offset += 1;
                }
                silent = covert;
            }
            assert!(!silent, "a covert fault's silent slot lies in its window");
            assert!(
                others.is_empty()
                    && batches.is_empty()
                    && resend.is_empty()
                    && link.carry.is_none(),
                "a window's objects fit its frames"
            );
            link.head = head;
            let log = UplinkFrameLog::new(&UplinkFrameLogParts {
                election_id: e.election_id(),
                station_id: station,
                gateway_id: gateway,
                session_index: index,
                link_id_hash: link.id,
                frames: LogFrames::new(leak_slice(frames)).unwrap(),
                leaves: LogLeaves::new(leak_slice(leaves)).unwrap(),
                objects: LogObjects::new(leak_slice(lists)).unwrap(),
            })
            .unwrap();
            let log = object(SCHEMA_UPLINK_FRAME_LOG, &log);
            wan += log.len() as u64;
            out.push((SCHEMA_UPLINK_FRAME_LOG, log));
            entries.push(SessionLink {
                link_id_hash: link.id,
                frames: normal,
                catchup_frames: other,
                missing_slots: short,
                stream_end: link.received,
                chain_head: head,
            });
        }
        entries.sort_by(|a, b| a.link_id_hash.as_bytes().cmp(b.link_id_hash.as_bytes()));
        let links: Vec<u8> = entries
            .iter()
            .flat_map(|l| group(l).iter().copied())
            .collect();
        let mut parts = UplinkSessionParts {
            election_id: e.election_id(),
            station_id: station,
            gateway_id: gateway,
            session_index: index,
            is_final: w.is_final,
            start_slot: w.start,
            end_slot: w.end,
            links: SessionLinks::new(leak_slice(links)).unwrap(),
            wan_bytes: 0,
            previous_session_hash: previous,
        };
        let size = UplinkSessionBody::new(&parts).unwrap().encoded_len() as u64;
        parts.wan_bytes = wan + size;
        let body = object(
            SCHEMA_UPLINK_SESSION_BODY,
            &UplinkSessionBody::new(&parts).unwrap(),
        );
        let body_hash = object_hash(body);
        let mut observers: Vec<CaptureSig<'static>> = Vec::new();
        if w.is_final {
            let mut people = e.people(s);
            people.retain(|p| p.role == ityv_encoding::EventRole::Observer);
            people.sort_by(|a, b| a.id.cmp(b.id));
            for p in people {
                let capture = hash_of("capture", &[e.stations[s].id.as_bytes(), p.id.as_bytes()]);
                let message = CaptureMessage {
                    body_hash,
                    observer_id: SignerId::new(text(p.id)).unwrap(),
                    capture_hash: capture,
                };
                let mut bytes = vec![0u8; message.encoded_len()];
                message.encode(&mut Writer::new(&mut bytes)).unwrap();
                observers.push(CaptureSig {
                    observer_id: SignerId::new(text(p.id)).unwrap(),
                    org_id: OrgId::new(text(p.org)).unwrap(),
                    capture_hash: capture,
                    sig: sign(&p.key, b"uplink-capture", &bytes),
                });
            }
        }
        let session = UplinkSession::new(
            body,
            sign(&e.gateway_label(s), b"uplink-session", body),
            &observers,
        )
        .unwrap();
        out.push((
            SCHEMA_UPLINK_SESSION,
            object(SCHEMA_UPLINK_SESSION, &session),
        ));
        self.sessions[s] = (index, body_hash);
        out
    }
}

/// The gateway identifier of a station.
#[must_use]
pub fn gateway_id(station: &str) -> GatewayId<'static> {
    GatewayId::new(text(&format!("GW-{station}"))).unwrap()
}
