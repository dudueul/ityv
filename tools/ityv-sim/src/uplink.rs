//! The connectivity side of a simulated election (ADR-0022, ADR-0041): the
//! manifest the genesis pins, and the gateway's frame logs and sessions
//! over the device events the ledger carries.
//!
//! Every scanner and check-in unit sends its manifest's normal frames in
//! every slot from its station's opening to the slot after its box's close
//! (the unit to the station's last box). The objects a device made since
//! the gateway's previous session go, in transmission order (a batch
//! attestation then its records by record hash, ticks and openings where
//! they come, the unit's observer counts and participation set), into the
//! first frames of the last slot the device sends in within the session's
//! window. A record no batch attestation has taken is never sent: the
//! device sends records only in closed batches (PROTOCOL.md §5.8 item 4).
//! The gateway closes a session at each window of six slots from the
//! station's opening ([`Window`], a step of the plan); the last is final,
//! after the station's participation set, and the station's two observers
//! sign a capture statement on it. Their capture's hash is fixture data:
//! the simulator writes no capture file.
//!
//! A scenario changes what a device or the gateway did with a [`Fault`] on
//! a window.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use ityv_crypto::uplink::{chain_next, chain_start, chunk_leaf, link_id, payload_root};
use ityv_crypto::{RecordPurpose, object_hash};
use ityv_encoding::{
    BatchAttest, CARRY_LEDGER, CARRY_PUBLIC, CARRY_ROLL, CARRY_SEALED, CARRY_SESSION, CHUNK_LEN,
    CaptureMessage, CaptureSig, CastRecord, ChallengeOpening, ConnectivityManifest, DeviceClass,
    Direction, ElectionId, Encode, FrameEntry, FrameKind, GatewayId, HEADER_LEN, Hash512, Ident,
    LogFrames, LogLeaves, LogObjects, MAX_PAYLOAD_LEN, ManifestEntries, ManifestEntry, Medium,
    ObjectHeader, ObserverCountAttestBody, OrgId, PAYLOAD_CHUNKS, ParticipationSet, ProgressBody,
    ProgressTick, Reader, SCHEMA_BATCH_ATTEST, SCHEMA_CAST_RECORD, SCHEMA_CHALLENGE_OPENING,
    SCHEMA_CONNECTIVITY_MANIFEST, SCHEMA_OBSERVER_COUNT_ATTEST_BODY, SCHEMA_PARTICIPATION_SET,
    SCHEMA_PROGRESS_TICK, SCHEMA_UPLINK_FRAME_HEADER, SCHEMA_UPLINK_FRAME_LOG,
    SCHEMA_UPLINK_SESSION, SCHEMA_UPLINK_SESSION_BODY, SCHEMA_VERSION_1, SCHEMA_WITNESSED_EVENT,
    Schedule, SchemaId, SessionLink, SessionLinks, SignerId, StationId, StreamObject,
    UplinkFrameHeader, UplinkFrameHeaderParts, UplinkFrameLog, UplinkFrameLogParts, UplinkSession,
    UplinkSessionBody, UplinkSessionParts, WitnessedEvent, Writer, decode_object, encode_object,
    schema_version,
};

use crate::election::Election;
use crate::util::{group, hash_of, leak_slice, object, record_sig, sign, text};

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
    /// The first frame of `slot` was lost on the line; the gateway declares
    /// the slot missing. What it carried never arrives.
    Lose {
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
fn header(parts: &UplinkFrameHeaderParts) -> ([u8; HEADER_LEN + 151], Hash512) {
    let mut buf = [0u8; HEADER_LEN + 151];
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
    /// Objects made and not yet sent, in transmission order.
    pending: Vec<&'static [u8]>,
    /// Records no batch attestation has taken yet.
    unbatched: Vec<&'static [u8]>,
    /// Every object seen (a replayed event is sent once).
    seen: BTreeSet<[u8; 64]>,
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
                    pending: Vec::new(),
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
    /// stream (a record waits for the batch attestation that takes it).
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
                let take = n.min(link.unbatched.len());
                let at = link.unbatched.len() - take;
                let mut records = link.unbatched.split_off(at);
                records.sort_by_key(|r| object_hash(r).0);
                link.pending.push(event);
                link.pending.extend(records);
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
            let fps = match d {
                Device::Box(_) => SCANNER_FRAMES.0,
                Device::Unit(_) => UNIT_FRAMES.0,
            };
            let gateway_label = e.gateway_label(s);
            let link = self.links.get_mut(&d).unwrap();
            // The objects of the window, in transmission order.
            let mut objects = std::mem::take(&mut link.pending);
            if w.faults.contains(&Fault::Unordered { device: d }) {
                let mut i = 0;
                while i < objects.len() {
                    if schema_of(objects[i]) == Some(SCHEMA_CAST_RECORD) {
                        let run_end = (i..objects.len())
                            .find(|j| schema_of(objects[*j]) != Some(SCHEMA_CAST_RECORD))
                            .unwrap_or(objects.len());
                        objects[i..run_end].reverse();
                        i = run_end;
                    } else {
                        i += 1;
                    }
                }
            }
            let mut data: Vec<u8> = Vec::new();
            let mut listed: Vec<StreamObject> = Vec::new();
            for o in &objects {
                listed.push(StreamObject {
                    schema: schema_of(o).unwrap(),
                    object_hash: object_hash(o),
                    stream_offset: link.offset + data.len() as u64,
                    len: o.len() as u32,
                });
                data.extend_from_slice(o);
            }
            let data_slot = hi.min(last);
            let mut rest: &[u8] = &data;
            let mut frames: Vec<u8> = Vec::new();
            let mut leaves: Vec<u8> = Vec::new();
            let mut received: Vec<(u64, u64)> = Vec::new();
            let (mut normal, mut short) = (0u64, 0u32);
            let hide = |slot| w.faults.contains(&Fault::Hide { device: d, slot });
            let mut head = link.head;
            for slot in lo..=hi {
                let extra = w.faults.contains(&Fault::Extra { device: d, slot });
                let count = if extra { fps + 1 } else { fps };
                let mut logged = 0u16;
                for i in 0..count {
                    let take = if slot == data_slot {
                        rest.len().min(MAX_PAYLOAD_LEN)
                    } else {
                        0
                    };
                    let (chunk, tail) = rest.split_at(take);
                    rest = tail;
                    let last_frame = i + 1 == fps;
                    let fill = last_frame && w.faults.contains(&Fault::Fill { device: d, slot });
                    let data_leaves: Vec<Hash512> =
                        chunk.chunks(CHUNK_LEN).map(chunk_leaf).collect();
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
                            c[..take - from].copy_from_slice(&chunk[from..take]);
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
                        kind: FrameKind::Normal,
                        stream_offset: link.offset,
                        payload_len: take as u32,
                        payload_root: root,
                    };
                    link.offset += take as u64;
                    let (obj, hash) = header(&parts);
                    let injected =
                        last_frame && w.faults.contains(&Fault::Inject { device: d, slot });
                    let sig = if injected {
                        record_sig(&gateway_label, RecordPurpose::UplinkFrame, &obj)
                    } else {
                        record_sig(&link.label, RecordPurpose::UplinkFrame, &obj)
                    };
                    let lost = i == 0
                        && (hide(slot) || w.faults.contains(&Fault::Lose { device: d, slot }));
                    if lost {
                        continue;
                    }
                    head = chain_next(&head, &hash);
                    let entry = FrameEntry {
                        slot,
                        index: i,
                        kind: FrameKind::Normal,
                        stream_offset: parts.stream_offset,
                        payload_len: parts.payload_len,
                        payload_root: root,
                        frame_sig: sig,
                    };
                    frames.extend_from_slice(group(&entry));
                    for l in &data_leaves {
                        leaves.extend_from_slice(l.as_bytes());
                    }
                    received.push((parts.stream_offset, parts.stream_offset + take as u64));
                    link.received = parts.stream_offset + take as u64;
                    normal += 1;
                    if i < fps {
                        logged += 1;
                    }
                }
                if logged < fps && !hide(slot) {
                    short += 1;
                }
            }
            assert!(rest.is_empty(), "a window's objects fit its frames");
            link.head = head;
            let objects: Vec<u8> = listed
                .iter()
                .filter(|o| {
                    received
                        .iter()
                        .any(|(a, b)| *a <= o.stream_offset && o.stream_offset < *b)
                })
                .flat_map(|o| group(o).iter().copied())
                .collect();
            let log = UplinkFrameLog::new(&UplinkFrameLogParts {
                election_id: e.election_id(),
                station_id: station,
                gateway_id: gateway,
                session_index: index,
                link_id_hash: link.id,
                frames: LogFrames::new(leak_slice(frames)).unwrap(),
                leaves: LogLeaves::new(leak_slice(leaves)).unwrap(),
                objects: LogObjects::new(leak_slice(objects)).unwrap(),
            })
            .unwrap();
            let log = object(SCHEMA_UPLINK_FRAME_LOG, &log);
            wan += log.len() as u64;
            out.push((SCHEMA_UPLINK_FRAME_LOG, log));
            entries.push(SessionLink {
                link_id_hash: link.id,
                frames: normal,
                catchup_frames: 0,
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
