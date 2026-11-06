//! Uplinks for the verifier's tests (ADR-0041): the standard connectivity
//! manifest, frame keys, gateways, and the frames, frame logs and gateway
//! sessions of a device's stream, built the way an honest device and
//! gateway would. A test changes what it needs in the built frames or
//! logs before they are encoded.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    dead_code,
    unreachable_pub
)]

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use std::vec::Vec;

use ityv_crypto::uplink::{
    chain_next, chain_start, chunk_leaf, link_id, objects_hash, payload_root, zero_leaf,
};
use ityv_crypto::{HybridSigningKey, RecordPurpose, RecordSigningKey, object_hash, sign_record};
use ityv_encoding::{
    BatchAttest, CARRY_PUBLIC, CARRY_SEALED, CHUNK_LEN, CaptureMessage, CaptureSig,
    ConnectivityManifest, DeviceClass, Direction, ElectionId, Encode, FrameEntry, FrameKind,
    GatewayId, HYBRID_SIG_LEN, Hash512, Ident, LogFrames, LogLeaves, LogObjects, MAX_PAYLOAD_LEN,
    ManifestEntries, ManifestEntry, Medium, ObjectHeader, Reader, SCHEMA_BATCH_ATTEST,
    SCHEMA_CAST_RECORD, SCHEMA_CONNECTIVITY_MANIFEST, SCHEMA_UPLINK_FRAME_HEADER,
    SCHEMA_UPLINK_FRAME_LOG, SCHEMA_UPLINK_SESSION, SCHEMA_UPLINK_SESSION_BODY, SCHEMA_VERSION_1,
    SCHEMA_VERSION_UPLINK, Schedule, SchemaId, SessionLink, SessionLinks, SignerId, StationId,
    StreamObject, UplinkFrame, UplinkFrameHeader, UplinkFrameHeaderParts, UplinkFrameLog,
    UplinkFrameLogParts, UplinkSession, UplinkSessionBody, UplinkSessionParts, decode_object,
};

use crate::common::{election, leak, leak_slice, object, registered, sign};

/// Normal and catch-up frames per slot of the scanners in the standard
/// test manifest (the reference values are 16 and 64, ADR-0022; the tests
/// keep frames few).
pub const SCANNER_FRAMES: (u16, u16) = (1, 2);
/// Normal and catch-up frames per slot of the check-in units.
pub const UNIT_FRAMES: (u16, u16) = (1, 2);

/// The key numbers of the frame keys: boxes from 600, check-in units from
/// 700.
pub const BOX_FRAME_BASE: u16 = 600;
pub const UNIT_FRAME_BASE: u16 = 700;

fn ident(bytes: &'static [u8], max: usize) -> Ident<'static> {
    Ident::new(bytes, max).unwrap()
}

/// One manifest entry.
#[allow(clippy::too_many_arguments)]
pub fn entry(
    class: DeviceClass,
    port: &'static [u8],
    direction: Direction,
    medium: Medium,
    peer: Option<DeviceClass>,
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
        counterpart: ident(b"declared", 64),
        schedule,
        frames_per_slot: frames.0,
        catchup_frames_per_slot: frames.1,
        carries,
    }
}

/// The standard manifest's entries: every class declared, the two frame
/// links, the one-way rules kept.
pub fn standard_entries() -> Vec<ManifestEntry<'static>> {
    use DeviceClass as C;
    use Direction as D;
    use Medium as M;
    use Schedule as S;
    let none = |class| entry(class, b"none", D::None, M::None, None, S::Unused, (0, 0), 0);
    std::vec![
        entry(
            C::InterpretationUnit,
            b"opto",
            D::OutOnly,
            M::Optocoupler,
            Some(C::CommitmentUnit),
            S::BoxOpenToClose,
            (0, 0),
            1 << 3
        ),
        entry(
            C::CommitmentUnit,
            b"uplink",
            D::OutOnly,
            M::OpticalTransmit,
            Some(C::Gateway),
            S::BoxOpenToClose,
            SCANNER_FRAMES,
            CARRY_PUBLIC | CARRY_SEALED
        ),
        entry(
            C::CheckinUnit,
            b"uplink",
            D::OutOnly,
            M::OpticalTransmit,
            Some(C::Gateway),
            S::BoxOpenToClose,
            UNIT_FRAMES,
            CARRY_PUBLIC
        ),
        none(C::ChamberModule),
        none(C::IdTerminalElectionDay),
        entry(
            C::IdTerminalEarlyVoting,
            b"roll-line",
            D::Both,
            M::ElectionLine,
            None,
            S::EarlyVoting,
            (0, 0),
            1 << 5
        ),
        entry(
            C::Gateway,
            b"wan",
            D::Both,
            M::OpticalLine,
            Some(C::LedgerCollector),
            S::Always,
            (0, 0),
            CARRY_PUBLIC | CARRY_SEALED | (1 << 6)
        ),
        entry(
            C::Tap,
            b"monitor",
            D::OutOnly,
            M::Ethernet,
            None,
            S::BoxOpenToClose,
            (0, 0),
            CARRY_PUBLIC | CARRY_SEALED
        ),
        entry(
            C::LedgerCollector,
            b"net",
            D::Both,
            M::OpticalLine,
            None,
            S::Always,
            (0, 0),
            1 << 4
        ),
        entry(
            C::BoardPublisher,
            b"net",
            D::Both,
            M::OpticalLine,
            None,
            S::Always,
            (0, 0),
            1 << 4
        ),
        entry(
            C::Witness,
            b"net",
            D::Both,
            M::OpticalLine,
            Some(C::LedgerCollector),
            S::Always,
            (0, 0),
            1 << 4
        ),
        entry(
            C::TrusteeReceiver,
            b"hsm",
            D::InOnly,
            M::OnSiteDirect,
            None,
            S::Witnessed,
            (0, 0),
            CARRY_SEALED
        ),
        none(C::ReceiptReader),
        none(C::ImprintReader),
        none(C::Printer),
    ]
}

/// The encoded manifest of `entries` (sorted by class and port).
pub fn manifest(entries: &[ManifestEntry<'static>]) -> &'static [u8] {
    manifest_of(election(), entries)
}

/// The encoded manifest of election `election` with `entries`.
pub fn manifest_of(
    election: ElectionId<'static>,
    entries: &[ManifestEntry<'static>],
) -> &'static [u8] {
    let mut entries = entries.to_vec();
    entries.sort_by(|a, b| a.key().cmp(&b.key()));
    let mut bytes = Vec::new();
    for e in &entries {
        let mut buf = std::vec![0u8; e.encoded_len()];
        let mut w = ityv_encoding::Writer::new(&mut buf);
        e.encode(&mut w).unwrap();
        bytes.extend_from_slice(&buf);
    }
    let entries = ManifestEntries::new(leak_slice(bytes)).unwrap();
    object(
        SCHEMA_CONNECTIVITY_MANIFEST,
        SCHEMA_VERSION_UPLINK,
        &ConnectivityManifest::new(election, entries),
    )
}

/// The standard manifest.
pub fn standard_manifest() -> &'static [u8] {
    static M: OnceLock<&'static [u8]> = OnceLock::new();
    M.get_or_init(|| manifest(&standard_entries()))
}

/// The frame signing key numbered `n`.
pub fn frame_signing(n: u16) -> RecordSigningKey {
    let [hi, lo] = n.to_be_bytes();
    let mut seed = [0x46; 32];
    seed[0] = hi;
    seed[1] = lo;
    RecordSigningKey::from_seed(seed)
}

/// The frame key numbered `n`.
pub fn frame_key(n: u16) -> &'static [u8; 32] {
    static CACHE: OnceLock<Mutex<BTreeMap<u16, &'static [u8; 32]>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut cache = cache.lock().unwrap();
    cache
        .entry(n)
        .or_insert_with(|| leak(*frame_signing(n).verifying_key().as_bytes()))
}

/// The link of frame key `n`.
pub fn link(n: u16) -> Hash512 {
    link_id(frame_key(n))
}

/// The gateway key number of a station: 800 plus a number per station
/// identifier.
pub fn gateway_number(station: &[u8]) -> u16 {
    static NUMBERS: OnceLock<Mutex<BTreeMap<Vec<u8>, u16>>> = OnceLock::new();
    let numbers = NUMBERS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut numbers = numbers.lock().unwrap();
    let next = 800 + numbers.len() as u16 * 2;
    *numbers.entry(station.to_vec()).or_insert(next)
}

/// The gateway entry of `station`.
pub fn gateway(station: &'static [u8]) -> ityv_encoding::GatewayEntry<'static> {
    let n = gateway_number(station);
    ityv_encoding::GatewayEntry {
        gateway_id: GatewayId::new(leak_slice([&b"GW-"[..], station].concat())).unwrap(),
        key: registered(n),
        attest_key: registered(n + 1),
    }
}

/// The signing key of `station`'s gateway.
pub fn gateway_signing(station: &[u8]) -> &'static HybridSigningKey {
    crate::common::signing(gateway_number(station))
}

/// One frame as a device built it.
#[derive(Debug, Clone)]
pub struct Built {
    pub slot: u64,
    pub index: u16,
    pub kind: FrameKind,
    pub stream_offset: u64,
    pub payload_len: u32,
    /// The data (`payload_len` bytes).
    pub data: Vec<u8>,
    /// Its object list: every object that overlaps the data.
    pub objects: Vec<StreamObject>,
    /// Nonzero fill bytes a test puts after the data: (payload offset,
    /// byte).
    pub fill: Vec<(usize, u8)>,
    pub payload_root: Hash512,
    pub leaves: Vec<Hash512>,
    pub sig: [u8; 64],
}

/// The encoded entries of `objects`.
pub fn list_bytes(objects: &[StreamObject]) -> Vec<u8> {
    let mut out = Vec::new();
    for o in objects {
        let mut buf = std::vec![0u8; o.encoded_len()];
        o.encode(&mut ityv_encoding::Writer::new(&mut buf)).unwrap();
        out.extend_from_slice(&buf);
    }
    out
}

impl Built {
    pub fn entry(&self) -> FrameEntry<'static> {
        FrameEntry {
            slot: self.slot,
            index: self.index,
            kind: self.kind,
            stream_offset: self.stream_offset,
            payload_len: self.payload_len,
            object_count: self.objects.len() as u16,
            payload_root: self.payload_root,
            frame_sig: leak(self.sig),
        }
    }

    /// The encoded object list.
    pub fn list(&self) -> &'static [u8] {
        leak_slice(list_bytes(&self.objects))
    }

    /// The frame's header on link `link`.
    pub fn header(&self, link: Hash512) -> UplinkFrameHeaderParts {
        self.entry().header(link, objects_hash(self.list()))
    }

    /// The bytes of chunk `j` of the payload (zero-extended).
    pub fn chunk(&self, j: usize) -> Vec<u8> {
        let mut c = std::vec![0u8; CHUNK_LEN];
        let start = j * CHUNK_LEN;
        for (i, b) in c.iter_mut().enumerate() {
            if let Some(d) = self.data.get(start + i) {
                *b = *d;
            }
        }
        for (at, byte) in &self.fill {
            if *at >= start && *at < start + CHUNK_LEN {
                c[at - start] = *byte;
            }
        }
        c
    }

    /// The whole payload (966,503 bytes), fill included.
    pub fn payload(&self) -> Vec<u8> {
        let mut p = self.data.clone();
        p.resize(MAX_PAYLOAD_LEN, 0);
        for (at, byte) in &self.fill {
            p[*at] = *byte;
        }
        p
    }

    /// Recomputes the leaves, root and signature under frame key `key` and
    /// link `link`: the data chunks' leaves are published, every chunk
    /// (fill included) goes into the root.
    pub fn seal(&mut self, key: u16, link: Hash512) {
        let data_chunks = (self.payload_len as usize).div_ceil(CHUNK_LEN);
        self.leaves = (0..data_chunks)
            .map(|j| chunk_leaf(&self.chunk(j)))
            .collect();
        self.payload_root = if self.fill.is_empty() {
            payload_root(self.leaves.iter().copied()).unwrap()
        } else {
            let touched: Vec<usize> = self.fill.iter().map(|(at, _)| at / CHUNK_LEN).collect();
            let zero = zero_leaf();
            let all: Vec<Hash512> = (0..256)
                .map(|j| {
                    if j < data_chunks || touched.contains(&j) {
                        chunk_leaf(&self.chunk(j))
                    } else {
                        zero
                    }
                })
                .collect();
            payload_root(all).unwrap()
        };
        self.sign(key, link);
    }

    /// Signs the header under frame key `key`.
    pub fn sign(&mut self, key: u16, link: Hash512) {
        let header = header_object(&self.header(link));
        self.sig = *sign_record(&frame_signing(key), RecordPurpose::UplinkFrame, header)
            .unwrap()
            .as_bytes();
    }
}

/// The encoded header object of `parts`.
pub fn header_object(parts: &UplinkFrameHeaderParts) -> &'static [u8] {
    object(
        SCHEMA_UPLINK_FRAME_HEADER,
        SCHEMA_VERSION_1,
        &UplinkFrameHeader::new(parts).unwrap(),
    )
}

/// The entries of `objects` (a stream's) that overlap `[start, start +
/// len)`; none for an empty range.
pub fn overlapping(objects: &[StreamObject], start: u64, len: u32) -> Vec<StreamObject> {
    if len == 0 {
        return Vec::new();
    }
    let end = start + u64::from(len);
    objects
        .iter()
        .filter(|o| o.stream_offset < end && o.end().unwrap() > start)
        .copied()
        .collect()
}

/// Frames that carry the raw bytes `stream` from slot `first` to slot
/// `last`, `per_slot` normal frames a slot, as early as they fit, listing
/// no object (bytes a device sends that are no object).
pub fn frames(key: u16, stream: &[u8], first: u64, last: u64, per_slot: u16) -> Vec<Built> {
    let link = link(key);
    let mut out = Vec::new();
    let mut offset = 0usize;
    for slot in first..=last {
        for index in 0..per_slot {
            let len = (stream.len() - offset).min(MAX_PAYLOAD_LEN);
            let mut f = Built {
                slot,
                index,
                kind: FrameKind::Normal,
                stream_offset: offset as u64,
                payload_len: len as u32,
                data: stream[offset..offset + len].to_vec(),
                objects: Vec::new(),
                fill: Vec::new(),
                payload_root: Hash512::ZERO,
                leaves: Vec::new(),
                sig: [0; 64],
            };
            f.seal(key, link);
            offset += len;
            out.push(f);
        }
    }
    out
}

/// The stream of `objects` laid end to end, with no fill: their bytes
/// concatenated, and each one's entry.
pub fn stream(objects: &[&'static [u8]]) -> (Vec<u8>, Vec<StreamObject>) {
    let mut bytes = Vec::new();
    let mut list = Vec::new();
    for o in objects {
        list.push(entry_at(o, bytes.len() as u64));
        bytes.extend_from_slice(o);
    }
    (bytes, list)
}

/// The entry of `object` at stream offset `at`.
pub fn entry_at(object: &'static [u8], at: u64) -> StreamObject {
    let mut r = Reader::new(object);
    let header = ObjectHeader::read(&mut r).unwrap();
    StreamObject {
        schema: header.schema_id(),
        object_hash: object_hash(object),
        stream_offset: at,
        len: object.len() as u32,
    }
}

/// Whether `object` is a share package.
fn is_package(object: &[u8]) -> bool {
    schema_of(object) == ityv_encoding::SCHEMA_SHARE_PACKAGE
}

/// How an honest device lays `objects` into frames of at most `capacity`
/// data bytes (ADR-0041 decision 3): each frame takes as much of the
/// stream as fits; a share package starts at a 4,096-byte boundary of the
/// frame it starts in, and so does the object after it, with zero fill
/// between; a package or the object after it whose boundary is past the
/// frame's end starts the next frame. Returns the stream (fill included),
/// its objects, and each frame's `(offset, len)` for `frames` frames.
pub fn layout(
    objects: &[&'static [u8]],
    capacity: usize,
    frames: usize,
) -> (Vec<u8>, Vec<StreamObject>, Vec<(u64, u32)>) {
    let mut stream: Vec<u8> = Vec::new();
    let mut listed: Vec<StreamObject> = Vec::new();
    let mut spans = Vec::new();
    let mut next = 0usize;
    let mut carry: &[u8] = &[];
    let mut previous_package = false;
    for _ in 0..frames {
        let start = stream.len();
        let mut used = 0usize;
        if !carry.is_empty() {
            let take = carry.len().min(capacity);
            stream.extend_from_slice(&carry[..take]);
            carry = &carry[take..];
            used = take;
        }
        while carry.is_empty() && next < objects.len() {
            let o = objects[next];
            let aligned = previous_package || is_package(o);
            let at = if aligned {
                used.div_ceil(CHUNK_LEN) * CHUNK_LEN
            } else {
                used
            };
            if at >= capacity {
                break;
            }
            stream.resize(start + at, 0);
            listed.push(entry_at(o, (start + at) as u64));
            let take = o.len().min(capacity - at);
            stream.extend_from_slice(&o[..take]);
            carry = &o[take..];
            used = at + take;
            previous_package = is_package(o);
            next += 1;
        }
        spans.push((start as u64, used as u32));
    }
    assert!(
        next == objects.len() && carry.is_empty(),
        "the frames hold the stream"
    );
    (stream, listed, spans)
}

/// The frames of a device on link `key` that sends `objects` from slot
/// `first` to slot `last`, `per_slot` normal frames a slot, laid out as
/// [`layout`] does, and the stream's objects.
pub fn device_frames(
    key: u16,
    objects: &[&'static [u8]],
    first: u64,
    last: u64,
    per_slot: u16,
) -> (Vec<Built>, Vec<StreamObject>) {
    device_frames_of(key, objects, first, last, per_slot, MAX_PAYLOAD_LEN)
}

/// As [`device_frames`], each frame holding at most `capacity` bytes:
/// the stream spread over more frames.
pub fn device_frames_of(
    key: u16,
    objects: &[&'static [u8]],
    first: u64,
    last: u64,
    per_slot: u16,
    capacity: usize,
) -> (Vec<Built>, Vec<StreamObject>) {
    let link = link(key);
    let count = (last - first + 1) as usize * usize::from(per_slot);
    let (stream, listed, spans) = layout(objects, capacity, count);
    let mut out = Vec::new();
    let mut spans = spans.into_iter();
    for slot in first..=last {
        for index in 0..per_slot {
            let (offset, len) = spans.next().unwrap();
            let at = offset as usize;
            let mut f = Built {
                slot,
                index,
                kind: FrameKind::Normal,
                stream_offset: offset,
                payload_len: len,
                data: stream[at..at + len as usize].to_vec(),
                objects: overlapping(&listed, offset, len),
                fill: Vec::new(),
                payload_root: Hash512::ZERO,
                leaves: Vec::new(),
                sig: [0; 64],
            };
            f.seal(key, link);
            out.push(f);
        }
    }
    (out, listed)
}

/// A device's link as the gateway records it.
#[derive(Debug, Clone)]
pub struct Link {
    pub key: u16,
    pub frames: Vec<Built>,
    /// The stream's objects (each frame lists those that overlap it).
    pub objects: Vec<StreamObject>,
}

impl Link {
    /// The link of frame key `key` sending `objects` from `first` to
    /// `last` at `per_slot` frames a slot.
    pub fn new(key: u16, objects: &[&'static [u8]], first: u64, last: u64, per_slot: u16) -> Self {
        let (frames, objects) = device_frames(key, objects, first, last, per_slot);
        Self {
            key,
            frames,
            objects,
        }
    }

    /// The link of a box's scanner (frame key `key`) as an honest one sends
    /// it: `objects` from `first` at one frame a slot, and in its close
    /// slot `close` a catch-up frame and then the close resend of `runs`,
    /// its batches again (PROTOCOL.md §5.8 item 4), going on into the next
    /// slot when it needs more frames. Without a batch, or closing in its
    /// first slot, the link of [`Link::new`].
    pub fn box_link(
        key: u16,
        objects: &[&'static [u8]],
        first: u64,
        close: u64,
        runs: &[&'static [u8]],
    ) -> Self {
        if runs.is_empty() || close <= first {
            return Self::new(key, objects, first, close, SCANNER_FRAMES.0);
        }
        let mut l = Self::new(key, objects, first, close - 1, SCANNER_FRAMES.0);
        let end = l
            .frames
            .last()
            .map_or(0, |f| f.stream_offset + u64::from(f.payload_len));
        let total: usize = runs.iter().map(|r| r.len() + CHUNK_LEN).sum();
        let (data, mut listed, mut spans) =
            layout(runs, MAX_PAYLOAD_LEN, total.div_ceil(MAX_PAYLOAD_LEN) + 1);
        while spans.len() > 1 && spans.last().is_some_and(|s| s.1 == 0) {
            spans.pop();
        }
        for o in &mut listed {
            o.stream_offset += end;
        }
        let link = link(key);
        // The catch-up frame (nothing left), then the resend's frames, the
        // last slot filled to its shape.
        let mut parts = std::vec![(close, 0u16, FrameKind::CatchUp, end, Vec::new())];
        for (k, (offset, len)) in spans.into_iter().enumerate() {
            let at = offset as usize;
            let position = k as u64 + 1;
            parts.push((
                close + position / 2,
                (position % 2) as u16,
                FrameKind::CloseResend,
                end + offset,
                data[at..at + len as usize].to_vec(),
            ));
        }
        if parts.len() % 2 == 1 {
            let slot = close + parts.len() as u64 / 2;
            let at = end + data.len() as u64;
            parts.push((slot, 1, FrameKind::CloseResend, at, Vec::new()));
        }
        for (slot, index, kind, offset, data) in parts {
            let payload_len = data.len() as u32;
            let mut f = Built {
                slot,
                index,
                kind,
                stream_offset: offset,
                payload_len,
                data,
                objects: overlapping(&listed, offset, payload_len),
                fill: Vec::new(),
                payload_root: Hash512::ZERO,
                leaves: Vec::new(),
                sig: [0; 64],
            };
            f.seal(key, link);
            l.frames.push(f);
        }
        l.objects.extend(listed);
        l
    }

    /// Lists in each frame the stream's objects that overlap it, and seals
    /// every frame again: after a test moved data between frames.
    pub fn relist(&mut self) {
        let link = link(self.key);
        for f in &mut self.frames {
            f.objects = overlapping(&self.objects, f.stream_offset, f.payload_len);
            f.seal(self.key, link);
        }
    }
}

/// What a session's link entry says, as a test may change it.
pub type LinkTweak<'t> = &'t dyn Fn(u32, &mut SessionLink);

/// Which session window a frame of link `l` goes in (`None`: the gateway
/// drops it), as a test may decide.
pub type Assign<'t> = &'t dyn Fn(usize, &Built) -> Option<usize>;

/// How a gateway records `links` at `station`: its windows and what a
/// test changes on the way.
pub struct Plan<'t> {
    pub station: &'static [u8],
    pub links: Vec<Link>,
    pub windows: Vec<(u64, u64)>,
    pub assign: Option<Assign<'t>>,
    pub tweak_link: Option<LinkTweak<'t>>,
    pub tweak_body: Option<&'t dyn Fn(&mut UplinkSessionParts<'static>)>,
    /// Observers who sign a capture statement on a session: (window,
    /// observer, organisation, roster key number).
    pub observers: Vec<(usize, &'static [u8], &'static [u8], u16)>,
    /// Another key for the gateway's signature.
    pub gateway_key: Option<&'static HybridSigningKey>,
}

impl Plan<'_> {
    /// The plan of `links` at `station` over windows of six slots from
    /// the first frame's slot; nothing changed.
    pub fn new(station: &'static [u8], links: Vec<Link>) -> Self {
        let first = links
            .iter()
            .flat_map(|l| l.frames.iter().map(|f| f.slot))
            .min()
            .unwrap();
        let last = links
            .iter()
            .flat_map(|l| l.frames.iter().map(|f| f.slot))
            .max()
            .unwrap();
        let mut windows = Vec::new();
        let mut start = first;
        while start <= last {
            windows.push((start, start + 5));
            start += 6;
        }
        Self {
            station,
            links,
            windows,
            assign: None,
            tweak_link: None,
            tweak_body: None,
            observers: Vec::new(),
            gateway_key: None,
        }
    }

    /// The window of `slot` (by default a frame goes in the window of its
    /// slot).
    fn window_of(&self, slot: u64) -> Option<usize> {
        self.windows
            .iter()
            .position(|(s, e)| *s <= slot && slot <= *e)
    }

    /// The frame logs and sessions, in ledger order: each session's logs,
    /// then the session; the last session is final.
    #[allow(clippy::too_many_lines)]
    pub fn events(&self) -> Vec<(SchemaId, &'static [u8])> {
        let gw = gateway(self.station);
        let mut out = Vec::new();
        let mut heads: BTreeMap<[u8; 64], (Hash512, u64)> = BTreeMap::new();
        let mut previous = Hash512::ZERO;
        for (k, (start, end)) in self.windows.iter().enumerate() {
            let index = k as u32 + 1;
            let mut entries: Vec<SessionLink> = Vec::new();
            for (li, l) in self.links.iter().enumerate() {
                let link = link(l.key);
                let frames: Vec<&Built> = l
                    .frames
                    .iter()
                    .filter(|f| {
                        let w = match self.assign {
                            Some(a) => a(li, f),
                            None => self.window_of(f.slot),
                        };
                        w == Some(k)
                    })
                    .collect();
                let (mut head, mut stream_end) = heads
                    .get(&link.0)
                    .copied()
                    .unwrap_or((chain_start(&link), 0));
                if frames.is_empty() {
                    continue;
                }
                for f in &frames {
                    let h = object_hash(header_object(&f.header(link)));
                    head = chain_next(&head, &h);
                    stream_end = f.stream_offset + u64::from(f.payload_len);
                }
                let mut frame_bytes = Vec::new();
                let mut leaf_bytes = Vec::new();
                let mut object_bytes = Vec::new();
                for f in &frames {
                    let e = f.entry();
                    let mut buf = std::vec![0u8; e.encoded_len()];
                    e.encode(&mut ityv_encoding::Writer::new(&mut buf)).unwrap();
                    frame_bytes.extend_from_slice(&buf);
                    for leaf in &f.leaves {
                        leaf_bytes.extend_from_slice(leaf.as_bytes());
                    }
                    object_bytes.extend_from_slice(&list_bytes(&f.objects));
                }
                let log = UplinkFrameLog::new(&UplinkFrameLogParts {
                    election_id: election(),
                    station_id: StationId::new(self.station).unwrap(),
                    gateway_id: gw.gateway_id,
                    session_index: index,
                    link_id_hash: link,
                    frames: LogFrames::new(leak_slice(frame_bytes)).unwrap(),
                    leaves: LogLeaves::new(leak_slice(leaf_bytes)).unwrap(),
                    objects: LogObjects::new(leak_slice(object_bytes)).unwrap(),
                })
                .unwrap();
                out.push((
                    SCHEMA_UPLINK_FRAME_LOG,
                    object(SCHEMA_UPLINK_FRAME_LOG, SCHEMA_VERSION_1, &log),
                ));
                heads.insert(link.0, (head, stream_end));
                entries.push(SessionLink {
                    link_id_hash: link,
                    frames: frames
                        .iter()
                        .filter(|f| f.kind == FrameKind::Normal)
                        .count() as u64,
                    catchup_frames: frames
                        .iter()
                        .filter(|f| f.kind != FrameKind::Normal)
                        .count() as u64,
                    missing_slots: 0,
                    stream_end,
                    chain_head: head,
                });
            }
            if let Some(t) = self.tweak_link {
                for e in &mut entries {
                    t(index, e);
                }
            }
            entries.sort_by(|a, b| a.link_id_hash.as_bytes().cmp(b.link_id_hash.as_bytes()));
            let mut link_bytes = Vec::new();
            for e in &entries {
                let mut buf = std::vec![0u8; e.encoded_len()];
                e.encode(&mut ityv_encoding::Writer::new(&mut buf)).unwrap();
                link_bytes.extend_from_slice(&buf);
            }
            let mut parts = UplinkSessionParts {
                election_id: election(),
                station_id: StationId::new(self.station).unwrap(),
                gateway_id: gw.gateway_id,
                session_index: index,
                is_final: k + 1 == self.windows.len(),
                start_slot: *start,
                end_slot: *end,
                links: SessionLinks::new(leak_slice(link_bytes)).unwrap(),
                wan_bytes: 1000 * u64::from(index),
                previous_session_hash: previous,
            };
            if let Some(t) = self.tweak_body {
                t(&mut parts);
            }
            let body = UplinkSessionBody::new(&parts).unwrap();
            let body = object(SCHEMA_UPLINK_SESSION_BODY, SCHEMA_VERSION_UPLINK, &body);
            previous = object_hash(body);
            let key = self
                .gateway_key
                .unwrap_or_else(|| gateway_signing(self.station));
            let sig = sign(key, b"uplink-session", body);
            let observers: Vec<CaptureSig<'static>> = self
                .observers
                .iter()
                .filter(|o| o.0 == k)
                .map(|(_, id, o, n)| {
                    capture_sig(
                        body,
                        id,
                        o,
                        crate::common::signing(crate::common::ROSTER_BASE + n),
                        Hash512([0xCA; 64]),
                    )
                })
                .collect();
            let session = UplinkSession::new(body, sig, &observers).unwrap();
            out.push((
                SCHEMA_UPLINK_SESSION,
                object(SCHEMA_UPLINK_SESSION, SCHEMA_VERSION_UPLINK, &session),
            ));
        }
        out
    }
}

/// The frame logs and sessions of `station`'s gateway over `links`, in
/// ledger order, with windows of six slots from the first frame's slot;
/// the last session is final. `tweak` may change each session's link
/// entries before signing.
pub fn sessions(
    station: &'static [u8],
    links: &[Link],
    tweak: Option<LinkTweak<'_>>,
) -> Vec<(SchemaId, &'static [u8])> {
    let mut plan = Plan::new(station, links.to_vec());
    plan.tweak_link = tweak;
    plan.events()
}

/// An observer's capture statement on a session body.
pub fn capture_sig(
    body: &'static [u8],
    observer: &'static [u8],
    org: &'static [u8],
    key: &HybridSigningKey,
    capture: Hash512,
) -> CaptureSig<'static> {
    let message = CaptureMessage {
        body_hash: object_hash(body),
        observer_id: SignerId::new(observer).unwrap(),
        capture_hash: capture,
    };
    let mut buf = std::vec![0u8; message.encoded_len()];
    message
        .encode(&mut ityv_encoding::Writer::new(&mut buf))
        .unwrap();
    CaptureSig {
        observer_id: SignerId::new(observer).unwrap(),
        org_id: ityv_encoding::OrgId::new(org).unwrap(),
        capture_hash: capture,
        sig: sign(key, b"uplink-capture", leak_slice(buf)),
    }
}

/// The schema of an encoded object.
pub fn schema_of(object: &[u8]) -> SchemaId {
    let mut r = Reader::new(object);
    ObjectHeader::read(&mut r).unwrap().schema_id()
}

/// The share package the test world's record `record` names: the stand-in
/// of its box and first module counter (`world::share_package`), if that
/// is the one it names.
pub fn package_of(record: &'static [u8]) -> Option<&'static [u8]> {
    use ityv_encoding::{CastRecord, SCHEMA_SHARE_PACKAGE};
    let r = decode_object::<CastRecord<'_>>(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, record).ok()?;
    let counter = r.body().module_counters().iter().next()?.counter;
    let mut body = r.body().box_id().as_bytes().to_vec();
    body.extend_from_slice(&counter.to_be_bytes());
    let p = fake_object(SCHEMA_SHARE_PACKAGE, &body);
    (object_hash(p) == *r.body().share_package_hash()).then_some(p)
}

/// `stream` with each record's share package right after it, where the
/// world can make it.
pub fn with_packages(stream: &[&'static [u8]]) -> Vec<&'static [u8]> {
    let mut out = Vec::new();
    for o in stream {
        out.push(*o);
        if schema_of(o) == SCHEMA_CAST_RECORD
            && let Some(p) = package_of(o)
        {
            out.push(p);
        }
    }
    out
}

/// A box's stream from its ledger events in order: each batch attestation
/// followed by its records (the first `record_count` seen before it that
/// no earlier batch took: a batch takes the counters after the previous
/// one's) in record-hash order; progress ticks and challenge openings
/// where they come.
pub fn box_stream(events: &[&'static [u8]]) -> Vec<&'static [u8]> {
    let mut out = Vec::new();
    let mut pending: Vec<&'static [u8]> = Vec::new();
    for e in events {
        let schema = schema_of(e);
        if schema == SCHEMA_CAST_RECORD {
            pending.push(e);
        } else if schema == SCHEMA_BATCH_ATTEST {
            let n = decode_object::<BatchAttest<'_>>(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, e)
                .map_or(pending.len(), |b| usize::from(b.body().record_count()));
            let take = n.min(pending.len());
            let mut group: Vec<&'static [u8]> = pending.drain(..take).collect();
            group.sort_by_key(|r| object_hash(r).0);
            out.push(*e);
            out.extend(group);
        } else {
            out.push(*e);
        }
    }
    out
}

/// The batch runs of a box's stream (as [`box_stream`] orders it): each
/// attestation and the records after it.
pub fn batch_runs(stream: &[&'static [u8]]) -> Vec<&'static [u8]> {
    let mut out = Vec::new();
    let mut inside = false;
    for o in stream {
        let schema = schema_of(o);
        inside = schema == SCHEMA_BATCH_ATTEST || (inside && schema == SCHEMA_CAST_RECORD);
        if inside {
            out.push(*o);
        }
    }
    out
}

/// The election identifier, for tests that build their own bodies.
pub fn election_id() -> ElectionId<'static> {
    election()
}

/// A signature of `len` repeated bytes, for forged entries.
pub const fn junk_sig(byte: u8) -> [u8; HYBRID_SIG_LEN] {
    [byte; HYBRID_SIG_LEN]
}

/// The frame key number of `key` (boxes from 600, units from 700).
pub fn key_number(key: &[u8; 32]) -> u16 {
    (BOX_FRAME_BASE..UNIT_FRAME_BASE + 100)
        .find(|n| frame_key(*n) == key)
        .expect("a frame key of the tests")
}

/// The body of a connectivity incident at `station` (`None`: the whole
/// election) and `box_id` (`None`: the whole station), slots 160 to 165;
/// `unit` when a commitment unit is involved.
pub fn incident_body(
    station: Option<&'static [u8]>,
    box_id: Option<&'static [u8]>,
    unit: bool,
) -> &'static [u8] {
    use ityv_encoding::{
        BoxId, ConnectivityIncidentBody, ConnectivityIncidentParts, IncidentKind,
        SCHEMA_CONNECTIVITY_INCIDENT_BODY,
    };
    let body = ConnectivityIncidentBody::new(&ConnectivityIncidentParts {
        election_id: election(),
        station_id: station.map(|s| StationId::new(s).unwrap()),
        box_id: box_id.map(|b| BoxId::new(b).unwrap()),
        kind: IncidentKind::CaptureMismatch,
        from_slot: 160,
        to_slot: 165,
        commitment_unit: unit,
        evidence_hash: Hash512([0xE0; 64]),
    })
    .unwrap();
    object(SCHEMA_CONNECTIVITY_INCIDENT_BODY, SCHEMA_VERSION_1, &body)
}

/// An object of schema `schema` whose body is `body` (not a canonical
/// object of that schema: a stand-in for bytes the public cannot read).
pub fn fake_object(schema: SchemaId, body: &[u8]) -> &'static [u8] {
    let mut out = std::vec![0u8; ityv_encoding::HEADER_LEN];
    ObjectHeader::new(schema, SCHEMA_VERSION_1, body.len() as u32)
        .write(&mut ityv_encoding::Writer::new(&mut out))
        .unwrap();
    out.extend_from_slice(body);
    leak_slice(out)
}

/// The encoded `UplinkFrame` of `frame` on link `key` (its fill must be
/// zero).
pub fn wire_frame(frame: &Built, key: u16) -> Vec<u8> {
    let payload: Box<[u8; MAX_PAYLOAD_LEN]> =
        frame.payload().into_boxed_slice().try_into().unwrap();
    let objects = ityv_encoding::FrameObjects::new(frame.list()).unwrap();
    let wire = UplinkFrame::new(&frame.header(link(key)), objects, &payload, &frame.sig).unwrap();
    let mut out = std::vec![0u8; ityv_encoding::HEADER_LEN + wire.encoded_len()];
    let n = ityv_encoding::encode_object(
        ityv_encoding::SCHEMA_UPLINK_FRAME,
        SCHEMA_VERSION_UPLINK,
        &wire,
        &mut out,
    )
    .unwrap();
    out.truncate(n);
    out
}

/// A capture file of `records`: each one's length, then its bytes.
pub fn capture_file(records: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for r in records {
        out.extend_from_slice(&(r.len() as u32).to_be_bytes());
        out.extend_from_slice(r);
    }
    out
}

/// The session number and link of an encoded frame log.
pub fn log_key(log: &[u8]) -> (u32, Hash512) {
    let l = decode_object::<UplinkFrameLog<'_>>(SCHEMA_UPLINK_FRAME_LOG, SCHEMA_VERSION_1, log)
        .unwrap();
    (l.parts().session_index, l.parts().link_id_hash)
}

/// The frame log `log` with `change` made to its fields, re-encoded.
pub fn relog(
    log: &'static [u8],
    change: impl FnOnce(&mut UplinkFrameLogParts<'static>),
) -> &'static [u8] {
    let l =
        decode_object::<UplinkFrameLog<'static>>(SCHEMA_UPLINK_FRAME_LOG, SCHEMA_VERSION_1, log)
            .unwrap();
    let mut parts = *l.parts();
    change(&mut parts);
    object(
        SCHEMA_UPLINK_FRAME_LOG,
        SCHEMA_VERSION_1,
        &UplinkFrameLog::new(&parts).unwrap(),
    )
}

/// Whose device event `event` is: its box, or its station.
pub fn device_of(event: &'static [u8]) -> Option<(bool, &'static [u8])> {
    use ityv_encoding::{
        CastRecord, ChallengeOpening, ParticipationSet, ProgressBody, ProgressTick,
        SCHEMA_CHALLENGE_OPENING, SCHEMA_PARTICIPATION_SET, SCHEMA_PROGRESS_TICK, schema_version,
    };
    let schema = schema_of(event);
    let v = schema_version(schema);
    if schema == SCHEMA_CAST_RECORD {
        let r = decode_object::<CastRecord<'_>>(schema, v, event).ok()?;
        Some((true, r.body().box_id().as_bytes()))
    } else if schema == SCHEMA_BATCH_ATTEST {
        let b = decode_object::<BatchAttest<'_>>(schema, v, event).ok()?;
        Some((true, b.body().box_id().as_bytes()))
    } else if schema == SCHEMA_CHALLENGE_OPENING {
        let c = decode_object::<ChallengeOpening<'_>>(schema, v, event).ok()?;
        Some((true, c.body().box_id().as_bytes()))
    } else if schema == SCHEMA_PROGRESS_TICK {
        match *decode_object::<ProgressTick<'_>>(schema, v, event)
            .ok()?
            .body()
        {
            ProgressBody::Box(b) => Some((true, b.parts().box_id.as_bytes())),
            ProgressBody::Checkin(c) => Some((false, c.parts().station_id.as_bytes())),
        }
    } else if schema == SCHEMA_PARTICIPATION_SET {
        let p = decode_object::<ParticipationSet<'_>>(schema, v, event).ok()?;
        Some((false, p.station_id().as_bytes()))
    } else {
        None
    }
}

/// The opening and close time buckets of box `box_id` in `events`.
fn box_buckets(events: &[&'static [u8]], box_id: &[u8]) -> (Option<u64>, Option<u64>) {
    use ityv_encoding::{
        BoxClose, BoxOpenedBody, SCHEMA_BOX_CLOSE, SCHEMA_BOX_OPENED_BODY, SCHEMA_WITNESSED_EVENT,
        WitnessedEvent, schema_version,
    };
    let mut open = None;
    let mut close = None;
    for e in events {
        let schema = schema_of(e);
        if schema == SCHEMA_WITNESSED_EVENT && open.is_none() {
            let Ok(w) = decode_object::<WitnessedEvent<'_>>(schema, schema_version(schema), e)
            else {
                continue;
            };
            if let Ok(b) = w.body::<BoxOpenedBody<'_>>(SCHEMA_BOX_OPENED_BODY)
                && b.parts().box_id.as_bytes() == box_id
            {
                open = Some(b.parts().time_bucket.get());
            }
        } else if schema == SCHEMA_BOX_CLOSE
            && close.is_none()
            && let Ok(c) = decode_object::<BoxClose<'_>>(schema, SCHEMA_VERSION_1, e)
            && c.body().box_id().as_bytes() == box_id
        {
            close = Some(c.body().time_bucket().get());
        }
    }
    (open, close)
}

/// The links that carry every device event of `events` (the ledger's
/// event objects so far) for every station of `genesis`'s last state, by
/// station: each opened box's scanner from the first slot of its opening
/// to the slot after its close bucket (its closing tick's), its records'
/// share packages after them; the station's in-service unit from the
/// station's first opening to its last box's close slot. While a box is
/// open, its scanner (and the unit) send to the end of the six-slot window
/// that holds the station's last close slot (or its first opening).
pub fn station_links(
    genesis: &ityv_verify::VerifiedGenesis<'static>,
    events: &[&'static [u8]],
) -> Vec<(&'static [u8], Vec<Link>)> {
    use ityv_encoding::TimeBucket;
    use ityv_verify::bucket_slots;
    let slots = |bucket: u64| bucket_slots(TimeBucket::new(bucket)).unwrap();
    let mut out = Vec::new();
    for station in genesis.stations() {
        let mut opened = Vec::new();
        for b in station.boxes() {
            let (open, close) = box_buckets(events, b.as_bytes());
            let Some(open) = open else {
                continue;
            };
            opened.push((b, slots(open).0, close.map(|c| slots(c).1 + 1)));
        }
        let Some(first) = opened.iter().map(|(_, f, _)| *f).min() else {
            continue;
        };
        let closed_end = opened.iter().filter_map(|(_, _, c)| *c).max();
        let any_open = opened.iter().any(|(_, _, c)| c.is_none());
        let end = closed_end.unwrap_or(first);
        let window_end = first + (end - first) / 6 * 6 + 5;
        let mut links = Vec::new();
        for (b, open, close) in &opened {
            let entry = genesis.expected_box(b.as_bytes()).unwrap();
            let mine: Vec<&'static [u8]> = events
                .iter()
                .copied()
                .filter(|e| device_of(e) == Some((true, b.as_bytes())))
                .collect();
            let stream = box_stream(&mine);
            let key = key_number(entry.frame_key);
            links.push(match close {
                Some(c) => Link::box_link(
                    key,
                    &with_packages(&stream),
                    *open,
                    *c,
                    &with_packages(&batch_runs(&stream)),
                ),
                None => Link::new(
                    key,
                    &with_packages(&stream),
                    *open,
                    window_end,
                    SCANNER_FRAMES.0,
                ),
            });
        }
        let station_id = station.station_id().as_bytes();
        let mine: Vec<&'static [u8]> = events
            .iter()
            .copied()
            .filter(|e| device_of(e) == Some((false, station_id)))
            .collect();
        links.push(Link::new(
            key_number(station.primary().frame_key),
            &mine,
            first,
            if any_open { window_end } else { end },
            UNIT_FRAMES.0,
        ));
        let id: &'static [u8] = leak_slice(station_id.to_vec());
        out.push((id, links));
    }
    out
}

/// The frame logs and sessions that carry every device event of `events`
/// for every station of `genesis`'s last state ([`station_links`]).
pub fn for_ledger(
    genesis: &ityv_verify::VerifiedGenesis<'static>,
    events: &[&'static [u8]],
) -> Vec<(SchemaId, &'static [u8])> {
    station_links(genesis, events)
        .into_iter()
        .flat_map(|(station, links)| sessions(station, &links, None))
        .collect()
}
