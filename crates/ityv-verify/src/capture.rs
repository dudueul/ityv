//! Tools of the three-source comparison (PROTOCOL.md §5.8 item 7;
//! ADR-0022 decisions 7 and 8, ADR-0041 decision 12; VC-081). They are
//! outside the status: their inputs are not on the public ledger, and a
//! mismatch reaches the ledger as a `ConnectivityIncident` the committee
//! and observers sign.
//!
//! * [`compare_capture`]: an observer's capture file, the frames its
//!   recorder took from a passive tap, against the frame logs the gateway
//!   published. The file is `u32_be length ‖ UplinkFrame object`, repeated,
//!   in the order received; its hash ([`ityv_crypto::uplink::capture_hash`])
//!   is what the observer signs on a session. Every captured frame is
//!   decoded (a nonzero byte after the data is not a canonical frame), its
//!   header and payload root computed from its bytes and its signature
//!   checked under the link's frame key; it is then matched with the
//!   published frame of the same link, slot and number: the same header,
//!   another header, or none (the gateway hid it). Published frames the
//!   capture lacks between the first and last slot it captured of their
//!   link are listed too (injected, or the tap missed them). The
//!   captured bytes are reassembled into the link's stream, and every
//!   object the captured frames list (the device signed the lists) that
//!   they hold whole must hash to its listed hash and start with a
//!   canonical header of its schema; captured bytes no listed object
//!   covers, and fill around a share package that is not zero, are not
//!   objects. A tap sees the sealed share packages too, so this is where
//!   their bytes and the fill after them are checked.
//! * [`compare_carrier`]: the carrier's connection records, which the
//!   committee receives and publishes (`LEGAL_ANNEX.md` amendment 8,
//!   §181-2 ⑤), against the sessions: on a gateway's outer line the bytes
//!   must be the sum of the sessions' `wan_bytes` and every interval with
//!   traffic must meet a session's window; the roll lookup line exists only
//!   at an early-voting station and carries traffic only between the
//!   station's first opening and last close. The byte counts compare
//!   exactly; the layer the gateway counts at is the carrier's (fixed by
//!   sub-regulation and the gateway reference design, M8).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use ityv_crypto::uplink::{capture_hash, link_id, objects_hash, payload_root_of};
use ityv_crypto::{RecordPurpose, RecordSignature, RecordVerifyingKey, object_hash, verify_record};
use ityv_encoding::{
    FRAME_HEADER_LEN, FrameObjects, HEADER_LEN, Hash512, ObjectHeader, Reader, SCHEMA_UPLINK_FRAME,
    SCHEMA_UPLINK_FRAME_HEADER, SCHEMA_UPLINK_FRAME_LOG, SCHEMA_VERSION_1, SCHEMA_VERSION_UPLINK,
    StationKind, StreamObject, UplinkFrame, UplinkFrameHeader, UplinkFrameLog, decode_object,
    encode_object,
};

use crate::connectivity::{ConnectivityStage, close_slot, opening_slot, tiling};
use crate::genesis::VerifiedGenesis;
use crate::index::LedgerIndex;

/// What a capture shows against the published chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaptureProblem {
    /// The file's records do not frame: a length runs past its end. The
    /// comparison stops there.
    Truncated,
    /// A record is not a canonical `UplinkFrame` (version 2): a nonzero
    /// byte after the data, a field out of range.
    NotFrame,
    /// A captured frame of a link the genesis does not register.
    UnknownLink,
    /// A captured frame whose signature is not its link's frame key over
    /// its header.
    Signature,
    /// A captured frame the published logs do not have: the gateway hid it.
    Hidden,
    /// A published frame the capture does not have, in the slots it covers
    /// on that link: injected, or missed by the tap.
    Missing,
    /// A captured frame whose header is not the published one of the same
    /// link, slot and number.
    Differs,
    /// Captured bytes at a listed object do not hash to it, or are not
    /// a canonical header of its schema.
    ObjectDiffers,
    /// Captured bytes no listed object covers, or fill around a share
    /// package that is not zero.
    NotObject,
}

/// One problem a capture shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CaptureFinding {
    /// The link.
    pub link_id_hash: Option<Hash512>,
    /// The frame's slot and number, for a frame.
    pub frame: Option<(u64, u16)>,
    /// The stream offset, for an object or bytes.
    pub stream_offset: Option<u64>,
    /// What is wrong.
    pub problem: CaptureProblem,
}

/// One captured frame, as matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CaptureFrame {
    /// Its link.
    pub link_id_hash: Hash512,
    /// Its slot.
    pub slot: u64,
    /// Its number.
    pub index: u16,
    /// Its header's object hash (the chain's frame hash).
    pub header_hash: Hash512,
}

/// The result of [`compare_capture`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureComparison {
    /// The file's hash, as the observer signs it.
    pub capture_hash: Hash512,
    /// Frames captured and decoded.
    pub frames: Vec<CaptureFrame>,
    /// Frames whose header is the published one.
    pub matched: u64,
    /// Published objects whose captured bytes hash to them.
    pub objects_matched: u64,
    /// Every problem, in the order found.
    pub findings: Vec<CaptureFinding>,
}

impl CaptureComparison {
    /// Whether the capture agrees with the published chain everywhere it
    /// reaches.
    #[must_use]
    pub fn agrees(&self) -> bool {
        self.findings.is_empty()
    }
}

/// A published frame's header hash, by link, slot and number.
type Published = BTreeMap<([u8; 64], u64, u16), Hash512>;

/// The published frames of every link, from the ledger's frame logs.
fn published(index: &LedgerIndex<'_>) -> Published {
    let mut frames = BTreeMap::new();
    for e in index.events() {
        if e.schema != SCHEMA_UPLINK_FRAME_LOG {
            continue;
        }
        let Some(log) = e.bytes.and_then(|b| {
            decode_object::<UplinkFrameLog<'_>>(SCHEMA_UPLINK_FRAME_LOG, SCHEMA_VERSION_1, b).ok()
        }) else {
            continue;
        };
        let link = log.parts().link_id_hash;
        for f in log.frames_with() {
            let header = f.entry.header(link, objects_hash(f.objects.as_bytes()));
            if let Some((h, _)) = header_object(&header) {
                frames.insert((link.0, f.entry.slot, f.entry.index), h);
            }
        }
    }
    frames
}

/// The length of an encoded frame header object.
const HEADER_OBJECT_LEN: usize = HEADER_LEN + FRAME_HEADER_LEN;

/// The header object of `parts` and its hash.
fn header_object(
    parts: &ityv_encoding::UplinkFrameHeaderParts,
) -> Option<(Hash512, [u8; HEADER_OBJECT_LEN])> {
    let h = UplinkFrameHeader::new(parts).ok()?;
    let mut buf = [0u8; HEADER_OBJECT_LEN];
    let len = encode_object(SCHEMA_UPLINK_FRAME_HEADER, SCHEMA_VERSION_1, &h, &mut buf).ok()?;
    Some((object_hash(buf.get(..len)?), buf))
}

/// One captured frame's data and object list.
struct Piece<'f> {
    offset: u64,
    data: &'f [u8],
    objects: FrameObjects<'f>,
}

/// Compares an observer's capture `file` with the frame logs `index`
/// carries, under the links `genesis` registers (VC-081).
///
/// What this does not prove: that the tap saw every frame on the line
/// (a frame the published logs have and the capture lacks is listed, not
/// judged), or anything about frames of links the capture does not touch
/// or slots before or after the capture.
#[must_use]
#[allow(clippy::too_many_lines)] // Frames, then the published frames missed, then the stream.
pub fn compare_capture(
    genesis: &VerifiedGenesis<'_>,
    index: &LedgerIndex<'_>,
    file: &[u8],
) -> CaptureComparison {
    let mut keys: BTreeMap<[u8; 64], &[u8; ityv_encoding::FRAME_KEY_LEN]> = BTreeMap::new();
    for state in 0..genesis.state_count() {
        for b in genesis.boxes_at(state) {
            keys.insert(link_id(b.frame_key).0, b.frame_key);
        }
        for s in genesis.stations_at(state) {
            for u in [s.primary(), s.spare()] {
                keys.insert(link_id(u.frame_key).0, u.frame_key);
            }
        }
    }
    let published_frames = published(index);
    let mut out = CaptureComparison {
        capture_hash: capture_hash(file),
        frames: Vec::new(),
        matched: 0,
        objects_matched: 0,
        findings: Vec::new(),
    };
    // The captured stream of each link: every frame's data and list.
    let mut streams: BTreeMap<[u8; 64], Vec<Piece<'_>>> = BTreeMap::new();
    let mut captured: BTreeSet<([u8; 64], u64, u16)> = BTreeSet::new();
    let mut r = Reader::new(file);
    while !r.is_empty() {
        let Ok(len) = r.read_u32() else {
            out.findings
                .push(finding(None, None, None, CaptureProblem::Truncated));
            break;
        };
        let Some(record) = usize::try_from(len).ok().and_then(|n| r.take(n).ok()) else {
            out.findings
                .push(finding(None, None, None, CaptureProblem::Truncated));
            break;
        };
        let Ok(frame) =
            decode_object::<UplinkFrame<'_>>(SCHEMA_UPLINK_FRAME, SCHEMA_VERSION_UPLINK, record)
        else {
            out.findings
                .push(finding(None, None, None, CaptureProblem::NotFrame));
            continue;
        };
        let mut parts = *frame.fields();
        parts.payload_root = payload_root_of(frame.payload());
        parts.objects_hash = objects_hash(frame.objects().as_bytes());
        let link = parts.link_id_hash;
        let at = Some((parts.slot, parts.index));
        let Some(key) = keys.get(&link.0) else {
            out.findings
                .push(finding(Some(link), at, None, CaptureProblem::UnknownLink));
            continue;
        };
        let Some((hash, object)) = header_object(&parts) else {
            out.findings
                .push(finding(Some(link), at, None, CaptureProblem::NotFrame));
            continue;
        };
        let signed = RecordVerifyingKey::from_bytes(**key).is_ok_and(|k| {
            verify_record(
                &k,
                RecordPurpose::UplinkFrame,
                &object,
                &RecordSignature::from_bytes(*frame.frame_sig()),
            )
            .is_ok()
        });
        if !signed {
            out.findings
                .push(finding(Some(link), at, None, CaptureProblem::Signature));
        }
        out.frames.push(CaptureFrame {
            link_id_hash: link,
            slot: parts.slot,
            index: parts.index,
            header_hash: hash,
        });
        captured.insert((link.0, parts.slot, parts.index));
        match published_frames.get(&(link.0, parts.slot, parts.index)) {
            None => out
                .findings
                .push(finding(Some(link), at, None, CaptureProblem::Hidden)),
            Some(h) if *h != hash => {
                out.findings
                    .push(finding(Some(link), at, None, CaptureProblem::Differs));
            }
            Some(_) => out.matched = out.matched.saturating_add(1),
        }
        streams.entry(link.0).or_default().push(Piece {
            offset: parts.stream_offset,
            data: frame.data(),
            objects: frame.objects(),
        });
    }
    // Published frames the capture lacks, in the slots it covers on their
    // link (a recorder that started late or stopped early reaches no
    // further).
    let mut reach: BTreeMap<[u8; 64], (u64, u64)> = BTreeMap::new();
    for f in &out.frames {
        reach
            .entry(f.link_id_hash.0)
            .and_modify(|(lo, hi)| {
                *lo = (*lo).min(f.slot);
                *hi = (*hi).max(f.slot);
            })
            .or_insert((f.slot, f.slot));
    }
    for (link, slot, idx) in published_frames.keys() {
        let reached = reach
            .get(link)
            .is_some_and(|(lo, hi)| *lo <= *slot && *slot <= *hi);
        if reached && !captured.contains(&(*link, *slot, *idx)) {
            out.findings.push(finding(
                Some(Hash512(*link)),
                Some((*slot, *idx)),
                None,
                CaptureProblem::Missing,
            ));
        }
    }
    // The stream: each frame's list tiles its data with zero fill, and
    // every listed object held whole hashes to its listed hash.
    for (link, mut pieces) in streams {
        pieces.sort_by_key(|p| p.offset);
        let mut objects: BTreeMap<u64, StreamObject> = BTreeMap::new();
        for p in &pieces {
            let len = u32::try_from(p.data.len()).unwrap_or(u32::MAX);
            let t = tiling(p.offset, len, &p.objects);
            if let Some((_, at)) = t.problem {
                out.findings.push(finding(
                    Some(Hash512(link)),
                    None,
                    Some(at),
                    CaptureProblem::NotObject,
                ));
            }
            for (lo, hi) in t.fill {
                let zero = assemble(&pieces, lo, hi.saturating_sub(lo))
                    .is_none_or(|b| b.iter().all(|x| *x == 0));
                if !zero {
                    out.findings.push(finding(
                        Some(Hash512(link)),
                        None,
                        Some(lo),
                        CaptureProblem::NotObject,
                    ));
                }
            }
            for o in p.objects.iter() {
                objects.entry(o.stream_offset).or_insert(o);
            }
        }
        for o in objects.values() {
            let Some(bytes) = assemble(&pieces, o.stream_offset, u64::from(o.len)) else {
                continue;
            };
            let header_ok = {
                let mut hr = Reader::new(&bytes);
                ObjectHeader::read(&mut hr).is_ok_and(|h| h.schema_id() == o.schema)
            };
            if header_ok && object_hash(&bytes) == o.object_hash {
                out.objects_matched = out.objects_matched.saturating_add(1);
            } else {
                out.findings.push(finding(
                    Some(Hash512(link)),
                    None,
                    Some(o.stream_offset),
                    CaptureProblem::ObjectDiffers,
                ));
            }
        }
    }
    out
}

/// The bytes `[offset, offset + len)` of the captured stream (`pieces`
/// sorted by offset), if every byte was captured.
fn assemble(pieces: &[Piece<'_>], offset: u64, len: u64) -> Option<Vec<u8>> {
    let end = offset.checked_add(len)?;
    let mut out = Vec::new();
    let mut at = offset;
    // Each step takes the piece that holds `at` and moves past its end, so
    // no piece is taken twice: at most one step per piece, and the one that
    // finds none.
    let mut steps = 0..=pieces.len();
    while at < end && steps.next().is_some() {
        let after = pieces.partition_point(|p| p.offset <= at);
        let p = pieces.get(after.checked_sub(1)?)?;
        let piece_end = p.offset.checked_add(u64::try_from(p.data.len()).ok()?)?;
        if at >= piece_end {
            return None;
        }
        let from = usize::try_from(at.checked_sub(p.offset)?).ok()?;
        let to = usize::try_from(end.min(piece_end).checked_sub(p.offset)?).ok()?;
        out.extend_from_slice(p.data.get(from..to)?);
        at = end.min(piece_end);
    }
    Some(out)
}

const fn finding(
    link_id_hash: Option<Hash512>,
    frame: Option<(u64, u16)>,
    stream_offset: Option<u64>,
    problem: CaptureProblem,
) -> CaptureFinding {
    CaptureFinding {
        link_id_hash,
        frame,
        stream_offset,
        problem,
    }
}

// ---------------------------------------------------------------------------
// The carrier's records.

/// A line the carrier records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CarrierLine {
    /// The station gateway's outer line.
    Gateway,
    /// The early-voting identity terminals' roll lookup line.
    RollLookup,
}

/// One aggregation interval of a line: the slots it covers and the bytes
/// the carrier counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CarrierInterval {
    /// The first slot.
    pub from_slot: u64,
    /// The last slot.
    pub to_slot: u64,
    /// Bytes both ways in the interval.
    pub bytes: u64,
}

/// One line's record as the committee publishes it (`LEGAL_ANNEX.md`
/// amendment 8, §181-2 ⑤). The form is the sub-regulation's; this is the
/// verifier's reading of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CarrierLog<'a> {
    /// The station.
    pub station_id: &'a [u8],
    /// The line.
    pub line: CarrierLine,
    /// Its intervals.
    pub intervals: &'a [CarrierInterval],
}

/// What a carrier record shows against the sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CarrierProblem {
    /// The station is not one of the genesis.
    UnknownStation,
    /// The carrier's bytes on the outer line are not the sessions'.
    Bytes {
        /// The carrier's total.
        carrier: u64,
        /// The sessions' `wan_bytes` total.
        sessions: u64,
    },
    /// Traffic in an interval no session's window meets.
    Unexplained,
    /// A roll lookup line at a station that is not an early-voting station.
    RollLineUndeclared,
    /// Roll lookup traffic outside the station's voting window.
    OutsideWindow,
}

/// One problem a carrier record shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CarrierFinding<'a> {
    /// The station.
    pub station_id: &'a [u8],
    /// The line.
    pub line: CarrierLine,
    /// The interval, when one interval shows it.
    pub interval: Option<CarrierInterval>,
    /// What is wrong.
    pub problem: CarrierProblem,
}

/// Compares the carrier's records `logs` with the sessions the
/// connectivity stage took (ADR-0041 decision 12).
///
/// What this does not prove: that the carrier's record is complete or
/// true (it is the third source, independent of the operator and the
/// observers), or that the bytes were the frames (a capture shows that).
#[must_use]
pub fn compare_carrier<'l>(
    genesis: &VerifiedGenesis<'_>,
    index: &LedgerIndex<'_>,
    stage: &ConnectivityStage<'_>,
    logs: &[CarrierLog<'l>],
) -> Vec<CarrierFinding<'l>> {
    let mut out = Vec::new();
    for log in logs {
        let mut push = |interval, problem| {
            out.push(CarrierFinding {
                station_id: log.station_id,
                line: log.line,
                interval,
                problem,
            });
        };
        let Some(station) = genesis.station(log.station_id) else {
            push(None, CarrierProblem::UnknownStation);
            continue;
        };
        match log.line {
            CarrierLine::Gateway => {
                let sessions = stage
                    .station(log.station_id)
                    .map_or(&[][..], |s| s.sessions.as_slice());
                let carrier = log
                    .intervals
                    .iter()
                    .fold(0u64, |acc, i| acc.saturating_add(i.bytes));
                let declared = sessions
                    .iter()
                    .fold(0u64, |acc, s| acc.saturating_add(s.wan_bytes));
                if carrier != declared {
                    push(
                        None,
                        CarrierProblem::Bytes {
                            carrier,
                            sessions: declared,
                        },
                    );
                }
                for i in log.intervals.iter().filter(|i| i.bytes > 0) {
                    let met = sessions
                        .iter()
                        .any(|s| s.start_slot <= i.to_slot && i.from_slot <= s.end_slot);
                    if !met {
                        push(Some(*i), CarrierProblem::Unexplained);
                    }
                }
            }
            CarrierLine::RollLookup => {
                if station.kind() != StationKind::EarlyVoting {
                    push(None, CarrierProblem::RollLineUndeclared);
                    continue;
                }
                let open = station
                    .boxes()
                    .filter_map(|b| opening_slot(index, b.as_bytes()))
                    .min();
                let close = station
                    .boxes()
                    .filter_map(|b| close_slot(index, b.as_bytes()))
                    .max();
                for i in log.intervals.iter().filter(|i| i.bytes > 0) {
                    let inside = open.is_some_and(|o| o <= i.from_slot)
                        && close.is_some_and(|c| i.to_slot <= c);
                    if !inside {
                        push(Some(*i), CarrierProblem::OutsideWindow);
                    }
                }
            }
        }
    }
    out
}
