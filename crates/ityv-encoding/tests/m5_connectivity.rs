//! The connectivity schemas (ENCODING.md §8.21–§8.24, §8.82–§8.84;
//! ADR-0022, ADR-0041): `ConnectivityManifest` (0x001C v2),
//! `UplinkFrame` (0x001D v2), `UplinkSessionBody` (0x001E v2),
//! `UplinkSession` (0x001F v2), `UplinkFrameHeader` (0x0057),
//! `UplinkFrameLog` (0x0058) and `ConnectivityIncidentBody` (0x0059, a
//! witnessed body). Round trips, the constructors' rules (the same as the
//! decoders'), every decoder rule at its offset, the published vector files
//! (a 1 MiB frame is not published: its rules are tested here) and property
//! tests.
//!
//! Signatures here are patterned bytes: the encoding layer treats them as
//! opaque fixed-width fields.
// Integration-test crate: outside the TCB. Test code expresses "this must
// hold" with unwrap/expect/panic/indexing and does small arithmetic on test
// sizes, so those restriction lints are relaxed for this file only
// (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::too_many_lines,
    clippy::cast_possible_truncation
)]

mod common;

use common::{
    Vector, check_file, encode_to_vec, ident_len, patterned, patterned64, render, self_check,
};
use ityv_encoding::{
    BoxId, CARRIES_MASK, CARRY_LEDGER, CARRY_PUBLIC, CARRY_SEALED, CARRY_SESSION, CaptureMessage,
    CaptureSig, ConnectivityIncidentBody, ConnectivityIncidentParts, ConnectivityManifest, Decode,
    DeviceClass, Direction, ED25519_SIG_LEN, ElectionId, Encode, ErrorKind, FRAME_BODY_LEN,
    FRAME_ENTRY_LEN, FRAME_HEADER_LEN, FRAME_OBJECTS_LEN, FrameEntry, FrameKind, FrameObjects,
    GatewayId, HEADER_LEN, HYBRID_SIG_LEN, Hash512, Ident, IncidentKind, LogFrames, LogLeaves,
    LogObjects, MAX_CAPTURE_SIGS, MAX_FRAME_OBJECTS, MAX_FRAMES_PER_SLOT, MAX_PAYLOAD_LEN,
    MAX_SESSION_BODY_LEN, MAX_SESSION_LINKS, ManifestEntries, ManifestEntry, Medium,
    OBJECT_ENTRY_LEN, OrgId, SCHEMA_CONNECTIVITY_INCIDENT_BODY, SCHEMA_CONNECTIVITY_MANIFEST,
    SCHEMA_UPLINK_FRAME, SCHEMA_UPLINK_FRAME_HEADER, SCHEMA_UPLINK_FRAME_LOG,
    SCHEMA_UPLINK_SESSION, SCHEMA_UPLINK_SESSION_BODY, SCHEMA_VERSION_1, SCHEMA_VERSION_UPLINK,
    SESSION_LINK_LEN, Schedule, SchemaId, SessionLink, SessionLinks, SignerId, StationId,
    StreamObject, UplinkFrame, UplinkFrameHeader, UplinkFrameHeaderParts, UplinkFrameLog,
    UplinkFrameLogParts, UplinkSession, UplinkSessionBody, UplinkSessionParts,
    WITNESSED_BODY_SCHEMAS, Writer, data_chunks, decode_object, purpose_of, schema_version,
};
use proptest::prelude::*;
use std::vec::Vec;

const E: &[u8] = b"KR-2030-PRES";
const ST: &[u8] = b"st-11-0042";
const GW: &[u8] = b"gw-11-0042";
const BOX: &[u8] = b"box-11-0042";

static SIG_A: [u8; HYBRID_SIG_LEN] = [0xA1; HYBRID_SIG_LEN];
static SIG_B: [u8; HYBRID_SIG_LEN] = [0xB2; HYBRID_SIG_LEN];
static FRAME_SIG: [u8; ED25519_SIG_LEN] = [0xF5; ED25519_SIG_LEN];

fn e() -> ElectionId<'static> {
    ElectionId::new(E).unwrap()
}

fn st() -> StationId<'static> {
    StationId::new(ST).unwrap()
}

fn gw() -> GatewayId<'static> {
    GatewayId::new(GW).unwrap()
}

fn ident(bytes: &'static [u8], max: usize) -> Ident<'static> {
    Ident::new(bytes, max).unwrap()
}

fn leak(bytes: Vec<u8>) -> &'static [u8] {
    Box::leak(bytes.into_boxed_slice())
}

fn bytes_of<T: Encode>(value: &T) -> Vec<u8> {
    let mut out = std::vec![0u8; value.encoded_len()];
    value.encode(&mut Writer::new(&mut out)).unwrap();
    out
}

fn kind_at<'a, T: Decode<'a>>(
    schema: SchemaId,
    version: u16,
    bytes: &'a [u8],
) -> (ErrorKind, usize) {
    let e = decode_object::<T>(schema, version, bytes)
        .map(drop)
        .unwrap_err();
    (e.kind(), e.offset())
}

fn fix_len(v: &mut [u8]) {
    let body_len = u32::try_from(v.len() - HEADER_LEN).unwrap();
    v[12..16].copy_from_slice(&body_len.to_be_bytes());
}

fn valid(label: &'static str, bytes: Vec<u8>) -> Vector {
    Vector {
        label,
        bytes,
        expected: None,
    }
}

fn invalid(label: &'static str, bytes: Vec<u8>, kind: &'static str, offset: usize) -> Vector {
    Vector {
        label,
        bytes,
        expected: Some((kind, offset)),
    }
}

// ---------------------------------------------------------------------------
// Registration.

#[test]
fn the_schemas_are_registered_with_their_versions() {
    for s in [
        SCHEMA_CONNECTIVITY_MANIFEST,
        SCHEMA_UPLINK_FRAME,
        SCHEMA_UPLINK_SESSION_BODY,
        SCHEMA_UPLINK_SESSION,
    ] {
        assert_eq!(schema_version(s), SCHEMA_VERSION_UPLINK);
    }
    assert_eq!(SCHEMA_VERSION_UPLINK, 2);
    for s in [
        SCHEMA_UPLINK_FRAME_HEADER,
        SCHEMA_UPLINK_FRAME_LOG,
        SCHEMA_CONNECTIVITY_INCIDENT_BODY,
    ] {
        assert_eq!(schema_version(s), SCHEMA_VERSION_1);
    }
    assert_eq!(
        [
            SCHEMA_CONNECTIVITY_MANIFEST.get(),
            SCHEMA_UPLINK_FRAME.get(),
            SCHEMA_UPLINK_SESSION_BODY.get(),
            SCHEMA_UPLINK_SESSION.get(),
            SCHEMA_UPLINK_FRAME_HEADER.get(),
            SCHEMA_UPLINK_FRAME_LOG.get(),
            SCHEMA_CONNECTIVITY_INCIDENT_BODY.get(),
        ],
        [0x001C, 0x001D, 0x001E, 0x001F, 0x0057, 0x0058, 0x0059]
    );
    assert!(WITNESSED_BODY_SCHEMAS.contains(&SCHEMA_CONNECTIVITY_INCIDENT_BODY));
    assert_eq!(
        purpose_of(SCHEMA_CONNECTIVITY_INCIDENT_BODY),
        Some(b"connectivity-incident".as_slice())
    );
    // The fixed widths: a frame is its header fields (87 bytes), the
    // object count and region, the payload and the signature.
    assert_eq!(FRAME_ENTRY_LEN, 153);
    assert_eq!(FRAME_HEADER_LEN, 215);
    assert_eq!(OBJECT_ENTRY_LEN, 80);
    assert_eq!(SESSION_LINK_LEN, 156);
    assert_eq!(MAX_FRAME_OBJECTS, 1024);
    assert_eq!(FRAME_OBJECTS_LEN, 81_920);
    assert_eq!(
        87 + 2 + FRAME_OBJECTS_LEN + MAX_PAYLOAD_LEN + 64,
        FRAME_BODY_LEN
    );
}

#[test]
fn every_code_round_trips_and_nothing_else_decodes() {
    for c in DeviceClass::ALL {
        assert_eq!(DeviceClass::from_code(c.code()), Some(*c));
        assert_eq!(c.is_tcb(), (1..=4).contains(&c.code()));
    }
    assert_eq!(DeviceClass::ALL.len(), 15);
    assert_eq!(DeviceClass::from_code(0), None);
    assert_eq!(DeviceClass::from_code(16), None);
    assert_eq!(Direction::from_code(4), None);
    assert_eq!(Medium::from_code(8), None);
    assert_eq!(Schedule::from_code(5), None);
    assert_eq!(FrameKind::from_code(4), None);
    assert_eq!(IncidentKind::from_code(0), None);
    assert_eq!(IncidentKind::from_code(11), None);
    assert!(!FrameKind::Normal.uses_catchup());
    for k in [
        FrameKind::CatchUp,
        FrameKind::CloseResend,
        FrameKind::WitnessedResend,
    ] {
        assert!(k.uses_catchup());
    }
    assert_eq!(data_chunks(0), 0);
    assert_eq!(data_chunks(1), 1);
    assert_eq!(data_chunks(4096), 1);
    assert_eq!(data_chunks(4097), 2);
    assert_eq!(data_chunks(MAX_PAYLOAD_LEN as u32), 236);
}

// ---------------------------------------------------------------------------
// 0x001C ConnectivityManifest.

fn scanner_entry() -> ManifestEntry<'static> {
    ManifestEntry {
        device_class: DeviceClass::CommitmentUnit,
        port: ident(b"uplink", 32),
        direction: Direction::OutOnly,
        medium: Medium::OpticalTransmit,
        peer_class: Some(DeviceClass::Gateway),
        counterpart: ident(b"station-gateway", 64),
        schedule: Schedule::BoxOpenToClose,
        frames_per_slot: 16,
        catchup_frames_per_slot: 64,
        carries: CARRY_PUBLIC | CARRY_SEALED,
    }
}

fn gateway_entry() -> ManifestEntry<'static> {
    ManifestEntry {
        device_class: DeviceClass::Gateway,
        port: ident(b"wan", 32),
        direction: Direction::Both,
        medium: Medium::OpticalLine,
        peer_class: None,
        counterpart: ident(b"ledger-collector", 64),
        schedule: Schedule::Always,
        frames_per_slot: 0,
        catchup_frames_per_slot: 0,
        carries: CARRY_LEDGER | CARRY_SESSION,
    }
}

fn manifest_of(entries: &[ManifestEntry<'static>]) -> ConnectivityManifest<'static> {
    let bytes: Vec<u8> = entries.iter().flat_map(bytes_of).collect();
    ConnectivityManifest::new(e(), ManifestEntries::new(leak(bytes)).unwrap())
}

fn manifest() -> ConnectivityManifest<'static> {
    manifest_of(&[scanner_entry(), gateway_entry()])
}

/// The offset of the first entry of an encoded manifest.
fn first_entry() -> usize {
    HEADER_LEN + ident_len(E) + 4
}

fn entry_len(e: &ManifestEntry<'_>) -> usize {
    e.encoded_len()
}

#[test]
fn a_manifest_round_trips_and_finds_each_classs_frame_link() {
    let m = manifest();
    let bytes = encode_to_vec(SCHEMA_CONNECTIVITY_MANIFEST, SCHEMA_VERSION_UPLINK, &m);
    let back: ConnectivityManifest<'_> =
        decode_object(SCHEMA_CONNECTIVITY_MANIFEST, SCHEMA_VERSION_UPLINK, &bytes).unwrap();
    assert_eq!(back, m);
    assert_eq!(back.election_id(), e());
    assert_eq!(back.entries().len(), 2);
    assert!(!back.entries().is_empty());
    let entries: Vec<ManifestEntry<'_>> = back.entries().iter().collect();
    assert_eq!(entries, [scanner_entry(), gateway_entry()]);
    assert_eq!(back.entries().as_bytes().len(), bytes.len() - first_entry());
    assert_eq!(
        back.frame_link(DeviceClass::CommitmentUnit),
        Some(scanner_entry())
    );
    assert_eq!(back.frame_link(DeviceClass::Gateway), None);
    // Two frame links of one class: none is the class's.
    let mut second = scanner_entry();
    second.port = ident(b"uplink-2", 32);
    let two = manifest_of(&[scanner_entry(), second, gateway_entry()]);
    assert_eq!(two.frame_link(DeviceClass::CommitmentUnit), None);
    // A port of the class that sends no frames is not its frame link.
    let mut quiet = scanner_entry();
    quiet.port = ident(b"service", 32);
    quiet.frames_per_slot = 0;
    quiet.catchup_frames_per_slot = 0;
    let with_quiet = manifest_of(&[quiet, scanner_entry(), gateway_entry()]);
    assert_eq!(
        with_quiet.frame_link(DeviceClass::CommitmentUnit),
        Some(scanner_entry())
    );
    assert!(scanner_entry().sends_frames());
    assert!(!gateway_entry().sends_frames());
    assert_eq!(scanner_entry().key(), (2, b"uplink".as_slice()));
}

#[test]
fn manifest_entries_follow_their_rules() {
    let good = bytes_of(&scanner_entry());
    // The counts: none, or 1 ≤ frames ≤ catch-up ≤ 64.
    for (frames, catchup, ok) in [
        (0u16, 0u16, true),
        (0, 1, false),
        (1, 0, false),
        (1, 1, true),
        (16, 64, true),
        (17, 16, false),
        (64, 64, true),
        (64, 65, false),
    ] {
        let mut e = scanner_entry();
        e.frames_per_slot = frames;
        e.catchup_frames_per_slot = catchup;
        assert_eq!(e.counts_valid(), ok, "{frames} {catchup}");
    }
    // Nothing, a stray byte, entries out of order or repeated.
    assert_eq!(ManifestEntries::new(&[]), None);
    let mut stray = good.clone();
    stray.push(0);
    assert_eq!(ManifestEntries::new(&stray), None);
    let gw = bytes_of(&gateway_entry());
    let reversed: Vec<u8> = gw.iter().chain(&good).copied().collect();
    assert_eq!(ManifestEntries::new(&reversed), None);
    let twice: Vec<u8> = good.iter().chain(&good).copied().collect();
    assert_eq!(ManifestEntries::new(&twice), None);
    // Over the bound.
    let many: Vec<u8> = (0..=256u16)
        .flat_map(|i| {
            let mut e = gateway_entry();
            let name: &'static [u8] = leak(std::format!("p{i:04}").into_bytes());
            e.port = ident(name, 32);
            bytes_of(&e)
        })
        .collect();
    assert_eq!(ManifestEntries::new(&many), None);
}

fn manifest_vectors() -> Vec<Vector> {
    let m = manifest();
    let bytes = encode_to_vec(SCHEMA_CONNECTIVITY_MANIFEST, SCHEMA_VERSION_UPLINK, &m);
    let at = first_entry();
    let scanner = entry_len(&scanner_entry());
    // Offsets inside the first (scanner) entry.
    let port_end = at + 1 + ident_len(b"uplink");
    let peer_at = port_end + 2;
    let schedule_at = peer_at + 1 + ident_len(b"station-gateway");
    let frames_at = schedule_at + 1;
    let carries_at = frames_at + 4;
    let mut v = std::vec![valid("a frame link and the gateway", bytes.clone())];
    let one = encode_to_vec(
        SCHEMA_CONNECTIVITY_MANIFEST,
        SCHEMA_VERSION_UPLINK,
        &manifest_of(&[gateway_entry()]),
    );
    v.push(valid("one entry", one));

    let mut b = bytes.clone();
    b[at - 4..at].copy_from_slice(&0u32.to_be_bytes());
    b.truncate(at);
    fix_len(&mut b);
    v.push(invalid("no entry", b, "InvariantViolation", at - 4));

    let mut b = bytes.clone();
    b[at] = 0;
    v.push(invalid("class zero", b, "ValueOutOfRange", at));
    let mut b = bytes.clone();
    b[at] = 16;
    v.push(invalid("class sixteen", b, "ValueOutOfRange", at));
    let mut b = bytes.clone();
    b[port_end] = 4;
    v.push(invalid("direction four", b, "ValueOutOfRange", port_end));
    let mut b = bytes.clone();
    b[port_end + 1] = 8;
    v.push(invalid("medium eight", b, "ValueOutOfRange", port_end + 1));
    let mut b = bytes.clone();
    b[peer_at] = 16;
    v.push(invalid("peer class sixteen", b, "ValueOutOfRange", peer_at));
    let mut b = bytes.clone();
    b[schedule_at] = 5;
    v.push(invalid("schedule five", b, "ValueOutOfRange", schedule_at));
    let mut b = bytes.clone();
    b[frames_at..frames_at + 2].copy_from_slice(&65u16.to_be_bytes());
    v.push(invalid(
        "frames above catch up",
        b,
        "ValueOutOfRange",
        frames_at,
    ));
    let mut b = bytes.clone();
    b[frames_at..frames_at + 4].copy_from_slice(&[0, 0, 0, 1]);
    v.push(invalid(
        "catch up without frames",
        b,
        "ValueOutOfRange",
        frames_at,
    ));
    let mut b = bytes.clone();
    b[carries_at..carries_at + 4].copy_from_slice(&(CARRIES_MASK + 1).to_be_bytes());
    v.push(invalid(
        "an undefined carries bit",
        b,
        "ValueOutOfRange",
        carries_at,
    ));

    // Out of order and repeated.
    let reversed = encode_to_vec(
        SCHEMA_CONNECTIVITY_MANIFEST,
        SCHEMA_VERSION_UPLINK,
        &manifest_of(&[scanner_entry()]),
    );
    let mut b = reversed[..at].to_vec();
    b[at - 4..at].copy_from_slice(&2u32.to_be_bytes());
    b.extend_from_slice(&bytes_of(&gateway_entry()));
    b.extend_from_slice(&bytes_of(&scanner_entry()));
    fix_len(&mut b);
    let second = at + entry_len(&gateway_entry());
    v.push(invalid("entries out of order", b, "NotSorted", second));
    let mut b = reversed[..at].to_vec();
    b[at - 4..at].copy_from_slice(&2u32.to_be_bytes());
    b.extend_from_slice(&bytes_of(&scanner_entry()));
    b.extend_from_slice(&bytes_of(&scanner_entry()));
    fix_len(&mut b);
    v.push(invalid("an entry twice", b, "Duplicate", at + scanner));
    v
}

#[test]
fn manifest_vectors_are_current_and_self_consistent() {
    let content = render(
        "ConnectivityManifest",
        SCHEMA_CONNECTIVITY_MANIFEST,
        &manifest_vectors(),
    );
    check_file("connectivity_manifest.txt", &content);
    self_check(&content, |b| {
        let v: ConnectivityManifest<'_> =
            decode_object(SCHEMA_CONNECTIVITY_MANIFEST, SCHEMA_VERSION_UPLINK, b)?;
        Ok(encode_to_vec(
            SCHEMA_CONNECTIVITY_MANIFEST,
            SCHEMA_VERSION_UPLINK,
            &v,
        ))
    });
}

// ---------------------------------------------------------------------------
// 0x0057 UplinkFrameHeader and 0x001D UplinkFrame.

fn header_parts() -> UplinkFrameHeaderParts {
    UplinkFrameHeaderParts {
        link_id_hash: patterned64(0x11),
        slot: 150,
        index: 3,
        kind: FrameKind::Normal,
        stream_offset: 4_000_000,
        payload_len: 9000,
        payload_root: patterned64(0x22),
        objects_hash: patterned64(0x33),
    }
}

#[test]
fn a_header_round_trips_and_keeps_its_fields_in_range() {
    let h = UplinkFrameHeader::new(&header_parts()).unwrap();
    assert_eq!(*h.parts(), header_parts());
    assert_eq!(h.parts().data_chunks(), 3);
    let bytes = encode_to_vec(SCHEMA_UPLINK_FRAME_HEADER, SCHEMA_VERSION_1, &h);
    assert_eq!(bytes.len(), HEADER_LEN + FRAME_HEADER_LEN);
    let back: UplinkFrameHeader =
        decode_object(SCHEMA_UPLINK_FRAME_HEADER, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(back, h);
    let mut p = header_parts();
    p.index = MAX_FRAMES_PER_SLOT;
    assert!(!p.valid());
    assert_eq!(
        UplinkFrameHeader::new(&p).unwrap_err().kind(),
        ErrorKind::ValueOutOfRange
    );
    p.index = MAX_FRAMES_PER_SLOT - 1;
    assert!(p.valid());
    p.payload_len = MAX_PAYLOAD_LEN as u32 + 1;
    assert!(!p.valid());
    p.payload_len = MAX_PAYLOAD_LEN as u32;
    assert!(p.valid());
}

fn header_vectors() -> Vec<Vector> {
    let h = UplinkFrameHeader::new(&header_parts()).unwrap();
    let bytes = encode_to_vec(SCHEMA_UPLINK_FRAME_HEADER, SCHEMA_VERSION_1, &h);
    let index_at = HEADER_LEN + 64 + 8;
    let kind_at = index_at + 2;
    let len_at = kind_at + 1 + 8;
    let mut v = std::vec![valid("a normal frame of 9000 bytes", bytes.clone())];
    let mut last = header_parts();
    last.index = 63;
    last.kind = FrameKind::WitnessedResend;
    last.payload_len = MAX_PAYLOAD_LEN as u32;
    v.push(valid(
        "the last number, a witnessed resend, a full payload",
        encode_to_vec(
            SCHEMA_UPLINK_FRAME_HEADER,
            SCHEMA_VERSION_1,
            &UplinkFrameHeader::new(&last).unwrap(),
        ),
    ));
    let mut b = bytes.clone();
    b[index_at..index_at + 2].copy_from_slice(&64u16.to_be_bytes());
    v.push(invalid("number 64", b, "ValueOutOfRange", index_at));
    let mut b = bytes.clone();
    b[kind_at] = 4;
    v.push(invalid("kind four", b, "ValueOutOfRange", kind_at));
    let mut b = bytes.clone();
    b[len_at..len_at + 4].copy_from_slice(&(MAX_PAYLOAD_LEN as u32 + 1).to_be_bytes());
    v.push(invalid(
        "a payload past the frame",
        b,
        "ValueOutOfRange",
        len_at,
    ));
    let mut b = bytes;
    b.pop();
    fix_len(&mut b);
    v.push(invalid(
        "an object hash cut short",
        b,
        "UnexpectedEnd",
        HEADER_LEN + 64 + 23 + 64,
    ));
    v
}

#[test]
fn header_vectors_are_current_and_self_consistent() {
    let content = render(
        "UplinkFrameHeader",
        SCHEMA_UPLINK_FRAME_HEADER,
        &header_vectors(),
    );
    check_file("uplink_frame_header.txt", &content);
    self_check(&content, |b| {
        let v: UplinkFrameHeader = decode_object(SCHEMA_UPLINK_FRAME_HEADER, SCHEMA_VERSION_1, b)?;
        Ok(encode_to_vec(
            SCHEMA_UPLINK_FRAME_HEADER,
            SCHEMA_VERSION_1,
            &v,
        ))
    });
}

/// The object list of the frame of [`header_parts`] (9,000 bytes from
/// 4,000,000): one object carried in from before it, one carried out past
/// its end.
fn frame_objects() -> FrameObjects<'static> {
    let list: Vec<u8> = [object(0x44, 3_999_000, 5000), object(0x45, 4_004_000, 8000)]
        .iter()
        .flat_map(bytes_of)
        .collect();
    FrameObjects::new(leak(list)).unwrap()
}

#[test]
fn a_frame_carries_its_objects_its_data_and_zeros_after_them() {
    let mut payload: Box<[u8; MAX_PAYLOAD_LEN]> = std::vec![0u8; MAX_PAYLOAD_LEN]
        .into_boxed_slice()
        .try_into()
        .unwrap();
    payload[..9000].fill(0x5A);
    let frame = UplinkFrame::new(&header_parts(), frame_objects(), &payload, &FRAME_SIG).unwrap();
    // The wire frame carries no root and no object hash.
    assert_eq!(frame.fields().payload_root, Hash512::ZERO);
    assert_eq!(frame.fields().objects_hash, Hash512::ZERO);
    assert_eq!(frame.fields().slot, 150);
    assert_eq!(frame.objects(), frame_objects());
    assert_eq!(frame.data().len(), 9000);
    assert_eq!(frame.payload().len(), MAX_PAYLOAD_LEN);
    assert_eq!(frame.frame_sig(), &FRAME_SIG);
    let bytes = encode_to_vec(SCHEMA_UPLINK_FRAME, SCHEMA_VERSION_UPLINK, &frame);
    assert_eq!(bytes.len(), HEADER_LEN + FRAME_BODY_LEN);
    let back: UplinkFrame<'_> =
        decode_object(SCHEMA_UPLINK_FRAME, SCHEMA_VERSION_UPLINK, &bytes).unwrap();
    assert_eq!(back, frame);
    assert_eq!(
        back.objects().iter().nth(1),
        Some(object(0x45, 4_004_000, 8000))
    );
    // Version 1 is not this frame.
    assert_eq!(
        kind_at::<UplinkFrame<'_>>(SCHEMA_UPLINK_FRAME, SCHEMA_VERSION_1, &bytes).0,
        ErrorKind::UnsupportedVersion
    );

    let count_at = HEADER_LEN + 87;
    let region_at = count_at + 2;
    let payload_at = region_at + FRAME_OBJECTS_LEN;
    let decode =
        |b: &[u8]| kind_at::<UplinkFrame<'_>>(SCHEMA_UPLINK_FRAME, SCHEMA_VERSION_UPLINK, b);
    // A nonzero byte after the data: the first one is reported.
    let mut b = bytes.clone();
    b[payload_at + 9000 + 7] = 1;
    b[payload_at + 500_000] = 1;
    assert_eq!(
        decode(&b),
        (ErrorKind::InvariantViolation, payload_at + 9007)
    );
    let mut b = bytes.clone();
    b[payload_at + MAX_PAYLOAD_LEN - 1] = 1;
    assert_eq!(
        decode(&b),
        (
            ErrorKind::InvariantViolation,
            payload_at + MAX_PAYLOAD_LEN - 1
        )
    );
    // A nonzero byte in the region after the listed objects.
    let mut b = bytes.clone();
    b[region_at + 2 * OBJECT_ENTRY_LEN + 3] = 1;
    assert_eq!(
        decode(&b),
        (
            ErrorKind::InvariantViolation,
            region_at + 2 * OBJECT_ENTRY_LEN + 3
        )
    );
    let mut b = bytes.clone();
    b[payload_at - 1] = 1;
    assert_eq!(decode(&b), (ErrorKind::InvariantViolation, payload_at - 1));
    // More objects than a frame lists.
    let mut b = bytes.clone();
    b[count_at..count_at + 2].copy_from_slice(&1025u16.to_be_bytes());
    assert_eq!(decode(&b), (ErrorKind::ValueOutOfRange, count_at));
    // Listed objects that overlap, or one shorter than a header.
    let second = region_at + OBJECT_ENTRY_LEN;
    let mut b = bytes.clone();
    b[second + 68..second + 76].copy_from_slice(&4_003_999u64.to_be_bytes());
    assert_eq!(decode(&b), (ErrorKind::InvariantViolation, second));
    let mut b = bytes.clone();
    b[second + 76..second + 80].copy_from_slice(&15u32.to_be_bytes());
    assert_eq!(decode(&b), (ErrorKind::ValueOutOfRange, second + 76));
    // An entry beyond the count is not part of the list but bytes of the
    // region that must be zero (its schema's last byte is the first that
    // is not).
    let mut b = bytes.clone();
    b[count_at..count_at + 2].copy_from_slice(&1u16.to_be_bytes());
    assert_eq!(decode(&b), (ErrorKind::InvariantViolation, second + 3));
    // A full region: 1,024 objects of 16 bytes.
    let full: Vec<u8> = (0..MAX_FRAME_OBJECTS as u64)
        .flat_map(|i| bytes_of(&object(1, 4_000_000 + 16 * i, 16)))
        .collect();
    let full = FrameObjects::new(leak(full)).unwrap();
    assert_eq!(full.len(), MAX_FRAME_OBJECTS);
    let mut p = header_parts();
    p.payload_len = 16 * 1024;
    let mut many: Box<[u8; MAX_PAYLOAD_LEN]> = std::vec![0u8; MAX_PAYLOAD_LEN]
        .into_boxed_slice()
        .try_into()
        .unwrap();
    many[..16 * 1024].fill(7);
    let f = UplinkFrame::new(&p, full, &many, &FRAME_SIG).unwrap();
    let fb = encode_to_vec(SCHEMA_UPLINK_FRAME, SCHEMA_VERSION_UPLINK, &f);
    assert_eq!(fb.len(), HEADER_LEN + FRAME_BODY_LEN);
    let back: UplinkFrame<'_> =
        decode_object(SCHEMA_UPLINK_FRAME, SCHEMA_VERSION_UPLINK, &fb).unwrap();
    assert_eq!(back.objects().len(), MAX_FRAME_OBJECTS);
    // The constructor refuses a nonzero byte after the data.
    payload[9000] = 1;
    assert_eq!(
        UplinkFrame::new(&header_parts(), frame_objects(), &payload, &FRAME_SIG).unwrap_err(),
        ityv_encoding::Error::new(ErrorKind::InvariantViolation, 0)
    );
    payload[9000] = 0;
    // A header out of range.
    let mut p = header_parts();
    p.index = 64;
    assert_eq!(
        UplinkFrame::new(&p, frame_objects(), &payload, &FRAME_SIG)
            .unwrap_err()
            .kind(),
        ErrorKind::ValueOutOfRange
    );
    // A full payload has no fill.
    let mut full = header_parts();
    full.payload_len = MAX_PAYLOAD_LEN as u32;
    payload[MAX_PAYLOAD_LEN - 1] = 9;
    let f = UplinkFrame::new(&full, FrameObjects::EMPTY, &payload, &FRAME_SIG).unwrap();
    assert_eq!(f.data().len(), MAX_PAYLOAD_LEN);
}

// ---------------------------------------------------------------------------
// 0x001E UplinkSessionBody and 0x001F UplinkSession.

fn session_link(seed: u8) -> SessionLink {
    SessionLink {
        link_id_hash: patterned64(seed),
        frames: 96,
        catchup_frames: 2,
        missing_slots: 1,
        stream_end: 123_456,
        chain_head: patterned64(seed.wrapping_add(0x40)),
    }
}

fn links_of(links: &[SessionLink]) -> SessionLinks<'static> {
    SessionLinks::new(leak(links.iter().flat_map(bytes_of).collect())).unwrap()
}

fn session_parts() -> UplinkSessionParts<'static> {
    UplinkSessionParts {
        election_id: e(),
        station_id: st(),
        gateway_id: gw(),
        session_index: 2,
        is_final: false,
        start_slot: 156,
        end_slot: 161,
        links: links_of(&[session_link(0x10), session_link(0x30)]),
        wan_bytes: 7_340_032,
        previous_session_hash: patterned64(0x77),
    }
}

fn body_bytes(p: &UplinkSessionParts<'static>) -> Vec<u8> {
    encode_to_vec(
        SCHEMA_UPLINK_SESSION_BODY,
        SCHEMA_VERSION_UPLINK,
        &UplinkSessionBody::new(p).unwrap(),
    )
}

/// The offset of the session number in an encoded body.
fn index_at() -> usize {
    HEADER_LEN + ident_len(E) + ident_len(ST) + ident_len(GW)
}

#[test]
fn a_session_body_round_trips_and_follows_its_rules() {
    let body = UplinkSessionBody::new(&session_parts()).unwrap();
    assert_eq!(*body.parts(), session_parts());
    let bytes = body_bytes(&session_parts());
    let back: UplinkSessionBody<'_> =
        decode_object(SCHEMA_UPLINK_SESSION_BODY, SCHEMA_VERSION_UPLINK, &bytes).unwrap();
    assert_eq!(back, body);
    let links: Vec<SessionLink> = back.parts().links.iter().collect();
    assert_eq!(links, [session_link(0x10), session_link(0x30)]);
    assert_eq!(back.parts().links.len(), 2);
    assert!(!back.parts().links.is_empty());
    assert!(SessionLinks::EMPTY.is_empty());

    let err = |p: &UplinkSessionParts<'static>| UplinkSessionBody::new(p).unwrap_err().kind();
    let mut p = session_parts();
    p.session_index = 0;
    assert_eq!(err(&p), ErrorKind::ValueOutOfRange);
    let mut p = session_parts();
    p.previous_session_hash = Hash512::ZERO;
    assert_eq!(err(&p), ErrorKind::InvalidPreviousHash);
    let mut p = session_parts();
    p.session_index = 1;
    assert_eq!(err(&p), ErrorKind::InvalidPreviousHash);
    p.previous_session_hash = Hash512::ZERO;
    assert!(UplinkSessionBody::new(&p).is_ok());
    for (start, end, ok) in [
        (156u64, 156u64, true),
        (156, 161, true),
        (156, 162, false),
        (156, 155, false),
        (u64::MAX - 5, u64::MAX, true),
        (u64::MAX, u64::MAX, true),
        (0, u64::MAX, false),
    ] {
        let mut p = session_parts();
        p.start_slot = start;
        p.end_slot = end;
        assert_eq!(UplinkSessionBody::new(&p).is_ok(), ok, "{start} {end}");
        if !ok {
            assert_eq!(err(&p), ErrorKind::InvariantViolation);
        }
    }
    // Links: whole, at most sixteen, strictly ascending.
    let one = bytes_of(&session_link(0x10));
    assert_eq!(SessionLinks::new(&one[..155]), None);
    let twice: Vec<u8> = one.iter().chain(&one).copied().collect();
    assert_eq!(SessionLinks::new(&twice), None);
    let down: Vec<u8> = bytes_of(&session_link(0x30))
        .into_iter()
        .chain(one.clone())
        .collect();
    assert_eq!(SessionLinks::new(&down), None);
    let many: Vec<u8> = (0..=MAX_SESSION_LINKS as u8)
        .flat_map(|i| bytes_of(&session_link(i * 4)))
        .collect();
    assert_eq!(SessionLinks::new(&many), None);
    assert!(SessionLinks::new(&many[..many.len() - SESSION_LINK_LEN]).is_some());
}

fn body_vectors() -> Vec<Vector> {
    let bytes = body_bytes(&session_parts());
    let at = index_at();
    let end_at = at + 4 + 1 + 8;
    let count_at = end_at + 8;
    let links_at = count_at + 4;
    let previous_at = links_at + 2 * SESSION_LINK_LEN + 8;
    let mut v = std::vec![valid("two links", bytes.clone())];
    let mut first = session_parts();
    first.session_index = 1;
    first.previous_session_hash = Hash512::ZERO;
    first.is_final = true;
    first.links = SessionLinks::EMPTY;
    first.end_slot = first.start_slot;
    v.push(valid(
        "a first and final session without links",
        body_bytes(&first),
    ));

    let mut b = bytes.clone();
    b[at..at + 4].copy_from_slice(&0u32.to_be_bytes());
    v.push(invalid("session zero", b, "ValueOutOfRange", at));
    let mut b = bytes.clone();
    b[end_at..end_at + 8].copy_from_slice(&162u64.to_be_bytes());
    v.push(invalid("seven slots", b, "InvariantViolation", end_at));
    let mut b = bytes.clone();
    b[end_at..end_at + 8].copy_from_slice(&155u64.to_be_bytes());
    v.push(invalid(
        "a window ending first",
        b,
        "InvariantViolation",
        end_at,
    ));
    let mut b = bytes.clone();
    b[count_at..count_at + 4].copy_from_slice(&17u32.to_be_bytes());
    v.push(invalid("seventeen links", b, "CountExceedsMax", count_at));
    let mut b = bytes.clone();
    let second = links_at + SESSION_LINK_LEN;
    let (l, r) = b[links_at..second + SESSION_LINK_LEN].split_at_mut(SESSION_LINK_LEN);
    l.swap_with_slice(r);
    v.push(invalid("links out of order", b, "NotSorted", second));
    let mut b = bytes.clone();
    b.copy_within(links_at..links_at + 64, second);
    v.push(invalid("one link twice", b, "Duplicate", second));
    let mut b = bytes.clone();
    b[previous_at..previous_at + 64].fill(0);
    v.push(invalid(
        "no previous hash after the first",
        b,
        "InvalidPreviousHash",
        previous_at,
    ));
    let mut b = bytes;
    b[at..at + 4].copy_from_slice(&1u32.to_be_bytes());
    v.push(invalid(
        "a previous hash on the first",
        b,
        "InvalidPreviousHash",
        previous_at,
    ));
    v
}

#[test]
fn session_body_vectors_are_current_and_self_consistent() {
    let content = render(
        "UplinkSessionBody",
        SCHEMA_UPLINK_SESSION_BODY,
        &body_vectors(),
    );
    check_file("uplink_session_body.txt", &content);
    self_check(&content, |b| {
        let v: UplinkSessionBody<'_> =
            decode_object(SCHEMA_UPLINK_SESSION_BODY, SCHEMA_VERSION_UPLINK, b)?;
        Ok(encode_to_vec(
            SCHEMA_UPLINK_SESSION_BODY,
            SCHEMA_VERSION_UPLINK,
            &v,
        ))
    });
}

fn capture(
    observer: &'static [u8],
    org: &'static [u8],
    sig: &'static [u8; HYBRID_SIG_LEN],
) -> CaptureSig<'static> {
    CaptureSig {
        observer_id: SignerId::new(observer).unwrap(),
        org_id: OrgId::new(org).unwrap(),
        capture_hash: patterned64(0xCA),
        sig,
    }
}

fn session() -> UplinkSession<'static> {
    let body = leak(body_bytes(&session_parts()));
    UplinkSession::new(
        body,
        &SIG_A,
        &[
            capture(b"obs-a", b"PARTY-A", &SIG_B),
            capture(b"obs-b", b"PARTY-B", &SIG_B),
        ],
    )
    .unwrap()
}

#[test]
fn a_session_round_trips_with_its_observers() {
    let s = session();
    assert_eq!(s.body().parts().session_index, 2);
    assert_eq!(s.gateway_sig(), &SIG_A);
    assert_eq!(s.observers().count(), 2);
    let bytes = encode_to_vec(SCHEMA_UPLINK_SESSION, SCHEMA_VERSION_UPLINK, &s);
    let back: UplinkSession<'_> =
        decode_object(SCHEMA_UPLINK_SESSION, SCHEMA_VERSION_UPLINK, &bytes).unwrap();
    assert_eq!(back, s);
    assert_eq!(back.body_bytes(), s.body_bytes());
    let observers: Vec<CaptureSig<'_>> = back.observers().collect();
    assert_eq!(observers[1].observer_id.as_bytes(), b"obs-b");

    let body = s.body_bytes();
    // Out of order, twice, five.
    let a = capture(b"obs-a", b"PARTY-A", &SIG_B);
    let b = capture(b"obs-b", b"PARTY-B", &SIG_B);
    for observers in [std::vec![b, a], std::vec![a, a], std::vec![a; 5]] {
        assert_eq!(
            UplinkSession::new(body, &SIG_A, &observers).unwrap_err(),
            ityv_encoding::Error::new(ErrorKind::InvariantViolation, 0)
        );
    }
    let four: Vec<CaptureSig<'static>> = [b"o1".as_slice(), b"o2", b"o3", b"o4"]
        .iter()
        .map(|id| capture(id, b"PARTY-A", &SIG_B))
        .collect();
    let s4 = UplinkSession::new(body, &SIG_A, &four).unwrap();
    assert_eq!(s4.observers().count(), MAX_CAPTURE_SIGS);
    // A body that is not a canonical session body, or too long.
    assert_eq!(
        UplinkSession::new(&body[..body.len() - 1], &SIG_A, &[])
            .unwrap_err()
            .kind(),
        ErrorKind::BodyLengthMismatch
    );
    let long = leak(std::vec![0u8; MAX_SESSION_BODY_LEN + 1]);
    assert_eq!(
        UplinkSession::new(long, &SIG_A, &[]).unwrap_err(),
        ityv_encoding::Error::new(ErrorKind::LengthExceedsMax, 0)
    );
    // The capture statement's fields.
    let m = CaptureMessage {
        body_hash: patterned64(1),
        observer_id: SignerId::new(b"obs-a").unwrap(),
        capture_hash: patterned64(2),
    };
    let mb = bytes_of(&m);
    assert_eq!(mb.len(), 64 + ident_len(b"obs-a") + 64);
    assert_eq!(&mb[..64], patterned64(1).as_bytes());
}

fn session_vectors() -> Vec<Vector> {
    let s = session();
    let bytes = encode_to_vec(SCHEMA_UPLINK_SESSION, SCHEMA_VERSION_UPLINK, &s);
    let body_len = s.body_bytes().len();
    let body_at = HEADER_LEN + 4;
    let count_at = body_at + body_len + HYBRID_SIG_LEN;
    let first = count_at + 4;
    let entry = ident_len(b"obs-a") + ident_len(b"PARTY-A") + 64 + HYBRID_SIG_LEN;
    let mut v = std::vec![valid("two observers", bytes.clone())];
    let bare = UplinkSession::new(s.body_bytes(), &SIG_A, &[]).unwrap();
    v.push(valid(
        "no observer",
        encode_to_vec(SCHEMA_UPLINK_SESSION, SCHEMA_VERSION_UPLINK, &bare),
    ));
    // The body's own rule, rebased onto the session.
    let mut b = bytes.clone();
    let inner = index_at();
    b[body_at + inner..body_at + inner + 4].copy_from_slice(&0u32.to_be_bytes());
    v.push(invalid(
        "a body of session zero",
        b,
        "ValueOutOfRange",
        body_at + inner,
    ));
    let mut b = bytes.clone();
    b[count_at..count_at + 4].copy_from_slice(&5u32.to_be_bytes());
    v.push(invalid("five observers", b, "CountExceedsMax", count_at));
    let mut b = bytes.clone();
    // obs-a → obs-c: then obs-b is out of order.
    b[first + 4 + 4] = b'c';
    v.push(invalid(
        "observers out of order",
        b,
        "NotSorted",
        first + entry,
    ));
    let mut b = bytes;
    b[first + entry + 4 + 4] = b'a';
    v.push(invalid("one observer twice", b, "Duplicate", first + entry));
    v
}

#[test]
fn session_vectors_are_current_and_self_consistent() {
    let content = render("UplinkSession", SCHEMA_UPLINK_SESSION, &session_vectors());
    check_file("uplink_session.txt", &content);
    self_check(&content, |b| {
        let v: UplinkSession<'_> = decode_object(SCHEMA_UPLINK_SESSION, SCHEMA_VERSION_UPLINK, b)?;
        Ok(encode_to_vec(
            SCHEMA_UPLINK_SESSION,
            SCHEMA_VERSION_UPLINK,
            &v,
        ))
    });
}

// ---------------------------------------------------------------------------
// 0x0058 UplinkFrameLog.

fn frame_entry(slot: u64, index: u16, offset: u64, len: u32, objects: u16) -> FrameEntry<'static> {
    FrameEntry {
        slot,
        index,
        kind: FrameKind::Normal,
        stream_offset: offset,
        payload_len: len,
        object_count: objects,
        payload_root: patterned64(0x33),
        frame_sig: &FRAME_SIG,
    }
}

fn object(seed: u8, offset: u64, len: u32) -> StreamObject {
    StreamObject {
        schema: SchemaId::new(0x0007),
        object_hash: patterned64(seed),
        stream_offset: offset,
        len,
    }
}

/// Two frames of 5,000 and 2,000 bytes: the first lists an object it
/// holds whole and one it carries out, the second lists the one carried
/// in.
fn log_parts() -> UplinkFrameLogParts<'static> {
    let frames = [
        frame_entry(150, 0, 0, 5000, 2),
        frame_entry(150, 1, 5000, 2000, 1),
    ];
    let frames: Vec<u8> = frames.iter().flat_map(bytes_of).collect();
    let leaves: Vec<u8> = [patterned64(0x50), patterned64(0x51), patterned64(0x52)]
        .iter()
        .flat_map(|h| h.0)
        .collect();
    let objects: Vec<u8> = [
        object(0x60, 0, 3000),
        object(0x61, 3000, 4000),
        object(0x61, 3000, 4000),
    ]
    .iter()
    .flat_map(bytes_of)
    .collect();
    UplinkFrameLogParts {
        election_id: e(),
        station_id: st(),
        gateway_id: gw(),
        session_index: 1,
        link_id_hash: patterned64(0x11),
        frames: LogFrames::new(leak(frames)).unwrap(),
        leaves: LogLeaves::new(leak(leaves)).unwrap(),
        objects: LogObjects::new(leak(objects)).unwrap(),
    }
}

#[test]
fn a_frame_log_round_trips_and_follows_its_rules() {
    let log = UplinkFrameLog::new(&log_parts()).unwrap();
    assert_eq!(*log.parts(), log_parts());
    let bytes = encode_to_vec(SCHEMA_UPLINK_FRAME_LOG, SCHEMA_VERSION_1, &log);
    let back: UplinkFrameLog<'_> =
        decode_object(SCHEMA_UPLINK_FRAME_LOG, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(back, log);
    let p = back.parts();
    assert_eq!(p.frames.len(), 2);
    assert!(!p.frames.is_empty());
    assert_eq!(p.frames.data_chunks(), 3);
    assert_eq!(p.frames.objects(), 3);
    let frames: Vec<FrameEntry<'_>> = p.frames.iter().collect();
    assert_eq!(frames[1], frame_entry(150, 1, 5000, 2000, 1));
    assert_eq!(
        frames[0].header(patterned64(0x11), patterned64(0x34)),
        UplinkFrameHeaderParts {
            link_id_hash: patterned64(0x11),
            slot: 150,
            index: 0,
            kind: FrameKind::Normal,
            stream_offset: 0,
            payload_len: 5000,
            payload_root: patterned64(0x33),
            objects_hash: patterned64(0x34),
        }
    );
    assert_eq!(p.leaves.len(), 3);
    assert!(!p.leaves.is_empty());
    assert!(LogLeaves::EMPTY.is_empty());
    assert_eq!(p.leaves.iter().nth(1), Some(patterned64(0x51)));
    assert_eq!(p.objects.len(), 3);
    assert!(!p.objects.is_empty());
    assert!(LogObjects::EMPTY.is_empty());
    assert_eq!(object(0x61, 3000, 2000).end(), Some(5000));
    assert_eq!(object(1, u64::MAX, 16).end(), None);
    // Each frame with its leaves and its list.
    let with: Vec<_> = back.frames_with().collect();
    assert_eq!(with.len(), 2);
    assert_eq!(with[0].entry, frames[0]);
    assert_eq!(with[0].leaves.len(), 2);
    assert_eq!(with[1].leaves.iter().next(), Some(patterned64(0x52)));
    assert_eq!(with[0].objects.len(), 2);
    assert_eq!(
        with[0].objects.iter().nth(1),
        Some(object(0x61, 3000, 4000))
    );
    assert_eq!(with[1].objects.len(), 1);
    assert_eq!(
        with[1].objects.iter().next(),
        Some(object(0x61, 3000, 4000))
    );
    assert!(!with[1].objects.is_empty());
    assert!(FrameObjects::EMPTY.is_empty());

    // The constructor: session 0, leaves or objects that do not match the
    // frames, a frame's list out of order.
    let mut q = log_parts();
    q.session_index = 0;
    assert_eq!(
        UplinkFrameLog::new(&q).unwrap_err().kind(),
        ErrorKind::ValueOutOfRange
    );
    let mut q = log_parts();
    q.leaves = LogLeaves::EMPTY;
    assert_eq!(
        UplinkFrameLog::new(&q).unwrap_err().kind(),
        ErrorKind::InvariantViolation
    );
    let mut q = log_parts();
    q.objects = LogObjects::EMPTY;
    assert_eq!(
        UplinkFrameLog::new(&q).unwrap_err().kind(),
        ErrorKind::InvariantViolation
    );
    let mut q = log_parts();
    let swapped: Vec<u8> = [
        object(0x61, 3000, 4000),
        object(0x60, 0, 3000),
        object(0x61, 3000, 4000),
    ]
    .iter()
    .flat_map(bytes_of)
    .collect();
    q.objects = LogObjects::new(leak(swapped)).unwrap();
    assert_eq!(
        UplinkFrameLog::new(&q).unwrap_err().kind(),
        ErrorKind::InvariantViolation
    );
    // The views.
    let one = bytes_of(&frame_entry(150, 0, 0, 5000, 0));
    assert_eq!(LogFrames::new(&[]), None);
    assert_eq!(LogFrames::new(&one[..152]), None);
    let twice: Vec<u8> = one.iter().chain(&one).copied().collect();
    assert_eq!(LogFrames::new(&twice), None);
    let down: Vec<u8> = bytes_of(&frame_entry(151, 0, 0, 0, 0))
        .into_iter()
        .chain(one.clone())
        .collect();
    assert_eq!(LogFrames::new(&down), None);
    let too_many = bytes_of(&frame_entry(150, 0, 0, 5000, 1025));
    assert_eq!(LogFrames::new(&too_many), None);
    assert!(LogFrames::new(&bytes_of(&frame_entry(150, 0, 0, 5000, 1024))).is_some());
    assert_eq!(LogLeaves::new(&[0u8; 63]), None);
    assert!(LogLeaves::new(&[0u8; 128]).is_some());
    let o = bytes_of(&object(1, 100, 16));
    assert_eq!(FrameObjects::new(&o[..79]), None);
    assert_eq!(LogObjects::new(&o[..79]), None);
    let overlap: Vec<u8> = o
        .iter()
        .copied()
        .chain(bytes_of(&object(2, 115, 16)))
        .collect();
    assert_eq!(FrameObjects::new(&overlap), None);
    // A log's entries are lists one after another: no order across them.
    assert_eq!(LogObjects::new(&overlap).map(|l| l.len()), Some(2));
    let touching: Vec<u8> = o
        .iter()
        .copied()
        .chain(bytes_of(&object(2, 116, 16)))
        .collect();
    assert_eq!(FrameObjects::new(&touching).map(|l| l.len()), Some(2));
    let short = bytes_of(&object(1, 100, 15));
    assert_eq!(LogObjects::new(&short), None);
    let past = bytes_of(&object(1, u64::MAX - 15, 16));
    assert_eq!(LogObjects::new(&past), None);
    assert!(LogObjects::new(&bytes_of(&object(1, u64::MAX - 16, 16))).is_some());
    let full: Vec<u8> = (0..1025u64)
        .flat_map(|i| bytes_of(&object(1, 16 * i, 16)))
        .collect();
    assert_eq!(FrameObjects::new(&full), None);
    assert_eq!(
        FrameObjects::new(&full[..1024 * 80]).map(|l| l.len()),
        Some(1024)
    );
}

fn log_vectors() -> Vec<Vector> {
    let log = UplinkFrameLog::new(&log_parts()).unwrap();
    let bytes = encode_to_vec(SCHEMA_UPLINK_FRAME_LOG, SCHEMA_VERSION_1, &log);
    let at = index_at();
    let frames_at = at + 4 + 64;
    let first = frames_at + 4;
    let second = first + FRAME_ENTRY_LEN;
    let leaves_at = second + FRAME_ENTRY_LEN;
    let objects_at = leaves_at + 4 + 3 * 64;
    let first_object = objects_at + 4;
    let second_object = first_object + OBJECT_ENTRY_LEN;
    let mut v = std::vec![valid(
        "two frames, an object carried from the first into the second",
        bytes.clone()
    )];

    let mut b = bytes.clone();
    b[at..at + 4].copy_from_slice(&0u32.to_be_bytes());
    v.push(invalid("session zero", b, "ValueOutOfRange", at));
    let mut b = bytes[..first].to_vec();
    b[frames_at..first].copy_from_slice(&0u32.to_be_bytes());
    b.extend_from_slice(&0u32.to_be_bytes());
    b.extend_from_slice(&0u32.to_be_bytes());
    fix_len(&mut b);
    v.push(invalid("no frame", b, "InvariantViolation", frames_at));
    let mut b = bytes.clone();
    b[frames_at..first].copy_from_slice(&385u32.to_be_bytes());
    v.push(invalid("385 frames", b, "CountExceedsMax", frames_at));
    let mut b = bytes.clone();
    b[second + 8..second + 10].copy_from_slice(&0u16.to_be_bytes());
    v.push(invalid("one frame twice", b, "Duplicate", second));
    let mut b = bytes.clone();
    b[second..second + 8].copy_from_slice(&149u64.to_be_bytes());
    v.push(invalid("frames out of order", b, "NotSorted", second));
    let mut b = bytes.clone();
    b[first + 8 + 2] = 4;
    v.push(invalid("kind four", b, "ValueOutOfRange", first + 10));
    let mut b = bytes.clone();
    b[first + 23..first + 25].copy_from_slice(&1025u16.to_be_bytes());
    v.push(invalid(
        "a frame listing 1,025 objects",
        b,
        "ValueOutOfRange",
        first + 23,
    ));
    let mut b = bytes.clone();
    b[leaves_at..leaves_at + 4].copy_from_slice(&2u32.to_be_bytes());
    v.push(invalid(
        "one leaf short",
        b,
        "InvariantViolation",
        leaves_at,
    ));
    let mut b = bytes.clone();
    b[objects_at..objects_at + 4].copy_from_slice(&2u32.to_be_bytes());
    v.push(invalid(
        "one object entry short",
        b,
        "InvariantViolation",
        objects_at,
    ));
    let mut b = bytes.clone();
    b[second_object + 68..second_object + 76].copy_from_slice(&2999u64.to_be_bytes());
    v.push(invalid(
        "objects of one frame overlapping",
        b,
        "InvariantViolation",
        second_object,
    ));
    let mut b = bytes.clone();
    b[second_object + 76..second_object + 80].copy_from_slice(&15u32.to_be_bytes());
    v.push(invalid(
        "an object shorter than a header",
        b,
        "ValueOutOfRange",
        second_object + 76,
    ));
    let mut b = bytes;
    b[first_object + 68..first_object + 76].copy_from_slice(&u64::MAX.to_be_bytes());
    v.push(invalid(
        "an object past the end of the stream",
        b,
        "ValueOutOfRange",
        first_object,
    ));
    v
}

#[test]
fn frame_log_vectors_are_current_and_self_consistent() {
    let content = render("UplinkFrameLog", SCHEMA_UPLINK_FRAME_LOG, &log_vectors());
    check_file("uplink_frame_log.txt", &content);
    self_check(&content, |b| {
        let v: UplinkFrameLog<'_> = decode_object(SCHEMA_UPLINK_FRAME_LOG, SCHEMA_VERSION_1, b)?;
        Ok(encode_to_vec(SCHEMA_UPLINK_FRAME_LOG, SCHEMA_VERSION_1, &v))
    });
}

// ---------------------------------------------------------------------------
// 0x0059 ConnectivityIncidentBody.

fn incident_parts() -> ConnectivityIncidentParts<'static> {
    ConnectivityIncidentParts {
        election_id: e(),
        station_id: Some(st()),
        box_id: Some(BoxId::new(BOX).unwrap()),
        kind: IncidentKind::CaptureMismatch,
        from_slot: 160,
        to_slot: 165,
        commitment_unit: true,
        evidence_hash: patterned64(0xEE),
    }
}

#[test]
fn an_incident_round_trips_and_follows_its_rules() {
    let body = ConnectivityIncidentBody::new(&incident_parts()).unwrap();
    assert_eq!(*body.parts(), incident_parts());
    let bytes = encode_to_vec(SCHEMA_CONNECTIVITY_INCIDENT_BODY, SCHEMA_VERSION_1, &body);
    let back: ConnectivityIncidentBody<'_> =
        decode_object(SCHEMA_CONNECTIVITY_INCIDENT_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(back, body);
    for kind in IncidentKind::ALL {
        let mut p = incident_parts();
        p.kind = *kind;
        assert!(ConnectivityIncidentBody::new(&p).is_ok());
    }
    let err = |p: &ConnectivityIncidentParts<'static>| {
        ConnectivityIncidentBody::new(p).unwrap_err().kind()
    };
    let mut p = incident_parts();
    p.station_id = None;
    assert_eq!(err(&p), ErrorKind::InvariantViolation);
    p.box_id = None;
    assert!(ConnectivityIncidentBody::new(&p).is_ok());
    let mut p = incident_parts();
    p.from_slot = 166;
    assert_eq!(err(&p), ErrorKind::InvariantViolation);
    // One slot: the interval may start where it ends, in the constructor
    // and in the decoder.
    p.from_slot = 165;
    let one = ConnectivityIncidentBody::new(&p).unwrap();
    let bytes = encode_to_vec(SCHEMA_CONNECTIVITY_INCIDENT_BODY, SCHEMA_VERSION_1, &one);
    let back: ConnectivityIncidentBody<'_> =
        decode_object(SCHEMA_CONNECTIVITY_INCIDENT_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(back, one);
    let mut p = incident_parts();
    p.evidence_hash = Hash512::ZERO;
    assert_eq!(err(&p), ErrorKind::InvalidPreviousHash);
}

fn incident_vectors() -> Vec<Vector> {
    let bytes = encode_to_vec(
        SCHEMA_CONNECTIVITY_INCIDENT_BODY,
        SCHEMA_VERSION_1,
        &ConnectivityIncidentBody::new(&incident_parts()).unwrap(),
    );
    let station_at = HEADER_LEN + ident_len(E);
    let box_at = station_at + 1 + ident_len(ST);
    let kind_at = box_at + 1 + ident_len(BOX);
    let to_at = kind_at + 1 + 8;
    let evidence_at = to_at + 8 + 1;
    let mut v = std::vec![valid("a box's commitment unit", bytes.clone())];
    let mut whole = incident_parts();
    whole.station_id = None;
    whole.box_id = None;
    whole.commitment_unit = false;
    whole.kind = IncidentKind::RadioCheckFinding;
    v.push(valid(
        "the whole election",
        encode_to_vec(
            SCHEMA_CONNECTIVITY_INCIDENT_BODY,
            SCHEMA_VERSION_1,
            &ConnectivityIncidentBody::new(&whole).unwrap(),
        ),
    ));
    // A box without a station: drop the station.
    let mut b = bytes[..station_at].to_vec();
    b.push(0);
    b.extend_from_slice(&bytes[box_at..]);
    fix_len(&mut b);
    v.push(invalid(
        "a box without a station",
        b,
        "InvariantViolation",
        station_at + 1,
    ));
    let mut b = bytes.clone();
    b[kind_at] = 0;
    v.push(invalid("kind zero", b, "ValueOutOfRange", kind_at));
    let mut b = bytes.clone();
    b[kind_at] = 11;
    v.push(invalid("kind eleven", b, "ValueOutOfRange", kind_at));
    let mut b = bytes.clone();
    b[to_at..to_at + 8].copy_from_slice(&159u64.to_be_bytes());
    v.push(invalid(
        "an interval ending first",
        b,
        "InvariantViolation",
        to_at,
    ));
    let mut b = bytes.clone();
    b[evidence_at - 1] = 2;
    v.push(invalid("a bool of two", b, "InvalidBool", evidence_at - 1));
    let mut b = bytes;
    b[evidence_at..evidence_at + 64].fill(0);
    v.push(invalid(
        "no evidence",
        b,
        "InvalidPreviousHash",
        evidence_at,
    ));
    v
}

#[test]
fn incident_vectors_are_current_and_self_consistent() {
    let content = render(
        "ConnectivityIncidentBody",
        SCHEMA_CONNECTIVITY_INCIDENT_BODY,
        &incident_vectors(),
    );
    check_file("connectivity_incident_body.txt", &content);
    self_check(&content, |b| {
        let v: ConnectivityIncidentBody<'_> =
            decode_object(SCHEMA_CONNECTIVITY_INCIDENT_BODY, SCHEMA_VERSION_1, b)?;
        Ok(encode_to_vec(
            SCHEMA_CONNECTIVITY_INCIDENT_BODY,
            SCHEMA_VERSION_1,
            &v,
        ))
    });
}

// ---------------------------------------------------------------------------
// Property tests.

fn frame_kind() -> impl Strategy<Value = FrameKind> {
    (0u8..4).prop_map(|c| FrameKind::from_code(c).unwrap())
}

proptest! {
    #[test]
    fn headers_round_trip(
        link in common::hash64(),
        slot in any::<u64>(),
        index in 0..MAX_FRAMES_PER_SLOT,
        kind in frame_kind(),
        offset in any::<u64>(),
        len in 0..=MAX_PAYLOAD_LEN as u32,
        root in common::hash64(),
        objects in common::hash64(),
    ) {
        let h = UplinkFrameHeader::new(&UplinkFrameHeaderParts {
            link_id_hash: Hash512(link),
            slot,
            index,
            kind,
            stream_offset: offset,
            payload_len: len,
            payload_root: Hash512(root),
            objects_hash: Hash512(objects),
        })
        .unwrap();
        let bytes = encode_to_vec(SCHEMA_UPLINK_FRAME_HEADER, SCHEMA_VERSION_1, &h);
        let back: UplinkFrameHeader =
            decode_object(SCHEMA_UPLINK_FRAME_HEADER, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back, h);
    }

    #[test]
    fn session_bodies_round_trip(
        index in 2u32..,
        start in any::<u64>(),
        span in 0u64..6,
        seeds in prop::collection::btree_set(any::<u8>(), 0..=16),
        wan in any::<u64>(),
        is_final in any::<bool>(),
    ) {
        prop_assume!(start.checked_add(span).is_some());
        let links: Vec<SessionLink> = seeds.iter().map(|s| {
            let mut l = session_link(0);
            l.link_id_hash = Hash512([*s; 64]);
            l
        }).collect();
        let mut p = session_parts();
        p.session_index = index;
        p.start_slot = start;
        p.end_slot = start + span;
        p.links = links_of(&links);
        p.wan_bytes = wan;
        p.is_final = is_final;
        let bytes = body_bytes(&p);
        let back: UplinkSessionBody<'_> =
            decode_object(SCHEMA_UPLINK_SESSION_BODY, SCHEMA_VERSION_UPLINK, &bytes).unwrap();
        prop_assert_eq!(*back.parts(), p);
    }

    #[test]
    fn decoding_arbitrary_bytes_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..600)) {
        let _ = decode_object::<ConnectivityManifest<'_>>(SCHEMA_CONNECTIVITY_MANIFEST, SCHEMA_VERSION_UPLINK, &bytes);
        let _ = decode_object::<UplinkFrameHeader>(SCHEMA_UPLINK_FRAME_HEADER, SCHEMA_VERSION_1, &bytes);
        let _ = decode_object::<UplinkSessionBody<'_>>(SCHEMA_UPLINK_SESSION_BODY, SCHEMA_VERSION_UPLINK, &bytes);
        let _ = decode_object::<UplinkSession<'_>>(SCHEMA_UPLINK_SESSION, SCHEMA_VERSION_UPLINK, &bytes);
        let _ = decode_object::<UplinkFrameLog<'_>>(SCHEMA_UPLINK_FRAME_LOG, SCHEMA_VERSION_1, &bytes);
        let _ = decode_object::<ConnectivityIncidentBody<'_>>(SCHEMA_CONNECTIVITY_INCIDENT_BODY, SCHEMA_VERSION_1, &bytes);
        let _ = ManifestEntries::new(&bytes);
        let _ = SessionLinks::new(&bytes);
        let _ = LogFrames::new(&bytes);
        let _ = LogObjects::new(&bytes);
        let _ = FrameObjects::new(&bytes);
    }

    #[test]
    fn mutated_vectors_never_panic(at in any::<prop::sample::Index>(), byte in any::<u8>()) {
        let log = UplinkFrameLog::new(&log_parts()).unwrap();
        let mut bytes = encode_to_vec(SCHEMA_UPLINK_FRAME_LOG, SCHEMA_VERSION_1, &log);
        let i = at.index(bytes.len());
        bytes[i] = byte;
        let _ = decode_object::<UplinkFrameLog<'_>>(SCHEMA_UPLINK_FRAME_LOG, SCHEMA_VERSION_1, &bytes);
        let mut session = encode_to_vec(SCHEMA_UPLINK_SESSION, SCHEMA_VERSION_UPLINK, &session());
        let j = at.index(session.len());
        session[j] = byte;
        let _ = decode_object::<UplinkSession<'_>>(SCHEMA_UPLINK_SESSION, SCHEMA_VERSION_UPLINK, &session);
    }
}

#[test]
fn the_patterned_helpers_are_what_the_vectors_assume() {
    let p: [u8; 4] = patterned(1);
    assert_eq!(p, [1, 2, 3, 4]);
}

#[test]
fn an_incident_is_signed_on_site_or_by_the_committee_with_two_observers() {
    use ityv_encoding::{
        EventRole, EventSig, PURPOSE_CONNECTIVITY_INCIDENT, SCHEMA_VERSION_WITNESSED,
        SCHEMA_WITNESSED_EVENT, WitnessedEvent, roles_satisfied,
    };
    let sig = |id: &'static [u8], role: EventRole, org: &'static [u8]| EventSig {
        signer_id: SignerId::new(id).unwrap(),
        role,
        org_id: OrgId::new(org).unwrap(),
        sig: &SIG_A,
    };
    let clerk_1 = sig(b"clerk-1", EventRole::Clerk, b"ORG-ST");
    let clerk_2 = sig(b"clerk-2", EventRole::Clerk, b"ORG-ST");
    let committee = sig(b"committee", EventRole::Committee, b"IVC");
    let obs_a = sig(b"obs-a", EventRole::Observer, b"PARTY-A");
    let obs_b = sig(b"obs-b", EventRole::Observer, b"PARTY-B");
    let obs_c = sig(b"obs-c", EventRole::Observer, b"PARTY-A");
    let auditor = sig(b"aud-1", EventRole::Auditor, b"AUDIT-A");
    let s = SCHEMA_CONNECTIVITY_INCIDENT_BODY;
    let ok = |who: &[EventSig<'static>]| roles_satisfied(s, || who.iter().copied());
    assert!(ok(&[clerk_1, clerk_2, obs_a, obs_b]));
    assert!(ok(&[committee, obs_a, obs_b]));
    // One clerk, one organisation, the committee without two
    // organisations, another role.
    assert!(!ok(&[clerk_1, obs_a, obs_b]));
    assert!(!ok(&[clerk_1, clerk_2, obs_a, obs_c]));
    assert!(!ok(&[committee, obs_a, obs_c]));
    assert!(!ok(&[committee, auditor, obs_a, obs_b]));
    assert!(!ok(&[obs_a, obs_b]));

    // In its envelope: round trip, purpose, and the body's own rule at its
    // place in the envelope.
    let body = leak(encode_to_vec(
        s,
        SCHEMA_VERSION_1,
        &ConnectivityIncidentBody::new(&incident_parts()).unwrap(),
    ));
    let event = WitnessedEvent::new(body, &[clerk_1, clerk_2, obs_a, obs_b]).unwrap();
    assert_eq!(event.purpose(), PURPOSE_CONNECTIVITY_INCIDENT);
    assert_eq!(event.body_schema(), s);
    let bytes = encode_to_vec(SCHEMA_WITNESSED_EVENT, SCHEMA_VERSION_WITNESSED, &event);
    let back: WitnessedEvent<'_> =
        decode_object(SCHEMA_WITNESSED_EVENT, SCHEMA_VERSION_WITNESSED, &bytes).unwrap();
    assert_eq!(back, event);
    assert_eq!(
        back.body::<ConnectivityIncidentBody<'_>>(s)
            .unwrap()
            .parts(),
        &incident_parts()
    );
    assert_eq!(
        WitnessedEvent::new(body, &[clerk_1, obs_a, obs_b])
            .unwrap_err()
            .kind(),
        ErrorKind::InvariantViolation
    );
    let kind_at = HEADER_LEN + ident_len(E) + 1 + ident_len(ST) + 1 + ident_len(BOX);
    let mut bad = body.to_vec();
    bad[kind_at] = 0;
    assert_eq!(
        WitnessedEvent::new(leak(bad), &[clerk_1, clerk_2, obs_a, obs_b])
            .unwrap_err()
            .kind(),
        ErrorKind::ValueOutOfRange
    );
}

#[test]
fn the_constants_are_the_specs() {
    use ityv_encoding::{
        CARRY_CHECKIN, CARRY_LINK, CARRY_ROLL, CHUNK_LEN, FRAME_KEY_LEN, MAX_LOG_FRAMES,
        MAX_LOG_LEAVES, MAX_LOG_OBJECTS, MAX_MANIFEST_ENTRIES, MAX_PORT_LEN, MAX_SESSION_SLOTS,
        MIN_OBJECT_LEN, PAYLOAD_CHUNKS, PURPOSE_CONNECTIVITY_INCIDENT, PURPOSE_UPLINK_CAPTURE,
        PURPOSE_UPLINK_FRAME, PURPOSE_UPLINK_SESSION, SCHEMA_GENESIS_BOX, SCHEMA_STATION_ENTRY,
        SCHEMA_VERSION_DEVICE_ENTRY, SLOT_MINUTES,
    };
    assert_eq!(FRAME_BODY_LEN, 1_048_576);
    assert_eq!(MAX_PAYLOAD_LEN, 966_503);
    assert_eq!((CHUNK_LEN, PAYLOAD_CHUNKS), (4096, 256));
    assert_eq!(CHUNK_LEN * PAYLOAD_CHUNKS, FRAME_BODY_LEN);
    assert_eq!((SLOT_MINUTES, MAX_SESSION_SLOTS), (10, 6));
    assert_eq!(MAX_FRAMES_PER_SLOT, 64);
    assert_eq!(
        (MAX_MANIFEST_ENTRIES, MAX_PORT_LEN, FRAME_KEY_LEN),
        (256, 32, 32)
    );
    assert_eq!(
        (MAX_SESSION_LINKS, MAX_SESSION_BODY_LEN, MAX_CAPTURE_SIGS),
        (16, 4096, 4)
    );
    assert_eq!(
        (MAX_LOG_FRAMES, MAX_LOG_LEAVES, MAX_LOG_OBJECTS),
        (384, 98_304, 393_216)
    );
    assert_eq!(MIN_OBJECT_LEN as usize, HEADER_LEN);
    assert_eq!(
        [
            CARRY_PUBLIC,
            CARRY_SEALED,
            CARRY_CHECKIN,
            CARRY_LINK,
            CARRY_LEDGER,
            CARRY_ROLL,
            CARRY_SESSION
        ],
        [1, 2, 4, 8, 16, 32, 64]
    );
    assert_eq!(CARRIES_MASK, 0x7F);
    assert_eq!(PURPOSE_UPLINK_FRAME, b"uplink-frame");
    assert_eq!(PURPOSE_UPLINK_SESSION, b"uplink-session");
    assert_eq!(PURPOSE_UPLINK_CAPTURE, b"uplink-capture");
    assert_eq!(PURPOSE_CONNECTIVITY_INCIDENT, b"connectivity-incident");
    // The device entries that carry the frame keys are version 2.
    assert_eq!(SCHEMA_VERSION_DEVICE_ENTRY, 2);
    assert_eq!(schema_version(SCHEMA_GENESIS_BOX), 2);
    assert_eq!(schema_version(SCHEMA_STATION_ENTRY), 2);
    // A log holds up to 98,304 leaves: 384 full frames.
    let most = std::vec![0u8; MAX_LOG_LEAVES * 64];
    assert_eq!(LogLeaves::new(&most).map(|l| l.len()), Some(MAX_LOG_LEAVES));
    let over = std::vec![0u8; (MAX_LOG_LEAVES + 1) * 64];
    assert_eq!(LogLeaves::new(&over), None);
}
