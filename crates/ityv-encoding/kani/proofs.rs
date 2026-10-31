//! Kani bounded model-checking harnesses (verification ladder V2).
//!
//! Compiled only under `cargo kani`. Each harness states one property from
//! ENCODING.md. Kani additionally checks every harness for panics, overflow
//! and out-of-bounds access on all explored inputs, which is the mechanical
//! form of the crate's "no panics" promise.
//!
//! Run with `cargo kani -p ityv-encoding` from the workspace root. The file
//! lives outside `src/` and is included as `crate::proofs` by a `#[path]`
//! attribute in `src/lib.rs`.
// Harness file: outside the TCB and outside `src/` (CONSTITUTION.md §1.1).
// A harness states expected values with plain indexing and unchecked
// arithmetic on bounded symbolic inputs, and Kani itself reports any panic
// or overflow in them, so these restriction lints are relaxed for this file
// only.
#![allow(
    clippy::unreachable,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc
)]

use crate::codec::{Decode, Encode};
use crate::envelope::{Header, MAGIC, decode, encode};
use crate::error::Kind;
use crate::primitives::{ElectionId, Hash512, Ident, SchemaId, Seq};
use crate::reader::Reader;
use crate::schema::ledger_frame::LedgerFrame;
use crate::schema::{SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1};
use crate::writer::Writer;

/// `u64` survives a write/read round trip and consumes exactly eight bytes.
#[kani::proof]
fn u64_round_trip() {
    let value: u64 = kani::any();
    let mut buf = [0u8; 8];
    let mut w = Writer::new(&mut buf);
    assert!(w.write_u64(value).is_ok());
    assert_eq!(w.finish(), 8);
    let mut r = Reader::new(&buf);
    assert_eq!(r.read_u64(), Ok(value));
    assert!(r.finish().is_ok());
}

/// `u32` and `u16` round trips.
#[kani::proof]
fn small_int_round_trips() {
    let a: u32 = kani::any();
    let b: u16 = kani::any();
    let mut buf = [0u8; 6];
    let mut w = Writer::new(&mut buf);
    assert!(w.write_u32(a).is_ok());
    assert!(w.write_u16(b).is_ok());
    let mut r = Reader::new(&buf);
    assert_eq!(r.read_u32(), Ok(a));
    assert_eq!(r.read_u16(), Ok(b));
    assert!(r.finish().is_ok());
}

/// A `bool` byte decodes if and only if it is `0x00` or `0x01`.
#[kani::proof]
fn bool_is_strict() {
    let byte: u8 = kani::any();
    let buf = [byte];
    let mut r = Reader::new(&buf);
    let result = r.read_bool();
    assert_eq!(result.is_ok(), byte == 0 || byte == 1);
    if byte > 1 {
        assert_eq!(
            result.map(|_| ()).err().map(|e| e.kind()),
            Some(Kind::InvalidBool)
        );
    }
}

/// A presence tag decodes if and only if it is `0x00` or `0x01`.
#[kani::proof]
fn presence_is_strict() {
    let byte: u8 = kani::any();
    let buf = [byte];
    let mut r = Reader::new(&buf);
    let result = r.read_presence();
    assert_eq!(result.is_ok(), byte == 0 || byte == 1);
}

/// `Ident::new` accepts exactly the strings of length 1..=max over the
/// alphabet `[A-Za-z0-9._:-]`.
#[kani::proof]
#[kani::unwind(6)]
fn ident_alphabet_is_exact() {
    const N: usize = 4;
    let bytes: [u8; N] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= N);
    let (prefix, _) = bytes.split_at_checked(len).unwrap_or((&[], &bytes));
    let accepted = Ident::new(prefix, N).is_some();
    let expected = len >= 1 && prefix.iter().all(|b| Ident::is_valid_byte(*b));
    assert_eq!(accepted, expected);
}

/// `Ident::is_valid_byte` matches the specified alphabet exactly.
#[kani::proof]
fn ident_byte_alphabet() {
    let b: u8 = kani::any();
    let expected = b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b':' || b == b'-';
    assert_eq!(Ident::is_valid_byte(b), expected);
}

/// A header whose first four bytes are not the magic is rejected at offset 0.
#[kani::proof]
fn header_rejects_bad_magic() {
    let input: [u8; 16] = kani::any();
    let magic_ok = input.first_chunk::<4>().is_some_and(|m| *m == MAGIC);
    kani::assume(!magic_ok);
    let mut r = Reader::new(&input);
    let result = Header::read(&mut r);
    assert_eq!(
        result.err().map(|e| (e.kind(), e.offset())),
        Some((Kind::BadMagic, 0))
    );
}

/// A header with non-zero flags or a wrong body length is rejected.
#[kani::proof]
fn header_rejects_flags_and_length() {
    let flags: u16 = kani::any();
    let body_len: u32 = kani::any();
    let mut buf = [0u8; 16];
    let mut w = Writer::new(&mut buf);
    assert!(w.write_array(&MAGIC).is_ok());
    assert!(w.write_u32(1).is_ok());
    assert!(w.write_u16(1).is_ok());
    assert!(w.write_u16(flags).is_ok());
    assert!(w.write_u32(body_len).is_ok());
    let mut r = Reader::new(&buf);
    let result = Header::read(&mut r);
    if flags != 0 {
        assert_eq!(result.err().map(|e| e.kind()), Some(Kind::NonZeroFlags));
    } else if body_len != 0 {
        assert_eq!(
            result.err().map(|e| e.kind()),
            Some(Kind::BodyLengthMismatch)
        );
    } else {
        assert!(result.is_ok());
    }
}

/// The reader never panics on arbitrary bounded input, whatever sequence of
/// reads is attempted.
#[kani::proof]
#[kani::unwind(10)]
fn reader_never_panics() {
    let buf: [u8; 24] = kani::any();
    let mut r = Reader::new(&buf);
    let _ = r.read_u8();
    let _ = r.read_u16();
    let _ = r.read_u32();
    let _ = r.read_u64();
    let _ = r.read_bool();
    let _ = r.read_presence();
    let _ = r.read_len(8);
    let _ = r.read_count(8);
    let _ = r.read_bytes(8);
    let _ = r.read_ident(8);
    let _ = r.read_array::<3>();
    let _ = r.take(5);
    let _ = r.finish();
}

/// The writer never panics on arbitrary bounded output space.
#[kani::proof]
fn writer_never_panics() {
    let mut buf = [0u8; 12];
    let limit: usize = kani::any();
    kani::assume(limit <= 12);
    let (out, _) = buf
        .split_at_mut_checked(limit)
        .unwrap_or((&mut [], &mut []));
    let mut w = Writer::new(out);
    let _ = w.write_u8(kani::any());
    let _ = w.write_u16(kani::any());
    let _ = w.write_u32(kani::any());
    let _ = w.write_u64(kani::any());
    let _ = w.write_bool(kani::any());
    let _ = w.write_bytes(b"ab", 2);
    assert!(w.finish() <= limit);
}

/// A `LedgerFrame` with arbitrary hashes and a non-zero sequence survives an
/// object-level round trip, and decoding consumes every byte.
#[kani::proof]
#[kani::unwind(70)] // 64-byte array comparisons unroll to 64 iterations plus slack.
fn ledger_frame_round_trip() {
    let seq_raw: u64 = kani::any();
    kani::assume(seq_raw >= 1);
    let Some(seq) = Seq::new(seq_raw) else {
        unreachable!("seq_raw >= 1 by assumption");
    };
    let prev: [u8; 64] = kani::any();
    let event: [u8; 64] = kani::any();
    let schema_raw: u32 = kani::any();
    let Some(election_id) = ElectionId::new(b"E") else {
        unreachable!("literal identifier is valid");
    };
    let frame = LedgerFrame::new(
        election_id,
        seq,
        Hash512(prev),
        SchemaId::new(schema_raw),
        Hash512(event),
    );
    let mut buf = [0u8; 256];
    let Ok(len) = encode(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &frame, &mut buf) else {
        unreachable!("256 bytes suffice for a one-byte identifier");
    };
    assert_eq!(len, 16 + frame.encoded_len());
    let (bytes, _) = buf.split_at_checked(len).unwrap_or((&[], &buf));
    let decoded: Result<LedgerFrame<'_>, _> = decode(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, bytes);
    assert_eq!(decoded, Ok(frame));
}

/// A zero sequence number is rejected at the offset of the `seq` field.
#[kani::proof]
#[kani::unwind(4)]
fn ledger_frame_rejects_zero_seq() {
    let mut buf = [0u8; 256];
    let mut w = Writer::new(&mut buf);
    assert!(w.write_u32(1).is_ok());
    assert!(w.write_u8(b'E').is_ok());
    assert!(w.write_u64(0).is_ok());
    let result = LedgerFrame::decode(&mut Reader::new(&buf));
    assert_eq!(
        result.err().map(|e| (e.kind(), e.offset())),
        Some((Kind::ValueOutOfRange, 5))
    );
}

// ---------------------------------------------------------------------------
// M3 schemas (ENCODING.md §8.6–§8.18)
// ---------------------------------------------------------------------------

use crate::primitives::{BoxId, StationId, TimeBucket};
use crate::schema::batch_attest::{BatchAttestBody, record_count_valid};
use crate::schema::box_close::{BoxCloseBody, SignerRole};
use crate::schema::cast_record::{ProofHeader, transport_flags_valid};
use crate::schema::scan_count::ScanCountAttestBody;
use crate::schema::share_package::{
    ChamberCode, MemberShare, SharePackage, Transport, pad_fields_valid, transport_code_valid,
};
use crate::schema::slip::SlipBody;
use crate::schema::{
    SCHEMA_BATCH_ATTEST_BODY, SCHEMA_BOX_CLOSE_BODY, SCHEMA_MEMBER_SHARE,
    SCHEMA_SCAN_COUNT_ATTEST_BODY, SCHEMA_SHARE_PACKAGE, SCHEMA_SLIP_BODY,
};

/// A `SlipBody` with a symbolic time bucket and tracking code survives an
/// object-level round trip and consumes every byte.
#[kani::proof]
#[kani::unwind(70)] // 64-byte array comparisons unroll to 64 iterations plus slack.
fn slip_body_round_trip() {
    let bucket: u64 = kani::any();
    let code: [u8; 64] = kani::any();
    let Some(election_id) = ElectionId::new(b"E") else {
        unreachable!("literal identifier is valid");
    };
    let Some(station_id) = StationId::new(b"S") else {
        unreachable!("literal identifier is valid");
    };
    let body = SlipBody::new(
        election_id,
        station_id,
        TimeBucket::new(bucket),
        Hash512(code),
    );
    let mut buf = [0u8; 128];
    let Ok(len) = encode(SCHEMA_SLIP_BODY, SCHEMA_VERSION_1, &body, &mut buf) else {
        unreachable!("128 bytes suffice for one-byte identifiers");
    };
    assert_eq!(len, 16 + 5 + 5 + 8 + 64);
    let (bytes, _) = buf.split_at_checked(len).unwrap_or((&[], &buf));
    let decoded: Result<SlipBody<'_>, _> = decode(SCHEMA_SLIP_BODY, SCHEMA_VERSION_1, bytes);
    assert_eq!(decoded, Ok(body));
}

/// A `ScanCountAttestBody` with symbolic counts and bucket survives an
/// object-level round trip (the journal head is concrete to keep the model
/// small; its bytes are copied verbatim like every other digest).
#[kani::proof]
#[kani::unwind(70)]
fn scan_count_body_round_trip() {
    let records: u64 = kani::any();
    let challenges: u64 = kani::any();
    let quarantines: u64 = kani::any();
    let bucket: u64 = kani::any();
    let Some(election_id) = ElectionId::new(b"E") else {
        unreachable!("literal identifier is valid");
    };
    let Some(box_id) = BoxId::new(b"B") else {
        unreachable!("literal identifier is valid");
    };
    let body = ScanCountAttestBody::new(
        election_id,
        box_id,
        records,
        challenges,
        quarantines,
        Hash512([7; 64]),
        TimeBucket::new(bucket),
    );
    let mut buf = [0u8; 160];
    let Ok(len) = encode(
        SCHEMA_SCAN_COUNT_ATTEST_BODY,
        SCHEMA_VERSION_1,
        &body,
        &mut buf,
    ) else {
        unreachable!("160 bytes suffice for one-byte identifiers");
    };
    assert_eq!(len, 16 + 5 + 5 + 24 + 64 + 8);
    let (bytes, _) = buf.split_at_checked(len).unwrap_or((&[], &buf));
    let decoded: Result<ScanCountAttestBody<'_>, _> =
        decode(SCHEMA_SCAN_COUNT_ATTEST_BODY, SCHEMA_VERSION_1, bytes);
    assert_eq!(decoded, Ok(body));
}

/// A `BoxCloseBody` with a symbolic paper count and open-batch count,
/// decoded from a literal object (one-byte identifiers, one module
/// counter): both fields come back as sent, every other field keeps its
/// literal value, and re-encoding reproduces the exact length and the
/// symbolic bytes. The literal was produced by this crate's encoder from
/// the fixture in the harness comments.
///
/// Why a literal rather than encode-then-decode: CBMC stops propagating
/// constants through a buffer once any byte of it is symbolic, so every
/// length-driven loop unrolls to the harness bound; a small literal with
/// one-byte identifiers keeps every such loop short.
#[kani::proof]
#[kani::unwind(12)]
fn box_close_body_round_trip() {
    let paper_count: u64 = kani::any();
    let open_batches: u8 = kani::any();
    let paper = paper_count.to_be_bytes();
    // election_id "E", box_id "B", counts (paper, 990, 990, 10, 3, 1),
    // digests 0x60/0x61/0x62 patterns, module_counters [("M", 994)],
    // open_batches, time_bucket 900.
    let buf: [u8; 292] = [
        0x49,
        0x54,
        0x59,
        0x56,
        0x00,
        0x00,
        0x00,
        0x07,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x14,
        0x00,
        0x00,
        0x00,
        0x01,
        0x45,
        0x00,
        0x00,
        0x00,
        0x01,
        0x42,
        paper[0],
        paper[1],
        paper[2],
        paper[3],
        paper[4],
        paper[5],
        paper[6],
        paper[7],
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x03,
        0xde,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x03,
        0xde,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x0a,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x03,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0x60,
        0x61,
        0x62,
        0x63,
        0x64,
        0x65,
        0x66,
        0x67,
        0x68,
        0x69,
        0x6a,
        0x6b,
        0x6c,
        0x6d,
        0x6e,
        0x6f,
        0x70,
        0x71,
        0x72,
        0x73,
        0x74,
        0x75,
        0x76,
        0x77,
        0x78,
        0x79,
        0x7a,
        0x7b,
        0x7c,
        0x7d,
        0x7e,
        0x7f,
        0x80,
        0x81,
        0x82,
        0x83,
        0x84,
        0x85,
        0x86,
        0x87,
        0x88,
        0x89,
        0x8a,
        0x8b,
        0x8c,
        0x8d,
        0x8e,
        0x8f,
        0x90,
        0x91,
        0x92,
        0x93,
        0x94,
        0x95,
        0x96,
        0x97,
        0x98,
        0x99,
        0x9a,
        0x9b,
        0x9c,
        0x9d,
        0x9e,
        0x9f,
        0x61,
        0x62,
        0x63,
        0x64,
        0x65,
        0x66,
        0x67,
        0x68,
        0x69,
        0x6a,
        0x6b,
        0x6c,
        0x6d,
        0x6e,
        0x6f,
        0x70,
        0x71,
        0x72,
        0x73,
        0x74,
        0x75,
        0x76,
        0x77,
        0x78,
        0x79,
        0x7a,
        0x7b,
        0x7c,
        0x7d,
        0x7e,
        0x7f,
        0x80,
        0x81,
        0x82,
        0x83,
        0x84,
        0x85,
        0x86,
        0x87,
        0x88,
        0x89,
        0x8a,
        0x8b,
        0x8c,
        0x8d,
        0x8e,
        0x8f,
        0x90,
        0x91,
        0x92,
        0x93,
        0x94,
        0x95,
        0x96,
        0x97,
        0x98,
        0x99,
        0x9a,
        0x9b,
        0x9c,
        0x9d,
        0x9e,
        0x9f,
        0xa0,
        0x62,
        0x63,
        0x64,
        0x65,
        0x66,
        0x67,
        0x68,
        0x69,
        0x6a,
        0x6b,
        0x6c,
        0x6d,
        0x6e,
        0x6f,
        0x70,
        0x71,
        0x72,
        0x73,
        0x74,
        0x75,
        0x76,
        0x77,
        0x78,
        0x79,
        0x7a,
        0x7b,
        0x7c,
        0x7d,
        0x7e,
        0x7f,
        0x80,
        0x81,
        0x82,
        0x83,
        0x84,
        0x85,
        0x86,
        0x87,
        0x88,
        0x89,
        0x8a,
        0x8b,
        0x8c,
        0x8d,
        0x8e,
        0x8f,
        0x90,
        0x91,
        0x92,
        0x93,
        0x94,
        0x95,
        0x96,
        0x97,
        0x98,
        0x99,
        0x9a,
        0x9b,
        0x9c,
        0x9d,
        0x9e,
        0x9f,
        0xa0,
        0xa1,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x01,
        0x4d,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x03,
        0xe2,
        open_batches,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x03,
        0x84,
    ];
    let decoded: Result<BoxCloseBody<'_>, _> =
        decode(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, &buf);
    let Ok(body) = decoded else {
        unreachable!("no rule constrains the paper count or the open-batch count");
    };
    assert_eq!(body.counts().paper, paper_count);
    assert_eq!(body.counts().records, 990);
    assert_eq!(body.counts().quarantined, 1);
    assert_eq!(body.open_batches(), open_batches);
    assert_eq!(body.time_bucket().get(), 900);
    assert_eq!(body.module_counters().len(), 1);
    let Some(counter) = body.module_counters().iter().next() else {
        unreachable!("one module counter was encoded");
    };
    assert_eq!(counter.counter, 994);
    let mut out = [0u8; 292];
    let Ok(len) = encode(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, &body, &mut out) else {
        unreachable!("the buffer is exactly sized");
    };
    assert_eq!(len, out.len());
    let Some(paper_out) = out.get(26..34) else {
        unreachable!("in range");
    };
    assert_eq!(paper_out, &paper);
    assert_eq!(out.get(283).copied(), Some(open_batches));
}

/// The proof header check of a cast record body, stated against PROTOCOL
/// §7.5 written out independently of the implementation: for any header
/// bytes and any claimed proof length, the header parses exactly when
/// `2 <= option_count <= 64`, `chunk_count` is the integer
/// `(option_count + 8) / 9`, and the length is
/// `3 + 32·option_count·chunk_count + 64·option_count` (one 32-byte
/// scalar per option per chunk, plus two per option). Hence a chunk count
/// that differs from the commitment count can never pass the body's
/// cross-field check.
#[kani::proof]
#[kani::unwind(4)]
fn proof_header_is_exact() {
    let head: [u8; 3] = kani::any();
    let len: usize = kani::any();
    let option_count = u16::from_be_bytes([head[0], head[1]]);
    let chunk_count = head[2];
    // Model the proof as its header plus an opaque tail of `len - 3` bytes;
    // the parser reads only the header and the total length.
    let parsed = ProofHeader::parse_with_len(head, len);
    let oc = usize::from(option_count);
    let cc = usize::from(chunk_count);
    let expected =
        (2..=64).contains(&option_count) && cc == (oc + 8) / 9 && len == 3 + 32 * oc * cc + 64 * oc;
    assert_eq!(parsed.is_some(), expected);
    if let Some(h) = parsed {
        assert_eq!(h.option_count, option_count);
        assert_eq!(h.chunk_count, chunk_count);
    }
}

// ---------------------------------------------------------------------------
// Finite-domain cross-field checks (ENCODING.md §8.6, §8.10, §8.12, §8.17)
// ---------------------------------------------------------------------------

/// `transport_flags` admits exactly the values whose bits above bit 1 are
/// clear (bit 0 KEM fallback, bit 1 neutral module).
#[kani::proof]
fn transport_flags_mask_is_exact() {
    let flags: u8 = kani::any();
    assert_eq!(transport_flags_valid(flags), flags >> 2 == 0);
}

/// Chamber codes: exactly 1 X, 2 Y, 3 J, 4 A, 5 C, 6 N decode, each to
/// the chamber whose code it is; every other byte is rejected.
#[kani::proof]
fn chamber_codes_are_exact() {
    let code: u8 = kani::any();
    let expected = match code {
        1 => Some(ChamberCode::X),
        2 => Some(ChamberCode::Y),
        3 => Some(ChamberCode::J),
        4 => Some(ChamberCode::A),
        5 => Some(ChamberCode::C),
        6 => Some(ChamberCode::N),
        _ => None,
    };
    assert_eq!(ChamberCode::from_code(code), expected);
    if let Some(chamber) = expected {
        assert_eq!(chamber.code(), code);
    }
}

/// Signer roles: exactly 1 (clerk) and 2 (observer) decode, each to the
/// role whose code it is; every other byte is rejected.
#[kani::proof]
fn signer_role_codes_are_exact() {
    let code: u8 = kani::any();
    let expected = match code {
        1 => Some(SignerRole::Clerk),
        2 => Some(SignerRole::Observer),
        _ => None,
    };
    assert_eq!(SignerRole::from_code(code), expected);
    if let Some(role) = expected {
        assert_eq!(role.code(), code);
    }
}

/// Transport codes and KEM pad fields: transport 0 admits any pad fields,
/// transport 1 only zero pad fields, and every other code is rejected.
#[kani::proof]
fn transport_and_pad_fields_are_exact() {
    let code: u8 = kani::any();
    let pad_id: u32 = kani::any();
    let pad_index: u64 = kani::any();
    assert_eq!(transport_code_valid(code), code == 0 || code == 1);
    let expected = match code {
        0 => true,
        1 => pad_id == 0 && pad_index == 0,
        _ => false,
    };
    assert_eq!(
        transport_code_valid(code) && pad_fields_valid(code, pad_id, pad_index),
        expected
    );
}

/// `record_count` admits exactly `1..=64`.
#[kani::proof]
fn record_count_range_is_exact() {
    let record_count: u16 = kani::any();
    assert_eq!(
        record_count_valid(record_count),
        record_count != 0 && record_count < 65
    );
}

/// Through the real decoder: a one-entry share package literal whose
/// chamber, transport and pad fields are symbolic decodes exactly when the
/// chamber code is `1..=6` and the transport is pad (any pad fields) or KEM
/// (zero pad fields); a decoded package reports those fields and re-encodes
/// them byte for byte, and a rejected one names the first offending field
/// in reading order (ENCODING §8.20).
#[kani::proof]
#[kani::unwind(16)]
fn share_entry_codes_through_decoder() {
    let chamber: u8 = kani::any();
    let transport: u8 = kani::any();
    let pad_id: u32 = kani::any();
    let pad_index: u64 = kani::any();
    let id_bytes = pad_id.to_be_bytes();
    let index_bytes = pad_index.to_be_bytes();
    // election_id "E", box_id "B", one commitment (0x09 bytes), one entry:
    // trustee_id "T", chamber, transport, pad_id, pad_index, ciphertext
    // 4 × 0x11, tag 16 × 0x22.
    let buf: [u8; 109] = [
        0x49,
        0x54,
        0x59,
        0x56,
        0x00,
        0x00,
        0x00,
        0x0b,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x5d,
        0x00,
        0x00,
        0x00,
        0x01,
        0x45,
        0x00,
        0x00,
        0x00,
        0x01,
        0x42,
        0x00,
        0x00,
        0x00,
        0x01,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x09,
        0x00,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x01,
        0x54,
        chamber,
        transport,
        id_bytes[0],
        id_bytes[1],
        id_bytes[2],
        id_bytes[3],
        index_bytes[0],
        index_bytes[1],
        index_bytes[2],
        index_bytes[3],
        index_bytes[4],
        index_bytes[5],
        index_bytes[6],
        index_bytes[7],
        0x00,
        0x00,
        0x00,
        0x04,
        0x11,
        0x11,
        0x11,
        0x11,
        0x22,
        0x22,
        0x22,
        0x22,
        0x22,
        0x22,
        0x22,
        0x22,
        0x22,
        0x22,
        0x22,
        0x22,
        0x22,
        0x22,
        0x22,
        0x22,
    ];
    let chamber_at = 71;
    let decoded: Result<SharePackage<'_>, _> = decode(SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1, &buf);
    let chamber_ok = (1..=6).contains(&chamber);
    let transport_ok = transport == 0 || (transport == 1 && pad_id == 0 && pad_index == 0);
    match decoded {
        Ok(package) => {
            assert!(chamber_ok && transport_ok);
            let Some(entry) = package.entries().next() else {
                unreachable!("one entry was encoded");
            };
            assert_eq!(entry.chamber.code(), chamber);
            let expected = if transport == 0 {
                Transport::Pad { pad_id, pad_index }
            } else {
                Transport::Kem
            };
            assert_eq!(entry.transport, expected);
            let mut out = [0u8; 109];
            let Ok(len) = encode(SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1, &package, &mut out) else {
                unreachable!("the buffer is exactly sized");
            };
            assert_eq!(len, out.len());
            let (Some(fields_out), Some(fields_in)) = (out.get(71..85), buf.get(71..85)) else {
                unreachable!("in range");
            };
            assert_eq!(fields_out, fields_in);
        }
        Err(e) => {
            assert!(!(chamber_ok && transport_ok));
            assert_eq!(e.kind(), Kind::ValueOutOfRange);
            let expected_at = if !chamber_ok {
                chamber_at
            } else if transport > 1 {
                chamber_at + 1
            } else if pad_id != 0 {
                chamber_at + 2
            } else {
                chamber_at + 6
            };
            assert_eq!(e.offset(), expected_at);
        }
    }
}

/// A `MemberShare` literal without an envelope label whose module flag,
/// first `cid` byte and last `tag` byte are symbolic: it decodes exactly
/// when the flag is a strict boolean and, without a module, `cid` and `tag`
/// are zero (§8.11); the decoded fields equal the inputs and re-encode byte
/// for byte; a rejected object names the first offending field in reading
/// order (ENCODING §8.20).
#[kani::proof]
#[kani::unwind(12)]
fn member_share_round_trip() {
    let flag: u8 = kani::any();
    let cid_byte: u8 = kani::any();
    let tag_byte: u8 = kani::any();
    // one share (last byte 0x33), has_module, cid (first byte symbolic,
    // rest zero), lab absent, tag (last byte symbolic, rest zero).
    let buf: [u8; 94] = [
        0x49, 0x54, 0x59, 0x56, 0x00, 0x00, 0x00, 0x15, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x4e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, flag, cid_byte, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, tag_byte,
    ];
    let decoded: Result<MemberShare<'_>, _> = decode(SCHEMA_MEMBER_SHARE, SCHEMA_VERSION_1, &buf);
    match decoded {
        Ok(share) => {
            assert!(flag == 1 || (flag == 0 && cid_byte == 0 && tag_byte == 0));
            assert_eq!(share.has_module(), flag == 1);
            assert_eq!(share.shares().count(), 1);
            assert_eq!(share.cid().0.first().copied(), Some(cid_byte));
            assert!(share.lab().is_none());
            assert_eq!(share.tag().last().copied(), Some(tag_byte));
            let mut out = [0u8; 94];
            let Ok(len) = encode(SCHEMA_MEMBER_SHARE, SCHEMA_VERSION_1, &share, &mut out) else {
                unreachable!("the buffer is exactly sized");
            };
            assert_eq!(len, out.len());
            assert_eq!(out.get(52).copied(), Some(flag));
            assert_eq!(out.get(53).copied(), Some(cid_byte));
            assert_eq!(out.get(93).copied(), Some(tag_byte));
        }
        Err(e) => {
            let (kind, at) = if flag > 1 {
                (Kind::InvalidBool, 52)
            } else if cid_byte != 0 {
                (Kind::InvariantViolation, 53)
            } else {
                assert!(flag == 0 && tag_byte != 0);
                (Kind::InvariantViolation, 78)
            };
            assert_eq!(e.kind(), kind);
            assert_eq!(e.offset(), at);
        }
    }
}

/// The same for a literal with an envelope label present: without a module
/// a present label is rejected at the label's offset once `cid` has passed,
/// and with a module every field round-trips.
#[kani::proof]
#[kani::unwind(12)]
fn member_share_round_trip_with_label() {
    let flag: u8 = kani::any();
    let cid_byte: u8 = kani::any();
    let tag_byte: u8 = kani::any();
    // one share (last byte 0x33), has_module, cid (first byte symbolic,
    // rest 0x55), lab present (0x66 bytes), tag (last byte symbolic, rest
    // 0x44).
    let buf: [u8; 118] = [
        0x49, 0x54, 0x59, 0x56, 0x00, 0x00, 0x00, 0x15, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x66, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, flag, cid_byte, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x01, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x44, 0x44,
        0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, tag_byte,
    ];
    let decoded: Result<MemberShare<'_>, _> = decode(SCHEMA_MEMBER_SHARE, SCHEMA_VERSION_1, &buf);
    match decoded {
        Ok(share) => {
            assert_eq!(flag, 1);
            assert!(share.has_module());
            assert!(share.lab().is_some());
            assert_eq!(share.cid().0.first().copied(), Some(cid_byte));
            assert_eq!(share.tag().last().copied(), Some(tag_byte));
            let mut out = [0u8; 118];
            let Ok(len) = encode(SCHEMA_MEMBER_SHARE, SCHEMA_VERSION_1, &share, &mut out) else {
                unreachable!("the buffer is exactly sized");
            };
            assert_eq!(len, out.len());
            assert_eq!(out.get(52).copied(), Some(flag));
            assert_eq!(out.get(53).copied(), Some(cid_byte));
            assert_eq!(out.get(117).copied(), Some(tag_byte));
        }
        Err(e) => {
            let (kind, at) = if flag > 1 {
                (Kind::InvalidBool, 52)
            } else if cid_byte != 0 {
                (Kind::InvariantViolation, 53)
            } else {
                assert_eq!(flag, 0);
                (Kind::InvariantViolation, 77)
            };
            assert_eq!(e.kind(), kind);
            assert_eq!(e.offset(), at);
        }
    }
}

/// A `BatchAttestBody` literal whose record count and first module range
/// are symbolic: it decodes exactly when `record_count ∈ 1..=64` and
/// `counter_first <= counter_last`; the decoded fields equal the inputs and
/// re-encode byte for byte; a rejected object names the record count
/// (checked as soon as it is read) or else the range's `counter_last`
/// (ENCODING §8.12, §8.20).
#[kani::proof]
#[kani::unwind(20)]
fn batch_attest_body_round_trip() {
    let record_count: u16 = kani::any();
    let counter_first: u64 = kani::any();
    let counter_last: u64 = kani::any();
    let rc = record_count.to_be_bytes();
    let first = counter_first.to_be_bytes();
    let last = counter_last.to_be_bytes();
    // election_id "E", box_id "B", batch_index 3, record_count, records_root
    // 0x10 pattern, ranges [("X", first, last), ("Y", 200, 263)], refusals
    // ["Y"], journal_head 0x20 pattern, time_bucket 500.
    let buf: [u8; 223] = [
        0x49, 0x54, 0x59, 0x56, 0x00, 0x00, 0x00, 0x12, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xcf, 0x00, 0x00, 0x00, 0x01, 0x45, 0x00, 0x00, 0x00, 0x01, 0x42, 0x00, 0x00, 0x00, 0x03,
        rc[0], rc[1], 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
        0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a,
        0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
        0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x58,
        0x00, 0x00, first[0], first[1], first[2], first[3], first[4], first[5], first[6], first[7],
        last[0], last[1], last[2], last[3], last[4], last[5], last[6], last[7], 0x00, 0x01, 0x59,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x59, 0x20, 0x21, 0x22, 0x23, 0x24,
        0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42,
        0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51,
        0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xf4,
    ];
    let decoded: Result<BatchAttestBody<'_>, _> =
        decode(SCHEMA_BATCH_ATTEST_BODY, SCHEMA_VERSION_1, &buf);
    let count_ok = record_count_valid(record_count);
    let range_ok = counter_first <= counter_last;
    match decoded {
        Ok(body) => {
            assert!(count_ok && range_ok);
            assert_eq!(body.record_count(), record_count);
            assert_eq!(body.batch_index(), 3);
            assert_eq!(body.time_bucket().get(), 500);
            assert_eq!(body.module_refusals().len(), 1);
            let Some(range) = body.module_ranges().next() else {
                unreachable!("two ranges were encoded");
            };
            assert_eq!(range.counter_first, counter_first);
            assert_eq!(range.counter_last, counter_last);
            assert_eq!(body.expected_signers().count(), 1);
            let mut out = [0u8; 223];
            let Ok(len) = encode(SCHEMA_BATCH_ATTEST_BODY, SCHEMA_VERSION_1, &body, &mut out)
            else {
                unreachable!("the buffer is exactly sized");
            };
            assert_eq!(len, out.len());
            let (Some(count_out), Some(range_out), Some(range_in)) =
                (out.get(30..32), out.get(107..123), buf.get(107..123))
            else {
                unreachable!("in range");
            };
            assert_eq!(count_out, &rc);
            assert_eq!(range_out, range_in);
        }
        Err(e) => {
            assert!(!(count_ok && range_ok));
            assert_eq!(e.kind(), Kind::ValueOutOfRange);
            assert_eq!(e.offset(), if count_ok { 115 } else { 30 });
        }
    }
}
