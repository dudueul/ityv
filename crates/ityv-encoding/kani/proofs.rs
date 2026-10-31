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
use crate::schema::box_close::{BoxCloseBody, BoxCloseParts, CloseCounts};
use crate::schema::cast_record::ProofHeader;
use crate::schema::scan_count::ScanCountAttestBody;
use crate::schema::slip::SlipBody;
use crate::schema::util::{ModuleCounter, ModuleCounters};
use crate::schema::{SCHEMA_BOX_CLOSE_BODY, SCHEMA_SCAN_COUNT_ATTEST_BODY, SCHEMA_SLIP_BODY};

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

/// A `BoxCloseBody` with symbolic paper and quarantine counts, open-batch
/// count and module counter survives an object-level round trip. The other
/// counts, the digests and the bucket are concrete to keep the model within
/// the CI budget; every field goes through the same fixed-width codec.
#[kani::proof]
#[kani::unwind(70)]
fn box_close_body_round_trip() {
    let counts = CloseCounts {
        paper: kani::any(),
        records: 990,
        attested: 990,
        without_record: 10,
        challenged: 3,
        quarantined: kani::any(),
    };
    let open_batches: u8 = kani::any();
    let bucket: u64 = 900;
    let counter: u64 = kani::any();
    let Some(election_id) = ElectionId::new(b"E") else {
        unreachable!("literal identifier is valid");
    };
    let Some(box_id) = BoxId::new(b"B") else {
        unreachable!("literal identifier is valid");
    };
    let Some(module_id) = crate::primitives::ModuleId::new(b"M") else {
        unreachable!("literal identifier is valid");
    };
    let Some(module_counters) = ModuleCounters::new(&[ModuleCounter { module_id, counter }]) else {
        unreachable!("one entry is trivially sorted");
    };
    let body = BoxCloseBody::new(&BoxCloseParts {
        election_id,
        box_id,
        counts,
        record_set_root: Hash512([1; 64]),
        journal_head: Hash512([2; 64]),
        seal_digest: Hash512([3; 64]),
        module_counters,
        open_batches,
        time_bucket: TimeBucket::new(bucket),
    });
    let mut buf = [0u8; 320];
    let Ok(len) = encode(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, &body, &mut buf) else {
        unreachable!("320 bytes suffice for one-byte identifiers");
    };
    assert_eq!(len, 16 + 5 + 5 + 48 + 192 + 4 + 5 + 8 + 1 + 8);
    let (bytes, _) = buf.split_at_checked(len).unwrap_or((&[], &buf));
    let decoded: Result<BoxCloseBody<'_>, _> =
        decode(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, bytes);
    assert_eq!(decoded, Ok(body));
}

/// The proof header check of a cast record body: for any header bytes, the
/// header parses exactly when the option count is in `1..=64`, the chunk
/// count is `⌈option_count/9⌉`, and the length matches the §7.5 formula;
/// hence a chunk count that differs from the commitment count can never
/// pass the body's cross-field check.
#[kani::proof]
#[kani::unwind(4)]
fn proof_header_is_exact() {
    let head: [u8; 3] = kani::any();
    let option_count = u16::from_be_bytes([head[0], head[1]]);
    let chunk_count = head[2];
    // Claimed length: the formula for the header's own fields, or one off.
    let claimed_ok: bool = kani::any();
    let formula = 3 + usize::from(option_count) * (usize::from(chunk_count) + 2) * 32;
    let len = if claimed_ok { formula } else { formula + 1 };
    // Model the proof as its header plus an opaque tail of `len - 3` bytes;
    // the parser reads only the header and the total length.
    let parsed = ProofHeader::parse_with_len(head, len);
    let expected = option_count >= 1
        && option_count <= 64
        && u16::from(chunk_count) == option_count.div_ceil(9)
        && claimed_ok;
    assert_eq!(parsed.is_some(), expected);
    if let Some(h) = parsed {
        assert_eq!(h.option_count, option_count);
        assert_eq!(h.chunk_count, chunk_count);
    }
}
