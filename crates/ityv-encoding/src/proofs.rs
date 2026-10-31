//! Kani bounded model-checking harnesses (verification ladder V2).
//!
//! Compiled only under `cargo kani`. Each harness states one property from
//! ENCODING.md. Kani additionally checks every harness for panics, overflow
//! and out-of-bounds access on all explored inputs, which is the mechanical
//! form of the crate's "no panics" promise.
//!
//! Run with `cargo kani -p ityv-encoding` from the workspace root.

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
