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

use crate::primitives::{
    BoxId, ModuleId, Point32, Scalar32, StationId, TimeBucket, Token192, TrusteeId,
};
use crate::schema::batch_attest::{
    BatchAttestBody, BatchAttestParts, ModuleRange, record_count_valid,
};
use crate::schema::box_close::{BoxCloseBody, BoxCloseParts, CloseCounts, SignerRole};
use crate::schema::cast_record::{ProofHeader, transport_flags_valid};
use crate::schema::scan_count::ScanCountAttestBody;
use crate::schema::share_package::{
    ChamberCode, MAX_SECRETS, MemberShare, ShareEntry, SharePackage, Transport, pad_fields_valid,
    transport_code_valid,
};
use crate::schema::slip::SlipBody;
use crate::schema::util::{Commitments, ModuleCounter, ModuleCounters, ModuleIds, Scalars};
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

/// A `BoxCloseBody` with a symbolic paper count and open-batch count
/// survives an object-level round trip. The other counts, the digests, the
/// module counter and the bucket are concrete to keep the model within the
/// CI budget; every field goes through the same fixed-width codec.
#[kani::proof]
#[kani::unwind(70)]
fn box_close_body_round_trip() {
    let counts = CloseCounts {
        paper: kani::any(),
        records: 990,
        attested: 990,
        without_record: 10,
        challenged: 3,
        quarantined: 1,
    };
    let open_batches: u8 = kani::any();
    let bucket: u64 = 900;
    let counter: u64 = 994;
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

/// Through the real decoder: a one-entry share package whose chamber,
/// transport and pad fields are symbolic decodes exactly when the chamber
/// code is `1..=6` and the transport is pad (any pad fields) or KEM (zero
/// pad fields); a decoded package reports those fields, and a rejected one
/// names the first offending field in reading order (ENCODING §8.20).
#[kani::proof]
#[kani::unwind(70)]
fn share_entry_codes_through_decoder() {
    let Some(election_id) = ElectionId::new(b"E") else {
        unreachable!("literal identifier is valid");
    };
    let Some(box_id) = BoxId::new(b"B") else {
        unreachable!("literal identifier is valid");
    };
    let Some(trustee_id) = TrusteeId::new(b"T") else {
        unreachable!("literal identifier is valid");
    };
    let Some(commitments) = Commitments::new(&[Point32([9; 32])]) else {
        unreachable!("one commitment is within 1..=8");
    };
    let ciphertext = [0x11u8; 4];
    let tag = [0x22u8; 16];
    let entry = ShareEntry {
        trustee_id,
        chamber: ChamberCode::X,
        transport: Transport::Pad {
            pad_id: 0,
            pad_index: 0,
        },
        ciphertext: &ciphertext,
        tag: &tag,
    };
    let Some(package) = SharePackage::new(election_id, box_id, &commitments, &[entry]) else {
        unreachable!("one entry is trivially sorted and within bounds");
    };
    let mut buf = [0u8; 160];
    let Ok(len) = encode(SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1, &package, &mut buf) else {
        unreachable!("160 bytes suffice for one-byte identifiers");
    };
    // header 16, E 5, B 5, commitments 4+32, count 4, trustee 5, then the
    // entry's chamber, transport, pad_id, pad_index, ciphertext 4+4, tag 16.
    let chamber_at = 16 + 5 + 5 + 36 + 4 + 5;
    assert_eq!(len, chamber_at + 1 + 1 + 4 + 8 + 8 + 16);
    let chamber: u8 = kani::any();
    let transport: u8 = kani::any();
    let pad_id: u32 = kani::any();
    let pad_index: u64 = kani::any();
    buf[chamber_at] = chamber;
    buf[chamber_at + 1] = transport;
    buf[chamber_at + 2..chamber_at + 6].copy_from_slice(&pad_id.to_be_bytes());
    buf[chamber_at + 6..chamber_at + 14].copy_from_slice(&pad_index.to_be_bytes());
    let (bytes, _) = buf.split_at_checked(len).unwrap_or((&[], &buf));
    let decoded: Result<SharePackage<'_>, _> =
        decode(SCHEMA_SHARE_PACKAGE, SCHEMA_VERSION_1, bytes);
    let chamber_ok = (1..=6).contains(&chamber);
    let transport_ok = transport == 0 || (transport == 1 && pad_id == 0 && pad_index == 0);
    match decoded {
        Ok(p) => {
            assert!(chamber_ok && transport_ok);
            let Some(got) = p.entries().next() else {
                unreachable!("one entry was encoded");
            };
            assert_eq!(got.chamber.code(), chamber);
            let expected = if transport == 0 {
                Transport::Pad { pad_id, pad_index }
            } else {
                Transport::Kem
            };
            assert_eq!(got.transport, expected);
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

/// A `MemberShare` with a symbolic module flag and symbolic bytes in the
/// share, `cid`, `lab` and `tag`: the constructor accepts exactly the §8.11
/// combinations (any value with a module; zero `cid`, absent `lab` and zero
/// `tag` without one), and every accepted value survives a round trip.
#[kani::proof]
#[kani::unwind(70)]
fn member_share_round_trip() {
    let has_module: bool = kani::any();
    let share_byte: u8 = kani::any();
    let cid_byte: u8 = kani::any();
    let lab_present: bool = kani::any();
    let tag_byte: u8 = kani::any();
    let mut share = [0u8; 32];
    share[31] = share_byte;
    let Some(shares) = Scalars::<MAX_SECRETS>::new(&[Scalar32(share)]) else {
        unreachable!("one share is within 1..=50");
    };
    let mut cid = [0u8; 24];
    cid[0] = cid_byte;
    let lab = if lab_present {
        Some(Token192([5; 24]))
    } else {
        None
    };
    let mut tag = [0u8; 16];
    tag[15] = tag_byte;
    let built = MemberShare::new(&shares, has_module, Token192(cid), lab, &tag);
    let expected_ok = has_module || (cid_byte == 0 && !lab_present && tag_byte == 0);
    assert_eq!(built.is_some(), expected_ok);
    let Some(value) = built else {
        return;
    };
    let mut buf = [0u8; 128];
    let Ok(len) = encode(SCHEMA_MEMBER_SHARE, SCHEMA_VERSION_1, &value, &mut buf) else {
        unreachable!("128 bytes suffice for one share");
    };
    let lab_len = if lab_present { 24 } else { 0 };
    assert_eq!(len, 16 + 4 + 32 + 1 + 24 + 1 + lab_len + 16);
    let (bytes, _) = buf.split_at_checked(len).unwrap_or((&[], &buf));
    let decoded: Result<MemberShare<'_>, _> = decode(SCHEMA_MEMBER_SHARE, SCHEMA_VERSION_1, bytes);
    assert_eq!(decoded, Ok(value));
}

/// Builds a one-range `BatchAttestBody`; `None` exactly when the parts
/// break a §8.12 rule.
fn batch_body<'a>(
    record_count: u16,
    ranges: &'a [ModuleRange<'a>],
) -> Option<BatchAttestBody<'a>> {
    let election_id = ElectionId::new(b"E")?;
    let box_id = BoxId::new(b"B")?;
    let refusals = ModuleIds::new(&[])?;
    BatchAttestBody::new(&BatchAttestParts {
        election_id,
        box_id,
        batch_index: 3,
        record_count,
        records_root: Hash512([1; 64]),
        module_ranges: ranges,
        module_refusals: refusals,
        journal_head: Hash512([2; 64]),
        time_bucket: TimeBucket::new(5),
    })
}

/// Encodes a one-range body and checks that it decodes to itself.
fn batch_round_trip(body: &BatchAttestBody<'_>) {
    let mut buf = [0u8; 256];
    let Ok(len) = encode(SCHEMA_BATCH_ATTEST_BODY, SCHEMA_VERSION_1, body, &mut buf) else {
        unreachable!("256 bytes suffice for one-byte identifiers");
    };
    assert_eq!(len, 16 + 5 + 5 + 4 + 2 + 64 + 4 + (5 + 16) + 4 + 64 + 8);
    let (bytes, _) = buf.split_at_checked(len).unwrap_or((&[], &buf));
    let decoded: Result<BatchAttestBody<'_>, _> =
        decode(SCHEMA_BATCH_ATTEST_BODY, SCHEMA_VERSION_1, bytes);
    assert_eq!(decoded.as_ref(), Ok(body));
}

/// A `BatchAttestBody` with a symbolic record count: the constructor
/// accepts exactly `record_count ∈ 1..=64`, and every accepted value
/// survives an object-level round trip.
#[kani::proof]
#[kani::unwind(70)]
fn batch_attest_body_round_trip() {
    let record_count: u16 = kani::any();
    let Some(module_id) = ModuleId::new(b"M") else {
        unreachable!("literal identifier is valid");
    };
    let ranges = [ModuleRange {
        module_id,
        counter_first: 1,
        counter_last: 64,
    }];
    let built = batch_body(record_count, &ranges);
    assert_eq!(built.is_some(), (1..=64).contains(&record_count));
    if let Some(body) = built {
        batch_round_trip(&body);
    }
}

/// A `BatchAttestBody` with a small symbolic counter range: the constructor
/// accepts exactly `counter_first <= counter_last`, and every accepted
/// value survives an object-level round trip.
#[kani::proof]
#[kani::unwind(70)]
fn batch_attest_body_counter_range() {
    let counter_first = u64::from(kani::any::<u8>());
    let counter_last = u64::from(kani::any::<u8>());
    let Some(module_id) = ModuleId::new(b"M") else {
        unreachable!("literal identifier is valid");
    };
    let ranges = [ModuleRange {
        module_id,
        counter_first,
        counter_last,
    }];
    let built = batch_body(64, &ranges);
    assert_eq!(built.is_some(), counter_first <= counter_last);
    if let Some(body) = built {
        batch_round_trip(&body);
    }
}
