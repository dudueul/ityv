//! Header and object-level tests for ENCODING.md §3 and §5.
// Integration-test crate: outside the TCB. Test code expresses "this must
// hold" with unwrap/expect/panic/indexing and does small arithmetic on test
// sizes, so those restriction lints are relaxed for this file only. No TCB
// crate may do this (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
)]

mod common;

use common::encode_to_vec;
use ityv_encoding::{
    ElectionId, Encode as _, ErrorKind, HEADER_LEN, Hash512, LedgerFrame, MAGIC, ObjectHeader,
    Reader, SCHEMA_LEDGER_FRAME, SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, SchemaId, Seq,
    Writer, decode_object, encode_object,
};

fn sample_frame() -> LedgerFrame<'static> {
    LedgerFrame::new(
        ElectionId::new(b"KR-2030-PRES").unwrap(),
        Seq::new(1).unwrap(),
        Hash512::ZERO,
        SchemaId::new(0x0005),
        Hash512([0xaa; 64]),
    )
}

fn decode_frame(bytes: &[u8]) -> Result<LedgerFrame<'_>, ityv_encoding::Error> {
    decode_object(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, bytes)
}

#[test]
fn header_layout_is_sixteen_bytes() {
    let bytes = encode_to_vec(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &sample_frame());
    assert_eq!(&bytes[..4], &MAGIC);
    assert_eq!(&bytes[4..8], &[0, 0, 0, 1]);
    assert_eq!(&bytes[8..10], &[0, 1]);
    assert_eq!(&bytes[10..12], &[0, 0]);
    let body_len = u32::from_be_bytes(bytes[12..16].try_into().unwrap());
    assert_eq!(usize::try_from(body_len).unwrap(), bytes.len() - HEADER_LEN);
    assert_eq!(bytes.len(), HEADER_LEN + sample_frame().encoded_len());
    let mut r = Reader::new(&bytes);
    let header = ObjectHeader::read(&mut r).unwrap();
    assert_eq!(header.schema_id(), SCHEMA_LEDGER_FRAME);
    assert_eq!(header.schema_version(), 1);
    assert_eq!(header.body_len(), body_len);
    assert_eq!(r.position(), HEADER_LEN);
}

#[test]
fn object_round_trips() {
    let frame = sample_frame();
    let bytes = encode_to_vec(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &frame);
    assert_eq!(decode_frame(&bytes).unwrap(), frame);
    let again = encode_to_vec(
        SCHEMA_LEDGER_FRAME,
        SCHEMA_VERSION_1,
        &decode_frame(&bytes).unwrap(),
    );
    assert_eq!(again, bytes);
}

#[test]
fn bad_magic_is_rejected_at_zero() {
    let mut bytes = encode_to_vec(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &sample_frame());
    bytes[0] = b'X';
    let e = decode_frame(&bytes).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (ErrorKind::BadMagic, 0));
}

#[test]
fn schema_mismatch_is_rejected_at_four() {
    let bytes = encode_to_vec(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &sample_frame());
    let e: ityv_encoding::Error =
        decode_object::<LedgerFrame<'_>>(SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, &bytes)
            .unwrap_err();
    assert_eq!((e.kind(), e.offset()), (ErrorKind::SchemaMismatch, 4));
}

#[test]
fn unsupported_version_is_rejected_at_eight() {
    let bytes = encode_to_vec(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &sample_frame());
    let e: ityv_encoding::Error =
        decode_object::<LedgerFrame<'_>>(SCHEMA_LEDGER_FRAME, 2, &bytes).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (ErrorKind::UnsupportedVersion, 8));
}

#[test]
fn non_zero_flags_are_rejected_at_ten() {
    let mut bytes = encode_to_vec(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &sample_frame());
    bytes[11] = 1;
    let e = decode_frame(&bytes).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (ErrorKind::NonZeroFlags, 10));
}

#[test]
fn body_length_must_match_exactly() {
    let good = encode_to_vec(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &sample_frame());

    let mut longer = good.clone();
    longer.push(0);
    let e = decode_frame(&longer).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (ErrorKind::BodyLengthMismatch, 12));

    let mut shorter = good.clone();
    shorter.pop();
    let e = decode_frame(&shorter).unwrap_err();
    assert_eq!((e.kind(), e.offset()), (ErrorKind::BodyLengthMismatch, 12));

    let mut lying = good.clone();
    lying.push(0);
    let declared = u32::from_be_bytes(lying[12..16].try_into().unwrap()) + 1;
    lying[12..16].copy_from_slice(&declared.to_be_bytes());
    let e = decode_frame(&lying).unwrap_err();
    assert_eq!(
        (e.kind(), e.offset()),
        (ErrorKind::TrailingBytes, good.len())
    );
}

#[test]
fn every_proper_prefix_is_rejected() {
    let bytes = encode_to_vec(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &sample_frame());
    for k in 0..bytes.len() {
        assert!(
            decode_frame(&bytes[..k]).is_err(),
            "prefix of length {k} decoded"
        );
    }
}

#[test]
fn encode_reports_small_buffers_without_writing_past_them() {
    let frame = sample_frame();
    let need = HEADER_LEN + frame.encoded_len();
    let mut small = std::vec![0xeeu8; need - 1];
    let e = encode_object(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &frame, &mut small).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::BufferTooSmall);
    let mut exact = std::vec![0u8; need];
    assert_eq!(
        encode_object(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &frame, &mut exact).unwrap(),
        need
    );
    let mut large = std::vec![0xeeu8; need + 5];
    assert_eq!(
        encode_object(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &frame, &mut large).unwrap(),
        need
    );
    assert_eq!(
        &large[need..],
        &[0xee; 5],
        "bytes beyond the object are untouched"
    );
}

#[test]
fn header_write_matches_read() {
    let header = ObjectHeader::new(SchemaId::new(9), 3, 0);
    let mut buf = [0u8; 16];
    let mut w = Writer::new(&mut buf);
    header.write(&mut w).unwrap();
    assert_eq!(w.finish(), 16);
    let mut r = Reader::new(&buf);
    assert_eq!(ObjectHeader::read(&mut r).unwrap(), header);
    r.finish().unwrap();
}
