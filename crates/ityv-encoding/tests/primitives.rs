//! Unit tests for every primitive and every rejection rule of ENCODING.md §2
//! and §5 at the reader/writer level.
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

use ityv_encoding::{
    Bytes, Decode, ElectionId, Encode, ErrorKind, Hash512, Ident, Point32, Reader, Scalar32,
    SchemaId, Seq, Token192, Writer,
};

fn kind_at(result: Result<impl core::fmt::Debug, ityv_encoding::Error>) -> (ErrorKind, usize) {
    let err = result.expect_err("expected an error");
    (err.kind(), err.offset())
}

#[test]
fn integers_are_big_endian_fixed_width() {
    let mut buf = [0u8; 15];
    let mut w = Writer::new(&mut buf);
    w.write_u8(0x01).unwrap();
    w.write_u16(0x0203).unwrap();
    w.write_u32(0x0405_0607).unwrap();
    w.write_u64(0x0809_0a0b_0c0d_0e0f).unwrap();
    assert_eq!(w.finish(), 15);
    assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    let mut r = Reader::new(&buf);
    assert_eq!(r.read_u8().unwrap(), 0x01);
    assert_eq!(r.read_u16().unwrap(), 0x0203);
    assert_eq!(r.read_u32().unwrap(), 0x0405_0607);
    assert_eq!(r.read_u64().unwrap(), 0x0809_0a0b_0c0d_0e0f);
    assert!(r.is_empty());
    r.finish().unwrap();
}

#[test]
fn reader_reports_unexpected_end_at_current_offset() {
    let buf = [0u8; 3];
    let mut r = Reader::new(&buf);
    r.read_u16().unwrap();
    assert_eq!(kind_at(r.read_u32()), (ErrorKind::UnexpectedEnd, 2));
    assert_eq!(r.position(), 2, "a failed read must not advance");
}

#[test]
fn writer_reports_buffer_too_small_at_current_offset() {
    let mut buf = [0u8; 5];
    let mut w = Writer::new(&mut buf);
    w.write_u32(7).unwrap();
    assert_eq!(kind_at(w.write_u16(1)), (ErrorKind::BufferTooSmall, 4));
    assert_eq!(w.position(), 4, "a failed write must not advance");
    assert_eq!(w.remaining(), 1);
}

#[test]
fn bool_is_strict() {
    for byte in 0u8..=255 {
        let buf = [byte];
        let mut r = Reader::new(&buf);
        match byte {
            0 => assert!(!r.read_bool().unwrap()),
            1 => assert!(r.read_bool().unwrap()),
            _ => assert_eq!(kind_at(r.read_bool()), (ErrorKind::InvalidBool, 0)),
        }
    }
    let mut out = [9u8; 2];
    let mut w = Writer::new(&mut out);
    w.write_bool(false).unwrap();
    w.write_bool(true).unwrap();
    assert_eq!(out, [0, 1]);
}

#[test]
fn presence_tag_is_strict() {
    let buf = [2u8, 1, 0];
    let mut r = Reader::new(&buf);
    assert_eq!(
        kind_at(r.read_presence()),
        (ErrorKind::InvalidPresenceTag, 0)
    );
    r.read_u8().unwrap();
    assert!(r.read_presence().unwrap());
    assert!(!r.read_presence().unwrap());
}

#[test]
fn option_round_trips_with_presence_tag() {
    let some: Option<u16> = Some(0xbeef);
    let none: Option<u16> = None;
    assert_eq!(some.encoded_len(), 3);
    assert_eq!(none.encoded_len(), 1);
    let mut buf = [0u8; 4];
    let mut w = Writer::new(&mut buf);
    some.encode(&mut w).unwrap();
    none.encode(&mut w).unwrap();
    assert_eq!(buf, [1, 0xbe, 0xef, 0]);
    let mut r = Reader::new(&buf);
    assert_eq!(Option::<u16>::decode(&mut r).unwrap(), some);
    assert_eq!(Option::<u16>::decode(&mut r).unwrap(), none);
    r.finish().unwrap();
}

#[test]
fn fixed_arrays_round_trip() {
    let hash = Hash512([7u8; 64]);
    let scalar = Scalar32([8u8; 32]);
    let point = Point32([9u8; 32]);
    let token = Token192([10u8; 24]);
    assert_eq!(
        hash.encoded_len() + scalar.encoded_len() + point.encoded_len() + token.encoded_len(),
        152
    );
    let mut buf = [0u8; 152];
    let mut w = Writer::new(&mut buf);
    hash.encode(&mut w).unwrap();
    scalar.encode(&mut w).unwrap();
    point.encode(&mut w).unwrap();
    token.encode(&mut w).unwrap();
    let mut r = Reader::new(&buf);
    assert_eq!(Hash512::decode(&mut r).unwrap(), hash);
    assert_eq!(Scalar32::decode(&mut r).unwrap(), scalar);
    assert_eq!(Point32::decode(&mut r).unwrap(), point);
    assert_eq!(Token192::decode(&mut r).unwrap(), token);
    r.finish().unwrap();
    assert!(Hash512::ZERO.is_zero());
    assert!(!hash.is_zero());
}

#[test]
fn bytes_have_u32_length_prefix_and_schema_max() {
    let mut buf = [0u8; 16];
    {
        let mut w = Writer::new(&mut buf);
        w.write_bytes(b"abc", 3).unwrap();
        assert_eq!(
            kind_at(w.write_bytes(b"abcd", 3)),
            (ErrorKind::LengthExceedsMax, 7)
        );
    }
    assert_eq!(&buf[..7], &[0, 0, 0, 3, b'a', b'b', b'c']);

    let mut r = Reader::new(&buf[..7]);
    assert_eq!(r.read_bytes(3).unwrap(), b"abc");
    let mut r = Reader::new(&buf[..7]);
    assert_eq!(kind_at(r.read_bytes(2)), (ErrorKind::LengthExceedsMax, 0));

    let short = [0u8, 0, 0, 5, b'a'];
    let mut r = Reader::new(&short);
    assert_eq!(kind_at(r.read_bytes(8)), (ErrorKind::UnexpectedEnd, 4));

    assert!(Bytes::new(b"", 0).is_some());
    assert!(Bytes::new(b"x", 0).is_none());
    assert_eq!(Bytes::new(b"xy", 2).unwrap().len(), 2);
    assert!(Bytes::new(b"", 2).unwrap().is_empty());
}

#[test]
fn ident_alphabet_and_length_rules() {
    for byte in 0u8..=255 {
        let expected = byte.is_ascii_alphanumeric() || b"._:-".contains(&byte);
        assert_eq!(Ident::is_valid_byte(byte), expected, "byte {byte:#04x}");
        assert_eq!(Ident::new(&[byte], 1).is_some(), expected);
    }
    assert!(
        Ident::new(b"", 64).is_none(),
        "empty identifiers are rejected"
    );
    assert!(Ident::new(&[b'a'; 64], 64).is_some());
    assert!(
        Ident::new(&[b'a'; 65], 64).is_none(),
        "schema max is enforced"
    );
    assert_eq!(Ident::new(b"KR-2030:x.y_z", 64).unwrap().len(), 13);
    assert!(
        Ident::new("한".as_bytes(), 64).is_none(),
        "non-ASCII is rejected"
    );
    assert!(Ident::new(b"a b", 64).is_none(), "space is rejected");
}

#[test]
fn ident_decoding_reports_exact_offsets() {
    let empty = [0u8, 0, 0, 0];
    let mut r = Reader::new(&empty);
    assert_eq!(kind_at(r.read_ident(8)), (ErrorKind::EmptyIdent, 0));

    let bad = [0u8, 0, 0, 3, b'a', b' ', b'c'];
    let mut r = Reader::new(&bad);
    assert_eq!(kind_at(r.read_ident(8)), (ErrorKind::InvalidIdentByte, 5));

    let too_long = [
        0u8, 0, 0, 9, b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a', b'a',
    ];
    let mut r = Reader::new(&too_long);
    assert_eq!(kind_at(r.read_ident(8)), (ErrorKind::LengthExceedsMax, 0));

    let good = [0u8, 0, 0, 2, b'o', b'k', 0xff];
    let mut r = Reader::new(&good);
    assert_eq!(r.read_ident(8).unwrap().as_bytes(), b"ok");
    assert_eq!(kind_at(r.finish()), (ErrorKind::TrailingBytes, 6));
}

#[test]
fn ident_newtypes_fix_the_standard_maximum() {
    assert_eq!(ElectionId::MAX_LEN, 64);
    assert!(ElectionId::new(&[b'e'; 64]).is_some());
    assert!(ElectionId::new(&[b'e'; 65]).is_none());
    let id = ElectionId::new(b"KR-2030").unwrap();
    assert_eq!(id.encoded_len(), 11);
    let mut buf = [0u8; 11];
    let mut w = Writer::new(&mut buf);
    id.encode(&mut w).unwrap();
    assert_eq!(&buf[..4], &[0, 0, 0, 7]);
    let mut r = Reader::new(&buf);
    assert_eq!(ElectionId::decode(&mut r).unwrap(), id);
}

#[test]
fn counts_are_bounded() {
    let mut buf = [0u8; 4];
    let mut w = Writer::new(&mut buf);
    assert_eq!(
        kind_at(w.write_count(17, 16)),
        (ErrorKind::CountExceedsMax, 0)
    );
    w.write_count(16, 16).unwrap();
    let mut r = Reader::new(&buf);
    assert_eq!(kind_at(r.read_count(15)), (ErrorKind::CountExceedsMax, 0));
    let mut r = Reader::new(&buf);
    assert_eq!(r.read_count(16).unwrap(), 16);
}

#[test]
fn ascending_check_distinguishes_sorted_duplicate_and_unsorted() {
    assert!(Reader::check_ascending(None, b"a", 0).is_ok());
    assert!(Reader::check_ascending(Some(b"a"), b"b", 1).is_ok());
    assert!(Reader::check_ascending(Some(b"a"), b"ab", 1).is_ok());
    assert_eq!(
        kind_at(Reader::check_ascending(Some(b"a"), b"a", 7)),
        (ErrorKind::Duplicate, 7)
    );
    assert_eq!(
        kind_at(Reader::check_ascending(Some(b"b"), b"a", 7)),
        (ErrorKind::NotSorted, 7)
    );
}

#[test]
fn seq_rejects_zero_and_schema_id_is_transparent() {
    assert!(Seq::new(0).is_none());
    assert_eq!(Seq::new(1), Some(Seq::FIRST));
    assert!(Seq::FIRST.is_first());
    assert!(!Seq::new(2).unwrap().is_first());
    let zero = [0u8; 8];
    let mut r = Reader::new(&zero);
    assert_eq!(
        kind_at(Seq::decode(&mut r)),
        (ErrorKind::ValueOutOfRange, 0)
    );
    assert_eq!(SchemaId::new(0x0004).get(), 4);
}

#[test]
fn error_display_names_kind_and_offset() {
    let e = ityv_encoding::Error::new(ErrorKind::BadMagic, 3);
    assert_eq!(std::format!("{e}"), "BadMagic at byte offset 3");
}
