//! Shared helpers for the integration tests. Test code is outside the TCB;
//! `clippy.toml` relaxes unwrap/expect/panic/indexing inside `#[test]`
//! functions only, so helpers here stay fully lint-clean.
//!
//! This module is compiled into every test binary and each binary uses a
//! different subset of it, so `dead_code` is allowed here and nowhere else.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use ityv_encoding::{Encode, ErrorKind, HEADER_LEN, SchemaId, encode_object};
use proptest::prelude::*;
use std::vec::Vec;

/// The identifier alphabet from ENCODING.md §2.
pub(crate) const ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-";

/// Encodes a complete object into a freshly sized vector.
pub(crate) fn encode_to_vec<T: Encode>(schema: SchemaId, version: u16, value: &T) -> Vec<u8> {
    let total = HEADER_LEN.saturating_add(value.encoded_len());
    let mut out = std::vec![0u8; total];
    let written = encode_object(schema, version, value, &mut out)
        .unwrap_or_else(|e| panic!("encoding must succeed: {e}"));
    out.truncate(written);
    out
}

/// Strategy for identifier bytes of length `1..=max`.
pub(crate) fn ident_bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(prop::sample::select(ALPHABET), 1..=max)
}

/// Strategy for a 64-byte digest.
pub(crate) fn hash64() -> impl Strategy<Value = [u8; 64]> {
    any::<[u8; 64]>()
}

/// Strategy for a non-zero sequence number.
pub(crate) fn nonzero_u64() -> impl Strategy<Value = u64> {
    (1u64..=u64::MAX).prop_map(|v| v)
}

/// Formats a byte slice as lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> std::string::String {
    use core::fmt::Write as _;
    let mut s = std::string::String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        // Writing to a String cannot fail.
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Parses lowercase or uppercase hex into bytes.
pub(crate) fn unhex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().collect();
    digits
        .chunks(2)
        .map(|pair| {
            let hi = hex_digit(pair.first().copied());
            let lo = hex_digit(pair.get(1).copied());
            hi.saturating_mul(16).saturating_add(lo)
        })
        .collect()
}

fn hex_digit(b: Option<u8>) -> u8 {
    match b {
        Some(c @ b'0'..=b'9') => c.saturating_sub(b'0'),
        Some(c @ b'a'..=b'f') => c.saturating_sub(b'a').saturating_add(10),
        Some(c @ b'A'..=b'F') => c.saturating_sub(b'A').saturating_add(10),
        Some(_) | None => panic!("invalid hex digit"),
    }
}

/// Parses an `ErrorKind` name as printed by `Debug`.
pub(crate) fn kind_from_name(name: &str) -> ErrorKind {
    const ALL: [ErrorKind; 23] = [
        ErrorKind::UnexpectedEnd,
        ErrorKind::BufferTooSmall,
        ErrorKind::BadMagic,
        ErrorKind::SchemaMismatch,
        ErrorKind::UnsupportedVersion,
        ErrorKind::NonZeroFlags,
        ErrorKind::BodyLengthMismatch,
        ErrorKind::TrailingBytes,
        ErrorKind::InvalidBool,
        ErrorKind::InvalidPresenceTag,
        ErrorKind::LengthExceedsMax,
        ErrorKind::LengthNotRepresentable,
        ErrorKind::EmptyIdent,
        ErrorKind::InvalidIdentByte,
        ErrorKind::CountExceedsMax,
        ErrorKind::NotSorted,
        ErrorKind::Duplicate,
        ErrorKind::ValueOutOfRange,
        ErrorKind::InvalidScopeCode,
        ErrorKind::InvalidPreviousHash,
        ErrorKind::ArithmeticOverflow,
        ErrorKind::InvariantViolation,
        ErrorKind::UnexpectedEnd,
    ];
    ALL.into_iter()
        .find(|k| std::format!("{k:?}") == name)
        .unwrap_or_else(|| panic!("unknown error kind name {name}"))
}
