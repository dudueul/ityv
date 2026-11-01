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

// ---------------------------------------------------------------------------
// Builders for the M3 schemas (ENCODING.md §8.6–§8.18).
// ---------------------------------------------------------------------------

use ityv_encoding::{Commitments, Point32, Scalar32};

/// A 64-byte digest with a recognizable pattern.
pub(crate) fn patterned64(seed: u8) -> ityv_encoding::Hash512 {
    let mut h = [0u8; 64];
    for (i, b) in h.iter_mut().enumerate() {
        *b = seed.wrapping_add(u8::try_from(i).unwrap());
    }
    ityv_encoding::Hash512(h)
}

/// A patterned fixed array of `N` bytes.
pub(crate) fn patterned<const N: usize>(seed: u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = seed.wrapping_add(u8::try_from(i % 251).unwrap());
    }
    out
}

/// A proof byte string with a valid PROTOCOL.md §7.5 header for
/// `option_count` options and `chunk_count` chunks, scalars filled with `fill`.
pub(crate) fn proof_bytes(option_count: u16, chunk_count: u8, fill: u8) -> Vec<u8> {
    let len = 3 + usize::from(option_count) * (usize::from(chunk_count) + 2) * 32;
    let mut out = std::vec![fill; len];
    out[0..2].copy_from_slice(&option_count.to_be_bytes());
    out[2] = chunk_count;
    out
}

/// `k` patterned commitments.
pub(crate) fn commitments(k: usize, seed: u8) -> Commitments {
    let points: Vec<Point32> = (0..k)
        .map(|i| Point32(patterned::<32>(seed.wrapping_add(u8::try_from(i).unwrap()))))
        .collect();
    Commitments::new(&points).unwrap()
}

/// `n` patterned scalars.
pub(crate) fn scalars(n: usize, seed: u8) -> Vec<Scalar32> {
    (0..n)
        .map(|i| Scalar32(patterned::<32>(seed.wrapping_add(u8::try_from(i).unwrap()))))
        .collect()
}

/// Encoded length of an identifier field: four-byte prefix plus bytes.
pub(crate) fn ident_len(id: &[u8]) -> usize {
    4 + id.len()
}

// ---------------------------------------------------------------------------
// Published vector files (ENCODING.md §7).
// ---------------------------------------------------------------------------

use ityv_encoding::SCHEMA_VERSION_1;
use std::string::String;

/// One published vector: valid, or invalid with the expected error.
pub(crate) struct Vector {
    pub(crate) label: &'static str,
    pub(crate) bytes: Vec<u8>,
    pub(crate) expected: Option<(&'static str, usize)>,
}

pub(crate) fn render(title: &str, schema: SchemaId, vectors: &[Vector]) -> String {
    use core::fmt::Write as _;
    let mut out = String::new();
    // Writing to a String cannot fail, so the results are discarded.
    let _ = writeln!(
        out,
        "# ityv-encoding test vectors: {title} (schema_id 0x{:04x}, version {SCHEMA_VERSION_1})",
        schema.get()
    );
    let _ = writeln!(out, "# VALID <label> <hex>");
    let _ = writeln!(out, "# INVALID <ErrorKind> <offset> <label> <hex>");
    for v in vectors {
        let label = v.label.replace(' ', "_");
        let _ = match v.expected {
            None => writeln!(out, "VALID {label} {}", hex(&v.bytes)),
            Some((kind, offset)) => {
                writeln!(out, "INVALID {kind} {offset} {label} {}", hex(&v.bytes))
            }
        };
    }
    out
}

pub(crate) fn check_file(name: &str, content: &str) {
    let path = std::format!("{}/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    if std::env::var_os("ITYV_UPDATE_VECTORS").is_some() {
        std::fs::write(&path, content).unwrap();
        return;
    }
    let on_disk = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("missing vector file {path}: {e}; run with ITYV_UPDATE_VECTORS=1")
    });
    assert_eq!(
        on_disk, content,
        "vector file {name} is stale; run with ITYV_UPDATE_VECTORS=1"
    );
}

/// Re-reads a rendered file and checks every line against the decoder, the
/// way an independent implementation would.
pub(crate) fn self_check<F>(content: &str, decode_and_reencode: F)
where
    F: Fn(&[u8]) -> Result<Vec<u8>, ityv_encoding::Error>,
{
    for line in content.lines().filter(|l| !l.starts_with('#')) {
        let fields: Vec<&str> = line.split(' ').collect();
        match fields.first().copied() {
            Some("VALID") => {
                let bytes = unhex(fields[2]);
                let re = decode_and_reencode(&bytes).unwrap_or_else(|e| panic!("{line}: {e}"));
                assert_eq!(re, bytes, "{line}");
            }
            Some("INVALID") => {
                let kind = kind_from_name(fields[1]);
                let offset: usize = fields[2].parse().unwrap();
                let bytes = unhex(fields[4]);
                let e = decode_and_reencode(&bytes).expect_err(line);
                assert_eq!((e.kind(), e.offset()), (kind, offset), "{line}");
            }
            _ => panic!("unexpected line: {line}"),
        }
    }
}
