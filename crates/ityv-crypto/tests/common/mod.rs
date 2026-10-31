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

use ityv_encoding::{Decode, Encode, Error as EncodingError, Reader, Writer};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::vec::Vec;

/// A deterministic CSPRNG for reproducible tests.
pub(crate) fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

/// Encodes a value into a freshly sized vector and checks the declared length.
pub(crate) fn encode_to_vec<T: Encode>(value: &T) -> Vec<u8> {
    let len = value.encoded_len();
    let mut out = std::vec![0u8; len];
    let mut writer = Writer::new(&mut out);
    value
        .encode(&mut writer)
        .unwrap_or_else(|e| panic!("encoding must succeed: {e}"));
    assert_eq!(writer.finish(), len, "encoded_len must match bytes written");
    out
}

/// Decodes a value that must consume the whole input.
pub(crate) fn decode_exact<'a, T: Decode<'a>>(bytes: &'a [u8]) -> Result<T, EncodingError> {
    let mut reader = Reader::new(bytes);
    let value = T::decode(&mut reader)?;
    reader.finish()?;
    Ok(value)
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

/// Parses hex into a fixed-size array.
pub(crate) fn unhex_array<const N: usize>(text: &str) -> [u8; N] {
    let bytes = unhex(text);
    bytes
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("expected {N} bytes, got {}", bytes.len()))
}

/// The byte string `0, 1, 2, …, n−1`.
pub(crate) fn counting(n: usize) -> Vec<u8> {
    (0..n).map(|i| u8::try_from(i % 256).unwrap()).collect()
}

/// A 32-byte array `0, 1, …, 31`.
pub(crate) fn counting32() -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap();
    }
    out
}
