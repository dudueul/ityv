//! Poly1305 one-time MAC (PROTOCOL.md §9.3) and one-time pad XOR
//! (§9.4), with an independent Poly1305 known answer (Python
//! `cryptography`).
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

use common::{counting32, decode_exact, encode_to_vec, hex};
use ityv_crypto::{Error, OneTimeKey, OneTimeTag, one_time_tag, verify_one_time_tag, xor_in_place};

#[test]
fn poly1305_known_answer() {
    let tag = one_time_tag(OneTimeKey::from_bytes(counting32()), b"share plaintext");
    assert_eq!(hex(tag.as_bytes()), "6a414761212df6ec64e5665410389087");
    assert!(
        verify_one_time_tag(
            OneTimeKey::from_bytes(counting32()),
            b"share plaintext",
            &tag
        )
        .is_ok()
    );
}

#[test]
fn tag_verification_negatives() {
    let key = || OneTimeKey::from_bytes([0x42; 32]);
    let tag = one_time_tag(key(), b"message");
    assert_eq!(
        verify_one_time_tag(key(), b"messagf", &tag).unwrap_err(),
        Error::TagMismatch
    );
    assert_eq!(
        verify_one_time_tag(OneTimeKey::from_bytes([0x43; 32]), b"message", &tag).unwrap_err(),
        Error::TagMismatch
    );
    let mut bad = *tag.as_bytes();
    bad[0] ^= 0x01;
    assert_eq!(
        verify_one_time_tag(key(), b"message", &OneTimeTag::from_bytes(bad)).unwrap_err(),
        Error::TagMismatch
    );
    // Empty messages are authenticated too.
    let empty = one_time_tag(key(), b"");
    assert!(verify_one_time_tag(key(), b"", &empty).is_ok());
    assert_ne!(empty, tag);
    assert_eq!(std::format!("{key:?}", key = key()), "OneTimeKey(..)");
}

#[test]
fn tag_encoding() {
    let tag = OneTimeTag::from_bytes([7u8; 16]);
    let bytes = encode_to_vec(&tag);
    assert_eq!(bytes, [7u8; 16]);
    assert_eq!(decode_exact::<OneTimeTag>(&bytes).unwrap(), tag);
    assert_eq!(OneTimeTag::ENCODED_LEN, 16);
}

#[test]
fn xor_in_place_is_an_involution_with_exact_lengths() {
    let original = *b"share plaintext bytes";
    let pad: [u8; 21] = core::array::from_fn(|i| u8::try_from(i * 7 + 3).unwrap());
    let mut buffer = original;
    xor_in_place(&mut buffer, &pad).unwrap();
    assert_ne!(buffer, original);
    xor_in_place(&mut buffer, &pad).unwrap();
    assert_eq!(buffer, original);
    for (i, b) in buffer.iter().enumerate() {
        assert_eq!(*b, original[i]);
    }

    let mut buffer = original;
    assert_eq!(
        xor_in_place(&mut buffer, &pad[..20]).unwrap_err(),
        Error::LengthMismatch
    );
    assert_eq!(buffer, original, "buffer untouched on length mismatch");
    let longer = [0u8; 22];
    assert_eq!(
        xor_in_place(&mut buffer, &longer).unwrap_err(),
        Error::LengthMismatch
    );
    assert_eq!(buffer, original);
    let mut empty: [u8; 0] = [];
    assert!(xor_in_place(&mut empty, &[]).is_ok());
}
