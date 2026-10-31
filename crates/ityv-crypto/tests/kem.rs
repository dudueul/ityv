//! Hybrid KEM and sealing: round trips, negatives, encoding, and independent
//! known answers for the X25519, Poly1305-free AEAD and key derivation
//! inputs (Python `cryptography`).
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

use common::{counting32, decode_exact, encode_to_vec, hex, rng, unhex, unhex_array};
use ityv_crypto::kem::{MLKEM1024_CT_LEN, MLKEM1024_EK_LEN, X25519_LEN};
use ityv_crypto::{
    AeadTag, Error, HybridCiphertext, HybridKemPublicKey, HybridKemSecretKey, SharedKey,
    decapsulate, encapsulate, open, seal,
};
use ityv_encoding::ErrorKind;

#[test]
fn encapsulate_decapsulate_seal_open_round_trip() {
    let mut rng = rng(10);
    let sk = HybridKemSecretKey::generate(&mut rng);
    let pk = sk.public_key();
    let (ct, key_send) = encapsulate(&pk, &mut rng).unwrap();
    let key_recv = decapsulate(&sk, &ct).unwrap();
    assert_eq!(key_send, key_recv);

    let mut buffer = *b"share plaintext for member 3";
    let tag = seal(key_send, b"aad", &mut buffer).unwrap();
    assert_ne!(&buffer, b"share plaintext for member 3");
    assert!(open(key_recv, b"aad", &mut buffer, &tag).is_ok());
    assert_eq!(&buffer, b"share plaintext for member 3");
}

#[test]
fn wrong_key_ciphertext_or_aad_fails() {
    let mut rng = rng(11);
    let sk = HybridKemSecretKey::generate(&mut rng);
    let pk = sk.public_key();
    let (ct, key_send) = encapsulate(&pk, &mut rng).unwrap();
    let mut buffer = *b"payload";
    let tag = seal(key_send, b"aad", &mut buffer).unwrap();
    let sealed = buffer;

    // Another secret key does not recover the key (implicit rejection).
    let other = HybridKemSecretKey::generate(&mut rng);
    let wrong = decapsulate(&other, &ct).unwrap();
    let mut attempt = sealed;
    assert_eq!(
        open(wrong, b"aad", &mut attempt, &tag).unwrap_err(),
        Error::AeadInvalid
    );
    assert_eq!(attempt, sealed, "buffer must be untouched on failure");

    // A tampered ML-KEM ciphertext yields a different key.
    let mut bad_ct = *ct.mlkem1024();
    bad_ct[0] ^= 0x01;
    let tampered = HybridCiphertext::from_parts(&bad_ct, *ct.x25519());
    let key = decapsulate(&sk, &tampered).unwrap();
    let mut attempt = sealed;
    assert!(open(key, b"aad", &mut attempt, &tag).is_err());

    // A tampered X25519 ciphertext yields a different key.
    let mut bad_x = *ct.x25519();
    bad_x[1] ^= 0x01;
    let tampered = HybridCiphertext::from_parts(ct.mlkem1024(), bad_x);
    let key = decapsulate(&sk, &tampered).unwrap();
    let mut attempt = sealed;
    assert!(open(key, b"aad", &mut attempt, &tag).is_err());

    // Wrong associated data or wrong tag.
    let key = decapsulate(&sk, &ct).unwrap();
    let mut attempt = sealed;
    assert!(open(key, b"other aad", &mut attempt, &tag).is_err());
    let key = decapsulate(&sk, &ct).unwrap();
    let mut bad_tag = *tag.as_bytes();
    bad_tag[15] ^= 0x01;
    let mut attempt = sealed;
    assert!(open(key, b"aad", &mut attempt, &AeadTag::from_bytes(bad_tag)).is_err());
}

#[test]
fn non_contributory_x25519_keys_are_rejected() {
    let mut rng = rng(12);
    let sk = HybridKemSecretKey::generate(&mut rng);
    let pk = sk.public_key();
    // The all-zero point as a public key gives the all-zero shared secret.
    let bad_pk = HybridKemPublicKey::from_parts(pk.mlkem1024(), [0u8; 32]).unwrap();
    assert_eq!(
        encapsulate(&bad_pk, &mut rng).unwrap_err(),
        Error::NonContributoryKey
    );
    let (ct, _) = encapsulate(&pk, &mut rng).unwrap();
    let bad_ct = HybridCiphertext::from_parts(ct.mlkem1024(), [0u8; 32]);
    assert_eq!(
        decapsulate(&sk, &bad_ct).unwrap_err(),
        Error::NonContributoryKey
    );
}

#[test]
fn malformed_mlkem_keys_are_rejected() {
    let mut rng = rng(13);
    let pk = HybridKemSecretKey::generate(&mut rng).public_key();
    // The FIPS 203 modulus check fails for an all-0xff encapsulation key.
    assert_eq!(
        HybridKemPublicKey::from_parts(&[0xff; MLKEM1024_EK_LEN], *pk.x25519()).unwrap_err(),
        Error::InvalidPublicKey
    );
    let mut bytes = encode_to_vec(&pk);
    for b in &mut bytes[..MLKEM1024_EK_LEN] {
        *b = 0xff;
    }
    let err = decode_exact::<HybridKemPublicKey>(&bytes).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ValueOutOfRange);
    assert_eq!(err.offset(), 0);
}

#[test]
fn keys_and_ciphertexts_encode_fixed_width() {
    let mut rng = rng(14);
    let sk = HybridKemSecretKey::generate(&mut rng);
    let pk = sk.public_key();
    let bytes = encode_to_vec(&pk);
    assert_eq!(bytes.len(), MLKEM1024_EK_LEN + X25519_LEN);
    assert_eq!(decode_exact::<HybridKemPublicKey>(&bytes).unwrap(), pk);
    let (ct, key) = encapsulate(&pk, &mut rng).unwrap();
    let bytes = encode_to_vec(&ct);
    assert_eq!(bytes.len(), MLKEM1024_CT_LEN + X25519_LEN);
    let decoded: HybridCiphertext = decode_exact(&bytes).unwrap();
    assert_eq!(decoded, ct);
    assert_eq!(decapsulate(&sk, &decoded).unwrap(), key);
    let mut buffer = [0u8; 4];
    let tag = seal(key, b"", &mut buffer).unwrap();
    let bytes = encode_to_vec(&tag);
    assert_eq!(bytes.len(), 16);
    assert_eq!(decode_exact::<AeadTag>(&bytes).unwrap(), tag);

    let (seed, x) = sk.expose_parts();
    let restored = HybridKemSecretKey::from_parts(seed, x);
    assert_eq!(restored.public_key(), pk);
    assert_eq!(std::format!("{sk:?}"), "HybridKemSecretKey(..)");
    assert_eq!(
        std::format!("{key_debug:?}", key_debug = SharedKey::from_bytes([0; 32])),
        "SharedKey(..)"
    );
    assert!(std::format!("{pk:?}").starts_with("HybridKemPublicKey"));
    assert!(std::format!("{ct:?}").starts_with("HybridCiphertext"));
}

#[test]
fn x25519_known_answer() {
    // Secret 0..31 and 32..63; public keys and shared secret from Python
    // `cryptography`. The ML-KEM seed is irrelevant for the X25519 half.
    let sk = HybridKemSecretKey::from_parts([7u8; 64], counting32());
    assert_eq!(
        hex(sk.public_key().x25519()),
        "8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f"
    );
    let mut peer_secret = [0u8; 32];
    for (i, b) in peer_secret.iter_mut().enumerate() {
        *b = u8::try_from(32 + i).unwrap();
    }
    let peer = HybridKemSecretKey::from_parts([8u8; 64], peer_secret);
    assert_eq!(
        hex(peer.public_key().x25519()),
        "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
    );
}

#[test]
fn chacha20poly1305_known_answer() {
    // Key 0..31, zero nonce, aad "aad bytes", plaintext "sealed share
    // package"; ciphertext and tag from Python `cryptography`.
    let key = SharedKey::from_bytes(counting32());
    let mut buffer = *b"sealed share package";
    let tag = seal(key, b"aad bytes", &mut buffer).unwrap();
    assert_eq!(hex(&buffer), "6bdd235dc88286a27b002e048f332f4493d09490");
    assert_eq!(hex(tag.as_bytes()), "801386794f175fed79317066aaf347df");
    let key = SharedKey::from_bytes(counting32());
    assert!(open(key, b"aad bytes", &mut buffer, &tag).is_ok());
    assert_eq!(&buffer, b"sealed share package");
    let expected_ct = unhex("6bdd235dc88286a27b002e048f332f4493d09490");
    assert_eq!(expected_ct.len(), 20);
    let expected_tag: [u8; 16] = unhex_array("801386794f175fed79317066aaf347df");
    assert_eq!(AeadTag::from_bytes(expected_tag), tag);
}
