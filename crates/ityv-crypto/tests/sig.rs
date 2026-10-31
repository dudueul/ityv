//! Hybrid, record and archive signatures: round trips, negatives, encoding
//! and an independent Ed25519 known answer (Python `cryptography`).
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

use common::{counting32, decode_exact, encode_to_vec, hex, rng, unhex_array};
use ityv_crypto::sig::{
    ED25519_SIG_LEN, ED25519_VK_LEN, MLDSA87_SIG_LEN, MLDSA87_VK_LEN, SLHDSA_SIG_LEN, SLHDSA_VK_LEN,
};
use ityv_crypto::{
    ArchiveSignature, ArchiveSigningKey, ArchiveVerifyingKey, Error, HybridSignature,
    HybridSigningKey, HybridVerifyingKey, PURPOSE_CAST_RECORD, PURPOSE_CHECKPOINT_ARCHIVE,
    PURPOSE_MODULE_RECORD, Purpose, RecordPurpose, RecordSignature, RecordSigningKey,
    RecordVerifyingKey, sign_archive, sign_hybrid, sign_record, verify_archive, verify_hybrid,
    verify_record,
};
use ityv_encoding::ErrorKind;

const OBJ: &[u8] = b"ITYV\x00\x00\x00\x01 some object bytes";

#[test]
fn hybrid_round_trip_and_negatives() {
    let mut rng = rng(1);
    let key = HybridSigningKey::generate(&mut rng);
    let vk = key.verifying_key();
    let purpose = Purpose::new(b"checkpoint").unwrap();
    let sig = sign_hybrid(&key, &purpose, OBJ, &mut rng).unwrap();
    let signed = verify_hybrid(&vk, &purpose, OBJ, &sig).unwrap();
    assert_eq!(signed.get().key(), &vk);
    assert_eq!(signed.get().purpose(), &purpose);
    assert_eq!(signed.get().object(), OBJ);
    assert_eq!(signed.get().signature(), &sig);
    assert_eq!(signed.into_inner().object(), OBJ);

    // Wrong object, wrong purpose, wrong key.
    assert_eq!(
        verify_hybrid(&vk, &purpose, b"other", &sig).unwrap_err(),
        Error::SignatureInvalid
    );
    let other_purpose = Purpose::new(b"genesis").unwrap();
    assert_eq!(
        verify_hybrid(&vk, &other_purpose, OBJ, &sig).unwrap_err(),
        Error::SignatureInvalid
    );
    let other_vk = HybridSigningKey::generate(&mut rng).verifying_key();
    assert_eq!(
        verify_hybrid(&other_vk, &purpose, OBJ, &sig).unwrap_err(),
        Error::SignatureInvalid
    );

    // Each half alone is not enough (VC-002): corrupt one half at a time.
    let mut mldsa = *sig.mldsa87();
    mldsa[100] ^= 0x01;
    let bad_mldsa = HybridSignature::from_parts(&mldsa, *sig.ed25519());
    assert_eq!(
        verify_hybrid(&vk, &purpose, OBJ, &bad_mldsa).unwrap_err(),
        Error::SignatureInvalid
    );
    let mut ed = *sig.ed25519();
    ed[5] ^= 0x80;
    let bad_ed = HybridSignature::from_parts(sig.mldsa87(), ed);
    assert_eq!(
        verify_hybrid(&vk, &purpose, OBJ, &bad_ed).unwrap_err(),
        Error::SignatureInvalid
    );

    // Mixing halves from two valid signatures of different keys fails.
    let other_key = HybridSigningKey::generate(&mut rng);
    let other_sig = sign_hybrid(&other_key, &purpose, OBJ, &mut rng).unwrap();
    let mixed = HybridSignature::from_parts(sig.mldsa87(), *other_sig.ed25519());
    assert_eq!(
        verify_hybrid(&vk, &purpose, OBJ, &mixed).unwrap_err(),
        Error::SignatureInvalid
    );

    // Signatures are over the digest of (purpose, obj): a different election
    // object with the same body bytes but different id must not verify.
    let mut other_obj = OBJ.to_vec();
    other_obj[8] ^= 0x01;
    assert!(verify_hybrid(&vk, &purpose, &other_obj, &sig).is_err());
}

#[test]
fn hybrid_keys_and_signatures_encode_fixed_width() {
    let mut rng = rng(2);
    let key = HybridSigningKey::generate(&mut rng);
    let vk = key.verifying_key();
    let bytes = encode_to_vec(&vk);
    assert_eq!(bytes.len(), MLDSA87_VK_LEN + ED25519_VK_LEN);
    assert_eq!(bytes.len(), HybridVerifyingKey::ENCODED_LEN);
    let decoded: HybridVerifyingKey = decode_exact(&bytes).unwrap();
    assert_eq!(decoded, vk);

    let purpose = Purpose::new(b"genesis").unwrap();
    let sig = sign_hybrid(&key, &purpose, OBJ, &mut rng).unwrap();
    let bytes = encode_to_vec(&sig);
    assert_eq!(bytes.len(), MLDSA87_SIG_LEN + ED25519_SIG_LEN);
    let decoded: HybridSignature = decode_exact(&bytes).unwrap();
    assert_eq!(decoded, sig);
    assert!(verify_hybrid(&vk, &purpose, OBJ, &decoded).is_ok());

    // Truncated input is rejected.
    assert_eq!(
        decode_exact::<HybridSignature>(&bytes[..bytes.len() - 1])
            .unwrap_err()
            .kind(),
        ErrorKind::UnexpectedEnd
    );

    // The seeds round-trip through storage.
    let (a, b) = key.expose_seeds();
    let restored = HybridSigningKey::from_seeds(a, b);
    assert_eq!(restored.verifying_key(), vk);
}

#[test]
fn hybrid_verifying_key_rejects_weak_ed25519_half() {
    let mut rng = rng(3);
    let vk = HybridSigningKey::generate(&mut rng).verifying_key();
    // The all-zero encoding is a small-order point: rejected at construction
    // and at decoding (ITYV-BEH-265).
    assert_eq!(
        HybridVerifyingKey::from_parts(vk.mldsa87(), [0u8; 32]).unwrap_err(),
        Error::InvalidPublicKey
    );
    let mut bytes = encode_to_vec(&vk);
    for b in &mut bytes[MLDSA87_VK_LEN..] {
        *b = 0;
    }
    let err = decode_exact::<HybridVerifyingKey>(&bytes).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ValueOutOfRange);
    assert_eq!(err.offset(), MLDSA87_VK_LEN);
    // The identity element (y = 1) is of small order and is rejected too.
    let mut identity = [0u8; 32];
    identity[0] = 1;
    assert_eq!(
        HybridVerifyingKey::from_parts(vk.mldsa87(), identity).unwrap_err(),
        Error::InvalidPublicKey
    );
    assert_eq!(
        RecordVerifyingKey::from_bytes(identity).unwrap_err(),
        Error::InvalidPublicKey
    );
}

#[test]
fn record_signature_known_answer() {
    // Seed 0..31; expected values from Python `cryptography` (Ed25519 over
    // the SHA3-512 signing digest computed with hashlib).
    let key = RecordSigningKey::from_seed(counting32());
    let vk = key.verifying_key();
    assert_eq!(
        hex(vk.as_bytes()),
        "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
    );
    let sig = sign_record(&key, RecordPurpose::CastRecord, b"record body").unwrap();
    assert_eq!(
        hex(sig.as_bytes()),
        "22a0c34044f9927ee6b17d5046d1265196f73fac012e0b5ff52f554fae5033bac09f0248a7ed61e1d42285f9d4a2d26e2e9b450091dece52f30a6bca8b97970f"
    );
    let sig2 = sign_record(&key, RecordPurpose::ModuleRecord, b"record body").unwrap();
    assert_eq!(
        hex(sig2.as_bytes()),
        "66cb95c6f83300900cd7390f9d259d0a2d18844f69a4b1b05bc2038d26e9332dcd3d3b89aedc22dd94054f0022ee7f67729b18a0731e028291a5668d4ea71d0b"
    );
    let signed = verify_record(&vk, RecordPurpose::CastRecord, b"record body", &sig).unwrap();
    assert_eq!(signed.get().key(), &vk);
    assert_eq!(signed.get().purpose(), RecordPurpose::CastRecord);
    assert_eq!(signed.get().object(), b"record body");
    assert_eq!(signed.get().signature(), &sig);
    assert!(verify_record(&vk, RecordPurpose::ModuleRecord, b"record body", &sig2).is_ok());
    // The two purposes are not interchangeable.
    assert_eq!(
        verify_record(&vk, RecordPurpose::ModuleRecord, b"record body", &sig).unwrap_err(),
        Error::SignatureInvalid
    );
    assert_eq!(
        verify_record(&vk, RecordPurpose::CastRecord, b"record body", &sig2).unwrap_err(),
        Error::SignatureInvalid
    );
    assert_eq!(RecordPurpose::CastRecord.purpose(), PURPOSE_CAST_RECORD);
    assert_eq!(RecordPurpose::ModuleRecord.purpose(), PURPOSE_MODULE_RECORD);
    assert_eq!(PURPOSE_CHECKPOINT_ARCHIVE.as_bytes(), b"checkpoint-archive");
    assert_eq!(key.expose_seed(), counting32());
}

#[test]
fn record_signature_negatives_and_encoding() {
    let mut rng = rng(4);
    let key = RecordSigningKey::generate(&mut rng);
    let vk = key.verifying_key();
    let sig = sign_record(&key, RecordPurpose::CastRecord, OBJ).unwrap();
    assert!(verify_record(&vk, RecordPurpose::CastRecord, OBJ, &sig).is_ok());
    assert!(verify_record(&vk, RecordPurpose::CastRecord, b"x", &sig).is_err());
    let other = RecordSigningKey::generate(&mut rng).verifying_key();
    assert!(verify_record(&other, RecordPurpose::CastRecord, OBJ, &sig).is_err());
    let mut bad = *sig.as_bytes();
    bad[63] ^= 0x01;
    assert!(
        verify_record(
            &vk,
            RecordPurpose::CastRecord,
            OBJ,
            &RecordSignature::from_bytes(bad)
        )
        .is_err()
    );

    let bytes = encode_to_vec(&vk);
    assert_eq!(bytes.len(), ED25519_VK_LEN);
    assert_eq!(decode_exact::<RecordVerifyingKey>(&bytes).unwrap(), vk);
    let bytes = encode_to_vec(&sig);
    assert_eq!(bytes.len(), ED25519_SIG_LEN);
    assert_eq!(decode_exact::<RecordSignature>(&bytes).unwrap(), sig);
    assert_eq!(
        RecordVerifyingKey::from_bytes([0u8; 32]).unwrap_err(),
        Error::InvalidPublicKey
    );
    assert_eq!(
        decode_exact::<RecordVerifyingKey>(&[0u8; 32])
            .unwrap_err()
            .kind(),
        ErrorKind::ValueOutOfRange
    );
    let restored = RecordSigningKey::from_seed(key.expose_seed());
    assert_eq!(restored.verifying_key(), vk);
    assert_eq!(std::format!("{key:?}"), "RecordSigningKey(..)");
}

#[test]
fn archive_signature_round_trip_negatives_and_encoding() {
    // SLH-DSA-SHAKE-256s is slow; one key pair and one signature serve every
    // check in this test.
    let mut rng = rng(5);
    let (key, vk) = ArchiveSigningKey::generate(&mut rng);
    let sig = sign_archive(&key, OBJ, &mut rng).unwrap();
    let signed = verify_archive(&vk, OBJ, &sig).unwrap();
    assert_eq!(signed.get().key(), &vk);
    assert_eq!(signed.get().object(), OBJ);
    assert_eq!(signed.get().signature(), &sig);
    assert_eq!(
        verify_archive(&vk, b"other", &sig).unwrap_err(),
        Error::SignatureInvalid
    );
    let mut bad = *sig.as_bytes();
    bad[SLHDSA_SIG_LEN - 1] ^= 0x01;
    assert_eq!(
        verify_archive(&vk, OBJ, &ArchiveSignature::from_bytes(&bad)).unwrap_err(),
        Error::SignatureInvalid
    );
    let mut bad_vk = *vk.as_bytes();
    bad_vk[0] ^= 0x01;
    assert!(verify_archive(&ArchiveVerifyingKey::from_bytes(bad_vk), OBJ, &sig).is_err());

    let bytes = encode_to_vec(&sig);
    assert_eq!(bytes.len(), SLHDSA_SIG_LEN);
    assert_eq!(decode_exact::<ArchiveSignature>(&bytes).unwrap(), sig);
    let bytes = encode_to_vec(&vk);
    assert_eq!(bytes.len(), SLHDSA_VK_LEN);
    assert_eq!(decode_exact::<ArchiveVerifyingKey>(&bytes).unwrap(), vk);

    let restored = ArchiveSigningKey::from_bytes(*key.expose_bytes());
    assert_eq!(restored.expose_bytes(), key.expose_bytes());
    assert_eq!(std::format!("{key:?}"), "ArchiveSigningKey(..)");
    assert_eq!(std::format!("{sig:?}"), "ArchiveSignature(..)");
}

#[test]
fn secret_keys_do_not_print_and_vectors_parse() {
    let mut rng = rng(6);
    let key = HybridSigningKey::generate(&mut rng);
    assert_eq!(std::format!("{key:?}"), "HybridSigningKey(..)");
    let vk = key.verifying_key();
    let text = std::format!("{vk:?}");
    assert!(text.starts_with("HybridVerifyingKey"));
    assert!(!text.contains("mldsa87"));
    let purpose = Purpose::new(b"slip").unwrap();
    let sig = sign_hybrid(&key, &purpose, OBJ, &mut rng).unwrap();
    let text = std::format!("{sig:?}");
    assert!(text.starts_with("HybridSignature"));
    assert!(text.contains("ed25519"));
    assert!(!text.contains("mldsa87"));
    assert!(std::format!("{:?}", RecordPurpose::CastRecord).starts_with("CastRecord"));
    let expected: [u8; 32] =
        unhex_array("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8");
    assert_eq!(expected.len(), 32);
}
