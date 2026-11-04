//! Real tokens (verification ladder V1): every token `openssl ts` made in
//! `tests/vectors` verifies with the values OpenSSL reads in it, and each
//! pin rule, imprint, policy and signature failure is refused with its own
//! error. The freetsa.org token is the interoperability check.
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
    clippy::missing_panics_doc
)]

mod common;

use common::{Expected, Pin, check_result, imprint_of, manifest, sha256, vector};
use ityv_tsa::{
    CertificateSource, DigestAlgorithm, Imprint, PinnedTsa, SignatureAlgorithm, TsaError,
    verify_token,
};

fn generated() -> std::vec::Vec<Expected> {
    let lines = manifest("manifest.txt");
    assert_eq!(lines.len(), 9, "make.sh records nine valid tokens");
    lines
}

fn embeds_certificate(expected: &Expected) -> bool {
    !expected.token.contains("nocert")
}

#[test]
fn every_valid_token_verifies() {
    for expected in generated() {
        let token = vector(&expected.token);
        let imprint = imprint_of(expected.imprint);
        let with_cert = Pin::for_token(&expected, true);
        let verified = with_cert
            .verify(&token, &imprint)
            .unwrap_or_else(|e| panic!("{}: {e}", expected.token));
        let source = if embeds_certificate(&expected) {
            CertificateSource::Embedded
        } else {
            CertificateSource::Pinned
        };
        check_result(&expected, &verified, source);

        // Without the pin's copy, only tokens that embed it verify.
        let hash_only = Pin::for_token(&expected, false);
        let result = hash_only.verify(&token, &imprint);
        if embeds_certificate(&expected) {
            check_result(&expected, &result.unwrap(), CertificateSource::Embedded);
        } else {
            assert_eq!(result, Err(TsaError::CertificateNotPinned));
        }
    }
}

#[test]
fn the_algorithms_are_the_expected_ones() {
    let algorithms: std::vec::Vec<_> = generated().iter().map(|e| e.signature).collect();
    for algorithm in [
        SignatureAlgorithm::RsaPkcs1Sha256,
        SignatureAlgorithm::RsaPkcs1Sha384,
        SignatureAlgorithm::RsaPkcs1Sha512,
        SignatureAlgorithm::EcdsaP256Sha256,
        SignatureAlgorithm::EcdsaP384Sha384,
        SignatureAlgorithm::EcdsaP384Sha512,
    ] {
        assert!(
            algorithms.contains(&algorithm),
            "{algorithm:?} has a vector"
        );
    }
}

#[test]
fn the_pin_must_allow_every_digest_and_the_signature() {
    for expected in generated() {
        let token = vector(&expected.token);
        let imprint = imprint_of(expected.imprint);
        let pin = Pin::for_token(&expected, true);
        for bit in [0x01u8, 0x02, 0x04] {
            if pin.digests & bit == 0 || pin.digests == bit {
                continue;
            }
            let mut narrower = pin.clone();
            narrower.digests &= !bit;
            assert_eq!(
                narrower.verify(&token, &imprint),
                Err(TsaError::DigestNotAllowed),
                "{} without digest bit {bit}",
                expected.token
            );
        }
        let mut other = pin.clone();
        other.signatures = 0x3F & !expected.signature.bit();
        assert_eq!(
            other.verify(&token, &imprint),
            Err(TsaError::SignatureNotAllowed),
            "{}",
            expected.token
        );
        if expected.ess.is_none() {
            let mut no_v1 = pin.clone();
            no_v1.ess_v1 = false;
            assert_eq!(
                no_v1.verify(&token, &imprint),
                Err(TsaError::SigningCertificateV1NotAllowed),
                "{}",
                expected.token
            );
        }
    }
}

#[test]
fn a_pin_with_only_one_digest_refuses_a_token_using_two() {
    // rsa2048-sha256 signs with SHA-256 over a SHA-512 imprint.
    let expected = &generated()[0];
    let token = vector(&expected.token);
    let mut pin = Pin::for_token(expected, false);
    pin.digests = DigestAlgorithm::Sha512.bit();
    assert_eq!(
        pin.verify(&token, &imprint_of(DigestAlgorithm::Sha512)),
        Err(TsaError::DigestNotAllowed)
    );
}

#[test]
fn a_token_from_another_authority_is_refused() {
    let lines = generated();
    let rsa = &lines[0];
    let p256 = lines.iter().find(|e| e.token == "p256-sha256.tst").unwrap();
    let token = vector(&rsa.token);
    let imprint = imprint_of(DigestAlgorithm::Sha512);
    let mut pin = Pin::for_token(p256, false);
    pin.digests = 0x07;
    pin.signatures = 0x3F;
    assert_eq!(
        pin.verify(&token, &imprint),
        Err(TsaError::CertificateNotPinned)
    );
    // With the other authority's certificate in the pin, the token's signer
    // identifier names a certificate that is not it.
    let mut with_cert = Pin::for_token(p256, true);
    with_cert.digests = 0x07;
    with_cert.signatures = 0x3F;
    assert_eq!(
        with_cert.verify(&token, &imprint),
        Err(TsaError::SignerIdentifierMismatch)
    );
}

#[test]
fn the_imprint_must_be_the_expected_one() {
    for expected in generated() {
        let token = vector(&expected.token);
        let pin = Pin::for_token(&expected, true);
        let other = Imprint::of(expected.imprint, b"another checkpoint");
        assert_eq!(
            pin.verify(&token, &other),
            Err(TsaError::ImprintMismatch),
            "{}",
            expected.token
        );
    }
    // A SHA-256 imprint where SHA-512 is expected, both allowed by the pin.
    let imprint256 = generated()
        .into_iter()
        .find(|e| e.token == "rsa2048-imprint256.tst")
        .unwrap();
    let token = vector(&imprint256.token);
    let mut pin = Pin::for_token(&imprint256, true);
    pin.digests = 0x07;
    assert_eq!(
        pin.verify(&token, &imprint_of(DigestAlgorithm::Sha512)),
        Err(TsaError::ImprintAlgorithmMismatch)
    );
    assert!(
        pin.verify(&token, &imprint_of(DigestAlgorithm::Sha256))
            .is_ok()
    );
}

#[test]
fn the_policy_must_be_pinned() {
    let lines = generated();
    let policy2 = lines
        .iter()
        .find(|e| e.token == "rsa2048-policy2.tst")
        .unwrap();
    let token = vector(&policy2.token);
    let imprint = imprint_of(DigestAlgorithm::Sha512);
    let mut pin = Pin::for_token(policy2, true);
    pin.policies = std::vec!["1.2.3.4.1".into()];
    assert_eq!(
        pin.verify(&token, &imprint),
        Err(TsaError::PolicyNotAllowed)
    );
    pin.policies = std::vec!["1.2.3.4.1".into(), "1.2.3.4.2".into()];
    let verified = pin.verify(&token, &imprint).unwrap();
    check_result(policy2, &verified, CertificateSource::Embedded);
    pin.policies = std::vec!["1.2.3.4.2.1".into(), "1.2.3.4".into()];
    assert_eq!(
        pin.verify(&token, &imprint),
        Err(TsaError::PolicyNotAllowed)
    );
}

fn permissive(cert: &str) -> Pin {
    let certificate = vector(cert);
    Pin {
        certificate_sha256: sha256(&certificate),
        digests: 0x07,
        signatures: 0x3F,
        ess_v1: true,
        policies: std::vec!["1.2.3.4.1".into()],
        certificate: Some(certificate),
    }
}

#[test]
fn unsupported_combinations_are_refused_whatever_the_pin() {
    let imprint = imprint_of(DigestAlgorithm::Sha512);
    assert_eq!(
        permissive("p256.crt").verify(&vector("p256-sha384.tst"), &imprint),
        Err(TsaError::UnsupportedSignatureAlgorithm)
    );
    assert_eq!(
        permissive("rsa1024.crt").verify(&vector("rsa1024-sha256.tst"), &imprint),
        Err(TsaError::RsaModulusSize)
    );
    assert_eq!(
        permissive("rsa2048.crt").verify(&vector("rsa2048-imprint1.tst"), &imprint),
        Err(TsaError::UnknownDigestAlgorithm)
    );
}

#[test]
fn a_flipped_signature_byte_is_refused() {
    for expected in generated() {
        let token = vector(&expected.token);
        let imprint = imprint_of(expected.imprint);
        let pin = Pin::for_token(&expected, true);
        // OpenSSL tokens end with the signature (no unsigned attributes).
        for back in [1usize, 2, 17] {
            let mut flipped = token.clone();
            let at = flipped.len() - back;
            flipped[at] ^= 0x01;
            assert_eq!(
                pin.verify(&flipped, &imprint),
                Err(TsaError::SignatureInvalid),
                "{} byte -{back}",
                expected.token
            );
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .unwrap()
}

/// The offset of the last seconds digit of the first `GeneralizedTime`
/// after `from`: a `0x18` tag whose value is 14 digits, maybe a fraction, and `Z`.
fn gen_time_seconds_digit(token: &[u8], from: usize) -> usize {
    (from..token.len() - 2)
        .find(|&i| {
            let len = usize::from(token[i + 1]);
            token[i] == 0x18
                && (15..=25).contains(&len)
                && token.get(i + 2 + len - 1) == Some(&b'Z')
                && token[i + 2..i + 16].iter().all(u8::is_ascii_digit)
        })
        .unwrap()
        + 15
}

#[test]
fn a_changed_tst_info_byte_breaks_the_message_digest() {
    for expected in generated() {
        let token = vector(&expected.token);
        let imprint = imprint_of(expected.imprint);
        let pin = Pin::for_token(&expected, true);
        // A byte of the hashed message inside the TSTInfo: still DER, still
        // the right shape, but not what was signed.
        let at = find(&token, imprint.digest()) + 5;
        let mut changed = token.clone();
        changed[at] ^= 0x80;
        assert_eq!(
            pin.verify(&changed, &imprint),
            Err(TsaError::MessageDigestMismatch),
            "{}",
            expected.token
        );
        // The genTime's last seconds digit.
        let second = gen_time_seconds_digit(&token, at);
        let mut retimed = token.clone();
        retimed[second] = if retimed[second] == b'1' { b'2' } else { b'1' };
        assert_eq!(
            pin.verify(&retimed, &imprint),
            Err(TsaError::MessageDigestMismatch),
            "{}",
            expected.token
        );
    }
}

#[test]
fn a_pin_certificate_must_match_the_hash() {
    let certificate = vector("rsa2048.crt");
    let other = vector("rsa3072.crt");
    let pin = Pin {
        certificate_sha256: sha256(&certificate),
        digests: 0x07,
        signatures: 0x3F,
        ess_v1: false,
        policies: std::vec!["1.2.3.4.1".into()],
        certificate: Some(other),
    };
    assert_eq!(
        PinnedTsa::from_bytes(&pin.bytes()),
        Err(TsaError::PinCertificate)
    );
}

#[test]
fn the_freetsa_token_is_read_under_the_strict_rules() {
    // A real token (tests/vectors/freetsa/fetch.sh): ECDSA P-384 with
    // SHA-512, an ESS v1 (SHA-1) binding, the TSA and root certificates
    // embedded, a nonce, ordering and a tsa name.
    let lines = manifest("freetsa/manifest.txt");
    assert_eq!(lines.len(), 1);
    let expected = &lines[0];
    let token = vector(&expected.token);
    let imprint = imprint_of(DigestAlgorithm::Sha512);
    let pin = Pin::for_token(expected, false);
    let verified = pin.verify(&token, &imprint).unwrap();
    check_result(expected, &verified, CertificateSource::Embedded);
    // ESS v1 is accepted only when the pin says so.
    let mut strict = pin.clone();
    strict.ess_v1 = false;
    assert_eq!(
        strict.verify(&token, &imprint),
        Err(TsaError::SigningCertificateV1NotAllowed)
    );
    // The embedded root is not the pinned certificate.
    let root = Pin {
        certificate_sha256: [0x5A; 32],
        ..pin.clone()
    };
    assert_eq!(
        root.verify(&token, &imprint),
        Err(TsaError::CertificateNotPinned)
    );
}

#[test]
fn the_public_entry_point_takes_the_genesis_bytes() {
    let expected = &generated()[0];
    let bytes = Pin::for_token(expected, false).bytes();
    let pin = PinnedTsa::from_bytes(&bytes).unwrap();
    assert_eq!(pin.certificate(), None);
    let mut again = std::vec![0u8; pin.encoded_len()];
    assert_eq!(pin.encode(&mut again), Ok(bytes.len()));
    assert_eq!(again, bytes);
    let token = vector(&expected.token);
    let verified = verify_token(&token, &pin, &imprint_of(DigestAlgorithm::Sha512)).unwrap();
    check_result(expected, &verified, CertificateSource::Embedded);
}
