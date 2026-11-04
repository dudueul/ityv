//! Strictness (verification ladder V1): each crafted token of
//! `tests/vectors` (forge.py: one change, re-signed where the change touches
//! signed bytes) is refused with its own error or accepted where the
//! change is allowed; non-canonical DER around a valid token is refused; and
//! every truncation of every token is an error, never a panic.
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
    CertificateSource, DerError, DigestAlgorithm, MAX_TOKEN_LEN, PinnedTsa, TsaError, verify_token,
};

/// The base of the forged tokens: rsa3072-sha384.tst.
fn base() -> Expected {
    manifest("manifest.txt")
        .into_iter()
        .find(|e| e.token == "rsa3072-sha384.tst")
        .unwrap()
}

#[test]
fn forged_tokens_are_refused_each_for_its_rule() {
    let base = base();
    let pin = Pin::for_token(&base, true);
    let imprint = imprint_of(DigestAlgorithm::Sha512);
    let der = TsaError::Der;
    for (name, expected) in [
        ("forged-no-ess", TsaError::MissingSigningCertificate),
        ("forged-ess-hash", TsaError::SigningCertificateMismatch),
        ("forged-ess-default", der(DerError::DefaultEncoded)),
        (
            "forged-ess-issuer-bad",
            TsaError::SigningCertificateIssuerMismatch,
        ),
        ("forged-content-type", TsaError::ContentTypeMismatch),
        ("forged-attrs-unsorted", der(DerError::SetNotSorted)),
        ("forged-critical-ext", TsaError::CriticalExtension),
        ("forged-bool-01", der(DerError::InvalidBoolean)),
        ("forged-ordering-false", der(DerError::DefaultEncoded)),
        ("forged-int-nonminimal", der(DerError::NonMinimalInteger)),
        ("forged-len-nonminimal", der(DerError::NonMinimalLength)),
        ("forged-tst-version", TsaError::TstInfoVersion),
        ("forged-time-trailing-zero", der(DerError::InvalidTime)),
        ("forged-outside-validity", TsaError::OutsideValidity),
        ("forged-tsa-name", TsaError::TsaNameMismatch),
        ("forged-sid-serial", TsaError::SignerIdentifierMismatch),
        ("forged-alg-mismatch", TsaError::SignatureDigestMismatch),
        ("forged-rsa-sig-modulus", TsaError::RsaSignatureOutOfRange),
        ("forged-rsa-sig-short", TsaError::RsaSignatureLength),
        ("forged-two-signers", TsaError::SignerCount),
        ("forged-crls", TsaError::CrlsPresent),
        ("forged-detached", TsaError::MissingContent),
        (
            "forged-ess-issuer-dns",
            TsaError::SigningCertificateIssuerMismatch,
        ),
        (
            "forged-ess-issuer-two",
            TsaError::SigningCertificateIssuerMismatch,
        ),
        ("forged-duplicate-attr", TsaError::DuplicateAttribute),
        ("forged-serial-21", TsaError::SerialTooLarge),
        ("forged-nonce-33", TsaError::NonceTooLarge),
        ("forged-time-before-not-before", TsaError::OutsideValidity),
        ("forged-time-after-not-after", TsaError::OutsideValidity),
        ("forged-sid-issuer-der", der(DerError::InvalidBoolean)),
        ("forged-sid-keyid-bad", TsaError::SignerIdentifierMismatch),
        ("forged-sid-keyid-v1", TsaError::SignerInfoVersion),
        ("forged-sid-version3", TsaError::SignerInfoVersion),
        ("forged-nine-certs", TsaError::TooManyCertificates),
        ("forged-cert-choice", TsaError::UnsupportedCertificateChoice),
    ] {
        let token = vector(&std::format!("{name}.tst"));
        assert_eq!(pin.verify(&token, &imprint), Err(expected), "{name}");
    }
}

#[test]
fn the_limits_are_inclusive() {
    let base = base();
    let pin = Pin::for_token(&base, true);
    let imprint = imprint_of(DigestAlgorithm::Sha512);
    let verify = |name: &str| {
        let token = vector(&std::format!("{name}.tst"));
        let verified = pin
            .verify(&token, &imprint)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        (
            verified.serial().to_vec(),
            verified.nonce().map(<[u8]>::to_vec),
            verified.gen_time(),
        )
    };
    // A 160-bit serial and a 256-bit nonce.
    assert_eq!(verify("forged-serial-20").0, [0xFF; 20]);
    assert_eq!(verify("forged-nonce-32").1, Some(std::vec![0xFF; 32]));
    // genTime equal to either end of the certificate's validity.
    let at_start = verify("forged-time-not-before").2;
    let at_end = verify("forged-time-not-after").2;
    assert!(at_start < at_end);
    assert_eq!(at_start.nanos(), 0);
    assert_eq!(at_end.nanos(), 0);
    // Exactly eight embedded certificates.
    let token = vector("forged-eight-certs.tst");
    check_result(
        &base,
        &pin.verify(&token, &imprint).unwrap(),
        CertificateSource::Embedded,
    );
}

#[test]
fn a_signer_named_by_key_identifier_verifies() {
    let base = base();
    let token = vector("forged-sid-keyid.tst");
    let verified = Pin::for_token(&base, true)
        .verify(&token, &imprint_of(DigestAlgorithm::Sha512))
        .unwrap();
    check_result(&base, &verified, CertificateSource::Embedded);
}

#[test]
fn forged_tokens_with_allowed_changes_verify() {
    let base = base();
    let pin = Pin::for_token(&base, true);
    let imprint = imprint_of(DigestAlgorithm::Sha512);
    for name in [
        // A non-critical TSTInfo extension is ignored.
        "forged-noncritical-ext",
        // An unknown signed attribute is ignored (and in the subset).
        "forged-unknown-attr",
        // An ESS issuerSerial that names the certificate.
        "forged-ess-issuer-ok",
        // sha384WithRSAEncryption instead of rsaEncryption.
        "forged-named-rsa-alg",
    ] {
        let token = vector(&std::format!("{name}.tst"));
        let verified = pin
            .verify(&token, &imprint)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        check_result(&base, &verified, CertificateSource::Embedded);
    }
}

#[test]
fn the_certificate_profile_is_enforced() {
    // Certificates for the same key that break one profile rule each
    // (make.sh), embedded and bound by forge.py.
    for (profile, expected) in [
        ("eku-noncritical", TsaError::EkuNotCritical),
        ("eku-two", TsaError::EkuNotTimestampingOnly),
        ("no-eku", TsaError::MissingTimestampingEku),
        ("ca", TsaError::SignerIsCa),
        ("key-usage-sign", TsaError::InvalidKeyUsage),
        ("cert-critical-ext", TsaError::CertificateCriticalExtension),
    ] {
        let token = vector(&std::format!("forged-{profile}.tst"));
        let certificate = vector(&std::format!("rsa3072-{profile}.crt"));
        let pin = Pin {
            certificate_sha256: sha256(&certificate),
            certificate: Some(certificate),
            ..Pin::for_token(&base(), false)
        };
        assert_eq!(
            pin.verify(&token, &imprint_of(DigestAlgorithm::Sha512)),
            Err(expected),
            "{profile}"
        );
    }
}

fn valid_tokens() -> std::vec::Vec<(Expected, std::vec::Vec<u8>)> {
    manifest("manifest.txt")
        .into_iter()
        .chain(manifest("freetsa/manifest.txt"))
        .map(|e| {
            let token = vector(&e.token);
            (e, token)
        })
        .collect()
}

/// Replaces the outer `SEQUENCE` header (`30 82 hi lo`) with `header`.
fn with_outer_header(token: &[u8], header: &[u8]) -> std::vec::Vec<u8> {
    assert_eq!(&token[..2], &[0x30, 0x82]);
    let mut out = header.to_vec();
    out.extend_from_slice(&token[4..]);
    out
}

#[test]
fn non_canonical_der_around_a_valid_token_is_refused() {
    for (expected, token) in valid_tokens() {
        let pin = Pin::for_token(&expected, true);
        let imprint = imprint_of(expected.imprint);
        assert!(pin.verify(&token, &imprint).is_ok());
        let name = &expected.token;
        let length = usize::from(u16::from_be_bytes([token[2], token[3]]));

        // A trailing byte.
        let mut trailing = token.clone();
        trailing.push(0x00);
        assert_eq!(
            pin.verify(&trailing, &imprint),
            Err(TsaError::Der(DerError::TrailingData)),
            "{name}"
        );

        // The indefinite length form, with end-of-contents octets.
        let mut indefinite = with_outer_header(&token, &[0x30, 0x80]);
        indefinite.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(
            pin.verify(&indefinite, &imprint),
            Err(TsaError::Der(DerError::IndefiniteLength)),
            "{name}"
        );

        // Three length octets where two suffice: outside the subset.
        let long = with_outer_header(&token, &[0x30, 0x83, 0x00, token[2], token[3]]);
        assert_eq!(
            pin.verify(&long, &imprint),
            Err(TsaError::Der(DerError::LengthTooLarge)),
            "{name}"
        );

        // The first inner element (the content type OID, `06 09`) with a
        // non-minimal long-form length, the outer length grown by one.
        assert_eq!(&token[4..6], &[0x06, 0x09]);
        let grown = u16::try_from(length + 1).unwrap().to_be_bytes();
        let mut inner = std::vec![0x30, 0x82, grown[0], grown[1], 0x06, 0x81, 0x09];
        inner.extend_from_slice(&token[6..]);
        assert_eq!(
            pin.verify(&inner, &imprint),
            Err(TsaError::Der(DerError::NonMinimalLength)),
            "{name}"
        );

        // The outer length one too long and one too short.
        let short = u16::try_from(length - 1).unwrap();
        let mut shorter = with_outer_header(&token, &[0x30, 0x82]);
        shorter.splice(2..2, short.to_be_bytes());
        assert!(pin.verify(&shorter, &imprint).is_err(), "{name}");
        let mut longer = with_outer_header(&token, &[0x30, 0x82]);
        longer.splice(2..2, u16::try_from(length + 1).unwrap().to_be_bytes());
        assert_eq!(
            pin.verify(&longer, &imprint),
            Err(TsaError::Der(DerError::Truncated)),
            "{name}"
        );

        // Not a SEQUENCE at all.
        let mut set = token.clone();
        set[0] = 0x31;
        assert_eq!(
            pin.verify(&set, &imprint),
            Err(TsaError::Der(DerError::UnexpectedTag)),
            "{name}"
        );
    }
}

#[test]
fn every_truncation_is_an_error() {
    for (expected, token) in valid_tokens() {
        let pin_bytes = Pin::for_token(&expected, true).bytes();
        let pin = PinnedTsa::from_bytes(&pin_bytes).unwrap();
        let imprint = imprint_of(expected.imprint);
        for cut in 0..token.len() {
            assert!(
                verify_token(&token[..cut], &pin, &imprint).is_err(),
                "{} cut at {cut}",
                expected.token
            );
        }
        assert!(verify_token(&token, &pin, &imprint).is_ok());
    }
}

#[test]
fn a_token_over_the_size_limit_is_refused_before_reading() {
    let expected = base();
    let pin = Pin::for_token(&expected, true);
    let mut big = vector(&expected.token);
    big.resize(MAX_TOKEN_LEN + 1, 0);
    assert_eq!(
        pin.verify(&big, &imprint_of(DigestAlgorithm::Sha512)),
        Err(TsaError::TokenTooLarge)
    );
    let mut at_limit = vector(&expected.token);
    at_limit.resize(MAX_TOKEN_LEN, 0);
    assert_eq!(
        pin.verify(&at_limit, &imprint_of(DigestAlgorithm::Sha512)),
        Err(TsaError::Der(DerError::TrailingData))
    );
}
