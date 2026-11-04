//! Strictness (verification ladder V1): each crafted token of
//! `tests/vectors` (forge.py: one change, re-signed where the change touches
//! signed bytes) is refused with its own error or accepted where the
//! change is allowed; non-canonical DER around a valid token is refused; and
//! every truncation of every token is an error, never a panic.
//! `tests/rules.rs` holds the list of one token per `TsaError` variant; the
//! lists here add the DER cases and further tokens per rule.
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

use common::{
    Expected, Pin, check_result, embedded_certificates, forged_base as base, imprint_of, manifest,
    sha256, vector,
};
use ityv_tsa::{
    CertificateSource, DerError, DigestAlgorithm, GenTime, MAX_ACCURACY_SECONDS, MAX_TOKEN_LEN,
    PinnedTsa, TsaError, VerifiedTimestamp, verify_token,
};

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
        ("forged-digest-set-empty", TsaError::DigestAlgorithmSet),
        ("forged-digest-set-two", TsaError::DigestAlgorithmSet),
        ("forged-attr-no-value", TsaError::AttributeValueCount),
        ("forged-nonce-negative", der(DerError::NegativeInteger)),
        ("forged-time-offset", der(DerError::InvalidTime)),
        ("forged-time-utc", der(DerError::UnexpectedTag)),
        // Unsigned sets in any order, but every element in the subset.
        ("forged-chain-cert-not-der", der(DerError::InvalidBoolean)),
        ("forged-unsigned-attr-not-der", der(DerError::SetNotSorted)),
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
        // The unsigned certificate set and unsigned attributes, unsorted.
        "forged-certs-unsorted",
        "forged-unsigned-attrs-unsorted",
        // ESS v2 hashAlgorithm SHA-256 with NULL parameters (not DEFAULT).
        "forged-ess-sha256-null",
    ] {
        let token = vector(&std::format!("{name}.tst"));
        let verified = pin
            .verify(&token, &imprint)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        check_result(&base, &verified, CertificateSource::Embedded);
    }
}

#[test]
fn an_ess_v1_binding_next_to_v2_verifies_when_the_pin_allows_it() {
    let base = base();
    let token = vector("forged-ess-v1-and-v2.tst");
    let imprint = imprint_of(DigestAlgorithm::Sha512);
    let pin = Pin {
        ess_v1: true,
        ..Pin::for_token(&base, true)
    };
    check_result(
        &base,
        &pin.verify(&token, &imprint).unwrap(),
        CertificateSource::Embedded,
    );
    assert_eq!(
        Pin::for_token(&base, true).verify(&token, &imprint),
        Err(TsaError::SigningCertificateV1NotAllowed)
    );
}

#[test]
fn a_critical_certificate_policies_extension_is_accepted() {
    // OpenSSL's certificate with a critical certificatePolicies (CPS and a
    // BMPString user notice), embedded and bound by forge.py.
    let token = vector("forged-policies-critical.tst");
    let certificate = vector("rsa3072-policies-critical.crt");
    assert_eq!(
        embedded_certificates(&token),
        core::slice::from_ref(&certificate)
    );
    let expected = Expected {
        cert: "rsa3072-policies-critical.crt".into(),
        ..base()
    };
    let pin = Pin::for_token(&expected, false);
    let verified = pin
        .verify(&token, &imprint_of(DigestAlgorithm::Sha512))
        .unwrap();
    check_result(&expected, &verified, CertificateSource::Embedded);
    assert_eq!(verified.certificate_sha256(), &sha256(&certificate));
}

#[test]
fn an_ecdsa_signature_with_high_s_verifies_too() {
    // (r, n - s) is a second valid signature: token bytes are not unique,
    // the result is the same. s = n is refused.
    let expected = manifest("manifest.txt")
        .into_iter()
        .find(|e| e.token == "p256-sha256.tst")
        .unwrap();
    let pin = Pin::for_token(&expected, false);
    let imprint = imprint_of(expected.imprint);
    let original = vector("p256-sha256.tst");
    let malleated = vector("forged-p256-high-s.tst");
    assert_ne!(original, malleated);
    let verified = pin.verify(&malleated, &imprint).unwrap();
    check_result(&expected, &verified, CertificateSource::Embedded);
    assert_eq!(Ok(verified), pin.verify(&original, &imprint));
    assert_eq!(
        pin.verify(&vector("forged-p256-s-order.tst"), &imprint),
        Err(TsaError::EcdsaSignatureEncoding)
    );
}

/// `(seconds, nanos)` of a time.
fn parts(time: Option<GenTime>) -> Option<(u64, u32)> {
    time.map(|time| (time.unix_seconds(), time.nanos()))
}

/// genTime moved by `offset` nanoseconds.
fn moved(verified: &VerifiedTimestamp<'_>, offset: i128) -> Option<(u64, u32)> {
    let time = verified.gen_time();
    let whole = i128::from(time.unix_seconds()) * 1_000_000_000 + i128::from(time.nanos()) + offset;
    Some((
        u64::try_from(whole / 1_000_000_000).ok()?,
        u32::try_from(whole % 1_000_000_000).ok()?,
    ))
}

#[test]
fn the_interval_is_gen_time_plus_or_minus_the_accuracy() {
    let base = base();
    let pin = Pin::for_token(&base, true);
    let imprint = imprint_of(DigestAlgorithm::Sha512);
    // The base states 1 s 500 ms 100 µs; forged-accuracy-max 3600 s and the same.
    let token = vector(&base.token);
    let verified = pin.verify(&token, &imprint).unwrap();
    assert_eq!(base.accuracy, Some((1, 500, 100)));
    let width = 1_500_100_000;
    assert_eq!(parts(verified.earliest()), moved(&verified, -width));
    assert_eq!(parts(verified.latest()), moved(&verified, width));

    let token = vector("forged-accuracy-max.tst");
    let verified = pin.verify(&token, &imprint).unwrap();
    let accuracy = verified.accuracy().unwrap();
    assert_eq!(
        (accuracy.seconds(), accuracy.millis(), accuracy.micros()),
        (MAX_ACCURACY_SECONDS, 500, 100)
    );
    let width = 3_600_500_100_000;
    assert_eq!(parts(verified.earliest()), moved(&verified, -width));
    assert_eq!(parts(verified.latest()), moved(&verified, width));

    // No accuracy in the token: the interval is genTime alone.
    let plain = manifest("manifest.txt")
        .into_iter()
        .find(|e| e.token == "rsa2048-sha256.tst")
        .unwrap();
    assert_eq!(plain.accuracy, None);
    let token = vector(&plain.token);
    let verified = Pin::for_token(&plain, true)
        .verify(&token, &imprint_of(plain.imprint))
        .unwrap();
    assert_eq!(verified.earliest(), Some(verified.gen_time()));
    assert_eq!(verified.latest(), Some(verified.gen_time()));
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
