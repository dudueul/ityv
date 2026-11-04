//! One token per rule (verification ladder V1): every `TsaError` variant a
//! token can produce is listed with one test token that breaks that rule
//! and no other, and the token is refused with exactly that variant.
//!
//! The tokens are the vectors of `tests/vectors` (`make.sh`, `forge.py`):
//! crafted variants of `rsa3072-sha384.tst`, tokens OpenSSL made that are
//! refused whatever the pin, and valid tokens under a pin or an expected
//! imprint that does not match them. The list is written by a macro that
//! also writes an exhaustive `match` over `TsaError`, so a new variant does
//! not compile until it is listed here. The variants no token can produce
//! (the pin's bytes, the caller's imprint, the pin encoder's buffer) are
//! listed apart; the `pin` and `alg` unit tests cover them. `Der(_)`
//! is one variant with its own list in `tests/strict.rs` and the `der` unit
//! tests.
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
    Pin, embedded_certificates, forged_base, imprint_of, manifest, permissive, sha256, vector,
};
use ityv_tsa::{DerError, DigestAlgorithm, Imprint, MAX_TOKEN_LEN, SignatureAlgorithm, TsaError};

/// Verifies one test token as its rule needs.
type Check = fn() -> Result<(), TsaError>;

/// The base's narrowest pin, without the certificate.
fn base_pin() -> Pin {
    Pin::for_token(&forged_base(), false)
}

fn sha512() -> Imprint {
    imprint_of(DigestAlgorithm::Sha512)
}

/// `token` (a file under `tests/vectors`) under `pin` and `imprint`.
fn verify(token: &str, pin: &Pin, imprint: &Imprint) -> Result<(), TsaError> {
    pin.verify(&vector(token), imprint).map(drop)
}

/// The crafted variant `name` of the base, under the base's pin.
fn forged(name: &str) -> Result<(), TsaError> {
    verify(&std::format!("{name}.tst"), &base_pin(), &sha512())
}

/// The crafted variant `name`, which embeds another certificate for the
/// base's key, under the base's pin for that certificate.
fn forged_certificate(name: &str) -> Result<(), TsaError> {
    let token = std::format!("{name}.tst");
    let embedded = embedded_certificates(&vector(&token));
    assert_eq!(embedded.len(), 1, "{name}");
    let pin = Pin {
        certificate_sha256: sha256(&embedded[0]),
        ..base_pin()
    };
    verify(&token, &pin, &sha512())
}

/// The base token, unchanged, under the base's pin changed by `edit`.
fn base_under(edit: fn(&mut Pin), imprint: &Imprint) -> Result<(), TsaError> {
    let mut pin = base_pin();
    edit(&mut pin);
    verify("rsa3072-sha384.tst", &pin, imprint)
}

macro_rules! rules {
    (
        tokens { $($variant:ident => $check:expr,)* }
        not_token_rules { $($other:ident,)* }
    ) => {
        /// The variants a token can produce, each with its check.
        fn token_rules() -> std::vec::Vec<(TsaError, Check)> {
            std::vec![$({
                let check: Check = $check;
                (TsaError::$variant, check)
            },)*]
        }

        /// The variants only a pin or the caller can produce.
        fn other_rules() -> std::vec::Vec<TsaError> {
            std::vec![$(TsaError::$other,)*]
        }

        /// Exhaustive over `TsaError`: a variant missing from both lists
        /// does not compile, and one in both is an unreachable pattern.
        const fn is_listed(error: TsaError) -> bool {
            match error {
                TsaError::Der(_) => false,
                $(TsaError::$variant => true,)*
                $(TsaError::$other => true,)*
            }
        }
    };
}

rules! {
tokens {
    TokenTooLarge => || {
        let mut big = vector("rsa3072-sha384.tst");
        big.resize(MAX_TOKEN_LEN + 1, 0);
        base_pin().verify(&big, &sha512()).map(drop)
    },
    NotSignedData => || forged("forged-not-signed-data"),
    SignedDataVersion => || forged("forged-signed-data-version"),
    DigestAlgorithmSet => || forged("forged-digest-set-other"),
    NotTstInfo => || forged("forged-not-tst-info"),
    MissingContent => || forged("forged-detached"),
    TooManyCertificates => || forged("forged-nine-certs"),
    UnsupportedCertificateChoice => || forged("forged-cert-choice"),
    CrlsPresent => || forged("forged-crls"),
    SignerCount => || forged("forged-two-signers"),
    SignerInfoVersion => || forged("forged-sid-keyid-v1"),
    MissingSignedAttributes => || forged("forged-no-signed-attrs"),
    AttributeValueCount => || forged("forged-attr-two-values"),
    DuplicateAttribute => || forged("forged-duplicate-attr"),
    MissingContentType => || forged("forged-no-content-type"),
    ContentTypeMismatch => || forged("forged-content-type"),
    MissingMessageDigest => || forged("forged-no-message-digest"),
    MessageDigestMismatch => || forged("forged-stale-digest"),
    MissingSigningCertificate => || forged("forged-no-ess"),
    SigningCertificateV1NotAllowed => || forged("forged-ess-v1-and-v2"),
    SigningCertificateMismatch => || forged("forged-ess-hash"),
    SigningCertificateIssuerMismatch => || forged("forged-ess-issuer-bad"),
    CertificateNotPinned => || {
        base_under(
            |pin| pin.certificate_sha256 = sha256(&vector("rsa2048.crt")),
            &sha512(),
        )
    },
    CertificateVersion => || forged_certificate("forged-cert-version"),
    CertificateCriticalExtension => || forged_certificate("forged-cert-critical-ext"),
    DuplicateExtension => || forged_certificate("forged-cert-duplicate-ext"),
    EmptyExtensions => || forged("forged-tst-ext-empty"),
    MissingTimestampingEku => || forged_certificate("forged-no-eku"),
    EkuNotCritical => || forged_certificate("forged-eku-noncritical"),
    EkuNotTimestampingOnly => || forged_certificate("forged-eku-two"),
    InvalidKeyUsage => || forged_certificate("forged-key-usage-sign"),
    SignerIsCa => || forged_certificate("forged-ca"),
    SignerIdentifierMismatch => || forged("forged-sid-serial"),
    OutsideValidity => || forged("forged-outside-validity"),
    UnsupportedPublicKey => || forged_certificate("forged-cert-pss-key"),
    RsaModulusSize => || {
        verify("rsa1024-sha256.tst", &permissive("rsa1024.crt"), &sha512())
    },
    RsaModulusEven => || forged_certificate("forged-cert-modulus-even"),
    RsaExponent => || forged_certificate("forged-cert-exponent-3"),
    InvalidEcPoint => || forged_certificate("forged-cert-ec-point"),
    UnknownDigestAlgorithm => || {
        verify("rsa2048-imprint1.tst", &permissive("rsa2048.crt"), &sha512())
    },
    DigestNotAllowed => || {
        base_under(|pin| pin.digests &= !DigestAlgorithm::Sha512.bit(), &sha512())
    },
    UnknownSignatureAlgorithm => || forged("forged-pss-alg"),
    SignatureDigestMismatch => || forged("forged-alg-mismatch"),
    UnsupportedSignatureAlgorithm => || {
        verify("p256-sha384.tst", &permissive("p256.crt"), &sha512())
    },
    SignatureNotAllowed => || {
        base_under(
            |pin| pin.signatures = SignatureAlgorithm::RsaPkcs1Sha256.bit(),
            &sha512(),
        )
    },
    RsaSignatureLength => || forged("forged-rsa-sig-short"),
    RsaSignatureOutOfRange => || forged("forged-rsa-sig-modulus"),
    EcdsaSignatureEncoding => || {
        let p256 = manifest("manifest.txt")
            .into_iter()
            .find(|e| e.token == "p256-sha256.tst")
            .unwrap();
        verify("forged-p256-zero-r.tst", &Pin::for_token(&p256, false), &sha512())
    },
    SignatureInvalid => || forged("forged-signature-flipped"),
    TstInfoVersion => || forged("forged-tst-version"),
    SerialTooLarge => || forged("forged-serial-21"),
    NonceTooLarge => || forged("forged-nonce-33"),
    InvalidAccuracy => || forged("forged-accuracy-millis-zero"),
    AccuracyTooLarge => || forged("forged-accuracy-over"),
    CriticalExtension => || forged("forged-critical-ext"),
    ImprintAlgorithmMismatch => || {
        base_under(|_| {}, &imprint_of(DigestAlgorithm::Sha256))
    },
    ImprintMismatch => || {
        base_under(|_| {}, &Imprint::of(DigestAlgorithm::Sha512, b"other data"))
    },
    PolicyNotAllowed => || {
        base_under(|pin| pin.policies = std::vec!["1.2.3.4.2".into()], &sha512())
    },
    TsaNameMismatch => || forged("forged-tsa-name"),
}
not_token_rules {
    ImprintLength,
    PinVersion,
    PinLength,
    PinDigests,
    PinSignatures,
    PinFlags,
    PinPolicies,
    PinCertificate,
    PinBufferTooSmall,
}
}

#[test]
fn every_rule_a_token_can_break_has_its_own_token() {
    let tokens = token_rules();
    assert_eq!(tokens.len(), 59);
    for (rule, check) in tokens {
        assert!(is_listed(rule));
        assert_eq!(check(), Err(rule), "{rule}");
    }
    assert!(other_rules().into_iter().all(is_listed));
    // And one of the DER subset's rules, for `Der(_)` itself.
    assert_eq!(
        forged("forged-bool-01"),
        Err(TsaError::Der(DerError::InvalidBoolean))
    );
}
