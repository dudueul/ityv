//! Shared helpers for the integration tests: the fixtures of
//! `tests/vectors` (see `make.sh` there), the manifest OpenSSL wrote for
//! them, and pins. Test code is outside the TCB.
//!
//! This module is compiled into every test binary and each binary uses a
//! different subset of it, so `dead_code` is allowed here and nowhere else.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc
)]

use ityv_tsa::{
    CertificateSource, DigestAlgorithm, Imprint, PinnedTsa, SignatureAlgorithm, TsaError,
    VerifiedTimestamp, verify_token,
};
use sha2::Digest as _;
use std::path::PathBuf;
use std::string::{String, ToString};
use std::vec::Vec;

/// A file under `tests/vectors`.
pub(crate) fn vector(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The base of the crafted tokens (`forged-*.tst`, forge.py): the manifest
/// line of `rsa3072-sha384.tst`.
pub(crate) fn forged_base() -> Expected {
    manifest("manifest.txt")
        .into_iter()
        .find(|e| e.token == "rsa3072-sha384.tst")
        .unwrap()
}

/// The DER elements of a value: `(tag, value, whole encoding)` each. Test
/// tokens use one- and two-octet long lengths at most.
pub(crate) fn elements(mut value: &[u8]) -> Vec<(u8, &[u8], &[u8])> {
    let mut out = Vec::new();
    while !value.is_empty() {
        let (len, start) = match value[1] {
            short @ 0x00..=0x7F => (usize::from(short), 2),
            0x81 => (usize::from(value[2]), 3),
            0x82 => (usize::from(u16::from_be_bytes([value[2], value[3]])), 4),
            other => panic!("length form {other:02x}"),
        };
        out.push((value[0], &value[start..start + len], &value[..start + len]));
        value = &value[start + len..];
    }
    out
}

/// The certificates embedded in `token` (`SignedData.certificates`), in
/// token order.
pub(crate) fn embedded_certificates(token: &[u8]) -> Vec<Vec<u8>> {
    let content_info = elements(token)[0].1;
    let signed_data = elements(elements(content_info)[1].1)[0].1;
    elements(signed_data)
        .into_iter()
        .find(|(tag, _, _)| *tag == 0xA0)
        .map(|(_, certificates, _)| {
            elements(certificates)
                .into_iter()
                .map(|(_, _, raw)| raw.to_vec())
                .collect()
        })
        .unwrap_or_default()
}

/// A pin for the authority of `cert` (a file under `tests/vectors`) that
/// allows every digest, every signature algorithm and ESS v1: for tokens
/// refused whatever the pin.
pub(crate) fn permissive(cert: &str) -> Pin {
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

/// The expected imprint of every vector: SHA-512 of `object-hash.bin`.
pub(crate) fn imprint_of(algorithm: DigestAlgorithm) -> Imprint {
    Imprint::of(algorithm, &vector("object-hash.bin"))
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

/// The DER encoding (tag, length, content) of a dotted object identifier.
pub(crate) fn oid_der(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted.split('.').map(|arc| arc.parse().unwrap()).collect();
    let mut content = std::vec![u8::try_from(40 * arcs[0] + arcs[1]).unwrap()];
    for &arc in &arcs[2..] {
        let mut chunk = std::vec![u8::try_from(arc & 0x7F).unwrap()];
        let mut rest = arc >> 7;
        while rest > 0 {
            chunk.push(0x80 | u8::try_from(rest & 0x7F).unwrap());
            rest >>= 7;
        }
        chunk.reverse();
        content.extend_from_slice(&chunk);
    }
    let mut out = std::vec![0x06, u8::try_from(content.len()).unwrap()];
    out.extend_from_slice(&content);
    out
}

pub(crate) fn digest_named(name: &str) -> DigestAlgorithm {
    match name {
        "sha256" => DigestAlgorithm::Sha256,
        "sha384" => DigestAlgorithm::Sha384,
        "sha512" => DigestAlgorithm::Sha512,
        other => panic!("digest {other}"),
    }
}

pub(crate) fn signature_named(name: &str) -> SignatureAlgorithm {
    match name {
        "RsaPkcs1Sha256" => SignatureAlgorithm::RsaPkcs1Sha256,
        "RsaPkcs1Sha384" => SignatureAlgorithm::RsaPkcs1Sha384,
        "RsaPkcs1Sha512" => SignatureAlgorithm::RsaPkcs1Sha512,
        "EcdsaP256Sha256" => SignatureAlgorithm::EcdsaP256Sha256,
        "EcdsaP384Sha384" => SignatureAlgorithm::EcdsaP384Sha384,
        "EcdsaP384Sha512" => SignatureAlgorithm::EcdsaP384Sha512,
        other => panic!("signature {other}"),
    }
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// One line of a manifest: how a valid token was made and what OpenSSL reads in it.
#[derive(Debug, Clone)]
pub(crate) struct Expected {
    pub(crate) token: String,
    pub(crate) cert: String,
    pub(crate) signature: SignatureAlgorithm,
    pub(crate) imprint: DigestAlgorithm,
    /// The ESS hash: `None` for v1 (SHA-1), else the v2 algorithm.
    pub(crate) ess: Option<DigestAlgorithm>,
    pub(crate) seconds: u64,
    pub(crate) nanos: u32,
    pub(crate) serial: Vec<u8>,
    pub(crate) policy: String,
    pub(crate) nonce: Option<Vec<u8>>,
    pub(crate) accuracy: Option<(u64, u16, u16)>,
    pub(crate) ordering: bool,
}

/// The lines of `manifest` (a path under `tests/vectors`).
pub(crate) fn manifest(manifest: &str) -> Vec<Expected> {
    let text = String::from_utf8(vector(manifest)).unwrap();
    text.lines()
        .map(|line| {
            let mut words = line.split(' ');
            let token = words.next().unwrap().to_string();
            let fields: std::collections::BTreeMap<&str, &str> =
                words.map(|word| word.split_once('=').unwrap()).collect();
            let field = |key: &str| *fields.get(key).unwrap_or_else(|| panic!("{key}"));
            let directory = manifest.rsplit_once('/').map_or("", |(dir, _)| dir);
            let prefix = |name: &str| {
                if directory.is_empty() {
                    name.to_string()
                } else {
                    std::format!("{directory}/{name}")
                }
            };
            let serial = hex(field("serial"));
            let serial = serial.iter().skip_while(|b| **b == 0).copied().collect();
            Expected {
                token: prefix(&token),
                cert: prefix(field("cert")),
                signature: signature_named(field("signature")),
                imprint: digest_named(field("imprint")),
                ess: (field("ess") != "sha1").then(|| digest_named(field("ess"))),
                seconds: field("time").parse().unwrap(),
                nanos: field("nanos").parse().unwrap(),
                serial,
                policy: field("policy").to_string(),
                nonce: (field("nonce") != "-").then(|| {
                    hex(field("nonce"))
                        .into_iter()
                        .skip_while(|b| *b == 0)
                        .collect()
                }),
                accuracy: (field("accuracy") != "-").then(|| {
                    let parts: Vec<&str> = field("accuracy").split(',').collect();
                    (
                        parts[0].parse().unwrap(),
                        parts[1].parse().unwrap(),
                        parts[2].parse().unwrap(),
                    )
                }),
                ordering: field("ordering") == "yes",
            }
        })
        .collect()
}

/// A pin under construction, encoded through the public byte form.
#[derive(Debug, Clone)]
pub(crate) struct Pin {
    pub(crate) certificate_sha256: [u8; 32],
    pub(crate) digests: u8,
    pub(crate) signatures: u8,
    pub(crate) ess_v1: bool,
    pub(crate) policies: Vec<String>,
    pub(crate) certificate: Option<Vec<u8>>,
}

impl Pin {
    /// The narrowest pin for `expected`: its certificate's hash, exactly
    /// the digests and the signature algorithm it uses, its policy, and the
    /// certificate itself if `with_certificate`.
    pub(crate) fn for_token(expected: &Expected, with_certificate: bool) -> Self {
        let certificate = vector(&expected.cert);
        let digests = expected.imprint.bit()
            | expected.signature.digest().bit()
            | expected.ess.map_or(0, DigestAlgorithm::bit);
        Self {
            certificate_sha256: sha256(&certificate),
            digests,
            signatures: expected.signature.bit(),
            ess_v1: expected.ess.is_none(),
            policies: std::vec![expected.policy.clone()],
            certificate: with_certificate.then_some(certificate),
        }
    }

    /// The pin's byte form, as a genesis would hold it.
    pub(crate) fn bytes(&self) -> Vec<u8> {
        let mut policies: Vec<Vec<u8>> = self.policies.iter().map(|p| oid_der(p)).collect();
        policies.sort();
        let policies: Vec<u8> = policies.concat();
        let certificate = self.certificate.clone().unwrap_or_default();
        let mut out = std::vec![1u8];
        out.extend_from_slice(&self.certificate_sha256);
        out.extend_from_slice(&[self.digests, self.signatures, u8::from(self.ess_v1)]);
        out.extend_from_slice(&u16::try_from(policies.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&policies);
        out.extend_from_slice(&u16::try_from(certificate.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&certificate);
        out
    }

    /// Verifies `token` under this pin.
    pub(crate) fn verify<'t>(
        &self,
        token: &'t [u8],
        expected: &Imprint,
    ) -> Result<VerifiedTimestamp<'t>, TsaError> {
        let bytes = self.bytes();
        let pin = PinnedTsa::from_bytes(&bytes).expect("test pins are well formed");
        verify_token(token, &pin, expected)
    }
}

/// Checks a verified token against its manifest line.
pub(crate) fn check_result(
    expected: &Expected,
    verified: &VerifiedTimestamp<'_>,
    source: CertificateSource,
) {
    let name = &expected.token;
    assert_eq!(
        verified.gen_time().unix_seconds(),
        expected.seconds,
        "{name}"
    );
    assert_eq!(verified.gen_time().nanos(), expected.nanos, "{name}");
    assert_eq!(verified.serial(), &expected.serial[..], "{name}");
    assert_eq!(
        verified.policy().content(),
        &oid_der(&expected.policy)[2..],
        "{name}"
    );
    assert_eq!(
        verified.nonce().map(<[u8]>::to_vec),
        expected.nonce,
        "{name}"
    );
    assert_eq!(
        verified
            .accuracy()
            .map(|a| (a.seconds(), a.millis(), a.micros())),
        expected.accuracy,
        "{name}"
    );
    assert_eq!(verified.ordering(), expected.ordering, "{name}");
    assert_eq!(verified.signature_algorithm(), expected.signature, "{name}");
    assert_eq!(verified.imprint(), &imprint_of(expected.imprint), "{name}");
    assert_eq!(
        verified.certificate_sha256(),
        &sha256(&vector(&expected.cert)),
        "{name}"
    );
    assert_eq!(verified.certificate_source(), source, "{name}");
}
