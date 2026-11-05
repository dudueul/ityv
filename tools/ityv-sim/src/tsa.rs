//! Two simulated timestamp authorities (ADR-0034, ADR-0039): one the
//! government runs and one it does not, each a P-256 key derived from a
//! label and the generator seed like every other key here, a self-signed
//! certificate with the critical `timeStamping` extended key usage, and
//! RFC 3161 tokens in the shape `ityv-tsa` accepts (CMS `SignedData` with
//! one `SignerInfo`, signed attributes `contentType`, `messageDigest` and
//! `signingCertificateV2`, a `TSTInfo` over the SHA-512 of a ledger
//! event's object hash).
//!
//! ECDSA signing is deterministic (RFC 6979), so two runs give the same
//! tokens. The keys are the simulator's own, derived from its public
//! seed: these authorities are fictional and their tokens prove nothing
//! outside a simulated election.

use ityv_encoding::{
    AuthorityId, ElectionId, Hash512, OrgId, PolicyAccuracy, SCHEMA_TIMESTAMP_RECORD, SchemaId,
    TimestampAuthorityEntry, TimestampAuthorityKind, TimestampPins, TimestampRecord,
    TimestampRecordParts,
};
use ityv_tsa::{DigestAlgorithm, DigestSet, PinnedTsa, SignatureAlgorithm, SignatureSet};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use sha2::Digest as _;

use crate::election::EPOCH_DAY;
use crate::util::{digest, leak_slice, object};

/// The policy every simulated token names (1.2.3.4.1), as a DER OID.
const POLICY: [u8; 6] = [0x06, 0x04, 0x2A, 0x03, 0x04, 0x01];

const OID_SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
const OID_TST_INFO: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
const OID_ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_PRIME256V1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_CONTENT_TYPE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03];
const OID_MESSAGE_DIGEST: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];
const OID_SIGNING_CERTIFICATE_V2: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F,
];
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x25];
const OID_TIME_STAMPING: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];

/// One simulated authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authority {
    /// Its identifier in the genesis and in timestamp records.
    pub id: &'static str,
    /// Its operator.
    pub operator: &'static str,
    /// Whether the government runs it.
    pub kind: TimestampAuthorityKind,
}

/// The government-run authority.
pub const GOV: Authority = Authority {
    id: "TSA-GOV-SIM",
    operator: "GOV-PKI-SIM",
    kind: TimestampAuthorityKind::Government,
};

/// The authority outside the government.
pub const FREE: Authority = Authority {
    id: "TSA-FREE-SIM",
    operator: "FREE-TSA-SIM",
    kind: TimestampAuthorityKind::NonGovernment,
};

/// Both authorities, government first.
pub const AUTHORITIES: [Authority; 2] = [GOV, FREE];

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        let len = u16::try_from(len).unwrap();
        out.push(0x82);
        out.extend_from_slice(&len.to_be_bytes());
    }
    out.extend_from_slice(content);
    out
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn seq(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x30, &cat(parts))
}

fn set(parts: &[&[u8]]) -> Vec<u8> {
    tlv(0x31, &cat(parts))
}

fn oid(content: &[u8]) -> Vec<u8> {
    tlv(0x06, content)
}

fn octets(content: &[u8]) -> Vec<u8> {
    tlv(0x04, content)
}

/// A non-negative `INTEGER` of big-endian `value`, minimal.
fn unsigned(value: &[u8]) -> Vec<u8> {
    let first = value
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(value.len() - 1);
    let mut content = value[first..].to_vec();
    if content[0] & 0x80 != 0 {
        content.insert(0, 0);
    }
    tlv(0x02, &content)
}

fn algorithm(id: &[u8], null: bool) -> Vec<u8> {
    if null {
        seq(&[&oid(id), &[0x05, 0x00]])
    } else {
        seq(&[&oid(id)])
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

/// The DER `Ecdsa-Sig-Value` of `key`'s signature over `message`.
fn ecdsa(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    let signature: Signature = key.sign(message);
    let bytes = signature.to_bytes();
    seq(&[&unsigned(&bytes[..32]), &unsigned(&bytes[32..])])
}

/// `YYYYMMDDhhmmss` of Unix time `seconds` (civil from days, H. Hinnant).
fn civil(seconds: u64) -> String {
    let days = i64::try_from(seconds / 86_400).unwrap();
    let rem = seconds % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}{:02}{:02}{:02}",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

/// An authority's key, certificate and pin.
struct Signer {
    key: SigningKey,
    name: Vec<u8>,
    serial: Vec<u8>,
    certificate: Vec<u8>,
    pin: Vec<u8>,
}

fn signer(a: Authority) -> Signer {
    let mut counter = 0u8;
    let key = loop {
        let seed = digest("tsa-key", &[a.id.as_bytes(), &[counter]]);
        if let Ok(key) = SigningKey::from_slice(&seed[..32]) {
            break key;
        }
        counter += 1;
    };
    let name = seq(&[&set(&[&seq(&[
        &oid(OID_COMMON_NAME),
        &tlv(0x0C, a.id.as_bytes()),
    ])])]);
    let mut serial = digest("tsa-serial", &[a.id.as_bytes()])[..16].to_vec();
    serial[0] = (serial[0] & 0x7F) | 0x01;
    let point = key.verifying_key().to_sec1_point(false);
    let mut bits = vec![0u8];
    bits.extend_from_slice(point.as_bytes());
    let spki = seq(&[
        &seq(&[&oid(OID_EC_PUBLIC_KEY), &oid(OID_PRIME256V1)]),
        &tlv(0x03, &bits),
    ]);
    let eku = seq(&[
        &oid(OID_EXT_KEY_USAGE),
        &[0x01, 0x01, 0xFF],
        &octets(&seq(&[&oid(OID_TIME_STAMPING)])),
    ]);
    let tbs = seq(&[
        &tlv(0xA0, &unsigned(&[2])),
        &unsigned(&serial),
        &algorithm(OID_ECDSA_SHA256, false),
        &name,
        &seq(&[&tlv(0x17, b"200101000000Z"), &tlv(0x17, b"491231235959Z")]),
        &name,
        &spki,
        &tlv(0xA3, &seq(&[&eku])),
    ]);
    let mut signature = vec![0u8];
    signature.extend_from_slice(&ecdsa(&key, &tbs));
    let certificate = seq(&[
        &tbs,
        &algorithm(OID_ECDSA_SHA256, false),
        &tlv(0x03, &signature),
    ]);
    let digests =
        DigestSet::from_bits(DigestAlgorithm::Sha256.bit() | DigestAlgorithm::Sha512.bit())
            .unwrap();
    let signatures = SignatureSet::from_bits(SignatureAlgorithm::EcdsaP256Sha256.bit()).unwrap();
    let pinned = PinnedTsa::new(
        sha256(&certificate),
        digests,
        signatures,
        false,
        &POLICY,
        None,
    )
    .unwrap();
    let mut pin = vec![0u8; pinned.encoded_len()];
    let len = pinned.encode(&mut pin).unwrap();
    pin.truncate(len);
    Signer {
        key,
        name,
        serial,
        certificate,
        pin,
    }
}

/// The genesis entries of both authorities (set 12): policy accuracy 0,
/// one pin each.
#[must_use]
pub fn authorities() -> Vec<TimestampAuthorityEntry<'static>> {
    AUTHORITIES
        .iter()
        .map(|a| {
            let pin = leak_slice(signer(*a).pin);
            TimestampAuthorityEntry {
                tsa_id: AuthorityId::new(a.id.as_bytes()).unwrap(),
                operator: OrgId::new(a.operator.as_bytes()).unwrap(),
                kind: a.kind,
                policy_accuracy: PolicyAccuracy::from_millis(0).unwrap(),
                pins: TimestampPins::new(&[pin]).unwrap(),
            }
        })
        .collect()
}

/// `a`'s token over the ledger event with object hash `target`, issued
/// at Unix time `seconds`, serial `serial`.
#[must_use]
pub fn token(a: Authority, target: &Hash512, seconds: u64, serial: u64) -> Vec<u8> {
    let s = signer(a);
    let imprint: [u8; 64] = sha2::Sha512::digest(target.as_bytes()).into();
    let mut generalized = civil(seconds).into_bytes();
    generalized.push(b'Z');
    let tst = seq(&[
        &unsigned(&[1]),
        &POLICY,
        &seq(&[&algorithm(OID_SHA512, true), &octets(&imprint)]),
        &unsigned(&serial.to_be_bytes()),
        &tlv(0x18, &generalized),
    ]);
    let mut attributes = [
        seq(&[&oid(OID_CONTENT_TYPE), &set(&[&oid(OID_TST_INFO)])]),
        seq(&[&oid(OID_MESSAGE_DIGEST), &set(&[&octets(&sha256(&tst))])]),
        seq(&[
            &oid(OID_SIGNING_CERTIFICATE_V2),
            &set(&[&seq(&[&seq(&[&seq(&[&octets(&sha256(&s.certificate))])])])]),
        ]),
    ];
    attributes.sort();
    let attributes = cat(&[&attributes[0], &attributes[1], &attributes[2]]);
    let signature = ecdsa(&s.key, &tlv(0x31, &attributes));
    let signer_info = seq(&[
        &unsigned(&[1]),
        &seq(&[&s.name, &unsigned(&s.serial)]),
        &algorithm(OID_SHA256, true),
        &tlv(0xA0, &attributes),
        &algorithm(OID_ECDSA_SHA256, false),
        &octets(&signature),
    ]);
    let signed_data = seq(&[
        &unsigned(&[3]),
        &set(&[&algorithm(OID_SHA256, true)]),
        &seq(&[&oid(OID_TST_INFO), &tlv(0xA0, &octets(&tst))]),
        &tlv(0xA0, &s.certificate),
        &set(&[&signer_info]),
    ]);
    seq(&[&oid(OID_SIGNED_DATA), &tlv(0xA0, &signed_data)])
}

/// Unix seconds a minute into time bucket `bucket` of the election.
#[must_use]
pub const fn in_bucket(bucket: u64) -> u64 {
    EPOCH_DAY * 86_400 + bucket * 900 + 60
}

/// The `TimestampRecord` of `a`'s token over the event `target` of schema
/// `schema`, issued a minute into `bucket`.
#[must_use]
pub fn record(
    election: ElectionId<'static>,
    a: Authority,
    schema: SchemaId,
    target: &Hash512,
    bucket: u64,
    serial: u64,
) -> &'static [u8] {
    let token = leak_slice(token(a, target, in_bucket(bucket), serial));
    let record = TimestampRecord::new(&TimestampRecordParts {
        election_id: election,
        target_schema: schema,
        target_hash: *target,
        authority_id: AuthorityId::new(a.id.as_bytes()).unwrap(),
        token: Some(token),
    })
    .unwrap();
    object(SCHEMA_TIMESTAMP_RECORD, &record)
}

#[cfg(test)]
mod tests {
    use ityv_tsa::{Imprint, verify_token};

    use super::*;

    #[test]
    fn a_token_verifies_under_its_authority_s_pin() {
        let target = Hash512([0x42; 64]);
        let seconds = in_bucket(300);
        for a in AUTHORITIES {
            let s = signer(a);
            let pin = PinnedTsa::from_bytes(&s.pin).unwrap();
            let token = token(a, &target, seconds, 7);
            let imprint = Imprint::of(DigestAlgorithm::Sha512, target.as_bytes());
            let verified = verify_token(&token, &pin, &imprint).unwrap();
            assert_eq!(verified.gen_time().unix_seconds(), seconds);
            // Deterministic: the same inputs give the same bytes.
            assert_eq!(super::token(a, &target, seconds, 7), token);
        }
        assert_eq!(civil(0), "19700101000000");
        assert_eq!(civil(951_782_400), "20000229000000");
        assert_eq!(civil(1_793_806_620), "20261104153700");
    }
}
