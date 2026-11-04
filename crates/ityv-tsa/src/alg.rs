//! Digest and signature algorithms, the sets a pin allows, and the imprint.

use crate::der::{self, Reader};
use crate::error::{DerError, TsaError};
use crate::oid;
use sha2::Digest as _;

/// A digest algorithm a token may use for its imprint, its `SignerInfo` or
/// its ESS signing-certificate v2 hash.
///
/// SHA-1 is not one of them: it appears only inside an ESS v1 attribute, and
/// only when the pin allows it ([`PinnedTsa::allows_ess_v1`](crate::PinnedTsa::allows_ess_v1)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DigestAlgorithm {
    /// SHA-256 (FIPS 180-4), `id-sha256`.
    Sha256,
    /// SHA-384 (FIPS 180-4), `id-sha384`.
    Sha384,
    /// SHA-512 (FIPS 180-4), `id-sha512`.
    Sha512,
}

impl DigestAlgorithm {
    /// The digest length in octets.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// The bit of this algorithm in a pin's digest mask.
    #[must_use]
    pub const fn bit(self) -> u8 {
        match self {
            Self::Sha256 => 0x01,
            Self::Sha384 => 0x02,
            Self::Sha512 => 0x04,
        }
    }

    fn from_oid(content: &[u8]) -> Option<Self> {
        match content {
            oid::SHA256 => Some(Self::Sha256),
            oid::SHA384 => Some(Self::Sha384),
            oid::SHA512 => Some(Self::Sha512),
            _ => None,
        }
    }

    /// The DER `DigestInfo` prefix of EMSA-PKCS1-v1_5 (RFC 8017 §9.2 note 1),
    /// with the `NULL` parameters RFC 8017 Appendix A.2.4 requires.
    pub(crate) const fn digest_info_prefix(self) -> &'static [u8; 19] {
        match self {
            Self::Sha256 => &[
                0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x01, 0x05, 0x00, 0x04, 0x20,
            ],
            Self::Sha384 => &[
                0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x02, 0x05, 0x00, 0x04, 0x30,
            ],
            Self::Sha512 => &[
                0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                0x03, 0x05, 0x00, 0x04, 0x40,
            ],
        }
    }

    /// The digest of the concatenation of `parts`.
    pub(crate) fn digest(self, parts: &[&[u8]]) -> Digest {
        match self {
            Self::Sha256 => {
                let mut hasher = sha2::Sha256::new();
                for part in parts {
                    hasher.update(part);
                }
                Digest::from_output(&hasher.finalize())
            }
            Self::Sha384 => {
                let mut hasher = sha2::Sha384::new();
                for part in parts {
                    hasher.update(part);
                }
                Digest::from_output(&hasher.finalize())
            }
            Self::Sha512 => {
                let mut hasher = sha2::Sha512::new();
                for part in parts {
                    hasher.update(part);
                }
                Digest::from_output(&hasher.finalize())
            }
        }
    }
}

/// The SHA-256 of `data`, the hash that pins a certificate.
pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

/// The SHA-1 of `data`, for the ESS signing-certificate v1 binding only.
pub(crate) fn sha1(data: &[u8]) -> [u8; 20] {
    sha1::Sha1::digest(data).into()
}

/// A digest value of at most 64 octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Digest {
    octets: [u8; 64],
    len: usize,
}

impl Digest {
    fn from_output(output: &[u8]) -> Self {
        let mut octets = [0u8; 64];
        for (target, source) in octets.iter_mut().zip(output) {
            *target = *source;
        }
        Self {
            octets,
            len: output.len().min(64),
        }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.octets.get(..self.len).unwrap_or(&[])
    }
}

/// The digest algorithms a pin allows, as a bit mask of [`DigestAlgorithm::bit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DigestSet(u8);

impl DigestSet {
    const KNOWN: u8 = 0x07;

    /// The set with the bits of `mask`, if it is non-empty and has no unknown bits.
    #[must_use]
    pub const fn from_bits(mask: u8) -> Option<Self> {
        if mask != 0 && mask & !Self::KNOWN == 0 {
            Some(Self(mask))
        } else {
            None
        }
    }

    /// The bit mask.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Whether `algorithm` is in the set.
    #[must_use]
    pub const fn contains(self, algorithm: DigestAlgorithm) -> bool {
        self.0 & algorithm.bit() != 0
    }
}

/// A signature algorithm: the key type, the curve and the digest together.
///
/// For ECDSA the digest is at least as long as the curve order (FIPS 186-5
/// §6.4: the digest is truncated to the order's length); P-256 with SHA-384
/// or SHA-512 is not supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256 (RFC 8017 §8.2).
    RsaPkcs1Sha256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    RsaPkcs1Sha384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    RsaPkcs1Sha512,
    /// ECDSA on P-256 with SHA-256 (FIPS 186-5).
    EcdsaP256Sha256,
    /// ECDSA on P-384 with SHA-384.
    EcdsaP384Sha384,
    /// ECDSA on P-384 with SHA-512 (the digest truncated to 384 bits).
    EcdsaP384Sha512,
}

impl SignatureAlgorithm {
    /// The bit of this algorithm in a pin's signature mask.
    #[must_use]
    pub const fn bit(self) -> u8 {
        match self {
            Self::RsaPkcs1Sha256 => 0x01,
            Self::RsaPkcs1Sha384 => 0x02,
            Self::RsaPkcs1Sha512 => 0x04,
            Self::EcdsaP256Sha256 => 0x08,
            Self::EcdsaP384Sha384 => 0x10,
            Self::EcdsaP384Sha512 => 0x20,
        }
    }

    /// The digest this algorithm signs.
    #[must_use]
    pub const fn digest(self) -> DigestAlgorithm {
        match self {
            Self::RsaPkcs1Sha256 | Self::EcdsaP256Sha256 => DigestAlgorithm::Sha256,
            Self::RsaPkcs1Sha384 | Self::EcdsaP384Sha384 => DigestAlgorithm::Sha384,
            Self::RsaPkcs1Sha512 | Self::EcdsaP384Sha512 => DigestAlgorithm::Sha512,
        }
    }
}

/// The signature algorithms a pin allows, as a bit mask of [`SignatureAlgorithm::bit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignatureSet(u8);

impl SignatureSet {
    const KNOWN: u8 = 0x3F;

    /// The set with the bits of `mask`, if it is non-empty and has no unknown bits.
    #[must_use]
    pub const fn from_bits(mask: u8) -> Option<Self> {
        if mask != 0 && mask & !Self::KNOWN == 0 {
            Some(Self(mask))
        } else {
            None
        }
    }

    /// The bit mask.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Whether `algorithm` is in the set.
    #[must_use]
    pub const fn contains(self, algorithm: SignatureAlgorithm) -> bool {
        self.0 & algorithm.bit() != 0
    }
}

/// The signature algorithm a `SignerInfo` names, before the key is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignatureFamily {
    /// `rsaEncryption` or `sha*WithRSAEncryption`.
    Rsa,
    /// `ecdsa-with-SHA*`.
    Ecdsa,
}

/// Reads an `AlgorithmIdentifier` and returns its algorithm and parameters.
fn algorithm_identifier<'a>(
    reader: &mut Reader<'a>,
) -> Result<(&'a [u8], Option<der::Tlv<'a>>), DerError> {
    let mut inner = reader.sequence()?;
    let algorithm = inner.oid()?;
    let parameters = if inner.is_empty() {
        None
    } else {
        Some(inner.checked_any()?)
    };
    inner.finish()?;
    Ok((algorithm, parameters))
}

/// Whether `parameters` are absent or `NULL` (RFC 5754 §2 for SHA-2, §3.2 for RSA).
fn absent_or_null(parameters: Option<der::Tlv<'_>>) -> bool {
    parameters.is_none_or(|tlv| tlv.tag == der::NULL)
}

/// Reads a digest `AlgorithmIdentifier`: SHA-256, SHA-384 or SHA-512 with
/// absent or `NULL` parameters (RFC 5754 §2 requires accepting both).
pub(crate) fn read_digest_algorithm(reader: &mut Reader<'_>) -> Result<DigestAlgorithm, TsaError> {
    let (algorithm, parameters) = algorithm_identifier(reader)?;
    match DigestAlgorithm::from_oid(algorithm) {
        Some(digest) if absent_or_null(parameters) => Ok(digest),
        Some(_) | None => Err(TsaError::UnknownDigestAlgorithm),
    }
}

/// Reads the `AlgorithmIdentifier` of an ESS v2 `hashAlgorithm` field, if
/// present. Absent means SHA-256 (RFC 5035 §5.4.1.1); SHA-256 written out is
/// a `DEFAULT` value DER omits.
pub(crate) fn read_ess_hash_algorithm(
    reader: &mut Reader<'_>,
) -> Result<DigestAlgorithm, TsaError> {
    if reader.peek_tag() != Some(der::SEQUENCE) {
        return Ok(DigestAlgorithm::Sha256);
    }
    match read_digest_algorithm(reader)? {
        DigestAlgorithm::Sha256 => Err(TsaError::Der(DerError::DefaultEncoded)),
        other @ (DigestAlgorithm::Sha384 | DigestAlgorithm::Sha512) => Ok(other),
    }
}

/// Reads a `SignerInfo` `signatureAlgorithm`. The `sha*WithRSAEncryption`
/// and `ecdsa-with-SHA*` forms must name `digest`, the `SignerInfo` digest
/// algorithm; `rsaEncryption` (RFC 3370 §3.2) takes it from there.
/// RSA parameters are absent or `NULL` (RFC 5754 §3.2); ECDSA parameters are
/// absent (RFC 5758 §3.2).
pub(crate) fn read_signature_algorithm(
    reader: &mut Reader<'_>,
    digest: DigestAlgorithm,
) -> Result<SignatureFamily, TsaError> {
    let (algorithm, parameters) = algorithm_identifier(reader)?;
    let (family, named) = match algorithm {
        oid::RSA_ENCRYPTION => (SignatureFamily::Rsa, None),
        oid::SHA256_WITH_RSA => (SignatureFamily::Rsa, Some(DigestAlgorithm::Sha256)),
        oid::SHA384_WITH_RSA => (SignatureFamily::Rsa, Some(DigestAlgorithm::Sha384)),
        oid::SHA512_WITH_RSA => (SignatureFamily::Rsa, Some(DigestAlgorithm::Sha512)),
        oid::ECDSA_SHA256 => (SignatureFamily::Ecdsa, Some(DigestAlgorithm::Sha256)),
        oid::ECDSA_SHA384 => (SignatureFamily::Ecdsa, Some(DigestAlgorithm::Sha384)),
        oid::ECDSA_SHA512 => (SignatureFamily::Ecdsa, Some(DigestAlgorithm::Sha512)),
        _ => return Err(TsaError::UnknownSignatureAlgorithm),
    };
    let parameters_ok = match family {
        SignatureFamily::Rsa => absent_or_null(parameters),
        SignatureFamily::Ecdsa => parameters.is_none(),
    };
    if !parameters_ok {
        return Err(TsaError::UnknownSignatureAlgorithm);
    }
    if named.is_some_and(|named| named != digest) {
        return Err(TsaError::SignatureDigestMismatch);
    }
    Ok(family)
}

/// The expected message imprint: a digest algorithm and the digest of the
/// timestamped data.
///
/// ADR-0034 §3: the data is the 64-octet checkpoint object hash and the
/// algorithm is SHA-512, so the imprint is `Imprint::of(Sha512, &object_hash)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Imprint {
    algorithm: DigestAlgorithm,
    digest: Digest,
}

impl Imprint {
    /// An imprint from a digest the caller computed.
    ///
    /// # Errors
    ///
    /// [`TsaError::ImprintLength`] if `digest` is not
    /// [`DigestAlgorithm::output_len`] octets.
    pub fn new(algorithm: DigestAlgorithm, digest: &[u8]) -> Result<Self, TsaError> {
        if digest.len() == algorithm.output_len() {
            Ok(Self {
                algorithm,
                digest: Digest::from_output(digest),
            })
        } else {
            Err(TsaError::ImprintLength)
        }
    }

    /// The imprint of `data`: its digest under `algorithm`.
    #[must_use]
    pub fn of(algorithm: DigestAlgorithm, data: &[u8]) -> Self {
        Self {
            algorithm,
            digest: algorithm.digest(&[data]),
        }
    }

    /// The digest algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }

    /// The digest octets.
    #[must_use]
    pub fn digest(&self) -> &[u8] {
        self.digest.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_match_known_answers() {
        // FIPS 180-4 examples for "abc".
        let abc = DigestAlgorithm::Sha256.digest(&[b"a", b"bc"]);
        assert_eq!(
            abc.as_slice()[..4],
            [0xBA, 0x78, 0x16, 0xBF],
            "SHA-256(abc) starts ba7816bf"
        );
        assert_eq!(abc.as_slice().len(), 32);
        let abc = DigestAlgorithm::Sha384.digest(&[b"abc"]);
        assert_eq!(abc.as_slice()[..4], [0xCB, 0x00, 0x75, 0x3F]);
        assert_eq!(abc.as_slice().len(), 48);
        let abc = DigestAlgorithm::Sha512.digest(&[b"ab", b"c"]);
        assert_eq!(abc.as_slice()[..4], [0xDD, 0xAF, 0x35, 0xA1]);
        assert_eq!(abc.as_slice().len(), 64);
        assert_eq!(sha256(b"abc")[..4], [0xBA, 0x78, 0x16, 0xBF]);
        assert_eq!(sha1(b"abc")[..4], [0xA9, 0x99, 0x3E, 0x36]);
        for digest in [
            DigestAlgorithm::Sha256,
            DigestAlgorithm::Sha384,
            DigestAlgorithm::Sha512,
        ] {
            assert_eq!(digest.digest(&[b""]).as_slice().len(), digest.output_len());
            let prefix = digest.digest_info_prefix();
            assert_eq!(usize::from(prefix[18]), digest.output_len());
            assert_eq!(
                usize::from(prefix[1]),
                digest.output_len().checked_add(17).unwrap()
            );
        }
    }

    #[test]
    fn sets_refuse_unknown_bits() {
        assert_eq!(DigestSet::from_bits(0), None);
        assert_eq!(DigestSet::from_bits(0x08), None);
        assert_eq!(DigestSet::from_bits(0x07).map(DigestSet::bits), Some(0x07));
        let set = DigestSet::from_bits(0x05).unwrap();
        assert!(set.contains(DigestAlgorithm::Sha256));
        assert!(!set.contains(DigestAlgorithm::Sha384));
        assert!(set.contains(DigestAlgorithm::Sha512));
        assert_eq!(SignatureSet::from_bits(0), None);
        assert_eq!(SignatureSet::from_bits(0x40), None);
        assert_eq!(
            SignatureSet::from_bits(0x3F).map(SignatureSet::bits),
            Some(0x3F)
        );
        let set = SignatureSet::from_bits(0x21).unwrap();
        assert!(set.contains(SignatureAlgorithm::RsaPkcs1Sha256));
        assert!(set.contains(SignatureAlgorithm::EcdsaP384Sha512));
        assert!(!set.contains(SignatureAlgorithm::EcdsaP384Sha384));
        let all = [
            SignatureAlgorithm::RsaPkcs1Sha256,
            SignatureAlgorithm::RsaPkcs1Sha384,
            SignatureAlgorithm::RsaPkcs1Sha512,
            SignatureAlgorithm::EcdsaP256Sha256,
            SignatureAlgorithm::EcdsaP384Sha384,
            SignatureAlgorithm::EcdsaP384Sha512,
        ];
        let mask = all.iter().fold(0u8, |mask, alg| mask | alg.bit());
        assert_eq!(mask, 0x3F);
        assert_eq!(
            all.map(SignatureAlgorithm::digest),
            [
                DigestAlgorithm::Sha256,
                DigestAlgorithm::Sha384,
                DigestAlgorithm::Sha512,
                DigestAlgorithm::Sha256,
                DigestAlgorithm::Sha384,
                DigestAlgorithm::Sha512,
            ]
        );
    }

    #[test]
    fn imprints() {
        assert_eq!(
            Imprint::new(DigestAlgorithm::Sha512, &[0; 32]),
            Err(TsaError::ImprintLength)
        );
        let imprint = Imprint::new(DigestAlgorithm::Sha256, &[7; 32]).unwrap();
        assert_eq!(imprint.digest(), &[7; 32]);
        assert_eq!(imprint.algorithm(), DigestAlgorithm::Sha256);
        let of = Imprint::of(DigestAlgorithm::Sha512, b"abc");
        assert_eq!(of.digest()[..4], [0xDD, 0xAF, 0x35, 0xA1]);
        assert_eq!(
            of,
            Imprint::new(DigestAlgorithm::Sha512, of.digest()).unwrap()
        );
    }

    fn digest_of(bytes: &[u8]) -> Result<DigestAlgorithm, TsaError> {
        let mut reader = Reader::new(bytes);
        let result = read_digest_algorithm(&mut reader);
        assert!(result.is_err() || reader.is_empty());
        result
    }

    #[test]
    fn digest_identifiers() {
        let sha256_null = [
            0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00,
        ];
        let sha512_absent = [
            0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
        ];
        let sha384_int = [
            0x30, 0x0E, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x02,
            0x01, 0x00,
        ];
        let sha1 = [0x30, 0x07, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A];
        assert_eq!(digest_of(&sha256_null), Ok(DigestAlgorithm::Sha256));
        assert_eq!(digest_of(&sha512_absent), Ok(DigestAlgorithm::Sha512));
        assert_eq!(
            digest_of(&sha384_int),
            Err(TsaError::UnknownDigestAlgorithm)
        );
        assert_eq!(digest_of(&sha1), Err(TsaError::UnknownDigestAlgorithm));
        let mut reader = Reader::new(&sha256_null);
        assert_eq!(
            read_ess_hash_algorithm(&mut reader),
            Err(TsaError::Der(DerError::DefaultEncoded))
        );
        let mut reader = Reader::new(&sha512_absent);
        assert_eq!(
            read_ess_hash_algorithm(&mut reader),
            Ok(DigestAlgorithm::Sha512)
        );
        let mut reader = Reader::new(&[0x04, 0x00]);
        assert_eq!(
            read_ess_hash_algorithm(&mut reader),
            Ok(DigestAlgorithm::Sha256)
        );
        assert_eq!(reader.peek_tag(), Some(0x04));
    }

    fn signature_of(bytes: &[u8], digest: DigestAlgorithm) -> Result<SignatureFamily, TsaError> {
        read_signature_algorithm(&mut Reader::new(bytes), digest)
    }

    #[test]
    fn signature_identifiers() {
        let with_oid = |oid: &[u8], tail: &[u8]| {
            let mut out = std::vec![0x30, 0, 0x06, u8::try_from(oid.len()).unwrap()];
            out.extend_from_slice(oid);
            out.extend_from_slice(tail);
            out[1] = u8::try_from(out.len().checked_sub(2).unwrap()).unwrap();
            out
        };
        let s256 = DigestAlgorithm::Sha256;
        let s384 = DigestAlgorithm::Sha384;
        let s512 = DigestAlgorithm::Sha512;
        let null = [0x05, 0x00];
        assert_eq!(
            signature_of(&with_oid(oid::RSA_ENCRYPTION, &null), s384),
            Ok(SignatureFamily::Rsa)
        );
        assert_eq!(
            signature_of(&with_oid(oid::RSA_ENCRYPTION, &[]), s384),
            Ok(SignatureFamily::Rsa)
        );
        assert_eq!(
            signature_of(&with_oid(oid::SHA256_WITH_RSA, &null), s256),
            Ok(SignatureFamily::Rsa)
        );
        assert_eq!(
            signature_of(&with_oid(oid::SHA384_WITH_RSA, &null), s384),
            Ok(SignatureFamily::Rsa)
        );
        assert_eq!(
            signature_of(&with_oid(oid::SHA512_WITH_RSA, &[]), s512),
            Ok(SignatureFamily::Rsa)
        );
        assert_eq!(
            signature_of(&with_oid(oid::SHA256_WITH_RSA, &null), s512),
            Err(TsaError::SignatureDigestMismatch)
        );
        assert_eq!(
            signature_of(&with_oid(oid::SHA384_WITH_RSA, &null), s256),
            Err(TsaError::SignatureDigestMismatch)
        );
        assert_eq!(
            signature_of(&with_oid(oid::SHA512_WITH_RSA, &null), s384),
            Err(TsaError::SignatureDigestMismatch)
        );
        assert_eq!(
            signature_of(&with_oid(oid::RSA_ENCRYPTION, &[0x02, 0x01, 0x00]), s256),
            Err(TsaError::UnknownSignatureAlgorithm)
        );
        assert_eq!(
            signature_of(&with_oid(oid::ECDSA_SHA256, &[]), s256),
            Ok(SignatureFamily::Ecdsa)
        );
        assert_eq!(
            signature_of(&with_oid(oid::ECDSA_SHA384, &[]), s384),
            Ok(SignatureFamily::Ecdsa)
        );
        assert_eq!(
            signature_of(&with_oid(oid::ECDSA_SHA512, &[]), s512),
            Ok(SignatureFamily::Ecdsa)
        );
        assert_eq!(
            signature_of(&with_oid(oid::ECDSA_SHA256, &null), s256),
            Err(TsaError::UnknownSignatureAlgorithm)
        );
        assert_eq!(
            signature_of(&with_oid(oid::ECDSA_SHA384, &[]), s512),
            Err(TsaError::SignatureDigestMismatch)
        );
        assert_eq!(
            signature_of(&with_oid(oid::ECDSA_SHA512, &[]), s256),
            Err(TsaError::SignatureDigestMismatch)
        );
        assert_eq!(
            signature_of(&with_oid(oid::ECDSA_SHA256, &[]), s384),
            Err(TsaError::SignatureDigestMismatch)
        );
        assert_eq!(
            signature_of(&with_oid(oid::EC_PUBLIC_KEY, &[]), s256),
            Err(TsaError::UnknownSignatureAlgorithm)
        );
        assert_eq!(
            signature_of(&with_oid(oid::SHA256, &[]), s256),
            Err(TsaError::UnknownSignatureAlgorithm)
        );
        // Trailing content after the parameters.
        assert_eq!(
            signature_of(
                &with_oid(oid::RSA_ENCRYPTION, &[0x05, 0x00, 0x05, 0x00]),
                s256
            ),
            Err(TsaError::Der(DerError::TrailingData))
        );
    }
}
