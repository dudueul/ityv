//! The pin of one timestamp authority, in the byte form a genesis can hold.
//!
//! | Offset | Size | Field |
//! |---|---|---|
//! | 0 | 1 | format version, [`PIN_FORMAT_VERSION`] |
//! | 1 | 32 | SHA-256 of the authority's signing certificate (DER) |
//! | 33 | 1 | digest mask ([`DigestAlgorithm::bit`](crate::DigestAlgorithm::bit)), non-empty |
//! | 34 | 1 | signature mask ([`SignatureAlgorithm::bit`](crate::SignatureAlgorithm::bit)), non-empty |
//! | 35 | 1 | flags: `0x01` accepts an ESS signing-certificate v1 (SHA-1) binding |
//! | 36 | 2 | `p`, length of the policy list, big-endian |
//! | 38 | `p` | 1 to [`MAX_POLICIES`] DER `OBJECT IDENTIFIER`s, strictly ascending |
//! | 38 + `p` | 2 | `c`, length of the certificate, big-endian; 0 for none |
//! | 40 + `p` | `c` | the DER certificate, whose SHA-256 is the pinned hash |
//!
//! Unknown mask or flag bits, an unsorted or repeated policy, a wrong
//! version, a short or long pin are refused, so every pin has one encoding.
//! The certificate is optional: tokens requested with `certReq` embed it,
//! and the pin's copy is used only when the token does not.

use crate::MAX_TOKEN_LEN;
use crate::alg::{self, DigestSet, SignatureAlgorithm, SignatureSet};
use crate::cert;
use crate::der::{self, OID, SEQUENCE};
use crate::error::TsaError;
use crate::oid::ObjectId;

/// The pin format version this crate reads and writes.
pub const PIN_FORMAT_VERSION: u8 = 1;

/// The most policies one pin allows.
pub const MAX_POLICIES: usize = 8;

/// The flag that accepts an ESS signing-certificate v1 binding.
const FLAG_ESS_V1: u8 = 0x01;

/// Octets of the fixed part before the policy list.
const FIXED_LEN: usize = 36;

/// A timestamp authority as the genesis pins it: its signing certificate's
/// hash, the policies, digests and signature algorithms it may use, whether
/// it may bind its certificate with ESS v1 (SHA-1), and optionally the
/// certificate itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedTsa<'a> {
    certificate_sha256: [u8; 32],
    digests: DigestSet,
    signatures: SignatureSet,
    ess_v1: bool,
    policies: &'a [u8],
    certificate: Option<&'a [u8]>,
}

impl<'a> PinnedTsa<'a> {
    /// A pin from its parts.
    ///
    /// `policies` is the concatenation of 1 to [`MAX_POLICIES`] DER
    /// `OBJECT IDENTIFIER` encodings (tag, length, content) in strictly
    /// ascending order of their encodings.
    ///
    /// # Errors
    ///
    /// - [`TsaError::PinPolicies`] if `policies` is not such a list.
    /// - [`TsaError::PinCertificate`] if `certificate` is not one DER
    ///   `SEQUENCE` of at most [`MAX_TOKEN_LEN`] octets whose SHA-256 is
    ///   `certificate_sha256`.
    pub fn new(
        certificate_sha256: [u8; 32],
        digests: DigestSet,
        signatures: SignatureSet,
        allow_ess_v1: bool,
        policies: &'a [u8],
        certificate: Option<&'a [u8]>,
    ) -> Result<Self, TsaError> {
        check_policies(policies)?;
        if let Some(certificate) = certificate {
            let well_formed = certificate.len() <= MAX_TOKEN_LEN
                && der::single(certificate, SEQUENCE).is_ok()
                && alg::sha256(certificate) == certificate_sha256;
            if !well_formed {
                return Err(TsaError::PinCertificate);
            }
        }
        Ok(Self {
            certificate_sha256,
            digests,
            signatures,
            ess_v1: allow_ess_v1,
            policies,
            certificate,
        })
    }

    /// Reads a pin in the byte form above.
    ///
    /// # Errors
    ///
    /// [`TsaError::PinVersion`], [`TsaError::PinLength`],
    /// [`TsaError::PinDigests`], [`TsaError::PinSignatures`],
    /// [`TsaError::PinFlags`], and the errors of [`PinnedTsa::new`].
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, TsaError> {
        let (&version, rest) = bytes.split_first().ok_or(TsaError::PinLength)?;
        if version != PIN_FORMAT_VERSION {
            return Err(TsaError::PinVersion);
        }
        let (hash, rest) = rest.split_first_chunk::<32>().ok_or(TsaError::PinLength)?;
        let (&[digests, signatures, flags], rest) =
            rest.split_first_chunk::<3>().ok_or(TsaError::PinLength)?;
        let digests = DigestSet::from_bits(digests).ok_or(TsaError::PinDigests)?;
        let signatures = SignatureSet::from_bits(signatures).ok_or(TsaError::PinSignatures)?;
        if flags & !FLAG_ESS_V1 != 0 {
            return Err(TsaError::PinFlags);
        }
        let (policies, rest) = length_prefixed(rest)?;
        let (certificate, rest) = length_prefixed(rest)?;
        if !rest.is_empty() {
            return Err(TsaError::PinLength);
        }
        Self::new(
            *hash,
            digests,
            signatures,
            flags & FLAG_ESS_V1 != 0,
            policies,
            (!certificate.is_empty()).then_some(certificate),
        )
    }

    /// The length of [`PinnedTsa::encode`]'s output.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        // Both lists are bounded (policies by MAX_POLICIES, the
        // certificate by MAX_TOKEN_LEN), so the sum is far from overflow.
        FIXED_LEN
            .saturating_add(4)
            .saturating_add(self.policies.len())
            .saturating_add(self.certificate.map_or(0, <[u8]>::len))
    }

    /// Writes the pin in the byte form above to the front of `out` and
    /// returns the number of octets written.
    ///
    /// # Errors
    ///
    /// [`TsaError::PinBufferTooSmall`] if `out` is shorter than
    /// [`PinnedTsa::encoded_len`].
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, TsaError> {
        let flags = if self.ess_v1 { FLAG_ESS_V1 } else { 0 };
        let certificate = self.certificate.unwrap_or(&[]);
        let mut at = put(out, 0, &[PIN_FORMAT_VERSION])?;
        at = put(out, at, &self.certificate_sha256)?;
        at = put(
            out,
            at,
            &[self.digests.bits(), self.signatures.bits(), flags],
        )?;
        at = put(out, at, &length_octets(self.policies)?)?;
        at = put(out, at, self.policies)?;
        at = put(out, at, &length_octets(certificate)?)?;
        put(out, at, certificate)
    }

    /// The pinned SHA-256 of the authority's signing certificate.
    #[must_use]
    pub const fn certificate_sha256(&self) -> &[u8; 32] {
        &self.certificate_sha256
    }

    /// The digest algorithms the authority may use (imprint, `SignerInfo`,
    /// ESS v2 certificate hash).
    #[must_use]
    pub const fn digests(&self) -> DigestSet {
        self.digests
    }

    /// The signature algorithms the authority may use.
    #[must_use]
    pub const fn signatures(&self) -> SignatureSet {
        self.signatures
    }

    /// Whether an ESS signing-certificate v1 (SHA-1) binding is accepted.
    #[must_use]
    pub const fn allows_ess_v1(&self) -> bool {
        self.ess_v1
    }

    /// The allowed policies, in ascending order.
    #[must_use]
    pub const fn policies(&self) -> Policies<'a> {
        Policies {
            rest: self.policies,
        }
    }

    /// The pinned certificate, if the pin carries it.
    #[must_use]
    pub const fn certificate(&self) -> Option<&'a [u8]> {
        self.certificate
    }

    /// The signer's key as the pin fixes it: the DER
    /// `SubjectPublicKeyInfo` of the pin's certificate copy, once the copy
    /// reads as [`verify_token`](crate::verify_token) reads a signer's
    /// certificate and some token could verify under the pin, that is some
    /// signature algorithm the pin allows is one the key makes, over a
    /// digest the pin allows. An ESS v2 binding may use any digest the pin
    /// allows, so it never stands in the way; the imprint's digest is the
    /// caller's to require.
    ///
    /// The key, not the certificate, is what one authority is: the same
    /// key under two certificates signs for one authority.
    ///
    /// # Errors
    ///
    /// - [`TsaError::CertificateNotPinned`] if the pin carries no copy.
    /// - The error of the copy, if `verify_token` would refuse it as a
    ///   signer's certificate (its profile, its key).
    /// - [`TsaError::SignatureNotAllowed`] if no signature algorithm the pin
    ///   allows is one the key makes with a digest the pin allows.
    pub fn signer_key(&self) -> Result<&'a [u8], TsaError> {
        let raw = self.certificate.ok_or(TsaError::CertificateNotPinned)?;
        let certificate = cert::parse(raw)?;
        let usable = SignatureAlgorithm::ALL.into_iter().any(|algorithm| {
            self.signatures.contains(algorithm)
                && self.digests.contains(algorithm.digest())
                && certificate.key.makes(algorithm)
        });
        if usable {
            Ok(certificate.key_info)
        } else {
            Err(TsaError::SignatureNotAllowed)
        }
    }

    /// Whether the policy with content octets `policy` is allowed.
    pub(crate) fn allows_policy(&self, policy: &[u8]) -> bool {
        self.policies().any(|allowed| allowed.content() == policy)
    }
}

/// The allowed policies of a pin.
#[derive(Debug, Clone)]
pub struct Policies<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Policies<'a> {
    type Item = ObjectId<'a>;

    fn next(&mut self) -> Option<ObjectId<'a>> {
        // The list was checked when the pin was made.
        let (tlv, rest) = der::parse_tlv(self.rest).ok()?;
        self.rest = rest;
        Some(ObjectId::checked(tlv.value))
    }
}

/// Checks a policy list: 1 to [`MAX_POLICIES`] valid DER object identifiers
/// in strictly ascending order of their encodings.
fn check_policies(policies: &[u8]) -> Result<(), TsaError> {
    let mut rest = policies;
    let mut previous: Option<&[u8]> = None;
    let mut count = 0usize;
    while !rest.is_empty() {
        let (tlv, after) = der::parse_tlv(rest).map_err(|_| TsaError::PinPolicies)?;
        let in_order = previous.is_none_or(|previous| previous < tlv.raw);
        if tlv.tag != OID || der::check_oid(tlv.value).is_err() || !in_order {
            return Err(TsaError::PinPolicies);
        }
        count = count.saturating_add(1);
        previous = Some(tlv.raw);
        rest = after;
    }
    if (1..=MAX_POLICIES).contains(&count) {
        Ok(())
    } else {
        Err(TsaError::PinPolicies)
    }
}

/// Splits a `u16` big-endian length and that many octets from the front of `input`.
fn length_prefixed(input: &[u8]) -> Result<(&[u8], &[u8]), TsaError> {
    let (len, rest) = input.split_first_chunk::<2>().ok_or(TsaError::PinLength)?;
    rest.split_at_checked(usize::from(u16::from_be_bytes(*len)))
        .ok_or(TsaError::PinLength)
}

/// The `u16` big-endian length of `field`.
fn length_octets(field: &[u8]) -> Result<[u8; 2], TsaError> {
    u16::try_from(field.len())
        .map(u16::to_be_bytes)
        .map_err(|_| TsaError::PinBufferTooSmall)
}

/// Copies `bytes` into `out` at `at` and returns the offset after them.
fn put(out: &mut [u8], at: usize, bytes: &[u8]) -> Result<usize, TsaError> {
    let end = at
        .checked_add(bytes.len())
        .ok_or(TsaError::PinBufferTooSmall)?;
    let target = out.get_mut(at..end).ok_or(TsaError::PinBufferTooSmall)?;
    for (target, source) in target.iter_mut().zip(bytes) {
        *target = *source;
    }
    Ok(end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DigestAlgorithm, SignatureAlgorithm};

    const POLICY_A: &[u8] = &[0x06, 0x03, 0x2A, 0x03, 0x04];
    const POLICY_B: &[u8] = &[0x06, 0x03, 0x2A, 0x03, 0x05];

    fn sets() -> (DigestSet, SignatureSet) {
        (
            DigestSet::from_bits(DigestAlgorithm::Sha512.bit()).unwrap(),
            SignatureSet::from_bits(SignatureAlgorithm::EcdsaP384Sha512.bit()).unwrap(),
        )
    }

    #[test]
    fn round_trip() {
        let (digests, signatures) = sets();
        let mut policies = POLICY_A.to_vec();
        policies.extend_from_slice(POLICY_B);
        let certificate = [0x30, 0x03, 0x02, 0x01, 0x07];
        let hash = alg::sha256(&certificate);
        for (ess, cert) in [(false, None), (true, Some(&certificate[..]))] {
            let pin = PinnedTsa::new(hash, digests, signatures, ess, &policies, cert).unwrap();
            let mut out = [0u8; 128];
            let len = pin.encode(&mut out).unwrap();
            assert_eq!(len, pin.encoded_len());
            assert_eq!(out[0], PIN_FORMAT_VERSION);
            assert_eq!(&out[1..33], &hash);
            assert_eq!(out[35], u8::from(ess));
            let decoded = PinnedTsa::from_bytes(&out[..len]).unwrap();
            assert_eq!(decoded, pin);
            assert_eq!(decoded.certificate(), cert);
            assert_eq!(decoded.certificate_sha256(), &hash);
            assert_eq!(decoded.digests(), digests);
            assert_eq!(decoded.signatures(), signatures);
            assert_eq!(decoded.allows_ess_v1(), ess);
            let listed: std::vec::Vec<_> = decoded.policies().map(|p| p.content()).collect();
            assert_eq!(listed, [&POLICY_A[2..], &POLICY_B[2..]]);
            assert!(decoded.allows_policy(&POLICY_B[2..]));
            assert!(!decoded.allows_policy(&[0x2A, 0x03, 0x06]));
            assert_eq!(
                pin.encode(&mut out[..len.checked_sub(1).unwrap()]),
                Err(TsaError::PinBufferTooSmall)
            );
            let mut long = out[..len].to_vec();
            long.push(0);
            assert_eq!(PinnedTsa::from_bytes(&long), Err(TsaError::PinLength));
            for cut in 0..len {
                assert!(PinnedTsa::from_bytes(&out[..cut]).is_err());
            }
        }
    }

    fn encoded(policies: &[u8]) -> std::vec::Vec<u8> {
        let mut out = std::vec![PIN_FORMAT_VERSION];
        out.extend_from_slice(&[0x11; 32]);
        out.extend_from_slice(&[0x04, 0x20, 0x00]);
        out.extend_from_slice(&u16::try_from(policies.len()).unwrap().to_be_bytes());
        out.extend_from_slice(policies);
        out.extend_from_slice(&[0x00, 0x00]);
        out
    }

    #[test]
    fn refusals() {
        let good = encoded(POLICY_A);
        assert!(PinnedTsa::from_bytes(&good).is_ok());
        let with = |at: usize, value: u8| {
            let mut bytes = good.clone();
            bytes[at] = value;
            PinnedTsa::from_bytes(&bytes).map(|pin| pin.allows_ess_v1())
        };
        assert_eq!(with(0, 2), Err(TsaError::PinVersion));
        assert_eq!(with(33, 0), Err(TsaError::PinDigests));
        assert_eq!(with(33, 0x08), Err(TsaError::PinDigests));
        assert_eq!(with(34, 0), Err(TsaError::PinSignatures));
        assert_eq!(with(34, 0x40), Err(TsaError::PinSignatures));
        assert_eq!(with(35, 0x02), Err(TsaError::PinFlags));
        assert_eq!(with(35, 0x01), Ok(true));
        assert_eq!(with(35, 0x00), Ok(false));
        assert_eq!(PinnedTsa::from_bytes(&[]), Err(TsaError::PinLength));

        let mut two = POLICY_B.to_vec();
        two.extend_from_slice(POLICY_A);
        assert_eq!(
            PinnedTsa::from_bytes(&encoded(&two)),
            Err(TsaError::PinPolicies)
        );
        let mut repeated = POLICY_A.to_vec();
        repeated.extend_from_slice(POLICY_A);
        assert_eq!(
            PinnedTsa::from_bytes(&encoded(&repeated)),
            Err(TsaError::PinPolicies)
        );
        assert_eq!(
            PinnedTsa::from_bytes(&encoded(&[])),
            Err(TsaError::PinPolicies)
        );
        assert_eq!(
            PinnedTsa::from_bytes(&encoded(&[0x04, 0x01, 0x2A])),
            Err(TsaError::PinPolicies)
        );
        assert_eq!(
            PinnedTsa::from_bytes(&encoded(&[0x06, 0x01, 0x80])),
            Err(TsaError::PinPolicies)
        );
        assert_eq!(
            PinnedTsa::from_bytes(&encoded(&[0x06, 0x81, 0x01])),
            Err(TsaError::PinPolicies)
        );
        let mut nine = std::vec::Vec::new();
        for last in 0..9u8 {
            nine.extend_from_slice(&[0x06, 0x02, 0x2A, last]);
        }
        assert_eq!(
            PinnedTsa::from_bytes(&encoded(&nine)),
            Err(TsaError::PinPolicies)
        );
        assert!(PinnedTsa::from_bytes(&encoded(&nine[..32])).is_ok());
    }

    #[test]
    fn certificate_refusals() {
        let (digests, signatures) = sets();
        let certificate = [0x30, 0x00];
        let hash = alg::sha256(&certificate);
        assert!(
            PinnedTsa::new(
                hash,
                digests,
                signatures,
                false,
                POLICY_A,
                Some(&certificate)
            )
            .is_ok()
        );
        assert_eq!(
            PinnedTsa::new(
                [0; 32],
                digests,
                signatures,
                false,
                POLICY_A,
                Some(&certificate)
            ),
            Err(TsaError::PinCertificate)
        );
        let trailing = [0x30, 0x00, 0x00];
        assert_eq!(
            PinnedTsa::new(
                alg::sha256(&trailing),
                digests,
                signatures,
                false,
                POLICY_A,
                Some(&trailing)
            ),
            Err(TsaError::PinCertificate)
        );
        let mut huge = std::vec![0x30, 0x82, 0x40, 0x00];
        huge.resize(4 + 0x4000, 0);
        assert_eq!(
            PinnedTsa::new(
                alg::sha256(&huge),
                digests,
                signatures,
                false,
                POLICY_A,
                Some(&huge)
            ),
            Err(TsaError::PinCertificate)
        );
        let mut limit = std::vec![0x30, 0x82, 0x3F, 0xFC];
        limit.resize(MAX_TOKEN_LEN, 0);
        assert!(
            PinnedTsa::new(
                alg::sha256(&limit),
                digests,
                signatures,
                false,
                POLICY_A,
                Some(&limit)
            )
            .is_ok()
        );
    }
}
