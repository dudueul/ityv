//! `verify_token`: one RFC 3161 token against one pinned authority and one
//! expected imprint.

use crate::MAX_TOKEN_LEN;
use crate::alg::{self, DigestAlgorithm, Imprint, SignatureAlgorithm, SignatureFamily};
use crate::cert::{self, Certificate, PublicKey};
use crate::cms::{self, EssCertId, SignedToken, SignerId};
use crate::der::{CONTEXT_4, Reader, SET};
use crate::ecdsa::Curve;
use crate::error::TsaError;
use crate::oid::ObjectId;
use crate::pin::PinnedTsa;
use crate::time::GenTime;
use crate::tst::{self, Accuracy};

/// Where the signer's certificate came from.
///
/// This reflects the token's `certificates` field, which is not signed:
/// anyone can add or remove certificates without breaking the signature, so
/// the same signed timestamp can verify with either source. It is a
/// diagnostic, never evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertificateSource {
    /// Embedded in the token (requested with `certReq`) and matched to the pin by hash.
    Embedded,
    /// The pin's own copy (the token embeds none with the pinned hash).
    Pinned,
}

/// A token that verified: what the authority signed, and with what.
///
/// It exists only as the result of [`verify_token`]. Borrowed fields point
/// into the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedTimestamp<'t> {
    gen_time: GenTime,
    accuracy: Option<Accuracy>,
    ordering: bool,
    policy: ObjectId<'t>,
    serial: &'t [u8],
    nonce: Option<&'t [u8]>,
    imprint: Imprint,
    certificate_sha256: [u8; 32],
    certificate_source: CertificateSource,
    signature_algorithm: SignatureAlgorithm,
}

impl<'t> VerifiedTimestamp<'t> {
    /// `genTime`, the time the authority asserts.
    #[must_use]
    pub const fn gen_time(&self) -> GenTime {
        self.gen_time
    }

    /// The accuracy, if the token states one.
    #[must_use]
    pub const fn accuracy(&self) -> Option<Accuracy> {
        self.accuracy
    }

    /// The earliest instant the authority's assertion allows: `genTime`
    /// minus the accuracy (RFC 3161 §2.4.2: the true time is within
    /// `genTime` ± accuracy), or `genTime` itself if the token states no
    /// accuracy. `None` if that is before the Unix epoch.
    ///
    /// The checkpoint stage judges with this interval, `earliest()` to
    /// [`latest`](Self::latest), not with `genTime` alone (ADR-0034 VC-115,
    /// VC-116; ADR-0037 9): a conclusion that the object existed by some
    /// instant (the anchor window, the backdating check) uses `latest()`; a
    /// conclusion that the token was made after some instant uses
    /// `earliest()`.
    ///
    /// A token without accuracy gives the interval `genTime` to `genTime`.
    /// RFC 3161 lets an authority's policy state the accuracy instead; such
    /// an accuracy is not in the token, so the genesis would have to carry it.
    #[must_use]
    pub fn earliest(&self) -> Option<GenTime> {
        match self.accuracy {
            Some(accuracy) => self
                .gen_time
                .checked_sub(accuracy.seconds(), accuracy.sub_second_nanos()),
            None => Some(self.gen_time),
        }
    }

    /// The latest instant the authority's assertion allows: `genTime` plus
    /// the accuracy, or `genTime` itself if the token states no accuracy
    /// (see [`earliest`](Self::earliest)).
    ///
    /// Never `None` for a verified token (`genTime` is before the year 10000
    /// and the accuracy at most [`MAX_ACCURACY_SECONDS`] and 999 999 µs);
    /// the result is checked all the same.
    ///
    /// [`MAX_ACCURACY_SECONDS`]: crate::MAX_ACCURACY_SECONDS
    #[must_use]
    pub fn latest(&self) -> Option<GenTime> {
        match self.accuracy {
            Some(accuracy) => self
                .gen_time
                .checked_add(accuracy.seconds(), accuracy.sub_second_nanos()),
            None => Some(self.gen_time),
        }
    }

    /// The `ordering` flag.
    #[must_use]
    pub const fn ordering(&self) -> bool {
        self.ordering
    }

    /// The policy, one the pin allows.
    #[must_use]
    pub const fn policy(&self) -> ObjectId<'t> {
        self.policy
    }

    /// The serial number's magnitude, big-endian without leading zero octets.
    #[must_use]
    pub const fn serial(&self) -> &'t [u8] {
        self.serial
    }

    /// The nonce's magnitude, if the token has one.
    #[must_use]
    pub const fn nonce(&self) -> Option<&'t [u8]> {
        self.nonce
    }

    /// The imprint, equal to the expected one.
    #[must_use]
    pub const fn imprint(&self) -> &Imprint {
        &self.imprint
    }

    /// The SHA-256 of the certificate that verified the signature: the pinned hash.
    #[must_use]
    pub const fn certificate_sha256(&self) -> &[u8; 32] {
        &self.certificate_sha256
    }

    /// Where that certificate came from: from the token's unsigned
    /// `certificates` field or from the pin. Not signed (see
    /// [`CertificateSource`]).
    #[must_use]
    pub const fn certificate_source(&self) -> CertificateSource {
        self.certificate_source
    }

    /// The signature algorithm, one the pin allows.
    #[must_use]
    pub const fn signature_algorithm(&self) -> SignatureAlgorithm {
        self.signature_algorithm
    }
}

/// Verifies an RFC 3161 `TimeStampToken` (`token`, DER `ContentInfo`)
/// issued by the authority `pin` describes over the `expected` imprint.
///
/// In order: the whole token is read in the strict DER subset; the signer's
/// certificate is the embedded one whose SHA-256 is the pinned hash, or the
/// pin's own copy; the certificate's profile, the signer identifier, and
/// that the pin allows every digest and the signature algorithm are
/// checked; then the signed attributes' content type, the ESS certificate
/// binding, the message digest over the `TSTInfo`, and the signature over
/// the DER signed attributes; and last the content: the imprint against
/// `expected`, the policy against the pin, the `tsa` name against the
/// certificate subject, and `genTime` within the certificate's validity.
///
/// What this does not prove: that `genTime` is the true time (the authority
/// asserts it; ADR-0034 asks for two authorities of different operators),
/// that the certificate is unrevoked or chains to any root (it is pinned
/// instead), or anything about the timestamped data beyond its digest. The
/// classical signature is corroboration, not the root of trust (ADR-0034 §5).
///
/// # Errors
///
/// The first rule the token breaks, as a [`TsaError`] variant.
pub fn verify_token<'t>(
    token: &'t [u8],
    pin: &PinnedTsa<'_>,
    expected: &Imprint,
) -> Result<VerifiedTimestamp<'t>, TsaError> {
    if token.len() > MAX_TOKEN_LEN {
        return Err(TsaError::TokenTooLarge);
    }
    let signed = cms::parse(token)?;
    let info = tst::parse(signed.content)?;
    let (certificate_der, certificate_source) = select_certificate(signed.certificates, pin)?;
    let certificate = cert::parse(certificate_der)?;
    check_signer_id(signed.signer_id, &certificate)?;
    let signature_algorithm = signature_algorithm(signed.family, signed.digest, &certificate.key)?;
    check_allowed(&signed, info.imprint_algorithm, signature_algorithm, pin)?;

    if let Some((algorithm, id)) = signed.ess_v2 {
        check_ess(
            &id,
            algorithm.digest(&[certificate_der]).as_slice(),
            &certificate,
        )?;
    }
    if let Some(id) = signed.ess_v1 {
        check_ess(&id, &alg::sha1(certificate_der), &certificate)?;
    }
    if signed.digest.digest(&[signed.content]).as_slice() != signed.message_digest {
        return Err(TsaError::MessageDigestMismatch);
    }
    // The signature covers the DER `SET OF` encoding of the signed
    // attributes: the same octets with the `[0]` tag replaced by `SET`
    // (RFC 5652 §5.4).
    let (_, attributes) = signed
        .signed_attributes
        .split_first()
        .ok_or(TsaError::MissingSignedAttributes)?;
    let digest = signed.digest.digest(&[&[SET], attributes]);
    match certificate.key {
        PublicKey::Rsa(key) => key.verify(signed.digest, digest.as_slice(), signed.signature)?,
        PublicKey::Ec(key) => key.verify(digest.as_slice(), signed.signature)?,
    }

    if info.imprint_algorithm != expected.algorithm() {
        return Err(TsaError::ImprintAlgorithmMismatch);
    }
    if info.imprint != expected.digest() {
        return Err(TsaError::ImprintMismatch);
    }
    if !pin.allows_policy(info.policy) {
        return Err(TsaError::PolicyNotAllowed);
    }
    if let Some(name) = info.tsa {
        // `directoryName [4] Name`, explicitly tagged inside the CHOICE.
        if name.tag != CONTEXT_4 || name.value != certificate.subject {
            return Err(TsaError::TsaNameMismatch);
        }
    }
    if info.gen_time < certificate.not_before || info.gen_time > certificate.not_after {
        return Err(TsaError::OutsideValidity);
    }
    Ok(VerifiedTimestamp {
        gen_time: info.gen_time,
        accuracy: info.accuracy,
        ordering: info.ordering,
        policy: ObjectId::checked(info.policy),
        serial: info.serial,
        nonce: info.nonce,
        imprint: *expected,
        certificate_sha256: *pin.certificate_sha256(),
        certificate_source,
        signature_algorithm,
    })
}

/// The embedded certificate with the pinned hash, else the pin's copy.
fn select_certificate<'c>(
    mut certificates: Reader<'c>,
    pin: &PinnedTsa<'c>,
) -> Result<(&'c [u8], CertificateSource), TsaError> {
    while !certificates.is_empty() {
        let certificate = certificates.read_any()?;
        if alg::sha256(certificate.raw) == *pin.certificate_sha256() {
            return Ok((certificate.raw, CertificateSource::Embedded));
        }
    }
    pin.certificate()
        .map(|certificate| (certificate, CertificateSource::Pinned))
        .ok_or(TsaError::CertificateNotPinned)
}

/// The signer identifier names `certificate`.
fn check_signer_id(id: SignerId<'_>, certificate: &Certificate<'_>) -> Result<(), TsaError> {
    let matches = match id {
        SignerId::IssuerSerial { issuer, serial } => {
            issuer == certificate.issuer && serial == certificate.serial
        }
        SignerId::KeyId(key_id) => certificate.subject_key_id == Some(key_id),
    };
    if matches {
        Ok(())
    } else {
        Err(TsaError::SignerIdentifierMismatch)
    }
}

/// The signature algorithm the `SignerInfo` and the key make together.
fn signature_algorithm(
    family: SignatureFamily,
    digest: DigestAlgorithm,
    key: &PublicKey<'_>,
) -> Result<SignatureAlgorithm, TsaError> {
    match (family, key, digest) {
        (SignatureFamily::Rsa, PublicKey::Rsa(_), DigestAlgorithm::Sha256) => {
            Ok(SignatureAlgorithm::RsaPkcs1Sha256)
        }
        (SignatureFamily::Rsa, PublicKey::Rsa(_), DigestAlgorithm::Sha384) => {
            Ok(SignatureAlgorithm::RsaPkcs1Sha384)
        }
        (SignatureFamily::Rsa, PublicKey::Rsa(_), DigestAlgorithm::Sha512) => {
            Ok(SignatureAlgorithm::RsaPkcs1Sha512)
        }
        (SignatureFamily::Ecdsa, PublicKey::Ec(key), digest) => match (key.curve(), digest) {
            (Curve::P256, DigestAlgorithm::Sha256) => Ok(SignatureAlgorithm::EcdsaP256Sha256),
            (Curve::P384, DigestAlgorithm::Sha384) => Ok(SignatureAlgorithm::EcdsaP384Sha384),
            (Curve::P384, DigestAlgorithm::Sha512) => Ok(SignatureAlgorithm::EcdsaP384Sha512),
            (Curve::P256, DigestAlgorithm::Sha384 | DigestAlgorithm::Sha512)
            | (Curve::P384, DigestAlgorithm::Sha256) => {
                Err(TsaError::UnsupportedSignatureAlgorithm)
            }
        },
        (SignatureFamily::Rsa, PublicKey::Ec(_), _)
        | (SignatureFamily::Ecdsa, PublicKey::Rsa(_), _) => {
            Err(TsaError::UnsupportedSignatureAlgorithm)
        }
    }
}

/// Every digest the token uses and its signature algorithm are ones the pin
/// allows, and an ESS v1 binding only if the pin accepts it.
fn check_allowed(
    signed: &SignedToken<'_>,
    imprint: DigestAlgorithm,
    signature: SignatureAlgorithm,
    pin: &PinnedTsa<'_>,
) -> Result<(), TsaError> {
    let digests = pin.digests();
    let ess_ok = signed
        .ess_v2
        .is_none_or(|(algorithm, _)| digests.contains(algorithm));
    if !digests.contains(signed.digest) || !digests.contains(imprint) || !ess_ok {
        return Err(TsaError::DigestNotAllowed);
    }
    if signed.ess_v1.is_some() && !pin.allows_ess_v1() {
        return Err(TsaError::SigningCertificateV1NotAllowed);
    }
    if pin.signatures().contains(signature) {
        Ok(())
    } else {
        Err(TsaError::SignatureNotAllowed)
    }
}

/// An ESS certificate identifier names `certificate`, whose hash under the
/// identifier's algorithm is `hash`.
fn check_ess(
    id: &EssCertId<'_>,
    hash: &[u8],
    certificate: &Certificate<'_>,
) -> Result<(), TsaError> {
    if id.hash != hash {
        return Err(TsaError::SigningCertificateMismatch);
    }
    match id.issuer_serial {
        Some(issuer_serial)
            if issuer_serial.directory != Some(certificate.issuer)
                || issuer_serial.serial != certificate.serial =>
        {
            Err(TsaError::SigningCertificateIssuerMismatch)
        }
        Some(_) | None => Ok(()),
    }
}
