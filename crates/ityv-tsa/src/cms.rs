//! The CMS layers of a `TimeStampToken` (RFC 3161 §2.4.2, RFC 5652):
//! `ContentInfo` → `SignedData` → one `SignerInfo` with its signed attributes.
//!
//! This module reads structure only. What the parts mean (which certificate,
//! whether digests and signature match) is decided in `verify`.

use crate::alg::{self, DigestAlgorithm, SignatureFamily};
use crate::der::{
    self, CONTEXT_0, CONTEXT_1, CONTEXT_4, INTEGER, PRIMITIVE_0, Reader, SEQUENCE, SET,
};
use crate::error::{DerError, TsaError};
use crate::oid;

/// The most certificates a token may embed.
pub const MAX_CERTIFICATES: usize = 8;

/// How the `SignerInfo` names its certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignerId<'a> {
    /// `issuerAndSerialNumber`: the issuer `Name` (whole encoding) and the
    /// serial's `INTEGER` content octets.
    IssuerSerial { issuer: &'a [u8], serial: &'a [u8] },
    /// `subjectKeyIdentifier`.
    KeyId(&'a [u8]),
}

/// `IssuerSerial` of an ESS certificate identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IssuerSerial<'a> {
    /// The `Name` (whole encoding) if `GeneralNames` is exactly one
    /// `directoryName`; any other form can name no certificate here.
    pub(crate) directory: Option<&'a [u8]>,
    /// The serial's `INTEGER` content octets.
    pub(crate) serial: &'a [u8],
}

/// The first `ESSCertID` or `ESSCertIDv2` of a signing-certificate
/// attribute: the one that must identify the signer's certificate (RFC 5035 §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EssCertId<'a> {
    pub(crate) hash: &'a [u8],
    pub(crate) issuer_serial: Option<IssuerSerial<'a>>,
}

/// The parts of a token's CMS layers that verification uses.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SignedToken<'a> {
    /// The encapsulated content: the `TSTInfo` encoding.
    pub(crate) content: &'a [u8],
    /// The embedded certificates (each checked to be in the subset).
    pub(crate) certificates: Reader<'a>,
    pub(crate) signer_id: SignerId<'a>,
    pub(crate) digest: DigestAlgorithm,
    /// The signed attributes, whole encoding (tag `[0]`).
    pub(crate) signed_attributes: &'a [u8],
    pub(crate) message_digest: &'a [u8],
    pub(crate) ess_v1: Option<EssCertId<'a>>,
    pub(crate) ess_v2: Option<(DigestAlgorithm, EssCertId<'a>)>,
    pub(crate) family: SignatureFamily,
    pub(crate) signature: &'a [u8],
}

/// Reads `ContentInfo` and `SignedData`.
pub(crate) fn parse(token: &[u8]) -> Result<SignedToken<'_>, TsaError> {
    let mut content_info = der::single(token, SEQUENCE)?;
    if content_info.oid()? != oid::SIGNED_DATA {
        return Err(TsaError::NotSignedData);
    }
    let mut explicit = content_info.nested(CONTEXT_0)?;
    content_info.finish()?;
    let mut signed_data = explicit.sequence()?;
    explicit.finish()?;

    if der::small_unsigned(signed_data.read(INTEGER)?.value)? != 3 {
        return Err(TsaError::SignedDataVersion);
    }
    let mut digests = signed_data.set(SET)?;
    if digests.is_empty() {
        return Err(TsaError::DigestAlgorithmSet);
    }
    let set_digest = alg::read_digest_algorithm(&mut digests)?;
    if !digests.is_empty() {
        return Err(TsaError::DigestAlgorithmSet);
    }

    let mut encapsulated = signed_data.sequence()?;
    if encapsulated.oid()? != oid::TST_INFO {
        return Err(TsaError::NotTstInfo);
    }
    if encapsulated.is_empty() {
        return Err(TsaError::MissingContent);
    }
    let mut explicit = encapsulated.nested(CONTEXT_0)?;
    let content = explicit.octets()?;
    explicit.finish()?;
    encapsulated.finish()?;

    let certificates = if signed_data.peek_tag() == Some(CONTEXT_0) {
        read_certificates(signed_data.nested(CONTEXT_0)?)?
    } else {
        Reader::new(&[])
    };
    if signed_data.peek_tag() == Some(CONTEXT_1) {
        return Err(TsaError::CrlsPresent);
    }
    let mut signers = signed_data.set(SET)?;
    signed_data.finish()?;
    if signers.is_empty() {
        return Err(TsaError::SignerCount);
    }
    let signer = signers.sequence()?;
    if !signers.is_empty() {
        return Err(TsaError::SignerCount);
    }
    let token = read_signer(signer, content, certificates)?;
    if token.digest != set_digest {
        return Err(TsaError::DigestAlgorithmSet);
    }
    Ok(token)
}

/// Checks the `CertificateSet`: X.509 certificates only, at most
/// [`MAX_CERTIFICATES`], each in the subset. Returns a reader over them.
///
/// The order of the certificates is not checked. DER sorts a `SET OF`, but
/// this set is not signed (anyone can reorder, add or remove certificates
/// without breaking the signature) and is only searched for the pinned
/// hash; an authority may well write it in chain order.
fn read_certificates(set: Reader<'_>) -> Result<Reader<'_>, TsaError> {
    let mut scan = set;
    let mut count = 0usize;
    while !scan.is_empty() {
        if scan.peek_tag() != Some(SEQUENCE) {
            return Err(TsaError::UnsupportedCertificateChoice);
        }
        scan.checked(SEQUENCE)?;
        count = count.saturating_add(1);
        if count > MAX_CERTIFICATES {
            return Err(TsaError::TooManyCertificates);
        }
    }
    Ok(set)
}

/// Reads the one `SignerInfo`.
fn read_signer<'a>(
    mut signer: Reader<'a>,
    content: &'a [u8],
    certificates: Reader<'a>,
) -> Result<SignedToken<'a>, TsaError> {
    let version = der::small_unsigned(signer.read(INTEGER)?.value)?;
    let (signer_id, expected_version) = match signer.peek_tag() {
        Some(SEQUENCE) => {
            let mut issuer_and_serial = signer.sequence()?;
            let issuer = issuer_and_serial.checked(SEQUENCE)?;
            let serial = issuer_and_serial.read(INTEGER)?;
            der::unsigned(serial.value)?;
            issuer_and_serial.finish()?;
            let id = SignerId::IssuerSerial {
                issuer: issuer.raw,
                serial: serial.value,
            };
            (id, 1)
        }
        Some(PRIMITIVE_0) => (SignerId::KeyId(signer.read_any()?.value), 3),
        Some(_) => return Err(TsaError::Der(DerError::UnexpectedTag)),
        None => return Err(TsaError::Der(DerError::MissingField)),
    };
    if version != expected_version {
        return Err(TsaError::SignerInfoVersion);
    }
    let digest = alg::read_digest_algorithm(&mut signer)?;
    if signer.peek_tag() != Some(CONTEXT_0) {
        return Err(TsaError::MissingSignedAttributes);
    }
    let attributes_tlv = signer.read(CONTEXT_0)?;
    let attributes = read_signed_attributes(signer.enter_set(&attributes_tlv)?)?;
    let family = alg::read_signature_algorithm(&mut signer, digest)?;
    let signature = signer.octets()?;
    if let Some(unsigned) = signer.optional(CONTEXT_1)? {
        // Unsigned attributes are not used, but each stays in the subset.
        // Like the certificate set, they are not signed, so their order is
        // not checked.
        der::check_contents(signer.enter(&unsigned)?)?;
    }
    signer.finish()?;
    Ok(SignedToken {
        content,
        certificates,
        signer_id,
        digest,
        signed_attributes: attributes_tlv.raw,
        message_digest: attributes.message_digest,
        ess_v1: attributes.ess_v1,
        ess_v2: attributes.ess_v2,
        family,
        signature,
    })
}

/// The signed attributes verification uses.
struct Attributes<'a> {
    message_digest: &'a [u8],
    ess_v1: Option<EssCertId<'a>>,
    ess_v2: Option<(DigestAlgorithm, EssCertId<'a>)>,
}

/// Reads the one value of a required attribute's `attrValues` with `read`.
fn single_value<'a, T>(
    mut values: Reader<'a>,
    read: impl FnOnce(&mut Reader<'a>) -> Result<T, TsaError>,
) -> Result<T, TsaError> {
    if values.is_empty() {
        return Err(TsaError::AttributeValueCount);
    }
    let value = read(&mut values)?;
    if values.is_empty() {
        Ok(value)
    } else {
        Err(TsaError::AttributeValueCount)
    }
}

/// Fails if a required attribute was already seen.
const fn once<T>(seen: Option<&T>) -> Result<(), TsaError> {
    if seen.is_some() {
        Err(TsaError::DuplicateAttribute)
    } else {
        Ok(())
    }
}

/// Reads `SignedAttributes ::= SET SIZE (1..MAX) OF Attribute`: content
/// type, message digest and an ESS signing-certificate attribute are
/// required; other attributes (such as signing time) must be in the subset.
fn read_signed_attributes(mut list: Reader<'_>) -> Result<Attributes<'_>, TsaError> {
    let mut content_type = None;
    let mut message_digest = None;
    let mut ess_v1 = None;
    let mut ess_v2 = None;
    while !list.is_empty() {
        let mut attribute = list.sequence()?;
        let id = attribute.oid()?;
        let values = attribute.set(SET)?;
        attribute.finish()?;
        match id {
            oid::CONTENT_TYPE => {
                once(content_type.as_ref())?;
                content_type = Some(single_value(values, |value| Ok(value.oid()?))?);
            }
            oid::MESSAGE_DIGEST => {
                once(message_digest.as_ref())?;
                message_digest = Some(single_value(values, |value| Ok(value.octets()?))?);
            }
            oid::SIGNING_CERTIFICATE_V2 => {
                once(ess_v2.as_ref())?;
                ess_v2 = Some(single_value(values, |value| {
                    let mut id = first_cert_id(value)?;
                    let algorithm = alg::read_ess_hash_algorithm(&mut id)?;
                    Ok((algorithm, read_cert_id(id)?))
                })?);
            }
            oid::SIGNING_CERTIFICATE => {
                once(ess_v1.as_ref())?;
                ess_v1 = Some(single_value(values, |value| {
                    read_cert_id(first_cert_id(value)?)
                })?);
            }
            _ => der::check_contents(values)?,
        }
    }
    match content_type {
        None => return Err(TsaError::MissingContentType),
        Some(content_type) if content_type != oid::TST_INFO => {
            return Err(TsaError::ContentTypeMismatch);
        }
        Some(_) => {}
    }
    let message_digest = message_digest.ok_or(TsaError::MissingMessageDigest)?;
    if ess_v1.is_none() && ess_v2.is_none() {
        return Err(TsaError::MissingSigningCertificate);
    }
    Ok(Attributes {
        message_digest,
        ess_v1,
        ess_v2,
    })
}

/// Reads `SigningCertificate` (RFC 2634 §5.4) or `SigningCertificateV2`
/// (RFC 5035 §5.4.1) up to its first certificate identifier and returns a
/// reader over that identifier. Later identifiers (the chain) and
/// `policies` are not used, but must be in the subset.
fn first_cert_id<'a>(value: &mut Reader<'a>) -> Result<Reader<'a>, TsaError> {
    let mut signing_certificate = value.sequence()?;
    let mut certs = signing_certificate.sequence()?;
    if !signing_certificate.is_empty() {
        signing_certificate.checked(SEQUENCE)?;
    }
    signing_certificate.finish()?;
    if certs.is_empty() {
        return Err(TsaError::MissingSigningCertificate);
    }
    let id = certs.sequence()?;
    der::check_contents(certs)?;
    Ok(id)
}

/// Reads the rest of `ESSCertID` or `ESSCertIDv2` (after `hashAlgorithm`):
/// `certHash OCTET STRING, issuerSerial IssuerSerial OPTIONAL`.
fn read_cert_id(mut id: Reader<'_>) -> Result<EssCertId<'_>, TsaError> {
    let hash = id.octets()?;
    let issuer_serial = if id.is_empty() {
        None
    } else {
        Some(read_issuer_serial(id.sequence()?)?)
    };
    id.finish()?;
    Ok(EssCertId {
        hash,
        issuer_serial,
    })
}

/// `IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber INTEGER }`.
fn read_issuer_serial(mut issuer_serial: Reader<'_>) -> Result<IssuerSerial<'_>, TsaError> {
    let mut names = issuer_serial.sequence()?;
    let first = names.checked_any()?;
    let only = names.is_empty();
    der::check_contents(names)?;
    let directory = if only && first.tag == CONTEXT_4 {
        let mut name = names.enter(&first)?;
        let directory = name.read(SEQUENCE)?;
        name.finish()?;
        Some(directory.raw)
    } else {
        None
    };
    let serial = issuer_serial.read(INTEGER)?;
    der::integer(serial.value)?;
    issuer_serial.finish()?;
    Ok(IssuerSerial {
        directory,
        serial: serial.value,
    })
}
