//! The signer's X.509 v3 certificate (RFC 5280), read for what verification
//! needs: serial, issuer, subject, validity, public key and extensions.
//!
//! The certificate is pinned by its hash, so its issuer's signature and the
//! path are not validated. Its extensions are: extended key usage, which must
//! be critical and exactly `id-kp-timeStamping` (RFC 3161 §2.3); key usage,
//! if present, digital signature and/or non-repudiation only; basic
//! constraints, if present, not a CA; subject key identifier, kept for a
//! signer identified by key. Any other critical extension is refused, a
//! processed extension may not repeat, and everything else must still be in
//! the DER subset.

use crate::der::{
    self, BIT_STRING, BOOLEAN, CONTEXT_0, CONTEXT_3, GENERALIZED_TIME, INTEGER, NULL, OCTET_STRING,
    OID, Reader, SEQUENCE, UTC_TIME,
};
use crate::ecdsa::{Curve, EcPublicKey};
use crate::error::{DerError, TsaError};
use crate::oid;
use crate::rsa::RsaPublicKey;
use crate::time::{self, GenTime};

/// The signer's public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicKey<'a> {
    Rsa(RsaPublicKey<'a>),
    Ec(EcPublicKey<'a>),
}

/// The parts of a certificate that verification uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Certificate<'a> {
    /// The serial number's `INTEGER` content octets.
    pub(crate) serial: &'a [u8],
    /// The issuer `Name`, whole encoding.
    pub(crate) issuer: &'a [u8],
    /// The subject `Name`, whole encoding.
    pub(crate) subject: &'a [u8],
    pub(crate) not_before: GenTime,
    pub(crate) not_after: GenTime,
    pub(crate) key: PublicKey<'a>,
    /// The subject key identifier extension's key identifier, if present.
    pub(crate) subject_key_id: Option<&'a [u8]>,
}

/// One `Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE, extnValue }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Extension<'a> {
    pub(crate) id: &'a [u8],
    pub(crate) critical: bool,
    pub(crate) value: &'a [u8],
}

/// Reads one `Extension`. `critical` written as `FALSE` is a `DEFAULT`
/// value DER omits.
pub(crate) fn read_extension<'a>(list: &mut Reader<'a>) -> Result<Extension<'a>, DerError> {
    let mut extension = list.sequence()?;
    let id = extension.oid()?;
    let critical = match extension.optional(BOOLEAN)? {
        Some(flag) if der::boolean(flag.value)? => true,
        Some(_) => return Err(DerError::DefaultEncoded),
        None => false,
    };
    let value = extension.octets()?;
    extension.finish()?;
    Ok(Extension {
        id,
        critical,
        value,
    })
}

/// Reads a certificate that is the whole of `raw`.
pub(crate) fn parse(raw: &[u8]) -> Result<Certificate<'_>, TsaError> {
    let mut certificate = der::single(raw, SEQUENCE)?;
    let mut tbs = certificate.sequence()?;
    // The issuer's signature algorithm and value: not verified (the
    // certificate is pinned), but in the subset.
    certificate.checked(SEQUENCE)?;
    certificate.checked(BIT_STRING)?;
    certificate.finish()?;

    if tbs.peek_tag() != Some(CONTEXT_0) {
        return Err(TsaError::CertificateVersion);
    }
    let mut version = tbs.nested(CONTEXT_0)?;
    let number = version.read(INTEGER)?;
    version.finish()?;
    if der::small_unsigned(number.value)? != 2 {
        return Err(TsaError::CertificateVersion);
    }
    let serial = tbs.read(INTEGER)?;
    der::unsigned(serial.value)?;
    tbs.checked(SEQUENCE)?;
    let issuer = tbs.checked(SEQUENCE)?;
    let mut validity = tbs.sequence()?;
    let not_before = read_time(&mut validity)?;
    let not_after = read_time(&mut validity)?;
    validity.finish()?;
    let subject = tbs.checked(SEQUENCE)?;
    let key = read_public_key(&mut tbs)?;
    if tbs.is_empty() {
        return Err(TsaError::MissingTimestampingEku);
    }
    let mut extensions = tbs.nested(CONTEXT_3)?;
    tbs.finish()?;
    let list = extensions.sequence()?;
    extensions.finish()?;
    let subject_key_id = read_extensions(list)?;
    Ok(Certificate {
        serial: serial.value,
        issuer: issuer.raw,
        subject: subject.raw,
        not_before,
        not_after,
        key,
        subject_key_id,
    })
}

/// `Time ::= CHOICE { utcTime UTCTime, generalTime GeneralizedTime }`,
/// without fractions (RFC 5280 §4.1.2.5).
fn read_time(validity: &mut Reader<'_>) -> Result<GenTime, DerError> {
    match validity.peek_tag() {
        Some(UTC_TIME) => time::utc_time(validity.read_any()?.value),
        Some(GENERALIZED_TIME) => time::generalized_time(validity.read_any()?.value, false),
        Some(_) => Err(DerError::UnexpectedTag),
        None => Err(DerError::MissingField),
    }
}

/// `SubjectPublicKeyInfo`: RSA (`rsaEncryption` with `NULL` parameters,
/// RFC 3279 §2.3.1) or EC (`id-ecPublicKey` with a named curve, RFC 5480 §2.1.1).
fn read_public_key<'a>(tbs: &mut Reader<'a>) -> Result<PublicKey<'a>, TsaError> {
    let mut info = tbs.sequence()?;
    let mut algorithm = info.sequence()?;
    let id = algorithm.oid()?;
    let parameters = if algorithm.is_empty() {
        None
    } else {
        Some(algorithm.checked_any()?)
    };
    algorithm.finish()?;
    let key = der::bit_string_octets(info.read(BIT_STRING)?.value)?;
    info.finish()?;
    match (id, parameters) {
        (oid::RSA_ENCRYPTION, Some(parameters)) if parameters.tag == NULL => {
            let mut rsa = der::single(key, SEQUENCE)?;
            let modulus = rsa.unsigned()?;
            let exponent = rsa.unsigned()?;
            rsa.finish()?;
            Ok(PublicKey::Rsa(RsaPublicKey::new(modulus, exponent)?))
        }
        (oid::EC_PUBLIC_KEY, Some(parameters)) if parameters.tag == OID => {
            let curve = match parameters.value {
                oid::P256 => Curve::P256,
                oid::P384 => Curve::P384,
                _ => return Err(TsaError::UnsupportedPublicKey),
            };
            Ok(PublicKey::Ec(EcPublicKey::new(curve, key)?))
        }
        _ => Err(TsaError::UnsupportedPublicKey),
    }
}

/// Records that a processed extension was seen; a second one is refused.
fn first_time(seen: &mut bool) -> Result<(), TsaError> {
    if *seen {
        return Err(TsaError::DuplicateExtension);
    }
    *seen = true;
    Ok(())
}

/// Checks the extension list and returns the subject key identifier.
fn read_extensions(mut list: Reader<'_>) -> Result<Option<&[u8]>, TsaError> {
    if list.is_empty() {
        return Err(TsaError::EmptyExtensions);
    }
    let mut eku = false;
    let mut key_usage = false;
    let mut basic_constraints = false;
    let mut key_id_seen = false;
    let mut key_id = None;
    while !list.is_empty() {
        let extension = read_extension(&mut list)?;
        match extension.id {
            oid::EXT_KEY_USAGE => {
                first_time(&mut eku)?;
                if !extension.critical {
                    return Err(TsaError::EkuNotCritical);
                }
                check_extended_key_usage(extension.value)?;
            }
            oid::KEY_USAGE => {
                first_time(&mut key_usage)?;
                check_key_usage(extension.value)?;
            }
            oid::BASIC_CONSTRAINTS => {
                first_time(&mut basic_constraints)?;
                check_basic_constraints(extension.value)?;
            }
            oid::SUBJECT_KEY_IDENTIFIER => {
                first_time(&mut key_id_seen)?;
                let mut value = Reader::new(extension.value);
                key_id = Some(value.read(OCTET_STRING)?.value);
                value.finish()?;
            }
            _ if extension.critical => return Err(TsaError::CertificateCriticalExtension),
            _ => {}
        }
    }
    if eku {
        Ok(key_id)
    } else {
        Err(TsaError::MissingTimestampingEku)
    }
}

/// `ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId`, which
/// must be exactly `id-kp-timeStamping`.
fn check_extended_key_usage(value: &[u8]) -> Result<(), TsaError> {
    let mut purposes = der::single(value, SEQUENCE)?;
    if purposes.is_empty() {
        return Err(TsaError::EkuNotTimestampingOnly);
    }
    let purpose = purposes.oid()?;
    if purpose == oid::TIME_STAMPING && purposes.is_empty() {
        Ok(())
    } else {
        Err(TsaError::EkuNotTimestampingOnly)
    }
}

/// `KeyUsage ::= BIT STRING`: digitalSignature (bit 0) and/or
/// nonRepudiation (bit 1), nothing else. DER removes trailing zero bits, so
/// these are the only three encodings.
fn check_key_usage(value: &[u8]) -> Result<(), TsaError> {
    match value {
        [0x03, 0x02, 0x07, 0x80] | [0x03, 0x02, 0x06, 0x40 | 0xC0] => Ok(()),
        _ => Err(TsaError::InvalidKeyUsage),
    }
}

/// `BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen … }`:
/// an end-entity certificate, so the value is the empty sequence.
fn check_basic_constraints(value: &[u8]) -> Result<(), TsaError> {
    let mut constraints = der::single(value, SEQUENCE)?;
    if let Some(ca) = constraints.optional(BOOLEAN)? {
        return Err(if der::boolean(ca.value)? {
            TsaError::SignerIsCa
        } else {
            TsaError::Der(DerError::DefaultEncoded)
        });
    }
    constraints.finish()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ext(bytes: &[u8]) -> Result<Extension<'_>, DerError> {
        read_extension(&mut Reader::new(bytes))
    }

    #[test]
    fn extension_flags() {
        let critical = [
            0x30, 0x0A, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x00,
        ];
        assert_eq!(
            ext(&critical),
            Ok(Extension {
                id: oid::KEY_USAGE,
                critical: true,
                value: &[]
            })
        );
        let plain = [0x30, 0x07, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x04, 0x00];
        assert_eq!(ext(&plain).map(|e| e.critical), Ok(false));
        let explicit_false = [
            0x30, 0x0A, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0x00, 0x04, 0x00,
        ];
        assert_eq!(ext(&explicit_false), Err(DerError::DefaultEncoded));
        let bad_bool = [
            0x30, 0x0A, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0x01, 0x04, 0x00,
        ];
        assert_eq!(ext(&bad_bool), Err(DerError::InvalidBoolean));
        let trailing = [
            0x30, 0x09, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x04, 0x00, 0x05, 0x00,
        ];
        assert_eq!(ext(&trailing), Err(DerError::TrailingData));
        let no_value = [0x30, 0x05, 0x06, 0x03, 0x55, 0x1D, 0x0F];
        assert_eq!(ext(&no_value), Err(DerError::MissingField));
    }

    #[test]
    fn key_usage_encodings() {
        assert_eq!(check_key_usage(&[0x03, 0x02, 0x07, 0x80]), Ok(()));
        assert_eq!(check_key_usage(&[0x03, 0x02, 0x06, 0x40]), Ok(()));
        assert_eq!(check_key_usage(&[0x03, 0x02, 0x06, 0xC0]), Ok(()));
        for bad in [
            &[0x03, 0x02, 0x05, 0xE0][..],
            &[0x03, 0x02, 0x00, 0x80],
            &[0x03, 0x02, 0x01, 0x04],
            &[0x03, 0x03, 0x07, 0x80, 0x00],
            &[0x03, 0x01, 0x00],
            &[],
        ] {
            assert_eq!(
                check_key_usage(bad),
                Err(TsaError::InvalidKeyUsage),
                "{bad:02x?}"
            );
        }
    }

    #[test]
    fn basic_constraints() {
        assert_eq!(check_basic_constraints(&[0x30, 0x00]), Ok(()));
        assert_eq!(
            check_basic_constraints(&[0x30, 0x03, 0x01, 0x01, 0xFF]),
            Err(TsaError::SignerIsCa)
        );
        assert_eq!(
            check_basic_constraints(&[0x30, 0x03, 0x01, 0x01, 0x00]),
            Err(TsaError::Der(DerError::DefaultEncoded))
        );
        assert_eq!(
            check_basic_constraints(&[0x30, 0x03, 0x02, 0x01, 0x00]),
            Err(TsaError::Der(DerError::TrailingData))
        );
        assert_eq!(
            check_basic_constraints(&[0x30, 0x03, 0x01, 0x01, 0x05]),
            Err(TsaError::Der(DerError::InvalidBoolean))
        );
    }

    #[test]
    fn extended_key_usage() {
        let ts = [
            0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08,
        ];
        assert_eq!(check_extended_key_usage(&ts), Ok(()));
        let server_auth = [
            0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
        ];
        assert_eq!(
            check_extended_key_usage(&server_auth),
            Err(TsaError::EkuNotTimestampingOnly)
        );
        let mut two = std::vec![0x30, 0x14];
        two.extend_from_slice(&ts[2..]);
        two.extend_from_slice(&server_auth[2..]);
        assert_eq!(
            check_extended_key_usage(&two),
            Err(TsaError::EkuNotTimestampingOnly)
        );
        assert_eq!(
            check_extended_key_usage(&[0x30, 0x00]),
            Err(TsaError::EkuNotTimestampingOnly)
        );
        assert_eq!(
            check_extended_key_usage(&[0x30, 0x02, 0x04, 0x00]),
            Err(TsaError::Der(DerError::UnexpectedTag))
        );
    }

    #[test]
    fn duplicates() {
        let mut seen = false;
        assert_eq!(first_time(&mut seen), Ok(()));
        assert!(seen);
        assert_eq!(first_time(&mut seen), Err(TsaError::DuplicateExtension));
    }
}
