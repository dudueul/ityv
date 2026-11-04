//! Object identifiers, as DER content octets.

use crate::der;
use crate::error::TsaError;

/// A validated `OBJECT IDENTIFIER`: its DER content octets (without tag and
/// length), borrowed from the token or the pin.
///
/// Two identifiers are equal exactly when their content octets are equal,
/// because DER has one encoding per identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectId<'a>(&'a [u8]);

impl<'a> ObjectId<'a> {
    /// Checks `content` (the content octets of a DER `OBJECT IDENTIFIER`)
    /// and wraps it.
    ///
    /// # Errors
    ///
    /// [`TsaError::Der`] with [`DerError::InvalidOid`](crate::DerError::InvalidOid)
    /// if `content` is empty, longer than [`MAX_OID_LEN`](crate::MAX_OID_LEN),
    /// has a non-minimal arc or ends inside an arc.
    pub fn from_content(content: &'a [u8]) -> Result<Self, TsaError> {
        der::check_oid(content)?;
        Ok(Self(content))
    }

    /// Wraps content octets the reader has already checked.
    pub(crate) const fn checked(content: &'a [u8]) -> Self {
        Self(content)
    }

    /// The DER content octets.
    #[must_use]
    pub const fn content(&self) -> &'a [u8] {
        self.0
    }
}

// PKCS #7 / CMS (RFC 5652) and S/MIME (RFC 2634, RFC 5035, RFC 3161).
/// `id-signedData`, 1.2.840.113549.1.7.2.
pub(crate) const SIGNED_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
/// `id-ct-TSTInfo`, 1.2.840.113549.1.9.16.1.4.
pub(crate) const TST_INFO: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x04,
];
/// `id-contentType`, 1.2.840.113549.1.9.3.
pub(crate) const CONTENT_TYPE: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03];
/// `id-messageDigest`, 1.2.840.113549.1.9.4.
pub(crate) const MESSAGE_DIGEST: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04];
/// `id-aa-signingCertificate`, 1.2.840.113549.1.9.16.2.12.
pub(crate) const SIGNING_CERTIFICATE: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x0C,
];
/// `id-aa-signingCertificateV2`, 1.2.840.113549.1.9.16.2.47.
pub(crate) const SIGNING_CERTIFICATE_V2: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x02, 0x2F,
];

// Digests (RFC 5754).
/// `id-sha256`, 2.16.840.1.101.3.4.2.1.
pub(crate) const SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// `id-sha384`, 2.16.840.1.101.3.4.2.2.
pub(crate) const SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
/// `id-sha512`, 2.16.840.1.101.3.4.2.3.
pub(crate) const SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

// RSA (RFC 8017, RFC 4055).
/// `rsaEncryption`, 1.2.840.113549.1.1.1.
pub(crate) const RSA_ENCRYPTION: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
/// `sha256WithRSAEncryption`, 1.2.840.113549.1.1.11.
pub(crate) const SHA256_WITH_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
/// `sha384WithRSAEncryption`, 1.2.840.113549.1.1.12.
pub(crate) const SHA384_WITH_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C];
/// `sha512WithRSAEncryption`, 1.2.840.113549.1.1.13.
pub(crate) const SHA512_WITH_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D];

// Elliptic curves (RFC 5480, RFC 5758).
/// `id-ecPublicKey`, 1.2.840.10045.2.1.
pub(crate) const EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// `secp256r1` (`prime256v1`), 1.2.840.10045.3.1.7.
pub(crate) const P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
/// `secp384r1`, 1.3.132.0.34.
pub(crate) const P384: &[u8] = &[0x2B, 0x81, 0x04, 0x00, 0x22];
/// `ecdsa-with-SHA256`, 1.2.840.10045.4.3.2.
pub(crate) const ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
/// `ecdsa-with-SHA384`, 1.2.840.10045.4.3.3.
pub(crate) const ECDSA_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
/// `ecdsa-with-SHA512`, 1.2.840.10045.4.3.4.
pub(crate) const ECDSA_SHA512: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04];

// Certificate extensions (RFC 5280) and key purposes.
/// `id-ce-subjectKeyIdentifier`, 2.5.29.14.
pub(crate) const SUBJECT_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1D, 0x0E];
/// `id-ce-keyUsage`, 2.5.29.15.
pub(crate) const KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x0F];
/// `id-ce-basicConstraints`, 2.5.29.19.
pub(crate) const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1D, 0x13];
/// `id-ce-extKeyUsage`, 2.5.29.37.
pub(crate) const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1D, 0x25];
/// `id-kp-timeStamping`, 1.3.6.1.5.5.7.3.8.
pub(crate) const TIME_STAMPING: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DerError;

    #[test]
    fn constants_are_valid() {
        for oid in [
            SIGNED_DATA,
            TST_INFO,
            CONTENT_TYPE,
            MESSAGE_DIGEST,
            SIGNING_CERTIFICATE,
            SIGNING_CERTIFICATE_V2,
            SHA256,
            SHA384,
            SHA512,
            RSA_ENCRYPTION,
            SHA256_WITH_RSA,
            SHA384_WITH_RSA,
            SHA512_WITH_RSA,
            EC_PUBLIC_KEY,
            P256,
            P384,
            ECDSA_SHA256,
            ECDSA_SHA384,
            ECDSA_SHA512,
            SUBJECT_KEY_IDENTIFIER,
            KEY_USAGE,
            BASIC_CONSTRAINTS,
            EXT_KEY_USAGE,
            TIME_STAMPING,
        ] {
            assert_eq!(ObjectId::from_content(oid).map(|id| id.content()), Ok(oid));
        }
        assert_eq!(
            ObjectId::from_content(&[0x2A, 0x86]),
            Err(TsaError::Der(DerError::InvalidOid))
        );
    }
}
