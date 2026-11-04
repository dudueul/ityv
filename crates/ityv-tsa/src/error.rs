//! Errors. Every refusal is one specific variant; errors carry no strings and
//! no heap data.

/// A violation of the strict DER subset this crate reads (X.690 DER, with the
/// limits of [`MAX_TOKEN_LEN`](crate::MAX_TOKEN_LEN) and
/// [`MAX_DEPTH`](crate::MAX_DEPTH)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DerError {
    /// An element's header or value runs past the end of its enclosing value.
    Truncated,
    /// A tag number of 31 or more (multi-octet tag); no structure here needs one.
    HighTagNumber,
    /// The indefinite length form (`0x80`), which DER forbids.
    IndefiniteLength,
    /// A length in the long form that fits a shorter form.
    NonMinimalLength,
    /// A length of more than two octets; no element of a bounded token needs one.
    LengthTooLarge,
    /// Constructed elements nested deeper than [`MAX_DEPTH`](crate::MAX_DEPTH).
    DepthExceeded,
    /// A required field is absent: its enclosing value ended first.
    MissingField,
    /// An element's tag is not the one the structure requires here.
    UnexpectedTag,
    /// A universal tag in a form DER forbids: a constructed string or time, a
    /// primitive `SEQUENCE` or `SET`, or the end-of-contents tag.
    InvalidTagForm,
    /// Bytes remain after the last field of a value or of the input.
    TrailingData,
    /// A `BOOLEAN` that is not the single octet `0x00` or `0xFF`.
    InvalidBoolean,
    /// A field whose `DEFAULT` value is written out, which DER forbids.
    DefaultEncoded,
    /// An `INTEGER` with no content octets.
    EmptyInteger,
    /// An `INTEGER` with a redundant leading `0x00` or `0xFF` octet.
    NonMinimalInteger,
    /// A negative `INTEGER` where only non-negative values are allowed.
    NegativeInteger,
    /// An `INTEGER` larger than its field allows.
    IntegerTooLarge,
    /// An `OBJECT IDENTIFIER` that is empty, longer than
    /// [`MAX_OID_LEN`](crate::MAX_OID_LEN), has a non-minimal arc or ends
    /// inside an arc.
    InvalidOid,
    /// A `NULL` with content octets.
    InvalidNull,
    /// A `BIT STRING` with more than seven unused bits, unused bits in an empty
    /// string, non-zero padding bits, or unused bits where whole octets are
    /// required.
    InvalidBitString,
    /// A `SET` or `SET OF` whose elements are not in ascending DER order.
    SetNotSorted,
    /// A `GeneralizedTime` or `UTCTime` outside the strict form: not
    /// `YYYYMMDDhhmmss[.f]Z` (or `YYMMDDhhmmssZ`), a field out of range, a
    /// fraction that is empty, longer than nine digits or ends in `0`, a
    /// fraction where none is allowed, or a year before 1970.
    InvalidTime,
}

/// Why a token, a pin or an imprint was refused.
///
/// The variants are grouped as the verification proceeds: size and DER, the
/// CMS layers, the signed attributes, the certificate and its key, the
/// algorithms the pin allows, the signature, and the `TSTInfo` content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TsaError {
    /// The token is longer than [`MAX_TOKEN_LEN`](crate::MAX_TOKEN_LEN).
    TokenTooLarge,
    /// The token (or a pinned certificate) is not in the strict DER subset.
    Der(DerError),

    /// The `ContentInfo` content type is not `id-signedData`.
    NotSignedData,
    /// The `SignedData` version is not 3 (RFC 5652 §5.1 for `id-ct-TSTInfo`).
    SignedDataVersion,
    /// `digestAlgorithms` is not exactly the one algorithm the signer uses.
    DigestAlgorithmSet,
    /// The encapsulated content type is not `id-ct-TSTInfo`.
    NotTstInfo,
    /// The encapsulated content is absent (a detached signature).
    MissingContent,
    /// More than [`MAX_CERTIFICATES`](crate::MAX_CERTIFICATES) embedded certificates.
    TooManyCertificates,
    /// An embedded certificate choice other than an X.509 `Certificate`.
    UnsupportedCertificateChoice,
    /// The `SignedData` carries revocation information, which this subset refuses.
    CrlsPresent,
    /// The token does not have exactly one `SignerInfo`.
    SignerCount,
    /// The `SignerInfo` version does not match its signer identifier form
    /// (1 for issuer and serial, 3 for subject key identifier).
    SignerInfoVersion,
    /// The `SignerInfo` has no signed attributes.
    MissingSignedAttributes,

    /// A required signed attribute does not have exactly one value.
    AttributeValueCount,
    /// A required signed attribute appears more than once.
    DuplicateAttribute,
    /// The content-type signed attribute is absent.
    MissingContentType,
    /// The content-type signed attribute is not `id-ct-TSTInfo`.
    ContentTypeMismatch,
    /// The message-digest signed attribute is absent.
    MissingMessageDigest,
    /// The message-digest signed attribute is not the digest of the `TSTInfo`.
    MessageDigestMismatch,
    /// Neither ESS signing-certificate attribute (v1 or v2) is present.
    MissingSigningCertificate,
    /// An ESS signing-certificate v1 (SHA-1) attribute, which the pin does not allow.
    SigningCertificateV1NotAllowed,
    /// The ESS certificate hash is not the hash of the signer's certificate.
    SigningCertificateMismatch,
    /// The ESS `issuerSerial` does not name the signer's certificate.
    SigningCertificateIssuerMismatch,

    /// Neither an embedded certificate nor the pinned certificate has the
    /// pinned hash (the token is from another authority, or the pin carries
    /// no certificate and the token embeds none).
    CertificateNotPinned,
    /// The signer's certificate is not X.509 v3.
    CertificateVersion,
    /// The signer's certificate has a critical extension this crate does not process.
    CertificateCriticalExtension,
    /// The signer's certificate repeats an extension this crate processes.
    DuplicateExtension,
    /// An extension list is present but empty.
    EmptyExtensions,
    /// The signer's certificate has no extended key usage extension.
    MissingTimestampingEku,
    /// The extended key usage extension is not critical (RFC 3161 §2.3).
    EkuNotCritical,
    /// The extended key usage is not exactly `id-kp-timeStamping` (RFC 3161 §2.3).
    EkuNotTimestampingOnly,
    /// The key usage is not digital signature and/or non-repudiation only.
    InvalidKeyUsage,
    /// The signer's certificate is a CA certificate.
    SignerIsCa,
    /// The signer identifier does not name the signer's certificate.
    SignerIdentifierMismatch,
    /// The `genTime` lies outside the signer certificate's validity period.
    OutsideValidity,

    /// The certificate's public key is neither RSA nor EC on P-256 or P-384,
    /// or its algorithm parameters are not the required ones.
    UnsupportedPublicKey,
    /// The RSA modulus is shorter than 2048 or longer than 4096 bits.
    RsaModulusSize,
    /// The RSA modulus is even.
    RsaModulusEven,
    /// The RSA public exponent is even or outside `2^16 < e < 2^256` (FIPS 186-5 §5.4).
    RsaExponent,
    /// The EC public key is not an uncompressed point on its curve.
    InvalidEcPoint,

    /// A digest algorithm other than SHA-256, SHA-384 or SHA-512, or
    /// parameters other than absent or `NULL`.
    UnknownDigestAlgorithm,
    /// A digest algorithm the pin does not allow.
    DigestNotAllowed,
    /// A signature algorithm identifier this crate does not know, or
    /// parameters it does not allow.
    UnknownSignatureAlgorithm,
    /// The signature algorithm names a digest other than the signer's digest algorithm.
    SignatureDigestMismatch,
    /// The key and digest do not form a supported signature algorithm: an RSA
    /// algorithm with an EC key or the reverse, or ECDSA with a digest other
    /// than the curve's (P-256 takes SHA-256 only; P-384 takes SHA-384 or
    /// SHA-512).
    UnsupportedSignatureAlgorithm,
    /// A signature algorithm the pin does not allow.
    SignatureNotAllowed,

    /// The RSA signature is not exactly as long as the modulus (RFC 8017 §8.2.2).
    RsaSignatureLength,
    /// The RSA signature, as an integer, is not less than the modulus (RFC 8017 §5.2.2).
    RsaSignatureOutOfRange,
    /// The ECDSA signature is not a strict DER `Ecdsa-Sig-Value` with `r` and
    /// `s` in `[1, n-1]`.
    EcdsaSignatureEncoding,
    /// The signature does not verify.
    SignatureInvalid,

    /// The `TSTInfo` version is not 1.
    TstInfoVersion,
    /// The serial number is longer than 160 bits (RFC 3161 §2.4.2).
    SerialTooLarge,
    /// The nonce is longer than [`MAX_NONCE_LEN`](crate::MAX_NONCE_LEN) octets.
    NonceTooLarge,
    /// An accuracy `millis` or `micros` outside `1..=999`.
    InvalidAccuracy,
    /// An accuracy `seconds` above [`MAX_ACCURACY_SECONDS`](crate::MAX_ACCURACY_SECONDS).
    AccuracyTooLarge,
    /// A critical `TSTInfo` extension (none is understood, so every one is refused).
    CriticalExtension,
    /// The token's imprint uses another digest algorithm than the expected one.
    ImprintAlgorithmMismatch,
    /// The token's imprint is not the expected digest.
    ImprintMismatch,
    /// The policy is not one the pin allows.
    PolicyNotAllowed,
    /// The `tsa` name is not the signer certificate's subject (RFC 3161 §2.4.2).
    TsaNameMismatch,

    /// An imprint whose digest length does not match its algorithm.
    ImprintLength,

    /// A pin whose format version is not [`PIN_FORMAT_VERSION`](crate::PIN_FORMAT_VERSION).
    PinVersion,
    /// A pin that ends early or has bytes after its last field.
    PinLength,
    /// A pin digest mask that is empty or has unknown bits.
    PinDigests,
    /// A pin signature mask that is empty or has unknown bits.
    PinSignatures,
    /// A pin flags octet with unknown bits.
    PinFlags,
    /// A pin policy list with a count outside `1..=MAX_POLICIES`, an invalid
    /// object identifier, or identifiers not in strictly ascending DER order.
    PinPolicies,
    /// A pinned certificate that is not one DER element or whose SHA-256 is
    /// not the pinned hash.
    PinCertificate,
    /// The output buffer is too small for the encoded pin.
    PinBufferTooSmall,
}

impl From<DerError> for TsaError {
    fn from(error: DerError) -> Self {
        Self::Der(error)
    }
}

impl core::fmt::Display for DerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl core::fmt::Display for TsaError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl core::error::Error for DerError {}

impl core::error::Error for TsaError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;

    #[test]
    fn errors_display_their_names() {
        assert_eq!(DerError::IndefiniteLength.to_string(), "IndefiniteLength");
        assert_eq!(TsaError::ImprintMismatch.to_string(), "ImprintMismatch");
        assert_eq!(
            TsaError::from(DerError::SetNotSorted).to_string(),
            "Der(SetNotSorted)"
        );
    }
}
