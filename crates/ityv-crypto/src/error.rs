//! Error type for every fallible operation in this crate.
//!
//! Errors carry no secrets and no heap data. Each verification has exactly one
//! failure variant so that a caller learns nothing about *why* a signature,
//! proof or tag failed beyond what the protocol publishes anyway.

/// Why an operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Error {
    /// A canonical-encoding error while writing or parsing a cryptographic
    /// object (`ityv-encoding` error with its byte offset).
    Encoding(ityv_encoding::Error),
    /// A purpose string is not an identifier of one to 32 bytes over
    /// `[A-Za-z0-9._:-]`.
    InvalidPurpose,
    /// A public key encoding is not a valid key of its algorithm.
    InvalidPublicKey,
    /// A secret key encoding is malformed.
    InvalidSecretKey,
    /// A signature did not verify. Covers malformed and wrong signatures alike.
    SignatureInvalid,
    /// A 32-byte point encoding is not a valid Ristretto255 point.
    InvalidPoint,
    /// A 32-byte scalar encoding is not canonical (not less than the group
    /// order).
    NonCanonicalScalar,
    /// An aggregate value has bits set above the packed digit range.
    DigitOverflow,
    /// An option index is outside the statement or the fixed capacity.
    OptionOutOfRange,
    /// A chunk index is outside the statement or the fixed capacity.
    ChunkOutOfRange,
    /// A statement's option count and chunk count are inconsistent or exceed
    /// the fixed capacity.
    InvalidStatement,
    /// A collection exceeds a fixed capacity.
    CapacityExceeded,
    /// Two byte strings that must have the same length do not.
    LengthMismatch,
    /// A chamber threshold has `k = 0`, `k > n` or `n` above the capacity.
    InvalidAccessStructure,
    /// A member identifier is outside the access structure.
    InvalidMember,
    /// The same member appears twice in a share subset.
    DuplicateShare,
    /// The share subset is not in the access structure Γ. Nothing is
    /// reconstructed.
    NotQualified,
    /// Shares beyond the threshold disagree with the reconstructed polynomial.
    InconsistentShares,
    /// A proof did not verify.
    ProofInvalid,
    /// An opening does not match its commitments.
    OpeningInvalid,
    /// An aggregate opening does not match the product of commitments.
    AggregateInvalid,
    /// An X25519 shared secret is the all-zero point (a non-contributory peer
    /// key).
    NonContributoryKey,
    /// Authenticated decryption failed.
    AeadInvalid,
    /// A one-time MAC tag does not match.
    TagMismatch,
    /// The backend library reported a failure on inputs this crate considered
    /// valid. This indicates a bug in the backend or in this crate.
    Backend,
}

impl From<ityv_encoding::Error> for Error {
    fn from(err: ityv_encoding::Error) -> Self {
        Self::Encoding(err)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Encoding(inner) => write!(f, "encoding error: {inner}"),
            Self::InvalidPurpose => f.write_str("purpose is not an identifier of 1..=32 bytes"),
            Self::InvalidPublicKey => f.write_str("public key encoding is invalid"),
            Self::InvalidSecretKey => f.write_str("secret key encoding is invalid"),
            Self::SignatureInvalid => f.write_str("signature verification failed"),
            Self::InvalidPoint => f.write_str("not a valid Ristretto255 point encoding"),
            Self::NonCanonicalScalar => f.write_str("scalar encoding is not canonical"),
            Self::DigitOverflow => f.write_str("aggregate exceeds the packed digit range"),
            Self::OptionOutOfRange => f.write_str("option index out of range"),
            Self::ChunkOutOfRange => f.write_str("chunk index out of range"),
            Self::InvalidStatement => f.write_str("statement counts are inconsistent"),
            Self::CapacityExceeded => f.write_str("fixed capacity exceeded"),
            Self::LengthMismatch => f.write_str("byte string lengths differ"),
            Self::InvalidAccessStructure => f.write_str("chamber threshold is invalid"),
            Self::InvalidMember => f.write_str("member is outside the access structure"),
            Self::DuplicateShare => f.write_str("member appears twice"),
            Self::NotQualified => f.write_str("share subset is not in the access structure"),
            Self::InconsistentShares => f.write_str("shares are inconsistent"),
            Self::ProofInvalid => f.write_str("proof verification failed"),
            Self::OpeningInvalid => f.write_str("opening does not match the commitment"),
            Self::AggregateInvalid => f.write_str("aggregate opening does not match"),
            Self::NonContributoryKey => f.write_str("peer key is non-contributory"),
            Self::AeadInvalid => f.write_str("authenticated decryption failed"),
            Self::TagMismatch => f.write_str("one-time MAC tag mismatch"),
            Self::Backend => f.write_str("backend failure"),
        }
    }
}

impl core::error::Error for Error {}
