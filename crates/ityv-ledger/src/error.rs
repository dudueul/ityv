//! Error type for every fallible operation in this crate.
//!
//! Errors carry no heap data and no secrets: a position, a count or a
//! classification, never the bytes that failed.

use crate::publication::Breach;

/// Which diversity dimension of the witness policy was short.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dimension {
    /// Distinct organisations among the signers.
    Organisations,
    /// Distinct infrastructure providers among the signers.
    Providers,
    /// Distinct regions among the signers.
    Regions,
}

/// Which set root of a checkpoint body did not match its recomputation.
/// (The ledger root is checked by the consistency proof, whose failure is
/// [`Error::ProofInvalid`].)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Root {
    /// `box_close_root`, the sorted-set root of box-close event hashes.
    BoxClose,
    /// `dispute_root`, the sorted-set root of open dispute event hashes.
    Dispute,
}

/// Why an operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Error {
    /// A canonical-encoding error while writing or parsing an object.
    Encoding(ityv_encoding::Error),
    /// A cryptographic error from `ityv-crypto`.
    Crypto(ityv_crypto::Error),
    /// The tree already holds 2^40 leaves.
    TreeFull,
    /// A tree size exceeds 2^40, or a proof is longer than the depth bound.
    Capacity,
    /// `old_size > new_size`, or sizes that cannot belong to one proof.
    SizeMismatch,
    /// A leaf index is not below the tree size.
    IndexOutOfRange,
    /// A leaf the accessor could not supply.
    LeafUnavailable,
    /// A proof did not verify against the roots and sizes given.
    ProofInvalid,
    /// A sorted set has an element smaller than its predecessor.
    NotSorted,
    /// A sorted set has an element equal to its predecessor.
    Duplicate,
    /// A frame or checkpoint sequence number is not the predecessor's plus one.
    SequenceGap,
    /// A previous-hash field does not equal the predecessor's hash.
    PreviousHashMismatch,
    /// An election identifier differs from the chain's.
    ElectionMismatch,
    /// The election, ledger or key-set identifier differs from the previous
    /// checkpoint's.
    LedgerMismatch,
    /// A checkpoint claims fewer leaves than its predecessor.
    TreeShrank,
    /// A checkpoint is bound to a different genesis.
    GenesisMismatch,
    /// A checkpoint root does not equal its recomputation.
    RootMismatch(Root),
    /// The frame stream ends inside a record: the bytes from `offset` are a
    /// torn tail to be quarantined; everything before them stays valid.
    TornTail {
        /// Start offset of the truncated record.
        offset: usize,
    },
    /// A frame record declares an impossible length.
    CorruptRecord {
        /// Start offset of the record.
        offset: usize,
    },
    /// A frame record does not decode as a `LedgerFrame` object.
    Record {
        /// Start offset of the record in the stream.
        offset: usize,
        /// The decoding error, with its offset relative to the record.
        inner: ityv_encoding::Error,
    },
    /// A witness identifier in a signed checkpoint is not on the roster.
    UnknownWitness {
        /// Position of the entry in the signature list.
        index: usize,
    },
    /// A witness signature did not verify.
    InvalidSignature {
        /// Position of the entry in the signature list.
        index: usize,
    },
    /// Fewer valid distinct signers than the quorum.
    QuorumShort {
        /// Valid distinct signers.
        have: usize,
        /// The quorum.
        need: usize,
    },
    /// Fewer distinct values in a diversity dimension than the policy needs.
    DiversityShort {
        /// The dimension.
        dimension: Dimension,
        /// Distinct values among the signers.
        have: usize,
        /// The policy minimum.
        need: usize,
    },
    /// A quorum profile does not satisfy `quorum <= witnesses` and
    /// `2·quorum − witnesses > byzantine_max`, or does not match the roster.
    ProfileInvalid,
    /// A roster is unsorted, has duplicate identifiers or exceeds capacity.
    RosterInvalid,
    /// Time-bucket arithmetic overflowed.
    Overflow,
    /// A publication deadline was missed.
    Breach(Breach),
}

impl From<ityv_encoding::Error> for Error {
    fn from(err: ityv_encoding::Error) -> Self {
        Self::Encoding(err)
    }
}

impl From<ityv_crypto::Error> for Error {
    fn from(err: ityv_crypto::Error) -> Self {
        Self::Crypto(err)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Encoding(inner) => write!(f, "encoding error: {inner}"),
            Self::Crypto(inner) => write!(f, "cryptographic error: {inner}"),
            Self::TreeFull => f.write_str("tree holds the maximum number of leaves"),
            Self::Capacity => f.write_str("fixed capacity exceeded"),
            Self::SizeMismatch => f.write_str("tree sizes are inconsistent"),
            Self::IndexOutOfRange => f.write_str("leaf index is not below the tree size"),
            Self::LeafUnavailable => f.write_str("leaf accessor returned no leaf"),
            Self::ProofInvalid => f.write_str("proof verification failed"),
            Self::NotSorted => f.write_str("set is not in ascending order"),
            Self::Duplicate => f.write_str("set contains a duplicate"),
            Self::SequenceGap => f.write_str("sequence number is not the predecessor plus one"),
            Self::PreviousHashMismatch => f.write_str("previous hash does not match"),
            Self::ElectionMismatch => f.write_str("election identifier differs"),
            Self::LedgerMismatch => f.write_str("election, ledger or key-set identifier differs"),
            Self::TreeShrank => f.write_str("tree size decreased"),
            Self::GenesisMismatch => f.write_str("genesis hash differs"),
            Self::RootMismatch(root) => write!(f, "{root:?} root does not match"),
            Self::TornTail { offset } => write!(f, "torn tail at offset {offset}"),
            Self::CorruptRecord { offset } => write!(f, "corrupt record at offset {offset}"),
            Self::Record { offset, inner } => {
                write!(f, "record at offset {offset} failed to decode: {inner}")
            }
            Self::UnknownWitness { index } => write!(f, "signature {index}: unknown witness"),
            Self::InvalidSignature { index } => write!(f, "signature {index}: invalid"),
            Self::QuorumShort { have, need } => write!(f, "quorum short: {have} of {need}"),
            Self::DiversityShort {
                dimension,
                have,
                need,
            } => write!(f, "{dimension:?} short: {have} of {need}"),
            Self::ProfileInvalid => f.write_str("quorum profile is invalid"),
            Self::RosterInvalid => f.write_str("roster is invalid"),
            Self::Overflow => f.write_str("time-bucket arithmetic overflowed"),
            Self::Breach(breach) => write!(f, "publication breach: {breach}"),
        }
    }
}

impl core::error::Error for Error {}
