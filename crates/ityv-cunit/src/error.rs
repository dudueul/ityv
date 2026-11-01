//! Error type for every fallible operation in this crate.
//!
//! Errors carry no heap data and no secrets: a classification, an index or
//! a counter, never the bytes that failed.

use core::fmt;

use crate::port::{JournalError, PortError};

/// Which configuration rule was violated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigFault {
    /// Modules are not strictly ascending by identifier, or more than six.
    ModulesUnsorted,
    /// X or Y has no own module, J, A or C has no module (own or neutral
    /// delegation), N has one, or a chamber has two.
    ChamberModules,
    /// Trustees are not strictly ascending by identifier, or more than 64.
    TrusteesUnsorted,
    /// A chamber's member indices are not exactly `0..n_c`.
    MemberIndices,
    /// A chamber's trustee count differs from its threshold's `n`.
    ThresholdCount,
    /// No ballot style, or more than the capacity.
    Styles,
    /// Styles are not strictly ascending by identifier bytes (unsorted or
    /// duplicate identifiers).
    StylesUnsorted,
}

/// A box-close invariant of PROTOCOL.md §10.2 (VC-038).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Invariant {
    /// `paper_count == record_count + no_record_count`.
    PaperCount,
    /// `record_count == attested_count + records in the open batch`.
    AttestedCount,
    /// Spoiled-envelope count `== challenge_count + quarantine_count`.
    SpoiledEnvelopes,
    /// Every module's final counter `== record_count + challenge_count + quarantine_count`.
    ModuleCounters,
    /// `open_batches == 0`.
    OpenBatches,
    /// Absentee profile: envelope count `== record_count`.
    EnvelopeCount,
    /// `no_record_count > 0` without a `FallbackDeclared` event.
    FallbackDeclared,
    /// A record's paper went missing, or an imprinted paper matched no
    /// record, at a resume (PROTOCOL.md §7.3 step 7).
    PaperIncidents,
}

/// Why an operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Error {
    /// A canonical-encoding error while writing or parsing an object.
    Encoding(ityv_encoding::Error),
    /// A cryptographic error from `ityv-crypto`.
    Crypto(ityv_crypto::Error),
    /// A Merkle error from `ityv-ledger` (sorted-set roots).
    Ledger(ityv_ledger::Error),
    /// A chamber-module port failed.
    Port(PortError),
    /// The journal sink failed to make an entry durable.
    Journal(JournalError),
    /// The election configuration is inconsistent.
    Config(ConfigFault),
    /// A host buffer is too small for the object being written.
    BufferTooSmall,
    /// The interpretation names another election.
    WrongElection,
    /// The interpretation names a ballot style the configuration lacks.
    UnknownBallotStyle,
    /// The option index is not in `0..=m+1`.
    OptionOutOfRange,
    /// The number of ports differs from the number of configured modules.
    PortCount,
    /// A module issue names another module than the port's.
    WrongModule,
    /// A module issue's chamber is not the chamber the module serves.
    WrongChamber,
    /// A module counter skips past the module's high-water mark plus one.
    CounterGap,
    /// A module counter is at or below the module's high-water mark (a
    /// replayed or backwards counter); the mark is unchanged.
    CounterRegression,
    /// A module issue's randomness count differs from the chunk count.
    ChunkCountMismatch,
    /// A module issue's envelope label is present or absent against the profile.
    LabelPresence,
    /// A module issue's tag count differs from the chamber's member count.
    TagCount,
    /// The returned pad identifier differs from the trustee's.
    PadIdMismatch,
    /// The returned pad index is not `counter × b` (VC-034).
    PadIndexMismatch,
    /// A module's record signature does not verify under its genesis key.
    RecordSignature,
    /// A module's batch signature does not verify under its genesis key.
    BatchSignature,
    /// The in-memory journal head differs from the head the host re-read
    /// from storage (VC-056). The unit stays faulted: it refuses new
    /// ballots, batches, scan counts and the close signature.
    JournalMismatch,
    /// A journal stream read at resume has a broken head chain, an entry
    /// that does not decode, or an entry inconsistent with the ones before.
    JournalCorrupt,
    /// The batch is empty, so it cannot be closed.
    BatchEmpty,
    /// The batch already holds 64 records.
    BatchFull,
    /// The box is closed; no new ballot, batch or attest can be produced.
    BoxClosed,
    /// A purpose literal was rejected by `ityv-crypto`.
    InvalidPurpose,
    /// An arithmetic bound was exceeded (counters, sizes).
    Overflow,
    /// A chamber code or index outside the fixed capacities.
    Capacity,
    /// A ballot is already in flight; the scanner handles one at a time.
    BallotInFlight,
    /// No ballot is in flight.
    NoBallotInFlight,
    /// The ballot is not the one in flight (it was quarantined or replaced).
    StaleBallot,
    /// A time bucket is earlier than the last journaled one.
    TimeRegression,
    /// Slips are printed only when the `VOTER_CODE` scope is active.
    VoterCodeDisabled,
    /// The close inputs carry an envelope count for an in-person box, or
    /// none for an absentee box.
    EnvelopeCountProfile,
    /// The close token belongs to another box.
    ForeignCloseToken,
}

impl From<ityv_encoding::Error> for Error {
    fn from(error: ityv_encoding::Error) -> Self {
        Self::Encoding(error)
    }
}

impl From<ityv_crypto::Error> for Error {
    fn from(error: ityv_crypto::Error) -> Self {
        Self::Crypto(error)
    }
}

impl From<ityv_ledger::Error> for Error {
    fn from(error: ityv_ledger::Error) -> Self {
        Self::Ledger(error)
    }
}

impl From<PortError> for Error {
    fn from(error: PortError) -> Self {
        Self::Port(error)
    }
}

impl From<JournalError> for Error {
    fn from(error: JournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<ConfigFault> for Error {
    fn from(fault: ConfigFault) -> Self {
        Self::Config(fault)
    }
}

impl fmt::Display for ConfigFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ModulesUnsorted => "modules not strictly ascending or more than six",
            Self::ChamberModules => {
                "chamber modules violate X/Y own, J/A/C own or neutral, N none, one per chamber"
            }
            Self::TrusteesUnsorted => "trustees not strictly ascending or more than 64",
            Self::MemberIndices => "member indices of a chamber are not 0..n",
            Self::ThresholdCount => "trustee count of a chamber differs from its threshold n",
            Self::Styles => "no ballot style, or more than 4096",
            Self::StylesUnsorted => "ballot styles not strictly ascending by identifier",
        })
    }
}

impl fmt::Display for Invariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PaperCount => "paper_count != record_count + no_record_count",
            Self::AttestedCount => "record_count != attested_count + open batch records",
            Self::SpoiledEnvelopes => "spoiled envelopes != challenge_count + quarantine_count",
            Self::ModuleCounters => "a module final counter != records + challenges + quarantines",
            Self::OpenBatches => "open_batches != 0",
            Self::EnvelopeCount => "envelope count != record_count",
            Self::FallbackDeclared => "no_record_count > 0 without FallbackDeclared",
            Self::PaperIncidents => "a paper went missing or matched no record at a resume",
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(e) => write!(f, "encoding: {e}"),
            Self::Crypto(e) => write!(f, "crypto: {e}"),
            Self::Ledger(e) => write!(f, "ledger: {e}"),
            Self::Port(e) => write!(f, "module port: {e}"),
            Self::Journal(e) => write!(f, "journal: {e}"),
            Self::Config(fault) => write!(f, "configuration: {fault}"),
            Self::BufferTooSmall => f.write_str("host buffer too small"),
            Self::WrongElection => f.write_str("interpretation names another election"),
            Self::UnknownBallotStyle => f.write_str("unknown ballot style"),
            Self::OptionOutOfRange => f.write_str("option index outside 0..=m+1"),
            Self::PortCount => f.write_str("port count differs from module count"),
            Self::WrongModule => f.write_str("module issue names another module"),
            Self::WrongChamber => f.write_str("module issue names another chamber"),
            Self::CounterGap => f.write_str("module counter skips past the high-water mark"),
            Self::CounterRegression => {
                f.write_str("module counter at or below the high-water mark")
            }
            Self::ChunkCountMismatch => {
                f.write_str("module randomness count differs from chunk count")
            }
            Self::LabelPresence => {
                f.write_str("envelope label presence disagrees with the profile")
            }
            Self::TagCount => f.write_str("module tag count differs from the member count"),
            Self::PadIdMismatch => f.write_str("pad identifier differs from the trustee's"),
            Self::PadIndexMismatch => f.write_str("pad index is not counter times the consumption"),
            Self::RecordSignature => f.write_str("module record signature does not verify"),
            Self::BatchSignature => f.write_str("module batch signature does not verify"),
            Self::JournalMismatch => {
                f.write_str("journal head differs from the host's re-read head")
            }
            Self::JournalCorrupt => f.write_str("journal stream is broken or corrupt"),
            Self::BatchEmpty => f.write_str("batch is empty"),
            Self::BatchFull => f.write_str("batch holds 64 records"),
            Self::BoxClosed => f.write_str("box is closed"),
            Self::InvalidPurpose => f.write_str("purpose literal rejected"),
            Self::Overflow => f.write_str("arithmetic bound exceeded"),
            Self::Capacity => f.write_str("fixed capacity exceeded"),
            Self::BallotInFlight => f.write_str("a ballot is already in flight"),
            Self::NoBallotInFlight => f.write_str("no ballot is in flight"),
            Self::StaleBallot => f.write_str("ballot is not the one in flight"),
            Self::TimeRegression => f.write_str("time bucket earlier than the journal's last"),
            Self::VoterCodeDisabled => f.write_str("voter code scope is not active"),
            Self::EnvelopeCountProfile => {
                f.write_str("envelope count presence disagrees with the profile")
            }
            Self::ForeignCloseToken => f.write_str("close token belongs to another box"),
        }
    }
}

impl core::error::Error for Error {}
