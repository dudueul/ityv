//! Errors. Every refusal is a value; nothing panics.
//!
//! An [`Error`] means the input cannot be applied at all (an illegal
//! transition, a missing capability, a malformed chain link). A recorded
//! event that is applicable but reveals a discrepancy is not an error: it
//! is applied and leaves a sticky [`crate::hold::HoldReason`] instead
//! (PROTOCOL.md §10.2: "마감은 수록되되 상태는 `HOLD_REVIEW`").

use ityv_encoding::Scope;

use crate::dispute::{DisputeEvent, DisputeStatus};
use crate::record::{Primary, RecordEvent};

/// Why an input was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Error {
    /// The record event does not apply to the record's current state.
    RecordTransition {
        /// The record's primary state.
        from: Primary,
        /// The refused event.
        event: RecordEvent,
    },
    /// The dispute event does not apply to the dispute's current status.
    DisputeTransition {
        /// The dispute's status.
        from: DisputeStatus,
        /// The refused event.
        event: DisputeEvent,
    },
    /// The operation needs a scope the legal authorization does not grant
    /// (VC-007).
    ScopeMissing(Scope),
    /// A granted scope lacks a scope it presupposes (VC-008, no stage
    /// skipping).
    ScopePrerequisite {
        /// The scope that was granted.
        scope: Scope,
        /// The scope it requires.
        requires: Scope,
    },
    /// The day is outside the legal authorization's effective window.
    OutsideEffectiveWindow,
    /// A verification token covers other bytes, another purpose or another
    /// signature than the one presented.
    SignatureObject,
    /// A verification token comes from an unexpected key, or two required
    /// signers are the same key (VC-006).
    SignatureSigner,
    /// A signature is present but no verification token covers it.
    Unverified,
    /// The authorization object does not decode.
    Decode,
    /// The input belongs to another election, box or dispute type.
    Mismatch,
    /// An identifier appears twice where it must be unique.
    Duplicate,
    /// The operation does not exist for the box's collection profile (a
    /// challenge in a receipt-scan box, a receipt outside the
    /// out-of-district profile, PROTOCOL.md §17).
    Profile,
    /// A signer, device or module is not registered in the genesis (VC-009,
    /// VC-037).
    NotRegistered,
    /// A repeated signer, or fewer than two clerks and two observers of
    /// different organisations (VC-016, VC-038).
    SignersShort,
    /// A custody handoff index is not the next one.
    CustodyIndex {
        /// The next index the chain expects.
        expected: u32,
        /// The index given.
        got: u32,
    },
    /// A custody handoff does not name the previous handoff, or its sender
    /// is not the previous receiver.
    CustodyPrevious,
    /// Sender and receiver of a custody handoff are the same organisation
    /// (VC-040).
    CustodySameOrganisation,
    /// A custody handoff leaves the route fixed in the genesis, or the
    /// route has fewer than two stops (VC-040).
    CustodyRoute,
    /// A custody handoff or seal change lacks a party's signature.
    CustodyUnsigned,
    /// A seal change does not start from the chain's current seal.
    CustodySeal,
    /// A late box close for a box not closed manually, or without a device
    /// signature.
    LateClose,
    /// A batch would attest more records than the ledger shows for the box.
    BatchExceedsRecords,
    /// A dispute was not received by both the election commission and the
    /// Independent Verification Committee.
    DisputeFiling,
    /// A tally event before its preconditions (VC-057, VC-063).
    TallyPremature,
    /// A counter would overflow.
    Overflow,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RecordTransition { from, event } => {
                write!(f, "record event {event:?} does not apply to {from:?}")
            }
            Self::DisputeTransition { from, event } => {
                write!(f, "dispute event {event:?} does not apply to {from:?}")
            }
            Self::ScopeMissing(scope) => write!(f, "scope {scope:?} is not authorized"),
            Self::ScopePrerequisite { scope, requires } => {
                write!(f, "scope {scope:?} requires {requires:?}")
            }
            Self::OutsideEffectiveWindow => f.write_str("outside the effective window"),
            Self::SignatureObject => f.write_str("token does not cover this signed object"),
            Self::SignatureSigner => f.write_str("signature from an unexpected signer"),
            Self::Unverified => f.write_str("signature present but not verified"),
            Self::Decode => f.write_str("object does not decode"),
            Self::Mismatch => f.write_str("belongs to another election, box or type"),
            Self::Duplicate => f.write_str("identifier appears twice"),
            Self::Profile => f.write_str("not available for this collection profile"),
            Self::NotRegistered => f.write_str("signer, device or module not registered"),
            Self::SignersShort => f.write_str("too few independent signers"),
            Self::CustodyIndex { expected, got } => {
                write!(f, "custody index {got}, expected {expected}")
            }
            Self::CustodyPrevious => f.write_str("custody handoff does not chain"),
            Self::CustodySameOrganisation => f.write_str("custody handoff within one organisation"),
            Self::CustodyRoute => f.write_str("custody handoff off the route"),
            Self::CustodyUnsigned => f.write_str("custody event not signed by both parties"),
            Self::CustodySeal => f.write_str("seal change does not start from the current seal"),
            Self::LateClose => f.write_str("late box close not applicable"),
            Self::BatchExceedsRecords => f.write_str("batch exceeds the records of the box"),
            Self::DisputeFiling => f.write_str("dispute not received by both bodies"),
            Self::TallyPremature => f.write_str("tally event before its preconditions"),
            Self::Overflow => f.write_str("counter overflow"),
        }
    }
}

impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::string::ToString;

    use ityv_encoding::Scope;

    use super::Error;
    use crate::dispute::{DisputeEvent, DisputeStatus};
    use crate::record::{Primary, RecordEvent};

    #[test]
    fn every_error_displays_distinctly() {
        let all = [
            Error::RecordTransition {
                from: Primary::Cast,
                event: RecordEvent::Challenged,
            },
            Error::DisputeTransition {
                from: DisputeStatus::Open,
                event: DisputeEvent::Investigate,
            },
            Error::ScopeMissing(Scope::Rla),
            Error::ScopePrerequisite {
                scope: Scope::VoterCode,
                requires: Scope::BallotMark,
            },
            Error::OutsideEffectiveWindow,
            Error::SignatureObject,
            Error::SignatureSigner,
            Error::Unverified,
            Error::Decode,
            Error::Mismatch,
            Error::Duplicate,
            Error::Profile,
            Error::NotRegistered,
            Error::SignersShort,
            Error::CustodyIndex {
                expected: 2,
                got: 3,
            },
            Error::CustodyPrevious,
            Error::CustodySameOrganisation,
            Error::CustodyRoute,
            Error::CustodyUnsigned,
            Error::CustodySeal,
            Error::LateClose,
            Error::BatchExceedsRecords,
            Error::DisputeFiling,
            Error::TallyPremature,
            Error::Overflow,
        ];
        let texts: BTreeSet<_> = all.iter().map(ToString::to_string).collect();
        assert_eq!(texts.len(), all.len());
        assert!(texts.iter().all(|t| !t.is_empty()));
        assert!(texts.contains("custody index 3, expected 2"));
        assert!(texts.contains("scope VoterCode requires BallotMark"));
        assert!(texts.contains("scope Rla is not authorized"));
        assert!(texts.contains("record event Challenged does not apply to Cast"));
        assert!(texts.contains("dispute event Investigate does not apply to Open"));
    }
}
