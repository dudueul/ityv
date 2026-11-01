//! `HOLD_REVIEW` as a sticky set of reasons.
//!
//! A hold never disappears by accumulation: reasons are only added. The two
//! exceptions are events the specification defines as resolving a specific
//! reason (a late box close for a manual close, a late batch close for open
//! batches, PROTOCOL.md §10.2, §7.2.1); only this crate can remove a
//! reason, and only through those transitions ([`crate::boxes`]).

/// Why something is under `HOLD_REVIEW`.
///
/// The codes are this crate's own numbering for display and for the sticky
/// set; they are not a wire format (ADR-0025).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum HoldReason {
    /// Polling-station box: `paper_count != record_count + no_record_count`.
    PaperRecordMismatch = 0,
    /// `attested_count` exceeds `record_count`, or differs from it with no
    /// batch open.
    AttestedMismatch = 1,
    /// Physical spoil envelopes `!= challenge_count + quarantine_count`.
    SpoilEnvelopeMismatch = 2,
    /// A module's final counter is not `record_count + challenge_count +
    /// quarantine_count`, or the modules at close are not those at opening.
    ModuleCounterGap = 3,
    /// Batches were still open at close (resolved once a late batch close
    /// attests every record).
    OpenBatches = 4,
    /// `visit_count <= record_count <= 8 * visit_count` does not hold.
    VisitBounds = 5,
    /// Ballots without a record but no `FallbackDeclared`.
    FallbackUndeclared = 6,
    /// The counts reported at close differ from the records, challenges or
    /// batch attestations observed on the ledger for the box.
    ObservedCountMismatch = 7,
    /// The close carries no device signature (`BoxCloseManual`; resolved by
    /// a `LateBoxClose` whose human counts match).
    ManualClose = 8,
    /// A `LateBoxClose` reports human counts different from the manual
    /// close.
    LateCloseDiffers = 9,
    /// A seal number did not match at opening.
    SealMismatch = 10,
    /// The box was not empty at opening.
    OpeningNonZero = 11,
    /// Out-of-district box: `paper_count` is not 0.
    AbsenteePaperNonZero = 12,
    /// Out-of-district box: `sticker_count != visit_count`; polling-station
    /// box: `sticker_count != 0`.
    StickerVisitMismatch = 13,
    /// Out-of-district box: `envelope_count != issued − returned empty`;
    /// polling-station box: `envelope_count != 0`.
    EnvelopeMismatch = 14,
    /// Out-of-district box closed without an `IssuanceCount` to compare
    /// the envelopes with.
    IssuanceMissing = 15,
    /// A custody handoff carries a count different from the close.
    CustodyCountMismatch = 16,
    /// A custody handoff's seal digest changed without a `SealChange`.
    CustodySealUnexplained = 17,
    /// The box reached counting without a complete custody chain.
    CustodyIncomplete = 18,
    /// The counting-centre imprint reader found unimprinted ballots or
    /// duplicate cast ids (`ImprintAudit`).
    ImprintAudit = 19,
    /// The issuance accounting identity does not hold.
    IssuanceMismatch = 20,
    /// The check-in count does not match issuance.
    ParticipationMismatch = 21,
    /// A record awaits a legal decision (`RECEIVED_DAMAGED`,
    /// `WRONG_DISTRICT`).
    LegalDecisionPending = 22,
    /// A verification step failed.
    StepFailed = 23,
    /// A dispute is unresolved.
    OpenDispute = 24,
    /// Split-view evidence exists (VC-065).
    SplitView = 25,
    /// The board was published late or not at all (§5.5).
    PublicationLate = 26,
    /// A box under review contributes to the verifier's status.
    BoxUnderReview = 27,
}

impl HoldReason {
    /// Every reason in code order.
    pub const ALL: [Self; 28] = [
        Self::PaperRecordMismatch,
        Self::AttestedMismatch,
        Self::SpoilEnvelopeMismatch,
        Self::ModuleCounterGap,
        Self::OpenBatches,
        Self::VisitBounds,
        Self::FallbackUndeclared,
        Self::ObservedCountMismatch,
        Self::ManualClose,
        Self::LateCloseDiffers,
        Self::SealMismatch,
        Self::OpeningNonZero,
        Self::AbsenteePaperNonZero,
        Self::StickerVisitMismatch,
        Self::EnvelopeMismatch,
        Self::IssuanceMissing,
        Self::CustodyCountMismatch,
        Self::CustodySealUnexplained,
        Self::CustodyIncomplete,
        Self::ImprintAudit,
        Self::IssuanceMismatch,
        Self::ParticipationMismatch,
        Self::LegalDecisionPending,
        Self::StepFailed,
        Self::OpenDispute,
        Self::SplitView,
        Self::PublicationLate,
        Self::BoxUnderReview,
    ];

    /// The reason's code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    const fn bit(self) -> u32 {
        // Codes are below 32 (pinned by a test), so the shift cannot overflow.
        1u32 << self.code()
    }
}

/// A set of hold reasons. Empty means not under review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct HoldSet {
    mask: u32,
}

impl HoldSet {
    /// No reason: not under review.
    #[must_use]
    pub const fn empty() -> Self {
        Self { mask: 0 }
    }

    /// Returns the set with `reason` added.
    #[must_use]
    pub const fn with(self, reason: HoldReason) -> Self {
        Self {
            mask: self.mask | reason.bit(),
        }
    }

    /// Returns the set with `reason` added when `condition` is true.
    #[must_use]
    pub const fn with_if(self, condition: bool, reason: HoldReason) -> Self {
        if condition { self.with(reason) } else { self }
    }

    /// Returns the union of two sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self {
            mask: self.mask | other.mask,
        }
    }

    /// Returns `true` if `reason` is in the set.
    #[must_use]
    pub const fn contains(self, reason: HoldReason) -> bool {
        self.mask & reason.bit() != 0
    }

    /// Returns `true` if every reason of `other` is in `self`.
    #[must_use]
    pub const fn is_superset_of(self, other: Self) -> bool {
        other.mask & !self.mask == 0
    }

    /// Returns `true` if there is no reason (not under review).
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.mask == 0
    }

    /// Number of reasons.
    #[must_use]
    pub const fn len(self) -> usize {
        // At most 32 bits are set, which always fits in usize.
        self.mask.count_ones() as usize
    }

    /// The reasons in code order.
    pub fn iter(self) -> impl Iterator<Item = HoldReason> {
        HoldReason::ALL
            .into_iter()
            .filter(move |reason| self.contains(*reason))
    }

    /// Removes `reason`. Only the resolving transitions of this crate call
    /// this (module documentation).
    #[must_use]
    pub(crate) const fn without(self, reason: HoldReason) -> Self {
        Self {
            mask: self.mask & !reason.bit(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{HoldReason, HoldSet};

    #[test]
    fn codes_are_dense_and_below_32() {
        for (index, reason) in HoldReason::ALL.iter().enumerate() {
            assert_eq!(usize::from(reason.code()), index);
            assert!(reason.code() < 32);
        }
    }

    #[test]
    fn set_operations() {
        let empty = HoldSet::empty();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.iter().count(), 0);
        let one = empty.with(HoldReason::ManualClose);
        assert!(!one.is_empty());
        assert_eq!(one.len(), 1);
        assert!(one.contains(HoldReason::ManualClose));
        assert!(!one.contains(HoldReason::OpenBatches));
        let two = one.with(HoldReason::BoxUnderReview);
        assert_eq!(two.len(), 2);
        assert!(two.is_superset_of(one));
        assert!(!one.is_superset_of(two));
        assert!(two.is_superset_of(empty));
        assert_eq!(
            two.iter().collect::<std::vec::Vec<_>>(),
            [HoldReason::ManualClose, HoldReason::BoxUnderReview]
        );
        assert_eq!(one.union(empty.with(HoldReason::BoxUnderReview)), two);
        assert_eq!(two.union(one), two);
        assert_eq!(one.union(two), two);
        assert_eq!(two.without(HoldReason::BoxUnderReview), one);
        assert_eq!(one.without(HoldReason::OpenBatches), one);
        assert_eq!(empty.with_if(false, HoldReason::SplitView), empty);
        assert_eq!(
            empty.with_if(true, HoldReason::SplitView),
            empty.with(HoldReason::SplitView)
        );
        let all = HoldReason::ALL
            .iter()
            .fold(HoldSet::empty(), |set, reason| set.with(*reason));
        assert_eq!(all.len(), HoldReason::ALL.len());
        assert_eq!(all.iter().count(), HoldReason::ALL.len());
        assert_eq!(HoldSet::default(), empty);
    }
}
