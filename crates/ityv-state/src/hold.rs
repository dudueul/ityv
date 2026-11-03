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
    /// A seal change reports a seal found broken (§10.3, reason code 1).
    SealBroken = 28,
    /// The station's paper stock does not add up: `stock_received ≠
    /// issued + unused + printer_waste` (§10.2, ITYV-BEH-089).
    IssuanceStockMismatch = 29,
    /// A progress alarm was not resolved: the on-site check found the gap
    /// unexplained, came too late or never came, or a claimed correction
    /// did not remove the alarm condition (§7.10, VC-103). The station
    /// switches to the counterfoil check until close.
    ProgressUnresolved = 30,
    /// The on-site check after a progress alarm confirmed sheets carried
    /// out of the station (§7.10 finding 2, VC-103).
    CarryOut = 31,
    /// A device's progress stream broke a rule: a count went down, a slot
    /// had two ticks or none, a tick came before opening or after the
    /// closing tick, or the last tick differs from the close counts
    /// (§7.10 item 8, VC-102).
    ProgressStream = 32,
    /// An event already on the ledger was recorded again: the later frame
    /// is invalid (§14 3, VC-101).
    EventReplayed = 33,
    /// A record of the box (a cast record or challenge opening) is in a
    /// frame after the frame of the box's close: the record is invalid
    /// (§10.2, §14 3, VC-039, VC-101). A batch attestation after the close
    /// is a late batch close, not a record.
    RecordAfterClose = 34,
    /// A frame or its event could not be accepted: the frame chain broke,
    /// the event is missing, not canonical, of a schema the verifier does
    /// not know, of another election, names a box or station no state of
    /// the genesis has, or is a genesis, amendment or legal authorization
    /// other than the pinned ones (§5.1, §14 3).
    LedgerUnchecked = 35,
    /// A checkpoint on the ledger is not a valid successor, is not signed
    /// by a diverse quorum of the witness set, or commits to a root, box
    /// close root or dispute root the ledger does not give (§5.4, §14 2,
    /// VC-011..014).
    CheckpointInvalid = 36,
    /// An expected box has no close on the ledger, or more than one first
    /// close (§14 4, completeness).
    CloseMissing = 37,
    /// The box's state machine refused one of its events: a signature
    /// that does not bind to its registered signer, an event out of order,
    /// a missing capability (§14 3, §14 4).
    BoxEventRefused = 38,
    /// The ledger carries no valid legal authorization (the pinned body
    /// with both authorities' signatures), so no gated stage can run
    /// (§4.4, VC-006..008).
    AuthorizationMissing = 39,
    /// The ledger carries a legal authorization object that cannot be
    /// taken: a signature does not verify under the authority's key the
    /// genesis registers, or its scopes break the prerequisite rules. A
    /// forged or broken authorization is evidence, even when a valid one is
    /// also on the ledger (§4.4, VC-006..008).
    AuthorizationInvalid = 40,
    /// A genesis amendment the verifier applied is not on the ledger, or
    /// the ledger carries the amendments out of order, so the frame from
    /// which each state applies is unknown (§4.3).
    AmendmentMissing = 41,
    /// A cast record of the box was rejected: its ballot style is not in
    /// the genesis, its proof does not verify, a record signature does not
    /// verify under a key the box had by its frame, it names a module the
    /// box does not have, or another record carries the same module
    /// counter (§7.2.1, §7.5, §14 5, VC-025, VC-026, VC-068).
    RecordRejected = 42,
    /// A batch attestation of the box does not hold: a signature, a module
    /// outside the box, two bodies under one batch index, a counter range
    /// with a gap or an overlap or beyond the close, a record straddling
    /// batches, or a record count or records root its member records do not
    /// give (§7.2.1, §14 5, VC-053).
    BatchInvalid = 43,
    /// The close's record set root is not the sorted-set root of the box's
    /// accepted records (§7.8, §14 5, VC-027).
    RecordSetMismatch = 44,
    /// A dispute event on the ledger cannot be taken: a signature that
    /// does not verify under the two authorities' keys, a filing without
    /// the capability for its day, a change that does not apply or names no
    /// dispute filed (§13, §14 9).
    DisputeRefused = 45,
    /// A challenge opening cannot be taken: the device's signature does
    /// not verify, or it names no accepted record of its box (§8).
    ChallengeRejected = 46,
    /// A challenge opening the device signed does not reconstruct its
    /// record: the opened values do not open the commitments, or the
    /// modules' contributions do not give the cast id and randomness, or
    /// name other counters (§8 item 3, VC-028). The device is quarantined
    /// and its paper compared in full (§8 item 5).
    OpeningMismatch = 47,
    /// A participation set cannot be taken: the check-in unit's signature
    /// does not verify under a unit key the station had by its frame, the
    /// module signatures are not one per party from that unit's party
    /// modules in chamber order or one does not verify, the genesis's last
    /// state has no such station, or a second set for the station carries
    /// other pseudonyms (§6.5, §14 6, VC-084).
    ParticipationSetInvalid = 48,
    /// A pseudonym appears more than once in the participation sets of the
    /// election, within one station or across stations: a double check-in
    /// to look into (§6.5, §6.6, VC-018).
    DuplicatePseudonym = 49,
    /// A module provisioning or party key ceremony record cannot be taken:
    /// not the record the genesis pins, a signature that does not verify
    /// or a missing signer group, fields that disagree with the genesis, no
    /// entropy commitment, a party key check that differs from the party's
    /// ceremony, or a second ceremony for a party (§6.4, §9.4.2, §14 6,
    /// VC-092, VC-093, VC-095).
    KeyProvisioningInvalid = 50,
    /// A station's issuance count or observer count (periodic or final)
    /// cannot be taken: a signature does not verify under the roster keys
    /// of the state in force at its frame, or its signers do not have the
    /// roles it needs. A later count that is taken does not hide it
    /// (§6.3, §6.5, §10.2, §14 6, VC-016, VC-018).
    StationCountRefused = 51,
}

impl HoldReason {
    /// Every reason in code order.
    pub const ALL: [Self; 52] = [
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
        Self::SealBroken,
        Self::IssuanceStockMismatch,
        Self::ProgressUnresolved,
        Self::CarryOut,
        Self::ProgressStream,
        Self::EventReplayed,
        Self::RecordAfterClose,
        Self::LedgerUnchecked,
        Self::CheckpointInvalid,
        Self::CloseMissing,
        Self::BoxEventRefused,
        Self::AuthorizationMissing,
        Self::AuthorizationInvalid,
        Self::AmendmentMissing,
        Self::RecordRejected,
        Self::BatchInvalid,
        Self::RecordSetMismatch,
        Self::DisputeRefused,
        Self::ChallengeRejected,
        Self::OpeningMismatch,
        Self::ParticipationSetInvalid,
        Self::DuplicatePseudonym,
        Self::KeyProvisioningInvalid,
        Self::StationCountRefused,
    ];

    /// The reason's code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    const fn bit(self) -> u64 {
        // Codes are below 64 (pinned by a test), so the shift cannot overflow.
        1u64 << self.code()
    }
}

/// A set of hold reasons. Empty means not under review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct HoldSet {
    mask: u64,
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
        // At most 64 bits are set, which always fits in usize.
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
    fn codes_are_dense_and_below_64() {
        for (index, reason) in HoldReason::ALL.iter().enumerate() {
            assert_eq!(usize::from(reason.code()), index);
            assert!(reason.code() < 64);
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
