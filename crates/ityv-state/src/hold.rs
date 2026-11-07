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
    /// A tally scope cannot be taken: its trustees' signatures do not
    /// verify or do not form a qualified quorum, it lacks the
    /// `CRYPTO_TALLY_AID` capability for its day, it names a ballot style
    /// or reporting unit the genesis does not have, it comes before every
    /// box of its style closed, before the receipts and legal decisions it
    /// waits for or within the late-close window, or another scope of the
    /// style and unit was already taken (§11.1, §14 7, VC-057, VC-099).
    TallyScopeRefused = 52,
    /// A tally scope the trustees signed is not what the ledger gives: the
    /// included records' count or root, the excluded records, an
    /// exclusion's reason (the first of §11.1 that applies) or its basis,
    /// or the ballots cast without a record, summed over the effective
    /// closes of the unit's boxes, differ (§11.1, §14 7, VC-042).
    TallyScopeMismatch = 53,
    /// An aggregate opening cannot be taken: its trustees' signatures do
    /// not verify or do not form a qualified quorum, it lacks the
    /// capability, it names a chunk the style does not have or a scope that
    /// was not taken, its scope was in no witness checkpoint before it
    /// (VC-063), or the chunk was already opened (§11.2, §14 7).
    AggregateRefused = 54,
    /// An aggregate opening does not open the sum of the included records'
    /// commitments, or its packed sum has digits out of range (§11.2,
    /// §11.3, VC-024, VC-043, VC-044). The trustees localize the faulty box
    /// by bisection and open its records.
    AggregateMismatch = 55,
    /// A paper count report cannot be taken: a signature does not verify
    /// under the roster keys of the state in force at its frame (the chair
    /// and observers of two organisations), it names a ballot style or
    /// reporting unit the genesis does not have or another number of
    /// candidates, or the unit's style already has a report (§11.5).
    PaperCountRefused = 56,
    /// A unit's paper count is below the machine's confirmed votes for a
    /// candidate, or the totals differ (§11.5, VC-075). Not evidence of
    /// fraud by itself: the audit's reason codes find the cause, and the
    /// unit's boxes get a larger sample.
    PaperCountMismatch = 57,
    /// A legal decision with a tally effect cannot be applied: its dispute
    /// is not a `POSTAL` dispute naming a record, the record is not an
    /// accepted record of that box, or the record does not await the law
    /// (§10.6 item 6, VC-099).
    TallyEffectRefused = 58,
    /// A receipt resolution cannot be taken: its trustees' signatures do not
    /// verify or do not form a qualified quorum, it lacks the
    /// `CRYPTO_TALLY_AID` capability for its day, its box is not an
    /// out-of-district box of the genesis or was not closed before it, its
    /// entries are not exactly the box's cast records, or the box already
    /// has one (§10.6 items 2 and 5, §14 7).
    ReceiptResolutionRefused = 59,
    /// A late batch close or late box close of a box was recorded after a
    /// tally scope of the box's ballot style was taken: the scope fixed
    /// `UNATTESTED` and the closes it cites (§7.2.1, §10.2, §11.1, VC-057,
    /// VC-100).
    LateCloseAfterScope = 60,
    /// An audit manifest freeze cannot be taken: a signature does not
    /// verify under the committee's or a roster observer's key, it lacks
    /// the `RLA` capability for its day, it names a ballot style no box of
    /// the genesis has, it comes before a tally scope of the style or after
    /// the seed, or the style already has another freeze (§12.1, §14 8).
    AuditFreezeRefused = 61,
    /// A ballot style's freeze is not what the ledger gives: the sample
    /// frame's count or root differs from the style's included records
    /// recomputed by the tally stage (§12.1, §14 8, ADR-0036).
    AuditFrameMismatch = 62,
    /// An audit seed cannot be taken: a signature does not verify, it lacks
    /// the capability, a style has no freeze before it, its beacon round is
    /// not the one every freeze designated, its checkpoint is not the last
    /// valid checkpoint before it or does not cover every freeze, the seed
    /// is not `SHA3-512("ityv:seed:v1" ‖ 0x00 ‖ dice ‖ beacon ‖ checkpoint)`
    /// (VC-045), the beacon value differs from the one the caller observed,
    /// or another seed was taken (§12.1, ADR-0036).
    AuditSeedRefused = 63,
    /// A sample opening reference cannot be taken: its trustees'
    /// signatures do not verify or do not form a qualified quorum, the
    /// authorization does not grant `OBSERVER_ACCESS` for the seed's day,
    /// no seed precedes it, its record is neither in the sample drawn so
    /// far nor of a device under full comparison, or the record was
    /// already opened (§12.2, §12.3, §12.5, VC-046, VC-059).
    SampleOpeningRefused = 64,
    /// A restricted sample opening supplied to the verifier does not
    /// reconstruct its record: it is not the body the trustees' reference
    /// names, or its option, cast id and randomness do not open the
    /// record's commitments (§12.3, VC-047).
    SampleOpeningMismatch = 65,
    /// A sample comparison cannot be taken: a signature does not verify
    /// under a roster auditor's or observer's key, its record was not
    /// opened by a reference in an earlier frame or the opening it names is
    /// not that one, its device is not the record's box, or the record was
    /// already compared (§12.3, §14 8).
    SampleComparisonRefused = 66,
    /// A comparison found the imprinted ballot missing (code 5) or the cast
    /// id on two ballots or an imprint that differs from the record (code
    /// 6): the box's custody is under investigation (§12.3).
    AuditCustody = 67,
    /// An audit finding cannot be taken: a signature does not verify, it
    /// names a device that is no box of its ballot style, or the same
    /// finding again (§12.4).
    AuditFindingRefused = 68,
    /// A hand count report cannot be taken: a signature does not verify
    /// under the keys of the unit's commission chair and observers, it
    /// names no unit of its style or another number of candidates, the
    /// style's audit did not call for a full hand count before it, or the
    /// unit already has one (§12.4, ADR-0036).
    HandCountRefused = 69,
    /// The audit commit cannot be taken: a signature does not verify, a
    /// style's freeze is missing, it designates another beacon than a
    /// freeze, its freezes root is not the root of the freezes taken, it is
    /// dated at or after the observed beacon publication, or a second
    /// commit (§12.1, ADR-0036).
    AuditCommitRefused = 70,
    /// The sample of a style could not be drawn from its seed (the stream
    /// rejected every word of a draw, or a drawn position is outside the
    /// frame): the audit cannot proceed (§12.2, ADR-0036).
    AuditSampleFailed = 71,
    /// A timestamp record on the ledger cannot be taken: its authority is
    /// not one the genesis pins, its token does not verify under any pin of
    /// that authority over the SHA-512 of the stamped event's object hash,
    /// or it stamps no earlier event of a kind that is timestamped (a
    /// checkpoint, the genesis or an amendment, a voter-roll event, a legal
    /// decision; never a record, check-in counter or progress record) (§5.5,
    /// ADR-0034 §7, VC-117, ADR-0039).
    TimestampInvalid = 72,
    /// A valid token says a checkpoint existed earlier than the time its
    /// witnesses attest, by more than the honest clock error: the latest
    /// instant the token allows falls more than `CLOCK_ERROR_BUCKETS`
    /// buckets before the checkpoint's bucket. The chain ends there (§5.5,
    /// ADR-0034 §4, VC-116, ADR-0039).
    TimestampMismatch = 73,
    /// A voter-roll event of the ledger was not taken: an extract, the
    /// freeze, a custody receipt or an amendment whose signer is not the
    /// authority the genesis registers for it, whose signature does not
    /// verify, that comes out of order or answers nothing, or that repeats
    /// or contradicts one taken (§6.1, ADR-0033, VC-107, VC-111,
    /// ADR-0040).
    RollEventRefused = 74,
    /// A custodian's receipt gives other values than the roll state it
    /// answers (entries root and count, counts table, sources root, a
    /// pseudonym root): the copies disagree and are compared in a dispute
    /// (§6.1, ADR-0033 decision 2, VC-108, ADR-0040).
    RollCustodyMismatch = 75,
    /// A contested check-in of the ledger, supplied by a verifier with
    /// access to the restricted body, does not verify: another election,
    /// a station or unit the genesis does not have, or signatures that are
    /// not the unit's and one party module's per party (§6.2, ADR-0033
    /// decision 6, ADR-0040). Only a verifier with access holds on it; the
    /// public verifier sees the frames.
    ContestedCheckinInvalid = 76,
    /// Contested check-ins supplied by a verifier with access carry one
    /// envelope label in two different messages, whatever their
    /// pseudonyms: no envelope with the label can be matched to one record,
    /// so every one of them is excluded from the count. Labels are random
    /// (ADR-0010 decision 2), so this is a device or insider fault, not a
    /// voter's act (§6.2, ADR-0033 decision 6, ADR-0040). Only a verifier
    /// with access holds on it; the public verifier sees the frames. A
    /// pseudonym that contested twice under two labels is excluded and
    /// reported without a hold, as one found in a participation set.
    ContestedLabelReused = 77,
    /// The roll does not match the election as it ran: an election-day
    /// station of the genesis's last state has no resident extract (a
    /// station added after the freeze), or an amendment was recorded after
    /// voting closed (after the first close the ledger shows at an
    /// election-day station: its participation set, its observers' final
    /// count or one of its boxes' close), which must not change the roll
    /// the voters were checked against (§6.1, ADR-0040).
    RollIncomplete = 78,
    /// The connectivity manifest breaks a rule of VC-077: a device class
    /// without an entry, a TCB device with an inbound port or a radio, a
    /// two-way port of a class that may not have one, a tap that is not
    /// send-only, a scanner or check-in unit without exactly one frame link
    /// of the declared shape, or a frame link that may carry check-in
    /// counters. Every box (§5.8 item 1, ADR-0022 decision 11, ADR-0041).
    ConnectivityManifest = 79,
    /// A gateway session cannot be taken, or its record disagrees with its
    /// frame logs: a gateway the genesis does not register for the
    /// station, a signature that does not verify, a session out of order or
    /// not chained to the previous one, a frame log missing, late or
    /// repeated, a chain head the logs do not give, or counts of frames,
    /// missing slots or stream end that are not the logs' (§5.8 item 5,
    /// VC-080, ADR-0041). Every box of the station.
    UplinkSessionRefused = 80,
    /// A frame breaks a rule of VC-078: a signature that is not the
    /// device's frame key over its header, a number or kind outside the
    /// slot's shape, a frame before the box's opening or a normal frame
    /// after its close, a stream offset that goes back or skips without a
    /// missing slot, or a payload root the published chunk leaves and zero
    /// fill do not give, or a chunk whose public bytes give another leaf
    /// (§5.8 item 3, ADR-0041). The device's box, or every box of the
    /// station for a check-in unit.
    UplinkFrameInvalid = 81,
    /// A link's stream breaks a rule of VC-079: an object of a kind the
    /// device may not send or the manifest does not let it carry, bytes
    /// that are not objects, a published object whose bytes or length are
    /// not the ledger's, a record outside a closed-batch run in record-hash
    /// order, a share package not right after its record, or a fully
    /// received object the ledger does not carry once the gateway closed
    /// (§5.8 item 4, ADR-0041). The device's box or station.
    UplinkObjectInvalid = 82,
    /// A device-signed ledger event of a station whose gateway sent its
    /// final session lies inside no received frame of its device's link:
    /// it reached the board by another path, or the gateway dropped the
    /// frame that carried it (§5.8 item 5, VC-080, ADR-0041). The event's
    /// box, or every box of its station.
    UplinkObjectOutside = 83,
    /// A connectivity incident was recorded: an undeclared connection, an
    /// inbound path or a radio, an off-schedule frame, a capture or carrier
    /// record that disagrees, the roll line used outside its window, an
    /// unexplained transmission, a teardown or radio check finding. The
    /// electronic layer of the box, the station or the whole election the
    /// incident names; the paper count is not affected (§5.8 item 10,
    /// VC-083, ADR-0041).
    ConnectivityIncident = 84,
    /// A connectivity incident cannot be taken: its signers are not two
    /// clerks and observers of two organisations, or the committee and
    /// observers of two organisations, registered on the genesis roster, or
    /// it names a station or box the genesis does not have (ADR-0041).
    /// Every box.
    ConnectivityIncidentRefused = 85,
}

impl HoldReason {
    /// Every reason in code order.
    pub const ALL: [Self; 86] = [
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
        Self::TallyScopeRefused,
        Self::TallyScopeMismatch,
        Self::AggregateRefused,
        Self::AggregateMismatch,
        Self::PaperCountRefused,
        Self::PaperCountMismatch,
        Self::TallyEffectRefused,
        Self::ReceiptResolutionRefused,
        Self::LateCloseAfterScope,
        Self::AuditFreezeRefused,
        Self::AuditFrameMismatch,
        Self::AuditSeedRefused,
        Self::SampleOpeningRefused,
        Self::SampleOpeningMismatch,
        Self::SampleComparisonRefused,
        Self::AuditCustody,
        Self::AuditFindingRefused,
        Self::HandCountRefused,
        Self::AuditCommitRefused,
        Self::AuditSampleFailed,
        Self::TimestampInvalid,
        Self::TimestampMismatch,
        Self::RollEventRefused,
        Self::RollCustodyMismatch,
        Self::ContestedCheckinInvalid,
        Self::ContestedLabelReused,
        Self::RollIncomplete,
        Self::ConnectivityManifest,
        Self::UplinkSessionRefused,
        Self::UplinkFrameInvalid,
        Self::UplinkObjectInvalid,
        Self::UplinkObjectOutside,
        Self::ConnectivityIncident,
        Self::ConnectivityIncidentRefused,
    ];

    /// The reason's code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    const fn bit(self) -> u128 {
        // Codes are below 128 (pinned by a test), so the shift cannot
        // overflow.
        1u128 << self.code()
    }
}

/// A set of hold reasons. Empty means not under review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct HoldSet {
    mask: u128,
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
        // At most 128 bits are set, which always fits in usize.
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
    fn codes_are_dense_and_below_128() {
        for (index, reason) in HoldReason::ALL.iter().enumerate() {
            assert_eq!(usize::from(reason.code()), index);
            assert!(reason.code() < 128);
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
