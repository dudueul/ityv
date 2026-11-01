//! The verifier status vocabulary (PROTOCOL.md §14, GLOSSARY 상태 어휘).
//!
//! [`evaluate`] maps the outcomes of the verifier's steps to exactly one
//! status:
//!
//! * any failed step, unresolved dispute, split-view evidence, late board
//!   or other hold: `HOLD_REVIEW`;
//! * otherwise steps 1–3, the box invariants of step 4 and step 5 passed,
//!   with the checkpoints anchored in time: `LOG_CONSISTENT`;
//! * and the completeness of step 4: `SOURCE_COMPLETENESS_CHECKED`;
//! * and steps 6 and 7: `CRYPTO_TALLY_VERIFIED`;
//! * and step 8 concluded by its rule: `PAPER_AUDITED`;
//! * otherwise `UNVERIFIED`, which is also where every report starts
//!   (ITYV-BEH-014, ITYV-BEH-161).
//!
//! The statuses are not interchangeable (VC-050): a report carries one
//! status that only [`evaluate`] sets, and there is no conversion between
//! statuses. `LEGAL_CERTIFIED` is not a status a machine reaches (VC-049):
//! [`Status`] has no such variant, and the verifier only displays a
//! [`LegalReference`], which exists only for a verified signature of a
//! legal authority.
//!
//! ```compile_fail
//! let _ = ityv_state::status::Status::LegalCertified;
//! ```
//!
//! ```compile_fail
//! fn certify<'a>(report: &ityv_state::status::StatusReport) -> ityv_state::status::LegalReference<'a> {
//!     ityv_state::status::LegalReference::from(*report)
//! }
//! ```
//!
//! Publication deadlines come from `ityv-ledger` (`FAILURE_CASES.md` §8): a
//! checkpoint not anchored within the hour leaves the status `UNVERIFIED`,
//! a board not published within 24 hours is `HOLD_REVIEW`.

use ityv_crypto::{HybridSigned, HybridVerifyingKey, Verified};
use ityv_encoding::{Scope, ScopeSet};
use ityv_ledger::{Breach, Error as LedgerError, Status as LedgerStatus};

use crate::dispute::Dispute;
use crate::error::Error;
use crate::hold::{HoldReason, HoldSet};

/// Signature purpose of a legal decision reference (PROTOCOL.md Appendix B).
pub const PURPOSE_LEGAL_DECISION: &[u8] = b"legal-decision";

/// The verifier's steps (§14), with step 4 split into its invariants and
/// its completeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Step {
    /// 1. Genesis.
    Genesis = 0,
    /// 2. Checkpoint chain.
    Checkpoints = 1,
    /// 3. Frames and events.
    Frames = 2,
    /// 4. Boxes: close invariants, module counters, custody chains.
    BoxInvariants = 3,
    /// 4. Boxes: every expected box has exactly one close.
    BoxCompleteness = 4,
    /// 5. Cast records.
    Records = 5,
    /// 6. Participation ledger.
    Participation = 6,
    /// 7. Tally.
    Tally = 7,
    /// 8. Audit.
    Audit = 8,
    /// 11. Connectivity.
    Connectivity = 9,
    /// 12. Software.
    Software = 10,
}

impl Step {
    /// Every step.
    pub const ALL: [Self; 11] = [
        Self::Genesis,
        Self::Checkpoints,
        Self::Frames,
        Self::BoxInvariants,
        Self::BoxCompleteness,
        Self::Records,
        Self::Participation,
        Self::Tally,
        Self::Audit,
        Self::Connectivity,
        Self::Software,
    ];

    const fn index(self) -> usize {
        self as usize
    }
}

/// The outcome of one step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// Not run (or not applicable at this stage).
    NotRun,
    /// Passed.
    Passed,
    /// Failed.
    Failed,
}

/// A publication deadline as `ityv-ledger` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Publication {
    /// Met.
    Satisfied,
    /// Not yet met, deadline not passed.
    Pending,
    /// Missed.
    Breached(Breach),
    /// The check itself failed (overflow or another ledger error).
    Failed,
}

impl Publication {
    /// Maps the result of `ityv_ledger::check_anchor` or
    /// `ityv_ledger::check_board`.
    #[must_use]
    pub const fn from_ledger(outcome: &Result<LedgerStatus, LedgerError>) -> Self {
        match outcome {
            Ok(LedgerStatus::Satisfied) => Self::Satisfied,
            Ok(LedgerStatus::Pending) => Self::Pending,
            Err(LedgerError::Breach(breach)) => Self::Breached(*breach),
            Err(_) => Self::Failed,
        }
    }
}

/// The status vocabulary a machine can reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    /// `UNVERIFIED`.
    Unverified,
    /// `LOG_CONSISTENT`.
    LogConsistent,
    /// `SOURCE_COMPLETENESS_CHECKED`.
    SourceCompletenessChecked,
    /// `CRYPTO_TALLY_VERIFIED`.
    CryptoTallyVerified,
    /// `PAPER_AUDITED`.
    PaperAudited,
    /// `HOLD_REVIEW`.
    HoldReview,
}

impl Status {
    /// The vocabulary name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unverified => "UNVERIFIED",
            Self::LogConsistent => "LOG_CONSISTENT",
            Self::SourceCompletenessChecked => "SOURCE_COMPLETENESS_CHECKED",
            Self::CryptoTallyVerified => "CRYPTO_TALLY_VERIFIED",
            Self::PaperAudited => "PAPER_AUDITED",
            Self::HoldReview => "HOLD_REVIEW",
        }
    }
}

/// What the verifier found, step by step. Every step starts not run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Evidence {
    outcomes: [Outcome; 11],
    scopes: ScopeSet,
    anchors: Publication,
    board: Publication,
    holds: HoldSet,
    audit_concluded: bool,
    receipt_scan: bool,
}

impl Evidence {
    /// Nothing verified yet, under the authorized `scopes`.
    #[must_use]
    pub const fn new(scopes: ScopeSet) -> Self {
        Self {
            outcomes: [Outcome::NotRun; 11],
            scopes,
            anchors: Publication::Pending,
            board: Publication::Pending,
            holds: HoldSet::empty(),
            audit_concluded: false,
            receipt_scan: false,
        }
    }

    /// Sets the outcome of `step`.
    #[must_use]
    pub fn with_step(mut self, step: Step, outcome: Outcome) -> Self {
        if let Some(slot) = self.outcomes.get_mut(step.index()) {
            *slot = outcome;
        }
        self
    }

    /// The outcome of `step`.
    #[must_use]
    pub fn step(&self, step: Step) -> Outcome {
        self.outcomes
            .get(step.index())
            .copied()
            .unwrap_or(Outcome::NotRun)
    }

    /// Sets the anchor deadline of the latest checkpoint.
    #[must_use]
    pub const fn with_anchors(mut self, anchors: Publication) -> Self {
        self.anchors = anchors;
        self
    }

    /// Sets the board deadline.
    #[must_use]
    pub const fn with_board(mut self, board: Publication) -> Self {
        self.board = board;
        self
    }

    /// Adds holds (from boxes, custody, issuance, records).
    #[must_use]
    pub const fn with_holds(mut self, holds: HoldSet) -> Self {
        self.holds = self.holds.union(holds);
        self
    }

    /// Adds a dispute; an unresolved one holds (§14 step 9).
    #[must_use]
    pub const fn with_dispute(self, dispute: &Dispute<'_>) -> Self {
        self.with_holds(HoldSet::empty().with_if(dispute.is_unresolved(), HoldReason::OpenDispute))
    }

    /// Records split-view evidence (§14 step 10, VC-065).
    #[must_use]
    pub const fn with_split_view(self) -> Self {
        self.with_holds(HoldSet::empty().with(HoldReason::SplitView))
    }

    /// Records that the audit's sample comparison concluded by its rule.
    #[must_use]
    pub const fn with_audit_concluded(mut self) -> Self {
        self.audit_concluded = true;
        self
    }

    /// Records that the scope includes `RECEIPT_SCAN` boxes (§17).
    #[must_use]
    pub const fn with_receipt_scan(mut self) -> Self {
        self.receipt_scan = true;
        self
    }
}

/// The verifier's report: one status and the reasons behind a hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StatusReport {
    status: Status,
    holds: HoldSet,
    receipt_scan: bool,
    count_only: bool,
}

impl StatusReport {
    /// The status.
    #[must_use]
    pub const fn status(self) -> Status {
        self.status
    }

    /// Why the status is `HOLD_REVIEW` (empty otherwise).
    #[must_use]
    pub const fn holds(self) -> HoldSet {
        self.holds
    }

    /// Whether the status covers `RECEIPT_SCAN` records, which the verifier
    /// shows as a separate range (§17).
    #[must_use]
    pub const fn receipt_scan(self) -> bool {
        self.receipt_scan
    }

    /// Whether only counts back the result: without `BALLOT_MARK`, or with
    /// `RECEIPT_SCAN` records, a substitution of equal numbers is not
    /// detectable and the report says so (ITYV-BEH-077, ITYV-BEH-170,
    /// ITYV-BEH-216).
    #[must_use]
    pub const fn count_only(self) -> bool {
        self.count_only
    }
}

/// Maps the evidence to one status.
#[must_use]
pub fn evaluate(evidence: &Evidence) -> StatusReport {
    let passed = |steps: &[Step]| steps.iter().all(|s| evidence.step(*s) == Outcome::Passed);
    let failed = Step::ALL
        .iter()
        .any(|s| evidence.step(*s) == Outcome::Failed);
    let publication_failed = matches!(evidence.anchors, Publication::Failed)
        || matches!(evidence.board, Publication::Failed);
    let holds = evidence
        .holds
        .with_if(failed || publication_failed, HoldReason::StepFailed)
        .with_if(
            matches!(evidence.board, Publication::Breached(_)),
            HoldReason::PublicationLate,
        );
    let status = if !holds.is_empty() {
        Status::HoldReview
    } else if !(passed(&[
        Step::Genesis,
        Step::Checkpoints,
        Step::Frames,
        Step::BoxInvariants,
        Step::Records,
    ]) && matches!(evidence.anchors, Publication::Satisfied))
    {
        Status::Unverified
    } else if !passed(&[Step::BoxCompleteness]) {
        Status::LogConsistent
    } else if !passed(&[Step::Participation, Step::Tally]) {
        Status::SourceCompletenessChecked
    } else if !(passed(&[Step::Audit]) && evidence.audit_concluded) {
        Status::CryptoTallyVerified
    } else {
        Status::PaperAudited
    };
    StatusReport {
        status,
        holds,
        receipt_scan: evidence.receipt_scan,
        count_only: evidence.receipt_scan || !evidence.scopes.contains(Scope::BallotMark),
    }
}

/// A `LegalDecisionRef` whose authority signature verified. The verifier
/// displays it next to its own status as `LEGAL_CERTIFIED`; it never
/// derives it (VC-049).
///
/// What it does not prove: what the decision says. Schema `0x000F` has no
/// canonical encoding yet, so the object bytes stay opaque until M5
/// decodes them (ADR-0025).
#[derive(Debug, Clone, Copy)]
pub struct LegalReference<'a> {
    object: &'a [u8],
    authority: &'a HybridVerifyingKey,
}

impl<'a> LegalReference<'a> {
    /// The vocabulary name under which the reference is displayed.
    pub const NAME: &'static str = "LEGAL_CERTIFIED";

    /// Accepts a verified signature of `authority` with purpose
    /// `legal-decision`.
    ///
    /// # Errors
    /// [`Error::SignatureObject`] for another purpose,
    /// [`Error::SignatureSigner`] for another key.
    pub fn from_signed(
        signed: &Verified<HybridSigned<'a>>,
        authority: &HybridVerifyingKey,
    ) -> Result<Self, Error> {
        let token = signed.get();
        if token.purpose().as_bytes() != PURPOSE_LEGAL_DECISION {
            return Err(Error::SignatureObject);
        }
        if token.key() != authority {
            return Err(Error::SignatureSigner);
        }
        Ok(Self {
            object: token.object(),
            authority: token.key(),
        })
    }

    /// The decision object bytes.
    #[must_use]
    pub const fn object(&self) -> &'a [u8] {
        self.object
    }

    /// The authority's key.
    #[must_use]
    pub const fn authority(&self) -> &'a HybridVerifyingKey {
        self.authority
    }
}

#[cfg(test)]
mod tests {
    use ityv_encoding::{Scope, ScopeSet, TimeBucket};
    use ityv_ledger::{Breach, Error as LedgerError, Status as LedgerStatus};

    use super::{Evidence, Outcome, Publication, Status, Step, evaluate};
    use crate::hold::{HoldReason, HoldSet};

    fn stage2() -> ScopeSet {
        ScopeSet::from_slice(&[
            Scope::PublicBoard,
            Scope::TrusteeBody,
            Scope::BallotMark,
            Scope::CryptoTallyAid,
            Scope::Rla,
        ])
    }

    fn passed(steps: &[Step]) -> Evidence {
        steps.iter().fold(
            Evidence::new(stage2()).with_anchors(Publication::Satisfied),
            |e, s| e.with_step(*s, Outcome::Passed),
        )
    }

    const LOG: [Step; 5] = [
        Step::Genesis,
        Step::Checkpoints,
        Step::Frames,
        Step::BoxInvariants,
        Step::Records,
    ];

    fn all_but(excluded: Step) -> std::vec::Vec<Step> {
        Step::ALL
            .iter()
            .copied()
            .filter(|s| *s != excluded)
            .collect()
    }

    #[test]
    fn default_is_unverified() {
        let report = evaluate(&Evidence::new(stage2()));
        assert_eq!(report.status(), Status::Unverified);
        assert!(report.holds().is_empty());
        assert!(!report.receipt_scan());
        assert!(!report.count_only());
    }

    #[test]
    fn ladder() {
        assert_eq!(evaluate(&passed(&LOG)).status(), Status::LogConsistent);
        let mut steps = LOG.to_vec();
        steps.push(Step::BoxCompleteness);
        assert_eq!(
            evaluate(&passed(&steps)).status(),
            Status::SourceCompletenessChecked
        );
        steps.push(Step::Participation);
        assert_eq!(
            evaluate(&passed(&steps)).status(),
            Status::SourceCompletenessChecked
        );
        steps.push(Step::Tally);
        assert_eq!(
            evaluate(&passed(&steps)).status(),
            Status::CryptoTallyVerified
        );
        steps.push(Step::Audit);
        assert_eq!(
            evaluate(&passed(&steps)).status(),
            Status::CryptoTallyVerified
        );
        assert_eq!(
            evaluate(&passed(&steps).with_audit_concluded()).status(),
            Status::PaperAudited
        );
        // Each prerequisite step is needed.
        for missing in LOG {
            let e = passed(&all_but(missing)).with_audit_concluded();
            assert_eq!(evaluate(&e).status(), Status::Unverified, "{missing:?}");
        }
        let e = passed(&all_but(Step::BoxCompleteness)).with_audit_concluded();
        assert_eq!(evaluate(&e).status(), Status::LogConsistent);
        for missing in [Step::Participation, Step::Tally] {
            let e = passed(&all_but(missing)).with_audit_concluded();
            assert_eq!(evaluate(&e).status(), Status::SourceCompletenessChecked);
        }
        let e = passed(&all_but(Step::Audit)).with_audit_concluded();
        assert_eq!(evaluate(&e).status(), Status::CryptoTallyVerified);
        // Steps 11 and 12 not run do not block the ladder.
        let mut core = LOG.to_vec();
        core.extend([
            Step::BoxCompleteness,
            Step::Participation,
            Step::Tally,
            Step::Audit,
        ]);
        assert_eq!(
            evaluate(&passed(&core).with_audit_concluded()).status(),
            Status::PaperAudited
        );
    }

    #[test]
    fn anchors_gate_log_consistency() {
        let all = passed(&Step::ALL).with_audit_concluded();
        assert_eq!(evaluate(&all).status(), Status::PaperAudited);
        let pending = all.with_anchors(Publication::Pending);
        assert_eq!(evaluate(&pending).status(), Status::Unverified);
        let short = all.with_anchors(Publication::Breached(Breach::AnchorsShort {
            have: 2,
            need: 3,
        }));
        let report = evaluate(&short);
        assert_eq!(report.status(), Status::Unverified);
        assert!(report.holds().is_empty());
        let failed = all.with_anchors(Publication::Failed);
        let report = evaluate(&failed);
        assert_eq!(report.status(), Status::HoldReview);
        assert_eq!(
            report.holds(),
            HoldSet::empty().with(HoldReason::StepFailed)
        );
    }

    #[test]
    fn holds_override() {
        let all = passed(&Step::ALL).with_audit_concluded();
        for step in Step::ALL {
            let report = evaluate(&all.with_step(step, Outcome::Failed));
            assert_eq!(report.status(), Status::HoldReview);
            assert_eq!(
                report.holds(),
                HoldSet::empty().with(HoldReason::StepFailed)
            );
        }
        let late = all.with_board(Publication::Breached(Breach::BoardUnpublished));
        let report = evaluate(&late);
        assert_eq!(report.status(), Status::HoldReview);
        assert_eq!(
            report.holds(),
            HoldSet::empty().with(HoldReason::PublicationLate)
        );
        let board_failed = all.with_board(Publication::Failed);
        assert_eq!(
            evaluate(&board_failed).holds(),
            HoldSet::empty().with(HoldReason::StepFailed)
        );
        assert_eq!(
            evaluate(&all.with_board(Publication::Pending)).status(),
            Status::PaperAudited
        );
        assert_eq!(
            evaluate(&all.with_board(Publication::Satisfied)).status(),
            Status::PaperAudited
        );
        let split = evaluate(&all.with_split_view());
        assert_eq!(split.status(), Status::HoldReview);
        assert_eq!(split.holds(), HoldSet::empty().with(HoldReason::SplitView));
        let boxed = evaluate(&all.with_holds(HoldSet::empty().with(HoldReason::BoxUnderReview)));
        assert_eq!(boxed.status(), Status::HoldReview);
        // Holds accumulate.
        let both = all
            .with_holds(HoldSet::empty().with(HoldReason::BoxUnderReview))
            .with_split_view();
        assert_eq!(evaluate(&both).holds().len(), 2);
    }

    #[test]
    fn receipt_scan_and_count_only() {
        let report = evaluate(&Evidence::new(stage2()).with_receipt_scan());
        assert!(report.receipt_scan());
        assert!(report.count_only());
        let stage0 = ScopeSet::from_slice(&[Scope::PublicBoard]);
        let report = evaluate(&Evidence::new(stage0));
        assert!(!report.receipt_scan());
        assert!(report.count_only());
    }

    #[test]
    fn steps_read_back() {
        let e = Evidence::new(stage2()).with_step(Step::Tally, Outcome::Failed);
        assert_eq!(e.step(Step::Tally), Outcome::Failed);
        assert_eq!(e.step(Step::Audit), Outcome::NotRun);
        for (index, step) in Step::ALL.iter().enumerate() {
            assert_eq!(step.index(), index);
        }
    }

    #[test]
    fn names() {
        let names = [
            (Status::Unverified, "UNVERIFIED"),
            (Status::LogConsistent, "LOG_CONSISTENT"),
            (
                Status::SourceCompletenessChecked,
                "SOURCE_COMPLETENESS_CHECKED",
            ),
            (Status::CryptoTallyVerified, "CRYPTO_TALLY_VERIFIED"),
            (Status::PaperAudited, "PAPER_AUDITED"),
            (Status::HoldReview, "HOLD_REVIEW"),
        ];
        for (status, name) in names {
            assert_eq!(status.name(), name);
        }
        assert_eq!(super::LegalReference::NAME, "LEGAL_CERTIFIED");
    }

    #[test]
    fn publication_mapping() {
        assert_eq!(
            Publication::from_ledger(&Ok(LedgerStatus::Satisfied)),
            Publication::Satisfied
        );
        assert_eq!(
            Publication::from_ledger(&Ok(LedgerStatus::Pending)),
            Publication::Pending
        );
        let breach = Breach::BoardLate {
            published: TimeBucket::new(200),
            deadline: TimeBucket::new(196),
        };
        assert_eq!(
            Publication::from_ledger(&Err(LedgerError::Breach(breach))),
            Publication::Breached(breach)
        );
        assert_eq!(
            Publication::from_ledger(&Err(LedgerError::Overflow)),
            Publication::Failed
        );
        // The real deadline checks.
        let close = TimeBucket::new(100);
        let outcome = ityv_ledger::check_board(close, None, TimeBucket::new(197));
        assert_eq!(
            Publication::from_ledger(&outcome),
            Publication::Breached(Breach::BoardUnpublished)
        );
        let outcome = ityv_ledger::check_anchor(close, &[close, close], TimeBucket::new(105));
        assert!(matches!(
            Publication::from_ledger(&outcome),
            Publication::Breached(Breach::AnchorsShort { .. })
        ));
    }
}
