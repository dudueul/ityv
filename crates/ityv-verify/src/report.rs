//! The verifier's report (PROTOCOL.md §14, the status ladder).
//!
//! [`verify_ledger`] runs every stage this crate has over one ledger, in
//! order, and maps what they found to one status through
//! `ityv_state::status::evaluate`, which alone decides it:
//!
//! 1. genesis: given (the caller verified it, [`crate::verify_genesis`]);
//! 2. the checkpoint chain ([`crate::verify_checkpoints`]): passed when no
//!    checkpoint broke a rule and the last valid one covers every frame but
//!    the checkpoints after it (a checkpoint cannot cover its own frame);
//!    not run while other frames remain that no checkpoint covers;
//! 3. frames and events ([`crate::build_index`]): passed unless the index
//!    holds the whole ledger;
//! 4. boxes ([`crate::verify_boxes`]), split into the invariants (every
//!    hold of every box, which leads to `HOLD_REVIEW`) and completeness
//!    (every expected box closed, which alone separates
//!    `SOURCE_COMPLETENESS_CHECKED` from `LOG_CONSISTENT`, so a box still
//!    open is not a hold);
//! 5. records ([`crate::verify_records`]);
//! 9. disputes ([`crate::verify_disputes`]): a dispute still unresolved
//!    after every dispute event holds the ledger, and so does a dispute
//!    event or legal decision that cannot be taken (a signature that does
//!    not verify, a filing without its capability, a change that does not
//!    apply, a decision of no registered authority or naming no dispute);
//!    each legal decision is shown next to its dispute.
//!
//! The legal authorization ([`crate::authorize_ledger`]) gives the scopes;
//! without `BALLOT_MARK` the report says that only counts back the result.
//!
//! The verifier has no clock. Whether the checkpoints were anchored in
//! time and the board published by its deadline needs the current time
//! and the anchor receipts, so the caller supplies both as [`Publications`]
//! (computed with `ityv_ledger::check_anchor` and
//! `ityv_ledger::check_board`). Until the anchors are satisfied the status
//! stays `UNVERIFIED`.
//!
//! What the report does not reach yet: participation, tally, audit,
//! split view, connectivity and software (stages 6–8, 10–12), so the
//! highest status it gives is `SOURCE_COMPLETENESS_CHECKED`.

use ityv_encoding::{CaptureProfile, ScopeSet};
use ityv_ledger::SCHEMA_SIGNED_CHECKPOINT;
use ityv_state::status::{Step, evaluate};
use ityv_state::{Evidence, HoldReason, HoldSet, Outcome, Publication, StatusReport};

use crate::authority::{AuthorityStage, authorize_ledger};
use crate::boxes::{BoxStage, verify_boxes};
use crate::checkpoint::{CheckpointChain, verify_checkpoints};
use crate::disputes::{DisputeStage, verify_disputes};
use crate::genesis::VerifiedGenesis;
use crate::index::{LedgerIndex, build_index};
use crate::records::{RecordStage, verify_records};

/// What the caller observed outside the ledger: the publication deadlines
/// (PROTOCOL.md §5.5, `FAILURE_CASES.md` §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Publications {
    /// The anchor deadline of the latest checkpoint.
    pub anchors: Publication,
    /// The board deadline.
    pub board: Publication,
}

/// Every stage's result over one ledger, and the status they give.
#[derive(Debug)]
pub struct Report<'a> {
    index: LedgerIndex<'a>,
    authority: AuthorityStage<'a>,
    checkpoints: CheckpointChain,
    boxes: BoxStage<'a>,
    records: RecordStage<'a>,
    disputes: DisputeStage<'a>,
    evidence: Evidence,
    status: StatusReport,
}

impl<'a> Report<'a> {
    /// The ledger index (stage 3).
    #[must_use]
    pub const fn index(&self) -> &LedgerIndex<'a> {
        &self.index
    }

    /// The legal authorization.
    #[must_use]
    pub const fn authority(&self) -> &AuthorityStage<'a> {
        &self.authority
    }

    /// The checkpoint chain (stage 2).
    #[must_use]
    pub const fn checkpoints(&self) -> &CheckpointChain {
        &self.checkpoints
    }

    /// The boxes (stage 4).
    #[must_use]
    pub const fn boxes(&self) -> &BoxStage<'a> {
        &self.boxes
    }

    /// The records (stage 5).
    #[must_use]
    pub const fn records(&self) -> &RecordStage<'a> {
        &self.records
    }

    /// The disputes (stage 9).
    #[must_use]
    pub const fn disputes(&self) -> &DisputeStage<'a> {
        &self.disputes
    }

    /// What was handed to the status rule, step by step.
    #[must_use]
    pub const fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// The status and, under `HOLD_REVIEW`, the reasons.
    #[must_use]
    pub const fn status(&self) -> StatusReport {
        self.status
    }
}

/// `holds` without the reason that only completeness may carry.
fn without_close_missing(holds: HoldSet) -> HoldSet {
    holds
        .iter()
        .filter(|r| *r != HoldReason::CloseMissing)
        .fold(HoldSet::empty(), HoldSet::with)
}

const fn outcome(passed: bool) -> Outcome {
    if passed {
        Outcome::Passed
    } else {
        Outcome::Failed
    }
}

/// The outcome of the checkpoint step: failed when a checkpoint broke a
/// rule; passed when the last valid checkpoint covers every frame but the
/// checkpoints after it (a checkpoint cannot cover its own frame); not
/// run otherwise (no checkpoint yet, or other frames after the covered
/// part).
fn checkpoint_outcome(chain: &CheckpointChain, index: &LedgerIndex<'_>) -> Outcome {
    if !chain.findings().is_empty() {
        return Outcome::Failed;
    }
    let covered = chain.covered();
    let checkpoints_after = index
        .events()
        .iter()
        .filter(|e| e.seq.get() > covered && e.schema == SCHEMA_SIGNED_CHECKPOINT)
        .count();
    let after = index.tree_size().saturating_sub(covered);
    if chain.last().is_some() && u64::try_from(checkpoints_after).ok() == Some(after) {
        Outcome::Passed
    } else {
        Outcome::NotRun
    }
}

/// Runs every stage over the ledger `frames` (with the event objects
/// `events` published beside it) against `genesis`, and gives the status.
#[must_use]
pub fn verify_ledger<'a>(
    genesis: &VerifiedGenesis<'a>,
    frames: &'a [u8],
    events: &[&'a [u8]],
    publications: Publications,
) -> Report<'a> {
    let index = build_index(genesis, frames, events);
    let authority = authorize_ledger(genesis, &index);
    let checkpoints = verify_checkpoints(genesis, &index, &authority);
    let boxes = verify_boxes(genesis, &index, &authority);
    let records = verify_records(genesis, &index, &boxes);
    let disputes = verify_disputes(genesis, &index, &authority);

    let box_holds = boxes.reports().iter().fold(HoldSet::empty(), |acc, r| {
        acc.union(without_close_missing(r.holds))
    });
    let holds = index
        .ledger_holds()
        .union(authority.holds())
        .union(checkpoints.holds())
        .union(box_holds)
        .union(records.holds())
        .union(disputes.holds());
    let scopes = authority
        .authorization()
        .map_or(ScopeSet::empty(), ityv_state::Authorization::scopes);
    let receipt_scan = genesis
        .boxes()
        .any(|b| b.profile == CaptureProfile::ReceiptScan);
    let mut evidence = Evidence::new(scopes)
        .with_step(Step::Genesis, Outcome::Passed)
        .with_step(Step::Checkpoints, checkpoint_outcome(&checkpoints, &index))
        .with_step(Step::Frames, outcome(index.ledger_holds().is_empty()))
        .with_step(Step::BoxInvariants, Outcome::Passed)
        .with_step(
            Step::BoxCompleteness,
            if boxes.complete() {
                Outcome::Passed
            } else {
                Outcome::NotRun
            },
        )
        .with_step(Step::Records, Outcome::Passed)
        .with_anchors(publications.anchors)
        .with_board(publications.board)
        .with_holds(holds);
    if receipt_scan {
        evidence = evidence.with_receipt_scan();
    }
    let status = evaluate(&evidence);
    Report {
        index,
        authority,
        checkpoints,
        boxes,
        records,
        disputes,
        evidence,
        status,
    }
}
