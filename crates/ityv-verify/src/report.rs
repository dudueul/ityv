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
//! - the voting progress record ([`crate::verify_progress`], §7.10, part
//!   of the box invariants): a stream, alarm or close comparison that does
//!   not hold holds its box or station;
//! 6. participation ([`crate::verify_participation`] and
//!    [`crate::verify_roll`]): passed when every station's identities,
//!    party ceremony and provisioning record could be checked and the
//!    roll's freeze and every amendment took effect under the custody
//!    quorum; not run while one is not yet on the ledger; an event that
//!    cannot be taken, a repeated pseudonym, an identity that does not
//!    hold, a custody receipt that disagrees or a supplied contested
//!    check-in that does not verify holds the ledger;
//! 7. tally ([`crate::verify_tally`]): passed when every ballot style and
//!    reporting unit of the genesis has a tally scope that is the
//!    recomputation, an opening of every chunk that verifies, and a paper
//!    count that agrees; not run while any of them is not yet on the
//!    ledger; a refused event or a mismatch holds;
//! 8. audit ([`crate::verify_audit`]): passed when the seed is taken with
//!    the beacon value the caller observed and every ballot style's audit
//!    concluded under its rule (a round within its threshold or a hand
//!    count of every unit, every device with a code 1 or 2 compared in full
//!    with a finding); not run otherwise; a refused event, a frame that is
//!    not the ledger's, an opening that does not reconstruct or a missing
//!    ballot holds. The report computes this itself: no caller flag makes
//!    the audit concluded;
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
//! The checkpoints are anchored in time by the timestamp tokens on the
//! ledger (ADR-0034, ADR-0039): the verifier decides the anchor deadline
//! itself from the tokens of the last valid checkpoint
//! ([`CheckpointChain::anchor_deadline`]). It has no clock, so the caller
//! supplies its current time bucket, which only tells a window still open
//! from one missed when the last checkpoint is short of tokens, and the
//! board deadline (`ityv_ledger::check_board`) as [`Publications`]. Until
//! the anchor deadline is met the status stays `UNVERIFIED`; frames after
//! the last checkpoint that carry only checkpoints and timestamp records
//! do not keep step 2 from passing, since the tokens of the last
//! checkpoint can only be recorded after it.
//!
//! With the participation ledger complete and every unit's tally passed,
//! the status reaches `CRYPTO_TALLY_VERIFIED`; with every style's audit
//! concluded, `PAPER_AUDITED`. What the report does not run yet: split
//! view, connectivity and software (stages 10–12).

use ityv_encoding::{CaptureProfile, SCHEMA_TIMESTAMP_RECORD, ScopeSet, TimeBucket};
use ityv_ledger::SCHEMA_SIGNED_CHECKPOINT;
use ityv_state::status::{Step, evaluate};
use ityv_state::{Evidence, HoldReason, HoldSet, Outcome, Publication, StatusReport};

use crate::audit::{AuditInput, AuditStage, verify_audit};
use crate::authority::{AuthorityStage, authorize_ledger};
use crate::boxes::{BoxStage, verify_boxes};
use crate::checkpoint::{CheckpointChain, verify_checkpoints};
use crate::disputes::{DisputeStage, verify_disputes};
use crate::genesis::VerifiedGenesis;
use crate::index::{LedgerIndex, build_index};
use crate::participation::{ParticipationStage, verify_participation};
use crate::progress::{ProgressStage, verify_progress};
use crate::records::{RecordStage, verify_records};
use crate::roll::{RollInput, RollStage, verify_roll};
use crate::tally::{TallyStage, verify_tally};

/// What the caller brings from outside the ledger for the publication
/// deadlines (PROTOCOL.md §5.5, `FAILURE_CASES.md` §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Publications {
    /// The caller's current time, as the genesis's 15-minute bucket index.
    /// The verifier decides the anchor deadline from the timestamp tokens
    /// on the ledger ([`CheckpointChain::anchor_deadline`]); this tells only
    /// whether the window of a last checkpoint still short of tokens is
    /// open (ADR-0034 §4).
    pub now: TimeBucket,
    /// The board deadline.
    pub board: Publication,
}

/// Every stage's result over one ledger, and the status they give.
#[derive(Debug)]
pub struct Report<'a> {
    index: LedgerIndex<'a>,
    authority: AuthorityStage<'a>,
    checkpoints: CheckpointChain<'a>,
    boxes: BoxStage<'a>,
    records: RecordStage<'a>,
    progress: ProgressStage<'a>,
    participation: ParticipationStage<'a>,
    roll: RollStage<'a>,
    disputes: DisputeStage<'a>,
    tally: TallyStage<'a>,
    audit: AuditStage<'a>,
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

    /// The checkpoint chain (stage 2), with the ledger's timestamp records.
    #[must_use]
    pub const fn checkpoints(&self) -> &CheckpointChain<'a> {
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

    /// The voting progress record.
    #[must_use]
    pub const fn progress(&self) -> &ProgressStage<'a> {
        &self.progress
    }

    /// The participation ledger (stage 6).
    #[must_use]
    pub const fn participation(&self) -> &ParticipationStage<'a> {
        &self.participation
    }

    /// The voter roll (stage 6).
    #[must_use]
    pub const fn roll(&self) -> &RollStage<'a> {
        &self.roll
    }

    /// The disputes (stage 9).
    #[must_use]
    pub const fn disputes(&self) -> &DisputeStage<'a> {
        &self.disputes
    }

    /// The tally (stage 7).
    #[must_use]
    pub const fn tally(&self) -> &TallyStage<'a> {
        &self.tally
    }

    /// The audit (stage 8).
    #[must_use]
    pub const fn audit(&self) -> &AuditStage<'a> {
        &self.audit
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

/// The outcome of a step that only passes or is not yet run: what it
/// found wrong is a hold, not a failure.
const fn ran(passed: bool) -> Outcome {
    if passed {
        Outcome::Passed
    } else {
        Outcome::NotRun
    }
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
/// checkpoints and timestamp records after it (a checkpoint cannot cover
/// its own frame, and its tokens come after it; a token is the authority's
/// signed statement, not ledger content another stage reads); not run
/// otherwise (no checkpoint yet, or other frames after the covered part).
fn checkpoint_outcome(chain: &CheckpointChain<'_>, index: &LedgerIndex<'_>) -> Outcome {
    if !chain.findings().is_empty() {
        return Outcome::Failed;
    }
    let covered = chain.covered();
    let checkpoints_after = index
        .events()
        .iter()
        .filter(|e| {
            e.seq.get() > covered
                && (e.schema == SCHEMA_SIGNED_CHECKPOINT || e.schema == SCHEMA_TIMESTAMP_RECORD)
        })
        .count();
    let after = index.tree_size().saturating_sub(covered);
    if chain.last().is_some() && u64::try_from(checkpoints_after).ok() == Some(after) {
        Outcome::Passed
    } else {
        Outcome::NotRun
    }
}

/// Runs every stage over the ledger `frames` (with the event objects
/// `events` published beside it) against `genesis`, and gives the status,
/// with nothing observed for the audit: no beacon value, no restricted
/// opening. The audit cannot conclude without the beacon value, so the
/// status stops at `CRYPTO_TALLY_VERIFIED` ([`verify_ledger_with`]).
#[must_use]
pub fn verify_ledger<'a>(
    genesis: &VerifiedGenesis<'a>,
    frames: &'a [u8],
    events: &[&'a [u8]],
    publications: Publications,
) -> Report<'a> {
    verify_ledger_with(
        genesis,
        frames,
        events,
        publications,
        &AuditInput::default(),
    )
}

/// As [`verify_ledger`], with what the caller brings to the audit: the
/// beacon value it observed and, for a verifier with access, the
/// restricted sample openings ([`AuditInput`]).
#[must_use]
pub fn verify_ledger_with<'a>(
    genesis: &VerifiedGenesis<'a>,
    frames: &'a [u8],
    events: &[&'a [u8]],
    publications: Publications,
    audit_input: &AuditInput<'_>,
) -> Report<'a> {
    verify_ledger_full(
        genesis,
        frames,
        events,
        publications,
        audit_input,
        &RollInput::default(),
    )
}

/// As [`verify_ledger_with`], with what a verifier with access brings to
/// the roll stage: the restricted contested check-ins ([`RollInput`]).
#[must_use]
pub fn verify_ledger_full<'a>(
    genesis: &VerifiedGenesis<'a>,
    frames: &'a [u8],
    events: &[&'a [u8]],
    publications: Publications,
    audit_input: &AuditInput<'_>,
    roll_input: &RollInput<'a>,
) -> Report<'a> {
    let index = build_index(genesis, frames, events);
    let authority = authorize_ledger(genesis, &index);
    let checkpoints = verify_checkpoints(genesis, &index, &authority);
    let boxes = verify_boxes(genesis, &index, &authority);
    let records = verify_records(genesis, &index, &boxes);
    let progress = verify_progress(genesis, &index, &boxes);
    let participation = verify_participation(genesis, &index, &boxes, &records);
    let roll = verify_roll(genesis, &index, &participation, roll_input);
    let disputes = verify_disputes(genesis, &index, &authority);
    let tally = verify_tally(
        genesis,
        &index,
        &authority,
        &checkpoints,
        &boxes,
        &records,
        &disputes,
    );
    let audit = verify_audit(
        genesis,
        &index,
        &authority,
        &checkpoints,
        &records,
        &tally,
        audit_input,
    );

    let box_holds = boxes.reports().iter().fold(HoldSet::empty(), |acc, r| {
        acc.union(without_close_missing(r.holds))
    });
    let holds = index
        .ledger_holds()
        .union(authority.holds())
        .union(checkpoints.holds())
        .union(box_holds)
        .union(records.holds())
        .union(progress.holds())
        .union(participation.holds())
        .union(roll.holds())
        .union(disputes.holds())
        .union(tally.holds())
        .union(audit.holds());
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
        .with_step(Step::BoxCompleteness, ran(boxes.complete()))
        .with_step(Step::Records, Outcome::Passed)
        .with_step(
            Step::Participation,
            ran(participation.complete() && roll.complete()),
        )
        .with_step(Step::Tally, ran(tally.passed()))
        .with_step(Step::Audit, ran(audit.passed()))
        .with_anchors(checkpoints.anchor_deadline(publications.now))
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
        progress,
        participation,
        roll,
        disputes,
        tally,
        audit,
        evidence,
        status,
    }
}
