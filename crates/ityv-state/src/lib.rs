//! Election state machines for ityv (ADR-0025).
//!
//! This crate decides, from inputs that other crates have already parsed and
//! verified, which state each election object is in and which transitions
//! are allowed. It covers the ledger side of the protocol: the device side
//! (the commitment unit's own box and visit typestates) is `ityv-cunit`,
//! the frames, checkpoints and publication deadlines are `ityv-ledger`, and
//! the full public verifier that drives these machines from a ledger is the
//! future `ityv-verify` (M5).
//!
//! | Module | What it decides | Specification |
//! |---|---|---|
//! | [`auth`] | Legal-scope capabilities from a `LegalAuthorization` | PROTOCOL.md §4.4, ADR-0002, VC-006..008 |
//! | [`record`] | Record statuses and tally disposition | §7.2.1, §8, §10.6, §11.1, VC-042, VC-055, VC-057 |
//! | [`close`] | Close invariants and independent signers | §10.1, §10.2, VC-037, VC-038 |
//! | [`boxes`] | Ballot-box life cycle as typestate | §10, VC-037..040 |
//! | [`custody`] | Custody chain and seal changes | §10.3, VC-040 |
//! | [`issuance`] | Issuance and participation identities | `FAILURE_CASES.md` §0 |
//! | [`tally`] | Tally-scope and aggregate-opening gates | §11.1, §11.2, VC-057, VC-063 |
//! | [`dispute`] | Dispute life cycle | §13, VC-048, VC-049 |
//! | [`status`] | The verifier status vocabulary | §14, VC-049, VC-050 |
//! | [`hold`] | Sticky `HOLD_REVIEW` reasons | §10.2, §14 |
//! | [`error`] | Typed refusals | — |
//!
//! Properties that hold by construction:
//!
//! * `#![no_std]`, no heap allocation, no `unsafe`, no panics (the
//!   workspace lint set; Kani harnesses under `cfg(kani)`).
//! * State is a type where the protocol fixes the order of events: a box
//!   is provisioned, opened, possibly in fallback, closed, counted and
//!   audited, and each transition consumes the previous state. A closed box
//!   has no method that takes a record (VC-039).
//! * Operations gated by a legal scope take a [`auth::Cap`] that only a
//!   checked [`auth::Authorization`] can grant (CONSTITUTION.md §1.7).
//! * Discrepancies never disappear by accumulation: they leave sticky
//!   [`hold::HoldReason`]s, which only the specification's own resolving
//!   events remove (a late box close, a late batch close).
//! * No machine state produces `LEGAL_CERTIFIED` (VC-049): the status
//!   vocabulary has no such variant, and a [`status::LegalReference`] comes
//!   only from a verified signature of a legal authority.
//!
//! What this crate does **not** prove: that a signature is valid (it
//! consumes `ityv-crypto`'s `Verified` tokens, or flags set by the caller
//! where no canonical object exists yet, listed in ADR-0025), that an
//! object is well formed (`ityv-encoding`), that a ledger is consistent
//! (`ityv-ledger`), or anything about paper the inputs do not report.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod auth;
pub mod boxes;
pub mod close;
pub mod custody;
pub mod dispute;
pub mod error;
pub mod hold;
pub mod issuance;
pub mod record;
pub mod status;
pub mod tally;

// Kani harnesses live outside `src/` because they carry a file-level lint
// relaxation, which CONSTITUTION.md §1.1 forbids under `src/`.
#[cfg(kani)]
#[path = "../kani/proofs.rs"]
mod proofs;

pub use auth::{
    Authorization, BallotMark, Cap, CryptoTallyAid, DeployAuth, ObserverAccess, PURPOSE_LEGAL_AUTH,
    PublicBoard, Rla, ScopeMarker, StageGate, TrusteeBody, VoterCode, authorize, check_scope_rules,
    prerequisites, stage,
};
pub use boxes::{
    Audited, BallotBox, BoxOpening, BoxSpec, Closed, Counted, Fallback, FallbackEvent,
    ImprintAudit, LateBatchClose, Open, PURPOSE_BOX_CLOSE, PURPOSE_LATE_BOX_CLOSE, PhysicalCounts,
    Provisioned, Transition,
};
pub use close::{
    CountFacts, MAX_VISIT_BALLOTS, Observed, RosterEntry, check_witnesses, count_verdict,
    modules_gap_free,
};
pub use custody::{Actor, CustodyChain, CustodyHandoff, ReasonCode, SealChange};
pub use dispute::{Dispute, DisputeEvent, DisputeFiling, DisputeStatus, DisputeType};
pub use error::Error;
pub use hold::{HoldReason, HoldSet};
pub use issuance::{EnvelopeIssuance, IssuanceCount, IssuanceTotals, issuance_verdict};
pub use record::{
    Disposition, Exclusion, Primary, Profile, Receipt, RecordEvent, RecordState, RecordStatus,
    TEST_STYLE_PREFIX, is_test_style,
};
pub use status::{
    Evidence, LegalReference, Outcome, PURPOSE_LEGAL_DECISION, Publication, Status, StatusReport,
    Step, evaluate,
};
pub use tally::{LATE_CLOSE_WINDOW, TallyReadiness, admit_aggregate_opening, admit_tally_scope};
