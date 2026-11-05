//! Election state machines for ityv (ADR-0025).
//!
//! This crate decides, from inputs that other crates have already parsed and
//! verified, which state each election object is in and which transitions
//! are allowed. It covers the ledger side of the protocol: the device side
//! (the commitment unit's own box and visit typestates) is `ityv-cunit`,
//! the frames, checkpoints and publication deadlines are `ityv-ledger`, and
//! the full public verifier that drives these machines from a ledger is
//! `ityv-verify` (ADR-0029).
//!
//! | Module | What it decides | Specification |
//! |---|---|---|
//! | [`genesis`] | The pinned, signed genesis and its proved entries | §4, ADR-0028, VC-005, VC-104, VC-105 |
//! | [`auth`] | Legal-scope capabilities from a `LegalAuthorization` | PROTOCOL.md §4.4, ADR-0002, VC-006..008 |
//! | [`record`] | Record statuses and tally disposition | §7.2.1, §8, §10.6, §11.1, VC-042, VC-055, VC-057 |
//! | [`close`] | Close invariants and independent signers | §10.1, §10.2, VC-037, VC-038 |
//! | [`boxes`] | Ballot-box life cycle as typestate | §10, VC-037..040 |
//! | [`custody`] | Custody chain and seal changes | §10.3, VC-040 |
//! | [`issuance`] | Issuance and participation identities | `FAILURE_CASES.md` §0 |
//! | [`tally`] | Tally-scope and aggregate-opening gates, trustee quorum, paper comparison | §11.1, §11.2, §11.5, VC-057, VC-063, VC-075 |
//! | [`audit`] | Audit gates, audit signers, the escalation rule, the reason-code follow-ups, hand counts | §12, VC-045..047, VC-074 |
//! | [`roll`] | Roll-event signers and the custody quorum | §6.1, ADR-0033, ADR-0040, VC-107, VC-108, VC-111 |
//! | [`dispute`] | Dispute life cycle | §13, VC-048, VC-049 |
//! | [`status`] | The verifier status vocabulary | §14, VC-049, VC-050 |
//! | [`progress`] | Progress streams, alarms, observer counts and device swaps | §6.2, §6.3, §7.10, VC-102, VC-103 |
//! | [`hold`] | Sticky `HOLD_REVIEW` reasons | §10.2, §14 |
//! | [`sig`] | Binding verification tokens to an event's signatures | §3.1, VC-006, VC-016, VC-098 |
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
//! * Every signature an event carries is matched to a `Verified` token for
//!   the same purpose, bytes and signature, from the key the genesis
//!   registers for that signer and role; no two signers of one event share
//!   a key half ([`sig`]).
//!
//! * Every key, box, station, route, roster signer and limit a machine
//!   uses comes from a genesis entry proved against a pinned genesis whose
//!   signatures were checked ([`genesis`]); a check-in total comes from the
//!   observers' signed final count, and the counts a spare device continues
//!   from come from the signed swap record ([`progress`]).
//!
//! What this crate does **not** prove: that a signature is valid (it
//! consumes `ityv-crypto`'s `Verified` tokens), that an object is well
//! formed (`ityv-encoding`), that a ledger is consistent (`ityv-ledger`),
//! that a genesis set is sorted and agrees with the other sets (`ityv-verify`
//! recomputes every set, VC-104), or anything about paper the inputs do not
//! report.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod audit;
pub mod auth;
pub mod boxes;
pub mod close;
pub mod custody;
pub mod dispute;
pub mod error;
pub mod genesis;
pub mod hold;
pub mod issuance;
pub mod progress;
pub mod record;
pub mod roll;
pub mod sig;
pub mod status;
pub mod tally;

// Kani harnesses live outside `src/` because they carry a file-level lint
// relaxation, which CONSTITUTION.md §1.1 forbids under `src/`.
#[cfg(kani)]
#[path = "../kani/proofs.rs"]
mod proofs;

pub use audit::{
    AuditPhase, FollowUp, HandCount, RoundCount, SeedReadiness, admit_audit_commit,
    admit_audit_finding, admit_audit_freeze, admit_audit_seed, admit_sample_opening, audit_phase,
    check_audit_signers, follow_up,
};
pub use auth::{
    Authorization, BallotMark, Cap, CryptoTallyAid, DeployAuth, ObserverAccess, PURPOSE_LEGAL_AUTH,
    PublicBoard, Rla, ScopeMarker, StageGate, TrusteeBody, VoterCode, authorize, check_scope_rules,
    prerequisites, stage,
};
pub use boxes::{
    Audited, BallotBox, BoxSpec, CloseTokens, Closed, Counted, Fallback, Open, PURPOSE_BOX_CLOSE,
    PURPOSE_LATE_BOX_CLOSE, Provisioned, Transition,
};
pub use close::{
    CountFacts, MAX_VISIT_BALLOTS, Named, Observed, RosterEntry, check_observers,
    check_witness_set, check_witnesses, count_verdict, modules_gap_free, roster_key,
};
pub use custody::CustodyChain;
pub use dispute::{Dispute, DisputeEvent, DisputeStatus, DisputeType};
pub use error::Error;
pub use genesis::{Anchor, Entry, Genesis, Pinned};
pub use hold::{HoldReason, HoldSet};
pub use issuance::{EnvelopeIssuance, IssuanceCount, IssuanceTotals, issuance_verdict};
pub use progress::{
    Alarms, BoxStream, BoxUnitSwap, CHECK_WINDOW_SLOTS, CheckinStream, CheckinUnitSwap,
    MAX_PENDING, MAX_STATION_BOXES, ObserverCount, SlotOutcome, StationProgress, check_tick,
    out_of,
};
pub use record::{
    Disposition, Exclusion, Primary, Profile, Receipt, RecordEvent, RecordState, RecordStatus,
    TEST_STYLE_PREFIX, is_test_style,
};
pub use roll::{admit_amendment, admit_extract, admit_freeze, admit_receipt, custody_quorum};
pub use sig::{Key, Signed, check_event, halves_differ};
pub use status::{
    Evidence, LegalReference, Outcome, PURPOSE_LEGAL_DECISION, Publication, Status, StatusReport,
    Step, evaluate,
};
pub use tally::{
    LATE_CLOSE_WINDOW, MachineCount, PaperComparison, PaperCount, QuorumTokens, TallyReadiness,
    access_structure, admit_aggregate_opening, admit_tally_scope, check_quorum,
    checkpointed_before, compare_paper, quorum_message,
};
