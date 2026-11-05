//! The ityv public verifier (ADR-0029; PROTOCOL.md §14).
//!
//! The verifier trusts nothing but the genesis pin its caller supplies
//! from outside the data it verifies. It drives the other TCB crates over
//! whole data sets: `ityv-crypto` verifies every signature into a token,
//! `ityv-ledger` recomputes every tree and frame link, `ityv-state` binds
//! tokens to registered signers and decides states. Each stage returns a
//! value only this crate can make, and the next stage takes that value,
//! so no stage runs on input an earlier stage did not accept.
//!
//! | Module | Stage | Specification |
//! |---|---|---|
//! | [`genesis`] | 1. Pin, signatures, every entry set whole, cross-set agreement, amendments | §4, §14 1, ADR-0028, VC-005, VC-009, VC-014, VC-067, VC-104, VC-105 |
//! | [`checkpoint`] | 2. Checkpoint chain: witness quorum and diversity, successor rules, roots recomputed from the ledger, no backdated time, the anchoring of each checkpoint | §5.3, §5.4, §5.5, §14 2, VC-011..014, VC-115, VC-116 |
//! | [`timestamp`] | External timestamps: the genesis's authorities, every timestamp record's token verified under its authority's pins over the stamped event | §5.5, ADR-0034, ADR-0037, ADR-0039, VC-114..118 |
//! | [`index`] | 3. Frame chain, event hashes, canonical events, replayed events, records after close | §5.1, §14 3, VC-010, VC-039, VC-101 |
//! | [`authority`] | The signed legal authorization that grants every capability | §4.4, VC-006..008 |
//! | [`boxes`] | 4. Every expected box through its state machine, following genesis amendments: opening, records, fallback, device swap, close invariants, late closes, custody, completeness | §4.3, §7, §14 4, VC-037..040, VC-100, VC-105, VC-106 |
//! | [`records`] | 5. Cast records: OR proofs, record signatures, batch attestations, counter continuity, record set roots, `UNATTESTED` | §7.2.1, §7.5, §7.6, §14 5, VC-025..027, VC-053, VC-057 |
//! | [`progress`] | Voting progress record: device streams in slot order, device swaps, station alarms and on-site checks, close comparisons | §7.10, ADR-0027, VC-102, VC-103, VC-106 |
//! | [`roll`] | 6. The voter roll: source extracts, the freeze as their merge, custody receipts and the custody quorum, amendments with their sources, contested check-ins | §6.1, §6.2, §14 6, ADR-0033, ADR-0040, VC-107..111 |
//! | [`participation`] | 6. Participation ledger: party key ceremonies, module provisioning records, participation sets, the station identities, repeated pseudonyms | §6.4, §6.5, §9.4.2, §14 6, VC-018, VC-084, VC-092, VC-093, VC-095 |
//! | [`tally`] | 7. Tally: receipt resolutions, legal tally effects, tally scopes recomputed, aggregate openings against the commitments, paper counts per reporting unit | §10.6, §11, §14 7, VC-024, VC-042..044, VC-057, VC-063, VC-075, VC-099 |
//! | [`audit`] | 8. Audit: freezes against the recomputed frames, the commit, the seed recomputed against the binding checkpoint and the observed beacon, the sample redrawn, opening references and comparisons, restricted openings reconstructed, escalation, full comparisons, findings, hand counts | §12, §14 8, VC-045..047, VC-059, VC-074 |
//! | [`connectivity`] | 11. Connectivity: the manifest's one-way rules, gateway sessions and their frame logs, every frame's signature, shape, window and padding proof, every stream's objects, the inclusion of every device event, incidents | §5.8, §14 11, ADR-0041, VC-077..080, VC-083 |
//! | [`capture`] | Tools outside the status: an observer's capture against the published chain, the carrier's records against the sessions | §5.8 item 7, ADR-0041, VC-081 |
//! | [`report`] | Every stage over one ledger and the status ladder | §14 (end), VC-049, VC-050 |
//! | [`error`] | Refusals of the genesis stage | — |
//!
//! Properties that hold by construction:
//!
//! * `#![no_std]` with `alloc` (the verifier holds whole sets and
//!   ledgers; the field devices never run it), no `unsafe`, no panics,
//!   no clock, no I/O, no unordered collections (the workspace lint set,
//!   CONSTITUTION.md §1).
//! * A [`genesis::VerifiedGenesis`] exists only for a genesis whose every
//!   rule held; an [`index::LedgerIndex`] is built only on one.
//! * Signatures are verified here and nowhere else from ledger data; no
//!   caller hands this crate a `Verified` token.
//! * Problems in the ledger do not stop the index: an invalid frame is
//!   left out, reported as a [`index::Finding`], and puts the box it
//!   belongs to (or the whole ledger) under `HOLD_REVIEW`.
//!
//! External timestamps (ADR-0039) are verified with `ityv-tsa` and judged
//! by the checkpoint stage; the ledger's anchor deadline comes from them.
//!
//! What this crate does **not** do yet (ROADMAP M5): the split-view and
//! software stages (10 and 12), and the radio checks and teardown reports
//! of the connectivity stage (VC-082). The highest status
//! [`report::verify_ledger_with`] gives is `PAPER_AUDITED`, and only with
//! the beacon value the caller observed; [`report::verify_ledger`], which
//! has none, stops at `CRYPTO_TALLY_VERIFIED`.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod audit;
pub mod authority;
pub mod boxes;
pub mod capture;
pub mod checkpoint;
pub mod connectivity;
mod cross;
pub mod disputes;
pub mod error;
pub mod genesis;
pub mod index;
pub mod participation;
pub mod progress;
pub mod records;
pub mod report;
pub mod roll;
mod sets;
mod sigs;
pub mod tally;
pub mod timestamp;

// Kani harnesses live outside `src/` because they carry a file-level lint
// relaxation, which CONSTITUTION.md §1.1 forbids under `src/`.
#[cfg(kani)]
#[path = "../kani/proofs.rs"]
mod proofs;

pub use audit::{
    AuditEvent, AuditInput, AuditRefusal, AuditRefused, AuditStage, AuditedRecord,
    BeaconObservation, CommitTaken, Comparison, DeclaredRule, DeviceAudit, FrameProblem,
    Reconstruction, Reconstructions, SeedTaken, StyleAudit, draw_sample, verify_audit,
};
pub use authority::{AuthorityStage, authorize_ledger};
pub use boxes::{BoxRefusal, BoxReport, BoxStage, Phase, Refusal, verify_boxes};
pub use capture::{
    CaptureComparison, CaptureFinding, CaptureFrame, CaptureProblem, CarrierFinding,
    CarrierInterval, CarrierLine, CarrierLog, CarrierProblem, compare_capture, compare_carrier,
};
pub use checkpoint::{
    CheckpointChain, CheckpointFinding, CheckpointFindingKind, VerifiedCheckpoint,
    verify_checkpoints, witness_entries, witness_set,
};
pub use connectivity::{
    ConnectivityStage, IncidentProblem, IncidentReport, LinkDevice, LinkFinding, LinkProblem,
    LinkReport, ManifestFinding, ManifestProblem, OutsideEvent, SessionFinding, SessionProblem,
    SessionReport, StationUplink, verify_connectivity,
};
pub use disputes::{Decision, DisputeEntry, DisputeStage, verify_disputes};
pub use error::{Error, Reference, Rule};
pub use genesis::{
    AmendableSets, AmendmentInput, FixedSets, GenesisInput, VerifiedGenesis, verify_genesis,
};
pub use index::{
    Finding, FindingKind, IndexedEvent, LedgerIndex, OPAQUE_SCHEMAS, Scope, build_index,
};
pub use participation::{
    CountFinding, KeyFinding, KeyProblem, ParticipationStage, SetFinding, SetProblem,
    StationParticipation, verify_participation,
};
pub use progress::{
    BoxProgressReport, CloseCheck, MAX_PROGRESS_SLOTS, ProgressReason, ProgressRefusal,
    ProgressStage, RaisedAlarm, StationProgressReport, bucket_slots, verify_progress,
};
pub use records::{
    AcceptedRecord, BatchFinding, BatchProblem, BoxRecords, RecordRefusal, RecordStage,
    RejectedRecord, verify_records,
};
pub use report::{Publications, Report, verify_ledger, verify_ledger_full, verify_ledger_with};
pub use roll::{
    ContestedFinding, ContestedReport, Custody, CustodyMismatch, RollEvent, RollInput, RollRefusal,
    RollRefused, RollStage, TakenAmendment, TakenExtract, roll_entry_commitment,
    roll_entry_included, verify_roll,
};
pub use tally::{
    ChunkOpening, ExpectedExclusion, OpeningOutcome, ScopeProblem, TallyEvent, TallyRefusal,
    TallyRefused, TallyStage, UnitTally, verify_tally,
};
pub use timestamp::{
    Anchoring, MAX_TIMESTAMP_ACCURACY_MS, MIN_POLICY_ACCURACY_MS, StampedToken, TimestampProblem,
    TimestampRefusal, TimestampStage, Unanswered, verify_timestamps,
};
