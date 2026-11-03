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
//! | [`checkpoint`] | 2. Checkpoint chain: witness quorum and diversity, successor rules, roots recomputed from the ledger | §5.3, §5.4, §14 2, VC-011..014 |
//! | [`index`] | 3. Frame chain, event hashes, canonical events, replayed events, records after close | §5.1, §14 3, VC-010, VC-039, VC-101 |
//! | [`authority`] | The signed legal authorization that grants every capability | §4.4, VC-006..008 |
//! | [`records`] | 5. Cast records: OR proofs, record signatures, batch attestations, counter continuity, record set roots, `UNATTESTED` | §7.2.1, §7.5, §7.6, §14 5, VC-025..027, VC-053, VC-057 |
//! | [`boxes`] | 4. Every expected box through its state machine: opening, records, fallback, close invariants, late closes, custody, completeness | §7, §14 4, VC-037..040, VC-100 |
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
//! What this crate does **not** do yet (ROADMAP M5): the record,
//! participation, tally, audit, dispute, split-view, connectivity and
//! software stages (5–12), and the status ladder that combines them.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod authority;
pub mod boxes;
pub mod checkpoint;
mod cross;
mod disputes;
pub mod error;
pub mod genesis;
pub mod index;
pub mod records;
mod sets;
mod sigs;

// Kani harnesses live outside `src/` because they carry a file-level lint
// relaxation, which CONSTITUTION.md §1.1 forbids under `src/`.
#[cfg(kani)]
#[path = "../kani/proofs.rs"]
mod proofs;

pub use authority::{AuthorityStage, authorize_ledger};
pub use boxes::{BoxRefusal, BoxReport, BoxStage, Phase, Refusal, verify_boxes};
pub use checkpoint::{
    CheckpointChain, CheckpointFinding, CheckpointFindingKind, VerifiedCheckpoint,
    verify_checkpoints,
};
pub use error::{Error, Reference, Rule};
pub use genesis::{
    AmendableSets, AmendmentInput, FixedSets, GenesisInput, VerifiedGenesis, verify_genesis,
};
pub use index::{
    Finding, FindingKind, IndexedEvent, LedgerIndex, OPAQUE_SCHEMAS, Scope, build_index,
};
pub use records::{
    AcceptedRecord, BatchFinding, BatchProblem, BoxRecords, RecordRefusal, RecordStage,
    RejectedRecord, verify_records,
};
