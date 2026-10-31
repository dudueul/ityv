//! The ityv evidence ledger (ADR-0016): Merkle tree, frame chain, witness
//! checkpoints, quorum policy and publication deadlines.
//!
//! | module | contents | specification |
//! |---|---|---|
//! | [`merkle`] | RFC 9162-shaped SHA3-512 tree, incremental accumulator, inclusion and consistency proofs, sorted-set roots | PROTOCOL.md §5.3 |
//! | [`frame`] | frame chain rules, chain state, on-disk stream parser with torn-tail isolation | PROTOCOL.md §5.1 |
//! | [`checkpoint`] | `SignedCheckpoint` (schema 0x0010), successor validation, witness signing memory | PROTOCOL.md §5.4, ENCODING.md §8.4 |
//! | [`policy`] | quorum profile validity, roster, quorum and diversity evaluation | PROTOCOL.md §5.4 (VC-014) |
//! | [`publication`] | anchor and board deadlines | PROTOCOL.md §5.5 |
//!
//! Properties that hold by construction:
//!
//! * `#![no_std]`, no heap allocation, no `unsafe`, no panics (workspace
//!   lint set; Kani harnesses under `cfg(kani)` for the tree algorithms).
//! * Every verification returns a [`Verified`] token that borrows all of
//!   its inputs and that only this crate can create.
//! * Fixed capacities: 2^40 leaves, proof length 40 (41 for consistency),
//!   64 witnesses and signatures. Nothing is sized by input.
//! * Hashing and signatures are reached only through `ityv-crypto`.
//!
//! What this crate does **not** do: store or load anything (the host owns
//! files, databases and durability), reach a network or a clock, interpret
//! event bodies, or decide state transitions such as closing (M4). It is a
//! single-writer design by contract: it enforces the append rules but the
//! host provides mutual exclusion.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod checkpoint;
pub mod error;
pub mod frame;
pub mod merkle;
pub mod policy;
pub mod publication;
pub mod verified;

// Kani harnesses live outside `src/` because they carry a file-level lint
// relaxation, which CONSTITUTION.md §1.1 forbids under `src/`.
#[cfg(kani)]
#[path = "../kani/proofs.rs"]
mod proofs;

pub use checkpoint::{
    LastSigned, MAX_BODY_LEN, MAX_SIGNATURES, MAX_WITNESS_ID_LEN, SCHEMA_SIGNED_CHECKPOINT,
    SCHEMA_WITNESS_MEMORY, SIGNATURE_LEN, Signable, Signatures, SignedCheckpoint,
    SignedCheckpointParts, Successor, WitnessMemory, WitnessSignatureEntry, WitnessSignatureRef,
    validate_successor,
};
pub use error::{Dimension, Error, Root};
pub use frame::{
    ChainHead, ChainState, FrameStream, Linked, MAX_FRAME_LEN, MIN_FRAME_LEN, RECORD_PREFIX_LEN,
    Record, Resend, classify_resend, link, next_frame, write_record,
};
pub use merkle::{
    Accumulator, ConsistencyProof, Consistent, EMPTY_ROOT, Included, InclusionProof, Leaves,
    MAX_CONSISTENCY_PATH, MAX_DEPTH, MAX_INCLUSION_PATH, MAX_TREE_SIZE, check_sorted,
    consistency_proof, depth_for_size, inclusion_proof, leaf_hash, node_hash, root_of_leaves,
    sorted_set_root, split_point, verify_consistency, verify_inclusion,
};
pub use policy::{
    DiversityPolicy, MAX_WITNESSES, Published, QuorumProfile, Roster, WitnessEntry, evaluate,
    profile_matches_roster,
};
pub use publication::{
    ANCHOR_WINDOW, BOARD_WINDOW, Breach, REQUIRED_ANCHORS, Status, anchor_deadline, board_deadline,
    check_anchor, check_board,
};
pub use verified::Verified;
