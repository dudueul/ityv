//! The commitment unit of the casting scanner (ADR-0017).
//!
//! `ityv-cunit` is the trusted core that turns one interpreted ballot into
//! every cryptographic object the scanner emits: the commitments and their
//! OR proof, the share package for the trustees, the record signatures,
//! the tracking code, the imprint command, and on request the pre-cast
//! challenge opening or the code slip. It also keeps the box's journal
//! chain, batch attestations and close accounting.
//!
//! The crate owns no I/O. The host implements [`port::ModulePort`] for each
//! chamber module and [`port::JournalSink`] for durable storage, supplies
//! time buckets and per-operation device seeds, and receives bytes in its
//! own buffers. Ordering rules are types: a [`ballot::Ballot`] can produce
//! an imprint command or a slip only in the `Durable` state, which exists
//! only after the journal sink reported the record durable (VC-054), and
//! a closed box ([`boxstate::ClosedBox`]) cannot interpret a new ballot
//! (VC-039). Every per-ballot secret lives in one caller-provided
//! [`ballot::BallotWork`], which a ballot borrows and which is wiped on
//! every exit path. After a power loss, [`boxstate::OpenBox::resume`]
//! rebuilds the box from the journal.
//!
//! | module | contents | specification |
//! |---|---|---|
//! | [`config`] | the validated election configuration | ADR-0017 §2, §12 |
//! | [`link`] | `Interpretation`, `VisitEnd`, `ModuleIssue`, `JournalEntry` objects | ENCODING.md §8.19 |
//! | [`port`] | host traits, the module batch-signing rule | ADR-0017 §3, §8 |
//! | [`rng`] | the SHA3-512 counter-mode generator | ADR-0017 §12 |
//! | [`ballot`] | per-ballot typestate and every per-ballot object | PROTOCOL.md §7.3–§7.7, §8, §9 |
//! | [`boxstate`] | box accounting, batches, scan counts, close, resume | PROTOCOL.md §7.2.1, §7.8, §10.2 |
//! | [`rules`] | the pure counting rules (Kani targets) | §7.2, VC-021, VC-034, VC-038, VC-052 |
//!
//! Properties: `#![no_std]`, no heap, no `unsafe`, no panics (workspace
//! lint set). Secrets live in the work area and are wiped when a ballot
//! reaches a terminal state, fails or is dropped (VC-020; the deductive
//! proof of erasure is a V3 item, see the crate README).
#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod ballot;
pub mod boxstate;
pub mod config;
pub mod error;
pub mod link;
pub mod port;
pub mod rng;
pub mod rules;

#[cfg(kani)]
#[path = "../kani/proofs.rs"]
mod proofs;

pub use ballot::{Ballot, BallotWork, BuildBuffers, ImprintCommand};
pub use boxstate::{
    CloseInputs, CloseOutput, CloseToken, ClosedBox, OpenBox, ResumeInputs, Signer, Totals,
};
pub use config::{BallotStyle, ConfigParts, ElectionConfig, ModuleConfig, Profile, TrusteeConfig};
pub use error::{ConfigFault, Error, Invariant};
pub use link::{
    Interpretation, JournalEntry, JournalKind, ModuleIssue, ModuleIssueParts, VisitEnd,
};
pub use port::{
    JournalError, JournalItem, JournalSink, JournalSource, ModulePort, PortError, Sealed,
    module_may_sign_batch,
};
pub use rng::DeviceRng;
pub use rules::{EnvelopeCounts, RecordTail, WaitingAction, WaitingArea};
