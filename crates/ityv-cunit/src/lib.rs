//! The commitment unit of the casting scanner (ADR-0017, ADR-0021).
//!
//! `ityv-cunit` is the trusted core that turns one voter's visit (one to
//! eight interpreted ballots) into every cryptographic object the scanner
//! emits: per ballot the commitments and their OR proof, the share package
//! for the trustees, the record signatures and the tracking code; per
//! visit the journaled decision, the imprint commands, the openings of the
//! checked ballots, the out-of-district label sticker and the code slip.
//! It also keeps the box's journal chain, batch attestations and close
//! accounting.
//!
//! The crate owns no I/O. The host implements [`port::ModulePort`] for each
//! chamber module, [`port::JournalSink`] for durable storage and
//! [`port::StagingPort`] for a visit's finished records and packages,
//! supplies time buckets and per-operation device seeds, and receives
//! bytes in its own buffers. Ordering rules are types: the cast-or-check
//! decision exists only on a [`visit::ReadyVisit`], which exists only once
//! every position of the visit carries its device and module record
//! signatures (VC-068); imprint commands exist only on a
//! [`visit::DecidedVisit`], after the decision entry is durable (VC-054);
//! a closed box ([`boxstate::ClosedBox`]) cannot interpret a new ballot
//! (VC-039). Every per-ballot secret lives in one caller-provided
//! [`ballot::BallotWork`] while the ballot is built, and the few a visit
//! keeps in one caller-provided [`visit::VisitWork`]; both are wiped on
//! every exit path. Each bound position is journaled with the counters it
//! consumed before the next ballot is taken, so after a power loss
//! [`boxstate::OpenBox::resume`] rebuilds the box from the journal (and a
//! dry-run question to each module) with every consumed counter
//! accounted for.
//!
//! | module | contents | specification |
//! |---|---|---|
//! | [`config`] | the validated election configuration | ADR-0017 §2, §12 |
//! | [`link`] | `Interpretation`, `VisitEnd`, `ModuleIssue`, `JournalEntry` objects | ENCODING.md §8.19 |
//! | [`port`] | host traits, the module batch- and record-signing rules | ADR-0017 §3, §8, VC-068 |
//! | [`rng`] | the SHA3-512 counter-mode generator | ADR-0017 §12 |
//! | [`ballot`] | per-position typestate and every per-ballot object | PROTOCOL.md §7.3 steps 1–5, §9 |
//! | [`visit`] | visit typestate: decision, journal, imprint, opening, sticker, slip | PROTOCOL.md §7.3 steps 6–11, §7.7, §8, ADR-0021 |
//! | [`boxstate`] | box accounting, batches, scan counts, close | PROTOCOL.md §7.2.1, §7.8, §10.2 |
//! | [`resume`] | resume from the journal after a power loss | PROTOCOL.md §7.3 재개, §7.8, VC-069 |
//! | [`rules`] | the pure counting and resume rules (Kani targets) | §7.2, VC-021, VC-034, VC-038, VC-052, VC-069 |
//!
//! Properties: `#![no_std]`, no heap, no `unsafe`, no panics (workspace
//! lint set). Secrets live in the work areas and are wiped when a ballot
//! is bound or fails and when a visit ends, fails or is dropped (VC-020;
//! the deductive proof of erasure is a V3 item, see the crate README).
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
pub mod resume;
pub mod rng;
pub mod rules;
pub mod visit;

#[cfg(kani)]
#[path = "../kani/proofs.rs"]
mod proofs;

pub use ballot::{Ballot, BallotWork, Bound, BuildBuffers};
pub use boxstate::{CloseInputs, CloseOutput, CloseToken, ClosedBox, OpenBox, Signer, Totals};
pub use config::{BallotStyle, ConfigParts, ElectionConfig, ModuleConfig, Profile, TrusteeConfig};
pub use error::{ConfigFault, Error, Invariant};
pub use link::{
    Interpretation, JournalEntry, JournalKind, ModuleIssue, ModuleIssueParts, VisitEnd,
};
pub use port::{
    JournalError, JournalItem, JournalSink, JournalSource, ModulePort, PortError, Sealed, Staged,
    StagingPort, module_may_sign_batch, module_may_sign_record,
};
pub use resume::ResumeInputs;
pub use rng::DeviceRng;
pub use rules::{
    Choice, EnvelopeCounts, PaperAction, ResumeCase, ResumePlan, Settlement, WaitingArea,
};
pub use visit::{
    DecidedVisit, Decision, ImprintCommand, LabelCommand, ProcessedVisit, ReadyVisit, VisitWork,
};
