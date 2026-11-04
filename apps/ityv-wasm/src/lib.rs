//! The verification console's WebAssembly wrapper (outside the TCB,
//! CONSTITUTION.md §0; ADR-0038).
//!
//! It reads a development bundle (`tools/ityv-sim/README.md`, "번들
//! 형식"), runs the real public verifier over it (`verify_genesis`, then
//! `verify_ledger`) and writes what the verifier found as JSON
//! ([`report`]), each record with its inclusion in the first checkpoint
//! covering it (module `inclusion`). The browser calls it through a C ABI
//! ([`ffi`]: `alloc`, `dealloc`, `verify_bundle`, `verify_bundle_pinned`,
//! `fingerprint`, `result_len`), so nothing between the bundle and the
//! verifier runs on a server.
//!
//! Rules (ADR-0038): no dependency but the workspace crates; the
//! workspace lint set except that `unsafe` is denied rather than
//! forbidden, and allowed item by item in [`ffi`] only, each block with
//! its SAFETY comment; checked arithmetic everywhere, so no input can make
//! the module trap; no status, hold or fingerprint computed here that a
//! TCB crate computes. What this crate does not prove: that the bundle's
//! pin is the published one (the console says so and lets the viewer enter
//! another), or anything the verifier itself does not check yet (audit,
//! split view, connectivity, software; PROTOCOL.md §14 8, 10–12).

extern crate alloc;

pub mod bundle;
pub mod ffi;
mod inclusion;
mod json;
pub mod report;

pub use report::{
    Lookup, UnitStatus, Verification, fingerprint, fingerprint_of, grouped, hold_names, sha3_hex,
    tally_refusal_hold, unit_statuses, verify,
};
