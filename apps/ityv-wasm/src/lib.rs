//! The verification console's WebAssembly wrapper (outside the TCB,
//! CONSTITUTION.md §0; ADR-0038).
//!
//! It reads a development bundle (`tools/ityv-sim/README.md`, "번들
//! 형식"), runs the real public verifier over it (`verify_genesis`, then
//! `verify_ledger`) and writes what the verifier found as JSON
//! ([`report`]). The browser calls it through a C ABI ([`ffi`]: `alloc`,
//! `dealloc`, `verify_bundle`, `verify_bundle_pinned`, `inclusion`,
//! `fingerprint`, `result_len`), so nothing between the bundle and the
//! verifier runs on a server.
//!
//! Rules (ADR-0038): no dependency but the workspace crates; no status,
//! hold or fingerprint computed here that a TCB crate computes; the only
//! `unsafe` is the FFI module's pointer handling, each block with its
//! SAFETY comment. What this crate does not prove: that the bundle's pin
//! is the published one (the console says so and lets the viewer enter
//! another), or anything the verifier itself does not check yet (audit,
//! split view, connectivity, software; PROTOCOL.md §14 8, 10–12).

pub mod bundle;
#[allow(unsafe_code)]
pub mod ffi;
mod json;
pub mod report;

pub use report::{Proofs, Verification, fingerprint, fingerprint_of, grouped, verify};
