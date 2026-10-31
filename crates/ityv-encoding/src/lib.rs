//! Canonical fixed-width binary encoding for ityv.
//!
//! This crate is the single implementation of `docs/spec/ENCODING.md`. Every
//! object that ityv hashes or signs has exactly one byte representation, and
//! every non-canonical byte string is rejected at the first offending offset.
//!
//! Properties that hold by construction:
//!
//! * `#![no_std]`, no heap allocation, no `unsafe`, no panics (enforced by
//!   the workspace lint set and checked by Kani harnesses under `cfg(kani)`).
//! * Decoding is non-recursive: nesting depth is fixed by the schema.
//! * `decode(encode(x)) == x` for every value `x`, and
//!   `encode(decode(b)) == b` for every canonical byte string `b`.
//!
//! What this crate does **not** prove: that the content of an object is true,
//! that a signature over it is valid, or that a scalar or point is a valid
//! group element. Scalar and point newtypes are checked for length only; the
//! cryptographic crate validates their algebraic form.
//!
//! The public API is re-exported at the crate root; the module structure is an
//! implementation detail.
#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod codec;
pub mod envelope;
pub mod error;
pub mod primitives;
pub mod reader;
pub mod schema;
pub mod writer;

// Kani harnesses live outside `src/` because they carry a file-level lint
// relaxation, which CONSTITUTION.md §1.1 forbids under `src/`.
#[cfg(kani)]
#[path = "../kani/proofs.rs"]
mod proofs;

pub use codec::{Decode, Encode, encode_slice, encoded_len_of_slice};
pub use envelope::{
    HEADER_LEN, Header as ObjectHeader, MAGIC, decode as decode_object, encode as encode_object,
};
pub use error::{Error, Kind as ErrorKind};
pub use primitives::{
    Bytes, Day, ElectionId, Hash512, IDENT_MAX_STANDARD, Ident, KeysetId, LedgerId, Point32,
    Scalar32, SchemaId, Seq, TimeBucket, Token192, TreeSize,
};
pub use reader::Reader;
pub use schema::authorization::{
    LegalAuthorizationBody, MAX_SCOPES, SCOPE_CODE_MAX, SCOPE_CODE_MIN, Scope, ScopeSet,
};
pub use schema::checkpoint::{CheckpointBody, CheckpointParts};
pub use schema::ledger_frame::LedgerFrame;
pub use schema::{
    SCHEMA_CHECKPOINT_BODY, SCHEMA_LEDGER_FRAME, SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1,
};
pub use writer::Writer;
