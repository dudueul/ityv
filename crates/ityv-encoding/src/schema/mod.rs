//! Exemplar schemas from the registry in ENCODING.md §6.
//!
//! Each schema is a plain struct with private fields, a parsing constructor,
//! getters, and `Encode`/`Decode` implementations that write fields in the
//! order the specification lists them.

pub mod authorization;
pub mod checkpoint;
pub mod ledger_frame;

use crate::primitives::SchemaId;

/// Schema version used by every schema defined in this crate.
pub const SCHEMA_VERSION_1: u16 = 1;

/// `LedgerFrame` (ENCODING.md §6, `0x0001`).
pub const SCHEMA_LEDGER_FRAME: SchemaId = SchemaId::new(0x0001);

/// `LegalAuthorization` (ENCODING.md §6, `0x0003`).
pub const SCHEMA_LEGAL_AUTHORIZATION: SchemaId = SchemaId::new(0x0003);

/// `CheckpointBody` (ENCODING.md §6, `0x0004`).
pub const SCHEMA_CHECKPOINT_BODY: SchemaId = SchemaId::new(0x0004);
