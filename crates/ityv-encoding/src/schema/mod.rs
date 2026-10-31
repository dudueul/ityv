//! Schemas from the registry in ENCODING.md §6.
//!
//! Each schema is a plain struct with private fields, a parsing constructor,
//! getters, and `Encode`/`Decode` implementations that write fields in the
//! order the specification lists them. Self-signed events are two objects:
//! a body and a wrapper that embeds the complete body object bytes next to
//! the signatures, so the signed message is exactly the body bytes
//! (ADR-0017 §2).

pub mod authorization;
pub mod batch_attest;
pub mod box_close;
pub mod cast_record;
pub mod challenge;
pub mod checkpoint;
pub mod ledger_frame;
pub mod scan_count;
pub mod share_package;
pub mod slip;
pub mod util;

use crate::primitives::SchemaId;

/// Schema version used by every schema defined in this crate.
pub const SCHEMA_VERSION_1: u16 = 1;

/// `LedgerFrame` (ENCODING.md §6, `0x0001`).
pub const SCHEMA_LEDGER_FRAME: SchemaId = SchemaId::new(0x0001);

/// `LegalAuthorization` (ENCODING.md §6, `0x0003`).
pub const SCHEMA_LEGAL_AUTHORIZATION: SchemaId = SchemaId::new(0x0003);

/// `CheckpointBody` (ENCODING.md §6, `0x0004`).
pub const SCHEMA_CHECKPOINT_BODY: SchemaId = SchemaId::new(0x0004);

/// `CastRecordBody` (ENCODING.md §8.6, `0x0005`).
pub const SCHEMA_CAST_RECORD_BODY: SchemaId = SchemaId::new(0x0005);

/// `ChallengeOpeningBody` (ENCODING.md §8.8, `0x0006`).
pub const SCHEMA_CHALLENGE_OPENING_BODY: SchemaId = SchemaId::new(0x0006);

/// `BoxCloseBody` (ENCODING.md §8.16, `0x0007`).
pub const SCHEMA_BOX_CLOSE_BODY: SchemaId = SchemaId::new(0x0007);

/// `Slip` (ENCODING.md §8.18, `0x000A`).
pub const SCHEMA_SLIP: SchemaId = SchemaId::new(0x000A);

/// `SharePackage` (ENCODING.md §8.10, `0x000B`).
pub const SCHEMA_SHARE_PACKAGE: SchemaId = SchemaId::new(0x000B);

/// `BatchAttestBody` (ENCODING.md §8.12, `0x0012`).
pub const SCHEMA_BATCH_ATTEST_BODY: SchemaId = SchemaId::new(0x0012);

/// `ScanCountAttestBody` (ENCODING.md §8.14, `0x0013`).
pub const SCHEMA_SCAN_COUNT_ATTEST_BODY: SchemaId = SchemaId::new(0x0013);

/// `MemberShare` (ENCODING.md §8.11, `0x0015`).
pub const SCHEMA_MEMBER_SHARE: SchemaId = SchemaId::new(0x0015);

/// `CastRecord` (ENCODING.md §8.7, `0x0016`).
pub const SCHEMA_CAST_RECORD: SchemaId = SchemaId::new(0x0016);

/// `BatchAttest` (ENCODING.md §8.13, `0x0017`).
pub const SCHEMA_BATCH_ATTEST: SchemaId = SchemaId::new(0x0017);

/// `ChallengeOpening` (ENCODING.md §8.9, `0x0018`).
pub const SCHEMA_CHALLENGE_OPENING: SchemaId = SchemaId::new(0x0018);

/// `SlipBody` (ENCODING.md §8.18, `0x0019`).
pub const SCHEMA_SLIP_BODY: SchemaId = SchemaId::new(0x0019);

/// `BoxClose` (ENCODING.md §8.17, `0x001A`).
pub const SCHEMA_BOX_CLOSE: SchemaId = SchemaId::new(0x001A);

/// `ScanCountAttest` (ENCODING.md §8.15, `0x001B`).
pub const SCHEMA_SCAN_COUNT_ATTEST: SchemaId = SchemaId::new(0x001B);
