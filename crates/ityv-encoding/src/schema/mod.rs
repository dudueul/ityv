//! Schemas from the registry in ENCODING.md §6.
//!
//! Each schema is a plain struct with private fields, a parsing constructor,
//! getters, and `Encode`/`Decode` implementations that write fields in the
//! order the specification lists them. Self-signed events are two objects:
//! a body and a wrapper that embeds the complete body object bytes next to
//! the signatures, so the signed message is exactly the body bytes
//! (ADR-0017 §2).

pub mod attestation;
pub mod audit;
pub mod authorization;
pub mod batch_attest;
pub mod box_close;
pub mod cast_record;
pub mod challenge;
pub mod checkin;
pub mod checkpoint;
pub mod events;
pub mod genesis;
pub mod genesis_body;
pub mod ledger_frame;
pub mod participation;
pub mod progress;
pub mod scan_count;
pub mod share_package;
pub mod slip;
pub mod tally;
pub mod util;
pub mod witnessed;

use crate::primitives::SchemaId;

/// Schema version 1, the version of every schema [`schema_version`] does
/// not name.
pub const SCHEMA_VERSION_1: u16 = 1;

/// The current version of `WitnessedEvent` (`0x0028`): version 3 admits
/// the event role 10, the auditor, and the audit bodies `0x000D`,
/// `0x0048`, `0x004B`, `0x004C`, `0x004D`, `0x004E` (ADR-0036). Version 2 admitted
/// the event role 9, the district commission chair (ADR-0035); version 1
/// neither.
pub const SCHEMA_VERSION_WITNESSED: u16 = 3;

/// The current version of `RosterSigner` (`0x003A`): version 3 admits the
/// roster role 6, the auditor (ADR-0036). Version 2 admitted the roster
/// role 5, the district commission chair (ADR-0035).
pub const SCHEMA_VERSION_ROSTER_SIGNER: u16 = 3;

/// The current version of `ReportingUnitEntry` (`0x0038`): version 2
/// adds the commission that reports the unit's paper count (ADR-0035).
pub const SCHEMA_VERSION_REPORTING_UNIT: u16 = 2;

/// The current version of `QuorumSigned` (`0x0045`): version 2 admits the
/// sample opening reference `0x004A` as a body (ADR-0036).
pub const SCHEMA_VERSION_QUORUM_SIGNED: u16 = 2;

/// The current version of schema `schema`, the only one this crate
/// encodes and decodes (ENCODING.md §3: a change of shape takes a new
/// version, and a version number is never reused for another shape).
#[must_use]
pub const fn schema_version(schema: SchemaId) -> u16 {
    match schema.get() {
        0x0002 => genesis_body::SCHEMA_VERSION_GENESIS,
        0x0028 => SCHEMA_VERSION_WITNESSED,
        0x0038 => SCHEMA_VERSION_REPORTING_UNIT,
        0x003A => SCHEMA_VERSION_ROSTER_SIGNER,
        0x0045 => SCHEMA_VERSION_QUORUM_SIGNED,
        _ => SCHEMA_VERSION_1,
    }
}

/// `LedgerFrame` (ENCODING.md §6, `0x0001`).
pub const SCHEMA_LEDGER_FRAME: SchemaId = SchemaId::new(0x0001);

/// `GenesisBody` (ENCODING.md §8.54, `0x0002`, version 6).
pub const SCHEMA_GENESIS_BODY: SchemaId = SchemaId::new(0x0002);

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

/// `AuditSeedBody` (ENCODING.md §8.67, `0x000D`).
pub const SCHEMA_AUDIT_SEED_BODY: SchemaId = SchemaId::new(0x000D);

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

/// `ParticipationSet` (ENCODING.md §8.25).
pub const SCHEMA_PARTICIPATION_SET: SchemaId = SchemaId::new(0x0020);

/// `DeviceAttestationBody` (ENCODING.md §8.28, `0x0023`).
pub const SCHEMA_DEVICE_ATTESTATION_BODY: SchemaId = SchemaId::new(0x0023);

/// `DeviceAttestation` (ENCODING.md §8.29, `0x0024`).
pub const SCHEMA_DEVICE_ATTESTATION: SchemaId = SchemaId::new(0x0024);

/// `AttestationSummary` (ENCODING.md §8.30, `0x0025`).
pub const SCHEMA_ATTESTATION_SUMMARY: SchemaId = SchemaId::new(0x0025);

/// `ModuleProvisioned` (ENCODING.md §8.31).
pub const SCHEMA_MODULE_PROVISIONED: SchemaId = SchemaId::new(0x0026);

/// `PartyKeyCeremony` (ENCODING.md §8.32).
pub const SCHEMA_PARTY_KEY_CEREMONY: SchemaId = SchemaId::new(0x0027);

/// `CustodyHandoffBody` (ENCODING.md §6, `0x0008`).
pub const SCHEMA_CUSTODY_HANDOFF_BODY: SchemaId = SchemaId::new(0x0008);

/// `DisputeEventBody` (ENCODING.md §6, `0x000E`).
pub const SCHEMA_DISPUTE_EVENT_BODY: SchemaId = SchemaId::new(0x000E);

/// `LegalDecisionRefBody` (ENCODING.md §6, `0x000F`).
pub const SCHEMA_LEGAL_DECISION_REF_BODY: SchemaId = SchemaId::new(0x000F);

/// `WitnessedEvent` (ENCODING.md §6, `0x0028`).
pub const SCHEMA_WITNESSED_EVENT: SchemaId = SchemaId::new(0x0028);

/// `BoxOpenedBody` (ENCODING.md §6, `0x0029`).
pub const SCHEMA_BOX_OPENED_BODY: SchemaId = SchemaId::new(0x0029);

/// `FallbackBody` (ENCODING.md §6, `0x002A`).
pub const SCHEMA_FALLBACK_BODY: SchemaId = SchemaId::new(0x002A);

/// `IssuanceCountBody` (ENCODING.md §6, `0x002B`).
pub const SCHEMA_ISSUANCE_COUNT_BODY: SchemaId = SchemaId::new(0x002B);

/// `ImprintAuditBody` (ENCODING.md §6, `0x002C`).
pub const SCHEMA_IMPRINT_AUDIT_BODY: SchemaId = SchemaId::new(0x002C);

/// `SealChangeBody` (ENCODING.md §6, `0x002D`).
pub const SCHEMA_SEAL_CHANGE_BODY: SchemaId = SchemaId::new(0x002D);

/// `LateBatchCloseBody` (ENCODING.md §6, `0x002E`).
pub const SCHEMA_LATE_BATCH_CLOSE_BODY: SchemaId = SchemaId::new(0x002E);

/// `BoxProgressBody` (ENCODING.md §8.44, `0x002F`).
pub const SCHEMA_BOX_PROGRESS_BODY: SchemaId = SchemaId::new(0x002F);

/// `CheckinProgressBody` (ENCODING.md §8.45, `0x0030`).
pub const SCHEMA_CHECKIN_PROGRESS_BODY: SchemaId = SchemaId::new(0x0030);

/// `ProgressTick` (ENCODING.md §8.46, `0x0031`).
pub const SCHEMA_PROGRESS_TICK: SchemaId = SchemaId::new(0x0031);

/// `ProgressCheckBody` (ENCODING.md §8.47, `0x0032`).
pub const SCHEMA_PROGRESS_CHECK_BODY: SchemaId = SchemaId::new(0x0032);

/// `SignedGenesis` (ENCODING.md §8.56, `0x0033`).
pub const SCHEMA_SIGNED_GENESIS: SchemaId = SchemaId::new(0x0033);

/// `GenesisAmendmentBody` (ENCODING.md §8.55, `0x0034`).
pub const SCHEMA_GENESIS_AMENDMENT_BODY: SchemaId = SchemaId::new(0x0034);

/// `GenesisBox` (ENCODING.md §8.43, `0x0035`).
pub const SCHEMA_GENESIS_BOX: SchemaId = SchemaId::new(0x0035);

/// `StationEntry` (ENCODING.md §8.49, `0x0036`).
pub const SCHEMA_STATION_ENTRY: SchemaId = SchemaId::new(0x0036);

/// `StationProgressPolicy` (ENCODING.md §8.48, `0x0037`).
pub const SCHEMA_STATION_PROGRESS_POLICY: SchemaId = SchemaId::new(0x0037);

/// `ReportingUnitEntry` (ENCODING.md §8.50, `0x0038`).
pub const SCHEMA_REPORTING_UNIT_ENTRY: SchemaId = SchemaId::new(0x0038);

/// `CustodyRoute` (ENCODING.md §8.43, `0x0039`).
pub const SCHEMA_CUSTODY_ROUTE: SchemaId = SchemaId::new(0x0039);

/// `RosterSigner` (ENCODING.md §8.43, `0x003A`).
pub const SCHEMA_ROSTER_SIGNER: SchemaId = SchemaId::new(0x003A);

/// `ModuleEntry` (ENCODING.md §8.51, `0x003B`).
pub const SCHEMA_MODULE_ENTRY: SchemaId = SchemaId::new(0x003B);

/// `BallotStyleEntry` (ENCODING.md §8.52, `0x003C`).
pub const SCHEMA_BALLOT_STYLE_ENTRY: SchemaId = SchemaId::new(0x003C);

/// `TrusteeEntry` (ENCODING.md §8.53, `0x003D`).
pub const SCHEMA_TRUSTEE_ENTRY: SchemaId = SchemaId::new(0x003D);

/// `WitnessRosterEntry` (ENCODING.md §8.53, `0x003E`).
pub const SCHEMA_WITNESS_ROSTER_ENTRY: SchemaId = SchemaId::new(0x003E);

/// `ObserverCountAttestBody` (ENCODING.md §8.57, `0x003F`).
pub const SCHEMA_OBSERVER_COUNT_ATTEST_BODY: SchemaId = SchemaId::new(0x003F);

/// `CheckinUnitSwapBody` (ENCODING.md §8.58, `0x0040`).
pub const SCHEMA_CHECKIN_UNIT_SWAP_BODY: SchemaId = SchemaId::new(0x0040);

/// `BoxUnitSwapBody` (ENCODING.md §8.59, `0x0041`).
pub const SCHEMA_BOX_UNIT_SWAP_BODY: SchemaId = SchemaId::new(0x0041);

/// `SignedLegalAuthorization` (ENCODING.md §8.60, `0x0042`).
pub const SCHEMA_SIGNED_LEGAL_AUTHORIZATION: SchemaId = SchemaId::new(0x0042);

/// `TallyScopeBody` (ENCODING.md §8.61, `0x0043`).
pub const SCHEMA_TALLY_SCOPE_BODY: SchemaId = SchemaId::new(0x0043);

/// `AggregateOpeningBody` (ENCODING.md §8.62, `0x0044`).
pub const SCHEMA_AGGREGATE_OPENING_BODY: SchemaId = SchemaId::new(0x0044);

/// `QuorumSigned` (ENCODING.md §8.63, `0x0045`).
pub const SCHEMA_QUORUM_SIGNED: SchemaId = SchemaId::new(0x0045);

/// `PaperCountReportBody` (ENCODING.md §8.64, `0x0046`).
pub const SCHEMA_PAPER_COUNT_REPORT_BODY: SchemaId = SchemaId::new(0x0046);

/// `ReceiptResolutionBody` (ENCODING.md §8.65, `0x0047`).
pub const SCHEMA_RECEIPT_RESOLUTION_BODY: SchemaId = SchemaId::new(0x0047);

/// `AuditManifestFreezeBody` (ENCODING.md §8.66, `0x0048`).
pub const SCHEMA_AUDIT_FREEZE_BODY: SchemaId = SchemaId::new(0x0048);

/// `SampleOpeningBody` (ENCODING.md §8.68, `0x0049`): restricted, never a
/// ledger event.
pub const SCHEMA_SAMPLE_OPENING_BODY: SchemaId = SchemaId::new(0x0049);

/// `SampleOpeningRefBody` (ENCODING.md §8.69, `0x004A`).
pub const SCHEMA_SAMPLE_OPENING_REF_BODY: SchemaId = SchemaId::new(0x004A);

/// `SampleComparisonBody` (ENCODING.md §8.70, `0x004B`).
pub const SCHEMA_SAMPLE_COMPARISON_BODY: SchemaId = SchemaId::new(0x004B);

/// `AuditFindingBody` (ENCODING.md §8.71, `0x004C`).
pub const SCHEMA_AUDIT_FINDING_BODY: SchemaId = SchemaId::new(0x004C);

/// `HandCountReportBody` (ENCODING.md §8.72, `0x004D`).
pub const SCHEMA_HAND_COUNT_REPORT_BODY: SchemaId = SchemaId::new(0x004D);

/// `AuditCommitBody` (ENCODING.md §8.73, `0x004E`).
pub const SCHEMA_AUDIT_COMMIT_BODY: SchemaId = SchemaId::new(0x004E);
