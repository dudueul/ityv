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
    BallotStyleId, BoxId, Bytes, Day, ElectionId, Hash512, IDENT_MAX_STANDARD, Ident, KeysetId,
    LedgerId, ModuleId, ObserverId, OrgId, Point32, ReportingUnitId, RouteId, Scalar32, SchemaId,
    Seq, SignerId, StationId, TimeBucket, Token192, TreeSize, TrusteeId, UnitId,
};
pub use reader::Reader;
pub use schema::attestation::{
    AttestationChallenge, AttestationSummary, ChallengeMessage, ChallengePath, DeviceAttestation,
    DeviceAttestationBody, DeviceAttestationParts, MAX_ATTESTATION_BODY_LEN, MAX_COMPONENTS,
    MAX_DEVICE_CLASS, MAX_DEVICE_ID_LEN, MAX_VERSION_LEN, MeasuredImage, ModuleStatement,
    ModuleStatementMessage, NONCE_LEN, SummaryParts,
};
pub use schema::authorization::{
    LegalAuthorizationBody, MAX_LEGAL_AUTHORIZATION_LEN, MAX_SCOPES, PURPOSE_LEGAL_AUTHORIZATION,
    SCOPE_CODE_MAX, SCOPE_CODE_MIN, Scope, ScopeSet, SignedLegalAuthorization,
};
pub use schema::batch_attest::{
    BatchAttest, BatchAttestBody, BatchAttestParts, MAX_BATCH_BODY_LEN, MAX_BATCH_RECORDS,
    ModuleBatchSig, ModuleRange, record_count_valid,
};
pub use schema::box_close::{
    Attestation, BoxClose, BoxCloseBody, BoxCloseParts, CloseCounts, MAX_ATTESTATIONS,
    MAX_BOX_CLOSE_BODY_LEN, MIN_CLERKS, MIN_OBSERVERS, SignerRole,
};
pub use schema::cast_record::{
    CastRecord, CastRecordBody, CastRecordParts, MAX_CAST_RECORD_BODY_LEN, MAX_OPTION_COUNT,
    MAX_PROOF_LEN, MIN_OPTION_COUNT, ModuleRecordSig, PROOF_SYSTEM_OR_REP_V1, ProofHeader,
    TRANSPORT_FLAGS_MASK, TRANSPORT_KEM_FALLBACK, TRANSPORT_NEUTRAL_MODULE, transport_flags_valid,
};
pub use schema::challenge::{
    ChallengeOpening, ChallengeOpeningBody, ChallengeOpeningParts, MAX_CHALLENGE_BODY_LEN,
    MAX_OPTION_INDEX, ModuleOpening,
};
pub use schema::checkin::{
    BoxUnitSwapBody, BoxUnitSwapParts, CheckinUnitSwapBody, CheckinUnitSwapParts,
    ObserverCountAttestBody, ObserverCountKind, ObserverCountParts,
};
pub use schema::checkpoint::{CheckpointBody, CheckpointParts};
pub use schema::events::{
    BoxOpenedBody, BoxOpenedParts, CustodyHandoffBody, CustodyHandoffParts, DisputeAction,
    DisputeEventBody, DisputeEventParts, DisputeType, EnvelopeIssuance, FallbackBody, FallbackKind,
    FallbackParts, FallbackReason, ImprintAuditBody, ImprintAuditParts, IssuanceCountBody,
    IssuanceCountParts, LateBatchCloseBody, LateBatchCloseParts, LateBatchReason,
    LegalDecisionRefBody, LegalDecisionRefParts, LegalOutcome, MarkerRange, SealChangeBody,
    SealChangeParts, SealChangeReason, TallyEffect,
};
pub use schema::genesis::{
    AMENDABLE_SET_COUNT, BallotStyleEntry, CaptureProfile, CheckinUnit, CustodyRoute,
    ENTRY_SET_COUNT, EntrySet, GenesisBox, GenesisEntry, MAX_OBSERVER_TOKENS, MAX_ROUTE_STOPS,
    MAX_STATION_BOXES, MIN_ROUTE_STOPS, ModuleEntry, ObserverToken, ReportingUnitEntry, RosterRole,
    RosterSigner, StationEntry, StationKind, StationParts, StationProgressPolicy,
    TOKEN_CHECK_KEY_LEN, TrusteeEntry, WitnessRosterEntry, chunks_for,
};
pub use schema::genesis_body::{
    AmendmentReason, ChamberThreshold, GenesisAmendmentBody, GenesisAmendmentParts, GenesisBody,
    GenesisKind, GenesisParts, GenesisWitnessSig, MAX_CHAMBERS, MAX_GENESIS_BODY_LEN,
    MAX_GENESIS_WITNESSES, MAX_PARTIES, MAX_PARTY_NAME_LEN, MIN_DIVERSITY, MIN_PARTIES, MIN_QUORUM,
    MIN_WITNESSES, PURPOSE_GENESIS, PURPOSE_GENESIS_AMENDMENT, PartyEntry, SCHEMA_VERSION_GENESIS,
    SetCommitment, SignedGenesis, WitnessQuorum, expected_chamber,
};
pub use schema::ledger_frame::LedgerFrame;
pub use schema::participation::{
    ActorSig, ActorSigs, COMMITTEE_ACTOR, KEM_EK_LEN, MAX_ACTOR_SIGS, MAX_MEMBER_COUNT,
    MAX_PARTY_MODULES, MAX_PSEUDONYMS, MAX_SHARE_HOLDERS, ModuleProvisioned,
    ModuleProvisionedMessage, ModuleProvisionedParts, PRF_KEY_CHECK_LEN, PSEUDONYM_LEN,
    PURPOSE_MODULE_PROVISIONED, PURPOSE_PARTICIPATION_SET, PURPOSE_PARTY_KEY, ParticipationMessage,
    ParticipationModuleSig, ParticipationSet, PartyKeyCeremony, PartyKeyMessage, PartyKeyParts,
    Pseudonyms, ShareHolder, is_party_chamber,
};
pub use schema::progress::{
    BoxProgressBody, BoxProgressParts, BoxProgressState, CheckinProgressBody, CheckinProgressParts,
    CheckinProgressState, MAX_PROGRESS_BODY_LEN, PURPOSE_BOX_PROGRESS, PURPOSE_CHECKIN_PROGRESS,
    ProgressAlarm, ProgressBody, ProgressCheckBody, ProgressCheckParts, ProgressFinding,
    ProgressTick,
};
pub use schema::scan_count::{
    MAX_OBSERVER_SIGS, MAX_SCAN_COUNT_BODY_LEN, MIN_OBSERVER_SIGS, ObserverSig, ScanCountAttest,
    ScanCountAttestBody,
};
pub use schema::share_package::{
    ChamberCode, MAX_CIPHERTEXT_LEN, MAX_ENTRIES, MAX_SECRETS, MemberShare, ShareEntry,
    SharePackage, Transport, pad_fields_valid, transport_code_valid,
};
pub use schema::slip::{MAX_SLIP_BODY_LEN, MAX_TRACKING_CODES, Slip, SlipBody};
pub use schema::tally::{
    AggregateOpeningBody, AggregateOpeningParts, EXCLUSION_LEN, ExclusionEntry, ExclusionReason,
    Exclusions, MAX_CANDIDATES, MAX_EXCLUSIONS, MAX_QUORUM_BODY_LEN, MAX_QUORUM_MESSAGE_LEN,
    MAX_QUORUM_SIGS, MAX_RECEIPT_ENTRIES, MAX_TALLY_COUNT, PURPOSE_AGGREGATE_OPENING,
    PURPOSE_PAPER_COUNT, PURPOSE_RECEIPT_RESOLUTION, PURPOSE_TALLY_SCOPE, PaperCountParts,
    PaperCountReportBody, PaperVotes, QuorumKind, QuorumSig, QuorumSigned, RECEIPT_ENTRY_LEN,
    ReceiptEntries, ReceiptEntry, ReceiptOutcome, ReceiptResolutionBody, ReceiptResolutionParts,
    TallyScopeBody, TallyScopeParts, write_quorum_message,
};
pub use schema::util::{
    Commitments, ED25519_SIG_LEN, HYBRID_SIG_LEN, HYBRID_VK_LEN, MAX_CHUNKS, MAX_MODULES,
    MLDSA87_VK_HALF, ModuleCounter, ModuleCounters, ModuleIds, Scalars, TAG_LEN, keys_share_half,
};
pub use schema::witnessed::{
    EventRole, EventSig, MAX_EVENT_SIGS, MAX_WITNESSED_BODY_LEN, MIN_EVENT_CLERKS,
    MIN_EVENT_OBSERVER_ORGS, WITNESSED_BODY_SCHEMAS, WitnessedEvent, purpose_of, roles_satisfied,
};
pub use schema::{
    SCHEMA_AGGREGATE_OPENING_BODY, SCHEMA_ATTESTATION_SUMMARY, SCHEMA_BALLOT_STYLE_ENTRY,
    SCHEMA_BATCH_ATTEST, SCHEMA_BATCH_ATTEST_BODY, SCHEMA_BOX_CLOSE, SCHEMA_BOX_CLOSE_BODY,
    SCHEMA_BOX_OPENED_BODY, SCHEMA_BOX_PROGRESS_BODY, SCHEMA_BOX_UNIT_SWAP_BODY,
    SCHEMA_CAST_RECORD, SCHEMA_CAST_RECORD_BODY, SCHEMA_CHALLENGE_OPENING,
    SCHEMA_CHALLENGE_OPENING_BODY, SCHEMA_CHECKIN_PROGRESS_BODY, SCHEMA_CHECKIN_UNIT_SWAP_BODY,
    SCHEMA_CHECKPOINT_BODY, SCHEMA_CUSTODY_HANDOFF_BODY, SCHEMA_CUSTODY_ROUTE,
    SCHEMA_DEVICE_ATTESTATION, SCHEMA_DEVICE_ATTESTATION_BODY, SCHEMA_DISPUTE_EVENT_BODY,
    SCHEMA_FALLBACK_BODY, SCHEMA_GENESIS_AMENDMENT_BODY, SCHEMA_GENESIS_BODY, SCHEMA_GENESIS_BOX,
    SCHEMA_IMPRINT_AUDIT_BODY, SCHEMA_ISSUANCE_COUNT_BODY, SCHEMA_LATE_BATCH_CLOSE_BODY,
    SCHEMA_LEDGER_FRAME, SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_LEGAL_DECISION_REF_BODY,
    SCHEMA_MEMBER_SHARE, SCHEMA_MODULE_ENTRY, SCHEMA_MODULE_PROVISIONED,
    SCHEMA_OBSERVER_COUNT_ATTEST_BODY, SCHEMA_PAPER_COUNT_REPORT_BODY, SCHEMA_PARTICIPATION_SET,
    SCHEMA_PARTY_KEY_CEREMONY, SCHEMA_PROGRESS_CHECK_BODY, SCHEMA_PROGRESS_TICK,
    SCHEMA_QUORUM_SIGNED, SCHEMA_RECEIPT_RESOLUTION_BODY, SCHEMA_REPORTING_UNIT_ENTRY,
    SCHEMA_ROSTER_SIGNER, SCHEMA_SCAN_COUNT_ATTEST, SCHEMA_SCAN_COUNT_ATTEST_BODY,
    SCHEMA_SEAL_CHANGE_BODY, SCHEMA_SHARE_PACKAGE, SCHEMA_SIGNED_GENESIS,
    SCHEMA_SIGNED_LEGAL_AUTHORIZATION, SCHEMA_SLIP, SCHEMA_SLIP_BODY, SCHEMA_STATION_ENTRY,
    SCHEMA_STATION_PROGRESS_POLICY, SCHEMA_TALLY_SCOPE_BODY, SCHEMA_TRUSTEE_ENTRY,
    SCHEMA_VERSION_1, SCHEMA_VERSION_REPORTING_UNIT, SCHEMA_VERSION_ROSTER_SIGNER,
    SCHEMA_VERSION_WITNESSED, SCHEMA_WITNESS_ROSTER_ENTRY, SCHEMA_WITNESSED_EVENT, schema_version,
};
pub use writer::Writer;
