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
    LedgerId, ModuleId, ObserverId, OrgId, Point32, RouteId, Scalar32, SchemaId, Seq, SignerId,
    StationId, TimeBucket, Token192, TreeSize, TrusteeId, UnitId,
};
pub use reader::Reader;
pub use schema::attestation::{
    AttestationChallenge, AttestationSummary, ChallengeMessage, ChallengePath, DeviceAttestation,
    DeviceAttestationBody, DeviceAttestationParts, MAX_ATTESTATION_BODY_LEN, MAX_COMPONENTS,
    MAX_DEVICE_CLASS, MAX_DEVICE_ID_LEN, MAX_VERSION_LEN, MeasuredImage, ModuleStatement,
    ModuleStatementMessage, NONCE_LEN, SummaryParts,
};
pub use schema::authorization::{
    LegalAuthorizationBody, MAX_SCOPES, SCOPE_CODE_MAX, SCOPE_CODE_MIN, Scope, ScopeSet,
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
    CaptureProfile, CustodyRoute, GenesisBox, MAX_ROUTE_STOPS, MIN_ROUTE_STOPS, RosterRole,
    RosterSigner, StationProgressPolicy,
};
pub use schema::ledger_frame::LedgerFrame;
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
pub use schema::util::{
    Commitments, ED25519_SIG_LEN, HYBRID_SIG_LEN, HYBRID_VK_LEN, MAX_CHUNKS, MAX_MODULES,
    ModuleCounter, ModuleCounters, ModuleIds, Scalars, TAG_LEN,
};
pub use schema::witnessed::{
    EventRole, EventSig, MAX_EVENT_SIGS, MAX_WITNESSED_BODY_LEN, MIN_EVENT_CLERKS,
    MIN_EVENT_OBSERVER_ORGS, WITNESSED_BODY_SCHEMAS, WitnessedEvent, purpose_of, roles_satisfied,
};
pub use schema::{
    SCHEMA_ATTESTATION_SUMMARY, SCHEMA_BATCH_ATTEST, SCHEMA_BATCH_ATTEST_BODY, SCHEMA_BOX_CLOSE,
    SCHEMA_BOX_CLOSE_BODY, SCHEMA_BOX_OPENED_BODY, SCHEMA_BOX_PROGRESS_BODY, SCHEMA_CAST_RECORD,
    SCHEMA_CAST_RECORD_BODY, SCHEMA_CHALLENGE_OPENING, SCHEMA_CHALLENGE_OPENING_BODY,
    SCHEMA_CHECKIN_PROGRESS_BODY, SCHEMA_CHECKPOINT_BODY, SCHEMA_CUSTODY_HANDOFF_BODY,
    SCHEMA_DEVICE_ATTESTATION, SCHEMA_DEVICE_ATTESTATION_BODY, SCHEMA_DISPUTE_EVENT_BODY,
    SCHEMA_FALLBACK_BODY, SCHEMA_IMPRINT_AUDIT_BODY, SCHEMA_ISSUANCE_COUNT_BODY,
    SCHEMA_LATE_BATCH_CLOSE_BODY, SCHEMA_LEDGER_FRAME, SCHEMA_LEGAL_AUTHORIZATION,
    SCHEMA_LEGAL_DECISION_REF_BODY, SCHEMA_MEMBER_SHARE, SCHEMA_PROGRESS_CHECK_BODY,
    SCHEMA_PROGRESS_TICK, SCHEMA_SCAN_COUNT_ATTEST, SCHEMA_SCAN_COUNT_ATTEST_BODY,
    SCHEMA_SEAL_CHANGE_BODY, SCHEMA_SHARE_PACKAGE, SCHEMA_SLIP, SCHEMA_SLIP_BODY, SCHEMA_VERSION_1,
    SCHEMA_WITNESSED_EVENT,
};
pub use writer::Writer;
