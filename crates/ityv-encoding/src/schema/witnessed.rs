//! `WitnessedEvent` (schema `0x0028`), version 3: one human-signed ledger
//! event, the body object bytes with the signatures of the people the
//! event names (ENCODING.md §8.42). Version 2 added the district
//! commission chair (role 9) and the paper count (ADR-0035); version 3 the
//! auditor (role 10) and the audit bodies (ADR-0036).
//!
//! Field order: `body`, `sigs`. The body is a complete object of one of
//! the schemas in [`WITNESSED_BODY_SCHEMAS`]; each signature is a hybrid
//! signature over exactly the body bytes with the body's purpose
//! ([`purpose_of`]). Which roles must sign depends on the body
//! ([`roles_satisfied`]); the decoder enforces the role set, the signature
//! bytes are verified by `ityv-crypto` and bound to registered keys by
//! `ityv-state`.

use crate::codec::{Decode, Encode};
use crate::envelope::{Header, decode as decode_object};
use crate::error::{Error, Kind};
use crate::primitives::{OrgId, SchemaId, SignerId};
use crate::reader::Reader;
use crate::schema::audit::{
    AuditFindingBody, AuditManifestFreezeBody, AuditSeedBody, HandCountReportBody,
    SampleComparisonBody,
};
use crate::schema::checkin::{BoxUnitSwapBody, CheckinUnitSwapBody, ObserverCountAttestBody};
use crate::schema::events::{
    BoxOpenedBody, CustodyHandoffBody, DisputeEventBody, FallbackBody, ImprintAuditBody,
    IssuanceCountBody, LateBatchCloseBody, LegalDecisionRefBody, SealChangeBody,
};
use crate::schema::progress::ProgressCheckBody;
use crate::schema::tally::PaperCountReportBody;
use crate::schema::util::{HYBRID_SIG_LEN, ascending_by, read_fixed};
use crate::schema::{
    SCHEMA_AUDIT_FINDING_BODY, SCHEMA_AUDIT_FREEZE_BODY, SCHEMA_AUDIT_SEED_BODY,
    SCHEMA_BOX_OPENED_BODY, SCHEMA_BOX_UNIT_SWAP_BODY, SCHEMA_CHECKIN_UNIT_SWAP_BODY,
    SCHEMA_CUSTODY_HANDOFF_BODY, SCHEMA_DISPUTE_EVENT_BODY, SCHEMA_FALLBACK_BODY,
    SCHEMA_HAND_COUNT_REPORT_BODY, SCHEMA_IMPRINT_AUDIT_BODY, SCHEMA_ISSUANCE_COUNT_BODY,
    SCHEMA_LATE_BATCH_CLOSE_BODY, SCHEMA_LEGAL_DECISION_REF_BODY,
    SCHEMA_OBSERVER_COUNT_ATTEST_BODY, SCHEMA_PAPER_COUNT_REPORT_BODY, SCHEMA_PROGRESS_CHECK_BODY,
    SCHEMA_SAMPLE_COMPARISON_BODY, SCHEMA_SEAL_CHANGE_BODY, SCHEMA_VERSION_1,
};
use crate::writer::Writer;

/// Maximum length of the embedded body object bytes.
pub const MAX_WITNESSED_BODY_LEN: usize = 2048;

/// Maximum number of signatures on one event.
pub const MAX_EVENT_SIGS: usize = 8;

/// Clerks a clerk-and-observer event needs.
pub const MIN_EVENT_CLERKS: usize = 2;

/// Observer organisations a clerk-and-observer event needs.
pub const MIN_EVENT_OBSERVER_ORGS: usize = 2;

/// Auditor organisations an audit comparison or finding needs.
pub const MIN_EVENT_AUDITOR_ORGS: usize = 2;

/// The body schemas a `WitnessedEvent` may carry.
pub const WITNESSED_BODY_SCHEMAS: [SchemaId; 19] = [
    SCHEMA_CUSTODY_HANDOFF_BODY,
    SCHEMA_DISPUTE_EVENT_BODY,
    SCHEMA_LEGAL_DECISION_REF_BODY,
    SCHEMA_BOX_OPENED_BODY,
    SCHEMA_FALLBACK_BODY,
    SCHEMA_ISSUANCE_COUNT_BODY,
    SCHEMA_IMPRINT_AUDIT_BODY,
    SCHEMA_SEAL_CHANGE_BODY,
    SCHEMA_LATE_BATCH_CLOSE_BODY,
    SCHEMA_PROGRESS_CHECK_BODY,
    SCHEMA_OBSERVER_COUNT_ATTEST_BODY,
    SCHEMA_CHECKIN_UNIT_SWAP_BODY,
    SCHEMA_BOX_UNIT_SWAP_BODY,
    SCHEMA_PAPER_COUNT_REPORT_BODY,
    SCHEMA_AUDIT_SEED_BODY,
    SCHEMA_AUDIT_FREEZE_BODY,
    SCHEMA_SAMPLE_COMPARISON_BODY,
    SCHEMA_AUDIT_FINDING_BODY,
    SCHEMA_HAND_COUNT_REPORT_BODY,
];

/// The signature purpose of a body schema (PROTOCOL.md Appendix B), or
/// `None` for a schema a `WitnessedEvent` does not carry.
#[must_use]
pub fn purpose_of(schema: SchemaId) -> Option<&'static [u8]> {
    let purpose: &'static [u8] = match schema.get() {
        0x0008 => b"handoff",
        0x000E => b"dispute",
        0x000F => b"legal-decision",
        0x0029 => b"box-open",
        0x002A => b"fallback",
        0x002B => b"issuance-count",
        0x002C => b"imprint-audit",
        0x002D => b"seal-change",
        0x002E => b"late-batch-close",
        0x0032 => b"progress-check",
        0x003F => b"observer-count",
        0x0040 => b"checkin-swap",
        0x0041 => b"box-swap",
        0x0046 => b"paper-count",
        0x000D => b"audit-seed",
        0x0048 => b"audit-freeze",
        0x004B => b"sample-comparison",
        0x004C => b"audit-finding",
        0x004D => b"hand-count",
        _ => return None,
    };
    Some(purpose)
}

/// The role in which a person or device signs an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EventRole {
    /// A polling or counting clerk.
    Clerk = 1,
    /// An observer.
    Observer = 2,
    /// The election commission (선관위).
    Commission = 3,
    /// The Independent Verification Committee (독립검증위원회).
    Committee = 4,
    /// The sender of a custody handoff.
    Sender = 5,
    /// The receiver of a custody handoff.
    Receiver = 6,
    /// A legal authority (court or other body empowered by law).
    Authority = 7,
    /// The ballot box's commitment unit.
    Device = 8,
    /// The chair of a district election commission (구·시·군 선관위
    /// 위원장), who reports the paper count of a reporting unit.
    Chair = 9,
    /// An auditor who compares a sampled record with its paper (version
    /// 3, ADR-0036).
    Auditor = 10,
}

impl EventRole {
    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Returns the role with wire code `code`, if defined.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Clerk),
            2 => Some(Self::Observer),
            3 => Some(Self::Commission),
            4 => Some(Self::Committee),
            5 => Some(Self::Sender),
            6 => Some(Self::Receiver),
            7 => Some(Self::Authority),
            8 => Some(Self::Device),
            9 => Some(Self::Chair),
            10 => Some(Self::Auditor),
            _ => None,
        }
    }
}

/// One signature on a witnessed event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventSig<'a> {
    /// The signer (the device identifier for [`EventRole::Device`]).
    pub signer_id: SignerId<'a>,
    /// The role.
    pub role: EventRole,
    /// The signer's organisation.
    pub org_id: OrgId<'a>,
    /// The hybrid signature over the body bytes.
    pub sig: &'a [u8; HYBRID_SIG_LEN],
}

fn count_role<'a>(sigs: impl Iterator<Item = EventSig<'a>>, role: EventRole) -> usize {
    sigs.filter(|s| s.role == role).count()
}

fn clerks_and_observers<'a, F, I>(sigs: F, extra: Option<EventRole>) -> bool
where
    F: Fn() -> I,
    I: Iterator<Item = EventSig<'a>>,
{
    let mut orgs: [Option<&[u8]>; MAX_EVENT_SIGS] = [None; MAX_EVENT_SIGS];
    let mut distinct = 0usize;
    for s in sigs() {
        match s.role {
            EventRole::Clerk => {}
            EventRole::Observer => {
                let org = s.org_id.as_bytes();
                let seen = orgs.iter().take(distinct).flatten().any(|o| *o == org);
                if !seen {
                    if let Some(slot) = orgs.get_mut(distinct) {
                        *slot = Some(org);
                    }
                    distinct = distinct.saturating_add(1);
                }
            }
            role @ (EventRole::Commission
            | EventRole::Committee
            | EventRole::Sender
            | EventRole::Receiver
            | EventRole::Authority
            | EventRole::Device
            | EventRole::Chair
            | EventRole::Auditor) => {
                if Some(role) != extra {
                    return false;
                }
            }
        }
    }
    let extra_ok = extra.is_none_or(|role| count_role(sigs(), role) == 1);
    count_role(sigs(), EventRole::Clerk) >= MIN_EVENT_CLERKS
        && distinct >= MIN_EVENT_OBSERVER_ORGS
        && extra_ok
}

/// Observers of two or more organisations and, when `extra` is given,
/// exactly one signer in that role, nothing else (`ObserverCountAttest`
/// without, `PaperCountReport` and `HandCountReport` with the chair,
/// `AuditManifestFreeze` and `AuditSeed` with the committee; VC-016,
/// VC-075).
fn observers_with<'a, F, I>(sigs: F, extra: Option<EventRole>) -> bool
where
    F: Fn() -> I,
    I: Iterator<Item = EventSig<'a>>,
{
    let mut orgs: [Option<&[u8]>; MAX_EVENT_SIGS] = [None; MAX_EVENT_SIGS];
    let mut distinct = 0usize;
    for s in sigs() {
        if s.role != EventRole::Observer {
            if Some(s.role) == extra {
                continue;
            }
            return false;
        }
        let org = s.org_id.as_bytes();
        if !orgs.iter().take(distinct).flatten().any(|o| *o == org) {
            if let Some(slot) = orgs.get_mut(distinct) {
                *slot = Some(org);
            }
            distinct = distinct.saturating_add(1);
        }
    }
    let extra_ok = extra.is_none_or(|role| count_role(sigs(), role) == 1);
    distinct >= MIN_EVENT_OBSERVER_ORGS && extra_ok
}

/// Adds the organisation of `s` to the first `*distinct` slots of `orgs`
/// unless it is there.
fn note_org<'a>(
    orgs: &mut [Option<&'a [u8]>; MAX_EVENT_SIGS],
    distinct: &mut usize,
    org: &'a [u8],
) {
    if !orgs.iter().take(*distinct).flatten().any(|o| *o == org) {
        if let Some(slot) = orgs.get_mut(*distinct) {
            *slot = Some(org);
        }
        *distinct = distinct.saturating_add(1);
    }
}

/// Auditors of two or more organisations and observers of two or more
/// organisations, nothing else (`SampleComparison`, `AuditFinding`;
/// PROTOCOL.md §12.3).
fn auditors_and_observers<'a, F, I>(sigs: F) -> bool
where
    F: Fn() -> I,
    I: Iterator<Item = EventSig<'a>>,
{
    let mut auditors: [Option<&[u8]>; MAX_EVENT_SIGS] = [None; MAX_EVENT_SIGS];
    let mut observers: [Option<&[u8]>; MAX_EVENT_SIGS] = [None; MAX_EVENT_SIGS];
    let (mut a, mut o) = (0usize, 0usize);
    for s in sigs() {
        match s.role {
            EventRole::Auditor => note_org(&mut auditors, &mut a, s.org_id.as_bytes()),
            EventRole::Observer => note_org(&mut observers, &mut o, s.org_id.as_bytes()),
            EventRole::Clerk
            | EventRole::Commission
            | EventRole::Committee
            | EventRole::Sender
            | EventRole::Receiver
            | EventRole::Authority
            | EventRole::Device
            | EventRole::Chair => return false,
        }
    }
    a >= MIN_EVENT_AUDITOR_ORGS && o >= MIN_EVENT_OBSERVER_ORGS
}

fn exactly<'a, F, I>(sigs: F, roles: &[EventRole]) -> bool
where
    F: Fn() -> I,
    I: Iterator<Item = EventSig<'a>>,
{
    sigs().count() == roles.len() && roles.iter().all(|r| count_role(sigs(), *r) == 1)
}

/// Whether `sigs` is the signer set `schema` requires:
///
/// * `BoxOpened`: the device once, two or more clerks, observers of two or
///   more organisations, nothing else;
/// * `Fallback`, `IssuanceCount`, `ImprintAudit`, `SealChange`,
///   `LateBatchClose`, `ProgressCheck`, `CheckinUnitSwap`, `BoxUnitSwap`:
///   two or more clerks and observers of two or more organisations,
///   nothing else;
/// * `ObserverCountAttest`: observers of two or more organisations,
///   nothing else;
/// * `PaperCountReport`, `HandCountReport`: the chair of the district
///   commission once, observers of two or more organisations, nothing
///   else;
/// * `AuditManifestFreeze`, `AuditSeed`: the committee once, observers of
///   two or more organisations, nothing else;
/// * `SampleComparison`, `AuditFinding`: auditors of two or more
///   organisations and observers of two or more organisations, nothing
///   else;
/// * `CustodyHandoff`: exactly one sender and one receiver;
/// * `DisputeEvent`: exactly the commission and the committee;
/// * `LegalDecisionRef`: exactly one authority.
pub fn roles_satisfied<'a, F, I>(schema: SchemaId, sigs: F) -> bool
where
    F: Fn() -> I,
    I: Iterator<Item = EventSig<'a>>,
{
    match schema.get() {
        0x0029 => clerks_and_observers(sigs, Some(EventRole::Device)),
        0x002A..=0x002E | 0x0032 | 0x0040 | 0x0041 => clerks_and_observers(sigs, None),
        0x003F => observers_with(sigs, None),
        0x0046 | 0x004D => observers_with(sigs, Some(EventRole::Chair)),
        0x000D | 0x0048 => observers_with(sigs, Some(EventRole::Committee)),
        0x004B | 0x004C => auditors_and_observers(sigs),
        0x0008 => exactly(sigs, &[EventRole::Sender, EventRole::Receiver]),
        0x000E => exactly(sigs, &[EventRole::Commission, EventRole::Committee]),
        0x000F => exactly(sigs, &[EventRole::Authority]),
        _ => false,
    }
}

/// Decodes `bytes` as a complete object of `schema`, discarding the value.
fn validate_body(schema: SchemaId, bytes: &[u8]) -> Result<(), Error> {
    let v = SCHEMA_VERSION_1;
    match schema.get() {
        0x0008 => decode_object::<CustodyHandoffBody<'_>>(schema, v, bytes).map(drop),
        0x000E => decode_object::<DisputeEventBody<'_>>(schema, v, bytes).map(drop),
        0x000F => decode_object::<LegalDecisionRefBody<'_>>(schema, v, bytes).map(drop),
        0x0029 => decode_object::<BoxOpenedBody<'_>>(schema, v, bytes).map(drop),
        0x002A => decode_object::<FallbackBody<'_>>(schema, v, bytes).map(drop),
        0x002B => decode_object::<IssuanceCountBody<'_>>(schema, v, bytes).map(drop),
        0x002C => decode_object::<ImprintAuditBody<'_>>(schema, v, bytes).map(drop),
        0x002D => decode_object::<SealChangeBody<'_>>(schema, v, bytes).map(drop),
        0x002E => decode_object::<LateBatchCloseBody<'_>>(schema, v, bytes).map(drop),
        0x0032 => decode_object::<ProgressCheckBody<'_>>(schema, v, bytes).map(drop),
        0x003F => decode_object::<ObserverCountAttestBody<'_>>(schema, v, bytes).map(drop),
        0x0040 => decode_object::<CheckinUnitSwapBody<'_>>(schema, v, bytes).map(drop),
        0x0041 => decode_object::<BoxUnitSwapBody<'_>>(schema, v, bytes).map(drop),
        0x0046 => decode_object::<PaperCountReportBody<'_>>(schema, v, bytes).map(drop),
        0x000D => decode_object::<AuditSeedBody<'_>>(schema, v, bytes).map(drop),
        0x0048 => decode_object::<AuditManifestFreezeBody<'_>>(schema, v, bytes).map(drop),
        0x004B => decode_object::<SampleComparisonBody<'_>>(schema, v, bytes).map(drop),
        0x004C => decode_object::<AuditFindingBody<'_>>(schema, v, bytes).map(drop),
        0x004D => decode_object::<HandCountReportBody<'_>>(schema, v, bytes).map(drop),
        _ => Err(Error::new(Kind::SchemaMismatch, 4)),
    }
}

/// Reads the schema of an embedded body and validates it completely.
fn check_body(bytes: &[u8]) -> Result<SchemaId, Error> {
    if bytes.len() > MAX_WITNESSED_BODY_LEN {
        return Err(Error::new(Kind::LengthExceedsMax, 0));
    }
    let header = Header::read(&mut Reader::new(bytes))?;
    validate_body(header.schema_id(), bytes)?;
    Ok(header.schema_id())
}

/// A human-signed ledger event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessedEvent<'a> {
    body_bytes: &'a [u8],
    body_schema: SchemaId,
    sigs: [Option<EventSig<'a>>; MAX_EVENT_SIGS],
    count: u8,
}

impl<'a> WitnessedEvent<'a> {
    /// Builds the event. The signatures must be strictly ascending by
    /// signer identifier and form the role set the body requires.
    ///
    /// # Errors
    /// The body's decoding error, `LengthExceedsMax` at 0 if the body is too
    /// long, `SchemaMismatch` at 4 for a body schema not in
    /// [`WITNESSED_BODY_SCHEMAS`], or `InvariantViolation` at 0 if the
    /// signature set is malformed.
    pub fn new(body_bytes: &'a [u8], sigs: &[EventSig<'a>]) -> Result<Self, Error> {
        let body_schema = check_body(body_bytes)?;
        let ascending = ascending_by(sigs, |x| x.signer_id.as_bytes());
        if sigs.len() > MAX_EVENT_SIGS
            || !ascending
            || !roles_satisfied(body_schema, || sigs.iter().copied())
        {
            return Err(Error::new(Kind::InvariantViolation, 0));
        }
        let mut slots = [None; MAX_EVENT_SIGS];
        for (slot, s) in slots.iter_mut().zip(sigs) {
            *slot = Some(*s);
        }
        Ok(Self {
            body_bytes,
            body_schema,
            sigs: slots,
            count: u8::try_from(sigs.len()).map_err(|_| Error::new(Kind::InvariantViolation, 0))?,
        })
    }

    /// The body object bytes (the signed message).
    #[must_use]
    pub const fn body_bytes(&self) -> &'a [u8] {
        self.body_bytes
    }

    /// The body's schema.
    #[must_use]
    pub const fn body_schema(&self) -> SchemaId {
        self.body_schema
    }

    /// The signature purpose of the body.
    #[must_use]
    pub fn purpose(&self) -> &'static [u8] {
        purpose_of(self.body_schema).unwrap_or(b"")
    }

    /// Decodes the body as `T`, which must be the type of `schema`.
    ///
    /// # Errors
    /// `SchemaMismatch` at 4 if the body has another schema.
    pub fn body<T: Decode<'a>>(&self, schema: SchemaId) -> Result<T, Error> {
        decode_object(schema, SCHEMA_VERSION_1, self.body_bytes)
    }

    /// The signatures in ascending signer order.
    pub fn sigs(&self) -> impl Iterator<Item = EventSig<'a>> + '_ {
        self.sigs
            .iter()
            .take(usize::from(self.count))
            .flatten()
            .copied()
    }

    /// Number of signatures.
    #[must_use]
    pub fn sig_count(&self) -> usize {
        usize::from(self.count)
    }
}

impl Encode for WitnessedEvent<'_> {
    fn encoded_len(&self) -> usize {
        let sigs = self.sigs().fold(4usize, |acc, s| {
            acc.saturating_add(s.signer_id.encoded_len())
                .saturating_add(1)
                .saturating_add(s.org_id.encoded_len())
                .saturating_add(HYBRID_SIG_LEN)
        });
        self.body_bytes.len().saturating_add(4).saturating_add(sigs)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_bytes(self.body_bytes, MAX_WITNESSED_BODY_LEN)?;
        w.write_count(usize::from(self.count), MAX_EVENT_SIGS)?;
        for s in self.sigs() {
            s.signer_id.encode(w)?;
            w.write_u8(s.role.code())?;
            s.org_id.encode(w)?;
            w.write_array(s.sig)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for WitnessedEvent<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let body_at = r.position();
        let body_bytes = r.read_bytes(MAX_WITNESSED_BODY_LEN)?;
        let body_schema = check_body(body_bytes).map_err(|inner| {
            let offset = body_at
                .checked_add(4)
                .and_then(|p| p.checked_add(inner.offset()))
                .unwrap_or(body_at);
            Error::new(inner.kind(), offset)
        })?;
        let sigs_at = r.position();
        let count = r.read_count(MAX_EVENT_SIGS)?;
        let mut sigs = [None; MAX_EVENT_SIGS];
        let mut previous: Option<&[u8]> = None;
        for slot in sigs.iter_mut().take(count) {
            let id_at = r.position();
            let signer_id = SignerId::decode(r)?;
            Reader::check_ascending(previous, signer_id.as_bytes(), id_at)?;
            previous = Some(signer_id.as_bytes());
            let role_at = r.position();
            let role = EventRole::from_code(r.read_u8()?)
                .ok_or_else(|| Error::new(Kind::ValueOutOfRange, role_at))?;
            let org_id = OrgId::decode(r)?;
            let sig = read_fixed::<HYBRID_SIG_LEN>(r)?;
            *slot = Some(EventSig {
                signer_id,
                role,
                org_id,
                sig,
            });
        }
        if !roles_satisfied(body_schema, || sigs.iter().take(count).flatten().copied()) {
            return Err(Error::new(Kind::InvariantViolation, sigs_at));
        }
        Ok(Self {
            body_bytes,
            body_schema,
            sigs,
            count: u8::try_from(count).map_err(|_| Error::new(Kind::CountExceedsMax, sigs_at))?,
        })
    }
}
