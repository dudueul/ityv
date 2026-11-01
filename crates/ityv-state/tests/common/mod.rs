//! Shared fixtures: leaked `'static` genesis inputs with real hybrid keys,
//! signing helpers, and signed ledger objects for one polling-station box.
// Integration-test helper module: outside the TCB. Fixtures express "this
// must hold" with unwrap/expect/indexing, leak inputs to obtain `'static`
// borrows, compute counts with plain arithmetic, and not every test binary
// uses every helper; so these lints are relaxed for this file only
// (CONSTITUTION.md §1.1).
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::panic
)]

use std::boxed::Box;
use std::vec::Vec;

use ityv_crypto::{
    HybridSignature, HybridSigned, HybridSigningKey, HybridVerifyingKey, Purpose, Verified,
    sign_hybrid, verify_hybrid,
};
use ityv_encoding::{
    Attestation, BallotStyleId, BatchAttest, BatchAttestBody, BatchAttestParts, BoxClose,
    BoxCloseBody, BoxCloseParts, BoxId, BoxOpenedBody, BoxOpenedParts, CastRecordBody,
    CastRecordParts, ChallengeOpeningBody, ChallengeOpeningParts, CloseCounts, Commitments,
    CustodyHandoffBody, CustodyHandoffParts, Day, ElectionId, Encode, EnvelopeIssuance, EventRole,
    EventSig, FallbackBody, FallbackKind, FallbackParts, FallbackReason, HYBRID_SIG_LEN, Hash512,
    ImprintAuditBody, ImprintAuditParts, IssuanceCountBody, IssuanceCountParts, LateBatchCloseBody,
    LateBatchCloseParts, LateBatchReason, ModuleBatchSig, ModuleCounter, ModuleCounters, ModuleId,
    ModuleIds, ModuleOpening, ModuleRange, ObjectHeader, OrgId, Point32, Reader, RosterRole,
    SCHEMA_BATCH_ATTEST_BODY, SCHEMA_BOX_CLOSE_BODY, SCHEMA_BOX_OPENED_BODY,
    SCHEMA_CUSTODY_HANDOFF_BODY, SCHEMA_FALLBACK_BODY, SCHEMA_IMPRINT_AUDIT_BODY,
    SCHEMA_ISSUANCE_COUNT_BODY, SCHEMA_LATE_BATCH_CLOSE_BODY, SCHEMA_SEAL_CHANGE_BODY,
    SCHEMA_VERSION_1, Scalar32, Scalars, SchemaId, Scope, ScopeSet, SealChangeBody,
    SealChangeParts, SealChangeReason, SignerId, SignerRole, StationId, TimeBucket, Token192,
    WitnessedEvent, encode_object, purpose_of,
};
use ityv_state::{Authorization, BoxSpec, CloseTokens, Profile, RosterEntry, Signed};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

pub(crate) const ELECTION: &[u8] = b"E-2026";
pub(crate) const BOX: &[u8] = b"BOX-001";
pub(crate) const STATION: &[u8] = b"ST-1";
pub(crate) const SEAL: Hash512 = Hash512([0x5e; 64]);
pub(crate) const CLOSE_BUCKET: u64 = 500;

pub(crate) fn election() -> ElectionId<'static> {
    ElectionId::new(ELECTION).unwrap()
}

pub(crate) fn other_election() -> ElectionId<'static> {
    ElectionId::new(b"E-OTHER").unwrap()
}

pub(crate) fn box_id() -> BoxId<'static> {
    BoxId::new(BOX).unwrap()
}

pub(crate) fn other_box() -> BoxId<'static> {
    BoxId::new(b"BOX-999").unwrap()
}

pub(crate) fn station() -> StationId<'static> {
    StationId::new(STATION).unwrap()
}

pub(crate) fn module(name: &'static [u8]) -> ModuleId<'static> {
    ModuleId::new(name).unwrap()
}

pub(crate) fn org(name: &'static [u8]) -> OrgId<'static> {
    OrgId::new(name).unwrap()
}

pub(crate) fn signer(id: &'static [u8]) -> SignerId<'static> {
    SignerId::new(id).unwrap()
}

pub(crate) fn leak<T>(value: T) -> &'static T {
    Box::leak(Box::new(value))
}

pub(crate) fn leak_slice<T>(values: Vec<T>) -> &'static [T] {
    Box::leak(values.into_boxed_slice())
}

/// The two modules the box opens with (ascending).
pub(crate) fn modules() -> ModuleIds<'static> {
    ModuleIds::new(&[module(b"MOD-P1"), module(b"MOD-P2")]).unwrap()
}

/// The people of the roster: identifier, role, organisation, key seed.
const PEOPLE: [(&[u8], RosterRole, &[u8], u8); 8] = [
    (b"clerk-1", RosterRole::Clerk, b"NEC", 20),
    (b"clerk-2", RosterRole::Clerk, b"NEC", 22),
    (b"obs-a", RosterRole::Observer, b"PARTY-A", 24),
    (b"obs-b", RosterRole::Observer, b"PARTY-B", 26),
    (b"obs-c", RosterRole::Observer, b"PARTY-A", 28),
    (b"chief", RosterRole::Custodian, b"STATION", 30),
    (b"officer", RosterRole::Custodian, b"POLICE", 32),
    (b"counter", RosterRole::Custodian, b"CENTRE", 34),
];

fn person_index(id: &[u8]) -> usize {
    PEOPLE
        .iter()
        .position(|p| p.0 == id)
        .unwrap_or_else(|| panic!("no person {id:?}"))
}

/// The signing key of a person on the roster.
pub(crate) fn person_key(id: &[u8]) -> &'static HybridSigningKey {
    let seed = PEOPLE[person_index(id)].3;
    leak(HybridSigningKey::from_seeds([seed; 32], [seed + 1; 32]))
}

pub(crate) fn person_org(id: &[u8]) -> &'static [u8] {
    PEOPLE[person_index(id)].2
}

pub(crate) fn roster() -> &'static [RosterEntry<'static>] {
    leak_slice(
        PEOPLE
            .iter()
            .map(|(id, role, o, _)| RosterEntry {
                signer_id: signer(id),
                role: *role,
                org_id: org(o),
                key: leak(person_key(id).verifying_key()),
            })
            .collect(),
    )
}

pub(crate) fn route() -> &'static [OrgId<'static>] {
    leak_slice(std::vec![org(b"STATION"), org(b"POLICE"), org(b"CENTRE")])
}

pub(crate) fn device_key() -> &'static HybridSigningKey {
    leak(HybridSigningKey::from_seeds([4; 32], [5; 32]))
}

pub(crate) fn spec(profile: Profile) -> BoxSpec<'static> {
    BoxSpec {
        election_id: election(),
        box_id: box_id(),
        station_id: station(),
        profile,
        registered_modules: leak_slice(std::vec![
            module(b"MOD-P1"),
            module(b"MOD-P2"),
            module(b"MOD-P3"),
        ]),
        device_key: leak(device_key().verifying_key()),
        roster: roster(),
        route: route(),
    }
}

/// Every scope of stages 0–3.
pub(crate) fn all_scopes() -> ScopeSet {
    ScopeSet::from_slice(&Scope::ALL)
}

pub(crate) fn authorization() -> Authorization<'static> {
    // The unsigned constructor is crate-private; integration tests build a
    // signed authorization (tests/auth.rs shows the full check).
    signed_authorization(all_scopes())
}

pub(crate) fn today() -> Day {
    Day::new(100)
}

/// A full legal authorization of another election.
pub(crate) fn signed_authorization_for(election_id: ElectionId<'static>) -> Authorization<'static> {
    authorization_of(election_id, all_scopes())
}

/// A legal authorization signed by two leaked keys.
pub(crate) fn signed_authorization(scopes: ScopeSet) -> Authorization<'static> {
    authorization_of(election(), scopes)
}

fn authorization_of(election_id: ElectionId<'static>, scopes: ScopeSet) -> Authorization<'static> {
    use ityv_encoding::{LegalAuthorizationBody, SCHEMA_LEGAL_AUTHORIZATION};
    let body = LegalAuthorizationBody::new(
        election_id,
        scopes,
        Hash512([1; 64]),
        Day::new(90),
        Day::new(110),
    )
    .unwrap();
    let object = object(SCHEMA_LEGAL_AUTHORIZATION, &body);
    let commission = leak(HybridSigningKey::from_seeds([10; 32], [11; 32]));
    let committee = leak(HybridSigningKey::from_seeds([12; 32], [13; 32]));
    let commission_vk = leak(commission.verifying_key());
    let committee_vk = leak(committee.verifying_key());
    let purpose = leak(Purpose::new(b"legal-auth").unwrap());
    let s1 = leak(sign(commission, purpose, object));
    let s2 = leak(sign(committee, purpose, object));
    let t1 = verify_hybrid(commission_vk, purpose, object, s1).unwrap();
    let t2 = verify_hybrid(committee_vk, purpose, object, s2).unwrap();
    ityv_state::authorize(object, &t1, commission_vk, &t2, committee_vk).unwrap()
}

pub(crate) fn sign(
    key: &HybridSigningKey,
    purpose: &Purpose<'_>,
    object: &[u8],
) -> HybridSignature {
    let mut rng = ChaCha20Rng::seed_from_u64(object.len() as u64);
    sign_hybrid(key, purpose, object, &mut rng).unwrap()
}

pub(crate) fn signature_bytes(signature: &HybridSignature) -> [u8; HYBRID_SIG_LEN] {
    let mut out = [0u8; HYBRID_SIG_LEN];
    let (ml, ed) = out.split_at_mut(signature.mldsa87().len());
    ml.copy_from_slice(signature.mldsa87());
    ed.copy_from_slice(signature.ed25519());
    out
}

/// A complete object of `schema`, leaked.
pub(crate) fn object<T: Encode>(schema: SchemaId, value: &T) -> &'static [u8] {
    let mut buf = std::vec![0u8; 8192];
    let len = encode_object(schema, SCHEMA_VERSION_1, value, &mut buf).unwrap();
    buf.truncate(len);
    leak_slice(buf)
}

/// One signature and its token: `key` signs `object` under `purpose`.
pub(crate) fn signed_by(
    key: &'static HybridSigningKey,
    purpose: &'static [u8],
    object: &'static [u8],
) -> (
    &'static [u8; HYBRID_SIG_LEN],
    Verified<HybridSigned<'static>>,
) {
    let purpose = leak(Purpose::new(purpose).unwrap());
    let signature = leak(sign(key, purpose, object));
    let vk = leak(key.verifying_key());
    let token = verify_hybrid(vk, purpose, object, signature).unwrap();
    (leak(signature_bytes(signature)), token)
}

/// Who signs an event: a person on the roster, or the box's device.
#[derive(Clone, Copy)]
pub(crate) enum By {
    /// A roster person in a role.
    Person(&'static [u8], EventRole),
    /// The device.
    Device,
    /// Anyone else: identifier, role, organisation and key.
    Other(
        &'static [u8],
        EventRole,
        &'static [u8],
        &'static HybridSigningKey,
    ),
}

impl By {
    fn parts(
        self,
    ) -> (
        &'static [u8],
        EventRole,
        &'static [u8],
        &'static HybridSigningKey,
    ) {
        match self {
            Self::Person(id, role) => (id, role, person_org(id), person_key(id)),
            Self::Device => (BOX, EventRole::Device, b"NEC", device_key()),
            Self::Other(id, role, o, key) => (id, role, o, key),
        }
    }
}

fn schema_of(body: &[u8]) -> SchemaId {
    ObjectHeader::read(&mut Reader::new(body))
        .unwrap()
        .schema_id()
}

/// A witnessed event over `body`, signed by `signers` under the body's
/// purpose, with one token per signature.
pub(crate) fn witnessed(body: &'static [u8], signers: &[By]) -> Signed<'static> {
    let purpose = purpose_of(schema_of(body)).unwrap();
    witnessed_with(body, signers, purpose)
}

/// As [`witnessed`] under an explicit purpose.
pub(crate) fn witnessed_with(
    body: &'static [u8],
    signers: &[By],
    purpose: &'static [u8],
) -> Signed<'static> {
    let mut parts: Vec<_> = signers.iter().map(|b| b.parts()).collect();
    parts.sort_by(|a, b| a.0.cmp(b.0));
    let mut sigs = Vec::new();
    let mut tokens = Vec::new();
    for (id, role, o, key) in parts {
        let (sig, token) = signed_by(key, purpose, body);
        sigs.push(EventSig {
            signer_id: signer(id),
            role,
            org_id: org(o),
            sig,
        });
        tokens.push(token);
    }
    let event = leak(WitnessedEvent::new(body, &sigs).unwrap());
    Signed {
        event,
        tokens: leak_slice(tokens),
    }
}

/// Two clerks and two observers of different organisations.
pub(crate) const WITNESSES: [By; 4] = [
    By::Person(b"clerk-1", EventRole::Clerk),
    By::Person(b"clerk-2", EventRole::Clerk),
    By::Person(b"obs-a", EventRole::Observer),
    By::Person(b"obs-b", EventRole::Observer),
];

/// Two clerks and two observers of one organisation: the encoding already
/// refuses such an event (`WitnessedEvent::new`).
pub(crate) const WEAK: [By; 4] = [
    By::Person(b"clerk-1", EventRole::Clerk),
    By::Person(b"clerk-2", EventRole::Clerk),
    By::Person(b"obs-a", EventRole::Observer),
    By::Person(b"obs-c", EventRole::Observer),
];

/// Two clerks and two observers, one of them naming an organisation the
/// roster does not register for them: well formed, but refused by the
/// state machine.
pub(crate) fn misregistered() -> [By; 4] {
    [
        By::Person(b"clerk-1", EventRole::Clerk),
        By::Person(b"clerk-2", EventRole::Clerk),
        By::Person(b"obs-a", EventRole::Observer),
        By::Other(
            b"obs-c",
            EventRole::Observer,
            b"PARTY-C",
            person_key(b"obs-c"),
        ),
    ]
}

pub(crate) fn with_device(signers: &[By]) -> Vec<By> {
    let mut all = std::vec![By::Device];
    all.extend_from_slice(signers);
    all
}

pub(crate) fn opened_body(
    box_id: BoxId<'static>,
    modules: ModuleIds<'static>,
    seals_match: bool,
    initial_count: u64,
) -> &'static [u8] {
    object(
        SCHEMA_BOX_OPENED_BODY,
        &BoxOpenedBody::new(&BoxOpenedParts {
            election_id: election(),
            box_id,
            modules,
            seal_digest: SEAL,
            seals_match,
            initial_count,
            time_bucket: TimeBucket::new(100),
        }),
    )
}

/// A clean signed opening with `modules`.
pub(crate) fn opening(modules: ModuleIds<'static>) -> Signed<'static> {
    witnessed(
        opened_body(box_id(), modules, true, 0),
        &with_device(&WITNESSES),
    )
}

pub(crate) fn fallback_body(box_id: BoxId<'static>, kind: FallbackKind) -> &'static [u8] {
    let reason = match kind {
        FallbackKind::Declared => FallbackReason::ScannerFault,
        FallbackKind::Ended => FallbackReason::NotApplicable,
    };
    object(
        SCHEMA_FALLBACK_BODY,
        &FallbackBody::new(&FallbackParts {
            election_id: election(),
            box_id,
            kind,
            reason,
            statement_hash: Hash512([0x51; 64]),
            markers: None,
            time_bucket: TimeBucket::new(300),
        })
        .unwrap(),
    )
}

pub(crate) fn fallback(kind: FallbackKind) -> Signed<'static> {
    witnessed(fallback_body(box_id(), kind), &WITNESSES)
}

pub(crate) fn audit_body(
    box_id: BoxId<'static>,
    unimprinted: u64,
    duplicates: u64,
) -> &'static [u8] {
    object(
        SCHEMA_IMPRINT_AUDIT_BODY,
        &ImprintAuditBody::new(&ImprintAuditParts {
            election_id: election(),
            box_id,
            unimprinted,
            duplicate_cast_ids: duplicates,
            time_bucket: TimeBucket::new(700),
        }),
    )
}

pub(crate) fn audit(unimprinted: u64, duplicates: u64) -> Signed<'static> {
    witnessed(audit_body(box_id(), unimprinted, duplicates), &WITNESSES)
}

pub(crate) fn handoff_parts(
    index: u32,
    from: &'static [u8],
    to: &'static [u8],
    previous: Hash512,
    count: u64,
) -> CustodyHandoffParts<'static> {
    CustodyHandoffParts {
        election_id: election(),
        box_id: box_id(),
        index,
        from_signer: signer(from),
        from_org: org(person_org(from)),
        to_signer: signer(to),
        to_org: org(person_org(to)),
        previous_handoff_hash: previous,
        seal_digest: SEAL,
        count,
        time_bucket: TimeBucket::new(510),
    }
}

pub(crate) fn handoff_body(parts: &CustodyHandoffParts<'static>) -> &'static [u8] {
    object(
        SCHEMA_CUSTODY_HANDOFF_BODY,
        &CustodyHandoffBody::new(parts).unwrap(),
    )
}

/// A handoff signed by its sender and receiver.
pub(crate) fn handoff(parts: &CustodyHandoffParts<'static>) -> Signed<'static> {
    let from: &'static [u8] = parts.from_signer.as_bytes();
    let to: &'static [u8] = parts.to_signer.as_bytes();
    witnessed(
        handoff_body(parts),
        &[
            By::Person(from, EventRole::Sender),
            By::Person(to, EventRole::Receiver),
        ],
    )
}

/// The two handoffs from the station to the counting centre.
pub(crate) fn handoffs(count: u64) -> [Signed<'static>; 2] {
    let first = handoff_parts(1, b"chief", b"officer", Hash512::ZERO, count);
    let first_hash = ityv_crypto::hash::object_hash(handoff_body(&first));
    let second = handoff_parts(2, b"officer", b"counter", first_hash, count);
    [handoff(&first), handoff(&second)]
}

pub(crate) fn seal_change(
    reason: SealChangeReason,
    previous: Hash512,
    new: Hash512,
) -> Signed<'static> {
    let body = object(
        SCHEMA_SEAL_CHANGE_BODY,
        &SealChangeBody::new(&SealChangeParts {
            election_id: election(),
            box_id: box_id(),
            reason,
            previous_seal_digest: previous,
            new_seal_digest: new,
            statement_hash: Hash512([0x52; 64]),
            time_bucket: TimeBucket::new(505),
        })
        .unwrap(),
    );
    witnessed(body, &WITNESSES)
}

pub(crate) fn issuance_body(
    election_id: ElectionId<'static>,
    station_id: StationId<'static>,
    envelopes: Option<EnvelopeIssuance>,
) -> &'static [u8] {
    object(
        SCHEMA_ISSUANCE_COUNT_BODY,
        &IssuanceCountBody::new(&IssuanceCountParts {
            election_id,
            station_id,
            stock_received: 50,
            issued: 40,
            voter_spoiled: 0,
            returned: 0,
            unused: 10,
            printer_waste: 0,
            envelopes,
            time_bucket: TimeBucket::new(499),
        }),
    )
}

pub(crate) fn issuance(envelopes: Option<EnvelopeIssuance>, signers: &[By]) -> Signed<'static> {
    witnessed(issuance_body(election(), station(), envelopes), signers)
}

pub(crate) fn counts(paper: u64, records: u64, challenged: u64) -> CloseCounts {
    CloseCounts {
        paper,
        records,
        attested: records,
        without_record: 0,
        challenged,
        quarantined: 0,
        visits: records,
        envelopes: 0,
        stickers: 0,
        spoil_envelopes: challenged,
    }
}

/// The parts of a close with the given counts, module counters equal to
/// `records + challenged + quarantined` for every given module.
pub(crate) fn close_parts(
    counts: CloseCounts,
    modules: &[ModuleId<'static>],
) -> BoxCloseParts<'static> {
    let consumed = counts.records + counts.challenged + counts.quarantined;
    let entries: Vec<ModuleCounter<'static>> = modules
        .iter()
        .map(|m| ModuleCounter {
            module_id: *m,
            counter: consumed,
        })
        .collect();
    BoxCloseParts {
        election_id: election(),
        box_id: box_id(),
        counts,
        record_set_root: Hash512([2; 64]),
        journal_head: Hash512([3; 64]),
        seal_digest: SEAL,
        module_counters: ModuleCounters::new(&entries).unwrap(),
        open_batches: 0,
        time_bucket: TimeBucket::new(CLOSE_BUCKET),
    }
}

pub(crate) fn module_list() -> &'static [ModuleId<'static>] {
    leak_slice(std::vec![module(b"MOD-P1"), module(b"MOD-P2")])
}

/// An encoded close body object.
pub(crate) fn close_body(parts: &BoxCloseParts<'static>) -> &'static [u8] {
    object(SCHEMA_BOX_CLOSE_BODY, &BoxCloseBody::new(parts))
}

/// A close with its tokens.
pub(crate) struct SignedClose {
    pub(crate) close: BoxClose<'static>,
    pub(crate) device: Option<Verified<HybridSigned<'static>>>,
    pub(crate) humans: &'static [Verified<HybridSigned<'static>>],
}

impl SignedClose {
    pub(crate) fn tokens(&'static self) -> CloseTokens<'static> {
        CloseTokens {
            device: self.device.as_ref(),
            humans: self.humans,
        }
    }
}

const CLOSE_WITNESSES: [(&[u8], SignerRole); 4] = [
    (b"clerk-1", SignerRole::Clerk),
    (b"clerk-2", SignerRole::Clerk),
    (b"obs-a", SignerRole::Observer),
    (b"obs-b", SignerRole::Observer),
];

/// Human attestations of `body` under `purpose`, with their tokens.
pub(crate) fn attest(
    body: &'static [u8],
    purpose: &'static [u8],
    who: &[(&'static [u8], SignerRole)],
) -> (
    &'static [Attestation<'static>],
    &'static [Verified<HybridSigned<'static>>],
) {
    let mut sorted = who.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let mut attestations = Vec::new();
    let mut tokens = Vec::new();
    for (id, role) in sorted {
        let (sig, token) = signed_by(person_key(id), purpose, body);
        attestations.push(Attestation {
            signer_id: signer(id),
            role,
            org_id: org(person_org(id)),
            sig,
        });
        tokens.push(token);
    }
    (leak_slice(attestations), leak_slice(tokens))
}

/// A close signed by `key` under `purpose` (device) and by the four
/// witnesses under the same purpose.
pub(crate) fn signed_close_with(
    parts: &BoxCloseParts<'static>,
    key: &'static HybridSigningKey,
    purpose: &'static [u8],
) -> SignedClose {
    let body = close_body(parts);
    let (sig, token) = signed_by(key, purpose, body);
    let (attestations, humans) = attest(body, purpose, &CLOSE_WITNESSES);
    let close = BoxClose::new(body, Some(sig), attestations).unwrap();
    SignedClose {
        close,
        device: Some(token),
        humans,
    }
}

pub(crate) fn signed_close(parts: &BoxCloseParts<'static>) -> SignedClose {
    signed_close_with(parts, device_key(), b"box-close")
}

pub(crate) fn late_close(parts: &BoxCloseParts<'static>) -> SignedClose {
    signed_close_with(parts, device_key(), b"late-box-close")
}

/// A close without the device signature.
pub(crate) fn manual_close(parts: &BoxCloseParts<'static>) -> SignedClose {
    let body = close_body(parts);
    let (attestations, humans) = attest(body, b"box-close", &CLOSE_WITNESSES);
    SignedClose {
        close: BoxClose::new(body, None, attestations).unwrap(),
        device: None,
        humans,
    }
}

pub(crate) fn patterned<const N: usize>(seed: u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    out
}

fn proof_bytes(option_count: u16, chunk_count: u8) -> &'static [u8] {
    let len = 3 + usize::from(option_count) * (usize::from(chunk_count) + 2) * 32;
    let mut out = std::vec![0xab; len];
    out[0..2].copy_from_slice(&option_count.to_be_bytes());
    out[2] = chunk_count;
    leak_slice(out)
}

/// A cast record body for `box_id` with counters of `modules`.
pub(crate) fn record_body(
    box_id: BoxId<'static>,
    style: &'static [u8],
    modules: &[ModuleId<'static>],
) -> CastRecordBody<'static> {
    let entries: Vec<ModuleCounter<'static>> = modules
        .iter()
        .map(|m| ModuleCounter {
            module_id: *m,
            counter: 1,
        })
        .collect();
    let points = [Point32(patterned(1)), Point32(patterned(2))];
    CastRecordBody::new(&CastRecordParts {
        election_id: election(),
        box_id,
        ballot_style_id: BallotStyleId::new(style).unwrap(),
        proof_system_id: 1,
        commitments: Commitments::new(&points).unwrap(),
        proof: proof_bytes(16, 2),
        module_counters: ModuleCounters::new(&entries).unwrap(),
        share_package_hash: Hash512([6; 64]),
        transport_flags: 0,
    })
    .unwrap()
}

pub(crate) fn challenge_body(box_id: BoxId<'static>) -> ChallengeOpeningBody<'static> {
    let rand = leak(Scalars::new(&[Scalar32(patterned(7)), Scalar32(patterned(8))]).unwrap());
    let modules = leak_slice(std::vec![ModuleOpening {
        module_id: module(b"MOD-P1"),
        counter: 3,
        rand: Scalars::new(&[Scalar32(patterned(9)), Scalar32(patterned(10))]).unwrap(),
        cid: Token192([1; 24]),
    }]);
    ChallengeOpeningBody::new(&ChallengeOpeningParts {
        election_id: election(),
        box_id,
        ballot_style_id: BallotStyleId::new(b"S-1").unwrap(),
        record_hash: Hash512([8; 64]),
        option_index: 2,
        cast_id: Token192([2; 24]),
        rand,
        modules,
    })
    .unwrap()
}

pub(crate) fn batch_parts(
    box_id: BoxId<'static>,
    record_count: u16,
    index: u32,
) -> BatchAttestParts<'static> {
    let ranges = leak_slice(std::vec![ModuleRange {
        module_id: module(b"MOD-P1"),
        counter_first: 1,
        counter_last: u64::from(record_count),
    }]);
    BatchAttestParts {
        election_id: election(),
        box_id,
        batch_index: index,
        record_count,
        records_root: Hash512([9; 64]),
        module_ranges: ranges,
        module_refusals: ModuleIds::new(&[]).unwrap(),
        journal_head: Hash512([10; 64]),
        time_bucket: TimeBucket::new(400),
    }
}

pub(crate) fn batch_body(box_id: BoxId<'static>, record_count: u16) -> BatchAttestBody<'static> {
    BatchAttestBody::new(&batch_parts(box_id, record_count, 0)).unwrap()
}

static PATTERN_SIG: [u8; HYBRID_SIG_LEN] = [0x33; HYBRID_SIG_LEN];

/// A batch attestation event (signatures are patterned bytes: this crate
/// does not check batch signatures).
pub(crate) fn batch_event(
    box_id: BoxId<'static>,
    record_count: u16,
    index: u32,
) -> BatchAttest<'static> {
    let body = BatchAttestBody::new(&batch_parts(box_id, record_count, index)).unwrap();
    let bytes = object(SCHEMA_BATCH_ATTEST_BODY, &body);
    BatchAttest::new(
        bytes,
        &[ModuleBatchSig {
            module_id: module(b"MOD-P1"),
            sig: &PATTERN_SIG,
        }],
        &PATTERN_SIG,
    )
    .unwrap()
}

/// A late batch close for `batch`, at `bucket`, signed by `signers`.
pub(crate) fn late_batch(
    batch: &BatchAttest<'static>,
    bucket: u64,
    signers: &[By],
) -> Signed<'static> {
    let body = object(
        SCHEMA_LATE_BATCH_CLOSE_BODY,
        &LateBatchCloseBody::new(&LateBatchCloseParts {
            election_id: election(),
            box_id: batch.body().box_id(),
            batch_body_hash: ityv_crypto::hash::object_hash(batch.body_bytes()),
            reason: LateBatchReason::DeviceRestart,
            time_bucket: TimeBucket::new(bucket),
        })
        .unwrap(),
    );
    witnessed(body, signers)
}

pub(crate) fn verifying(key: &HybridSigningKey) -> &'static HybridVerifyingKey {
    leak(key.verifying_key())
}
