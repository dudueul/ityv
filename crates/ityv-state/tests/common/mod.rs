//! Shared fixtures: leaked `'static` genesis inputs, signing helpers and
//! ledger objects for one polling-station box.
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
    clippy::cast_possible_truncation
)]

use std::boxed::Box;
use std::vec::Vec;

use ityv_crypto::{
    HybridSignature, HybridSigned, HybridSigningKey, Purpose, Verified, sign_hybrid, verify_hybrid,
};
use ityv_encoding::{
    Attestation, BallotStyleId, BatchAttestBody, BatchAttestParts, BoxClose, BoxCloseBody,
    BoxCloseParts, BoxId, CastRecordBody, CastRecordParts, ChallengeOpeningBody,
    ChallengeOpeningParts, CloseCounts, Commitments, Day, ElectionId, HYBRID_SIG_LEN, Hash512,
    ModuleCounter, ModuleCounters, ModuleId, ModuleIds, ModuleOpening, ModuleRange, OrgId, Point32,
    SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, Scalar32, Scalars, Scope, ScopeSet, SignerId,
    SignerRole, TimeBucket, Token192, encode_object,
};
use ityv_state::{Authorization, BoxSpec, Profile, RosterEntry};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

pub(crate) const ELECTION: &[u8] = b"E-2026";
pub(crate) const BOX: &[u8] = b"BOX-001";
pub(crate) const SEAL: Hash512 = Hash512([0x5e; 64]);
pub(crate) static ZERO_SIG: [u8; HYBRID_SIG_LEN] = [0; HYBRID_SIG_LEN];

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

pub(crate) fn module(name: &'static [u8]) -> ModuleId<'static> {
    ModuleId::new(name).unwrap()
}

pub(crate) fn org(name: &'static [u8]) -> OrgId<'static> {
    OrgId::new(name).unwrap()
}

pub(crate) fn leak<T>(value: T) -> &'static T {
    Box::leak(Box::new(value))
}

pub(crate) fn leak_slice<T>(values: Vec<T>) -> &'static [T] {
    Box::leak(values.into_boxed_slice())
}

/// The two registered modules of the box.
pub(crate) fn modules() -> &'static [ModuleId<'static>] {
    leak_slice(std::vec![module(b"MOD-P1"), module(b"MOD-P2")])
}

pub(crate) fn person(
    id: &'static [u8],
    role: SignerRole,
    org_name: &'static [u8],
) -> RosterEntry<'static> {
    RosterEntry {
        signer_id: SignerId::new(id).unwrap(),
        role,
        org_id: org(org_name),
    }
}

pub(crate) fn roster() -> &'static [RosterEntry<'static>] {
    leak_slice(std::vec![
        person(b"clerk-1", SignerRole::Clerk, b"NEC"),
        person(b"clerk-2", SignerRole::Clerk, b"NEC"),
        person(b"obs-a", SignerRole::Observer, b"PARTY-A"),
        person(b"obs-b", SignerRole::Observer, b"PARTY-B"),
        person(b"obs-c", SignerRole::Observer, b"PARTY-A"),
    ])
}

pub(crate) fn attestation(entry: RosterEntry<'static>) -> Attestation<'static> {
    Attestation {
        signer_id: entry.signer_id,
        role: entry.role,
        org_id: entry.org_id,
        sig: &ZERO_SIG,
    }
}

/// Two clerks and two observers of different organisations.
pub(crate) fn witnesses() -> &'static [Attestation<'static>] {
    let r = roster();
    leak_slice(r.iter().take(4).map(|e| attestation(*e)).collect())
}

/// Two clerks and two observers of one organisation.
pub(crate) fn weak_witnesses() -> &'static [Attestation<'static>] {
    let r = roster();
    leak_slice(std::vec![
        attestation(r[0]),
        attestation(r[1]),
        attestation(r[2]),
        attestation(r[4]),
    ])
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

pub(crate) fn authorization() -> Authorization<'static> {
    // The unsigned constructor is crate-private; integration tests build a
    // signed authorization (tests/auth.rs shows the full check).
    signed_authorization(ScopeSet::from_slice(&[
        Scope::PublicBoard,
        Scope::TrusteeBody,
        Scope::BallotMark,
        Scope::CryptoTallyAid,
        Scope::Rla,
        Scope::VoterCode,
    ]))
}

pub(crate) fn today() -> Day {
    Day::new(100)
}

/// A full legal authorization of another election.
pub(crate) fn signed_authorization_for(election_id: ElectionId<'static>) -> Authorization<'static> {
    authorization_of(
        election_id,
        ScopeSet::from_slice(&[
            Scope::PublicBoard,
            Scope::TrusteeBody,
            Scope::BallotMark,
            Scope::CryptoTallyAid,
            Scope::Rla,
            Scope::VoterCode,
        ]),
    )
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
    let mut buf = std::vec![0u8; 512];
    let len = encode_object(
        SCHEMA_LEGAL_AUTHORIZATION,
        SCHEMA_VERSION_1,
        &body,
        &mut buf,
    )
    .unwrap();
    buf.truncate(len);
    let object: &'static [u8] = leak_slice(buf);
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
        time_bucket: TimeBucket::new(500),
    }
}

/// An encoded close body object.
pub(crate) fn close_body(parts: &BoxCloseParts<'static>) -> &'static [u8] {
    let body = BoxCloseBody::new(parts);
    let mut buf = std::vec![0u8; 1024];
    let len = encode_object(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, &body, &mut buf).unwrap();
    buf.truncate(len);
    leak_slice(buf)
}

/// A signed close: the event, and the verification token of its device
/// signature under `purpose`.
pub(crate) struct SignedClose {
    pub(crate) close: BoxClose<'static>,
    pub(crate) token: Verified<HybridSigned<'static>>,
}

pub(crate) fn signed_close_with(
    parts: &BoxCloseParts<'static>,
    key: &'static HybridSigningKey,
    purpose: &'static [u8],
) -> SignedClose {
    let body = close_body(parts);
    let purpose = leak(Purpose::new(purpose).unwrap());
    let signature = leak(sign(key, purpose, body));
    let bytes = leak(signature_bytes(signature));
    let close = BoxClose::new(body, Some(bytes), witnesses()).unwrap();
    let vk = leak(key.verifying_key());
    let token = verify_hybrid(vk, purpose, body, signature).unwrap();
    SignedClose { close, token }
}

pub(crate) fn signed_close(parts: &BoxCloseParts<'static>) -> SignedClose {
    signed_close_with(parts, device_key(), b"box-close")
}

pub(crate) fn manual_close(parts: &BoxCloseParts<'static>) -> BoxClose<'static> {
    BoxClose::new(close_body(parts), None, witnesses()).unwrap()
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

pub(crate) fn batch_body(box_id: BoxId<'static>, record_count: u16) -> BatchAttestBody<'static> {
    let ranges = leak_slice(std::vec![ModuleRange {
        module_id: module(b"MOD-P1"),
        counter_first: 1,
        counter_last: u64::from(record_count),
    }]);
    BatchAttestBody::new(&BatchAttestParts {
        election_id: election(),
        box_id,
        batch_index: 0,
        record_count,
        records_root: Hash512([9; 64]),
        module_ranges: ranges,
        module_refusals: ModuleIds::new(&[]).unwrap(),
        journal_head: Hash512([10; 64]),
        time_bucket: TimeBucket::new(400),
    })
    .unwrap()
}
