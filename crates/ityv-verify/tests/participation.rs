//! The participation stage (PROTOCOL.md §6.4, §6.5, §9.4.2, §14 6;
//! VC-018, VC-084, VC-092, VC-093, VC-095): party key ceremonies, module
//! provisioning records the genesis pins, participation sets signed by a
//! check-in unit and its party modules, the station identities and
//! repeated pseudonyms. Every signature is a real hybrid signature under a
//! key the genesis registers.
// Integration tests: outside the TCB. Assertions use unwrap/expect, so these
// lints are relaxed for this file only (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

mod common;

use std::collections::BTreeMap;
use std::sync::OnceLock;
use std::vec::Vec;

use common::{
    BOX_DEVICE_BASE, COMMITTEE, Draft, Ledger, ROSTER_BASE, SIGNERS, SPARE_BASE, leak, leak_slice,
    module_signing, modules, object, sign, sign_genesis_with, signing, trustee_signing,
    unit_signing,
};
use ityv_crypto::{HybridSigningKey, Purpose, object_hash, sign_hybrid};
use ityv_encoding::{
    ActorSig, Attestation, BoxClose, BoxCloseBody, BoxCloseParts, BoxId, BoxOpenedBody,
    BoxOpenedParts, ChamberCode, CloseCounts, ElectionId, Encode, EventRole, EventSig,
    HYBRID_SIG_LEN, Hash512, Ident, IssuanceCountBody, IssuanceCountParts, KEM_EK_LEN,
    ModuleCounter, ModuleCounters, ModuleId, ModuleProvisioned, ModuleProvisionedMessage,
    ModuleProvisionedParts, ObserverCountAttestBody, ObserverCountKind, ObserverCountParts, OrgId,
    ParticipationMessage, ParticipationModuleSig, ParticipationSet, PartyKeyCeremony,
    PartyKeyMessage, PartyKeyParts, Pseudonyms, SCHEMA_BOX_CLOSE, SCHEMA_BOX_CLOSE_BODY,
    SCHEMA_BOX_OPENED_BODY, SCHEMA_ISSUANCE_COUNT_BODY, SCHEMA_MODULE_PROVISIONED,
    SCHEMA_OBSERVER_COUNT_ATTEST_BODY, SCHEMA_PARTICIPATION_SET, SCHEMA_PARTY_KEY_CEREMONY,
    SCHEMA_SIGNED_GENESIS, SCHEMA_SIGNED_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1,
    SCHEMA_WITNESSED_EVENT, SchemaId, ShareHolder, SignerId, SignerRole, StationId, StationKind,
    StationProgressPolicy, TimeBucket, TrusteeId, UnitId, WitnessedEvent, Writer, purpose_of,
};
use ityv_state::{HoldReason, HoldSet};
use ityv_verify::{
    KeyProblem, LedgerIndex, ParticipationStage, Scope as EventScope, SetProblem,
    StationParticipation, VerifiedGenesis, authorize_ledger, build_index, verify_boxes,
    verify_genesis, verify_participation, verify_records,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const SEAL: Hash512 = Hash512([0x5e; 64]);
const OPEN_BUCKET: u64 = 100;
const CLOSE_BUCKET: u64 = 140;
static KEM: [u8; KEM_EK_LEN] = [0x6B; KEM_EK_LEN];
static PRF_P1: [u8; 32] = [0x11; 32];
static PRF_P2: [u8; 32] = [0x22; 32];
static PRF_OTHER: [u8; 32] = [0x99; 32];

fn election() -> ElectionId<'static> {
    common::election()
}

fn id(bytes: &'static [u8]) -> Ident<'static> {
    common::id(bytes)
}

/// A field group's encoding, without an object header.
fn group<T: Encode>(value: &T) -> &'static [u8] {
    let mut out = std::vec![0u8; value.encoded_len()];
    let mut w = Writer::new(&mut out);
    value.encode(&mut w).unwrap();
    assert_eq!(w.finish(), out.len());
    leak_slice(out)
}

// ---------------------------------------------------------------------
// The modules of `Draft::standard`, in its order (the `n` of their keys).

struct Module {
    name: &'static [u8],
    chamber: ChamberCode,
    device: &'static [u8],
    unit: bool,
}

const fn m(name: &'static [u8], chamber: ChamberCode, device: &'static [u8], unit: bool) -> Module {
    Module {
        name,
        chamber,
        device,
        unit,
    }
}

const MODULES: [Module; 16] = [
    m(b"M-B1-P1", ChamberCode::P1, b"BOX-1", false),
    m(b"M-B1-P2", ChamberCode::P2, b"BOX-1", false),
    m(b"M-B2-P1", ChamberCode::P1, b"BOX-2", false),
    m(b"M-B2-P2", ChamberCode::P2, b"BOX-2", false),
    m(b"M-B2-J", ChamberCode::J, b"BOX-2", false),
    m(b"M-B3-P1", ChamberCode::P1, b"BOX-3", false),
    m(b"M-B3-P2", ChamberCode::P2, b"BOX-3", false),
    m(b"M-B3-A", ChamberCode::A, b"BOX-3", false),
    m(b"M-U1A-P1", ChamberCode::P1, b"U-1A", true),
    m(b"M-U1A-P2", ChamberCode::P2, b"U-1A", true),
    m(b"M-U1B-P1", ChamberCode::P1, b"U-1B", true),
    m(b"M-U1B-P2", ChamberCode::P2, b"U-1B", true),
    m(b"M-U2A-P1", ChamberCode::P1, b"U-2A", true),
    m(b"M-U2A-P2", ChamberCode::P2, b"U-2A", true),
    m(b"M-U2B-P1", ChamberCode::P1, b"U-2B", true),
    m(b"M-U2B-P2", ChamberCode::P2, b"U-2B", true),
];

/// The chamber members of `Draft::standard` (P1 and P2 have two).
const fn members(chamber: ChamberCode) -> u8 {
    match chamber {
        ChamberCode::P1 | ChamberCode::P2 => 2,
        ChamberCode::P3
        | ChamberCode::P4
        | ChamberCode::J
        | ChamberCode::A
        | ChamberCode::C
        | ChamberCode::N => 1,
    }
}

/// The trustee key number and identifier of the first member of
/// `chamber`.
fn member(chamber: ChamberCode) -> (u16, &'static [u8]) {
    match chamber {
        ChamberCode::P1 => (0, b"T-P1-1"),
        ChamberCode::P2 => (2, b"T-P2-1"),
        ChamberCode::J => (4, b"T-J"),
        ChamberCode::A => (5, b"T-A"),
        ChamberCode::C => (6, b"T-C"),
        ChamberCode::P3 | ChamberCode::P4 | ChamberCode::N => (7, b"T-N"),
    }
}

fn party_prf(chamber: ChamberCode) -> &'static [u8; 32] {
    if chamber == ChamberCode::P1 {
        &PRF_P1
    } else {
        &PRF_P2
    }
}

/// An attendee of a provisioning record or ceremony: identifier and key.
type Signer = (&'static [u8], &'static HybridSigningKey);

fn committee() -> Signer {
    (b"committee", signing(COMMITTEE))
}

fn observer(name: &'static [u8]) -> Signer {
    let n = if name == b"obs-a" { 2 } else { 3 };
    (name, signing(ROSTER_BASE + n))
}

/// Signatures of `signers` over `message` under `purpose`, ascending.
fn actor_sigs(signers: &[Signer], purpose: &[u8], message: &[u8]) -> Vec<ActorSig<'static>> {
    let mut sorted = signers.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    sorted
        .iter()
        .map(|(name, key)| ActorSig {
            actor_id: id(name),
            sig: sign(key, purpose, message),
        })
        .collect()
}

/// What is wrong with a provisioning record a genesis pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flaw {
    Device,
    Members,
    Chamber,
    Entropy,
    NoKeyCheck,
    SecureElementOnly,
    OtherKeyCheck,
    BoxKeyCheck,
    NoCommittee,
    NoMember,
    OneOrg,
    Forged,
    Stranger,
}

/// The provisioning record of module `n`, with `flaw` if any.
fn provisioning(n: usize, flaw: Option<Flaw>) -> &'static [u8] {
    provisioning_of(&MODULES[n], flaw)
}

/// The provisioning record of `module`, with `flaw` if any.
fn provisioning_of(module: &Module, flaw: Option<Flaw>) -> &'static [u8] {
    let party_unit = module.unit && matches!(module.chamber, ChamberCode::P1 | ChamberCode::P2);
    let mut parts = ModuleProvisionedParts {
        election_id: election(),
        module_id: ModuleId::new(module.name).unwrap(),
        device_id: id(module.device),
        chamber: module.chamber,
        member_count: members(module.chamber),
        pad_length: 1 << 20,
        chassis_id: id(b"CH-1"),
        pad_card_id: id(b"PAD-1"),
        reprovision_count: 0,
        chassis_check_hash: Hash512([0x4C; 64]),
        kem_ek: &KEM,
        entropy_commitment: Hash512([0x5D; 64]),
        se_present: party_unit,
        prf_key_check: party_unit.then(|| party_prf(module.chamber)),
    };
    match flaw {
        Some(Flaw::Device) => parts.device_id = id(b"U-2B"),
        Some(Flaw::Members) => parts.member_count += 1,
        Some(Flaw::Chamber) => parts.chamber = ChamberCode::P2,
        Some(Flaw::Entropy) => parts.entropy_commitment = Hash512::ZERO,
        Some(Flaw::NoKeyCheck) => {
            parts.se_present = false;
            parts.prf_key_check = None;
        }
        Some(Flaw::SecureElementOnly) => parts.prf_key_check = None,
        Some(Flaw::OtherKeyCheck) => parts.prf_key_check = Some(&PRF_OTHER),
        Some(Flaw::BoxKeyCheck) => {
            parts.se_present = true;
            parts.prf_key_check = Some(party_prf(module.chamber));
        }
        _ => {}
    }
    let message = group(&ModuleProvisionedMessage::new(&parts).unwrap());
    let (member_n, member_id) = member(module.chamber);
    let mut signers: Vec<Signer> = std::vec![
        committee(),
        (member_id, trustee_signing(member_n)),
        observer(b"obs-a"),
        observer(b"obs-b"),
    ];
    match flaw {
        Some(Flaw::NoCommittee) => signers.retain(|s| s.0 != b"committee"),
        Some(Flaw::NoMember) => signers.retain(|s| s.0 != member_id),
        Some(Flaw::OneOrg) => signers.retain(|s| s.0 != b"obs-b"),
        Some(Flaw::Forged) => signers[0].1 = signing(SPARE_BASE),
        Some(Flaw::Stranger) => signers.push((b"T-J", trustee_signing(4))),
        _ => {}
    }
    let sigs = actor_sigs(&signers, b"module-provisioned", message);
    object(
        SCHEMA_MODULE_PROVISIONED,
        SCHEMA_VERSION_1,
        &ModuleProvisioned::new(message, &sigs).unwrap(),
    )
}

/// What is wrong with a party key ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CeremonyFlaw {
    NotAParty,
    Outsider,
    SameHsm,
    NoCommittee,
    HolderSilent,
    OneOrg,
    Forged,
    Stranger,
    Later,
    /// The same fields under other signature bytes.
    Reseeded,
}

/// The ceremony of party chamber `chamber` (P1 or P2), with `flaw`.
fn ceremony(chamber: ChamberCode, flaw: Option<CeremonyFlaw>) -> &'static [u8] {
    let (first, second): (Signer, Signer) = if chamber == ChamberCode::P1 {
        (
            (b"T-P1-1", trustee_signing(0)),
            (b"T-P1-2", trustee_signing(1)),
        )
    } else {
        (
            (b"T-P2-1", trustee_signing(2)),
            (b"T-P2-2", trustee_signing(3)),
        )
    };
    let mut holders = [
        ShareHolder {
            trustee_id: TrusteeId::new(first.0).unwrap(),
            hsm_model: id(b"YubiHSM2"),
            hsm_serial_hash: Hash512([0x81; 64]),
        },
        ShareHolder {
            trustee_id: TrusteeId::new(second.0).unwrap(),
            hsm_model: id(b"NitrokeyHSM2"),
            hsm_serial_hash: Hash512([0x82; 64]),
        },
    ];
    let mut message_chamber = chamber;
    let mut bucket = 50;
    match flaw {
        Some(CeremonyFlaw::NotAParty) => message_chamber = ChamberCode::P3,
        Some(CeremonyFlaw::Outsider) => holders[1].trustee_id = TrusteeId::new(b"T-J").unwrap(),
        Some(CeremonyFlaw::SameHsm) => holders[1].hsm_model = id(b"YubiHSM2"),
        Some(CeremonyFlaw::Later) => bucket = 51,
        _ => {}
    }
    holders.sort_by(|a, b| a.trustee_id.as_bytes().cmp(b.trustee_id.as_bytes()));
    let message = group(
        &PartyKeyMessage::new(&PartyKeyParts {
            election_id: election(),
            chamber: message_chamber,
            wrapped_module_count: 4,
            share_threshold: 2,
            share_holders: &holders,
            prf_key_check: party_prf(chamber),
            time_bucket: TimeBucket::new(bucket),
        })
        .unwrap(),
    );
    let mut signers: Vec<Signer> = std::vec![
        first,
        second,
        committee(),
        observer(b"obs-a"),
        observer(b"obs-b"),
    ];
    match flaw {
        Some(CeremonyFlaw::NoCommittee) => signers.retain(|s| s.0 != b"committee"),
        Some(CeremonyFlaw::HolderSilent) => signers.retain(|s| s.0 != second.0),
        Some(CeremonyFlaw::OneOrg) => signers.retain(|s| s.0 != b"obs-b"),
        Some(CeremonyFlaw::Forged) => signers[2].1 = signing(SPARE_BASE),
        Some(CeremonyFlaw::Stranger) => signers.push((b"T-J", trustee_signing(4))),
        _ => {}
    }
    let mut sigs = actor_sigs(&signers, b"party-key", message);
    if flaw == Some(CeremonyFlaw::Reseeded) {
        for s in &mut sigs {
            if s.actor_id.as_bytes() == b"committee" {
                s.sig = reseeded_sign(signing(COMMITTEE), b"party-key", message);
            }
        }
    }
    object(
        SCHEMA_PARTY_KEY_CEREMONY,
        SCHEMA_VERSION_1,
        &PartyKeyCeremony::new(message, &sigs).unwrap(),
    )
}

/// `key`'s signature over `message` under `purpose`, with other signing
/// randomness than `common::sign`: other bytes, the same signer.
fn reseeded_sign(
    key: &HybridSigningKey,
    purpose: &[u8],
    message: &[u8],
) -> &'static [u8; HYBRID_SIG_LEN] {
    let purpose = Purpose::new(purpose).unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(0x5EED);
    let sig = sign_hybrid(key, &purpose, message, &mut rng).unwrap();
    let mut out = [0u8; HYBRID_SIG_LEN];
    let (ml, ed) = out.split_at_mut(sig.mldsa87().len());
    ml.copy_from_slice(sig.mldsa87());
    ed.copy_from_slice(sig.ed25519());
    leak(out)
}

// ---------------------------------------------------------------------
// The world: the standard genesis whose module entries pin the records
// above, with a legal authorization for the boxes to open.

struct World {
    genesis: &'static VerifiedGenesis<'static>,
    signed_genesis: &'static [u8],
    authorization: &'static [u8],
    /// The provisioning record of each module, in `MODULES` order.
    records: Vec<&'static [u8]>,
    /// The signed amendment `amend` made, if any.
    amendment: Option<&'static [u8]>,
}

fn world_with(flaws: &[(usize, Flaw)]) -> World {
    amended_world(flaws, None)
}

/// As [`world_with`], with one amendment made by `amend` when given.
fn amended_world(flaws: &[(usize, Flaw)], amend: Option<fn(&mut Draft)>) -> World {
    spare_world(flaws, amend, &[])
}

/// As [`amended_world`], with `spares`: modules no device lists, each
/// with its key number and the record the genesis pins for it.
fn spare_world(
    flaws: &[(usize, Flaw)],
    amend: Option<fn(&mut Draft)>,
    spares: &[(Module, u16)],
) -> World {
    let flaws: BTreeMap<usize, Flaw> = flaws.iter().copied().collect();
    let mut draft = Draft::standard();
    let mut records: Vec<&'static [u8]> = (0..MODULES.len())
        .map(|n| provisioning(n, flaws.get(&n).copied()))
        .collect();
    for (spare, n) in spares {
        draft
            .modules
            .push(common::module_entry(*n, spare.name, spare.chamber));
        records.push(provisioning_of(spare, None));
    }
    for (entry, record) in draft.modules.iter_mut().zip(&records) {
        entry.provisioned_hash = object_hash(record);
    }
    let (body, authorization) = common::legal_authorization(
        &[
            ityv_encoding::Scope::PublicBoard,
            ityv_encoding::Scope::TrusteeBody,
            ityv_encoding::Scope::BallotMark,
        ],
        20_000,
        20_100,
    );
    let built = leak(sign_genesis_with(&draft, draft.raw(), &SIGNERS, |p| {
        p.legal_authorization_hash = object_hash(body);
    }));
    let amendments: Vec<_> = amend
        .map(|f| {
            let mut next = draft.clone();
            f(&mut next);
            next.appointments = next.referenced_appointments();
            common::amendment(1, built.pin, &next.raw(), &SIGNERS)
        })
        .into_iter()
        .collect();
    World {
        genesis: leak(verify_genesis(&built.pin, &built.input(), &amendments).unwrap()),
        signed_genesis: built.signed,
        authorization,
        records,
        amendment: amendments.first().map(|a| a.signed),
    }
}

fn world() -> &'static World {
    static WORLD: OnceLock<&'static World> = OnceLock::new();
    WORLD.get_or_init(|| leak(world_with(&[])))
}

// ---------------------------------------------------------------------
// Station events.

/// A `WitnessedEvent` over `body` of `schema`, signed by the people
/// `who` (identifier, role) and, when given, the box device `device`.
fn witnessed(
    schema: SchemaId,
    body: &'static [u8],
    who: &[(&'static [u8], EventRole)],
    device: Option<(&'static [u8], u16)>,
) -> &'static [u8] {
    let purpose = purpose_of(schema).unwrap();
    let person = |name: &[u8]| -> (&'static [u8], u16) {
        match name {
            b"clerk-1" => (b"ORG-ST", 0),
            b"clerk-2" => (b"ORG-ST", 1),
            b"obs-a" => (b"PARTY-A", 2),
            _ => (b"PARTY-B", 3),
        }
    };
    let mut parts: Vec<(&'static [u8], EventRole, &'static [u8], u16)> = who
        .iter()
        .map(|&(name, role)| {
            let (o, n) = person(name);
            (name, role, o, ROSTER_BASE + n)
        })
        .collect();
    if let Some((box_id, n)) = device {
        parts.push((box_id, EventRole::Device, b"ORG-ST", BOX_DEVICE_BASE + n));
    }
    parts.sort_by(|a, b| a.0.cmp(b.0));
    let sigs: Vec<EventSig<'static>> = parts
        .iter()
        .map(|&(name, role, o, n)| EventSig {
            signer_id: SignerId::new(name).unwrap(),
            role,
            org_id: OrgId::new(o).unwrap(),
            sig: sign(signing(n), purpose, body),
        })
        .collect();
    object(
        SCHEMA_WITNESSED_EVENT,
        SCHEMA_VERSION_1,
        &WitnessedEvent::new(body, &sigs).unwrap(),
    )
}

const WITNESSES: [(&[u8], EventRole); 4] = [
    (b"clerk-1", EventRole::Clerk),
    (b"clerk-2", EventRole::Clerk),
    (b"obs-a", EventRole::Observer),
    (b"obs-b", EventRole::Observer),
];

const OBSERVERS: [(&[u8], EventRole); 2] = [
    (b"obs-a", EventRole::Observer),
    (b"obs-b", EventRole::Observer),
];

/// The boxes: identifier, device key number, modules.
/// A box: identifier, device key number, modules.
type BoxSpec = (&'static [u8], u16, &'static [&'static [u8]]);

const BOXES: [BoxSpec; 3] = [
    (b"BOX-1", 0, &[b"M-B1-P1", b"M-B1-P2"]),
    (b"BOX-2", 1, &[b"M-B2-J", b"M-B2-P1", b"M-B2-P2"]),
    (b"BOX-3", 2, &[b"M-B3-A", b"M-B3-P1", b"M-B3-P2"]),
];

fn opened(b: usize) -> &'static [u8] {
    let (box_id, n, mods) = BOXES[b];
    let body = BoxOpenedBody::new(&BoxOpenedParts {
        election_id: election(),
        box_id: BoxId::new(box_id).unwrap(),
        modules: modules(mods),
        seal_digest: SEAL,
        seals_match: true,
        initial_count: 0,
        time_bucket: TimeBucket::new(OPEN_BUCKET),
    });
    let body = object(SCHEMA_BOX_OPENED_BODY, SCHEMA_VERSION_1, &body);
    witnessed(SCHEMA_BOX_OPENED_BODY, body, &WITNESSES, Some((box_id, n)))
}

/// The close of box `b` with `without_record` ballots and no records.
fn closed(b: usize, without_record: u64) -> &'static [u8] {
    let (box_id, n, mods) = BOXES[b];
    let counters: Vec<ModuleCounter<'static>> = mods
        .iter()
        .map(|m| ModuleCounter {
            module_id: ModuleId::new(m).unwrap(),
            counter: 0,
        })
        .collect();
    let body = BoxCloseBody::new(&BoxCloseParts {
        election_id: election(),
        box_id: BoxId::new(box_id).unwrap(),
        counts: CloseCounts {
            paper: without_record,
            records: 0,
            attested: 0,
            without_record,
            challenged: 0,
            quarantined: 0,
            visits: 0,
            envelopes: 0,
            stickers: 0,
            spoil_envelopes: 0,
        },
        record_set_root: Hash512([0x23; 64]),
        journal_head: Hash512([0x24; 64]),
        seal_digest: SEAL,
        module_counters: ModuleCounters::new(&counters).unwrap(),
        open_batches: 0,
        time_bucket: TimeBucket::new(CLOSE_BUCKET),
    });
    let body = object(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, &body);
    let attestations: Vec<Attestation<'static>> = [
        (
            b"clerk-1".as_slice(),
            SignerRole::Clerk,
            b"ORG-ST".as_slice(),
            0,
        ),
        (b"clerk-2", SignerRole::Clerk, b"ORG-ST", 1),
        (b"obs-a", SignerRole::Observer, b"PARTY-A", 2),
        (b"obs-b", SignerRole::Observer, b"PARTY-B", 3),
    ]
    .iter()
    .map(|&(name, role, o, k)| Attestation {
        signer_id: SignerId::new(name).unwrap(),
        role,
        org_id: OrgId::new(o).unwrap(),
        sig: sign(signing(ROSTER_BASE + k), b"box-close", body),
    })
    .collect();
    let device = sign(signing(BOX_DEVICE_BASE + n), b"box-close", body);
    object(
        SCHEMA_BOX_CLOSE,
        SCHEMA_VERSION_1,
        &BoxClose::new(body, Some(device), &attestations).unwrap(),
    )
}

/// The observers' count of `station` read from `unit`.
fn observer_count(
    station: &'static [u8],
    unit: &'static [u8],
    count: u64,
    kind: ObserverCountKind,
) -> &'static [u8] {
    let body = ObserverCountAttestBody::new(&ObserverCountParts {
        election_id: election(),
        station_id: StationId::new(station).unwrap(),
        unit_id: UnitId::new(unit).unwrap(),
        count,
        kind,
        time_bucket: TimeBucket::new(CLOSE_BUCKET),
    });
    let body = object(SCHEMA_OBSERVER_COUNT_ATTEST_BODY, SCHEMA_VERSION_1, &body);
    witnessed(SCHEMA_OBSERVER_COUNT_ATTEST_BODY, body, &OBSERVERS, None)
}

/// The issuance count of `station`: `issued` ballots, `spoiled` of them
/// spoiled by voters, a stock of 10.
fn issuance(station: &'static [u8], issued: u64, spoiled: u64) -> &'static [u8] {
    let body = IssuanceCountBody::new(&IssuanceCountParts {
        election_id: election(),
        station_id: StationId::new(station).unwrap(),
        stock_received: 10,
        issued,
        voter_spoiled: spoiled,
        returned: 0,
        unused: 10 - issued,
        printer_waste: 0,
        envelopes: None,
        time_bucket: TimeBucket::new(CLOSE_BUCKET),
    });
    let body = object(SCHEMA_ISSUANCE_COUNT_BODY, SCHEMA_VERSION_1, &body);
    witnessed(SCHEMA_ISSUANCE_COUNT_BODY, body, &WITNESSES, None)
}

/// The check-in units: identifier, key number, party modules (key
/// numbers, P1 then P2).
const UNITS: [(&[u8], u16, [u16; 2]); 4] = [
    (b"U-1A", 0, [8, 9]),
    (b"U-1B", 1, [10, 11]),
    (b"U-2A", 2, [12, 13]),
    (b"U-2B", 3, [14, 15]),
];

/// What is wrong with a participation set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetFlaw {
    ForgedCounter,
    Swapped,
    OneModule,
    ForeignModule,
    ForgedModule,
}

/// The participation set of `station` signed by unit `u` (an index into
/// `UNITS`), with one pseudonym per byte of `fills`.
fn participation(
    station: &'static [u8],
    u: usize,
    fills: &[u8],
    flaw: Option<SetFlaw>,
) -> &'static [u8] {
    let mut sorted = fills.to_vec();
    sorted.sort_unstable();
    let bytes: Vec<u8> = sorted.iter().flat_map(|f| [*f; 64]).collect();
    let message = group(&ParticipationMessage {
        election_id: election(),
        station_id: StationId::new(station).unwrap(),
        pseudonyms: Pseudonyms::new(leak_slice(bytes)).unwrap(),
    });
    let (_, unit_n, mods) = UNITS[u];
    let counter_key = if flaw == Some(SetFlaw::ForgedCounter) {
        signing(SPARE_BASE)
    } else {
        unit_signing(unit_n)
    };
    let counter = sign(counter_key, b"participation-set", message);
    let mut modules: Vec<(u16, &'static HybridSigningKey)> =
        mods.iter().map(|&n| (n, module_signing(n))).collect();
    match flaw {
        Some(SetFlaw::Swapped) => modules.swap(0, 1),
        Some(SetFlaw::OneModule) => modules.truncate(1),
        Some(SetFlaw::ForeignModule) => modules[1] = (15, module_signing(15)),
        Some(SetFlaw::ForgedModule) => modules[1].1 = signing(SPARE_BASE + 1),
        _ => {}
    }
    let sigs: Vec<ParticipationModuleSig<'static>> = modules
        .iter()
        .map(|&(n, key)| ParticipationModuleSig {
            module_id: ModuleId::new(MODULES[usize::from(n)].name).unwrap(),
            sig: sign(key, b"participation-set", message),
        })
        .collect();
    object(
        SCHEMA_PARTICIPATION_SET,
        SCHEMA_VERSION_1,
        &ParticipationSet::new(message, counter, &sigs).unwrap(),
    )
}

// ---------------------------------------------------------------------
// Running the stages.

fn key_events(world: &World) -> Vec<(SchemaId, &'static [u8])> {
    let mut events = std::vec![
        (SCHEMA_PARTY_KEY_CEREMONY, ceremony(ChamberCode::P1, None)),
        (SCHEMA_PARTY_KEY_CEREMONY, ceremony(ChamberCode::P2, None)),
    ];
    events.extend(
        world
            .records
            .iter()
            .map(|r| (SCHEMA_MODULE_PROVISIONED, *r)),
    );
    events
}

fn w(event: &'static [u8]) -> (SchemaId, &'static [u8]) {
    (SCHEMA_WITNESSED_EVENT, event)
}

/// Every box opened and closed (ST-1: 2 + 1 ballots, ST-2: 2), the
/// observers' final counts (3 and 2) and the issuance counts (ST-1: 4
/// issued, 1 spoiled; ST-2: 2 issued).
fn station_events() -> Vec<(SchemaId, &'static [u8])> {
    std::vec![
        w(opened(0)),
        w(opened(1)),
        w(opened(2)),
        w(observer_count(
            b"ST-1",
            b"U-1A",
            3,
            ObserverCountKind::Final
        )),
        w(observer_count(
            b"ST-2",
            b"U-2A",
            2,
            ObserverCountKind::Final
        )),
        w(issuance(b"ST-1", 4, 1)),
        w(issuance(b"ST-2", 2, 0)),
        (SCHEMA_BOX_CLOSE, closed(0, 2)),
        (SCHEMA_BOX_CLOSE, closed(1, 1)),
        (SCHEMA_BOX_CLOSE, closed(2, 2)),
    ]
}

fn sets() -> Vec<(SchemaId, &'static [u8])> {
    std::vec![
        (
            SCHEMA_PARTICIPATION_SET,
            participation(b"ST-1", 0, &[1, 2, 3], None)
        ),
        (
            SCHEMA_PARTICIPATION_SET,
            participation(b"ST-2", 2, &[4, 5], None)
        ),
    ]
}

/// The whole ledger of a clean election.
fn clean(world: &World) -> Vec<(SchemaId, &'static [u8])> {
    let mut events = key_events(world);
    events.extend(station_events());
    events.extend(sets());
    events
}

struct Run {
    index: &'static LedgerIndex<'static>,
    stage: ParticipationStage<'static>,
}

fn run_in(world: &World, events: &[(SchemaId, &'static [u8])]) -> Run {
    let mut ledger = Ledger::new();
    ledger
        .push(SCHEMA_SIGNED_GENESIS, world.signed_genesis)
        .push(SCHEMA_SIGNED_LEGAL_AUTHORIZATION, world.authorization);
    for &(schema, event) in events {
        ledger.push(schema, event);
    }
    let index = leak(build_index(world.genesis, ledger.bytes(), &ledger.events));
    assert!(index.ledger_holds().is_empty(), "{:?}", index.findings());
    let authority = leak(authorize_ledger(world.genesis, index));
    let boxes = leak(verify_boxes(world.genesis, index, authority));
    let records = leak(verify_records(world.genesis, index, boxes));
    Run {
        index,
        stage: verify_participation(world.genesis, index, boxes, records),
    }
}

fn go(events: &[(SchemaId, &'static [u8])]) -> Run {
    run_in(world(), events)
}

fn only(reason: HoldReason) -> HoldSet {
    HoldSet::empty().with(reason)
}

// ---------------------------------------------------------------------
// The clean election.

#[test]
fn a_clean_election_is_complete_and_holds_nothing() {
    let run = go(&clean(world()));
    let stage = &run.stage;
    assert!(stage.complete());
    assert_eq!(stage.holds(), HoldSet::empty());
    assert!(stage.set_findings().is_empty());
    assert!(stage.key_findings().is_empty());
    assert_eq!(stage.duplicates(), 0);
    assert!(stage.missing_ceremonies().is_empty());
    assert!(stage.missing_provisioning().is_empty());
    let chambers: Vec<ChamberCode> = stage.ceremonies().iter().map(|c| c.0).collect();
    assert_eq!(chambers, [ChamberCode::P1, ChamberCode::P2]);
    assert_eq!(stage.ceremonies()[0].1.get(), 3);
    assert_eq!(stage.stations().len(), 2);
    let st1 = stage.station(b"ST-1").unwrap();
    assert_eq!(st1.count, Some(3));
    assert_eq!(st1.observers, Some(3));
    assert!(st1.set.is_some() && st1.issuance.is_some() && st1.closed);
    assert!(st1.complete());
    assert_eq!(st1.holds, HoldSet::empty());
    let st2 = stage.station(b"ST-2").unwrap();
    assert_eq!((st2.count, st2.observers), (Some(2), Some(2)));
    assert!(stage.station(b"ST-9").is_none());
}

#[test]
fn the_index_scopes_the_new_events() {
    let run = go(&clean(world()));
    let scope_of = |schema: SchemaId| -> Vec<EventScope<'static>> {
        run.index
            .events()
            .iter()
            .filter(|e| e.schema == schema)
            .map(|e| e.scope)
            .collect()
    };
    assert!(
        scope_of(SCHEMA_PARTY_KEY_CEREMONY)
            .iter()
            .all(|s| *s == EventScope::Election)
    );
    let provisioning = scope_of(SCHEMA_MODULE_PROVISIONED);
    assert_eq!(
        provisioning[0],
        EventScope::Box(BoxId::new(b"BOX-1").unwrap())
    );
    assert_eq!(
        provisioning[8],
        EventScope::Station(StationId::new(b"ST-1").unwrap())
    );
    assert_eq!(
        scope_of(SCHEMA_PARTICIPATION_SET),
        [
            EventScope::Station(StationId::new(b"ST-1").unwrap()),
            EventScope::Station(StationId::new(b"ST-2").unwrap()),
        ]
    );
}

// ---------------------------------------------------------------------
// What is not yet on the ledger.

#[test]
fn what_is_missing_leaves_the_stage_incomplete_without_a_hold() {
    let world = world();
    // No ceremony of P2, no record of module 15, no set of ST-2.
    let mut events = key_events(world);
    events.remove(1);
    events.pop();
    events.extend(station_events());
    events.push(sets()[0]);
    let run = go(&events);
    let stage = &run.stage;
    assert!(!stage.complete());
    assert_eq!(stage.holds(), HoldSet::empty());
    assert_eq!(stage.missing_ceremonies(), [ChamberCode::P2]);
    assert_eq!(stage.missing_provisioning().len(), 1);
    assert_eq!(
        stage.missing_provisioning()[0].0.as_bytes(),
        MODULES[15].name
    );
    assert_eq!(
        stage.missing_provisioning()[0].1,
        object_hash(world.records[15])
    );
    let st2 = stage.station(b"ST-2").unwrap();
    assert_eq!((st2.set, st2.count), (None, None));
    assert!(!st2.complete());
    assert!(stage.station(b"ST-1").unwrap().complete());
}

/// A check of one station's report.
type Check = fn(&StationParticipation<'_>) -> bool;

#[test]
fn each_station_identity_needs_its_own_evidence() {
    let world = world();
    let cases: [(usize, Check); 4] = [
        // No final observer count of ST-1.
        (3, |s| s.observers.is_none()),
        // No issuance count of ST-1.
        (5, |s| s.issuance.is_none()),
        // BOX-1 not closed.
        (7, |s| !s.closed),
        // BOX-1 not opened, so its close is refused: still not closed.
        (0, |s| !s.closed),
    ];
    for (drop, check) in cases {
        let mut events = key_events(world);
        let mut station = station_events();
        station.remove(drop);
        events.extend(station);
        events.extend(sets());
        let run = go(&events);
        let st1 = run.stage.station(b"ST-1").unwrap();
        assert!(check(st1), "dropping {drop}");
        assert!(!st1.complete(), "dropping {drop}");
        assert!(!run.stage.complete());
        assert!(run.stage.station(b"ST-2").unwrap().complete());
    }
}

#[test]
fn a_periodic_count_is_not_the_final_count() {
    let world = world();
    let mut events = key_events(world);
    let mut station = station_events();
    station[3] = w(observer_count(
        b"ST-1",
        b"U-1A",
        3,
        ObserverCountKind::Periodic,
    ));
    events.extend(station);
    events.extend(sets());
    let run = go(&events);
    assert_eq!(run.stage.station(b"ST-1").unwrap().observers, None);
}

// ---------------------------------------------------------------------
// The identities.

#[test]
fn a_count_other_than_the_observers_final_count_is_a_mismatch() {
    let world = world();
    let mut events = key_events(world);
    let mut station = station_events();
    // The last final count wins: 4 after 3.
    station.insert(
        4,
        w(observer_count(
            b"ST-1",
            b"U-1A",
            4,
            ObserverCountKind::Final,
        )),
    );
    events.extend(station);
    events.extend(sets());
    let run = go(&events);
    let st1 = run.stage.station(b"ST-1").unwrap();
    assert_eq!(st1.observers, Some(4));
    // 3 pseudonyms against 4; and 4 − 1 spoiled is 3 against 4 too.
    assert_eq!(st1.holds, only(HoldReason::ParticipationMismatch));
    assert_eq!(run.stage.holds(), only(HoldReason::ParticipationMismatch));
    assert!(run.stage.complete());
}

#[test]
fn the_issuance_identities_reach_the_station() {
    let world = world();
    for (issued, spoiled, expected) in [
        // 5 issued, 1 spoiled: 5 ≠ 3 + 1, and 5 − 1 = 4 ≠ 3 checked in.
        (
            5,
            1,
            HoldSet::empty()
                .with(HoldReason::IssuanceMismatch)
                .with(HoldReason::ParticipationMismatch),
        ),
        // 4 issued, 0 spoiled: 4 ≠ 3 + 0, and 4 ≠ 3 checked in.
        (
            4,
            0,
            HoldSet::empty()
                .with(HoldReason::IssuanceMismatch)
                .with(HoldReason::ParticipationMismatch),
        ),
    ] {
        let mut events = key_events(world);
        let mut station = station_events();
        station[5] = w(issuance(b"ST-1", issued, spoiled));
        events.extend(station);
        events.extend(sets());
        let run = go(&events);
        assert_eq!(run.stage.station(b"ST-1").unwrap().holds, expected);
        assert_eq!(run.stage.holds(), expected);
    }
}

#[test]
fn a_repeated_pseudonym_is_held_wherever_it_is() {
    let world = world();
    // Across stations: pseudonym 2 at ST-1 and ST-2.
    let mut events = key_events(world);
    events.extend(station_events());
    events.push((
        SCHEMA_PARTICIPATION_SET,
        participation(b"ST-1", 0, &[1, 2, 3], None),
    ));
    events.push((
        SCHEMA_PARTICIPATION_SET,
        participation(b"ST-2", 2, &[2, 5], None),
    ));
    let run = go(&events);
    assert_eq!(run.stage.duplicates(), 1);
    for station in [b"ST-1", b"ST-2"] {
        assert_eq!(
            run.stage.station(station).unwrap().holds,
            only(HoldReason::DuplicatePseudonym)
        );
    }
    assert_eq!(run.stage.holds(), only(HoldReason::DuplicatePseudonym));

    // Within one station, three times: two repeats, ST-2 untouched.
    let mut events = key_events(world);
    events.extend(station_events());
    events.push((
        SCHEMA_PARTICIPATION_SET,
        participation(b"ST-1", 0, &[7, 7, 7], None),
    ));
    events.push((
        SCHEMA_PARTICIPATION_SET,
        participation(b"ST-2", 2, &[4, 5], None),
    ));
    let run = go(&events);
    assert_eq!(run.stage.duplicates(), 2);
    assert_eq!(
        run.stage.station(b"ST-1").unwrap().holds,
        only(HoldReason::DuplicatePseudonym)
    );
    assert_eq!(run.stage.station(b"ST-2").unwrap().holds, HoldSet::empty());
}

// ---------------------------------------------------------------------
// Participation sets that cannot be taken.

fn set_problems(run: &Run) -> Vec<(u64, SetProblem)> {
    run.stage
        .set_findings()
        .iter()
        .map(|f| (f.seq.get(), f.problem))
        .collect()
}

#[test]
fn a_set_must_be_signed_by_a_unit_and_its_party_modules_in_order() {
    let world = world();
    for flaw in [
        SetFlaw::ForgedCounter,
        SetFlaw::Swapped,
        SetFlaw::OneModule,
        SetFlaw::ForeignModule,
        SetFlaw::ForgedModule,
    ] {
        let mut events = clean(world);
        let n = events.len();
        events[n - 2] = (
            SCHEMA_PARTICIPATION_SET,
            participation(b"ST-1", 0, &[1, 2, 3], Some(flaw)),
        );
        let run = go(&events);
        let expected = if flaw == SetFlaw::ForgedCounter {
            SetProblem::CounterSignature
        } else {
            SetProblem::ModuleSignatures
        };
        let seq = 2 + n as u64 - 1;
        assert_eq!(set_problems(&run), [(seq, expected)], "{flaw:?}");
        assert_eq!(run.stage.set_findings()[0].station_id.as_bytes(), b"ST-1");
        assert_eq!(
            run.stage.holds(),
            only(HoldReason::ParticipationSetInvalid),
            "{flaw:?}"
        );
        let st1 = run.stage.station(b"ST-1").unwrap();
        assert_eq!((st1.set, st1.count), (None, None), "{flaw:?}");
        assert!(!run.stage.complete());
    }
}

#[test]
fn the_spare_unit_may_sign_with_its_own_modules() {
    let world = world();
    let mut events = clean(world);
    let n = events.len();
    events[n - 2] = (
        SCHEMA_PARTICIPATION_SET,
        participation(b"ST-1", 1, &[1, 2, 3], None),
    );
    let run = go(&events);
    assert!(run.stage.set_findings().is_empty());
    assert!(run.stage.complete());
    // Another station's unit may not.
    events[n - 2] = (
        SCHEMA_PARTICIPATION_SET,
        participation(b"ST-1", 2, &[1, 2, 3], None),
    );
    let run = go(&events);
    assert_eq!(
        run.stage.set_findings()[0].problem,
        SetProblem::CounterSignature
    );
}

#[test]
fn a_second_set_for_a_station_conflicts_unless_it_is_the_same() {
    let world = world();
    let mut events = clean(world);
    // The same pseudonyms signed by the spare unit: the same set.
    events.push((
        SCHEMA_PARTICIPATION_SET,
        participation(b"ST-1", 1, &[1, 2, 3], None),
    ));
    let run = go(&events);
    assert!(run.stage.set_findings().is_empty());
    assert_eq!(run.stage.holds(), HoldSet::empty());
    // Other pseudonyms: a conflict; the first set stands.
    events.push((
        SCHEMA_PARTICIPATION_SET,
        participation(b"ST-1", 1, &[1, 2, 4], None),
    ));
    let run = go(&events);
    assert_eq!(
        set_problems(&run),
        [(2 + events.len() as u64, SetProblem::Conflict)]
    );
    assert_eq!(run.stage.holds(), only(HoldReason::ParticipationSetInvalid));
    let st1 = run.stage.station(b"ST-1").unwrap();
    assert_eq!(st1.set.unwrap().get(), 2 + events.len() as u64 - 3);
    assert_eq!(st1.holds, HoldSet::empty());
}

// ---------------------------------------------------------------------
// Party key ceremonies.

fn key_problems(run: &Run) -> Vec<(u64, SchemaId, KeyProblem)> {
    run.stage
        .key_findings()
        .iter()
        .map(|f| (f.seq.get(), f.schema, f.problem))
        .collect()
}

#[test]
fn a_ceremony_needs_its_party_its_holders_and_every_signer_group() {
    let world = world();
    for (flaw, problem) in [
        (CeremonyFlaw::NotAParty, KeyProblem::NotAParty),
        (CeremonyFlaw::Outsider, KeyProblem::Fields),
        (CeremonyFlaw::SameHsm, KeyProblem::Fields),
        (CeremonyFlaw::NoCommittee, KeyProblem::Signers),
        (CeremonyFlaw::HolderSilent, KeyProblem::Signers),
        (CeremonyFlaw::OneOrg, KeyProblem::Signers),
        (CeremonyFlaw::Forged, KeyProblem::Signature),
        (CeremonyFlaw::Stranger, KeyProblem::Signature),
    ] {
        let mut events = clean(world);
        events[1] = (
            SCHEMA_PARTY_KEY_CEREMONY,
            ceremony(ChamberCode::P2, Some(flaw)),
        );
        let run = go(&events);
        assert_eq!(
            key_problems(&run),
            [(4, SCHEMA_PARTY_KEY_CEREMONY, problem)],
            "{flaw:?}"
        );
        assert_eq!(
            run.stage.holds(),
            only(HoldReason::KeyProvisioningInvalid),
            "{flaw:?}"
        );
        assert_eq!(
            run.stage.missing_ceremonies(),
            [ChamberCode::P2],
            "{flaw:?}"
        );
        assert!(!run.stage.complete());
    }
}

#[test]
fn the_same_ceremony_under_other_signature_bytes_is_no_conflict() {
    let world = world();
    let again = ceremony(ChamberCode::P1, Some(CeremonyFlaw::Reseeded));
    assert_ne!(again, ceremony(ChamberCode::P1, None));
    let mut events = clean(world);
    events.insert(2, (SCHEMA_PARTY_KEY_CEREMONY, again));
    let run = go(&events);
    assert!(run.stage.key_findings().is_empty());
    assert_eq!(run.stage.holds(), HoldSet::empty());
    assert_eq!(run.stage.ceremonies()[0].1.get(), 3);
    assert!(run.stage.complete());
}

#[test]
fn a_second_ceremony_with_other_fields_conflicts() {
    let world = world();
    let mut events = clean(world);
    events.insert(
        2,
        (
            SCHEMA_PARTY_KEY_CEREMONY,
            ceremony(ChamberCode::P1, Some(CeremonyFlaw::Later)),
        ),
    );
    let run = go(&events);
    assert_eq!(
        key_problems(&run),
        [(5, SCHEMA_PARTY_KEY_CEREMONY, KeyProblem::Conflict)]
    );
    assert_eq!(
        run.stage.ceremonies()[0],
        (ChamberCode::P1, ityv_encoding::Seq::new(3).unwrap())
    );
    assert!(run.stage.missing_ceremonies().is_empty());
}

// ---------------------------------------------------------------------
// Module provisioning records.

/// A world whose genesis pins one flawed record per module listed.
fn flawed_world() -> &'static World {
    static WORLD: OnceLock<&'static World> = OnceLock::new();
    WORLD.get_or_init(|| {
        leak(world_with(&[
            (0, Flaw::Device),
            (1, Flaw::Members),
            (2, Flaw::Chamber),
            (3, Flaw::Entropy),
            (4, Flaw::NoCommittee),
            (5, Flaw::NoMember),
            (6, Flaw::OneOrg),
            (7, Flaw::Forged),
            (8, Flaw::NoKeyCheck),
            (9, Flaw::OtherKeyCheck),
            (10, Flaw::Stranger),
            (11, Flaw::SecureElementOnly),
        ]))
    })
}

#[test]
fn a_pinned_record_must_agree_with_the_genesis_and_be_signed_by_all_three_groups() {
    let world = flawed_world();
    let run = go_in(world, &clean(world));
    // Frames: genesis 1, authorization 2, ceremonies 3 and 4, then the
    // records of modules 0..16 at 5..21.
    let expected: Vec<(u64, SchemaId, KeyProblem)> = [
        KeyProblem::Fields,            // 0: another device
        KeyProblem::Fields,            // 1: not the chamber's member count
        KeyProblem::Fields,            // 2: another chamber
        KeyProblem::EntropyCommitment, // 3
        KeyProblem::Signers,           // 4: no committee
        KeyProblem::Signers,           // 5: no member of the chamber
        KeyProblem::Signers,           // 6: observers of one organisation
        KeyProblem::Signature,         // 7: a forged committee signature
        KeyProblem::KeyCheck,          // 8: a unit's party module without one
        KeyProblem::KeyCheck,          // 9: not the ceremony's
        KeyProblem::Signature,         // 10: a member of another chamber
        KeyProblem::KeyCheck,          // 11: a secure element but no check
    ]
    .iter()
    .enumerate()
    .map(|(n, p)| (5 + n as u64, SCHEMA_MODULE_PROVISIONED, *p))
    .collect();
    assert_eq!(key_problems(&run), expected);
    assert_eq!(run.stage.holds(), only(HoldReason::KeyProvisioningInvalid));
    assert_eq!(run.stage.missing_provisioning().len(), 12);
    // Only the provisioning is missing.
    assert!(run.stage.missing_ceremonies().is_empty());
    assert!(
        run.stage
            .stations()
            .iter()
            .all(StationParticipation::complete)
    );
    assert!(!run.stage.complete());
}

#[test]
fn a_box_party_module_carries_no_key_check() {
    let world = leak(world_with(&[(0, Flaw::BoxKeyCheck)]));
    let run = go_in(world, &clean(world));
    assert_eq!(
        key_problems(&run),
        [(5, SCHEMA_MODULE_PROVISIONED, KeyProblem::KeyCheck)]
    );
}

#[test]
fn a_record_the_genesis_does_not_pin_is_refused() {
    let world = world();
    let mut events = clean(world);
    // Module 0's record with a flaw: another object than the pinned one.
    events.insert(
        2,
        (
            SCHEMA_MODULE_PROVISIONED,
            provisioning(0, Some(Flaw::Entropy)),
        ),
    );
    let run = go(&events);
    assert_eq!(
        key_problems(&run),
        [(5, SCHEMA_MODULE_PROVISIONED, KeyProblem::NotPinned)]
    );
    // The pinned one still provisions the module.
    assert!(run.stage.missing_provisioning().is_empty());
}

#[test]
fn without_its_ceremony_a_unit_module_still_needs_a_key_check() {
    let world = world();
    let mut events = clean(world);
    events.remove(0);
    let run = go(&events);
    assert!(run.stage.key_findings().is_empty());
    assert_eq!(run.stage.missing_ceremonies(), [ChamberCode::P1]);
    // Only the ceremony is missing.
    assert!(run.stage.missing_provisioning().is_empty());
    assert!(
        run.stage
            .stations()
            .iter()
            .all(StationParticipation::complete)
    );
    assert!(!run.stage.complete());
    let flawed = leak(world_with(&[(8, Flaw::NoKeyCheck)]));
    let mut events = clean(flawed);
    events.remove(0);
    let run = go_in(flawed, &events);
    assert_eq!(
        key_problems(&run),
        [(12, SCHEMA_MODULE_PROVISIONED, KeyProblem::KeyCheck)]
    );
}

fn go_in(world: &World, events: &[(SchemaId, &'static [u8])]) -> Run {
    run_in(world, events)
}

#[test]
fn a_key_finding_does_not_touch_the_stations() {
    let world = flawed_world();
    let run = go_in(world, &clean(world));
    assert_eq!(run.stage.key_findings().len(), 12);
    for s in run.stage.stations() {
        assert_eq!(s.holds, HoldSet::empty());
        assert!(s.complete());
    }
}

// ---------------------------------------------------------------------
// Amendments.

/// Station `ST-2` becomes `ST-3`, with the same units and box.
fn rename_station(d: &mut Draft) {
    d.stations[1] = common::station(
        b"ST-3",
        StationKind::EarlyVoting,
        common::checkin_unit(2, b"U-2A", &[b"M-U2A-P1", b"M-U2A-P2"]),
        common::checkin_unit(3, b"U-2B", &[b"M-U2B-P1", b"M-U2B-P2"]),
        &[b"BOX-3"],
        &[],
    );
    d.boxes[2] = common::genesis_box(
        2,
        b"BOX-3",
        b"ST-3",
        b"RU-2",
        &[b"M-B3-P1", b"M-B3-P2", b"M-B3-A"],
    );
    d.policies[1] = StationProgressPolicy::new(StationId::new(b"ST-3").unwrap(), 2, 8).unwrap();
}

#[test]
fn a_set_for_a_station_the_last_state_lacks_is_refused() {
    let world = leak(amended_world(&[], Some(rename_station)));
    let mut events = key_events(world);
    events.push((SCHEMA_SIGNED_GENESIS, world.amendment.unwrap()));
    events.extend(sets());
    events.push((
        SCHEMA_PARTICIPATION_SET,
        participation(b"ST-3", 2, &[4, 5], None),
    ));
    let run = go_in(world, &events);
    let n = 2 + events.len() as u64;
    // ST-2's set (signed by a unit of state 0) names a station the last
    // state does not have; ST-3's, by the same unit, is taken.
    assert_eq!(set_problems(&run), [(n - 1, SetProblem::Station)]);
    assert_eq!(run.stage.holds(), only(HoldReason::ParticipationSetInvalid));
    let ids: Vec<&[u8]> = run
        .stage
        .stations()
        .iter()
        .map(|s| s.station_id.as_bytes())
        .collect();
    assert_eq!(ids, [b"ST-1".as_slice(), b"ST-3"]);
    assert_eq!(run.stage.station(b"ST-3").unwrap().set.unwrap().get(), n);
    // Every module of both states is provisioned (the amendment pins the
    // same records).
    assert!(run.stage.missing_provisioning().is_empty());
}

// ---------------------------------------------------------------------
// Spare modules.

#[test]
fn a_spare_module_names_a_device_of_the_genesis() {
    let world = leak(spare_world(
        &[],
        None,
        &[
            // A spare party module for U-1A: a unit module, so it needs
            // the secure element and its party's key check.
            (m(b"M-SPARE-P1", ChamberCode::P1, b"U-1A", true), 16),
            // A spare judiciary module for BOX-2.
            (m(b"M-SPARE-J", ChamberCode::J, b"BOX-2", false), 17),
            // A spare for a device no state has.
            (m(b"M-SPARE-P2", ChamberCode::P2, b"BOX-9", false), 18),
        ],
    ));
    let run = go_in(world, &clean(world));
    // The records of the 16 listed modules come at frames 5 to 20, the
    // spares' at 21, 22 and 23.
    assert_eq!(
        key_problems(&run),
        [(23, SCHEMA_MODULE_PROVISIONED, KeyProblem::Fields)]
    );
    assert_eq!(run.stage.missing_provisioning().len(), 1);
    assert_eq!(
        run.stage.missing_provisioning()[0].0.as_bytes(),
        b"M-SPARE-P2"
    );
}
