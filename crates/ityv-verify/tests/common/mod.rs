//! A complete genesis for the verifier's tests: two parties, two stations,
//! three boxes, every set filled and consistent, real hybrid keys (all
//! distinct) and real signatures. A test takes [`Draft::standard`],
//! changes what it needs, encodes it with [`Draft::raw`], may change the
//! encoded sets, and signs with [`sign_genesis`]; the body always commits
//! to the sets exactly as given, so order and duplicate rules are reached.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    dead_code,
    unreachable_pub
)]

use std::boxed::Box;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use std::vec::Vec;

use ityv_crypto::{HybridSignature, HybridSigningKey, HybridVerifyingKey, Purpose, sign_hybrid};
use ityv_encoding::{
    AMENDABLE_SET_COUNT, AmendmentReason, BallotStyleEntry, BallotStyleId, BoxId, CaptureProfile,
    ChamberCode, ChamberThreshold, CheckinUnit, CustodyRoute, Day, ENTRY_SET_COUNT, ElectionId,
    Encode, EntrySet, GenesisAmendmentBody, GenesisAmendmentParts, GenesisBody, GenesisBox,
    GenesisEntry, GenesisParts, GenesisWitnessSig, HYBRID_SIG_LEN, HYBRID_VK_LEN, Hash512, Ident,
    ModuleEntry, ModuleId, ModuleIds, ObserverToken, OrgId, PartyEntry, ReportingUnitEntry,
    ReportingUnitId, RosterRole, RosterSigner, RouteId, SCHEMA_GENESIS_AMENDMENT_BODY,
    SCHEMA_GENESIS_BODY, SCHEMA_SIGNED_GENESIS, SCHEMA_VERSION_1, SCHEMA_VERSION_GENESIS, SchemaId,
    SetCommitment, SignedGenesis, SignerId, StationEntry, StationId, StationKind, StationParts,
    StationProgressPolicy, TimeBucket, TrusteeEntry, TrusteeId, UnitId, WitnessQuorum,
    WitnessRosterEntry, encode_object,
};
use ityv_ledger::{Accumulator, sorted_set_root};
use ityv_verify::{AmendableSets, AmendmentInput, FixedSets, GenesisInput};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

pub fn leak<T>(value: T) -> &'static T {
    Box::leak(Box::new(value))
}

pub fn leak_slice<T>(values: Vec<T>) -> &'static [T] {
    Box::leak(values.into_boxed_slice())
}

pub fn election() -> ElectionId<'static> {
    ElectionId::new(b"E-2028-GEN").unwrap()
}

/// A complete object of `schema` (version `version`), leaked.
pub fn object<T: Encode>(schema: SchemaId, version: u16, value: &T) -> &'static [u8] {
    let mut buf = std::vec![0u8; 16 + value.encoded_len()];
    let len = encode_object(schema, version, value, &mut buf).unwrap();
    buf.truncate(len);
    leak_slice(buf)
}

/// The signing key numbered `n`; every number gives a different key in
/// both halves.
pub fn signing(n: u16) -> &'static HybridSigningKey {
    static KEYS: OnceLock<Mutex<BTreeMap<u16, &'static HybridSigningKey>>> = OnceLock::new();
    let keys = KEYS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut keys = keys.lock().unwrap();
    keys.entry(n).or_insert_with(|| {
        let [hi, lo] = n.to_be_bytes();
        let mut ml = [0x4D; 32];
        ml[0] = hi;
        ml[1] = lo;
        let mut ed = [0x45; 32];
        ed[0] = hi;
        ed[1] = lo;
        leak(HybridSigningKey::from_seeds(ml, ed))
    })
}

/// The registered bytes of a verifying key.
pub fn key_bytes(key: &HybridVerifyingKey) -> &'static [u8; HYBRID_VK_LEN] {
    let mut out = [0u8; HYBRID_VK_LEN];
    let (ml, ed) = out.split_at_mut(key.mldsa87().len());
    ml.copy_from_slice(key.mldsa87());
    ed.copy_from_slice(key.ed25519());
    leak(out)
}

/// The registered bytes of key `n`.
pub fn registered(n: u16) -> &'static [u8; HYBRID_VK_LEN] {
    static CACHE: OnceLock<Mutex<BTreeMap<u16, &'static [u8; HYBRID_VK_LEN]>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    if let Some(k) = cache.lock().unwrap().get(&n) {
        return k;
    }
    let k = key_bytes(&signing(n).verifying_key());
    cache.lock().unwrap().insert(n, k);
    k
}

fn signature_bytes(signature: &HybridSignature) -> [u8; HYBRID_SIG_LEN] {
    let mut out = [0u8; HYBRID_SIG_LEN];
    let (ml, ed) = out.split_at_mut(signature.mldsa87().len());
    ml.copy_from_slice(signature.mldsa87());
    ed.copy_from_slice(signature.ed25519());
    out
}

/// `key`'s signature over `object` under `purpose`, as bytes.
pub fn sign(
    key: &HybridSigningKey,
    purpose: &[u8],
    object: &[u8],
) -> &'static [u8; HYBRID_SIG_LEN] {
    sign_seeded(key, purpose, object, object.len() as u64)
}

/// As [`sign`], with the hedged signing randomness drawn from `seed`: a
/// second, different signature over the same object.
pub fn sign_seeded(
    key: &HybridSigningKey,
    purpose: &[u8],
    object: &[u8],
    seed: u64,
) -> &'static [u8; HYBRID_SIG_LEN] {
    let purpose = Purpose::new(purpose).unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    leak(signature_bytes(
        &sign_hybrid(key, &purpose, object, &mut rng).unwrap(),
    ))
}

pub const COMMISSION: u16 = 1;
pub const COMMITTEE: u16 = 2;
const WITNESS_BASE: u16 = 10;
const TRUSTEE_BASE: u16 = 30;
pub const BOX_DEVICE_BASE: u16 = 100;
const BOX_ATTEST_BASE: u16 = 150;
const UNIT_BASE: u16 = 200;
const UNIT_ATTEST_BASE: u16 = 250;
pub const ROSTER_BASE: u16 = 300;
const MODULE_BASE: u16 = 400;
const MODULE_ATTEST_BASE: u16 = 500;
/// Keys a test may use for new entries without colliding.
pub const SPARE_BASE: u16 = 900;

pub const WITNESS_IDS: [&[u8]; 13] = [
    b"W01", b"W02", b"W03", b"W04", b"W05", b"W06", b"W07", b"W08", b"W09", b"W10", b"W11", b"W12",
    b"W13",
];
const ORGS: [&[u8]; 7] = [
    b"ORG-A", b"ORG-B", b"ORG-C", b"ORG-D", b"ORG-E", b"ORG-F", b"ORG-G",
];
const PROVIDERS: [&[u8]; 4] = [b"PROV-1", b"PROV-2", b"PROV-3", b"PROV-4"];
const REGIONS: [&[u8]; 3] = [b"SEOUL", b"BUSAN", b"GWANGJU"];

/// The nine witnesses that sign by default (seven organisations, four
/// providers, three regions).
pub const SIGNERS: [usize; 9] = [0, 1, 2, 3, 4, 5, 6, 7, 8];

/// Nine witnesses of only five organisations.
pub const NARROW_SIGNERS: [usize; 9] = [0, 1, 2, 3, 4, 7, 8, 9, 10];

pub fn id(bytes: &'static [u8]) -> Ident<'static> {
    Ident::new(bytes, 64).unwrap()
}

pub fn org(bytes: &'static [u8]) -> OrgId<'static> {
    OrgId::new(bytes).unwrap()
}

pub fn module(bytes: &'static [u8]) -> ModuleId<'static> {
    ModuleId::new(bytes).unwrap()
}

pub fn modules(ids: &[&'static [u8]]) -> ModuleIds<'static> {
    let mut v: Vec<ModuleId<'static>> = ids.iter().map(|m| module(m)).collect();
    v.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    ModuleIds::new(&v).unwrap()
}

/// A distinct appointment hash for entry `n`.
pub fn appointment(n: u8) -> Hash512 {
    let mut h = [0xA0; 64];
    h[0] = n;
    Hash512(h)
}

/// Everything a genesis holds, before encoding.
#[derive(Clone)]
pub struct Draft {
    pub boxes: Vec<GenesisBox<'static>>,
    pub stations: Vec<StationEntry<'static>>,
    pub policies: Vec<StationProgressPolicy<'static>>,
    pub units: Vec<ReportingUnitEntry<'static>>,
    pub routes: Vec<CustodyRoute<'static>>,
    pub roster: Vec<RosterSigner<'static>>,
    pub modules: Vec<ModuleEntry<'static>>,
    pub appointments: Vec<Hash512>,
    pub styles: Vec<BallotStyleEntry<'static>>,
    pub trustees: Vec<TrusteeEntry<'static>>,
    pub witnesses: Vec<WitnessRosterEntry<'static>>,
    pub parties: Vec<PartyEntry<'static>>,
    pub chambers: Vec<ChamberThreshold>,
    pub quorum: WitnessQuorum,
}

pub fn genesis_box(
    n: u16,
    id: &'static [u8],
    station: &'static [u8],
    unit: &'static [u8],
    mods: &[&'static [u8]],
) -> GenesisBox<'static> {
    GenesisBox {
        box_id: BoxId::new(id).unwrap(),
        station_id: StationId::new(station).unwrap(),
        ballot_style_id: BallotStyleId::new(if n == 2 { b"STYLE-2" } else { b"STYLE-1" }).unwrap(),
        profile: CaptureProfile::InPerson,
        route_id: RouteId::new(if n == 2 { b"R-2" } else { b"R-1" }).unwrap(),
        reporting_unit_id: ReportingUnitId::new(unit).unwrap(),
        device_key: registered(BOX_DEVICE_BASE + n),
        attest_key: registered(BOX_ATTEST_BASE + n),
        modules: modules(mods),
    }
}

pub fn checkin_unit(n: u16, id: &'static [u8], mods: &[&'static [u8]]) -> CheckinUnit<'static> {
    CheckinUnit {
        unit_id: UnitId::new(id).unwrap(),
        key: registered(UNIT_BASE + n),
        attest_key: registered(UNIT_ATTEST_BASE + n),
        modules: modules(mods),
    }
}

pub fn station(
    id: &'static [u8],
    kind: StationKind,
    primary: CheckinUnit<'static>,
    spare: CheckinUnit<'static>,
    boxes: &[&'static [u8]],
    tokens: &[ObserverToken<'static>],
) -> StationEntry<'static> {
    StationEntry::new(&StationParts {
        station_id: StationId::new(id).unwrap(),
        kind,
        primary,
        spare,
        boxes: leak_slice(boxes.iter().map(|b| BoxId::new(b).unwrap()).collect()),
        id_terminals_hash: Hash512([0x33; 64]),
        tokens: leak_slice(tokens.to_vec()),
    })
    .unwrap()
}

pub fn roster_signer(
    n: u16,
    id: &'static [u8],
    role: RosterRole,
    o: &'static [u8],
    station: Option<&'static [u8]>,
) -> RosterSigner<'static> {
    RosterSigner {
        signer_id: SignerId::new(id).unwrap(),
        role,
        org_id: org(o),
        station_id: station.map(|s| StationId::new(s).unwrap()),
        key: registered(ROSTER_BASE + n),
        appointment_hash: appointment(n as u8),
    }
}

pub fn module_entry(n: u16, id: &'static [u8], chamber: ChamberCode) -> ModuleEntry<'static> {
    ModuleEntry {
        module_id: module(id),
        chamber,
        key: registered(MODULE_BASE + n),
        attest_key: registered(MODULE_ATTEST_BASE + n),
        provisioned_hash: Hash512([0x44; 64]),
    }
}

pub fn token(observer: &'static [u8], o: &'static [u8], check: u8) -> ObserverToken<'static> {
    ObserverToken {
        observer_id: SignerId::new(observer).unwrap(),
        org_id: org(o),
        check_key: leak([check; 32]),
    }
}

const fn threshold(chamber: ChamberCode, threshold: u8, members: u8) -> ChamberThreshold {
    ChamberThreshold {
        chamber,
        threshold,
        members,
    }
}

impl Draft {
    /// The standard, valid genesis.
    #[allow(clippy::too_many_lines)]
    pub fn standard() -> Self {
        let boxes = std::vec![
            genesis_box(0, b"BOX-1", b"ST-1", b"RU-1", &[b"M-B1-P1", b"M-B1-P2"]),
            genesis_box(
                1,
                b"BOX-2",
                b"ST-1",
                b"RU-1",
                &[b"M-B2-P1", b"M-B2-P2", b"M-B2-J"]
            ),
            genesis_box(
                2,
                b"BOX-3",
                b"ST-2",
                b"RU-2",
                &[b"M-B3-P1", b"M-B3-P2", b"M-B3-A"]
            ),
        ];
        let stations = std::vec![
            station(
                b"ST-1",
                StationKind::ElectionDay,
                checkin_unit(0, b"U-1A", &[b"M-U1A-P1", b"M-U1A-P2"]),
                checkin_unit(1, b"U-1B", &[b"M-U1B-P1", b"M-U1B-P2"]),
                &[b"BOX-1", b"BOX-2"],
                &[
                    token(b"obs-a", b"PARTY-A", 0xC1),
                    token(b"obs-b", b"PARTY-B", 0xC2)
                ],
            ),
            station(
                b"ST-2",
                StationKind::EarlyVoting,
                checkin_unit(2, b"U-2A", &[b"M-U2A-P1", b"M-U2A-P2"]),
                checkin_unit(3, b"U-2B", &[b"M-U2B-P1", b"M-U2B-P2"]),
                &[b"BOX-3"],
                &[],
            ),
        ];
        let policies = std::vec![
            StationProgressPolicy::new(StationId::new(b"ST-1").unwrap(), 4, 12).unwrap(),
            StationProgressPolicy::new(StationId::new(b"ST-2").unwrap(), 2, 8).unwrap(),
        ];
        let units = std::vec![
            ReportingUnitEntry::new(ReportingUnitId::new(b"RU-1").unwrap(), 2).unwrap(),
            ReportingUnitEntry::new(ReportingUnitId::new(b"RU-2").unwrap(), 1).unwrap(),
        ];
        let routes = std::vec![
            CustodyRoute::new(
                RouteId::new(b"R-1").unwrap(),
                true,
                &[org(b"ORG-ST"), org(b"POLICE"), org(b"ORG-CC")]
            )
            .unwrap(),
            CustodyRoute::new(
                RouteId::new(b"R-2").unwrap(),
                false,
                &[org(b"ORG-ST"), org(b"POST"), org(b"ORG-CC")]
            )
            .unwrap(),
        ];
        let roster = std::vec![
            roster_signer(0, b"clerk-1", RosterRole::Clerk, b"ORG-ST", Some(b"ST-1")),
            roster_signer(1, b"clerk-2", RosterRole::Clerk, b"ORG-ST", Some(b"ST-1")),
            roster_signer(2, b"obs-a", RosterRole::Observer, b"PARTY-A", Some(b"ST-1")),
            roster_signer(3, b"obs-b", RosterRole::Observer, b"PARTY-B", Some(b"ST-1")),
            roster_signer(4, b"police-1", RosterRole::Custodian, b"POLICE", None),
            roster_signer(5, b"court", RosterRole::Authority, b"COURT", None),
        ];
        let mut module_list = Vec::new();
        let names: [(&'static [u8], ChamberCode); 16] = [
            (b"M-B1-P1", ChamberCode::P1),
            (b"M-B1-P2", ChamberCode::P2),
            (b"M-B2-P1", ChamberCode::P1),
            (b"M-B2-P2", ChamberCode::P2),
            (b"M-B2-J", ChamberCode::J),
            (b"M-B3-P1", ChamberCode::P1),
            (b"M-B3-P2", ChamberCode::P2),
            (b"M-B3-A", ChamberCode::A),
            (b"M-U1A-P1", ChamberCode::P1),
            (b"M-U1A-P2", ChamberCode::P2),
            (b"M-U1B-P1", ChamberCode::P1),
            (b"M-U1B-P2", ChamberCode::P2),
            (b"M-U2A-P1", ChamberCode::P1),
            (b"M-U2A-P2", ChamberCode::P2),
            (b"M-U2B-P1", ChamberCode::P1),
            (b"M-U2B-P2", ChamberCode::P2),
        ];
        for (n, (name, chamber)) in names.iter().enumerate() {
            module_list.push(module_entry(n as u16, name, *chamber));
        }
        let styles = std::vec![
            BallotStyleEntry::new(
                BallotStyleId::new(b"STYLE-1").unwrap(),
                5,
                Hash512([0x51; 64])
            )
            .unwrap(),
            BallotStyleEntry::new(
                BallotStyleId::new(b"STYLE-2").unwrap(),
                9,
                Hash512([0x52; 64])
            )
            .unwrap(),
        ];
        let chambers = std::vec![
            threshold(ChamberCode::P1, 1, 2),
            threshold(ChamberCode::P2, 1, 2),
            threshold(ChamberCode::J, 1, 1),
            threshold(ChamberCode::A, 1, 1),
            threshold(ChamberCode::C, 1, 1),
            threshold(ChamberCode::N, 1, 1),
        ];
        let trustee_ids: [(&'static [u8], ChamberCode); 8] = [
            (b"T-P1-1", ChamberCode::P1),
            (b"T-P1-2", ChamberCode::P1),
            (b"T-P2-1", ChamberCode::P2),
            (b"T-P2-2", ChamberCode::P2),
            (b"T-J", ChamberCode::J),
            (b"T-A", ChamberCode::A),
            (b"T-C", ChamberCode::C),
            (b"T-N", ChamberCode::N),
        ];
        let trustees = trustee_ids
            .iter()
            .enumerate()
            .map(|(n, (tid, chamber))| TrusteeEntry {
                trustee_id: TrusteeId::new(tid).unwrap(),
                chamber: *chamber,
                org_id: org(b"TRUST-ORG"),
                key: registered(TRUSTEE_BASE + n as u16),
                appointment_hash: appointment(100 + n as u8),
            })
            .collect();
        let witnesses = (0..13)
            .map(|i| WitnessRosterEntry {
                witness_id: id(WITNESS_IDS[i]),
                org_id: org(ORGS[i % ORGS.len()]),
                provider: id(PROVIDERS[i % PROVIDERS.len()]),
                region: id(REGIONS[i % REGIONS.len()]),
                key: registered(WITNESS_BASE + i as u16),
                appointment_hash: appointment(200 + i as u8),
            })
            .collect();
        let mut draft = Self {
            boxes,
            stations,
            policies,
            units,
            routes,
            roster,
            modules: module_list,
            appointments: Vec::new(),
            styles,
            trustees,
            witnesses,
            parties: std::vec![
                PartyEntry {
                    chamber: ChamberCode::P1,
                    name: "가당",
                    seats: 160,
                    evidence_hash: Hash512([0x61; 64]),
                },
                PartyEntry {
                    chamber: ChamberCode::P2,
                    name: "나당",
                    seats: 110,
                    evidence_hash: Hash512([0x62; 64]),
                },
            ],
            chambers,
            quorum: WitnessQuorum {
                witnesses: 13,
                quorum: 9,
                byzantine_max: 4,
                min_orgs: 7,
                min_providers: 4,
                min_regions: 3,
            },
        };
        draft.appointments = draft.referenced_appointments();
        draft
    }

    /// Every appointment hash the entries refer to, sorted.
    pub fn referenced_appointments(&self) -> Vec<Hash512> {
        let mut out: Vec<Hash512> = self
            .roster
            .iter()
            .map(|r| r.appointment_hash)
            .chain(self.trustees.iter().map(|t| t.appointment_hash))
            .chain(self.witnesses.iter().map(|w| w.appointment_hash))
            .collect();
        out.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        out.dedup();
        out
    }

    /// The draft encoded, each set sorted by key.
    pub fn raw(&self) -> Raw {
        Raw {
            boxes: encode_set(&self.boxes),
            stations: encode_set(&self.stations),
            policies: encode_set(&self.policies),
            units: encode_set(&self.units),
            routes: encode_set(&self.routes),
            roster: encode_set(&self.roster),
            modules: encode_set(&self.modules),
            appointments: self.appointments.clone(),
            styles: encode_set(&self.styles),
            trustees: encode_set(&self.trustees),
            witnesses: encode_set(&self.witnesses),
        }
    }
}

fn encode_set<'a, T: GenesisEntry<'a> + Encode + Clone>(items: &[T]) -> Vec<&'static [u8]> {
    let mut items = items.to_vec();
    items.sort_by(|a, b| a.key().cmp(b.key()));
    let schema = T::SET.schema().unwrap();
    items
        .iter()
        .map(|t| object(schema, SCHEMA_VERSION_1, t))
        .collect()
}

/// The encoded sets, in the order the body will commit to.
#[derive(Clone)]
pub struct Raw {
    pub boxes: Vec<&'static [u8]>,
    pub stations: Vec<&'static [u8]>,
    pub policies: Vec<&'static [u8]>,
    pub units: Vec<&'static [u8]>,
    pub routes: Vec<&'static [u8]>,
    pub roster: Vec<&'static [u8]>,
    pub modules: Vec<&'static [u8]>,
    pub appointments: Vec<Hash512>,
    pub styles: Vec<&'static [u8]>,
    pub trustees: Vec<&'static [u8]>,
    pub witnesses: Vec<&'static [u8]>,
}

fn commit_objects(objects: &[&[u8]]) -> SetCommitment {
    let mut acc = Accumulator::empty();
    for o in objects {
        acc.push(&ityv_crypto::object_hash(o)).unwrap();
    }
    SetCommitment {
        count: objects.len() as u64,
        root: acc.root(),
    }
}

impl Raw {
    /// The commitments of the sets as they are, in `EntrySet` order.
    pub fn commitments(&self) -> [SetCommitment; ENTRY_SET_COUNT] {
        [
            commit_objects(&self.boxes),
            commit_objects(&self.stations),
            commit_objects(&self.policies),
            commit_objects(&self.units),
            commit_objects(&self.routes),
            commit_objects(&self.roster),
            commit_objects(&self.modules),
            SetCommitment {
                count: self.appointments.len() as u64,
                // An unsorted list has no sorted-set root; commit to the
                // root of the sorted copy so the order rule is what fails.
                root: {
                    let mut sorted = self.appointments.clone();
                    sorted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
                    sorted.dedup();
                    sorted_set_root(&sorted).unwrap()
                },
            },
            commit_objects(&self.styles),
            commit_objects(&self.trustees),
            commit_objects(&self.witnesses),
        ]
    }

    pub fn amendable(&self) -> AmendableSets<'static> {
        AmendableSets {
            boxes: leak_slice(self.boxes.clone()),
            stations: leak_slice(self.stations.clone()),
            progress_policies: leak_slice(self.policies.clone()),
            reporting_units: leak_slice(self.units.clone()),
            routes: leak_slice(self.routes.clone()),
            roster: leak_slice(self.roster.clone()),
            modules: leak_slice(self.modules.clone()),
            appointments: leak_slice(self.appointments.clone()),
        }
    }

    pub fn fixed(&self) -> FixedSets<'static> {
        FixedSets {
            ballot_styles: leak_slice(self.styles.clone()),
            trustees: leak_slice(self.trustees.clone()),
            witnesses: leak_slice(self.witnesses.clone()),
        }
    }
}

/// A signed genesis ready to verify.
pub struct Built {
    pub pin: Hash512,
    pub signed: &'static [u8],
    pub body: &'static [u8],
    pub raw: Raw,
}

impl Built {
    pub fn input(&self) -> GenesisInput<'static> {
        GenesisInput {
            signed: self.signed,
            sets: self.raw.amendable(),
            fixed: self.raw.fixed(),
        }
    }
}

/// Signs `body` under `purpose` by the commission, the committee and the
/// witnesses `who`: the encoded `SignedGenesis`.
pub fn seal(body: &'static [u8], purpose: &[u8], who: &[usize]) -> &'static [u8] {
    let c = sign(signing(COMMISSION), purpose, body);
    let k = sign(signing(COMMITTEE), purpose, body);
    let sigs: Vec<GenesisWitnessSig<'static>> = who
        .iter()
        .map(|&i| GenesisWitnessSig {
            witness_id: id(WITNESS_IDS[i]),
            sig: sign(signing(WITNESS_BASE + i as u16), purpose, body),
        })
        .collect();
    let signed = SignedGenesis::new(body, c, k, &sigs).unwrap();
    object(SCHEMA_SIGNED_GENESIS, SCHEMA_VERSION_1, &signed)
}

/// The body parts of `draft` committing to `raw`.
pub fn parts(draft: &Draft, raw: &Raw) -> GenesisParts<'static> {
    GenesisParts {
        election_id: election(),
        election_epoch_day: Day::new(20_000),
        policy_hash: Hash512([0x01; 64]),
        proof_system_id: id(b"ityv-orproof-v1"),
        legal_authorization_hash: Hash512([0x02; 64]),
        connectivity_manifest_hash: Hash512([0x03; 64]),
        release_manifest_hash: Hash512([0x04; 64]),
        commission_key: registered(COMMISSION),
        committee_key: registered(COMMITTEE),
        quorum: draft.quorum,
        parties: leak_slice(draft.parties.clone()),
        chambers: leak_slice(draft.chambers.clone()),
        sets: raw.commitments(),
    }
}

/// Builds and signs the genesis of `draft` with sets `raw`; `tweak` may
/// change the body parts first.
pub fn sign_genesis_with(
    draft: &Draft,
    raw: Raw,
    who: &[usize],
    tweak: impl FnOnce(&mut GenesisParts<'static>),
) -> Built {
    let mut p = parts(draft, &raw);
    tweak(&mut p);
    let body = GenesisBody::new(&p).unwrap();
    let body = object(SCHEMA_GENESIS_BODY, SCHEMA_VERSION_GENESIS, &body);
    let signed = seal(body, b"genesis", who);
    Built {
        pin: ityv_crypto::object_hash(body),
        signed,
        body,
        raw,
    }
}

/// The standard signing of `draft` with sets `raw`.
pub fn sign_genesis(draft: &Draft, raw: Raw) -> Built {
    sign_genesis_with(draft, raw, &SIGNERS, |_| {})
}

/// The standard genesis, built once.
pub fn standard() -> &'static Built {
    static BUILT: OnceLock<&'static Built> = OnceLock::new();
    BUILT.get_or_init(|| {
        let draft = Draft::standard();
        leak(sign_genesis(&draft, draft.raw()))
    })
}

/// An amendment numbered `seq` after the body hashing to `previous`,
/// committing to the amendable sets of `raw`.
pub fn amendment(seq: u64, previous: Hash512, raw: &Raw, who: &[usize]) -> AmendmentInput<'static> {
    amendment_for(election(), seq, previous, raw, who)
}

/// As [`amendment`], for `election`.
pub fn amendment_for(
    election: ElectionId<'static>,
    seq: u64,
    previous: Hash512,
    raw: &Raw,
    who: &[usize],
) -> AmendmentInput<'static> {
    let all = raw.commitments();
    let mut sets = [SetCommitment {
        count: 0,
        root: Hash512::ZERO,
    }; AMENDABLE_SET_COUNT];
    sets.copy_from_slice(&all[..AMENDABLE_SET_COUNT]);
    let body = GenesisAmendmentBody::new(&GenesisAmendmentParts {
        election_id: election,
        seq,
        previous_hash: previous,
        reason: AmendmentReason::DeviceReplacement,
        reason_hash: Hash512([0x5E; 64]),
        time_bucket: TimeBucket::new(300),
        release_manifest_hash: Hash512([0x5F; 64]),
        sets,
    })
    .unwrap();
    let body = object(SCHEMA_GENESIS_AMENDMENT_BODY, SCHEMA_VERSION_1, &body);
    AmendmentInput {
        signed: seal(body, b"genesis-amendment", who),
        sets: raw.amendable(),
    }
}

/// The object hash of the body an encoded `SignedGenesis` carries.
pub fn body_hash(signed: &[u8]) -> Hash512 {
    let s: SignedGenesis<'_> =
        ityv_encoding::decode_object(SCHEMA_SIGNED_GENESIS, SCHEMA_VERSION_1, signed).unwrap();
    ityv_crypto::object_hash(s.body_bytes())
}

/// Which set an entry set is, for assertions.
pub fn set_of<'a, T: GenesisEntry<'a>>() -> EntrySet {
    T::SET
}

/// The signing key of witness `i` (`W01` is 0).
pub fn witness_signing(i: usize) -> &'static HybridSigningKey {
    signing(WITNESS_BASE + i as u16)
}

/// `key`'s hybrid signature over `object` under `purpose`.
pub fn hybrid_signature(
    key: &HybridSigningKey,
    purpose: &[u8],
    object: &[u8],
) -> &'static HybridSignature {
    let purpose = Purpose::new(purpose).unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(object.len() as u64);
    leak(sign_hybrid(key, &purpose, object, &mut rng).unwrap())
}

/// A legal authorization of `scopes` effective from day `from` to day
/// `until`: the body object and the ledger object carrying it with the
/// commission's and the committee's signatures.
pub fn legal_authorization(
    scopes: &[ityv_encoding::Scope],
    from: u64,
    until: u64,
) -> (&'static [u8], &'static [u8]) {
    let body = ityv_encoding::LegalAuthorizationBody::new(
        election(),
        ityv_encoding::ScopeSet::from_slice(scopes),
        Hash512([0x31; 64]),
        Day::new(from),
        Day::new(until),
    )
    .unwrap();
    let body = object(
        ityv_encoding::SCHEMA_LEGAL_AUTHORIZATION,
        SCHEMA_VERSION_1,
        &body,
    );
    let signed = ityv_encoding::SignedLegalAuthorization::new(
        body,
        sign(signing(COMMISSION), b"legal-auth", body),
        sign(signing(COMMITTEE), b"legal-auth", body),
    )
    .unwrap();
    (
        body,
        object(
            ityv_encoding::SCHEMA_SIGNED_LEGAL_AUTHORIZATION,
            SCHEMA_VERSION_1,
            &signed,
        ),
    )
}

/// The standard genesis pinning a legal authorization of `PUBLIC_BOARD`,
/// `TRUSTEE_BODY` and `BALLOT_MARK` for days 20 000..20 100, built once,
/// with the signed authorization object for the ledger.
pub fn authorized() -> &'static (Built, &'static [u8]) {
    static BUILT: OnceLock<&'static (Built, &'static [u8])> = OnceLock::new();
    BUILT.get_or_init(|| {
        let draft = Draft::standard();
        let (body, signed) = legal_authorization(
            &[
                ityv_encoding::Scope::PublicBoard,
                ityv_encoding::Scope::TrusteeBody,
                ityv_encoding::Scope::BallotMark,
            ],
            20_000,
            20_100,
        );
        let built = sign_genesis_with(&draft, draft.raw(), &SIGNERS, |p| {
            p.legal_authorization_hash = ityv_crypto::object_hash(body);
        });
        leak((built, signed))
    })
}

/// A frame stream: frames chained in order, each naming one event.
pub struct Ledger {
    stream: Vec<u8>,
    prev: Hash512,
    seq: u64,
    /// The events, in frame order.
    pub events: Vec<&'static [u8]>,
}

impl Ledger {
    pub fn new() -> Self {
        Self {
            stream: Vec::new(),
            prev: Hash512::ZERO,
            seq: 0,
            events: Vec::new(),
        }
    }

    /// Appends a frame carrying `event` as `schema`.
    pub fn push(&mut self, schema: SchemaId, event: &'static [u8]) -> &mut Self {
        self.seq += 1;
        let frame = ityv_encoding::LedgerFrame::new(
            election(),
            ityv_encoding::Seq::new(self.seq).unwrap(),
            self.prev,
            schema,
            ityv_crypto::object_hash(event),
        );
        let bytes = object(ityv_encoding::SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &frame);
        self.prev = ityv_crypto::object_hash(bytes);
        self.stream
            .extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
        self.stream.extend_from_slice(bytes);
        self.events.push(event);
        self
    }

    /// The encoded frame stream.
    pub fn bytes(&self) -> &'static [u8] {
        leak_slice(self.stream.clone())
    }
}

// ---------------------------------------------------------------------
// Record-stage helpers.

/// The signing key of module entry `n` (the `n` given to `module_entry`).
pub fn module_signing(n: u16) -> &'static HybridSigningKey {
    signing(MODULE_BASE + n)
}

/// The registered key of module entry `n`.
pub fn module_key(n: u16) -> &'static [u8; HYBRID_VK_LEN] {
    registered(MODULE_BASE + n)
}

// ---------------------------------------------------------------------
// Progress-stage helpers.

/// The signing key of check-in unit `n` (the `n` given to `checkin_unit`).
pub fn unit_signing(n: u16) -> &'static HybridSigningKey {
    signing(UNIT_BASE + n)
}
