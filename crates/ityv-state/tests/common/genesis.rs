//! A real genesis for the integration tests: every set encoded, sorted by
//! key and committed by its Merkle root, the body signed by the commission,
//! the committee and nine witnesses, pinned, sealed, and entries proved
//! against it (ADR-0028). Built once per (legal authorization, profile)
//! and leaked.

use std::boxed::Box;
use std::sync::Mutex;
use std::vec::Vec;

use ityv_crypto::hash::object_hash;
use ityv_crypto::{HybridSigned, HybridSigningKey, HybridVerifyingKey, Verified};
use ityv_encoding::{
    AMENDABLE_SET_COUNT, AmendmentReason, BallotStyleEntry, BallotStyleId, BoxId, CaptureProfile,
    ChamberCode, ChamberThreshold, CheckinUnit, CustodyRoute, Day, ENTRY_SET_COUNT, Encode,
    EntrySet, GenesisAmendmentBody, GenesisAmendmentParts, GenesisBody, GenesisBox, GenesisEntry,
    GenesisParts, GenesisWitnessSig, HYBRID_VK_LEN, Hash512, Ident, ModuleEntry, ModuleId,
    ModuleIds, PartyEntry, ReportingUnitEntry, ReportingUnitId, RosterRole, RosterSigner, RouteId,
    SCHEMA_GENESIS_AMENDMENT_BODY, SCHEMA_GENESIS_BODY, SCHEMA_VERSION_1, SCHEMA_VERSION_GENESIS,
    SchemaId, SetCommitment, SignedGenesis, StationEntry, StationId, StationKind, StationParts,
    StationProgressPolicy, TimeBucket, TrusteeEntry, TrusteeId, WitnessQuorum, WitnessRosterEntry,
    encode_object,
};
use ityv_ledger::{InclusionProof, inclusion_proof, root_of_leaves};
use ityv_state::{Entry, Genesis, Pinned, RosterEntry};

use super::{
    BOX, PEOPLE, STATION, device_key, leak, leak_slice, org, person_key, signed_by, signer,
};

/// A key's registered bytes.
pub(crate) fn key_bytes(key: &HybridVerifyingKey) -> &'static [u8; HYBRID_VK_LEN] {
    let mut out = [0u8; HYBRID_VK_LEN];
    let (ml, ed) = out.split_at_mut(key.mldsa87().len());
    ml.copy_from_slice(key.mldsa87());
    ed.copy_from_slice(key.ed25519());
    leak(out)
}

fn signing(seed: u8) -> &'static HybridSigningKey {
    leak(HybridSigningKey::from_seeds([seed; 32], [seed + 1; 32]))
}

fn registered(seed: u8) -> &'static [u8; HYBRID_VK_LEN] {
    key_bytes(&signing(seed).verifying_key())
}

/// The election commission's signing key.
pub(crate) fn commission() -> &'static HybridSigningKey {
    signing(10)
}

/// The Independent Verification Committee's signing key.
pub(crate) fn committee() -> &'static HybridSigningKey {
    signing(12)
}

/// The check-in unit in service at `ST-1`.
pub(crate) fn unit_key() -> &'static HybridSigningKey {
    signing(60)
}

/// The sealed spare unit at `ST-1`.
pub(crate) fn spare_unit_key() -> &'static HybridSigningKey {
    signing(62)
}

/// The spare commitment unit the amendment registers for `BOX-001`.
pub(crate) fn spare_device_key() -> &'static HybridSigningKey {
    signing(64)
}

/// The legal authority on the roster (`court`).
pub(crate) fn court_key() -> &'static HybridSigningKey {
    signing(30)
}

/// Witness `i` (0-based): `W01`…`W13`.
pub(crate) const WITNESS_COUNT: usize = 13;

const WITNESS_IDS: [&[u8]; WITNESS_COUNT] = [
    b"W01", b"W02", b"W03", b"W04", b"W05", b"W06", b"W07", b"W08", b"W09", b"W10", b"W11", b"W12",
    b"W13",
];
const ORGS: [&[u8]; 7] = [
    b"ORG-1", b"ORG-2", b"ORG-3", b"ORG-4", b"ORG-5", b"ORG-6", b"ORG-7",
];
const PROVIDERS: [&[u8]; 4] = [b"PROV-1", b"PROV-2", b"PROV-3", b"PROV-4"];
const REGIONS: [&[u8]; 3] = [b"REG-1", b"REG-2", b"REG-3"];

pub(crate) fn witness_key(i: usize) -> &'static HybridSigningKey {
    signing(100 + 2 * u8::try_from(i).unwrap())
}

fn witness(i: usize) -> WitnessRosterEntry<'static> {
    let id = |b: &'static [u8]| Ident::new(b, 64).unwrap();
    WitnessRosterEntry {
        witness_id: id(WITNESS_IDS[i]),
        org_id: org(ORGS[i % ORGS.len()]),
        provider: id(PROVIDERS[i % PROVIDERS.len()]),
        region: id(REGIONS[i % REGIONS.len()]),
        key: key_bytes(&witness_key(i).verifying_key()),
        appointment_hash: Hash512([0x70; 64]),
    }
}

/// The nine witnesses that sign by default: `W01`…`W09` (seven
/// organisations, four providers, three regions).
pub(crate) const SIGNERS: [usize; 9] = [0, 1, 2, 3, 4, 5, 6, 7, 8];

/// One encoded set: objects in key order, their hashes and commitment.
pub(crate) struct Set {
    objects: Vec<&'static [u8]>,
    keys: Vec<Vec<u8>>,
    hashes: Vec<Hash512>,
}

impl Set {
    fn of<'a, T: GenesisEntry<'a> + Encode>(mut items: Vec<T>) -> Self {
        items.sort_by(|a, b| a.key().cmp(b.key()));
        let schema = T::SET.schema().unwrap();
        let objects: Vec<&'static [u8]> = items.iter().map(|t| encode(schema, 1, t)).collect();
        let keys = items.iter().map(|t| t.key().to_vec()).collect();
        let hashes = objects.iter().map(|o| object_hash(o)).collect();
        Self {
            objects,
            keys,
            hashes,
        }
    }

    fn hashes(mut hashes: Vec<Hash512>) -> Self {
        hashes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        Self {
            objects: Vec::new(),
            keys: Vec::new(),
            hashes,
        }
    }

    pub(crate) fn commitment(&self) -> SetCommitment {
        let n = u64::try_from(self.hashes.len()).unwrap();
        SetCommitment {
            count: n,
            root: root_of_leaves(&self.hashes.as_slice(), n).unwrap(),
        }
    }

    /// The object, index and proof of the entry with `key`.
    pub(crate) fn find(&self, key: &[u8]) -> (&'static [u8], u64, &'static InclusionProof) {
        let i = self.keys.iter().position(|k| k == key).unwrap();
        let n = u64::try_from(self.hashes.len()).unwrap();
        let index = u64::try_from(i).unwrap();
        let proof = leak(inclusion_proof(&self.hashes.as_slice(), n, index).unwrap());
        (self.objects[i], index, proof)
    }
}

fn encode<T: Encode>(schema: SchemaId, version: u16, value: &T) -> &'static [u8] {
    let mut buf = std::vec![0u8; 16 + value.encoded_len()];
    let len = encode_object(schema, version, value, &mut buf).unwrap();
    buf.truncate(len);
    leak_slice(buf)
}

fn modules() -> ModuleIds<'static> {
    ModuleIds::new(&[
        ModuleId::new(b"MOD-P1").unwrap(),
        ModuleId::new(b"MOD-P2").unwrap(),
        ModuleId::new(b"MOD-P3").unwrap(),
    ])
    .unwrap()
}

fn genesis_box(
    id: &'static [u8],
    station: &'static [u8],
    profile: CaptureProfile,
    route: &'static [u8],
    device: &'static [u8; HYBRID_VK_LEN],
) -> GenesisBox<'static> {
    GenesisBox {
        box_id: BoxId::new(id).unwrap(),
        station_id: StationId::new(station).unwrap(),
        ballot_style_id: BallotStyleId::new(b"STYLE-1").unwrap(),
        profile,
        route_id: RouteId::new(route).unwrap(),
        reporting_unit_id: ReportingUnitId::new(b"RU-1").unwrap(),
        device_key: device,
        attest_key: registered(90),
        modules: modules(),
    }
}

fn boxes(profile: CaptureProfile, device: &'static [u8; HYBRID_VK_LEN]) -> Set {
    Set::of(std::vec![
        genesis_box(BOX, STATION, profile, b"R-1", device),
        genesis_box(
            b"BOX-002",
            b"ST-2",
            CaptureProfile::InPerson,
            b"R-2",
            registered(66)
        ),
    ])
}

fn unit(id: &'static [u8], seed: u8) -> CheckinUnit<'static> {
    CheckinUnit {
        unit_id: ityv_encoding::UnitId::new(id).unwrap(),
        key: registered(seed),
        attest_key: registered(92),
        modules: ModuleIds::new(&[
            ModuleId::new(b"MOD-P1").unwrap(),
            ModuleId::new(b"MOD-P2").unwrap(),
        ])
        .unwrap(),
    }
}

fn station(
    id: &'static [u8],
    primary: CheckinUnit<'static>,
    spare: CheckinUnit<'static>,
    b: &[&'static [u8]],
) -> StationEntry<'static> {
    StationEntry::new(&StationParts {
        station_id: StationId::new(id).unwrap(),
        kind: StationKind::ElectionDay,
        primary,
        spare,
        boxes: leak_slice(b.iter().map(|b| BoxId::new(b).unwrap()).collect()),
        id_terminals_hash: Hash512([0x33; 64]),
        tokens: &[],
    })
    .unwrap()
}

fn roster_entries() -> Vec<RosterSigner<'static>> {
    let mut entries: Vec<RosterSigner<'static>> = PEOPLE
        .iter()
        .map(|(id, role, o, _)| RosterSigner {
            signer_id: signer(id),
            role: *role,
            org_id: org(o),
            station_id: Some(StationId::new(STATION).unwrap()),
            key: key_bytes(&person_key(id).verifying_key()),
            appointment_hash: Hash512([0x71; 64]),
        })
        .collect();
    // Two observers whose keys share the Ed25519 half (one signer).
    for (id, o, seed) in [
        (&b"obs-x"[..], &b"PARTY-X"[..], 60u8),
        (b"obs-y", b"PARTY-Y", 62),
    ] {
        let key = HybridSigningKey::from_seeds([seed; 32], [61; 32]);
        entries.push(RosterSigner {
            signer_id: signer(id),
            role: RosterRole::Observer,
            org_id: org(o),
            station_id: Some(StationId::new(STATION).unwrap()),
            key: key_bytes(&key.verifying_key()),
            appointment_hash: Hash512([0x71; 64]),
        });
    }
    entries.push(RosterSigner {
        signer_id: signer(b"court"),
        role: RosterRole::Authority,
        org_id: org(b"COURT"),
        station_id: None,
        key: key_bytes(&court_key().verifying_key()),
        appointment_hash: Hash512([0x72; 64]),
    });
    entries
}

const PARTIES: [PartyEntry<'static>; 2] = [
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
];

const fn threshold(chamber: ChamberCode, threshold: u8, members: u8) -> ChamberThreshold {
    ChamberThreshold {
        chamber,
        threshold,
        members,
    }
}

const CHAMBERS: [ChamberThreshold; 6] = [
    threshold(ChamberCode::P1, 2, 3),
    threshold(ChamberCode::P2, 2, 3),
    threshold(ChamberCode::J, 2, 3),
    threshold(ChamberCode::A, 2, 3),
    threshold(ChamberCode::C, 2, 3),
    threshold(ChamberCode::N, 3, 5),
];

/// The default witness quorum: 13/9/4 with 7 organisations, 4 providers,
/// 3 regions.
pub(crate) const QUORUM: WitnessQuorum = WitnessQuorum {
    witnesses: 13,
    quorum: 9,
    byzantine_max: 4,
    min_orgs: 7,
    min_providers: 4,
    min_regions: 3,
};

/// A built genesis and everything needed to prove entries and amend it.
pub(crate) struct Built {
    pub(crate) genesis: Genesis<'static>,
    pub(crate) signed: &'static SignedGenesis<'static>,
    pub(crate) pin: Hash512,
    pub(crate) sets: Vec<Set>,
    pub(crate) profile: CaptureProfile,
}

/// Signatures of the commission, the committee and the witnesses `who`
/// over `body` under `purpose`: the signed object, its tokens and the
/// witness entries.
pub(crate) fn seal(
    body: &'static [u8],
    purpose: &'static [u8],
    who: &[usize],
) -> (
    &'static SignedGenesis<'static>,
    &'static [Verified<HybridSigned<'static>>],
) {
    let (c_sig, c_token) = signed_by(commission(), purpose, body);
    let (k_sig, k_token) = signed_by(committee(), purpose, body);
    let mut tokens = std::vec![c_token, k_token];
    let mut sigs = Vec::new();
    for i in who {
        let (sig, token) = signed_by(witness_key(*i), purpose, body);
        sigs.push(GenesisWitnessSig {
            witness_id: Ident::new(WITNESS_IDS[*i], 64).unwrap(),
            sig,
        });
        tokens.push(token);
    }
    (
        leak(SignedGenesis::new(body, c_sig, k_sig, &sigs).unwrap()),
        leak_slice(tokens),
    )
}

impl Built {
    fn set(&self, set: EntrySet) -> &Set {
        &self.sets[set.index()]
    }

    /// The proved entry of `T`'s set with `key`, against `genesis`.
    pub(crate) fn entry_in<T: GenesisEntry<'static>>(
        &self,
        genesis: &Genesis<'static>,
        key: &[u8],
    ) -> Entry<T> {
        let (bytes, index, proof) = self.set(T::SET).find(key);
        genesis.entry(bytes, index, proof).unwrap()
    }

    /// The proved entry of `T`'s set with `key`.
    pub(crate) fn entry<T: GenesisEntry<'static>>(&self, key: &[u8]) -> Entry<T> {
        self.entry_in(&self.genesis, key)
    }

    /// The raw object, index and proof of an entry, for refusal tests.
    pub(crate) fn raw(
        &self,
        set: EntrySet,
        key: &[u8],
    ) -> (&'static [u8], u64, &'static InclusionProof) {
        self.set(set).find(key)
    }

    /// The witness entries of `who`, proved through `pinned`.
    pub(crate) fn witnesses_via(
        &self,
        pinned: &Pinned<'static>,
        who: &[usize],
    ) -> &'static [Entry<WitnessRosterEntry<'static>>] {
        prove_witnesses(&self.sets, pinned, who)
    }

    /// The witness entries of `who`, proved against the sealed genesis.
    pub(crate) fn witnesses(&self, who: &[usize]) -> &'static [Entry<WitnessRosterEntry<'static>>] {
        leak_slice(
            who.iter()
                .map(|i| self.entry::<WitnessRosterEntry<'static>>(WITNESS_IDS[*i]))
                .collect(),
        )
    }

    /// Every roster entry, proved.
    pub(crate) fn roster(&self) -> &'static [RosterEntry<'static>] {
        leak_slice(
            self.set(EntrySet::Roster)
                .keys
                .iter()
                .map(|k| self.entry::<RosterSigner<'static>>(k))
                .collect(),
        )
    }

    /// The amendment body that registers the spare device for `BOX-001`.
    pub(crate) fn amendment_body(&self, seq: u64, previous: Hash512) -> &'static [u8] {
        let new_boxes = boxes(self.profile, key_bytes(&spare_device_key().verifying_key()));
        let mut sets = [SetCommitment {
            count: 0,
            root: Hash512::ZERO,
        }; AMENDABLE_SET_COUNT];
        for (slot, set) in sets.iter_mut().zip(&self.sets) {
            *slot = set.commitment();
        }
        sets[EntrySet::Boxes.index()] = new_boxes.commitment();
        let body = GenesisAmendmentBody::new(&GenesisAmendmentParts {
            election_id: super::election(),
            seq,
            previous_hash: previous,
            reason: AmendmentReason::DeviceReplacement,
            reason_hash: Hash512([0x5E; 64]),
            time_bucket: TimeBucket::new(300),
            release_manifest_hash: Hash512([0x5F; 64]),
            sets,
        })
        .unwrap();
        encode(SCHEMA_GENESIS_AMENDMENT_BODY, SCHEMA_VERSION_1, &body)
    }

    /// The genesis amended to the spare device for `BOX-001`, and the new
    /// box entry.
    pub(crate) fn amended(&self) -> (&'static Genesis<'static>, Entry<GenesisBox<'static>>) {
        let body = self.amendment_body(1, self.pin);
        let (signed, tokens) = seal(body, b"genesis-amendment", &SIGNERS);
        let amended = leak(
            self.genesis
                .amend(signed, tokens, self.witnesses(&SIGNERS))
                .unwrap(),
        );
        let new_boxes = boxes(self.profile, key_bytes(&spare_device_key().verifying_key()));
        let (bytes, index, proof) = new_boxes.find(BOX);
        let entry = amended.entry(bytes, index, proof).unwrap();
        (amended, entry)
    }
}

/// The genesis body for `legal` (the pinned legal authorization hash) and
/// a `BOX-001` of `profile`, with its sets.
pub(crate) fn body(
    legal: Hash512,
    profile: CaptureProfile,
    quorum: WitnessQuorum,
) -> (&'static [u8], Vec<Set>) {
    let sets = std::vec![
        boxes(profile, key_bytes(&device_key().verifying_key())),
        Set::of(std::vec![
            station(
                b"ST-1",
                unit(b"UNIT-1", 60),
                unit(b"UNIT-2", 62),
                &[BOX, b"BOX-999"]
            ),
            station(
                b"ST-2",
                unit(b"UNIT-3", 68),
                unit(b"UNIT-4", 70),
                &[b"BOX-002"]
            ),
        ]),
        Set::of(std::vec![
            StationProgressPolicy::new(StationId::new(b"ST-1").unwrap(), 3, 6).unwrap(),
            StationProgressPolicy::new(StationId::new(b"ST-2").unwrap(), 2, 6).unwrap(),
        ]),
        Set::of(std::vec![
            ReportingUnitEntry::new(ReportingUnitId::new(b"RU-1").unwrap(), 2).unwrap()
        ]),
        Set::of(std::vec![
            CustodyRoute::new(
                RouteId::new(b"R-1").unwrap(),
                false,
                &[org(b"STATION"), org(b"POLICE"), org(b"CENTRE")],
            )
            .unwrap(),
            CustodyRoute::new(
                RouteId::new(b"R-2").unwrap(),
                false,
                &[org(b"STATION"), org(b"CENTRE")],
            )
            .unwrap(),
        ]),
        Set::of(roster_entries()),
        Set::of(
            [&b"MOD-P1"[..], b"MOD-P2", b"MOD-P3"]
                .iter()
                .zip([ChamberCode::P1, ChamberCode::P2, ChamberCode::J])
                .map(|(id, chamber)| ModuleEntry {
                    module_id: ModuleId::new(id).unwrap(),
                    chamber,
                    key: registered(94),
                    attest_key: registered(96),
                    provisioned_hash: Hash512([0x73; 64]),
                })
                .collect(),
        ),
        Set::hashes(std::vec![
            Hash512([0x70; 64]),
            Hash512([0x71; 64]),
            Hash512([0x72; 64])
        ]),
        Set::of(std::vec![
            BallotStyleEntry::new(BallotStyleId::new(b"STYLE-1").unwrap(), 5, Hash512([3; 64]))
                .unwrap()
        ]),
        Set::of(std::vec![TrusteeEntry {
            trustee_id: TrusteeId::new(b"T-P1-1").unwrap(),
            chamber: ChamberCode::P1,
            org_id: org(b"PARTY-A"),
            key: registered(98),
            appointment_hash: Hash512([0x74; 64]),
        }]),
        Set::of((0..WITNESS_COUNT).map(witness).collect()),
    ];
    let mut commitments = [SetCommitment {
        count: 0,
        root: Hash512::ZERO,
    }; ENTRY_SET_COUNT];
    for (slot, set) in commitments.iter_mut().zip(&sets) {
        *slot = set.commitment();
    }
    let body = GenesisBody::new(&GenesisParts {
        election_id: super::election(),
        election_epoch_day: Day::new(90),
        policy_hash: Hash512([0x10; 64]),
        proof_system_id: Ident::new(b"PS-OR-1", 64).unwrap(),
        legal_authorization_hash: legal,
        connectivity_manifest_hash: Hash512([0x12; 64]),
        release_manifest_hash: Hash512([0x13; 64]),
        commission_key: key_bytes(&commission().verifying_key()),
        committee_key: key_bytes(&committee().verifying_key()),
        quorum,
        parties: &PARTIES,
        chambers: &CHAMBERS,
        sets: commitments,
    })
    .unwrap();
    (
        encode(SCHEMA_GENESIS_BODY, SCHEMA_VERSION_GENESIS, &body),
        sets,
    )
}

fn prove_witnesses(
    sets: &[Set],
    pinned: &Pinned<'static>,
    who: &[usize],
) -> &'static [Entry<WitnessRosterEntry<'static>>] {
    leak_slice(
        who.iter()
            .map(|i| {
                let (bytes, index, proof) = sets[EntrySet::Witnesses.index()].find(WITNESS_IDS[*i]);
                pinned.witness(bytes, index, proof).unwrap()
            })
            .collect(),
    )
}

type Key = ([u8; 64], u8);

static CACHE: Mutex<Vec<(Key, &'static Built)>> = Mutex::new(Vec::new());

/// The sealed genesis pinning `legal` with a `BOX-001` of `profile`.
pub(crate) fn built(legal: Hash512, profile: CaptureProfile) -> &'static Built {
    let key = (legal.0, profile.code());
    let mut cache = CACHE.lock().unwrap();
    if let Some((_, b)) = cache.iter().find(|(k, _)| *k == key) {
        return b;
    }
    let (body_bytes, sets) = body(legal, profile, QUORUM);
    let (signed, tokens) = seal(body_bytes, b"genesis", &SIGNERS);
    let pin = object_hash(body_bytes);
    let pinned = Pinned::new(&pin, signed).unwrap();
    let witnesses = prove_witnesses(&sets, &pinned, &SIGNERS);
    let built = Built {
        genesis: pinned.seal(tokens, witnesses).unwrap(),
        signed,
        pin,
        sets,
        profile,
    };
    let built: &'static Built = Box::leak(Box::new(built));
    cache.push((key, built));
    built
}
