//! A signed election built from an [`ElectionSpec`]: the genesis with
//! every set, real keys for every device, person, module, trustee and
//! witness, and every ledger event of the days the stations ran.
//!
//! Ported from the verifier's test worlds (`crates/ityv-verify/tests/`),
//! generalised to any number of units, stations and boxes. Every record
//! carries a real OR proof over commitments made from known secrets, so
//! aggregate openings open their real sums; every signature is real.

use ityv_crypto::{
    Bases, CastId, ChunkIndex, Commitment, MAX_CHUNKS, Opening, OptionCount, OptionIndex,
    RecordPurpose, Scalar, Sha3Hasher, Statement, commit, object_hash, packed_value, prove,
};
use ityv_encoding::{
    AMENDABLE_SET_COUNT, ActorSig, AggregateOpeningBody, AggregateOpeningParts, AmendmentReason,
    Attestation, AuditCommitBody, AuditCommitParts, AuditFindingBody, AuditFindingParts,
    AuditFreezeParts, AuditManifestFreezeBody, AuditRound, AuditRounds, AuditSeedBody,
    AuditSeedParts, BallotStyleEntry, BallotStyleId, BatchAttest, BatchAttestBody,
    BatchAttestParts, BoxClose, BoxCloseBody, BoxCloseParts, BoxId, BoxOpenedBody, BoxOpenedParts,
    BoxProgressBody, BoxProgressParts, BoxProgressState, CaptureProfile, CastRecord,
    CastRecordBody, CastRecordParts, ChamberCode, ChamberThreshold, CheckinProgressBody,
    CheckinProgressParts, CheckinProgressState, CheckinUnit, CloseCounts, Commitments,
    ComparisonCode, CustodyRoute, Day as EpochDay, DisputeAction, DisputeEventBody,
    DisputeEventParts, DisputeType, ENTRY_SET_COUNT, Encode, EnvelopeIssuance, EventRole, EventSig,
    ExclusionEntry, Exclusions, FallbackBody, FallbackKind, FallbackParts, FallbackReason,
    GenesisAmendmentBody, GenesisAmendmentParts, GenesisBody, GenesisBox, GenesisEntry,
    GenesisParts, GenesisWitnessSig, HandCountReportBody, Hash512, Ident, IssuanceCountBody,
    IssuanceCountParts, KEM_EK_LEN, LateBatchCloseBody, LateBatchCloseParts, LateBatchReason,
    LegalAuthorizationBody, MAX_QUORUM_MESSAGE_LEN, ModuleBatchSig, ModuleCounter, ModuleCounters,
    ModuleEntry, ModuleId, ModuleIds, ModuleProvisioned, ModuleProvisionedMessage,
    ModuleProvisionedParts, ModuleRange, ModuleRecordSig, ObserverCountAttestBody,
    ObserverCountKind, ObserverCountParts, ObserverToken, OrgId, PaperCountParts,
    PaperCountReportBody, PaperVotes, ParticipationMessage, ParticipationModuleSig,
    ParticipationSet, PartyEntry, PartyKeyCeremony, PartyKeyMessage, PartyKeyParts, Point32,
    ProgressAlarm, ProgressCheckBody, ProgressCheckParts, ProgressFinding, ProgressTick,
    Pseudonyms, QuorumSig, QuorumSigned, ReceiptEntries, ReceiptEntry, ReceiptOutcome,
    ReceiptResolutionBody, ReceiptResolutionParts, ReportingUnitEntry, ReportingUnitId,
    RollAmendmentBody, RollAmendmentParts, RollAmendmentReason, RollAuthorityEntry,
    RollAuthorityKind, RollCustodyReceiptBody, RollCustodyReceiptParts, RollFreezeBody,
    RollFreezeParts, RollSourceExtractBody, RollSourceExtractParts, RollSourceKind, RollState,
    RosterRole, RosterSigner, RouteId, SCHEMA_AGGREGATE_OPENING_BODY, SCHEMA_BATCH_ATTEST,
    SCHEMA_BATCH_ATTEST_BODY, SCHEMA_BOX_CLOSE, SCHEMA_BOX_CLOSE_BODY, SCHEMA_BOX_OPENED_BODY,
    SCHEMA_BOX_PROGRESS_BODY, SCHEMA_CAST_RECORD, SCHEMA_CAST_RECORD_BODY,
    SCHEMA_CHECKIN_PROGRESS_BODY, SCHEMA_DISPUTE_EVENT_BODY, SCHEMA_FALLBACK_BODY,
    SCHEMA_GENESIS_AMENDMENT_BODY, SCHEMA_GENESIS_BODY, SCHEMA_ISSUANCE_COUNT_BODY,
    SCHEMA_LATE_BATCH_CLOSE_BODY, SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_MODULE_PROVISIONED,
    SCHEMA_OBSERVER_COUNT_ATTEST_BODY, SCHEMA_PAPER_COUNT_REPORT_BODY, SCHEMA_PARTICIPATION_SET,
    SCHEMA_PARTY_KEY_CEREMONY, SCHEMA_PROGRESS_CHECK_BODY, SCHEMA_PROGRESS_TICK,
    SCHEMA_QUORUM_SIGNED, SCHEMA_RECEIPT_RESOLUTION_BODY, SCHEMA_ROLL_AMENDMENT_BODY,
    SCHEMA_ROLL_CUSTODY_RECEIPT_BODY, SCHEMA_ROLL_FREEZE_BODY, SCHEMA_ROLL_SOURCE_EXTRACT_BODY,
    SCHEMA_SIGNED_GENESIS, SCHEMA_SIGNED_LEGAL_AUTHORIZATION, SCHEMA_TALLY_SCOPE_BODY,
    SCHEMA_VERSION_1, SCHEMA_WITNESSED_EVENT, Scalar32, Scope, ScopeSet, SetCommitment,
    ShareHolder, SignedGenesis, SignedLegalAuthorization, SignerId, SignerRole, StationEntry,
    StationId, StationKind, StationParts, StationProgressPolicy, TallyScopeBody, TallyScopeParts,
    TimeBucket, Token192, TrusteeEntry, TrusteeId, UnitId, WitnessQuorum, WitnessRosterEntry,
    WitnessedEvent, Writer, purpose_of, write_quorum_message,
};
use ityv_encoding::{
    SCHEMA_AUDIT_COMMIT_BODY, SCHEMA_AUDIT_FINDING_BODY, SCHEMA_AUDIT_FREEZE_BODY,
    SCHEMA_AUDIT_SEED_BODY, SCHEMA_HAND_COUNT_REPORT_BODY, SCHEMA_SAMPLE_COMPARISON_BODY,
    SCHEMA_SAMPLE_OPENING_BODY, SCHEMA_SAMPLE_OPENING_REF_BODY, SampleComparisonBody,
    SampleComparisonParts, SampleOpeningBody, SampleOpeningParts, SampleOpeningRefBody,
    SampleOpeningRefParts, Scalars,
};
use ityv_ledger::{Accumulator, sorted_set_root};
use ityv_verify::{AmendableSets, AmendmentInput, FixedSets, GenesisInput, VerifiedGenesis};

use crate::day::{Day, Mark, simulate};
use crate::spec::ElectionSpec;
use crate::util::{
    digest, ed25519_half, group, hash_of, leak, leak_slice, leak_str, object, record_sig,
    registered, rng, sign, sign_variant, text,
};

/// The election epoch day.
pub const EPOCH_DAY: u64 = 20_000;
/// Records per batch attestation (PROTOCOL.md §7.2.1).
pub const BATCH_SIZE: usize = 64;
/// The seal digest every box opens and closes with.
pub const SEAL: Hash512 = Hash512([0x5e; 64]);

/// The witness identifiers.
pub const WITNESS_IDS: [&str; 13] = [
    "W01", "W02", "W03", "W04", "W05", "W06", "W07", "W08", "W09", "W10", "W11", "W12", "W13",
];
const WITNESS_ORGS: [&str; 7] = [
    "WIT-ORG-A",
    "WIT-ORG-B",
    "WIT-ORG-C",
    "WIT-ORG-D",
    "WIT-ORG-E",
    "WIT-ORG-F",
    "WIT-ORG-G",
];
const PROVIDERS: [&str; 4] = ["PROV-1", "PROV-2", "PROV-3", "PROV-4"];
const REGIONS: [&str; 3] = ["REGION-N", "REGION-S", "REGION-W"];
/// The nine witnesses that sign by default (seven organisations, four
/// providers, three regions).
pub const SIGNERS: [usize; 9] = [0, 1, 2, 3, 4, 5, 6, 7, 8];
/// Trustees: identifier and chamber.
const TRUSTEES: [(&str, ChamberCode); 8] = [
    ("T-P1-1", ChamberCode::P1),
    ("T-P1-2", ChamberCode::P1),
    ("T-P2-1", ChamberCode::P2),
    ("T-P2-2", ChamberCode::P2),
    ("T-J", ChamberCode::J),
    ("T-A", ChamberCode::A),
    ("T-C", ChamberCode::C),
    ("T-N", ChamberCode::N),
];
/// The qualified quorum that signs tally events: P1, P2 and three of J,
/// A, C, N (ascending).
pub const QUORUM: [&str; 5] = ["T-A", "T-C", "T-J", "T-P1-1", "T-P2-1"];

fn ident(s: &str) -> Ident<'static> {
    Ident::new(text(s), 64).unwrap()
}
fn org(s: &str) -> OrgId<'static> {
    OrgId::new(text(s)).unwrap()
}
fn signer(s: &str) -> SignerId<'static> {
    SignerId::new(text(s)).unwrap()
}
fn module_id(s: &str) -> ModuleId<'static> {
    ModuleId::new(text(s)).unwrap()
}
fn modules_of(ids: &[&str]) -> ModuleIds<'static> {
    let mut v: Vec<ModuleId<'static>> = ids.iter().map(|m| module_id(m)).collect();
    v.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    ModuleIds::new(leak_slice(v)).unwrap()
}

/// A person who signs events: identifier, role, organisation, key label.
#[derive(Debug, Clone)]
pub struct Person {
    /// Roster identifier.
    pub id: &'static str,
    /// The role they sign events in.
    pub role: EventRole,
    /// Their organisation.
    pub org: &'static str,
    /// Their key label.
    pub key: String,
}

/// A chamber module of a device.
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    /// Module identifier.
    pub id: &'static str,
    /// Its chamber.
    pub chamber: ChamberCode,
    /// The device it sits in.
    pub device: &'static str,
    /// Whether that device is a check-in unit.
    pub unit: bool,
    /// Key label.
    pub key: String,
}

/// A box of the election.
#[derive(Debug, Clone)]
pub struct BoxInfo {
    /// Identifier.
    pub id: &'static str,
    /// Station index.
    pub station: usize,
    /// Index within the station.
    pub index: usize,
    /// Ballot style.
    pub style: &'static str,
    /// Candidates of the style.
    pub candidates: u16,
    /// Reporting unit.
    pub unit: &'static str,
    /// Out-of-district.
    pub absentee: bool,
    /// Device key label.
    pub device: String,
    /// Modules, ascending by identifier.
    pub mods: Vec<ModuleInfo>,
}

/// A station of the election.
#[derive(Debug, Clone)]
pub struct StationInfo {
    /// Identifier.
    pub id: &'static str,
    /// The unit in service and its spare.
    pub units: [&'static str; 2],
    /// The two clerks and two observers (of two organisations).
    pub people: Vec<Person>,
    /// Global box indexes.
    pub boxes: Vec<usize>,
}

/// A cast record and the secrets it was made from.
#[derive(Debug, Clone, Copy)]
pub struct CastInfo {
    /// The `CastRecord` object.
    pub event: &'static [u8],
    /// The body object.
    pub body: &'static [u8],
    /// The tracking code (body hash).
    pub code: Hash512,
    /// The option index.
    pub option: u16,
    /// The voter's mark.
    pub mark: Mark,
    /// The cast id.
    pub cast_id: CastId,
    /// Summed randomness per chunk.
    pub rand: [Scalar; MAX_CHUNKS],
    /// Module counter.
    pub counter: u64,
    /// Chunks.
    pub chunks: u8,
    /// The slot it was cast in.
    pub slot: u64,
    /// The device's record signature.
    pub device_sig: &'static [u8; 64],
    /// The modules' record signatures.
    pub module_sigs: &'static [ModuleRecordSig<'static>],
}

/// A whole signed election.
pub struct Election {
    /// What it was built from.
    pub spec: ElectionSpec,
    /// The election identifier.
    pub eid: &'static str,
    /// The genesis pin.
    pub pin: Hash512,
    /// The `SignedGenesis` object.
    pub signed: &'static [u8],
    /// The amendable sets, encoded.
    pub sets: AmendableSets<'static>,
    /// The fixed sets, encoded.
    pub fixed: FixedSets<'static>,
    genesis: Option<&'static VerifiedGenesis<'static>>,
    /// The `SignedLegalAuthorization` object.
    pub authorization: &'static [u8],
    /// Boxes, in station order.
    pub boxes: Vec<BoxInfo>,
    /// Stations.
    pub stations: Vec<StationInfo>,
    /// Every module.
    pub modules: Vec<ModuleInfo>,
    /// Each station's day.
    pub days: Vec<Day>,
    /// Each box's records.
    pub casts: Vec<Vec<CastInfo>>,
    /// Global people (provisioning and ceremony observers, custodian,
    /// court, chairs).
    pub observers: [Person; 2],
    /// Each unit's chair.
    pub chairs: Vec<(&'static str, Person)>,
    /// The two auditors (of two organisations) who sign sample comparisons
    /// and audit findings.
    pub auditors: [Person; 2],
    /// The raw sets, kept to amend.
    pub(crate) raw: Raw,
}

/// The encoded sets of a genesis state.
#[derive(Clone)]
pub(crate) struct Raw {
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
    pub timestamps: Vec<&'static [u8]>,
    pub rolls: Vec<&'static [u8]>,
}

fn encode_set<'a, T: GenesisEntry<'a> + Encode + Clone>(items: &[T]) -> Vec<&'static [u8]> {
    let mut items = items.to_vec();
    items.sort_by(|a, b| a.key().cmp(b.key()));
    let schema = T::SET.schema().unwrap();
    items.iter().map(|t| object(schema, t)).collect()
}

fn commit_objects(objects: &[&[u8]]) -> SetCommitment {
    let mut acc = Accumulator::empty();
    for o in objects {
        acc.push(&object_hash(o)).unwrap();
    }
    SetCommitment {
        count: objects.len() as u64,
        root: acc.root(),
    }
}

impl Raw {
    fn commitments(&self) -> [SetCommitment; ENTRY_SET_COUNT] {
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
                root: sorted_set_root(&self.appointments).unwrap(),
            },
            commit_objects(&self.styles),
            commit_objects(&self.trustees),
            commit_objects(&self.witnesses),
            commit_objects(&self.timestamps),
            commit_objects(&self.rolls),
        ]
    }

    fn amendable(&self) -> AmendableSets<'static> {
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

    fn fixed(&self) -> FixedSets<'static> {
        FixedSets {
            ballot_styles: leak_slice(self.styles.clone()),
            trustees: leak_slice(self.trustees.clone()),
            witnesses: leak_slice(self.witnesses.clone()),
            timestamp_authorities: leak_slice(self.timestamps.clone()),
            roll_authorities: leak_slice(self.rolls.clone()),
        }
    }
}

/// The roll's authorities of every simulated election (ADR-0040): one
/// district head for every precinct, the Ministry's snapshot, and three
/// custodians (the court administration, the Ministry, the committee).
pub const ROLL_AUTHORITIES: [(&str, &str, RollAuthorityKind); 5] = [
    ("R-C-INT", "MOIS-SIM", RollAuthorityKind::CustodianInterior),
    ("R-C-IVC", "IVC-SIM", RollAuthorityKind::CustodianCommittee),
    (
        "R-C-JUD",
        "COURT-ADMIN-SIM",
        RollAuthorityKind::CustodianJudiciary,
    ),
    ("R-GU", "DISTRICT-SIM", RollAuthorityKind::ResidentExtract),
    (
        "R-SNAPSHOT",
        "MOIS-SIM",
        RollAuthorityKind::ResidentSnapshot,
    ),
];

/// The roll's extracts with their sources, the freeze body, the frozen
/// state and the sources root.
type RollBodies = (
    Vec<(&'static [u8], &'static str)>,
    &'static [u8],
    RollState,
    Hash512,
);

/// The options of a style with `candidates` candidates (BLANK and
/// UNREADABLE added).
#[must_use]
pub const fn options_of(candidates: u16) -> u16 {
    candidates + 2
}

impl Election {
    fn key(&self, what: &str) -> String {
        format!("{}/{what}", self.eid)
    }

    /// Key label of the commission.
    #[must_use]
    pub fn commission(&self) -> String {
        self.key("commission")
    }

    /// Key label of the committee.
    #[must_use]
    pub fn committee(&self) -> String {
        self.key("committee")
    }

    /// Key label of witness `i`.
    #[must_use]
    pub fn witness(&self, i: usize) -> String {
        self.key(&format!("witness/{}", WITNESS_IDS[i]))
    }

    /// Key label of trustee `id`.
    #[must_use]
    pub fn trustee(&self, id: &str) -> String {
        self.key(&format!("trustee/{id}"))
    }

    /// The roll authority `id` signing in the role its function gives.
    #[must_use]
    pub fn roll_signer(&self, id: &'static str) -> Person {
        let (id, o, kind) = *ROLL_AUTHORITIES.iter().find(|a| a.0 == id).unwrap();
        Person {
            id,
            role: if kind.is_custodian() {
                EventRole::RollCustodian
            } else {
                EventRole::RollSource
            },
            org: o,
            key: self.key(&format!("roll/{id}")),
        }
    }

    /// The election identifier as an encoding value.
    #[must_use]
    pub fn election_id(&self) -> ityv_encoding::ElectionId<'static> {
        ityv_encoding::ElectionId::new(text(self.eid)).unwrap()
    }

    /// The box with identifier `id`.
    #[must_use]
    pub fn box_index(&self, id: &str) -> usize {
        self.boxes.iter().position(|b| b.id == id).unwrap()
    }

    /// The station with identifier `id`.
    #[must_use]
    pub fn station_index(&self, id: &str) -> usize {
        self.stations.iter().position(|s| s.id == id).unwrap()
    }

    /// Builds and signs the election of `spec`: genesis, keys, days and
    /// records.
    #[must_use]
    pub fn build(spec: ElectionSpec) -> Self {
        let eid = spec.election_id;
        let key = |what: &str| format!("{eid}/{what}");
        let mut boxes: Vec<BoxInfo> = Vec::new();
        let mut stations: Vec<StationInfo> = Vec::new();
        let mut modules: Vec<ModuleInfo> = Vec::new();
        let party_chambers: Vec<ChamberCode> = spec.parties.iter().map(|p| p.chamber).collect();
        let module_name = |device: &str, c: ChamberCode| -> &'static str {
            leak_str(format!("M-{device}-{c:?}"))
        };
        for (si, s) in spec.stations.iter().enumerate() {
            let units = [
                leak_str(format!("{}-UA", s.id)),
                leak_str(format!("{}-UB", s.id)),
            ];
            for u in units {
                for c in &party_chambers {
                    modules.push(ModuleInfo {
                        id: module_name(u, *c),
                        chamber: *c,
                        device: u,
                        unit: true,
                        key: key(&format!("module/{}", module_name(u, *c))),
                    });
                }
            }
            let people = vec![
                Person {
                    id: leak_str(format!("{}-clerk-1", s.id)),
                    role: EventRole::Clerk,
                    org: "ORG-STATION",
                    key: key(&format!("roster/{}-clerk-1", s.id)),
                },
                Person {
                    id: leak_str(format!("{}-clerk-2", s.id)),
                    role: EventRole::Clerk,
                    org: "ORG-STATION",
                    key: key(&format!("roster/{}-clerk-2", s.id)),
                },
                Person {
                    id: leak_str(format!("{}-obs-a", s.id)),
                    role: EventRole::Observer,
                    org: "PARTY-A",
                    key: key(&format!("roster/{}-obs-a", s.id)),
                },
                Person {
                    id: leak_str(format!("{}-obs-b", s.id)),
                    role: EventRole::Observer,
                    org: "PARTY-B",
                    key: key(&format!("roster/{}-obs-b", s.id)),
                },
            ];
            let mut idx = Vec::new();
            for (bi, b) in s.boxes.iter().enumerate() {
                let mut mods: Vec<ModuleInfo> = party_chambers
                    .iter()
                    .map(|c| ModuleInfo {
                        id: module_name(b.id, *c),
                        chamber: *c,
                        device: b.id,
                        unit: false,
                        key: key(&format!("module/{}", module_name(b.id, *c))),
                    })
                    .collect();
                mods.sort_by(|a, b| a.id.cmp(b.id));
                modules.extend(mods.iter().cloned());
                idx.push(boxes.len());
                boxes.push(BoxInfo {
                    id: b.id,
                    station: si,
                    index: bi,
                    style: b.style,
                    candidates: spec.style(b.style).candidates.len() as u16,
                    unit: b.unit,
                    absentee: b.absentee,
                    device: key(&format!("box/{}/device", b.id)),
                    mods,
                });
            }
            stations.push(StationInfo {
                id: s.id,
                units,
                people,
                boxes: idx,
            });
        }
        let observers = [
            Person {
                id: "obs-a",
                role: EventRole::Observer,
                org: "PARTY-A",
                key: key("roster/obs-a"),
            },
            Person {
                id: "obs-b",
                role: EventRole::Observer,
                org: "PARTY-B",
                key: key("roster/obs-b"),
            },
        ];
        let chairs: Vec<(&'static str, Person)> = spec
            .units
            .iter()
            .map(|u| {
                (
                    u.id,
                    Person {
                        id: leak_str(format!("chair-{}", u.id)),
                        role: EventRole::Chair,
                        org: u.commission,
                        key: key(&format!("roster/chair-{}", u.id)),
                    },
                )
            })
            .collect();
        let auditors = [
            Person {
                id: "aud-1",
                role: EventRole::Auditor,
                org: "AUDIT-A",
                key: key("roster/aud-1"),
            },
            Person {
                id: "aud-2",
                role: EventRole::Auditor,
                org: "AUDIT-B",
                key: key("roster/aud-2"),
            },
        ];
        let days: Vec<Day> = spec.stations.iter().map(|s| simulate(&spec, s)).collect();

        let mut election = Self {
            eid,
            pin: Hash512::ZERO,
            signed: &[],
            sets: AmendableSets {
                boxes: &[],
                stations: &[],
                progress_policies: &[],
                reporting_units: &[],
                routes: &[],
                roster: &[],
                modules: &[],
                appointments: &[],
            },
            fixed: FixedSets {
                ballot_styles: &[],
                trustees: &[],
                witnesses: &[],
                timestamp_authorities: &[],
                roll_authorities: &[],
            },
            genesis: None,
            authorization: &[],
            boxes,
            stations,
            modules,
            days,
            casts: Vec::new(),
            observers,
            chairs,
            auditors,
            raw: Raw {
                boxes: Vec::new(),
                stations: Vec::new(),
                policies: Vec::new(),
                units: Vec::new(),
                routes: Vec::new(),
                roster: Vec::new(),
                modules: Vec::new(),
                appointments: Vec::new(),
                styles: Vec::new(),
                trustees: Vec::new(),
                witnesses: Vec::new(),
                timestamps: Vec::new(),
                rolls: Vec::new(),
            },
            spec,
        };
        election.seal_genesis();
        let mut casts = Vec::new();
        for (bi, b) in election.boxes.iter().enumerate() {
            let day = &election.days[b.station];
            let list: Vec<CastInfo> = day.casts[b.index]
                .iter()
                .enumerate()
                .map(|(i, c)| {
                    election.cast(
                        bi,
                        i as u64 + 1,
                        c.mark.option(b.candidates),
                        c.mark,
                        c.slot,
                        0,
                    )
                })
                .collect();
            casts.push(list);
        }
        election.casts = casts;
        election
    }

    fn roster_entries(&self) -> Vec<RosterSigner<'static>> {
        let mut out = Vec::new();
        let mut n = 0u8;
        let mut add = |p: &Person, role: RosterRole, station: Option<&'static str>| {
            n = n.wrapping_add(1);
            out.push(RosterSigner {
                signer_id: signer(p.id),
                role,
                org_id: org(p.org),
                station_id: station.map(|s| StationId::new(text(s)).unwrap()),
                key: registered(&p.key),
                appointment_hash: hash_of("appointment", &[p.id.as_bytes()]),
            });
        };
        for s in &self.stations {
            for p in &s.people {
                let role = if p.role == EventRole::Clerk {
                    RosterRole::Clerk
                } else {
                    RosterRole::Observer
                };
                add(p, role, Some(s.id));
            }
        }
        for p in &self.observers {
            add(p, RosterRole::Observer, None);
        }
        for (_, p) in &self.chairs {
            add(p, RosterRole::Chair, None);
        }
        for p in &self.auditors {
            add(p, RosterRole::Auditor, None);
        }
        let police = Person {
            id: "police-1",
            role: EventRole::Sender,
            org: "POLICE",
            key: self.key("roster/police-1"),
        };
        add(&police, RosterRole::Custodian, None);
        let court = Person {
            id: "court",
            role: EventRole::Authority,
            org: "COURT",
            key: self.key("roster/court"),
        };
        add(&court, RosterRole::Authority, None);
        out
    }

    fn legal_authorization(&self) -> (&'static [u8], &'static [u8]) {
        let scopes = [
            Scope::PublicBoard,
            Scope::TrusteeBody,
            Scope::BallotMark,
            Scope::CryptoTallyAid,
            Scope::Rla,
            Scope::ObserverAccess,
        ];
        let body = LegalAuthorizationBody::new(
            self.election_id(),
            ScopeSet::from_slice(&scopes),
            hash_of("legal-basis", &[self.eid.as_bytes()]),
            EpochDay::new(EPOCH_DAY),
            EpochDay::new(EPOCH_DAY + 100),
        )
        .unwrap();
        let body = object(SCHEMA_LEGAL_AUTHORIZATION, &body);
        let signed = SignedLegalAuthorization::new(
            body,
            sign(&self.commission(), b"legal-auth", body),
            sign(&self.committee(), b"legal-auth", body),
        )
        .unwrap();
        (body, object(SCHEMA_SIGNED_LEGAL_AUTHORIZATION, &signed))
    }

    /// The provisioning record of module `m` (VC-093, VC-095).
    #[must_use]
    pub fn provisioning(&self, m: &ModuleInfo) -> &'static [u8] {
        let message = group(
            &ModuleProvisionedMessage::new(&ModuleProvisionedParts {
                election_id: self.election_id(),
                module_id: module_id(m.id),
                device_id: ident(m.device),
                chamber: m.chamber,
                member_count: 2,
                pad_length: 1 << 20,
                chassis_id: ident(&format!("CH-{}", m.device)),
                pad_card_id: ident(&format!("PAD-{}", m.id)),
                reprovision_count: 0,
                chassis_check_hash: hash_of("chassis", &[m.id.as_bytes()]),
                kem_ek: kem_key(),
                entropy_commitment: hash_of("entropy", &[m.id.as_bytes()]),
                se_present: m.unit,
                prf_key_check: m.unit.then(|| self.prf(m.chamber)),
            })
            .unwrap(),
        );
        let member = if m.chamber == ChamberCode::P1 {
            "T-P1-1"
        } else {
            "T-P2-1"
        };
        let mut signers: Vec<(&str, String)> = vec![
            ("committee", self.committee()),
            (member, self.trustee(member)),
            (self.observers[0].id, self.observers[0].key.clone()),
            (self.observers[1].id, self.observers[1].key.clone()),
        ];
        signers.sort_by(|a, b| a.0.cmp(b.0));
        let sigs: Vec<ActorSig<'static>> = signers
            .iter()
            .map(|(name, k)| ActorSig {
                actor_id: ident(name),
                sig: sign(k, b"module-provisioned", message),
            })
            .collect();
        object(
            SCHEMA_MODULE_PROVISIONED,
            &ModuleProvisioned::new(message, &sigs).unwrap(),
        )
    }

    fn prf(&self, chamber: ChamberCode) -> &'static [u8; 32] {
        let d = digest("prf-key-check", &[self.eid.as_bytes(), &[chamber.code()]]);
        let mut out = [0u8; 32];
        out.copy_from_slice(&d[..32]);
        leak(out)
    }

    /// The key ceremony of party `chamber` (VC-092).
    #[must_use]
    pub fn ceremony(&self, chamber: ChamberCode) -> &'static [u8] {
        let (first, second) = if chamber == ChamberCode::P1 {
            ("T-P1-1", "T-P1-2")
        } else {
            ("T-P2-1", "T-P2-2")
        };
        let holders = [
            ShareHolder {
                trustee_id: TrusteeId::new(text(first)).unwrap(),
                hsm_model: ident("HSM-MODEL-ALPHA"),
                hsm_serial_hash: hash_of("hsm", &[first.as_bytes()]),
            },
            ShareHolder {
                trustee_id: TrusteeId::new(text(second)).unwrap(),
                hsm_model: ident("HSM-MODEL-BETA"),
                hsm_serial_hash: hash_of("hsm", &[second.as_bytes()]),
            },
        ];
        let message = group(
            &PartyKeyMessage::new(&PartyKeyParts {
                election_id: self.election_id(),
                chamber,
                wrapped_module_count: (self.stations.len() * 2) as u32,
                share_threshold: 2,
                share_holders: leak_slice(holders.to_vec()),
                prf_key_check: self.prf(chamber),
                time_bucket: TimeBucket::new(50),
            })
            .unwrap(),
        );
        let mut signers: Vec<(&str, String)> = vec![
            (first, self.trustee(first)),
            (second, self.trustee(second)),
            ("committee", self.committee()),
            (self.observers[0].id, self.observers[0].key.clone()),
            (self.observers[1].id, self.observers[1].key.clone()),
        ];
        signers.sort_by(|a, b| a.0.cmp(b.0));
        let sigs: Vec<ActorSig<'static>> = signers
            .iter()
            .map(|(name, k)| ActorSig {
                actor_id: ident(name),
                sig: sign(k, b"party-key", message),
            })
            .collect();
        object(
            SCHEMA_PARTY_KEY_CEREMONY,
            &PartyKeyCeremony::new(message, &sigs).unwrap(),
        )
    }

    fn draft_sets(&self) -> Raw {
        let s = &self.spec;
        let gboxes: Vec<GenesisBox<'static>> = self
            .boxes
            .iter()
            .map(|b| GenesisBox {
                box_id: BoxId::new(text(b.id)).unwrap(),
                station_id: StationId::new(text(self.stations[b.station].id)).unwrap(),
                ballot_style_id: BallotStyleId::new(text(b.style)).unwrap(),
                profile: if b.absentee {
                    CaptureProfile::Absentee
                } else {
                    CaptureProfile::InPerson
                },
                route_id: RouteId::new(if b.absentee { b"R-POST" } else { b"R-ESCORT" }).unwrap(),
                reporting_unit_id: ReportingUnitId::new(text(b.unit)).unwrap(),
                device_key: registered(&b.device),
                attest_key: registered(&format!("{}/attest", b.device)),
                modules: modules_of(&b.mods.iter().map(|m| m.id).collect::<Vec<_>>()),
            })
            .collect();
        let unit_entry = |u: &'static str| -> CheckinUnit<'static> {
            let mods: Vec<&str> = self
                .modules
                .iter()
                .filter(|m| m.device == u)
                .map(|m| m.id)
                .collect();
            CheckinUnit {
                unit_id: UnitId::new(text(u)).unwrap(),
                key: registered(&self.key(&format!("unit/{u}"))),
                attest_key: registered(&self.key(&format!("unit/{u}/attest"))),
                modules: modules_of(&mods),
            }
        };
        let stations: Vec<StationEntry<'static>> = self
            .stations
            .iter()
            .zip(&s.stations)
            .map(|(st, spec)| {
                let mut box_ids: Vec<BoxId<'static>> = st
                    .boxes
                    .iter()
                    .map(|b| BoxId::new(text(self.boxes[*b].id)).unwrap())
                    .collect();
                box_ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
                let tokens: Vec<ObserverToken<'static>> = st
                    .people
                    .iter()
                    .filter(|p| p.role == EventRole::Observer)
                    .map(|p| ObserverToken {
                        observer_id: signer(p.id),
                        org_id: org(p.org),
                        check_key: ed25519_half(&self.key(&format!("token/{}", p.id))),
                    })
                    .collect();
                StationEntry::new(&StationParts {
                    station_id: StationId::new(text(st.id)).unwrap(),
                    kind: spec.kind,
                    primary: unit_entry(st.units[0]),
                    spare: unit_entry(st.units[1]),
                    boxes: leak_slice(box_ids),
                    id_terminals_hash: hash_of("id-terminals", &[st.id.as_bytes()]),
                    tokens: leak_slice(tokens),
                })
                .unwrap()
            })
            .collect();
        let policies: Vec<StationProgressPolicy<'static>> = s
            .stations
            .iter()
            .zip(&self.days)
            .map(|(st, day)| {
                StationProgressPolicy::new(
                    StationId::new(text(st.id)).unwrap(),
                    st.booths,
                    day.limit as u32,
                )
                .unwrap()
            })
            .collect();
        let units: Vec<ReportingUnitEntry<'static>> = s
            .units
            .iter()
            .map(|u| {
                let count = self.boxes.iter().filter(|b| b.unit == u.id).count() as u32;
                ReportingUnitEntry::new(
                    ReportingUnitId::new(text(u.id)).unwrap(),
                    count,
                    org(u.commission),
                )
                .unwrap()
            })
            .collect();
        let routes = vec![
            CustodyRoute::new(
                RouteId::new(b"R-ESCORT").unwrap(),
                true,
                &[org("ORG-STATION"), org("POLICE"), org("ORG-COUNT")],
            )
            .unwrap(),
            CustodyRoute::new(
                RouteId::new(b"R-POST").unwrap(),
                false,
                &[org("ORG-STATION"), org("POST"), org("ORG-COUNT")],
            )
            .unwrap(),
        ];
        let roster = self.roster_entries();
        let module_entries: Vec<ModuleEntry<'static>> = self
            .modules
            .iter()
            .map(|m| ModuleEntry {
                module_id: module_id(m.id),
                chamber: m.chamber,
                key: registered(&m.key),
                attest_key: registered(&format!("{}/attest", m.key)),
                provisioned_hash: object_hash(self.provisioning(m)),
            })
            .collect();
        let styles: Vec<BallotStyleEntry<'static>> = s
            .styles
            .iter()
            .map(|st| {
                BallotStyleEntry::new(
                    BallotStyleId::new(text(st.id)).unwrap(),
                    st.candidates.len() as u16,
                    hash_of("layout", &[st.id.as_bytes()]),
                )
                .unwrap()
            })
            .collect();
        let trustees: Vec<TrusteeEntry<'static>> = TRUSTEES
            .iter()
            .map(|(tid, chamber)| TrusteeEntry {
                trustee_id: TrusteeId::new(text(tid)).unwrap(),
                chamber: *chamber,
                org_id: org("TRUST-ORG"),
                key: registered(&self.trustee(tid)),
                appointment_hash: hash_of("appointment", &[tid.as_bytes()]),
            })
            .collect();
        let witnesses: Vec<WitnessRosterEntry<'static>> = (0..13)
            .map(|i| WitnessRosterEntry {
                witness_id: ident(WITNESS_IDS[i]),
                org_id: org(WITNESS_ORGS[i % WITNESS_ORGS.len()]),
                provider: ident(PROVIDERS[i % PROVIDERS.len()]),
                region: ident(REGIONS[i % REGIONS.len()]),
                key: registered(&self.witness(i)),
                appointment_hash: hash_of("appointment", &[WITNESS_IDS[i].as_bytes()]),
            })
            .collect();
        let mut appointments: Vec<Hash512> = roster
            .iter()
            .map(|r| r.appointment_hash)
            .chain(trustees.iter().map(|t| t.appointment_hash))
            .chain(witnesses.iter().map(|w| w.appointment_hash))
            .collect();
        appointments.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        appointments.dedup();
        Raw {
            boxes: encode_set(&gboxes),
            stations: encode_set(&stations),
            policies: encode_set(&policies),
            units: encode_set(&units),
            routes: encode_set(&routes),
            roster: encode_set(&roster),
            modules: encode_set(&module_entries),
            appointments,
            styles: encode_set(&styles),
            trustees: encode_set(&trustees),
            witnesses: encode_set(&witnesses),
            timestamps: encode_set(&crate::tsa::authorities()),
            rolls: encode_set(&self.roll_entries()),
        }
    }

    fn roll_entries(&self) -> Vec<RollAuthorityEntry<'static>> {
        ROLL_AUTHORITIES
            .iter()
            .map(|(id, o, kind)| RollAuthorityEntry {
                authority_id: ityv_encoding::AuthorityId::new(text(id)).unwrap(),
                org_id: org(o),
                kind: *kind,
                key: registered(&self.key(&format!("roll/{id}"))),
            })
            .collect()
    }

    /// Signs `body` under `purpose` by the commission, the committee and
    /// the default witnesses: the encoded `SignedGenesis`.
    fn seal(&self, body: &'static [u8], purpose: &[u8]) -> &'static [u8] {
        let c = sign(&self.commission(), purpose, body);
        let k = sign(&self.committee(), purpose, body);
        let sigs: Vec<GenesisWitnessSig<'static>> = SIGNERS
            .iter()
            .map(|&i| GenesisWitnessSig {
                witness_id: ident(WITNESS_IDS[i]),
                sig: sign(&self.witness(i), purpose, body),
            })
            .collect();
        let signed = SignedGenesis::new(body, c, k, &sigs).unwrap();
        object(SCHEMA_SIGNED_GENESIS, &signed)
    }

    fn seal_genesis(&mut self) {
        let raw = self.draft_sets();
        let (auth_body, authorization) = self.legal_authorization();
        let parties: Vec<PartyEntry<'static>> = self
            .spec
            .parties
            .iter()
            .map(|p| PartyEntry {
                chamber: p.chamber,
                name: p.name,
                seats: p.seats,
                evidence_hash: hash_of("party-evidence", &[p.name.as_bytes()]),
            })
            .collect();
        let chambers = vec![
            ChamberThreshold {
                chamber: ChamberCode::P1,
                threshold: 1,
                members: 2,
            },
            ChamberThreshold {
                chamber: ChamberCode::P2,
                threshold: 1,
                members: 2,
            },
            ChamberThreshold {
                chamber: ChamberCode::J,
                threshold: 1,
                members: 1,
            },
            ChamberThreshold {
                chamber: ChamberCode::A,
                threshold: 1,
                members: 1,
            },
            ChamberThreshold {
                chamber: ChamberCode::C,
                threshold: 1,
                members: 1,
            },
            ChamberThreshold {
                chamber: ChamberCode::N,
                threshold: 1,
                members: 1,
            },
        ];
        let parts = GenesisParts {
            election_id: self.election_id(),
            election_epoch_day: EpochDay::new(EPOCH_DAY),
            policy_hash: hash_of("policy", &[self.eid.as_bytes()]),
            proof_system_id: ident("ityv-orproof-v1"),
            legal_authorization_hash: object_hash(auth_body),
            connectivity_manifest_hash: hash_of("connectivity", &[self.eid.as_bytes()]),
            release_manifest_hash: hash_of("release", &[self.eid.as_bytes()]),
            commission_key: registered(&self.commission()),
            committee_key: registered(&self.committee()),
            quorum: WitnessQuorum {
                witnesses: 13,
                quorum: 9,
                byzantine_max: 4,
                min_orgs: 7,
                min_providers: 4,
                min_regions: 3,
            },
            custody_quorum: 3,
            parties: leak_slice(parties),
            chambers: leak_slice(chambers),
            sets: raw.commitments(),
        };
        let body = GenesisBody::new(&parts).unwrap();
        let body = object(SCHEMA_GENESIS_BODY, &body);
        let signed = self.seal(body, b"genesis");
        let pin = object_hash(body);
        let sets = raw.amendable();
        let fixed = raw.fixed();
        let genesis = ityv_verify::verify_genesis(
            &pin,
            &GenesisInput {
                signed,
                sets,
                fixed,
            },
            &[],
        )
        .unwrap_or_else(|e| panic!("the simulated genesis must verify: {e:?}"));
        self.pin = pin;
        self.signed = signed;
        self.sets = sets;
        self.fixed = fixed;
        self.genesis = Some(leak(genesis));
        self.authorization = authorization;
        self.raw = raw;
    }

    /// The verified genesis.
    #[must_use]
    pub fn genesis(&self) -> &'static VerifiedGenesis<'static> {
        self.genesis.unwrap()
    }

    /// The genesis input (signed genesis and every set).
    #[must_use]
    pub fn input(&self) -> GenesisInput<'static> {
        GenesisInput {
            signed: self.signed,
            sets: self.sets,
            fixed: self.fixed,
        }
    }

    /// An amendment numbered 1 that changes nothing but records a device
    /// replacement statement (all eight sets as they are), for the
    /// missing-amendment scenario.
    #[must_use]
    pub fn unchanged_amendment(&self) -> AmendmentInput<'static> {
        let all = self.raw.commitments();
        let mut sets = [SetCommitment {
            count: 0,
            root: Hash512::ZERO,
        }; AMENDABLE_SET_COUNT];
        sets.copy_from_slice(&all[..AMENDABLE_SET_COUNT]);
        let body = GenesisAmendmentBody::new(&GenesisAmendmentParts {
            election_id: self.election_id(),
            seq: 1,
            previous_hash: self.pin,
            reason: AmendmentReason::DeviceReplacement,
            reason_hash: hash_of("amendment-reason", &[self.eid.as_bytes()]),
            time_bucket: TimeBucket::new(self.days[0].open_bucket - 4),
            release_manifest_hash: hash_of("release", &[self.eid.as_bytes()]),
            sets,
        })
        .unwrap();
        let body = object(SCHEMA_GENESIS_AMENDMENT_BODY, &body);
        AmendmentInput {
            signed: self.seal(body, b"genesis-amendment"),
            sets: self.raw.amendable(),
        }
    }

    // -----------------------------------------------------------------
    // The voter roll (ADR-0033, ADR-0040).

    /// The roll's resident extract for precinct `precinct` (or the
    /// Ministry's snapshot without one), with entries derived from `seed`:
    /// its body and its source.
    fn roll_extract(
        &self,
        kind: RollSourceKind,
        precinct: Option<&'static str>,
        seed: &[u8],
    ) -> (&'static [u8], &'static str) {
        let authority = if kind == RollSourceKind::Snapshot {
            "R-SNAPSHOT"
        } else {
            "R-GU"
        };
        let body = object(
            SCHEMA_ROLL_SOURCE_EXTRACT_BODY,
            &RollSourceExtractBody::new(&RollSourceExtractParts {
                election_id: self.election_id(),
                authority_id: ityv_encoding::AuthorityId::new(text(authority)).unwrap(),
                kind,
                precinct: precinct.map(|p| StationId::new(text(p)).unwrap()),
                reference_day: EpochDay::new(EPOCH_DAY - 30),
                entry_count: 1_000,
                entries_root: hash_of("roll-extract", &[self.eid.as_bytes(), seed]),
            })
            .unwrap(),
        );
        (body, authority)
    }

    /// The roll's extracts (every election-day station's, then the
    /// snapshot), the freeze body over them, the frozen state and the
    /// sources root.
    fn roll_bodies(&self) -> RollBodies {
        let mut extracts: Vec<(&'static [u8], &'static str)> = self
            .spec
            .stations
            .iter()
            .filter(|s| s.kind == StationKind::ElectionDay)
            .map(|s| self.roll_extract(RollSourceKind::Residents, Some(s.id), s.id.as_bytes()))
            .collect();
        extracts.push(self.roll_extract(RollSourceKind::Snapshot, None, b"snapshot"));
        let mut hashes: Vec<Hash512> = extracts.iter().map(|(b, _)| object_hash(b)).collect();
        hashes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let sources_root = sorted_set_root(&hashes).unwrap();
        let state = RollState {
            entries_root: hash_of("roll-entries", &[self.eid.as_bytes()]),
            entry_count: 1_000 * (extracts.len() as u64 - 1),
            counts_hash: hash_of("roll-counts", &[self.eid.as_bytes()]),
            pseudonym_root: hash_of("roll-pseudonyms", &[self.eid.as_bytes()]),
        };
        let freeze = object(
            SCHEMA_ROLL_FREEZE_BODY,
            &RollFreezeBody::new(&RollFreezeParts {
                election_id: self.election_id(),
                state,
                sources_root,
                source_count: u32::try_from(extracts.len()).unwrap(),
                time_bucket: TimeBucket::new(0),
            })
            .unwrap(),
        );
        (extracts, freeze, state, sources_root)
    }

    /// The commission and the committee, who sign the freeze and every
    /// amendment.
    fn roll_authorities(&self) -> [Person; 2] {
        [
            Person {
                id: "nec",
                role: EventRole::Commission,
                org: "NEC",
                key: self.commission(),
            },
            Person {
                id: "ivc",
                role: EventRole::Committee,
                org: "IVC",
                key: self.committee(),
            },
        ]
    }

    /// The receipts of `custodians` for the roll state `state` of the
    /// freeze or amendment body `subject` (the court administration's
    /// carries the pseudonym root; a freeze's carry the sources root).
    fn roll_receipts(
        &self,
        subject: &'static [u8],
        state: RollState,
        sources_root: Option<Hash512>,
        custodians: &[&'static str],
        bucket: u64,
    ) -> Vec<&'static [u8]> {
        custodians
            .iter()
            .map(|custodian| {
                let receipt = object(
                    SCHEMA_ROLL_CUSTODY_RECEIPT_BODY,
                    &RollCustodyReceiptBody::new(&RollCustodyReceiptParts {
                        election_id: self.election_id(),
                        custodian: ityv_encoding::AuthorityId::new(text(custodian)).unwrap(),
                        subject_hash: object_hash(subject),
                        entries_root: state.entries_root,
                        entry_count: state.entry_count,
                        counts_hash: state.counts_hash,
                        sources_root,
                        pseudonym_root: (*custodian == "R-C-JUD").then_some(state.pseudonym_root),
                        time_bucket: TimeBucket::new(bucket),
                    })
                    .unwrap(),
                );
                self.witnessed(receipt, &[self.roll_signer(custodian)], 0)
            })
            .collect()
    }

    /// A complete roll: each election-day station's resident extract by
    /// the district head, the Ministry's snapshot, the freeze of their
    /// merge, and the receipts of the three custodians (the court
    /// administration with the pseudonym root). Each is a `WitnessedEvent`.
    #[must_use]
    pub fn roll(&self) -> Vec<&'static [u8]> {
        let (extracts, freeze, state, sources_root) = self.roll_bodies();
        let mut events: Vec<&'static [u8]> = extracts
            .iter()
            .map(|(body, authority)| self.witnessed(body, &[self.roll_signer(authority)], 0))
            .collect();
        events.push(self.witnessed(freeze, &self.roll_authorities(), 0));
        events.extend(self.roll_receipts(
            freeze,
            state,
            Some(sources_root),
            &["R-C-JUD", "R-C-INT", "R-C-IVC"],
            1,
        ));
        events
    }

    /// A second resident extract of the first election-day station, with
    /// other entries, signed by its district head: after the freeze no
    /// extract is taken (ADR-0040; a change goes through an amendment).
    #[must_use]
    pub fn roll_late_extract(&self) -> &'static [u8] {
        let station = self
            .spec
            .stations
            .iter()
            .find(|s| s.kind == StationKind::ElectionDay)
            .unwrap();
        let (body, authority) = self.roll_extract(
            RollSourceKind::Residents,
            Some(station.id),
            b"added after the freeze",
        );
        self.witnessed(body, &[self.roll_signer(authority)], 0)
    }

    /// Amendment 1 of the roll: an objection decision of the district
    /// head (one voter added), signed by the commission, the committee and
    /// the district head, then the receipts of `custodians` for it.
    #[must_use]
    pub fn roll_amendment(&self, custodians: &[&'static str]) -> Vec<&'static [u8]> {
        let (_, freeze, frozen, _) = self.roll_bodies();
        let state = RollState {
            entries_root: hash_of("roll-entries-amended", &[self.eid.as_bytes()]),
            entry_count: frozen.entry_count + 1,
            counts_hash: hash_of("roll-counts-amended", &[self.eid.as_bytes()]),
            pseudonym_root: hash_of("roll-pseudonyms-amended", &[self.eid.as_bytes()]),
        };
        let amendment = object(
            SCHEMA_ROLL_AMENDMENT_BODY,
            &RollAmendmentBody::new(&RollAmendmentParts {
                election_id: self.election_id(),
                seq: 1,
                previous_hash: object_hash(freeze),
                reason: RollAmendmentReason::ObjectionDecision,
                authority_id: ityv_encoding::AuthorityId::new(text("R-GU")).unwrap(),
                basis_hash: hash_of("roll-objection-decision", &[self.eid.as_bytes()]),
                state,
                time_bucket: TimeBucket::new(2),
            })
            .unwrap(),
        );
        let [commission, committee] = self.roll_authorities();
        let mut events = vec![self.witnessed(
            amendment,
            &[commission, committee, self.roll_signer("R-GU")],
            0,
        )];
        events.extend(self.roll_receipts(amendment, state, None, custodians, 3));
        events
    }

    // -----------------------------------------------------------------
    // Station and box events.

    /// A `WitnessedEvent` over `body` signed by `who` (sorted here), with
    /// signature variant `variant`.
    fn witnessed(&self, body: &'static [u8], who: &[Person], variant: u64) -> &'static [u8] {
        let schema = ityv_encoding::ObjectHeader::read(&mut ityv_encoding::Reader::new(body))
            .unwrap()
            .schema_id();
        let purpose = purpose_of(schema).unwrap();
        let mut who = who.to_vec();
        who.sort_by(|a, b| a.id.cmp(b.id));
        let sigs: Vec<EventSig<'static>> = who
            .iter()
            .map(|p| EventSig {
                signer_id: signer(p.id),
                role: p.role,
                org_id: org(p.org),
                sig: sign_variant(&p.key, purpose, body, variant),
            })
            .collect();
        object(
            SCHEMA_WITNESSED_EVENT,
            &WitnessedEvent::new(body, &sigs).unwrap(),
        )
    }

    /// The station's people signing a station event.
    #[must_use]
    pub fn people(&self, station: usize) -> Vec<Person> {
        self.stations[station].people.clone()
    }

    /// A witnessed event of `station` over `body`.
    #[must_use]
    pub fn station_witnessed(&self, station: usize, body: &'static [u8]) -> &'static [u8] {
        self.witnessed(body, &self.people(station), 0)
    }

    /// Box `b`'s opening.
    #[must_use]
    pub fn opened(&self, b: usize, seals_match: bool) -> &'static [u8] {
        let bx = &self.boxes[b];
        let body = BoxOpenedBody::new(&BoxOpenedParts {
            election_id: self.election_id(),
            box_id: BoxId::new(text(bx.id)).unwrap(),
            modules: modules_of(&bx.mods.iter().map(|m| m.id).collect::<Vec<_>>()),
            seal_digest: SEAL,
            seals_match,
            initial_count: 0,
            time_bucket: TimeBucket::new(self.days[bx.station].open_bucket),
        });
        let body = object(SCHEMA_BOX_OPENED_BODY, &body);
        let mut who = self.people(bx.station);
        who.push(Person {
            id: bx.id,
            role: EventRole::Device,
            org: "ORG-STATION",
            key: bx.device.clone(),
        });
        self.witnessed(body, &who, 0)
    }

    /// Record `counter` of box `b` for `option`, cast in `slot`; its
    /// secrets come from a stream seeded by the box, counter and
    /// `variant`.
    #[must_use]
    pub fn cast(
        &self,
        b: usize,
        counter: u64,
        option: u16,
        mark: Mark,
        slot: u64,
        variant: u64,
    ) -> CastInfo {
        let bx = &self.boxes[b];
        let bases = Bases::derive();
        let tag = [
            self.eid.as_bytes(),
            bx.id.as_bytes(),
            &counter.to_be_bytes()[..],
            &variant.to_be_bytes()[..],
        ];
        let mut r = rng("cast", &tag);
        let options = OptionCount::new(options_of(bx.candidates)).unwrap();
        let chunks = options.chunk_count();
        let mut hasher = Sha3Hasher::new();
        hasher.absorb(b"ityv:castid:v1");
        hasher.absorb(&[0x00]);
        let mut rand = [Scalar::ZERO; MAX_CHUNKS];
        for (mi, _) in bx.mods.iter().enumerate() {
            let d = digest("cid", &[tag[0], tag[1], tag[2], tag[3], &[mi as u8]]);
            hasher.absorb(&d[..24]);
            for sum in rand.iter_mut().take(usize::from(chunks)) {
                let p = Scalar::random(&mut r);
                *sum = sum.add(&p);
            }
        }
        let d = hasher.finish();
        let cast_id = CastId::new(Token192(d[..24].try_into().unwrap()));
        let index = OptionIndex::new(option).unwrap();
        let commitments: Vec<Commitment> = (0..chunks)
            .map(|j| {
                commit(
                    &bases,
                    index,
                    &cast_id,
                    &rand[usize::from(j)],
                    ChunkIndex::new(j).unwrap(),
                )
            })
            .collect();
        let statement = Statement::new(
            self.election_id(),
            ident(bx.id),
            ident(bx.style),
            options,
            &commitments,
        )
        .unwrap();
        let proof = prove(
            &bases,
            &statement,
            &Opening::new(index, cast_id, rand),
            &mut r,
        )
        .unwrap();
        let mut buf = vec![0u8; proof.encoded_len()];
        let mut w = Writer::new(&mut buf);
        proof.encode(&mut w).unwrap();
        let points: Vec<Point32> = commitments.iter().map(|c| c.to_point32()).collect();
        let counters: Vec<ModuleCounter<'static>> = bx
            .mods
            .iter()
            .map(|m| ModuleCounter {
                module_id: module_id(m.id),
                counter,
            })
            .collect();
        let body = CastRecordBody::new(&CastRecordParts {
            election_id: self.election_id(),
            box_id: BoxId::new(text(bx.id)).unwrap(),
            ballot_style_id: BallotStyleId::new(text(bx.style)).unwrap(),
            proof_system_id: 1,
            commitments: Commitments::new(&points).unwrap(),
            proof: leak_slice(buf),
            module_counters: ModuleCounters::new(&counters).unwrap(),
            share_package_hash: hash_of("share-package", &tag),
            transport_flags: 0,
        })
        .unwrap();
        let body = object(SCHEMA_CAST_RECORD_BODY, &body);
        let body_hash = object_hash(body);
        let device_sig = record_sig(&bx.device, RecordPurpose::CastRecord, body);
        let module_sigs: Vec<ModuleRecordSig<'static>> = bx
            .mods
            .iter()
            .map(|m| ModuleRecordSig {
                module_id: module_id(m.id),
                ed25519: record_sig(
                    &m.key,
                    RecordPurpose::ModuleRecord,
                    &module_message(&body_hash, m.id, counter),
                ),
            })
            .collect();
        let module_sigs = leak_slice(module_sigs);
        let event = object(
            SCHEMA_CAST_RECORD,
            &CastRecord::new(body, device_sig, module_sigs).unwrap(),
        );
        CastInfo {
            event,
            body,
            code: body_hash,
            option,
            mark,
            cast_id,
            rand,
            counter,
            chunks,
            slot,
            device_sig,
            module_sigs,
        }
    }

    /// The record `body` carried with another record's signatures (a
    /// record changed after it was signed).
    #[must_use]
    pub fn resigned_with(body_of: &CastInfo, sigs_of: &CastInfo) -> &'static [u8] {
        object(
            SCHEMA_CAST_RECORD,
            &CastRecord::new(body_of.body, sigs_of.device_sig, sigs_of.module_sigs).unwrap(),
        )
    }

    /// Batch `index` of box `b` over counters `first..=last`, attesting
    /// `members`, in time bucket `bucket`.
    #[must_use]
    pub fn batch(
        &self,
        b: usize,
        index: u32,
        (first, last): (u64, u64),
        members: &[Hash512],
        bucket: u64,
    ) -> &'static [u8] {
        let bx = &self.boxes[b];
        let ranges: Vec<ModuleRange<'static>> = bx
            .mods
            .iter()
            .map(|m| ModuleRange {
                module_id: module_id(m.id),
                counter_first: first,
                counter_last: last,
            })
            .collect();
        let body = BatchAttestBody::new(&BatchAttestParts {
            election_id: self.election_id(),
            box_id: BoxId::new(text(bx.id)).unwrap(),
            batch_index: index,
            record_count: u16::try_from(members.len()).unwrap(),
            records_root: root(members),
            module_ranges: leak_slice(ranges),
            module_refusals: ModuleIds::EMPTY,
            journal_head: hash_of("journal", &[bx.id.as_bytes(), &index.to_be_bytes()]),
            time_bucket: TimeBucket::new(bucket),
        })
        .unwrap();
        let body = object(SCHEMA_BATCH_ATTEST_BODY, &body);
        let sigs: Vec<ModuleBatchSig<'static>> = bx
            .mods
            .iter()
            .map(|m| ModuleBatchSig {
                module_id: module_id(m.id),
                sig: sign(&m.key, b"batch-attest", body),
            })
            .collect();
        object(
            SCHEMA_BATCH_ATTEST,
            &BatchAttest::new(body, &sigs, sign(&bx.device, b"batch-attest", body)).unwrap(),
        )
    }

    /// The witnessed late batch close of `batch_event` of box `b`.
    #[must_use]
    pub fn late_batch_close(
        &self,
        b: usize,
        batch_event: &'static [u8],
        bucket: u64,
    ) -> &'static [u8] {
        let bx = &self.boxes[b];
        let parsed: BatchAttest<'static> =
            ityv_encoding::decode_object(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, batch_event)
                .unwrap();
        let body = LateBatchCloseBody::new(&LateBatchCloseParts {
            election_id: self.election_id(),
            box_id: BoxId::new(text(bx.id)).unwrap(),
            batch_body_hash: object_hash(parsed.body_bytes()),
            reason: LateBatchReason::DeviceRestart,
            time_bucket: TimeBucket::new(bucket),
        })
        .unwrap();
        self.station_witnessed(bx.station, object(SCHEMA_LATE_BATCH_CLOSE_BODY, &body))
    }

    /// The close counts of box `b` with `records` records, `attested` of
    /// them attested.
    #[must_use]
    pub fn close_counts(&self, b: usize, records: u64, attested: u64) -> CloseCounts {
        let bx = &self.boxes[b];
        let without = self.days[bx.station].paper_only[bx.index].len() as u64;
        CloseCounts {
            paper: if bx.absentee { 0 } else { records + without },
            records,
            attested,
            without_record: without,
            challenged: 0,
            quarantined: 0,
            visits: records,
            envelopes: if bx.absentee { records } else { 0 },
            stickers: if bx.absentee { records } else { 0 },
            spoil_envelopes: 0,
        }
    }

    /// The close of box `b` with `counts` and the record set `codes`;
    /// `device` names the purpose the device and the people sign under
    /// (`box-close`, `late-box-close`), `None` for a manual close.
    #[must_use]
    pub fn close(
        &self,
        b: usize,
        counts: CloseCounts,
        codes: &[Hash512],
        device: Option<&[u8]>,
        people: Option<&[Person]>,
    ) -> &'static [u8] {
        let bx = &self.boxes[b];
        let purpose = device.unwrap_or(b"box-close");
        let last = counts.records + counts.challenged + counts.quarantined;
        let counters: Vec<ModuleCounter<'static>> = bx
            .mods
            .iter()
            .map(|m| ModuleCounter {
                module_id: module_id(m.id),
                counter: last,
            })
            .collect();
        let body = BoxCloseBody::new(&BoxCloseParts {
            election_id: self.election_id(),
            box_id: BoxId::new(text(bx.id)).unwrap(),
            counts,
            record_set_root: root(codes),
            journal_head: hash_of("journal-close", &[bx.id.as_bytes()]),
            seal_digest: SEAL,
            module_counters: ModuleCounters::new(&counters).unwrap(),
            open_batches: u8::from(counts.attested < counts.records),
            time_bucket: TimeBucket::new(self.days[bx.station].close_bucket),
        });
        let body = object(SCHEMA_BOX_CLOSE_BODY, &body);
        let people = people.map_or_else(|| self.people(bx.station), <[Person]>::to_vec);
        let attestations: Vec<Attestation<'static>> = people
            .iter()
            .map(|p| Attestation {
                signer_id: signer(p.id),
                role: if p.role == EventRole::Clerk {
                    SignerRole::Clerk
                } else {
                    SignerRole::Observer
                },
                org_id: org(p.org),
                sig: sign(&p.key, purpose, body),
            })
            .collect();
        object(
            SCHEMA_BOX_CLOSE,
            &BoxClose::new(
                body,
                device.map(|p| sign(&bx.device, p, body)),
                &attestations,
            )
            .unwrap(),
        )
    }

    /// Box `b`'s progress tick.
    #[must_use]
    pub fn box_tick(
        &self,
        b: usize,
        slot: u64,
        sheets_in: u64,
        state: BoxProgressState,
    ) -> &'static [u8] {
        let bx = &self.boxes[b];
        let body = object(
            SCHEMA_BOX_PROGRESS_BODY,
            &BoxProgressBody::new(&BoxProgressParts {
                election_id: self.election_id(),
                box_id: BoxId::new(text(bx.id)).unwrap(),
                slot,
                sheets_in,
                state,
            }),
        );
        object(
            SCHEMA_PROGRESS_TICK,
            &ProgressTick::new(body, sign(&bx.device, b"box-progress", body)).unwrap(),
        )
    }

    /// Station `s`'s check-in unit tick.
    #[must_use]
    pub fn checkin_tick(
        &self,
        s: usize,
        slot: u64,
        c: [u64; 4],
        state: CheckinProgressState,
    ) -> &'static [u8] {
        let st = &self.stations[s];
        let body = object(
            SCHEMA_CHECKIN_PROGRESS_BODY,
            &CheckinProgressBody::new(&CheckinProgressParts {
                election_id: self.election_id(),
                station_id: StationId::new(text(st.id)).unwrap(),
                unit_id: UnitId::new(text(st.units[0])).unwrap(),
                slot,
                checkins: c[0],
                issued: c[1],
                spoiled: c[2],
                returned: c[3],
                state,
            })
            .unwrap(),
        );
        let key = self.key(&format!("unit/{}", st.units[0]));
        object(
            SCHEMA_PROGRESS_TICK,
            &ProgressTick::new(body, sign(&key, b"checkin-progress", body)).unwrap(),
        )
    }

    /// The fallback event of box `b`.
    #[must_use]
    pub fn fallback(&self, b: usize, declared: bool, bucket: u64) -> &'static [u8] {
        let bx = &self.boxes[b];
        let body = FallbackBody::new(&FallbackParts {
            election_id: self.election_id(),
            box_id: BoxId::new(text(bx.id)).unwrap(),
            kind: if declared {
                FallbackKind::Declared
            } else {
                FallbackKind::Ended
            },
            reason: if declared {
                FallbackReason::ScannerFault
            } else {
                FallbackReason::NotApplicable
            },
            statement_hash: hash_of(
                "fallback-statement",
                &[bx.id.as_bytes(), &[u8::from(declared)]],
            ),
            markers: None,
            time_bucket: TimeBucket::new(bucket),
        })
        .unwrap();
        self.station_witnessed(bx.station, object(SCHEMA_FALLBACK_BODY, &body))
    }

    /// An on-site check at station `s`.
    #[must_use]
    pub fn progress_check(
        &self,
        s: usize,
        alarm_slot: u64,
        alarm: ProgressAlarm,
        finding: ProgressFinding,
        holding: u64,
        bucket: u64,
    ) -> &'static [u8] {
        let st = &self.stations[s];
        let body = ProgressCheckBody::new(&ProgressCheckParts {
            election_id: self.election_id(),
            station_id: StationId::new(text(st.id)).unwrap(),
            alarm_slot,
            alarm,
            holding,
            finding,
            carried_out: u64::from(finding == ProgressFinding::CarriedOut),
            statement_hash: hash_of(
                "check-statement",
                &[st.id.as_bytes(), &alarm_slot.to_be_bytes()],
            ),
            time_bucket: TimeBucket::new(bucket),
        })
        .unwrap();
        self.station_witnessed(s, object(SCHEMA_PROGRESS_CHECK_BODY, &body))
    }

    /// Station `s`'s issuance count at close, signed by `who`.
    #[must_use]
    pub fn issuance(&self, s: usize, who: &[Person]) -> &'static [u8] {
        let st = &self.stations[s];
        let day = &self.days[s];
        let last = day.last();
        let stock = (last.issued / 100 + 1) * 100 + 50;
        let absentee: Vec<usize> = st
            .boxes
            .iter()
            .copied()
            .filter(|b| self.boxes[*b].absentee)
            .collect();
        let envelopes = (!absentee.is_empty()).then(|| {
            let cast: u64 = absentee.iter().map(|b| self.casts[*b].len() as u64).sum();
            let empty: u64 = absentee
                .iter()
                .map(|b| day.returned_by_box[self.boxes[*b].index])
                .sum();
            EnvelopeIssuance {
                issued: cast + empty,
                returned_empty: empty,
            }
        });
        let body = IssuanceCountBody::new(&IssuanceCountParts {
            election_id: self.election_id(),
            station_id: StationId::new(text(st.id)).unwrap(),
            stock_received: stock,
            issued: last.issued,
            voter_spoiled: last.spoiled,
            returned: last.returned,
            unused: stock - last.issued,
            printer_waste: 0,
            envelopes,
            time_bucket: TimeBucket::new(day.close_bucket),
        });
        self.witnessed(object(SCHEMA_ISSUANCE_COUNT_BODY, &body), who, 0)
    }

    /// Station `s`'s observers' final check-in count.
    #[must_use]
    pub fn observer_count(&self, s: usize) -> &'static [u8] {
        let st = &self.stations[s];
        let day = &self.days[s];
        let body = ObserverCountAttestBody::new(&ObserverCountParts {
            election_id: self.election_id(),
            station_id: StationId::new(text(st.id)).unwrap(),
            unit_id: UnitId::new(text(st.units[0])).unwrap(),
            count: day.last().checkins,
            kind: ObserverCountKind::Final,
            time_bucket: TimeBucket::new(day.close_bucket),
        });
        let observers: Vec<Person> = st
            .people
            .iter()
            .filter(|p| p.role == EventRole::Observer)
            .cloned()
            .collect();
        self.witnessed(
            object(SCHEMA_OBSERVER_COUNT_ATTEST_BODY, &body),
            &observers,
            0,
        )
    }

    /// Station `s`'s participation set: one pseudonym per check-in, the
    /// pseudonym at `repeat` (if any) given twice.
    #[must_use]
    pub fn participation(&self, s: usize, repeat: Option<usize>) -> &'static [u8] {
        let st = &self.stations[s];
        let n = self.days[s].last().checkins;
        let mut list: Vec<[u8; 64]> = (0..n)
            .map(|i| {
                digest(
                    "pseudonym",
                    &[self.eid.as_bytes(), st.id.as_bytes(), &i.to_be_bytes()],
                )
            })
            .collect();
        if let Some(r) = repeat {
            let copy = list[r];
            let last = list.len() - 1;
            list[last] = copy;
        }
        list.sort_unstable();
        let bytes: Vec<u8> = list.iter().flatten().copied().collect();
        let message = group(&ParticipationMessage {
            election_id: self.election_id(),
            station_id: StationId::new(text(st.id)).unwrap(),
            pseudonyms: Pseudonyms::new(leak_slice(bytes)).unwrap(),
        });
        let mut mods: Vec<&ModuleInfo> = self
            .modules
            .iter()
            .filter(|m| m.device == st.units[0])
            .collect();
        mods.sort_by_key(|m| m.chamber.code());
        let sigs: Vec<ParticipationModuleSig<'static>> = mods
            .iter()
            .map(|m| ParticipationModuleSig {
                module_id: module_id(m.id),
                sig: sign(&m.key, b"participation-set", message),
            })
            .collect();
        let unit_key = self.key(&format!("unit/{}", st.units[0]));
        object(
            SCHEMA_PARTICIPATION_SET,
            &ParticipationSet::new(
                message,
                sign(&unit_key, b"participation-set", message),
                &sigs,
            )
            .unwrap(),
        )
    }

    // -----------------------------------------------------------------
    // Tally events.

    /// `body` signed by the trustees `who` under `purpose`.
    #[must_use]
    pub fn quorum(&self, body: &'static [u8], purpose: &[u8], who: &[&str]) -> &'static [u8] {
        let ids: Vec<TrusteeId<'static>> = who
            .iter()
            .map(|t| TrusteeId::new(text(t)).unwrap())
            .collect();
        let mut out = vec![0u8; MAX_QUORUM_MESSAGE_LEN];
        let mut w = Writer::new(&mut out);
        write_quorum_message(&object_hash(body), &ids, &mut w).unwrap();
        let n = w.finish();
        out.truncate(n);
        let message = leak_slice(out);
        let sigs: Vec<QuorumSig<'static>> = who
            .iter()
            .map(|t| QuorumSig {
                trustee_id: TrusteeId::new(text(t)).unwrap(),
                sig: sign(&self.trustee(t), purpose, message),
            })
            .collect();
        object(
            SCHEMA_QUORUM_SIGNED,
            &QuorumSigned::new(body, &sigs).unwrap(),
        )
    }

    /// The receipt resolution of absentee box `b`: every record received.
    #[must_use]
    pub fn resolution(&self, b: usize, bucket: u64) -> &'static [u8] {
        let bx = &self.boxes[b];
        let mut list: Vec<(Hash512, ReceiptOutcome)> = self.casts[b]
            .iter()
            .map(|c| (c.code, ReceiptOutcome::Received))
            .collect();
        list.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        let mut bytes = vec![0u8; list.len() * 65];
        let mut w = Writer::new(&mut bytes);
        for (record_hash, outcome) in &list {
            ReceiptEntry {
                record_hash: *record_hash,
                outcome: *outcome,
            }
            .encode(&mut w)
            .unwrap();
        }
        let body = ReceiptResolutionBody::new(&ReceiptResolutionParts {
            election_id: self.election_id(),
            box_id: BoxId::new(text(bx.id)).unwrap(),
            entries: ReceiptEntries::new(leak_slice(bytes)).unwrap(),
            time_bucket: TimeBucket::new(bucket),
        });
        self.quorum(
            object(SCHEMA_RECEIPT_RESOLUTION_BODY, &body),
            b"receipt-resolution",
            &QUORUM,
        )
    }

    /// The tally scope body of `style` in `unit`.
    #[must_use]
    pub fn scope_body(
        &self,
        style: &str,
        unit: &str,
        included: &[Hash512],
        exclusions: &[ExclusionEntry],
        no_record: u64,
        bucket: u64,
    ) -> &'static [u8] {
        let mut list = exclusions.to_vec();
        list.sort_by(|a, b| a.record_hash.as_bytes().cmp(b.record_hash.as_bytes()));
        let mut bytes = vec![0u8; list.len() * 129];
        let mut w = Writer::new(&mut bytes);
        for e in &list {
            e.encode(&mut w).unwrap();
        }
        let body = TallyScopeBody::new(&TallyScopeParts {
            election_id: self.election_id(),
            ballot_style_id: BallotStyleId::new(text(style)).unwrap(),
            reporting_unit_id: ReportingUnitId::new(text(unit)).unwrap(),
            included_count: included.len() as u64,
            included_root: root(included),
            no_record_count: no_record,
            exclusions: Exclusions::new(leak_slice(bytes)).unwrap(),
            time_bucket: TimeBucket::new(bucket),
        })
        .unwrap();
        object(SCHEMA_TALLY_SCOPE_BODY, &body)
    }

    /// The aggregate opening body of chunk `chunk` over `casts`.
    #[must_use]
    pub fn opening_body(
        &self,
        style: &str,
        unit: &str,
        scope: &'static [u8],
        chunk: u8,
        casts: &[CastInfo],
        bucket: u64,
    ) -> &'static [u8] {
        let (t, r, s) = sums(casts, chunk);
        let body = AggregateOpeningBody::new(&AggregateOpeningParts {
            election_id: self.election_id(),
            ballot_style_id: BallotStyleId::new(text(style)).unwrap(),
            reporting_unit_id: ReportingUnitId::new(text(unit)).unwrap(),
            scope_hash: object_hash(scope),
            chunk,
            packed_sum: Scalar32(t.to_bytes()),
            rand_sum: Scalar32(r.to_bytes()),
            id_sum: Scalar32(s.to_bytes()),
            time_bucket: TimeBucket::new(bucket),
        })
        .unwrap();
        object(SCHEMA_AGGREGATE_OPENING_BODY, &body)
    }

    /// The paper count of `style` in `unit`, signed by the unit's chair
    /// and the two observers.
    #[must_use]
    pub fn paper(
        &self,
        style: &str,
        unit: &str,
        votes: &[u64],
        invalid: u64,
        bucket: u64,
    ) -> &'static [u8] {
        let body = PaperCountReportBody::new(&PaperCountParts {
            election_id: self.election_id(),
            reporting_unit_id: ReportingUnitId::new(text(unit)).unwrap(),
            ballot_style_id: BallotStyleId::new(text(style)).unwrap(),
            votes: PaperVotes::new(votes).unwrap(),
            invalid,
            time_bucket: TimeBucket::new(bucket),
        })
        .unwrap();
        let chair = self
            .chairs
            .iter()
            .find(|(u, _)| *u == unit)
            .unwrap()
            .1
            .clone();
        let who = [chair, self.observers[0].clone(), self.observers[1].clone()];
        self.witnessed(object(SCHEMA_PAPER_COUNT_REPORT_BODY, &body), &who, 0)
    }

    /// The paper of every ballot of `style` in `unit` (records and
    /// ballots without a record): votes per candidate and invalid.
    #[must_use]
    pub fn paper_truth(&self, style: &str, unit: &str) -> (Vec<u64>, u64) {
        let m = usize::from(self.spec.style(style).candidates.len() as u16);
        let mut votes = vec![0u64; m];
        let mut invalid = 0u64;
        let mut add = |mark: Mark| match mark.paper() {
            Some(c) => votes[usize::from(c) - 1] += 1,
            None => invalid += 1,
        };
        for (bi, bx) in self.boxes.iter().enumerate() {
            if bx.style != style || bx.unit != unit {
                continue;
            }
            for c in &self.casts[bi] {
                add(c.mark);
            }
            for mark in &self.days[bx.station].paper_only[bx.index] {
                add(*mark);
            }
        }
        (votes, invalid)
    }

    // -----------------------------------------------------------------
    // Audit events (PROTOCOL.md §12, ADR-0036).

    /// The committee and the two roster observers: the signers of a
    /// freeze, the commit and the seed.
    fn committee_and_observers(&self) -> [Person; 3] {
        [
            Person {
                id: "committee",
                role: EventRole::Committee,
                org: "IVC",
                key: self.committee(),
            },
            self.observers[0].clone(),
            self.observers[1].clone(),
        ]
    }

    /// The two auditors and the two roster observers: the signers of a
    /// comparison and a finding.
    fn auditors_and_observers(&self) -> [Person; 4] {
        [
            self.auditors[0].clone(),
            self.auditors[1].clone(),
            self.observers[0].clone(),
            self.observers[1].clone(),
        ]
    }

    /// The freeze body of `style` over the records `frame` (any order) with
    /// the rounds `rounds` (cumulative size, threshold) and the beacon
    /// `beacon` (designation document hash, round).
    #[must_use]
    pub fn freeze_body(
        &self,
        style: &str,
        frame: &[Hash512],
        rounds: &[(u64, u32)],
        beacon: (Hash512, u64),
        bucket: u64,
    ) -> &'static [u8] {
        let list: Vec<AuditRound> = rounds
            .iter()
            .map(|&(sample_size, threshold)| AuditRound {
                sample_size,
                threshold,
            })
            .collect();
        let body = AuditManifestFreezeBody::new(&AuditFreezeParts {
            election_id: self.election_id(),
            ballot_style_id: BallotStyleId::new(text(style)).unwrap(),
            frame_count: frame.len() as u64,
            frame_root: root(frame),
            rule_hash: hash_of("audit-rule", &[self.eid.as_bytes(), style.as_bytes()]),
            risk_limit_ppm: 50_000,
            beacon_source: beacon.0,
            beacon_round: beacon.1,
            rounds: AuditRounds::new(&list).unwrap(),
            time_bucket: TimeBucket::new(bucket),
        })
        .unwrap();
        object(SCHEMA_AUDIT_FREEZE_BODY, &body)
    }

    /// The committee's and observers' event over an audit body (a freeze,
    /// the commit or the seed), with signature variant `variant`.
    #[must_use]
    pub fn committee_event(&self, body: &'static [u8], variant: u64) -> &'static [u8] {
        self.witnessed(body, &self.committee_and_observers(), variant)
    }

    /// The audit commit body: the dice record `dice`, the beacon and the
    /// freeze bodies `freezes`.
    #[must_use]
    pub fn commit_body(
        &self,
        dice: Hash512,
        beacon: (Hash512, u64),
        freezes: &[&'static [u8]],
        bucket: u64,
    ) -> &'static [u8] {
        let hashes: Vec<Hash512> = freezes.iter().map(|b| object_hash(b)).collect();
        let body = AuditCommitBody::new(&AuditCommitParts {
            election_id: self.election_id(),
            dice_hash: dice,
            beacon_source: beacon.0,
            beacon_round: beacon.1,
            freezes_root: root(&hashes),
            time_bucket: TimeBucket::new(bucket),
        })
        .unwrap();
        object(SCHEMA_AUDIT_COMMIT_BODY, &body)
    }

    /// The seed body: `seed` over the dice record, the beacon value and
    /// the binding checkpoint's hash.
    #[must_use]
    pub fn seed_body(
        &self,
        dice: Hash512,
        round: u64,
        beacon_value: Hash512,
        checkpoint: Hash512,
        seed: Hash512,
        bucket: u64,
    ) -> &'static [u8] {
        let body = AuditSeedBody::new(&AuditSeedParts {
            election_id: self.election_id(),
            dice_hash: dice,
            beacon_round: round,
            beacon_value,
            checkpoint_hash: checkpoint,
            seed,
            time_bucket: TimeBucket::new(bucket),
        })
        .unwrap();
        object(SCHEMA_AUDIT_SEED_BODY, &body)
    }

    /// The restricted opening of record `c` of `style` (never on the
    /// ledger; a verifier with access is handed it).
    #[must_use]
    pub fn restricted_opening(&self, style: &str, c: &CastInfo) -> &'static [u8] {
        let list: Vec<Scalar32> = c.rand[..usize::from(c.chunks)]
            .iter()
            .map(|s| Scalar32(s.to_bytes()))
            .collect();
        let rand = Scalars::new(&list).unwrap();
        let body = SampleOpeningBody::new(&SampleOpeningParts {
            election_id: self.election_id(),
            ballot_style_id: BallotStyleId::new(text(style)).unwrap(),
            record_hash: c.code,
            option_index: c.option,
            cast_id: c.cast_id.token(),
            rand: &rand,
        })
        .unwrap();
        object(SCHEMA_SAMPLE_OPENING_BODY, &body)
    }

    /// The trustees' public reference to the restricted opening `opening`
    /// of record `record` of `style`.
    #[must_use]
    pub fn opening_reference(
        &self,
        style: &str,
        record: Hash512,
        opening: Hash512,
    ) -> &'static [u8] {
        let body = SampleOpeningRefBody::new(&SampleOpeningRefParts {
            election_id: self.election_id(),
            ballot_style_id: BallotStyleId::new(text(style)).unwrap(),
            record_hash: record,
            opening_hash: opening,
        })
        .unwrap();
        self.quorum(
            object(SCHEMA_SAMPLE_OPENING_REF_BODY, &body),
            b"sample-opening",
            &QUORUM,
        )
    }

    /// The auditors' comparison of record `record` of box `b` (opened as
    /// `opening`) with the paper: `code`.
    #[must_use]
    pub fn comparison(
        &self,
        b: usize,
        record: Hash512,
        opening: Hash512,
        code: ComparisonCode,
        transfer_mark: bool,
    ) -> &'static [u8] {
        let bx = &self.boxes[b];
        let body = SampleComparisonBody::new(&SampleComparisonParts {
            election_id: self.election_id(),
            ballot_style_id: BallotStyleId::new(text(bx.style)).unwrap(),
            record_hash: record,
            opening_hash: opening,
            device_id: BoxId::new(text(bx.id)).unwrap(),
            code,
            transfer_mark,
        })
        .unwrap();
        self.witnessed(
            object(SCHEMA_SAMPLE_COMPARISON_BODY, &body),
            &self.auditors_and_observers(),
            0,
        )
    }

    /// The auditors' finding on box `b` (the device under full
    /// comparison), in time bucket `bucket`.
    #[must_use]
    pub fn finding(&self, b: usize, bucket: u64) -> &'static [u8] {
        let bx = &self.boxes[b];
        let body = AuditFindingBody::new(&AuditFindingParts {
            election_id: self.election_id(),
            ballot_style_id: BallotStyleId::new(text(bx.style)).unwrap(),
            device_id: BoxId::new(text(bx.id)).unwrap(),
            finding_hash: hash_of("audit-finding", &[self.eid.as_bytes(), bx.id.as_bytes()]),
            time_bucket: TimeBucket::new(bucket),
        })
        .unwrap();
        self.witnessed(
            object(SCHEMA_AUDIT_FINDING_BODY, &body),
            &self.auditors_and_observers(),
            0,
        )
    }

    /// The hand count of `style` in `unit` (every ballot counted by hand:
    /// the paper truth), signed as a paper count is.
    #[must_use]
    pub fn hand_count(&self, style: &str, unit: &str, bucket: u64) -> &'static [u8] {
        let (votes, invalid) = self.paper_truth(style, unit);
        let body = HandCountReportBody::new(&PaperCountParts {
            election_id: self.election_id(),
            reporting_unit_id: ReportingUnitId::new(text(unit)).unwrap(),
            ballot_style_id: BallotStyleId::new(text(style)).unwrap(),
            votes: PaperVotes::new(&votes).unwrap(),
            invalid,
            time_bucket: TimeBucket::new(bucket),
        })
        .unwrap();
        let chair = self
            .chairs
            .iter()
            .find(|(u, _)| *u == unit)
            .unwrap()
            .1
            .clone();
        let who = [chair, self.observers[0].clone(), self.observers[1].clone()];
        self.witnessed(object(SCHEMA_HAND_COUNT_REPORT_BODY, &body), &who, 0)
    }

    /// A dispute filing by the two authorities naming record `record` of
    /// box `b`: the filing body's hash and the event.
    #[must_use]
    pub fn filing(
        &self,
        b: usize,
        kind: DisputeType,
        record: Option<Hash512>,
        bucket: u64,
    ) -> (Hash512, &'static [u8]) {
        let bx = &self.boxes[b];
        let body = DisputeEventBody::new(&DisputeEventParts {
            election_id: self.election_id(),
            action: DisputeAction::Filed,
            dispute_type: kind,
            box_id: Some(BoxId::new(text(bx.id)).unwrap()),
            record_hash: record,
            evidence_hash: hash_of(
                "dispute-evidence",
                &[record.unwrap_or(Hash512::ZERO).as_bytes()],
            ),
            filing_hash: Hash512::ZERO,
            result_hash: Hash512::ZERO,
            time_bucket: TimeBucket::new(bucket),
        })
        .unwrap();
        let body = object(SCHEMA_DISPUTE_EVENT_BODY, &body);
        let who = [
            Person {
                id: "commission",
                role: EventRole::Commission,
                org: "NEC",
                key: self.commission(),
            },
            Person {
                id: "committee",
                role: EventRole::Committee,
                org: "IVC",
                key: self.committee(),
            },
        ];
        (object_hash(body), self.witnessed(body, &who, 0))
    }
}

fn kem_key() -> &'static [u8; KEM_EK_LEN] {
    static KEM: [u8; KEM_EK_LEN] = [0x6B; KEM_EK_LEN];
    &KEM
}

/// The module record message `body_hash ‖ module_id ‖ counter`.
fn module_message(body_hash: &Hash512, module: &str, counter: u64) -> Vec<u8> {
    let mut buf = [0u8; 140];
    let mut w = Writer::new(&mut buf);
    body_hash.encode(&mut w).unwrap();
    module_id(module).encode(&mut w).unwrap();
    w.write_u64(counter).unwrap();
    let len = w.finish();
    buf[..len].to_vec()
}

/// The sorted-set root of `codes`.
#[must_use]
pub fn root(codes: &[Hash512]) -> Hash512 {
    let mut codes = codes.to_vec();
    codes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    sorted_set_root(&codes).unwrap()
}

/// `T_j`, `R_j` and `S` of `casts` for chunk `chunk`.
#[must_use]
pub fn sums(casts: &[CastInfo], chunk: u8) -> (Scalar, Scalar, Scalar) {
    let j = ChunkIndex::new(chunk).unwrap();
    casts.iter().fold(
        (Scalar::ZERO, Scalar::ZERO, Scalar::ZERO),
        |(t, r, s), c| {
            (
                t.add(&packed_value(OptionIndex::new(c.option).unwrap(), j)),
                r.add(&c.rand[usize::from(chunk)]),
                s.add(&c.cast_id.to_scalar()),
            )
        },
    )
}

/// Whether a station is an early-voting station.
#[must_use]
pub fn early(kind: StationKind) -> bool {
    kind == StationKind::EarlyVoting
}
