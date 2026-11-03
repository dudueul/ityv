//! The participation stage (PROTOCOL.md §6.4, §6.5, §9.4.2, §14 6;
//! VC-018, VC-084, VC-092, VC-093, VC-095).
//!
//! [`verify_participation`] reads three kinds of ledger event:
//!
//! * **Party key ceremonies** (`PartyKeyCeremony`, `0x0027`). Each party
//!   of the genesis needs one: for a chamber the genesis lists as a party,
//!   with share holders who are members of that chamber on distinct HSM
//!   products (§6.4 item 2), signed by the committee (actor
//!   [`ityv_encoding::COMMITTEE_ACTOR`], the genesis committee key), by
//!   every share holder, and by roster observers of two or more
//!   organisations. A second valid ceremony for the party with other
//!   fields is a conflict.
//! * **Module provisioning records** (`ModuleProvisioned`, `0x0026`). Every
//!   module of every genesis state needs the record whose object hash its
//!   entry pins, signed by the committee, a member of the module's chamber
//!   and observers of two or more organisations; with the entry's chamber,
//!   the device that lists the module in that state, the chamber's member
//!   count, a non-zero entropy commitment (VC-095), and for a check-in
//!   unit's party module a secure element and the party ceremony's key
//!   check (VC-093); no other module carries a key check.
//! * **Participation sets** (`ParticipationSet`, `0x0020`). Every station
//!   of the genesis's last state needs one: signed by a check-in unit of
//!   the station (in service or spare, in any genesis state up to the
//!   set's frame) and by one party module per party of the genesis, each a
//!   module of that unit, in chamber order P1…Pn (VC-084). A second set
//!   for the station with other pseudonyms is a conflict. Then the
//!   identities (VC-018): `count` is the station's final observer count
//!   (the last `ObserverCountAttest` of kind final), and the station's
//!   last `IssuanceCount` balances against its boxes:
//!   `ityv_state::issuance_verdict` with the cast and challenged records
//!   the record stage accepted and the ballots without a record and
//!   quarantined from each box's close. Across every accepted set no
//!   pseudonym appears twice.
//!
//! Every signature is verified under the key the genesis registers for
//! the signer: units and modules in any state up to the event's frame,
//! observers on the roster of those states, trustees and the committee
//! from the genesis. One signer's keys may not share a half with
//! another's (VC-098).
//!
//! An event that cannot be taken is evidence: it is listed, and holds the
//! ledger ([`HoldReason::ParticipationSetInvalid`],
//! [`HoldReason::KeyProvisioningInvalid`]), as does a repeated pseudonym
//! ([`HoldReason::DuplicatePseudonym`]) and a station whose identities do
//! not hold ([`HoldReason::ParticipationMismatch`] and the issuance
//! reasons). What is not yet on the ledger leaves the stage incomplete
//! instead: a station without a set, its final observer count, its
//! issuance count or a close of each of its boxes; a party without its
//! ceremony; a module without its provisioning record.
//!
//! What this stage does not do yet: `ParticipationRestriction` (VC-094),
//! `DuplicateIdentification` (VC-076), the counter's sequence across a
//! unit swap (VC-073, restricted), and the subset check against the roll
//! (§6.5 item 4, after the roll's pseudonym set is published).

use alloc::collections::{BTreeMap, BTreeSet, BinaryHeap};
use alloc::vec::Vec;
use core::cmp::Reverse;

use ityv_crypto::Purpose;
use ityv_crypto::hash::object_hash;
use ityv_encoding::{
    ActorSigs, COMMITTEE_ACTOR, ChamberCode, CheckinUnit, Decode, HYBRID_SIG_LEN, HYBRID_VK_LEN,
    Hash512, ModuleId, ModuleProvisioned, OrgId, PURPOSE_MODULE_PROVISIONED,
    PURPOSE_PARTICIPATION_SET, PURPOSE_PARTY_KEY, ParticipationSet, PartyKeyCeremony, RosterRole,
    SCHEMA_ISSUANCE_COUNT_BODY, SCHEMA_MODULE_PROVISIONED, SCHEMA_OBSERVER_COUNT_ATTEST_BODY,
    SCHEMA_PARTICIPATION_SET, SCHEMA_PARTY_KEY_CEREMONY, SCHEMA_VERSION_1, SCHEMA_WITNESSED_EVENT,
    SchemaId, Seq, StationId, WitnessedEvent, decode_object, is_party_chamber, keys_share_half,
};
use ityv_state::{
    HoldReason, HoldSet, IssuanceCount, IssuanceTotals, ObserverCount, Primary, RosterEntry,
    Signed, issuance_verdict,
};

use crate::boxes::BoxStage;
use crate::genesis::VerifiedGenesis;
use crate::index::{IndexedEvent, LedgerIndex};
use crate::records::RecordStage;
use crate::sigs::Material;

/// Why a participation set was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SetProblem {
    /// The genesis's last state has no such station.
    Station,
    /// The check-in unit's signature does not verify under the key of a
    /// unit of the station (in service or spare) in any genesis state up
    /// to the set's frame.
    CounterSignature,
    /// The module signatures are not one per party of the genesis, each
    /// from a module of the signing unit, in chamber order P1…Pn, or one
    /// does not verify.
    ModuleSignatures,
    /// The station already has an accepted set with other pseudonyms.
    Conflict,
}

/// A participation set that was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SetFinding<'a> {
    /// The frame that carries it.
    pub seq: Seq,
    /// The station it names.
    pub station_id: StationId<'a>,
    /// Why.
    pub problem: SetProblem,
}

/// Why a provisioning or ceremony record was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyProblem {
    /// A provisioning record whose object hash no genesis state pins for
    /// its module.
    NotPinned,
    /// A ceremony for a chamber that is not a party of the genesis.
    NotAParty,
    /// A signer is neither the committee, a member of the chamber nor a
    /// roster observer by the record's frame; two signers' keys share a
    /// half; or a signature does not verify.
    Signature,
    /// A signer group is missing: the committee, a member of the chamber
    /// (for a ceremony, every share holder), or observers of two or more
    /// organisations.
    Signers,
    /// A field disagrees with the genesis: the module's chamber or device,
    /// the chamber's member count, a share holder who is not a member of
    /// the party's chamber, or two share holders on one HSM product.
    Fields,
    /// The entropy commitment is zero (VC-095).
    EntropyCommitment,
    /// A check-in unit's party module without a secure element or a key
    /// check, with a check other than its party ceremony's, or another
    /// module with a check (VC-093).
    KeyCheck,
    /// The party already has an accepted ceremony with other fields.
    Conflict,
}

/// A provisioning or ceremony record that was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyFinding {
    /// The frame that carries it.
    pub seq: Seq,
    /// Its schema (`ModuleProvisioned` or `PartyKeyCeremony`).
    pub schema: SchemaId,
    /// Why.
    pub problem: KeyProblem,
}

/// What the stage concluded about one station of the genesis's last
/// state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StationParticipation<'a> {
    /// The station.
    pub station_id: StationId<'a>,
    /// The frame of its accepted participation set.
    pub set: Option<Seq>,
    /// The number of pseudonyms in that set.
    pub count: Option<u32>,
    /// The observers' final check-in count.
    pub observers: Option<u64>,
    /// The frame of its last accepted issuance count.
    pub issuance: Option<Seq>,
    /// Whether every box of the station has a close.
    pub closed: bool,
    /// The station's holds: a count that is not the observers' final
    /// count, the issuance verdict, a repeated pseudonym.
    pub holds: HoldSet,
}

impl StationParticipation<'_> {
    /// Whether every identity of the station could be checked: a set, a
    /// final observer count, an issuance count and every box closed.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.set.is_some() && self.observers.is_some() && self.issuance.is_some() && self.closed
    }
}

/// The participation stage over one ledger.
#[derive(Debug, Clone)]
pub struct ParticipationStage<'a> {
    stations: Vec<StationParticipation<'a>>,
    set_findings: Vec<SetFinding<'a>>,
    key_findings: Vec<KeyFinding>,
    duplicates: u64,
    ceremonies: Vec<(ChamberCode, Seq)>,
    missing_ceremonies: Vec<ChamberCode>,
    missing_provisioning: Vec<(ModuleId<'a>, Hash512)>,
    holds: HoldSet,
}

impl<'a> ParticipationStage<'a> {
    /// One report per station of the genesis's last state, in key order.
    #[must_use]
    pub fn stations(&self) -> &[StationParticipation<'a>] {
        &self.stations
    }

    /// The report of station `station_id`.
    #[must_use]
    pub fn station(&self, station_id: &[u8]) -> Option<&StationParticipation<'a>> {
        self.stations
            .iter()
            .find(|s| s.station_id.as_bytes() == station_id)
    }

    /// The participation sets not taken, in frame order.
    #[must_use]
    pub fn set_findings(&self) -> &[SetFinding<'a>] {
        &self.set_findings
    }

    /// The provisioning and ceremony records not taken, in frame order.
    #[must_use]
    pub fn key_findings(&self) -> &[KeyFinding] {
        &self.key_findings
    }

    /// The repeated pseudonyms across the accepted sets: for each value,
    /// its occurrences beyond the first (the public duplicate count of
    /// §6.5).
    #[must_use]
    pub const fn duplicates(&self) -> u64 {
        self.duplicates
    }

    /// The accepted ceremony of each party, in chamber order.
    #[must_use]
    pub fn ceremonies(&self) -> &[(ChamberCode, Seq)] {
        &self.ceremonies
    }

    /// The parties without an accepted ceremony.
    #[must_use]
    pub fn missing_ceremonies(&self) -> &[ChamberCode] {
        &self.missing_ceremonies
    }

    /// The modules (with the record hash their entry pins) without an
    /// accepted provisioning record, in key order.
    #[must_use]
    pub fn missing_provisioning(&self) -> &[(ModuleId<'a>, Hash512)] {
        &self.missing_provisioning
    }

    /// Every hold of the stage.
    #[must_use]
    pub const fn holds(&self) -> HoldSet {
        self.holds
    }

    /// Whether every station's identities, every party's ceremony and
    /// every module's provisioning record could be checked.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.stations.iter().all(StationParticipation::complete)
            && self.missing_ceremonies.is_empty()
            && self.missing_provisioning.is_empty()
    }
}

/// A roster observer: organisation and key.
type Observers<'a> = BTreeMap<&'a [u8], (OrgId<'a>, &'a [u8; HYBRID_VK_LEN])>;

/// The roster keys of one state, by signer.
type Keys<'a> = BTreeMap<&'a [u8], &'a [u8; HYBRID_VK_LEN]>;

/// The device a module is listed on in one genesis state.
#[derive(Debug, Clone, Copy)]
struct Device<'a> {
    id: &'a [u8],
    checkin_unit: bool,
}

/// A module entry a genesis state pins a provisioning record for.
#[derive(Debug, Clone, Copy)]
struct Pinned<'a> {
    module_id: ModuleId<'a>,
    chamber: ChamberCode,
    device: Option<Device<'a>>,
}

/// An accepted ceremony.
#[derive(Debug, Clone, Copy)]
struct Ceremony<'a> {
    seq: Seq,
    message: &'a [u8],
    prf_key_check: &'a [u8; 32],
}

/// Everything the checks read, gathered once.
struct Ctx<'g, 'a> {
    genesis: &'g VerifiedGenesis<'a>,
    index: &'g LedgerIndex<'a>,
    /// The parties' chambers, in order (P1…Pn).
    parties: Vec<ChamberCode>,
    rosters: Vec<Vec<RosterEntry<'a>>>,
    keys: Vec<Keys<'a>>,
    observers: Vec<Observers<'a>>,
}

/// Whether `sig` over `message` verifies under `key` for `purpose`.
fn verifies(
    sig: &[u8; HYBRID_SIG_LEN],
    key: &[u8; HYBRID_VK_LEN],
    purpose: &Purpose<'_>,
    message: &[u8],
) -> bool {
    Material::new(core::iter::once((sig, key)))
        .is_some_and(|m| m.verify(purpose, message).is_some())
}

fn decode<'a, T: Decode<'a>>(e: &IndexedEvent<'a>) -> Option<T> {
    decode_object(e.schema, SCHEMA_VERSION_1, e.bytes?).ok()
}

/// Who signed a provisioning or ceremony record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Actor<'a> {
    Committee,
    Member(&'a [u8]),
    Observer(&'a [u8]),
}

impl<'a> Ctx<'_, 'a> {
    /// The signer `actor_id` of a record of chamber `chamber` at frame
    /// `seq`, with the key it signs with.
    fn actor(
        &self,
        actor_id: &[u8],
        chamber: ChamberCode,
        seq: Seq,
    ) -> Option<(Actor<'a>, &'a [u8; HYBRID_VK_LEN])> {
        if actor_id == COMMITTEE_ACTOR {
            return Some((Actor::Committee, self.genesis.genesis().committee_key()));
        }
        if let Some(t) = self
            .genesis
            .trustees()
            .find(|t| t.trustee_id.as_bytes() == actor_id)
        {
            return (t.chamber == chamber)
                .then_some((Actor::Member(t.trustee_id.as_bytes()), t.key));
        }
        let last = self.index.state_at(seq);
        self.observers
            .iter()
            .take(last.saturating_add(1))
            .rev()
            .find_map(|o| o.get(actor_id))
            .map(|(org, key)| (Actor::Observer(org.as_bytes()), *key))
    }

    /// The signers of a record of chamber `chamber` at frame `seq`, each
    /// signature verified over `message`; `None` if one is unknown, two
    /// keys share a half, or a signature does not verify.
    fn signers(
        &self,
        sigs: &ActorSigs<'a>,
        chamber: ChamberCode,
        seq: Seq,
        purpose: &[u8],
        message: &[u8],
    ) -> Option<Vec<Actor<'a>>> {
        let purpose = Purpose::new(purpose)?;
        let mut keys: Vec<&[u8; HYBRID_VK_LEN]> = Vec::new();
        let mut actors = Vec::new();
        for s in sigs.iter() {
            let (actor, key) = self.actor(s.actor_id.as_bytes(), chamber, seq)?;
            if keys.iter().any(|k| keys_share_half(k, key))
                || !verifies(s.sig, key, &purpose, message)
            {
                return None;
            }
            keys.push(key);
            actors.push(actor);
        }
        Some(actors)
    }
}

/// Whether `actors` include the committee, a member of the chamber and
/// observers of two or more organisations.
fn groups_present(actors: &[Actor<'_>]) -> bool {
    let committee = actors.contains(&Actor::Committee);
    let member = actors.iter().any(|a| matches!(a, Actor::Member(_)));
    let orgs: BTreeSet<&[u8]> = actors
        .iter()
        .filter_map(|a| match a {
            Actor::Observer(org) => Some(*org),
            Actor::Committee | Actor::Member(_) => None,
        })
        .collect();
    committee && member && orgs.len() >= 2
}

/// Checks one ceremony; the accepted ones go into `accepted`.
fn ceremony<'a>(
    ctx: &Ctx<'_, 'a>,
    e: &IndexedEvent<'a>,
    c: &PartyKeyCeremony<'a>,
    accepted: &mut BTreeMap<ChamberCode, Ceremony<'a>>,
) -> Result<(), KeyProblem> {
    let m = c.message();
    let chamber = m.chamber();
    if !ctx.parties.contains(&chamber) {
        return Err(KeyProblem::NotAParty);
    }
    let holders_members = m.share_holders().all(|h| {
        ctx.genesis
            .trustees()
            .any(|t| t.trustee_id.as_bytes() == h.trustee_id.as_bytes() && t.chamber == chamber)
    });
    let models: BTreeSet<&[u8]> = m.share_holders().map(|h| h.hsm_model.as_bytes()).collect();
    if !holders_members || models.len() != usize::from(m.share_count()) {
        return Err(KeyProblem::Fields);
    }
    let actors = ctx
        .signers(
            c.signatures(),
            chamber,
            e.seq,
            PURPOSE_PARTY_KEY,
            c.message_bytes(),
        )
        .ok_or(KeyProblem::Signature)?;
    let every_holder = m
        .share_holders()
        .all(|h| actors.contains(&Actor::Member(h.trustee_id.as_bytes())));
    if !groups_present(&actors) || !every_holder {
        return Err(KeyProblem::Signers);
    }
    match accepted.get(&chamber) {
        Some(first) if first.message != c.message_bytes() => Err(KeyProblem::Conflict),
        Some(_) => Ok(()),
        None => {
            accepted.insert(
                chamber,
                Ceremony {
                    seq: e.seq,
                    message: c.message_bytes(),
                    prf_key_check: m.prf_key_check(),
                },
            );
            Ok(())
        }
    }
}

/// The module entries every genesis state pins a provisioning record
/// for, by module and record hash, with the device that lists the module
/// in the earliest state that pins it.
fn pinned<'a>(genesis: &VerifiedGenesis<'a>) -> BTreeMap<(&'a [u8], [u8; 64]), Pinned<'a>> {
    let mut out = BTreeMap::new();
    for state in 0..genesis.state_count() {
        let mut devices: BTreeMap<&'a [u8], Device<'a>> = BTreeMap::new();
        for b in genesis.boxes_at(state) {
            for m in b.modules.iter() {
                devices.insert(
                    m.as_bytes(),
                    Device {
                        id: b.box_id.as_bytes(),
                        checkin_unit: false,
                    },
                );
            }
        }
        for s in genesis.stations_at(state) {
            for unit in [s.primary(), s.spare()] {
                for m in unit.modules.iter() {
                    devices.insert(
                        m.as_bytes(),
                        Device {
                            id: unit.unit_id.as_bytes(),
                            checkin_unit: true,
                        },
                    );
                }
            }
        }
        for m in genesis.modules_at(state) {
            out.entry((m.module_id.as_bytes(), m.provisioned_hash.0))
                .or_insert(Pinned {
                    module_id: m.module_id,
                    chamber: m.chamber,
                    device: devices.get(m.module_id.as_bytes()).copied(),
                });
        }
    }
    out
}

/// Checks one provisioning record against the entry that pins it.
fn provisioning<'a>(
    ctx: &Ctx<'_, 'a>,
    e: &IndexedEvent<'a>,
    record: &ModuleProvisioned<'a>,
    pin: Option<&Pinned<'a>>,
    ceremonies: &BTreeMap<ChamberCode, Ceremony<'a>>,
) -> Result<(), KeyProblem> {
    let pin = pin.ok_or(KeyProblem::NotPinned)?;
    let p = record.parts();
    let members = ctx
        .genesis
        .genesis()
        .body()
        .chambers()
        .find(|c| c.chamber == p.chamber)
        .map(|c| c.members);
    let device_ok = pin.device.is_some_and(|d| d.id == p.device_id.as_bytes());
    if pin.chamber != p.chamber || !device_ok || members != Some(p.member_count) {
        return Err(KeyProblem::Fields);
    }
    let actors = ctx
        .signers(
            record.signatures(),
            p.chamber,
            e.seq,
            PURPOSE_MODULE_PROVISIONED,
            record.message_bytes(),
        )
        .ok_or(KeyProblem::Signature)?;
    if !groups_present(&actors) {
        return Err(KeyProblem::Signers);
    }
    if p.entropy_commitment == Hash512::ZERO {
        return Err(KeyProblem::EntropyCommitment);
    }
    let party_unit_module =
        pin.device.is_some_and(|d| d.checkin_unit) && is_party_chamber(p.chamber);
    let check_ok = if party_unit_module {
        let expected = ceremonies.get(&p.chamber).map(|c| c.prf_key_check);
        p.se_present
            && p.prf_key_check
                .is_some_and(|check| expected.is_none_or(|x| x == check))
    } else {
        p.prf_key_check.is_none()
    };
    if check_ok {
        Ok(())
    } else {
        Err(KeyProblem::KeyCheck)
    }
}

/// The unit of `station_id` (in service or spare, in a state up to
/// `last`) whose key verifies the set's counter signature, with the
/// state it was found in.
fn signing_unit<'a, 'g>(
    genesis: &'g VerifiedGenesis<'a>,
    set: &ParticipationSet<'a>,
    last: usize,
    purpose: &Purpose<'_>,
) -> Vec<(usize, &'g CheckinUnit<'a>)> {
    (0..=last)
        .filter_map(|state| {
            genesis
                .station_at(state, set.station_id().as_bytes())
                .map(|s| (state, s))
        })
        .flat_map(|(state, s)| [(state, s.primary()), (state, s.spare())])
        .filter(|(_, unit)| verifies(set.counter_sig(), unit.key, purpose, set.message_bytes()))
        .collect()
}

/// Checks one participation set's signatures.
fn set_signatures(
    ctx: &Ctx<'_, '_>,
    e: &IndexedEvent<'_>,
    set: &ParticipationSet<'_>,
) -> Result<(), SetProblem> {
    if ctx.genesis.station(set.station_id().as_bytes()).is_none() {
        return Err(SetProblem::Station);
    }
    let purpose = Purpose::new(PURPOSE_PARTICIPATION_SET).ok_or(SetProblem::CounterSignature)?;
    let last = ctx.index.state_at(e.seq);
    let units = signing_unit(ctx.genesis, set, last, &purpose);
    if units.is_empty() {
        return Err(SetProblem::CounterSignature);
    }
    let modules_ok = |state: usize, unit: &CheckinUnit<'_>| {
        set.module_sig_count() == ctx.parties.len()
            && set.module_sigs().zip(&ctx.parties).all(|(sig, party)| {
                unit.modules.contains(sig.module_id)
                    && ctx
                        .genesis
                        .module_at(state, sig.module_id.as_bytes())
                        .is_some_and(|m| {
                            m.chamber == *party
                                && verifies(sig.sig, m.key, &purpose, set.message_bytes())
                        })
            })
    };
    if units.iter().any(|(state, unit)| modules_ok(*state, unit)) {
        Ok(())
    } else {
        Err(SetProblem::ModuleSignatures)
    }
}

/// The last witnessed event of `body_schema` among the station's events
/// that `accept` takes, with its result, verified under the roster of the
/// state in force at its frame.
fn last_witnessed<'a, R>(
    ctx: &Ctx<'_, 'a>,
    station_id: &[u8],
    body_schema: SchemaId,
    accept: impl Fn(&Signed<'_>, &[RosterEntry<'_>]) -> Option<R>,
) -> Option<(Seq, R)> {
    let mut last = None;
    for e in ctx.index.station_events(station_id) {
        if e.schema != SCHEMA_WITNESSED_EVENT {
            continue;
        }
        let Some(event) = decode::<WitnessedEvent<'a>>(e) else {
            continue;
        };
        if event.body_schema() != body_schema {
            continue;
        }
        if let Some(r) = with_signed(ctx, e.seq, &event, &accept) {
            last = Some((e.seq, r));
        }
    }
    last
}

/// Runs `f` on the witnessed event at frame `seq` with its tokens, made
/// under the roster keys of the state in force at that frame.
fn with_signed<R>(
    ctx: &Ctx<'_, '_>,
    seq: Seq,
    event: &WitnessedEvent<'_>,
    f: impl FnOnce(&Signed<'_>, &[RosterEntry<'_>]) -> Option<R>,
) -> Option<R> {
    let state = ctx.index.state_at(seq);
    let keys = ctx.keys.get(state)?;
    let roster = ctx.rosters.get(state)?;
    let purpose = Purpose::new(event.purpose())?;
    let pairs: Option<Vec<(&[u8; HYBRID_SIG_LEN], &[u8; HYBRID_VK_LEN])>> = event
        .sigs()
        .map(|s| keys.get(s.signer_id.as_bytes()).map(|k| (s.sig, *k)))
        .collect();
    let material = Material::new(pairs?.into_iter())?;
    let tokens = material.verify(&purpose, event.body_bytes())?;
    f(
        &Signed {
            event,
            tokens: &tokens,
        },
        roster,
    )
}

/// The station's totals over its boxes: cast and challenged records from
/// the record stage, ballots without a record and quarantined from each
/// close; `None` while a box has no close.
fn totals(
    genesis: &VerifiedGenesis<'_>,
    station_id: &[u8],
    boxes: &BoxStage<'_>,
    records: &RecordStage<'_>,
) -> Option<IssuanceTotals> {
    let station = genesis.station(station_id)?;
    let mut t = IssuanceTotals {
        records: 0,
        without_record: 0,
        challenged: 0,
        quarantined: 0,
    };
    for box_id in station.boxes() {
        let counts = boxes.report(box_id.as_bytes())?.counts?;
        let (cast, challenged) = records.report(box_id.as_bytes()).map_or((0u64, 0u64), |r| {
            r.records
                .iter()
                .fold((0u64, 0u64), |(c, h), rec| match rec.state.primary() {
                    Primary::Cast | Primary::Receipt(_) => (c.saturating_add(1), h),
                    Primary::ChallengedSpoiled => (c, h.saturating_add(1)),
                    Primary::Quarantined => (c, h),
                })
        });
        t.records = t.records.checked_add(cast)?;
        t.challenged = t.challenged.checked_add(challenged)?;
        t.without_record = t.without_record.checked_add(counts.without_record)?;
        t.quarantined = t.quarantined.checked_add(counts.quarantined)?;
    }
    Some(t)
}

/// One station's report.
fn station_report<'a>(
    ctx: &Ctx<'_, 'a>,
    station_id: StationId<'a>,
    set: Option<(Seq, u32)>,
    boxes: &BoxStage<'a>,
    records: &RecordStage<'a>,
) -> StationParticipation<'a> {
    let id = station_id.as_bytes();
    let election = ctx.genesis.election_id();
    let observers = last_witnessed(ctx, id, SCHEMA_OBSERVER_COUNT_ATTEST_BODY, |s, r| {
        ObserverCount::check(s, r)
            .ok()?
            .final_total(election, station_id)
    });
    let issuance = last_witnessed(ctx, id, SCHEMA_ISSUANCE_COUNT_BODY, |s, r| {
        IssuanceCount::check(s, r).ok().map(|_| ())
    });
    let totals = totals(ctx.genesis, id, boxes, records);
    let mut holds = HoldSet::empty();
    if let (Some((_, count)), Some((_, total))) = (set, observers) {
        holds = holds.with_if(u64::from(count) != total, HoldReason::ParticipationMismatch);
    }
    if let (Some((obs_seq, _)), Some((iss_seq, ())), Some(t)) = (observers, issuance, totals) {
        holds = holds.union(issuance_holds(ctx, id, obs_seq, iss_seq, &t));
    }
    StationParticipation {
        station_id,
        set: set.map(|(seq, _)| seq),
        count: set.map(|(_, count)| count),
        observers: observers.map(|(_, total)| total),
        issuance: issuance.map(|(seq, ())| seq),
        closed: totals.is_some(),
        holds,
    }
}

/// The issuance verdict of the station's issuance count at frame
/// `iss_seq` with its final observer count at frame `obs_seq`.
fn issuance_holds(
    ctx: &Ctx<'_, '_>,
    station_id: &[u8],
    obs_seq: Seq,
    iss_seq: Seq,
    totals: &IssuanceTotals,
) -> HoldSet {
    let event_at = |seq: Seq| {
        ctx.index
            .station_events(station_id)
            .find(|e| e.seq == seq)
            .and_then(decode::<WitnessedEvent<'_>>)
    };
    let verdict = event_at(obs_seq)
        .zip(event_at(iss_seq))
        .and_then(|(obs, iss)| {
            with_signed(ctx, obs_seq, &obs, |obs_signed, obs_roster| {
                let observers = ObserverCount::check(obs_signed, obs_roster).ok()?;
                with_signed(ctx, iss_seq, &iss, |iss_signed, iss_roster| {
                    let issuance = IssuanceCount::check(iss_signed, iss_roster).ok()?;
                    issuance_verdict(&issuance, totals, Some(&observers)).ok()
                })
            })
        });
    // Both events were taken a moment ago, so the verdict exists; were it
    // missing, the station's participation is not shown to hold.
    verdict.unwrap_or(HoldSet::empty().with(HoldReason::ParticipationMismatch))
}

/// The number of repeated pseudonyms across `sets` (occurrences beyond
/// the first of each value), and the indices of the sets that hold one.
/// A k-way merge of the sorted sets: no copy of the pseudonyms.
fn repeated(sets: &[ParticipationSet<'_>]) -> (u64, BTreeSet<usize>) {
    let mut iters: Vec<_> = sets.iter().map(|s| s.pseudonyms().iter()).collect();
    let mut heap = BinaryHeap::new();
    for (i, it) in iters.iter_mut().enumerate() {
        if let Some(p) = it.next() {
            heap.push(Reverse((p, i)));
        }
    }
    let mut count = 0u64;
    let mut marked = BTreeSet::new();
    let mut previous: Option<(&[u8; 64], usize)> = None;
    while let Some(Reverse((p, i))) = heap.pop() {
        if let Some((q, j)) = previous
            && q == p
        {
            count = count.saturating_add(1);
            marked.insert(i);
            marked.insert(j);
        }
        previous = Some((p, i));
        if let Some(next) = iters.get_mut(i).and_then(Iterator::next) {
            heap.push(Reverse((next, i)));
        }
    }
    (count, marked)
}

/// Runs the participation stage (PROTOCOL.md §14 6) over the ledger.
#[must_use]
#[allow(clippy::too_many_lines)] // The stage's three passes, in order.
pub fn verify_participation<'a>(
    genesis: &VerifiedGenesis<'a>,
    index: &LedgerIndex<'a>,
    boxes: &BoxStage<'a>,
    records: &RecordStage<'a>,
) -> ParticipationStage<'a> {
    let rosters: Vec<Vec<RosterEntry<'a>>> = (0..genesis.state_count())
        .map(|k| genesis.roster_at(k))
        .collect();
    let keys = rosters
        .iter()
        .map(|r| {
            r.iter()
                .map(|e| (e.get().signer_id.as_bytes(), e.get().key))
                .collect()
        })
        .collect();
    let observers = rosters
        .iter()
        .map(|r| {
            r.iter()
                .filter(|e| e.get().role == RosterRole::Observer)
                .map(|e| (e.get().signer_id.as_bytes(), (e.get().org_id, e.get().key)))
                .collect()
        })
        .collect();
    let ctx = Ctx {
        genesis,
        index,
        parties: genesis
            .genesis()
            .body()
            .parties()
            .map(|p| p.chamber)
            .collect(),
        rosters,
        keys,
        observers,
    };
    let mut key_findings = Vec::new();

    // 1. Party key ceremonies.
    let mut ceremonies: BTreeMap<ChamberCode, Ceremony<'a>> = BTreeMap::new();
    for e in index
        .events()
        .iter()
        .filter(|e| e.schema == SCHEMA_PARTY_KEY_CEREMONY)
    {
        let result = decode::<PartyKeyCeremony<'a>>(e)
            .ok_or(KeyProblem::Fields)
            .and_then(|c| ceremony(&ctx, e, &c, &mut ceremonies));
        if let Err(problem) = result {
            key_findings.push(KeyFinding {
                seq: e.seq,
                schema: e.schema,
                problem,
            });
        }
    }

    // 2. Module provisioning records.
    let pins = pinned(genesis);
    let mut provisioned: BTreeSet<(&'a [u8], [u8; 64])> = BTreeSet::new();
    for e in index
        .events()
        .iter()
        .filter(|e| e.schema == SCHEMA_MODULE_PROVISIONED)
    {
        let Some((record, bytes)) = decode::<ModuleProvisioned<'a>>(e).zip(e.bytes) else {
            continue;
        };
        let key = (record.parts().module_id.as_bytes(), object_hash(bytes).0);
        match provisioning(&ctx, e, &record, pins.get(&key), &ceremonies) {
            Ok(()) => {
                provisioned.insert(key);
            }
            Err(problem) => key_findings.push(KeyFinding {
                seq: e.seq,
                schema: e.schema,
                problem,
            }),
        }
    }
    key_findings.sort_by_key(|f| f.seq.get());

    // 3. Participation sets.
    let mut set_findings = Vec::new();
    let mut accepted: BTreeMap<&'a [u8], (Seq, ParticipationSet<'a>)> = BTreeMap::new();
    for e in index
        .events()
        .iter()
        .filter(|e| e.schema == SCHEMA_PARTICIPATION_SET)
    {
        let Some(set) = decode::<ParticipationSet<'a>>(e) else {
            continue;
        };
        let station = set.station_id().as_bytes();
        let result = set_signatures(&ctx, e, &set).and_then(|()| match accepted.get(station) {
            Some((_, first)) if first.message_bytes() != set.message_bytes() => {
                Err(SetProblem::Conflict)
            }
            Some(_) => Ok(()),
            None => {
                accepted.insert(station, (e.seq, set));
                Ok(())
            }
        });
        if let Err(problem) = result {
            set_findings.push(SetFinding {
                seq: e.seq,
                station_id: set.station_id(),
                problem,
            });
        }
    }

    let sets: Vec<ParticipationSet<'a>> = accepted.values().map(|(_, s)| *s).collect();
    let (duplicates, marked) = repeated(&sets);
    let marked_stations: BTreeSet<&[u8]> = accepted
        .keys()
        .enumerate()
        .filter(|(i, _)| marked.contains(i))
        .map(|(_, id)| *id)
        .collect();

    let stations: Vec<StationParticipation<'a>> = genesis
        .stations()
        .map(|s| {
            let id = s.station_id();
            let set = accepted
                .get(id.as_bytes())
                .map(|(seq, set)| (*seq, set.count()));
            let mut report = station_report(&ctx, id, set, boxes, records);
            report.holds = report.holds.with_if(
                marked_stations.contains(id.as_bytes()),
                HoldReason::DuplicatePseudonym,
            );
            report
        })
        .collect();

    let missing_ceremonies: Vec<ChamberCode> = ctx
        .parties
        .iter()
        .copied()
        .filter(|c| !ceremonies.contains_key(c))
        .collect();
    let missing_provisioning: Vec<(ModuleId<'a>, Hash512)> = pins
        .iter()
        .filter(|(key, _)| !provisioned.contains(*key))
        .map(|((_, hash), pin)| (pin.module_id, Hash512(*hash)))
        .collect();

    let holds = stations
        .iter()
        .fold(HoldSet::empty(), |acc, s| acc.union(s.holds))
        .with_if(
            !set_findings.is_empty(),
            HoldReason::ParticipationSetInvalid,
        )
        .with_if(!key_findings.is_empty(), HoldReason::KeyProvisioningInvalid)
        .with_if(duplicates > 0, HoldReason::DuplicatePseudonym);
    ParticipationStage {
        stations,
        set_findings,
        key_findings,
        duplicates,
        ceremonies: ceremonies.iter().map(|(c, x)| (*c, x.seq)).collect(),
        missing_ceremonies,
        missing_provisioning,
        holds,
    }
}
