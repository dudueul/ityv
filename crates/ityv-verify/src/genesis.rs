//! The genesis stage of the verifier (PROTOCOL.md §14 1; ADR-0028;
//! VC-005, VC-009, VC-014, VC-067, VC-104, VC-105).
//!
//! [`verify_genesis`] takes the pin the caller obtained out of band, the
//! signed genesis with every entry of every set, and every amendment with
//! the full amendable sets of the state it creates. In order it:
//!
//! 1. decodes the `SignedGenesis` and refuses it unless its body's object
//!    hash is the pin (`ityv_state::Pinned::new`, VC-005);
//! 2. checks the witness set whole, verifies the commission's, the
//!    committee's and every witness's hybrid signature under the keys the
//!    body and the witness set register, and seals the genesis with those
//!    tokens (`ityv_state::Pinned::seal`: quorum, diversity, no shared key
//!    half; VC-014, VC-098);
//! 3. checks every other set whole (canonical entries, strictly ascending
//!    keys, count and root recomputed) and the sets against each other
//!    (the rules below);
//! 4. for each amendment in order, verifies its signatures the same way
//!    and applies it (`ityv_state::Genesis::amend`: next number, chained to
//!    the previous body, same election, same quorum; VC-105), then checks
//!    the eight amendable sets of the new state whole and against the
//!    fixed sets again.
//!
//! The sets of one state must agree with each other (ADR-0028 decision 8,
//! VC-009, VC-067, VC-104):
//!
//! * every box names a station, route, ballot style, reporting unit and
//!   modules that exist, and its station lists it; every box a station
//!   lists exists and names that station;
//! * every station has exactly one progress policy and every policy names
//!   a station;
//! * every reporting unit's box count is the number of boxes that name it;
//! * every roster signer's station exists, and every observer token of a
//!   station names an observer of the token's organisation on the roster;
//! * every roster, trustee and witness entry's appointment is in the
//!   appointment set (VC-009);
//! * every box carries one module of each party chamber `P1`…`Pn` and at
//!   most one each of `J`, `A` and `C`; every check-in unit carries exactly
//!   one module of each party chamber; no module belongs to a party
//!   chamber the genesis does not have; each chamber has exactly `n_c`
//!   trustees (VC-067, VC-017);
//! * no two devices share an identifier (boxes, check-in units and
//!   modules), so a device attestation names exactly one device;
//! * no two keys of the state share a half: the two authorities, every
//!   box's device and attestation keys, every check-in unit's keys, every
//!   roster signer, module, trustee and witness.
//!
//! The result, [`VerifiedGenesis`], exists only if every step passed. It
//! proves entries for the state machines from the sets it checked, so a
//! state machine fed through it never sees an entry the full check did
//! not see.
//!
//! What this stage does not prove: that the pin is the one the gazette
//! published (the caller supplies it, and must not take it from the same
//! source as the genesis); that the documents the body pins (policy, legal
//! authorization, connectivity and release manifests) say what they
//! should; anything about the ledger.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use ityv_crypto::Purpose;
use ityv_encoding::{
    BallotStyleEntry, CustodyRoute, ENTRY_SET_COUNT, ElectionId, EntrySet, GenesisBody, GenesisBox,
    GenesisEntry, HYBRID_SIG_LEN, HYBRID_VK_LEN, Hash512, ModuleEntry, ReportingUnitEntry,
    RollAuthorityEntry, RosterSigner, SCHEMA_SIGNED_GENESIS, SCHEMA_VERSION_1, SetCommitment,
    SignedGenesis, StationEntry, StationId, StationProgressPolicy, TimestampAuthorityEntry,
    TrusteeEntry, WitnessRosterEntry, decode_object,
};
use ityv_ledger::InclusionProof;
use ityv_state::{Anchor, Entry, Genesis, Pinned};

use crate::cross;
use crate::error::{Error, Rule};
use crate::roll;
use crate::sets::{Appointments, Set};
use crate::sigs::Material;
use crate::timestamp;

/// The eight amendable sets of one genesis state, each entry as its
/// encoded object, in the order the set commits to them.
#[derive(Debug, Clone, Copy)]
pub struct AmendableSets<'a> {
    /// `GenesisBox` objects.
    pub boxes: &'a [&'a [u8]],
    /// `StationEntry` objects.
    pub stations: &'a [&'a [u8]],
    /// `StationProgressPolicy` objects.
    pub progress_policies: &'a [&'a [u8]],
    /// `ReportingUnitEntry` objects.
    pub reporting_units: &'a [&'a [u8]],
    /// `CustodyRoute` objects.
    pub routes: &'a [&'a [u8]],
    /// `RosterSigner` objects.
    pub roster: &'a [&'a [u8]],
    /// `ModuleEntry` objects.
    pub modules: &'a [&'a [u8]],
    /// Appointment event hashes.
    pub appointments: &'a [Hash512],
}

/// The five sets an amendment cannot change.
#[derive(Debug, Clone, Copy)]
pub struct FixedSets<'a> {
    /// `BallotStyleEntry` objects.
    pub ballot_styles: &'a [&'a [u8]],
    /// `TrusteeEntry` objects.
    pub trustees: &'a [&'a [u8]],
    /// `WitnessRosterEntry` objects.
    pub witnesses: &'a [&'a [u8]],
    /// `TimestampAuthorityEntry` objects (ADR-0039).
    pub timestamp_authorities: &'a [&'a [u8]],
    /// `RollAuthorityEntry` objects (ADR-0040).
    pub roll_authorities: &'a [&'a [u8]],
}

/// A genesis as published: the `SignedGenesis` object and every entry.
#[derive(Debug, Clone, Copy)]
pub struct GenesisInput<'a> {
    /// The encoded `SignedGenesis` (schema `0x0033`) carrying the
    /// `GenesisBody`.
    pub signed: &'a [u8],
    /// The amendable sets as the genesis commits to them.
    pub sets: AmendableSets<'a>,
    /// The fixed sets.
    pub fixed: FixedSets<'a>,
}

/// An amendment as published: the `SignedGenesis` object carrying the
/// `GenesisAmendmentBody`, and all eight amendable sets of the state it
/// creates (unchanged sets included).
#[derive(Debug, Clone, Copy)]
pub struct AmendmentInput<'a> {
    /// The encoded `SignedGenesis` (schema `0x0033`) carrying the
    /// `GenesisAmendmentBody`.
    pub signed: &'a [u8],
    /// The amendable sets of the new state.
    pub sets: AmendableSets<'a>,
}

/// The decoded amendable sets of one state.
#[derive(Debug, Clone)]
pub(crate) struct Amendable<'a> {
    pub(crate) boxes: Set<'a, GenesisBox<'a>>,
    pub(crate) stations: Set<'a, StationEntry<'a>>,
    pub(crate) policies: Set<'a, StationProgressPolicy<'a>>,
    pub(crate) units: Set<'a, ReportingUnitEntry<'a>>,
    pub(crate) routes: Set<'a, CustodyRoute<'a>>,
    pub(crate) roster: Set<'a, RosterSigner<'a>>,
    pub(crate) modules: Set<'a, ModuleEntry<'a>>,
    pub(crate) appointments: Appointments,
}

/// The decoded fixed sets.
#[derive(Debug, Clone)]
pub(crate) struct Fixed<'a> {
    pub(crate) styles: Set<'a, BallotStyleEntry<'a>>,
    pub(crate) trustees: Set<'a, TrusteeEntry<'a>>,
    pub(crate) witnesses: Set<'a, WitnessRosterEntry<'a>>,
    pub(crate) timestamps: Set<'a, TimestampAuthorityEntry<'a>>,
    pub(crate) rolls: Set<'a, RollAuthorityEntry<'a>>,
}

fn commitment(
    state: u64,
    sets: &[SetCommitment; ENTRY_SET_COUNT],
    set: EntrySet,
) -> Result<&SetCommitment, Error> {
    sets.get(set.index())
        .ok_or(Error::set(state, set, Rule::Count))
}

fn parse<'a, T: GenesisEntry<'a>>(
    state: u64,
    entries: &[&'a [u8]],
    sets: &[SetCommitment; ENTRY_SET_COUNT],
) -> Result<Set<'a, T>, Error> {
    Set::parse(state, entries, commitment(state, sets, T::SET)?)
}

impl<'a> Amendable<'a> {
    fn parse(
        state: u64,
        input: &AmendableSets<'a>,
        sets: &[SetCommitment; ENTRY_SET_COUNT],
    ) -> Result<Self, Error> {
        Ok(Self {
            boxes: parse(state, input.boxes, sets)?,
            stations: parse(state, input.stations, sets)?,
            policies: parse(state, input.progress_policies, sets)?,
            units: parse(state, input.reporting_units, sets)?,
            routes: parse(state, input.routes, sets)?,
            roster: parse(state, input.roster, sets)?,
            modules: parse(state, input.modules, sets)?,
            appointments: Appointments::parse(
                state,
                input.appointments,
                commitment(state, sets, EntrySet::Appointments)?,
            )?,
        })
    }
}

impl<'a> Fixed<'a> {
    fn parse(
        state: u64,
        input: &FixedSets<'a>,
        sets: &[SetCommitment; ENTRY_SET_COUNT],
    ) -> Result<Self, Error> {
        Ok(Self {
            styles: parse(state, input.ballot_styles, sets)?,
            trustees: parse(state, input.trustees, sets)?,
            witnesses: parse(state, input.witnesses, sets)?,
            timestamps: parse(state, input.timestamp_authorities, sets)?,
            rolls: parse(state, input.roll_authorities, sets)?,
        })
    }
}

fn decode_signed(state: u64, bytes: &[u8]) -> Result<SignedGenesis<'_>, Error> {
    decode_object(SCHEMA_SIGNED_GENESIS, SCHEMA_VERSION_1, bytes)
        .map_err(|_| Error::body(state, Rule::Decode))
}

/// An entry's bytes, position and inclusion proof.
type Proof<'a> = (&'a [u8], u64, InclusionProof);

/// The witness-set entries of the signing witnesses, in signature order,
/// each with its bytes, position and proof.
fn signing_witnesses<'a>(
    state: u64,
    signed: &SignedGenesis<'_>,
    witnesses: &Set<'a, WitnessRosterEntry<'a>>,
) -> Result<Vec<Proof<'a>>, Error> {
    signed
        .witness_sigs()
        .map(|s| {
            witnesses
                .proof(s.witness_id.as_bytes())
                .ok_or(Error::body(state, Rule::WitnessUnknown))
        })
        .collect()
}

/// The (signature, registered key) pairs of `signed`: the commission's,
/// the committee's, then each witness's in signature order.
fn material<'s>(
    state: u64,
    signed: &'s SignedGenesis<'s>,
    body: &GenesisBody<'s>,
    witness_keys: &[&'s [u8; HYBRID_VK_LEN]],
) -> Result<Material, Error> {
    let authorities: [(&[u8; HYBRID_SIG_LEN], &[u8; HYBRID_VK_LEN]); 2] = [
        (signed.commission_sig(), body.commission_key()),
        (signed.committee_sig(), body.committee_key()),
    ];
    let witnesses = signed
        .witness_sigs()
        .map(|s| s.sig)
        .zip(witness_keys.iter().copied());
    Material::new(authorities.into_iter().chain(witnesses))
        .ok_or(Error::body(state, Rule::Signature))
}

/// A genesis whose pin, signatures, sets, cross-set agreement and
/// amendments were all checked.
#[derive(Debug, Clone)]
pub struct VerifiedGenesis<'a> {
    genesis: Genesis<'a>,
    anchors: Vec<Anchor>,
    sets: Amendable<'a>,
    /// The states before the last, from the genesis (state 0) on.
    history: Vec<State<'a>>,
    fixed: Fixed<'a>,
    /// Every state's devices and places, for scoping ledger events signed
    /// before an amendment changed them.
    seen: Seen<'a>,
}

/// One earlier genesis state with its checked amendable sets.
#[derive(Debug, Clone)]
struct State<'a> {
    genesis: Genesis<'a>,
    sets: Amendable<'a>,
}

/// The boxes, stations and check-in units of every genesis state.
#[derive(Debug, Clone, Default)]
struct Seen<'a> {
    boxes: BTreeSet<&'a [u8]>,
    stations: BTreeSet<&'a [u8]>,
    units: BTreeMap<&'a [u8], StationId<'a>>,
}

impl<'a> Seen<'a> {
    /// Adds the boxes, stations and units of one state. A unit keeps the
    /// station of the earliest state that has it.
    fn add(&mut self, sets: &Amendable<'a>) {
        for item in sets.boxes.items() {
            self.boxes.insert(item.value.box_id.as_bytes());
        }
        for item in sets.stations.items() {
            let s = &item.value;
            self.stations.insert(s.station_id().as_bytes());
            for unit in [s.primary(), s.spare()] {
                self.units
                    .entry(unit.unit_id.as_bytes())
                    .or_insert(s.station_id());
            }
        }
    }
}

/// Verifies a genesis and its amendments whole (PROTOCOL.md §14 1).
///
/// `pin` must come from outside the source of `input`: the gazette, the
/// committee's site, the designated public verifiers, print (VC-005).
///
/// # Errors
/// The first rule broken, with the state, set and entry where it broke.
pub fn verify_genesis<'a>(
    pin: &Hash512,
    input: &GenesisInput<'a>,
    amendments: &[AmendmentInput<'a>],
) -> Result<VerifiedGenesis<'a>, Error> {
    let signed = decode_signed(0, input.signed)?;
    let pinned = Pinned::new(pin, &signed).map_err(|e| {
        Error::body(
            0,
            if e == ityv_state::Error::Pin {
                Rule::Pin
            } else {
                Rule::Kind
            },
        )
    })?;
    let body = signed.genesis().ok_or(Error::body(0, Rule::Kind))?;
    let fixed = Fixed::parse(0, &input.fixed, body.sets())?;
    timestamp::check_authorities(0, &fixed.timestamps, body.election_epoch_day())?;
    roll::check_authorities(0, &fixed.rolls, body.custody_quorum())?;

    let signing = signing_witnesses(0, &signed, &fixed.witnesses)?;
    let mut entries = Vec::with_capacity(signing.len());
    for (bytes, index, proof) in &signing {
        let entry = pinned
            .witness(bytes, *index, proof)
            .map_err(|_| Error::body(0, Rule::WitnessUnknown))?;
        entries.push(entry);
    }
    let keys: Vec<&[u8; HYBRID_VK_LEN]> = entries.iter().map(|e| e.get().key).collect();
    let material = material(0, &signed, &body, &keys)?;
    let purpose = Purpose::new(signed.purpose()).ok_or(Error::body(0, Rule::Signature))?;
    let tokens = material
        .verify(&purpose, signed.body_bytes())
        .ok_or(Error::body(0, Rule::Signature))?;
    let mut genesis = pinned
        .seal(&tokens, &entries)
        .map_err(|e| Error::body(0, Rule::Seal(e)))?;

    let mut sets = Amendable::parse(0, &input.sets, genesis.sets())?;
    cross::check(0, &sets, &fixed, genesis.body())?;
    let mut seen = Seen::default();
    seen.add(&sets);
    let mut anchors = Vec::with_capacity(amendments.len().saturating_add(1));
    anchors.push(genesis.anchor());
    let mut history = Vec::with_capacity(amendments.len());

    for (k, amendment) in amendments.iter().enumerate() {
        let state = u64::try_from(k)
            .ok()
            .and_then(|k| k.checked_add(1))
            .ok_or(Error::body(
                u64::MAX,
                Rule::Chain(ityv_state::Error::Overflow),
            ))?;
        let next = amend(state, &genesis, &fixed, amendment)?;
        let next_sets = Amendable::parse(state, &amendment.sets, next.sets())?;
        cross::check(state, &next_sets, &fixed, next.body())?;
        seen.add(&next_sets);
        anchors.push(next.anchor());
        history.push(State {
            genesis,
            sets: core::mem::replace(&mut sets, next_sets),
        });
        genesis = next;
    }

    Ok(VerifiedGenesis {
        genesis,
        anchors,
        sets,
        history,
        fixed,
        seen,
    })
}

/// The entry `key` of `set`, proved against `genesis`.
fn prove_in<'a, T: GenesisEntry<'a>>(
    genesis: &Genesis<'a>,
    set: &Set<'a, T>,
    key: &[u8],
) -> Option<Entry<T>> {
    let (bytes, index, proof) = set.proof(key)?;
    genesis.entry(bytes, index, &proof).ok()
}

/// Verifies one amendment's signatures and applies it to `genesis`.
fn amend<'a>(
    state: u64,
    genesis: &Genesis<'a>,
    fixed: &Fixed<'a>,
    amendment: &AmendmentInput<'a>,
) -> Result<Genesis<'a>, Error> {
    let signed = decode_signed(state, amendment.signed)?;
    if signed.amendment().is_none() {
        return Err(Error::body(state, Rule::Kind));
    }
    let signing = signing_witnesses(state, &signed, &fixed.witnesses)?;
    let mut entries: Vec<Entry<WitnessRosterEntry<'a>>> = Vec::with_capacity(signing.len());
    for (bytes, index, proof) in &signing {
        let entry = genesis
            .entry(bytes, *index, proof)
            .map_err(|_| Error::body(state, Rule::WitnessUnknown))?;
        entries.push(entry);
    }
    let keys: Vec<&[u8; HYBRID_VK_LEN]> = entries.iter().map(|e| e.get().key).collect();
    let material = material(state, &signed, genesis.body(), &keys)?;
    let purpose = Purpose::new(signed.purpose()).ok_or(Error::body(state, Rule::Signature))?;
    let tokens = material
        .verify(&purpose, signed.body_bytes())
        .ok_or(Error::body(state, Rule::Signature))?;
    genesis.amend(&signed, &tokens, &entries).map_err(|e| {
        let chain = e == ityv_state::Error::Mismatch || e == ityv_state::Error::Overflow;
        Error::body(state, if chain { Rule::Chain(e) } else { Rule::Seal(e) })
    })
}

impl<'a> VerifiedGenesis<'a> {
    /// The genesis in its last state, as `ityv-state` holds it.
    #[must_use]
    pub const fn genesis(&self) -> &Genesis<'a> {
        &self.genesis
    }

    /// The election.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.genesis.election_id()
    }

    /// Every state from the genesis (amendment number 0) to the last
    /// amendment, in order.
    #[must_use]
    pub fn anchors(&self) -> &[Anchor] {
        &self.anchors
    }

    /// The expected boxes of the last state, in key order.
    pub fn boxes(&self) -> impl Iterator<Item = &GenesisBox<'a>> + '_ {
        self.sets.boxes.items().iter().map(|i| &i.value)
    }

    /// The stations of the last state, in key order.
    pub fn stations(&self) -> impl Iterator<Item = &StationEntry<'a>> + '_ {
        self.sets.stations.items().iter().map(|i| &i.value)
    }

    /// The expected box `box_id` of the last state, if any.
    #[must_use]
    pub fn expected_box(&self, box_id: &[u8]) -> Option<&GenesisBox<'a>> {
        self.sets.boxes.find(box_id)
    }

    /// The station `station_id` of the last state, if any.
    #[must_use]
    pub fn station(&self, station_id: &[u8]) -> Option<&StationEntry<'a>> {
        self.sets.stations.find(station_id)
    }

    /// The station whose check-in unit (in service or spare) is `unit_id`
    /// in any state of the genesis, if any.
    #[must_use]
    pub fn unit_station(&self, unit_id: &[u8]) -> Option<StationId<'a>> {
        self.seen.units.get(unit_id).copied()
    }

    /// Whether any state of the genesis has the box `box_id`.
    #[must_use]
    pub fn knows_box(&self, box_id: &[u8]) -> bool {
        self.seen.boxes.contains(box_id)
    }

    /// Whether any state of the genesis has the station `station_id`.
    #[must_use]
    pub fn knows_station(&self, station_id: &[u8]) -> bool {
        self.seen.stations.contains(station_id)
    }

    fn prove<T: GenesisEntry<'a>>(&self, set: &Set<'a, T>, key: &[u8]) -> Option<Entry<T>> {
        prove_in(&self.genesis, set, key)
    }

    /// The number of states: the genesis (state 0) and one per amendment.
    #[must_use]
    pub fn state_count(&self) -> usize {
        self.history.len().saturating_add(1)
    }

    /// The genesis and amendable sets of state `state`.
    fn state(&self, state: usize) -> Option<(&Genesis<'a>, &Amendable<'a>)> {
        match self.history.get(state) {
            Some(s) => Some((&s.genesis, &s.sets)),
            None => (state == self.history.len()).then_some((&self.genesis, &self.sets)),
        }
    }

    /// The genesis in state `state` (0 is the genesis, `k` the state after
    /// the `k`-th amendment), as `ityv-state` holds it.
    #[must_use]
    pub fn genesis_at(&self, state: usize) -> Option<&Genesis<'a>> {
        self.state(state).map(|(g, _)| g)
    }

    /// The expected box `box_id` of state `state`, if any.
    #[must_use]
    pub fn expected_box_at(&self, state: usize, box_id: &[u8]) -> Option<&GenesisBox<'a>> {
        self.state(state)?.1.boxes.find(box_id)
    }

    /// The expected box `key`, proved against state `state`.
    #[must_use]
    pub fn box_entry_at(&self, state: usize, key: &[u8]) -> Option<Entry<GenesisBox<'a>>> {
        let (g, sets) = self.state(state)?;
        prove_in(g, &sets.boxes, key)
    }

    /// The custody route `key`, proved against state `state`.
    #[must_use]
    pub fn route_entry_at(&self, state: usize, key: &[u8]) -> Option<Entry<CustodyRoute<'a>>> {
        let (g, sets) = self.state(state)?;
        prove_in(g, &sets.routes, key)
    }

    /// The reporting unit `key`, proved against state `state`.
    #[must_use]
    pub fn reporting_unit_entry_at(
        &self,
        state: usize,
        key: &[u8],
    ) -> Option<Entry<ReportingUnitEntry<'a>>> {
        let (g, sets) = self.state(state)?;
        prove_in(g, &sets.units, key)
    }

    /// The station `station_id` of state `state`, if any.
    #[must_use]
    pub fn station_at(&self, state: usize, station_id: &[u8]) -> Option<&StationEntry<'a>> {
        self.state(state)?.1.stations.find(station_id)
    }

    /// The station `key`, proved against state `state`.
    #[must_use]
    pub fn station_entry_at(&self, state: usize, key: &[u8]) -> Option<Entry<StationEntry<'a>>> {
        let (g, sets) = self.state(state)?;
        prove_in(g, &sets.stations, key)
    }

    /// The progress policy of station `key`, proved against state `state`.
    #[must_use]
    pub fn policy_entry_at(
        &self,
        state: usize,
        key: &[u8],
    ) -> Option<Entry<StationProgressPolicy<'a>>> {
        let (g, sets) = self.state(state)?;
        prove_in(g, &sets.policies, key)
    }

    /// The module `module_id` of state `state`, if any.
    #[must_use]
    pub fn module_at(&self, state: usize, module_id: &[u8]) -> Option<&ModuleEntry<'a>> {
        self.state(state)?.1.modules.find(module_id)
    }

    /// The expected boxes of state `state`, in key order (none for a state
    /// that does not exist).
    pub fn boxes_at(&self, state: usize) -> impl Iterator<Item = &GenesisBox<'a>> + '_ {
        self.state(state)
            .into_iter()
            .flat_map(|(_, sets)| sets.boxes.items().iter().map(|i| &i.value))
    }

    /// The stations of state `state`, in key order (none for a state that
    /// does not exist).
    pub fn stations_at(&self, state: usize) -> impl Iterator<Item = &StationEntry<'a>> + '_ {
        self.state(state)
            .into_iter()
            .flat_map(|(_, sets)| sets.stations.items().iter().map(|i| &i.value))
    }

    /// The modules of state `state`, in key order (none for a state that
    /// does not exist).
    pub fn modules_at(&self, state: usize) -> impl Iterator<Item = &ModuleEntry<'a>> + '_ {
        self.state(state)
            .into_iter()
            .flat_map(|(_, sets)| sets.modules.items().iter().map(|i| &i.value))
    }

    /// The trustees (chamber members), in key order (the set is fixed for
    /// the election).
    pub fn trustees(&self) -> impl Iterator<Item = &TrusteeEntry<'a>> + '_ {
        self.fixed.trustees.items().iter().map(|i| &i.value)
    }

    /// Every roster signer of state `state`, proved against it, in key
    /// order (empty for a state that does not exist).
    #[must_use]
    pub fn roster_at(&self, state: usize) -> Vec<Entry<RosterSigner<'a>>> {
        self.state(state)
            .map(|(g, sets)| {
                sets.roster
                    .items()
                    .iter()
                    .filter_map(|i| prove_in(g, &sets.roster, i.value.key()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The ballot style `ballot_style_id` (fixed for the election), if
    /// any.
    #[must_use]
    pub fn ballot_style(&self, ballot_style_id: &[u8]) -> Option<&BallotStyleEntry<'a>> {
        self.fixed.styles.find(ballot_style_id)
    }

    /// The expected box `key`, proved against the last state.
    #[must_use]
    pub fn box_entry(&self, key: &[u8]) -> Option<Entry<GenesisBox<'a>>> {
        self.prove(&self.sets.boxes, key)
    }

    /// The station `key`, proved against the last state.
    #[must_use]
    pub fn station_entry(&self, key: &[u8]) -> Option<Entry<StationEntry<'a>>> {
        self.prove(&self.sets.stations, key)
    }

    /// The progress policy of station `key`, proved against the last
    /// state.
    #[must_use]
    pub fn policy_entry(&self, key: &[u8]) -> Option<Entry<StationProgressPolicy<'a>>> {
        self.prove(&self.sets.policies, key)
    }

    /// The reporting unit `key`, proved against the last state.
    #[must_use]
    pub fn reporting_unit_entry(&self, key: &[u8]) -> Option<Entry<ReportingUnitEntry<'a>>> {
        self.prove(&self.sets.units, key)
    }

    /// The custody route `key`, proved against the last state.
    #[must_use]
    pub fn route_entry(&self, key: &[u8]) -> Option<Entry<CustodyRoute<'a>>> {
        self.prove(&self.sets.routes, key)
    }

    /// The roster signer `key`, proved against the last state.
    #[must_use]
    pub fn roster_entry(&self, key: &[u8]) -> Option<Entry<RosterSigner<'a>>> {
        self.prove(&self.sets.roster, key)
    }

    /// Every roster signer, proved against the last state, in key order.
    #[must_use]
    pub fn roster(&self) -> Vec<Entry<RosterSigner<'a>>> {
        self.sets
            .roster
            .items()
            .iter()
            .filter_map(|i| self.roster_entry(i.value.key()))
            .collect()
    }

    /// The module `key`, proved against the last state.
    #[must_use]
    pub fn module_entry(&self, key: &[u8]) -> Option<Entry<ModuleEntry<'a>>> {
        self.prove(&self.sets.modules, key)
    }

    /// The ballot style `key`, proved against the last state.
    #[must_use]
    pub fn ballot_style_entry(&self, key: &[u8]) -> Option<Entry<BallotStyleEntry<'a>>> {
        self.prove(&self.fixed.styles, key)
    }

    /// The trustee `key`, proved against the last state.
    #[must_use]
    pub fn trustee_entry(&self, key: &[u8]) -> Option<Entry<TrusteeEntry<'a>>> {
        self.prove(&self.fixed.trustees, key)
    }

    /// The witness `key`, proved against the last state.
    #[must_use]
    pub fn witness_entry(&self, key: &[u8]) -> Option<Entry<WitnessRosterEntry<'a>>> {
        self.prove(&self.fixed.witnesses, key)
    }

    /// The witness set, in key order (it is fixed for the election).
    pub fn witnesses(&self) -> impl Iterator<Item = &WitnessRosterEntry<'a>> + '_ {
        self.fixed.witnesses.items().iter().map(|i| &i.value)
    }

    /// The timestamp authorities, in key order (fixed for the election,
    /// ADR-0039).
    pub fn timestamp_authorities(&self) -> impl Iterator<Item = &TimestampAuthorityEntry<'a>> + '_ {
        self.fixed.timestamps.items().iter().map(|i| &i.value)
    }

    /// The timestamp authority `tsa_id`, if the genesis pins it.
    #[must_use]
    pub fn timestamp_authority(&self, tsa_id: &[u8]) -> Option<&TimestampAuthorityEntry<'a>> {
        self.fixed.timestamps.find(tsa_id)
    }

    /// The roll's sources and custodians, in key order (fixed for the
    /// election, ADR-0040).
    pub fn roll_authorities(&self) -> impl Iterator<Item = &RollAuthorityEntry<'a>> + '_ {
        self.fixed.rolls.items().iter().map(|i| &i.value)
    }

    /// The roll authority `authority_id`, if the genesis registers it.
    #[must_use]
    pub fn roll_authority(&self, authority_id: &[u8]) -> Option<&RollAuthorityEntry<'a>> {
        self.fixed.rolls.find(authority_id)
    }

    /// The roll authority `authority_id`, proved against the last state.
    #[must_use]
    pub fn roll_authority_entry(
        &self,
        authority_id: &[u8],
    ) -> Option<Entry<RollAuthorityEntry<'a>>> {
        self.prove(&self.fixed.rolls, authority_id)
    }
}
