//! Agreement between the entry sets of one genesis state (ADR-0028
//! decision 8, VC-009, VC-067, VC-104).
//!
//! An inclusion proof shows that one entry is in a set; it cannot show
//! that the entries of different sets fit together. These checks need
//! every entry of every set and run once per genesis state (the genesis
//! and the state after each amendment):
//!
//! * every box names a station, route, ballot style, reporting unit and
//!   modules that exist, and its station lists it;
//! * every box a station lists exists and names that station, so the
//!   station's list is exactly the boxes that name it;
//! * every station has exactly one progress policy and every policy names
//!   a station;
//! * every reporting unit's box count is the number of boxes that name it;
//! * every roster signer's station exists, and every observer token of a
//!   station names an observer of the token's organisation on the roster;
//! * every roster, trustee and witness entry's appointment is in the
//!   appointment set (VC-009);
//! * every box carries one module of each party chamber `P1`…`Pn`, at
//!   most one each of `J`, `A` and `C`, and none of `N`; every check-in
//!   unit carries exactly one module of each party chamber; no module
//!   belongs to `N` or to a party chamber the genesis does not have; and
//!   each chamber has exactly `n_c` trustees (VC-067, VC-017);
//! * no two devices share an identifier (boxes, check-in units and
//!   modules), so a device attestation names exactly one device;
//! * no two keys of the state share a half: the two authorities, every
//!   box's device and attestation keys, every check-in unit's keys, every
//!   roster signer, module, trustee and witness.
//!
//! What these checks do not prove: that an entry is true of the world (a
//! box exists physically, a person holds the key registered for them);
//! that the parties are the right ones (ADR-0019 decides eligibility, the
//! body carries the evidence hash); that keys were generated as the
//! procedures require.

use alloc::collections::{BTreeMap, BTreeSet};

use ityv_encoding::{
    ChamberCode, EntrySet, GenesisBody, HYBRID_VK_LEN, MLDSA87_VK_HALF, ModuleIds, RosterRole,
};

use crate::error::{Error, Reference, Rule};
use crate::genesis::{Amendable, Fixed};

/// The highest chamber code (`N`).
pub(crate) const CHAMBER_CODES: usize = 8;

/// Number of modules per chamber code, indexed by `code − 1`.
pub(crate) type ChamberTally = [u8; CHAMBER_CODES];

/// Whether `code` is a party chamber present in a genesis of `parties`
/// party chambers.
fn is_party(code: ChamberCode, parties: usize) -> bool {
    let c = usize::from(code.code());
    c >= 1 && c <= parties
}

/// Counts the chambers of `modules`.
fn tally(
    state: u64,
    set: EntrySet,
    index: usize,
    modules: &ModuleIds<'_>,
    a: &Amendable<'_>,
) -> Result<ChamberTally, Error> {
    let mut counts: ChamberTally = [0; CHAMBER_CODES];
    for id in modules.iter() {
        let module = a.modules.find(id.as_bytes()).ok_or(Error::entry(
            state,
            set,
            index,
            Rule::Missing(Reference::Module),
        ))?;
        let slot = usize::from(module.chamber.code())
            .checked_sub(1)
            .and_then(|i| counts.get_mut(i))
            .ok_or(Error::entry(state, set, index, Rule::Chambers))?;
        *slot = slot.saturating_add(1);
    }
    Ok(counts)
}

/// Whether a box's modules are one per party chamber, at most one each
/// of `J`, `A`, `C`, and none of absent party chambers.
pub(crate) fn box_modules_valid(counts: ChamberTally, parties: usize) -> bool {
    counts.iter().enumerate().all(|(i, &n)| match i {
        // P1..P4: exactly one for the genesis's parties, none otherwise.
        0..=3 => n == u8::from(i < parties),
        // J, A, C: optional, at most one. (N: a module of N does not
        // decode, so its count is always 0.)
        _ => n <= 1,
    })
}

/// Whether a check-in unit's modules are exactly one per party chamber.
pub(crate) fn unit_modules_valid(counts: ChamberTally, parties: usize) -> bool {
    counts
        .iter()
        .enumerate()
        .all(|(i, &n)| n == u8::from(i < parties))
}

/// The two halves of a registered key.
fn halves(key: &[u8; HYBRID_VK_LEN]) -> Option<(&[u8], &[u8])> {
    key.split_first_chunk::<MLDSA87_VK_HALF>()
        .map(|(ml, ed)| (ml.as_slice(), ed))
}

/// Every key half of one state, with where it was first seen.
struct Keys<'k> {
    state: u64,
    seen: BTreeSet<&'k [u8]>,
}

impl<'k> Keys<'k> {
    fn new(state: u64) -> Self {
        Self {
            state,
            seen: BTreeSet::new(),
        }
    }

    /// Adds both halves of `key`, owned by entry `index` of `set` (or by
    /// the body when `set` is `None`).
    fn add(
        &mut self,
        key: &'k [u8; HYBRID_VK_LEN],
        set: Option<EntrySet>,
        index: usize,
    ) -> Result<(), Error> {
        let err = || match set {
            Some(s) => Error::entry(self.state, s, index, Rule::SharedKey),
            None => Error::body(self.state, Rule::SharedKey),
        };
        let (ml, ed) = halves(key).ok_or_else(err)?;
        // The two halves have different lengths, so one map holds both
        // without an ML-DSA-87 half ever equalling an Ed25519 half.
        for half in [ml, ed] {
            if !self.seen.insert(half) {
                return Err(err());
            }
        }
        Ok(())
    }
}

/// Checks that the sets of one state agree with each other and with
/// `body` (the genesis body; amendments keep its parties and chambers).
///
/// # Errors
/// The first broken rule, at the entry that breaks it.
#[allow(clippy::too_many_lines)] // One pass per set, in the order of the module docs.
pub(crate) fn check(
    state: u64,
    a: &Amendable<'_>,
    f: &Fixed<'_>,
    body: &GenesisBody<'_>,
) -> Result<(), Error> {
    let parties = body.parties().count();

    // Boxes: references, modules, and per-station and per-unit counts.
    let mut unit_boxes: BTreeMap<&[u8], u32> = BTreeMap::new();
    for (i, item) in a.boxes.items().iter().enumerate() {
        let b = &item.value;
        let at = |rule| Error::entry(state, EntrySet::Boxes, i, rule);
        let station = a
            .stations
            .find(b.station_id.as_bytes())
            .ok_or(at(Rule::Missing(Reference::Station)))?;
        if !station
            .boxes()
            .any(|id| id.as_bytes() == b.box_id.as_bytes())
        {
            return Err(at(Rule::StationBoxes));
        }
        if a.routes.find(b.route_id.as_bytes()).is_none() {
            return Err(at(Rule::Missing(Reference::Route)));
        }
        if f.styles.find(b.ballot_style_id.as_bytes()).is_none() {
            return Err(at(Rule::Missing(Reference::BallotStyle)));
        }
        if a.units.find(b.reporting_unit_id.as_bytes()).is_none() {
            return Err(at(Rule::Missing(Reference::ReportingUnit)));
        }
        let counts = tally(state, EntrySet::Boxes, i, &b.modules, a)?;
        if !box_modules_valid(counts, parties) {
            return Err(at(Rule::Chambers));
        }
        let n = unit_boxes
            .entry(b.reporting_unit_id.as_bytes())
            .or_insert(0);
        *n = n.checked_add(1).ok_or(at(Rule::UnitBoxCount))?;
    }

    // Stations: the box list names boxes that name the station back, one
    // policy each, and the check-in units' modules.
    for (i, item) in a.stations.items().iter().enumerate() {
        let s = &item.value;
        let at = |rule| Error::entry(state, EntrySet::Stations, i, rule);
        for id in s.boxes() {
            let b = a
                .boxes
                .find(id.as_bytes())
                .ok_or(at(Rule::Missing(Reference::Box)))?;
            if b.station_id.as_bytes() != s.station_id().as_bytes() {
                return Err(at(Rule::StationBoxes));
            }
        }
        if a.policies.find(s.station_id().as_bytes()).is_none() {
            return Err(at(Rule::StationPolicy));
        }
        for unit in [s.primary(), s.spare()] {
            let counts = tally(state, EntrySet::Stations, i, &unit.modules, a)?;
            if !unit_modules_valid(counts, parties) {
                return Err(at(Rule::Chambers));
            }
        }
        for token in s.tokens() {
            let observer = a.roster.find(token.observer_id.as_bytes());
            let valid = observer.is_some_and(|o| {
                o.role == RosterRole::Observer && o.org_id.as_bytes() == token.org_id.as_bytes()
            });
            if !valid {
                return Err(at(Rule::ObserverToken));
            }
        }
    }

    // Progress policies name stations.
    for (i, item) in a.policies.items().iter().enumerate() {
        if a.stations
            .find(item.value.station_id().as_bytes())
            .is_none()
        {
            return Err(Error::entry(
                state,
                EntrySet::ProgressPolicies,
                i,
                Rule::StationPolicy,
            ));
        }
    }

    // Reporting units count their boxes.
    for (i, item) in a.units.items().iter().enumerate() {
        let u = &item.value;
        let named = unit_boxes.get(u.unit_id().as_bytes()).copied().unwrap_or(0);
        if named != u.box_count() {
            return Err(Error::entry(
                state,
                EntrySet::ReportingUnits,
                i,
                Rule::UnitBoxCount,
            ));
        }
    }

    // Roster: stations exist, appointments are registered.
    for (i, item) in a.roster.items().iter().enumerate() {
        let r = &item.value;
        let at = |rule| Error::entry(state, EntrySet::Roster, i, rule);
        if let Some(station) = r.station_id
            && a.stations.find(station.as_bytes()).is_none()
        {
            return Err(at(Rule::Missing(Reference::Station)));
        }
        if !a.appointments.contains(&r.appointment_hash) {
            return Err(at(Rule::Appointment));
        }
    }

    // Modules belong to chambers the genesis has.
    for (i, item) in a.modules.items().iter().enumerate() {
        let code = item.value.chamber;
        let allowed = is_party(code, parties)
            || matches!(code, ChamberCode::J | ChamberCode::A | ChamberCode::C);
        if !allowed {
            return Err(Error::entry(state, EntrySet::Modules, i, Rule::Chambers));
        }
    }

    // Trustees: appointments, and exactly n_c per chamber.
    let mut members: ChamberTally = [0; CHAMBER_CODES];
    for (i, item) in f.trustees.items().iter().enumerate() {
        let t = &item.value;
        let at = |rule| Error::entry(state, EntrySet::Trustees, i, rule);
        if !a.appointments.contains(&t.appointment_hash) {
            return Err(at(Rule::Appointment));
        }
        let slot = usize::from(t.chamber.code())
            .checked_sub(1)
            .and_then(|c| members.get_mut(c))
            .ok_or(at(Rule::Trustees))?;
        *slot = slot.checked_add(1).ok_or(at(Rule::Trustees))?;
    }
    let mut listed: ChamberTally = [0; CHAMBER_CODES];
    for c in body.chambers() {
        if let Some(slot) = usize::from(c.chamber.code())
            .checked_sub(1)
            .and_then(|i| listed.get_mut(i))
        {
            *slot = c.members;
        }
    }
    if members != listed {
        return Err(Error::set(state, EntrySet::Trustees, Rule::Trustees));
    }

    // Witnesses: appointments.
    for (i, item) in f.witnesses.items().iter().enumerate() {
        if !a.appointments.contains(&item.value.appointment_hash) {
            return Err(Error::entry(
                state,
                EntrySet::Witnesses,
                i,
                Rule::Appointment,
            ));
        }
    }

    check_devices(state, a)?;
    check_keys(state, a, f, body)
}

/// No two devices of one state share an identifier (boxes, check-in units
/// and modules live in one namespace for device attestations).
fn check_devices(state: u64, a: &Amendable<'_>) -> Result<(), Error> {
    let mut ids: BTreeSet<&[u8]> = BTreeSet::new();
    // Box identifiers are distinct within their set (strict order).
    for item in a.boxes.items() {
        ids.insert(item.value.box_id.as_bytes());
    }
    for (i, item) in a.modules.items().iter().enumerate() {
        if !ids.insert(item.value.module_id.as_bytes()) {
            return Err(Error::entry(state, EntrySet::Modules, i, Rule::DeviceId));
        }
    }
    for (i, item) in a.stations.items().iter().enumerate() {
        for unit in [item.value.primary(), item.value.spare()] {
            if !ids.insert(unit.unit_id.as_bytes()) {
                return Err(Error::entry(state, EntrySet::Stations, i, Rule::DeviceId));
            }
        }
    }
    Ok(())
}

/// No two keys of one state share a half.
fn check_keys(
    state: u64,
    a: &Amendable<'_>,
    f: &Fixed<'_>,
    body: &GenesisBody<'_>,
) -> Result<(), Error> {
    let mut keys = Keys::new(state);
    keys.add(body.commission_key(), None, 0)?;
    keys.add(body.committee_key(), None, 0)?;
    for (i, item) in a.boxes.items().iter().enumerate() {
        keys.add(item.value.device_key, Some(EntrySet::Boxes), i)?;
        keys.add(item.value.attest_key, Some(EntrySet::Boxes), i)?;
    }
    for (i, item) in a.stations.items().iter().enumerate() {
        for unit in [item.value.primary(), item.value.spare()] {
            keys.add(unit.key, Some(EntrySet::Stations), i)?;
            keys.add(unit.attest_key, Some(EntrySet::Stations), i)?;
        }
    }
    for (i, item) in a.roster.items().iter().enumerate() {
        keys.add(item.value.key, Some(EntrySet::Roster), i)?;
    }
    for (i, item) in a.modules.items().iter().enumerate() {
        keys.add(item.value.key, Some(EntrySet::Modules), i)?;
        keys.add(item.value.attest_key, Some(EntrySet::Modules), i)?;
    }
    for (i, item) in f.trustees.items().iter().enumerate() {
        keys.add(item.value.key, Some(EntrySet::Trustees), i)?;
    }
    for (i, item) in f.witnesses.items().iter().enumerate() {
        keys.add(item.value.key, Some(EntrySet::Witnesses), i)?;
    }
    Ok(())
}
