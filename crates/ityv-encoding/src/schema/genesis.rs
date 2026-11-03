//! The genesis entry objects (ADR-0028; PROTOCOL.md §4.1; ENCODING.md
//! §8.43, §8.48–§8.53).
//!
//! A national genesis holds tens of thousands of boxes, stations and
//! roster signers, so it is not one object. The `GenesisBody` (schema
//! `0x0002`, [`crate::schema::genesis_body`]) carries the scalar fields,
//! the pins, the two authority keys and, for each entry set, a count and a
//! Merkle root. Every entry is a complete object of its own schema; its
//! leaf input is the entry's object hash (ENCODING.md §4), a set is
//! strictly ascending by the entries' key ([`GenesisEntry::key`]), and the
//! root is the RFC 9162-shaped SHA3-512 tree root of `ityv-ledger`
//! (PROTOCOL.md §5.3). An entry is used only with an inclusion proof
//! against the root its set has in a pinned genesis.

use crate::codec::{Decode, Encode};
use crate::error::{Error, Kind};
use crate::primitives::{
    BallotStyleId, BoxId, Hash512, IDENT_MAX_STANDARD, Ident, ModuleId, OrgId, ReportingUnitId,
    RouteId, SchemaId, SignerId, StationId, TrusteeId, UnitId,
};
use crate::reader::Reader;
use crate::schema::share_package::ChamberCode;
use crate::schema::util::{
    HYBRID_VK_LEN, MAX_CHUNKS, ModuleIds, ascending_by, keys_share_half, read_fixed,
};
use crate::schema::{
    SCHEMA_BALLOT_STYLE_ENTRY, SCHEMA_CUSTODY_ROUTE, SCHEMA_GENESIS_BOX, SCHEMA_MODULE_ENTRY,
    SCHEMA_REPORTING_UNIT_ENTRY, SCHEMA_ROSTER_SIGNER, SCHEMA_STATION_ENTRY,
    SCHEMA_STATION_PROGRESS_POLICY, SCHEMA_TRUSTEE_ENTRY, SCHEMA_WITNESS_ROSTER_ENTRY,
};
use crate::writer::Writer;

/// Maximum number of organisations on one custody route.
pub const MAX_ROUTE_STOPS: usize = 8;

/// Minimum number of organisations on one custody route.
pub const MIN_ROUTE_STOPS: usize = 2;

/// Maximum number of boxes at one station (PROTOCOL.md §17: one box per
/// election round, an out-of-district box at an early-voting station, two
/// rounds in local elections).
pub const MAX_STATION_BOXES: usize = 8;

/// Maximum number of observer tokens registered for one station.
pub const MAX_OBSERVER_TOKENS: usize = 16;

/// Length of an observer token's check key (Ed25519, PROTOCOL.md §3.2).
pub const TOKEN_CHECK_KEY_LEN: usize = 32;

/// Number of entry sets in a genesis.
pub const ENTRY_SET_COUNT: usize = 11;

/// Number of entry sets a `GenesisAmendment` may replace (the first
/// eight codes of [`EntrySet`]).
pub const AMENDABLE_SET_COUNT: usize = 8;

/// The collection profile of a box (PROTOCOL.md §17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CaptureProfile {
    /// A polling-station box (선거일·관내 사전투표).
    InPerson = 1,
    /// An out-of-district or overseas box: ballots go in return
    /// envelopes.
    Absentee = 2,
    /// A receiving commission's scanner for home and ship voting.
    ReceiptScan = 3,
}

impl CaptureProfile {
    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Returns the profile with wire code `code`, if defined.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::InPerson),
            2 => Some(Self::Absentee),
            3 => Some(Self::ReceiptScan),
            _ => None,
        }
    }
}

/// The registered role of a person on the roster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RosterRole {
    /// A polling or counting clerk.
    Clerk = 1,
    /// An observer.
    Observer = 2,
    /// A custodian who carries or receives boxes (police, postal staff,
    /// counting-centre staff).
    Custodian = 3,
    /// A legal authority whose decisions the verifier shows next to its
    /// own status (a court or another body the law empowers, PROTOCOL.md
    /// §13).
    Authority = 4,
    /// The chair of a district election commission (구·시·군 선관위
    /// 위원장), who signs the paper count of a reporting unit
    /// (PROTOCOL.md §11.5).
    Chair = 5,
}

impl RosterRole {
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
            3 => Some(Self::Custodian),
            4 => Some(Self::Authority),
            5 => Some(Self::Chair),
            _ => None,
        }
    }
}

/// The kind of a polling station.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum StationKind {
    /// An election-day polling station (선거일 투표소): the issuing clerk
    /// fixes the number of sheets.
    ElectionDay = 1,
    /// An early-voting station (사전투표소): the ballot printer reports
    /// the sheets it printed.
    EarlyVoting = 2,
    /// A receiving commission (home and ship voting).
    Receiving = 3,
}

impl StationKind {
    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Returns the kind with wire code `code`, if defined.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::ElectionDay),
            2 => Some(Self::EarlyVoting),
            3 => Some(Self::Receiving),
            _ => None,
        }
    }
}

/// The entry sets of a genesis, in the order of their commitments in the
/// `GenesisBody` (ADR-0028). Codes 1–8 may be replaced by a
/// `GenesisAmendment`; codes 9–11 are fixed for the election.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum EntrySet {
    /// `expected_boxes[]`: [`GenesisBox`], by `box_id`.
    Boxes = 1,
    /// `stations[]`: [`StationEntry`], by `station_id`.
    Stations = 2,
    /// `progress_policies[]`: [`StationProgressPolicy`], by `station_id`.
    ProgressPolicies = 3,
    /// `reporting_units[]`: [`ReportingUnitEntry`], by `unit_id`.
    ReportingUnits = 4,
    /// `custody_routes[]`: [`CustodyRoute`], by `route_id`.
    Routes = 5,
    /// The roster of clerks, observers, custodians and legal authorities:
    /// [`RosterSigner`], by `signer_id`.
    Roster = 6,
    /// The chamber modules: [`ModuleEntry`], by `module_id`.
    Modules = 7,
    /// `appointments[]`: bare `Appointment` event hashes in ascending byte
    /// order (the sorted-set rule of PROTOCOL.md §5.3); no entry objects.
    Appointments = 8,
    /// `ballot_styles[]`: [`BallotStyleEntry`], by `ballot_style_id`.
    BallotStyles = 9,
    /// `trustee_roster`: [`TrusteeEntry`], by `trustee_id`.
    Trustees = 10,
    /// `witness_roster`: [`WitnessRosterEntry`], by `witness_id`. Its root
    /// is the `witness_roster_hash`.
    Witnesses = 11,
}

impl EntrySet {
    /// Every set in commitment order.
    pub const ALL: [Self; ENTRY_SET_COUNT] = [
        Self::Boxes,
        Self::Stations,
        Self::ProgressPolicies,
        Self::ReportingUnits,
        Self::Routes,
        Self::Roster,
        Self::Modules,
        Self::Appointments,
        Self::BallotStyles,
        Self::Trustees,
        Self::Witnesses,
    ];

    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// The position of the set's commitment (`code − 1`).
    #[must_use]
    pub const fn index(self) -> usize {
        (self as usize).saturating_sub(1)
    }

    /// Whether a `GenesisAmendment` may replace the set.
    #[must_use]
    pub const fn amendable(self) -> bool {
        self.index() < AMENDABLE_SET_COUNT
    }

    /// The schema of the set's entries, or `None` for the appointment
    /// hashes.
    #[must_use]
    pub const fn schema(self) -> Option<SchemaId> {
        match self {
            Self::Boxes => Some(SCHEMA_GENESIS_BOX),
            Self::Stations => Some(SCHEMA_STATION_ENTRY),
            Self::ProgressPolicies => Some(SCHEMA_STATION_PROGRESS_POLICY),
            Self::ReportingUnits => Some(SCHEMA_REPORTING_UNIT_ENTRY),
            Self::Routes => Some(SCHEMA_CUSTODY_ROUTE),
            Self::Roster => Some(SCHEMA_ROSTER_SIGNER),
            Self::Modules => Some(SCHEMA_MODULE_ENTRY),
            Self::Appointments => None,
            Self::BallotStyles => Some(SCHEMA_BALLOT_STYLE_ENTRY),
            Self::Trustees => Some(SCHEMA_TRUSTEE_ENTRY),
            Self::Witnesses => Some(SCHEMA_WITNESS_ROSTER_ENTRY),
        }
    }
}

/// An entry object of one genesis set.
pub trait GenesisEntry<'a>: Encode + Decode<'a> {
    /// The set the entry belongs to; its schema is the set's.
    const SET: EntrySet;

    /// The sort key: a set is strictly ascending by it, so no key appears
    /// twice in one set.
    fn key(&self) -> &'a [u8];
}

fn read_code<T>(r: &mut Reader<'_>, from: impl Fn(u8) -> Option<T>) -> Result<T, Error> {
    let at = r.position();
    from(r.read_u8()?).ok_or_else(|| Error::new(Kind::ValueOutOfRange, at))
}

/// Reads a hash that must not be all zeros: a reference to an event or a
/// document that must exist (`InvalidPreviousHash`, as for the appointment
/// reference of VC-009).
pub(crate) fn read_nonzero_hash(r: &mut Reader<'_>) -> Result<Hash512, Error> {
    let at = r.position();
    let hash = Hash512::decode(r)?;
    if hash.is_zero() {
        return Err(Error::new(Kind::InvalidPreviousHash, at));
    }
    Ok(hash)
}

fn ident_len(id: &Ident<'_>) -> usize {
    id.byte_len().saturating_add(4)
}

/// One expected box (`expected_boxes[]`, schema `0x0035`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GenesisBox<'a> {
    /// The box.
    pub box_id: BoxId<'a>,
    /// Its station.
    pub station_id: StationId<'a>,
    /// Its ballot style.
    pub ballot_style_id: BallotStyleId<'a>,
    /// Its collection profile.
    pub profile: CaptureProfile,
    /// Its custody route.
    pub route_id: RouteId<'a>,
    /// The reporting unit whose paper results include it.
    pub reporting_unit_id: ReportingUnitId<'a>,
    /// The commitment unit's hybrid verifying key.
    pub device_key: &'a [u8; HYBRID_VK_LEN],
    /// The commitment unit's attestation key (PROTOCOL.md §7.9).
    pub attest_key: &'a [u8; HYBRID_VK_LEN],
    /// The chamber modules registered for it (ascending).
    pub modules: ModuleIds<'a>,
}

impl Encode for GenesisBox<'_> {
    fn encoded_len(&self) -> usize {
        self.box_id
            .encoded_len()
            .saturating_add(self.station_id.encoded_len())
            .saturating_add(self.ballot_style_id.encoded_len())
            .saturating_add(1)
            .saturating_add(self.route_id.encoded_len())
            .saturating_add(self.reporting_unit_id.encoded_len())
            .saturating_add(HYBRID_VK_LEN)
            .saturating_add(HYBRID_VK_LEN)
            .saturating_add(self.modules.encoded_len())
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.box_id.encode(w)?;
        self.station_id.encode(w)?;
        self.ballot_style_id.encode(w)?;
        w.write_u8(self.profile.code())?;
        self.route_id.encode(w)?;
        self.reporting_unit_id.encode(w)?;
        w.write_array(self.device_key)?;
        w.write_array(self.attest_key)?;
        self.modules.encode(w)
    }
}

impl<'a> Decode<'a> for GenesisBox<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            box_id: BoxId::decode(r)?,
            station_id: StationId::decode(r)?,
            ballot_style_id: BallotStyleId::decode(r)?,
            profile: read_code(r, CaptureProfile::from_code)?,
            route_id: RouteId::decode(r)?,
            reporting_unit_id: ReportingUnitId::decode(r)?,
            device_key: read_fixed::<HYBRID_VK_LEN>(r)?,
            attest_key: read_fixed::<HYBRID_VK_LEN>(r)?,
            modules: ModuleIds::decode(r)?,
        })
    }
}

impl<'a> GenesisEntry<'a> for GenesisBox<'a> {
    const SET: EntrySet = EntrySet::Boxes;

    fn key(&self) -> &'a [u8] {
        self.box_id.as_bytes()
    }
}

/// A check-in unit (카운터·가명 유닛) of a station: its device key, its
/// attestation key and the party modules plugged into it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckinUnit<'a> {
    /// The unit.
    pub unit_id: UnitId<'a>,
    /// The unit's hybrid verifying key (`CheckinCounter`, progress ticks).
    pub key: &'a [u8; HYBRID_VK_LEN],
    /// The unit's attestation key (PROTOCOL.md §7.9).
    pub attest_key: &'a [u8; HYBRID_VK_LEN],
    /// The party modules plugged into the unit (ascending).
    pub modules: ModuleIds<'a>,
}

impl<'a> CheckinUnit<'a> {
    fn len(&self) -> usize {
        self.unit_id
            .encoded_len()
            .saturating_add(HYBRID_VK_LEN)
            .saturating_add(HYBRID_VK_LEN)
            .saturating_add(self.modules.encoded_len())
    }

    fn write(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.unit_id.encode(w)?;
        w.write_array(self.key)?;
        w.write_array(self.attest_key)?;
        self.modules.encode(w)
    }

    fn read(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            unit_id: UnitId::decode(r)?,
            key: read_fixed::<HYBRID_VK_LEN>(r)?,
            attest_key: read_fixed::<HYBRID_VK_LEN>(r)?,
            modules: ModuleIds::decode(r)?,
        })
    }
}

/// An observer token registered for a station: the observer as the roster
/// names them, and the token's Ed25519 check key for `attest-challenge`
/// (PROTOCOL.md §7.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObserverToken<'a> {
    /// The observer, as on the roster.
    pub observer_id: SignerId<'a>,
    /// The observer's organisation.
    pub org_id: OrgId<'a>,
    /// The token's check key.
    pub check_key: &'a [u8; TOKEN_CHECK_KEY_LEN],
}

/// Unvalidated inputs for [`StationEntry::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StationParts<'a> {
    /// The station.
    pub station_id: StationId<'a>,
    /// Its kind.
    pub kind: StationKind,
    /// The check-in unit in service.
    pub primary: CheckinUnit<'a>,
    /// The sealed spare unit (PROTOCOL.md §6.2).
    pub spare: CheckinUnit<'a>,
    /// Every box at the station, ascending.
    pub boxes: &'a [BoxId<'a>],
    /// Hash of the station's identity-terminal list (the terminals are
    /// outside the TCB and hold no registered key).
    pub id_terminals_hash: Hash512,
    /// The station's observer tokens, ascending by observer.
    pub tokens: &'a [ObserverToken<'a>],
}

/// One polling station (`stations[]`, schema `0x0036`).
///
/// Rules: the two units have different identifiers and keys that share no
/// half (`InvariantViolation`); one to eight boxes (`InvariantViolation`
/// for none, `CountExceedsMax`) and at most sixteen tokens, each list
/// strictly ascending (`NotSorted`, `Duplicate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StationEntry<'a> {
    station_id: StationId<'a>,
    kind: StationKind,
    primary: CheckinUnit<'a>,
    spare: CheckinUnit<'a>,
    boxes: [Option<BoxId<'a>>; MAX_STATION_BOXES],
    box_count: u8,
    id_terminals_hash: Hash512,
    tokens: [Option<ObserverToken<'a>>; MAX_OBSERVER_TOKENS],
    token_count: u8,
}

fn units_valid(a: &CheckinUnit<'_>, b: &CheckinUnit<'_>) -> bool {
    a.unit_id.as_bytes() != b.unit_id.as_bytes() && !keys_share_half(a.key, b.key)
}

impl<'a> StationEntry<'a> {
    /// Builds an entry.
    ///
    /// # Errors
    /// `InvariantViolation` at 0 if a rule is broken.
    pub fn new(parts: &StationParts<'a>) -> Result<Self, Error> {
        let bad = Error::new(Kind::InvariantViolation, 0);
        let boxes_ok = !parts.boxes.is_empty()
            && parts.boxes.len() <= MAX_STATION_BOXES
            && ascending_by(parts.boxes, |b| b.as_bytes());
        let tokens_ok = parts.tokens.len() <= MAX_OBSERVER_TOKENS
            && ascending_by(parts.tokens, |t| t.observer_id.as_bytes());
        if !boxes_ok || !tokens_ok || !units_valid(&parts.primary, &parts.spare) {
            return Err(bad);
        }
        let mut boxes = [None; MAX_STATION_BOXES];
        for (slot, b) in boxes.iter_mut().zip(parts.boxes) {
            *slot = Some(*b);
        }
        let mut tokens = [None; MAX_OBSERVER_TOKENS];
        for (slot, t) in tokens.iter_mut().zip(parts.tokens) {
            *slot = Some(*t);
        }
        Ok(Self {
            station_id: parts.station_id,
            kind: parts.kind,
            primary: parts.primary,
            spare: parts.spare,
            boxes,
            box_count: u8::try_from(parts.boxes.len()).map_err(|_| bad)?,
            id_terminals_hash: parts.id_terminals_hash,
            tokens,
            token_count: u8::try_from(parts.tokens.len()).map_err(|_| bad)?,
        })
    }

    /// The station.
    #[must_use]
    pub const fn station_id(&self) -> StationId<'a> {
        self.station_id
    }

    /// Its kind.
    #[must_use]
    pub const fn kind(&self) -> StationKind {
        self.kind
    }

    /// The check-in unit in service.
    #[must_use]
    pub const fn primary(&self) -> &CheckinUnit<'a> {
        &self.primary
    }

    /// The sealed spare unit.
    #[must_use]
    pub const fn spare(&self) -> &CheckinUnit<'a> {
        &self.spare
    }

    /// Every box at the station, ascending.
    pub fn boxes(&self) -> impl Iterator<Item = BoxId<'a>> + '_ {
        self.boxes
            .iter()
            .take(usize::from(self.box_count))
            .flatten()
            .copied()
    }

    /// Hash of the identity-terminal list.
    #[must_use]
    pub const fn id_terminals_hash(&self) -> &Hash512 {
        &self.id_terminals_hash
    }

    /// The observer tokens, ascending by observer.
    pub fn tokens(&self) -> impl Iterator<Item = ObserverToken<'a>> + '_ {
        self.tokens
            .iter()
            .take(usize::from(self.token_count))
            .flatten()
            .copied()
    }
}

impl Encode for StationEntry<'_> {
    fn encoded_len(&self) -> usize {
        let boxes = self
            .boxes()
            .fold(4usize, |acc, b| acc.saturating_add(b.encoded_len()));
        let tokens = self.tokens().fold(4usize, |acc, t| {
            acc.saturating_add(t.observer_id.encoded_len())
                .saturating_add(t.org_id.encoded_len())
                .saturating_add(TOKEN_CHECK_KEY_LEN)
        });
        self.station_id
            .encoded_len()
            .saturating_add(1)
            .saturating_add(self.primary.len())
            .saturating_add(self.spare.len())
            .saturating_add(boxes)
            .saturating_add(64)
            .saturating_add(tokens)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.station_id.encode(w)?;
        w.write_u8(self.kind.code())?;
        self.primary.write(w)?;
        self.spare.write(w)?;
        w.write_count(usize::from(self.box_count), MAX_STATION_BOXES)?;
        for b in self.boxes() {
            b.encode(w)?;
        }
        self.id_terminals_hash.encode(w)?;
        w.write_count(usize::from(self.token_count), MAX_OBSERVER_TOKENS)?;
        for t in self.tokens() {
            t.observer_id.encode(w)?;
            t.org_id.encode(w)?;
            w.write_array(t.check_key)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for StationEntry<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let station_id = StationId::decode(r)?;
        let kind = read_code(r, StationKind::from_code)?;
        let primary = CheckinUnit::read(r)?;
        let spare_at = r.position();
        let spare = CheckinUnit::read(r)?;
        if !units_valid(&primary, &spare) {
            return Err(Error::new(Kind::InvariantViolation, spare_at));
        }
        let boxes_at = r.position();
        let box_count = r.read_count(MAX_STATION_BOXES)?;
        if box_count == 0 {
            return Err(Error::new(Kind::InvariantViolation, boxes_at));
        }
        let mut boxes = [None; MAX_STATION_BOXES];
        let mut previous: Option<&[u8]> = None;
        for slot in boxes.iter_mut().take(box_count) {
            let at = r.position();
            let b = BoxId::decode(r)?;
            Reader::check_ascending(previous, b.as_bytes(), at)?;
            previous = Some(b.as_bytes());
            *slot = Some(b);
        }
        let id_terminals_hash = Hash512::decode(r)?;
        let tokens_at = r.position();
        let token_count = r.read_count(MAX_OBSERVER_TOKENS)?;
        let mut tokens = [None; MAX_OBSERVER_TOKENS];
        let mut previous: Option<&[u8]> = None;
        for slot in tokens.iter_mut().take(token_count) {
            let at = r.position();
            let observer_id = SignerId::decode(r)?;
            Reader::check_ascending(previous, observer_id.as_bytes(), at)?;
            previous = Some(observer_id.as_bytes());
            *slot = Some(ObserverToken {
                observer_id,
                org_id: OrgId::decode(r)?,
                check_key: read_fixed::<TOKEN_CHECK_KEY_LEN>(r)?,
            });
        }
        Ok(Self {
            station_id,
            kind,
            primary,
            spare,
            boxes,
            box_count: u8::try_from(box_count)
                .map_err(|_| Error::new(Kind::CountExceedsMax, boxes_at))?,
            id_terminals_hash,
            tokens,
            token_count: u8::try_from(token_count)
                .map_err(|_| Error::new(Kind::CountExceedsMax, tokens_at))?,
        })
    }
}

impl<'a> GenesisEntry<'a> for StationEntry<'a> {
    const SET: EntrySet = EntrySet::Stations;

    fn key(&self) -> &'a [u8] {
        self.station_id.as_bytes()
    }
}

/// A station's progress-alarm policy (`progress_policies[]`, schema
/// `0x0037`, ENCODING.md §8.48, ADR-0027).
///
/// Rules: `booth_count ≥ 1` and `limit_sheets ≥ 1` (`ValueOutOfRange`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StationProgressPolicy<'a> {
    station_id: StationId<'a>,
    booth_count: u16,
    limit_sheets: u32,
}

impl<'a> StationProgressPolicy<'a> {
    /// Builds a policy.
    ///
    /// # Errors
    /// `ValueOutOfRange` at 0 if a count is zero.
    pub const fn new(
        station_id: StationId<'a>,
        booth_count: u16,
        limit_sheets: u32,
    ) -> Result<Self, Error> {
        if booth_count == 0 || limit_sheets == 0 {
            return Err(Error::new(Kind::ValueOutOfRange, 0));
        }
        Ok(Self {
            station_id,
            booth_count,
            limit_sheets,
        })
    }

    /// The station.
    #[must_use]
    pub const fn station_id(&self) -> StationId<'a> {
        self.station_id
    }

    /// Booths at the station.
    #[must_use]
    pub const fn booth_count(&self) -> u16 {
        self.booth_count
    }

    /// The alarm limit `L` in sheets.
    #[must_use]
    pub const fn limit_sheets(&self) -> u32 {
        self.limit_sheets
    }
}

impl Encode for StationProgressPolicy<'_> {
    fn encoded_len(&self) -> usize {
        self.station_id.encoded_len().saturating_add(6)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.station_id.encode(w)?;
        w.write_u16(self.booth_count)?;
        w.write_u32(self.limit_sheets)
    }
}

impl<'a> Decode<'a> for StationProgressPolicy<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let station_id = StationId::decode(r)?;
        let booth_at = r.position();
        let booth_count = r.read_u16()?;
        if booth_count == 0 {
            return Err(Error::new(Kind::ValueOutOfRange, booth_at));
        }
        let limit_at = r.position();
        let limit_sheets = r.read_u32()?;
        if limit_sheets == 0 {
            return Err(Error::new(Kind::ValueOutOfRange, limit_at));
        }
        Ok(Self {
            station_id,
            booth_count,
            limit_sheets,
        })
    }
}

impl<'a> GenesisEntry<'a> for StationProgressPolicy<'a> {
    const SET: EntrySet = EntrySet::ProgressPolicies;

    fn key(&self) -> &'a [u8] {
        self.station_id.as_bytes()
    }
}

/// One reporting unit (`reporting_units[]`, schema `0x0038`): the unit in
/// which paper results are published by law. Each box names its unit
/// ([`GenesisBox::reporting_unit_id`]); the unit states how many boxes
/// name it, so a verifier holding the box set sees a box moved between
/// units.
///
/// Rule: `box_count ≥ 1` (`ValueOutOfRange`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReportingUnitEntry<'a> {
    unit_id: ReportingUnitId<'a>,
    box_count: u32,
}

impl<'a> ReportingUnitEntry<'a> {
    /// Builds an entry.
    ///
    /// # Errors
    /// `ValueOutOfRange` at 0 for no boxes.
    pub const fn new(unit_id: ReportingUnitId<'a>, box_count: u32) -> Result<Self, Error> {
        if box_count == 0 {
            return Err(Error::new(Kind::ValueOutOfRange, 0));
        }
        Ok(Self { unit_id, box_count })
    }

    /// The unit.
    #[must_use]
    pub const fn unit_id(&self) -> ReportingUnitId<'a> {
        self.unit_id
    }

    /// Number of boxes in the unit.
    #[must_use]
    pub const fn box_count(&self) -> u32 {
        self.box_count
    }
}

impl Encode for ReportingUnitEntry<'_> {
    fn encoded_len(&self) -> usize {
        self.unit_id.encoded_len().saturating_add(4)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.unit_id.encode(w)?;
        w.write_u32(self.box_count)
    }
}

impl<'a> Decode<'a> for ReportingUnitEntry<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let unit_id = ReportingUnitId::decode(r)?;
        let at = r.position();
        let box_count = r.read_u32()?;
        if box_count == 0 {
            return Err(Error::new(Kind::ValueOutOfRange, at));
        }
        Ok(Self { unit_id, box_count })
    }
}

impl<'a> GenesisEntry<'a> for ReportingUnitEntry<'a> {
    const SET: EntrySet = EntrySet::ReportingUnits;

    fn key(&self) -> &'a [u8] {
        self.unit_id.as_bytes()
    }
}

/// One custody route (`custody_routes[]`, schema `0x0039`): the
/// organisations in order, from the polling station to the counting
/// centre.
///
/// Rules: two to eight stops (`CountExceedsMax`, `InvariantViolation`),
/// adjacent stops differ (`InvariantViolation`, VC-040).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CustodyRoute<'a> {
    route_id: RouteId<'a>,
    count_at_origin: bool,
    stops: [Option<OrgId<'a>>; MAX_ROUTE_STOPS],
    count: u8,
}

fn stops_valid(stops: &[OrgId<'_>]) -> bool {
    stops.len() >= MIN_ROUTE_STOPS
        && stops.len() <= MAX_ROUTE_STOPS
        && stops.windows(2).all(|pair| match pair {
            [a, b] => a.as_bytes() != b.as_bytes(),
            _ => true,
        })
}

impl<'a> CustodyRoute<'a> {
    /// Builds a route.
    ///
    /// # Errors
    /// `InvariantViolation` at 0 if the stops break a rule.
    pub fn new(
        route_id: RouteId<'a>,
        count_at_origin: bool,
        stops: &[OrgId<'a>],
    ) -> Result<Self, Error> {
        if !stops_valid(stops) {
            return Err(Error::new(Kind::InvariantViolation, 0));
        }
        let mut slots = [None; MAX_ROUTE_STOPS];
        for (slot, s) in slots.iter_mut().zip(stops) {
            *slot = Some(*s);
        }
        Ok(Self {
            route_id,
            count_at_origin,
            stops: slots,
            count: u8::try_from(stops.len())
                .map_err(|_| Error::new(Kind::InvariantViolation, 0))?,
        })
    }

    /// The route.
    #[must_use]
    pub const fn route_id(&self) -> RouteId<'a> {
        self.route_id
    }

    /// Whether ballots are counted where they were cast
    /// (`COUNT_AT_ORIGIN`).
    #[must_use]
    pub const fn count_at_origin(&self) -> bool {
        self.count_at_origin
    }

    /// The stops in order.
    pub fn stops(&self) -> impl Iterator<Item = OrgId<'a>> + '_ {
        self.stops
            .iter()
            .take(usize::from(self.count))
            .flatten()
            .copied()
    }

    /// Number of stops (two to eight).
    #[must_use]
    pub fn stop_count(&self) -> usize {
        usize::from(self.count)
    }

    /// The stop at `index`, or `None` past the last stop.
    #[must_use]
    pub fn stop(&self, index: usize) -> Option<OrgId<'a>> {
        // Slots past the last stop are `None` by construction.
        self.stops.get(index).copied().flatten()
    }
}

impl Encode for CustodyRoute<'_> {
    fn encoded_len(&self) -> usize {
        self.stops().fold(
            self.route_id
                .encoded_len()
                .saturating_add(1)
                .saturating_add(4),
            |acc, s| acc.saturating_add(s.encoded_len()),
        )
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.route_id.encode(w)?;
        w.write_bool(self.count_at_origin)?;
        w.write_count(self.stop_count(), MAX_ROUTE_STOPS)?;
        for s in self.stops() {
            s.encode(w)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for CustodyRoute<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let route_id = RouteId::decode(r)?;
        let count_at_origin = r.read_bool()?;
        let count_at = r.position();
        let count = r.read_count(MAX_ROUTE_STOPS)?;
        let mut stops = [None; MAX_ROUTE_STOPS];
        let mut previous: Option<&[u8]> = None;
        for slot in stops.iter_mut().take(count) {
            let at = r.position();
            let stop = OrgId::decode(r)?;
            if previous == Some(stop.as_bytes()) {
                return Err(Error::new(Kind::InvariantViolation, at));
            }
            previous = Some(stop.as_bytes());
            *slot = Some(stop);
        }
        if count < MIN_ROUTE_STOPS {
            return Err(Error::new(Kind::InvariantViolation, count_at));
        }
        Ok(Self {
            route_id,
            count_at_origin,
            stops,
            count: u8::try_from(count).map_err(|_| Error::new(Kind::CountExceedsMax, count_at))?,
        })
    }
}

impl<'a> GenesisEntry<'a> for CustodyRoute<'a> {
    const SET: EntrySet = EntrySet::Routes;

    fn key(&self) -> &'a [u8] {
        self.route_id.as_bytes()
    }
}

/// One person on the roster (schema `0x003A`): who may sign box events,
/// custody handoffs or legal decisions, in which role, for which
/// organisation, with which key.
///
/// Rule: `appointment_hash` is nonzero (`InvalidPreviousHash`, VC-009).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RosterSigner<'a> {
    /// The person.
    pub signer_id: SignerId<'a>,
    /// The registered role.
    pub role: RosterRole,
    /// The registered organisation.
    pub org_id: OrgId<'a>,
    /// The station the person serves (clerks and observers), or `None`
    /// (custodians, counting-centre staff, legal authorities).
    pub station_id: Option<StationId<'a>>,
    /// The person's hybrid verifying key.
    pub key: &'a [u8; HYBRID_VK_LEN],
    /// Hash of the `Appointment` event (PROTOCOL.md §4.5).
    pub appointment_hash: Hash512,
}

impl Encode for RosterSigner<'_> {
    fn encoded_len(&self) -> usize {
        let station = self
            .station_id
            .map_or(1, |s| s.encoded_len().saturating_add(1));
        self.signer_id
            .encoded_len()
            .saturating_add(1)
            .saturating_add(self.org_id.encoded_len())
            .saturating_add(station)
            .saturating_add(HYBRID_VK_LEN)
            .saturating_add(64)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.signer_id.encode(w)?;
        w.write_u8(self.role.code())?;
        self.org_id.encode(w)?;
        match &self.station_id {
            None => w.write_presence(false)?,
            Some(s) => {
                w.write_presence(true)?;
                s.encode(w)?;
            }
        }
        w.write_array(self.key)?;
        self.appointment_hash.encode(w)
    }
}

impl<'a> Decode<'a> for RosterSigner<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let signer_id = SignerId::decode(r)?;
        let role = read_code(r, RosterRole::from_code)?;
        let org_id = OrgId::decode(r)?;
        let station_id = if r.read_presence()? {
            Some(StationId::decode(r)?)
        } else {
            None
        };
        Ok(Self {
            signer_id,
            role,
            org_id,
            station_id,
            key: read_fixed::<HYBRID_VK_LEN>(r)?,
            appointment_hash: read_nonzero_hash(r)?,
        })
    }
}

impl<'a> GenesisEntry<'a> for RosterSigner<'a> {
    const SET: EntrySet = EntrySet::Roster;

    fn key(&self) -> &'a [u8] {
        self.signer_id.as_bytes()
    }
}

/// One chamber module (schema `0x003B`): the keys of a module that a box
/// or a check-in unit names (PROTOCOL.md §3.2, §9.4.2).
///
/// Rules: the chamber is not `N`, which has no module (`ValueOutOfRange`);
/// `provisioned_hash` is nonzero (`InvalidPreviousHash`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModuleEntry<'a> {
    /// The module.
    pub module_id: ModuleId<'a>,
    /// Its chamber.
    pub chamber: ChamberCode,
    /// Its hybrid verifying key (batch signatures; the Ed25519 half signs
    /// cast records).
    pub key: &'a [u8; HYBRID_VK_LEN],
    /// Its attestation key (PROTOCOL.md §7.9).
    pub attest_key: &'a [u8; HYBRID_VK_LEN],
    /// Hash of its `ModuleProvisioned` event (ENCODING.md §8.31).
    pub provisioned_hash: Hash512,
}

const fn module_chamber(code: u8) -> Option<ChamberCode> {
    match ChamberCode::from_code(code) {
        Some(ChamberCode::N) | None => None,
        Some(chamber) => Some(chamber),
    }
}

impl Encode for ModuleEntry<'_> {
    fn encoded_len(&self) -> usize {
        self.module_id
            .encoded_len()
            .saturating_add(1)
            .saturating_add(HYBRID_VK_LEN)
            .saturating_add(HYBRID_VK_LEN)
            .saturating_add(64)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.module_id.encode(w)?;
        w.write_u8(self.chamber.code())?;
        w.write_array(self.key)?;
        w.write_array(self.attest_key)?;
        self.provisioned_hash.encode(w)
    }
}

impl<'a> Decode<'a> for ModuleEntry<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            module_id: ModuleId::decode(r)?,
            chamber: read_code(r, module_chamber)?,
            key: read_fixed::<HYBRID_VK_LEN>(r)?,
            attest_key: read_fixed::<HYBRID_VK_LEN>(r)?,
            provisioned_hash: read_nonzero_hash(r)?,
        })
    }
}

impl<'a> GenesisEntry<'a> for ModuleEntry<'a> {
    const SET: EntrySet = EntrySet::Modules;

    fn key(&self) -> &'a [u8] {
        self.module_id.as_bytes()
    }
}

/// The number of commitment chunks for `choices` choices,
/// `k = ⌈(m + 2)/9⌉` (PROTOCOL.md §7.4).
#[must_use]
pub const fn chunks_for(choices: u16) -> u32 {
    (choices as u32).saturating_add(10) / 9
}

/// One ballot style (`ballot_styles[]`, schema `0x003C`).
///
/// Rules: at least one choice and at most eight chunks
/// (`ValueOutOfRange`); `chunks` is `⌈(choices + 2)/9⌉`
/// (`InvariantViolation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BallotStyleEntry<'a> {
    ballot_style_id: BallotStyleId<'a>,
    choices: u16,
    chunks: u8,
    layout_hash: Hash512,
}

/// [`MAX_CHUNKS`] as the type of [`chunks_for`].
const MAX_STYLE_CHUNKS: u32 = 8;

const _: () = assert!(MAX_STYLE_CHUNKS as usize == MAX_CHUNKS);

const fn choices_valid(choices: u16) -> bool {
    choices >= 1 && chunks_for(choices) <= MAX_STYLE_CHUNKS
}

impl<'a> BallotStyleEntry<'a> {
    /// Builds an entry; the chunk count follows from `choices`.
    ///
    /// # Errors
    /// `ValueOutOfRange` at 0 for no choices or more than eight chunks.
    pub fn new(
        ballot_style_id: BallotStyleId<'a>,
        choices: u16,
        layout_hash: Hash512,
    ) -> Result<Self, Error> {
        let bad = Error::new(Kind::ValueOutOfRange, 0);
        if !choices_valid(choices) {
            return Err(bad);
        }
        Ok(Self {
            ballot_style_id,
            choices,
            chunks: u8::try_from(chunks_for(choices)).map_err(|_| bad)?,
            layout_hash,
        })
    }

    /// The ballot style.
    #[must_use]
    pub const fn ballot_style_id(&self) -> BallotStyleId<'a> {
        self.ballot_style_id
    }

    /// Number of choices `m`.
    #[must_use]
    pub const fn choices(&self) -> u16 {
        self.choices
    }

    /// Number of commitment chunks `k`.
    #[must_use]
    pub const fn chunks(&self) -> u8 {
        self.chunks
    }

    /// Hash of the layout document (`BALLOT_LAYOUT.md` §2, §3).
    #[must_use]
    pub const fn layout_hash(&self) -> &Hash512 {
        &self.layout_hash
    }
}

impl Encode for BallotStyleEntry<'_> {
    fn encoded_len(&self) -> usize {
        self.ballot_style_id.encoded_len().saturating_add(3 + 64)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.ballot_style_id.encode(w)?;
        w.write_u16(self.choices)?;
        w.write_u8(self.chunks)?;
        self.layout_hash.encode(w)
    }
}

impl<'a> Decode<'a> for BallotStyleEntry<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let ballot_style_id = BallotStyleId::decode(r)?;
        let choices_at = r.position();
        let choices = r.read_u16()?;
        if !choices_valid(choices) {
            return Err(Error::new(Kind::ValueOutOfRange, choices_at));
        }
        let chunks_at = r.position();
        let chunks = r.read_u8()?;
        if u32::from(chunks) != chunks_for(choices) {
            return Err(Error::new(Kind::InvariantViolation, chunks_at));
        }
        Ok(Self {
            ballot_style_id,
            choices,
            chunks,
            layout_hash: Hash512::decode(r)?,
        })
    }
}

impl<'a> GenesisEntry<'a> for BallotStyleEntry<'a> {
    const SET: EntrySet = EntrySet::BallotStyles;

    fn key(&self) -> &'a [u8] {
        self.ballot_style_id.as_bytes()
    }
}

/// One trustee member (`trustee_roster`, schema `0x003D`). The chamber
/// thresholds `k_c`, `n_c` are in the genesis body.
///
/// Rule: `appointment_hash` is nonzero (`InvalidPreviousHash`, VC-009).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrusteeEntry<'a> {
    /// The member.
    pub trustee_id: TrusteeId<'a>,
    /// The chamber.
    pub chamber: ChamberCode,
    /// The member's organisation.
    pub org_id: OrgId<'a>,
    /// The member's hybrid verifying key.
    pub key: &'a [u8; HYBRID_VK_LEN],
    /// Hash of the `Appointment` event.
    pub appointment_hash: Hash512,
}

impl Encode for TrusteeEntry<'_> {
    fn encoded_len(&self) -> usize {
        self.trustee_id
            .encoded_len()
            .saturating_add(1)
            .saturating_add(self.org_id.encoded_len())
            .saturating_add(HYBRID_VK_LEN)
            .saturating_add(64)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.trustee_id.encode(w)?;
        w.write_u8(self.chamber.code())?;
        self.org_id.encode(w)?;
        w.write_array(self.key)?;
        self.appointment_hash.encode(w)
    }
}

impl<'a> Decode<'a> for TrusteeEntry<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            trustee_id: TrusteeId::decode(r)?,
            chamber: read_code(r, ChamberCode::from_code)?,
            org_id: OrgId::decode(r)?,
            key: read_fixed::<HYBRID_VK_LEN>(r)?,
            appointment_hash: read_nonzero_hash(r)?,
        })
    }
}

impl<'a> GenesisEntry<'a> for TrusteeEntry<'a> {
    const SET: EntrySet = EntrySet::Trustees;

    fn key(&self) -> &'a [u8] {
        self.trustee_id.as_bytes()
    }
}

/// One witness (`witness_roster`, schema `0x003E`): the quorum and
/// diversity rules of PROTOCOL.md §5.4 count organisations, providers and
/// regions over these entries.
///
/// Rule: `appointment_hash` is nonzero (`InvalidPreviousHash`, VC-009).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WitnessRosterEntry<'a> {
    /// The witness.
    pub witness_id: Ident<'a>,
    /// Its organisation.
    pub org_id: OrgId<'a>,
    /// Its infrastructure provider.
    pub provider: Ident<'a>,
    /// Its region.
    pub region: Ident<'a>,
    /// Its hybrid verifying key (purposes `checkpoint`, `genesis`,
    /// `genesis-amendment`).
    pub key: &'a [u8; HYBRID_VK_LEN],
    /// Hash of the `Appointment` event.
    pub appointment_hash: Hash512,
}

impl Encode for WitnessRosterEntry<'_> {
    fn encoded_len(&self) -> usize {
        ident_len(&self.witness_id)
            .saturating_add(self.org_id.encoded_len())
            .saturating_add(ident_len(&self.provider))
            .saturating_add(ident_len(&self.region))
            .saturating_add(HYBRID_VK_LEN)
            .saturating_add(64)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_ident(&self.witness_id, IDENT_MAX_STANDARD)?;
        self.org_id.encode(w)?;
        w.write_ident(&self.provider, IDENT_MAX_STANDARD)?;
        w.write_ident(&self.region, IDENT_MAX_STANDARD)?;
        w.write_array(self.key)?;
        self.appointment_hash.encode(w)
    }
}

impl<'a> Decode<'a> for WitnessRosterEntry<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            witness_id: r.read_ident(IDENT_MAX_STANDARD)?,
            org_id: OrgId::decode(r)?,
            provider: r.read_ident(IDENT_MAX_STANDARD)?,
            region: r.read_ident(IDENT_MAX_STANDARD)?,
            key: read_fixed::<HYBRID_VK_LEN>(r)?,
            appointment_hash: read_nonzero_hash(r)?,
        })
    }
}

impl<'a> GenesisEntry<'a> for WitnessRosterEntry<'a> {
    const SET: EntrySet = EntrySet::Witnesses;

    fn key(&self) -> &'a [u8] {
        self.witness_id.as_bytes()
    }
}
