//! Field types of the genesis (`Genesis`, schema `0x0002`, PROTOCOL.md
//! §4.1; ENCODING.md §8.43, §8.48) that `ityv-state` needs: the expected
//! boxes, the custody routes, the roster of people who sign box events
//! and the stations' progress-alarm limits.
//!
//! These are not objects of their own: they appear inside the genesis
//! body, which pins them by its hash. The genesis object as a whole is a
//! later M5 task; these types fix the canonical encoding of its entries
//! now so that the state machines take the genesis's own bytes.

use crate::codec::{Decode, Encode};
use crate::error::{Error, Kind};
use crate::primitives::{BallotStyleId, BoxId, Hash512, OrgId, RouteId, SignerId, StationId};
use crate::reader::Reader;
use crate::schema::util::{HYBRID_VK_LEN, ModuleIds, read_fixed};
use crate::writer::Writer;

/// Maximum number of organisations on one custody route.
pub const MAX_ROUTE_STOPS: usize = 8;

/// Minimum number of organisations on one custody route.
pub const MIN_ROUTE_STOPS: usize = 2;

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
            _ => None,
        }
    }
}

fn read_code<T>(r: &mut Reader<'_>, from: impl Fn(u8) -> Option<T>) -> Result<T, Error> {
    let at = r.position();
    from(r.read_u8()?).ok_or_else(|| Error::new(Kind::ValueOutOfRange, at))
}

/// One expected box (`expected_boxes[]`).
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
    /// The commitment unit's hybrid verifying key.
    pub device_key: &'a [u8; HYBRID_VK_LEN],
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
            .saturating_add(HYBRID_VK_LEN)
            .saturating_add(self.modules.encoded_len())
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.box_id.encode(w)?;
        self.station_id.encode(w)?;
        self.ballot_style_id.encode(w)?;
        w.write_u8(self.profile.code())?;
        self.route_id.encode(w)?;
        w.write_array(self.device_key)?;
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
            device_key: read_fixed::<HYBRID_VK_LEN>(r)?,
            modules: ModuleIds::decode(r)?,
        })
    }
}

/// One custody route (`custody_routes[]`): the organisations in order,
/// from the polling station to the counting centre.
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

/// One person on the roster: who may sign box events, in which role, for
/// which organisation, with which key.
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
    /// (custodians, counting-centre staff).
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
        let key = read_fixed::<HYBRID_VK_LEN>(r)?;
        let at = r.position();
        let appointment_hash = Hash512::decode(r)?;
        if appointment_hash.is_zero() {
            return Err(Error::new(Kind::InvalidPreviousHash, at));
        }
        Ok(Self {
            signer_id,
            role,
            org_id,
            station_id,
            key,
            appointment_hash,
        })
    }
}

/// A station's progress-alarm policy (`progress_policies[]`, ENCODING.md
/// §8.48, ADR-0027).
///
/// Rules: `booth_count ≥ 1` and `limit_sheets ≥ 1` (`ValueOutOfRange`).
/// The genesis lists the policies by `station_id` in ascending order
/// without duplicates; the genesis decoder checks that order.
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
