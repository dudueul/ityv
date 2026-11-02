//! Witnessed station events of the check-in side (ADR-0028; PROTOCOL.md
//! §6.2, §6.3, §7.10; ENCODING.md §8.57–§8.59): the observers' attestation
//! of the check-in count (`ObserverCountAttestBody`, `0x003F`), and the
//! on-site records of a device swap that the progress streams continue
//! from (`CheckinUnitSwapBody`, `0x0040`; `BoxUnitSwapBody`, `0x0041`).
//! All three are signed through `WitnessedEvent` (`0x0028`).

use crate::codec::{Decode, Encode};
use crate::error::{Error, Kind};
use crate::primitives::{BoxId, ElectionId, StationId, TimeBucket, UnitId};
use crate::reader::Reader;
use crate::writer::Writer;

fn invalid(at: usize) -> Error {
    Error::new(Kind::InvariantViolation, at)
}

// ---------------------------------------------------------------------------
// 0x003F ObserverCountAttestBody

/// Whether an observer count is a running one or the final one at close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ObserverCountKind {
    /// Every fifty check-ins or two hours, whichever comes first.
    Periodic = 1,
    /// At close: the station's check-in total.
    Final = 2,
}

impl ObserverCountKind {
    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Returns the kind with wire code `code`, if defined.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Periodic),
            2 => Some(Self::Final),
            _ => None,
        }
    }
}

/// The fields of an observer count attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObserverCountParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The station.
    pub station_id: StationId<'a>,
    /// The check-in unit whose counter the observers read.
    pub unit_id: UnitId<'a>,
    /// The station's check-ins so far (the last sequence number).
    pub count: u64,
    /// Periodic or final.
    pub kind: ObserverCountKind,
    /// When.
    pub time_bucket: TimeBucket,
}

/// An observer count attestation body (schema `0x003F`, PROTOCOL.md §6.3).
///
/// Rule: the kind code is 1 or 2 (`ValueOutOfRange`). Signed by observers
/// only, two or more of two or more organisations (VC-016).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObserverCountAttestBody<'a> {
    parts: ObserverCountParts<'a>,
}

impl<'a> ObserverCountAttestBody<'a> {
    /// Builds the body.
    #[must_use]
    pub const fn new(parts: &ObserverCountParts<'a>) -> Self {
        Self { parts: *parts }
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &ObserverCountParts<'a> {
        &self.parts
    }
}

impl Encode for ObserverCountAttestBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.station_id.encoded_len())
            .saturating_add(p.unit_id.encoded_len())
            .saturating_add(8 + 1 + 8)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.station_id.encode(w)?;
        p.unit_id.encode(w)?;
        w.write_u64(p.count)?;
        w.write_u8(p.kind.code())?;
        p.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for ObserverCountAttestBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let station_id = StationId::decode(r)?;
        let unit_id = UnitId::decode(r)?;
        let count = r.read_u64()?;
        let kind_at = r.position();
        let kind = ObserverCountKind::from_code(r.read_u8()?)
            .ok_or_else(|| Error::new(Kind::ValueOutOfRange, kind_at))?;
        Ok(Self {
            parts: ObserverCountParts {
                election_id,
                station_id,
                unit_id,
                count,
                kind,
                time_bucket: TimeBucket::decode(r)?,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// 0x0040 CheckinUnitSwapBody

/// The fields of a check-in unit swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckinUnitSwapParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The station.
    pub station_id: StationId<'a>,
    /// The failed unit.
    pub failed_unit: UnitId<'a>,
    /// The spare unit that takes over.
    pub spare_unit: UnitId<'a>,
    /// The progress slot from which the spare reports.
    pub at_slot: u64,
    /// Whether the signers read the failed unit's last counts (on its
    /// screen or from its journal). If not, the counts below are zero and
    /// the station's progress record and participation identity hold
    /// (PROTOCOL.md §6.2, §7.10 item 8).
    pub confirmed: bool,
    /// The sequence number the spare starts from (one more than the
    /// failed unit's last; the check-ins so far are `next_seq − 1`).
    pub next_seq: u64,
    /// Sheets issued so far.
    pub issued: u64,
    /// Spoiled sheets taken back so far.
    pub spoiled: u64,
    /// Unused sheets returned so far.
    pub returned: u64,
}

impl CheckinUnitSwapParts<'_> {
    /// Whether the fields are consistent: two different units, `next_seq ≥
    /// 1`, and zero counts when unconfirmed.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        let zero = self.issued == 0 && self.spoiled == 0 && self.returned == 0;
        self.failed_unit.as_bytes() != self.spare_unit.as_bytes()
            && self.next_seq >= 1
            && (self.confirmed || zero)
    }

    /// The counts the spare continues from, in the progress order
    /// `[checkins, issued, spoiled, returned]`.
    #[must_use]
    pub const fn counts(&self) -> [u64; 4] {
        [
            self.next_seq.saturating_sub(1),
            self.issued,
            self.spoiled,
            self.returned,
        ]
    }
}

/// A check-in unit swap body (schema `0x0040`, PROTOCOL.md §6.2).
///
/// Rule: [`CheckinUnitSwapParts::is_valid`] (`InvariantViolation`).
/// Signed by two clerks and observers of two organisations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckinUnitSwapBody<'a> {
    parts: CheckinUnitSwapParts<'a>,
}

impl<'a> CheckinUnitSwapBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// `InvariantViolation` at 0 if the fields are inconsistent.
    pub fn new(parts: &CheckinUnitSwapParts<'a>) -> Result<Self, Error> {
        if parts.is_valid() {
            Ok(Self { parts: *parts })
        } else {
            Err(invalid(0))
        }
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &CheckinUnitSwapParts<'a> {
        &self.parts
    }
}

impl Encode for CheckinUnitSwapBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.station_id.encoded_len())
            .saturating_add(p.failed_unit.encoded_len())
            .saturating_add(p.spare_unit.encoded_len())
            .saturating_add(8 + 1 + 8 * 4)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.station_id.encode(w)?;
        p.failed_unit.encode(w)?;
        p.spare_unit.encode(w)?;
        w.write_u64(p.at_slot)?;
        w.write_bool(p.confirmed)?;
        w.write_u64(p.next_seq)?;
        w.write_u64(p.issued)?;
        w.write_u64(p.spoiled)?;
        w.write_u64(p.returned)
    }
}

impl<'a> Decode<'a> for CheckinUnitSwapBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let station_id = StationId::decode(r)?;
        let failed_unit = UnitId::decode(r)?;
        let spare_at = r.position();
        let spare_unit = UnitId::decode(r)?;
        if failed_unit.as_bytes() == spare_unit.as_bytes() {
            return Err(invalid(spare_at));
        }
        let at_slot = r.read_u64()?;
        let confirmed = r.read_bool()?;
        let seq_at = r.position();
        let next_seq = r.read_u64()?;
        if next_seq == 0 {
            return Err(Error::new(Kind::ValueOutOfRange, seq_at));
        }
        let counts_at = r.position();
        let parts = CheckinUnitSwapParts {
            election_id,
            station_id,
            failed_unit,
            spare_unit,
            at_slot,
            confirmed,
            next_seq,
            issued: r.read_u64()?,
            spoiled: r.read_u64()?,
            returned: r.read_u64()?,
        };
        if parts.is_valid() {
            Ok(Self { parts })
        } else {
            Err(invalid(counts_at))
        }
    }
}

// ---------------------------------------------------------------------------
// 0x0041 BoxUnitSwapBody

/// The fields of a commitment-unit swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoxUnitSwapParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The box.
    pub box_id: BoxId<'a>,
    /// The progress slot from which the spare reports.
    pub at_slot: u64,
    /// Whether the signers read the failed unit's last `sheets_in`. If
    /// not, `sheets_in` is zero and the box's progress record holds.
    pub confirmed: bool,
    /// Sheets in the box so far.
    pub sheets_in: u64,
}

impl BoxUnitSwapParts<'_> {
    /// Whether the fields are consistent: zero sheets when unconfirmed.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.confirmed || self.sheets_in == 0
    }
}

/// A commitment-unit swap body (schema `0x0041`, PROTOCOL.md §7.10 item
/// 8). The spare's key is registered by a `GenesisAmendment` (§4.3); this
/// event records, on site, the count the spare continues from.
///
/// Rule: [`BoxUnitSwapParts::is_valid`] (`InvariantViolation`). Signed by
/// two clerks and observers of two organisations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoxUnitSwapBody<'a> {
    parts: BoxUnitSwapParts<'a>,
}

impl<'a> BoxUnitSwapBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// `InvariantViolation` at 0 if the fields are inconsistent.
    pub const fn new(parts: &BoxUnitSwapParts<'a>) -> Result<Self, Error> {
        if parts.is_valid() {
            Ok(Self { parts: *parts })
        } else {
            Err(Error::new(Kind::InvariantViolation, 0))
        }
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &BoxUnitSwapParts<'a> {
        &self.parts
    }
}

impl Encode for BoxUnitSwapBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.box_id.encoded_len())
            .saturating_add(8 + 1 + 8)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.box_id.encode(w)?;
        w.write_u64(p.at_slot)?;
        w.write_bool(p.confirmed)?;
        w.write_u64(p.sheets_in)
    }
}

impl<'a> Decode<'a> for BoxUnitSwapBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let box_id = BoxId::decode(r)?;
        let at_slot = r.read_u64()?;
        let confirmed = r.read_bool()?;
        let sheets_at = r.position();
        let parts = BoxUnitSwapParts {
            election_id,
            box_id,
            at_slot,
            confirmed,
            sheets_in: r.read_u64()?,
        };
        if parts.is_valid() {
            Ok(Self { parts })
        } else {
            Err(invalid(sheets_at))
        }
    }
}
