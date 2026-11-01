//! The voting progress record (ADR-0027; PROTOCOL.md §7.10; ENCODING.md
//! §8.44–§8.47), version 1.
//!
//! | schema | object | signed by | purpose |
//! |---|---|---|---|
//! | `0x002F` | [`BoxProgressBody`] | the box's commitment unit | `box-progress` |
//! | `0x0030` | [`CheckinProgressBody`] | the station's check-in unit | `checkin-progress` |
//! | `0x0031` | [`ProgressTick`] | — (carries one body and its signature) | — |
//! | `0x0032` | [`ProgressCheckBody`] | clerks and observers, in a [`crate::WitnessedEvent`] | `progress-check` |
//!
//! The bodies carry cumulative box- or station-level totals and nothing
//! else: no ballot-style breakdown, record hash, pseudonym, order, journal
//! head or time finer than the slot (VC-102). Comparing totals across
//! ticks and evaluating the alarms is `ityv-state`'s job; the rules here
//! are only the ones that make one body malformed.

use crate::codec::{Decode, Encode};
use crate::envelope::{Header, decode as decode_object};
use crate::error::{Error, Kind};
use crate::primitives::{BoxId, ElectionId, Hash512, SchemaId, StationId, TimeBucket, UnitId};
use crate::reader::Reader;
use crate::schema::util::{HYBRID_SIG_LEN, read_fixed};
use crate::schema::{SCHEMA_BOX_PROGRESS_BODY, SCHEMA_CHECKIN_PROGRESS_BODY, SCHEMA_VERSION_1};
use crate::writer::Writer;

/// Maximum length of the body object a [`ProgressTick`] embeds.
pub const MAX_PROGRESS_BODY_LEN: usize = 512;

/// Purpose of a commitment unit's progress signature.
pub const PURPOSE_BOX_PROGRESS: &[u8] = b"box-progress";

/// Purpose of a check-in unit's progress signature.
pub const PURPOSE_CHECKIN_PROGRESS: &[u8] = b"checkin-progress";

fn invalid(at: usize) -> Error {
    Error::new(Kind::InvariantViolation, at)
}

fn read_code<T>(r: &mut Reader<'_>, from: impl Fn(u8) -> Option<T>) -> Result<T, Error> {
    let at = r.position();
    from(r.read_u8()?).ok_or_else(|| Error::new(Kind::ValueOutOfRange, at))
}

macro_rules! progress_enum {
    (
        $(#[$meta:meta])*
        $name:ident { $( $(#[$vmeta:meta])* $variant:ident = $code:literal ),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(u8)]
        pub enum $name {
            $( $(#[$vmeta])* $variant = $code ),+
        }

        impl $name {
            /// Every value in code order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The wire code.
            #[must_use]
            pub const fn code(self) -> u8 {
                self as u8
            }

            /// Returns the value with wire code `code`, if defined.
            #[must_use]
            pub const fn from_code(code: u8) -> Option<Self> {
                match code {
                    $( $code => Some(Self::$variant), )+
                    _ => None,
                }
            }
        }
    };
}

progress_enum! {
    /// The state a commitment unit reports for its box.
    BoxProgressState {
        /// Taking ballots through the scanner.
        Casting = 1,
        /// In fallback casting (`FallbackDeclared` without `FallbackEnded`).
        Fallback = 2,
        /// Closed; the last tick of the box.
        Closed = 3,
    }
}

progress_enum! {
    /// The state a check-in unit reports for its station.
    CheckinProgressState {
        /// Checking voters in.
        Checking = 1,
        /// A spare unit continuing after `CheckinUnitSwap`.
        AfterSwap = 2,
        /// Closed; the last tick of the unit.
        Closed = 3,
    }
}

progress_enum! {
    /// A progress alarm (PROTOCOL.md §7.10 item 4).
    ProgressAlarm {
        /// More sheets entered than were issued (`PROGRESS_NEGATIVE`).
        Negative = 1,
        /// More sheets in hand than the station limit (`PROGRESS_HIGH`).
        High = 2,
        /// Sheets still outside after two quiet slots (`PROGRESS_FLOOR`).
        Floor = 3,
    }
}

progress_enum! {
    /// What the on-site check found (PROTOCOL.md §7.10 item 6).
    ProgressFinding {
        /// The people holding ballots explain the gap.
        Explained = 1,
        /// Sheets were carried out of the station.
        CarriedOut = 2,
        /// A missed reissue or return entry, now entered.
        Corrected = 3,
        /// Not explained.
        Unexplained = 4,
    }
}

// ---------------------------------------------------------------------------
// 0x002F BoxProgressBody

/// The fields of a box progress tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoxProgressParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The box.
    pub box_id: BoxId<'a>,
    /// The 10-minute uplink slot since the election epoch (ADR-0022).
    pub slot: u64,
    /// Sheets that entered the box: records + challenged + quarantined.
    pub sheets_in: u64,
    /// The box state.
    pub state: BoxProgressState,
}

/// A box progress body (schema `0x002F`). Rule: state code in range
/// (`ValueOutOfRange`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoxProgressBody<'a> {
    parts: BoxProgressParts<'a>,
}

impl<'a> BoxProgressBody<'a> {
    /// Builds the body.
    #[must_use]
    pub const fn new(parts: &BoxProgressParts<'a>) -> Self {
        Self { parts: *parts }
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &BoxProgressParts<'a> {
        &self.parts
    }
}

impl Encode for BoxProgressBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.box_id.encoded_len())
            .saturating_add(17)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.box_id.encode(w)?;
        w.write_u64(p.slot)?;
        w.write_u64(p.sheets_in)?;
        w.write_u8(p.state.code())
    }
}

impl<'a> Decode<'a> for BoxProgressBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            parts: BoxProgressParts {
                election_id: ElectionId::decode(r)?,
                box_id: BoxId::decode(r)?,
                slot: r.read_u64()?,
                sheets_in: r.read_u64()?,
                state: read_code(r, BoxProgressState::from_code)?,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// 0x0030 CheckinProgressBody

/// The fields of a check-in progress tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckinProgressParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The station.
    pub station_id: StationId<'a>,
    /// The check-in unit (the spare's identifier after a swap).
    pub unit_id: UnitId<'a>,
    /// The 10-minute uplink slot.
    pub slot: u64,
    /// People checked in.
    pub checkins: u64,
    /// Sheets issued, reissues included.
    pub issued: u64,
    /// Spoiled sheets taken back.
    pub spoiled: u64,
    /// Unused sheets returned.
    pub returned: u64,
    /// The unit state.
    pub state: CheckinProgressState,
}

impl CheckinProgressParts<'_> {
    /// Whether `spoiled + returned ≤ issued` without overflow.
    #[must_use]
    pub const fn sheets_consistent(&self) -> bool {
        match self.spoiled.checked_add(self.returned) {
            Some(back) => back <= self.issued,
            None => false,
        }
    }
}

/// A check-in progress body (schema `0x0030`).
///
/// Rules: `spoiled ≤ issued` and `spoiled + returned ≤ issued`
/// (`InvariantViolation` at the field that breaks it); state code in range
/// (`ValueOutOfRange`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckinProgressBody<'a> {
    parts: CheckinProgressParts<'a>,
}

impl<'a> CheckinProgressBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// `InvariantViolation` at 0 if more sheets came back than were
    /// issued.
    pub const fn new(parts: &CheckinProgressParts<'a>) -> Result<Self, Error> {
        if parts.sheets_consistent() {
            Ok(Self { parts: *parts })
        } else {
            Err(Error::new(Kind::InvariantViolation, 0))
        }
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &CheckinProgressParts<'a> {
        &self.parts
    }
}

impl Encode for CheckinProgressBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.station_id.encoded_len())
            .saturating_add(p.unit_id.encoded_len())
            .saturating_add(41)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.station_id.encode(w)?;
        p.unit_id.encode(w)?;
        w.write_u64(p.slot)?;
        w.write_u64(p.checkins)?;
        w.write_u64(p.issued)?;
        w.write_u64(p.spoiled)?;
        w.write_u64(p.returned)?;
        w.write_u8(p.state.code())
    }
}

impl<'a> Decode<'a> for CheckinProgressBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let station_id = StationId::decode(r)?;
        let unit_id = UnitId::decode(r)?;
        let slot = r.read_u64()?;
        let checkins = r.read_u64()?;
        let issued = r.read_u64()?;
        let spoiled_at = r.position();
        let spoiled = r.read_u64()?;
        if spoiled > issued {
            return Err(invalid(spoiled_at));
        }
        let returned_at = r.position();
        let returned = r.read_u64()?;
        let parts = CheckinProgressParts {
            election_id,
            station_id,
            unit_id,
            slot,
            checkins,
            issued,
            spoiled,
            returned,
            state: CheckinProgressState::Checking,
        };
        if !parts.sheets_consistent() {
            return Err(invalid(returned_at));
        }
        Ok(Self {
            parts: CheckinProgressParts {
                state: read_code(r, CheckinProgressState::from_code)?,
                ..parts
            },
        })
    }
}

// ---------------------------------------------------------------------------
// 0x0031 ProgressTick

/// The body a [`ProgressTick`] carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgressBody<'a> {
    /// A commitment unit's tick.
    Box(BoxProgressBody<'a>),
    /// A check-in unit's tick.
    Checkin(CheckinProgressBody<'a>),
}

impl ProgressBody<'_> {
    /// The signature purpose of this body.
    #[must_use]
    pub const fn purpose(&self) -> &'static [u8] {
        match self {
            Self::Box(_) => PURPOSE_BOX_PROGRESS,
            Self::Checkin(_) => PURPOSE_CHECKIN_PROGRESS,
        }
    }

    /// The slot.
    #[must_use]
    pub const fn slot(&self) -> u64 {
        match self {
            Self::Box(b) => b.parts.slot,
            Self::Checkin(c) => c.parts.slot,
        }
    }
}

/// Decodes `bytes` as a complete progress body of either schema. An inner
/// error is reported at its offset inside `bytes`.
fn progress_body(bytes: &[u8]) -> Result<ProgressBody<'_>, Error> {
    if bytes.len() > MAX_PROGRESS_BODY_LEN {
        return Err(Error::new(Kind::LengthExceedsMax, 0));
    }
    let header = Header::read(&mut Reader::new(bytes))?;
    let schema: SchemaId = header.schema_id();
    if schema == SCHEMA_BOX_PROGRESS_BODY {
        decode_object(schema, SCHEMA_VERSION_1, bytes).map(ProgressBody::Box)
    } else if schema == SCHEMA_CHECKIN_PROGRESS_BODY {
        decode_object(schema, SCHEMA_VERSION_1, bytes).map(ProgressBody::Checkin)
    } else {
        Err(Error::new(Kind::SchemaMismatch, 4))
    }
}

/// One device-signed progress tick (schema `0x0031`): the complete body
/// object bytes and the device's hybrid signature over exactly those
/// bytes with the body's purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProgressTick<'a> {
    body_bytes: &'a [u8],
    body: ProgressBody<'a>,
    sig: &'a [u8; HYBRID_SIG_LEN],
}

impl<'a> ProgressTick<'a> {
    /// Builds a tick from a complete body object and the signature.
    ///
    /// # Errors
    /// `LengthExceedsMax` at 0 if the body is too long, `SchemaMismatch` at
    /// 4 for another body schema, or the body's decoding error.
    pub fn new(body_bytes: &'a [u8], sig: &'a [u8; HYBRID_SIG_LEN]) -> Result<Self, Error> {
        Ok(Self {
            body: progress_body(body_bytes)?,
            body_bytes,
            sig,
        })
    }

    /// The body object bytes (the signed message).
    #[must_use]
    pub const fn body_bytes(&self) -> &'a [u8] {
        self.body_bytes
    }

    /// The decoded body.
    #[must_use]
    pub const fn body(&self) -> &ProgressBody<'a> {
        &self.body
    }

    /// The signature purpose.
    #[must_use]
    pub const fn purpose(&self) -> &'static [u8] {
        self.body.purpose()
    }

    /// The device's hybrid signature.
    #[must_use]
    pub const fn sig(&self) -> &'a [u8; HYBRID_SIG_LEN] {
        self.sig
    }
}

impl Encode for ProgressTick<'_> {
    fn encoded_len(&self) -> usize {
        self.body_bytes
            .len()
            .saturating_add(4)
            .saturating_add(HYBRID_SIG_LEN)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_bytes(self.body_bytes, MAX_PROGRESS_BODY_LEN)?;
        w.write_array(self.sig)
    }
}

impl<'a> Decode<'a> for ProgressTick<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let at = r.position();
        let body_bytes = r.read_bytes(MAX_PROGRESS_BODY_LEN)?;
        let body = progress_body(body_bytes).map_err(|inner| {
            let offset = at
                .checked_add(4)
                .and_then(|p| p.checked_add(inner.offset()))
                .unwrap_or(at);
            Error::new(inner.kind(), offset)
        })?;
        Ok(Self {
            body_bytes,
            body,
            sig: read_fixed::<HYBRID_SIG_LEN>(r)?,
        })
    }
}

// ---------------------------------------------------------------------------
// 0x0032 ProgressCheckBody

/// The fields of an on-site check after a progress alarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProgressCheckParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The station.
    pub station_id: StationId<'a>,
    /// The slot in which the alarm was raised.
    pub alarm_slot: u64,
    /// Which alarm.
    pub alarm: ProgressAlarm,
    /// People holding ballots (in booths and in the queue).
    pub holding: u64,
    /// What the check found.
    pub finding: ProgressFinding,
    /// Sheets carried out: at least 1 for [`ProgressFinding::CarriedOut`],
    /// otherwise 0.
    pub carried_out: u64,
    /// Hash of the signers' statement.
    pub statement_hash: Hash512,
    /// When.
    pub time_bucket: TimeBucket,
}

impl ProgressCheckParts<'_> {
    /// Whether `carried_out` matches the finding.
    #[must_use]
    pub fn carried_out_consistent(&self) -> bool {
        (self.finding == ProgressFinding::CarriedOut) == (self.carried_out > 0)
    }
}

/// A progress-check body (schema `0x0032`).
///
/// Rules: alarm and finding codes in range (`ValueOutOfRange`);
/// `carried_out ≥ 1` exactly for finding 2 (`InvariantViolation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProgressCheckBody<'a> {
    parts: ProgressCheckParts<'a>,
}

impl<'a> ProgressCheckBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// `InvariantViolation` at 0 if `carried_out` does not match the
    /// finding.
    pub fn new(parts: &ProgressCheckParts<'a>) -> Result<Self, Error> {
        if parts.carried_out_consistent() {
            Ok(Self { parts: *parts })
        } else {
            Err(invalid(0))
        }
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &ProgressCheckParts<'a> {
        &self.parts
    }
}

impl Encode for ProgressCheckBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.station_id.encoded_len())
            .saturating_add(8 + 1 + 8 + 1 + 8 + 64 + 8)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.station_id.encode(w)?;
        w.write_u64(p.alarm_slot)?;
        w.write_u8(p.alarm.code())?;
        w.write_u64(p.holding)?;
        w.write_u8(p.finding.code())?;
        w.write_u64(p.carried_out)?;
        p.statement_hash.encode(w)?;
        p.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for ProgressCheckBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let station_id = StationId::decode(r)?;
        let alarm_slot = r.read_u64()?;
        let alarm = read_code(r, ProgressAlarm::from_code)?;
        let holding = r.read_u64()?;
        let finding = read_code(r, ProgressFinding::from_code)?;
        let carried_at = r.position();
        let carried_out = r.read_u64()?;
        let parts = ProgressCheckParts {
            election_id,
            station_id,
            alarm_slot,
            alarm,
            holding,
            finding,
            carried_out,
            statement_hash: Hash512([0; 64]),
            time_bucket: TimeBucket::new(0),
        };
        if !parts.carried_out_consistent() {
            return Err(invalid(carried_at));
        }
        Ok(Self {
            parts: ProgressCheckParts {
                statement_hash: Hash512::decode(r)?,
                time_bucket: TimeBucket::decode(r)?,
                ..parts
            },
        })
    }
}
