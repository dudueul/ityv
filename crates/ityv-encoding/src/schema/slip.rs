//! `SlipBody` (schema `0x0019`) and `Slip` (schema `0x000A`), version 1:
//! the voter's tracking-code slip, one per visit (PROTOCOL.md §7.7,
//! ENCODING.md §8.18, ADR-0021).
//!
//! `SlipBody` field order: `election_id`, `station_id`, `time_bucket`,
//! `tracking_codes` (1–8, in the visit's position order, no code twice).
//! `Slip` field order: `body`, `device_sig`.

use crate::codec::{Decode, Encode};
use crate::error::{Error, Kind};
use crate::primitives::{ElectionId, Hash512, StationId, TimeBucket};
use crate::reader::Reader;
use crate::schema::SCHEMA_SLIP_BODY;
use crate::schema::util::{HYBRID_SIG_LEN, check_embedded, decode_embedded, read_fixed};
use crate::writer::Writer;

/// Maximum length of the embedded `SlipBody` object bytes.
pub const MAX_SLIP_BODY_LEN: usize = 1024;

/// Most tracking codes on one slip: the ballots of one visit.
pub const MAX_TRACKING_CODES: usize = 8;

/// The body of a slip.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SlipBody<'a> {
    election_id: ElectionId<'a>,
    station_id: StationId<'a>,
    time_bucket: TimeBucket,
    codes: [Hash512; MAX_TRACKING_CODES],
    count: u8,
}

/// `true` if `codes` holds `code` among its first entries.
fn holds(codes: &[Hash512], code: &Hash512) -> bool {
    codes.iter().any(|c| c == code)
}

impl<'a> SlipBody<'a> {
    /// Builds a slip body over the tracking codes of one visit, in position
    /// order. `None` if there are none, more than eight, or a code appears
    /// twice.
    #[must_use]
    pub fn new(
        election_id: ElectionId<'a>,
        station_id: StationId<'a>,
        time_bucket: TimeBucket,
        tracking_codes: &[Hash512],
    ) -> Option<Self> {
        if tracking_codes.is_empty() || tracking_codes.len() > MAX_TRACKING_CODES {
            return None;
        }
        let mut codes = [Hash512::ZERO; MAX_TRACKING_CODES];
        for (i, (slot, code)) in codes.iter_mut().zip(tracking_codes).enumerate() {
            if holds(tracking_codes.get(..i).unwrap_or(&[]), code) {
                return None;
            }
            *slot = *code;
        }
        Some(Self {
            election_id,
            station_id,
            time_bucket,
            codes,
            count: u8::try_from(tracking_codes.len()).ok()?,
        })
    }

    /// The election.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.election_id
    }

    /// The polling station.
    #[must_use]
    pub const fn station_id(&self) -> StationId<'a> {
        self.station_id
    }

    /// The time bucket of casting.
    #[must_use]
    pub const fn time_bucket(&self) -> TimeBucket {
        self.time_bucket
    }

    /// The tracking codes (object hashes of the cast record bodies), in
    /// the visit's position order.
    #[must_use]
    pub fn tracking_codes(&self) -> &[Hash512] {
        self.codes.get(..usize::from(self.count)).unwrap_or(&[])
    }
}

impl Encode for SlipBody<'_> {
    fn encoded_len(&self) -> usize {
        self.election_id
            .encoded_len()
            .saturating_add(self.station_id.encoded_len())
            .saturating_add(8)
            .saturating_add(4)
            .saturating_add(usize::from(self.count).saturating_mul(64))
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.election_id.encode(w)?;
        self.station_id.encode(w)?;
        self.time_bucket.encode(w)?;
        w.write_count(usize::from(self.count), MAX_TRACKING_CODES)?;
        for code in self.tracking_codes() {
            code.encode(w)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for SlipBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let station_id = StationId::decode(r)?;
        let time_bucket = TimeBucket::decode(r)?;
        let count_at = r.position();
        let count = r.read_count(MAX_TRACKING_CODES)?;
        if count == 0 {
            return Err(Error::new(Kind::ValueOutOfRange, count_at));
        }
        let mut codes = [Hash512::ZERO; MAX_TRACKING_CODES];
        for i in 0..count {
            let at = r.position();
            let code = Hash512::decode(r)?;
            if holds(codes.get(..i).unwrap_or(&[]), &code) {
                return Err(Error::new(Kind::Duplicate, at));
            }
            if let Some(slot) = codes.get_mut(i) {
                *slot = code;
            }
        }
        Ok(Self {
            election_id,
            station_id,
            time_bucket,
            codes,
            count: u8::try_from(count).map_err(|_| Error::new(Kind::CountExceedsMax, count_at))?,
        })
    }
}

/// A slip: the body object bytes with the device's hybrid signature
/// (purpose `slip`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slip<'a> {
    body_bytes: &'a [u8],
    body: SlipBody<'a>,
    device_sig: &'a [u8; HYBRID_SIG_LEN],
}

impl<'a> Slip<'a> {
    /// Builds a slip from a complete body object and the signature.
    ///
    /// # Errors
    /// The body's decoding error, or `LengthExceedsMax` at 0 if too long.
    pub fn new(body_bytes: &'a [u8], device_sig: &'a [u8; HYBRID_SIG_LEN]) -> Result<Self, Error> {
        let body = check_embedded(body_bytes, MAX_SLIP_BODY_LEN, SCHEMA_SLIP_BODY)?;
        Ok(Self {
            body_bytes,
            body,
            device_sig,
        })
    }

    /// The body object bytes (the signed message).
    #[must_use]
    pub const fn body_bytes(&self) -> &'a [u8] {
        self.body_bytes
    }

    /// The decoded body.
    #[must_use]
    pub const fn body(&self) -> &SlipBody<'a> {
        &self.body
    }

    /// The device's hybrid signature.
    #[must_use]
    pub const fn device_sig(&self) -> &'a [u8; HYBRID_SIG_LEN] {
        self.device_sig
    }
}

impl Encode for Slip<'_> {
    fn encoded_len(&self) -> usize {
        self.body_bytes
            .len()
            .saturating_add(4)
            .saturating_add(HYBRID_SIG_LEN)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_bytes(self.body_bytes, MAX_SLIP_BODY_LEN)?;
        w.write_array(self.device_sig)
    }
}

impl<'a> Decode<'a> for Slip<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let (body_bytes, body) = decode_embedded(r, MAX_SLIP_BODY_LEN, SCHEMA_SLIP_BODY)?;
        let device_sig = read_fixed::<HYBRID_SIG_LEN>(r)?;
        Ok(Self {
            body_bytes,
            body,
            device_sig,
        })
    }
}
