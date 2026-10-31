//! `ScanCountAttestBody` (schema `0x0013`) and `ScanCountAttest`
//! (schema `0x001B`), version 1: the observer-signed anchor of a scanner's
//! running counts (PROTOCOL.md §7.8, ENCODING.md §8.14–§8.15).
//!
//! `ScanCountAttestBody` field order: `election_id`, `box_id`,
//! `record_count`, `challenge_count`, `quarantine_count`, `journal_head`,
//! `time_bucket`. `ScanCountAttest` field order: `body`, `observer_sigs`.

use crate::codec::{Decode, Encode};
use crate::error::{Error, Kind};
use crate::primitives::{BoxId, ElectionId, Hash512, ObserverId, OrgId, TimeBucket};
use crate::reader::Reader;
use crate::schema::SCHEMA_SCAN_COUNT_ATTEST_BODY;
use crate::schema::util::{
    HYBRID_SIG_LEN, ascending_by, check_embedded, decode_embedded, read_fixed,
};
use crate::writer::Writer;

/// Maximum length of the embedded `ScanCountAttestBody` object bytes.
pub const MAX_SCAN_COUNT_BODY_LEN: usize = 512;

/// Maximum number of observer signatures.
pub const MAX_OBSERVER_SIGS: usize = 4;

/// Minimum number of observer signatures, from distinct organizations.
pub const MIN_OBSERVER_SIGS: usize = 2;

/// The body of a scan-count attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScanCountAttestBody<'a> {
    election_id: ElectionId<'a>,
    box_id: BoxId<'a>,
    record_count: u64,
    challenge_count: u64,
    quarantine_count: u64,
    journal_head: Hash512,
    time_bucket: TimeBucket,
}

impl<'a> ScanCountAttestBody<'a> {
    /// Builds a body. All invariants are carried by the field types.
    #[must_use]
    pub const fn new(
        election_id: ElectionId<'a>,
        box_id: BoxId<'a>,
        record_count: u64,
        challenge_count: u64,
        quarantine_count: u64,
        journal_head: Hash512,
        time_bucket: TimeBucket,
    ) -> Self {
        Self {
            election_id,
            box_id,
            record_count,
            challenge_count,
            quarantine_count,
            journal_head,
            time_bucket,
        }
    }

    /// The election.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.election_id
    }

    /// The ballot box.
    #[must_use]
    pub const fn box_id(&self) -> BoxId<'a> {
        self.box_id
    }

    /// Cumulative cast records.
    #[must_use]
    pub const fn record_count(&self) -> u64 {
        self.record_count
    }

    /// Cumulative challenge spoils.
    #[must_use]
    pub const fn challenge_count(&self) -> u64 {
        self.challenge_count
    }

    /// Cumulative quarantines.
    #[must_use]
    pub const fn quarantine_count(&self) -> u64 {
        self.quarantine_count
    }

    /// The sealed journal head at attestation time.
    #[must_use]
    pub const fn journal_head(&self) -> &Hash512 {
        &self.journal_head
    }

    /// The time bucket of the attestation.
    #[must_use]
    pub const fn time_bucket(&self) -> TimeBucket {
        self.time_bucket
    }
}

impl Encode for ScanCountAttestBody<'_> {
    fn encoded_len(&self) -> usize {
        self.election_id
            .encoded_len()
            .saturating_add(self.box_id.encoded_len())
            .saturating_add(24)
            .saturating_add(64)
            .saturating_add(8)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.election_id.encode(w)?;
        self.box_id.encode(w)?;
        w.write_u64(self.record_count)?;
        w.write_u64(self.challenge_count)?;
        w.write_u64(self.quarantine_count)?;
        self.journal_head.encode(w)?;
        self.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for ScanCountAttestBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            election_id: ElectionId::decode(r)?,
            box_id: BoxId::decode(r)?,
            record_count: r.read_u64()?,
            challenge_count: r.read_u64()?,
            quarantine_count: r.read_u64()?,
            journal_head: Hash512::decode(r)?,
            time_bucket: TimeBucket::decode(r)?,
        })
    }
}

/// One observer's hybrid signature over the body bytes (purpose `scan-count`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObserverSig<'a> {
    /// The observer.
    pub observer_id: ObserverId<'a>,
    /// The observer's organization.
    pub org_id: OrgId<'a>,
    /// The signature.
    pub sig: &'a [u8; HYBRID_SIG_LEN],
}

/// Returns `true` if at least two distinct organizations appear.
fn two_orgs<'a, I>(sigs: I) -> bool
where
    I: IntoIterator<Item = ObserverSig<'a>>,
{
    let mut first: Option<&[u8]> = None;
    for sig in sigs {
        match first {
            None => first = Some(sig.org_id.as_bytes()),
            Some(org) if org != sig.org_id.as_bytes() => return true,
            Some(_) => {}
        }
    }
    false
}

/// A scan-count attestation: the body object bytes with two or more
/// observer signatures from at least two organizations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanCountAttest<'a> {
    body_bytes: &'a [u8],
    body: ScanCountAttestBody<'a>,
    sigs: [Option<ObserverSig<'a>>; MAX_OBSERVER_SIGS],
    sig_count: u8,
}

impl<'a> ScanCountAttest<'a> {
    /// Builds the event. The signatures must be ascending by observer
    /// identifier, two to four of them, from at least two organizations.
    ///
    /// # Errors
    /// The body's decoding error, `LengthExceedsMax` at 0 if the body is too
    /// long, or `InvariantViolation` at 0 if the signature set is malformed.
    pub fn new(body_bytes: &'a [u8], sigs: &[ObserverSig<'a>]) -> Result<Self, Error> {
        let body = check_embedded(
            body_bytes,
            MAX_SCAN_COUNT_BODY_LEN,
            SCHEMA_SCAN_COUNT_ATTEST_BODY,
        )?;
        let ascending = ascending_by(sigs, |x| x.observer_id.as_bytes());
        if sigs.len() < MIN_OBSERVER_SIGS
            || sigs.len() > MAX_OBSERVER_SIGS
            || !ascending
            || !two_orgs(sigs.iter().copied())
        {
            return Err(Error::new(Kind::InvariantViolation, 0));
        }
        let mut slots = [None; MAX_OBSERVER_SIGS];
        for (slot, sig) in slots.iter_mut().zip(sigs) {
            *slot = Some(*sig);
        }
        Ok(Self {
            body_bytes,
            body,
            sigs: slots,
            sig_count: u8::try_from(sigs.len())
                .map_err(|_| Error::new(Kind::InvariantViolation, 0))?,
        })
    }

    /// The body object bytes (the signed message).
    #[must_use]
    pub const fn body_bytes(&self) -> &'a [u8] {
        self.body_bytes
    }

    /// The decoded body.
    #[must_use]
    pub const fn body(&self) -> &ScanCountAttestBody<'a> {
        &self.body
    }

    /// The observer signatures in ascending identifier order.
    pub fn observer_sigs(&self) -> impl Iterator<Item = ObserverSig<'a>> + '_ {
        self.sigs
            .iter()
            .take(usize::from(self.sig_count))
            .flatten()
            .copied()
    }
}

impl Encode for ScanCountAttest<'_> {
    fn encoded_len(&self) -> usize {
        let sigs = self.observer_sigs().fold(4usize, |acc, s| {
            acc.saturating_add(s.observer_id.encoded_len())
                .saturating_add(s.org_id.encoded_len())
                .saturating_add(HYBRID_SIG_LEN)
        });
        self.body_bytes.len().saturating_add(4).saturating_add(sigs)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_bytes(self.body_bytes, MAX_SCAN_COUNT_BODY_LEN)?;
        w.write_count(usize::from(self.sig_count), MAX_OBSERVER_SIGS)?;
        for sig in self.observer_sigs() {
            sig.observer_id.encode(w)?;
            sig.org_id.encode(w)?;
            w.write_array(sig.sig)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for ScanCountAttest<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let (body_bytes, body) =
            decode_embedded(r, MAX_SCAN_COUNT_BODY_LEN, SCHEMA_SCAN_COUNT_ATTEST_BODY)?;
        let sigs_at = r.position();
        let count = r.read_count(MAX_OBSERVER_SIGS)?;
        if count < MIN_OBSERVER_SIGS {
            return Err(Error::new(Kind::InvariantViolation, sigs_at));
        }
        let mut sigs = [None; MAX_OBSERVER_SIGS];
        let mut previous: Option<&[u8]> = None;
        for slot in sigs.iter_mut().take(count) {
            let id_at = r.position();
            let observer_id = ObserverId::decode(r)?;
            Reader::check_ascending(previous, observer_id.as_bytes(), id_at)?;
            previous = Some(observer_id.as_bytes());
            let org_id = OrgId::decode(r)?;
            let sig = read_fixed::<HYBRID_SIG_LEN>(r)?;
            *slot = Some(ObserverSig {
                observer_id,
                org_id,
                sig,
            });
        }
        if !two_orgs(sigs.iter().take(count).flatten().copied()) {
            return Err(Error::new(Kind::InvariantViolation, sigs_at));
        }
        Ok(Self {
            body_bytes,
            body,
            sigs,
            sig_count: u8::try_from(count)
                .map_err(|_| Error::new(Kind::CountExceedsMax, sigs_at))?,
        })
    }
}
