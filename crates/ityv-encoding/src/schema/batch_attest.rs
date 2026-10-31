//! `BatchAttestBody` (schema `0x0012`) and `BatchAttest` (schema `0x0017`),
//! version 1: the per-batch post-quantum attestation of cast records
//! (PROTOCOL.md §7.2.1, ENCODING.md §8.12–§8.13).
//!
//! `BatchAttestBody` field order: `election_id`, `box_id`, `batch_index`,
//! `record_count`, `records_root`, `module_ranges`, `module_refusals`,
//! `journal_head`, `time_bucket`. `BatchAttest` field order: `body`,
//! `module_sigs`, `device_sig`.

use crate::codec::{Decode, Encode};
use crate::error::{Error, Kind};
use crate::primitives::{BoxId, ElectionId, Hash512, ModuleId, TimeBucket};
use crate::reader::Reader;
use crate::schema::SCHEMA_BATCH_ATTEST_BODY;
use crate::schema::util::{
    HYBRID_SIG_LEN, MAX_MODULES, ModuleIds, ascending_by, check_embedded, decode_embedded,
    read_fixed,
};
use crate::writer::Writer;

/// Maximum number of records in one batch.
pub const MAX_BATCH_RECORDS: u16 = 64;

/// Maximum length of the embedded `BatchAttestBody` object bytes.
pub const MAX_BATCH_BODY_LEN: usize = 2048;

/// Returns `true` if `record_count` is within `1..=64`.
#[must_use]
pub const fn record_count_valid(record_count: u16) -> bool {
    record_count >= 1 && record_count <= MAX_BATCH_RECORDS
}

/// One module's counter range within a batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModuleRange<'a> {
    /// The module.
    pub module_id: ModuleId<'a>,
    /// First counter value of the batch.
    pub counter_first: u64,
    /// Last counter value of the batch (inclusive).
    pub counter_last: u64,
}

/// Unvalidated inputs for [`BatchAttestBody::new`].
#[derive(Debug, Clone, Copy)]
pub struct BatchAttestParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The ballot box.
    pub box_id: BoxId<'a>,
    /// The batch index within the box, from zero.
    pub batch_index: u32,
    /// Number of records in the batch (`1..=64`).
    pub record_count: u16,
    /// Sorted-set root of the record hashes.
    pub records_root: Hash512,
    /// The module counter ranges, ascending by identifier.
    pub module_ranges: &'a [ModuleRange<'a>],
    /// The modules that refused to sign (each must have a range).
    pub module_refusals: ModuleIds<'a>,
    /// The sealed journal head when the batch closed.
    pub journal_head: Hash512,
    /// The time bucket of the batch close.
    pub time_bucket: TimeBucket,
}

/// The body of a batch attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BatchAttestBody<'a> {
    election_id: ElectionId<'a>,
    box_id: BoxId<'a>,
    batch_index: u32,
    record_count: u16,
    records_root: Hash512,
    ranges: [Option<ModuleRange<'a>>; MAX_MODULES],
    range_count: u8,
    module_refusals: ModuleIds<'a>,
    journal_head: Hash512,
    time_bucket: TimeBucket,
}

impl<'a> BatchAttestBody<'a> {
    /// Builds a body. Returns `None` if `record_count` is outside `1..=64`,
    /// the ranges are not strictly ascending by identifier or number more
    /// than six, any range has `counter_first > counter_last`, or a refusal
    /// names a module without a range.
    #[must_use]
    pub fn new(parts: &BatchAttestParts<'a>) -> Option<Self> {
        let module_ranges = parts.module_ranges;
        if !record_count_valid(parts.record_count) {
            return None;
        }
        if module_ranges.len() > MAX_MODULES {
            return None;
        }
        let ascending = ascending_by(module_ranges, |x| x.module_id.as_bytes());
        if !ascending
            || module_ranges
                .iter()
                .any(|m| m.counter_first > m.counter_last)
        {
            return None;
        }
        if parts.module_refusals.iter().any(|id| {
            !module_ranges
                .iter()
                .any(|m| m.module_id.as_bytes() == id.as_bytes())
        }) {
            return None;
        }
        let mut ranges = [None; MAX_MODULES];
        for (slot, range) in ranges.iter_mut().zip(module_ranges) {
            *slot = Some(*range);
        }
        Some(Self {
            election_id: parts.election_id,
            box_id: parts.box_id,
            batch_index: parts.batch_index,
            record_count: parts.record_count,
            records_root: parts.records_root,
            ranges,
            range_count: u8::try_from(module_ranges.len()).ok()?,
            module_refusals: parts.module_refusals,
            journal_head: parts.journal_head,
            time_bucket: parts.time_bucket,
        })
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

    /// The batch index within the box, from zero.
    #[must_use]
    pub const fn batch_index(&self) -> u32 {
        self.batch_index
    }

    /// Number of records in the batch (`1..=64`).
    #[must_use]
    pub const fn record_count(&self) -> u16 {
        self.record_count
    }

    /// Sorted-set root of the record hashes.
    #[must_use]
    pub const fn records_root(&self) -> &Hash512 {
        &self.records_root
    }

    /// The module counter ranges in ascending identifier order.
    pub fn module_ranges(&self) -> impl Iterator<Item = ModuleRange<'a>> + '_ {
        self.ranges
            .iter()
            .take(usize::from(self.range_count))
            .flatten()
            .copied()
    }

    /// The modules that refused to sign.
    #[must_use]
    pub const fn module_refusals(&self) -> &ModuleIds<'a> {
        &self.module_refusals
    }

    /// The modules expected to sign: ranges minus refusals, ascending.
    pub fn expected_signers(&self) -> impl Iterator<Item = ModuleId<'a>> + '_ {
        self.module_ranges()
            .map(|m| m.module_id)
            .filter(|id| !self.module_refusals.contains(*id))
    }

    /// The sealed journal head when the batch closed.
    #[must_use]
    pub const fn journal_head(&self) -> &Hash512 {
        &self.journal_head
    }

    /// The time bucket of the batch close.
    #[must_use]
    pub const fn time_bucket(&self) -> TimeBucket {
        self.time_bucket
    }
}

impl Encode for BatchAttestBody<'_> {
    fn encoded_len(&self) -> usize {
        let ranges = self.module_ranges().fold(4usize, |acc, m| {
            acc.saturating_add(m.module_id.encoded_len())
                .saturating_add(16)
        });
        self.election_id
            .encoded_len()
            .saturating_add(self.box_id.encoded_len())
            .saturating_add(4)
            .saturating_add(2)
            .saturating_add(64)
            .saturating_add(ranges)
            .saturating_add(self.module_refusals.encoded_len())
            .saturating_add(64)
            .saturating_add(8)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.election_id.encode(w)?;
        self.box_id.encode(w)?;
        w.write_u32(self.batch_index)?;
        w.write_u16(self.record_count)?;
        self.records_root.encode(w)?;
        w.write_count(usize::from(self.range_count), MAX_MODULES)?;
        for m in self.module_ranges() {
            m.module_id.encode(w)?;
            w.write_u64(m.counter_first)?;
            w.write_u64(m.counter_last)?;
        }
        self.module_refusals.encode(w)?;
        self.journal_head.encode(w)?;
        self.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for BatchAttestBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let box_id = BoxId::decode(r)?;
        let batch_index = r.read_u32()?;
        let count_at = r.position();
        let record_count = r.read_u16()?;
        if !record_count_valid(record_count) {
            return Err(Error::new(Kind::ValueOutOfRange, count_at));
        }
        let records_root = Hash512::decode(r)?;
        let ranges_at = r.position();
        let range_count = r.read_count(MAX_MODULES)?;
        let mut ranges = [None; MAX_MODULES];
        let mut previous: Option<&[u8]> = None;
        for slot in ranges.iter_mut().take(range_count) {
            let id_at = r.position();
            let module_id = ModuleId::decode(r)?;
            Reader::check_ascending(previous, module_id.as_bytes(), id_at)?;
            previous = Some(module_id.as_bytes());
            let counter_first = r.read_u64()?;
            let last_at = r.position();
            let counter_last = r.read_u64()?;
            if counter_first > counter_last {
                return Err(Error::new(Kind::ValueOutOfRange, last_at));
            }
            *slot = Some(ModuleRange {
                module_id,
                counter_first,
                counter_last,
            });
        }
        let refusals_at = r.position();
        let module_refusals = ModuleIds::decode(r)?;
        let known = |id: ModuleId<'_>| {
            ranges
                .iter()
                .take(range_count)
                .flatten()
                .any(|m| m.module_id.as_bytes() == id.as_bytes())
        };
        if module_refusals.iter().any(|id| !known(id)) {
            return Err(Error::new(Kind::InvariantViolation, refusals_at));
        }
        let journal_head = Hash512::decode(r)?;
        let time_bucket = TimeBucket::decode(r)?;
        Ok(Self {
            election_id,
            box_id,
            batch_index,
            record_count,
            records_root,
            ranges,
            range_count: u8::try_from(range_count)
                .map_err(|_| Error::new(Kind::CountExceedsMax, ranges_at))?,
            module_refusals,
            journal_head,
            time_bucket,
        })
    }
}

/// One module's hybrid signature over the body bytes (purpose `batch-attest`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModuleBatchSig<'a> {
    /// The module.
    pub module_id: ModuleId<'a>,
    /// The signature.
    pub sig: &'a [u8; HYBRID_SIG_LEN],
}

/// A batch attestation: the body object bytes with the module and device
/// hybrid signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchAttest<'a> {
    body_bytes: &'a [u8],
    body: BatchAttestBody<'a>,
    module_sigs: [Option<ModuleBatchSig<'a>>; MAX_MODULES],
    sig_count: u8,
    device_sig: &'a [u8; HYBRID_SIG_LEN],
}

/// Returns `true` if `sigs` names exactly `expected`, in order.
fn same_signers<'a, I>(sigs: &[Option<ModuleBatchSig<'a>>], count: usize, expected: I) -> bool
where
    I: IntoIterator<Item = ModuleId<'a>>,
{
    let mut expected = expected.into_iter();
    for sig in sigs.iter().take(count).flatten() {
        match expected.next() {
            Some(id) if id.as_bytes() == sig.module_id.as_bytes() => {}
            _ => return false,
        }
    }
    expected.next().is_none()
}

impl<'a> BatchAttest<'a> {
    /// Builds the event. The module signatures must be ascending by
    /// identifier and name exactly the body's ranges minus its refusals.
    ///
    /// # Errors
    /// The body's decoding error, `LengthExceedsMax` at 0 if the body is too
    /// long, or `InvariantViolation` at 0 if the signature set is malformed.
    pub fn new(
        body_bytes: &'a [u8],
        module_sigs: &[ModuleBatchSig<'a>],
        device_sig: &'a [u8; HYBRID_SIG_LEN],
    ) -> Result<Self, Error> {
        let body: BatchAttestBody<'a> =
            check_embedded(body_bytes, MAX_BATCH_BODY_LEN, SCHEMA_BATCH_ATTEST_BODY)?;
        if module_sigs.len() > MAX_MODULES {
            return Err(Error::new(Kind::InvariantViolation, 0));
        }
        let mut sigs = [None; MAX_MODULES];
        for (slot, sig) in sigs.iter_mut().zip(module_sigs) {
            *slot = Some(*sig);
        }
        if !same_signers(&sigs, module_sigs.len(), body.expected_signers()) {
            return Err(Error::new(Kind::InvariantViolation, 0));
        }
        Ok(Self {
            body_bytes,
            body,
            module_sigs: sigs,
            sig_count: u8::try_from(module_sigs.len())
                .map_err(|_| Error::new(Kind::InvariantViolation, 0))?,
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
    pub const fn body(&self) -> &BatchAttestBody<'a> {
        &self.body
    }

    /// The module signatures in ascending identifier order.
    pub fn module_sigs(&self) -> impl Iterator<Item = ModuleBatchSig<'a>> + '_ {
        self.module_sigs
            .iter()
            .take(usize::from(self.sig_count))
            .flatten()
            .copied()
    }

    /// The device's hybrid signature.
    #[must_use]
    pub const fn device_sig(&self) -> &'a [u8; HYBRID_SIG_LEN] {
        self.device_sig
    }
}

impl Encode for BatchAttest<'_> {
    fn encoded_len(&self) -> usize {
        let sigs = self.module_sigs().fold(4usize, |acc, s| {
            acc.saturating_add(s.module_id.encoded_len())
                .saturating_add(HYBRID_SIG_LEN)
        });
        self.body_bytes
            .len()
            .saturating_add(4)
            .saturating_add(sigs)
            .saturating_add(HYBRID_SIG_LEN)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_bytes(self.body_bytes, MAX_BATCH_BODY_LEN)?;
        w.write_count(usize::from(self.sig_count), MAX_MODULES)?;
        for sig in self.module_sigs() {
            sig.module_id.encode(w)?;
            w.write_array(sig.sig)?;
        }
        w.write_array(self.device_sig)
    }
}

impl<'a> Decode<'a> for BatchAttest<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let (body_bytes, body): (&'a [u8], BatchAttestBody<'a>) =
            decode_embedded(r, MAX_BATCH_BODY_LEN, SCHEMA_BATCH_ATTEST_BODY)?;
        let sigs_at = r.position();
        let count = r.read_count(MAX_MODULES)?;
        let mut module_sigs = [None; MAX_MODULES];
        let mut previous: Option<&[u8]> = None;
        for slot in module_sigs.iter_mut().take(count) {
            let id_at = r.position();
            let module_id = ModuleId::decode(r)?;
            Reader::check_ascending(previous, module_id.as_bytes(), id_at)?;
            previous = Some(module_id.as_bytes());
            let sig = read_fixed::<HYBRID_SIG_LEN>(r)?;
            *slot = Some(ModuleBatchSig { module_id, sig });
        }
        if !same_signers(&module_sigs, count, body.expected_signers()) {
            return Err(Error::new(Kind::InvariantViolation, sigs_at));
        }
        let device_sig = read_fixed::<HYBRID_SIG_LEN>(r)?;
        Ok(Self {
            body_bytes,
            body,
            module_sigs,
            sig_count: u8::try_from(count)
                .map_err(|_| Error::new(Kind::CountExceedsMax, sigs_at))?,
            device_sig,
        })
    }
}
