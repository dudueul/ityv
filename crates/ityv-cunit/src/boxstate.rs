//! Box accounting: the journal chain, batches, scan counts, close and
//! resume (PROTOCOL.md §7.2.1, §7.8, §10.2; ADR-0017 §7–§9 and 개정).
//!
//! An [`OpenBox`] owns the state that outlives one ballot: the high-water
//! mark of every module counter, the journal head, the open batch, the
//! totals, the open visit ([`crate::visit`]) and the position in flight.
//! Positions are built one at a time and visits are processed one at a
//! time; batches, scan counts and the close are produced only between
//! visits, so every counter a batch attests belongs to a position whose
//! journal entry already exists.
//!
//! A journal-head mismatch at batch close latches the box into a fault
//! state (VC-056): it then refuses new ballots, batches, scan counts and
//! the close signature, and the device is replaced.
//!
//! [`OpenBox::prepare_close`] writes the close entry and marks the box
//! closed at run time; [`OpenBox::into_closed`] then turns it into a
//! [`ClosedBox`], which has no method that accepts a ballot.
//!
//! After a power loss, [`OpenBox::resume`] ([`crate::resume`]) rebuilds the
//! box from the journal stream alone.

use core::fmt;

use ityv_crypto::{
    HybridSignature, HybridSigningKey, Purpose, RecordPurpose, RecordSignature, object_hash,
    sign_hybrid, verify_hybrid,
};
use ityv_encoding::{
    BatchAttest, BatchAttestBody, BatchAttestParts, BoxCloseBody, BoxCloseParts, CloseCounts,
    Encode, HYBRID_SIG_LEN, Hash512, MAX_BATCH_BODY_LEN, MAX_BOX_CLOSE_BODY_LEN, ModuleBatchSig,
    ModuleCounter, ModuleCounters, ModuleIds, ModuleRange, SCHEMA_BATCH_ATTEST,
    SCHEMA_BATCH_ATTEST_BODY, SCHEMA_BOX_CLOSE_BODY, SCHEMA_SCAN_COUNT_ATTEST_BODY,
    SCHEMA_VERSION_1, ScanCountAttestBody, TimeBucket, Writer, encode_object,
};
use ityv_ledger::merkle::sorted_set_root;

use crate::config::{ElectionConfig, MAX_MODULES, Profile};
use crate::error::Error;
use crate::link::{JournalEntry, JournalKind, MAX_JOURNAL_ENTRY_LEN, SCHEMA_JOURNAL_ENTRY};
use crate::port::{JournalSink, ModulePort};
use crate::rng::DeviceRng;
use crate::rules::{self, CloseFacts, CounterCheck, EnvelopeCounts, Violations};
use crate::visit::Visit;

/// Purpose of the batch attestation signatures.
pub const PURPOSE_BATCH_ATTEST: &[u8] = b"batch-attest";
/// Purpose of the device's box-close signature.
pub const PURPOSE_BOX_CLOSE: &[u8] = b"box-close";
/// Bytes of a `BatchAttest` object at most, header included:
/// 16 + (4 + 1366) + (4 + 7·(68 + 4691)) + 4691.
pub const MAX_BATCH_ATTEST_LEN: usize = 39_394;
/// Work buffer [`OpenBox::close_batch`] needs: one hybrid signature per
/// module and one for the device, then the `BatchAttest` object.
pub const BATCH_WORK_LEN: usize = BATCH_SIG_REGION_LEN + MAX_BATCH_ATTEST_LEN;
/// The signature region of the batch work buffer: the module slots, then
/// the device slot.
const BATCH_SIG_REGION_LEN: usize = (MAX_MODULES + 1) * HYBRID_SIG_LEN;
/// Work buffer [`OpenBox::prepare_close`] needs: the body object and the
/// device signature.
pub const CLOSE_WORK_LEN: usize = MAX_BOX_CLOSE_BODY_LEN + HYBRID_SIG_LEN;
/// Bytes of a `ScanCountAttestBody` object at most, header included.
pub const MAX_SCAN_COUNT_BODY_OBJECT_LEN: usize = 248;

const BATCH_CAP: usize = 64;

/// A purpose literal of this crate, checked by `ityv-crypto`.
pub(crate) fn purpose(bytes: &'static [u8]) -> Result<Purpose<'static>, Error> {
    Purpose::new(bytes).ok_or(Error::InvalidPurpose)
}

/// Writes the fixed-width encoding of a hybrid signature.
pub(crate) fn write_hybrid(
    sig: &HybridSignature,
    out: &mut [u8; HYBRID_SIG_LEN],
) -> Result<(), Error> {
    let mut w = Writer::new(out);
    sig.encode(&mut w)?;
    if w.finish() == HYBRID_SIG_LEN {
        Ok(())
    } else {
        Err(Error::Overflow)
    }
}

/// The device's hybrid signing key and the host's seed for one signing
/// operation (hedged ML-DSA signing; ADR-0017 §12).
#[derive(Clone, Copy)]
pub struct Signer<'k> {
    key: &'k HybridSigningKey,
    seed: &'k [u8; 32],
}

impl<'k> Signer<'k> {
    /// Pairs the device key with a fresh per-operation seed.
    #[must_use]
    pub const fn new(key: &'k HybridSigningKey, seed: &'k [u8; 32]) -> Self {
        Self { key, seed }
    }

    /// Signs `body` under the classical-only `purpose` with the Ed25519
    /// half of the key alone (an attestation summary QR).
    pub(crate) fn sign_ed25519_half(
        &self,
        purpose: RecordPurpose,
        body: &[u8],
    ) -> Result<RecordSignature, Error> {
        Ok(ityv_crypto::sign_ed25519_half(self.key, purpose, body)?)
    }

    /// Signs `body` under `purpose` into `out`.
    pub(crate) fn sign_into(
        &self,
        purpose_bytes: &'static [u8],
        body: &[u8],
        out: &mut [u8; HYBRID_SIG_LEN],
    ) -> Result<(), Error> {
        let sig = sign_hybrid(
            self.key,
            &purpose(purpose_bytes)?,
            body,
            &mut DeviceRng::for_signing(self.seed),
        )?;
        write_hybrid(&sig, out)
    }
}

impl fmt::Debug for Signer<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Signer(..)")
    }
}

/// The ballot currently between interpretation and its terminal journal
/// entry: the counters it consumed and, once its record entry is durable,
/// the record hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InFlight {
    pub(crate) ticket: u64,
    pub(crate) counters: [u64; MAX_MODULES],
    pub(crate) issued: [bool; MAX_MODULES],
    pub(crate) record: Option<Hash512>,
}

/// The fields of one journal entry besides the chain link.
pub(crate) struct EntryFields<'a> {
    pub(crate) kind: JournalKind,
    pub(crate) record_hash: Hash512,
    pub(crate) share_package_hash: Hash512,
    pub(crate) counters: &'a [u64; MAX_MODULES],
    pub(crate) include: [bool; MAX_MODULES],
    pub(crate) time_bucket: TimeBucket,
}

/// No module counters (visit entries and quarantines without counters).
pub(crate) const NO_COUNTERS: [u64; MAX_MODULES] = [0; MAX_MODULES];

/// The open batch: the record hashes it holds and the bucket of its last
/// record.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Batch {
    pub(crate) hashes: [Hash512; BATCH_CAP],
    pub(crate) count: u16,
    pub(crate) last_record_bucket: u64,
}

impl Batch {
    const fn new() -> Self {
        Self {
            hashes: [Hash512::ZERO; BATCH_CAP],
            count: 0,
            last_record_bucket: 0,
        }
    }

    /// The sorted-set root of the batch's record hashes.
    pub(crate) fn root(&self) -> Result<Hash512, Error> {
        let mut sorted = self.hashes;
        let records = sorted
            .get_mut(..usize::from(self.count))
            .ok_or(Error::Capacity)?;
        records.sort_unstable_by_key(|hash| hash.0);
        Ok(sorted_set_root(records)?)
    }
}

/// The fixed parts of a batch body.
struct BatchDraft<'r, 'c> {
    ranges: &'r [ModuleRange<'c>],
    records_root: Hash512,
    time_bucket: TimeBucket,
}

/// Where a box stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Accepting ballots.
    Open,
    /// Latched by a journal mismatch (VC-056).
    Faulted,
    /// The close entry is durable; the hash binds the close token.
    Closed { close_body: Hash512 },
}

/// The last scan-count attestation point (VC-052).
#[derive(Debug, Clone, Copy)]
pub(crate) struct ScanPoint {
    pub(crate) records: u64,
    pub(crate) bucket: u64,
    pub(crate) pending: bool,
}

/// The inputs of a close that only people and the host know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseInputs {
    /// Physical ballots counted independently by two clerks.
    pub paper: u64,
    /// Ballots received through the emergency slot.
    pub without_record: u64,
    /// Physical envelopes in the spoiled/quarantine bag.
    pub spoiled_envelopes: u64,
    /// Absentee profile: the envelope and sticker counts and the station's
    /// envelope accounting (required); in person: `None` (required).
    pub envelopes: Option<EnvelopeCounts>,
    /// Whether a `FallbackDeclared` event exists for this box.
    pub fallback_declared: bool,
    /// The sorted-set root of every record hash of the box, computed by the
    /// host from the journal (`ityv_ledger::merkle::sorted_set_root`). The
    /// unit signs it; the public verifier recomputes it from the published
    /// records, so a wrong value means `HOLD_REVIEW` (VC-027).
    pub record_set_root: Hash512,
    /// The digest of the applied seal numbers.
    pub seal_digest: Hash512,
}

/// Proof that this box's close entry is durable; consumed by
/// [`OpenBox::into_closed`], which accepts only the token of its own close.
#[derive(Debug, PartialEq, Eq)]
pub struct CloseToken {
    close_body: Hash512,
}

impl CloseToken {
    /// The object hash of the `BoxCloseBody` this token stands for.
    #[must_use]
    pub const fn close_body_hash(&self) -> &Hash512 {
        &self.close_body
    }
}

/// What [`OpenBox::prepare_close`] produces.
#[derive(Debug)]
pub struct CloseOutput<'w> {
    /// The `BoxCloseBody` object (schema 0x0007).
    pub body: &'w [u8],
    /// The device's hybrid signature over `body` (purpose `box-close`).
    pub device_sig: &'w [u8; HYBRID_SIG_LEN],
    /// The violated close invariants; non-empty means `HOLD_REVIEW`.
    pub verdict: Violations,
    /// Proof that the close entry is in the journal.
    pub token: CloseToken,
}

/// The totals of a box.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Totals {
    /// Cast records (journaled, not quarantined).
    pub records: u64,
    /// Visits with at least one cast ballot. Until the unit groups ballots
    /// into visits (ADR-0021), every cast record is its own visit.
    pub visits: u64,
    /// Records attested in closed batches.
    pub attested: u64,
    /// Ballots spoiled by a challenge.
    pub challenged: u64,
    /// Ballots quarantined.
    pub quarantined: u64,
}

/// A ballot box accepting ballots.
#[derive(Debug)]
pub struct OpenBox<'c> {
    pub(crate) config: &'c ElectionConfig<'c>,
    pub(crate) bases: ityv_crypto::Bases,
    pub(crate) marks: [u64; MAX_MODULES],
    pub(crate) attested_through: [u64; MAX_MODULES],
    pub(crate) journal_head: Hash512,
    pub(crate) last_bucket: u64,
    pub(crate) totals: Totals,
    pub(crate) batch: Batch,
    pub(crate) batch_index: u32,
    pub(crate) scan: ScanPoint,
    pub(crate) in_flight: Option<InFlight>,
    pub(crate) visit: Option<Visit<'c>>,
    pub(crate) next_ticket: u64,
    pub(crate) phase: Phase,
    pub(crate) paper_incidents: u64,
}

impl<'c> OpenBox<'c> {
    /// Opens a box at bucket `opened` (the `BoxOpened` event's bucket).
    #[must_use]
    pub fn open(config: &'c ElectionConfig<'c>, opened: TimeBucket) -> Self {
        Self {
            config,
            bases: ityv_crypto::Bases::derive(),
            marks: [0; MAX_MODULES],
            attested_through: [0; MAX_MODULES],
            journal_head: Hash512::ZERO,
            last_bucket: opened.get(),
            totals: Totals::default(),
            batch: Batch::new(),
            batch_index: 0,
            scan: ScanPoint {
                records: 0,
                bucket: opened.get(),
                pending: false,
            },
            in_flight: None,
            visit: None,
            next_ticket: 1,
            phase: Phase::Open,
            paper_incidents: 0,
        }
    }

    /// The configuration.
    #[must_use]
    pub const fn config(&self) -> &'c ElectionConfig<'c> {
        self.config
    }

    pub(crate) const fn bases(&self) -> &ityv_crypto::Bases {
        &self.bases
    }

    /// The head of the sealed journal (zero before the first entry). The
    /// host must not feed this value back to [`Self::close_batch`]: that
    /// check compares it with the head the host re-reads from storage.
    #[must_use]
    pub const fn journal_head(&self) -> &Hash512 {
        &self.journal_head
    }

    /// The totals so far.
    #[must_use]
    pub const fn totals(&self) -> Totals {
        self.totals
    }

    /// The latest time bucket the box used (the opening's, or the last
    /// journal entry's): every later entry must carry this bucket or a
    /// later one.
    #[must_use]
    pub const fn last_time_bucket(&self) -> TimeBucket {
        TimeBucket::new(self.last_bucket)
    }

    /// The high-water mark of every module counter, in configuration order.
    #[must_use]
    pub fn module_counters(&self) -> &[u64] {
        self.marks.get(..self.config.modules().len()).unwrap_or(&[])
    }

    /// Records in the open batch.
    #[must_use]
    pub const fn batch_records(&self) -> u16 {
        self.batch.count
    }

    /// The index the next batch will carry.
    #[must_use]
    pub const fn batch_index(&self) -> u32 {
        self.batch_index
    }

    /// `true` if the open batch must be closed before the next ballot
    /// (64 records, or a full bucket since its last record).
    #[must_use]
    pub const fn batch_due(&self, now: TimeBucket) -> bool {
        rules::batch_due(self.batch.count, self.batch.last_record_bucket, now.get())
    }

    /// `true` if a scan-count attestation is due (VC-052): fifty records or
    /// eight buckets since the last one, or the box was just resumed.
    #[must_use]
    pub fn scan_count_due(&self, now: TimeBucket) -> bool {
        let since = self.totals.records.saturating_sub(self.scan.records);
        self.scan.pending || rules::scan_count_due(since, self.scan.bucket, now.get())
    }

    /// `true` while a position is between interpretation and its binding
    /// to the visit.
    #[must_use]
    pub const fn has_ballot_in_flight(&self) -> bool {
        self.in_flight.is_some()
    }

    /// `true` while a visit is open: from its first interpretation until it
    /// is finished or abandoned.
    #[must_use]
    pub const fn has_visit_open(&self) -> bool {
        self.visit.is_some() || self.in_flight.is_some()
    }

    /// `Err` while a visit is open (batches, scan counts and the close are
    /// produced only between visits).
    pub(crate) const fn between_visits(&self) -> Result<(), Error> {
        if self.has_visit_open() {
            Err(Error::VisitOpen)
        } else {
            Ok(())
        }
    }

    /// Papers lost or unmatched at a resume (PROTOCOL.md §7.3 step 7); any
    /// makes the close `HOLD_REVIEW`.
    #[must_use]
    pub const fn paper_incidents(&self) -> u64 {
        self.paper_incidents
    }

    /// `true` once a journal mismatch latched the box (VC-056).
    #[must_use]
    pub const fn is_faulted(&self) -> bool {
        matches!(self.phase, Phase::Faulted)
    }

    /// `Ok` while the box accepts work.
    pub(crate) const fn usable(&self) -> Result<(), Error> {
        match self.phase {
            Phase::Open => Ok(()),
            Phase::Faulted => Err(Error::JournalMismatch),
            Phase::Closed { .. } => Err(Error::BoxClosed),
        }
    }

    /// `Ok` if `time_bucket` is not earlier than the last one used.
    pub(crate) const fn check_time(&self, time_bucket: TimeBucket) -> Result<(), Error> {
        if time_bucket.get() < self.last_bucket {
            Err(Error::TimeRegression)
        } else {
            Ok(())
        }
    }

    /// Starts the next position: of the open visit, or of a new visit if
    /// none is open. A new visit needs room for eight records in the open
    /// batch.
    pub(crate) fn begin_ballot(&mut self) -> Result<u64, Error> {
        self.usable()?;
        if self.in_flight.is_some() {
            return Err(Error::BallotInFlight);
        }
        if let Some(visit) = &self.visit {
            visit.accepts_position()?;
        } else {
            if self.batch.count > rules::BATCH_VISIT_START_MAX {
                return Err(Error::BatchFull);
            }
            let ticket = self.take_ticket()?;
            self.visit = Some(Visit::new(ticket));
        }
        let ticket = self.take_ticket()?;
        self.in_flight = Some(InFlight {
            ticket,
            counters: [0; MAX_MODULES],
            issued: [false; MAX_MODULES],
            record: None,
        });
        Ok(ticket)
    }

    /// A fresh ticket for a position or a visit.
    fn take_ticket(&mut self) -> Result<u64, Error> {
        let ticket = self.next_ticket;
        self.next_ticket = ticket.checked_add(1).ok_or(Error::Overflow)?;
        Ok(ticket)
    }

    pub(crate) fn check_ticket(&self, ticket: u64) -> Result<InFlight, Error> {
        match self.in_flight {
            Some(flight) if flight.ticket == ticket => Ok(flight),
            Some(_) => Err(Error::StaleBallot),
            None => Err(Error::NoBallotInFlight),
        }
    }

    /// Accepts `counter` from module `module` for the ballot `ticket` if it
    /// is the module's high-water mark plus one; a regression or a gap is
    /// refused and changes nothing (ADR-0017 개정 2).
    pub(crate) fn note_issue(
        &mut self,
        ticket: u64,
        module: usize,
        counter: u64,
    ) -> Result<(), Error> {
        let mut flight = self.check_ticket(ticket)?;
        let mark = self.marks.get_mut(module).ok_or(Error::Capacity)?;
        match rules::advance_mark(mark, counter) {
            CounterCheck::Next => {}
            CounterCheck::Regression => return Err(Error::CounterRegression),
            CounterCheck::Gap => return Err(Error::CounterGap),
        }
        *flight.counters.get_mut(module).ok_or(Error::Capacity)? = counter;
        *flight.issued.get_mut(module).ok_or(Error::Capacity)? = true;
        self.in_flight = Some(flight);
        Ok(())
    }

    /// The `ModuleCounters` of `counters` for the configured modules,
    /// skipping modules not in `include`.
    pub(crate) fn counter_list(
        &self,
        counters: &[u64; MAX_MODULES],
        include: [bool; MAX_MODULES],
    ) -> Result<ModuleCounters<'c>, Error> {
        let modules = self.config.modules();
        let first = modules.first().ok_or(Error::Capacity)?;
        let mut list = [ModuleCounter {
            module_id: first.module_id(),
            counter: 0,
        }; MAX_MODULES];
        let mut n = 0usize;
        for ((module, &counter), included) in modules.iter().zip(counters).zip(include) {
            if included {
                let slot = list.get_mut(n).ok_or(Error::Capacity)?;
                *slot = ModuleCounter {
                    module_id: module.module_id(),
                    counter,
                };
                n = n.checked_add(1).ok_or(Error::Overflow)?;
            }
        }
        ModuleCounters::new(list.get(..n).unwrap_or(&[])).ok_or(Error::Capacity)
    }

    /// Appends one journal entry, durable before this returns, and advances
    /// the head (ADR-0017 §7).
    pub(crate) fn journal(
        &mut self,
        sink: &mut dyn JournalSink,
        fields: &EntryFields<'_>,
        share_package: Option<&[u8]>,
    ) -> Result<(), Error> {
        self.journal_with(sink, fields, share_package, false)
    }

    /// Appends one journal entry, durable at once or (`deferred`) with the
    /// next durable one, and advances the head.
    pub(crate) fn journal_with(
        &mut self,
        sink: &mut dyn JournalSink,
        fields: &EntryFields<'_>,
        share_package: Option<&[u8]>,
        deferred: bool,
    ) -> Result<(), Error> {
        self.check_time(fields.time_bucket)?;
        let list = self.counter_list(fields.counters, fields.include)?;
        let entry = JournalEntry::new(
            self.journal_head,
            fields.kind,
            fields.record_hash,
            fields.share_package_hash,
            list,
            fields.time_bucket,
        );
        let mut buf = [0u8; MAX_JOURNAL_ENTRY_LEN];
        let len = encode_object(SCHEMA_JOURNAL_ENTRY, SCHEMA_VERSION_1, &entry, &mut buf)?;
        let bytes = buf.get(..len).ok_or(Error::BufferTooSmall)?;
        if deferred {
            sink.append_deferred(bytes, share_package)?;
        } else {
            sink.append(bytes, share_package)?;
        }
        self.journal_head = object_hash(bytes);
        self.last_bucket = fields.time_bucket.get();
        Ok(())
    }

    /// Puts a cast record into the open batch and counts it.
    pub(crate) fn push_record(
        &mut self,
        record_hash: Hash512,
        time_bucket: TimeBucket,
    ) -> Result<(), Error> {
        let slot = self
            .batch
            .hashes
            .get_mut(usize::from(self.batch.count))
            .ok_or(Error::BatchFull)?;
        *slot = record_hash;
        self.batch.count = self.batch.count.checked_add(1).ok_or(Error::Overflow)?;
        self.batch.last_record_bucket = time_bucket.get();
        self.totals.records = self.totals.records.checked_add(1).ok_or(Error::Overflow)?;
        Ok(())
    }

    /// Removes `record_hash` from the open batch (keeping the order of the
    /// others) and moves it from the record count to the quarantine count.
    pub(crate) fn withdraw_record(&mut self, record_hash: &Hash512) -> Result<(), Error> {
        let count = usize::from(self.batch.count);
        let records = self.batch.hashes.get_mut(..count).ok_or(Error::Capacity)?;
        let index = records
            .iter()
            .position(|hash| hash == record_hash)
            .ok_or(Error::StaleBallot)?;
        let tail = records.get_mut(index..).ok_or(Error::Capacity)?;
        tail.rotate_left(1);
        if let Some(last) = tail.last_mut() {
            *last = Hash512::ZERO;
        }
        self.batch.count = self.batch.count.checked_sub(1).ok_or(Error::BatchEmpty)?;
        self.totals.records = self.totals.records.checked_sub(1).ok_or(Error::Overflow)?;
        self.count_quarantine()
    }

    /// Counts one quarantined ballot.
    pub(crate) fn count_quarantine(&mut self) -> Result<(), Error> {
        self.totals.quarantined = self
            .totals
            .quarantined
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        Ok(())
    }

    /// The attested range of every module for the open batch: from the
    /// counter after the last attested one to the high-water mark.
    fn batch_ranges(&self) -> Result<[ModuleRange<'c>; MAX_MODULES], Error> {
        let modules = self.config.modules();
        let first = modules.first().ok_or(Error::Capacity)?;
        let mut ranges = [ModuleRange {
            module_id: first.module_id(),
            counter_first: 0,
            counter_last: 0,
        }; MAX_MODULES];
        for (((slot, module), &last), &through) in ranges
            .iter_mut()
            .zip(modules)
            .zip(&self.marks)
            .zip(&self.attested_through)
        {
            let counter_first = through.checked_add(1).ok_or(Error::Overflow)?;
            if counter_first > last {
                return Err(Error::CounterGap);
            }
            *slot = ModuleRange {
                module_id: module.module_id(),
                counter_first,
                counter_last: last,
            };
        }
        Ok(ranges)
    }

    /// Writes the final `BatchAttestBody` object, listing the modules that
    /// did not consent in `module_refusals`.
    fn batch_body(
        &self,
        draft: &BatchDraft<'_, 'c>,
        consent: [bool; MAX_MODULES],
        out: &mut [u8; MAX_BATCH_BODY_LEN],
    ) -> Result<usize, Error> {
        let modules = self.config.modules();
        let first = modules.first().ok_or(Error::Capacity)?;
        let mut refused_ids = [first.module_id(); MAX_MODULES];
        let mut n_refused = 0usize;
        for (module, consented) in modules.iter().zip(consent) {
            if !consented {
                *refused_ids.get_mut(n_refused).ok_or(Error::Capacity)? = module.module_id();
                n_refused = n_refused.checked_add(1).ok_or(Error::Overflow)?;
            }
        }
        let refusals =
            ModuleIds::new(refused_ids.get(..n_refused).unwrap_or(&[])).ok_or(Error::Capacity)?;
        let body = BatchAttestBody::new(&BatchAttestParts {
            election_id: self.config.election_id(),
            box_id: self.config.box_id(),
            batch_index: self.batch_index,
            record_count: self.batch.count,
            records_root: draft.records_root,
            module_ranges: draft.ranges,
            module_refusals: refusals,
            journal_head: self.journal_head,
            time_bucket: draft.time_bucket,
        })
        .ok_or(Error::Capacity)?;
        Ok(encode_object(
            SCHEMA_BATCH_ATTEST_BODY,
            SCHEMA_VERSION_1,
            &body,
            out,
        )?)
    }

    /// Asks every consenting module once for its signature over the final
    /// body and verifies it with the module's genesis key; the signatures
    /// land in the module slots of `sig_region`, one per module in
    /// configuration order.
    fn collect_batch_signatures(
        &self,
        ports: &mut [&mut dyn ModulePort],
        consent: [bool; MAX_MODULES],
        body: &[u8],
        sig_region: &mut [u8],
    ) -> Result<(), Error> {
        let batch_purpose = purpose(PURPOSE_BATCH_ATTEST)?;
        for (((port, module), consented), chunk) in ports
            .iter_mut()
            .zip(self.config.modules())
            .zip(consent)
            .zip(sig_region.chunks_exact_mut(HYBRID_SIG_LEN))
        {
            if consented {
                let sig = port.sign_batch(body)?;
                let verified = verify_hybrid(module.batch_key(), &batch_purpose, body, &sig)
                    .map_err(|_| Error::BatchSignature)?;
                let slot: &mut [u8; HYBRID_SIG_LEN] =
                    chunk.try_into().map_err(|_| Error::Capacity)?;
                write_hybrid(verified.get().signature(), slot)?;
            }
        }
        Ok(())
    }

    /// Closes the open batch (PROTOCOL.md §7.2.1, ADR-0017 개정 6–7).
    ///
    /// First every precondition: the box is usable, no visit is open,
    /// `host_head` (which the host must re-read from storage, not
    /// copy from [`Self::journal_head`]) equals the head in memory, the
    /// batch is not empty, one port per module, `time_bucket` is not
    /// earlier than the last, `work` holds [`BATCH_WORK_LEN`] bytes. A head
    /// mismatch latches the box faulted (VC-056). Then every module
    /// answers the dry run [`ModulePort::check_batch`]; the final
    /// `BatchAttestBody` lists the modules that did not consent; each
    /// consenting module signs it exactly once and its signature is
    /// verified. The device signs, the batch-close entry (kind 4,
    /// `record_hash` = the records root) is journaled, and the
    /// `BatchAttest` object is returned from `work`.
    ///
    /// # Errors
    /// [`Error::BoxClosed`], [`Error::JournalMismatch`],
    /// [`Error::VisitOpen`], [`Error::BatchEmpty`],
    /// [`Error::PortCount`], [`Error::TimeRegression`],
    /// [`Error::BufferTooSmall`], [`Error::BatchSignature`], port, signing,
    /// encoding and journal errors. The batch stays open on error.
    pub fn close_batch<'w>(
        &mut self,
        host_head: &Hash512,
        ports: &mut [&mut dyn ModulePort],
        signer: Signer<'_>,
        sink: &mut dyn JournalSink,
        time_bucket: TimeBucket,
        work: &'w mut [u8],
    ) -> Result<&'w [u8], Error> {
        self.usable()?;
        self.between_visits()?;
        if *host_head != self.journal_head {
            self.phase = Phase::Faulted;
            return Err(Error::JournalMismatch);
        }
        if self.batch.count == 0 {
            return Err(Error::BatchEmpty);
        }
        let modules = self.config.modules();
        if ports.len() != modules.len() {
            return Err(Error::PortCount);
        }
        self.check_time(time_bucket)?;
        if work.len() < BATCH_WORK_LEN {
            return Err(Error::BufferTooSmall);
        }
        let (sig_region, out) = work
            .split_at_mut_checked(BATCH_SIG_REGION_LEN)
            .ok_or(Error::BufferTooSmall)?;
        let records_root = self.batch.root()?;
        let all_ranges = self.batch_ranges()?;
        let ranges = all_ranges.get(..modules.len()).ok_or(Error::Capacity)?;

        let mut consent = [false; MAX_MODULES];
        for ((port, range), slot) in ports.iter_mut().zip(ranges).zip(consent.iter_mut()) {
            *slot = port.check_batch(range.counter_first, range.counter_last)?;
        }
        let draft = BatchDraft {
            ranges,
            records_root,
            time_bucket,
        };
        let mut body_buf = [0u8; MAX_BATCH_BODY_LEN];
        let body_len = self.batch_body(&draft, consent, &mut body_buf)?;
        let body_bytes = body_buf.get(..body_len).ok_or(Error::BufferTooSmall)?;
        self.collect_batch_signatures(ports, consent, body_bytes, sig_region)?;
        let (module_chunks, device_chunk) = sig_region
            .split_at_mut_checked(MAX_MODULES * HYBRID_SIG_LEN)
            .ok_or(Error::BufferTooSmall)?;
        let device_slot: &mut [u8; HYBRID_SIG_LEN] =
            device_chunk.try_into().map_err(|_| Error::Capacity)?;
        signer.sign_into(PURPOSE_BATCH_ATTEST, body_bytes, device_slot)?;
        let len = self.assemble_batch(body_bytes, module_chunks, device_slot, consent, out)?;

        let marks = self.marks;
        self.journal(
            sink,
            &EntryFields {
                kind: JournalKind::BatchClose,
                record_hash: records_root,
                share_package_hash: Hash512::ZERO,
                counters: &marks,
                include: [true; MAX_MODULES],
                time_bucket,
            },
            None,
        )?;
        self.settle_batch()?;
        out.get(..len).ok_or(Error::BufferTooSmall)
    }

    /// Moves the open batch into the attested totals after its entry.
    pub(crate) fn settle_batch(&mut self) -> Result<(), Error> {
        self.totals.attested = self
            .totals
            .attested
            .checked_add(u64::from(self.batch.count))
            .ok_or(Error::Overflow)?;
        self.attested_through = self.marks;
        self.batch = Batch::new();
        self.batch_index = self.batch_index.checked_add(1).ok_or(Error::Overflow)?;
        Ok(())
    }

    /// Writes the `BatchAttest` object from the body, the signatures of the
    /// modules that signed, and the device signature.
    fn assemble_batch(
        &self,
        body_bytes: &[u8],
        module_chunks: &[u8],
        device_slot: &[u8; HYBRID_SIG_LEN],
        signed: [bool; MAX_MODULES],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let modules = self.config.modules();
        let first = modules.first().ok_or(Error::Capacity)?;
        let mut sig_list = [ModuleBatchSig {
            module_id: first.module_id(),
            sig: device_slot,
        }; MAX_MODULES];
        let mut n_sigs = 0usize;
        for ((module, chunk), is_signed) in modules
            .iter()
            .zip(module_chunks.chunks_exact(HYBRID_SIG_LEN))
            .zip(signed)
        {
            if is_signed {
                let sig: &[u8; HYBRID_SIG_LEN] = chunk.try_into().map_err(|_| Error::Capacity)?;
                *sig_list.get_mut(n_sigs).ok_or(Error::Capacity)? = ModuleBatchSig {
                    module_id: module.module_id(),
                    sig,
                };
                n_sigs = n_sigs.checked_add(1).ok_or(Error::Overflow)?;
            }
        }
        let attest = BatchAttest::new(
            body_bytes,
            sig_list.get(..n_sigs).unwrap_or(&[]),
            device_slot,
        )?;
        Ok(encode_object(
            SCHEMA_BATCH_ATTEST,
            SCHEMA_VERSION_1,
            &attest,
            out,
        )?)
    }

    /// Writes a `ScanCountAttestBody` object (VC-052) into `work` and marks
    /// the attestation point. The observers' signatures are added outside
    /// the unit. Refused while a visit is open (PROTOCOL.md §7.8), so the
    /// counts and the head it attests never move backwards.
    ///
    /// # Errors
    /// [`Error::BoxClosed`], [`Error::JournalMismatch`],
    /// [`Error::VisitOpen`], [`Error::TimeRegression`] or an encoding
    /// error.
    pub fn scan_count_body<'w>(
        &mut self,
        time_bucket: TimeBucket,
        work: &'w mut [u8],
    ) -> Result<&'w [u8], Error> {
        self.usable()?;
        self.between_visits()?;
        self.check_time(time_bucket)?;
        let body = ScanCountAttestBody::new(
            self.config.election_id(),
            self.config.box_id(),
            self.totals.records,
            self.totals.challenged,
            self.totals.quarantined,
            self.journal_head,
            time_bucket,
        );
        let len = encode_object(SCHEMA_SCAN_COUNT_ATTEST_BODY, SCHEMA_VERSION_1, &body, work)?;
        self.scan = ScanPoint {
            records: self.totals.records,
            bucket: time_bucket.get(),
            pending: false,
        };
        self.last_bucket = time_bucket.get();
        work.get(..len).ok_or(Error::BufferTooSmall)
    }

    /// The facts of VC-038 for this box and `inputs`.
    #[must_use]
    pub fn close_facts<'s>(&'s self, inputs: &CloseInputs) -> CloseFacts<'s> {
        CloseFacts {
            paper: inputs.paper,
            records: self.totals.records,
            visits: self.totals.visits,
            attested: self.totals.attested,
            open_batch_records: u64::from(self.batch.count),
            without_record: inputs.without_record,
            challenged: self.totals.challenged,
            quarantined: self.totals.quarantined,
            spoiled_envelopes: inputs.spoiled_envelopes,
            module_final_counters: self.module_counters(),
            open_batches: u8::from(self.batch.count > 0),
            envelopes: inputs.envelopes,
            fallback_declared: inputs.fallback_declared,
            paper_incidents: self.paper_incidents,
        }
    }

    /// Closes the box (PROTOCOL.md §10.2): checks every precondition (the
    /// box is usable, no visit open, the time bucket, the envelope
    /// count against the profile, `work` holds [`CLOSE_WORK_LEN`] bytes),
    /// evaluates the VC-038 invariants, writes the `BoxCloseBody` object
    /// and the device signature into `work`, journals the close entry
    /// (kind 5, `record_hash` = the record set root) and marks the box
    /// closed. The close is recorded even when invariants are violated; the
    /// verdict then means `HOLD_REVIEW`. Call [`Self::into_closed`] with the
    /// returned token.
    ///
    /// # Errors
    /// [`Error::BoxClosed`], [`Error::JournalMismatch`],
    /// [`Error::VisitOpen`], [`Error::TimeRegression`],
    /// [`Error::EnvelopeCountProfile`], [`Error::BufferTooSmall`],
    /// signing, encoding and journal errors; the box stays open on error.
    pub fn prepare_close<'w>(
        &mut self,
        inputs: &CloseInputs,
        signer: Signer<'_>,
        sink: &mut dyn JournalSink,
        time_bucket: TimeBucket,
        work: &'w mut [u8],
    ) -> Result<CloseOutput<'w>, Error> {
        self.usable()?;
        self.between_visits()?;
        self.check_time(time_bucket)?;
        let absentee = matches!(self.config.profile(), Profile::Absentee);
        if inputs.envelopes.is_some() != absentee {
            return Err(Error::EnvelopeCountProfile);
        }
        if work.len() < CLOSE_WORK_LEN {
            return Err(Error::BufferTooSmall);
        }
        let verdict = rules::close_verdict(&self.close_facts(inputs));
        let marks = self.marks;
        let module_counters = self.counter_list(&marks, [true; MAX_MODULES])?;
        let body = BoxCloseBody::new(&BoxCloseParts {
            election_id: self.config.election_id(),
            box_id: self.config.box_id(),
            counts: CloseCounts {
                paper: inputs.paper,
                records: self.totals.records,
                attested: self.totals.attested,
                without_record: inputs.without_record,
                challenged: self.totals.challenged,
                quarantined: self.totals.quarantined,
                visits: self.totals.visits,
                envelopes: inputs.envelopes.map_or(0, |e| e.envelopes),
                stickers: inputs.envelopes.map_or(0, |e| e.stickers),
                spoil_envelopes: inputs.spoiled_envelopes,
            },
            record_set_root: inputs.record_set_root,
            journal_head: self.journal_head,
            seal_digest: inputs.seal_digest,
            module_counters,
            open_batches: u8::from(self.batch.count > 0),
            time_bucket,
        });
        let (body_region, sig_region) = work
            .split_at_mut_checked(MAX_BOX_CLOSE_BODY_LEN)
            .ok_or(Error::BufferTooSmall)?;
        let len = encode_object(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, &body, body_region)?;
        let body_bytes: &'w [u8] = body_region;
        let body_bytes = body_bytes.get(..len).ok_or(Error::BufferTooSmall)?;
        let slot: &'w mut [u8; HYBRID_SIG_LEN] = sig_region
            .get_mut(..HYBRID_SIG_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::BufferTooSmall)?;
        signer.sign_into(PURPOSE_BOX_CLOSE, body_bytes, slot)?;
        self.journal(
            sink,
            &EntryFields {
                kind: JournalKind::BoxClose,
                record_hash: inputs.record_set_root,
                share_package_hash: Hash512::ZERO,
                counters: &marks,
                include: [true; MAX_MODULES],
                time_bucket,
            },
            None,
        )?;
        let close_body = object_hash(body_bytes);
        self.phase = Phase::Closed { close_body };
        Ok(CloseOutput {
            body: body_bytes,
            device_sig: slot,
            verdict,
            token: CloseToken { close_body },
        })
    }

    /// Turns a box whose close entry is durable into a [`ClosedBox`]. The
    /// token must be the one [`Self::prepare_close`] returned for this box.
    ///
    /// # Errors
    /// [`Error::ForeignCloseToken`] if the box is not closed or the token
    /// belongs to another close; the box is dropped (its close entry is
    /// durable either way).
    pub fn into_closed(self, token: CloseToken) -> Result<ClosedBox<'c>, Error> {
        match self.phase {
            Phase::Closed { close_body } if close_body == token.close_body => Ok(ClosedBox {
                config: self.config,
                totals: self.totals,
                journal_head: self.journal_head,
                marks: self.marks,
                token,
            }),
            Phase::Open | Phase::Faulted | Phase::Closed { .. } => Err(Error::ForeignCloseToken),
        }
    }
}

/// A closed box. It has no method that accepts a ballot, a batch or a
/// scan count: after close, the box's `box_id` takes no new record (VC-039).
///
/// ```compile_fail
/// # fn closed_box_has_no_interpret(
/// #     closed: ityv_cunit::boxstate::ClosedBox<'_>,
/// #     work: &mut ityv_cunit::ballot::BallotWork,
/// # ) {
/// let _ = closed.interpret(&[], work);
/// # }
/// ```
///
/// The same call compiles on an open box:
///
/// ```
/// # fn open_box_interprets(
/// #     open: &mut ityv_cunit::boxstate::OpenBox<'_>,
/// #     work: &mut ityv_cunit::ballot::BallotWork,
/// # ) {
/// let _ = open.interpret(&[], work);
/// # }
/// ```
#[derive(Debug)]
pub struct ClosedBox<'c> {
    config: &'c ElectionConfig<'c>,
    totals: Totals,
    journal_head: Hash512,
    marks: [u64; MAX_MODULES],
    token: CloseToken,
}

impl<'c> ClosedBox<'c> {
    /// The configuration.
    #[must_use]
    pub const fn config(&self) -> &'c ElectionConfig<'c> {
        self.config
    }

    /// The final totals.
    #[must_use]
    pub const fn totals(&self) -> Totals {
        self.totals
    }

    /// The final journal head (after the close entry).
    #[must_use]
    pub const fn journal_head(&self) -> &Hash512 {
        &self.journal_head
    }

    /// The final module counters, in configuration order.
    #[must_use]
    pub fn module_counters(&self) -> &[u64] {
        self.marks.get(..self.config.modules().len()).unwrap_or(&[])
    }

    /// The object hash of the signed `BoxCloseBody`.
    #[must_use]
    pub const fn close_body_hash(&self) -> &Hash512 {
        self.token.close_body_hash()
    }
}
