//! Box accounting: the journal chain, batches, scan counts and close
//! (PROTOCOL.md §7.2.1, §7.8, §10.2; ADR-0017 §7–§9).
//!
//! An [`OpenBox`] owns the state that outlives one ballot: the module
//! counters seen so far, the journal head, the open batch, the totals and
//! the ballot in flight. Ballots are processed one at a time: a new
//! interpretation is refused while a ballot is in flight, and a batch can
//! be closed only between ballots, so every counter a batch attests belongs
//! to a ballot whose journal entry already exists.
//!
//! [`OpenBox::prepare_close`] writes the close entry and marks the box
//! closed at run time; [`OpenBox::into_closed`] then turns it into a
//! [`ClosedBox`], which has no method that accepts a ballot.

use ityv_crypto::{HybridSignature, HybridSigningKey, Purpose, object_hash, sign_hybrid};
use ityv_encoding::{
    BatchAttest, BatchAttestBody, BatchAttestParts, BoxCloseBody, BoxCloseParts, CloseCounts,
    Encode, HYBRID_SIG_LEN, Hash512, MAX_BATCH_BODY_LEN, MAX_BOX_CLOSE_BODY_LEN, ModuleBatchSig,
    ModuleCounter, ModuleCounters, ModuleIds, ModuleRange, SCHEMA_BATCH_ATTEST,
    SCHEMA_BATCH_ATTEST_BODY, SCHEMA_BOX_CLOSE_BODY, SCHEMA_SCAN_COUNT_ATTEST_BODY,
    SCHEMA_VERSION_1, ScanCountAttestBody, TimeBucket, Writer, encode_object,
};
use ityv_ledger::merkle::sorted_set_root;

use crate::config::{ElectionConfig, MAX_MODULES};
use crate::error::Error;
use crate::link::{JournalEntry, JournalKind, MAX_JOURNAL_ENTRY_LEN, SCHEMA_JOURNAL_ENTRY};
use crate::port::{JournalSink, ModulePort};
use crate::rng::DeviceRng;
use crate::rules::{self, BATCH_MAX_RECORDS, CloseFacts, Violations};

/// Purpose of the batch attestation signatures.
pub const PURPOSE_BATCH_ATTEST: &[u8] = b"batch-attest";
/// Purpose of the device's box-close signature.
pub const PURPOSE_BOX_CLOSE: &[u8] = b"box-close";
/// Bytes of a `BatchAttest` object at most, header included:
/// 16 + (4 + 1214) + (4 + 6·(68 + 4691)) + 4691.
pub const MAX_BATCH_ATTEST_LEN: usize = 34_483;
/// Work buffer [`OpenBox::close_batch`] needs: seven hybrid signatures and
/// the `BatchAttest` object.
pub const BATCH_WORK_LEN: usize = 7 * HYBRID_SIG_LEN + MAX_BATCH_ATTEST_LEN;
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

/// The ballot currently between interpretation and its terminal journal
/// entry, with the counters it has consumed so far.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InFlight {
    pub(crate) ticket: u64,
    pub(crate) counters: [u64; MAX_MODULES],
    pub(crate) issued: [bool; MAX_MODULES],
}

/// The open batch: the record hashes it holds and the bucket of its last
/// record.
#[derive(Debug, Clone, Copy)]
struct Batch {
    hashes: [Hash512; BATCH_CAP],
    count: u16,
    last_record_bucket: u64,
}

impl Batch {
    const fn new() -> Self {
        Self {
            hashes: [Hash512::ZERO; BATCH_CAP],
            count: 0,
            last_record_bucket: 0,
        }
    }
}

/// The fixed parts of a batch body while modules are asked to sign.
struct BatchDraft<'r, 'c> {
    ranges: &'r [ModuleRange<'c>],
    records_root: Hash512,
    time_bucket: TimeBucket,
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
    /// Absentee profile: physical envelopes; `None` in person.
    pub absentee_envelopes: Option<u64>,
    /// Whether a `FallbackDeclared` event exists for this box.
    pub fallback_declared: bool,
    /// The sorted-set root of every record hash of the box, computed by the
    /// host from the journal (`ityv_ledger::merkle::sorted_set_root`). The
    /// public verifier recomputes it from the published records (VC-027).
    pub record_set_root: Hash512,
    /// The digest of the applied seal numbers.
    pub seal_digest: Hash512,
}

/// Proof that the close entry is durable; consumed by
/// [`OpenBox::into_closed`].
#[derive(Debug)]
pub struct CloseToken(());

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
    /// Cast records (imprinted, not quarantined).
    pub records: u64,
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
    config: &'c ElectionConfig<'c>,
    bases: ityv_crypto::Bases,
    pub(crate) counters: [u64; MAX_MODULES],
    attested_through: [u64; MAX_MODULES],
    journal_head: Hash512,
    last_bucket: u64,
    pub(crate) totals: Totals,
    batch: Batch,
    batch_index: u32,
    scan_records: u64,
    scan_bucket: u64,
    pub(crate) in_flight: Option<InFlight>,
    next_ticket: u64,
    closing: bool,
}

impl<'c> OpenBox<'c> {
    /// Opens a box at bucket `opened` (the `BoxOpened` event's bucket).
    #[must_use]
    pub fn open(config: &'c ElectionConfig<'c>, opened: TimeBucket) -> Self {
        Self {
            config,
            bases: ityv_crypto::Bases::derive(),
            counters: [0; MAX_MODULES],
            attested_through: [0; MAX_MODULES],
            journal_head: Hash512::ZERO,
            last_bucket: opened.get(),
            totals: Totals::default(),
            batch: Batch::new(),
            batch_index: 0,
            scan_records: 0,
            scan_bucket: opened.get(),
            in_flight: None,
            next_ticket: 1,
            closing: false,
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

    /// The head of the sealed journal (zero before the first entry).
    #[must_use]
    pub const fn journal_head(&self) -> &Hash512 {
        &self.journal_head
    }

    /// The totals so far.
    #[must_use]
    pub const fn totals(&self) -> Totals {
        self.totals
    }

    /// The last counter seen from each module, in configuration order.
    #[must_use]
    pub fn module_counters(&self) -> &[u64] {
        self.counters
            .get(..self.config.modules().len())
            .unwrap_or(&[])
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

    /// `true` if a scan-count attestation is due (VC-052).
    #[must_use]
    pub fn scan_count_due(&self, now: TimeBucket) -> bool {
        let since = self.totals.records.saturating_sub(self.scan_records);
        rules::scan_count_due(since, self.scan_bucket, now.get())
    }

    /// `true` while a ballot is between interpretation and its terminal
    /// journal entry.
    #[must_use]
    pub const fn has_ballot_in_flight(&self) -> bool {
        self.in_flight.is_some()
    }

    pub(crate) fn begin_ballot(&mut self) -> Result<u64, Error> {
        if self.closing {
            return Err(Error::BoxClosed);
        }
        if self.in_flight.is_some() {
            return Err(Error::BallotInFlight);
        }
        if self.batch.count >= BATCH_MAX_RECORDS {
            return Err(Error::BatchFull);
        }
        let ticket = self.next_ticket;
        self.next_ticket = ticket.checked_add(1).ok_or(Error::Overflow)?;
        self.in_flight = Some(InFlight {
            ticket,
            counters: [0; MAX_MODULES],
            issued: [false; MAX_MODULES],
        });
        Ok(ticket)
    }

    pub(crate) fn check_ticket(&self, ticket: u64) -> Result<InFlight, Error> {
        match self.in_flight {
            Some(flight) if flight.ticket == ticket => Ok(flight),
            Some(_) => Err(Error::StaleBallot),
            None => Err(Error::NoBallotInFlight),
        }
    }

    pub(crate) fn note_issue(
        &mut self,
        ticket: u64,
        module: usize,
        counter: u64,
    ) -> Result<(), Error> {
        let mut flight = self.check_ticket(ticket)?;
        let slot = self.counters.get_mut(module).ok_or(Error::Capacity)?;
        *slot = counter;
        *flight.counters.get_mut(module).ok_or(Error::Capacity)? = counter;
        *flight.issued.get_mut(module).ok_or(Error::Capacity)? = true;
        self.in_flight = Some(flight);
        Ok(())
    }

    pub(crate) fn end_ballot(&mut self, ticket: u64) -> Result<(), Error> {
        self.check_ticket(ticket)?;
        self.in_flight = None;
        Ok(())
    }

    /// The `ModuleCounters` of `counters` for the configured modules,
    /// skipping modules not in `include`.
    pub(crate) fn counter_list(
        &self,
        counters: &[u64; MAX_MODULES],
        include: [bool; MAX_MODULES],
    ) -> Result<Option<ModuleCounters<'c>>, Error> {
        let modules = self.config.modules();
        let Some(first) = modules.first() else {
            return Err(Error::Capacity);
        };
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
        if n == 0 {
            return Ok(None);
        }
        ModuleCounters::new(list.get(..n).unwrap_or(&[]))
            .map(Some)
            .ok_or(Error::Capacity)
    }

    /// Appends one journal entry and advances the head (ADR-0017 §7).
    #[expect(
        clippy::too_many_arguments,
        reason = "one argument per journal entry field"
    )]
    pub(crate) fn journal(
        &mut self,
        sink: &mut dyn JournalSink,
        kind: JournalKind,
        record_hash: Hash512,
        share_package_hash: Hash512,
        counters: &[u64; MAX_MODULES],
        include: [bool; MAX_MODULES],
        time_bucket: TimeBucket,
        share_package: Option<&[u8]>,
    ) -> Result<(), Error> {
        if time_bucket.get() < self.last_bucket {
            return Err(Error::TimeRegression);
        }
        let Some(list) = self.counter_list(counters, include)? else {
            return Err(Error::Capacity);
        };
        let entry = JournalEntry::new(
            self.journal_head,
            kind,
            record_hash,
            share_package_hash,
            list,
            time_bucket,
        );
        let mut buf = [0u8; MAX_JOURNAL_ENTRY_LEN];
        let len = encode_object(SCHEMA_JOURNAL_ENTRY, SCHEMA_VERSION_1, &entry, &mut buf)?;
        let bytes = buf.get(..len).ok_or(Error::BufferTooSmall)?;
        sink.append(bytes, share_package)?;
        self.journal_head = object_hash(bytes);
        self.last_bucket = time_bucket.get();
        Ok(())
    }

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

    /// Removes the last record of the open batch after an imprint failure.
    pub(crate) fn withdraw_record(&mut self, record_hash: &Hash512) -> Result<(), Error> {
        let last = self.batch.count.checked_sub(1).ok_or(Error::BatchEmpty)?;
        let slot = self
            .batch
            .hashes
            .get_mut(usize::from(last))
            .ok_or(Error::Capacity)?;
        if slot != record_hash {
            return Err(Error::StaleBallot);
        }
        *slot = Hash512::ZERO;
        self.batch.count = last;
        self.totals.records = self.totals.records.checked_sub(1).ok_or(Error::Overflow)?;
        Ok(())
    }

    /// Journals the ballot in flight as quarantined (kind 3) when its value
    /// was lost (link failure during issue, a dropped ballot, a journal
    /// failure at cast). A ballot that consumed no module counter is
    /// returned to the voter instead and leaves no entry. Any ballot value
    /// still held becomes stale.
    ///
    /// # Errors
    /// [`Error::NoBallotInFlight`], or the journal's error.
    pub fn quarantine_in_flight(
        &mut self,
        sink: &mut dyn JournalSink,
        time_bucket: TimeBucket,
    ) -> Result<(), Error> {
        let flight = self.in_flight.ok_or(Error::NoBallotInFlight)?;
        if flight.issued.iter().any(|&issued| issued) {
            self.journal(
                sink,
                JournalKind::Quarantine,
                Hash512::ZERO,
                Hash512::ZERO,
                &flight.counters,
                flight.issued,
                time_bucket,
                None,
            )?;
            self.totals.quarantined = self
                .totals
                .quarantined
                .checked_add(1)
                .ok_or(Error::Overflow)?;
        }
        self.in_flight = None;
        Ok(())
    }

    /// The attested range of every module for the open batch: from the
    /// counter after the last attested one to the last counter seen.
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
            .zip(&self.counters)
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

    /// Asks every module to sign the batch body, listing refusing modules
    /// in the body and asking the others again until no new module refuses.
    /// Returns the final body length in `body_buf` and which modules signed;
    /// their signatures are in the first six slots of `sig_region`.
    fn collect_batch_signatures(
        &self,
        draft: &BatchDraft<'_, 'c>,
        ports: &mut [&mut dyn ModulePort],
        sig_region: &mut [u8],
        body_buf: &mut [u8; MAX_BATCH_BODY_LEN],
    ) -> Result<(usize, [bool; MAX_MODULES]), Error> {
        let modules = self.config.modules();
        let first = modules.first().ok_or(Error::Capacity)?;
        let mut refused = [false; MAX_MODULES];
        loop {
            let mut refused_ids = [first.module_id(); MAX_MODULES];
            let mut n_refused = 0usize;
            for (module, &is_refused) in modules.iter().zip(&refused) {
                if is_refused {
                    *refused_ids.get_mut(n_refused).ok_or(Error::Capacity)? = module.module_id();
                    n_refused = n_refused.checked_add(1).ok_or(Error::Overflow)?;
                }
            }
            let refusals = ModuleIds::new(refused_ids.get(..n_refused).unwrap_or(&[]))
                .ok_or(Error::Capacity)?;
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
            let len = encode_object(SCHEMA_BATCH_ATTEST_BODY, SCHEMA_VERSION_1, &body, body_buf)?;
            let body_bytes = body_buf.get(..len).ok_or(Error::BufferTooSmall)?;
            let mut new_refusal = false;
            let mut signed = [false; MAX_MODULES];
            for ((port, chunk), (is_refused, is_signed)) in ports
                .iter_mut()
                .zip(sig_region.chunks_exact_mut(HYBRID_SIG_LEN))
                .zip(refused.iter_mut().zip(signed.iter_mut()))
            {
                if *is_refused {
                    continue;
                }
                if let Some(sig) = port.sign_batch(body_bytes)? {
                    let slot: &mut [u8; HYBRID_SIG_LEN] =
                        chunk.try_into().map_err(|_| Error::Capacity)?;
                    write_hybrid(&sig, slot)?;
                    *is_signed = true;
                } else {
                    *is_refused = true;
                    new_refusal = true;
                }
            }
            if !new_refusal {
                return Ok((len, signed));
            }
        }
    }

    /// Closes the open batch (PROTOCOL.md §7.2.1): checks the journal head
    /// the host re-read from storage against the head in memory (VC-056),
    /// asks every module to sign the `BatchAttestBody` (listing refusing
    /// modules in the body and asking the others again), signs it with the
    /// device key, journals a batch-close entry (kind 4, `record_hash` =
    /// the batch's records root) and returns the `BatchAttest` object
    /// written into `work` (at least [`BATCH_WORK_LEN`] bytes).
    ///
    /// # Errors
    /// [`Error::BallotInFlight`], [`Error::JournalMismatch`],
    /// [`Error::BatchEmpty`], [`Error::PortCount`], port, signing, encoding
    /// and journal errors.
    #[expect(
        clippy::too_many_arguments,
        reason = "host-supplied capabilities of one operation"
    )]
    pub fn close_batch<'w>(
        &mut self,
        host_head: &Hash512,
        ports: &mut [&mut dyn ModulePort],
        device_key: &HybridSigningKey,
        signing_seed: &[u8; 32],
        sink: &mut dyn JournalSink,
        time_bucket: TimeBucket,
        work: &'w mut [u8],
    ) -> Result<&'w [u8], Error> {
        if self.closing {
            return Err(Error::BoxClosed);
        }
        if self.in_flight.is_some() {
            return Err(Error::BallotInFlight);
        }
        if *host_head != self.journal_head {
            return Err(Error::JournalMismatch);
        }
        if self.batch.count == 0 {
            return Err(Error::BatchEmpty);
        }
        let modules = self.config.modules();
        if ports.len() != modules.len() {
            return Err(Error::PortCount);
        }
        let mut sorted = self.batch.hashes;
        let records = sorted
            .get_mut(..usize::from(self.batch.count))
            .ok_or(Error::Capacity)?;
        records.sort_unstable_by_key(|hash| hash.0);
        let records_root = sorted_set_root(records)?;
        let all_ranges = self.batch_ranges()?;
        let draft = BatchDraft {
            ranges: all_ranges.get(..modules.len()).ok_or(Error::Capacity)?,
            records_root,
            time_bucket,
        };

        let (sig_region, out) = work
            .split_at_mut_checked(7 * HYBRID_SIG_LEN)
            .ok_or(Error::BufferTooSmall)?;
        let mut body_buf = [0u8; MAX_BATCH_BODY_LEN];
        let (body_len, signed) =
            self.collect_batch_signatures(&draft, ports, sig_region, &mut body_buf)?;
        let body_bytes = body_buf.get(..body_len).ok_or(Error::BufferTooSmall)?;
        let device_sig = sign_hybrid(
            device_key,
            &purpose(PURPOSE_BATCH_ATTEST)?,
            body_bytes,
            &mut DeviceRng::for_signing(signing_seed),
        )?;
        let (module_chunks, device_chunk) = sig_region.split_at_mut(6 * HYBRID_SIG_LEN);
        let device_slot: &mut [u8; HYBRID_SIG_LEN] =
            device_chunk.try_into().map_err(|_| Error::Capacity)?;
        write_hybrid(&device_sig, device_slot)?;
        let len = self.assemble_batch(body_bytes, module_chunks, device_slot, signed, out)?;

        let counters = self.counters;
        let include = [true; MAX_MODULES];
        self.journal(
            sink,
            JournalKind::BatchClose,
            records_root,
            Hash512::ZERO,
            &counters,
            include,
            time_bucket,
            None,
        )?;
        self.totals.attested = self
            .totals
            .attested
            .checked_add(u64::from(self.batch.count))
            .ok_or(Error::Overflow)?;
        self.attested_through = self.counters;
        self.batch = Batch::new();
        self.batch_index = self.batch_index.checked_add(1).ok_or(Error::Overflow)?;
        out.get(..len).ok_or(Error::BufferTooSmall)
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
    /// the unit.
    ///
    /// # Errors
    /// [`Error::BoxClosed`], [`Error::TimeRegression`] or an encoding error.
    pub fn scan_count_body<'w>(
        &mut self,
        time_bucket: TimeBucket,
        work: &'w mut [u8],
    ) -> Result<&'w [u8], Error> {
        if self.closing {
            return Err(Error::BoxClosed);
        }
        if time_bucket.get() < self.last_bucket {
            return Err(Error::TimeRegression);
        }
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
        self.scan_records = self.totals.records;
        self.scan_bucket = time_bucket.get();
        work.get(..len).ok_or(Error::BufferTooSmall)
    }

    /// The facts of VC-038 for this box and `inputs`.
    #[must_use]
    pub fn close_facts<'s>(&'s self, inputs: &CloseInputs) -> CloseFacts<'s> {
        CloseFacts {
            paper: inputs.paper,
            records: self.totals.records,
            attested: self.totals.attested,
            open_batch_records: u64::from(self.batch.count),
            without_record: inputs.without_record,
            challenged: self.totals.challenged,
            quarantined: self.totals.quarantined,
            spoiled_envelopes: inputs.spoiled_envelopes,
            module_final_counters: self.module_counters(),
            open_batches: u8::from(self.batch.count > 0),
            absentee_envelopes: inputs.absentee_envelopes,
            fallback_declared: inputs.fallback_declared,
        }
    }

    /// Closes the box (PROTOCOL.md §10.2): evaluates the VC-038 invariants,
    /// writes the `BoxCloseBody` object and the device signature into
    /// `work` (at least [`CLOSE_WORK_LEN`] bytes), journals the close entry
    /// (kind 5, `record_hash` = the record set root) and marks the box
    /// closed. The close is recorded even when invariants are violated; the
    /// verdict then means `HOLD_REVIEW`. Call [`Self::into_closed`] with the
    /// returned token.
    ///
    /// # Errors
    /// [`Error::BoxClosed`], [`Error::BallotInFlight`], signing, encoding
    /// and journal errors; the box stays open on error.
    pub fn prepare_close<'w>(
        &mut self,
        inputs: &CloseInputs,
        device_key: &HybridSigningKey,
        signing_seed: &[u8; 32],
        sink: &mut dyn JournalSink,
        time_bucket: TimeBucket,
        work: &'w mut [u8],
    ) -> Result<CloseOutput<'w>, Error> {
        if self.closing {
            return Err(Error::BoxClosed);
        }
        if self.in_flight.is_some() {
            return Err(Error::BallotInFlight);
        }
        let verdict = rules::close_verdict(&self.close_facts(inputs));
        let include = [true; MAX_MODULES];
        let counters = self.counters;
        let module_counters = self
            .counter_list(&counters, include)?
            .ok_or(Error::Capacity)?;
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
        let sig = sign_hybrid(
            device_key,
            &purpose(PURPOSE_BOX_CLOSE)?,
            body_bytes,
            &mut DeviceRng::for_signing(signing_seed),
        )?;
        let slot: &'w mut [u8; HYBRID_SIG_LEN] = sig_region
            .get_mut(..HYBRID_SIG_LEN)
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::BufferTooSmall)?;
        write_hybrid(&sig, slot)?;
        self.journal(
            sink,
            JournalKind::BoxClose,
            inputs.record_set_root,
            Hash512::ZERO,
            &counters,
            include,
            time_bucket,
            None,
        )?;
        self.closing = true;
        Ok(CloseOutput {
            body: body_bytes,
            device_sig: slot,
            verdict,
            token: CloseToken(()),
        })
    }

    /// Turns a box whose close entry is durable into a [`ClosedBox`].
    #[must_use]
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the token is consumed as proof of the durable close entry"
    )]
    pub fn into_closed(self, token: CloseToken) -> ClosedBox<'c> {
        let CloseToken(()) = token;
        ClosedBox {
            config: self.config,
            totals: self.totals,
            journal_head: self.journal_head,
            counters: self.counters,
        }
    }
}

/// A closed box. It has no method that accepts a ballot, a batch or a
/// scan count: after close, the box's `box_id` takes no new record (VC-039).
///
/// ```compile_fail
/// # fn closed_box_has_no_interpret(closed: ityv_cunit::boxstate::ClosedBox<'_>) {
/// let _ = closed.interpret(&[]);
/// # }
/// ```
///
/// The same call compiles on an open box:
///
/// ```
/// # fn open_box_interprets(open: &mut ityv_cunit::boxstate::OpenBox<'_>) {
/// let _ = open.interpret(&[]);
/// # }
/// ```
#[derive(Debug, Clone, Copy)]
pub struct ClosedBox<'c> {
    config: &'c ElectionConfig<'c>,
    totals: Totals,
    journal_head: Hash512,
    counters: [u64; MAX_MODULES],
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
        self.counters
            .get(..self.config.modules().len())
            .unwrap_or(&[])
    }
}
