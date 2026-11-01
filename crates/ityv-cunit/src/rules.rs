//! The pure counting rules of the unit, kept free of cryptography and I/O
//! so that the bounded model checker can explore them exhaustively
//! (`kani/proofs.rs`).
//!
//! | rule | source |
//! |---|---|
//! | [`option_in_range`] | PROTOCOL.md §7.3 step 1 (`t ∈ 0..=m+1`) |
//! | [`counter_follows`] | PROTOCOL.md §7.2 (module counters increase by one) |
//! | [`pad_consumption`], [`pad_index`] | PROTOCOL.md §9.4.3 (VC-034) |
//! | [`batch_due`] | PROTOCOL.md §7.2.1 (64 records or one idle bucket) |
//! | [`scan_count_due`] | PROTOCOL.md §7.8 (50 records or eight buckets, VC-052) |
//! | [`close_verdict`] | PROTOCOL.md §10.2 (VC-038) |

use crate::error::Invariant;

/// Records per batch at most (PROTOCOL.md §7.2.1).
pub const BATCH_MAX_RECORDS: u16 = 64;
/// Idle buckets after the last record that close a batch (15 minutes).
pub const BATCH_IDLE_BUCKETS: u64 = 1;
/// Records between scan-count attestations (PROTOCOL.md §7.8).
pub const SCAN_COUNT_RECORDS: u64 = 50;
/// Buckets between scan-count attestations (two hours).
pub const SCAN_COUNT_BUCKETS: u64 = 8;
/// Pad bytes consumed per record besides the member share: the Poly1305
/// key of the transport tag and the key of the module tag (§9.4.3).
pub const PAD_KEY_BYTES: u64 = 64;

/// `true` if `option_index` names an option of a set of `option_count`
/// options (`0` BLANK, `1..=m` candidates, `m + 1` UNREADABLE).
#[must_use]
pub const fn option_in_range(option_count: u16, option_index: u16) -> bool {
    option_index < option_count
}

/// `true` if `counter` is the module counter that follows `previous`.
#[must_use]
pub const fn counter_follows(previous: u64, counter: u64) -> bool {
    match previous.checked_add(1) {
        Some(next) => next == counter,
        None => false,
    }
}

/// The pad bytes `b` a module consumes per record for one member whose
/// `MemberShare` object is `member_share_len` bytes long.
#[must_use]
pub fn pad_consumption(member_share_len: usize) -> Option<u64> {
    u64::try_from(member_share_len)
        .ok()
        .and_then(|len| len.checked_add(PAD_KEY_BYTES))
}

/// The pad offset of record `counter`: `counter × b`, or `None` on overflow.
#[must_use]
pub const fn pad_index(counter: u64, consumption: u64) -> Option<u64> {
    counter.checked_mul(consumption)
}

/// `true` if the open batch must be closed now: it holds the maximum
/// number of records, or it holds at least one and a full bucket has
/// passed since its last record.
#[must_use]
pub const fn batch_due(records: u16, last_record_bucket: u64, now: u64) -> bool {
    if records >= BATCH_MAX_RECORDS {
        return true;
    }
    if records == 0 {
        return false;
    }
    match last_record_bucket.checked_add(BATCH_IDLE_BUCKETS) {
        Some(deadline) => now >= deadline,
        None => false,
    }
}

/// `true` if a scan-count attestation is due: fifty records since the
/// last one, or eight buckets since the last one.
#[must_use]
pub const fn scan_count_due(records_since: u64, last_attest_bucket: u64, now: u64) -> bool {
    if records_since >= SCAN_COUNT_RECORDS {
        return true;
    }
    match last_attest_bucket.checked_add(SCAN_COUNT_BUCKETS) {
        Some(deadline) => now >= deadline,
        None => false,
    }
}

/// Everything the close invariants of VC-038 compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseFacts<'a> {
    /// Physical ballots counted by two clerks.
    pub paper: u64,
    /// Cast records (imprinted, not quarantined).
    pub records: u64,
    /// Records attested in closed batches.
    pub attested: u64,
    /// Records in the batch still open at close.
    pub open_batch_records: u64,
    /// Ballots received through the emergency slot.
    pub without_record: u64,
    /// Ballots spoiled by a pre-cast challenge.
    pub challenged: u64,
    /// Ballots quarantined.
    pub quarantined: u64,
    /// Physical envelopes in the spoiled/quarantine bag.
    pub spoiled_envelopes: u64,
    /// Final counter of every module.
    pub module_final_counters: &'a [u64],
    /// Batches still open.
    pub open_batches: u8,
    /// Absentee profile: physical envelopes; `None` in person.
    pub absentee_envelopes: Option<u64>,
    /// Whether a `FallbackDeclared` event exists for this box.
    pub fallback_declared: bool,
}

/// The set of violated close invariants, one flag per [`Invariant`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Violations([bool; 7]);

impl Violations {
    const fn index(invariant: Invariant) -> usize {
        match invariant {
            Invariant::PaperCount => 0,
            Invariant::AttestedCount => 1,
            Invariant::SpoiledEnvelopes => 2,
            Invariant::ModuleCounters => 3,
            Invariant::OpenBatches => 4,
            Invariant::EnvelopeCount => 5,
            Invariant::FallbackDeclared => 6,
        }
    }

    fn with(mut self, invariant: Invariant, violated: bool) -> Self {
        if let Some(flag) = self.0.get_mut(Self::index(invariant)) {
            *flag = violated;
        }
        self
    }

    /// `true` if `invariant` is violated.
    #[must_use]
    pub fn contains(self, invariant: Invariant) -> bool {
        self.0.get(Self::index(invariant)).copied().unwrap_or(false)
    }

    /// `true` if no invariant is violated (the close is not `HOLD_REVIEW`).
    #[must_use]
    pub fn is_empty(self) -> bool {
        !self.0.iter().any(|&flag| flag)
    }

    /// The number of violated invariants.
    #[must_use]
    pub fn count(self) -> usize {
        self.0.iter().filter(|&&flag| flag).count()
    }
}

fn sum(values: &[u64]) -> Option<u64> {
    values.iter().try_fold(0u64, |acc, &v| acc.checked_add(v))
}

/// Checks every close invariant of PROTOCOL.md §10.2 (VC-038). An
/// arithmetic overflow in a sum counts as a violation of that invariant.
#[must_use]
pub fn close_verdict(facts: &CloseFacts<'_>) -> Violations {
    let paper_ok = sum(&[facts.records, facts.without_record]) == Some(facts.paper);
    let attested_ok = sum(&[facts.attested, facts.open_batch_records]) == Some(facts.records);
    let spoiled_ok = sum(&[facts.challenged, facts.quarantined]) == Some(facts.spoiled_envelopes);
    let consumed = sum(&[facts.records, facts.challenged, facts.quarantined]);
    let counters_ok = consumed.is_some_and(|c| facts.module_final_counters.iter().all(|&f| f == c));
    let envelopes_ok = facts.absentee_envelopes.is_none_or(|n| n == facts.records);
    let fallback_ok = facts.without_record == 0 || facts.fallback_declared;
    Violations::default()
        .with(Invariant::PaperCount, !paper_ok)
        .with(Invariant::AttestedCount, !attested_ok)
        .with(Invariant::SpoiledEnvelopes, !spoiled_ok)
        .with(Invariant::ModuleCounters, !counters_ok)
        .with(Invariant::OpenBatches, facts.open_batches != 0)
        .with(Invariant::EnvelopeCount, !envelopes_ok)
        .with(Invariant::FallbackDeclared, !fallback_ok)
}
