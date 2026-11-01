//! The pure counting rules of the unit, kept free of cryptography and I/O
//! so that the bounded model checker can explore them exhaustively
//! (`kani/proofs.rs`).
//!
//! | rule | source |
//! |---|---|
//! | [`option_in_range`] | PROTOCOL.md §7.3 step 1 (`t ∈ 0..=m+1`) |
//! | [`check_counter`], [`advance_mark`] | PROTOCOL.md §7.2 (counter high-water mark) |
//! | [`pad_consumption`], [`pad_index`] | PROTOCOL.md §9.4.3 (VC-034) |
//! | [`batch_due`] | PROTOCOL.md §7.2.1 (64 records or one idle bucket) |
//! | [`scan_count_due`] | PROTOCOL.md §7.8 (50 records or eight buckets, VC-052) |
//! | [`close_verdict`] | PROTOCOL.md §10.2 (VC-038) |
//! | [`waiting_area_action`] | PROTOCOL.md §7.3 step 7 (resume after a power loss) |

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
/// Offset of the transport MAC key inside a record's pad region.
pub const PAD_MAC_KEY_OFFSET: u64 = 0;
/// Offset of the module tag key `key_{c,i,n}` inside a record's pad region.
pub const PAD_TAG_KEY_OFFSET: u64 = 32;
/// Offset of the plaintext pad inside a record's pad region; the pad runs
/// for the length of that ballot's `MemberShare` and the rest of the
/// region is not used.
pub const PAD_PLAINTEXT_OFFSET: u64 = 64;

/// `true` if `option_index` names an option of a set of `option_count`
/// options (`0` BLANK, `1..=m` candidates, `m + 1` UNREADABLE).
#[must_use]
pub const fn option_in_range(option_count: u16, option_index: u16) -> bool {
    option_index < option_count
}

/// How a counter a module returned relates to the module's high-water
/// mark, the highest counter the unit has accepted from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CounterCheck {
    /// `counter == mark + 1`: accepted.
    Next,
    /// `counter <= mark`: a replayed or backwards counter.
    Regression,
    /// `counter > mark + 1`: the module skipped counters.
    Gap,
}

/// Classifies `counter` against `mark`.
#[must_use]
pub const fn check_counter(mark: u64, counter: u64) -> CounterCheck {
    if counter <= mark {
        CounterCheck::Regression
    } else if counter.abs_diff(mark) == 1 {
        CounterCheck::Next
    } else {
        CounterCheck::Gap
    }
}

/// Applies [`check_counter`]: the mark moves to `counter` only when it is
/// the next one; a regression or a gap leaves it unchanged.
pub const fn advance_mark(mark: &mut u64, counter: u64) -> CounterCheck {
    let check = check_counter(*mark, counter);
    if matches!(check, CounterCheck::Next) {
        *mark = counter;
    }
    check
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

/// Ballots in one visit at most (ADR-0021): `record_count ≤ 8·visit_count`.
pub const MAX_VISIT_BALLOTS: u64 = 8;

/// What people count at an out-of-district or overseas box's close, with
/// the station's envelope accounting (PROTOCOL.md §10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnvelopeCounts {
    /// Return envelopes in the box (`envelope_count`).
    pub envelopes: u64,
    /// Label stickers on them, emergency marks not counted
    /// (`sticker_count`).
    pub stickers: u64,
    /// Return envelopes issued (`IssuanceCount`).
    pub issued: u64,
    /// Empty return envelopes handed back (`IssuanceCount`).
    pub returned_empty: u64,
}

/// Everything the close invariants of VC-038 compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseFacts<'a> {
    /// Physical ballots counted by two clerks (0 at an absentee box,
    /// whose ballots stay inside their envelopes).
    pub paper: u64,
    /// Cast records (imprinted, not quarantined).
    pub records: u64,
    /// Visits with at least one cast ballot.
    pub visits: u64,
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
    /// Absentee profile: the envelope and sticker counts; `None` in
    /// person.
    pub envelopes: Option<EnvelopeCounts>,
    /// Whether a `FallbackDeclared` event exists for this box.
    pub fallback_declared: bool,
    /// Papers lost or unmatched at a resume (PROTOCOL.md §7.3 step 7).
    pub paper_incidents: u64,
}

/// The set of violated close invariants, one flag per [`Invariant`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Violations([bool; 10]);

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
            Invariant::PaperIncidents => 7,
            Invariant::VisitCount => 8,
            Invariant::StickerCount => 9,
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
    // An absentee box's ballots stay in their envelopes: no paper count.
    let paper_ok = if facts.envelopes.is_some() {
        facts.paper == 0
    } else {
        sum(&[facts.records, facts.without_record]) == Some(facts.paper)
    };
    let attested_ok = sum(&[facts.attested, facts.open_batch_records]) == Some(facts.records);
    let spoiled_ok = sum(&[facts.challenged, facts.quarantined]) == Some(facts.spoiled_envelopes);
    let consumed = sum(&[facts.records, facts.challenged, facts.quarantined]);
    let counters_ok = consumed.is_some_and(|c| facts.module_final_counters.iter().all(|&f| f == c));
    // `visits ≤ records ≤ 8·visits`; the product saturates, which keeps
    // the comparison exact because `records` is itself a `u64`.
    let visits_ok = facts.visits <= facts.records
        && facts.records <= facts.visits.saturating_mul(MAX_VISIT_BALLOTS);
    let envelopes_ok = facts
        .envelopes
        .is_none_or(|e| e.issued.checked_sub(e.returned_empty) == Some(e.envelopes));
    let stickers_ok = facts.envelopes.is_none_or(|e| e.stickers == facts.visits);
    let fallback_ok = facts.without_record == 0 || facts.fallback_declared;
    Violations::default()
        .with(Invariant::PaperCount, !paper_ok)
        .with(Invariant::AttestedCount, !attested_ok)
        .with(Invariant::SpoiledEnvelopes, !spoiled_ok)
        .with(Invariant::ModuleCounters, !counters_ok)
        .with(Invariant::OpenBatches, facts.open_batches != 0)
        .with(Invariant::EnvelopeCount, !envelopes_ok)
        .with(Invariant::FallbackDeclared, !fallback_ok)
        .with(Invariant::PaperIncidents, facts.paper_incidents != 0)
        .with(Invariant::VisitCount, !visits_ok)
        .with(Invariant::StickerCount, !stickers_ok)
}

/// What two clerks and two observers found in the waiting area after a
/// power loss (PROTOCOL.md §7.3 step 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WaitingArea {
    /// No paper.
    Empty,
    /// A paper carrying a printed cast id.
    Imprinted,
    /// A paper without a printed cast id.
    Unimprinted,
}

/// The state of the journal's last record when the journal ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordTail {
    /// The journal holds no record.
    NoRecord,
    /// The last entry is a record without its imprint or quarantine entry.
    Open,
    /// The last record has its imprint entry (kind 6).
    Imprinted,
    /// The last record was quarantined by its hash (kind 3).
    Quarantined,
    /// The last record's paper went missing at an earlier resume: another
    /// entry followed it without an imprint or quarantine entry.
    Missing,
}

/// What resume does with the waiting area.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WaitingAction {
    /// Nothing is in the waiting area and nothing is owed.
    Nothing,
    /// The paper is the open record's and is imprinted: the unit journals
    /// the imprint (kind 6) and the paper drops into the box.
    JournalImprint,
    /// The paper's imprint entry already exists: it drops into the box.
    Drop,
    /// The paper is the open record's but carries no imprint: the unit
    /// quarantines that record by its hash (kind 3) and the paper goes to
    /// the quarantine envelope.
    QuarantineRecord,
    /// The paper was never journaled: the unit journals a quarantine
    /// without record (kind 3, hash zero) and the paper goes to the
    /// quarantine envelope.
    QuarantineUnjournaled,
    /// The paper's record is already quarantined: the paper goes to the
    /// quarantine envelope and nothing is journaled.
    Divert,
    /// An imprinted paper that matches no record: the unit journals a
    /// quarantine without record, the paper goes to the quarantine envelope,
    /// and the host records an incident (`HOLD_REVIEW`).
    QuarantineUnmatched,
    /// The open record's paper is gone: nothing is journaled, the host
    /// records an incident and the close reports it (`HOLD_REVIEW`).
    PaperMissing,
}

/// The resume decision of PROTOCOL.md §7.3 step 7 for the attested
/// waiting-area state and the journal's last record.
#[must_use]
pub const fn waiting_area_action(area: WaitingArea, tail: RecordTail) -> WaitingAction {
    match (area, tail) {
        (WaitingArea::Empty, RecordTail::Open) => WaitingAction::PaperMissing,
        (WaitingArea::Empty, _) => WaitingAction::Nothing,
        (WaitingArea::Imprinted, RecordTail::Open) => WaitingAction::JournalImprint,
        (WaitingArea::Imprinted, RecordTail::Imprinted) => WaitingAction::Drop,
        (WaitingArea::Imprinted, RecordTail::Quarantined) => WaitingAction::Divert,
        (WaitingArea::Imprinted, RecordTail::NoRecord | RecordTail::Missing) => {
            WaitingAction::QuarantineUnmatched
        }
        (WaitingArea::Unimprinted, RecordTail::Open) => WaitingAction::QuarantineRecord,
        (WaitingArea::Unimprinted, _) => WaitingAction::QuarantineUnjournaled,
    }
}
