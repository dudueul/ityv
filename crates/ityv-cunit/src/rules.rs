//! The pure counting rules of the unit, kept free of cryptography and I/O
//! so that the bounded model checker can explore them exhaustively
//! (`kani/proofs.rs`).
//!
//! | rule | source |
//! |---|---|
//! | [`option_in_range`] | PROTOCOL.md §7.3 step 1 (`t ∈ 0..=m+1`) |
//! | [`check_counter`], [`advance_mark`] | PROTOCOL.md §7.2 (counter high-water mark) |
//! | [`pad_consumption`], [`pad_index`] | PROTOCOL.md §9.4.3 (VC-034) |
//! | [`batch_due`] | PROTOCOL.md §7.2.1 (no room for a visit, or one idle bucket) |
//! | [`scan_count_due`] | PROTOCOL.md §7.8 (50 records or eight buckets, VC-052) |
//! | [`close_verdict`] | PROTOCOL.md §10.2 (VC-038) |
//! | [`resume_plan`] | PROTOCOL.md §7.3 재개 (resume after a power loss, VC-069) |

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

/// The most records a batch may hold when a visit starts: a visit adds up
/// to eight records at its decision, and a batch never exceeds
/// [`BATCH_MAX_RECORDS`] (PROTOCOL.md §7.2.1).
pub const BATCH_VISIT_START_MAX: u16 = BATCH_MAX_RECORDS - 8;

/// `true` if the open batch must be closed before the next visit: it has
/// no room left for a full visit, or it holds at least one record and a
/// full bucket has passed since its last record.
#[must_use]
pub const fn batch_due(records: u16, last_record_bucket: u64, now: u64) -> bool {
    if records > BATCH_VISIT_START_MAX {
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

/// Ballots in one visit at most (ADR-0021), as a count of positions.
pub const VISIT_POSITIONS: usize = 8;

/// What a visit position was decided to be (PROTOCOL.md §7.3 step 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Choice {
    /// Cast: imprinted and dropped into the box (or the return tray).
    Cast,
    /// Checked: opened (`ChallengeOpening`) and spoiled.
    Check,
}

/// How the journal has settled a cast position after the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Settlement {
    /// Neither imprinted nor quarantined yet.
    Open,
    /// The imprint entry (kind 6) is durable.
    Imprinted,
    /// A quarantine entry (kind 3) names the record.
    Quarantined,
}

/// Where the journal's last visit stands at resume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VisitStage {
    /// No visit is pending: none was journaled, or the last one was closed
    /// (abandoned, or ended by an earlier resume).
    None,
    /// Position entries (kinds 1 and 2) without their decision entry.
    Undecided,
    /// The decision entry (kind 7) is durable.
    Decided,
}

/// The journal's last visit, as [`resume_plan`] reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VisitState {
    /// Where the visit stands.
    pub stage: VisitStage,
    /// Its journaled positions (at most [`VISIT_POSITIONS`]).
    pub positions: u8,
    /// The decision of each position (decided visits).
    pub choices: [Choice; VISIT_POSITIONS],
    /// The settlement of each cast position (decided visits).
    pub settled: [Settlement; VISIT_POSITIONS],
    /// Whether the label-printed entry (kind 8) is durable.
    pub label_printed: bool,
}

impl VisitState {
    /// No pending visit.
    pub const NONE: Self = Self {
        stage: VisitStage::None,
        positions: 0,
        choices: [Choice::Cast; VISIT_POSITIONS],
        settled: [Settlement::Open; VISIT_POSITIONS],
        label_printed: false,
    };
}

/// What two clerks and two observers found after a power loss
/// (PROTOCOL.md §7.3, 재개): the papers still in the waiting area, whether
/// the front one carries a printed cast id, and (out of district) whether
/// the visit's label sticker came out of the printer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WaitingArea {
    /// Papers in the waiting area.
    pub papers: u8,
    /// The front paper carries a printed cast id.
    pub front_imprinted: bool,
    /// The visit's label sticker was printed.
    pub sticker_printed: bool,
}

/// Which case of the resume rule (VC-069) applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResumeCase {
    /// Nothing is pending and the waiting area is empty.
    Nothing,
    /// (1) The machine stopped before a visit's decision: every bound
    /// position is quarantined by its record hash; a paper behind them
    /// whose ballot consumed counters (the one in flight) by a quarantine
    /// without record carrying them; any other paper consumed nothing and
    /// goes back to the voter.
    BeforeDecision,
    /// (2) The machine stopped after the decision: the remaining positions
    /// are settled as decided, except that a cast paper without an imprint
    /// is quarantined.
    AfterDecision,
    /// (3) Out of district, every position is settled but no sticker entry
    /// exists: the visit's cast records are quarantined.
    LabelMissing,
    /// (4) The papers do not fit the journal: an incident, nothing is
    /// journaled, the box is `HOLD_REVIEW`.
    Inconsistent,
}

/// Where one paper of the waiting area goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PaperAction {
    /// Into the box (in person) or the return tray (out of district).
    Drop,
    /// Into the spoiled-ballot chute (a checked position).
    SpoilChute,
    /// Into the quarantine envelope.
    Quarantine,
    /// Back to the voter, to be inserted again: its ballot consumed no
    /// counter and nothing names it.
    Return,
    /// Kept aside for the review of an incident.
    Hold,
}

/// What the unit does at resume ([`resume_plan`]); entries are appended
/// in this order: the imprint entry, the quarantines by record hash in
/// position order, the quarantines without record (the first carrying
/// the counters of the ballot in flight, if the modules issued them).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResumePlan {
    /// The case.
    pub case: ResumeCase,
    /// Where each paper goes, front first; `papers[..paper_count]` is set.
    pub papers: [PaperAction; VISIT_POSITIONS],
    /// Papers in the waiting area.
    pub paper_count: u8,
    /// The position whose imprint entry (kind 6) is appended.
    pub imprint: Option<u8>,
    /// Positions quarantined by their record hash (kind 3).
    pub quarantine: [bool; VISIT_POSITIONS],
    /// Quarantines without record (kind 3, hash zero) for papers no entry
    /// names that cannot go back to the voter.
    pub unjournaled: u8,
    /// Out of district: the visit's papers already in the return tray go
    /// to the quarantine envelope.
    pub return_tray: bool,
    /// The host records an incident (the close is `HOLD_REVIEW`).
    pub incident: bool,
}

impl ResumePlan {
    const fn new(case: ResumeCase, paper_count: u8) -> Self {
        Self {
            case,
            papers: [PaperAction::Hold; VISIT_POSITIONS],
            paper_count,
            imprint: None,
            quarantine: [false; VISIT_POSITIONS],
            unjournaled: 0,
            return_tray: false,
            incident: false,
        }
    }

    fn inconsistent(paper_count: u8) -> Self {
        let mut plan = Self::new(ResumeCase::Inconsistent, paper_count);
        plan.incident = true;
        plan
    }

    fn set_paper(&mut self, index: usize, action: PaperAction) {
        if let Some(slot) = self.papers.get_mut(index) {
            *slot = action;
        }
    }
}

/// The resume rule of PROTOCOL.md §7.3 (VC-069) for the journal's last
/// visit, the attested waiting area and `in_flight`: whether the modules
/// issued counters the journal does not show (the ballot being built when
/// the machine stopped, before its bound entry). Papers are processed in
/// position order, so the papers left are always the visit's last
/// positions, followed by the papers of positions not yet bound.
///
/// * No pending visit: the papers belong to a visit none of whose
///   positions was bound: case 1 (see the unbound papers below).
/// * An undecided visit (bound entries, no decision entry): case 1. Every
///   bound position not yet quarantined is quarantined by its record hash
///   and its paper goes to the quarantine envelope; fewer papers than
///   bound positions is an incident.
/// * Unbound papers, in case 1: the first one is the ballot in flight; if
///   `in_flight`, it is quarantined by an entry without record carrying
///   the issued counters (without such a paper the entry is still written,
///   and the missing paper is an incident). Every other unbound paper
///   consumed nothing and goes back to the voter. An imprinted front paper
///   or a printed sticker fits no unbound ballot: every paper is
///   quarantined without record, and it is an incident.
/// * A decided visit: the papers are taken to be its positions
///   `N−R+1..N`. That fits if every unsettled cast position is among them,
///   only the front may be settled, the front is imprinted exactly when it
///   is a cast position with or awaiting its imprint entry, and no sticker
///   is out while papers are left. Then (case 2) a checked paper goes to
///   the chute; the front cast paper, if imprinted, gets its imprint entry
///   (if missing) and drops; every other cast paper is quarantined. Out of
///   district without a sticker entry the labels are lost, so every cast
///   record of the visit is quarantined and the return tray goes to the
///   quarantine envelope (case 3 when no paper is left). If it does not
///   fit, or `in_flight`, and the visit owes nothing (every cast position
///   settled, and its sticker entry out of district), the papers are a new
///   visit's unbound papers (case 1); out of district after the sticker
///   entry they always are. Otherwise case 4: an incident, nothing
///   journaled.
#[must_use]
pub fn resume_plan(
    visit: &VisitState,
    area: WaitingArea,
    absentee: bool,
    in_flight: bool,
) -> ResumePlan {
    let papers = area.papers;
    if usize::from(papers) > VISIT_POSITIONS {
        return ResumePlan::inconsistent(papers);
    }
    match visit.stage {
        VisitStage::None => unbound_plan(area, in_flight),
        VisitStage::Undecided => undecided_plan(visit, area, in_flight),
        VisitStage::Decided => decided_plan(visit, area, absentee, in_flight),
    }
}

/// Case 1 for papers none of which is bound, or nothing.
fn unbound_plan(area: WaitingArea, in_flight: bool) -> ResumePlan {
    if area.papers == 0 && !in_flight {
        return ResumePlan::new(ResumeCase::Nothing, 0);
    }
    let mut plan = ResumePlan::new(ResumeCase::BeforeDecision, area.papers);
    place_unbound(&mut plan, area, 0, in_flight);
    plan
}

/// Case 1 for an undecided visit of `visit.positions` bound positions.
fn undecided_plan(visit: &VisitState, area: WaitingArea, in_flight: bool) -> ResumePlan {
    let mut plan = ResumePlan::new(ResumeCase::BeforeDecision, area.papers);
    let n = usize::from(visit.positions).min(VISIT_POSITIONS);
    for (slot, settled) in plan.quarantine.iter_mut().zip(visit.settled.iter()).take(n) {
        *slot = !matches!(settled, Settlement::Quarantined);
    }
    for slot in plan.papers.iter_mut().take(usize::from(area.papers).min(n)) {
        *slot = PaperAction::Quarantine;
    }
    if usize::from(area.papers) < n {
        plan.incident = true;
    }
    place_unbound(&mut plan, area, n, in_flight);
    plan
}

/// The papers from index `first` on are unbound: the first is the
/// ballot in flight (quarantined with its counters if `in_flight`), the
/// others go back to the voter, unless an imprint or a sticker shows
/// that something does not fit.
fn place_unbound(plan: &mut ResumePlan, area: WaitingArea, first: usize, in_flight: bool) {
    let papers = usize::from(area.papers);
    let unbound = papers.saturating_sub(first);
    let anomaly = area.front_imprinted || area.sticker_printed;
    if anomaly {
        plan.incident = true;
    }
    for (offset, slot) in plan.papers.iter_mut().skip(first).take(unbound).enumerate() {
        let quarantined = anomaly || (in_flight && offset == 0);
        *slot = if quarantined {
            PaperAction::Quarantine
        } else {
            PaperAction::Return
        };
    }
    // one entry per quarantined unbound paper; the counters of the ballot
    // in flight are journaled even when its paper is missing
    let entries = if anomaly {
        unbound.max(usize::from(in_flight))
    } else {
        usize::from(in_flight)
    };
    plan.unjournaled = u8::try_from(entries).unwrap_or(u8::MAX);
    if in_flight && unbound == 0 {
        plan.incident = true;
    }
}

/// The resume rule for a decided visit.
fn decided_plan(
    visit: &VisitState,
    area: WaitingArea,
    absentee: bool,
    in_flight: bool,
) -> ResumePlan {
    let n = usize::from(visit.positions).min(VISIT_POSITIONS);
    let positions = visit.choices.iter().zip(visit.settled.iter()).take(n);
    let unsettled = positions
        .clone()
        .any(|(c, s)| matches!(c, Choice::Cast) && matches!(s, Settlement::Open));
    let live = positions
        .clone()
        .any(|(c, s)| matches!(c, Choice::Cast) && !matches!(s, Settlement::Quarantined));
    let label_missing = absentee && !visit.label_printed && live;
    let complete = !unsettled && !label_missing;
    if complete && area.papers == 0 && !in_flight {
        return ResumePlan::new(ResumeCase::Nothing, 0);
    }
    // Out of district a sticker entry means every position was processed:
    // papers left belong to a new visit. So do they once the modules
    // issued for a ballot after the decision.
    let processed = (absentee && visit.label_printed) || in_flight;
    let fitted = if processed {
        None
    } else {
        trailing_plan(visit, area, absentee, label_missing, n)
    };
    match fitted {
        Some(plan) => plan,
        // A settled visit: the papers are a new visit's (an imprinted one,
        // or a sticker, does not fit and is an incident).
        None if complete => unbound_plan(area, in_flight),
        None => ResumePlan::inconsistent(area.papers),
    }
}

/// The plan if the papers are the visit's last positions `N−R+1..N`
/// (case 2, or case 3 with no paper left), or `None` if they do not fit:
/// a cast paper still unsettled is missing, a settled paper other than
/// the front is still there, the front's imprint does not match its
/// entries, or a sticker is out while papers are left.
fn trailing_plan(
    visit: &VisitState,
    area: WaitingArea,
    absentee: bool,
    label_missing: bool,
    n: usize,
) -> Option<ResumePlan> {
    let papers = usize::from(area.papers);
    if papers > n || (area.sticker_printed && papers > 0) {
        return None;
    }
    let front = n.saturating_sub(papers);
    let mut plan = ResumePlan::new(ResumeCase::AfterDecision, area.papers);
    let positions = visit.choices.iter().zip(visit.settled.iter()).take(n);
    for (p, (choice, settled)) in positions.enumerate() {
        let remaining = p >= front;
        let is_front = p == front;
        let fits = match (choice, settled, remaining) {
            // a cast paper leaves the waiting area only once settled
            (Choice::Cast, Settlement::Open, false) => false,
            (Choice::Check, _, true) => !(is_front && area.front_imprinted),
            (Choice::Cast, Settlement::Open, true) | (_, _, false) => true,
            (Choice::Cast, Settlement::Imprinted, true) => is_front && area.front_imprinted,
            (Choice::Cast, Settlement::Quarantined, true) => is_front && !area.front_imprinted,
        };
        if !fits {
            return None;
        }
        let cast_live =
            matches!(choice, Choice::Cast) && !matches!(settled, Settlement::Quarantined);
        if !remaining {
            if label_missing && cast_live {
                if let Some(q) = plan.quarantine.get_mut(p) {
                    *q = true;
                }
                plan.return_tray = true;
            }
            continue;
        }
        let action = match (choice, settled) {
            (Choice::Check, _) => PaperAction::SpoilChute,
            (Choice::Cast, Settlement::Quarantined) => PaperAction::Quarantine,
            (Choice::Cast, Settlement::Open | Settlement::Imprinted)
                if is_front && area.front_imprinted && !absentee =>
            {
                if matches!(settled, Settlement::Open) {
                    plan.imprint = u8::try_from(p).ok();
                }
                PaperAction::Drop
            }
            (Choice::Cast, Settlement::Open | Settlement::Imprinted) => {
                if let Some(q) = plan.quarantine.get_mut(p) {
                    *q = true;
                }
                PaperAction::Quarantine
            }
        };
        plan.set_paper(p.saturating_sub(front), action);
    }
    if label_missing && papers == 0 {
        plan.case = ResumeCase::LabelMissing;
    }
    Some(plan)
}
