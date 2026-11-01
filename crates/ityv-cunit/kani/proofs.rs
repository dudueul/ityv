//! Kani bounded model-checking harnesses (verification ladder V2).
//!
//! Compiled only under `cargo kani`, as `crate::proofs` via a `#[path]`
//! attribute in `src/lib.rs`. Each harness states one property of the
//! unit's pure counting rules (`src/rules.rs` and the module batch rule in
//! `src/port.rs`) against an independently written statement, mostly in
//! 128-bit arithmetic so that the reference cannot overflow where the
//! implementation must use checked 64-bit arithmetic:
//!
//! * the option bound of PROTOCOL.md §7.3 step 1;
//! * the module counter high-water mark (PROTOCOL.md §7.2, ADR-0017 개정 2):
//!   the classification of one counter, and over a sequence of issues that
//!   the mark never moves backwards and never accepts a counter twice;
//! * the pad consumption and pad index of §9.4.3 (VC-034);
//! * the module's batch-signing rule (VC-021);
//! * the batch and scan-count triggers (§7.2.1, §7.8, VC-052);
//! * every close invariant of §10.2 (VC-038), including the visit and
//!   sticker counts of ADR-0021;
//! * the resume rule for the journal's last visit and the attested waiting
//!   area (§7.3 재개, VC-069): total, and leaving every cast position
//!   settled.
//!
//! Kani additionally checks every harness for panics, overflow and
//! out-of-bounds access on all explored inputs.
//!
//! Run with `cargo kani -p ityv-cunit` from the workspace root.
// Harness file: outside the TCB and outside `src/` (CONSTITUTION.md §1.1).
// A harness states expected values with plain indexing and `as` casts on
// bounded symbolic inputs, and Kani itself reports any panic or overflow
// in them, so these restriction lints are relaxed for this file only.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::missing_panics_doc
)]

use crate::error::Invariant;
use crate::port::module_may_sign_batch;
use crate::rules::{
    BATCH_IDLE_BUCKETS, BATCH_VISIT_START_MAX, Choice, CloseFacts, CounterCheck, EnvelopeCounts,
    PAD_KEY_BYTES, PaperAction, ResumeCase, SCAN_COUNT_BUCKETS, SCAN_COUNT_RECORDS, Settlement,
    VISIT_POSITIONS, VisitStage, VisitState, WaitingArea, advance_mark, batch_due, check_counter,
    close_verdict, option_in_range, pad_consumption, pad_index, resume_plan, scan_count_due,
};

/// The option bound accepts exactly the indices `0..=option_count − 1`.
#[kani::proof]
fn option_bound_is_exact() {
    let count: u16 = kani::any();
    let index: u16 = kani::any();
    kani::assume(count >= 2 && count <= 64);
    let expected = (index as u32) <= (count as u32) - 1;
    assert_eq!(option_in_range(count, index), expected);
}

/// One counter is classified exactly: the next one is `mark + 1`, a
/// regression is at or below the mark, a gap is beyond `mark + 1`.
#[kani::proof]
fn counter_check_is_exact() {
    let mark: u64 = kani::any();
    let counter: u64 = kani::any();
    let (m, c) = (mark as u128, counter as u128);
    let expected = if c <= m {
        CounterCheck::Regression
    } else if c == m + 1 {
        CounterCheck::Next
    } else {
        CounterCheck::Gap
    };
    assert_eq!(check_counter(mark, counter), expected);
}

/// Over a sequence of four issues with arbitrary counters (replays,
/// regressions, gaps included), the mark moves only on an accepted
/// counter, moves to exactly that counter, never decreases, and no counter
/// is accepted twice.
#[kani::proof]
#[kani::unwind(5)]
fn counter_mark_never_reuses() {
    let start: u64 = kani::any();
    let mut mark = start;
    let mut accepted = [0u64; 4];
    let mut n = 0usize;
    for _ in 0..4 {
        let counter: u64 = kani::any();
        let before = mark;
        let check = advance_mark(&mut mark, counter);
        if check == CounterCheck::Next {
            assert_eq!(mark, counter);
            assert_eq!(mark as u128, before as u128 + 1);
            for &previous in &accepted[..n] {
                assert_ne!(previous, counter);
            }
            accepted[n] = counter;
            n += 1;
        } else {
            assert_eq!(mark, before);
        }
        assert!(mark >= before);
    }
    assert_eq!(mark as u128, start as u128 + n as u128);
}

/// The pad consumption is the member share length plus the two 32-byte
/// keys, and the pad index is `counter × b` whenever it fits in 64 bits.
#[kani::proof]
fn pad_index_arithmetic_is_exact() {
    let len: usize = kani::any();
    kani::assume(len >= 62 + 32 && len <= 62 + 32 * 50 + 24);
    let b = pad_consumption(len).unwrap();
    assert_eq!(b as u128, len as u128 + PAD_KEY_BYTES as u128);
    let counter: u64 = kani::any();
    let product = (counter as u128) * (b as u128);
    match pad_index(counter, b) {
        Some(index) => assert_eq!(index as u128, product),
        None => assert!(product > u64::MAX as u128),
    }
}

/// The module signs a batch exactly when its pending counters are the
/// contiguous range `first..=last` in order (up to four pending counters).
#[kani::proof]
#[kani::unwind(6)]
fn module_batch_rule_is_exact() {
    let len: usize = kani::any();
    kani::assume(len <= 4);
    let pending: [u64; 4] = kani::any();
    let first: u64 = kani::any();
    let last: u64 = kani::any();
    let slice = &pending[..len];
    let mut contiguous = true;
    let mut i = 0;
    while i < len {
        if (slice[i] as u128) != (first as u128) + (i as u128) {
            contiguous = false;
        }
        i += 1;
    }
    let expected =
        first <= last && (len as u128) == (last as u128) - (first as u128) + 1 && contiguous;
    assert_eq!(module_may_sign_batch(slice, first, last), expected);
}

/// A batch is due once it has no room left for a full visit (more than
/// 56 records), or when it holds a record and a full bucket has passed
/// since its last record.
#[kani::proof]
fn batch_trigger_is_exact() {
    let records: u16 = kani::any();
    let last: u64 = kani::any();
    let now: u64 = kani::any();
    let idle = (now as u128) >= (last as u128) + (BATCH_IDLE_BUCKETS as u128);
    let expected = records > BATCH_VISIT_START_MAX || (records > 0 && idle && last < u64::MAX);
    assert_eq!(batch_due(records, last, now), expected);
}

/// A scan count is due at fifty records since the last one, or eight
/// buckets after it.
#[kani::proof]
fn scan_count_trigger_is_exact() {
    let since: u64 = kani::any();
    let last: u64 = kani::any();
    let now: u64 = kani::any();
    let elapsed = (now as u128) >= (last as u128) + (SCAN_COUNT_BUCKETS as u128);
    let fits = (last as u128) + (SCAN_COUNT_BUCKETS as u128) <= u64::MAX as u128;
    let expected = since >= SCAN_COUNT_RECORDS || (elapsed && fits);
    assert_eq!(scan_count_due(since, last, now), expected);
}

/// Every close invariant of VC-038, for two modules and symbolic counts,
/// against the statement written out in 128-bit arithmetic.
#[kani::proof]
#[kani::unwind(12)] // the ten violation flags, plus slack
fn close_verdict_is_exact() {
    let counters: [u64; 2] = kani::any();
    let envelopes: Option<EnvelopeCounts> = if kani::any() {
        Some(EnvelopeCounts {
            envelopes: kani::any(),
            stickers: kani::any(),
            issued: kani::any(),
            returned_empty: kani::any(),
        })
    } else {
        None
    };
    let facts = CloseFacts {
        paper: kani::any(),
        records: kani::any(),
        visits: kani::any(),
        attested: kani::any(),
        open_batch_records: kani::any(),
        without_record: kani::any(),
        challenged: kani::any(),
        quarantined: kani::any(),
        spoiled_envelopes: kani::any(),
        module_final_counters: &counters,
        open_batches: kani::any(),
        envelopes,
        fallback_declared: kani::any(),
        paper_incidents: kani::any(),
    };
    let v = close_verdict(&facts);
    let records = facts.records as u128;
    let consumed = records + facts.challenged as u128 + facts.quarantined as u128;
    let paper_expected = match envelopes {
        Some(_) => 0,
        None => records + facts.without_record as u128,
    };
    assert_eq!(
        v.contains(Invariant::PaperCount),
        paper_expected != facts.paper as u128
    );
    assert_eq!(
        v.contains(Invariant::AttestedCount),
        facts.attested as u128 + facts.open_batch_records as u128 != records
    );
    assert_eq!(
        v.contains(Invariant::SpoiledEnvelopes),
        facts.challenged as u128 + facts.quarantined as u128 != facts.spoiled_envelopes as u128
    );
    assert_eq!(
        v.contains(Invariant::ModuleCounters),
        counters[0] as u128 != consumed || counters[1] as u128 != consumed
    );
    assert_eq!(v.contains(Invariant::OpenBatches), facts.open_batches != 0);
    let visits = facts.visits as u128;
    assert_eq!(
        v.contains(Invariant::VisitCount),
        visits > records || records > 8 * visits
    );
    assert_eq!(
        v.contains(Invariant::EnvelopeCount),
        matches!(envelopes, Some(e) if e.issued as i128 - e.returned_empty as i128 != e.envelopes as i128)
    );
    assert_eq!(
        v.contains(Invariant::StickerCount),
        matches!(envelopes, Some(e) if e.stickers != facts.visits)
    );
    assert_eq!(
        v.contains(Invariant::FallbackDeclared),
        facts.without_record > 0 && !facts.fallback_declared
    );
    assert_eq!(
        v.contains(Invariant::PaperIncidents),
        facts.paper_incidents > 0
    );
    let any = v.contains(Invariant::PaperCount)
        || v.contains(Invariant::AttestedCount)
        || v.contains(Invariant::SpoiledEnvelopes)
        || v.contains(Invariant::ModuleCounters)
        || v.contains(Invariant::OpenBatches)
        || v.contains(Invariant::EnvelopeCount)
        || v.contains(Invariant::FallbackDeclared)
        || v.contains(Invariant::PaperIncidents)
        || v.contains(Invariant::VisitCount)
        || v.contains(Invariant::StickerCount);
    assert_eq!(v.is_empty(), !any);
}

fn any_choice() -> Choice {
    if kani::any() {
        Choice::Cast
    } else {
        Choice::Check
    }
}

fn any_settlement() -> Settlement {
    match kani::any::<u8>() % 3 {
        0 => Settlement::Open,
        1 => Settlement::Imprinted,
        _ => Settlement::Quarantined,
    }
}

fn any_stage() -> VisitStage {
    match kani::any::<u8>() % 3 {
        0 => VisitStage::None,
        1 => VisitStage::Undecided,
        _ => VisitStage::Decided,
    }
}

/// The resume rule of PROTOCOL.md §7.3 (VC-069) is total and leaves
/// nothing owed, for every last visit of up to eight positions and every
/// attested waiting area: a plan never names a paper beyond those
/// attested; a case-4 plan journals nothing and holds every paper; a
/// case-1 plan quarantines every paper (the undecided positions by record
/// hash, the rest without record); a case-2 or case-3 plan follows a
/// decision, and once applied every cast position is settled, and out of
/// district without a sticker entry none is left cast; an imprint entry is
/// appended only for an imprinted front paper in person.
#[kani::proof]
#[kani::unwind(10)]
fn the_resume_plan_is_total_and_settles_every_cast_position() {
    let mut visit = VisitState::NONE;
    visit.stage = any_stage();
    visit.positions = kani::any();
    kani::assume(usize::from(visit.positions) <= VISIT_POSITIONS);
    visit.label_printed = kani::any();
    for (choice, settled) in visit.choices.iter_mut().zip(visit.settled.iter_mut()) {
        *choice = any_choice();
        *settled = any_settlement();
    }
    let area = WaitingArea {
        papers: kani::any(),
        front_imprinted: kani::any(),
        sticker_printed: kani::any(),
    };
    kani::assume(area.papers <= 9);
    let absentee: bool = kani::any();
    let plan = resume_plan(&visit, area, absentee);
    assert_eq!(plan.paper_count, area.papers);
    let n = usize::from(visit.positions);
    let papers = usize::from(area.papers).min(VISIT_POSITIONS);
    let acts = &plan.papers[..papers];
    match plan.case {
        ResumeCase::Nothing => {
            assert_eq!(area.papers, 0);
            assert!(plan.imprint.is_none() && plan.unjournaled == 0 && !plan.incident);
            assert!(!plan.quarantine.iter().any(|&q| q));
        }
        ResumeCase::Inconsistent => {
            assert!(plan.incident);
            assert!(plan.imprint.is_none() && plan.unjournaled == 0);
            assert!(!plan.quarantine.iter().any(|&q| q));
            assert!(acts.iter().all(|&a| a == PaperAction::Hold));
        }
        ResumeCase::BeforeDecision => {
            assert!(acts.iter().all(|&a| a == PaperAction::Quarantine));
            assert!(plan.imprint.is_none());
            for p in 0..VISIT_POSITIONS {
                let undecided = visit.stage == VisitStage::Undecided && p < n;
                assert_eq!(plan.quarantine[p], undecided);
            }
            let named = if visit.stage == VisitStage::Undecided {
                visit.positions
            } else {
                0
            };
            assert_eq!(plan.unjournaled, area.papers.saturating_sub(named));
        }
        ResumeCase::AfterDecision | ResumeCase::LabelMissing => {
            assert_eq!(visit.stage, VisitStage::Decided);
            assert!(usize::from(area.papers) <= n);
            assert_eq!(plan.unjournaled, 0);
            assert!(acts.iter().all(|&a| a != PaperAction::Hold));
            if plan.case == ResumeCase::LabelMissing {
                assert!(absentee && area.papers == 0);
            }
            if let Some(p) = plan.imprint {
                assert!(area.front_imprinted && !absentee);
                assert_eq!(usize::from(p), n - usize::from(area.papers));
            }
            let mut live_after = false;
            for p in 0..n {
                let cast = visit.choices[p] == Choice::Cast;
                if !cast {
                    assert!(!plan.quarantine[p]);
                    continue;
                }
                let settled_after = if plan.quarantine[p] {
                    Settlement::Quarantined
                } else if plan.imprint == Some(p as u8) {
                    Settlement::Imprinted
                } else {
                    visit.settled[p]
                };
                assert!(settled_after != Settlement::Open);
                if settled_after == Settlement::Imprinted {
                    live_after = true;
                }
            }
            if absentee && !visit.label_printed {
                assert!(!live_after);
            }
        }
    }
}
