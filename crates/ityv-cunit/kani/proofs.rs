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
//! * module counter continuity (PROTOCOL.md §7.2);
//! * the pad consumption and pad index of §9.4.3 (VC-034);
//! * the module's batch-signing rule (VC-021);
//! * the batch and scan-count triggers (§7.2.1, §7.8, VC-052);
//! * every close invariant of §10.2 (VC-038).
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
    BATCH_IDLE_BUCKETS, BATCH_MAX_RECORDS, CloseFacts, PAD_KEY_BYTES, SCAN_COUNT_BUCKETS,
    SCAN_COUNT_RECORDS, batch_due, close_verdict, counter_follows, option_in_range,
    pad_consumption, pad_index, scan_count_due,
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

/// A counter follows exactly when it is one more than the previous, and
/// the largest counter has no successor.
#[kani::proof]
fn counter_continuity_is_exact() {
    let previous: u64 = kani::any();
    let counter: u64 = kani::any();
    let expected = (counter as u128) == (previous as u128) + 1;
    assert_eq!(counter_follows(previous, counter), expected);
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

/// A batch is due at 64 records, or when it holds a record and a full
/// bucket has passed since its last record.
#[kani::proof]
fn batch_trigger_is_exact() {
    let records: u16 = kani::any();
    let last: u64 = kani::any();
    let now: u64 = kani::any();
    let idle = (now as u128) >= (last as u128) + (BATCH_IDLE_BUCKETS as u128);
    let expected = records >= BATCH_MAX_RECORDS || (records > 0 && idle && last < u64::MAX);
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
#[kani::unwind(4)]
fn close_verdict_is_exact() {
    let counters: [u64; 2] = kani::any();
    let absentee: Option<u64> = kani::any();
    let facts = CloseFacts {
        paper: kani::any(),
        records: kani::any(),
        attested: kani::any(),
        open_batch_records: kani::any(),
        without_record: kani::any(),
        challenged: kani::any(),
        quarantined: kani::any(),
        spoiled_envelopes: kani::any(),
        module_final_counters: &counters,
        open_batches: kani::any(),
        absentee_envelopes: absentee,
        fallback_declared: kani::any(),
    };
    let v = close_verdict(&facts);
    let records = facts.records as u128;
    let consumed = records + facts.challenged as u128 + facts.quarantined as u128;
    assert_eq!(
        v.contains(Invariant::PaperCount),
        records + facts.without_record as u128 != facts.paper as u128
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
    assert_eq!(
        v.contains(Invariant::EnvelopeCount),
        matches!(absentee, Some(n) if n != facts.records)
    );
    assert_eq!(
        v.contains(Invariant::FallbackDeclared),
        facts.without_record > 0 && !facts.fallback_declared
    );
    let any = v.contains(Invariant::PaperCount)
        || v.contains(Invariant::AttestedCount)
        || v.contains(Invariant::SpoiledEnvelopes)
        || v.contains(Invariant::ModuleCounters)
        || v.contains(Invariant::OpenBatches)
        || v.contains(Invariant::EnvelopeCount)
        || v.contains(Invariant::FallbackDeclared);
    assert_eq!(v.is_empty(), !any);
}
