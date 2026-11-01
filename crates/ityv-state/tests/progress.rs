//! The voting progress record (ADR-0027, PROTOCOL.md §7.10): device
//! streams against real hybrid signatures (VC-102), the station alarms and
//! their on-site checks (VC-103), and a property test against an
//! independently written reference evaluator.
// Integration tests: outside the TCB. Assertions use unwrap/expect, so these
// lints are relaxed for this file only (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::many_single_char_names
)]

mod common;

use common::{
    By, WITNESSES, box_id, close_parts, counts, election, issuance, leak, misregistered, module,
    object, other_box, other_election, roster, signed_by, signed_close, station, witnessed,
};
use ityv_crypto::{HybridSigningKey, HybridVerifyingKey};
use ityv_encoding::{
    BoxId, BoxProgressBody, BoxProgressParts, BoxProgressState, CheckinProgressBody,
    CheckinProgressParts, CheckinProgressState, Hash512, ProgressAlarm, ProgressCheckBody,
    ProgressCheckParts, ProgressFinding, ProgressTick, SCHEMA_BOX_PROGRESS_BODY,
    SCHEMA_CHECKIN_PROGRESS_BODY, SCHEMA_PROGRESS_CHECK_BODY, StationId, StationProgressPolicy,
    TimeBucket, UnitId,
};
use ityv_state::{
    BoxStream, CheckinStream, Error, HoldReason, HoldSet, IssuanceCount, MAX_STATION_BOXES, Signed,
    StationProgress, check_tick, out_of,
};
use std::vec::Vec;

fn unit_key() -> &'static HybridSigningKey {
    leak(HybridSigningKey::from_seeds([60; 32], [61; 32]))
}

fn spare_key() -> &'static HybridSigningKey {
    leak(HybridSigningKey::from_seeds([62; 32], [63; 32]))
}

fn vk(key: &'static HybridSigningKey) -> &'static HybridVerifyingKey {
    leak(key.verifying_key())
}

fn box_body(
    box_id: BoxId<'static>,
    slot: u64,
    sheets_in: u64,
    state: BoxProgressState,
) -> &'static BoxProgressBody<'static> {
    leak(BoxProgressBody::new(&BoxProgressParts {
        election_id: election(),
        box_id,
        slot,
        sheets_in,
        state,
    }))
}

fn checkin_body(
    slot: u64,
    c: [u64; 4],
    state: CheckinProgressState,
) -> CheckinProgressBody<'static> {
    CheckinProgressBody::new(&CheckinProgressParts {
        election_id: election(),
        station_id: station(),
        unit_id: UnitId::new(b"UNIT-1").unwrap(),
        slot,
        checkins: c[0],
        issued: c[1],
        spoiled: c[2],
        returned: c[3],
        state,
    })
    .unwrap()
}

/// A signed tick over `body` (schema `schema`) by `key` under `purpose`.
fn tick<T: ityv_encoding::Encode>(
    schema: ityv_encoding::SchemaId,
    body: &T,
    key: &'static HybridSigningKey,
    purpose: &'static [u8],
) -> (
    &'static ProgressTick<'static>,
    &'static ityv_crypto::Verified<ityv_crypto::HybridSigned<'static>>,
) {
    let bytes = object(schema, body);
    let (sig, token) = signed_by(key, purpose, bytes);
    (leak(ProgressTick::new(bytes, sig).unwrap()), leak(token))
}

fn box_tick(
    slot: u64,
    sheets_in: u64,
    state: BoxProgressState,
) -> (
    &'static ProgressTick<'static>,
    &'static ityv_crypto::Verified<ityv_crypto::HybridSigned<'static>>,
) {
    tick(
        SCHEMA_BOX_PROGRESS_BODY,
        box_body(box_id(), slot, sheets_in, state),
        common::device_key(),
        b"box-progress",
    )
}

fn checkin_tick(
    key: &'static HybridSigningKey,
    slot: u64,
    c: [u64; 4],
    state: CheckinProgressState,
) -> (
    &'static ProgressTick<'static>,
    &'static ityv_crypto::Verified<ityv_crypto::HybridSigned<'static>>,
) {
    tick(
        SCHEMA_CHECKIN_PROGRESS_BODY,
        &checkin_body(slot, c, state),
        key,
        b"checkin-progress",
    )
}

fn stream_hold() -> HoldSet {
    HoldSet::empty().with(HoldReason::ProgressStream)
}

#[test]
fn box_stream_signatures_and_identity() {
    let device = vk(common::device_key());
    let mut s = BoxStream::open(election(), box_id(), device, 10);
    let (t, k) = box_tick(10, 3, BoxProgressState::Casting);
    let body = s.accept(t, k).unwrap().unwrap();
    assert_eq!(body.parts().sheets_in, 3);
    assert!(s.holds().is_empty());
    assert_eq!(check_tick(t, k, device), Ok(()));
    // Another key.
    assert_eq!(
        check_tick(t, k, vk(unit_key())),
        Err(Error::SignatureSigner)
    );
    // A signature under the other purpose.
    let (t2, k2) = tick(
        SCHEMA_BOX_PROGRESS_BODY,
        box_body(box_id(), 11, 4, BoxProgressState::Casting),
        common::device_key(),
        b"checkin-progress",
    );
    assert_eq!(s.accept(t2, k2), Err(Error::SignatureObject));
    // A token for another tick.
    let (t3, _) = box_tick(11, 4, BoxProgressState::Casting);
    assert_eq!(s.accept(t3, k), Err(Error::SignatureObject));
    // A check-in tick, another box, another election.
    let (c, ck) = checkin_tick(
        common::device_key(),
        11,
        [1, 1, 0, 0],
        CheckinProgressState::Checking,
    );
    assert_eq!(s.accept(c, ck), Err(Error::Mismatch));
    let (o, ok) = tick(
        SCHEMA_BOX_PROGRESS_BODY,
        box_body(other_box(), 11, 4, BoxProgressState::Casting),
        common::device_key(),
        b"box-progress",
    );
    assert_eq!(s.accept(o, ok), Err(Error::Mismatch));
    let other = leak(BoxProgressBody::new(&BoxProgressParts {
        election_id: other_election(),
        box_id: box_id(),
        slot: 11,
        sheets_in: 4,
        state: BoxProgressState::Casting,
    }));
    let (o, ok) = tick(
        SCHEMA_BOX_PROGRESS_BODY,
        other,
        common::device_key(),
        b"box-progress",
    );
    assert_eq!(s.accept(o, ok), Err(Error::Mismatch));
    // None of the refused ticks changed the stream.
    let (t, k) = box_tick(11, 4, BoxProgressState::Casting);
    assert!(s.accept(t, k).unwrap().is_some());
    assert!(s.holds().is_empty());
}

#[test]
fn box_stream_slot_rules() {
    let device = vk(common::device_key());
    let feed = |s: &mut BoxStream<'static>, slot, n, state| {
        let (t, k) = box_tick(slot, n, state);
        s.accept(t, k).unwrap()
    };
    // Before opening.
    let mut s = BoxStream::open(election(), box_id(), device, 10);
    assert!(feed(&mut s, 9, 0, BoxProgressState::Casting).is_none());
    assert_eq!(s.holds(), stream_hold());
    // A second tick for a slot.
    let mut s = BoxStream::open(election(), box_id(), device, 10);
    assert!(feed(&mut s, 10, 1, BoxProgressState::Casting).is_some());
    assert!(feed(&mut s, 10, 1, BoxProgressState::Casting).is_none());
    assert_eq!(s.holds(), stream_hold());
    // A gap: the later tick is used, the stream holds.
    let mut s = BoxStream::open(election(), box_id(), device, 10);
    assert!(feed(&mut s, 10, 1, BoxProgressState::Casting).is_some());
    assert!(feed(&mut s, 12, 2, BoxProgressState::Casting).is_some());
    assert_eq!(s.holds(), stream_hold());
    // A count going down.
    let mut s = BoxStream::open(election(), box_id(), device, 10);
    assert!(feed(&mut s, 10, 5, BoxProgressState::Casting).is_some());
    assert!(feed(&mut s, 11, 4, BoxProgressState::Casting).is_some());
    assert_eq!(s.holds(), stream_hold());
    // Equal counts are fine; after the closing tick nothing is taken.
    let mut s = BoxStream::open(election(), box_id(), device, 10);
    assert!(feed(&mut s, 10, 5, BoxProgressState::Casting).is_some());
    assert!(feed(&mut s, 11, 5, BoxProgressState::Fallback).is_some());
    assert!(feed(&mut s, 12, 6, BoxProgressState::Closed).is_some());
    assert!(s.holds().is_empty());
    assert!(feed(&mut s, 13, 6, BoxProgressState::Closed).is_none());
    assert_eq!(s.holds(), stream_hold());
    // Slot overflow is an error, not a panic.
    let mut s = BoxStream::open(election(), box_id(), device, u64::MAX);
    let (t, k) = box_tick(u64::MAX, 1, BoxProgressState::Casting);
    assert_eq!(s.accept(t, k), Err(Error::Overflow));
}

#[test]
fn box_stream_close_and_swap() {
    let device = vk(common::device_key());
    // records 10 + challenged 2 + quarantined 0 = 12.
    let close = leak(signed_close(&close_parts(
        counts(10, 10, 2),
        &[module(b"MOD-P1"), module(b"MOD-P2")],
    )));
    let feed = |s: &mut BoxStream<'static>, slot, n, state| {
        let (t, k) = box_tick(slot, n, state);
        s.accept(t, k).unwrap()
    };
    let mut s = BoxStream::open(election(), box_id(), device, 10);
    feed(&mut s, 10, 5, BoxProgressState::Casting);
    feed(&mut s, 11, 12, BoxProgressState::Closed);
    assert!(s.finish(&close.close).is_empty());
    // Not closed by a closing tick.
    let mut s = BoxStream::open(election(), box_id(), device, 10);
    feed(&mut s, 10, 12, BoxProgressState::Casting);
    assert_eq!(s.finish(&close.close), stream_hold());
    // Closed with another count.
    let mut s = BoxStream::open(election(), box_id(), device, 10);
    feed(&mut s, 10, 11, BoxProgressState::Closed);
    assert_eq!(s.finish(&close.close), stream_hold());
    // A close whose counts overflow.
    let mut parts = close_parts(counts(10, 10, 2), &[]);
    parts.counts.records = u64::MAX;
    let big = leak(signed_close(&parts));
    let mut s = BoxStream::open(election(), box_id(), device, 10);
    feed(&mut s, 10, 1, BoxProgressState::Closed);
    assert_eq!(s.finish(&big.close), stream_hold());
    // Even a stream with no hold of its own.
    assert!(s.holds().is_empty());

    // A replaced scanner: the spare continues from the confirmed count;
    // the slots of the swap are excused.
    let spare = spare_key();
    let mut s = BoxStream::open(election(), box_id(), device, 10);
    feed(&mut s, 10, 4, BoxProgressState::Casting);
    s.swap(vk(spare), 14, 5);
    let (t, k) = tick(
        SCHEMA_BOX_PROGRESS_BODY,
        box_body(box_id(), 14, 12, BoxProgressState::Closed),
        spare,
        b"box-progress",
    );
    assert!(s.accept(t, k).unwrap().is_some());
    assert!(s.finish(&close.close).is_empty());
    // The old device's key no longer works.
    let mut s = BoxStream::open(election(), box_id(), device, 10);
    s.swap(vk(spare), 10, 0);
    let (t, k) = box_tick(10, 1, BoxProgressState::Casting);
    assert_eq!(s.accept(t, k), Err(Error::SignatureSigner));
    // A swap that lowers the count, comes after close, or claims a slot
    // before the last tick holds.
    let mut s = BoxStream::open(election(), box_id(), device, 10);
    feed(&mut s, 10, 4, BoxProgressState::Casting);
    s.swap(vk(spare), 11, 3);
    assert_eq!(s.holds(), stream_hold());
    let mut s = BoxStream::open(election(), box_id(), device, 10);
    feed(&mut s, 10, 4, BoxProgressState::Closed);
    s.swap(vk(spare), 11, 4);
    assert_eq!(s.holds(), stream_hold());
    let mut s = BoxStream::open(election(), box_id(), device, 10);
    feed(&mut s, 10, 4, BoxProgressState::Casting);
    feed(&mut s, 11, 4, BoxProgressState::Casting);
    feed(&mut s, 12, 4, BoxProgressState::Casting);
    s.swap(vk(spare), 11, 4);
    assert_eq!(s.holds(), stream_hold());
    // A swap at the slot after the last tick is clean.
    let mut s = BoxStream::open(election(), box_id(), device, 10);
    feed(&mut s, 10, 4, BoxProgressState::Casting);
    s.swap(vk(spare), 11, 4);
    assert!(s.holds().is_empty());
    let mut s = BoxStream::open(election(), box_id(), device, 10);
    feed(&mut s, 10, 4, BoxProgressState::Casting);
    s.swap(vk(spare), 10, 4);
    assert!(s.holds().is_empty());
}

#[test]
fn checkin_stream_rules() {
    let unit = unit_key();
    let mut s = CheckinStream::open(election(), station(), vk(unit), 10);
    let (t, k) = checkin_tick(unit, 10, [2, 4, 1, 0], CheckinProgressState::Checking);
    assert!(s.accept(t, k).unwrap().is_some());
    // Each of the four counts is watched for going down.
    for i in 0..4 {
        let mut s = CheckinStream::open(election(), station(), vk(unit), 10);
        let (t, k) = checkin_tick(unit, 10, [2, 4, 1, 1], CheckinProgressState::Checking);
        s.accept(t, k).unwrap();
        let mut c = [2, 4, 1, 1];
        c[i] -= 1;
        if c[2] + c[3] > c[1] {
            continue;
        }
        let (t, k) = checkin_tick(unit, 11, c, CheckinProgressState::Checking);
        s.accept(t, k).unwrap();
        assert_eq!(s.holds(), stream_hold(), "count {i}");
    }
    // Box ticks, another station, another key.
    let (b, bk) = box_tick(11, 1, BoxProgressState::Casting);
    assert_eq!(s.accept(b, bk), Err(Error::SignatureSigner));
    let mut d = CheckinStream::open(election(), station(), vk(common::device_key()), 10);
    assert_eq!(d.accept(b, bk), Err(Error::Mismatch));
    let other = CheckinProgressBody::new(&CheckinProgressParts {
        election_id: election(),
        station_id: StationId::new(b"ST-2").unwrap(),
        unit_id: UnitId::new(b"UNIT-1").unwrap(),
        slot: 11,
        checkins: 2,
        issued: 4,
        spoiled: 1,
        returned: 0,
        state: CheckinProgressState::Checking,
    })
    .unwrap();
    let (o, ok) = tick(
        SCHEMA_CHECKIN_PROGRESS_BODY,
        &other,
        unit,
        b"checkin-progress",
    );
    assert_eq!(s.accept(o, ok), Err(Error::Mismatch));
    let elsewhere = CheckinProgressBody::new(&CheckinProgressParts {
        election_id: other_election(),
        ..*other.parts()
    })
    .unwrap();
    let elsewhere = CheckinProgressBody::new(&CheckinProgressParts {
        station_id: station(),
        ..*elsewhere.parts()
    })
    .unwrap();
    let (o, ok) = tick(
        SCHEMA_CHECKIN_PROGRESS_BODY,
        &elsewhere,
        unit,
        b"checkin-progress",
    );
    assert_eq!(s.accept(o, ok), Err(Error::Mismatch));
    assert!(s.holds().is_empty());

    // Close: issuance 40 issued, 0 spoiled, 0 returned; observers 38.
    let issued = IssuanceCount::check(&issuance(None, &WITNESSES), roster()).unwrap();
    let mut s = CheckinStream::open(election(), station(), vk(unit), 10);
    let (t, k) = checkin_tick(unit, 10, [38, 40, 0, 0], CheckinProgressState::Closed);
    s.accept(t, k).unwrap();
    assert!(s.finish(&issued, 38).is_empty());
    assert_eq!(s.finish(&issued, 37), stream_hold());
    let mut s = CheckinStream::open(election(), station(), vk(unit), 10);
    let (t, k) = checkin_tick(unit, 10, [38, 40, 0, 0], CheckinProgressState::Checking);
    s.accept(t, k).unwrap();
    assert_eq!(s.finish(&issued, 38), stream_hold());
    for c in [[38, 39, 0, 0], [38, 40, 1, 0], [38, 40, 0, 1]] {
        let mut s = CheckinStream::open(election(), station(), vk(unit), 10);
        let (t, k) = checkin_tick(unit, 10, c, CheckinProgressState::Closed);
        s.accept(t, k).unwrap();
        assert_eq!(s.finish(&issued, 38), stream_hold());
    }
    // A unit swap continues from the counts the swap confirms.
    let spare = spare_key();
    let mut s = CheckinStream::open(election(), station(), vk(unit), 10);
    let (t, k) = checkin_tick(unit, 10, [10, 11, 0, 0], CheckinProgressState::Checking);
    s.accept(t, k).unwrap();
    s.swap(vk(spare), 13, [12, 13, 0, 0]);
    let (t, k) = checkin_tick(spare, 13, [38, 40, 0, 0], CheckinProgressState::Closed);
    assert!(s.accept(t, k).unwrap().is_some());
    assert!(s.finish(&issued, 38).is_empty());
}

// --- station ----------------------------------------------------------------

const LIMIT: u32 = 6;

fn policy() -> StationProgressPolicy<'static> {
    StationProgressPolicy::new(station(), 3, LIMIT).unwrap()
}

fn evaluator() -> StationProgress<'static> {
    StationProgress::new(election(), &policy(), &[box_id()]).unwrap()
}

/// Feeds slot `slot` with `issued` sheets issued and `sheets_in` in the box
/// (no spoiled or returned) and closes it.
fn step(
    e: &mut StationProgress<'static>,
    slot: u64,
    issued: u64,
    sheets_in: u64,
) -> ityv_state::SlotOutcome {
    e.record_checkin(&checkin_body(
        slot,
        [issued, issued, 0, 0],
        CheckinProgressState::Checking,
    ))
    .unwrap();
    e.record_box(box_body(
        box_id(),
        slot,
        sheets_in,
        BoxProgressState::Casting,
    ))
    .unwrap();
    e.close_slot(slot).unwrap()
}

fn check(
    alarm: ProgressAlarm,
    alarm_slot: u64,
    finding: ProgressFinding,
    carried_out: u64,
) -> Signed<'static> {
    check_by(
        alarm,
        alarm_slot,
        finding,
        carried_out,
        &WITNESSES,
        station(),
    )
}

fn check_by(
    alarm: ProgressAlarm,
    alarm_slot: u64,
    finding: ProgressFinding,
    carried_out: u64,
    who: &[By],
    station_id: StationId<'static>,
) -> Signed<'static> {
    let body = object(
        SCHEMA_PROGRESS_CHECK_BODY,
        &ProgressCheckBody::new(&ProgressCheckParts {
            election_id: election(),
            station_id,
            alarm_slot,
            alarm,
            holding: 0,
            finding,
            carried_out,
            statement_hash: Hash512([9; 64]),
            time_bucket: TimeBucket::new(1),
        })
        .unwrap(),
    );
    witnessed(body, who)
}

fn unresolved() -> HoldSet {
    HoldSet::empty().with(HoldReason::ProgressUnresolved)
}

#[test]
fn quiet_station_without_sheets_outside_raises_nothing() {
    let mut e = evaluator();
    assert!(!e.suspended());
    // Nobody comes for four slots, then five sheets go in and stay in.
    for s in 0..4 {
        let o = step(&mut e, s, 0, 0);
        assert_eq!(o.out, 0);
        assert!(o.raised.is_empty());
    }
    for s in 4..8 {
        assert!(step(&mut e, s, 5, 5).raised.is_empty());
    }
    assert!(e.finish().is_empty());
    assert!(!e.suspended());
    assert!(!e.counterfoil_required());
}

#[test]
fn chain_voting_raises_the_floor_alarm_once() {
    let mut e = evaluator();
    // One sheet leaves at slot 1 and never comes back; slots 2–5 are
    // quiet.
    assert!(step(&mut e, 0, 0, 0).raised.is_empty());
    assert!(step(&mut e, 1, 3, 2).raised.is_empty());
    assert!(step(&mut e, 2, 3, 2).raised.is_empty());
    let o = step(&mut e, 3, 3, 2);
    assert_eq!(o.out, 1);
    assert!(o.raised.contains(ProgressAlarm::Floor));
    assert!(!o.raised.is_empty());
    assert!(!o.raised.contains(ProgressAlarm::High));
    assert!(step(&mut e, 4, 3, 2).raised.is_empty());
    assert_eq!(e.waiting().collect::<Vec<_>>(), [(ProgressAlarm::Floor, 3)]);
    // The check confirms one sheet carried out.
    e.record_check(
        &check(ProgressAlarm::Floor, 3, ProgressFinding::CarriedOut, 1),
        roster(),
        4,
    )
    .unwrap();
    assert_eq!(e.holds(), HoldSet::empty().with(HoldReason::CarryOut));
    assert!(e.counterfoil_required());
    assert_eq!(e.out(), Ok(0));
    assert_eq!(e.waiting().count(), 0);
    // The relay continues: the next voter brings the marked sheet in and
    // takes the new one out — the gap stays at one sheet on top of the
    // one already counted, and the next quiet stretch raises again.
    assert!(step(&mut e, 5, 4, 3).raised.is_empty());
    assert!(step(&mut e, 6, 5, 3).raised.is_empty());
    assert!(step(&mut e, 7, 5, 3).raised.is_empty());
    assert!(step(&mut e, 8, 5, 3).raised.contains(ProgressAlarm::Floor));
    assert!(e.finish().contains(HoldReason::ProgressUnresolved));
}

#[test]
fn negative_and_high_need_two_slots() {
    let mut e = evaluator();
    step(&mut e, 0, 0, 0);
    // One slot negative, then fine: nothing.
    assert!(step(&mut e, 1, 2, 3).raised.is_empty());
    assert!(step(&mut e, 2, 4, 3).raised.is_empty());
    // Two slots negative: one alarm, then no repeat while it lasts.
    assert!(step(&mut e, 3, 4, 5).raised.is_empty());
    let o = step(&mut e, 4, 5, 7);
    assert_eq!(o.out, -2);
    assert!(o.raised.contains(ProgressAlarm::Negative));
    assert!(step(&mut e, 5, 5, 7).raised.is_empty());
    assert!(step(&mut e, 6, 6, 8).raised.is_empty());
    // Fixed, then two slots negative again: a new alarm.
    step(&mut e, 7, 8, 8);
    step(&mut e, 8, 8, 9);
    assert!(
        step(&mut e, 9, 8, 9)
            .raised
            .contains(ProgressAlarm::Negative)
    );

    let mut e = evaluator();
    step(&mut e, 0, 0, 0);
    assert!(step(&mut e, 1, 7, 0).raised.is_empty());
    let o = step(&mut e, 2, 8, 1);
    assert_eq!(o.out, 7);
    assert!(o.raised.contains(ProgressAlarm::High));
    // At the limit exactly: no alarm.
    let mut e = evaluator();
    step(&mut e, 0, 6, 0);
    assert!(step(&mut e, 1, 7, 1).raised.is_empty());
}

#[test]
fn findings() {
    // Floor, explained by a slow voter: resolved, no hold.
    let mut e = evaluator();
    for (s, (i, n)) in [(0, 0), (2, 1), (2, 1), (2, 1)].into_iter().enumerate() {
        step(&mut e, s as u64, i, n);
    }
    e.record_check(
        &check(ProgressAlarm::Floor, 3, ProgressFinding::Explained, 0),
        roster(),
        5,
    )
    .unwrap();
    assert!(e.holds().is_empty());
    assert!(!e.counterfoil_required());
    assert!(e.finish().is_empty());
    // Twice: the alarm no longer waits.
    assert_eq!(
        e.record_check(
            &check(ProgressAlarm::Floor, 3, ProgressFinding::Explained, 0),
            roster(),
            5
        ),
        Err(Error::Mismatch)
    );

    // Unexplained: hold and counterfoil.
    let mut e = evaluator();
    for (s, (i, n)) in [(0, 0), (2, 1), (2, 1), (2, 1)].into_iter().enumerate() {
        step(&mut e, s as u64, i, n);
    }
    e.record_check(
        &check(ProgressAlarm::Floor, 3, ProgressFinding::Unexplained, 0),
        roster(),
        3,
    )
    .unwrap();
    assert_eq!(e.holds(), unresolved());
    assert!(e.counterfoil_required());

    // Negative: only a correction resolves it.
    let negative = || {
        let mut e = evaluator();
        step(&mut e, 0, 0, 0);
        step(&mut e, 1, 2, 3);
        assert!(
            step(&mut e, 2, 2, 3)
                .raised
                .contains(ProgressAlarm::Negative)
        );
        e
    };
    let mut e = negative();
    e.record_check(
        &check(ProgressAlarm::Negative, 2, ProgressFinding::Explained, 0),
        roster(),
        3,
    )
    .unwrap();
    assert_eq!(e.holds(), unresolved());
    assert!(e.counterfoil_required());
    let mut e = negative();
    e.record_check(
        &check(ProgressAlarm::Negative, 2, ProgressFinding::CarriedOut, 1),
        roster(),
        3,
    )
    .unwrap();
    assert_eq!(e.holds(), unresolved().with(HoldReason::CarryOut));
    // A correction that fixes the counts by the next slot is accepted.
    let mut e = negative();
    e.record_check(
        &check(ProgressAlarm::Negative, 2, ProgressFinding::Corrected, 0),
        roster(),
        3,
    )
    .unwrap();
    assert_eq!(e.waiting().count(), 0);
    step(&mut e, 3, 2, 3); // same slot as the check: not judged yet
    assert!(e.holds().is_empty());
    step(&mut e, 4, 3, 3);
    assert!(e.holds().is_empty());
    assert!(!e.counterfoil_required());
    assert!(e.finish().is_empty());
    // One that does not fix them is unresolved.
    let mut e = negative();
    e.record_check(
        &check(ProgressAlarm::Negative, 2, ProgressFinding::Corrected, 0),
        roster(),
        2,
    )
    .unwrap();
    step(&mut e, 3, 2, 3);
    assert_eq!(e.holds(), unresolved());
    assert!(e.counterfoil_required());

    // High, explained by the queue.
    let mut e = evaluator();
    step(&mut e, 0, 0, 0);
    step(&mut e, 1, 7, 0);
    step(&mut e, 2, 8, 0);
    e.record_check(
        &check(ProgressAlarm::High, 2, ProgressFinding::Explained, 0),
        roster(),
        4,
    )
    .unwrap();
    assert!(e.holds().is_empty());
}

#[test]
fn check_window_and_identity() {
    let floor = || {
        let mut e = evaluator();
        for (s, (i, n)) in [(0, 0), (2, 1), (2, 1), (2, 1)].into_iter().enumerate() {
            step(&mut e, s as u64, i, n);
        }
        e
    };
    // Before the alarm slot or after the window.
    let mut e = floor();
    let c = check(ProgressAlarm::Floor, 3, ProgressFinding::Explained, 0);
    assert_eq!(e.record_check(&c, roster(), 2), Err(Error::LateWindow));
    assert_eq!(e.record_check(&c, roster(), 6), Err(Error::LateWindow));
    assert_eq!(e.record_check(&c, roster(), 3), Ok(()));
    // Another alarm or slot.
    let mut e = floor();
    assert_eq!(
        e.record_check(
            &check(ProgressAlarm::High, 3, ProgressFinding::Explained, 0),
            roster(),
            4
        ),
        Err(Error::Mismatch)
    );
    assert_eq!(
        e.record_check(
            &check(ProgressAlarm::Floor, 2, ProgressFinding::Explained, 0),
            roster(),
            4
        ),
        Err(Error::Mismatch)
    );
    // Another station, unregistered witnesses.
    let c = check_by(
        ProgressAlarm::Floor,
        3,
        ProgressFinding::Explained,
        0,
        &WITNESSES,
        StationId::new(b"ST-2").unwrap(),
    );
    assert_eq!(e.record_check(&c, roster(), 4), Err(Error::Mismatch));
    let c = check_by(
        ProgressAlarm::Floor,
        3,
        ProgressFinding::Explained,
        0,
        &misregistered(),
        station(),
    );
    assert_eq!(e.record_check(&c, roster(), 4), Err(Error::NotRegistered));
    // Another body in the envelope.
    let issuance_event = issuance(None, &WITNESSES);
    assert_eq!(
        e.record_check(&issuance_event, roster(), 4),
        Err(Error::Decode)
    );
    assert_eq!(e.waiting().count(), 1);
    // No check by the end of the window: unresolved at the slot after.
    step(&mut e, 4, 2, 1);
    step(&mut e, 5, 2, 1);
    assert!(e.holds().is_empty());
    step(&mut e, 6, 2, 1);
    assert_eq!(e.holds(), unresolved());
    assert!(e.counterfoil_required());
    assert_eq!(e.waiting().count(), 0);
}

#[test]
fn suspension_and_slot_order() {
    let mut e = evaluator();
    step(&mut e, 0, 0, 0);
    // Slots in order only; a refused close changes nothing.
    let before = e;
    assert_eq!(e.close_slot(5), Err(Error::Mismatch));
    assert_eq!(e, before);
    // A fallback tick suspends; no alarm afterwards.
    e.record_box(box_body(box_id(), 1, 0, BoxProgressState::Fallback))
        .unwrap();
    assert!(e.suspended());
    for s in 1..6 {
        e.record_checkin(&checkin_body(
            s,
            [9, 9, 0, 0],
            CheckinProgressState::Checking,
        ))
        .unwrap();
        assert!(e.close_slot(s).unwrap().raised.is_empty());
    }
    assert!(e.finish().is_empty());
    // A check-in tick after a swap suspends, as does the caller.
    let mut e = evaluator();
    e.record_checkin(&checkin_body(
        0,
        [1, 1, 0, 0],
        CheckinProgressState::AfterSwap,
    ))
    .unwrap();
    assert!(e.suspended());
    let mut e = evaluator();
    step(&mut e, 0, 0, 0);
    step(&mut e, 1, 2, 3);
    assert!(
        step(&mut e, 2, 2, 3)
            .raised
            .contains(ProgressAlarm::Negative)
    );
    e.suspend();
    // The alarm raised before still needs its check.
    for s in 3..6 {
        assert!(step(&mut e, s, 2, 3).raised.is_empty());
    }
    assert_eq!(e.holds(), unresolved());
}

#[test]
fn station_identity() {
    assert_eq!(
        StationProgress::new(election(), &policy(), &[]).unwrap_err(),
        Error::Overflow
    );
    let many: Vec<BoxId<'static>> = (0..=MAX_STATION_BOXES)
        .map(|i| BoxId::new(leak(std::format!("B-{i}")).as_bytes()).unwrap())
        .collect();
    assert_eq!(
        StationProgress::new(election(), &policy(), &many).unwrap_err(),
        Error::Overflow
    );
    assert!(StationProgress::new(election(), &policy(), &many[..MAX_STATION_BOXES]).is_ok());
    assert_eq!(
        StationProgress::new(election(), &policy(), &[box_id(), box_id()]).unwrap_err(),
        Error::Mismatch
    );
    let mut e = StationProgress::new(election(), &policy(), &[box_id(), other_box()]).unwrap();
    let unknown = BoxId::new(b"BOX-404").unwrap();
    assert_eq!(
        e.record_box(box_body(unknown, 0, 1, BoxProgressState::Casting)),
        Err(Error::Mismatch)
    );
    let elsewhere = BoxProgressBody::new(&BoxProgressParts {
        election_id: other_election(),
        box_id: box_id(),
        slot: 0,
        sheets_in: 1,
        state: BoxProgressState::Casting,
    });
    assert_eq!(e.record_box(&elsewhere), Err(Error::Mismatch));
    let other_station = CheckinProgressBody::new(&CheckinProgressParts {
        station_id: StationId::new(b"ST-2").unwrap(),
        ..*checkin_body(0, [1, 1, 0, 0], CheckinProgressState::Checking).parts()
    })
    .unwrap();
    assert_eq!(e.record_checkin(&other_station), Err(Error::Mismatch));
    let other_e = CheckinProgressBody::new(&CheckinProgressParts {
        election_id: other_election(),
        ..*checkin_body(0, [1, 1, 0, 0], CheckinProgressState::Checking).parts()
    })
    .unwrap();
    assert_eq!(e.record_checkin(&other_e), Err(Error::Mismatch));
    // Two boxes add up.
    e.record_box(box_body(box_id(), 0, 2, BoxProgressState::Casting))
        .unwrap();
    e.record_box(box_body(other_box(), 0, 3, BoxProgressState::Casting))
        .unwrap();
    e.record_checkin(&checkin_body(
        0,
        [6, 7, 1, 1],
        CheckinProgressState::Checking,
    ))
    .unwrap();
    assert_eq!(e.close_slot(0).unwrap().out, 0);
    assert_eq!(out_of(u64::MAX, 0, 0, 0, 0), Some(i128::from(u64::MAX)));
    assert_eq!(
        out_of(0, u64::MAX, u64::MAX, u64::MAX, u64::MAX),
        Some(-4 * i128::from(u64::MAX))
    );
}

// --- reference --------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct SlotIn {
    issued: u64,
    spoiled: u64,
    returned: u64,
    boxes: [u64; 2],
}

/// The alarm rules of PROTOCOL.md §7.10 item 4, written over whole arrays.
fn reference(
    slots: &[SlotIn],
    limit: i128,
    suspend_at: Option<usize>,
) -> (Vec<[bool; 3]>, Vec<i128>) {
    let n = slots.len();
    let out: Vec<i128> = slots
        .iter()
        .map(|s| {
            i128::from(s.issued)
                - i128::from(s.boxes[0])
                - i128::from(s.boxes[1])
                - i128::from(s.spoiled)
                - i128::from(s.returned)
        })
        .collect();
    let sum_in = |t: usize| slots[t].boxes[0] + slots[t].boxes[1];
    let quiet =
        |t: usize| t > 0 && slots[t].issued == slots[t - 1].issued && sum_in(t) == sum_in(t - 1);
    let suspended = |t: usize| suspend_at.is_some_and(|s| t >= s);
    let cond = |t: usize| -> [bool; 3] {
        if suspended(t) {
            return [false; 3];
        }
        [
            t > 0 && out[t] < 0 && out[t - 1] < 0,
            t > 0 && out[t] > limit && out[t - 1] > limit,
            t > 0 && quiet(t) && quiet(t - 1) && out[t] > 0,
        ]
    };
    let raised = (0..n)
        .map(|t| {
            let now = cond(t);
            let before = if t > 0 { cond(t - 1) } else { [false; 3] };
            [
                now[0] && !before[0],
                now[1] && !before[1],
                now[2] && !before[2],
            ]
        })
        .collect();
    (raised, out)
}

proptest::proptest! {
    #[test]
    fn evaluator_matches_reference(
        raw in proptest::collection::vec((0u64..6, 0u64..3, 0u64..3, 0u64..4, 0u64..4), 1..14),
        limit in 1u32..5,
        suspend in proptest::option::of(0usize..14),
    ) {
        let slots: Vec<SlotIn> = raw
            .iter()
            .map(|&(issued, s, r, a, b)| SlotIn {
                issued: issued + s + r,
                spoiled: s,
                returned: r,
                boxes: [a, b],
            })
            .collect();
        let policy = StationProgressPolicy::new(station(), 1, limit).unwrap();
        let mut e = StationProgress::new(election(), &policy, &[box_id(), other_box()]).unwrap();
        let (raised, out) = reference(&slots, i128::from(limit), suspend);
        for (t, s) in slots.iter().enumerate() {
            let slot = t as u64;
            e.record_checkin(&checkin_body(slot, [0, s.issued, s.spoiled, s.returned], CheckinProgressState::Checking)).unwrap();
            e.record_box(box_body(box_id(), slot, s.boxes[0], BoxProgressState::Casting)).unwrap();
            e.record_box(box_body(other_box(), slot, s.boxes[1], BoxProgressState::Casting)).unwrap();
            if suspend == Some(t) {
                e.suspend();
            }
            let o = e.close_slot(slot).unwrap();
            proptest::prop_assert_eq!(o.out, out[t]);
            let got = [
                o.raised.contains(ProgressAlarm::Negative),
                o.raised.contains(ProgressAlarm::High),
                o.raised.contains(ProgressAlarm::Floor),
            ];
            proptest::prop_assert_eq!(got, raised[t]);
        }
        // Unanswered alarms are unresolved from the third slot after them,
        // and at close in any case.
        let last = slots.len() - 1;
        let overdue = raised
            .iter()
            .enumerate()
            .any(|(t, r)| r.iter().any(|x| *x) && t + 3 <= last);
        let any = raised.iter().any(|r| r.iter().any(|x| *x));
        proptest::prop_assert_eq!(e.holds().contains(HoldReason::ProgressUnresolved), overdue);
        proptest::prop_assert_eq!(e.counterfoil_required(), overdue);
        proptest::prop_assert_eq!(e.finish().contains(HoldReason::ProgressUnresolved), any);
    }
}
