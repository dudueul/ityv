//! One station's simulated voting day, slot by slot (PROTOCOL.md §7.10).
//!
//! Voters arrive along a curve with a morning and an evening peak, check
//! in, take one ballot, and cast it in the same 10-minute slot or the
//! next. A few spoil a ballot and take another, a few hand theirs back.
//! The day's [`DayEvent`]s bend the flow so that the station evaluator of
//! the verifier raises a given alarm, and add the on-site check that
//! answers it. Nothing here is cryptographic; the stream is fixed by the
//! station identifier and the generator seed.

use ityv_encoding::{ProgressAlarm, ProgressFinding};

use crate::spec::{DayEvent, ElectionSpec, StationSpec};
use crate::util::Dice;

/// Slots per day.
pub const SLOTS_PER_DAY: u64 = 144;
/// Buckets (15 minutes) per day.
pub const BUCKETS_PER_DAY: u64 = 96;
/// The opening slot offset within a day (06:00).
pub const OPEN_SLOT_OF_DAY: u64 = 36;

/// The slots a time bucket overlaps (as `ityv_verify::bucket_slots`).
#[must_use]
pub const fn bucket_slots(bucket: u64) -> (u64, u64) {
    (bucket * 3 / 2, u64::midpoint(bucket * 3, 2))
}

/// The first bucket whose last slot is `slot` or `slot + 1`.
#[must_use]
pub fn bucket_ending_near(slot: u64) -> u64 {
    let start = (slot * 2 / 3).saturating_sub(2);
    (start..start + 6)
        .find(|b| {
            let last = bucket_slots(*b).1;
            last == slot || last == slot + 1
        })
        .unwrap()
}

/// The first bucket whose slots include `slot`.
#[must_use]
pub fn bucket_covering(slot: u64) -> u64 {
    let start = (slot * 2 / 3).saturating_sub(2);
    (start..start + 6)
        .find(|b| {
            let (a, z) = bucket_slots(*b);
            a <= slot && slot <= z
        })
        .unwrap()
}

/// What a voter marked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// One candidate, from 1.
    Candidate(u16),
    /// Nothing marked: the machine reads `BLANK`, the paper is invalid.
    Blank,
    /// A mark the machine reads as `UNREADABLE`; the people counting the
    /// paper decide it for a candidate or as invalid.
    Ambiguous(Option<u16>),
}

impl Mark {
    /// The option index the interpretation unit gives (0 `BLANK`, `m + 1`
    /// `UNREADABLE`).
    #[must_use]
    pub const fn option(self, candidates: u16) -> u16 {
        match self {
            Self::Candidate(c) => c,
            Self::Blank => 0,
            Self::Ambiguous(_) => candidates + 1,
        }
    }

    /// The candidate the paper count gives, if any.
    #[must_use]
    pub const fn paper(self) -> Option<u16> {
        match self {
            Self::Candidate(c) | Self::Ambiguous(Some(c)) => Some(c),
            Self::Blank | Self::Ambiguous(None) => None,
        }
    }
}

/// The counts after one slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The slot.
    pub slot: u64,
    /// Check-ins (people) so far.
    pub checkins: u64,
    /// Issued sheets so far, as the terminal entered them.
    pub issued: u64,
    /// Spoiled sheets taken back so far.
    pub spoiled: u64,
    /// Sheets handed back unused so far.
    pub returned: u64,
    /// Each box's sheets in so far (records).
    pub sheets_in: Vec<u64>,
    /// Each box's fallback state in this slot.
    pub fallback: Vec<bool>,
}

/// A ballot cast with a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cast {
    /// The slot it went in.
    pub slot: u64,
    /// What it says.
    pub mark: Mark,
}

/// An on-site check answering an alarm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Check {
    /// The alarm's slot.
    pub alarm_slot: u64,
    /// The alarm.
    pub alarm: ProgressAlarm,
    /// What the check found.
    pub finding: ProgressFinding,
    /// People holding ballots.
    pub holding: u64,
    /// The check's time bucket.
    pub bucket: u64,
    /// The slot after whose ticks it is recorded.
    pub after_slot: u64,
}

/// An emergency-insertion period of one box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FallbackSpan {
    /// The box index at the station.
    pub index: usize,
    /// First slot in fallback.
    pub from_slot: u64,
    /// First slot scanning again.
    pub to_slot: u64,
    /// `FallbackDeclared` time bucket.
    pub declared_bucket: u64,
    /// `FallbackEnded` time bucket.
    pub ended_bucket: u64,
}

/// A station's whole day.
#[derive(Debug, Clone)]
pub struct Day {
    /// The opening slot.
    pub open_slot: u64,
    /// The closing slot (its tick is the closing tick).
    pub close_slot: u64,
    /// The opening time bucket.
    pub open_bucket: u64,
    /// The closing time bucket.
    pub close_bucket: u64,
    /// One row per slot, opening to close.
    pub rows: Vec<Row>,
    /// Each box's records, in order.
    pub casts: Vec<Vec<Cast>>,
    /// Each box's ballots without a record (emergency slot).
    pub paper_only: Vec<Vec<Mark>>,
    /// Ballots handed back unused, by the box the voter was headed for
    /// (an out-of-district voter hands back the envelope empty).
    pub returned_by_box: Vec<u64>,
    /// The on-site checks.
    pub checks: Vec<Check>,
    /// Alarms the day raises (for the scenario's expectations).
    pub alarms: Vec<(u64, ProgressAlarm)>,
    /// The emergency insertion, if any.
    pub fallback: Option<FallbackSpan>,
    /// The progress limit `L`.
    pub limit: u64,
}

impl Day {
    /// The last row (closing).
    #[must_use]
    pub fn last(&self) -> &Row {
        self.rows.last().unwrap()
    }
}

/// Integer arrival weight of slot offset `i` of an `n`-slot day: a base,
/// a morning peak around 09:00, a lunch bump and an evening peak around
/// 17:00 (minutes from 06:00 are `10 i`).
fn weight(i: u64, n: u64) -> u64 {
    if n < 20 {
        return 10;
    }
    let t = 360 + 10 * i;
    let peak = |c: u64, width: u64, h: u64| -> u64 {
        let d = t.abs_diff(c);
        if d >= width {
            0
        } else {
            h * (width - d) / width
        }
    };
    12 + peak(540, 100, 60) + peak(750, 80, 14) + peak(1020, 90, 44)
}

/// A pending cast: the box, the mark, the slot it goes in.
struct Pending {
    index: usize,
    mark: Mark,
    slot: u64,
}

/// Simulates `station` of `election` over `slots` slots.
#[must_use]
pub fn simulate(election: &ElectionSpec, station: &StationSpec) -> Day {
    let n = election.slots;
    let open_slot = station.day * SLOTS_PER_DAY + OPEN_SLOT_OF_DAY;
    let close_slot = open_slot + n - 1;
    let open_bucket = station.day * BUCKETS_PER_DAY + 24;
    assert_eq!(bucket_slots(open_bucket).0, open_slot);
    let close_bucket = bucket_covering(close_slot);
    let limit = u64::from(station.booths) * 2;
    let boxes = station.boxes.len();
    let mut dice = Dice::new(
        "day",
        &[election.election_id.as_bytes(), station.id.as_bytes()],
    );

    // Arrivals per slot offset, summing to the station's voters.
    let total: u64 = (0..n).map(|i| weight(i, n)).sum();
    let voters = u64::from(station.voters);
    let mut arrivals: Vec<u64> = Vec::new();
    let mut cum = 0u64;
    for i in 0..n {
        let before = voters * cum / total;
        cum += weight(i, n);
        arrivals.push(voters * cum / total - before);
    }
    // No arrival in the closing slot, so that every ballot is in by close.
    let last = arrivals.pop().unwrap();
    *arrivals.last_mut().unwrap() += last;
    arrivals.push(0);

    // Slot offsets whose arrivals cast in the same slot, the holder of a
    // floor alarm, the missed entries of a negative alarm, a group.
    let mut no_delay: Vec<bool> = vec![false; n as usize];
    no_delay[(n - 2) as usize] = true;
    let mut holder: Option<(u64, u64)> = None; // (arrive offset, cast offset)
    let mut missed: Vec<(u64, u64)> = Vec::new(); // (offset, sheets not entered)
    let mut group: Option<(u64, u64)> = None; // (offset, size)
    let mut fallback: Option<FallbackSpan> = None;
    let mut checks: Vec<Check> = Vec::new();
    let mut alarms: Vec<(u64, ProgressAlarm)> = Vec::new();
    for event in &station.events {
        match *event {
            DayEvent::Floor { at, checked } => {
                let moved = arrivals[at as usize] + arrivals[(at + 1) as usize];
                arrivals[at as usize] = 0;
                arrivals[(at + 1) as usize] = 0;
                arrivals[(at + 2) as usize] += moved;
                arrivals[(at - 1) as usize] = arrivals[(at - 1) as usize].max(1);
                no_delay[(at - 1) as usize] = true;
                no_delay[(at - 2) as usize] = true;
                holder = Some((at - 1, at + 2));
                let alarm_slot = open_slot + at + 1;
                alarms.push((alarm_slot, ProgressAlarm::Floor));
                if checked {
                    let bucket = bucket_ending_near(alarm_slot);
                    checks.push(Check {
                        alarm_slot,
                        alarm: ProgressAlarm::Floor,
                        finding: ProgressFinding::Explained,
                        holding: 1,
                        bucket,
                        after_slot: bucket_slots(bucket).1,
                    });
                }
            }
            DayEvent::Negative { at } => {
                arrivals[at as usize] = arrivals[at as usize].max(3);
                for o in at - 1..=at + 1 {
                    no_delay[o as usize] = true;
                }
                missed.push((at, 2));
                let alarm_slot = open_slot + at + 1;
                alarms.push((alarm_slot, ProgressAlarm::Negative));
                let bucket = bucket_ending_near(alarm_slot + 1);
                checks.push(Check {
                    alarm_slot,
                    alarm: ProgressAlarm::Negative,
                    finding: ProgressFinding::Corrected,
                    holding: 0,
                    bucket,
                    after_slot: bucket_slots(bucket).1,
                });
            }
            DayEvent::High { at } => {
                let size = limit + 8;
                group = Some((at, size));
                let alarm_slot = open_slot + at + 1;
                alarms.push((alarm_slot, ProgressAlarm::High));
                let bucket = bucket_ending_near(alarm_slot);
                checks.push(Check {
                    alarm_slot,
                    alarm: ProgressAlarm::High,
                    finding: ProgressFinding::Explained,
                    holding: size,
                    bucket,
                    after_slot: bucket_slots(bucket).1,
                });
            }
            DayEvent::Fallback { index, from, to } => {
                let from_slot = open_slot + from;
                let to_slot = open_slot + to;
                fallback = Some(FallbackSpan {
                    index,
                    from_slot,
                    to_slot,
                    declared_bucket: bucket_covering(from_slot),
                    ended_bucket: bucket_covering(to_slot),
                });
            }
        }
    }

    let weights: Vec<u64> = station.boxes.iter().map(|b| b.share).collect();
    let mut rows: Vec<Row> = Vec::new();
    let mut casts: Vec<Vec<Cast>> = vec![Vec::new(); boxes];
    let mut paper_only: Vec<Vec<Mark>> = vec![Vec::new(); boxes];
    let mut pending: Vec<Pending> = Vec::new();
    let (mut checkins, mut issued, mut spoiled, mut returned) = (0u64, 0u64, 0u64, 0u64);
    let mut sheets_in = vec![0u64; boxes];
    let mut returned_by_box = vec![0u64; boxes];

    let mark_for = |dice: &mut Dice, index: usize| -> Mark {
        let style = election.style(station.boxes[index].style);
        let w: Vec<u64> = style.candidates.iter().map(|c| c.weight).collect();
        let pick = (dice.weighted(&w) + 1) as u16;
        if dice.chance(8) {
            Mark::Blank
        } else if dice.chance(12) {
            Mark::Ambiguous(if dice.chance(650) { Some(pick) } else { None })
        } else {
            Mark::Candidate(pick)
        }
    };

    for i in 0..n {
        let slot = open_slot + i;
        let in_fallback = |index: usize| {
            fallback.is_some_and(|f| f.index == index && f.from_slot <= slot && slot < f.to_slot)
        };
        let mut arrive = arrivals[i as usize];
        if let Some((at, size)) = group
            && at == i
        {
            arrive += size;
        }
        for k in 0..arrive {
            checkins += 1;
            issued += 1;
            let index = dice.weighted(&weights);
            let mark = mark_for(&mut dice, index);
            if dice.chance(5) && holder.is_none_or(|(a, _)| a != i) {
                returned += 1;
                returned_by_box[index] += 1;
                continue;
            }
            if dice.chance(15) {
                spoiled += 1;
                issued += 1;
            }
            let cast_slot = if let Some((at, size)) = group
                && at == i
                && k >= arrive - size
            {
                // The group: half in two slots, the rest in three.
                slot + 2 + u64::from(k % 2 == 1)
            } else if holder.is_some_and(|(a, _)| a == i) && k == 0 {
                open_slot + holder.unwrap().1
            } else if no_delay[i as usize] || dice.chance(700) {
                slot
            } else {
                slot + 1
            };
            pending.push(Pending {
                index,
                mark,
                slot: cast_slot.min(close_slot),
            });
        }
        // Casts due in this slot.
        let mut still = Vec::new();
        for p in pending.drain(..) {
            if p.slot <= slot {
                if in_fallback(p.index) {
                    paper_only[p.index].push(p.mark);
                } else {
                    sheets_in[p.index] += 1;
                    casts[p.index].push(Cast { slot, mark: p.mark });
                }
            } else {
                still.push(p);
            }
        }
        pending = still;
        let lag: u64 = missed
            .iter()
            .filter(|(at, _)| i == *at || i == at + 1)
            .map(|(_, k)| *k)
            .sum();
        rows.push(Row {
            slot,
            checkins,
            issued: issued - lag,
            spoiled,
            returned,
            sheets_in: sheets_in.clone(),
            fallback: (0..boxes).map(in_fallback).collect(),
        });
    }
    assert!(pending.is_empty(), "every ballot is in by close");
    Day {
        open_slot,
        close_slot,
        open_bucket,
        close_bucket,
        rows,
        casts,
        paper_only,
        returned_by_box,
        checks,
        alarms,
        fallback,
        limit,
    }
}
