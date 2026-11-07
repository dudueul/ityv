//! The ledger plan of a whole election, in the order events reach the
//! board: genesis and authorization, key ceremonies and module records,
//! the voter roll (extracts, freeze, custody receipts),
//! the voting days slot by slot (openings, records, batches, progress
//! ticks, emergency insertion, on-site checks, hourly checkpoints),
//! closes and station counts, participation sets, receipt resolutions,
//! then the tally of every ballot style and reporting unit. Each station
//! gateway's sessions come at the end of each six-slot window from the
//! station's opening; the last ones, final, after the participation sets
//! (ADR-0041, [`crate::uplink`]).

use std::collections::BTreeSet;

use ityv_crypto::OptionCount;
use ityv_encoding::{
    BoxProgressState, CheckinProgressState, SCHEMA_AGGREGATE_OPENING_BODY, SCHEMA_BATCH_ATTEST,
    SCHEMA_BOX_CLOSE, SCHEMA_CAST_RECORD, SCHEMA_MODULE_PROVISIONED, SCHEMA_PARTICIPATION_SET,
    SCHEMA_PARTY_KEY_CEREMONY, SCHEMA_PROGRESS_TICK, SCHEMA_QUORUM_SIGNED, SCHEMA_SIGNED_GENESIS,
    SCHEMA_SIGNED_LEGAL_AUTHORIZATION, SCHEMA_WITNESSED_EVENT,
};

use crate::day::bucket_covering;
use crate::election::{BATCH_SIZE, CastInfo, Election, QUORUM, options_of};
use crate::ledger::Step;
use crate::uplink::{Device, Window, windows};

/// How far the plan goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Until {
    /// Voting still open: stop after the ticks of this slot (absolute),
    /// with a checkpoint over everything so far.
    Voting(u64),
    /// Every box closed and every station counted; no tally yet.
    Closed,
    /// The whole election, tallied.
    Tallied,
}

/// A tally unit: ballot style and reporting unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TallyUnit {
    /// Ballot style.
    pub style: &'static str,
    /// Reporting unit.
    pub unit: &'static str,
}

/// Where the notable steps are, for scenarios that change them.
#[derive(Debug, Clone, Default)]
pub struct Marks {
    /// Per box: the step of each record.
    pub records: Vec<Vec<usize>>,
    /// Per box: the step of each batch attestation.
    pub batches: Vec<Vec<usize>>,
    /// Per box: the step of its close.
    pub closes: Vec<Option<usize>>,
    /// Per station: the step of its issuance count.
    pub issuance: Vec<Option<usize>>,
    /// Per station: the step of its participation set.
    pub participation: Vec<Option<usize>>,
    /// Per station: the steps of its gateway's sessions, in order.
    pub uplink: Vec<Vec<usize>>,
    /// The legal authorization's step.
    pub authorization: usize,
    /// Tally units with the steps of their scope, openings and paper.
    pub tally: Vec<(TallyUnit, usize, Vec<usize>, usize)>,
    /// The step of the last checkpoint.
    pub last_checkpoint: Option<usize>,
    /// The bucket from which a tally scope may be taken.
    pub ready: u64,
    /// The last close bucket.
    pub last_close: u64,
}

/// A plan and its marks.
#[derive(Debug, Clone)]
pub struct Plan {
    /// The steps.
    pub steps: Vec<Step>,
    /// Where things are.
    pub marks: Marks,
}

impl Plan {
    fn push(&mut self, step: Step) -> usize {
        self.steps.push(step);
        self.steps.len() - 1
    }

    fn event(&mut self, schema: ityv_encoding::SchemaId, event: &'static [u8]) -> usize {
        self.push(Step::event(schema, event))
    }

    fn checkpoint(&mut self, bucket: u64) -> usize {
        let at = self.push(Step::Checkpoint { bucket, stamps: 2 });
        self.marks.last_checkpoint = Some(at);
        at
    }
}

/// The tally units of `election` (every style and unit some box has).
#[must_use]
pub fn tally_units(election: &Election) -> Vec<TallyUnit> {
    let set: BTreeSet<TallyUnit> = election
        .boxes
        .iter()
        .map(|b| TallyUnit {
            style: b.style,
            unit: b.unit,
        })
        .collect();
    set.into_iter().collect()
}

/// The records of a tally unit.
#[must_use]
pub fn unit_casts(election: &Election, u: TallyUnit) -> Vec<CastInfo> {
    election
        .boxes
        .iter()
        .enumerate()
        .filter(|(_, b)| b.style == u.style && b.unit == u.unit)
        .flat_map(|(i, _)| election.casts[i].iter().copied())
        .collect()
}

/// Ballots without a record in a tally unit.
#[must_use]
pub fn unit_no_record(election: &Election, u: TallyUnit) -> u64 {
    election
        .boxes
        .iter()
        .filter(|b| b.style == u.style && b.unit == u.unit)
        .map(|b| election.days[b.station].paper_only[b.index].len() as u64)
        .sum()
}

/// The plan of `election` up to `until`.
#[must_use]
pub fn plan(election: &Election, until: Until) -> Plan {
    let e = election;
    let nb = e.boxes.len();
    let ns = e.stations.len();
    let mut p = Plan {
        steps: Vec::new(),
        marks: Marks {
            records: vec![Vec::new(); nb],
            batches: vec![Vec::new(); nb],
            closes: vec![None; nb],
            issuance: vec![None; ns],
            participation: vec![None; ns],
            uplink: vec![Vec::new(); ns],
            ..Marks::default()
        },
    };
    // Each station's session windows: from its opening to the slot after
    // its last link's last slot.
    let station_windows: Vec<Vec<(u64, u64)>> = (0..ns)
        .map(|s| {
            let (first, last) = e.link_slots(Device::Unit(s));
            windows(first, last + 1)
        })
        .collect();
    let mut next_window = vec![0usize; ns];
    p.event(SCHEMA_SIGNED_GENESIS, e.signed);
    p.marks.authorization = p.event(SCHEMA_SIGNED_LEGAL_AUTHORIZATION, e.authorization);
    for party in &e.spec.parties {
        p.event(SCHEMA_PARTY_KEY_CEREMONY, e.ceremony(party.chamber));
    }
    for m in &e.modules {
        p.event(SCHEMA_MODULE_PROVISIONED, e.provisioning(m));
    }
    for event in e.roll() {
        p.event(SCHEMA_WITNESSED_EVENT, event);
    }

    let mut days: Vec<u64> = e.spec.stations.iter().map(|s| s.day).collect();
    days.sort_unstable();
    days.dedup();
    // Per box: records cast so far, and the first counter of the batch
    // still open.
    let mut cast_so_far = vec![0usize; nb];
    let mut batch_from = vec![0usize; nb];
    let mut batch_index = vec![0u32; nb];
    let mut last_close = 0u64;
    for day in days {
        let stations: Vec<usize> = (0..ns).filter(|s| e.spec.stations[*s].day == day).collect();
        let open = stations.iter().map(|s| e.days[*s].open_slot).min().unwrap();
        let close = stations
            .iter()
            .map(|s| e.days[*s].close_slot)
            .max()
            .unwrap();
        for slot in open..=close {
            for &s in &stations {
                let d = &e.days[s];
                if slot < d.open_slot || slot > d.close_slot {
                    continue;
                }
                if slot == d.open_slot {
                    for &b in &e.stations[s].boxes {
                        p.event(SCHEMA_WITNESSED_EVENT, e.opened(b, true));
                    }
                }
                if let Some(f) = d.fallback {
                    let b = e.stations[s].boxes[f.index];
                    if slot == f.from_slot {
                        p.event(
                            SCHEMA_WITNESSED_EVENT,
                            e.fallback(b, true, f.declared_bucket),
                        );
                    }
                    if slot == f.to_slot {
                        p.event(SCHEMA_WITNESSED_EVENT, e.fallback(b, false, f.ended_bucket));
                    }
                }
                for &b in &e.stations[s].boxes {
                    while cast_so_far[b] < e.casts[b].len()
                        && e.casts[b][cast_so_far[b]].slot == slot
                    {
                        let at = p.event(SCHEMA_CAST_RECORD, e.casts[b][cast_so_far[b]].event);
                        p.marks.records[b].push(at);
                        cast_so_far[b] += 1;
                        if cast_so_far[b] - batch_from[b] == BATCH_SIZE {
                            let at = push_batch(
                                &mut p,
                                e,
                                b,
                                batch_index[b],
                                batch_from[b],
                                cast_so_far[b],
                                slot,
                            );
                            p.marks.batches[b].push(at);
                            batch_index[b] += 1;
                            batch_from[b] = cast_so_far[b];
                        }
                    }
                }
                let row = &d.rows[(slot - d.open_slot) as usize];
                let closing = slot == d.close_slot;
                p.event(
                    SCHEMA_PROGRESS_TICK,
                    e.checkin_tick(
                        s,
                        slot,
                        [row.checkins, row.issued, row.spoiled, row.returned],
                        if closing {
                            CheckinProgressState::Closed
                        } else {
                            CheckinProgressState::Checking
                        },
                    ),
                );
                for (i, &b) in e.stations[s].boxes.iter().enumerate() {
                    let state = if closing {
                        BoxProgressState::Closed
                    } else if row.fallback[i] {
                        BoxProgressState::Fallback
                    } else {
                        BoxProgressState::Casting
                    };
                    p.event(
                        SCHEMA_PROGRESS_TICK,
                        e.box_tick(b, slot, row.sheets_in[i], state),
                    );
                }
                for c in d.checks.iter().filter(|c| c.after_slot == slot) {
                    p.event(
                        SCHEMA_WITNESSED_EVENT,
                        e.progress_check(s, c.alarm_slot, c.alarm, c.finding, c.holding, c.bucket),
                    );
                }
                // The gateway's session of a window that ends here (never
                // the last: that one ends after the close).
                if let Some(&(start, end)) = station_windows[s].get(next_window[s])
                    && end == slot
                {
                    let at = p.push(Step::Uplink(Window {
                        station: s,
                        start,
                        end,
                        is_final: false,
                        faults: Vec::new(),
                    }));
                    p.marks.uplink[s].push(at);
                    next_window[s] += 1;
                }
            }
            if until == Until::Voting(slot) {
                p.checkpoint(bucket_covering(slot) + 1);
                return p;
            }
            if (slot - open) % 12 == 11 && slot != close {
                p.checkpoint(bucket_covering(slot));
            }
        }
        // Close of the day.
        for &s in &stations {
            let d = &e.days[s];
            let at = p.event(SCHEMA_WITNESSED_EVENT, e.issuance(s, &e.people(s)));
            p.marks.issuance[s] = Some(at);
            for &b in &e.stations[s].boxes {
                if cast_so_far[b] > batch_from[b] {
                    let at = push_batch(
                        &mut p,
                        e,
                        b,
                        batch_index[b],
                        batch_from[b],
                        cast_so_far[b],
                        d.close_slot,
                    );
                    p.marks.batches[b].push(at);
                    batch_index[b] += 1;
                    batch_from[b] = cast_so_far[b];
                }
                let n = e.casts[b].len() as u64;
                let codes: Vec<_> = e.casts[b].iter().map(|c| c.code).collect();
                let at = p.event(
                    SCHEMA_BOX_CLOSE,
                    e.close(b, e.close_counts(b, n, n), &codes, Some(b"box-close"), None),
                );
                p.marks.closes[b] = Some(at);
            }
            p.event(SCHEMA_WITNESSED_EVENT, e.observer_count(s));
            last_close = last_close.max(d.close_bucket);
        }
        p.checkpoint(bucket_covering(close) + 1);
    }
    p.marks.last_close = last_close;
    let ready = last_close + 97;
    p.marks.ready = ready;
    for s in 0..ns {
        let at = p.event(SCHEMA_PARTICIPATION_SET, e.participation(s, None));
        p.marks.participation[s] = Some(at);
    }
    // Each gateway's remaining sessions, the last final.
    for s in 0..ns {
        let n = station_windows[s].len();
        for (k, &(start, end)) in station_windows[s].iter().enumerate().skip(next_window[s]) {
            let at = p.push(Step::Uplink(Window {
                station: s,
                start,
                end,
                is_final: k + 1 == n,
                faults: Vec::new(),
            }));
            p.marks.uplink[s].push(at);
        }
        next_window[s] = n;
    }
    for (b, bx) in e.boxes.iter().enumerate() {
        if bx.absentee {
            p.event(SCHEMA_QUORUM_SIGNED, e.resolution(b, ready));
        }
    }
    p.checkpoint(ready + 1);
    if until == Until::Closed {
        return p;
    }
    let units = tally_units(e);
    let mut scopes = Vec::new();
    for u in &units {
        let casts = unit_casts(e, *u);
        let codes: Vec<_> = casts.iter().map(|c| c.code).collect();
        let body = e.scope_body(
            u.style,
            u.unit,
            &codes,
            &[],
            unit_no_record(e, *u),
            ready + 1,
        );
        let at = p.event(
            SCHEMA_QUORUM_SIGNED,
            e.quorum(body, b"tally-scope", &QUORUM),
        );
        scopes.push((body, at));
    }
    p.checkpoint(ready + 1);
    for (u, (body, scope_at)) in units.iter().zip(&scopes) {
        let casts = unit_casts(e, *u);
        let style = e.spec.style(u.style);
        let chunks = OptionCount::new(options_of(style.candidates.len() as u16))
            .unwrap()
            .chunk_count();
        let mut openings = Vec::new();
        for j in 0..chunks {
            let ob = e.opening_body(u.style, u.unit, body, j, &casts, ready + 2);
            openings.push(p.event(
                SCHEMA_QUORUM_SIGNED,
                e.quorum(ob, b"aggregate-opening", &QUORUM),
            ));
        }
        let (votes, invalid) = e.paper_truth(u.style, u.unit);
        let paper = p.event(
            SCHEMA_WITNESSED_EVENT,
            e.paper(u.style, u.unit, &votes, invalid, ready + 3),
        );
        p.marks.tally.push((*u, *scope_at, openings, paper));
    }
    p.checkpoint(ready + 4);
    p
}

fn push_batch(
    p: &mut Plan,
    e: &Election,
    b: usize,
    index: u32,
    from: usize,
    to: usize,
    slot: u64,
) -> usize {
    let members: Vec<_> = e.casts[b][from..to].iter().map(|c| c.code).collect();
    let event = e.batch(
        b,
        index,
        (from as u64 + 1, to as u64),
        &members,
        bucket_covering(slot),
    );
    p.event(SCHEMA_BATCH_ATTEST, event)
}

/// The aggregate-opening schema, re-exported for scenarios.
pub const OPENING_BODY: ityv_encoding::SchemaId = SCHEMA_AGGREGATE_OPENING_BODY;
