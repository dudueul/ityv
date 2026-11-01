//! The voting progress record (ADR-0027; PROTOCOL.md §7.10; VC-102,
//! VC-103).
//!
//! Two parts:
//!
//! * **Device streams** ([`BoxStream`], [`CheckinStream`]): the ticks of one
//!   commitment unit or one check-in unit, each checked against the
//!   device's key, with the stream rules of VC-102: one tick per slot,
//!   slots in order from opening, counts that never go down, nothing
//!   after the closing tick, and a last tick that equals the close counts.
//!   A broken rule is the sticky hold [`HoldReason::ProgressStream`]; the
//!   tick is still taken so the alarms see what the device said.
//! * **The station evaluator** ([`StationProgress`]): the three alarms of
//!   §7.10 item 4 computed slot by slot from the latest counts, the
//!   on-site checks that answer them, and the station holds
//!   [`HoldReason::ProgressUnresolved`] and [`HoldReason::CarryOut`] with
//!   the counterfoil-check flag.
//!
//! Ticks are fed in slot order. A tick that reaches the ledger late is
//! taken by replaying the station from its opening (the evaluator is
//! small and `Copy`); a slot that never arrives keeps the previous counts
//! and is a stream hold at close. Nothing here reads or changes a record:
//! alarms never touch a record status, and nothing about them is a reason
//! to treat a ballot as invalid.

use ityv_crypto::{HybridSigned, HybridVerifyingKey, Verified};
use ityv_encoding::{
    BoxClose, BoxId, BoxProgressBody, BoxProgressState, CheckinProgressBody, CheckinProgressState,
    ElectionId, ProgressAlarm, ProgressBody, ProgressCheckBody, ProgressFinding, ProgressTick,
    SCHEMA_PROGRESS_CHECK_BODY, StationId, StationProgressPolicy,
};

use crate::close::{RosterEntry, check_witnesses};
use crate::error::Error;
use crate::hold::{HoldReason, HoldSet};
use crate::issuance::IssuanceCount;
use crate::sig::{Signed, check_token};

/// Boxes one station can have in the evaluator.
///
/// A polling station has one box per election round, and an early-voting
/// station adds an out-of-district box; two-round local elections give two
/// rounds, and a replaced scanner keeps its `box_id`. Eight leaves room
/// for every arrangement in PROTOCOL.md §17 and keeps the evaluator a
/// fixed-size value.
pub const MAX_STATION_BOXES: usize = 8;

/// Slots after the alarm slot within which the on-site check must be
/// recorded (PROTOCOL.md §7.10 item 6).
pub const CHECK_WINDOW_SLOTS: u64 = 2;

/// Alarms (or corrections) that can wait at the same time. An alarm
/// waits at most three slots: it is answered within the window, or
/// overdue at the third slot after it, and a correction is judged by the
/// first slot after it. A new alarm of a kind needs its condition to fail
/// in between, so the same kind fires at least two slots apart; a negative
/// or high alarm needs two failing-then-holding slots and fires at least
/// three apart. So at most two floor alarms and one of each other kind
/// wait together.
pub const MAX_PENDING: usize = 4;

/// Checks a tick's device signature: the token must cover the tick's body
/// bytes under the body's purpose, with the tick's signature bytes, from
/// `key`.
///
/// # Errors
/// [`Error::SignatureObject`] or [`Error::SignatureSigner`].
pub fn check_tick(
    tick: &ProgressTick<'_>,
    token: &Verified<HybridSigned<'_>>,
    key: &HybridVerifyingKey,
) -> Result<(), Error> {
    check_token(token, tick.body_bytes(), tick.purpose(), tick.sig(), key)
}

// ---------------------------------------------------------------------------
// Device streams (VC-102)

/// The stream rules shared by both devices, over `N` cumulative counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Stream<const N: usize> {
    next_slot: u64,
    last: [u64; N],
    closed: bool,
    holds: HoldSet,
}

impl<const N: usize> Stream<N> {
    pub(crate) const fn new(first_slot: u64, start: [u64; N]) -> Self {
        Self {
            next_slot: first_slot,
            last: start,
            closed: false,
            holds: HoldSet::empty(),
        }
    }

    const fn hold(&mut self) {
        self.holds = self.holds.with(HoldReason::ProgressStream);
    }

    /// Takes one tick. Returns whether its counts may be used by the
    /// evaluator (a duplicate or a tick outside the stream is not).
    pub(crate) fn accept(
        &mut self,
        slot: u64,
        counts: [u64; N],
        closing: bool,
    ) -> Result<bool, Error> {
        if self.closed || slot < self.next_slot {
            // After the closing tick, before opening, or a second tick for
            // a slot already taken.
            self.hold();
            return Ok(false);
        }
        if slot > self.next_slot {
            // Slots in between never arrived (replay with them if they do).
            self.hold();
        }
        if counts
            .iter()
            .zip(&self.last)
            .any(|(now, before)| now < before)
        {
            self.hold();
        }
        self.last = counts;
        self.next_slot = slot.checked_add(1).ok_or(Error::Overflow)?;
        self.closed = closing;
        Ok(true)
    }

    /// Continues after a device swap from the counts the swap record
    /// confirms; the slots of the swap itself are excused.
    fn swap(&mut self, at_slot: u64, counts: [u64; N]) {
        if self.closed || at_slot < self.next_slot.saturating_sub(1) {
            self.hold();
        }
        if counts
            .iter()
            .zip(&self.last)
            .any(|(now, before)| now < before)
        {
            self.hold();
        }
        self.last = counts;
        self.next_slot = self.next_slot.max(at_slot);
    }

    /// The holds at close: the stream's own and a final mismatch.
    pub(crate) fn finish(&self, expected: [u64; N]) -> HoldSet {
        self.holds.with_if(
            !self.closed || self.last != expected,
            HoldReason::ProgressStream,
        )
    }
}

/// The progress stream of one box's commitment unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoxStream<'a> {
    election_id: ElectionId<'a>,
    box_id: BoxId<'a>,
    key: &'a HybridVerifyingKey,
    inner: Stream<1>,
}

impl<'a> BoxStream<'a> {
    /// Opens the stream of `box_id`, whose first tick belongs to
    /// `first_slot` (the slot of `BoxOpened`), with the device key from the
    /// genesis entry.
    #[must_use]
    pub const fn open(
        election_id: ElectionId<'a>,
        box_id: BoxId<'a>,
        key: &'a HybridVerifyingKey,
        first_slot: u64,
    ) -> Self {
        Self {
            election_id,
            box_id,
            key,
            inner: Stream::new(first_slot, [0]),
        }
    }

    /// Takes one tick of this box and returns its body for the station
    /// evaluator, or `None` if the tick broke a slot rule (the hold is
    /// recorded).
    ///
    /// # Errors
    /// The signature errors of [`check_tick`], [`Error::Mismatch`] for a
    /// check-in tick or a tick of another box or election,
    /// [`Error::Overflow`].
    pub fn accept(
        &mut self,
        tick: &ProgressTick<'a>,
        token: &Verified<HybridSigned<'_>>,
    ) -> Result<Option<BoxProgressBody<'a>>, Error> {
        check_tick(tick, token, self.key)?;
        let ProgressBody::Box(body) = *tick.body() else {
            return Err(Error::Mismatch);
        };
        let p = body.parts();
        if p.election_id.as_bytes() != self.election_id.as_bytes()
            || p.box_id.as_bytes() != self.box_id.as_bytes()
        {
            return Err(Error::Mismatch);
        }
        let closing = p.state == BoxProgressState::Closed;
        let usable = self.inner.accept(p.slot, [p.sheets_in], closing)?;
        Ok(usable.then_some(body))
    }

    /// Continues with a spare commitment unit from `at_slot`, with its key
    /// and the sheets-in count the replacement record confirms (PROTOCOL.md
    /// §7.10 item 8).
    pub fn swap(&mut self, key: &'a HybridVerifyingKey, at_slot: u64, sheets_in: u64) {
        self.key = key;
        self.inner.swap(at_slot, [sheets_in]);
    }

    /// The stream holds at close: the last tick must be a closing tick
    /// whose count is the close's `records + challenged + quarantined`.
    /// Only for a close with the device signature; a manual close already
    /// holds (PROTOCOL.md §10.2).
    #[must_use]
    pub fn finish(&self, close: &BoxClose<'_>) -> HoldSet {
        let c = close.body().counts();
        let expected = c
            .records
            .checked_add(c.challenged)
            .and_then(|v| v.checked_add(c.quarantined));
        match expected {
            Some(sheets) => self.inner.finish([sheets]),
            None => self.inner.holds.with(HoldReason::ProgressStream),
        }
    }

    /// The holds so far.
    #[must_use]
    pub const fn holds(&self) -> HoldSet {
        self.inner.holds
    }
}

/// The progress stream of one station's check-in unit, counts in the order
/// `checkins`, `issued`, `spoiled`, `returned`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckinStream<'a> {
    election_id: ElectionId<'a>,
    station_id: StationId<'a>,
    key: &'a HybridVerifyingKey,
    inner: Stream<4>,
}

const fn checkin_counts(body: &CheckinProgressBody<'_>) -> [u64; 4] {
    let p = body.parts();
    [p.checkins, p.issued, p.spoiled, p.returned]
}

impl<'a> CheckinStream<'a> {
    /// Opens the stream of `station_id` with the unit's key. The genesis
    /// `stations[]` entry that holds the key has no canonical type yet
    /// (ROADMAP M5); the caller passes the key from the verified genesis.
    #[must_use]
    pub const fn open(
        election_id: ElectionId<'a>,
        station_id: StationId<'a>,
        key: &'a HybridVerifyingKey,
        first_slot: u64,
    ) -> Self {
        Self {
            election_id,
            station_id,
            key,
            inner: Stream::new(first_slot, [0; 4]),
        }
    }

    /// Takes one tick of this station's unit; see [`BoxStream::accept`].
    ///
    /// # Errors
    /// As [`BoxStream::accept`].
    pub fn accept(
        &mut self,
        tick: &ProgressTick<'a>,
        token: &Verified<HybridSigned<'_>>,
    ) -> Result<Option<CheckinProgressBody<'a>>, Error> {
        check_tick(tick, token, self.key)?;
        let ProgressBody::Checkin(body) = *tick.body() else {
            return Err(Error::Mismatch);
        };
        let p = body.parts();
        if p.election_id.as_bytes() != self.election_id.as_bytes()
            || p.station_id.as_bytes() != self.station_id.as_bytes()
        {
            return Err(Error::Mismatch);
        }
        let closing = p.state == CheckinProgressState::Closed;
        let usable = self.inner.accept(p.slot, checkin_counts(&body), closing)?;
        Ok(usable.then_some(body))
    }

    /// Continues with the spare unit from `at_slot`, with its key and the
    /// counts `CheckinUnitSwap` confirms (`[checkins, issued, spoiled,
    /// returned]`).
    pub fn swap(&mut self, key: &'a HybridVerifyingKey, at_slot: u64, counts: [u64; 4]) {
        self.key = key;
        self.inner.swap(at_slot, counts);
    }

    /// The stream holds at close: the last tick must be a closing tick
    /// whose issued, spoiled and returned counts are the `IssuanceCount`'s
    /// and whose check-ins are the last `ObserverCountAttest` total
    /// (`observer_total`, which has no canonical type yet).
    #[must_use]
    pub fn finish(&self, issuance: &IssuanceCount<'_>, observer_total: u64) -> HoldSet {
        let p = issuance.parts();
        self.inner
            .finish([observer_total, p.issued, p.voter_spoiled, p.returned])
    }

    /// The holds so far.
    #[must_use]
    pub const fn holds(&self) -> HoldSet {
        self.inner.holds
    }
}

// ---------------------------------------------------------------------------
// The station evaluator (VC-103)

/// The alarms raised in one slot, as a set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Alarms {
    mask: u8,
}

const fn alarm_index(alarm: ProgressAlarm) -> usize {
    match alarm {
        ProgressAlarm::Negative => 0,
        ProgressAlarm::High => 1,
        ProgressAlarm::Floor => 2,
    }
}

const ALARMS: [ProgressAlarm; 3] = [
    ProgressAlarm::Negative,
    ProgressAlarm::High,
    ProgressAlarm::Floor,
];

impl Alarms {
    /// No alarm.
    #[must_use]
    pub const fn none() -> Self {
        Self { mask: 0 }
    }

    const fn with(self, alarm: ProgressAlarm) -> Self {
        Self {
            mask: self.mask | (1u8 << alarm_index(alarm)),
        }
    }

    /// Whether `alarm` is in the set.
    #[must_use]
    pub const fn contains(self, alarm: ProgressAlarm) -> bool {
        self.mask & (1u8 << alarm_index(alarm)) != 0
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.mask == 0
    }
}

/// What closing one slot found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SlotOutcome {
    /// Sheets outside the boxes after this slot (negative: more sheets
    /// entered than were issued).
    pub out: i128,
    /// Alarms raised in this slot.
    pub raised: Alarms,
}

/// An alarm waiting for its on-site check, or a check of finding 3
/// waiting for the next slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Pending {
    alarm: ProgressAlarm,
    slot: u64,
    corrected_at: Option<u64>,
}

/// The counts the alarm rules need from the previous slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Previous {
    issued: u64,
    sheets_in: u64,
    negative: bool,
    high: bool,
    conditions: [bool; 3],
}

/// One station's alarms and checks (PROTOCOL.md §7.10 items 4–7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StationProgress<'a> {
    election_id: ElectionId<'a>,
    station_id: StationId<'a>,
    limit: u64,
    box_ids: [Option<BoxId<'a>>; MAX_STATION_BOXES],
    sheets_in: [u64; MAX_STATION_BOXES],
    issued: u64,
    spoiled: u64,
    returned: u64,
    carried_out: u64,
    next_slot: Option<u64>,
    previous: Option<Previous>,
    quiet_slots: u8,
    suspended: bool,
    pending: [Option<Pending>; MAX_PENDING],
    holds: HoldSet,
    counterfoil: bool,
}

impl<'a> StationProgress<'a> {
    /// Starts the evaluator for the station of `policy`, with the boxes
    /// the genesis lists for it.
    ///
    /// # Errors
    /// [`Error::Overflow`] for more than [`MAX_STATION_BOXES`] boxes or none,
    /// [`Error::Mismatch`] for a repeated box.
    pub fn new(
        election_id: ElectionId<'a>,
        policy: &StationProgressPolicy<'a>,
        boxes: &[BoxId<'a>],
    ) -> Result<Self, Error> {
        if boxes.is_empty() || boxes.len() > MAX_STATION_BOXES {
            return Err(Error::Overflow);
        }
        let mut box_ids = [None; MAX_STATION_BOXES];
        for (slot, id) in box_ids.iter_mut().zip(boxes) {
            if boxes
                .iter()
                .filter(|other| other.as_bytes() == id.as_bytes())
                .count()
                != 1
            {
                return Err(Error::Mismatch);
            }
            *slot = Some(*id);
        }
        Ok(Self {
            election_id,
            station_id: policy.station_id(),
            limit: u64::from(policy.limit_sheets()),
            box_ids,
            sheets_in: [0; MAX_STATION_BOXES],
            issued: 0,
            spoiled: 0,
            returned: 0,
            carried_out: 0,
            next_slot: None,
            previous: None,
            quiet_slots: 0,
            suspended: false,
            pending: [None; MAX_PENDING],
            holds: HoldSet::empty(),
            counterfoil: false,
        })
    }

    /// Takes a box tick accepted by its [`BoxStream`]. A tick in fallback
    /// suspends the alarms (§7.10 item 5).
    ///
    /// # Errors
    /// [`Error::Mismatch`] for another election or a box not at this
    /// station.
    pub fn record_box(&mut self, body: &BoxProgressBody<'_>) -> Result<(), Error> {
        let p = body.parts();
        if p.election_id.as_bytes() != self.election_id.as_bytes() {
            return Err(Error::Mismatch);
        }
        let index = self
            .box_ids
            .iter()
            .position(|id| id.is_some_and(|id| id.as_bytes() == p.box_id.as_bytes()))
            .ok_or(Error::Mismatch)?;
        let count = self.sheets_in.get_mut(index).ok_or(Error::Mismatch)?;
        *count = p.sheets_in;
        if p.state == BoxProgressState::Fallback {
            self.suspended = true;
        }
        Ok(())
    }

    /// Takes a check-in tick accepted by the [`CheckinStream`]. A tick after
    /// a unit swap suspends the alarms.
    ///
    /// # Errors
    /// [`Error::Mismatch`] for another election or station.
    pub fn record_checkin(&mut self, body: &CheckinProgressBody<'_>) -> Result<(), Error> {
        let p = body.parts();
        if p.election_id.as_bytes() != self.election_id.as_bytes()
            || p.station_id.as_bytes() != self.station_id.as_bytes()
        {
            return Err(Error::Mismatch);
        }
        self.issued = p.issued;
        self.spoiled = p.spoiled;
        self.returned = p.returned;
        if p.state == CheckinProgressState::AfterSwap {
            self.suspended = true;
        }
        Ok(())
    }

    /// Stops the alarms until close: after `FallbackDeclared`, a
    /// commitment-unit replacement or `CheckinUnitSwap` (§7.10 item 5).
    /// Alarms already raised still need their checks.
    pub const fn suspend(&mut self) {
        self.suspended = true;
    }

    /// The current sheets outside the boxes.
    ///
    /// # Errors
    /// [`Error::Overflow`] (not reachable: the counts are at most ten
    /// `u64` values).
    pub fn out(&self) -> Result<i128, Error> {
        let sheets_in = self.sheets_in_total()?;
        out_of(
            self.issued,
            sheets_in,
            self.spoiled,
            self.returned,
            self.carried_out,
        )
        .ok_or(Error::Overflow)
    }

    fn sheets_in_total(&self) -> Result<u64, Error> {
        self.sheets_in
            .iter()
            .try_fold(0u64, |acc, v| acc.checked_add(*v))
            .ok_or(Error::Overflow)
    }

    /// Closes slot `slot` with the latest counts and raises the alarms that
    /// start in it. Slots are closed one by one in order from the first
    /// slot of the station.
    ///
    /// # Errors
    /// [`Error::Mismatch`] if `slot` is not the next slot,
    /// [`Error::Overflow`]. On error nothing changes.
    pub fn close_slot(&mut self, slot: u64) -> Result<SlotOutcome, Error> {
        let mut next = *self;
        let outcome = next.close_slot_inner(slot)?;
        *self = next;
        Ok(outcome)
    }

    fn close_slot_inner(&mut self, slot: u64) -> Result<SlotOutcome, Error> {
        if self.next_slot.is_some_and(|expected| expected != slot) {
            return Err(Error::Mismatch);
        }
        self.next_slot = Some(slot.checked_add(1).ok_or(Error::Overflow)?);
        let sheets_in = self.sheets_in_total()?;
        let out = self.out()?;
        let quiet = self
            .previous
            .is_some_and(|p| p.issued == self.issued && p.sheets_in == sheets_in);
        self.quiet_slots = if quiet {
            self.quiet_slots.saturating_add(1).min(2)
        } else {
            0
        };
        let negative = out < 0;
        let high = out > i128::from(self.limit);
        let before = self.previous;
        let conditions = if self.suspended {
            [false; 3]
        } else {
            [
                negative && before.is_some_and(|p| p.negative),
                high && before.is_some_and(|p| p.high),
                self.quiet_slots >= 2 && out > 0,
            ]
        };
        // Checks of finding 3 are judged by the first slot after them.
        for entry in &mut self.pending {
            if let Some(p) = *entry
                && let Some(at) = p.corrected_at
                && at < slot
            {
                let still = conditions
                    .get(alarm_index(p.alarm))
                    .copied()
                    .unwrap_or(true);
                if still {
                    self.holds = self.holds.with(HoldReason::ProgressUnresolved);
                    self.counterfoil = true;
                }
                *entry = None;
            }
        }
        // Alarms without a check after the window.
        for entry in &mut self.pending {
            if let Some(p) = *entry
                && p.corrected_at.is_none()
                && p.slot.saturating_add(CHECK_WINDOW_SLOTS) < slot
            {
                self.holds = self.holds.with(HoldReason::ProgressUnresolved);
                self.counterfoil = true;
                *entry = None;
            }
        }
        let mut raised = Alarms::none();
        for (alarm, now) in ALARMS.iter().zip(conditions) {
            let was = before.is_some_and(|p| {
                p.conditions
                    .get(alarm_index(*alarm))
                    .copied()
                    .unwrap_or(false)
            });
            if now && !was {
                let free = self
                    .pending
                    .iter_mut()
                    .find(|e| e.is_none())
                    .ok_or(Error::Overflow)?;
                *free = Some(Pending {
                    alarm: *alarm,
                    slot,
                    corrected_at: None,
                });
                raised = raised.with(*alarm);
            }
        }
        self.previous = Some(Previous {
            issued: self.issued,
            sheets_in,
            negative,
            high,
            conditions,
        });
        Ok(SlotOutcome { out, raised })
    }

    /// Records the on-site check of an alarm, recorded on the ledger in
    /// slot `at_slot`, against the roster (two clerks and observers of two
    /// organisations, as every witnessed event).
    ///
    /// Findings: 1 resolves a high or floor alarm; 2 adds the sheets to the
    /// carried-out count and holds [`HoldReason::CarryOut`]; 3 waits for
    /// the next slot, which must no longer meet the alarm's condition; 4
    /// holds [`HoldReason::ProgressUnresolved`]. A negative alarm is
    /// resolved only by finding 3: neither people holding ballots nor
    /// carried-out sheets explain sheets that entered without being issued.
    /// Findings 2 and 4, and an unexplained negative alarm, also require
    /// the counterfoil check until close.
    ///
    /// # Errors
    /// The decoding and signature errors of
    /// [`crate::close::check_witnesses`], [`Error::Mismatch`] for another
    /// election or station or an alarm that is not waiting,
    /// [`Error::LateWindow`] after the window, [`Error::Overflow`]. On
    /// error nothing changes.
    pub fn record_check(
        &mut self,
        signed: &Signed<'_>,
        roster: &[RosterEntry<'_>],
        at_slot: u64,
    ) -> Result<(), Error> {
        let body: ProgressCheckBody<'_> = signed
            .event
            .body(SCHEMA_PROGRESS_CHECK_BODY)
            .map_err(|_| Error::Decode)?;
        check_witnesses(signed, roster, None)?;
        let p = body.parts();
        if p.election_id.as_bytes() != self.election_id.as_bytes()
            || p.station_id.as_bytes() != self.station_id.as_bytes()
        {
            return Err(Error::Mismatch);
        }
        let entry = self
            .pending
            .iter_mut()
            .find(|e| {
                e.is_some_and(|w| {
                    w.alarm == p.alarm && w.slot == p.alarm_slot && w.corrected_at.is_none()
                })
            })
            .ok_or(Error::Mismatch)?;
        if at_slot < p.alarm_slot || at_slot > p.alarm_slot.saturating_add(CHECK_WINDOW_SLOTS) {
            return Err(Error::LateWindow);
        }
        let negative = p.alarm == ProgressAlarm::Negative;
        let mut holds = self.holds;
        let mut counterfoil = self.counterfoil;
        let mut carried_out = self.carried_out;
        match p.finding {
            ProgressFinding::Explained => {
                if negative {
                    holds = holds.with(HoldReason::ProgressUnresolved);
                    counterfoil = true;
                }
                *entry = None;
            }
            ProgressFinding::CarriedOut => {
                carried_out = carried_out
                    .checked_add(p.carried_out)
                    .ok_or(Error::Overflow)?;
                holds = holds
                    .with(HoldReason::CarryOut)
                    .with_if(negative, HoldReason::ProgressUnresolved);
                counterfoil = true;
                *entry = None;
            }
            ProgressFinding::Corrected => {
                *entry = Some(Pending {
                    alarm: p.alarm,
                    slot: p.alarm_slot,
                    corrected_at: Some(at_slot),
                });
            }
            ProgressFinding::Unexplained => {
                holds = holds.with(HoldReason::ProgressUnresolved);
                counterfoil = true;
                *entry = None;
            }
        }
        self.holds = holds;
        self.counterfoil = counterfoil;
        self.carried_out = carried_out;
        Ok(())
    }

    /// The station holds so far; they apply to every box of the station.
    #[must_use]
    pub const fn holds(&self) -> HoldSet {
        self.holds
    }

    /// Whether the station must use the counterfoil check until close
    /// (§7.10 item 7).
    #[must_use]
    pub const fn counterfoil_required(&self) -> bool {
        self.counterfoil
    }

    /// Whether the alarms are suspended.
    #[must_use]
    pub const fn suspended(&self) -> bool {
        self.suspended
    }

    /// Alarms still waiting for a check, with their slots.
    pub fn waiting(&self) -> impl Iterator<Item = (ProgressAlarm, u64)> + '_ {
        self.pending
            .iter()
            .flatten()
            .filter(|p| p.corrected_at.is_none())
            .map(|p| (p.alarm, p.slot))
    }

    /// The holds at close: alarms still waiting for a check count as
    /// unresolved.
    #[must_use]
    pub fn finish(&self) -> HoldSet {
        self.holds.with_if(
            self.pending.iter().flatten().next().is_some(),
            HoldReason::ProgressUnresolved,
        )
    }
}

/// `issued − sheets_in − spoiled − returned − carried_out`, exact.
#[must_use]
pub fn out_of(
    issued: u64,
    sheets_in: u64,
    spoiled: u64,
    returned: u64,
    carried_out: u64,
) -> Option<i128> {
    i128::from(issued)
        .checked_sub(i128::from(sheets_in))?
        .checked_sub(i128::from(spoiled))?
        .checked_sub(i128::from(returned))?
        .checked_sub(i128::from(carried_out))
}

#[cfg(test)]
mod tests {
    use ityv_encoding::ProgressAlarm;

    use super::{ALARMS, Alarms};

    #[test]
    fn alarm_set() {
        let none = Alarms::none();
        assert!(none.is_empty());
        for alarm in ALARMS {
            let one = none.with(alarm);
            assert!(!one.is_empty());
            assert!(one.contains(alarm));
            // Adding twice keeps it.
            assert!(one.with(alarm).contains(alarm));
            for other in ALARMS {
                assert_eq!(one.contains(other), other == alarm);
            }
        }
        let all = ALARMS.iter().fold(none, |set, a| set.with(*a));
        assert!(all.contains(ProgressAlarm::Negative));
        assert!(all.contains(ProgressAlarm::High));
        assert!(all.contains(ProgressAlarm::Floor));
    }
}
