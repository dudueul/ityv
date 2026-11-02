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
//! Keys, boxes and limits come from proved genesis entries
//! ([`crate::genesis::Entry`]); the counts a spare device continues from
//! come from the swap events ([`CheckinUnitSwap`], [`BoxUnitSwap`]); the
//! check-in total at close comes from the observers' final
//! [`ObserverCount`].
//!
//! Ticks are fed in slot order. A tick that reaches the ledger late is
//! taken by replaying the station from its opening (the evaluator is
//! small and `Copy`); a slot that never arrives keeps the previous counts
//! and is a stream hold at close. Nothing here reads or changes a record:
//! alarms never touch a record status, and nothing about them is a reason
//! to treat a ballot as invalid.

use ityv_crypto::{HybridSigned, Verified};
use ityv_encoding::{
    BoxClose, BoxId, BoxProgressBody, BoxProgressState, BoxUnitSwapBody, BoxUnitSwapParts,
    CheckinProgressBody, CheckinProgressState, CheckinUnit, CheckinUnitSwapBody,
    CheckinUnitSwapParts, ElectionId, GenesisBox, ObserverCountAttestBody, ObserverCountKind,
    ObserverCountParts, ProgressAlarm, ProgressBody, ProgressCheckBody, ProgressFinding,
    ProgressTick, SCHEMA_BOX_UNIT_SWAP_BODY, SCHEMA_CHECKIN_UNIT_SWAP_BODY,
    SCHEMA_OBSERVER_COUNT_ATTEST_BODY, SCHEMA_PROGRESS_CHECK_BODY, StationEntry, StationId,
    StationProgressPolicy, UnitId,
};

pub use ityv_encoding::MAX_STATION_BOXES;

use crate::close::{RosterEntry, check_observers, check_witnesses};
use crate::error::Error;
use crate::genesis::{Anchor, Entry, Genesis};
use crate::hold::{HoldReason, HoldSet};
use crate::issuance::IssuanceCount;
use crate::sig::{Key, Signed, check_token};

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
    key: &Key,
) -> Result<(), Error> {
    check_token(token, tick.body_bytes(), tick.purpose(), tick.sig(), key)
}

// ---------------------------------------------------------------------------
// Witnessed station events (ADR-0028)

/// An observer count (`ObserverCountAttestBody`, schema `0x003F`) whose
/// signatures were bound to the roster: observers only, of two or more
/// organisations (PROTOCOL.md §6.3, VC-016).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObserverCount<'a> {
    parts: ObserverCountParts<'a>,
}

impl<'a> ObserverCount<'a> {
    /// Checks a signed observer count.
    ///
    /// # Errors
    /// [`Error::Decode`] if the event is not an observer count, and the
    /// errors of [`crate::close::check_observers`].
    pub fn check(signed: &Signed<'a>, roster: &[RosterEntry<'_>]) -> Result<Self, Error> {
        let body: ObserverCountAttestBody<'a> = signed
            .event
            .body(SCHEMA_OBSERVER_COUNT_ATTEST_BODY)
            .map_err(|_| Error::Decode)?;
        check_observers(signed, roster)?;
        Ok(Self {
            parts: *body.parts(),
        })
    }

    /// An observer count without signatures, for unit tests and Kani
    /// harnesses only.
    #[cfg(any(test, kani))]
    pub(crate) const fn unsigned(parts: ObserverCountParts<'a>) -> Self {
        Self { parts }
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &ObserverCountParts<'a> {
        &self.parts
    }

    /// The station's check-in total, if this is the final count of
    /// `station_id` in `election_id`.
    #[must_use]
    pub fn final_total(
        &self,
        election_id: ElectionId<'_>,
        station_id: StationId<'_>,
    ) -> Option<u64> {
        let p = &self.parts;
        (p.kind == ObserverCountKind::Final
            && p.election_id.as_bytes() == election_id.as_bytes()
            && p.station_id.as_bytes() == station_id.as_bytes())
        .then_some(p.count)
    }
}

/// A check-in unit swap (`CheckinUnitSwapBody`, schema `0x0040`) whose
/// signatures were bound to the roster (two clerks, observers of two
/// organisations).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckinUnitSwap<'a> {
    parts: CheckinUnitSwapParts<'a>,
}

impl<'a> CheckinUnitSwap<'a> {
    /// Checks a signed check-in unit swap.
    ///
    /// # Errors
    /// [`Error::Decode`] if the event is not a check-in unit swap, and the
    /// errors of [`check_witnesses`].
    pub fn check(signed: &Signed<'a>, roster: &[RosterEntry<'_>]) -> Result<Self, Error> {
        let body: CheckinUnitSwapBody<'a> = signed
            .event
            .body(SCHEMA_CHECKIN_UNIT_SWAP_BODY)
            .map_err(|_| Error::Decode)?;
        check_witnesses(signed, roster, None)?;
        Ok(Self {
            parts: *body.parts(),
        })
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &CheckinUnitSwapParts<'a> {
        &self.parts
    }
}

/// A commitment-unit swap (`BoxUnitSwapBody`, schema `0x0041`) whose
/// signatures were bound to the roster (two clerks, observers of two
/// organisations).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoxUnitSwap<'a> {
    parts: BoxUnitSwapParts<'a>,
}

impl<'a> BoxUnitSwap<'a> {
    /// Checks a signed commitment-unit swap.
    ///
    /// # Errors
    /// [`Error::Decode`] if the event is not a commitment-unit swap, and
    /// the errors of [`check_witnesses`].
    pub fn check(signed: &Signed<'a>, roster: &[RosterEntry<'_>]) -> Result<Self, Error> {
        let body: BoxUnitSwapBody<'a> = signed
            .event
            .body(SCHEMA_BOX_UNIT_SWAP_BODY)
            .map_err(|_| Error::Decode)?;
        check_witnesses(signed, roster, None)?;
        Ok(Self {
            parts: *body.parts(),
        })
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &BoxUnitSwapParts<'a> {
        &self.parts
    }
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
    anchor: Anchor,
    box_id: BoxId<'a>,
    key: &'a Key,
    inner: Stream<1>,
}

impl<'a> BoxStream<'a> {
    /// Opens the stream of the box `entry` names, whose first tick belongs
    /// to `first_slot` (the slot of `BoxOpened`), with the device key of
    /// the entry.
    ///
    /// # Errors
    /// [`Error::StaleEntry`] if `entry` was not proved against the current
    /// state of `genesis`.
    pub fn open(
        genesis: &Genesis<'a>,
        entry: &Entry<GenesisBox<'a>>,
        first_slot: u64,
    ) -> Result<Self, Error> {
        let anchor = genesis.anchor();
        anchor.admits(entry)?;
        let entry = entry.get();
        Ok(Self {
            election_id: genesis.election_id(),
            anchor,
            box_id: entry.box_id,
            key: entry.device_key,
            inner: Stream::new(first_slot, [0]),
        })
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

    /// Continues with a spare commitment unit: its key from the entry
    /// `entry` of `amended`, a later state of the genesis the stream was
    /// opened with (PROTOCOL.md §4.3), and the slot and sheets-in count
    /// the on-site `swap` record confirms (§7.10 item 8). A count the
    /// signers could not read holds the stream.
    ///
    /// # Errors
    /// [`Error::StaleEntry`] unless `amended` is a later state of the
    /// stream's genesis and `entry` was proved against it,
    /// [`Error::Mismatch`] if the entry or the swap names another box or
    /// election, or the entry still has the current key. On error nothing
    /// changes.
    pub fn swap(
        &mut self,
        amended: &Genesis<'a>,
        entry: &Entry<GenesisBox<'a>>,
        swap: &BoxUnitSwap<'_>,
    ) -> Result<(), Error> {
        let anchor = amended.anchor();
        self.anchor.advance(&anchor)?;
        anchor.admits(entry)?;
        let (e, p) = (entry.get(), swap.parts());
        if e.box_id.as_bytes() != self.box_id.as_bytes()
            || p.box_id.as_bytes() != self.box_id.as_bytes()
            || p.election_id.as_bytes() != self.election_id.as_bytes()
            || e.device_key == self.key
        {
            return Err(Error::Mismatch);
        }
        self.anchor = anchor;
        self.key = e.device_key;
        self.inner.swap(p.at_slot, [p.sheets_in]);
        self.inner.holds = self
            .inner
            .holds
            .with_if(!p.confirmed, HoldReason::ProgressStream);
        Ok(())
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
    unit_id: UnitId<'a>,
    key: &'a Key,
    spare: CheckinUnit<'a>,
    inner: Stream<4>,
}

const fn checkin_counts(body: &CheckinProgressBody<'_>) -> [u64; 4] {
    let p = body.parts();
    [p.checkins, p.issued, p.spoiled, p.returned]
}

impl<'a> CheckinStream<'a> {
    /// Opens the stream of the station `station` names, with the key of
    /// its check-in unit in service.
    ///
    /// # Errors
    /// [`Error::StaleEntry`] if `station` was not proved against the
    /// current state of `genesis`.
    pub fn open(
        genesis: &Genesis<'a>,
        station: &Entry<StationEntry<'a>>,
        first_slot: u64,
    ) -> Result<Self, Error> {
        genesis.anchor().admits(station)?;
        let station = station.get();
        let primary = station.primary();
        Ok(Self {
            election_id: genesis.election_id(),
            station_id: station.station_id(),
            unit_id: primary.unit_id,
            key: primary.key,
            spare: *station.spare(),
            inner: Stream::new(first_slot, [0; 4]),
        })
    }

    /// Takes one tick of this station's unit; see [`BoxStream::accept`].
    ///
    /// # Errors
    /// As [`BoxStream::accept`], and [`Error::Mismatch`] for a tick of the
    /// unit not in service.
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
            || p.unit_id.as_bytes() != self.unit_id.as_bytes()
        {
            return Err(Error::Mismatch);
        }
        let closing = p.state == CheckinProgressState::Closed;
        let usable = self.inner.accept(p.slot, checkin_counts(&body), closing)?;
        Ok(usable.then_some(body))
    }

    /// Continues with the station's sealed spare unit (its key from the
    /// station entry) from the slot and counts the `swap` record confirms
    /// (`[next_seq − 1, issued, spoiled, returned]`, PROTOCOL.md §6.2). A
    /// count the signers could not read holds the stream. The spare is
    /// used once: a second swap would name the spare as the failed unit
    /// and has no spare to go to.
    ///
    /// # Errors
    /// [`Error::Mismatch`] if the swap names another election or station,
    /// a failed unit other than the one in service, or a spare other than
    /// the station's.
    pub fn swap(&mut self, swap: &CheckinUnitSwap<'_>) -> Result<(), Error> {
        let p = swap.parts();
        if p.election_id.as_bytes() != self.election_id.as_bytes()
            || p.station_id.as_bytes() != self.station_id.as_bytes()
            || p.failed_unit.as_bytes() != self.unit_id.as_bytes()
            || p.spare_unit.as_bytes() != self.spare.unit_id.as_bytes()
        {
            return Err(Error::Mismatch);
        }
        self.unit_id = self.spare.unit_id;
        self.key = self.spare.key;
        self.inner.swap(p.at_slot, p.counts());
        self.inner.holds = self
            .inner
            .holds
            .with_if(!p.confirmed, HoldReason::ProgressStream);
        Ok(())
    }

    /// The stream holds at close: the last tick must be a closing tick
    /// whose issued, spoiled and returned counts are the `IssuanceCount`'s
    /// and whose check-ins are the observers' final count.
    ///
    /// # Errors
    /// [`Error::Mismatch`] if the issuance count is another station's, or
    /// `observers` is not the final count of this station.
    pub fn finish(
        &self,
        issuance: &IssuanceCount<'_>,
        observers: &ObserverCount<'_>,
    ) -> Result<HoldSet, Error> {
        let p = issuance.parts();
        if p.election_id.as_bytes() != self.election_id.as_bytes()
            || p.station_id.as_bytes() != self.station_id.as_bytes()
        {
            return Err(Error::Mismatch);
        }
        let total = observers
            .final_total(self.election_id, self.station_id)
            .ok_or(Error::Mismatch)?;
        Ok(self
            .inner
            .finish([total, p.issued, p.voter_spoiled, p.returned]))
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
    /// Starts the evaluator for `station`, with the boxes its entry lists
    /// and the limit of its progress policy.
    ///
    /// # Errors
    /// [`Error::StaleEntry`] if an entry was not proved against the
    /// current state of `genesis`, [`Error::Mismatch`] if the policy is
    /// another station's.
    pub fn new(
        genesis: &Genesis<'a>,
        station: &Entry<StationEntry<'a>>,
        policy: &Entry<StationProgressPolicy<'a>>,
    ) -> Result<Self, Error> {
        let anchor = genesis.anchor();
        anchor.admits(station)?;
        anchor.admits(policy)?;
        let (station, policy) = (station.get(), policy.get());
        if station.station_id().as_bytes() != policy.station_id().as_bytes() {
            return Err(Error::Mismatch);
        }
        Ok(Self::start(genesis.election_id(), policy, station.boxes()))
    }

    /// The evaluator for the station of `policy` with `boxes` (at most
    /// [`MAX_STATION_BOXES`], distinct, as a station entry guarantees).
    pub(crate) fn start(
        election_id: ElectionId<'a>,
        policy: &StationProgressPolicy<'a>,
        boxes: impl Iterator<Item = BoxId<'a>>,
    ) -> Self {
        let mut box_ids = [None; MAX_STATION_BOXES];
        for (slot, id) in box_ids.iter_mut().zip(boxes) {
            *slot = Some(id);
        }
        Self {
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
        }
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
