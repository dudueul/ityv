//! The progress stage (PROTOCOL.md §7.10; ADR-0027; VC-102, VC-103,
//! VC-106).
//!
//! For every station of the genesis's last state, [`verify_progress`]
//! drives `ityv_state`'s progress evaluators with the station's voting
//! progress record from the [`LedgerIndex`]:
//!
//! * each commitment unit's ticks through a `BoxStream` and the check-in
//!   unit's through a `CheckinStream` (VC-102: one tick per slot, slots in
//!   order from opening, counts that never go down, nothing after the
//!   closing tick), with the device swaps the box stage accepted
//!   (`BoxUnitSwap`) and the witnessed check-in unit swaps
//!   (`CheckinUnitSwap`), from whose counts the spare continues (VC-106);
//! * the counts the streams take through the station's `StationProgress`,
//!   slot by slot, which raises the negative, high and floor alarms, takes
//!   the on-site `ProgressCheck` of each and holds the station
//!   (`PROGRESS_UNRESOLVED`, `CARRY_OUT`) when a check is missing or finds
//!   carried-out or unexplained sheets (VC-103);
//! * at close, each box's last tick against its device-signed close and the
//!   check-in unit's last tick against the station's `IssuanceCount` and
//!   final `ObserverCountAttest` (§7.10 item 8).
//!
//! The rules are `ityv-state`'s. This stage does what they leave to the
//! caller:
//!
//! 1. **Slots and time buckets.** Slots are 10 minutes and time buckets 15
//!    minutes, both counted from the election epoch day (§5.8 item 3), so
//!    bucket `b` overlaps slots `⌊3b/2⌋` to `⌊(3b+2)/2⌋` ([`bucket_slots`]).
//! 2. **Opening.** A device stream starts at the slot of its first tick
//!    whose signature verifies, kept within the opening window: the slots
//!    the time bucket of the box's accepted `BoxOpened` overlaps and the
//!    slot after them (the opening's own slot or the first slot after it).
//!    A tick before the window is before opening; a first tick after it
//!    leaves the slots in between missing. The check-in unit opens with the
//!    station's first accepted `BoxOpened` (by frame). A tick of a box or
//!    station that never opened is refused ([`ProgressReason::NotOpened`]).
//! 3. **Order.** Each device's ticks are fed in slot order (frame order
//!    within a slot), not frame order: a tick that reaches the ledger late
//!    is counted as if on time (§7.10 item 4). A swap at slot `s` comes
//!    before the ticks of slot `s`.
//! 4. **Keys.** A tick's signature is verified under the device's key in
//!    every genesis state up to the one in force at its frame (the box's
//!    device key; the station's in-service and spare unit keys); the stream
//!    takes the token only from the key it is bound to, so a replaced
//!    device's tick after the swap is refused. Witnessed events are
//!    verified under the roster of the state in force at their frame.
//! 5. **Swaps.** A `BoxUnitSwap` the box stage accepted moves the box's
//!    stream to the device key of the state in force at the swap's frame;
//!    a `CheckinUnitSwap` moves the station's stream to its spare unit.
//!    Either suspends the station's alarms from its slot, as does an
//!    accepted `FallbackDeclared` from the first slot of its time bucket
//!    (§7.10 item 5); a tick in fallback or after a swap suspends them too.
//! 6. **Checks.** A `ProgressCheck` counts as recorded in the last slot its
//!    time bucket overlaps: the window of two slots must hold for the whole
//!    bucket, and a correction (finding 3) is judged by the slot after the
//!    latest one it could have been recorded in. A check is applied right
//!    after its slot is closed.
//! 7. **Station entries.** The evaluator and the check-in stream take the
//!    station entry and progress policy of the genesis state in force at
//!    the station's first opening frame.
//! 8. **Close.** A box whose close the box stage accepted is compared with
//!    its effective close (the last accepted `BoxClose`, as the record
//!    stage takes it) when that close carries the device's signature; a
//!    manual close is not compared (its own hold, §10.2). A station is
//!    closed when every box of its last-state entry is; then its check-in
//!    stream is compared with the station's last `IssuanceCount` and last
//!    final `ObserverCountAttest`, and either missing (or refused) holds
//!    the station; and its alarms still waiting are unresolved. Before
//!    then only the holds so far count: a ledger read during voting is not
//!    held for what has not come yet.
//! 9. **Bound.** A station's slots run at most [`MAX_PROGRESS_SLOTS`] past
//!    its first slot; a tick or swap later than that is refused.
//! 10. **Holds.** Every refused event is listed and holds: a tick, swap or
//!     count `PROGRESS_STREAM`, a check `PROGRESS_UNRESOLVED`. A box's
//!     stream holds its box; the check-in stream, the alarms and the
//!     station's refusals hold every box of the station
//!     ([`ProgressStage::box_holds`]). A station an amendment removed has
//!     each of its progress events refused and held.
//!
//! What this stage does not prove: that a check's statement is true, that
//! a swap's confirmed counts are the failed device's (only the witnesses'
//! signatures say so), the check-in sequence continuity across a unit swap
//! (VC-073, a restricted verifier's), or anything that would change a
//! record: alarms never touch a record's status.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use ityv_crypto::{HybridSigned, Purpose, Verified};
use ityv_encoding::{
    BoxClose, BoxId, BoxOpenedBody, BoxProgressBody, BoxUnitSwapBody, CheckinProgressBody,
    CheckinUnitSwapBody, Decode, EventRole, FallbackBody, FallbackKind, HYBRID_SIG_LEN,
    HYBRID_VK_LEN, ObserverCountAttestBody, ObserverCountKind, ProgressAlarm, ProgressCheckBody,
    ProgressTick, SCHEMA_BOX_CLOSE, SCHEMA_BOX_OPENED_BODY, SCHEMA_BOX_UNIT_SWAP_BODY,
    SCHEMA_CHECKIN_UNIT_SWAP_BODY, SCHEMA_FALLBACK_BODY, SCHEMA_ISSUANCE_COUNT_BODY,
    SCHEMA_OBSERVER_COUNT_ATTEST_BODY, SCHEMA_PROGRESS_CHECK_BODY, SCHEMA_PROGRESS_TICK,
    SCHEMA_VERSION_1, SCHEMA_WITNESSED_EVENT, SchemaId, Seq, StationEntry, StationId, TimeBucket,
    WitnessedEvent, decode_object,
};
use ityv_state::{
    BoxStream, BoxUnitSwap, CheckinStream, CheckinUnitSwap, Error, HoldReason, HoldSet,
    IssuanceCount, ObserverCount, RosterEntry, Signed, StationProgress,
};

use crate::boxes::{BoxStage, Phase};
use crate::genesis::VerifiedGenesis;
use crate::index::{IndexedEvent, LedgerIndex, Scope};
use crate::sigs::Material;

/// The most slots a station's progress record may span from its first
/// slot: 31 days of 10-minute slots, longer than any voting period
/// (postal receipt included). A later tick or swap is refused.
pub const MAX_PROGRESS_SLOTS: u64 = 31 * 144;

/// The alarms, in the order a slot's report lists them.
const ALARMS: [ProgressAlarm; 3] = [
    ProgressAlarm::Negative,
    ProgressAlarm::High,
    ProgressAlarm::Floor,
];

/// Why the progress stage did not take an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgressReason {
    /// `ityv-state` refused it.
    State(Error),
    /// No key the genesis registers for a signer verifies its signature.
    Signature,
    /// The stream took the tick, but it breaks a slot rule (a second tick
    /// for its slot, a tick before the stream's first slot or after its
    /// closing tick): its counts are not used.
    Unused,
    /// A tick, swap or check of a box or station that never opened (no
    /// accepted `BoxOpened`).
    NotOpened,
    /// A slot more than [`MAX_PROGRESS_SLOTS`] after the station's first
    /// slot, or a time bucket with no slot.
    OutOfRange,
    /// A progress event of a station the genesis's last state does not
    /// have.
    Unexpected,
}

/// One event the progress stage did not take.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProgressRefusal {
    /// The frame that carries it.
    pub seq: Seq,
    /// Why.
    pub reason: ProgressReason,
}

/// Whether a device stream was compared with its close (§7.10 item 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CloseCheck {
    /// Not closed yet: nothing to compare.
    Open,
    /// Compared: a box with its device-signed close; a station's check-in
    /// stream with its `IssuanceCount` and final `ObserverCountAttest`.
    Compared,
    /// A manual close: not compared (it holds on its own, §10.2).
    Manual,
    /// Closed, but what the comparison needs is missing or was refused.
    Missing,
}

/// An alarm the station evaluator raised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RaisedAlarm {
    /// The slot whose close raised it.
    pub slot: u64,
    /// Which alarm.
    pub alarm: ProgressAlarm,
}

/// What the progress stage concluded about one box's commitment unit.
#[derive(Debug, Clone)]
pub struct BoxProgressReport<'a> {
    /// The box.
    pub box_id: BoxId<'a>,
    /// Its station.
    pub station_id: StationId<'a>,
    /// The slot its stream started at, if it opened.
    pub first_slot: Option<u64>,
    /// The ticks whose counts the station evaluator took.
    pub ticks: usize,
    /// Whether the stream was compared with the close.
    pub close: CloseCheck,
    /// The holds of the box's stream and of its refusals (the station's
    /// holds come on top, [`ProgressStage::box_holds`]).
    pub holds: HoldSet,
    /// The box's events this stage did not take, in frame order.
    pub refusals: Vec<ProgressRefusal>,
}

/// What the progress stage concluded about one station.
#[derive(Debug, Clone)]
pub struct StationProgressReport<'a> {
    /// The station.
    pub station_id: StationId<'a>,
    /// The first slot the evaluator closed from, if the station opened.
    pub first_slot: Option<u64>,
    /// The last slot the evaluator closed.
    pub last_slot: Option<u64>,
    /// The check-in ticks whose counts the evaluator took.
    pub ticks: usize,
    /// Every alarm raised, in slot order.
    pub alarms: Vec<RaisedAlarm>,
    /// The frames of the on-site checks the evaluator took.
    pub checks: Vec<Seq>,
    /// Whether the alarms were suspended (§7.10 item 5).
    pub suspended: bool,
    /// Whether the station must use the counterfoil check until close
    /// (§7.10 item 7).
    pub counterfoil: bool,
    /// Whether the check-in stream was compared at close.
    pub close: CloseCheck,
    /// The holds on every box of the station: the check-in stream's, the
    /// alarms' and those of the station's refusals.
    pub holds: HoldSet,
    /// The station's events this stage did not take (with the box ticks
    /// the evaluator refused), in frame order.
    pub refusals: Vec<ProgressRefusal>,
}

/// The progress stage over every station.
#[derive(Debug, Clone)]
pub struct ProgressStage<'a> {
    stations: Vec<StationProgressReport<'a>>,
    boxes: Vec<BoxProgressReport<'a>>,
}

impl<'a> ProgressStage<'a> {
    /// One report per station of the genesis's last state, in station
    /// order, then one per station an amendment removed that has progress
    /// events.
    #[must_use]
    pub fn stations(&self) -> &[StationProgressReport<'a>] {
        &self.stations
    }

    /// The report of station `station_id`.
    #[must_use]
    pub fn station(&self, station_id: &[u8]) -> Option<&StationProgressReport<'a>> {
        self.stations
            .iter()
            .find(|r| r.station_id.as_bytes() == station_id)
    }

    /// One report per box of the stations of the genesis's last state, in
    /// station order and then in the station's box order.
    #[must_use]
    pub fn boxes(&self) -> &[BoxProgressReport<'a>] {
        &self.boxes
    }

    /// The report of box `box_id`.
    #[must_use]
    pub fn report(&self, box_id: &[u8]) -> Option<&BoxProgressReport<'a>> {
        self.boxes.iter().find(|r| r.box_id.as_bytes() == box_id)
    }

    /// Every hold on box `box_id`: its own stream's and its station's.
    #[must_use]
    pub fn box_holds(&self, box_id: &[u8]) -> HoldSet {
        self.report(box_id).map_or(HoldSet::empty(), |r| {
            r.holds.union(
                self.station(r.station_id.as_bytes())
                    .map_or(HoldSet::empty(), |s| s.holds),
            )
        })
    }

    /// Every hold of the stage.
    #[must_use]
    pub fn holds(&self) -> HoldSet {
        self.boxes
            .iter()
            .map(|r| r.holds)
            .chain(self.stations.iter().map(|r| r.holds))
            .fold(HoldSet::empty(), HoldSet::union)
    }
}

/// The 10-minute slots that the 15-minute time bucket `bucket` overlaps,
/// first and last, both counted from the election epoch day; `None` past
/// the last slot.
#[must_use]
pub fn bucket_slots(bucket: TimeBucket) -> Option<(u64, u64)> {
    let minutes = bucket.get().checked_mul(3)?;
    Some((
        minutes.checked_div(2)?,
        minutes.checked_add(2)?.checked_div(2)?,
    ))
}

// ---------------------------------------------------------------------------
// Decoding and signatures.

type Token<'t> = Verified<HybridSigned<'t>>;
type Tokens<'t> = Option<Vec<Token<'t>>>;

/// The registered key of each roster signer, by identifier.
type Keys<'a> = BTreeMap<&'a [u8], &'a [u8; HYBRID_VK_LEN]>;

fn decode<'a, T: Decode<'a>>(schema: SchemaId, bytes: &'a [u8]) -> Option<T> {
    decode_object(schema, SCHEMA_VERSION_1, bytes).ok()
}

/// A tick, decoded, with the material of every key that may have signed
/// it.
struct Tick<'a> {
    seq: Seq,
    signed: ProgressTick<'a>,
    purpose: Option<Purpose<'static>>,
    candidates: Vec<Material>,
}

impl<'a> Tick<'a> {
    fn new<'k>(
        seq: Seq,
        bytes: &'a [u8],
        keys: impl Iterator<Item = &'k [u8; HYBRID_VK_LEN]>,
    ) -> Option<Self> {
        let tick: ProgressTick<'a> = decode(SCHEMA_PROGRESS_TICK, bytes)?;
        let mut seen: BTreeSet<&[u8; HYBRID_VK_LEN]> = BTreeSet::new();
        let candidates = keys
            .filter(|k| seen.insert(*k))
            .filter_map(|k| Material::new(core::iter::once((tick.sig(), k))))
            .collect();
        Some(Self {
            seq,
            signed: tick,
            purpose: Purpose::new(tick.purpose()),
            candidates,
        })
    }

    fn slot(&self) -> u64 {
        self.signed.body().slot()
    }

    /// The token of the first candidate key that verifies the tick.
    fn token(&self) -> Option<Token<'_>> {
        let purpose = self.purpose.as_ref()?;
        self.candidates.iter().find_map(|m| {
            m.verify(purpose, self.signed.body_bytes())
                .and_then(|t| t.into_iter().next())
        })
    }
}

/// A witnessed event, decoded, with the material its tokens need and the
/// genesis state in force at its frame.
struct Witnessed<'a> {
    seq: Seq,
    state: usize,
    event: WitnessedEvent<'a>,
    purpose: Option<Purpose<'static>>,
    material: Option<Material>,
}

impl<'a> Witnessed<'a> {
    /// Each signature with its signer's key on the roster `keys` (a station
    /// event has no device signature).
    fn new(seq: Seq, state: usize, event: &WitnessedEvent<'a>, keys: &Keys<'_>) -> Self {
        let event = *event;
        let pairs: Option<Vec<(&[u8; HYBRID_SIG_LEN], &[u8; HYBRID_VK_LEN])>> = event
            .sigs()
            .map(|s| {
                let key = if s.role == EventRole::Device {
                    None
                } else {
                    keys.get(s.signer_id.as_bytes()).copied()
                };
                key.map(|k| (s.sig, k))
            })
            .collect();
        Self {
            seq,
            state,
            event,
            purpose: Purpose::new(event.purpose()),
            material: pairs.and_then(|p| Material::new(p.into_iter())),
        }
    }

    fn tokens(&self) -> Tokens<'_> {
        self.material
            .as_ref()?
            .verify(self.purpose.as_ref()?, self.event.body_bytes())
    }
}

/// A witnessed event with the slot it belongs to (a swap's `at_slot`, a
/// check's recording slot).
struct Slotted<'a> {
    slot: u64,
    item: Witnessed<'a>,
}

/// What every station's run shares.
struct Shared<'x, 'a> {
    genesis: &'x VerifiedGenesis<'a>,
    index: &'x LedgerIndex<'a>,
    boxes: &'x BoxStage<'a>,
    /// The roster of each genesis state, proved against it.
    rosters: &'x [Vec<RosterEntry<'a>>],
    /// The roster keys of each genesis state.
    keys: &'x [Keys<'a>],
}

impl<'a> Shared<'_, 'a> {
    fn roster(&self, state: usize) -> &[RosterEntry<'a>] {
        self.rosters.get(state).map_or(&[], Vec::as_slice)
    }

    fn witnessed(&self, seq: Seq, event: &WitnessedEvent<'a>) -> Witnessed<'a> {
        let state = self.index.state_at(seq);
        let empty = Keys::new();
        Witnessed::new(seq, state, event, self.keys.get(state).unwrap_or(&empty))
    }
}

/// A box's progress events, decoded.
struct BoxItems<'a> {
    box_id: BoxId<'a>,
    /// The frame and time bucket of the box's accepted `BoxOpened`.
    opened: Option<(Seq, TimeBucket)>,
    /// The time buckets of its accepted `FallbackDeclared` events.
    fallbacks: Vec<TimeBucket>,
    /// Whether the box stage closed the box.
    closed: bool,
    /// Its last accepted `BoxClose`.
    close: Option<BoxClose<'a>>,
    ticks: Vec<Tick<'a>>,
    /// Its accepted `BoxUnitSwap` events, at their slots.
    swaps: Vec<Slotted<'a>>,
    /// Events that do not decode.
    refused: Vec<ProgressRefusal>,
}

fn box_items<'a>(shared: &Shared<'_, 'a>, box_id: BoxId<'a>) -> BoxItems<'a> {
    let report = shared.boxes.report(box_id.as_bytes());
    let skipped: BTreeSet<u64> = report
        .map(|r| r.refusals.iter().map(|x| x.seq.get()).collect())
        .unwrap_or_default();
    let mut items = BoxItems {
        box_id,
        opened: None,
        fallbacks: Vec::new(),
        closed: report.is_some_and(|r| matches!(r.phase, Phase::Closed | Phase::Counted)),
        close: None,
        ticks: Vec::new(),
        swaps: Vec::new(),
        refused: Vec::new(),
    };
    for e in shared.index.box_events(box_id.as_bytes()) {
        let Some(bytes) = e.bytes else {
            continue;
        };
        if e.schema == SCHEMA_PROGRESS_TICK {
            let state = shared.index.state_at(e.seq);
            let keys = (0..=state)
                .filter_map(|s| shared.genesis.expected_box_at(s, box_id.as_bytes()))
                .map(|b| b.device_key);
            match Tick::new(e.seq, bytes, keys) {
                Some(t) => items.ticks.push(t),
                None => items.refused.push(undecoded(e)),
            }
        } else if skipped.contains(&e.seq.get()) {
            // The box stage refused it.
        } else if e.schema == SCHEMA_BOX_CLOSE {
            if let Some(close) = decode(e.schema, bytes) {
                items.close = Some(close);
            }
        } else if e.schema == SCHEMA_WITNESSED_EVENT
            && let Some(w) = decode::<WitnessedEvent<'a>>(e.schema, bytes)
        {
            box_event(shared, &mut items, e.seq, &w);
        }
    }
    items
}

/// One accepted witnessed event of a box.
fn box_event<'a>(
    shared: &Shared<'_, 'a>,
    items: &mut BoxItems<'a>,
    seq: Seq,
    w: &WitnessedEvent<'a>,
) {
    let body = w.body_schema();
    if body == SCHEMA_BOX_OPENED_BODY {
        if items.opened.is_none() {
            items.opened = w
                .body::<BoxOpenedBody<'a>>(body)
                .ok()
                .map(|b| (seq, b.parts().time_bucket));
        }
    } else if body == SCHEMA_FALLBACK_BODY {
        if let Ok(b) = w.body::<FallbackBody<'a>>(body)
            && b.parts().kind == FallbackKind::Declared
        {
            items.fallbacks.push(b.parts().time_bucket);
        }
    } else if body == SCHEMA_BOX_UNIT_SWAP_BODY
        && let Ok(b) = w.body::<BoxUnitSwapBody<'a>>(body)
    {
        items.swaps.push(Slotted {
            slot: b.parts().at_slot,
            item: shared.witnessed(seq, w),
        });
    }
}

const fn undecoded(e: &IndexedEvent<'_>) -> ProgressRefusal {
    ProgressRefusal {
        seq: e.seq,
        reason: ProgressReason::State(Error::Decode),
    }
}

/// A station's progress events, decoded.
struct StationItems<'a> {
    station_id: StationId<'a>,
    boxes: Vec<BoxItems<'a>>,
    ticks: Vec<Tick<'a>>,
    swaps: Vec<Slotted<'a>>,
    checks: Vec<Slotted<'a>>,
    /// The station's last final `ObserverCountAttest`.
    observers: Option<Witnessed<'a>>,
    /// The station's last `IssuanceCount`.
    issuance: Option<Witnessed<'a>>,
    /// Ticks and swaps that do not decode.
    refused: Vec<ProgressRefusal>,
    /// Checks without a recording slot.
    refused_checks: Vec<ProgressRefusal>,
}

fn station_items<'a>(shared: &Shared<'_, 'a>, station: &StationEntry<'a>) -> StationItems<'a> {
    let id = station.station_id();
    let mut items = StationItems {
        station_id: id,
        boxes: station.boxes().map(|b| box_items(shared, b)).collect(),
        ticks: Vec::new(),
        swaps: Vec::new(),
        checks: Vec::new(),
        observers: None,
        issuance: None,
        refused: Vec::new(),
        refused_checks: Vec::new(),
    };
    for e in shared.index.station_events(id.as_bytes()) {
        let Some(bytes) = e.bytes else {
            continue;
        };
        if e.schema == SCHEMA_PROGRESS_TICK {
            let state = shared.index.state_at(e.seq);
            let keys = (0..=state)
                .filter_map(|s| shared.genesis.station_at(s, id.as_bytes()))
                .flat_map(|st| [st.primary().key, st.spare().key]);
            match Tick::new(e.seq, bytes, keys) {
                Some(t) => items.ticks.push(t),
                None => items.refused.push(undecoded(e)),
            }
        } else if e.schema == SCHEMA_WITNESSED_EVENT {
            match decode::<WitnessedEvent<'a>>(e.schema, bytes) {
                Some(w) => station_event(shared, &mut items, e, &w),
                None => items.refused.push(undecoded(e)),
            }
        }
    }
    items
}

/// One witnessed event of a station.
fn station_event<'a>(
    shared: &Shared<'_, 'a>,
    items: &mut StationItems<'a>,
    e: &IndexedEvent<'a>,
    w: &WitnessedEvent<'a>,
) {
    let body = w.body_schema();
    if body == SCHEMA_PROGRESS_CHECK_BODY {
        match w
            .body::<ProgressCheckBody<'a>>(body)
            .ok()
            .and_then(|b| bucket_slots(b.parts().time_bucket))
        {
            Some((_, last)) => items.checks.push(Slotted {
                slot: last,
                item: shared.witnessed(e.seq, w),
            }),
            None => items.refused_checks.push(ProgressRefusal {
                seq: e.seq,
                reason: ProgressReason::OutOfRange,
            }),
        }
    } else if body == SCHEMA_CHECKIN_UNIT_SWAP_BODY {
        match w.body::<CheckinUnitSwapBody<'a>>(body) {
            Ok(b) => items.swaps.push(Slotted {
                slot: b.parts().at_slot,
                item: shared.witnessed(e.seq, w),
            }),
            Err(_) => items.refused.push(undecoded(e)),
        }
    } else if body == SCHEMA_OBSERVER_COUNT_ATTEST_BODY {
        if w.body::<ObserverCountAttestBody<'a>>(body)
            .is_ok_and(|b| b.parts().kind == ObserverCountKind::Final)
        {
            items.observers = Some(shared.witnessed(e.seq, w));
        }
    } else if body == SCHEMA_ISSUANCE_COUNT_BODY {
        items.issuance = Some(shared.witnessed(e.seq, w));
    }
}

/// The tokens of a box's items.
struct BoxTokens<'t> {
    ticks: Vec<Option<Token<'t>>>,
    swaps: Vec<Tokens<'t>>,
}

/// The tokens of a station's items.
struct StationTokens<'t> {
    boxes: Vec<BoxTokens<'t>>,
    ticks: Vec<Option<Token<'t>>>,
    swaps: Vec<Tokens<'t>>,
    checks: Vec<Tokens<'t>>,
    observers: Tokens<'t>,
    issuance: Tokens<'t>,
}

impl StationItems<'_> {
    fn tokens(&self) -> StationTokens<'_> {
        StationTokens {
            boxes: self
                .boxes
                .iter()
                .map(|b| BoxTokens {
                    ticks: b.ticks.iter().map(Tick::token).collect(),
                    swaps: b.swaps.iter().map(|s| s.item.tokens()).collect(),
                })
                .collect(),
            ticks: self.ticks.iter().map(Tick::token).collect(),
            swaps: self.swaps.iter().map(|s| s.item.tokens()).collect(),
            checks: self.checks.iter().map(|s| s.item.tokens()).collect(),
            observers: self.observers.as_ref().and_then(Witnessed::tokens),
            issuance: self.issuance.as_ref().and_then(Witnessed::tokens),
        }
    }
}

// ---------------------------------------------------------------------------
// Device streams.

/// One device's stream, as [`run_stream`] drives it.
trait Device<'a> {
    /// What a usable tick gives the station evaluator.
    type Body;

    /// Takes one tick.
    fn take_tick(
        &mut self,
        tick: &ProgressTick<'a>,
        token: &Token<'_>,
    ) -> Result<Option<Self::Body>, Error>;

    /// Takes one witnessed swap, checked against the roster of its state.
    fn take_swap(
        &mut self,
        shared: &Shared<'_, 'a>,
        swap: &Witnessed<'a>,
        tokens: &[Token<'_>],
    ) -> Result<(), Error>;
}

/// A commitment unit's stream.
struct BoxDevice<'a> {
    stream: BoxStream<'a>,
    box_id: BoxId<'a>,
}

impl<'a> Device<'a> for BoxDevice<'a> {
    type Body = BoxProgressBody<'a>;

    fn take_tick(
        &mut self,
        tick: &ProgressTick<'a>,
        token: &Token<'_>,
    ) -> Result<Option<Self::Body>, Error> {
        self.stream.accept(tick, token)
    }

    fn take_swap(
        &mut self,
        shared: &Shared<'_, 'a>,
        swap: &Witnessed<'a>,
        tokens: &[Token<'_>],
    ) -> Result<(), Error> {
        let signed = Signed {
            event: &swap.event,
            tokens,
        };
        let checked = BoxUnitSwap::check(&signed, shared.roster(swap.state))?;
        let genesis = shared
            .genesis
            .genesis_at(swap.state)
            .ok_or(Error::StaleEntry)?;
        let entry = shared
            .genesis
            .box_entry_at(swap.state, self.box_id.as_bytes())
            .ok_or(Error::StaleEntry)?;
        self.stream.swap(genesis, &entry, &checked)
    }
}

impl<'a> Device<'a> for CheckinStream<'a> {
    type Body = CheckinProgressBody<'a>;

    fn take_tick(
        &mut self,
        tick: &ProgressTick<'a>,
        token: &Token<'_>,
    ) -> Result<Option<Self::Body>, Error> {
        self.accept(tick, token)
    }

    fn take_swap(
        &mut self,
        shared: &Shared<'_, 'a>,
        swap: &Witnessed<'a>,
        tokens: &[Token<'_>],
    ) -> Result<(), Error> {
        let signed = Signed {
            event: &swap.event,
            tokens,
        };
        let checked = CheckinUnitSwap::check(&signed, shared.roster(swap.state))?;
        CheckinStream::swap(self, &checked)
    }
}

/// What one device's stream gave.
struct Pass<B> {
    /// The bodies of its usable ticks, with their slots and frames.
    usable: Vec<(u64, Seq, B)>,
    /// The slots of the swaps it took.
    swapped: Vec<u64>,
    refusals: Vec<ProgressRefusal>,
}

impl<B> Pass<B> {
    /// Every tick and swap refused for `reason`.
    fn refused(ticks: &[Tick<'_>], swaps: &[Slotted<'_>], reason: ProgressReason) -> Self {
        Self {
            usable: Vec::new(),
            swapped: Vec::new(),
            refusals: ticks
                .iter()
                .map(|t| t.seq)
                .chain(swaps.iter().map(|s| s.item.seq))
                .map(|seq| ProgressRefusal { seq, reason })
                .collect(),
        }
    }
}

/// One step of a device's stream.
enum Step<'r, 'a, 't> {
    Tick(&'r Tick<'a>, Option<&'r Token<'t>>),
    Swap(&'r Slotted<'a>, Option<&'r [Token<'t>]>),
}

/// Feeds a device's swaps and ticks in slot order (a swap before the ticks
/// of its slot, frame order within a slot), refusing anything after
/// `horizon`.
fn run_stream<'a, D: Device<'a>>(
    shared: &Shared<'_, 'a>,
    device: &mut D,
    ticks: &[Tick<'a>],
    tick_tokens: &[Option<Token<'_>>],
    swaps: &[Slotted<'a>],
    swap_tokens: &[Tokens<'_>],
    horizon: u64,
) -> Pass<D::Body> {
    let mut steps: Vec<(u64, u8, u64, Step<'_, 'a, '_>)> = swaps
        .iter()
        .zip(swap_tokens)
        .map(|(s, t)| (s.slot, 0, s.item.seq.get(), Step::Swap(s, t.as_deref())))
        .chain(
            ticks
                .iter()
                .zip(tick_tokens)
                .map(|(t, k)| (t.slot(), 1, t.seq.get(), Step::Tick(t, k.as_ref()))),
        )
        .collect();
    steps.sort_by_key(|s| (s.0, s.1, s.2));
    let mut pass = Pass {
        usable: Vec::new(),
        swapped: Vec::new(),
        refusals: Vec::new(),
    };
    for (slot, _, _, step) in steps {
        let seq = match step {
            Step::Tick(t, _) => t.seq,
            Step::Swap(s, _) => s.item.seq,
        };
        let outcome = if slot > horizon {
            Err(ProgressReason::OutOfRange)
        } else {
            match step {
                Step::Tick(_, None) | Step::Swap(_, None) => Err(ProgressReason::Signature),
                Step::Tick(t, Some(token)) => match device.take_tick(&t.signed, token) {
                    Ok(Some(body)) => {
                        pass.usable.push((slot, t.seq, body));
                        Ok(())
                    }
                    Ok(None) => Err(ProgressReason::Unused),
                    Err(e) => Err(ProgressReason::State(e)),
                },
                Step::Swap(s, Some(tokens)) => device
                    .take_swap(shared, &s.item, tokens)
                    .map(|()| pass.swapped.push(slot))
                    .map_err(ProgressReason::State),
            }
        };
        if let Err(reason) = outcome {
            pass.refusals.push(ProgressRefusal { seq, reason });
        }
    }
    pass
}

/// The first slot of a device stream opened in time bucket `opened`: the
/// earliest of `slots` (its ticks whose signatures verify) kept within the
/// opening window, or the window's start without one; `None` for a bucket
/// with no slot.
fn first_slot(opened: TimeBucket, slots: impl Iterator<Item = u64>) -> Option<u64> {
    let (start, end) = bucket_slots(opened)?;
    let last = end.saturating_add(1);
    Some(slots.min().map_or(start, |s| s.max(start).min(last)))
}

/// The slots of the ticks whose signatures verify.
fn verified<'r>(
    ticks: &'r [Tick<'_>],
    tokens: &'r [Option<Token<'_>>],
) -> impl Iterator<Item = u64> + 'r {
    ticks
        .iter()
        .zip(tokens)
        .filter(|(_, k)| k.is_some())
        .map(|(t, _)| t.slot())
}

// ---------------------------------------------------------------------------
// One box.

/// A box's stream run, for the station.
struct BoxRun<'a> {
    report: BoxProgressReport<'a>,
    usable: Vec<(u64, Seq, BoxProgressBody<'a>)>,
    /// Slots from which the box suspends the station's alarms.
    suspensions: Vec<u64>,
}

fn run_box<'a>(
    shared: &Shared<'_, 'a>,
    station_id: StationId<'a>,
    items: &BoxItems<'a>,
    tokens: &BoxTokens<'_>,
    first: Option<u64>,
    horizon: u64,
) -> BoxRun<'a> {
    let id = items.box_id;
    let opened = first.zip(items.opened).map(|(first, (seq, _))| {
        let state = shared.index.state_at(seq);
        shared
            .genesis
            .genesis_at(state)
            .zip(shared.genesis.box_entry_at(state, id.as_bytes()))
            .ok_or(Error::StaleEntry)
            .and_then(|(g, e)| BoxStream::open(g, &e, first))
    });
    let (pass, stream) = match opened {
        Some(Ok(stream)) => {
            let mut device = BoxDevice { stream, box_id: id };
            let pass = run_stream(
                shared,
                &mut device,
                &items.ticks,
                &tokens.ticks,
                &items.swaps,
                &tokens.swaps,
                horizon,
            );
            (pass, Some(device.stream))
        }
        Some(Err(e)) => (
            Pass::refused(&items.ticks, &items.swaps, ProgressReason::State(e)),
            None,
        ),
        None => (
            Pass::refused(&items.ticks, &items.swaps, ProgressReason::NotOpened),
            None,
        ),
    };
    let close = match (items.closed, items.close.as_ref()) {
        (false, _) => CloseCheck::Open,
        (true, Some(c)) if c.device_sig().is_some() => CloseCheck::Compared,
        (true, Some(_)) => CloseCheck::Manual,
        (true, None) => CloseCheck::Missing,
    };
    let stream_holds = match (stream.as_ref(), items.close.as_ref()) {
        (Some(s), Some(c)) if close == CloseCheck::Compared => s.finish(c),
        (Some(s), _) => s.holds(),
        (None, _) => HoldSet::empty(),
    };
    let mut refusals = pass.refusals;
    refusals.extend(items.refused.iter().copied());
    refusals.sort_by_key(|r| r.seq.get());
    let holds = stream_holds.with_if(
        !refusals.is_empty() || close == CloseCheck::Missing,
        HoldReason::ProgressStream,
    );
    let suspensions = items
        .fallbacks
        .iter()
        .filter_map(|b| bucket_slots(*b).map(|(start, _)| start))
        .chain(pass.swapped)
        .collect();
    BoxRun {
        report: BoxProgressReport {
            box_id: id,
            station_id,
            first_slot: stream.and(first),
            ticks: pass.usable.len(),
            close,
            holds,
            refusals,
        },
        usable: pass.usable,
        suspensions,
    }
}

// ---------------------------------------------------------------------------
// The station evaluator.

/// What the evaluator found.
#[derive(Default)]
struct Evaluation {
    alarms: Vec<RaisedAlarm>,
    checks: Vec<Seq>,
    last_slot: Option<u64>,
    /// A slot could not be closed (`ityv-state` refused it).
    failed: bool,
    /// Box and check-in ticks the evaluator refused.
    refusals: Vec<ProgressRefusal>,
    /// Checks it refused.
    check_refusals: Vec<ProgressRefusal>,
}

/// What the station's streams give the evaluator.
struct Streams<'a> {
    boxes: Vec<(u64, Seq, BoxProgressBody<'a>)>,
    checkins: Vec<(u64, Seq, CheckinProgressBody<'a>)>,
    suspensions: Vec<u64>,
}

/// Takes one check, recorded in its slot.
fn apply_check<'a>(
    shared: &Shared<'_, 'a>,
    eval: &mut StationProgress<'a>,
    (check, tokens): (&Slotted<'a>, Option<&[Token<'_>]>),
    out: &mut Evaluation,
) {
    let seq = check.item.seq;
    let taken = match tokens {
        Some(tokens) => eval
            .record_check(
                &Signed {
                    event: &check.item.event,
                    tokens,
                },
                shared.roster(check.item.state),
                check.slot,
            )
            .map_err(ProgressReason::State),
        None => Err(ProgressReason::Signature),
    };
    match taken {
        Ok(()) => out.checks.push(seq),
        Err(reason) => out.check_refusals.push(ProgressRefusal { seq, reason }),
    }
}

/// Closes the station's slots one by one from `start` to its last usable
/// tick: suspensions first, then the slot's counts, then the slot's close,
/// then the checks recorded in it.
fn evaluate<'a>(
    shared: &Shared<'_, 'a>,
    eval: &mut StationProgress<'a>,
    start: u64,
    streams: Streams<'a>,
    checks: &[(&Slotted<'a>, Option<&[Token<'_>]>)],
) -> Evaluation {
    let mut out = Evaluation::default();
    let Streams {
        mut boxes,
        mut checkins,
        mut suspensions,
    } = streams;
    boxes.sort_by_key(|u| (u.0, u.1.get()));
    checkins.sort_by_key(|u| (u.0, u.1.get()));
    suspensions.sort_unstable();
    let mut checks = checks.to_vec();
    checks.sort_by_key(|(c, _)| (c.slot, c.item.seq.get()));
    let last = boxes
        .iter()
        .map(|u| u.0)
        .chain(checkins.iter().map(|u| u.0))
        .max();
    let mut boxes = boxes.into_iter().peekable();
    let mut checkins = checkins.into_iter().peekable();
    let mut suspensions = suspensions.into_iter().peekable();
    let mut checks = checks.into_iter().peekable();
    // Every usable slot is at least `start` and at most
    // `start + MAX_PROGRESS_SLOTS`, so this loop is bounded.
    for slot in last.map(|last| start..=last).into_iter().flatten() {
        while suspensions.next_if(|s| *s <= slot).is_some() {
            eval.suspend();
        }
        while let Some((_, seq, body)) = boxes.next_if(|u| u.0 == slot) {
            if let Err(e) = eval.record_box(&body) {
                out.refusals.push(ProgressRefusal {
                    seq,
                    reason: ProgressReason::State(e),
                });
            }
        }
        while let Some((_, seq, body)) = checkins.next_if(|u| u.0 == slot) {
            if let Err(e) = eval.record_checkin(&body) {
                out.refusals.push(ProgressRefusal {
                    seq,
                    reason: ProgressReason::State(e),
                });
            }
        }
        let Ok(closed) = eval.close_slot(slot) else {
            out.failed = true;
            break;
        };
        out.alarms.extend(
            ALARMS
                .iter()
                .filter(|a| closed.raised.contains(**a))
                .map(|a| RaisedAlarm { slot, alarm: *a }),
        );
        out.last_slot = Some(slot);
        while let Some(check) = checks.next_if(|(c, _)| c.slot <= slot) {
            apply_check(shared, eval, check, &mut out);
        }
    }
    for check in checks {
        apply_check(shared, eval, check, &mut out);
    }
    for _ in suspensions {
        eval.suspend();
    }
    out
}

// ---------------------------------------------------------------------------
// One station.

/// The check-in stream's comparison at close: what it found, and the
/// refusals of the counts it needs.
fn checkin_close(
    shared: &Shared<'_, '_>,
    stream: Option<&CheckinStream<'_>>,
    items: &StationItems<'_>,
    tokens: &StationTokens<'_>,
    refusals: &mut Vec<ProgressRefusal>,
) -> (CloseCheck, HoldSet) {
    let observers = with_tokens(
        items.observers.as_ref(),
        tokens.observers.as_deref(),
        refusals,
    );
    let issuance = with_tokens(
        items.issuance.as_ref(),
        tokens.issuance.as_deref(),
        refusals,
    );
    let observers = observers.and_then(|(item, tokens)| {
        let signed = Signed {
            event: &item.event,
            tokens,
        };
        ObserverCount::check(&signed, shared.roster(item.state))
            .map_err(|e| {
                refusals.push(ProgressRefusal {
                    seq: item.seq,
                    reason: ProgressReason::State(e),
                });
            })
            .ok()
    });
    let issuance = issuance.and_then(|(item, tokens)| {
        let signed = Signed {
            event: &item.event,
            tokens,
        };
        IssuanceCount::check(&signed, shared.roster(item.state))
            .map_err(|e| {
                refusals.push(ProgressRefusal {
                    seq: item.seq,
                    reason: ProgressReason::State(e),
                });
            })
            .ok()
            .map(|count| (item.seq, count))
    });
    let missing = (
        CloseCheck::Missing,
        stream
            .map_or(HoldSet::empty(), CheckinStream::holds)
            .with(HoldReason::ProgressStream),
    );
    match (stream, observers, issuance) {
        (Some(stream), Some(observers), Some((seq, issuance))) => {
            match stream.finish(&issuance, &observers) {
                Ok(holds) => (CloseCheck::Compared, holds),
                Err(e) => {
                    refusals.push(ProgressRefusal {
                        seq,
                        reason: ProgressReason::State(e),
                    });
                    missing
                }
            }
        }
        _ => missing,
    }
}

/// `item` with its tokens; a signature that does not verify is refused.
fn with_tokens<'r, 'a, 't>(
    item: Option<&'r Witnessed<'a>>,
    tokens: Option<&'r [Token<'t>]>,
    refusals: &mut Vec<ProgressRefusal>,
) -> Option<(&'r Witnessed<'a>, &'r [Token<'t>])> {
    let item = item?;
    if tokens.is_none() {
        refusals.push(ProgressRefusal {
            seq: item.seq,
            reason: ProgressReason::Signature,
        });
    }
    Some(item).zip(tokens)
}

/// The evaluator and check-in stream of a station that opened at frame
/// `opened`, from the entries of the genesis state in force there.
fn station_start<'a>(
    shared: &Shared<'_, 'a>,
    id: StationId<'a>,
    opened: Seq,
    first: Option<u64>,
) -> (
    Result<StationProgress<'a>, Error>,
    Result<CheckinStream<'a>, Error>,
) {
    let state = shared.index.state_at(opened);
    let genesis = shared.genesis.genesis_at(state);
    let station = shared.genesis.station_entry_at(state, id.as_bytes());
    let policy = shared.genesis.policy_entry_at(state, id.as_bytes());
    let eval = genesis
        .zip(station.as_ref())
        .zip(policy.as_ref())
        .ok_or(Error::StaleEntry)
        .and_then(|((g, s), p)| StationProgress::new(g, s, p));
    let stream = genesis
        .zip(station.as_ref())
        .zip(first)
        .ok_or(Error::StaleEntry)
        .and_then(|((g, s), first)| CheckinStream::open(g, s, first));
    (eval, stream)
}

#[allow(clippy::too_many_lines)] // The station's steps in order: openings, streams, alarms, close.
fn run_station<'a>(
    shared: &Shared<'_, 'a>,
    items: &StationItems<'a>,
) -> (StationProgressReport<'a>, Vec<BoxProgressReport<'a>>) {
    let tokens = items.tokens();
    let id = items.station_id;
    // The station opens with its first accepted `BoxOpened` by frame.
    let opening = items
        .boxes
        .iter()
        .filter_map(|b| b.opened)
        .min_by_key(|(seq, _)| seq.get());
    let box_firsts: Vec<Option<u64>> = items
        .boxes
        .iter()
        .zip(&tokens.boxes)
        .map(|(b, t)| {
            b.opened
                .and_then(|(_, bucket)| first_slot(bucket, verified(&b.ticks, &t.ticks)))
        })
        .collect();
    let checkin_first =
        opening.and_then(|(_, bucket)| first_slot(bucket, verified(&items.ticks, &tokens.ticks)));
    let start = box_firsts
        .iter()
        .chain(core::iter::once(&checkin_first))
        .flatten()
        .min()
        .copied();
    let horizon = start.map_or(0, |s| s.saturating_add(MAX_PROGRESS_SLOTS));

    let mut box_reports = Vec::new();
    let mut streams = Streams {
        boxes: Vec::new(),
        checkins: Vec::new(),
        suspensions: Vec::new(),
    };
    for ((b, t), first) in items.boxes.iter().zip(&tokens.boxes).zip(&box_firsts) {
        let run = run_box(shared, id, b, t, *first, horizon);
        box_reports.push(run.report);
        streams.boxes.extend(run.usable);
        streams.suspensions.extend(run.suspensions);
    }

    let (eval, stream) = match opening {
        Some((seq, _)) => {
            let (eval, stream) = station_start(shared, id, seq, checkin_first);
            (Some(eval), Some(stream))
        }
        None => (None, None),
    };
    let (pass, stream) = match stream {
        Some(Ok(mut stream)) => {
            let pass = run_stream(
                shared,
                &mut stream,
                &items.ticks,
                &tokens.ticks,
                &items.swaps,
                &tokens.swaps,
                horizon,
            );
            (pass, Some(stream))
        }
        Some(Err(e)) => (
            Pass::refused(&items.ticks, &items.swaps, ProgressReason::State(e)),
            None,
        ),
        None => (
            Pass::refused(&items.ticks, &items.swaps, ProgressReason::NotOpened),
            None,
        ),
    };
    let checkin_ticks = pass.usable.len();
    streams.checkins = pass.usable;
    streams.suspensions.extend(pass.swapped);
    let mut refusals = pass.refusals;
    refusals.extend(items.refused.iter().copied());

    let checks: Vec<(&Slotted<'a>, Option<&[Token<'_>]>)> = items
        .checks
        .iter()
        .zip(&tokens.checks)
        .map(|(c, t)| (c, t.as_deref()))
        .collect();
    let (evaluation, eval) = match (eval, start) {
        (Some(Ok(mut eval)), Some(start)) => {
            let evaluation = evaluate(shared, &mut eval, start, streams, &checks);
            // A slot that could not be closed (not reachable: the slots run
            // in order within the bound) leaves the station unevaluated.
            let eval = (!evaluation.failed).then_some(eval);
            (evaluation, eval)
        }
        (eval, _) => {
            // The station never opened; or (not reachable: its entries are
            // proved against the state they are used in) its evaluator
            // could not start, which leaves it unevaluated.
            let reason = eval
                .and_then(Result::err)
                .map_or(ProgressReason::NotOpened, ProgressReason::State);
            let evaluation = Evaluation {
                check_refusals: refused_checks(&checks, reason),
                ..Evaluation::default()
            };
            (evaluation, None)
        }
    };
    let unevaluated = opening.is_some() && eval.is_none();
    refusals.extend(evaluation.refusals.iter().copied());

    // Close: the station is closed when every box of it is.
    let closed = items.boxes.iter().all(|b| b.closed);
    let (close, checkin_holds) = if closed {
        checkin_close(shared, stream.as_ref(), items, &tokens, &mut refusals)
    } else {
        (
            CloseCheck::Open,
            stream
                .as_ref()
                .map_or(HoldSet::empty(), CheckinStream::holds),
        )
    };
    let eval_holds = eval.as_ref().map_or(HoldSet::empty(), |e| {
        if closed { e.finish() } else { e.holds() }
    });
    let mut check_refusals = evaluation.check_refusals;
    check_refusals.extend(items.refused_checks.iter().copied());
    let holds = checkin_holds
        .union(eval_holds)
        .with_if(!refusals.is_empty(), HoldReason::ProgressStream)
        .with_if(
            !check_refusals.is_empty() || unevaluated,
            HoldReason::ProgressUnresolved,
        );
    refusals.extend(check_refusals);
    refusals.sort_by_key(|r| r.seq.get());
    let report = StationProgressReport {
        station_id: id,
        first_slot: eval.as_ref().and(start),
        last_slot: evaluation.last_slot,
        ticks: checkin_ticks,
        alarms: evaluation.alarms,
        checks: evaluation.checks,
        suspended: eval.as_ref().is_some_and(StationProgress::suspended),
        counterfoil: eval
            .as_ref()
            .is_some_and(StationProgress::counterfoil_required),
        close,
        holds,
        refusals,
    };
    (report, box_reports)
}

fn refused_checks(
    checks: &[(&Slotted<'_>, Option<&[Token<'_>]>)],
    reason: ProgressReason,
) -> Vec<ProgressRefusal> {
    checks
        .iter()
        .map(|(c, _)| ProgressRefusal {
            seq: c.item.seq,
            reason,
        })
        .collect()
}

/// The progress events of stations an amendment removed: each is refused
/// and its station held.
fn removed_stations<'a>(
    genesis: &VerifiedGenesis<'a>,
    index: &LedgerIndex<'a>,
) -> Vec<StationProgressReport<'a>> {
    let mut found: BTreeMap<&'a [u8], (StationId<'a>, Vec<ProgressRefusal>)> = BTreeMap::new();
    for e in index.events() {
        let Scope::Station(s) = e.scope else {
            continue;
        };
        if genesis.station(s.as_bytes()).is_some() || !is_progress(e) {
            continue;
        }
        found
            .entry(s.as_bytes())
            .or_insert((s, Vec::new()))
            .1
            .push(ProgressRefusal {
                seq: e.seq,
                reason: ProgressReason::Unexpected,
            });
    }
    found
        .into_values()
        .map(|(station_id, refusals)| StationProgressReport {
            station_id,
            first_slot: None,
            last_slot: None,
            ticks: 0,
            alarms: Vec::new(),
            checks: Vec::new(),
            suspended: false,
            counterfoil: false,
            close: CloseCheck::Open,
            holds: HoldSet::empty().with(HoldReason::ProgressStream),
            refusals,
        })
        .collect()
}

/// Whether a station event belongs to the progress record: a check-in
/// tick, a check or a check-in unit swap.
fn is_progress(e: &IndexedEvent<'_>) -> bool {
    if e.schema == SCHEMA_PROGRESS_TICK {
        return true;
    }
    e.schema == SCHEMA_WITNESSED_EVENT
        && e.bytes
            .and_then(|b| decode::<WitnessedEvent<'_>>(e.schema, b))
            .is_some_and(|w| {
                let body = w.body_schema();
                body == SCHEMA_PROGRESS_CHECK_BODY || body == SCHEMA_CHECKIN_UNIT_SWAP_BODY
            })
}

/// Runs the progress record of every station of the genesis's last state
/// through `ityv-state`'s evaluators, with the box stage's openings,
/// fallbacks, swaps and closes.
#[must_use]
pub fn verify_progress<'a>(
    genesis: &VerifiedGenesis<'a>,
    index: &LedgerIndex<'a>,
    boxes: &BoxStage<'a>,
) -> ProgressStage<'a> {
    let rosters: Vec<Vec<RosterEntry<'a>>> = (0..genesis.state_count())
        .map(|k| genesis.roster_at(k))
        .collect();
    let keys: Vec<Keys<'a>> = rosters
        .iter()
        .map(|roster| {
            roster
                .iter()
                .map(|r| (r.get().signer_id.as_bytes(), r.get().key))
                .collect()
        })
        .collect();
    let shared = Shared {
        genesis,
        index,
        boxes,
        rosters: &rosters,
        keys: &keys,
    };
    let mut stations = Vec::new();
    let mut box_reports = Vec::new();
    for station in genesis.stations() {
        let items = station_items(&shared, station);
        let (report, reports) = run_station(&shared, &items);
        stations.push(report);
        box_reports.extend(reports);
    }
    stations.extend(removed_stations(genesis, index));
    ProgressStage {
        stations,
        boxes: box_reports,
    }
}
