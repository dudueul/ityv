//! The box stage (PROTOCOL.md §14 4; VC-037..040, VC-100).
//!
//! For every box the genesis expects, [`verify_boxes`] drives
//! `ityv_state`'s ballot-box state machine with the box's events from the
//! [`LedgerIndex`], in frame order:
//!
//! * a `BoxOpened` provisions the box under a `PUBLIC_BOARD` capability and
//!   opens it (device, two clerks and observers of two organisations);
//! * cast records (under a `BALLOT_MARK` capability), challenge openings
//!   and batch attestations count into the open box; `FallbackDeclared`
//!   and `FallbackEnded` move it in and out of the fallback state;
//! * a `BoxClose` closes the open box (purpose `box-close`, with the
//!   station's last `IssuanceCount` before it for an out-of-district box);
//!   one that comes after the box closed is a late close (purpose
//!   `late-box-close`), so a refused close leaves the box open for the next;
//! * after the close: a batch attestation and the `LateBatchClose` naming
//!   its body hash form a late batch close (a `LateBatchClose` while the
//!   box is open is out of order); seal changes and custody handoffs
//!   extend the custody chain; an `ImprintAudit` counts the box.
//!
//! A record, challenge opening or batch body counts once per box: the same
//! body under other signature bytes is another ledger object, but not
//! another ballot or batch. A box the genesis's last state does not expect
//! (an amendment removed it) is not run: each of its events is refused
//! and the box is held.
//!
//! Amendments (PROTOCOL.md §4.3) apply from the frame that carries them
//! ([`LedgerIndex::state_at`]). Each event is checked under the genesis
//! state in force at its frame: its signers' keys are that state's roster
//! keys and the box's device key in that state, and before the event the
//! machine follows that state (`BallotBox::follow`) when it is a later
//! one. An event of a state without the box is refused. A device swap
//! must be witnessed: when the state in force gives an open box (or one in
//! fallback) a new device key or a new frame key (its transmitter replaced
//! alone, ADR-0041 decision 2), a device-signed close is refused until a
//! `BoxUnitSwap` (two clerks, observers of two organisations) records the
//! swap on site, and a swap is taken only for an open box whose device key
//! or frame key an amendment changed. A transmitter taken out is not put
//! back: a swap into a state that gives the box a frame key an amendment
//! already took from it is refused (the device's close is still taken). A replaced device's own events after the
//! amendment's frame do not verify under the new key and are refused.
//!
//! Every signature is verified here, under the key the genesis registers
//! for the signer (the box's device key for the device), into a token that
//! `ityv-state` binds to the signer, role, organisation, purpose and bytes.
//! Capabilities are granted for the day of the box's opening (records carry
//! no time, VC-001).
//!
//! Each box ends with its phase, its holds and the events its machine
//! refused. A refused event leaves [`HoldReason::BoxEventRefused`]; a box
//! that never closed leaves [`HoldReason::CloseMissing`] (completeness:
//! every expected box has its close). The machine's own holds (the close
//! invariants of VC-038, the custody chain of VC-040, the open-batch and
//! manual-close holds and their resolution by late closes, VC-100) and the
//! index's holds on the box, its station and the ledger are added.
//!
//! What this stage does not prove: that a cast record's signatures and
//! proof are valid, that its batch attestation covers it (the record
//! stage, which also takes a replaced device's records uploaded late);
//! that the box's counts agree with the station's progress record, or
//! that the swap's slot and count continue the progress stream (the
//! progress stage).

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use ityv_crypto::hash::object_hash;
use ityv_crypto::{HybridSigned, Purpose, Verified};
use ityv_encoding::schema_version;
use ityv_encoding::{
    BatchAttest, BoxClose, BoxId, BoxOpenedBody, CaptureProfile, CastRecord, ChallengeOpening,
    CloseCounts, Decode, EventRole, FRAME_KEY_LEN, FallbackBody, FallbackKind, GenesisBox,
    HYBRID_SIG_LEN, HYBRID_VK_LEN, LateBatchCloseBody, SCHEMA_BATCH_ATTEST, SCHEMA_BOX_CLOSE,
    SCHEMA_BOX_OPENED_BODY, SCHEMA_BOX_UNIT_SWAP_BODY, SCHEMA_CAST_RECORD,
    SCHEMA_CHALLENGE_OPENING, SCHEMA_CUSTODY_HANDOFF_BODY, SCHEMA_FALLBACK_BODY,
    SCHEMA_IMPRINT_AUDIT_BODY, SCHEMA_ISSUANCE_COUNT_BODY, SCHEMA_LATE_BATCH_CLOSE_BODY,
    SCHEMA_SEAL_CHANGE_BODY, SCHEMA_WITNESSED_EVENT, SchemaId, Seq, WitnessedEvent, decode_object,
};
use ityv_state::{
    BallotBox, BallotMark, BoxSpec, BoxUnitSwap, Cap, CloseTokens, Closed, Counted, Fallback,
    HoldReason, HoldSet, Open, PURPOSE_BOX_CLOSE, PURPOSE_LATE_BOX_CLOSE, Provisioned, PublicBoard,
    RosterEntry, Signed, Transition,
};

use crate::authority::{AuthorityStage, day_of};
use crate::genesis::VerifiedGenesis;
use crate::index::{IndexedEvent, LedgerIndex};
use crate::sigs::Material;

/// How far a box got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Phase {
    /// Provisioned in the genesis; never opened.
    Provisioned,
    /// Open.
    Open,
    /// Open, in the fallback state.
    Fallback,
    /// Closed.
    Closed,
    /// Counted (`ImprintAudit`).
    Counted,
}

/// Why the box stage refused an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// The state machine refused it.
    State(ityv_state::Error),
    /// A signer is not on the roster, or a signature does not verify under
    /// the registered key.
    Signature,
    /// The box was not in a state that takes this event.
    OutOfOrder,
    /// No legal authorization grants the capability the event needs on the
    /// day of the box's opening.
    Capability,
    /// A batch attestation after the close without its `LateBatchClose`,
    /// or the reverse.
    Unmatched,
    /// A cast record, challenge opening or batch attestation whose body an
    /// earlier event of the box already carries (the same body under other
    /// signature bytes is a different ledger object).
    Duplicate,
    /// An event of a box the genesis state in force at its frame (or the
    /// last state) does not have.
    Unexpected,
}

/// One refused event of a box.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoxRefusal {
    /// The frame that carries it.
    pub seq: Seq,
    /// Why.
    pub refusal: Refusal,
}

/// What the box stage concluded about one box.
#[derive(Debug, Clone)]
pub struct BoxReport<'a> {
    /// The box.
    pub box_id: BoxId<'a>,
    /// How far it got.
    pub phase: Phase,
    /// Every hold on it: its machine's, the stage's and the index's (box,
    /// station and ledger).
    pub holds: HoldSet,
    /// The counts of its close, once closed.
    pub counts: Option<CloseCounts>,
    /// The events its machine refused, in frame order.
    pub refusals: Vec<BoxRefusal>,
}

/// The box stage over every expected box.
#[derive(Debug, Clone)]
pub struct BoxStage<'a> {
    reports: Vec<BoxReport<'a>>,
}

impl<'a> BoxStage<'a> {
    /// One report per expected box, in box order, then one per box with
    /// events that the genesis's last state does not expect.
    #[must_use]
    pub fn reports(&self) -> &[BoxReport<'a>] {
        &self.reports
    }

    /// The report of box `box_id`.
    #[must_use]
    pub fn report(&self, box_id: &[u8]) -> Option<&BoxReport<'a>> {
        self.reports.iter().find(|r| r.box_id.as_bytes() == box_id)
    }

    /// Whether every expected box has its close (§14 4, completeness).
    #[must_use]
    pub fn complete(&self) -> bool {
        self.reports
            .iter()
            .all(|r| !r.holds.contains(HoldReason::CloseMissing))
    }
}

/// The tokens of one signed object, in signature order (`None` when a key
/// is missing or a signature does not verify).
type Tokens<'t> = Option<Vec<Verified<HybridSigned<'t>>>>;

/// The registered key of each roster signer, by identifier.
type Keys<'a> = BTreeMap<&'a [u8], &'a [u8; HYBRID_VK_LEN]>;

/// A witnessed event, decoded, with the material its tokens need.
struct WitnessedItem<'a> {
    event: WitnessedEvent<'a>,
    purpose: Purpose<'static>,
    material: Option<Material>,
}

impl<'a> WitnessedItem<'a> {
    /// Each signature with its signer's registered key: the roster's, or
    /// `device` for the device (`None` when the event has no device).
    fn new(
        event: &WitnessedEvent<'a>,
        keys: &Keys<'_>,
        device: Option<&[u8; HYBRID_VK_LEN]>,
    ) -> Option<Self> {
        let event = *event;
        let purpose = Purpose::new(event.purpose())?;
        let pairs: Option<Vec<(&[u8; HYBRID_SIG_LEN], &[u8; HYBRID_VK_LEN])>> = event
            .sigs()
            .map(|s| {
                let key = if s.role == EventRole::Device {
                    device
                } else {
                    keys.get(s.signer_id.as_bytes()).copied()
                };
                key.map(|k| (s.sig, k))
            })
            .collect();
        let material = pairs.and_then(|p| Material::new(p.into_iter()));
        Some(Self {
            event,
            purpose,
            material,
        })
    }

    fn tokens(&self) -> Tokens<'_> {
        self.material
            .as_ref()?
            .verify(&self.purpose, self.event.body_bytes())
    }
}

/// A close, decoded, with the material its tokens need. Whether it closes
/// the box (purpose `box-close`) or is a late close (`late-box-close`)
/// depends on the state the box is in when it comes, so both sets of
/// tokens are made in advance.
struct CloseItem<'a> {
    close: BoxClose<'a>,
    first: Purpose<'static>,
    late: Purpose<'static>,
    material: Option<Material>,
    /// For an out-of-district box: the station's last `IssuanceCount`
    /// before the close.
    issuance: Option<WitnessedItem<'a>>,
}

impl CloseItem<'_> {
    fn tokens<'t>(&'t self, purpose: &'t Purpose<'t>) -> Tokens<'t> {
        self.material
            .as_ref()?
            .verify(purpose, self.close.body_bytes())
    }
}

/// An event of a box, decoded.
enum Item<'a> {
    Witnessed(Box<WitnessedItem<'a>>),
    Close(Box<CloseItem<'a>>),
    Record(Box<CastRecord<'a>>),
    Challenge(Box<ChallengeOpening<'a>>),
    Batch(Box<BatchAttest<'a>>),
    /// An event of a genesis state that does not have the box.
    Absent,
    /// An event of another stage.
    Skip,
}

/// The tokens of one item.
#[derive(Default)]
struct ItemTokens<'t> {
    /// A witnessed event's, or a close's under `box-close`.
    first: Tokens<'t>,
    /// A close's under `late-box-close`.
    late: Tokens<'t>,
    /// A close's issuance count's.
    issuance: Tokens<'t>,
}

impl Item<'_> {
    fn tokens(&self) -> ItemTokens<'_> {
        match self {
            Self::Witnessed(w) => ItemTokens {
                first: w.tokens(),
                ..ItemTokens::default()
            },
            Self::Close(c) => ItemTokens {
                first: c.tokens(&c.first),
                late: c.tokens(&c.late),
                issuance: c.issuance.as_ref().and_then(WitnessedItem::tokens),
            },
            Self::Record(_) | Self::Challenge(_) | Self::Batch(_) | Self::Absent | Self::Skip => {
                ItemTokens::default()
            }
        }
    }
}

/// The body schemas of the witnessed events this stage runs.
const BOX_BODY_SCHEMAS: [SchemaId; 7] = [
    SCHEMA_BOX_OPENED_BODY,
    SCHEMA_BOX_UNIT_SWAP_BODY,
    SCHEMA_FALLBACK_BODY,
    SCHEMA_LATE_BATCH_CLOSE_BODY,
    SCHEMA_SEAL_CHANGE_BODY,
    SCHEMA_CUSTODY_HANDOFF_BODY,
    SCHEMA_IMPRINT_AUDIT_BODY,
];

fn decode<'a, T: Decode<'a>>(schema: SchemaId, bytes: &'a [u8]) -> Option<T> {
    decode_object(schema, schema_version(schema), bytes).ok()
}

/// What preparing a box's events needs.
struct Prep<'x, 'a> {
    genesis: &'x VerifiedGenesis<'a>,
    index: &'x LedgerIndex<'a>,
    /// The roster keys of each genesis state.
    keys: &'x [Keys<'a>],
    box_id: BoxId<'a>,
}

impl<'a> Prep<'_, 'a> {
    /// Decodes one indexed event of the box under the genesis state in
    /// force at its frame ([`LedgerIndex::state_at`]), which it returns
    /// with the item.
    fn item(&self, event: &IndexedEvent<'a>) -> (usize, Item<'a>) {
        let state = self.index.state_at(event.seq);
        let found = self
            .genesis
            .expected_box_at(state, self.box_id.as_bytes())
            .zip(self.keys.get(state));
        let item = match found {
            Some((entry, keys)) => self.decode(event, entry, keys),
            None => Item::Absent,
        };
        (state, item)
    }

    /// Decodes one event with the box's entry and the roster keys of its
    /// state.
    fn decode(
        &self,
        event: &IndexedEvent<'a>,
        entry: &GenesisBox<'a>,
        keys: &Keys<'a>,
    ) -> Item<'a> {
        let Some(bytes) = event.bytes else {
            return Item::Skip;
        };
        let schema = event.schema;
        let device = Some(entry.device_key);
        let item = if schema == SCHEMA_WITNESSED_EVENT {
            decode::<WitnessedEvent<'a>>(schema, bytes).and_then(|w| {
                let body = w.body_schema();
                if BOX_BODY_SCHEMAS.contains(&body) {
                    WitnessedItem::new(&w, keys, device).map(|w| Item::Witnessed(Box::new(w)))
                } else {
                    // Disputes and other events of the box belong to other
                    // stages.
                    None
                }
            })
        } else if schema == SCHEMA_BOX_CLOSE {
            decode::<BoxClose<'a>>(schema, bytes).and_then(|close| {
                let pairs: Option<Vec<(&[u8; HYBRID_SIG_LEN], &[u8; HYBRID_VK_LEN])>> = close
                    .device_sig()
                    .map(|sig| Some((sig, entry.device_key)))
                    .into_iter()
                    .chain(
                        close
                            .attestations()
                            .map(|a| keys.get(a.signer_id.as_bytes()).map(|k| (a.sig, *k))),
                    )
                    .collect();
                Some(Item::Close(Box::new(CloseItem {
                    close,
                    first: Purpose::new(PURPOSE_BOX_CLOSE)?,
                    late: Purpose::new(PURPOSE_LATE_BOX_CLOSE)?,
                    material: pairs.and_then(|p| Material::new(p.into_iter())),
                    issuance: self.issuance(entry, event.seq),
                })))
            })
        } else if schema == SCHEMA_CAST_RECORD {
            decode(schema, bytes).map(|r| Item::Record(Box::new(r)))
        } else if schema == SCHEMA_CHALLENGE_OPENING {
            decode(schema, bytes).map(|c| Item::Challenge(Box::new(c)))
        } else if schema == SCHEMA_BATCH_ATTEST {
            decode(schema, bytes).map(|b| Item::Batch(Box::new(b)))
        } else {
            // Scan counts, progress ticks and device attestations belong to
            // other stages.
            None
        };
        item.unwrap_or(Item::Skip)
    }

    /// For an out-of-district box, the station's last `IssuanceCount`
    /// before frame `before` (it has no device signature), with the roster
    /// keys of the state in force at its own frame.
    fn issuance(&self, entry: &GenesisBox<'a>, before: Seq) -> Option<WitnessedItem<'a>> {
        if entry.profile != CaptureProfile::Absentee {
            return None;
        }
        let mut last = None;
        for e in self.index.station_events(entry.station_id.as_bytes()) {
            if e.seq.get() >= before.get() {
                break;
            }
            if e.schema != SCHEMA_WITNESSED_EVENT {
                continue;
            }
            if let Some(w) = e
                .bytes
                .and_then(|b| decode::<WitnessedEvent<'a>>(SCHEMA_WITNESSED_EVENT, b))
                .filter(|w| w.body_schema() == SCHEMA_ISSUANCE_COUNT_BODY)
            {
                last = Some((e.seq, w));
            }
        }
        let (seq, w) = last?;
        WitnessedItem::new(&w, self.keys.get(self.index.state_at(seq))?, None)
    }
}

/// A box's state machine in whatever state it is in.
enum Machine<'r> {
    Spec(BoxSpec<'r>),
    Provisioned(BallotBox<'r, Provisioned>),
    Open(BallotBox<'r, Open>),
    Fallback(BallotBox<'r, Fallback>),
    Closed(BallotBox<'r, Closed<'r>>),
    Counted(BallotBox<'r, Counted<'r>>),
}

impl<'r> Machine<'r> {
    fn phase(&self) -> Phase {
        match self {
            Self::Spec(_) | Self::Provisioned(_) => Phase::Provisioned,
            Self::Open(_) => Phase::Open,
            Self::Fallback(_) => Phase::Fallback,
            Self::Closed(_) => Phase::Closed,
            Self::Counted(_) => Phase::Counted,
        }
    }

    fn holds(&self) -> HoldSet {
        match self {
            Self::Spec(_) => HoldSet::empty(),
            Self::Provisioned(b) => b.holds(),
            Self::Open(b) => b.holds(),
            Self::Fallback(b) => b.holds(),
            Self::Closed(b) => b.holds(),
            Self::Counted(b) => b.holds(),
        }
    }

    fn counts(&self) -> Option<CloseCounts> {
        match self {
            Self::Closed(b) => Some(*b.counts()),
            Self::Counted(b) => Some(*b.counts()),
            Self::Spec(_) | Self::Provisioned(_) | Self::Open(_) | Self::Fallback(_) => None,
        }
    }

    /// The spec the machine uses.
    fn spec(&self) -> &BoxSpec<'r> {
        match self {
            Self::Spec(spec) => spec,
            Self::Provisioned(b) => b.spec(),
            Self::Open(b) => b.spec(),
            Self::Fallback(b) => b.spec(),
            Self::Closed(b) => b.spec(),
            Self::Counted(b) => b.spec(),
        }
    }

    /// Follows `spec`, built from a later genesis state.
    fn follow(self, spec: &BoxSpec<'r>) -> Step<'r> {
        match self {
            Self::Spec(_) => (Self::Spec(*spec), None),
            Self::Provisioned(mut b) => {
                let r = b.follow(spec);
                kept(Self::Provisioned(b), r)
            }
            Self::Open(mut b) => {
                let r = b.follow(spec);
                kept(Self::Open(b), r)
            }
            Self::Fallback(mut b) => {
                let r = b.follow(spec);
                kept(Self::Fallback(b), r)
            }
            Self::Closed(mut b) => {
                let r = b.follow(spec);
                kept(Self::Closed(b), r)
            }
            Self::Counted(mut b) => {
                let r = b.follow(spec);
                kept(Self::Counted(b), r)
            }
        }
    }
}

/// A machine after one step, and why the step was refused, if it was.
type Step<'r> = (Machine<'r>, Option<Refusal>);

/// Folds a transition into the machine and the refusal.
fn settle<'r, A, B>(
    t: Transition<A, B>,
    keep: fn(A) -> Machine<'r>,
    next: fn(B) -> Machine<'r>,
) -> Step<'r> {
    match t {
        Transition::Done(b) => (next(b), None),
        Transition::Refused(a, e) => (keep(a), Some(Refusal::State(e))),
    }
}

/// Keeps the machine as it is and reports `result`'s error.
fn kept(m: Machine<'_>, result: Result<impl Sized, ityv_state::Error>) -> Step<'_> {
    (m, result.err().map(Refusal::State))
}

/// A close's tokens split into the device's (when it signed) and the
/// attesters'.
fn close_tokens<'t>(
    close: &BoxClose<'_>,
    tokens: &'t [Verified<HybridSigned<'t>>],
) -> Option<CloseTokens<'t>> {
    if close.device_sig().is_some() {
        let (device, humans) = tokens.split_first()?;
        Some(CloseTokens {
            device: Some(device),
            humans,
        })
    } else {
        Some(CloseTokens {
            device: None,
            humans: tokens,
        })
    }
}

/// The run of one box.
struct Run<'r, 'g> {
    genesis: &'g VerifiedGenesis<'g>,
    authority: &'g AuthorityStage<'g>,
    ballot_mark: Option<Cap<'g, BallotMark>>,
    /// Post-close batch attestations and late batch closes waiting for
    /// their partner.
    batches: Vec<(Seq, &'r BatchAttest<'r>)>,
    lates: Vec<(Seq, Signed<'r>)>,
    /// The object hashes of the record, challenge and batch bodies seen.
    bodies: BTreeSet<[u8; 64]>,
    /// The record hashes the box's challenge openings name: the records of
    /// challenged ballots, which the device publishes but does not count
    /// as cast (§8).
    challenged: BTreeSet<[u8; 64]>,
    refusals: Vec<BoxRefusal>,
    /// The box's spec in each genesis state (`None` where a state does not
    /// have the box).
    specs: Vec<Option<BoxSpec<'r>>>,
    /// The box's frame key (its transmitter's, ADR-0041 decision 2) in each
    /// genesis state.
    frame_keys: Vec<Option<&'g [u8; FRAME_KEY_LEN]>>,
    /// The genesis state the machine follows.
    state: usize,
    /// An amendment gave the open box a new device key or a new frame key
    /// (a transmitter replaced alone) and no `BoxUnitSwap` has recorded the
    /// swap yet.
    swap_due: bool,
    /// The frame keys amendments took from the box: a transmitter taken
    /// out is not put back, a replacement is always a fresh spare
    /// (ADR-0041 decision 2).
    retired: Vec<&'g [u8; FRAME_KEY_LEN]>,
}

impl<'r> Run<'r, '_> {
    fn refuse(&mut self, seq: Seq, refusal: Refusal) {
        self.refusals.push(BoxRefusal { seq, refusal });
    }

    /// Moves the machine to `state`, the genesis state in force at the
    /// next event; refuses the event if that state does not have the box.
    fn advance(&mut self, m: Machine<'r>, state: usize) -> Step<'r> {
        let Some(spec) = self.specs.get(state).copied().flatten() else {
            return (m, Some(Refusal::Unexpected));
        };
        if state <= self.state {
            return (m, None);
        }
        let open = matches!(m, Machine::Open(_) | Machine::Fallback(_));
        let frame_key = |k: usize| self.frame_keys.get(k).copied().flatten();
        let (before, after) = (frame_key(self.state), frame_key(state));
        let replaced = m.spec().device_key() != spec.device_key() || before != after;
        // Every key of the states passed over that the new state does not
        // keep (several amendments may lie between two of the box's events,
        // all before its opening for one).
        let gone: Vec<&[u8; FRAME_KEY_LEN]> = (self.state..state)
            .filter_map(frame_key)
            .filter(|k| Some(*k) != after)
            .collect();
        let (m, refusal) = m.follow(&spec);
        if refusal.is_none() {
            self.state = state;
            self.swap_due |= open && replaced;
            self.retired.extend(gone);
        }
        (m, refusal)
    }

    /// An on-site device swap, taken only when an amendment gave the open
    /// box a new device key or a new frame key. The index scoped the event
    /// to this box and election by its body. A swap into a state whose
    /// frame key an amendment already took from the box (a transmitter
    /// put back) is refused; the on-site record stands, so the device's
    /// close is taken.
    fn swap(&mut self, spec: &BoxSpec<'_>, signed: &Signed<'_>) -> Option<Refusal> {
        if !self.swap_due {
            return Some(Refusal::OutOfOrder);
        }
        match BoxUnitSwap::check(signed, spec.roster()) {
            Ok(_) => {
                self.swap_due = false;
                let key = self.frame_keys.get(self.state).copied().flatten();
                key.is_some_and(|k| self.retired.contains(&k))
                    .then_some(Refusal::OutOfOrder)
            }
            Err(e) => Some(Refusal::State(e)),
        }
    }

    /// Opens the box with a signed `BoxOpened`: a `PUBLIC_BOARD`
    /// capability for its day, provisioning (once), opening, and then a
    /// `BALLOT_MARK` capability for the same day for its records.
    fn open(&mut self, m: Machine<'r>, signed: &Signed<'r>) -> Step<'r> {
        let day = signed
            .event
            .body::<BoxOpenedBody<'_>>(SCHEMA_BOX_OPENED_BODY)
            .ok()
            .and_then(|b| day_of(self.genesis, b.parts().time_bucket));
        let auth = self.authority.authorization();
        let public = day
            .zip(auth)
            .and_then(|(d, a)| a.grant::<PublicBoard>(d).ok());
        let provisioned = match (m, public) {
            (Machine::Spec(spec), Some(public)) => match BallotBox::provision(&spec, &public) {
                Ok(b) => b,
                Err(e) => return (Machine::Spec(spec), Some(Refusal::State(e))),
            },
            (Machine::Provisioned(b), Some(_)) => b,
            (m @ (Machine::Spec(_) | Machine::Provisioned(_)), None) => {
                return (m, Some(Refusal::Capability));
            }
            (
                m @ (Machine::Open(_)
                | Machine::Fallback(_)
                | Machine::Closed(_)
                | Machine::Counted(_)),
                _,
            ) => return (m, Some(Refusal::OutOfOrder)),
        };
        let step = settle(
            provisioned.open(signed),
            Machine::Provisioned,
            Machine::Open,
        );
        if matches!(step.0, Machine::Open(_)) {
            self.ballot_mark = day
                .zip(auth)
                .and_then(|(d, a)| a.grant::<BallotMark>(d).ok());
        }
        step
    }

    /// A witnessed event of the box, by its body schema.
    fn witnessed(&mut self, m: Machine<'r>, seq: Seq, signed: Signed<'r>) -> Step<'r> {
        let schema = signed.event.body_schema();
        if schema == SCHEMA_BOX_OPENED_BODY {
            self.open(m, &signed)
        } else if schema == SCHEMA_FALLBACK_BODY {
            let kind = signed
                .event
                .body::<FallbackBody<'_>>(schema)
                .ok()
                .map(|b| b.parts().kind);
            match (m, kind) {
                (Machine::Open(b), Some(FallbackKind::Declared)) => settle(
                    b.declare_fallback(&signed),
                    Machine::Open,
                    Machine::Fallback,
                ),
                (Machine::Fallback(b), Some(FallbackKind::Ended)) => {
                    settle(b.end_fallback(&signed), Machine::Fallback, Machine::Open)
                }
                (m, _) => (m, Some(Refusal::OutOfOrder)),
            }
        } else if schema == SCHEMA_LATE_BATCH_CLOSE_BODY {
            // A late batch close is taken only after the box's close.
            if matches!(m, Machine::Closed(_) | Machine::Counted(_)) {
                self.lates.push((seq, signed));
                (self.match_late(m), None)
            } else {
                (m, Some(Refusal::OutOfOrder))
            }
        } else if schema == SCHEMA_BOX_UNIT_SWAP_BODY {
            match m {
                Machine::Open(b) => {
                    let r = self.swap(b.spec(), &signed);
                    (Machine::Open(b), r)
                }
                Machine::Fallback(b) => {
                    let r = self.swap(b.spec(), &signed);
                    (Machine::Fallback(b), r)
                }
                m @ (Machine::Spec(_)
                | Machine::Provisioned(_)
                | Machine::Closed(_)
                | Machine::Counted(_)) => (m, Some(Refusal::OutOfOrder)),
            }
        } else if schema == SCHEMA_SEAL_CHANGE_BODY {
            match m {
                Machine::Closed(mut b) => {
                    let r = b.seal_change(&signed);
                    kept(Machine::Closed(b), r)
                }
                m @ (Machine::Spec(_)
                | Machine::Provisioned(_)
                | Machine::Open(_)
                | Machine::Fallback(_)
                | Machine::Counted(_)) => (m, Some(Refusal::OutOfOrder)),
            }
        } else if schema == SCHEMA_CUSTODY_HANDOFF_BODY {
            match m {
                Machine::Closed(mut b) => {
                    let r = b.handoff(&signed);
                    kept(Machine::Closed(b), r)
                }
                m @ (Machine::Spec(_)
                | Machine::Provisioned(_)
                | Machine::Open(_)
                | Machine::Fallback(_)
                | Machine::Counted(_)) => (m, Some(Refusal::OutOfOrder)),
            }
        } else {
            // `prepare` keeps only the schemas above and the imprint audit.
            match m {
                Machine::Closed(b) => settle(b.count(&signed), Machine::Closed, Machine::Counted),
                m @ (Machine::Spec(_)
                | Machine::Provisioned(_)
                | Machine::Open(_)
                | Machine::Fallback(_)
                | Machine::Counted(_)) => (m, Some(Refusal::OutOfOrder)),
            }
        }
    }

    /// Pairs the waiting late batch closes with post-close batch
    /// attestations by the batch body hash, in frame order.
    fn match_late(&mut self, mut m: Machine<'r>) -> Machine<'r> {
        for (late_seq, late) in core::mem::take(&mut self.lates) {
            let wanted = late
                .event
                .body::<LateBatchCloseBody<'_>>(SCHEMA_LATE_BATCH_CLOSE_BODY)
                .ok()
                .map(|b| b.parts().batch_body_hash);
            let found = wanted.and_then(|h| {
                self.batches
                    .iter()
                    .position(|(_, batch)| object_hash(batch.body_bytes()) == h)
            });
            let Some(i) = found else {
                self.lates.push((late_seq, late));
                continue;
            };
            let (batch_seq, batch) = self.batches.remove(i);
            let r = match &mut m {
                Machine::Closed(b) => b.late_batch(batch, &late),
                Machine::Counted(b) => b.late_batch(batch, &late),
                Machine::Spec(_)
                | Machine::Provisioned(_)
                | Machine::Open(_)
                | Machine::Fallback(_) => Err(ityv_state::Error::LateClose),
            };
            if let Err(e) = r {
                // Both halves of a refused pair are refused.
                self.refuse(batch_seq, Refusal::State(e));
                self.refuse(late_seq, Refusal::State(e));
            }
        }
        m
    }

    /// A close of an open box, or a late close of a closed one. A device
    /// signature waits for the on-site record of a device swap.
    fn close(
        &self,
        m: Machine<'r>,
        item: &'r CloseItem<'r>,
        tokens: &'r ItemTokens<'r>,
    ) -> Step<'r> {
        if self.swap_due && item.close.device_sig().is_some() {
            return (m, Some(Refusal::OutOfOrder));
        }
        let late = matches!(m, Machine::Closed(_) | Machine::Counted(_));
        let chosen = if late { &tokens.late } else { &tokens.first };
        let Some(t) = chosen.as_deref().and_then(|t| close_tokens(&item.close, t)) else {
            return (m, Some(Refusal::Signature));
        };
        let issuance = item
            .issuance
            .as_ref()
            .zip(tokens.issuance.as_deref())
            .map(|(w, tokens)| Signed {
                event: &w.event,
                tokens,
            });
        match m {
            Machine::Open(b) => settle(
                b.close(&item.close, &t, issuance.as_ref()),
                Machine::Open,
                Machine::Closed,
            ),
            Machine::Fallback(b) => settle(
                b.close(&item.close, &t, issuance.as_ref()),
                Machine::Fallback,
                Machine::Closed,
            ),
            Machine::Closed(mut b) => {
                let r = b.late_close(&item.close, &t);
                kept(Machine::Closed(b), r)
            }
            Machine::Counted(mut b) => {
                let r = b.late_close(&item.close, &t);
                kept(Machine::Counted(b), r)
            }
            m @ (Machine::Spec(_) | Machine::Provisioned(_)) => (m, Some(Refusal::OutOfOrder)),
        }
    }

    /// A cast record, a challenge opening or a batch attestation of the
    /// open box (or one in fallback).
    fn counted(&mut self, m: Machine<'r>, seq: Seq, item: &'r Item<'r>) -> Step<'r> {
        let body = match item {
            Item::Record(record) => Some(record.body_bytes()),
            Item::Challenge(opening) => Some(opening.body_bytes()),
            Item::Batch(batch) => Some(batch.body_bytes()),
            Item::Witnessed(_) | Item::Close(_) | Item::Absent | Item::Skip => None,
        };
        if let Some(body) = body
            && !self.bodies.insert(object_hash(body).0)
        {
            return (m, Some(Refusal::Duplicate));
        }
        let challenged = matches!(item, Item::Record(record)
            if self.challenged.contains(&object_hash(record.body_bytes()).0));
        match (m, item) {
            // The record of a challenged ballot: published, not cast.
            (m @ (Machine::Open(_) | Machine::Fallback(_)), Item::Record(_)) if challenged => {
                (m, None)
            }
            (Machine::Open(mut b), Item::Record(record)) => match self.ballot_mark.as_ref() {
                Some(cap) => {
                    let r = b.record(cap, record.body());
                    kept(Machine::Open(b), r)
                }
                None => (Machine::Open(b), Some(Refusal::Capability)),
            },
            (Machine::Fallback(mut b), Item::Record(record)) => match self.ballot_mark.as_ref() {
                Some(cap) => {
                    let r = b.record(cap, record.body());
                    kept(Machine::Fallback(b), r)
                }
                None => (Machine::Fallback(b), Some(Refusal::Capability)),
            },
            (Machine::Open(mut b), Item::Challenge(opening)) => {
                let r = b.challenge(opening.body());
                kept(Machine::Open(b), r)
            }
            (Machine::Fallback(mut b), Item::Challenge(opening)) => {
                let r = b.challenge(opening.body());
                kept(Machine::Fallback(b), r)
            }
            (Machine::Open(mut b), Item::Batch(batch)) => {
                let r = b.batch(batch.body());
                kept(Machine::Open(b), r)
            }
            (Machine::Fallback(mut b), Item::Batch(batch)) => {
                let r = b.batch(batch.body());
                kept(Machine::Fallback(b), r)
            }
            (m @ (Machine::Closed(_) | Machine::Counted(_)), Item::Batch(batch)) => {
                // A late batch close: it waits for its `LateBatchClose`.
                self.batches.push((seq, &**batch));
                (self.match_late(m), None)
            }
            (m, _) => (m, Some(Refusal::OutOfOrder)),
        }
    }

    /// One item of the box.
    fn step(
        &mut self,
        m: Machine<'r>,
        seq: Seq,
        state: usize,
        item: &'r Item<'r>,
        tokens: &'r ItemTokens<'r>,
    ) -> Machine<'r> {
        let (m, refusal) = match self.advance(m, state) {
            (m, Some(r)) => (m, Some(r)),
            (m, None) => self.event(m, seq, item, tokens),
        };
        if let Some(r) = refusal {
            self.refuse(seq, r);
        }
        m
    }

    /// One item of the box, with the machine in the item's state.
    fn event(
        &mut self,
        m: Machine<'r>,
        seq: Seq,
        item: &'r Item<'r>,
        tokens: &'r ItemTokens<'r>,
    ) -> Step<'r> {
        match item {
            Item::Witnessed(w) => match tokens.first.as_deref() {
                Some(tokens) => self.witnessed(
                    m,
                    seq,
                    Signed {
                        event: &w.event,
                        tokens,
                    },
                ),
                None => (m, Some(Refusal::Signature)),
            },
            Item::Close(c) => self.close(m, c, tokens),
            Item::Record(_) | Item::Challenge(_) | Item::Batch(_) => self.counted(m, seq, item),
            Item::Absent => (m, Some(Refusal::Unexpected)),
            Item::Skip => (m, None),
        }
    }
}

/// What every box's run shares.
struct Shared<'x, 'a> {
    genesis: &'x VerifiedGenesis<'a>,
    index: &'x LedgerIndex<'a>,
    authority: &'x AuthorityStage<'a>,
    /// The roster of each genesis state, proved against it.
    rosters: &'x [Vec<RosterEntry<'a>>],
    /// The roster keys of each genesis state.
    keys: &'x [Keys<'a>],
}

/// The spec of box `box_id` in genesis state `state`, if the state has it.
fn spec_at<'x>(shared: &Shared<'x, '_>, state: usize, box_id: &[u8]) -> Option<BoxSpec<'x>> {
    let genesis = shared.genesis.genesis_at(state)?;
    let entry = shared.genesis.box_entry_at(state, box_id)?;
    let route = shared
        .genesis
        .route_entry_at(state, entry.get().route_id.as_bytes())?;
    let roster = shared.rosters.get(state)?;
    BoxSpec::new(genesis, &entry, &route, roster).ok()
}

/// Runs one box.
fn run_box<'a>(shared: &Shared<'_, 'a>, entry: &GenesisBox<'a>) -> BoxReport<'a> {
    let id = entry.box_id;
    let prep = Prep {
        genesis: shared.genesis,
        index: shared.index,
        keys: shared.keys,
        box_id: id,
    };
    let items: Vec<(Seq, usize, Item<'a>)> = shared
        .index
        .box_events(id.as_bytes())
        .map(|e| {
            let (state, item) = prep.item(e);
            (e.seq, state, item)
        })
        .collect();
    let tokens: Vec<ItemTokens<'_>> = items.iter().map(|(_, _, i)| i.tokens()).collect();

    let genesis = shared.genesis;
    let specs: Vec<Option<BoxSpec<'_>>> = (0..genesis.state_count())
        .map(|k| spec_at(shared, k, id.as_bytes()))
        .collect();
    // The machine starts in the first state that has the box.
    let first = specs
        .iter()
        .enumerate()
        .find_map(|(k, spec)| spec.map(|spec| (k, spec)));
    let mut run = Run {
        genesis,
        authority: shared.authority,
        ballot_mark: None,
        batches: Vec::new(),
        lates: Vec::new(),
        bodies: BTreeSet::new(),
        challenged: items
            .iter()
            .filter_map(|(_, _, item)| match item {
                Item::Challenge(opening) => Some(opening.body().record_hash().0),
                Item::Witnessed(_)
                | Item::Close(_)
                | Item::Record(_)
                | Item::Batch(_)
                | Item::Absent
                | Item::Skip => None,
            })
            .collect(),
        refusals: Vec::new(),
        specs,
        frame_keys: (0..genesis.state_count())
            .map(|k| {
                genesis
                    .expected_box_at(k, id.as_bytes())
                    .map(|b| b.frame_key)
            })
            .collect(),
        state: first.map_or(0, |(k, _)| k),
        swap_due: false,
        retired: Vec::new(),
    };
    let (phase, machine_holds, counts) = match first {
        Some((_, spec)) => {
            let mut m = Machine::Spec(spec);
            for ((seq, state, item), t) in items.iter().zip(&tokens) {
                m = run.step(m, *seq, *state, item, t);
            }
            (m.phase(), m.holds(), m.counts())
        }
        // The genesis stage proved every box entry and its route, so a
        // spec `ityv-state` refuses is a refusal of the whole box: none of
        // its events is run, and it is held.
        None => (
            Phase::Provisioned,
            HoldSet::empty().with(HoldReason::BoxEventRefused),
            None,
        ),
    };
    let unmatched: Vec<Seq> = run
        .batches
        .iter()
        .map(|(s, _)| *s)
        .chain(run.lates.iter().map(|(s, _)| *s))
        .collect();
    let mut refusals = run.refusals;
    refusals.extend(unmatched.into_iter().map(|seq| BoxRefusal {
        seq,
        refusal: Refusal::Unmatched,
    }));
    refusals.sort_by_key(|r| r.seq.get());
    let holds = shared
        .index
        .box_holds(id.as_bytes())
        .union(machine_holds)
        .union(shared.authority.holds())
        .with_if(!refusals.is_empty(), HoldReason::BoxEventRefused)
        .with_if(
            !matches!(phase, Phase::Closed | Phase::Counted),
            HoldReason::CloseMissing,
        );
    BoxReport {
        box_id: id,
        phase,
        holds,
        counts,
        refusals,
    }
}

/// Runs every expected box of the genesis's last state through its state
/// machine with the box's ledger events, each under the genesis state in
/// force at its frame.
#[must_use]
pub fn verify_boxes<'a>(
    genesis: &VerifiedGenesis<'a>,
    index: &LedgerIndex<'a>,
    authority: &AuthorityStage<'a>,
) -> BoxStage<'a> {
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
        authority,
        rosters: &rosters,
        keys: &keys,
    };
    let mut reports: Vec<BoxReport<'a>> = genesis.boxes().map(|b| run_box(&shared, b)).collect();
    // A box an earlier state had but the last does not: its events are not
    // run, so each is refused and the box held.
    let unexpected = index
        .boxes_with_events()
        .filter(|id| genesis.expected_box(id).is_none())
        .filter_map(|id| BoxId::new(id).map(|box_id| unexpected_report(index, authority, box_id)));
    reports.extend(unexpected);
    BoxStage { reports }
}

/// The report of a box with events that the last state does not expect.
fn unexpected_report<'a>(
    index: &LedgerIndex<'a>,
    authority: &AuthorityStage<'a>,
    box_id: BoxId<'a>,
) -> BoxReport<'a> {
    let refusals: Vec<BoxRefusal> = index
        .box_events(box_id.as_bytes())
        .map(|e| BoxRefusal {
            seq: e.seq,
            refusal: Refusal::Unexpected,
        })
        .collect();
    BoxReport {
        box_id,
        phase: Phase::Provisioned,
        holds: index
            .box_holds(box_id.as_bytes())
            .union(authority.holds())
            .with(HoldReason::BoxEventRefused),
        counts: None,
        refusals,
    }
}
