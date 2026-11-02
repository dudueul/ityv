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
//!   its body hash form a late batch close; seal changes and custody
//!   handoffs extend the custody chain; an `ImprintAudit` counts the box.
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
//! stage); that the box's counts agree with the station's progress record
//! (the progress stage); anything about boxes whose device key an
//! amendment replaced (a `BoxUnitSwap` is refused here until the stage
//! follows amendments, so such a box is held).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use ityv_crypto::hash::object_hash;
use ityv_crypto::{HybridSigned, Purpose, Verified};
use ityv_encoding::{
    BatchAttest, BoxClose, BoxId, BoxOpenedBody, CaptureProfile, CastRecord, ChallengeOpening,
    CloseCounts, Day, Decode, EventRole, FallbackBody, FallbackKind, GenesisBox, HYBRID_SIG_LEN,
    HYBRID_VK_LEN, LateBatchCloseBody, SCHEMA_BATCH_ATTEST, SCHEMA_BOX_CLOSE,
    SCHEMA_BOX_OPENED_BODY, SCHEMA_BOX_UNIT_SWAP_BODY, SCHEMA_CAST_RECORD,
    SCHEMA_CHALLENGE_OPENING, SCHEMA_CUSTODY_HANDOFF_BODY, SCHEMA_FALLBACK_BODY,
    SCHEMA_IMPRINT_AUDIT_BODY, SCHEMA_ISSUANCE_COUNT_BODY, SCHEMA_LATE_BATCH_CLOSE_BODY,
    SCHEMA_SEAL_CHANGE_BODY, SCHEMA_VERSION_1, SCHEMA_WITNESSED_EVENT, SchemaId, Seq, TimeBucket,
    WitnessedEvent, decode_object,
};
use ityv_state::{
    BallotBox, BallotMark, BoxSpec, Cap, CloseTokens, Closed, Counted, Fallback, HoldReason,
    HoldSet, Open, PURPOSE_BOX_CLOSE, PURPOSE_LATE_BOX_CLOSE, Provisioned, PublicBoard,
    RosterEntry, Signed, Transition,
};

use crate::authority::AuthorityStage;
use crate::genesis::VerifiedGenesis;
use crate::index::{IndexedEvent, LedgerIndex};
use crate::sigs::Material;

/// Time buckets per day (fifteen-minute buckets, PROTOCOL.md §3).
const BUCKETS_PER_DAY: u64 = 96;

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
    /// A device swap: the stage does not yet follow an amendment that
    /// replaces a box's device key.
    Unsupported,
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
    /// One report per expected box, in box order.
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
    /// A device swap (`BoxUnitSwap`).
    Swap,
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
            Self::Record(_) | Self::Challenge(_) | Self::Batch(_) | Self::Swap | Self::Skip => {
                ItemTokens::default()
            }
        }
    }
}

/// The body schemas of the witnessed events this stage runs.
const BOX_BODY_SCHEMAS: [SchemaId; 6] = [
    SCHEMA_BOX_OPENED_BODY,
    SCHEMA_FALLBACK_BODY,
    SCHEMA_LATE_BATCH_CLOSE_BODY,
    SCHEMA_SEAL_CHANGE_BODY,
    SCHEMA_CUSTODY_HANDOFF_BODY,
    SCHEMA_IMPRINT_AUDIT_BODY,
];

fn decode<'a, T: Decode<'a>>(schema: SchemaId, bytes: &'a [u8]) -> Option<T> {
    decode_object(schema, SCHEMA_VERSION_1, bytes).ok()
}

/// What preparing a box's events needs.
struct Prep<'x, 'a> {
    index: &'x LedgerIndex<'a>,
    keys: &'x Keys<'a>,
    entry: &'x GenesisBox<'a>,
}

impl<'a> Prep<'_, 'a> {
    /// Decodes one indexed event of the box.
    fn item(&self, event: &IndexedEvent<'a>) -> Item<'a> {
        let Some(bytes) = event.bytes else {
            return Item::Skip;
        };
        let schema = event.schema;
        let device = Some(self.entry.device_key);
        let item = if schema == SCHEMA_WITNESSED_EVENT {
            decode::<WitnessedEvent<'a>>(schema, bytes).and_then(|w| {
                let body = w.body_schema();
                if body == SCHEMA_BOX_UNIT_SWAP_BODY {
                    Some(Item::Swap)
                } else if BOX_BODY_SCHEMAS.contains(&body) {
                    WitnessedItem::new(&w, self.keys, device).map(|w| Item::Witnessed(Box::new(w)))
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
                    .map(|sig| Some((sig, self.entry.device_key)))
                    .into_iter()
                    .chain(
                        close
                            .attestations()
                            .map(|a| self.keys.get(a.signer_id.as_bytes()).map(|k| (a.sig, *k))),
                    )
                    .collect();
                Some(Item::Close(Box::new(CloseItem {
                    close,
                    first: Purpose::new(PURPOSE_BOX_CLOSE)?,
                    late: Purpose::new(PURPOSE_LATE_BOX_CLOSE)?,
                    material: pairs.and_then(|p| Material::new(p.into_iter())),
                    issuance: self.issuance(event.seq),
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
    /// before frame `before` (it has no device signature).
    fn issuance(&self, before: Seq) -> Option<WitnessedItem<'a>> {
        if self.entry.profile != CaptureProfile::Absentee {
            return None;
        }
        let mut last = None;
        for e in self.index.station_events(self.entry.station_id.as_bytes()) {
            if e.seq.get() >= before.get() {
                break;
            }
            if let Some(w) = e
                .bytes
                .and_then(|b| decode::<WitnessedEvent<'a>>(e.schema, b))
                .filter(|w| w.body_schema() == SCHEMA_ISSUANCE_COUNT_BODY)
            {
                last = Some(w);
            }
        }
        WitnessedItem::new(&last?, self.keys, None)
    }
}

/// The day of `bucket`, counted from the genesis's epoch day.
fn day_of(genesis: &VerifiedGenesis<'_>, bucket: TimeBucket) -> Option<Day> {
    let epoch = genesis.genesis().body().election_epoch_day().get();
    bucket
        .get()
        .checked_div(BUCKETS_PER_DAY)
        .and_then(|d| epoch.checked_add(d))
        .map(Day::new)
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

impl Machine<'_> {
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
    refusals: Vec<BoxRefusal>,
}

impl<'r> Run<'r, '_> {
    fn refuse(&mut self, seq: Seq, refusal: Refusal) {
        self.refusals.push(BoxRefusal { seq, refusal });
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
            self.lates.push((seq, signed));
            (self.match_late(m), None)
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
            let (_, batch) = self.batches.remove(i);
            let r = match &mut m {
                Machine::Closed(b) => b.late_batch(batch, &late),
                Machine::Counted(b) => b.late_batch(batch, &late),
                Machine::Spec(_)
                | Machine::Provisioned(_)
                | Machine::Open(_)
                | Machine::Fallback(_) => Err(ityv_state::Error::LateClose),
            };
            if let Err(e) = r {
                self.refuse(late_seq, Refusal::State(e));
            }
        }
        m
    }

    /// A close of an open box, or a late close of a closed one.
    fn close(m: Machine<'r>, item: &'r CloseItem<'r>, tokens: &'r ItemTokens<'r>) -> Step<'r> {
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
        match (m, item) {
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
        item: &'r Item<'r>,
        tokens: &'r ItemTokens<'r>,
    ) -> Machine<'r> {
        let (m, refusal) = match item {
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
            Item::Close(c) => Self::close(m, c, tokens),
            Item::Record(_) | Item::Challenge(_) | Item::Batch(_) => self.counted(m, seq, item),
            Item::Swap => (m, Some(Refusal::Unsupported)),
            Item::Skip => (m, None),
        };
        if let Some(r) = refusal {
            self.refuse(seq, r);
        }
        m
    }
}

/// What every box's run shares.
struct Shared<'x, 'a> {
    genesis: &'x VerifiedGenesis<'a>,
    index: &'x LedgerIndex<'a>,
    authority: &'x AuthorityStage<'a>,
    roster: &'x [RosterEntry<'a>],
    keys: &'x Keys<'a>,
}

/// Runs one box.
fn run_box<'a>(shared: &Shared<'_, 'a>, entry: &GenesisBox<'a>) -> BoxReport<'a> {
    let id = entry.box_id;
    let prep = Prep {
        index: shared.index,
        keys: shared.keys,
        entry,
    };
    let items: Vec<(Seq, Item<'a>)> = shared
        .index
        .box_events(id.as_bytes())
        .map(|e| (e.seq, prep.item(e)))
        .collect();
    let tokens: Vec<ItemTokens<'_>> = items.iter().map(|(_, i)| i.tokens()).collect();

    let genesis = shared.genesis;
    let spec = genesis
        .box_entry(id.as_bytes())
        .zip(genesis.route_entry(entry.route_id.as_bytes()))
        .and_then(|(e, route)| BoxSpec::new(genesis.genesis(), &e, &route, shared.roster).ok());
    let mut run = Run {
        genesis,
        authority: shared.authority,
        ballot_mark: None,
        batches: Vec::new(),
        lates: Vec::new(),
        refusals: Vec::new(),
    };
    let (phase, machine_holds, counts) = match spec {
        Some(spec) => {
            let mut m = Machine::Spec(spec);
            for ((seq, item), t) in items.iter().zip(&tokens) {
                m = run.step(m, *seq, item, t);
            }
            (m.phase(), m.holds(), m.counts())
        }
        // The genesis stage proved every box entry and its route, so a
        // spec `ityv-state` refuses is a refusal of the whole box.
        None => (Phase::Provisioned, HoldSet::empty(), None),
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
/// machine with the box's ledger events.
#[must_use]
pub fn verify_boxes<'a>(
    genesis: &VerifiedGenesis<'a>,
    index: &LedgerIndex<'a>,
    authority: &AuthorityStage<'a>,
) -> BoxStage<'a> {
    let roster = genesis.roster();
    let keys: Keys<'a> = roster
        .iter()
        .map(|r| (r.get().signer_id.as_bytes(), r.get().key))
        .collect();
    let shared = Shared {
        genesis,
        index,
        authority,
        roster: &roster,
        keys: &keys,
    };
    BoxStage {
        reports: genesis.boxes().map(|b| run_box(&shared, b)).collect(),
    }
}
