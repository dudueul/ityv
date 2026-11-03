//! Dispute events run through `ityv_state`'s dispute state machine
//! (PROTOCOL.md §13): the status of every dispute after each accepted
//! dispute event, in frame order.
//!
//! A filing is taken under a `PUBLIC_BOARD` capability (an inclusion
//! dispute under `VOTER_CODE`) for the day of its time bucket, with the
//! commission's and the committee's signatures verified here under the
//! keys the genesis body registers. A later event changes the dispute it
//! names only if `ityv_state::Dispute::record` takes it: the same election,
//! type, target and evidence, both signatures, and a transition the
//! dispute's status allows (forward only: a dispute referred to the legal
//! track is never resolved as a technical matter). An event that is not
//! taken changes nothing, so a forged or out-of-order resolution never
//! removes a dispute from the unresolved set.
//!
//! A `LegalDecisionRef` (PROTOCOL.md §13 item 4) is taken when its one
//! signature verifies under the key the genesis roster registers for that
//! signer as a legal authority of that organisation (in the genesis state
//! in force at its frame or an earlier one), its body names that
//! organisation, and it names a dispute filed in an earlier frame. It is
//! shown next to that dispute and changes nothing else: the dispute's
//! machine status stays what the dispute events made it (VC-049), so a
//! dispute referred to the legal track stays unresolved.
//!
//! The stage (PROTOCOL.md §14 item 9) is the public list of every dispute
//! with its status, the frames of its events and the decisions naming it,
//! and the frames of the dispute events and decisions not taken. The
//! report holds the ledger on any event not taken (`DisputeRefused`) and
//! on any dispute still unresolved (`OpenDispute`). The checkpoint stage
//! uses the steps to recompute each checkpoint's dispute root.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use ityv_crypto::hash::object_hash;
use ityv_crypto::{HybridSigned, Purpose, Verified};
use ityv_encoding::{
    BoxId, Day, DisputeAction, DisputeEventBody, DisputeType, EventRole, HYBRID_SIG_LEN,
    HYBRID_VK_LEN, Hash512, LegalOutcome, OrgId, RosterRole, SCHEMA_DISPUTE_EVENT_BODY,
    SCHEMA_LEGAL_DECISION_REF_BODY, SCHEMA_VERSION_1, SCHEMA_WITNESSED_EVENT, Seq, TallyEffect,
    WitnessedEvent, decode_object,
};
use ityv_state::status::LegalReference;
use ityv_state::{
    Dispute, DisputeStatus, HoldReason, HoldSet, PublicBoard, RosterEntry, Signed, VoterCode,
};

use crate::authority::{AuthorityStage, day_of};
use crate::genesis::VerifiedGenesis;
use crate::index::LedgerIndex;
use crate::sigs::Material;

/// One dispute event that was taken: the dispute it opened or changed, and
/// whether that dispute is unresolved after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct DisputeStep {
    /// The frame that carries the event.
    pub(crate) seq: Seq,
    /// The object hash of the dispute's filing body.
    pub(crate) filing: [u8; 64],
    /// Whether the dispute is unresolved after the event.
    pub(crate) unresolved: bool,
}

/// A dispute event or a legal decision, decoded, with the material its
/// tokens need.
struct Prepared<'a> {
    seq: Seq,
    event: WitnessedEvent<'a>,
    purpose: Purpose<'static>,
    material: Option<Material>,
    /// For a legal decision, the roster entry of its signer.
    authority: Option<RosterEntry<'a>>,
}

/// Each signature with the key the genesis registers for its role (the
/// envelope admits only one commission and one committee signature).
fn material(event: &WitnessedEvent<'_>, genesis: &VerifiedGenesis<'_>) -> Option<Material> {
    let g = genesis.genesis();
    let pairs: Option<Vec<(&[u8; HYBRID_SIG_LEN], &[u8; HYBRID_VK_LEN])>> = event
        .sigs()
        .map(|s| match s.role {
            EventRole::Commission => Some((s.sig, g.commission_key())),
            EventRole::Committee => Some((s.sig, g.committee_key())),
            EventRole::Clerk
            | EventRole::Observer
            | EventRole::Sender
            | EventRole::Receiver
            | EventRole::Authority
            | EventRole::Device => None,
        })
        .collect();
    Material::new(pairs?.into_iter())
}

/// The legal authority that signed `event` at frame `seq`, as the roster
/// of the genesis state in force there (or, failing that, of an earlier
/// state) registers it: the same signer, organisation and role.
fn authority_of<'a>(
    event: &WitnessedEvent<'_>,
    seq: Seq,
    rosters: &[Vec<RosterEntry<'a>>],
    index: &LedgerIndex<'_>,
) -> Option<RosterEntry<'a>> {
    // The decoder admits exactly one signature, of the authority role
    // (`ityv_encoding::roles_satisfied`).
    let sig = event.sigs().next()?;
    let state = index.state_at(seq);
    rosters.get(..=state)?.iter().rev().find_map(|roster| {
        roster
            .iter()
            .find(|r| {
                let s = r.get();
                s.role == RosterRole::Authority
                    && s.signer_id.as_bytes() == sig.signer_id.as_bytes()
                    && s.org_id.as_bytes() == sig.org_id.as_bytes()
            })
            .copied()
    })
}

/// The dispute events and legal decisions of the ledger, decoded, in frame
/// order.
fn prepare<'a>(
    genesis: &VerifiedGenesis<'a>,
    index: &LedgerIndex<'a>,
    rosters: &[Vec<RosterEntry<'a>>],
) -> Vec<Prepared<'a>> {
    index
        .events()
        .iter()
        .filter(|e| e.schema == SCHEMA_WITNESSED_EVENT)
        .filter_map(|e| {
            let event: WitnessedEvent<'a> =
                decode_object(SCHEMA_WITNESSED_EVENT, SCHEMA_VERSION_1, e.bytes?).ok()?;
            let schema = event.body_schema();
            let (material, authority) = if schema == SCHEMA_DISPUTE_EVENT_BODY {
                (material(&event, genesis), None)
            } else if schema == SCHEMA_LEGAL_DECISION_REF_BODY {
                let authority = authority_of(&event, e.seq, rosters, index);
                let material = authority.as_ref().and_then(|a| {
                    let sig = event.sigs().next()?;
                    Material::new(core::iter::once((sig.sig, a.get().key)))
                });
                (material, authority)
            } else {
                return None;
            };
            Some(Prepared {
                seq: e.seq,
                purpose: Purpose::new(event.purpose())?,
                material,
                authority,
                event,
            })
        })
        .collect()
}

/// Files a dispute under the capability its type needs, for the day of its
/// time bucket.
fn file<'r>(
    signed: &Signed<'r>,
    genesis: &VerifiedGenesis<'_>,
    authority: &AuthorityStage<'_>,
) -> Option<Dispute<'r>> {
    let body: DisputeEventBody<'_> = signed.event.body(SCHEMA_DISPUTE_EVENT_BODY).ok()?;
    let p = body.parts();
    let auth = authority.authorization()?;
    let day = day_of(genesis, p.time_bucket)?;
    let g = genesis.genesis();
    if p.dispute_type == DisputeType::InclusionMissing {
        let cap = auth.grant::<VoterCode>(day).ok()?;
        Dispute::file_inclusion(signed, g, &cap).ok()
    } else {
        let cap = auth.grant::<PublicBoard>(day).ok()?;
        Dispute::file(signed, g, &cap).ok()
    }
}

/// A legal decision shown next to the dispute it names (PROTOCOL.md §13
/// item 4, §14 item 9). It is a reference the verifier displays as
/// `LEGAL_CERTIFIED`; the verifier never derives it (VC-049).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Decision<'a> {
    /// The frame that carries the decision.
    pub seq: Seq,
    /// The deciding authority, as the decision and the roster name it.
    pub authority_id: OrgId<'a>,
    /// Hash of the decision document.
    pub document_hash: Hash512,
    /// The outcome.
    pub outcome: LegalOutcome,
    /// The effect on the tally scope of the record the dispute names.
    pub tally_effect: TallyEffect,
    /// The day of the decision.
    pub decided_day: Day,
}

/// One dispute after every dispute event on the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisputeEntry<'a> {
    /// The object hash of the filing body: the dispute's name.
    pub filing: Hash512,
    /// The dispute type.
    pub dispute_type: DisputeType,
    /// The box concerned, if any.
    pub box_id: Option<BoxId<'a>>,
    /// The record concerned, if any.
    pub record_hash: Option<Hash512>,
    /// The status the dispute events made.
    pub status: DisputeStatus,
    /// The result document of the last event that carries one (a
    /// resolution or a referral).
    pub result_hash: Option<Hash512>,
    /// The frames of the events taken, the filing first.
    pub events: Vec<Seq>,
    /// The legal decisions naming the dispute, in frame order.
    pub decisions: Vec<Decision<'a>>,
}

impl DisputeEntry<'_> {
    /// Whether the dispute is unresolved: every status but
    /// `RESOLVED_TECHNICAL`, the legal referral included.
    #[must_use]
    pub const fn is_unresolved(&self) -> bool {
        !matches!(self.status, DisputeStatus::ResolvedTechnical)
    }
}

/// The dispute stage (PROTOCOL.md §14 item 9).
#[derive(Debug, Clone, Default)]
pub struct DisputeStage<'a> {
    /// The events taken, in frame order.
    pub(crate) steps: Vec<DisputeStep>,
    disputes: Vec<DisputeEntry<'a>>,
    refused: Vec<Seq>,
}

impl<'a> DisputeStage<'a> {
    /// Every dispute filed, in filing order.
    #[must_use]
    pub fn disputes(&self) -> &[DisputeEntry<'a>] {
        &self.disputes
    }

    /// The disputes still unresolved.
    pub fn unresolved(&self) -> impl Iterator<Item = &DisputeEntry<'a>> + '_ {
        self.disputes.iter().filter(|d| d.is_unresolved())
    }

    /// The frames of the dispute events and legal decisions not taken: a
    /// signature that does not verify under the registered key, a filing
    /// without its capability or filed again, a change that does not apply
    /// or names no dispute filed, a decision whose authority is not
    /// registered or that names no dispute filed before it.
    #[must_use]
    pub fn refused(&self) -> &[Seq] {
        &self.refused
    }

    /// `OpenDispute` while a dispute is unresolved, `DisputeRefused` when
    /// an event was not taken.
    #[must_use]
    pub fn holds(&self) -> HoldSet {
        HoldSet::empty()
            .with_if(self.unresolved().next().is_some(), HoldReason::OpenDispute)
            .with_if(!self.refused.is_empty(), HoldReason::DisputeRefused)
    }
}

/// Takes the legal decision `p` (its tokens `t`) if it names a dispute
/// filed before it.
fn decide<'a>(
    p: &Prepared<'a>,
    t: &[Verified<HybridSigned<'_>>],
    disputes: &BTreeMap<[u8; 64], (Dispute<'_>, DisputeEntry<'a>)>,
) -> Option<([u8; 64], Decision<'a>)> {
    let authority = p.authority.as_ref()?;
    let reference = LegalReference::from_signed(t.first()?, authority).ok()?;
    let body = *reference.body();
    if body.authority_id.as_bytes() != authority.get().org_id.as_bytes() {
        return None;
    }
    let key = body.dispute_hash.0;
    let (dispute, _) = disputes.get(&key)?;
    if !reference.concerns(dispute) {
        return None;
    }
    Some((
        key,
        Decision {
            seq: p.seq,
            authority_id: authority.get().org_id,
            document_hash: body.decision_doc_hash,
            outcome: body.outcome,
            tally_effect: body.tally_effect,
            decided_day: body.decided_day,
        },
    ))
}

/// Runs every dispute event of the ledger through the dispute state
/// machine, in frame order, and shows each legal decision next to the
/// dispute it names (PROTOCOL.md §13, §14 item 9).
#[must_use]
pub fn verify_disputes<'a>(
    genesis: &VerifiedGenesis<'a>,
    index: &LedgerIndex<'a>,
    authority: &AuthorityStage<'_>,
) -> DisputeStage<'a> {
    let rosters: Vec<Vec<RosterEntry<'a>>> = (0..genesis.state_count())
        .map(|k| genesis.roster_at(k))
        .collect();
    let prepared = prepare(genesis, index, &rosters);
    let tokens: Vec<Option<Vec<Verified<HybridSigned<'_>>>>> = prepared
        .iter()
        .map(|p| {
            p.material
                .as_ref()?
                .verify(&p.purpose, p.event.body_bytes())
        })
        .collect();
    // Each dispute filed, by the object hash of its filing body, with its
    // public entry.
    let mut disputes: BTreeMap<[u8; 64], (Dispute<'_>, DisputeEntry<'a>)> = BTreeMap::new();
    let mut order: Vec<[u8; 64]> = Vec::new();
    let mut stage = DisputeStage::default();
    for (p, t) in prepared.iter().zip(&tokens) {
        let Some(t) = t else {
            stage.refused.push(p.seq);
            continue;
        };
        if p.authority.is_some() {
            match decide(p, t, &disputes) {
                Some((key, decision)) => {
                    if let Some((_, entry)) = disputes.get_mut(&key) {
                        entry.decisions.push(decision);
                    }
                }
                None => stage.refused.push(p.seq),
            }
            continue;
        }
        let signed = Signed {
            event: &p.event,
            tokens: t,
        };
        let Ok(body) = p
            .event
            .body::<DisputeEventBody<'a>>(SCHEMA_DISPUTE_EVENT_BODY)
        else {
            stage.refused.push(p.seq);
            continue;
        };
        let parts = body.parts();
        let result = (parts.result_hash != Hash512::ZERO).then_some(parts.result_hash);
        let taken = if parts.action == DisputeAction::Filed {
            let key = object_hash(p.event.body_bytes()).0;
            // A filing already taken is not filed again.
            if disputes.contains_key(&key) {
                None
            } else {
                file(&signed, genesis, authority).map(|d| {
                    order.push(key);
                    let entry = DisputeEntry {
                        filing: Hash512(key),
                        dispute_type: parts.dispute_type,
                        box_id: parts.box_id,
                        record_hash: parts.record_hash,
                        status: d.status(),
                        result_hash: None,
                        events: Vec::new(),
                        decisions: Vec::new(),
                    };
                    (key, d, entry)
                })
            }
        } else {
            let key = parts.filing_hash.0;
            disputes.get(&key).and_then(|(d, entry)| {
                let d = d.record(&signed, genesis.genesis()).ok()?;
                Some((key, d, entry.clone()))
            })
        };
        match taken {
            Some((key, d, mut entry)) => {
                stage.steps.push(DisputeStep {
                    seq: p.seq,
                    filing: key,
                    unresolved: d.is_unresolved(),
                });
                entry.status = d.status();
                entry.events.push(p.seq);
                if result.is_some() {
                    entry.result_hash = result;
                }
                disputes.insert(key, (d, entry));
            }
            None => stage.refused.push(p.seq),
        }
    }
    stage.disputes = order
        .iter()
        .filter_map(|key| disputes.remove(key).map(|(_, entry)| entry))
        .collect();
    stage
}
