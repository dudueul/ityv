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
//! The events not taken are listed; the report holds the ledger on any
//! of them (`DisputeRefused`), and on any dispute still unresolved. The
//! checkpoint stage uses the steps to recompute each checkpoint's dispute
//! root.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use ityv_crypto::hash::object_hash;
use ityv_crypto::{HybridSigned, Purpose, Verified};
use ityv_encoding::{
    DisputeAction, DisputeEventBody, DisputeType, EventRole, HYBRID_SIG_LEN, HYBRID_VK_LEN,
    SCHEMA_DISPUTE_EVENT_BODY, SCHEMA_VERSION_1, SCHEMA_WITNESSED_EVENT, Seq, WitnessedEvent,
    decode_object,
};
use ityv_state::{Dispute, PublicBoard, Signed, VoterCode};

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

/// A dispute event, decoded, with the material its tokens need.
struct Prepared<'a> {
    seq: Seq,
    event: WitnessedEvent<'a>,
    purpose: Purpose<'static>,
    material: Option<Material>,
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

/// The dispute events of the ledger, decoded, in frame order.
fn prepare<'a>(genesis: &VerifiedGenesis<'_>, index: &LedgerIndex<'a>) -> Vec<Prepared<'a>> {
    index
        .events()
        .iter()
        .filter(|e| e.schema == SCHEMA_WITNESSED_EVENT)
        .filter_map(|e| {
            let event: WitnessedEvent<'a> =
                decode_object(SCHEMA_WITNESSED_EVENT, SCHEMA_VERSION_1, e.bytes?).ok()?;
            if event.body_schema() != SCHEMA_DISPUTE_EVENT_BODY {
                return None;
            }
            Some(Prepared {
                seq: e.seq,
                purpose: Purpose::new(event.purpose())?,
                material: material(&event, genesis),
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

/// What the dispute events of a ledger did.
#[derive(Debug, Clone, Default)]
pub(crate) struct DisputeLog {
    /// The events taken, in frame order.
    pub(crate) steps: Vec<DisputeStep>,
    /// The frames of the dispute events not taken: a signature that does
    /// not verify, a filing without its capability or filed again, a change
    /// that does not apply or names no dispute filed.
    pub(crate) refused: Vec<Seq>,
}

/// The steps of every dispute on the ledger, in frame order, and the
/// events refused.
pub(crate) fn dispute_steps(
    genesis: &VerifiedGenesis<'_>,
    index: &LedgerIndex<'_>,
    authority: &AuthorityStage<'_>,
) -> DisputeLog {
    let prepared = prepare(genesis, index);
    let tokens: Vec<Option<Vec<Verified<HybridSigned<'_>>>>> = prepared
        .iter()
        .map(|p| {
            p.material
                .as_ref()?
                .verify(&p.purpose, p.event.body_bytes())
        })
        .collect();
    let mut disputes: BTreeMap<[u8; 64], Dispute<'_>> = BTreeMap::new();
    let mut log = DisputeLog::default();
    for (p, t) in prepared.iter().zip(&tokens) {
        let Some(t) = t else {
            log.refused.push(p.seq);
            continue;
        };
        let signed = Signed {
            event: &p.event,
            tokens: t,
        };
        let Ok(body) = p
            .event
            .body::<DisputeEventBody<'_>>(SCHEMA_DISPUTE_EVENT_BODY)
        else {
            log.refused.push(p.seq);
            continue;
        };
        let parts = body.parts();
        let taken = if parts.action == DisputeAction::Filed {
            let key = object_hash(p.event.body_bytes()).0;
            // A filing already taken is not filed again.
            if disputes.contains_key(&key) {
                None
            } else {
                file(&signed, genesis, authority).map(|d| (key, d))
            }
        } else {
            let key = parts.filing_hash.0;
            disputes
                .get(&key)
                .and_then(|d| d.record(&signed, genesis.genesis()).ok())
                .map(|d| (key, d))
        };
        match taken {
            Some((key, d)) => {
                log.steps.push(DisputeStep {
                    seq: p.seq,
                    filing: key,
                    unresolved: d.is_unresolved(),
                });
                disputes.insert(key, d);
            }
            None => log.refused.push(p.seq),
        }
    }
    log
}

/// The number of disputes unresolved after every step.
pub(crate) fn unresolved(steps: &[DisputeStep]) -> usize {
    let last: BTreeMap<[u8; 64], bool> = steps.iter().map(|s| (s.filing, s.unresolved)).collect();
    last.values().filter(|open| **open).count()
}
