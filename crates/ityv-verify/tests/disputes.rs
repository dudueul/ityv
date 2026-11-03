//! The dispute stage (PROTOCOL.md §13, §14 9; VC-049): every dispute with
//! its status, events and result, legal decisions shown next to the
//! dispute they name without changing its status, and every dispute event
//! or decision that cannot be taken listed and held, on events with real
//! hybrid signatures.
// Integration tests: outside the TCB. Assertions use unwrap/expect, so these
// lints are relaxed for this file only (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::arithmetic_side_effects
)]

mod common;

use std::sync::OnceLock;

use common::{
    COMMISSION, COMMITTEE, Ledger, ROSTER_BASE, SPARE_BASE, authorized, leak, object, sign,
    sign_seeded, signing,
};
use ityv_crypto::object_hash;
use ityv_encoding::{
    BoxId, Day, DisputeAction, DisputeEventBody, DisputeEventParts, DisputeType, EventRole,
    EventSig, Hash512, LegalDecisionRefBody, LegalDecisionRefParts, LegalOutcome, OrgId,
    SCHEMA_DISPUTE_EVENT_BODY, SCHEMA_LEGAL_DECISION_REF_BODY, SCHEMA_SIGNED_GENESIS,
    SCHEMA_SIGNED_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, SCHEMA_WITNESSED_EVENT, Seq, SignerId,
    TallyEffect, TimeBucket, WitnessedEvent,
};
use ityv_state::{DisputeStatus, HoldReason, HoldSet};
use ityv_verify::{
    Decision, DisputeStage, VerifiedGenesis, authorize_ledger, build_index, verify_disputes,
    verify_genesis,
};

/// The key number of the court, the legal authority of the roster.
const COURT: u16 = ROSTER_BASE + 5;
/// The key number of `clerk-1`.
const CLERK: u16 = ROSTER_BASE;

fn verified() -> &'static VerifiedGenesis<'static> {
    static VERIFIED: OnceLock<&'static VerifiedGenesis<'static>> = OnceLock::new();
    VERIFIED.get_or_init(|| {
        let built = &authorized().0;
        leak(verify_genesis(&built.pin, &built.input(), &[]).unwrap())
    })
}

/// A dispute event: the filing when `filing` is `None`, otherwise a later
/// event of `action` naming it; `evidence` tells filings apart; `forged`
/// signs with keys the genesis does not register. Returns (the filing's
/// hash, event bytes).
fn dispute(
    action: DisputeAction,
    filing: Option<Hash512>,
    evidence: u8,
    forged: bool,
) -> (Hash512, &'static [u8]) {
    dispute_signed(action, filing, evidence, forged, 0)
}

/// As [`dispute`], the signatures drawn with `seed` (another seed gives
/// another event object over the same body).
fn dispute_signed(
    action: DisputeAction,
    filing: Option<Hash512>,
    evidence: u8,
    forged: bool,
    seed: u64,
) -> (Hash512, &'static [u8]) {
    let result = match action {
        DisputeAction::ResolvedTechnical | DisputeAction::ReferredLegal => Hash512([0x3A; 64]),
        DisputeAction::Filed | DisputeAction::Investigating => Hash512::ZERO,
    };
    let body = DisputeEventBody::new(&DisputeEventParts {
        election_id: common::election(),
        action,
        dispute_type: DisputeType::Custody,
        box_id: Some(BoxId::new(b"BOX-1").unwrap()),
        record_hash: None,
        evidence_hash: Hash512([evidence; 64]),
        filing_hash: filing.unwrap_or(Hash512::ZERO),
        result_hash: result,
        time_bucket: TimeBucket::new(60),
    })
    .unwrap();
    let body = object(SCHEMA_DISPUTE_EVENT_BODY, SCHEMA_VERSION_1, &body);
    let (commission, committee) = if forged {
        (SPARE_BASE, SPARE_BASE + 1)
    } else {
        (COMMISSION, COMMITTEE)
    };
    let sigs = [
        EventSig {
            signer_id: SignerId::new(b"commission").unwrap(),
            role: EventRole::Commission,
            org_id: OrgId::new(b"NEC").unwrap(),
            sig: sign_seeded(signing(commission), b"dispute", body, seed),
        },
        EventSig {
            signer_id: SignerId::new(b"committee").unwrap(),
            role: EventRole::Committee,
            org_id: OrgId::new(b"IVC").unwrap(),
            sig: sign_seeded(signing(committee), b"dispute", body, seed),
        },
    ];
    let event = WitnessedEvent::new(body, &sigs).unwrap();
    (
        filing.unwrap_or_else(|| object_hash(body)),
        object(SCHEMA_WITNESSED_EVENT, SCHEMA_VERSION_1, &event),
    )
}

/// Who signs a legal decision, and what its body says.
#[derive(Clone, Copy)]
struct Signer {
    id: &'static [u8],
    org: &'static [u8],
    key: u16,
    /// The authority the body names.
    body_org: &'static [u8],
}

const THE_COURT: Signer = Signer {
    id: b"court",
    org: b"COURT",
    key: COURT,
    body_org: b"COURT",
};

/// A legal decision on the dispute `dispute_hash`, signed by `by`.
fn decision(dispute_hash: Hash512, by: Signer) -> &'static [u8] {
    let body = LegalDecisionRefBody::new(&LegalDecisionRefParts {
        election_id: common::election(),
        authority_id: OrgId::new(by.body_org).unwrap(),
        decision_doc_hash: Hash512([0x5D; 64]),
        dispute_hash,
        outcome: LegalOutcome::Upheld,
        tally_effect: TallyEffect::NoEffect,
        decided_day: Day::new(20_050),
    })
    .unwrap();
    let body = object(SCHEMA_LEGAL_DECISION_REF_BODY, SCHEMA_VERSION_1, &body);
    let sigs = [EventSig {
        signer_id: SignerId::new(by.id).unwrap(),
        role: EventRole::Authority,
        org_id: OrgId::new(by.org).unwrap(),
        sig: sign(signing(by.key), b"legal-decision", body),
    }];
    let event = WitnessedEvent::new(body, &sigs).unwrap();
    object(SCHEMA_WITNESSED_EVENT, SCHEMA_VERSION_1, &event)
}

/// The dispute stage of a ledger of the genesis (frame 1), the legal
/// authorization (frame 2) and `events` (from frame 3).
fn run(events: &[&'static [u8]]) -> DisputeStage<'static> {
    let mut ledger = Ledger::new();
    ledger.push(SCHEMA_SIGNED_GENESIS, authorized().0.signed);
    ledger.push(SCHEMA_SIGNED_LEGAL_AUTHORIZATION, authorized().1);
    for e in events {
        ledger.push(SCHEMA_WITNESSED_EVENT, e);
    }
    let index = leak(build_index(verified(), ledger.bytes(), &ledger.events));
    assert!(index.findings().is_empty(), "{:?}", index.findings());
    let authority = leak(authorize_ledger(verified(), index));
    assert!(authority.holds().is_empty(), "{:?}", authority.holds());
    verify_disputes(verified(), index, authority)
}

fn seqs(n: &[u64]) -> Vec<Seq> {
    n.iter().map(|&s| Seq::new(s).unwrap()).collect()
}

#[test]
fn a_dispute_is_listed_with_its_status_events_and_result() {
    let (filing, filed) = dispute(DisputeAction::Filed, None, 1, false);
    let stage = run(&[filed]);
    assert_eq!(stage.disputes().len(), 1);
    let d = &stage.disputes()[0];
    assert_eq!(d.filing, filing);
    assert_eq!(d.dispute_type, DisputeType::Custody);
    assert_eq!(d.box_id.unwrap().as_bytes(), b"BOX-1");
    assert_eq!(d.record_hash, None);
    assert_eq!(d.status, DisputeStatus::Open);
    assert_eq!(d.result_hash, None);
    assert_eq!(d.events, seqs(&[3]));
    assert!(d.is_unresolved());
    assert_eq!(stage.unresolved().count(), 1);
    assert_eq!(
        stage.holds(),
        HoldSet::empty().with(HoldReason::OpenDispute)
    );

    let (_, investigating) = dispute(DisputeAction::Investigating, Some(filing), 1, false);
    let (_, resolved) = dispute(DisputeAction::ResolvedTechnical, Some(filing), 1, false);
    let stage = run(&[filed, investigating, resolved]);
    let d = &stage.disputes()[0];
    assert_eq!(d.status, DisputeStatus::ResolvedTechnical);
    assert_eq!(d.result_hash, Some(Hash512([0x3A; 64])));
    assert_eq!(d.events, seqs(&[3, 4, 5]));
    assert!(!d.is_unresolved());
    assert_eq!(stage.unresolved().count(), 0);
    assert!(stage.refused().is_empty());
    assert!(stage.holds().is_empty(), "{:?}", stage.holds());
}

#[test]
fn disputes_are_listed_in_filing_order_and_each_keeps_its_own_status() {
    let (a, filed_a) = dispute(DisputeAction::Filed, None, 1, false);
    let (b, filed_b) = dispute(DisputeAction::Filed, None, 2, false);
    let (_, investigating_a) = dispute(DisputeAction::Investigating, Some(a), 1, false);
    let (_, resolved_b) = dispute(DisputeAction::ResolvedTechnical, Some(b), 2, false);
    let stage = run(&[filed_a, filed_b, resolved_b, investigating_a]);
    let filings: Vec<Hash512> = stage.disputes().iter().map(|d| d.filing).collect();
    assert_eq!(filings, [a, b]);
    assert_eq!(stage.disputes()[0].status, DisputeStatus::Investigating);
    assert_eq!(stage.disputes()[0].events, seqs(&[3, 6]));
    assert_eq!(stage.disputes()[0].result_hash, None);
    assert_eq!(stage.disputes()[1].status, DisputeStatus::ResolvedTechnical);
    assert_eq!(stage.disputes()[1].events, seqs(&[4, 5]));
    let open: Vec<Hash512> = stage.unresolved().map(|d| d.filing).collect();
    assert_eq!(open, [a]);
}

#[test]
fn a_legal_decision_is_shown_next_to_its_dispute_and_changes_nothing() {
    let (filing, filed) = dispute(DisputeAction::Filed, None, 1, false);
    let (_, referred) = dispute(DisputeAction::ReferredLegal, Some(filing), 1, false);
    let stage = run(&[filed, referred, decision(filing, THE_COURT)]);
    assert!(stage.refused().is_empty(), "{:?}", stage.refused());
    let d = &stage.disputes()[0];
    // Referred to the legal track: still unresolved for the machine.
    assert_eq!(d.status, DisputeStatus::ReferredLegal);
    assert!(d.is_unresolved());
    assert_eq!(d.events, seqs(&[3, 4]));
    assert_eq!(
        d.decisions,
        [Decision {
            seq: Seq::new(5).unwrap(),
            authority_id: OrgId::new(b"COURT").unwrap(),
            document_hash: Hash512([0x5D; 64]),
            outcome: LegalOutcome::Upheld,
            tally_effect: TallyEffect::NoEffect,
            decided_day: Day::new(20_050),
        }]
    );
    assert_eq!(
        stage.holds(),
        HoldSet::empty().with(HoldReason::OpenDispute)
    );
    // A decision on an open dispute is shown too.
    let stage = run(&[filed, decision(filing, THE_COURT)]);
    assert_eq!(stage.disputes()[0].decisions.len(), 1);
    assert_eq!(stage.disputes()[0].status, DisputeStatus::Open);
    assert!(stage.refused().is_empty());
}

#[test]
fn a_decision_that_cannot_be_taken_holds_the_ledger() {
    let (filing, filed) = dispute(DisputeAction::Filed, None, 1, false);
    let cases: [(&str, &'static [u8]); 5] = [
        (
            "a key the roster does not register for the court",
            decision(
                filing,
                Signer {
                    key: SPARE_BASE,
                    ..THE_COURT
                },
            ),
        ),
        (
            "a roster member who is not a legal authority",
            decision(
                filing,
                Signer {
                    id: b"clerk-1",
                    org: b"ORG-ST",
                    key: CLERK,
                    body_org: b"ORG-ST",
                },
            ),
        ),
        (
            "an organisation other than the roster's",
            decision(
                filing,
                Signer {
                    org: b"NEC",
                    ..THE_COURT
                },
            ),
        ),
        (
            "a body naming another authority",
            decision(
                filing,
                Signer {
                    body_org: b"OTHER",
                    ..THE_COURT
                },
            ),
        ),
        (
            "no dispute filed by that hash",
            decision(Hash512([0x77; 64]), THE_COURT),
        ),
    ];
    for (case, bad) in cases {
        let stage = run(&[filed, bad]);
        assert_eq!(stage.refused(), seqs(&[4]), "{case}");
        assert!(stage.disputes()[0].decisions.is_empty(), "{case}");
        assert_eq!(
            stage.holds(),
            HoldSet::empty()
                .with(HoldReason::OpenDispute)
                .with(HoldReason::DisputeRefused),
            "{case}"
        );
    }
    // A decision before the filing it names.
    let stage = run(&[decision(filing, THE_COURT), filed]);
    assert_eq!(stage.refused(), seqs(&[3]));
    assert!(stage.disputes()[0].decisions.is_empty());
}

#[test]
fn a_dispute_event_that_cannot_be_taken_is_refused_and_changes_nothing() {
    let (filing, filed) = dispute(DisputeAction::Filed, None, 1, false);
    // A forged filing opens nothing.
    let (_, forged) = dispute(DisputeAction::Filed, None, 2, true);
    let stage = run(&[forged]);
    assert!(stage.disputes().is_empty());
    assert_eq!(stage.refused(), seqs(&[3]));
    assert_eq!(
        stage.holds(),
        HoldSet::empty().with(HoldReason::DisputeRefused)
    );
    // A forged resolution does not resolve; a filing taken twice is not
    // filed again.
    let (_, forged) = dispute(DisputeAction::ResolvedTechnical, Some(filing), 1, true);
    let stage = run(&[filed, forged]);
    assert_eq!(stage.refused(), seqs(&[4]));
    assert_eq!(stage.disputes()[0].status, DisputeStatus::Open);
    assert_eq!(stage.disputes()[0].events, seqs(&[3]));
    // The same filing body again, under fresh signatures (another event
    // object, so not a replay): refused, the dispute unchanged.
    let (again_filing, again) = dispute_signed(DisputeAction::Filed, None, 1, false, 7);
    assert_eq!(again_filing, filing);
    assert_ne!(object_hash(again), object_hash(filed));
    let (_, investigating) = dispute(DisputeAction::Investigating, Some(filing), 1, false);
    let stage = run(&[filed, investigating, again]);
    assert_eq!(stage.refused(), seqs(&[5]));
    assert_eq!(stage.disputes().len(), 1);
    assert_eq!(stage.disputes()[0].status, DisputeStatus::Investigating);
    assert_eq!(stage.disputes()[0].events, seqs(&[3, 4]));
}
