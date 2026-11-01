//! Legal authorization, capabilities, disputes, the tally gates and the
//! legal reference against real signatures.
// Integration tests: outside the TCB. Assertions use unwrap/expect, so these
// lints are relaxed for this file only (CONSTITUTION.md §1.1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::{By, election, leak, leak_slice, sign, signed_authorization, today, witnessed};
use ityv_crypto::{HybridSigningKey, Purpose, verify_hybrid};
use ityv_encoding::{
    Day, DisputeAction, DisputeEventBody, DisputeEventParts, EventRole, Hash512,
    LegalAuthorizationBody, LegalDecisionRefBody, LegalDecisionRefParts, LegalOutcome, OrgId,
    SCHEMA_DISPUTE_EVENT_BODY, SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_LEGAL_DECISION_REF_BODY,
    SCHEMA_VERSION_1, Scope, ScopeSet, TallyEffect, TimeBucket, encode_object,
};
use ityv_state::{
    BallotMark, Bodies, CryptoTallyAid, Dispute, DisputeEvent, DisputeStatus, DisputeType, Error,
    LATE_CLOSE_WINDOW, LegalReference, PublicBoard, Rla, Signed, TallyReadiness, VoterCode,
    admit_aggregate_opening, admit_tally_scope, authorize,
};

struct Signers {
    commission: &'static HybridSigningKey,
    committee: &'static HybridSigningKey,
}

fn signers() -> Signers {
    Signers {
        commission: leak(HybridSigningKey::from_seeds([20; 32], [21; 32])),
        committee: leak(HybridSigningKey::from_seeds([22; 32], [23; 32])),
    }
}

fn object(scopes: ScopeSet) -> &'static [u8] {
    let body = LegalAuthorizationBody::new(
        election(),
        scopes,
        Hash512([1; 64]),
        Day::new(90),
        Day::new(110),
    )
    .unwrap();
    let mut buf = std::vec![0u8; 512];
    let len = encode_object(
        SCHEMA_LEGAL_AUTHORIZATION,
        SCHEMA_VERSION_1,
        &body,
        &mut buf,
    )
    .unwrap();
    buf.truncate(len);
    leak_slice(buf)
}

fn stage2() -> ScopeSet {
    ScopeSet::from_slice(&[Scope::PublicBoard, Scope::TrusteeBody, Scope::BallotMark])
}

/// Signs `object` with `key` under `purpose` and verifies it.
fn token(
    key: &'static HybridSigningKey,
    purpose: &'static [u8],
    object: &'static [u8],
) -> ityv_crypto::Verified<ityv_crypto::HybridSigned<'static>> {
    let purpose = leak(Purpose::new(purpose).unwrap());
    let signature = leak(sign(key, purpose, object));
    let vk = leak(key.verifying_key());
    verify_hybrid(vk, purpose, object, signature).unwrap()
}

#[test]
fn authorize_rejects_keys_sharing_a_half() {
    let obj = object(stage2());
    let commission = leak(HybridSigningKey::from_seeds([30; 32], [31; 32]));
    let commission_vk = commission.verifying_key();
    let t1 = token(commission, b"legal-auth", obj);
    // Same Ed25519 half, different ML-DSA-87 half.
    let shared_ed = leak(HybridSigningKey::from_seeds([32; 32], [31; 32]));
    // Same ML-DSA-87 half, different Ed25519 half.
    let shared_ml = leak(HybridSigningKey::from_seeds([30; 32], [33; 32]));
    for other in [shared_ed, shared_ml] {
        let vk = other.verifying_key();
        let t2 = token(other, b"legal-auth", obj);
        assert_eq!(
            authorize(obj, &t1, &commission_vk, &t2, &vk).unwrap_err(),
            Error::SignatureSigner
        );
    }
    let distinct = leak(HybridSigningKey::from_seeds([32; 32], [33; 32]));
    let t2 = token(distinct, b"legal-auth", obj);
    assert!(authorize(obj, &t1, &commission_vk, &t2, &distinct.verifying_key()).is_ok());
}

#[test]
fn authorize_checks_both_signatures() {
    let s = signers();
    let obj = object(stage2());
    let commission_vk = s.commission.verifying_key();
    let committee_vk = s.committee.verifying_key();
    let t1 = token(s.commission, b"legal-auth", obj);
    let t2 = token(s.committee, b"legal-auth", obj);
    let auth = authorize(obj, &t1, &commission_vk, &t2, &committee_vk).unwrap();
    assert_eq!(auth.election_id(), election());
    assert_eq!(auth.scopes(), stage2());
    assert_eq!(auth.effective_from_day(), Day::new(90));
    assert_eq!(auth.effective_until_day(), Day::new(110));
    assert!(auth.grant::<BallotMark>(Day::new(100)).is_ok());
    assert_eq!(
        auth.grant::<Rla>(Day::new(100)).unwrap_err(),
        Error::ScopeMissing(Scope::Rla)
    );

    // The same key twice is one signer.
    assert_eq!(
        authorize(obj, &t1, &commission_vk, &t1, &commission_vk).unwrap_err(),
        Error::SignatureSigner
    );
    // Swapped tokens come from the wrong keys.
    assert_eq!(
        authorize(obj, &t2, &commission_vk, &t1, &committee_vk).unwrap_err(),
        Error::SignatureSigner
    );
    assert_eq!(
        authorize(obj, &t1, &commission_vk, &t1, &committee_vk).unwrap_err(),
        Error::SignatureSigner
    );
    // Wrong purpose, for either signer.
    let p1 = token(s.commission, b"legal-decision", obj);
    let p2 = token(s.committee, b"genesis", obj);
    assert_eq!(
        authorize(obj, &p1, &commission_vk, &t2, &committee_vk).unwrap_err(),
        Error::SignatureObject
    );
    assert_eq!(
        authorize(obj, &t1, &commission_vk, &p2, &committee_vk).unwrap_err(),
        Error::SignatureObject
    );
    // A token over another object, for either signer.
    let other = object(ScopeSet::from_slice(&[Scope::PublicBoard]));
    let o1 = token(s.commission, b"legal-auth", other);
    let o2 = token(s.committee, b"legal-auth", other);
    assert_eq!(
        authorize(obj, &o1, &commission_vk, &t2, &committee_vk).unwrap_err(),
        Error::SignatureObject
    );
    assert_eq!(
        authorize(obj, &t1, &commission_vk, &o2, &committee_vk).unwrap_err(),
        Error::SignatureObject
    );
}

#[test]
fn authorize_decodes_and_checks_scopes() {
    let s = signers();
    let commission_vk = s.commission.verifying_key();
    let committee_vk = s.committee.verifying_key();
    let garbage: &'static [u8] = leak_slice(std::vec![0u8; 40]);
    let g1 = token(s.commission, b"legal-auth", garbage);
    let g2 = token(s.committee, b"legal-auth", garbage);
    assert_eq!(
        authorize(garbage, &g1, &commission_vk, &g2, &committee_vk).unwrap_err(),
        Error::Decode
    );
    // VOTER_CODE without BALLOT_MARK (VC-008).
    let skipped = object(ScopeSet::from_slice(&[
        Scope::PublicBoard,
        Scope::TrusteeBody,
        Scope::VoterCode,
    ]));
    let k1 = token(s.commission, b"legal-auth", skipped);
    let k2 = token(s.committee, b"legal-auth", skipped);
    assert_eq!(
        authorize(skipped, &k1, &commission_vk, &k2, &committee_vk).unwrap_err(),
        Error::ScopePrerequisite {
            scope: Scope::VoterCode,
            requires: Scope::BallotMark
        }
    );
}

fn decision_object(dispute_hash: Hash512, tally_effect: TallyEffect) -> &'static [u8] {
    common::object(
        SCHEMA_LEGAL_DECISION_REF_BODY,
        &LegalDecisionRefBody::new(&LegalDecisionRefParts {
            election_id: election(),
            authority_id: OrgId::new(b"COURT").unwrap(),
            decision_doc_hash: Hash512([5; 64]),
            dispute_hash,
            outcome: LegalOutcome::Upheld,
            tally_effect,
            decided_day: Day::new(120),
        })
        .unwrap(),
    )
}

#[test]
fn legal_reference_needs_the_authority_signature() {
    let authority = leak(HybridSigningKey::from_seeds([30; 32], [31; 32]));
    let authority_vk = authority.verifying_key();
    let decision = decision_object(Hash512([6; 64]), TallyEffect::Exclude);
    let signed = leak(token(authority, b"legal-decision", decision));
    let reference = LegalReference::from_signed(signed, &authority_vk).unwrap();
    assert_eq!(reference.object(), decision);
    assert_eq!(reference.authority(), &authority_vk);
    assert_eq!(reference.outcome(), LegalOutcome::Upheld);
    assert_eq!(reference.tally_effect(), TallyEffect::Exclude);
    assert_eq!(reference.body().dispute_hash, Hash512([6; 64]));
    assert_eq!(LegalReference::NAME, "LEGAL_CERTIFIED");
    let wrong_purpose = leak(token(authority, b"dispute", decision));
    assert_eq!(
        LegalReference::from_signed(wrong_purpose, &authority_vk).unwrap_err(),
        Error::SignatureObject
    );
    let stranger = leak(HybridSigningKey::from_seeds([32; 32], [33; 32]));
    let forged = leak(token(stranger, b"legal-decision", decision));
    assert_eq!(
        LegalReference::from_signed(forged, &authority_vk).unwrap_err(),
        Error::SignatureSigner
    );
    // The object must be a canonical LegalDecisionRefBody.
    let opaque: &'static [u8] = b"decision object";
    let opaque = leak(token(authority, b"legal-decision", opaque));
    assert_eq!(
        LegalReference::from_signed(opaque, &authority_vk).unwrap_err(),
        Error::Decode
    );
}

#[test]
fn capabilities_from_a_signed_authorization() {
    let full = common::authorization();
    assert!(full.grant::<VoterCode>(today()).is_ok());
    assert!(full.grant::<Rla>(today()).is_ok());
    let partial = signed_authorization(ScopeSet::from_slice(&[
        Scope::PublicBoard,
        Scope::TrusteeBody,
        Scope::BallotMark,
        Scope::CryptoTallyAid,
    ]));
    let tally = partial.grant::<CryptoTallyAid>(today()).unwrap();
    let ready = TallyReadiness {
        boxes_closed: true,
        receipts_resolved: true,
        legal_resolved: true,
        last_close: TimeBucket::new(10),
        now: TimeBucket::new(11 + LATE_CLOSE_WINDOW),
    };
    assert_eq!(
        admit_tally_scope(&tally, partial.election_id(), &ready),
        Ok(())
    );
    assert_eq!(
        admit_aggregate_opening(&tally, partial.election_id(), true),
        Ok(())
    );
    assert_eq!(
        partial.grant::<Rla>(today()).unwrap_err(),
        Error::ScopeMissing(Scope::Rla)
    );
    assert_eq!(
        partial.grant::<VoterCode>(today()).unwrap_err(),
        Error::ScopeMissing(Scope::VoterCode)
    );
    assert_eq!(
        partial.grant::<PublicBoard>(Day::new(111)).unwrap_err(),
        Error::OutsideEffectiveWindow
    );
}

struct Parties {
    commission: &'static HybridSigningKey,
    committee: &'static HybridSigningKey,
    bodies: Bodies<'static>,
}

fn parties() -> Parties {
    let commission = leak(HybridSigningKey::from_seeds([50; 32], [51; 32]));
    let committee = leak(HybridSigningKey::from_seeds([52; 32], [53; 32]));
    Parties {
        commission,
        committee,
        bodies: Bodies {
            commission: common::verifying(commission),
            committee: common::verifying(committee),
        },
    }
}

fn dispute_body(
    action: DisputeAction,
    dispute_type: DisputeType,
    filing_hash: Hash512,
    result_hash: Hash512,
) -> &'static [u8] {
    common::object(
        SCHEMA_DISPUTE_EVENT_BODY,
        &DisputeEventBody::new(&DisputeEventParts {
            election_id: election(),
            action,
            dispute_type,
            box_id: Some(common::box_id()),
            record_hash: Some(Hash512([3; 64])),
            evidence_hash: Hash512([4; 64]),
            filing_hash,
            result_hash,
            time_bucket: TimeBucket::new(800),
        })
        .unwrap(),
    )
}

fn by_bodies(p: &Parties) -> [By; 2] {
    [
        By::Other(b"nec", EventRole::Commission, b"NEC", p.commission),
        By::Other(b"ivc", EventRole::Committee, b"IVC", p.committee),
    ]
}

fn filing(p: &Parties, dispute_type: DisputeType) -> Signed<'static> {
    witnessed(
        dispute_body(
            DisputeAction::Filed,
            dispute_type,
            Hash512::ZERO,
            Hash512::ZERO,
        ),
        &by_bodies(p),
    )
}

#[test]
fn disputes_need_both_bodies() {
    let p = parties();
    let auth = common::authorization();
    let board = auth.grant::<PublicBoard>(today()).unwrap();
    let code = auth.grant::<VoterCode>(today()).unwrap();
    for t in DisputeType::ALL {
        let f = filing(&p, *t);
        if *t == DisputeType::InclusionMissing {
            assert_eq!(
                Dispute::file(&f, &p.bodies, &board),
                Err(Error::ScopeMissing(Scope::VoterCode))
            );
            let d = Dispute::file_inclusion(&f, &p.bodies, &code).unwrap();
            assert_eq!(d.status(), DisputeStatus::Open);
            assert_eq!(d.dispute_type(), *t);
        } else {
            assert_eq!(
                Dispute::file_inclusion(&f, &p.bodies, &code),
                Err(Error::Mismatch)
            );
            let d = Dispute::file(&f, &p.bodies, &board).unwrap();
            assert_eq!(d.status(), DisputeStatus::Open);
            assert!(d.is_unresolved());
            assert_eq!(d.election_id(), election());
            assert_eq!(d.box_id(), Some(common::box_id()));
            assert_eq!(d.record_hash(), Some(&Hash512([3; 64])));
            assert_eq!(d.evidence_hash(), &Hash512([4; 64]));
            assert_eq!(
                d.filing_hash(),
                &ityv_crypto::hash::object_hash(f.event.body_bytes())
            );
        }
    }
    let f = filing(&p, DisputeType::Custody);
    // A capability of another election.
    let other = common::signed_authorization_for(common::other_election());
    let foreign = other.grant::<PublicBoard>(today()).unwrap();
    assert_eq!(Dispute::file(&f, &p.bodies, &foreign), Err(Error::Mismatch));
    // Keys of the bodies swapped, or one key for both.
    let swapped = Bodies {
        commission: p.bodies.committee,
        committee: p.bodies.commission,
    };
    assert_eq!(
        Dispute::file(&f, &swapped, &board),
        Err(Error::SignatureSigner)
    );
    let same = Bodies {
        commission: p.bodies.commission,
        committee: p.bodies.commission,
    };
    assert_eq!(
        Dispute::file(&f, &same, &board),
        Err(Error::SignatureSigner)
    );
    // Keys that share one half are one body.
    let half = leak(HybridSigningKey::from_seeds([54; 32], [51; 32]));
    let shared = Bodies {
        commission: p.bodies.commission,
        committee: common::verifying(half),
    };
    assert_eq!(
        Dispute::file(&f, &shared, &board),
        Err(Error::SignatureSigner)
    );
    // A token missing.
    let short = Signed {
        event: f.event,
        tokens: &f.tokens[..1],
    };
    assert_eq!(
        Dispute::file(&short, &p.bodies, &board),
        Err(Error::Unverified)
    );
    // Not a dispute event, or not a filing.
    let not_dispute = common::audit(0, 0);
    assert_eq!(
        Dispute::file(&not_dispute, &p.bodies, &board),
        Err(Error::Decode)
    );
    let investigating = witnessed(
        dispute_body(
            DisputeAction::Investigating,
            DisputeType::Custody,
            Hash512([9; 64]),
            Hash512::ZERO,
        ),
        &by_bodies(&p),
    );
    assert_eq!(
        Dispute::file(&investigating, &p.bodies, &board),
        Err(Error::DisputeFiling)
    );
}

#[test]
fn dispute_status_changes_are_signed() {
    let p = parties();
    let auth = common::authorization();
    let board = auth.grant::<PublicBoard>(today()).unwrap();
    let f = filing(&p, DisputeType::Custody);
    let d = Dispute::file(&f, &p.bodies, &board).unwrap();
    let filing_hash = *d.filing_hash();
    let step = |action, result| {
        witnessed(
            dispute_body(action, DisputeType::Custody, filing_hash, result),
            &by_bodies(&p),
        )
    };
    let d = d
        .record(
            &step(DisputeAction::Investigating, Hash512::ZERO),
            &p.bodies,
        )
        .unwrap();
    assert_eq!(d.status(), DisputeStatus::Investigating);
    // A second filing, an event for another filing, or another type.
    assert_eq!(d.record(&f, &p.bodies), Err(Error::Mismatch));
    let elsewhere = witnessed(
        dispute_body(
            DisputeAction::ResolvedTechnical,
            DisputeType::Custody,
            Hash512([8; 64]),
            Hash512([7; 64]),
        ),
        &by_bodies(&p),
    );
    assert_eq!(d.record(&elsewhere, &p.bodies), Err(Error::Mismatch));
    let retyped = witnessed(
        dispute_body(
            DisputeAction::ResolvedTechnical,
            DisputeType::Postal,
            filing_hash,
            Hash512([7; 64]),
        ),
        &by_bodies(&p),
    );
    assert_eq!(d.record(&retyped, &p.bodies), Err(Error::Mismatch));
    // Signed by one body only (a stranger in the committee's place).
    let stranger = leak(HybridSigningKey::from_seeds([56; 32], [57; 32]));
    let half_signed = witnessed(
        dispute_body(
            DisputeAction::ResolvedTechnical,
            DisputeType::Custody,
            filing_hash,
            Hash512([7; 64]),
        ),
        &[
            By::Other(b"nec", EventRole::Commission, b"NEC", p.commission),
            By::Other(b"ivc", EventRole::Committee, b"IVC", stranger),
        ],
    );
    assert_eq!(
        d.record(&half_signed, &p.bodies),
        Err(Error::SignatureSigner)
    );
    // An illegal step.
    assert_eq!(
        d.record(
            &step(DisputeAction::Investigating, Hash512::ZERO),
            &p.bodies
        ),
        Err(Error::DisputeTransition {
            from: DisputeStatus::Investigating,
            event: DisputeEvent::Investigate
        })
    );
    let resolved = d
        .record(
            &step(DisputeAction::ResolvedTechnical, Hash512([7; 64])),
            &p.bodies,
        )
        .unwrap();
    assert!(!resolved.is_unresolved());
    // The appeal goes to the legal track and stays unresolved.
    let referred = resolved
        .record(
            &step(DisputeAction::ReferredLegal, Hash512([6; 64])),
            &p.bodies,
        )
        .unwrap();
    assert_eq!(referred.status(), DisputeStatus::ReferredLegal);
    assert!(referred.is_unresolved());
    // A decision names the filing; it does not change the status.
    let authority = leak(HybridSigningKey::from_seeds([58; 32], [59; 32]));
    let decision = decision_object(filing_hash, TallyEffect::NoEffect);
    let signed = leak(token(authority, b"legal-decision", decision));
    let reference = LegalReference::from_signed(signed, common::verifying(authority)).unwrap();
    assert!(reference.concerns(&referred));
    assert!(referred.is_unresolved());
    let other = decision_object(Hash512([1; 64]), TallyEffect::NoEffect);
    let other = leak(token(authority, b"legal-decision", other));
    let other = LegalReference::from_signed(other, common::verifying(authority)).unwrap();
    assert!(!other.concerns(&referred));
}
