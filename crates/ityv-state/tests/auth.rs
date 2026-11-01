//! Legal authorization, capabilities, disputes, the tally gates and the
//! legal reference against real signatures.
// Integration tests: outside the TCB. Assertions use unwrap/expect, so these
// lints are relaxed for this file only (CONSTITUTION.md §1.1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod common;

use common::{election, leak, leak_slice, sign, signed_authorization, today};
use ityv_crypto::{HybridSigningKey, Purpose, verify_hybrid};
use ityv_encoding::{
    Day, Hash512, LegalAuthorizationBody, SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, Scope,
    ScopeSet, TimeBucket, encode_object,
};
use ityv_state::{
    BallotMark, CryptoTallyAid, Dispute, DisputeFiling, DisputeType, Error, LATE_CLOSE_WINDOW,
    LegalReference, PublicBoard, Rla, TallyReadiness, VoterCode, admit_aggregate_opening,
    admit_tally_scope, authorize,
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

#[test]
fn legal_reference_needs_the_authority_signature() {
    let authority = leak(HybridSigningKey::from_seeds([30; 32], [31; 32]));
    let authority_vk = authority.verifying_key();
    let decision: &'static [u8] = b"decision object";
    let signed = leak(token(authority, b"legal-decision", decision));
    let reference = LegalReference::from_signed(signed, &authority_vk).unwrap();
    assert_eq!(reference.object(), decision);
    assert_eq!(reference.authority(), &authority_vk);
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
}

#[test]
fn capabilities_from_a_signed_authorization() {
    let auth = signed_authorization(ScopeSet::from_slice(&[
        Scope::PublicBoard,
        Scope::TrusteeBody,
        Scope::BallotMark,
        Scope::CryptoTallyAid,
        Scope::VoterCode,
    ]));
    let board = auth.grant::<PublicBoard>(today()).unwrap();
    let code = auth.grant::<VoterCode>(today()).unwrap();
    let filing = DisputeFiling {
        election_id: election(),
        dispute_type: DisputeType::InclusionMissing,
        box_id: None,
        record_hash: None,
        evidence_hash: Hash512([4; 64]),
        commission_signed: true,
        committee_signed: true,
    };
    assert!(
        Dispute::file_inclusion(&filing, &code)
            .unwrap()
            .is_unresolved()
    );
    assert_eq!(
        Dispute::file(&filing, &board).unwrap_err(),
        Error::ScopeMissing(Scope::VoterCode)
    );
    let tally = auth.grant::<CryptoTallyAid>(today()).unwrap();
    let ready = TallyReadiness {
        boxes_closed: true,
        receipts_resolved: true,
        last_close: TimeBucket::new(10),
        now: TimeBucket::new(11 + LATE_CLOSE_WINDOW),
    };
    assert_eq!(
        admit_tally_scope(&tally, auth.election_id(), &ready),
        Ok(())
    );
    assert_eq!(
        admit_aggregate_opening(&tally, auth.election_id(), true),
        Ok(())
    );
    assert_eq!(
        auth.grant::<Rla>(today()).unwrap_err(),
        Error::ScopeMissing(Scope::Rla)
    );
    assert_eq!(
        auth.grant::<PublicBoard>(Day::new(111)).unwrap_err(),
        Error::OutsideEffectiveWindow
    );
}
