//! Quorum profiles, rosters, and the evaluation of signed checkpoints.
// Integration-test crate: outside the TCB (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::missing_panics_doc
)]

mod common;

use common::{
    body_object, body_parts, decode_signed, roster_entries, signed_checkpoint_object, witnesses,
};
use ityv_encoding::{Hash512, Ident};
use ityv_ledger::{
    Dimension, DiversityPolicy, EMPTY_ROOT, Error, MAX_WITNESSES, QuorumProfile, Roster, evaluate,
    profile_matches_roster,
};

#[test]
fn quorum_profiles_follow_the_intersection_rule() {
    assert_eq!(
        QuorumProfile::new(13, 9, 4),
        Some(QuorumProfile::DEFAULT_13_9_4)
    );
    assert_eq!(
        QuorumProfile::new(19, 13, 6),
        Some(QuorumProfile::ALT_19_13_6)
    );
    assert!(
        QuorumProfile::new(13, 8, 4).is_none(),
        "16 − 13 = 3, not > 4"
    );
    assert!(
        QuorumProfile::new(13, 9, 5).is_none(),
        "18 − 13 = 5, not > 5"
    );
    assert!(
        QuorumProfile::new(13, 14, 0).is_none(),
        "quorum above roster"
    );
    assert!(QuorumProfile::new(13, 0, 0).is_none(), "zero quorum");
    assert!(
        QuorumProfile::new(65, 64, 0).is_none(),
        "roster above capacity"
    );
    assert_eq!(
        QuorumProfile::new(1, 1, 0).map(QuorumProfile::quorum_intersection),
        Some(1)
    );
    assert_eq!(QuorumProfile::DEFAULT_13_9_4.quorum_intersection(), 5);
    assert_eq!(QuorumProfile::ALT_19_13_6.quorum_intersection(), 7);
    assert_eq!(QuorumProfile::DEFAULT_13_9_4.witnesses(), 13);
    assert_eq!(QuorumProfile::DEFAULT_13_9_4.quorum(), 9);
    assert_eq!(QuorumProfile::DEFAULT_13_9_4.byzantine_max(), 4);
    // Exhaustive check of the rule against its arithmetic definition.
    for n in 0..=70u8 {
        for q in 0..=70u8 {
            for f in 0..=70u8 {
                let expected = q >= 1
                    && q <= n
                    && usize::from(n) <= MAX_WITNESSES
                    && 2 * u32::from(q) > u32::from(n) + u32::from(f);
                assert_eq!(QuorumProfile::is_valid(n, q, f), expected, "{n} {q} {f}");
            }
        }
    }
    let d = DiversityPolicy::DEFAULT;
    assert_eq!(
        (d.min_orgs(), d.min_providers(), d.min_regions()),
        (7, 4, 3)
    );
    assert_eq!(DiversityPolicy::new(1, 2, 3).min_regions(), 3);
}

#[test]
fn rosters_must_be_sorted_unique_and_bounded() {
    let ws = witnesses(3);
    let entries = roster_entries(&ws);
    let roster = Roster::new(&entries).unwrap();
    assert_eq!(roster.len(), 3);
    assert!(!roster.is_empty());
    assert!(roster.find(&Ident::new(b"W01", 64).unwrap()).is_some());
    assert!(roster.find(&Ident::new(b"W09", 64).unwrap()).is_none());
    let mut unsorted = roster_entries(&ws);
    unsorted.swap(0, 1);
    assert_eq!(Roster::new(&unsorted).unwrap_err(), Error::RosterInvalid);
    let mut dup = roster_entries(&ws);
    dup[1].id = dup[0].id;
    assert_eq!(Roster::new(&dup).unwrap_err(), Error::RosterInvalid);
    let many = witnesses(65);
    let entries = roster_entries(&many);
    assert_eq!(Roster::new(&entries).unwrap_err(), Error::RosterInvalid);
    assert!(Roster::new(&[]).unwrap().is_empty());
    assert!(!profile_matches_roster(
        QuorumProfile::DEFAULT_13_9_4,
        &roster
    ));
}

fn body13() -> std::vec::Vec<u8> {
    body_object(&body_parts(
        1,
        0,
        EMPTY_ROOT,
        Hash512::ZERO,
        EMPTY_ROOT,
        EMPTY_ROOT,
        Hash512([7; 64]),
        1,
    ))
}

#[test]
fn a_valid_quorum_is_accepted_and_counted() {
    let ws = witnesses(13);
    let entries = roster_entries(&ws);
    let roster = Roster::new(&entries).unwrap();
    assert!(profile_matches_roster(
        QuorumProfile::DEFAULT_13_9_4,
        &roster
    ));
    let body = body13();
    let bytes = signed_checkpoint_object(&ws, &[0, 1, 2, 3, 4, 5, 6, 7, 8], &body);
    let signed = decode_signed(&bytes);
    let published = evaluate(
        &roster,
        &QuorumProfile::DEFAULT_13_9_4,
        &DiversityPolicy::DEFAULT,
        &signed,
    )
    .unwrap();
    let p = published.get();
    assert_eq!(p.signers(), 9);
    assert_eq!(p.orgs(), 9);
    assert_eq!(p.providers(), 5);
    assert_eq!(p.regions(), 4);
    assert_eq!(p.signed().signature_count(), 9);
    assert_eq!(p.profile().quorum(), 9);
    assert_eq!(p.roster().len(), 13);
    assert_eq!(p.diversity().min_orgs(), 7);
}

#[test]
fn eight_signers_are_short_of_the_quorum() {
    let ws = witnesses(13);
    let entries = roster_entries(&ws);
    let roster = Roster::new(&entries).unwrap();
    let body = body13();
    let bytes = signed_checkpoint_object(&ws, &[0, 1, 2, 3, 4, 5, 6, 7], &body);
    let signed = decode_signed(&bytes);
    assert_eq!(
        evaluate(
            &roster,
            &QuorumProfile::DEFAULT_13_9_4,
            &DiversityPolicy::DEFAULT,
            &signed
        )
        .unwrap_err(),
        Error::QuorumShort { have: 8, need: 9 }
    );
}

#[test]
fn a_profile_that_does_not_match_the_roster_is_rejected() {
    let ws = witnesses(12);
    let entries = roster_entries(&ws);
    let roster = Roster::new(&entries).unwrap();
    let body = body13();
    let bytes = signed_checkpoint_object(&ws, &[0, 1, 2, 3, 4, 5, 6, 7, 8], &body);
    let signed = decode_signed(&bytes);
    assert_eq!(
        evaluate(
            &roster,
            &QuorumProfile::DEFAULT_13_9_4,
            &DiversityPolicy::DEFAULT,
            &signed
        )
        .unwrap_err(),
        Error::ProfileInvalid
    );
}

#[test]
fn unknown_witnesses_and_duplicates_are_rejected() {
    let ws = witnesses(14);
    // Roster of the first 13; witness 13 signs too.
    let entries = roster_entries(&ws[..13]);
    let roster = Roster::new(&entries).unwrap();
    let body = body13();
    let bytes = signed_checkpoint_object(&ws, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 13], &body);
    let signed = decode_signed(&bytes);
    assert_eq!(
        evaluate(
            &roster,
            &QuorumProfile::DEFAULT_13_9_4,
            &DiversityPolicy::DEFAULT,
            &signed
        )
        .unwrap_err(),
        Error::UnknownWitness { index: 9 }
    );
    // A duplicate identifier cannot be encoded (the parts constructor and
    // the decoder both reject it), so a signer is never counted twice.
    let mut r = common::rng(5);
    let sig = ityv_crypto::sign_hybrid(&ws[0].key, &ityv_crypto::PURPOSE_CHECKPOINT, &body, &mut r)
        .unwrap();
    let e = ityv_ledger::WitnessSignatureEntry {
        witness_id: Ident::new(b"W00", 64).unwrap(),
        signature: &sig,
    };
    assert_eq!(
        ityv_ledger::SignedCheckpointParts::new(&body, &[e, e]).unwrap_err(),
        Error::Duplicate
    );
}

#[test]
fn a_signature_over_a_different_body_fails() {
    let ws = witnesses(13);
    let entries = roster_entries(&ws);
    let roster = Roster::new(&entries).unwrap();
    let body = body13();
    let other = body_object(&body_parts(
        1,
        0,
        EMPTY_ROOT,
        Hash512::ZERO,
        EMPTY_ROOT,
        EMPTY_ROOT,
        Hash512([7; 64]),
        2,
    ));
    // Eight signatures over the body plus one over a different body (a fork
    // at the same sequence number): the object is rejected, not counted
    // as eight.
    let mut r = common::rng(9);
    let mut sigs = std::vec::Vec::new();
    for w in ws.iter().take(8) {
        sigs.push(
            ityv_crypto::sign_hybrid(&w.key, &ityv_crypto::PURPOSE_CHECKPOINT, &body, &mut r)
                .unwrap(),
        );
    }
    sigs.push(
        ityv_crypto::sign_hybrid(&ws[8].key, &ityv_crypto::PURPOSE_CHECKPOINT, &other, &mut r)
            .unwrap(),
    );
    let entries_sig: std::vec::Vec<_> = sigs
        .iter()
        .enumerate()
        .map(|(i, s)| ityv_ledger::WitnessSignatureEntry {
            witness_id: Ident::new(ws[i].id.as_bytes(), 64).unwrap(),
            signature: s,
        })
        .collect();
    let parts = ityv_ledger::SignedCheckpointParts::new(&body, &entries_sig).unwrap();
    let bytes = common::object_to_vec(ityv_ledger::SCHEMA_SIGNED_CHECKPOINT, &parts);
    let signed = decode_signed(&bytes);
    assert_eq!(
        evaluate(
            &roster,
            &QuorumProfile::DEFAULT_13_9_4,
            &DiversityPolicy::DEFAULT,
            &signed
        )
        .unwrap_err(),
        Error::InvalidSignature { index: 8 }
    );
}

#[test]
fn each_diversity_dimension_is_enforced() {
    let ws = witnesses(13);
    let entries = roster_entries(&ws);
    let roster = Roster::new(&entries).unwrap();
    let body = body13();
    let bytes = signed_checkpoint_object(&ws, &[0, 1, 2, 3, 4, 5, 6, 7, 8], &body);
    let signed = decode_signed(&bytes);
    // Nine signers span 9 orgs, 5 providers, 4 regions: a policy at exactly
    // those numbers is satisfied.
    let exact = DiversityPolicy::new(9, 5, 4);
    let published = evaluate(&roster, &QuorumProfile::DEFAULT_13_9_4, &exact, &signed).unwrap();
    assert_eq!(published.get().regions(), 4);
    let strict_orgs = DiversityPolicy::new(10, 4, 3);
    assert_eq!(
        evaluate(
            &roster,
            &QuorumProfile::DEFAULT_13_9_4,
            &strict_orgs,
            &signed
        )
        .unwrap_err(),
        Error::DiversityShort {
            dimension: Dimension::Organisations,
            have: 9,
            need: 10
        }
    );
    let strict_providers = DiversityPolicy::new(7, 6, 3);
    assert_eq!(
        evaluate(
            &roster,
            &QuorumProfile::DEFAULT_13_9_4,
            &strict_providers,
            &signed
        )
        .unwrap_err(),
        Error::DiversityShort {
            dimension: Dimension::Providers,
            have: 5,
            need: 6
        }
    );
    let strict_regions = DiversityPolicy::new(7, 4, 5);
    assert_eq!(
        evaluate(
            &roster,
            &QuorumProfile::DEFAULT_13_9_4,
            &strict_regions,
            &signed
        )
        .unwrap_err(),
        Error::DiversityShort {
            dimension: Dimension::Regions,
            have: 4,
            need: 5
        }
    );
    // Nine signers from one organisation fail the default policy.
    let mut same_org = witnesses(13);
    for w in &mut same_org {
        w.org = std::string::String::from("ORG-ONE");
    }
    let entries = roster_entries(&same_org);
    let roster = Roster::new(&entries).unwrap();
    let bytes = signed_checkpoint_object(&same_org, &[0, 1, 2, 3, 4, 5, 6, 7, 8], &body);
    let signed = decode_signed(&bytes);
    assert_eq!(
        evaluate(
            &roster,
            &QuorumProfile::DEFAULT_13_9_4,
            &DiversityPolicy::DEFAULT,
            &signed
        )
        .unwrap_err(),
        Error::DiversityShort {
            dimension: Dimension::Organisations,
            have: 1,
            need: 7
        }
    );
}
