//! The audit scenarios say what their audits did: the verifier's audit
//! stage over each one shows the phase, the escalation, the full
//! comparison, the hand count, the refusal the attack was built to draw,
//! and the binding checkpoint's time against the beacon publication. The
//! console's report shows the same and never carries a restricted
//! opening.
// Integration tests: outside the TCB. Assertions use unwrap and indexing.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use ityv_encoding::ComparisonCode;
use ityv_sim::scenarios::{Scenario, Set, scenarios};
use ityv_sim::{bundle, genesis, ledger, publications, verify, verify_with};
use ityv_state::{AuditPhase, HoldReason, Status};
use ityv_verify::{AuditEvent, AuditInput, AuditRefusal, Reconstruction, Report};

fn named(name: &str) -> Scenario {
    scenarios(Set::Quick)
        .into_iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("no scenario {name}"))
}

fn refused(r: &Report<'_>) -> Vec<(AuditEvent, AuditRefusal)> {
    r.audit()
        .refused()
        .iter()
        .map(|x| (x.event, x.refusal))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    ityv_sim::util::hex(bytes)
}

#[test]
fn a_clean_audit_concludes_in_the_first_round_before_the_beacon() {
    let s = named("audit-clean");
    let l = ledger(&s);
    let r = verify(&s, l);
    assert_eq!(r.status().status(), Status::PaperAudited);
    let audit = r.audit();
    assert!(audit.passed());
    assert!(audit.seed().unwrap().beacon_confirmed);
    for style in audit.styles() {
        assert_eq!(style.phase, Some(AuditPhase::Concluded { round: 0 }));
        assert!(audit.concluded(style));
        assert!(
            style
                .records
                .iter()
                .all(|x| x.comparison.unwrap().code == ComparisonCode::Match)
        );
    }
    // The binding checkpoint covers the commit, is at or after its time and
    // three or more buckets before the publication (seven here).
    let commit = audit.commit().unwrap();
    let binding = r
        .checkpoints()
        .checkpoints()
        .iter()
        .find(|k| Some(k.frame) == commit.binding)
        .unwrap();
    let published = s.beacon.unwrap().published;
    assert!(binding.time_bucket.get() >= commit.time_bucket.get());
    assert_eq!(published - binding.time_bucket.get(), 7);
    assert!(commit.time_bucket.get() < published);

    // Without the observation the audit cannot conclude, and nothing is held.
    let public = verify_with(&s, l, &AuditInput::default());
    assert_eq!(public.status().status(), Status::CryptoTallyVerified);
    assert!(public.status().holds().is_empty());
    // A verifier with access reconstructs every opening (VC-047).
    let openings = ityv_sim::util::leak_slice(s.openings.clone());
    let with_access = verify_with(
        &s,
        l,
        &AuditInput {
            beacon: ityv_sim::observation(&s),
            openings,
        },
    );
    assert_eq!(with_access.status().status(), Status::PaperAudited);
    assert!(with_access.audit().all_reconstructed());
    // The public report says it was not supplied.
    assert!(audit.styles().iter().all(|st| {
        st.records
            .iter()
            .all(|x| x.reconstruction == Reconstruction::NotSupplied)
    }));
}

#[test]
fn the_console_shows_the_audit_and_no_restricted_opening() {
    let s = named("audit-clean");
    let bytes = bundle::encode(&s, ledger(&s));
    let v = ityv_wasm::verify(&bytes, None, true);
    assert!(v.json.contains("\"status\":\"PAPER_AUDITED\""));
    for key in [
        "\"audit\":{",
        "\"observation\":{\"fixture\":true",
        "\"beaconConfirmed\":true",
        "\"binding\":{",
        "\"phase\":{\"kind\":\"Concluded\",\"round\":0}",
        "\"margin\":3",
        "\"reconstruction\":\"NotSupplied\"",
    ] {
        assert!(v.json.contains(key), "{key}");
    }
    // Nothing of a restricted body: not its bytes, not a cast id, not a
    // randomness scalar.
    for body in &s.openings {
        assert!(!v.json.contains(&hex(body)));
        let tail = &body[body.len() - 32..];
        assert!(!v.json.contains(&hex(tail)));
    }
    for casts in &s.election.casts {
        for c in casts {
            assert!(!v.json.contains(&hex(&c.cast_id.token().0)));
            assert!(!v.json.contains(&hex(&c.rand[0].to_bytes())));
        }
    }
    // Without the observation: the tally stands, the audit does not
    // conclude.
    let v = ityv_wasm::verify(&bytes, None, false);
    assert!(v.json.contains("\"status\":\"CRYPTO_TALLY_VERIFIED\""));
    assert!(v.json.contains("\"observation\":null"));
    assert!(v.json.contains("\"bundleHasObservation\":true"));
    assert!(v.json.contains("\"beaconConfirmed\":false"));
}

#[test]
fn a_misread_ballot_escalates_to_the_second_round() {
    let s = named("audit-escalation");
    let r = verify(&s, ledger(&s));
    assert_eq!(r.status().status(), Status::PaperAudited);
    let style = r.audit().style(b"S-HB").unwrap();
    assert_eq!(style.phase, Some(AuditPhase::Concluded { round: 1 }));
    assert!(style.counts[0].nonzero > u64::from(style.rounds.unwrap().as_slice()[0].threshold));
    assert_eq!(style.counts[1].compared, 8);
    // Code 3 calls for no full comparison.
    assert!(
        style
            .devices
            .iter()
            .all(|d| d.full_comparison_from.is_none())
    );
    assert!(style.devices.iter().any(|d| d.codes[3] > 0));
}

#[test]
fn past_the_last_round_every_unit_is_counted_by_hand() {
    let s = named("audit-hand-count");
    let r = verify(&s, ledger(&s));
    assert_eq!(r.status().status(), Status::PaperAudited);
    let style = r.audit().style(b"S-HB").unwrap();
    assert_eq!(style.phase, Some(AuditPhase::HandCount));
    assert!(style.hand_count_from.is_some());
    assert_eq!(style.hand_counts.len(), style.units.len());
    let v = ityv_wasm::verify(&bundle::encode(&s, ledger(&s)), None, true);
    assert!(v.json.contains("\"kind\":\"HandCount\""));
}

#[test]
fn swapped_readings_call_for_a_full_comparison_and_a_finding() {
    let s = named("fault-swapped-readings");
    let r = verify(&s, ledger(&s));
    assert_eq!(r.status().status(), Status::PaperAudited);
    let style = r.audit().style(b"S-HB").unwrap();
    let device = style
        .devices
        .iter()
        .find(|d| d.box_id.as_bytes() == b"BOX-HB-1")
        .unwrap();
    assert!(device.full_comparison_from.is_some());
    assert_eq!(device.compared, device.records);
    assert_eq!(device.codes[1], 2);
    assert_eq!(device.findings.len(), 1);
    assert!(device.followed_up());
}

#[test]
fn one_style_audited_leaves_the_ledger_at_the_tally_and_its_units_audited() {
    let s = named("audit-one-style");
    let r = verify(&s, ledger(&s));
    assert_eq!(r.status().status(), Status::CryptoTallyVerified);
    let audit = r.audit();
    assert!(audit.concluded(audit.style(b"S-HB").unwrap()));
    assert!(!audit.concluded(audit.style(b"S-NR").unwrap()));
    let units = ityv_wasm::unit_statuses(genesis(&s), &r, publications(&s));
    for u in &units {
        let want = if u.style == b"S-HB" {
            Status::PaperAudited
        } else {
            Status::CryptoTallyVerified
        };
        assert_eq!(u.status.status(), want, "{:?}", u.unit);
    }
}

#[test]
fn a_missing_ballot_holds_the_box() {
    let s = named("fault-audit-ballot-missing");
    let r = verify(&s, ledger(&s));
    let style = r.audit().style(b"S-HB").unwrap();
    assert!(style.holds.contains(HoldReason::AuditCustody));
    assert!(
        style
            .devices
            .iter()
            .any(|d| d.holds.contains(HoldReason::AuditCustody))
    );
    // The other style's units are not held for it.
    let units = ityv_wasm::unit_statuses(genesis(&s), &r, publications(&s));
    let nr = units.iter().find(|u| u.style == b"S-NR").unwrap();
    assert_eq!(nr.status.status(), Status::PaperAudited);
    let hb = units.iter().find(|u| u.style == b"S-HB").unwrap();
    assert_eq!(hb.status.status(), Status::HoldReview);
}

#[test]
fn each_attack_on_the_seed_draws_its_refusal() {
    for (name, want) in [
        (
            "attack-seed-grinding",
            (AuditEvent::Seed, AuditRefusal::Late),
        ),
        (
            "attack-binding-backdated",
            (AuditEvent::Seed, AuditRefusal::Backdated),
        ),
        (
            "fault-commit-missing",
            (AuditEvent::Seed, AuditRefusal::Premature),
        ),
        (
            "attack-commit-conflict",
            (AuditEvent::Commit, AuditRefusal::Conflict),
        ),
    ] {
        let s = named(name);
        let r = verify(&s, ledger(&s));
        let list = refused(&r);
        assert_eq!(list.first(), Some(&want), "{name}: {list:?}");
        assert_ne!(r.status().status(), Status::PaperAudited, "{name}");
        if want.0 == AuditEvent::Seed {
            assert!(r.audit().seed().is_none(), "{name}");
            // Every opening is then too early, and every comparison.
            assert!(list[1..].iter().all(|(e, why)| {
                *why == AuditRefusal::Premature
                    && matches!(e, AuditEvent::Opening | AuditEvent::Comparison)
            }));
        } else {
            assert!(r.audit().seed().is_some());
            assert_eq!(list.len(), 1);
        }
    }
    // The grinding checkpoint is two buckets before the publication.
    let s = named("attack-seed-grinding");
    let r = verify(&s, ledger(&s));
    let commit = r.audit().commit().unwrap();
    let binding = r
        .checkpoints()
        .checkpoints()
        .iter()
        .find(|k| Some(k.frame) == commit.binding)
        .unwrap();
    assert_eq!(s.beacon.unwrap().published - binding.time_bucket.get(), 2);
}
