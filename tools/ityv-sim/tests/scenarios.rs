//! Every scenario gives the outcome it expects, through the verifier
//! directly and through the console's WASM wrapper; the bundles are
//! byte-identical across runs.
// Integration tests: outside the TCB. Assertions use unwrap and indexing.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use ityv_sim::scenarios::{Scenario, Set, scenarios};
use ityv_sim::{bundle, ledger, outcome, verify};

fn names(holds: &[ityv_state::HoldReason]) -> Vec<String> {
    holds.iter().map(|h| format!("{h:?}")).collect()
}

fn check(set: Set) {
    let all = scenarios(set);
    let mut failures = Vec::new();
    for s in &all {
        let l = ledger(s);
        let report = verify(s, l);
        let (status, holds) = outcome(&report);
        let ok = status == s.expected.status && holds == s.expected.holds;
        eprintln!(
            "{:<32} expected {:<28} {:?}\n{:<32} actual   {:<28} {:?}{}",
            s.name,
            s.expected.status.name(),
            names(&s.expected.holds),
            "",
            status.name(),
            names(&holds),
            if ok { "" } else { "   <-- MISMATCH" }
        );
        if !ok {
            failures.push(s.name);
        }
        alarms_agree(s, &report);
        wasm_agrees(s, l, status.name(), &holds);
    }
    assert!(
        failures.is_empty(),
        "scenarios not as expected: {failures:?}"
    );
}

/// The verifier raises exactly the alarms the simulated days were built
/// to raise (up to the last slot on the ledger), and stops the alarms of
/// the station that used its emergency slot.
fn alarms_agree(s: &Scenario, report: &ityv_verify::Report<'_>) {
    let e = s.election;
    for (i, st) in e.stations.iter().enumerate() {
        let day = &e.days[i];
        let Some(p) = report.progress().station(st.id.as_bytes()) else {
            continue;
        };
        let last = p.last_slot.unwrap_or(0);
        let want: Vec<(u64, ityv_encoding::ProgressAlarm)> = day
            .alarms
            .iter()
            .copied()
            .filter(|(slot, _)| *slot <= last)
            .collect();
        let got: Vec<(u64, ityv_encoding::ProgressAlarm)> =
            p.alarms.iter().map(|a| (a.slot, a.alarm)).collect();
        if s.name.starts_with("attack-no-authorization") || s.name == "attack-overflow-progress" {
            continue;
        }
        assert_eq!(got, want, "{}: alarms of {}", s.name, st.id);
        if let Some(f) = day.fallback
            && f.from_slot <= last
        {
            assert!(p.suspended, "{}: {} should be suspended", s.name, st.id);
        }
    }
}

/// The console's wrapper reads the bundle and reports the same status and
/// holds.
fn wasm_agrees(
    s: &Scenario,
    l: &ityv_sim::ledger::Ledger,
    status: &str,
    holds: &[ityv_state::HoldReason],
) {
    let bytes = bundle::encode(s, l);
    let v = ityv_wasm::verify(&bytes, None, true);
    assert!(
        v.json.contains(&format!("\"status\":\"{status}\"")),
        "{}: {}",
        s.name,
        &v.json[..v.json.len().min(400)]
    );
    let holds_json: Vec<String> = holds
        .iter()
        .map(|h| format!("{{\"code\":{},\"name\":\"{h:?}\"}}", h.code()))
        .collect();
    assert!(
        v.json
            .contains(&format!("\"holds\":[{}]", holds_json.join(","))),
        "{}: holds differ",
        s.name
    );
    assert!(v.json.contains(&format!("\"scenario\":\"{}\"", s.name)));
}

#[test]
fn every_quick_scenario_gives_its_expected_outcome() {
    check(Set::Quick);
}

/// The large demonstration elections (minutes in a debug build; run with
/// `cargo test -p ityv-sim --release -- --ignored`).
#[test]
#[ignore = "large; run with --release -- --ignored"]
fn every_full_scenario_gives_its_expected_outcome() {
    check(Set::Full);
}

#[test]
fn bundles_are_byte_identical_across_runs() {
    let a = scenarios(Set::Quick);
    let first: Vec<Vec<u8>> = a.iter().map(|s| bundle::encode(s, ledger(s))).collect();
    // A second lay-down of the same plans, and a second build of the plans
    // themselves, give the same bytes.
    let b = scenarios(Set::Quick);
    for (s, bytes) in b.iter().zip(&first) {
        assert_eq!(&bundle::encode(s, ledger(s)), bytes, "{}", s.name);
    }
    assert!(first.iter().all(|b| b.starts_with(bundle::MAGIC)));
    // An election built afresh (not the cached one) lays down the same
    // ledger, byte for byte.
    let fresh = ityv_sim::election::Election::build(ityv_sim::catalog::quick(Vec::new()));
    let steps = ityv_sim::plan::plan(&fresh, ityv_sim::plan::Until::Tallied).steps;
    let again = ityv_sim::ledger::lay_down(&fresh, &steps);
    assert_eq!(again.frames, ledger(&a[0]).frames);
    assert_eq!(again.events, ledger(&a[0]).events);
}

#[test]
fn the_wasm_reader_refuses_what_is_not_a_bundle() {
    let v = ityv_wasm::verify(b"not a bundle at all", None, true);
    assert!(v.json.contains("\"error\":\"bundle: Magic\""));
    let s = &scenarios(Set::Quick)[0];
    let mut bytes = bundle::encode(s, ledger(s));
    bytes.truncate(bytes.len() - 1);
    let v = ityv_wasm::verify(&bytes, None, true);
    assert!(
        v.json.contains("\"error\":\"bundle: Truncated\""),
        "{}",
        v.json
    );
    // Another pin: the genesis stage refuses and nothing above it runs.
    let bytes = bundle::encode(s, ledger(s));
    let v = ityv_wasm::verify(&bytes, Some(ityv_encoding::Hash512([7; 64])), true);
    assert!(v.json.contains("\"ok\":false"), "{}", v.json);
    assert!(v.json.contains("\"status\":\"HOLD_REVIEW\""), "{}", v.json);
}

#[test]
fn a_clean_report_carries_checkpoints_units_records_and_inclusion() {
    let s = &scenarios(Set::Quick)[0];
    assert_eq!(s.name, "quick-clean");
    let bytes = bundle::encode(s, ledger(s));
    let v = ityv_wasm::verify(&bytes, None, true);
    for key in [
        "\"checkpoints\":{",
        "\"units\":[",
        "\"records\":[",
        "\"progress\":[",
        "\"fingerprint\":\"",
        "\"status\":\"CRYPTO_TALLY_VERIFIED\"",
    ] {
        assert!(v.json.contains(key), "{key}");
    }
    // Every record of the clean ledger is in a checkpoint, by a verified
    // proof carried in the report, with the bundle's identity beside it.
    let records = &v.json[v.json.find("\"records\":[").unwrap()..];
    assert!(records.matches("\"included\":true").count() >= 17);
    assert!(!records.contains("\"included\":false"));
    assert!(v.json.contains(&format!(
        "\"bundleHash\":\"{}\"",
        ityv_sim::util::sha3_hex(&bytes)
    )));
    // A record the last checkpoint does not cover is on the ledger but not
    // included.
    let s = scenarios(Set::Quick)
        .into_iter()
        .find(|s| s.name == "fault-missing-coverage")
        .unwrap();
    let v = ityv_wasm::verify(&bundle::encode(&s, ledger(&s)), None, true);
    let records = &v.json[v.json.find("\"records\":[").unwrap()..];
    assert!(records.contains("\"checkpoint\":null,\"included\":false"));
    assert!(records.contains("\"included\":true"));
}
