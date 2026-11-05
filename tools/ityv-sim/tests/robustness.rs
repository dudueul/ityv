//! The console's WASM wrapper never panics and always writes valid JSON,
//! whatever the bundle: byte mutations and truncations of a real bundle,
//! a hostile scenario name, counts that overflow when summed. And the
//! values the wrapper composes stay honest: a tally unit reads better than
//! the ledger only when every ledger hold is on other units' boxes, the
//! copied tally-refusal mapping matches the verifier, and the console's
//! hold names are ityv-state's.
// Integration tests: outside the TCB. Assertions use unwrap, indexing
// and plain arithmetic.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation
)]

use std::panic::{AssertUnwindSafe, catch_unwind};

use ityv_encoding::{
    ProgressBody, ProgressTick, SCHEMA_PROGRESS_TICK, SCHEMA_VERSION_1, decode_object,
};
use ityv_sim::ledger::Step;
use ityv_sim::scenarios::{Scenario, Set, scenarios};
use ityv_sim::util::{Dice, leak_str};
use ityv_sim::{bundle, genesis, ledger, publications, verify};
use ityv_state::{HoldReason, Status};
use ityv_verify::{AuditEvent, TallyEvent};

// ---------------------------------------------------------------------
// A minimal JSON validator (no dependency): the whole text is one value.

fn ws(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && matches!(b[i], b' ' | b'\n' | b'\r' | b'\t') {
        i += 1;
    }
    i
}

fn string(b: &[u8], mut i: usize) -> Option<usize> {
    if b.get(i) != Some(&b'"') {
        return None;
    }
    i += 1;
    while i < b.len() {
        match b[i] {
            b'"' => return Some(i + 1),
            b'\\' => {
                let e = *b.get(i + 1)?;
                if e == b'u' {
                    let hex = b.get(i + 2..i + 6)?;
                    if !hex.iter().all(u8::is_ascii_hexdigit) {
                        return None;
                    }
                    i += 6;
                } else if b"\"\\/bfnrt".contains(&e) {
                    i += 2;
                } else {
                    return None;
                }
            }
            c if c < 0x20 => return None,
            _ => i += 1,
        }
    }
    None
}

fn value(b: &[u8], i: usize) -> Option<usize> {
    let i = ws(b, i);
    match *b.get(i)? {
        b'{' => {
            let mut i = ws(b, i + 1);
            if b.get(i) == Some(&b'}') {
                return Some(i + 1);
            }
            loop {
                i = ws(b, string(b, ws(b, i))?);
                if b.get(i) != Some(&b':') {
                    return None;
                }
                i = ws(b, value(b, i + 1)?);
                match b.get(i)? {
                    b',' => i += 1,
                    b'}' => return Some(i + 1),
                    _ => return None,
                }
            }
        }
        b'[' => {
            let mut i = ws(b, i + 1);
            if b.get(i) == Some(&b']') {
                return Some(i + 1);
            }
            loop {
                i = ws(b, value(b, i)?);
                match b.get(i)? {
                    b',' => i += 1,
                    b']' => return Some(i + 1),
                    _ => return None,
                }
            }
        }
        b'"' => string(b, i),
        b't' => b.get(i..i + 4).filter(|w| *w == b"true").map(|_| i + 4),
        b'f' => b.get(i..i + 5).filter(|w| *w == b"false").map(|_| i + 5),
        b'n' => b.get(i..i + 4).filter(|w| *w == b"null").map(|_| i + 4),
        b'-' | b'0'..=b'9' => {
            let mut j = i + 1;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            Some(j)
        }
        _ => None,
    }
}

fn valid_json(text: &str) -> bool {
    let b = text.as_bytes();
    value(b, 0).is_some_and(|end| ws(b, end) == b.len())
}

/// Runs the wrapper over `bytes`; it must return, with valid JSON.
fn wrap(bytes: &[u8]) -> String {
    let out = catch_unwind(AssertUnwindSafe(|| {
        ityv_wasm::verify(bytes, None, true).json
    }));
    let json =
        out.unwrap_or_else(|_| panic!("ityv_wasm::verify panicked on {} bytes", bytes.len()));
    assert!(
        valid_json(&json),
        "invalid JSON: {}",
        &json[..json.len().min(300)]
    );
    json
}

fn quick(name: &str) -> Scenario {
    scenarios(Set::Quick)
        .into_iter()
        .find(|s| s.name == name)
        .unwrap()
}

#[test]
fn every_quick_report_is_valid_json() {
    for s in scenarios(Set::Quick) {
        wrap(&bundle::encode(&s, ledger(&s)));
    }
}

#[test]
fn mutated_and_truncated_bundles_never_panic() {
    let s = quick("quick-clean");
    let bytes = bundle::encode(&s, ledger(&s));
    let mut dice = Dice::new("mutation", &[]);
    let len = bytes.len() as u64;
    // Structure first (magic, version, section tags and lengths, the first
    // objects), then anywhere.
    for k in 0..56u64 {
        let mut m = bytes.clone();
        let pos = if k < 20 {
            dice.below(256)
        } else {
            dice.below(len)
        } as usize;
        m[pos] ^= 1 << dice.below(8);
        if k % 7 == 0 {
            m[pos] = 0xff;
        }
        wrap(&m);
    }
    for cut in [
        0usize,
        1,
        8,
        9,
        10,
        11,
        12,
        14,
        18,
        64,
        200,
        1000,
        bytes.len() / 2,
        bytes.len() - 1,
    ] {
        let json = wrap(&bytes[..cut]);
        assert!(json.contains("\"error\":\"bundle: "), "cut {cut}");
    }
    // Extra bytes after the last section are refused.
    let mut long = bytes.clone();
    long.push(0);
    assert!(wrap(&long).contains("\"error\":\"bundle: Truncated\""));
}

#[test]
fn a_hostile_scenario_name_stays_one_escaped_string() {
    let mut s = quick("quick-clean");
    s.name = leak_str(
        "<img src=x onerror=\"document.title='PWNED'\">\"},\"status\":\"PAPER_AUDITED\",\"x\":\"\\\u{1}\u{2028}\u{2029}\u{7f}"
            .to_owned(),
    );
    let json = wrap(&bundle::encode(&s, ledger(&s)));
    assert!(!json.contains("\"status\":\"PAPER_AUDITED\""));
    assert!(json.contains("\"status\":\"CRYPTO_TALLY_VERIFIED\""));
    assert!(json.contains("\\u2028\\u2029\\u007f"));
    assert!(json.contains("onerror=\\\"document.title"));
}

/// Both boxes of the two-box station report `sheets_in = 2^63` from the
/// first slot: their sum does not fit in 64 bits.
#[test]
fn counts_whose_sum_overflows_are_reported_not_trapped() {
    let mut s = quick("quick-clean");
    let e = s.election;
    let station = e.stations.iter().find(|st| st.boxes.len() >= 2).unwrap();
    let open = e.days[e.station_index(station.id)].open_slot;
    for step in &mut s.steps {
        let Step::Event { schema, event, .. } = step else {
            continue;
        };
        if *schema != SCHEMA_PROGRESS_TICK {
            continue;
        }
        let tick: ProgressTick<'_> =
            decode_object(SCHEMA_PROGRESS_TICK, SCHEMA_VERSION_1, event).unwrap();
        if let ProgressBody::Box(b) = tick.body() {
            let p = *b.parts();
            let bi = e.box_index(std::str::from_utf8(p.box_id.as_bytes()).unwrap());
            if station.boxes.contains(&bi) && p.slot >= open {
                *event = e.box_tick(bi, p.slot, 1 << 63, p.state);
            }
        }
    }
    let l = ledger(&s);
    let direct = ityv_sim::outcome(&verify(&s, l));
    assert_eq!(direct.0, Status::HoldReview);
    let v = ityv_wasm::verify(&bundle::encode(&s, l), None, true);
    assert!(valid_json(&v.json));
    assert_eq!(v.status(), Some(direct.0.name()));
    assert!(v.json.contains("\"overflow\":true"));
    assert!(v.json.contains("\"sheetsIn\":null"));
}

/// One box of a two-box station reports `sheets_in = u64::MAX` from its
/// fourth slot on (the reviewer's "one device" bundle): the other box's
/// small count makes the station's sum overflow.
#[test]
fn one_box_at_u64_max_is_reported_not_trapped() {
    let mut s = quick("quick-clean");
    let e = s.election;
    let station = e.stations.iter().find(|st| st.boxes.len() >= 2).unwrap();
    let target = station.boxes[0];
    let open = e.days[e.station_index(station.id)].open_slot;
    let mut replaced = 0;
    for step in &mut s.steps {
        let Step::Event { schema, event, .. } = step else {
            continue;
        };
        if *schema != SCHEMA_PROGRESS_TICK {
            continue;
        }
        let tick: ProgressTick<'_> =
            decode_object(SCHEMA_PROGRESS_TICK, SCHEMA_VERSION_1, event).unwrap();
        if let ProgressBody::Box(b) = tick.body() {
            let p = *b.parts();
            let bi = e.box_index(std::str::from_utf8(p.box_id.as_bytes()).unwrap());
            if bi == target && p.slot >= open + 3 {
                *event = e.box_tick(bi, p.slot, u64::MAX, p.state);
                replaced += 1;
            }
        }
    }
    assert!(replaced > 0);
    let l = ledger(&s);
    let direct = ityv_sim::outcome(&verify(&s, l));
    let v = ityv_wasm::verify(&bundle::encode(&s, l), None, true);
    assert!(valid_json(&v.json));
    assert_eq!(v.status(), Some(direct.0.name()));
    assert!(v.json.contains("\"overflow\":true"));
    // The box's own count is exact (a string above 2^53 - 1).
    assert!(v.json.contains("\"18446744073709551615\""));
}

#[test]
fn a_unit_reads_better_than_the_ledger_only_when_every_hold_is_elsewhere() {
    let mut exercised = 0;
    for s in scenarios(Set::Quick) {
        let l = ledger(&s);
        let report = verify(&s, l);
        let g = genesis(&s);
        let units = ityv_wasm::unit_statuses(g, &report, publications(&s));
        let look = ityv_wasm::Lookup::new(&report);
        let ledger_status = report.status();
        for (i, u) in units.iter().enumerate() {
            assert!(
                ledger_status.holds().is_superset_of(u.status.holds()),
                "{}: unit holds beyond the ledger's",
                s.name
            );
            assert!(!u.boxes.is_empty(), "{}: a unit without boxes", s.name);
            // A unit reads PAPER_AUDITED only when its own style's audit
            // concluded.
            if u.status.status() == Status::PaperAudited {
                let audit = report.audit();
                assert!(
                    audit.style(&u.style).is_some_and(|st| audit.concluded(st)),
                    "{}: unit audited without its style's audit",
                    s.name
                );
            }
            if ledger_status.status() == Status::HoldReview
                && u.status.status() != Status::HoldReview
            {
                exercised += 1;
                // A unit's own reasons: its boxes', its tally's and its
                // ballot style's audit's.
                let tallies = report.tally().units();
                let carries = |k: usize, r: HoldReason| {
                    tallies[k].holds.contains(r)
                        || units[k].boxes.iter().any(|b| look.box_holds(b).contains(r))
                        || report
                            .audit()
                            .style(&units[k].style)
                            .is_some_and(|st| st.holds.contains(r))
                };
                for r in ledger_status.holds().iter() {
                    let elsewhere = (0..units.len()).filter(|k| *k != i).any(|k| carries(k, r));
                    let here = carries(i, r);
                    assert!(
                        elsewhere && !here,
                        "{}: unit {:?} reads {} although {r:?} is not only on other units' boxes",
                        s.name,
                        String::from_utf8_lossy(&u.unit),
                        u.status.status().name()
                    );
                }
            }
        }
    }
    assert!(
        exercised > 0,
        "no scenario has a unit outside the ledger's hold"
    );
}

/// The console attributes a refused tally or audit event's hold to the
/// whole ledger through the verifier's own mapping (`TallyEvent::hold`,
/// `AuditEvent::hold`); every refusal the scenarios produce is held so.
#[test]
fn refused_events_hold_what_the_verifier_maps_them_to() {
    let mut tally: Vec<TallyEvent> = Vec::new();
    let mut audit: Vec<AuditEvent> = Vec::new();
    for s in scenarios(Set::Quick) {
        let report = verify(&s, ledger(&s));
        for r in report.tally().refused() {
            let hold = r.event.hold();
            assert!(
                report.status().holds().contains(hold),
                "{}: {:?} refused but {hold:?} not held",
                s.name,
                r.event
            );
            assert!(report.tally().holds().contains(hold));
            if !tally.contains(&r.event) {
                tally.push(r.event);
            }
        }
        for r in report.audit().refused() {
            let hold = r.event.hold();
            assert!(
                report.status().holds().contains(hold),
                "{}: {:?} refused but {hold:?} not held",
                s.name,
                r.event
            );
            assert!(report.audit().holds().contains(hold));
            if !audit.contains(&r.event) {
                audit.push(r.event);
            }
        }
    }
    for kind in [
        TallyEvent::Scope,
        TallyEvent::Opening,
        TallyEvent::LateClose,
        TallyEvent::Receipt,
    ] {
        assert!(tally.contains(&kind), "no scenario refuses a {kind:?}");
    }
    for kind in [
        AuditEvent::Commit,
        AuditEvent::Seed,
        AuditEvent::Opening,
        AuditEvent::Comparison,
    ] {
        assert!(audit.contains(&kind), "no scenario refuses a {kind:?}");
    }
}

#[test]
fn the_console_names_every_hold_as_ityv_state_does() {
    let vocab = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../apps/ityv-console/src/vocab.ts"
    ))
    .unwrap();
    let names = ityv_wasm::hold_names();
    assert_eq!(names.len(), HoldReason::ALL.len());
    for (code, name) in names {
        let entry = format!("  {code}: {{ name: \"{name}\",");
        assert!(vocab.contains(&entry), "vocab.ts lacks `{entry}`");
    }
}
