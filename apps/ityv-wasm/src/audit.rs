//! The audit section of the console's report: what `ityv_verify`'s audit
//! stage found for each ballot style, the inputs of the seed, and the
//! binding checkpoint's time against the beacon publication observed.
//!
//! Every value is the verifier's own; this module arranges it. Only public
//! information is written: the drawn records' tracking codes, boxes and
//! comparisons. No restricted opening (`SampleOpeningBody`, its choice,
//! cast id or randomness) is ever read or written here: the bundle holds
//! none, the console hands the verifier none, and the stage keeps opened
//! values to itself (it reports only whether a supplied body
//! reconstructed).
//!
//! The beacon observation comes from the bundle (the simulator's fixture
//! data) and is labelled as such; the console may verify without it.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use ityv_crypto::beacon_value;
use ityv_encoding::Hash512;
use ityv_ledger::{CLOCK_ERROR_BUCKETS, WITNESS_TIME_TOLERANCE};
use ityv_state::AuditPhase;
use ityv_verify::{AuditedRecord, Report, StyleAudit};

use crate::bundle::BeaconInput;
use crate::json::Json;
use crate::report::{fingerprint, grouped, hex, holds_json, text};

/// How many buckets the binding checkpoint must precede the beacon
/// publication by (ADR-0036 4: `binding ≤ published − 3`).
const MARGIN: u64 = WITNESS_TIME_TOLERANCE
    .saturating_add(CLOCK_ERROR_BUCKETS)
    .saturating_add(1);

/// The longest fixture output also written as text.
const MAX_TEXT: usize = 256;

fn fp(h: &Hash512) -> String {
    grouped(&fingerprint(h.as_bytes()))
}

fn len(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// Writes the phase of a style's audit.
fn write_phase(j: &mut Json, phase: Option<AuditPhase>) {
    match phase {
        Some(AuditPhase::Sampling { round }) => {
            j.object("phase");
            j.str("kind", "Sampling");
            j.num("round", u64::from(round));
            j.end_object();
        }
        Some(AuditPhase::Concluded { round }) => {
            j.object("phase");
            j.str("kind", "Concluded");
            j.num("round", u64::from(round));
            j.end_object();
        }
        Some(AuditPhase::HandCount) => {
            j.object("phase");
            j.str("kind", "HandCount");
            j.null("round");
            j.end_object();
        }
        None => j.null("phase"),
    }
}

/// Writes what the audit did with one record: its opening reference, the
/// reconstruction (never the opened values) and the comparison.
fn write_record_fields(j: &mut Json, rec: Option<&AuditedRecord<'_>>) {
    let Some(r) = rec else {
        j.null("opened");
        j.null("reconstruction");
        j.null("comparison");
        return;
    };
    j.num("opened", r.opening.get());
    j.str("reconstruction", &format!("{:?}", r.reconstruction));
    if let Some(c) = r.comparison {
        j.object("comparison");
        j.num("seq", c.seq.get());
        j.num("code", u64::from(c.code.code()));
        j.str("name", &format!("{:?}", c.code));
        j.bool("transferMark", c.transfer_mark);
        j.end_object();
    } else {
        j.null("comparison");
    }
}

/// Writes the rule a style's freeze declared and its rounds with the
/// comparisons among each round's draws.
fn write_rule(j: &mut Json, s: &StyleAudit<'_>) {
    if let Some(r) = &s.rule {
        j.object("rule");
        j.str("ruleHash", &fp(&r.rule_hash));
        j.num("riskLimitPpm", u64::from(r.risk_limit_ppm));
        j.str("beaconSource", &fp(&r.beacon_source));
        j.num("beaconRound", r.beacon_round);
        j.end_object();
    } else {
        j.null("rule");
    }
    j.array("rounds");
    if let Some(rounds) = &s.rounds {
        for (round, count) in rounds.as_slice().iter().zip(&s.counts) {
            j.begin_object();
            j.num("size", round.sample_size);
            j.num("threshold", u64::from(round.threshold));
            j.num("drawn", round.sample_size.min(s.frame_count));
            j.num("compared", count.compared);
            j.num("nonzero", count.nonzero);
            j.end_object();
        }
    }
    j.end_array();
}

/// Writes each device (box) of a style under audit.
fn write_devices(j: &mut Json, s: &StyleAudit<'_>) {
    j.array("devices");
    for d in &s.devices {
        j.begin_object();
        j.str("box", &text(d.box_id.as_bytes()));
        j.str("station", &text(d.station_id.as_bytes()));
        j.num("records", d.records);
        j.num("compared", d.compared);
        j.array("codes");
        for c in d.codes {
            j.item_num(c);
        }
        j.end_array();
        j.num("transferMarks", d.transfer_marks);
        j.opt_num(
            "fullComparisonFrom",
            d.full_comparison_from.map(ityv_encoding::Seq::get),
        );
        j.array("findings");
        for f in &d.findings {
            j.item_num(f.get());
        }
        j.end_array();
        j.bool("followedUp", d.followed_up());
        holds_json(j, "holds", d.holds);
        j.end_object();
    }
    j.end_array();
}

fn write_style(
    j: &mut Json,
    report: &Report<'_>,
    s: &StyleAudit<'_>,
    boxes: &BTreeMap<[u8; 64], String>,
) {
    let audit = report.audit();
    j.begin_object();
    j.str("style", &text(s.ballot_style_id.as_bytes()));
    j.array("units");
    for u in &s.units {
        j.item_str(&text(u.as_bytes()));
    }
    j.end_array();
    j.num("frameCount", s.frame_count);
    j.opt_str("frameRoot", s.frame_root.as_ref().map(fp).as_deref());
    j.opt_num("freeze", s.freeze.map(ityv_encoding::Seq::get));
    j.array("frameProblems");
    for p in &s.frame_problems {
        j.item_str(&format!("{p:?}"));
    }
    j.end_array();
    write_rule(j, s);
    write_phase(j, s.phase);
    j.bool("concluded", audit.concluded(s));
    j.opt_num(
        "handCountFrom",
        s.hand_count_from.map(ityv_encoding::Seq::get),
    );
    j.array("handCounts");
    for (u, seq) in &s.hand_counts {
        j.begin_object();
        j.str("unit", &text(u.as_bytes()));
        j.num("seq", seq.get());
        j.end_object();
    }
    j.end_array();
    let opened: BTreeMap<[u8; 64], &AuditedRecord<'_>> =
        s.records.iter().map(|r| (r.record_hash.0, r)).collect();
    // The drawn records in draw order: public (anyone redraws them from
    // the seed, VC-046).
    j.array("sample");
    for (position, code) in s.sample.iter().enumerate() {
        j.begin_object();
        j.num("position", len(position));
        j.str("code", &hex(code.as_bytes()));
        j.opt_str("box", boxes.get(&code.0).map(String::as_str));
        write_record_fields(j, opened.get(&code.0).copied());
        j.end_object();
    }
    j.end_array();
    // Records opened that no round draws: those of a device under full
    // comparison.
    j.array("fullComparison");
    for r in s.records.iter().filter(|r| r.position.is_none()) {
        j.begin_object();
        j.str("code", &hex(r.record_hash.as_bytes()));
        j.str("box", &text(r.box_id.as_bytes()));
        write_record_fields(j, Some(r));
        j.end_object();
    }
    j.end_array();
    write_devices(j, s);
    let n = s.reconstructions();
    j.object("reconstructions");
    j.num("opened", n.opened);
    j.num("reconstructed", n.reconstructed);
    j.num("mismatched", n.mismatched);
    j.num("notSupplied", n.not_supplied);
    j.end_object();
    holds_json(j, "holds", s.holds);
    j.end_object();
}

/// Writes the beacon observation handed to the verifier, with the beacon
/// value it gives for the designated source.
fn write_observation(j: &mut Json, observation: Option<BeaconInput<'_>>, source: Option<Hash512>) {
    let Some(o) = observation else {
        j.null("observation");
        return;
    };
    j.object("observation");
    j.bool("fixture", true);
    j.num("round", o.round);
    j.num("published", o.published);
    j.str("outputHex", &hex(o.output));
    let as_text = core::str::from_utf8(o.output)
        .ok()
        .filter(|t| t.len() <= MAX_TEXT);
    j.opt_str("outputText", as_text);
    j.opt_str(
        "beaconValue",
        source
            .map(|src| fp(&beacon_value(&src, o.round, o.output)))
            .as_deref(),
    );
    j.end_object();
}

/// Writes the commit the stage took and its binding checkpoint.
fn write_commit(j: &mut Json, report: &Report<'_>) {
    let Some(c) = report.audit().commit() else {
        j.null("commit");
        return;
    };
    j.object("commit");
    j.num("seq", c.seq.get());
    j.num("bucket", c.time_bucket.get());
    j.str("dice", &fp(&c.dice_hash));
    j.str("beaconSource", &fp(&c.beacon_source));
    j.num("beaconRound", c.beacon_round);
    let binding = c.binding.and_then(|frame| {
        report
            .checkpoints()
            .checkpoints()
            .iter()
            .find(|k| k.frame == frame)
    });
    if let Some(k) = binding {
        j.object("binding");
        j.num("frame", k.frame.get());
        j.num("seq", k.checkpoint_seq.get());
        j.num("bucket", k.time_bucket.get());
        j.str("fingerprint", &fp(&k.body_hash));
        j.end_object();
    } else {
        j.null("binding");
    }
    j.end_object();
}

/// Writes the `audit` section. `observation` is the beacon publication
/// handed to the verifier (`None` if the console verified without one);
/// `in_bundle` whether the bundle carries one.
pub(crate) fn write_audit(
    j: &mut Json,
    report: &Report<'_>,
    observation: Option<BeaconInput<'_>>,
    in_bundle: bool,
) {
    let audit = report.audit();
    let boxes: BTreeMap<[u8; 64], String> = report
        .records()
        .reports()
        .iter()
        .flat_map(|b| {
            let id = text(b.box_id.as_bytes());
            b.records
                .iter()
                .map(move |r| (r.tracking_code.0, id.clone()))
        })
        .collect();
    j.object("audit");
    j.bool("bundleHasObservation", in_bundle);
    // The designated beacon: the commit's, or any freeze's.
    let source = audit.commit().map(|c| c.beacon_source).or_else(|| {
        audit
            .styles()
            .iter()
            .find_map(|s| s.rule.map(|r| r.beacon_source))
    });
    write_observation(j, observation, source);
    j.num("margin", MARGIN);
    write_commit(j, report);
    if let Some(s) = audit.seed() {
        j.object("seed");
        j.num("seq", s.seq.get());
        j.str("seed", &fp(&s.seed));
        j.num("beaconRound", s.beacon_round);
        j.bool("beaconConfirmed", s.beacon_confirmed);
        j.end_object();
    } else {
        j.null("seed");
    }
    j.bool("passed", audit.passed());
    j.bool("allReconstructed", audit.all_reconstructed());
    j.array("styles");
    for s in audit.styles() {
        write_style(j, report, s, &boxes);
    }
    j.end_array();
    j.array("refused");
    for r in audit.refused() {
        j.begin_object();
        j.num("seq", r.seq.get());
        j.str("event", &format!("{:?}", r.event));
        j.str("refusal", &format!("{:?}", r.refusal));
        j.end_object();
    }
    j.end_array();
    j.array("stationMarks");
    for (station, marks, compared) in audit.station_marks() {
        j.begin_object();
        j.str("station", &text(station.as_bytes()));
        j.num("marks", marks);
        j.num("compared", compared);
        j.end_object();
    }
    j.end_array();
    holds_json(j, "holds", audit.holds());
    j.end_object();
}

/// The hold of each kind of refused audit event (ledger-wide: a refusal
/// does not say which style it concerns).
pub(crate) fn refused_holds(report: &Report<'_>) -> ityv_state::HoldSet {
    report
        .audit()
        .refused()
        .iter()
        .fold(ityv_state::HoldSet::empty(), |h, r| h.with(r.event.hold()))
}

/// The holds of ballot style `style`'s audit.
pub(crate) fn style_holds(report: &Report<'_>, style: &[u8]) -> ityv_state::HoldSet {
    report
        .audit()
        .style(style)
        .map_or(ityv_state::HoldSet::empty(), |s| s.holds)
}

/// Whether style `style`'s audit concluded.
pub(crate) fn style_concluded(report: &Report<'_>, style: &[u8]) -> bool {
    let audit = report.audit();
    audit.style(style).is_some_and(|s| audit.concluded(s))
}

/// Every refusal of the audit stage, for the report's list of refused
/// events: frame, and the event and why.
pub(crate) fn refusal_rows(report: &Report<'_>) -> Vec<(u64, String)> {
    report
        .audit()
        .refused()
        .iter()
        .map(|r| (r.seq.get(), format!("{:?}: {:?}", r.event, r.refusal)))
        .collect()
}
