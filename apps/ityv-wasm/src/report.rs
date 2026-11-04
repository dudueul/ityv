//! The console's report: every stage of `ityv_verify::verify_ledger` over
//! a bundle, written as JSON for display.
//!
//! The status, the holds, the stages, the checkpoints and every refusal
//! are the verifier's own values. Two things are composed here, both
//! through TCB code: the status of each tally unit (the verifier's
//! evidence narrowed to the unit's boxes and tally, handed to
//! `ityv_state::status::evaluate`), and each station's progress series
//! (the counts of the ticks the progress stage took, with `out` from
//! `ityv_state::out_of`). Neither replaces the ledger's status, which the
//! report gives first.

use std::collections::{BTreeMap, BTreeSet};

use ityv_encoding::{
    Hash512, ProgressBody, ProgressTick, SCHEMA_PROGRESS_TICK, SCHEMA_VERSION_1, ScopeSet,
    TimeBucket, decode_object,
};
use ityv_ledger::{FrameStream, check_anchor, check_board, inclusion_proof, verify_inclusion};
use ityv_state::{
    Evidence, HoldReason, HoldSet, Outcome, Publication, StatusReport, Step, evaluate, out_of,
};
use ityv_verify::{
    Publications, Report, TallyEvent, UnitTally, VerifiedGenesis, verify_genesis, verify_ledger,
};

use crate::bundle::{Bundle, decode};
use crate::json::Json;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The fingerprint notation (`ENCODING.md`, 소프트웨어 지문 표기): the
/// first 20 bytes of `hash` in Base32 (RFC 4648 alphabet, upper case, no
/// padding), 32 characters.
#[must_use]
pub fn fingerprint(hash: &[u8]) -> String {
    let mut out = String::with_capacity(32);
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    for byte in hash.iter().take(20) {
        acc = (acc << 8) | u64::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = usize::try_from((acc >> bits) & 0x1f).unwrap_or(0);
            out.push(char::from(BASE32.get(index).copied().unwrap_or(b'A')));
        }
    }
    out
}

/// `fp` cut into groups of four separated by spaces (all of it: eight
/// groups of a 32-character fingerprint).
#[must_use]
pub fn grouped(fp: &str) -> String {
    let chars: Vec<char> = fp.chars().collect();
    chars
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Lower-case hexadecimal.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            s.push(char::from(
                DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'0'),
            ));
        }
    }
    s
}

fn holds_json(j: &mut Json, key: &str, holds: HoldSet) {
    j.array(key);
    for h in holds.iter() {
        j.begin_object();
        j.num("code", u64::from(h.code()));
        j.str("name", &format!("{h:?}"));
        j.end_object();
    }
    j.end_array();
}

const fn outcome_name(o: Outcome) -> &'static str {
    match o {
        Outcome::NotRun => "NOT_RUN",
        Outcome::Passed => "PASSED",
        Outcome::Failed => "FAILED",
    }
}

fn publication_name(p: Publication) -> String {
    match p {
        Publication::Satisfied => "SATISFIED".to_owned(),
        Publication::Pending => "PENDING".to_owned(),
        Publication::Breached(b) => format!("BREACHED: {b}"),
        Publication::Failed => "FAILED".to_owned(),
    }
}

const fn step_name(s: Step) -> &'static str {
    match s {
        Step::Genesis => "Genesis",
        Step::Checkpoints => "Checkpoints",
        Step::Frames => "Frames",
        Step::BoxInvariants => "BoxInvariants",
        Step::BoxCompleteness => "BoxCompleteness",
        Step::Records => "Records",
        Step::Participation => "Participation",
        Step::Tally => "Tally",
        Step::Audit => "Audit",
        Step::Connectivity => "Connectivity",
        Step::Software => "Software",
    }
}

/// The hold a refused tally event puts on the ledger.
const fn tally_refusal_hold(event: TallyEvent) -> HoldReason {
    match event {
        TallyEvent::Receipt => HoldReason::ReceiptResolutionRefused,
        TallyEvent::Decision => HoldReason::TallyEffectRefused,
        TallyEvent::Scope => HoldReason::TallyScopeRefused,
        TallyEvent::Opening => HoldReason::AggregateRefused,
        TallyEvent::Paper => HoldReason::PaperCountRefused,
        TallyEvent::LateClose => HoldReason::LateCloseAfterScope,
    }
}

/// What inclusion proofs need after the report: every frame hash and the
/// verified checkpoints.
#[derive(Debug, Clone, Default)]
pub struct Proofs {
    frames: Vec<Hash512>,
    /// (checkpoint seq, frame, tree size, root)
    checkpoints: Vec<(u64, u64, u64, Hash512)>,
}

impl Proofs {
    /// The inclusion of frame `seq` in the first verified checkpoint
    /// that covers it, as JSON: the proof is generated and verified by
    /// `ityv-ledger` against that checkpoint's root.
    #[must_use]
    pub fn inclusion_json(&self, seq: u64) -> String {
        let mut j = Json::new();
        j.begin_object();
        j.num("seq", seq);
        let covering = self
            .checkpoints
            .iter()
            .find(|(_, _, size, _)| *size >= seq && seq > 0);
        match covering {
            None => {
                j.bool("included", false);
                j.null("checkpoint");
            }
            Some((cp_seq, frame, size, root)) => {
                let index = seq.saturating_sub(1);
                let leaf = usize::try_from(index).ok().and_then(|i| self.frames.get(i));
                let verified = leaf.is_some_and(|leaf| {
                    inclusion_proof(&self.frames.as_slice(), *size, index)
                        .ok()
                        .is_some_and(|proof| {
                            verify_inclusion(root, *size, index, leaf, &proof).is_ok()
                        })
                });
                let path = inclusion_proof(&self.frames.as_slice(), *size, index)
                    .map_or(0, |p| p.hashes().len());
                j.bool("included", verified);
                j.num("checkpoint", *cp_seq);
                j.num("checkpointFrame", *frame);
                j.num("treeSize", *size);
                j.num("pathLength", path as u64);
                j.str("root", &grouped(&fingerprint(root.as_bytes())));
            }
        }
        j.end_object();
        j.finish()
    }
}

/// The report and what inclusion proofs need.
#[derive(Debug)]
pub struct Verification {
    /// The JSON report.
    pub json: String,
    /// For later inclusion proofs.
    pub proofs: Proofs,
}

fn publications(b: &Bundle<'_>) -> Publications {
    let p = &b.publications;
    let receipts: Vec<TimeBucket> = p.receipts.iter().map(|r| TimeBucket::new(*r)).collect();
    Publications {
        anchors: Publication::from_ledger(&check_anchor(
            TimeBucket::new(p.checkpoint),
            &receipts,
            TimeBucket::new(p.now),
        )),
        board: Publication::from_ledger(&check_board(
            TimeBucket::new(p.close),
            p.published.map(TimeBucket::new),
            TimeBucket::new(p.now),
        )),
    }
}

/// Verifies `bytes` (a development bundle) with the bundle's pin, or with
/// `pin` when the caller gives one, and writes the report.
#[must_use]
pub fn verify(bytes: &[u8], pin: Option<Hash512>) -> Verification {
    let bundle = match decode(bytes) {
        Ok(b) => b,
        Err(e) => {
            let mut j = Json::new();
            j.begin_object();
            j.str("format", "ityv-console-report/1");
            j.str("error", &format!("bundle: {}", e.name()));
            j.end_object();
            return Verification {
                json: j.finish(),
                proofs: Proofs::default(),
            };
        }
    };
    let pin_used = pin.unwrap_or(bundle.pin);
    let input = bundle.genesis();
    let amendments = bundle.amendments();
    let mut j = Json::new();
    j.begin_object();
    j.str("format", "ityv-console-report/1");
    j.str("scenario", bundle.name);
    j.str("pin", &grouped(&fingerprint(pin_used.as_bytes())));
    j.bool("pinFromBundle", pin.is_none() || pin == Some(bundle.pin));
    let genesis = match verify_genesis(&pin_used, &input, &amendments) {
        Ok(g) => g,
        Err(e) => {
            // Genesis is all or nothing: no stage above it runs. The status
            // is what the status rule gives a failed genesis step.
            let evidence =
                Evidence::new(ScopeSet::empty()).with_step(Step::Genesis, Outcome::Failed);
            let status = evaluate(&evidence);
            j.object("genesis");
            j.bool("ok", false);
            j.str("error", &format!("{e:?}"));
            j.end_object();
            j.str("status", status.status().name());
            holds_json(&mut j, "holds", status.holds());
            j.end_object();
            return Verification {
                json: j.finish(),
                proofs: Proofs::default(),
            };
        }
    };
    let report = verify_ledger(
        &genesis,
        bundle.frames,
        &bundle.events,
        publications(&bundle),
    );
    write_report(&mut j, &genesis, &bundle, &report);
    j.end_object();
    let proofs = Proofs {
        frames: report.index().frame_hashes().to_vec(),
        checkpoints: report
            .checkpoints()
            .checkpoints()
            .iter()
            .map(|c| (c.checkpoint_seq.get(), c.frame.get(), c.tree_size, c.root))
            .collect(),
    };
    Verification {
        json: j.finish(),
        proofs,
    }
}

/// The frame schema of every frame in the stream, by sequence number.
fn frame_schemas(frames: &[u8]) -> BTreeMap<u64, u32> {
    let mut out = BTreeMap::new();
    let mut s = FrameStream::new(frames);
    while let Some(Ok(r)) = s.next_record() {
        out.insert(r.frame().seq().get(), r.frame().event_schema_id().get());
    }
    out
}

/// Every hold the verifier puts on box `id`, from every stage.
fn box_holds(report: &Report<'_>, id: &[u8]) -> HoldSet {
    let own = report
        .boxes()
        .report(id)
        .map_or(HoldSet::empty(), |r| r.holds);
    let records = report
        .records()
        .report(id)
        .map_or(HoldSet::empty(), |r| r.holds);
    own.union(report.index().box_holds(id))
        .union(records)
        .union(report.progress().box_holds(id))
}

/// The holds on the whole ledger (not on one box or unit).
fn ledger_holds(report: &Report<'_>) -> HoldSet {
    let tally = report
        .tally()
        .refused()
        .iter()
        .fold(HoldSet::empty(), |h, r| h.with(tally_refusal_hold(r.event)));
    report
        .index()
        .ledger_holds()
        .union(report.authority().holds())
        .union(report.checkpoints().holds())
        .union(report.participation().holds())
        .union(report.disputes().holds())
        .union(tally)
}

/// The status of one tally unit: the ledger's evidence with box
/// completeness, holds and tally narrowed to the unit.
fn unit_status(
    report: &Report<'_>,
    genesis: &VerifiedGenesis<'_>,
    unit: &UnitTally<'_>,
    publications: Publications,
) -> StatusReport {
    let ev = report.evidence();
    let boxes: Vec<&[u8]> = genesis
        .boxes()
        .filter(|b| {
            b.ballot_style_id.as_bytes() == unit.ballot_style_id.as_bytes()
                && b.reporting_unit_id.as_bytes() == unit.reporting_unit_id.as_bytes()
        })
        .map(|b| b.box_id.as_bytes())
        .collect();
    let closed = boxes.iter().all(|id| {
        report
            .boxes()
            .report(id)
            .is_some_and(|r| !r.holds.contains(HoldReason::CloseMissing))
    });
    let holds = boxes
        .iter()
        .fold(ledger_holds(report).union(unit.holds), |h, id| {
            h.union(box_holds(report, id))
        });
    let holds = holds
        .iter()
        .filter(|r| *r != HoldReason::CloseMissing)
        .fold(HoldSet::empty(), HoldSet::with);
    let scopes = report
        .authority()
        .authorization()
        .map_or(ScopeSet::empty(), ityv_state::Authorization::scopes);
    let evidence = [
        Step::Genesis,
        Step::Checkpoints,
        Step::Frames,
        Step::BoxInvariants,
        Step::Records,
        Step::Participation,
    ]
    .iter()
    .fold(Evidence::new(scopes), |e, s| e.with_step(*s, ev.step(*s)))
    .with_step(
        Step::BoxCompleteness,
        if closed {
            Outcome::Passed
        } else {
            Outcome::NotRun
        },
    )
    .with_step(
        Step::Tally,
        if unit.passed() {
            Outcome::Passed
        } else {
            Outcome::NotRun
        },
    )
    .with_anchors(publications.anchors)
    .with_board(publications.board)
    .with_holds(holds);
    evaluate(&evidence)
}

fn write_report(
    j: &mut Json,
    genesis: &VerifiedGenesis<'_>,
    bundle: &Bundle<'_>,
    report: &Report<'_>,
) {
    let status = report.status();
    let pubs = publications(bundle);
    j.object("genesis");
    j.bool("ok", true);
    j.str(
        "election",
        &String::from_utf8_lossy(genesis.election_id().as_bytes()),
    );
    j.num("states", genesis.state_count() as u64);
    j.num("boxes", genesis.boxes().count() as u64);
    j.num("stations", genesis.stations().count() as u64);
    j.end_object();
    j.str("status", status.status().name());
    holds_json(j, "holds", status.holds());
    j.bool("countOnly", status.count_only());
    j.bool("receiptScan", status.receipt_scan());
    j.array("stages");
    for s in Step::ALL {
        j.begin_object();
        j.str("step", step_name(s));
        j.str("outcome", outcome_name(report.evidence().step(s)));
        j.end_object();
    }
    j.end_array();
    j.object("publications");
    j.str("anchors", &publication_name(pubs.anchors));
    j.str("board", &publication_name(pubs.board));
    j.end_object();
    j.object("ledger");
    j.num("treeSize", report.index().tree_size());
    j.str(
        "root",
        &grouped(&fingerprint(report.index().root().as_bytes())),
    );
    j.num("events", report.index().events().len() as u64);
    j.end_object();
    write_checkpoints(j, report);
    write_boxes(j, genesis, report);
    write_units(j, genesis, report, pubs);
    write_refused(j, bundle, report);
    write_progress(j, genesis, report);
    write_participation(j, report);
    write_disputes(j, report);
    write_records(j, report);
}

fn write_checkpoints(j: &mut Json, report: &Report<'_>) {
    let chain = report.checkpoints();
    j.object("checkpoints");
    j.num("covered", chain.covered());
    j.num("unchecked", chain.unchecked() as u64);
    j.array("valid");
    for c in chain.checkpoints() {
        j.begin_object();
        j.num("frame", c.frame.get());
        j.num("seq", c.checkpoint_seq.get());
        j.num("treeSize", c.tree_size);
        j.num("timeBucket", c.time_bucket.get());
        j.str(
            "fingerprint",
            &grouped(&fingerprint(c.body_hash.as_bytes())),
        );
        j.str("root", &grouped(&fingerprint(c.root.as_bytes())));
        j.end_object();
    }
    j.end_array();
    j.array("findings");
    for f in chain.findings() {
        j.begin_object();
        j.num("frame", f.frame.get());
        j.str("kind", &format!("{:?}", f.kind));
        j.end_object();
    }
    j.end_array();
    j.end_object();
}

fn write_boxes(j: &mut Json, genesis: &VerifiedGenesis<'_>, report: &Report<'_>) {
    j.array("boxes");
    for r in report.boxes().reports() {
        let id = r.box_id.as_bytes();
        j.begin_object();
        j.str("box", &String::from_utf8_lossy(id));
        if let Some(g) = genesis.expected_box(id) {
            j.str("station", &String::from_utf8_lossy(g.station_id.as_bytes()));
            j.str(
                "style",
                &String::from_utf8_lossy(g.ballot_style_id.as_bytes()),
            );
            j.str(
                "unit",
                &String::from_utf8_lossy(g.reporting_unit_id.as_bytes()),
            );
            j.str("profile", &format!("{:?}", g.profile));
        }
        j.str("phase", &format!("{:?}", r.phase));
        holds_json(j, "holds", box_holds(report, id));
        match r.counts {
            Some(c) => {
                j.object("close");
                j.num("paper", c.paper);
                j.num("records", c.records);
                j.num("attested", c.attested);
                j.num("withoutRecord", c.without_record);
                j.num("challenged", c.challenged);
                j.num("quarantined", c.quarantined);
                j.num("visits", c.visits);
                j.num("envelopes", c.envelopes);
                j.num("stickers", c.stickers);
                j.end_object();
            }
            None => j.null("close"),
        }
        if let Some(rec) = report.records().report(id) {
            j.num("accepted", rec.records.len() as u64);
            j.num("rejected", rec.rejected.len() as u64);
            j.num("unattested", rec.unattested.len() as u64);
        }
        j.end_object();
    }
    j.end_array();
}

fn write_units(
    j: &mut Json,
    genesis: &VerifiedGenesis<'_>,
    report: &Report<'_>,
    pubs: Publications,
) {
    j.array("units");
    for u in report.tally().units() {
        let st = unit_status(report, genesis, u, pubs);
        j.begin_object();
        j.str(
            "style",
            &String::from_utf8_lossy(u.ballot_style_id.as_bytes()),
        );
        j.str(
            "unit",
            &String::from_utf8_lossy(u.reporting_unit_id.as_bytes()),
        );
        j.str("status", st.status().name());
        holds_json(j, "holds", st.holds());
        holds_json(j, "unitHolds", u.holds);
        j.array("boxes");
        for b in genesis.boxes().filter(|b| {
            b.ballot_style_id.as_bytes() == u.ballot_style_id.as_bytes()
                && b.reporting_unit_id.as_bytes() == u.reporting_unit_id.as_bytes()
        }) {
            j.item_str(&String::from_utf8_lossy(b.box_id.as_bytes()));
        }
        j.end_array();
        j.num("included", u.included.len() as u64);
        j.num("excluded", u.exclusions.len() as u64);
        j.num("noRecord", u.no_record_count);
        j.num("chunks", u64::from(u.chunks));
        j.opt_num("scope", u.scope.map(ityv_encoding::Seq::get));
        j.array("scopeProblems");
        for p in &u.scope_problems {
            j.item_str(&format!("{p:?}"));
        }
        j.end_array();
        j.array("openings");
        for o in &u.openings {
            j.begin_object();
            j.num("chunk", u64::from(o.chunk));
            j.num("seq", o.seq.get());
            j.str("outcome", &format!("{:?}", o.outcome));
            j.end_object();
        }
        j.end_array();
        match &u.counts {
            Some(c) => {
                j.array("counts");
                for v in c {
                    j.item_num(*v);
                }
                j.end_array();
            }
            None => j.null("counts"),
        }
        j.opt_num("paper", u.paper.map(ityv_encoding::Seq::get));
        match u.comparison {
            Some(c) => {
                j.object("comparison");
                j.bool("agrees", c.agrees());
                j.opt_num("firstBelow", c.first_below.map(u64::from));
                j.bool("totalsAgree", c.totals_agree);
                j.end_object();
            }
            None => j.null("comparison"),
        }
        j.bool("complete", u.complete());
        j.bool("passed", u.passed());
        j.end_object();
    }
    j.end_array();
}

fn write_refused(j: &mut Json, bundle: &Bundle<'_>, report: &Report<'_>) {
    let schemas = frame_schemas(bundle.frames);
    let mut list: Vec<(u64, &str, String)> = Vec::new();
    for f in report.index().findings() {
        if let Some(seq) = f.seq {
            list.push((seq.get(), "frames", format!("{:?}", f.kind)));
        }
    }
    for f in report.checkpoints().findings() {
        list.push((f.frame.get(), "checkpoints", format!("{:?}", f.kind)));
    }
    for s in report.authority().refused() {
        list.push((s.get(), "authority", "Refused".to_owned()));
    }
    for b in report.boxes().reports() {
        for r in &b.refusals {
            list.push((r.seq.get(), "boxes", format!("{:?}", r.refusal)));
        }
    }
    for b in report.records().reports() {
        for r in &b.rejected {
            list.push((r.seq.get(), "records", format!("{:?}", r.refusal)));
        }
        for f in &b.batches {
            list.push((f.seq.get(), "records", format!("Batch{:?}", f.problem)));
        }
        for s in &b.refused_challenges {
            list.push((s.get(), "records", "ChallengeRefused".to_owned()));
        }
        for s in &b.failed_openings {
            list.push((s.get(), "records", "OpeningMismatch".to_owned()));
        }
    }
    for b in report.progress().boxes() {
        for r in &b.refusals {
            list.push((r.seq.get(), "progress", format!("{:?}", r.reason)));
        }
    }
    for s in report.progress().stations() {
        for r in &s.refusals {
            list.push((r.seq.get(), "progress", format!("{:?}", r.reason)));
        }
    }
    let p = report.participation();
    for f in p.set_findings() {
        list.push((f.seq.get(), "participation", format!("{:?}", f.problem)));
    }
    for f in p.key_findings() {
        list.push((f.seq.get(), "participation", format!("{:?}", f.problem)));
    }
    for f in p.count_findings() {
        list.push((
            f.seq.get(),
            "participation",
            "StationCountRefused".to_owned(),
        ));
    }
    for r in report.tally().refused() {
        list.push((
            r.seq.get(),
            "tally",
            format!("{:?}: {:?}", r.event, r.refusal),
        ));
    }
    for s in report.disputes().refused() {
        list.push((s.get(), "disputes", "Refused".to_owned()));
    }
    list.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));
    list.dedup();
    j.array("refused");
    for (seq, stage, reason) in &list {
        j.begin_object();
        j.num("seq", *seq);
        match schemas.get(seq) {
            Some(s) => j.str("schema", &format!("0x{s:04X}")),
            None => j.null("schema"),
        }
        j.str("stage", stage);
        j.str("reason", reason);
        j.end_object();
    }
    j.end_array();
}

fn write_progress(j: &mut Json, genesis: &VerifiedGenesis<'_>, report: &Report<'_>) {
    let index = report.index();
    j.array("progress");
    for st in report.progress().stations() {
        let id = st.station_id.as_bytes();
        let refused: BTreeSet<u64> = st
            .refusals
            .iter()
            .map(|r| r.seq.get())
            .chain(
                report
                    .progress()
                    .boxes()
                    .iter()
                    .filter(|b| b.station_id.as_bytes() == id)
                    .flat_map(|b| b.refusals.iter().map(|r| r.seq.get())),
            )
            .collect();
        let boxes: Vec<&[u8]> = genesis
            .station(id)
            .map(|s| s.boxes().map(|b| b.as_bytes()).collect())
            .unwrap_or_default();
        // (slot) -> ticks taken: check-in counts, and each box's sheets in.
        let mut checkin: BTreeMap<u64, [u64; 4]> = BTreeMap::new();
        let mut sheets: BTreeMap<(u64, usize), u64> = BTreeMap::new();
        let mut taken = |e: &ityv_verify::IndexedEvent<'_>| {
            if e.schema != SCHEMA_PROGRESS_TICK || refused.contains(&e.seq.get()) {
                return;
            }
            let Some(bytes) = e.bytes else { return };
            let Ok(tick) =
                decode_object::<ProgressTick<'_>>(SCHEMA_PROGRESS_TICK, SCHEMA_VERSION_1, bytes)
            else {
                return;
            };
            match tick.body() {
                ProgressBody::Checkin(c) => {
                    let p = c.parts();
                    checkin
                        .entry(p.slot)
                        .or_insert([p.checkins, p.issued, p.spoiled, p.returned]);
                }
                ProgressBody::Box(b) => {
                    let p = b.parts();
                    if let Some(i) = boxes.iter().position(|x| *x == p.box_id.as_bytes()) {
                        sheets.entry((p.slot, i)).or_insert(p.sheets_in);
                    }
                }
            }
        };
        for e in index.station_events(id) {
            taken(e);
        }
        for b in &boxes {
            for e in index.box_events(b) {
                taken(e);
            }
        }
        let limit = genesis
            .policy_entry(id)
            .map(|p| u64::from(p.get().limit_sheets()));
        j.begin_object();
        j.str("station", &String::from_utf8_lossy(id));
        j.opt_num("limit", limit);
        j.opt_num("firstSlot", st.first_slot);
        j.opt_num("lastSlot", st.last_slot);
        j.num("ticks", st.ticks as u64);
        j.bool("suspended", st.suspended);
        j.bool("counterfoil", st.counterfoil);
        j.str("close", &format!("{:?}", st.close));
        holds_json(j, "holds", st.holds);
        j.array("alarms");
        for a in &st.alarms {
            j.begin_object();
            j.num("slot", a.slot);
            j.str("alarm", &format!("{:?}", a.alarm));
            j.end_object();
        }
        j.end_array();
        j.array("checks");
        for c in &st.checks {
            j.item_num(c.get());
        }
        j.end_array();
        j.array("series");
        if let (Some(first), Some(last)) = (st.first_slot, st.last_slot) {
            let mut c = [0u64; 4];
            let mut s_in = vec![0u64; boxes.len()];
            for slot in first..=last {
                if let Some(v) = checkin.get(&slot) {
                    c = *v;
                }
                for (i, v) in s_in.iter_mut().enumerate() {
                    if let Some(n) = sheets.get(&(slot, i)) {
                        *v = *n;
                    }
                }
                let total: u64 = s_in.iter().sum();
                j.begin_object();
                j.num("slot", slot);
                j.num("checkins", c[0]);
                j.num("issued", c[1]);
                j.num("spoiled", c[2]);
                j.num("returned", c[3]);
                j.num("sheetsIn", total);
                match out_of(c[1], total, c[2], c[3], 0) {
                    Some(o) => j.int("out", o),
                    None => j.null("out"),
                }
                j.end_object();
            }
        }
        j.end_array();
        j.end_object();
    }
    j.end_array();
}

fn write_participation(j: &mut Json, report: &Report<'_>) {
    let p = report.participation();
    j.object("participation");
    j.bool("complete", p.complete());
    j.num("duplicates", p.duplicates());
    holds_json(j, "holds", p.holds());
    j.array("stations");
    for s in p.stations() {
        j.begin_object();
        j.str("station", &String::from_utf8_lossy(s.station_id.as_bytes()));
        j.opt_num("set", s.set.map(ityv_encoding::Seq::get));
        j.opt_num("count", s.count.map(u64::from));
        j.opt_num("observers", s.observers);
        j.bool("closed", s.closed);
        holds_json(j, "holds", s.holds);
        j.end_object();
    }
    j.end_array();
    j.end_object();
}

fn write_disputes(j: &mut Json, report: &Report<'_>) {
    let d = report.disputes();
    j.object("disputes");
    j.array("list");
    for e in d.disputes() {
        j.begin_object();
        j.str("filing", &grouped(&fingerprint(e.filing.as_bytes())));
        j.str("type", &format!("{:?}", e.dispute_type));
        j.opt_str(
            "box",
            e.box_id
                .map(|b| String::from_utf8_lossy(b.as_bytes()).into_owned())
                .as_deref(),
        );
        j.str("status", e.status.name());
        j.bool("unresolved", e.is_unresolved());
        j.array("events");
        for s in &e.events {
            j.item_num(s.get());
        }
        j.end_array();
        j.num("decisions", e.decisions.len() as u64);
        j.end_object();
    }
    j.end_array();
    j.end_object();
}

fn write_records(j: &mut Json, report: &Report<'_>) {
    let checkpoints: Vec<(u64, u64)> = report
        .checkpoints()
        .checkpoints()
        .iter()
        .map(|c| (c.checkpoint_seq.get(), c.tree_size))
        .collect();
    let covering = |seq: u64| {
        checkpoints
            .iter()
            .find(|(_, size)| *size >= seq)
            .map(|(s, _)| *s)
    };
    j.array("records");
    for b in report.records().reports() {
        let id = String::from_utf8_lossy(b.box_id.as_bytes()).into_owned();
        for r in &b.records {
            j.begin_object();
            j.str("code", &hex(r.tracking_code.as_bytes()));
            j.str("box", &id);
            j.num("seq", r.seq.get());
            j.str("state", r.state.status().name());
            j.opt_num("checkpoint", covering(r.seq.get()));
            j.end_object();
        }
        for r in &b.rejected {
            j.begin_object();
            j.str("code", &hex(r.tracking_code.as_bytes()));
            j.str("box", &id);
            j.num("seq", r.seq.get());
            j.str("state", "REJECTED");
            j.opt_num("checkpoint", covering(r.seq.get()));
            j.end_object();
        }
    }
    j.end_array();
}

/// The fingerprint of `bytes` (SHA3-512 object-free hash), for the
/// prototype identity lines.
#[must_use]
pub fn fingerprint_of(bytes: &[u8]) -> String {
    let mut h = ityv_crypto::Sha3Hasher::new();
    h.absorb(bytes);
    fingerprint(&h.finish())
}

#[cfg(test)]
mod tests {
    use super::{fingerprint, grouped};

    #[test]
    fn base32_of_the_first_twenty_bytes() {
        // RFC 4648 §10: BASE32("fooba") = "MZXW6YTB".
        assert_eq!(fingerprint(b"fooba"), "MZXW6YTB");
        let zeros = fingerprint(&[0u8; 64]);
        assert_eq!(zeros.len(), 32);
        assert_eq!(grouped(&zeros), "AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA");
    }
}
