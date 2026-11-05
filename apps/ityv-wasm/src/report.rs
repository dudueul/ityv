//! The console's report: every stage of `ityv_verify::verify_ledger` over
//! a bundle, written as JSON for display.
//!
//! The status, the holds, the stages, the checkpoints and every refusal
//! are the verifier's own values. Three things are composed here, each
//! through TCB code:
//!
//! * the status of each tally unit: the verifier's evidence with box
//!   completeness and tally narrowed to the unit, and the ledger's whole
//!   hold set minus only the holds that are attributable to other units'
//!   boxes alone, handed to `ityv_state::status::evaluate`;
//! * each station's progress series: the counts of the ticks the
//!   progress stage took, `out` from `ityv_state::out_of`;
//! * each record's inclusion in the first verified checkpoint covering
//!   its frame, decided by `ityv_ledger::verify_inclusion` (module `inclusion`).
//!
//! None of them replaces the ledger's status, which the report gives
//! first. Every count from the ledger is carried with checked arithmetic:
//! a sum that does not fit is written `null` with an `overflow` flag, never
//! wrapped and never a trap. Integers above 2^53 − 1 are written as JSON
//! strings (the `json` module).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use ityv_crypto::Sha3Hasher;
use ityv_encoding::{
    Hash512, ProgressBody, ProgressTick, SCHEMA_PROGRESS_TICK, SCHEMA_VERSION_1, ScopeSet,
    TimeBucket, decode_object,
};
use ityv_ledger::{FrameStream, check_anchor, check_board};
use ityv_state::{
    Evidence, HoldReason, HoldSet, Outcome, Publication, StatusReport, Step, evaluate, out_of,
};
use ityv_verify::{
    BoxProgressReport, BoxRecords, BoxReport, IndexedEvent, Publications, Report,
    StationProgressReport, TallyEvent, UnitTally, VerifiedGenesis, verify_genesis, verify_ledger,
};

use crate::bundle::{Bundle, decode};
use crate::inclusion::Tree;
use crate::json::Json;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
/// Bit offsets of the eight 5-bit groups of a 40-bit block, high first.
const SHIFTS: [u32; 8] = [35, 30, 25, 20, 15, 10, 5, 0];

/// The fingerprint notation (`ENCODING.md`, 소프트웨어 지문 표기): the
/// first 20 bytes of `hash` in Base32 (RFC 4648 alphabet, upper case, no
/// padding), 32 characters for a hash of 20 bytes or more; a shorter
/// input gives only its whole 5-byte blocks.
#[must_use]
pub fn fingerprint(hash: &[u8]) -> String {
    let mut out = String::with_capacity(32);
    for block in hash
        .get(..hash.len().min(20))
        .unwrap_or(&[])
        .chunks_exact(5)
    {
        let mut buf = [0u8; 8];
        if let Some(tail) = buf.get_mut(3..) {
            tail.copy_from_slice(block);
        }
        let v = u64::from_be_bytes(buf);
        for shift in SHIFTS {
            let index = v.checked_shr(shift).map_or(0, |x| x & 0x1f);
            let c = usize::try_from(index).ok().and_then(|i| BASE32.get(i));
            out.push(char::from(c.copied().unwrap_or(b'A')));
        }
    }
    out
}

/// `fp` cut into groups of four separated by spaces.
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
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b.checked_shr(4).unwrap_or(0), b & 0x0f] {
            s.push(char::from(
                DIGITS.get(usize::from(nibble)).copied().unwrap_or(b'0'),
            ));
        }
    }
    s
}

/// The SHA3-512 of `bytes`, hexadecimal: the bundle's identity in the
/// report and in the simulator's `index.json`.
#[must_use]
pub fn sha3_hex(bytes: &[u8]) -> String {
    let mut h = Sha3Hasher::new();
    h.absorb(bytes);
    hex(&h.finish())
}

/// The fingerprint of the SHA3-512 of `bytes`, for the prototype
/// identity lines.
#[must_use]
pub fn fingerprint_of(bytes: &[u8]) -> String {
    let mut h = Sha3Hasher::new();
    h.absorb(bytes);
    fingerprint(&h.finish())
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

/// The hold a refused tally event puts on the ledger: a copy of
/// `ityv_verify::tally::refusal_hold`, which is private (follow-up:
/// expose it; `tools/ityv-sim/tests` pins this copy to the verifier's
/// observable outcome for every refusal the scenarios produce).
#[must_use]
pub const fn tally_refusal_hold(event: TallyEvent) -> HoldReason {
    match event {
        TallyEvent::Receipt => HoldReason::ReceiptResolutionRefused,
        TallyEvent::Decision => HoldReason::TallyEffectRefused,
        TallyEvent::Scope => HoldReason::TallyScopeRefused,
        TallyEvent::Opening => HoldReason::AggregateRefused,
        TallyEvent::Paper => HoldReason::PaperCountRefused,
        TallyEvent::LateClose => HoldReason::LateCloseAfterScope,
    }
}

/// The report and the bundle's identity.
#[derive(Debug)]
pub struct Verification {
    /// The JSON report.
    pub json: String,
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
/// `pin` when the caller gives one, and writes the report. Never panics on
/// any input (`tools/ityv-sim/tests` runs it over mutated bundles).
#[must_use]
pub fn verify(bytes: &[u8], pin: Option<Hash512>) -> Verification {
    let mut j = Json::new();
    j.begin_object();
    j.str("format", "ityv-console-report/2");
    j.str("bundleHash", &sha3_hex(bytes));
    j.num(
        "bundleBytes",
        u64::try_from(bytes.len()).unwrap_or(u64::MAX),
    );
    let bundle = match decode(bytes) {
        Ok(b) => b,
        Err(e) => {
            j.str("error", &format!("bundle: {}", e.name()));
            j.end_object();
            return Verification { json: j.finish() };
        }
    };
    let pin_used = pin.unwrap_or(bundle.pin);
    let input = bundle.genesis();
    let amendments = bundle.amendments();
    j.str("scenario", bundle.name);
    j.str("pin", &grouped(&fingerprint(pin_used.as_bytes())));
    j.str("pinHex", &hex(pin_used.as_bytes()));
    // Whether no pin was given and the bundle's own was used; a pin the
    // caller gave counts as outside even when it equals the bundle's (the
    // outside source then agrees with the bundle).
    j.bool("pinFromBundle", pin.is_none());
    j.bool("pinEqualsBundle", pin.is_none_or(|p| p == bundle.pin));
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
            return Verification { json: j.finish() };
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
    Verification { json: j.finish() }
}

/// Every stage's per-box and per-station report, indexed once.
pub struct Lookup<'r, 'a> {
    report: &'r Report<'a>,
    boxes: BTreeMap<&'a [u8], &'r BoxReport<'a>>,
    records: BTreeMap<&'a [u8], &'r BoxRecords<'a>>,
    progress_boxes: BTreeMap<&'a [u8], &'r BoxProgressReport<'a>>,
    progress_stations: BTreeMap<&'a [u8], &'r StationProgressReport<'a>>,
}

impl<'r, 'a> Lookup<'r, 'a> {
    /// Indexes `report`.
    #[must_use]
    pub fn new(report: &'r Report<'a>) -> Self {
        Self {
            report,
            boxes: report
                .boxes()
                .reports()
                .iter()
                .map(|r| (r.box_id.as_bytes(), r))
                .collect(),
            records: report
                .records()
                .reports()
                .iter()
                .map(|r| (r.box_id.as_bytes(), r))
                .collect(),
            progress_boxes: report
                .progress()
                .boxes()
                .iter()
                .map(|r| (r.box_id.as_bytes(), r))
                .collect(),
            progress_stations: report
                .progress()
                .stations()
                .iter()
                .map(|r| (r.station_id.as_bytes(), r))
                .collect(),
        }
    }

    /// Every hold the verifier puts on box `id`, from every stage (the
    /// index's include the ledger's own).
    #[must_use]
    pub fn box_holds(&self, id: &[u8]) -> HoldSet {
        let own = self.boxes.get(id).map_or(HoldSet::empty(), |r| r.holds);
        let records = self.records.get(id).map_or(HoldSet::empty(), |r| r.holds);
        let progress = self.progress_boxes.get(id).map_or(HoldSet::empty(), |r| {
            r.holds.union(
                self.progress_stations
                    .get(r.station_id.as_bytes())
                    .map_or(HoldSet::empty(), |s| s.holds),
            )
        });
        own.union(self.report.index().box_holds(id))
            .union(records)
            .union(progress)
    }

    /// The holds on the whole ledger, not on one box or unit: the index's
    /// ledger holds, the authorization, checkpoints, participation,
    /// disputes and refused tally events, and every hold of a box or
    /// station the genesis's last state does not have (an amendment
    /// removed it).
    #[must_use]
    pub fn ledger_level(&self, genesis: &VerifiedGenesis<'_>) -> HoldSet {
        let r = self.report;
        let tally = r
            .tally()
            .refused()
            .iter()
            .fold(HoldSet::empty(), |h, x| h.with(tally_refusal_hold(x.event)));
        let removed_boxes = self
            .boxes
            .keys()
            .chain(self.progress_boxes.keys())
            .filter(|id| genesis.expected_box(id).is_none())
            .fold(HoldSet::empty(), |h, id| h.union(self.box_holds(id)));
        let removed_stations = self
            .progress_stations
            .iter()
            .filter(|(id, _)| genesis.station(id).is_none())
            .fold(HoldSet::empty(), |h, (_, s)| h.union(s.holds));
        r.index()
            .ledger_holds()
            .union(r.authority().holds())
            .union(r.checkpoints().holds())
            .union(r.participation().holds())
            .union(r.disputes().holds())
            .union(tally)
            .union(removed_boxes)
            .union(removed_stations)
    }
}

/// The genesis boxes of tally unit `u`.
fn unit_boxes<'g>(genesis: &'g VerifiedGenesis<'_>, u: &UnitTally<'_>) -> Vec<&'g [u8]> {
    genesis
        .boxes()
        .filter(|b| {
            b.ballot_style_id.as_bytes() == u.ballot_style_id.as_bytes()
                && b.reporting_unit_id.as_bytes() == u.reporting_unit_id.as_bytes()
        })
        .map(|b| b.box_id.as_bytes())
        .collect()
}

/// A tally unit's status.
#[derive(Debug, Clone)]
pub struct UnitStatus {
    /// Ballot style.
    pub style: Vec<u8>,
    /// Reporting unit.
    pub unit: Vec<u8>,
    /// Its genesis boxes.
    pub boxes: Vec<Vec<u8>>,
    /// The status and holds.
    pub status: StatusReport,
}

/// The status of every tally unit of `report`: the ledger's evidence with
/// box completeness (the unit has boxes and every one is closed) and the
/// tally narrowed to the unit, and the ledger's whole hold set minus the
/// reasons that only boxes or tallies of other units carry.
#[must_use]
pub fn unit_statuses(
    genesis: &VerifiedGenesis<'_>,
    report: &Report<'_>,
    publications: Publications,
) -> Vec<UnitStatus> {
    let look = Lookup::new(report);
    let ledger_level = look.ledger_level(genesis);
    let units = report.tally().units();
    let ev = report.evidence();
    let scopes = report
        .authority()
        .authorization()
        .map_or(ScopeSet::empty(), ityv_state::Authorization::scopes);
    let per_unit: Vec<(Vec<&[u8]>, HoldSet)> = units
        .iter()
        .map(|u| {
            let boxes = unit_boxes(genesis, u);
            let holds = boxes
                .iter()
                .fold(u.holds, |h, id| h.union(look.box_holds(id)));
            (boxes, holds)
        })
        .collect();
    let ledger = report.status().holds();
    units
        .iter()
        .zip(&per_unit)
        .enumerate()
        .map(|(i, (u, (boxes, mine)))| {
            let others = per_unit
                .iter()
                .enumerate()
                .filter(|(k, _)| *k != i)
                .fold(HoldSet::empty(), |h, (_, (_, o))| h.union(*o));
            let holds = ledger
                .iter()
                .filter(|r| {
                    !(others.contains(*r) && !mine.contains(*r) && !ledger_level.contains(*r))
                })
                .fold(HoldSet::empty(), HoldSet::with);
            let closed = !boxes.is_empty()
                && boxes.iter().all(|id| {
                    look.boxes
                        .get(id)
                        .is_some_and(|r| !r.holds.contains(HoldReason::CloseMissing))
                });
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
                if u.passed() {
                    Outcome::Passed
                } else {
                    Outcome::NotRun
                },
            )
            .with_anchors(publications.anchors)
            .with_board(publications.board)
            .with_holds(holds);
            UnitStatus {
                style: u.ballot_style_id.as_bytes().to_vec(),
                unit: u.reporting_unit_id.as_bytes().to_vec(),
                boxes: boxes.iter().map(|b| b.to_vec()).collect(),
                status: evaluate(&evidence),
            }
        })
        .collect()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn write_report(
    j: &mut Json,
    genesis: &VerifiedGenesis<'_>,
    bundle: &Bundle<'_>,
    report: &Report<'_>,
) {
    let status = report.status();
    let pubs = publications(bundle);
    let look = Lookup::new(report);
    j.object("genesis");
    j.bool("ok", true);
    j.str("election", &text(genesis.election_id().as_bytes()));
    j.num(
        "states",
        u64::try_from(genesis.state_count()).unwrap_or(u64::MAX),
    );
    j.num(
        "boxes",
        u64::try_from(genesis.boxes().count()).unwrap_or(u64::MAX),
    );
    j.num(
        "stations",
        u64::try_from(genesis.stations().count()).unwrap_or(u64::MAX),
    );
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
    j.num(
        "events",
        u64::try_from(report.index().events().len()).unwrap_or(u64::MAX),
    );
    j.end_object();
    write_checkpoints(j, report);
    write_boxes(j, genesis, &look);
    write_units(j, genesis, report, pubs);
    write_refused(j, bundle, report);
    write_progress(j, genesis, &look);
    write_participation(j, report);
    write_disputes(j, report);
    write_records(j, report);
}

fn write_checkpoints(j: &mut Json, report: &Report<'_>) {
    let chain = report.checkpoints();
    j.object("checkpoints");
    j.num("covered", chain.covered());
    j.num(
        "unchecked",
        u64::try_from(chain.unchecked()).unwrap_or(u64::MAX),
    );
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

fn write_boxes(j: &mut Json, genesis: &VerifiedGenesis<'_>, look: &Lookup<'_, '_>) {
    j.array("boxes");
    for r in look.report.boxes().reports() {
        let id = r.box_id.as_bytes();
        j.begin_object();
        j.str("box", &text(id));
        if let Some(g) = genesis.expected_box(id) {
            j.str("station", &text(g.station_id.as_bytes()));
            j.str("style", &text(g.ballot_style_id.as_bytes()));
            j.str("unit", &text(g.reporting_unit_id.as_bytes()));
            j.str("profile", &format!("{:?}", g.profile));
        }
        j.str("phase", &format!("{:?}", r.phase));
        holds_json(j, "holds", look.box_holds(id));
        if let Some(c) = r.counts {
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
        } else {
            j.null("close");
        }
        if let Some(rec) = look.records.get(id) {
            j.num(
                "accepted",
                u64::try_from(rec.records.len()).unwrap_or(u64::MAX),
            );
            j.num(
                "rejected",
                u64::try_from(rec.rejected.len()).unwrap_or(u64::MAX),
            );
            j.num(
                "unattested",
                u64::try_from(rec.unattested.len()).unwrap_or(u64::MAX),
            );
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
    let statuses = unit_statuses(genesis, report, pubs);
    j.array("units");
    for (u, st) in report.tally().units().iter().zip(&statuses) {
        j.begin_object();
        j.str("style", &text(u.ballot_style_id.as_bytes()));
        j.str("unit", &text(u.reporting_unit_id.as_bytes()));
        j.str("status", st.status.status().name());
        holds_json(j, "holds", st.status.holds());
        holds_json(j, "unitHolds", u.holds);
        j.array("boxes");
        for b in &st.boxes {
            j.item_str(&text(b));
        }
        j.end_array();
        j.num(
            "included",
            u64::try_from(u.included.len()).unwrap_or(u64::MAX),
        );
        j.num(
            "excluded",
            u64::try_from(u.exclusions.len()).unwrap_or(u64::MAX),
        );
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
        if let Some(c) = &u.counts {
            j.array("counts");
            for v in c {
                j.item_num(*v);
            }
            j.end_array();
        } else {
            j.null("counts");
        }
        j.opt_num("paper", u.paper.map(ityv_encoding::Seq::get));
        if let Some(c) = u.comparison {
            j.object("comparison");
            j.bool("agrees", c.agrees());
            j.opt_num("firstBelow", c.first_below.map(u64::from));
            j.bool("totalsAgree", c.totals_agree);
            j.end_object();
        } else {
            j.null("comparison");
        }
        j.bool("complete", u.complete());
        j.bool("passed", u.passed());
        j.end_object();
    }
    j.end_array();
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
        if let Some(s) = schemas.get(seq) {
            j.str("schema", &format!("0x{s:04X}"));
        } else {
            j.null("schema");
        }
        j.str("stage", stage);
        j.str("reason", reason);
        j.end_object();
    }
    j.end_array();
}

/// The counts of the ticks the progress stage took for one station, by
/// slot: check-in counts, and each box's sheets in.
struct Ticks {
    checkin: BTreeMap<u64, [u64; 4]>,
    sheets: BTreeMap<(u64, usize), u64>,
    boxes: usize,
}

fn station_ticks(
    genesis: &VerifiedGenesis<'_>,
    look: &Lookup<'_, '_>,
    st: &StationProgressReport<'_>,
) -> Ticks {
    let index = look.report.index();
    let id = st.station_id.as_bytes();
    let boxes: Vec<&[u8]> = genesis
        .station(id)
        .map(|s| s.boxes().map(|b| b.as_bytes()).collect())
        .unwrap_or_default();
    let refused: BTreeSet<u64> = st
        .refusals
        .iter()
        .map(|r| r.seq.get())
        .chain(
            boxes
                .iter()
                .filter_map(|b| look.progress_boxes.get(b))
                .flat_map(|b| b.refusals.iter().map(|r| r.seq.get())),
        )
        .collect();
    let mut t = Ticks {
        checkin: BTreeMap::new(),
        sheets: BTreeMap::new(),
        boxes: boxes.len(),
    };
    let mut take = |e: &IndexedEvent<'_>| {
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
                t.checkin
                    .entry(p.slot)
                    .or_insert([p.checkins, p.issued, p.spoiled, p.returned]);
            }
            ProgressBody::Box(b) => {
                let p = b.parts();
                if let Some(i) = boxes.iter().position(|x| *x == p.box_id.as_bytes()) {
                    t.sheets.entry((p.slot, i)).or_insert(p.sheets_in);
                }
            }
        }
    };
    for e in index.station_events(id) {
        take(e);
    }
    for b in &boxes {
        for e in index.box_events(b) {
            take(e);
        }
    }
    t
}

/// Writes the series from `first` to `last`; returns whether a sum of
/// sheets in did not fit in 64 bits.
fn write_series(j: &mut Json, t: &Ticks, first: u64, last: u64) -> bool {
    let mut overflow = false;
    let mut c = [0u64; 4];
    let mut s_in = alloc::vec![0u64; t.boxes];
    // The progress stage bounds a station's slots (MAX_PROGRESS_SLOTS); a
    // range beyond it is not walked.
    let end = if last.saturating_sub(first) > ityv_verify::MAX_PROGRESS_SLOTS {
        first
    } else {
        last
    };
    for slot in first..=end {
        if let Some(v) = t.checkin.get(&slot) {
            c = *v;
        }
        for (i, v) in s_in.iter_mut().enumerate() {
            if let Some(n) = t.sheets.get(&(slot, i)) {
                *v = *n;
            }
        }
        let [checkins, issued, spoiled, returned] = c;
        j.begin_object();
        j.num("slot", slot);
        j.num("checkins", checkins);
        j.num("issued", issued);
        j.num("spoiled", spoiled);
        j.num("returned", returned);
        if let Some(total) = s_in.iter().try_fold(0u64, |acc, v| acc.checked_add(*v)) {
            j.num("sheetsIn", total);
            match out_of(issued, total, spoiled, returned, 0) {
                Some(o) => j.int("out", o),
                None => j.null("out"),
            }
        } else {
            overflow = true;
            j.null("sheetsIn");
            j.null("out");
            j.bool("overflow", true);
        }
        j.end_object();
    }
    overflow
}

fn write_progress(j: &mut Json, genesis: &VerifiedGenesis<'_>, look: &Lookup<'_, '_>) {
    j.array("progress");
    for st in look.report.progress().stations() {
        let id = st.station_id.as_bytes();
        let ticks = station_ticks(genesis, look, st);
        let limit = genesis
            .policy_entry(id)
            .map(|p| u64::from(p.get().limit_sheets()));
        j.begin_object();
        j.str("station", &text(id));
        j.opt_num("limit", limit);
        j.opt_num("firstSlot", st.first_slot);
        j.opt_num("lastSlot", st.last_slot);
        j.num("ticks", u64::try_from(st.ticks).unwrap_or(u64::MAX));
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
        let overflow = match (st.first_slot, st.last_slot) {
            (Some(first), Some(last)) => write_series(j, &ticks, first, last),
            (Some(_) | None, None) | (None, Some(_)) => false,
        };
        j.end_array();
        j.bool("overflow", overflow);
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
        j.str("station", &text(s.station_id.as_bytes()));
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
        j.opt_str("box", e.box_id.map(|b| text(b.as_bytes())).as_deref());
        j.str("status", e.status.name());
        j.bool("unresolved", e.is_unresolved());
        j.array("events");
        for s in &e.events {
            j.item_num(s.get());
        }
        j.end_array();
        j.num(
            "decisions",
            u64::try_from(e.decisions.len()).unwrap_or(u64::MAX),
        );
        j.end_object();
    }
    j.end_array();
    j.end_object();
}

/// Every record with its inclusion in the first verified checkpoint that
/// covers its frame, decided by `ityv_ledger::verify_inclusion`.
fn write_records(j: &mut Json, report: &Report<'_>) {
    let checkpoints: Vec<(u64, u64, Hash512, String)> = report
        .checkpoints()
        .checkpoints()
        .iter()
        .map(|c| {
            (
                c.checkpoint_seq.get(),
                c.tree_size,
                c.root,
                grouped(&fingerprint(c.body_hash.as_bytes())),
            )
        })
        .collect();
    let mut tree = Tree::new(report.index().frame_hashes());
    let mut one = |j: &mut Json, code: &Hash512, box_id: &str, seq: u64, state: &str| {
        j.begin_object();
        j.str("code", &hex(code.as_bytes()));
        j.str("box", box_id);
        j.num("seq", seq);
        j.str("state", state);
        if let Some((cp, size, root, fp)) = checkpoints.iter().find(|c| c.1 >= seq) {
            let (included, path) = tree.included(root, *size, seq);
            j.num("checkpoint", *cp);
            j.num("treeSize", *size);
            j.str("checkpointFingerprint", fp);
            j.bool("included", included);
            j.num("pathLength", u64::try_from(path).unwrap_or(u64::MAX));
        } else {
            j.null("checkpoint");
            j.bool("included", false);
        }
        j.end_object();
    };
    j.array("records");
    for b in report.records().reports() {
        let id = text(b.box_id.as_bytes());
        for r in &b.records {
            one(
                j,
                &r.tracking_code,
                &id,
                r.seq.get(),
                r.state.status().name(),
            );
        }
        for r in &b.rejected {
            one(j, &r.tracking_code, &id, r.seq.get(), "REJECTED");
        }
    }
    j.end_array();
}

impl Verification {
    /// The report's status word, for tests (`None` if absent).
    #[must_use]
    pub fn status(&self) -> Option<&str> {
        let at = self.json.find("\"status\":\"")?.checked_add(10)?;
        let rest = self.json.get(at..)?;
        rest.find('"').and_then(|end| rest.get(..end))
    }
}

/// The name of every hold reason by code (for the console's vocabulary
/// test).
#[must_use]
pub fn hold_names() -> Vec<(u8, String)> {
    HoldReason::ALL
        .iter()
        .map(|h| (h.code(), format!("{h:?}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{fingerprint, grouped, hex};

    #[test]
    fn base32_of_the_first_twenty_bytes() {
        // RFC 4648 §10: BASE32("fooba") = "MZXW6YTB".
        assert_eq!(fingerprint(b"fooba"), "MZXW6YTB");
        let zeros = fingerprint(&[0u8; 64]);
        assert_eq!(zeros.len(), 32);
        assert_eq!(grouped(&zeros), "AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA");
        assert_eq!(fingerprint(&[0xff; 20]), "7".repeat(32));
        assert_eq!(hex(&[0x0a, 0xf1]), "0af1");
    }
}
