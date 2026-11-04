//! The comparison audit of a tallied election as plan steps (PROTOCOL.md
//! §12, ADR-0036): a freeze per ballot style, the audit commit, the
//! binding checkpoint, the seed over the beacon value, the sample redrawn
//! as the verifier draws it, the trustees' opening references and the
//! auditors' comparisons in the order the audit calls for them, full
//! comparisons and findings for codes 1 and 2, and hand counts when every
//! round is exceeded.
//!
//! What is made up here, and shown as such by the console: the dice
//! record, the beacon designation and the beacon round's published output
//! (fixture data; a real verifier observes the beacon itself). A scenario
//! that needs its sample to have a shape (a misread ballot among the
//! first round's draws) takes the first fixture output whose sample has
//! it. In a real election nobody can choose: the commit fixes every input
//! but the beacon value before the beacon is published (ADR-0036 4).
//!
//! The restricted sample openings (`SampleOpeningBody`) are kept beside
//! the scenario for the tests that verify with access; they are never put
//! on the ledger or in a bundle.

use std::collections::BTreeMap;

use ityv_crypto::{audit_seed, beacon_value, object_hash};
use ityv_encoding::{
    AuditRound, AuditRounds, BallotStyleId, ComparisonCode, Hash512, MAX_AUDIT_ROUNDS,
    SCHEMA_QUORUM_SIGNED, SCHEMA_WITNESSED_EVENT,
};
use ityv_state::{AuditPhase, RoundCount, audit_phase};
use ityv_verify::draw_sample;

use crate::day::Mark;
use crate::election::{CastInfo, Election};
use crate::ledger::{Step, lay_down};
use crate::plan::{Plan, TallyUnit, Until, plan, tally_units, unit_casts};
use crate::util::{hash_of, text};

/// The beacon round every simulated audit designates.
pub const BEACON_ROUND: u64 = 4_242;

/// A beacon publication as the caller observed it (fixture data): what the
/// console hands the verifier as `ityv_verify::BeaconObservation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Beacon {
    /// The round.
    pub round: u64,
    /// The round's published output.
    pub output: &'static [u8],
    /// The time bucket in which it was published.
    pub published: u64,
}

/// The time buckets of an audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// The freezes.
    pub freeze: u64,
    /// The commit (the bucket it declares).
    pub commit: u64,
    /// The checkpoint cut right after the commit.
    pub binding: u64,
    /// The beacon round's publication: seven buckets after the binding
    /// checkpoint (the rule asks three; the rest is the operating margin
    /// of PROTOCOL §12.1).
    pub published: u64,
    /// The seed.
    pub seed: u64,
    /// Findings.
    pub finding: u64,
    /// Hand counts.
    pub hand_count: u64,
    /// The last checkpoint.
    pub end: u64,
}

impl Timing {
    /// The audit two hours after a tally ready from bucket `ready` (whose
    /// last checkpoint is at `ready + 4`).
    #[must_use]
    pub const fn after(ready: u64) -> Self {
        let freeze = ready + 8;
        let commit = freeze + 1;
        let published = commit + 7;
        Self {
            freeze,
            commit,
            binding: commit,
            published,
            seed: published + 1,
            finding: published + 2,
            hand_count: published + 3,
            end: published + 4,
        }
    }
}

/// What the paper shows against the record, as the simulated day made
/// them: a mark the scanner read as `UNREADABLE` that the paper shows as
/// a vote is code 3; everything else agrees.
#[must_use]
pub const fn truthful(c: &CastInfo) -> ComparisonCode {
    match c.mark {
        Mark::Ambiguous(Some(_)) => ComparisonCode::UnreadableValid,
        Mark::Candidate(_) | Mark::Blank | Mark::Ambiguous(None) => ComparisonCode::Match,
    }
}

/// The usual rounds for a frame of `n` records: about two fifths of the
/// frame, then twice that, each tolerating a third of its size less one.
#[must_use]
pub fn standard_rounds(n: u64) -> Vec<(u64, u32)> {
    let first = (n / 3 + 1).clamp(1, n.max(1));
    let second = (2 * first).min(n);
    let threshold = |size: u64| u32::try_from((size - 1) / 3).unwrap();
    let mut out = vec![(first, threshold(first))];
    if second > first {
        out.push((second, threshold(second)));
    }
    out
}

/// One record of a style's frame.
#[derive(Debug, Clone, Copy)]
pub struct FrameRecord {
    /// Its box (global index).
    pub b: usize,
    /// The record and its secrets.
    pub cast: CastInfo,
}

/// An audit being laid out after a tallied plan.
pub struct Audit {
    /// The election.
    pub e: &'static Election,
    /// The plan so far (the tally, then the audit).
    pub plan: Plan,
    /// The time buckets.
    pub t: Timing,
    /// The dice record hash (fixture).
    pub dice: Hash512,
    /// The beacon designation document hash (fixture).
    pub source: Hash512,
    rules: BTreeMap<&'static str, Vec<(u64, u32)>>,
    freezes: Vec<&'static [u8]>,
    commit_at: Option<usize>,
    /// The seed computed over the binding checkpoint.
    pub seed: Option<Hash512>,
    /// The beacon publication the seed used.
    pub beacon: Option<Beacon>,
    /// The restricted bodies of every opening referenced (never on the
    /// ledger).
    pub openings: Vec<&'static [u8]>,
    codes: BTreeMap<[u8; 64], ComparisonCode>,
    variant: u64,
}

impl Audit {
    /// After the whole tallied plan of `e`.
    #[must_use]
    pub fn new(e: &'static Election) -> Self {
        let plan = plan(e, Until::Tallied);
        let t = Timing::after(plan.marks.ready);
        Self {
            e,
            plan,
            t,
            dice: hash_of("audit-dice", &[e.eid.as_bytes()]),
            source: hash_of("beacon-designation", &[e.eid.as_bytes()]),
            rules: BTreeMap::new(),
            freezes: Vec::new(),
            commit_at: None,
            seed: None,
            beacon: None,
            openings: Vec::new(),
            codes: BTreeMap::new(),
            variant: 0,
        }
    }

    fn push(&mut self, step: Step) -> usize {
        self.plan.steps.push(step);
        self.plan.steps.len() - 1
    }

    /// The tally units of ballot style `style`.
    fn units(&self, style: &str) -> Vec<TallyUnit> {
        tally_units(self.e)
            .into_iter()
            .filter(|u| u.style == style)
            .collect()
    }

    /// The sample frame of `style`: every record of every unit of the
    /// style (the tally includes them all), sorted by tracking code.
    #[must_use]
    pub fn frame(&self, style: &str) -> Vec<FrameRecord> {
        let mut out: Vec<FrameRecord> = Vec::new();
        for (b, bx) in self.e.boxes.iter().enumerate() {
            if bx.style == style {
                out.extend(self.e.casts[b].iter().map(|c| FrameRecord { b, cast: *c }));
            }
        }
        debug_assert_eq!(
            out.len(),
            self.units(style)
                .iter()
                .map(|u| unit_casts(self.e, *u).len())
                .sum::<usize>()
        );
        out.sort_by(|x, y| x.cast.code.as_bytes().cmp(y.cast.code.as_bytes()));
        out
    }

    /// The rounds frozen for `style`.
    #[must_use]
    pub fn rounds(&self, style: &str) -> Vec<(u64, u32)> {
        self.rules
            .get(style)
            .cloned()
            .unwrap_or_else(|| standard_rounds(self.frame(style).len() as u64))
    }

    /// Freezes every ballot style: `rules` where given, the standard
    /// rounds otherwise.
    pub fn freeze_all(&mut self, rules: &[(&'static str, Vec<(u64, u32)>)]) {
        for (style, r) in rules {
            self.rules.insert(style, r.clone());
        }
        let styles: Vec<&'static str> = self.e.spec.styles.iter().map(|s| s.id).collect();
        for style in styles {
            let frame: Vec<Hash512> = self.frame(style).iter().map(|r| r.cast.code).collect();
            let body = self.e.freeze_body(
                style,
                &frame,
                &self.rounds(style),
                (self.source, BEACON_ROUND),
                self.t.freeze,
            );
            self.freezes.push(body);
            let event = self.e.committee_event(body, 0);
            self.push(Step::event(SCHEMA_WITNESSED_EVENT, event));
        }
    }

    /// The audit commit over the freezes with dice record `dice`,
    /// declaring bucket `bucket`.
    pub fn commit_with(&mut self, dice: Hash512, bucket: u64) {
        let body = self
            .e
            .commit_body(dice, (self.source, BEACON_ROUND), &self.freezes, bucket);
        self.variant += 1;
        let event = self.e.committee_event(body, self.variant);
        let at = self.push(Step::event(SCHEMA_WITNESSED_EVENT, event));
        self.commit_at.get_or_insert(at);
    }

    /// The audit commit, as usual.
    pub fn commit(&mut self) {
        self.commit_with(self.dice, self.t.commit);
    }

    /// A checkpoint in bucket `bucket`.
    pub fn checkpoint(&mut self, bucket: u64) {
        self.push(Step::Checkpoint { bucket });
    }

    /// The binding checkpoint's hash: the first checkpoint after the
    /// commit, or without a commit the last one so far (what an operator
    /// without a commit would name).
    fn binding(&self) -> Hash512 {
        let steps = &self.plan.steps;
        let is_checkpoint = |s: &Step| matches!(s, Step::Checkpoint { .. });
        let at = match self.commit_at {
            Some(c) => c + steps[c..].iter().position(is_checkpoint).unwrap(),
            None => steps.iter().rposition(is_checkpoint).unwrap(),
        };
        lay_down(self.e, &steps[..=at])
            .last_checkpoint_hash
            .unwrap()
    }

    /// The seed: over the binding checkpoint, the dice record and the
    /// value of the first fixture output for which `wanted` holds of the
    /// seed. Pushes the seed event.
    pub fn seed(&mut self, wanted: impl Fn(&Self, &Hash512) -> bool) {
        let binding = self.binding();
        let (output, value, seed) = (0u32..256)
            .map(|k| {
                let output = text(&format!(
                    "ityv-sim fixture beacon: {} round {BEACON_ROUND} output {k}",
                    self.e.eid
                ));
                let value = beacon_value(&self.source, BEACON_ROUND, output);
                (output, value, audit_seed(&self.dice, &value, &binding))
            })
            .find(|(_, _, seed)| wanted(self, seed))
            .expect("no fixture output gives the wanted sample");
        let body = self
            .e
            .seed_body(self.dice, BEACON_ROUND, value, binding, seed, self.t.seed);
        let event = self.e.committee_event(body, 0);
        self.push(Step::event(SCHEMA_WITNESSED_EVENT, event));
        self.seed = Some(seed);
        self.beacon = Some(Beacon {
            round: BEACON_ROUND,
            output,
            published: self.t.published,
        });
    }

    /// The records `seed` draws for `style`, in draw order, as many as the
    /// last round holds.
    #[must_use]
    pub fn drawn(&self, style: &str, seed: &Hash512) -> Vec<FrameRecord> {
        let frame = self.frame(style);
        let last = self.rounds(style).last().unwrap().0;
        draw_sample(
            seed,
            BallotStyleId::new(text(style)).unwrap(),
            frame.len() as u64,
            last,
        )
        .unwrap()
        .iter()
        .map(|p| frame[*p as usize])
        .collect()
    }

    /// Opens record `r` and compares it with its paper as `code`.
    fn open_and_compare(&mut self, style: &str, r: &FrameRecord, code: ComparisonCode) {
        let body = self.e.restricted_opening(style, &r.cast);
        let opening = object_hash(body);
        self.openings.push(body);
        let reference = self.e.opening_reference(style, r.cast.code, opening);
        self.push(Step::event(SCHEMA_QUORUM_SIGNED, reference));
        let comparison = self.e.comparison(r.b, r.cast.code, opening, code, false);
        self.push(Step::event(SCHEMA_WITNESSED_EVENT, comparison));
        self.codes.insert(r.cast.code.0, code);
    }

    /// The phase of `style` with the comparisons so far.
    fn phase(&self, style: &str, sample: &[FrameRecord]) -> AuditPhase {
        let rounds = self.rounds(style);
        let n = self.frame(style).len() as u64;
        let mut counts = [RoundCount::default(); MAX_AUDIT_ROUNDS];
        for (i, &(size, _)) in rounds.iter().enumerate() {
            let take = usize::try_from(size.min(n)).unwrap();
            for r in &sample[..take.min(sample.len())] {
                if let Some(code) = self.codes.get(&r.cast.code.0) {
                    counts[i].compared += 1;
                    if *code != ComparisonCode::Match {
                        counts[i].nonzero += 1;
                    }
                }
            }
        }
        let list: Vec<AuditRound> = rounds
            .iter()
            .map(|&(sample_size, threshold)| AuditRound {
                sample_size,
                threshold,
            })
            .collect();
        audit_phase(&AuditRounds::new(&list).unwrap(), n, &counts)
    }

    /// Compares `style`'s sample in the order the audit calls for it: the
    /// current round's draws one by one until a round concludes or every
    /// round is exceeded; then every record of each device a code 1 or 2
    /// put under full comparison, and a finding for it; then, if every
    /// round was exceeded, a hand count of each unit. `judge` says what
    /// the paper shows. Returns the phase reached.
    pub fn compare(
        &mut self,
        style: &'static str,
        judge: impl Fn(&FrameRecord) -> ComparisonCode,
    ) -> AuditPhase {
        let seed = self.seed.expect("seed before comparisons");
        let sample = self.drawn(style, &seed);
        let rounds = self.rounds(style);
        let n = self.frame(style).len() as u64;
        let mut full: Vec<usize> = Vec::new();
        let phase = loop {
            let phase = self.phase(style, &sample);
            let AuditPhase::Sampling { round } = phase else {
                break phase;
            };
            let take = usize::try_from(rounds[usize::from(round)].0.min(n)).unwrap();
            let next = sample[..take]
                .iter()
                .find(|r| !self.codes.contains_key(&r.cast.code.0))
                .copied()
                .expect("a round still sampling has a record left");
            let code = judge(&next);
            self.open_and_compare(style, &next, code);
            if matches!(
                code,
                ComparisonCode::OtherCandidate | ComparisonCode::CandidateInvalid
            ) && !full.contains(&next.b)
            {
                full.push(next.b);
            }
        };
        for b in full {
            let rest: Vec<FrameRecord> = self
                .frame(style)
                .into_iter()
                .filter(|r| r.b == b && !self.codes.contains_key(&r.cast.code.0))
                .collect();
            for r in rest {
                self.open_and_compare(style, &r, judge(&r));
            }
            let finding = self.e.finding(b, self.t.finding);
            self.push(Step::event(SCHEMA_WITNESSED_EVENT, finding));
        }
        if phase == AuditPhase::HandCount {
            for u in self.units(style) {
                let event = self.e.hand_count(u.style, u.unit, self.t.hand_count);
                self.push(Step::event(SCHEMA_WITNESSED_EVENT, event));
            }
        }
        phase
    }

    /// The last checkpoint, over the whole audit.
    pub fn finish(&mut self) {
        self.checkpoint(self.t.end);
    }
}
