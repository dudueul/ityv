//! The audit stage (PROTOCOL.md §12, §14 8; VC-045..047, VC-059, VC-074;
//! ADR-0036).
//!
//! [`verify_audit`] runs the record-first comparison audit of every ballot
//! style that a box of the genesis's last state has, over the events of
//! the ledger in frame order:
//!
//! * **Freezes** (`AuditManifestFreezeBody` in a `WitnessedEvent`, §12.1),
//!   one per style, signed by the committee and observers of two or more
//!   organisations under `RLA` for its day, after every tally scope of the
//!   style and before the seed. The freeze's sample frame (count and
//!   sorted-set root) is compared with the style's included records
//!   recomputed by the tally stage over every reporting unit; a frame that
//!   differs holds the style ([`HoldReason::AuditFrameMismatch`]) and its
//!   audit cannot conclude. The freeze declares the rounds: cumulative
//!   sample sizes and the most discrepancies each round tolerates.
//! * **The seed** (`AuditSeedBody`, §12.1), one per election, signed like a
//!   freeze, under `RLA`, after every style's freeze. Its checkpoint must be
//!   the last valid checkpoint recorded before it, covering every freeze;
//!   its beacon round the one every freeze designated; its seed
//!   `SHA3-512("ityv:seed:v1" ‖ 0x00 ‖ dice ‖ beacon ‖ checkpoint)`
//!   (VC-045). The verifier cannot fetch the beacon: the caller supplies the
//!   value it observed for the round ([`AuditInput::beacon`]); a value that
//!   differs refuses the seed, and no value leaves the stage incomplete.
//! * **The sample** (§12.2, VC-046): for each style, a partial Fisher–Yates
//!   shuffle of the sorted frame driven by the style's sample stream
//!   ([`draw_sample`], `ityv_crypto::SampleStream`), as long as the last
//!   round. Round `r` is the first `min(size_r, frame)` records drawn.
//! * **Sample opening references** (`SampleOpeningRefBody` in a
//!   `QuorumSigned`, §12.3): the trustees' public reference to the
//!   restricted opening of one record, by the object hash of its body.
//!   Taken after the seed, under `OBSERVER_ACCESS` for the seed's day, by
//!   a qualified trustee quorum, once per record, and only for a record
//!   the audit calls for: in the sample of the round being compared, or
//!   of a device under full comparison (§12.5). A trustee opening of
//!   anything else is refused: an opening reveals a choice to its viewers.
//! * **Restricted openings** (`SampleOpeningBody`, VC-047): a caller with
//!   access supplies the bodies ([`AuditInput::openings`]); each one whose
//!   object hash an accepted reference names is reconstructed against the
//!   record's commitments. A body that does not reconstruct holds the style
//!   ([`HoldReason::SampleOpeningMismatch`]). The public verifier has no
//!   bodies and checks presence and signatures only; the result for each
//!   record is a [`Reconstruction`], never the opened values.
//! * **Comparisons** (`SampleComparisonBody`, §12.3), once per record, after
//!   its reference and naming its opening, signed by auditors of two
//!   organisations and observers of two organisations, the device being
//!   the record's box. Every nonzero code counts toward the escalation rule
//!   (`ityv_state::audit_phase`); codes 1 and 2 put the device under full
//!   comparison and call for an `AuditFinding` (VC-074); codes 3 and 4 are
//!   counted per device; codes 5 and 6 hold the box
//!   ([`HoldReason::AuditCustody`]); transfer marks are counted per device
//!   (and so per station).
//! * **Findings** (`AuditFindingBody`, §12.4), signed like a comparison,
//!   under `RLA`, naming a box of the style.
//! * **Hand counts** (`HandCountReportBody`, §12.4), one per reporting
//!   unit of the style, signed like a paper count, and only after the
//!   style's sample escalated past its last round.
//!
//! A style's audit concludes ([`AuditStage::concluded`]) when its freeze
//! agrees with the ledger, the seed is taken with its beacon confirmed, a
//! round concluded under its threshold or every unit of the style has its
//! hand count, every device with a code 1 or 2 has every included record
//! compared and a finding recorded after its first such code, and the style
//! holds nothing. The stage passes when every style concluded and nothing
//! was refused; only then does the report reach `PAPER_AUDITED`.
//!
//! Every event the stage cannot take is listed ([`AuditRefused`]) and holds;
//! the same body again is [`AuditRefusal::Repeated`], another body for the
//! same subject [`AuditRefusal::Conflict`].
//!
//! What this stage does not prove: that the declared sample sizes and
//! thresholds are what the rule document's formula gives (ADR-0036); that
//! the dice record and the beacon value are what was drawn (the caller
//! vouches for the beacon); that the auditors judged the paper rightly (the
//! parties' observers cross-check, §12.3); full comparisons for the other
//! reasons of §12.5 (quarantine, attestation incidents), whose events have
//! no schema yet.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use ityv_crypto::hash::object_hash;
use ityv_crypto::{
    Bases, CastId, Opening, OptionCount, OptionIndex, Purpose, SampleStream, audit_seed,
    verify_opening,
};
use ityv_encoding::{
    AuditFindingBody, AuditFindingParts, AuditFreezeParts, AuditManifestFreezeBody, AuditRounds,
    AuditSeedBody, AuditSeedParts, BallotStyleId, BoxId, CastRecord, ComparisonCode, Decode,
    EventRole, HandCountReportBody, Hash512, MAX_AUDIT_ROUNDS, PaperCountParts, QuorumKind,
    QuorumSigned, ReportingUnitId, SCHEMA_AUDIT_FINDING_BODY, SCHEMA_AUDIT_FREEZE_BODY,
    SCHEMA_AUDIT_SEED_BODY, SCHEMA_CAST_RECORD, SCHEMA_HAND_COUNT_REPORT_BODY,
    SCHEMA_QUORUM_SIGNED, SCHEMA_SAMPLE_COMPARISON_BODY, SCHEMA_SAMPLE_OPENING_BODY,
    SCHEMA_WITNESSED_EVENT, SampleComparisonBody, SampleComparisonParts, SampleOpeningBody,
    SampleOpeningRefParts, SchemaId, Seq, StationId, TimeBucket, WitnessedEvent, decode_object,
    schema_version,
};
use ityv_ledger::sorted_set_root;
use ityv_state::{
    AuditPhase, Cap, FollowUp, HandCount, HoldReason, HoldSet, ObserverAccess, Rla, RosterEntry,
    RoundCount, SeedReadiness, Signed, admit_audit_freeze, admit_audit_seed, admit_sample_opening,
    audit_phase, check_audit_signers, follow_up,
};

use crate::authority::{AuthorityStage, day_of};
use crate::checkpoint::{CheckpointChain, VerifiedCheckpoint};
use crate::genesis::VerifiedGenesis;
use crate::index::LedgerIndex;
use crate::records::{RecordStage, commitments_of, scalars};
use crate::sigs::Material;
use crate::tally::{TallyStage, Trustees, event_at};

/// The beacon value the caller observed (PROTOCOL.md §12.1): the published
/// value of round `round` of the beacon the freezes designate. The
/// verifier cannot fetch it; like the genesis pin, it comes from outside
/// the data it verifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BeaconValue {
    /// The beacon round.
    pub round: u64,
    /// Its published value.
    pub value: Hash512,
}

/// What the caller brings to the audit beyond the ledger.
#[derive(Debug, Clone, Copy, Default)]
pub struct AuditInput<'i> {
    /// The beacon value observed for the seed's round, if the caller has
    /// it. Without it the audit cannot conclude.
    pub beacon: Option<BeaconValue>,
    /// Restricted `SampleOpeningBody` objects (schema `0x0049`) a caller
    /// with access holds, in any order; empty for the public verifier.
    pub openings: &'i [&'i [u8]],
}

/// Which kind of audit event a refusal concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditEvent {
    /// An audit manifest freeze.
    Freeze,
    /// The audit seed.
    Seed,
    /// A sample opening reference.
    Opening,
    /// A sample comparison.
    Comparison,
    /// An audit finding.
    Finding,
    /// A hand count report.
    HandCount,
}

/// Why the audit stage refused an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditRefusal {
    /// A signature does not verify under the key registered for its signer
    /// (the committee's, a roster auditor's, observer's or chair's, of the
    /// state in force or an earlier one), a signer is not registered in the
    /// role and organisation it names, two signers share a key half, or the
    /// trustees are not a qualified quorum.
    Signature,
    /// No legal authorization grants `RLA` (freeze, seed, finding) for the
    /// day of its time bucket, or `OBSERVER_ACCESS` (opening) for the day of
    /// the seed.
    Capability,
    /// It names a ballot style, reporting unit, record or device the audit
    /// does not have, a record of another style or device, or another
    /// number of candidates.
    Subject,
    /// Too early: a freeze before every tally scope of its style; a seed
    /// before every style's freeze or whose checkpoint does not cover them;
    /// an opening before the seed; a comparison before its record's
    /// opening; a hand count before the style's sample escalated past its
    /// last round.
    Premature,
    /// The seed's checkpoint is not the last valid checkpoint recorded
    /// before it.
    Checkpoint,
    /// The seed's beacon round is not the one every freeze designated, the
    /// freezes designate different beacons, or its value differs from the
    /// one the caller observed.
    Beacon,
    /// The seed is not the hash of its inputs (VC-045).
    Recompute,
    /// An opening of a record that is neither in the sample of the round
    /// being compared nor of a device under full comparison.
    NotCalled,
    /// A comparison names another opening than the one taken for its
    /// record.
    Opening,
    /// The body already taken for its subject (style, election, record,
    /// finding or unit), again under other signature bytes.
    Repeated,
    /// A second freeze of a style, seed, opening or comparison of a record,
    /// finding or hand count of a unit, with another body than the one
    /// taken: two signed answers to one question.
    Conflict,
}

/// An event the audit stage refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditRefused {
    /// The frame that carries it.
    pub seq: Seq,
    /// What kind of event it is.
    pub event: AuditEvent,
    /// Why it was refused.
    pub refusal: AuditRefusal,
}

/// How a freeze's sample frame differs from the ledger's (ADR-0036).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameProblem {
    /// The frame count is not the number of included records.
    Count,
    /// The frame root is not their sorted-set root.
    Root,
}

/// What the restricted opening of a record showed (VC-047). The opened
/// values themselves never leave the stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reconstruction {
    /// The caller supplied no body with the referenced hash (the public
    /// verifier).
    NotSupplied,
    /// The supplied body opens every commitment of the record.
    Reconstructed,
    /// The supplied body is not a sample opening of the record, or does not
    /// open its commitments.
    Mismatch,
}

/// A comparison the stage took.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Comparison {
    /// The frame that carries it.
    pub seq: Seq,
    /// The reason code.
    pub code: ComparisonCode,
    /// Whether ink transferred onto the paper.
    pub transfer_mark: bool,
}

/// A record the audit opened (in the sample or under full comparison).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditedRecord<'a> {
    /// The record's tracking code.
    pub record_hash: Hash512,
    /// Its box (the device).
    pub box_id: BoxId<'a>,
    /// Its position in the drawn sample, if drawn.
    pub position: Option<u64>,
    /// The frame of the opening reference taken.
    pub opening: Seq,
    /// The restricted opening checked against the record.
    pub reconstruction: Reconstruction,
    /// The comparison taken.
    pub comparison: Option<Comparison>,
}

/// One device (box) of a ballot style under audit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAudit<'a> {
    /// The box.
    pub box_id: BoxId<'a>,
    /// Its station.
    pub station_id: StationId<'a>,
    /// Its included records (the part of the frame it holds).
    pub records: u64,
    /// Comparisons taken of its records.
    pub compared: u64,
    /// Comparisons per reason code `0..=6`: codes 3 and 4 are the
    /// device's published rates (§12.3).
    pub codes: [u64; 7],
    /// Comparisons with a transfer mark.
    pub transfer_marks: u64,
    /// The frame of its first code 1 or 2: from there every record of the
    /// device is compared (§12.5, VC-074).
    pub full_comparison_from: Option<Seq>,
    /// The frames of the findings taken for the device.
    pub findings: Vec<Seq>,
    /// The device's holds.
    pub holds: HoldSet,
}

impl DeviceAudit<'_> {
    /// Whether what the device's comparisons call for is done: without a
    /// code 1 or 2 nothing; with one, every record compared and a finding
    /// recorded after the first such code.
    #[must_use]
    pub fn followed_up(&self) -> bool {
        self.full_comparison_from.is_none_or(|from| {
            self.compared == self.records && self.findings.iter().any(|f| f.get() > from.get())
        })
    }
}

/// The audit of one ballot style.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StyleAudit<'a> {
    /// The ballot style.
    pub ballot_style_id: BallotStyleId<'a>,
    /// Its reporting units.
    pub units: Vec<ReportingUnitId<'a>>,
    /// The number of records in the sample frame (the included records of
    /// every unit).
    pub frame_count: u64,
    /// Their sorted-set root.
    pub frame_root: Option<Hash512>,
    /// The frame of the freeze taken.
    pub freeze: Option<Seq>,
    /// How that freeze's frame differs from the ledger's.
    pub frame_problems: Vec<FrameProblem>,
    /// The rounds the freeze declared.
    pub rounds: Option<AuditRounds>,
    /// The records drawn, in draw order, as many as the last round holds
    /// (public: anyone recomputes them, VC-046).
    pub sample: Vec<Hash512>,
    /// The comparisons among each round's sample.
    pub counts: [RoundCount; MAX_AUDIT_ROUNDS],
    /// Where the audit stands, once there is a sample.
    pub phase: Option<AuditPhase>,
    /// The frame of the comparison after which the style is counted by
    /// hand.
    pub hand_count_from: Option<Seq>,
    /// The records opened, ascending by tracking code.
    pub records: Vec<AuditedRecord<'a>>,
    /// Every box of the style, in identifier order.
    pub devices: Vec<DeviceAudit<'a>>,
    /// The hand counts taken: unit and frame.
    pub hand_counts: Vec<(ReportingUnitId<'a>, Seq)>,
    /// The style's holds.
    pub holds: HoldSet,
}

impl StyleAudit<'_> {
    /// Whether the style's audit concluded under its rule, given whether
    /// the seed was taken with its beacon confirmed.
    fn concluded_with(&self, seeded: bool) -> bool {
        let by_rule = match self.phase {
            Some(AuditPhase::Concluded { .. }) => true,
            Some(AuditPhase::HandCount) => self
                .units
                .iter()
                .all(|u| self.hand_counts.iter().any(|(h, _)| h == u)),
            Some(AuditPhase::Sampling { .. }) | None => false,
        };
        seeded
            && self.freeze.is_some()
            && self.frame_problems.is_empty()
            && by_rule
            && self.devices.iter().all(DeviceAudit::followed_up)
            && self.holds.is_empty()
    }
}

/// The seed the stage took.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SeedTaken {
    /// The frame that carries it.
    pub seq: Seq,
    /// The seed (recomputed).
    pub seed: Hash512,
    /// The beacon round.
    pub beacon_round: u64,
    /// Whether the caller observed the same beacon value for the round.
    pub beacon_confirmed: bool,
}

/// The audit stage (PROTOCOL.md §14 item 8).
#[derive(Debug, Clone, Default)]
pub struct AuditStage<'a> {
    styles: Vec<StyleAudit<'a>>,
    seed: Option<SeedTaken>,
    refused: Vec<AuditRefused>,
}

impl<'a> AuditStage<'a> {
    /// One entry per ballot style of the genesis's last state, in style
    /// order.
    #[must_use]
    pub fn styles(&self) -> &[StyleAudit<'a>] {
        &self.styles
    }

    /// The audit of ballot style `style`.
    #[must_use]
    pub fn style(&self, style: &[u8]) -> Option<&StyleAudit<'a>> {
        self.styles
            .iter()
            .find(|s| s.ballot_style_id.as_bytes() == style)
    }

    /// The seed taken.
    #[must_use]
    pub const fn seed(&self) -> Option<&SeedTaken> {
        self.seed.as_ref()
    }

    /// The events refused, in frame order.
    #[must_use]
    pub fn refused(&self) -> &[AuditRefused] {
        &self.refused
    }

    /// Every style's holds and one per kind of event refused.
    #[must_use]
    pub fn holds(&self) -> HoldSet {
        let styles = self
            .styles
            .iter()
            .fold(HoldSet::empty(), |h, s| h.union(s.holds));
        self.refused
            .iter()
            .fold(styles, |h, r| h.with(refusal_hold(r.event)))
    }

    /// Whether the style `style` concluded under its rule: the seed taken
    /// with its beacon confirmed, the freeze agreeing with the ledger, a
    /// round concluded or a hand count of every unit, every device with a
    /// code 1 or 2 followed up ([`DeviceAudit::followed_up`]), and nothing
    /// held.
    #[must_use]
    pub fn concluded(&self, style: &StyleAudit<'_>) -> bool {
        style.concluded_with(self.seed.is_some_and(|s| s.beacon_confirmed))
    }

    /// Whether every style's audit concluded and nothing was refused.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.refused.is_empty()
            && self.seed.is_some_and(|s| s.beacon_confirmed)
            && self.styles.iter().all(|s| self.concluded(s))
    }

    /// The transfer marks and comparisons of every station's devices
    /// (§12.3: the frequency per station checks the privacy sleeves).
    #[must_use]
    pub fn station_marks(&self) -> Vec<(StationId<'a>, u64, u64)> {
        let mut out: BTreeMap<&'a [u8], (StationId<'a>, u64, u64)> = BTreeMap::new();
        for d in self.styles.iter().flat_map(|s| &s.devices) {
            let slot = out
                .entry(d.station_id.as_bytes())
                .or_insert((d.station_id, 0, 0));
            slot.1 = slot.1.saturating_add(d.transfer_marks);
            slot.2 = slot.2.saturating_add(d.compared);
        }
        out.into_values().collect()
    }
}

/// The hold of a refused event.
const fn refusal_hold(event: AuditEvent) -> HoldReason {
    match event {
        AuditEvent::Freeze => HoldReason::AuditFreezeRefused,
        AuditEvent::Seed => HoldReason::AuditSeedRefused,
        AuditEvent::Opening => HoldReason::SampleOpeningRefused,
        AuditEvent::Comparison => HoldReason::SampleComparisonRefused,
        AuditEvent::Finding => HoldReason::AuditFindingRefused,
        AuditEvent::HandCount => HoldReason::HandCountRefused,
    }
}

/// The sample of a frame of `frame_len` records under `seed` for ballot
/// style `style` (PROTOCOL.md §12.2, VC-046): the first `min(count,
/// frame_len)` positions of a Fisher–Yates shuffle of `0..frame_len` driven
/// by the style's sample stream. Draw `i` swaps position `i` with position
/// `i + below(frame_len − i)` and yields the index now at `i`; so every
/// position is drawn at most once, and a longer sample begins with the
/// shorter one. `None` if the stream rejects [`ityv_crypto::sample::MAX_TRIES`]
/// words in a row.
#[must_use]
pub fn draw_sample(
    seed: &Hash512,
    style: BallotStyleId<'_>,
    frame_len: u64,
    count: u64,
) -> Option<Vec<u64>> {
    let mut stream = SampleStream::new(seed, style);
    let n = count.min(frame_len);
    let mut moved: BTreeMap<u64, u64> = BTreeMap::new();
    let mut out: Vec<u64> = Vec::new();
    for i in 0..n {
        let j = i.checked_add(stream.below(frame_len.checked_sub(i)?)?)?;
        let at_i = moved.get(&i).copied().unwrap_or(i);
        let at_j = moved.get(&j).copied().unwrap_or(j);
        moved.insert(j, at_i);
        moved.insert(i, at_j);
        out.push(at_j);
    }
    Some(out)
}

fn decode<'a, T: Decode<'a>>(schema: SchemaId, bytes: &'a [u8]) -> Option<T> {
    decode_object(schema, schema_version(schema), bytes).ok()
}

/// The refusal of a second event for what `taken` (a body hash) already
/// answers: the same body again, or a conflict.
fn again(taken: Hash512, body: &[u8]) -> AuditRefusal {
    if taken == object_hash(body) {
        AuditRefusal::Repeated
    } else {
        AuditRefusal::Conflict
    }
}

/// An accepted record of a style's frame: its box and its cast record.
struct FrameRecord<'a> {
    style: BallotStyleId<'a>,
    box_id: BoxId<'a>,
    record: Option<CastRecord<'a>>,
}

/// What the stage needs throughout.
struct Ctx<'g, 'a> {
    genesis: &'g VerifiedGenesis<'a>,
    index: &'g LedgerIndex<'a>,
    authority: &'g AuthorityStage<'a>,
    trustees: Trustees<'a>,
    checkpoints: &'g [VerifiedCheckpoint],
    records: BTreeMap<[u8; 64], FrameRecord<'a>>,
}

impl<'a> Ctx<'_, 'a> {
    /// The capability of scope `S` for the day of `bucket`.
    fn cap<S: ityv_state::ScopeMarker>(&self, bucket: TimeBucket) -> Option<Cap<'a, S>> {
        let day = day_of(self.genesis, bucket)?;
        self.authority.authorization()?.grant(day).ok()
    }

    /// Binds the signatures of `event` at frame `seq` and checks them with
    /// `check`: the committee's under the genesis key; each other signer's
    /// under the key of an entry the roster of the state in force or an
    /// earlier one registers for that signer, the newest whose key
    /// verifies (an amendment may rotate a key; an event signed before it
    /// carries the old one). `check` then binds roles and organisations to
    /// the roster in force and those entries.
    fn people_signed<F>(&self, seq: Seq, event: &WitnessedEvent<'_>, check: F) -> bool
    where
        F: FnOnce(&Signed<'_>, &[RosterEntry<'a>], &[RosterEntry<'a>]) -> bool,
    {
        let Some(purpose) = Purpose::new(event.purpose()) else {
            return false;
        };
        let state = self.index.state_at(seq);
        let rosters: Vec<Vec<RosterEntry<'a>>> =
            (0..=state).map(|k| self.genesis.roster_at(k)).collect();
        let committee = self.genesis.genesis().committee_key();
        let mut keys: Vec<RosterEntry<'a>> = Vec::new();
        let mut pairs = Vec::new();
        for s in event.sigs() {
            if s.role == EventRole::Committee {
                pairs.push((s.sig, committee));
                continue;
            }
            let found = rosters
                .iter()
                .rev()
                .flatten()
                .filter(|r| r.get().signer_id.as_bytes() == s.signer_id.as_bytes())
                .find(|r| {
                    Material::new(core::iter::once((s.sig, r.get().key)))
                        .is_some_and(|m| m.verify(&purpose, event.body_bytes()).is_some())
                });
            let Some(entry) = found else {
                return false;
            };
            keys.push(*entry);
            pairs.push((s.sig, entry.get().key));
        }
        let (Some(material), Some(in_force)) = (Material::new(pairs.into_iter()), rosters.last())
        else {
            return false;
        };
        let Some(tokens) = material.verify(&purpose, event.body_bytes()) else {
            return false;
        };
        check(
            &Signed {
                event,
                tokens: &tokens,
            },
            in_force,
            &keys,
        )
    }

    /// Whether `event` is signed by the committee, observers and auditors
    /// it names ([`check_audit_signers`]).
    fn audit_signed(&self, seq: Seq, event: &WitnessedEvent<'_>) -> bool {
        let committee = self.genesis.genesis().committee_key();
        self.people_signed(seq, event, |signed, roster, keys| {
            check_audit_signers(signed, roster, keys, committee).is_ok()
        })
    }

    /// The last valid checkpoint recorded before frame `at`.
    fn last_checkpoint(&self, at: Seq) -> Option<&VerifiedCheckpoint> {
        self.checkpoints
            .iter()
            .filter(|c| c.frame.get() < at.get())
            .max_by_key(|c| c.frame.get())
    }
}

/// A ballot style under audit, while the stage runs.
struct StyleWork<'a> {
    audit: StyleAudit<'a>,
    /// The sorted frame.
    frame: Vec<Hash512>,
    /// The frames of the tally scopes of its units (`None` where not yet
    /// taken).
    scopes: Vec<Option<Seq>>,
    /// The freeze taken: its body hash and fields.
    freeze: Option<(Hash512, AuditFreezeParts<'a>)>,
    /// The sample position of each drawn record.
    positions: BTreeMap<[u8; 64], u64>,
    /// Per opened record: its reference's body hash and opening hash.
    openings: BTreeMap<[u8; 64], (Hash512, Hash512)>,
    /// Per compared record: the comparison's body hash.
    comparisons: BTreeMap<[u8; 64], Hash512>,
    /// The findings taken, by (device, finding hash): body hash.
    findings: BTreeMap<(&'a [u8], [u8; 64]), Hash512>,
    /// The hand counts taken, by unit: body hash.
    hand_counts: BTreeMap<&'a [u8], Hash512>,
}

impl StyleWork<'_> {
    /// The rounds' sample sizes bounded by the frame.
    fn round_sizes(&self) -> Vec<u64> {
        let frame = self.audit.frame_count;
        self.audit
            .rounds
            .map(|r| {
                r.as_slice()
                    .iter()
                    .map(|round| round.sample_size.min(frame))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Whether the audit calls for an opening of `record` of `box_id` at
    /// this point: in the sample of the round being compared, or of a
    /// device under full comparison.
    fn calls_for(&self, record: &Hash512, box_id: &[u8]) -> bool {
        let sampled = match (self.audit.phase, self.positions.get(&record.0)) {
            (Some(AuditPhase::Sampling { round }), Some(position)) => self
                .round_sizes()
                .get(usize::from(round))
                .is_some_and(|size| position < size),
            _ => false,
        };
        let full = self
            .audit
            .devices
            .iter()
            .any(|d| d.box_id.as_bytes() == box_id && d.full_comparison_from.is_some());
        sampled || full
    }

    /// Records a comparison of `record` (at sample position `position`, if
    /// drawn) with code `code` in the round counts, and moves the phase.
    fn count(&mut self, seq: Seq, position: Option<u64>, code: ComparisonCode) {
        if let Some(position) = position {
            let sizes = self.round_sizes();
            for (count, size) in self.audit.counts.iter_mut().zip(sizes) {
                if position < size {
                    count.compared = count.compared.saturating_add(1);
                    if follow_up(code).is_discrepancy() {
                        count.nonzero = count.nonzero.saturating_add(1);
                    }
                }
            }
        }
        if let Some(rounds) = self.audit.rounds.as_ref()
            && self.audit.phase.is_some()
        {
            let phase = audit_phase(rounds, self.audit.frame_count, &self.audit.counts);
            if phase == AuditPhase::HandCount && self.audit.hand_count_from.is_none() {
                self.audit.hand_count_from = Some(seq);
            }
            self.audit.phase = Some(phase);
        }
    }
}

/// The audit events of the ledger, decoded, in frame order.
enum Item<'a> {
    Freeze(Box<(WitnessedEvent<'a>, AuditFreezeParts<'a>)>),
    Seed(Box<(WitnessedEvent<'a>, AuditSeedParts<'a>)>),
    Opening(Box<(QuorumSigned<'a>, SampleOpeningRefParts<'a>)>),
    Comparison(Box<(WitnessedEvent<'a>, SampleComparisonParts<'a>)>),
    Finding(Box<(WitnessedEvent<'a>, AuditFindingParts<'a>)>),
    HandCount(Box<(WitnessedEvent<'a>, PaperCountParts<'a>)>),
}

fn items<'a>(index: &LedgerIndex<'a>) -> Vec<(Seq, Item<'a>)> {
    let mut out = Vec::new();
    for e in index.events() {
        let Some(bytes) = e.bytes else { continue };
        let item = if e.schema == SCHEMA_WITNESSED_EVENT {
            let Some(w) = decode::<WitnessedEvent<'a>>(e.schema, bytes) else {
                continue;
            };
            let s = w.body_schema();
            if s == SCHEMA_AUDIT_FREEZE_BODY {
                w.body::<AuditManifestFreezeBody<'a>>(s)
                    .ok()
                    .map(|b| Item::Freeze(Box::new((w, *b.parts()))))
            } else if s == SCHEMA_AUDIT_SEED_BODY {
                w.body::<AuditSeedBody<'a>>(s)
                    .ok()
                    .map(|b| Item::Seed(Box::new((w, *b.parts()))))
            } else if s == SCHEMA_SAMPLE_COMPARISON_BODY {
                w.body::<SampleComparisonBody<'a>>(s)
                    .ok()
                    .map(|b| Item::Comparison(Box::new((w, *b.parts()))))
            } else if s == SCHEMA_AUDIT_FINDING_BODY {
                w.body::<AuditFindingBody<'a>>(s)
                    .ok()
                    .map(|b| Item::Finding(Box::new((w, *b.parts()))))
            } else if s == SCHEMA_HAND_COUNT_REPORT_BODY {
                w.body::<HandCountReportBody<'a>>(s)
                    .ok()
                    .map(|b| Item::HandCount(Box::new((w, *b.parts()))))
            } else {
                None
            }
        } else if e.schema == SCHEMA_QUORUM_SIGNED {
            decode::<QuorumSigned<'a>>(e.schema, bytes)
                .filter(|q| q.kind() == QuorumKind::SampleOpening)
                .and_then(|q| {
                    q.sample_opening_ref()
                        .map(|b| Item::Opening(Box::new((q, *b.parts()))))
                })
        } else {
            None
        };
        if let Some(item) = item {
            out.push((e.seq, item));
        }
    }
    out
}

/// The stage's working state.
struct Work<'a> {
    styles: BTreeMap<&'a [u8], StyleWork<'a>>,
    seed: Option<(Hash512, SeedTaken)>,
    /// `OBSERVER_ACCESS` for the seed's day.
    viewing: Option<Cap<'a, ObserverAccess>>,
    refused: Vec<AuditRefused>,
}

impl<'a> Work<'a> {
    fn refuse(&mut self, seq: Seq, event: AuditEvent, refusal: AuditRefusal) {
        self.refused.push(AuditRefused {
            seq,
            event,
            refusal,
        });
    }

    /// The seed's frame, if a seed was taken.
    fn seed_frame(&self) -> Option<Seq> {
        self.seed.map(|(_, s)| s.seq)
    }

    fn take_freeze(
        &mut self,
        ctx: &Ctx<'_, 'a>,
        seq: Seq,
        event: &WitnessedEvent<'_>,
        p: &AuditFreezeParts<'a>,
    ) -> Result<(), AuditRefusal> {
        if !ctx.audit_signed(seq, event) {
            return Err(AuditRefusal::Signature);
        }
        let cap = ctx
            .cap::<Rla>(p.time_bucket)
            .ok_or(AuditRefusal::Capability)?;
        let style = self
            .styles
            .get_mut(p.ballot_style_id.as_bytes())
            .ok_or(AuditRefusal::Subject)?;
        // The seed waits for every style's freeze, so after the seed every
        // freeze is a second one: repeated or conflicting, never taken.
        if let Some((taken, _)) = style.freeze {
            return Err(again(taken, event.body_bytes()));
        }
        let scopes_taken = style
            .scopes
            .iter()
            .all(|s| s.is_some_and(|s| s.get() < seq.get()));
        admit_audit_freeze(&cap, p.election_id, scopes_taken)
            .map_err(|_| AuditRefusal::Premature)?;
        let a = &mut style.audit;
        a.freeze = Some(seq);
        a.rounds = Some(p.rounds);
        if p.frame_count != a.frame_count {
            a.frame_problems.push(FrameProblem::Count);
        }
        if a.frame_root != Some(p.frame_root) {
            a.frame_problems.push(FrameProblem::Root);
        }
        a.holds = a
            .holds
            .with_if(!a.frame_problems.is_empty(), HoldReason::AuditFrameMismatch);
        style.freeze = Some((object_hash(event.body_bytes()), *p));
        Ok(())
    }

    fn take_seed(
        &mut self,
        ctx: &Ctx<'_, 'a>,
        input: &AuditInput<'_>,
        seq: Seq,
        event: &WitnessedEvent<'_>,
        p: &AuditSeedParts<'_>,
    ) -> Result<(), AuditRefusal> {
        if !ctx.audit_signed(seq, event) {
            return Err(AuditRefusal::Signature);
        }
        let cap = ctx
            .cap::<Rla>(p.time_bucket)
            .ok_or(AuditRefusal::Capability)?;
        if let Some((taken, _)) = self.seed {
            return Err(again(taken, event.body_bytes()));
        }
        let freezes: Vec<(Seq, &AuditFreezeParts<'a>)> = self
            .styles
            .values()
            .filter_map(|s| s.audit.freeze.zip(s.freeze.as_ref().map(|(_, p)| p)))
            .collect();
        let styles_frozen = freezes.len() == self.styles.len();
        let one_beacon = freezes.iter().all(|(_, f)| {
            f.beacon_round == p.beacon_round
                && freezes
                    .first()
                    .is_some_and(|(_, first)| first.beacon_source == f.beacon_source)
        });
        if !one_beacon {
            return Err(AuditRefusal::Beacon);
        }
        let checkpoint = ctx
            .last_checkpoint(seq)
            .filter(|c| c.body_hash == p.checkpoint_hash)
            .ok_or(AuditRefusal::Checkpoint)?;
        let freezes_checkpointed = freezes
            .iter()
            .all(|(frame, _)| frame.get() <= checkpoint.tree_size);
        admit_audit_seed(
            &cap,
            p.election_id,
            SeedReadiness {
                styles_frozen,
                freezes_checkpointed,
            },
        )
        .map_err(|_| AuditRefusal::Premature)?;
        let seed = audit_seed(&p.dice_hash, &p.beacon_value, &p.checkpoint_hash);
        if seed != p.seed {
            return Err(AuditRefusal::Recompute);
        }
        let observed = input.beacon.filter(|b| b.round == p.beacon_round);
        if observed.is_some_and(|b| b.value != p.beacon_value) {
            return Err(AuditRefusal::Beacon);
        }
        self.seed = Some((
            object_hash(event.body_bytes()),
            SeedTaken {
                seq,
                seed,
                beacon_round: p.beacon_round,
                beacon_confirmed: observed.is_some(),
            },
        ));
        self.viewing = ctx.cap::<ObserverAccess>(p.time_bucket);
        for style in self.styles.values_mut() {
            draw(style, &seed);
        }
        Ok(())
    }

    fn take_opening(
        &mut self,
        ctx: &Ctx<'_, 'a>,
        seq: Seq,
        q: &QuorumSigned<'_>,
        p: &SampleOpeningRefParts<'_>,
    ) -> Result<(), AuditRefusal> {
        if !ctx.trustees.signed(q) {
            return Err(AuditRefusal::Signature);
        }
        if self.seed_frame().is_none_or(|s| s.get() >= seq.get()) {
            return Err(AuditRefusal::Premature);
        }
        let viewing = self.viewing.as_ref().ok_or(AuditRefusal::Capability)?;
        let record = ctx
            .records
            .get(&p.record_hash.0)
            .filter(|r| r.style.as_bytes() == p.ballot_style_id.as_bytes())
            .ok_or(AuditRefusal::Subject)?;
        let style = self
            .styles
            .get_mut(record.style.as_bytes())
            .ok_or(AuditRefusal::Subject)?;
        if let Some((taken, _)) = style.openings.get(&p.record_hash.0) {
            return Err(again(*taken, q.body_bytes()));
        }
        let called = style.calls_for(&p.record_hash, record.box_id.as_bytes());
        admit_sample_opening(viewing, p.election_id, called)
            .map_err(|_| AuditRefusal::NotCalled)?;
        style.openings.insert(
            p.record_hash.0,
            (object_hash(q.body_bytes()), p.opening_hash),
        );
        style.audit.records.push(AuditedRecord {
            record_hash: p.record_hash,
            box_id: record.box_id,
            position: style.positions.get(&p.record_hash.0).copied(),
            opening: seq,
            reconstruction: Reconstruction::NotSupplied,
            comparison: None,
        });
        Ok(())
    }

    fn take_comparison(
        &mut self,
        ctx: &Ctx<'_, 'a>,
        seq: Seq,
        event: &WitnessedEvent<'_>,
        p: &SampleComparisonParts<'_>,
    ) -> Result<(), AuditRefusal> {
        if !ctx.audit_signed(seq, event) {
            return Err(AuditRefusal::Signature);
        }
        let record = ctx
            .records
            .get(&p.record_hash.0)
            .filter(|r| {
                r.style.as_bytes() == p.ballot_style_id.as_bytes()
                    && r.box_id.as_bytes() == p.device_id.as_bytes()
            })
            .ok_or(AuditRefusal::Subject)?;
        let style = self
            .styles
            .get_mut(record.style.as_bytes())
            .ok_or(AuditRefusal::Subject)?;
        if let Some(taken) = style.comparisons.get(&p.record_hash.0) {
            return Err(again(*taken, event.body_bytes()));
        }
        let (_, opening_hash) = *style
            .openings
            .get(&p.record_hash.0)
            .ok_or(AuditRefusal::Premature)?;
        if opening_hash != p.opening_hash {
            return Err(AuditRefusal::Opening);
        }
        style
            .comparisons
            .insert(p.record_hash.0, object_hash(event.body_bytes()));
        let comparison = Comparison {
            seq,
            code: p.code,
            transfer_mark: p.transfer_mark,
        };
        let mut position = None;
        if let Some(r) = style
            .audit
            .records
            .iter_mut()
            .find(|r| r.record_hash == p.record_hash)
        {
            r.comparison = Some(comparison);
            position = r.position;
        }
        let follow = follow_up(p.code);
        if let Some(d) = style
            .audit
            .devices
            .iter_mut()
            .find(|d| d.box_id.as_bytes() == p.device_id.as_bytes())
        {
            d.compared = d.compared.saturating_add(1);
            if let Some(n) = d.codes.get_mut(usize::from(p.code.code())) {
                *n = n.saturating_add(1);
            }
            if p.transfer_mark {
                d.transfer_marks = d.transfer_marks.saturating_add(1);
            }
            if follow == FollowUp::FullComparison && d.full_comparison_from.is_none() {
                d.full_comparison_from = Some(seq);
            }
            d.holds = d
                .holds
                .with_if(follow == FollowUp::Custody, HoldReason::AuditCustody);
        }
        style.audit.holds = style
            .audit
            .holds
            .with_if(follow == FollowUp::Custody, HoldReason::AuditCustody);
        style.count(seq, position, p.code);
        Ok(())
    }

    fn take_finding(
        &mut self,
        ctx: &Ctx<'_, 'a>,
        seq: Seq,
        event: &WitnessedEvent<'_>,
        p: &AuditFindingParts<'a>,
    ) -> Result<(), AuditRefusal> {
        if !ctx.audit_signed(seq, event) {
            return Err(AuditRefusal::Signature);
        }
        let _cap = ctx
            .cap::<Rla>(p.time_bucket)
            .ok_or(AuditRefusal::Capability)?;
        let style = self
            .styles
            .get_mut(p.ballot_style_id.as_bytes())
            .ok_or(AuditRefusal::Subject)?;
        let device = style
            .audit
            .devices
            .iter_mut()
            .find(|d| d.box_id.as_bytes() == p.device_id.as_bytes())
            .ok_or(AuditRefusal::Subject)?;
        let key = (p.device_id.as_bytes(), p.finding_hash.0);
        if let Some(taken) = style.findings.get(&key) {
            return Err(again(*taken, event.body_bytes()));
        }
        device.findings.push(seq);
        style.findings.insert(key, object_hash(event.body_bytes()));
        Ok(())
    }

    fn take_hand_count(
        &mut self,
        ctx: &Ctx<'_, 'a>,
        seq: Seq,
        event: &WitnessedEvent<'_>,
        p: &PaperCountParts<'a>,
    ) -> Result<(), AuditRefusal> {
        let unit = ctx
            .genesis
            .reporting_unit_entry_at(ctx.index.state_at(seq), p.reporting_unit_id.as_bytes())
            .ok_or(AuditRefusal::Subject)?;
        let signed = ctx.people_signed(seq, event, |signed, roster, keys| {
            HandCount::check(signed, roster, keys, &unit).is_ok()
        });
        if !signed {
            return Err(AuditRefusal::Signature);
        }
        let choices = ctx
            .genesis
            .ballot_style(p.ballot_style_id.as_bytes())
            .map(ityv_encoding::BallotStyleEntry::choices);
        let style = self
            .styles
            .get_mut(p.ballot_style_id.as_bytes())
            .filter(|s| s.audit.units.contains(&p.reporting_unit_id))
            .ok_or(AuditRefusal::Subject)?;
        if choices != Some(u16::try_from(p.votes.len()).unwrap_or(u16::MAX)) {
            return Err(AuditRefusal::Subject);
        }
        if let Some(taken) = style.hand_counts.get(p.reporting_unit_id.as_bytes()) {
            return Err(again(*taken, event.body_bytes()));
        }
        // Events are taken in frame order and the hand count phase is never
        // left, so the phase is the hand count only after the comparison of
        // an earlier frame that took it there (`hand_count_from`).
        if style.audit.phase != Some(AuditPhase::HandCount) {
            return Err(AuditRefusal::Premature);
        }
        style.hand_counts.insert(
            p.reporting_unit_id.as_bytes(),
            object_hash(event.body_bytes()),
        );
        style.audit.hand_counts.push((p.reporting_unit_id, seq));
        Ok(())
    }
}

/// Draws the sample of `style` under `seed`, if its freeze agrees with
/// the ledger, and opens its first round.
fn draw(style: &mut StyleWork<'_>, seed: &Hash512) {
    let a = &mut style.audit;
    let Some(rounds) = a.rounds.filter(|_| a.frame_problems.is_empty()) else {
        return;
    };
    let last = rounds.as_slice().last().map_or(0, |r| r.sample_size);
    let Some(positions) = draw_sample(seed, a.ballot_style_id, a.frame_count, last) else {
        return;
    };
    for (draw_index, position) in positions.iter().enumerate() {
        let code = usize::try_from(*position)
            .ok()
            .and_then(|p| style.frame.get(p));
        let (Some(code), Ok(draw_index)) = (code, u64::try_from(draw_index)) else {
            return;
        };
        a.sample.push(*code);
        style.positions.insert(code.0, draw_index);
    }
    a.phase = Some(audit_phase(&rounds, a.frame_count, &a.counts));
}

/// Checks every supplied restricted opening against its record (VC-047).
fn reconstruct(ctx: &Ctx<'_, '_>, work: &mut Work<'_>, input: &AuditInput<'_>) {
    if input.openings.is_empty() {
        return;
    }
    let supply: BTreeMap<[u8; 64], &[u8]> = input
        .openings
        .iter()
        .map(|b| (object_hash(b).0, *b))
        .collect();
    let bases = Bases::derive();
    for style in work.styles.values_mut() {
        let mut failed = false;
        for r in &mut style.audit.records {
            let Some((_, opening_hash)) = style.openings.get(&r.record_hash.0) else {
                continue;
            };
            let Some(bytes) = supply.get(&opening_hash.0) else {
                continue;
            };
            let opens = ctx
                .records
                .get(&r.record_hash.0)
                .is_some_and(|record| opening_opens(ctx, &bases, record, &r.record_hash, bytes));
            r.reconstruction = if opens {
                Reconstruction::Reconstructed
            } else {
                failed = true;
                Reconstruction::Mismatch
            };
        }
        style.audit.holds = style
            .audit
            .holds
            .with_if(failed, HoldReason::SampleOpeningMismatch);
    }
}

/// Whether `bytes` is a canonical sample opening of the record `code`
/// (election, style and tracking code) whose option, cast id and exactly
/// `k` canonical randomness scalars open every commitment of `record`.
fn opening_opens(
    ctx: &Ctx<'_, '_>,
    bases: &Bases,
    record: &FrameRecord<'_>,
    code: &Hash512,
    bytes: &[u8],
) -> bool {
    let Some(body) = decode::<SampleOpeningBody<'_>>(SCHEMA_SAMPLE_OPENING_BODY, bytes) else {
        return false;
    };
    let same = body.election_id().as_bytes() == ctx.genesis.election_id().as_bytes()
        && body.ballot_style_id().as_bytes() == record.style.as_bytes()
        && body.record_hash() == code;
    let options = ctx
        .genesis
        .ballot_style(record.style.as_bytes())
        .and_then(|s| s.choices().checked_add(2))
        .and_then(OptionCount::new);
    let (true, Some(options), Some(cast)) = (same, options, record.record.as_ref()) else {
        return false;
    };
    let chunks = usize::from(options.chunk_count());
    let (Some(rand), Some(option), Some(commitments)) = (
        scalars(body.rand().as_slice(), chunks),
        OptionIndex::new(body.option_index()),
        commitments_of(cast),
    ) else {
        return false;
    };
    let opening = Opening::new(option, CastId::new(*body.cast_id()), rand);
    verify_opening(bases, options, &commitments, &opening).is_ok()
}

/// The styles of the tally's units, with their frames and devices.
fn styles<'a>(
    genesis: &VerifiedGenesis<'a>,
    tally: &TallyStage<'a>,
) -> BTreeMap<&'a [u8], StyleWork<'a>> {
    let mut out: BTreeMap<&'a [u8], StyleWork<'a>> = BTreeMap::new();
    for u in tally.units() {
        let style = out
            .entry(u.ballot_style_id.as_bytes())
            .or_insert_with(|| StyleWork {
                audit: StyleAudit {
                    ballot_style_id: u.ballot_style_id,
                    units: Vec::new(),
                    frame_count: 0,
                    frame_root: None,
                    freeze: None,
                    frame_problems: Vec::new(),
                    rounds: None,
                    sample: Vec::new(),
                    counts: [RoundCount::default(); MAX_AUDIT_ROUNDS],
                    phase: None,
                    hand_count_from: None,
                    records: Vec::new(),
                    devices: Vec::new(),
                    hand_counts: Vec::new(),
                    holds: HoldSet::empty(),
                },
                frame: Vec::new(),
                scopes: Vec::new(),
                freeze: None,
                positions: BTreeMap::new(),
                openings: BTreeMap::new(),
                comparisons: BTreeMap::new(),
                findings: BTreeMap::new(),
                hand_counts: BTreeMap::new(),
            });
        style.audit.units.push(u.reporting_unit_id);
        style.scopes.push(u.scope);
        style.frame.extend(u.included.iter().copied());
    }
    for style in out.values_mut() {
        style.frame.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        style.audit.frame_count = u64::try_from(style.frame.len()).unwrap_or(u64::MAX);
        style.audit.frame_root = sorted_set_root(&style.frame).ok();
    }
    for b in genesis.boxes() {
        if let Some(style) = out.get_mut(b.ballot_style_id.as_bytes()) {
            style.audit.devices.push(DeviceAudit {
                box_id: b.box_id,
                station_id: b.station_id,
                records: 0,
                compared: 0,
                codes: [0; 7],
                transfer_marks: 0,
                full_comparison_from: None,
                findings: Vec::new(),
                holds: HoldSet::empty(),
            });
        }
    }
    for style in out.values_mut() {
        style
            .audit
            .devices
            .sort_by(|a, b| a.box_id.as_bytes().cmp(b.box_id.as_bytes()));
    }
    out
}

/// The included records of every style's frame, with their boxes and cast
/// records.
fn frame_records<'a>(
    index: &LedgerIndex<'a>,
    records: &RecordStage<'a>,
    styles: &mut BTreeMap<&'a [u8], StyleWork<'a>>,
) -> BTreeMap<[u8; 64], FrameRecord<'a>> {
    let included: BTreeMap<[u8; 64], BallotStyleId<'a>> = styles
        .values()
        .flat_map(|s| s.frame.iter().map(|c| (c.0, s.audit.ballot_style_id)))
        .collect();
    let mut out = BTreeMap::new();
    for report in records.reports() {
        for r in &report.records {
            let Some(style) = included.get(&r.tracking_code.0) else {
                continue;
            };
            let record = event_at(index, r.seq)
                .and_then(|e| e.bytes)
                .and_then(|b| decode::<CastRecord<'a>>(SCHEMA_CAST_RECORD, b));
            out.insert(
                r.tracking_code.0,
                FrameRecord {
                    style: *style,
                    box_id: report.box_id,
                    record,
                },
            );
            if let Some(d) = styles.get_mut(style.as_bytes()).and_then(|s| {
                s.audit
                    .devices
                    .iter_mut()
                    .find(|d| d.box_id.as_bytes() == report.box_id.as_bytes())
            }) {
                d.records = d.records.saturating_add(1);
            }
        }
    }
    out
}

/// Runs the audit of every ballot style of the genesis's last state over
/// the ledger (PROTOCOL.md §14 item 8), with what the caller observed and
/// holds in `input`.
#[must_use]
pub fn verify_audit<'a>(
    genesis: &VerifiedGenesis<'a>,
    index: &LedgerIndex<'a>,
    authority: &AuthorityStage<'a>,
    checkpoints: &CheckpointChain,
    records: &RecordStage<'a>,
    tally: &TallyStage<'a>,
    input: &AuditInput<'_>,
) -> AuditStage<'a> {
    let mut styles = styles(genesis, tally);
    let frame = frame_records(index, records, &mut styles);
    let ctx = Ctx {
        genesis,
        index,
        authority,
        trustees: Trustees::of(genesis),
        checkpoints: checkpoints.checkpoints(),
        records: frame,
    };
    let mut work = Work {
        styles,
        seed: None,
        viewing: None,
        refused: Vec::new(),
    };
    for (seq, item) in items(index) {
        let (event, taken) = match &item {
            Item::Freeze(b) => (AuditEvent::Freeze, work.take_freeze(&ctx, seq, &b.0, &b.1)),
            Item::Seed(b) => (
                AuditEvent::Seed,
                work.take_seed(&ctx, input, seq, &b.0, &b.1),
            ),
            Item::Opening(b) => (
                AuditEvent::Opening,
                work.take_opening(&ctx, seq, &b.0, &b.1),
            ),
            Item::Comparison(b) => (
                AuditEvent::Comparison,
                work.take_comparison(&ctx, seq, &b.0, &b.1),
            ),
            Item::Finding(b) => (
                AuditEvent::Finding,
                work.take_finding(&ctx, seq, &b.0, &b.1),
            ),
            Item::HandCount(b) => (
                AuditEvent::HandCount,
                work.take_hand_count(&ctx, seq, &b.0, &b.1),
            ),
        };
        if let Err(refusal) = taken {
            work.refuse(seq, event, refusal);
        }
    }
    reconstruct(&ctx, &mut work, input);
    let mut styles: Vec<StyleAudit<'a>> = Vec::new();
    for mut s in work.styles.into_values() {
        s.audit
            .records
            .sort_by(|a, b| a.record_hash.as_bytes().cmp(b.record_hash.as_bytes()));
        styles.push(s.audit);
    }
    AuditStage {
        styles,
        seed: work.seed.map(|(_, s)| s),
        refused: work.refused,
    }
}

#[cfg(test)]
mod tests {
    use ityv_encoding::{BallotStyleId, Hash512};

    use super::draw_sample;

    fn seed() -> Hash512 {
        ityv_crypto::audit_seed(
            &Hash512([0x11; 64]),
            &Hash512([0x22; 64]),
            &Hash512([0x33; 64]),
        )
    }

    /// Known answers computed independently from the specification
    /// (Python `hashlib.sha3_512`, ADR-0036).
    #[test]
    fn the_sample_matches_independent_answers() {
        let s1 = BallotStyleId::new(b"STYLE-1").unwrap();
        let s2 = BallotStyleId::new(b"STYLE-2").unwrap();
        assert_eq!(
            draw_sample(&seed(), s1, 1000, 10).unwrap(),
            [237, 61, 728, 869, 826, 325, 653, 610, 912, 359]
        );
        assert_eq!(draw_sample(&seed(), s1, 5, 5).unwrap(), [2, 3, 4, 0, 1]);
        assert_eq!(draw_sample(&seed(), s1, 5, 9).unwrap(), [2, 3, 4, 0, 1]);
        assert_eq!(draw_sample(&seed(), s1, 3, 2).unwrap(), [1, 0]);
        assert_eq!(
            draw_sample(&seed(), s2, (1 << 26) - 1, 4).unwrap(),
            [43_217_382, 30_407_386, 59_593_142, 17_149_559]
        );
        assert_eq!(draw_sample(&seed(), s1, 0, 4).unwrap(), []);
        assert_eq!(draw_sample(&seed(), s1, 4, 0).unwrap(), []);
    }

    #[test]
    fn a_longer_sample_extends_the_shorter_and_never_repeats() {
        let s = BallotStyleId::new(b"S").unwrap();
        let short = draw_sample(&seed(), s, 50, 10).unwrap();
        let long = draw_sample(&seed(), s, 50, 50).unwrap();
        assert_eq!(&long[..10], short.as_slice());
        let mut sorted = long.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..50).collect::<std::vec::Vec<u64>>());
    }
}
