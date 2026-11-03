//! The tally stage (PROTOCOL.md §10.6, §11, §14 7; VC-024, VC-042..044,
//! VC-057, VC-063, VC-075, VC-099; ADR-0035).
//!
//! [`verify_tally`] recomputes, for every ballot style and reporting unit
//! that a box of the genesis's last state has, what the tally must be, and
//! compares the trustees' and the commission's events with it. It reads:
//!
//! * **Receipt resolutions** (`ReceiptResolutionBody` in a `QuorumSigned`,
//!   §10.6 items 2 and 5). One per out-of-district box, after the box's
//!   close, signed by a qualified trustee quorum under `CRYPTO_TALLY_AID`
//!   for the day of its time bucket, giving exactly one outcome to each
//!   cast record of the box (not the challenged ones). Each outcome moves
//!   its record (`RECEIVED`, `RECEIVED_DAMAGED`, `RECEIVED_LATE`,
//!   `WRONG_DISTRICT`, `CAST_NOT_RECEIVED`).
//! * **Legal decisions** with a tally effect (the dispute stage's
//!   [`crate::Decision`], §10.6 item 6, VC-099). The decision's dispute
//!   must be a `POSTAL` dispute naming a box and a record; the record must
//!   be an accepted record of that box that awaits the law
//!   (`RECEIVED_DAMAGED` or `WRONG_DISTRICT` by a resolution in an earlier
//!   frame) and has no decision yet. `Include` counts it; `Exclude` makes it
//!   `LEGAL_EXCLUDED` with the decision event's hash as basis.
//! * **Tally scopes** (`TallyScopeBody`, §11.1). Signed by a qualified
//!   trustee quorum ([`ityv_state::check_quorum`]: every signer a trustee
//!   of the genesis, each token from that trustee's key, no shared key
//!   half, a qualified set of the chamber access structure Γ), under
//!   `CRYPTO_TALLY_AID`, for a style and unit of the genesis, at most one
//!   per style and unit, and only when ready
//!   ([`ityv_state::admit_tally_scope`]): every box of the style closed in
//!   an earlier frame, every out-of-district box of the style with cast
//!   records resolved in an earlier frame, every record of the style that
//!   awaits the law decided in an earlier frame, and the witnesses' time
//!   (the latest time bucket of a valid checkpoint recorded before the
//!   scope) more than 96 buckets after the last close of the style. The
//!   verifier has no clock, and the trustees' own bucket is only their
//!   claim: a forward-dated scope inside the late-close window would fix
//!   as `UNATTESTED` what a late batch close may still attest (VC-057).
//!   A late batch close or late box close recorded after a scope of its
//!   box's style is refused and holds. The scope taken is compared with
//!   the recomputation: the included records'
//!   count and sorted-set root, every exclusion's record, reason (the
//!   first of §11.1 that applies, VC-042) and basis, and the no-record
//!   count against the unit's closes.
//! * **Aggregate openings** (`AggregateOpeningBody`, §11.2). The same
//!   quorum and capability, a chunk the style has, the scope taken for the
//!   style and unit (by the object hash of its body), at most one per
//!   chunk, and only after some valid witness checkpoint recorded before
//!   the opening covers the scope's frame
//!   ([`ityv_state::admit_aggregate_opening`], VC-063). The opening is then
//!   checked against the recomputed included set: `C_total,j`, the sum of
//!   the included records' chunk-`j` commitments, must equal `T_j·G_val +
//!   S·G_id + R_j·H` (VC-043), and every 26-bit digit of `T_j` must be at
//!   most the included count (VC-024). Once every chunk opens, the digits
//!   of the style's options are the counts per option, and they must sum to
//!   the included count (so no vote sits on an option the style does not
//!   have).
//! * **Paper count reports** (`PaperCountReportBody` in a
//!   `WitnessedEvent`, §11.5). Signed by the chair of the district
//!   commission the unit names (`ReportingUnitEntry::commission_org`, so a
//!   chair of another district cannot file the unit's report first) and
//!   by observers of two or more organisations, each under the key the
//!   roster of the genesis state in force at its frame registers for that
//!   signer, role and organisation; for a style and unit of the genesis,
//!   with one count per candidate of the style; at most one per style and
//!   unit. With the opened counts it is compared by
//!   [`ityv_state::compare_paper`] (VC-075): no candidate below the
//!   machine's confirmed votes, and `Σ P_t + I = Σ D_t + B + U + F + X`,
//!   where `F` is the unit's no-record count and `X` the excluded records
//!   whose ballot paper is among the unit's counted ballots (an excluded
//!   record still cast or `RECEIVED`: `UNATTESTED`, `SHARE_MISSING`, a test
//!   ballot cast).
//!
//! Every trustee signature covers the quorum message (the body's object
//! hash and the participating trustees, [`ityv_state::quorum_message`]),
//! so a body cannot be re-wrapped with another list of participants. The
//! first event taken answers its unit, chunk or box; the same body again
//! is [`TallyRefusal::Repeated`], another body a [`TallyRefusal::Conflict`]:
//! both are listed and hold, and a conflict is never silently "already
//! answered".
//!
//! The basis of each exclusion is the object hash of the ledger event that
//! gives the reason: the cast record itself for `TEST_BALLOT`, the first
//! accepted challenge opening of the record for `CHALLENGED_SPOILED`, the
//! receipt resolution for `CAST_NOT_RECEIVED` and `RECEIVED_LATE`, the
//! decision for `LEGAL_EXCLUDED`, and the box's effective close for
//! `UNATTESTED` (the close ends the box without the record's batch; after
//! the late-close window nothing can attest it). `QUARANTINED` and
//! `SHARE_MISSING` have no ledger event yet (`ImprintFailure`,
//! `ShareReceipt`); a record cannot reach them.
//!
//! Every event the stage cannot take is listed ([`TallyRefused`]) and
//! holds: [`HoldReason::ReceiptResolutionRefused`],
//! [`HoldReason::TallyEffectRefused`], [`HoldReason::TallyScopeRefused`],
//! [`HoldReason::AggregateRefused`], [`HoldReason::PaperCountRefused`],
//! [`HoldReason::LateCloseAfterScope`]. A
//! scope that differs from the recomputation holds its unit
//! ([`HoldReason::TallyScopeMismatch`]), so does an opening that does not
//! open or whose digits are out of range ([`HoldReason::AggregateMismatch`],
//! the trustees then localize the faulty box, §11.3) and a paper count that
//! does not agree ([`HoldReason::PaperCountMismatch`]). What is not yet on
//! the ledger (a unit's scope, an opening of a chunk, its paper count)
//! leaves the stage incomplete instead.
//!
//! What this stage does not prove: that the trustees' shares match the
//! commitments record by record (an opening that fails says only that some
//! record's share does not, §11.3); that the chair heads the commission of
//! the unit (the genesis does not tie a unit to a commission); the
//! receiving commission's label counts (VC-060, no schema yet); that the
//! witnesses' clocks were right (their checkpoints are anchored in time by
//! the checkpoint stage, ADR-0034).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use ityv_crypto::hash::object_hash;
use ityv_crypto::{
    AccessStructure, Bases, Commitment, Purpose, Scalar, decode_digits, sum_commitments,
    verify_aggregate,
};
use ityv_encoding::schema_version;
use ityv_encoding::{
    AggregateOpeningParts, BallotStyleId, BoxClose, CaptureProfile, CastRecord, ChallengeOpening,
    Decode, DisputeType, ExclusionReason, GenesisBox, HYBRID_SIG_LEN, HYBRID_VK_LEN, Hash512,
    MAX_QUORUM_MESSAGE_LEN, PaperCountParts, PaperCountReportBody, QuorumKind, QuorumSigned,
    ReceiptOutcome, ReceiptResolutionParts, ReportingUnitEntry, ReportingUnitId,
    SCHEMA_BATCH_ATTEST, SCHEMA_BOX_CLOSE, SCHEMA_CAST_RECORD, SCHEMA_CHALLENGE_OPENING,
    SCHEMA_LATE_BATCH_CLOSE_BODY, SCHEMA_PAPER_COUNT_REPORT_BODY, SCHEMA_QUORUM_SIGNED,
    SCHEMA_WITNESSED_EVENT, SchemaId, Seq, TallyEffect, TallyScopeParts, TimeBucket, TrusteeEntry,
    WitnessedEvent, decode_object,
};
use ityv_ledger::sorted_set_root;
use ityv_state::{
    Cap, CryptoTallyAid, Disposition, Entry, Exclusion, HoldReason, HoldSet, MachineCount,
    PaperComparison, PaperCount, Primary, QuorumTokens, Receipt, RecordEvent, RecordState,
    RosterEntry, Signed, TallyReadiness, access_structure, admit_aggregate_opening,
    admit_tally_scope, check_quorum, checkpointed_before, compare_paper, quorum_message,
};

use crate::authority::{AuthorityStage, day_of};
use crate::boxes::BoxStage;
use crate::checkpoint::CheckpointChain;
use crate::disputes::DisputeStage;
use crate::genesis::VerifiedGenesis;
use crate::index::{IndexedEvent, LedgerIndex};
use crate::records::RecordStage;
use crate::sigs::Material;

/// Options per chunk (PROTOCOL.md §7.4).
const DIGITS: usize = 9;

/// Which kind of tally event a refusal concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TallyEvent {
    /// A receipt resolution (§10.6).
    Receipt,
    /// A legal decision with a tally effect (§10.6 item 6).
    Decision,
    /// A tally scope (§11.1).
    Scope,
    /// An aggregate opening (§11.2).
    Opening,
    /// A paper count report (§11.5).
    Paper,
    /// A late batch close or late box close of a box (§7.2.1, §10.2).
    LateClose,
}

/// Why the tally stage refused an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TallyRefusal {
    /// A signature does not verify under the key registered for its
    /// signer, a signer is not a trustee (for a paper count: not the
    /// roster's chair or an observer in the role and organisation it
    /// names), two signers share a key half, or the trustees are not a
    /// qualified set of the chamber access structure.
    Signature,
    /// No legal authorization grants `CRYPTO_TALLY_AID` for the day of its
    /// time bucket.
    Capability,
    /// It names a ballot style and reporting unit that no box of the
    /// genesis has, a chunk the style does not have, another number of
    /// candidates than the style's, or (a resolution) a box that is not an
    /// out-of-district box of the genesis.
    Subject,
    /// Too early: a scope before every box of its style closed, before the
    /// receipt resolutions and legal decisions it waits for, or within the
    /// late-close window (VC-057, VC-099); an opening whose scope no valid
    /// witness checkpoint before it covers (VC-063); a resolution before its
    /// box closed.
    Premature,
    /// An opening that names no tally scope taken for its style and unit.
    NoScope,
    /// A receipt resolution whose entries are not exactly the box's cast
    /// records.
    Entries,
    /// The body of the scope, opening, paper count or resolution already
    /// taken for its unit, chunk or box, again (under other signature
    /// bytes).
    Repeated,
    /// A second scope of a style and unit, a second opening of a chunk, a
    /// second paper count of a style and unit, or a second resolution of a
    /// box, with another body than the one taken: two signed answers to
    /// one question, which only people can settle.
    Conflict,
    /// A late close recorded after a tally scope of its box's style was
    /// taken: the scope fixed what was attested (VC-057).
    AfterScope,
    /// A tally effect that cannot apply: the decision's dispute is not a
    /// `POSTAL` dispute naming a box and a record, the record is not an
    /// accepted record of that box, or it does not await the law (or
    /// already has a decision) when the decision comes (VC-099).
    Effect,
}

/// An event the tally stage refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TallyRefused {
    /// The frame that carries it.
    pub seq: Seq,
    /// What kind of event it is.
    pub event: TallyEvent,
    /// Why it was refused.
    pub refusal: TallyRefusal,
}

/// A record the recomputation excludes, with its reason and the basis it
/// must cite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExpectedExclusion {
    /// The record's tracking code.
    pub record_hash: Hash512,
    /// The first reason of §11.1 that applies.
    pub reason: ExclusionReason,
    /// The object hash of the event that gives the reason; `None` when the
    /// ledger has no such event, so that no scope can cite one.
    pub basis: Option<Hash512>,
}

/// How a tally scope differs from the recomputation (VC-042).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScopeProblem {
    /// The included count differs.
    IncludedCount,
    /// The included records' sorted-set root differs.
    IncludedRoot,
    /// The no-record count differs from the sum over the unit's closes.
    NoRecordCount,
    /// The recomputation excludes the record; the scope does not.
    Missing(Hash512),
    /// The scope excludes a record the recomputation does not.
    Unexpected(Hash512),
    /// The scope excludes the record for a reason other than the first of
    /// §11.1 that applies.
    Reason(Hash512),
    /// The scope's basis is not the event that gives the reason.
    Basis(Hash512),
}

/// What checking an aggregate opening found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpeningOutcome {
    /// `C_total,j == T_j·G_val + S·G_id + R_j·H` holds and every digit is
    /// in range (VC-024, VC-043).
    Verified,
    /// The equation does not hold, or a sum is not a canonical scalar
    /// (VC-043, VC-044).
    Equation,
    /// The packed sum has a digit above the included count, or bits above
    /// the packed range (VC-024).
    Digits,
}

/// An aggregate opening the stage took.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChunkOpening {
    /// The chunk `j`.
    pub chunk: u8,
    /// The frame that carries it.
    pub seq: Seq,
    /// What checking it found.
    pub outcome: OpeningOutcome,
}

/// The tally of one ballot style in one reporting unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnitTally<'a> {
    /// The ballot style.
    pub ballot_style_id: BallotStyleId<'a>,
    /// The reporting unit.
    pub reporting_unit_id: ReportingUnitId<'a>,
    /// The style's chunk count.
    pub chunks: u8,
    /// The recomputed included records' tracking codes, ascending.
    pub included: Vec<Hash512>,
    /// Their sorted-set root.
    pub included_root: Option<Hash512>,
    /// The recomputed exclusions, ascending by record hash.
    pub exclusions: Vec<ExpectedExclusion>,
    /// The ballots of the unit's boxes cast without a record, from their
    /// effective closes.
    pub no_record_count: u64,
    /// The excluded records whose paper is among the unit's counted
    /// ballots (`X` of §11.5).
    pub excluded_with_paper: u64,
    /// The frame of the tally scope taken.
    pub scope: Option<Seq>,
    /// How that scope differs from the recomputation.
    pub scope_problems: Vec<ScopeProblem>,
    /// The openings taken, in frame order.
    pub openings: Vec<ChunkOpening>,
    /// The count per option (`BLANK`, the candidates, `UNREADABLE`) once
    /// every chunk opened and the counts sum to the included count.
    pub counts: Option<Vec<u64>>,
    /// The frame of the paper count report taken.
    pub paper: Option<Seq>,
    /// The paper compared with the counts (VC-075).
    pub comparison: Option<PaperComparison>,
    /// The unit's holds.
    pub holds: HoldSet,
}

impl UnitTally<'_> {
    /// Whether the unit has its scope, an opening of every chunk and its
    /// paper count.
    #[must_use]
    pub fn complete(&self) -> bool {
        let opened: BTreeSet<u8> = self.openings.iter().map(|o| o.chunk).collect();
        self.scope.is_some()
            && self.paper.is_some()
            && (0..self.chunks).all(|j| opened.contains(&j))
    }

    /// Whether the unit is complete and holds nothing. Each disagreement
    /// is a hold: a scope that is not the recomputation
    /// (`TallyScopeMismatch`), an opening that does not verify or counts
    /// that do not sum to the included count (`AggregateMismatch`, so a
    /// complete unit without a hold has its counts), a paper count that
    /// does not agree (`PaperCountMismatch`, so it has its comparison), and
    /// every event refused for the unit.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.complete() && self.holds.is_empty()
    }
}

/// The tally stage (PROTOCOL.md §14 item 7).
#[derive(Debug, Clone, Default)]
pub struct TallyStage<'a> {
    units: Vec<UnitTally<'a>>,
    refused: Vec<TallyRefused>,
}

impl<'a> TallyStage<'a> {
    /// One entry per ballot style and reporting unit of the genesis's last
    /// state, in (style, unit) order.
    #[must_use]
    pub fn units(&self) -> &[UnitTally<'a>] {
        &self.units
    }

    /// The tally of style `style` in unit `unit`.
    #[must_use]
    pub fn unit(&self, style: &[u8], unit: &[u8]) -> Option<&UnitTally<'a>> {
        self.units.iter().find(|u| {
            u.ballot_style_id.as_bytes() == style && u.reporting_unit_id.as_bytes() == unit
        })
    }

    /// The events refused, in frame order.
    #[must_use]
    pub fn refused(&self) -> &[TallyRefused] {
        &self.refused
    }

    /// Every unit's holds and one per kind of event refused.
    #[must_use]
    pub fn holds(&self) -> HoldSet {
        let units = self
            .units
            .iter()
            .fold(HoldSet::empty(), |h, u| h.union(u.holds));
        self.refused
            .iter()
            .fold(units, |h, r| h.with(refusal_hold(r.event)))
    }

    /// Whether every unit has its scope, openings and paper count.
    #[must_use]
    pub fn complete(&self) -> bool {
        self.units.iter().all(UnitTally::complete)
    }

    /// Whether every unit passed and nothing was refused.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.refused.is_empty() && self.units.iter().all(UnitTally::passed)
    }
}

/// The hold of a refused event.
const fn refusal_hold(event: TallyEvent) -> HoldReason {
    match event {
        TallyEvent::Receipt => HoldReason::ReceiptResolutionRefused,
        TallyEvent::Decision => HoldReason::TallyEffectRefused,
        TallyEvent::Scope => HoldReason::TallyScopeRefused,
        TallyEvent::Opening => HoldReason::AggregateRefused,
        TallyEvent::Paper => HoldReason::PaperCountRefused,
        TallyEvent::LateClose => HoldReason::LateCloseAfterScope,
    }
}

/// The wire reason of a record's exclusion.
const fn reason_of(exclusion: Exclusion) -> ExclusionReason {
    match exclusion {
        Exclusion::TestBallot => ExclusionReason::TestBallot,
        Exclusion::ChallengedSpoiled => ExclusionReason::ChallengedSpoiled,
        Exclusion::Quarantined => ExclusionReason::Quarantined,
        Exclusion::CastNotReceived => ExclusionReason::CastNotReceived,
        Exclusion::ReceivedLate => ExclusionReason::ReceivedLate,
        Exclusion::LegalExcluded => ExclusionReason::LegalExcluded,
        Exclusion::ShareMissing => ExclusionReason::ShareMissing,
        Exclusion::Unattested => ExclusionReason::Unattested,
    }
}

/// The record state a receipt outcome gives.
const fn receipt_of(outcome: ReceiptOutcome) -> Receipt {
    match outcome {
        ReceiptOutcome::Received => Receipt::Received,
        ReceiptOutcome::Damaged => Receipt::Damaged,
        ReceiptOutcome::Late => Receipt::Late,
        ReceiptOutcome::WrongDistrict => Receipt::WrongDistrict,
        ReceiptOutcome::NotReceived => Receipt::NotReceived,
    }
}

/// Whether a record's ballot paper is among the counted ballots of its
/// unit: it was cast into the box, or its envelope was received.
const fn paper_counted(state: RecordState) -> bool {
    matches!(
        state.primary(),
        Primary::Cast | Primary::Receipt(Receipt::Received)
    )
}

/// Whether a record awaits the law (§10.6 item 6).
const fn awaits_law(state: RecordState) -> bool {
    matches!(
        state.primary(),
        Primary::Receipt(Receipt::Damaged | Receipt::WrongDistrict)
    )
}

fn decode<'a, T: Decode<'a>>(schema: SchemaId, bytes: &'a [u8]) -> Option<T> {
    decode_object(schema, schema_version(schema), bytes).ok()
}

/// One accepted record of a box and what the tally knows of it.
struct Rec<'a> {
    code: Hash512,
    /// The cast record event's object hash.
    event: Hash512,
    /// Its state after receipts and legal decisions.
    state: RecordState,
    /// Whether the record stage left it cast (not challenged): a record the
    /// receipt resolution must resolve.
    cast: bool,
    record: Option<CastRecord<'a>>,
    /// The first accepted challenge opening of the record.
    challenge: Option<Hash512>,
    /// The resolution that gave its outcome: frame and event hash.
    receipt: Option<(Seq, Hash512)>,
    /// The legal decision that applied: frame and event hash.
    legal: Option<(Seq, Hash512)>,
}

/// One box of the genesis's last state and what the tally knows of it.
struct BoxInfo<'a> {
    entry: GenesisBox<'a>,
    /// The first accepted close: frame and time bucket.
    close: Option<(Seq, TimeBucket)>,
    /// The effective (last accepted) close: event hash and ballots cast
    /// without a record.
    effective: Option<(Hash512, u64)>,
    /// The resolution taken: its frame and body hash.
    resolution: Option<(Seq, Hash512)>,
    /// The frames of the late closes taken: every close after the first,
    /// every late batch close, and every batch attestation after the first
    /// close (the box stage pairs a late batch close with its batch in
    /// either order, so the later of the two completes it).
    late: Vec<Seq>,
    records: Vec<Rec<'a>>,
}

impl BoxInfo<'_> {
    fn absentee(&self) -> bool {
        self.entry.profile == CaptureProfile::Absentee
    }

    /// The basis of an exclusion of `rec` for `reason`.
    fn basis(&self, rec: &Rec<'_>, exclusion: Exclusion) -> Option<Hash512> {
        match exclusion {
            // Quarantine and missing shares have no ledger event yet; the
            // record itself stands in, as for a test ballot.
            Exclusion::TestBallot | Exclusion::Quarantined | Exclusion::ShareMissing => {
                Some(rec.event)
            }
            Exclusion::ChallengedSpoiled => rec.challenge,
            Exclusion::CastNotReceived | Exclusion::ReceivedLate => rec.receipt.map(|(_, h)| h),
            Exclusion::LegalExcluded => rec.legal.map(|(_, h)| h),
            Exclusion::Unattested => self.effective.map(|(h, _)| h),
        }
    }
}

/// The accepted event at frame `seq`.
fn event_at<'s, 'a>(index: &'s LedgerIndex<'a>, seq: Seq) -> Option<&'s IndexedEvent<'a>> {
    let events = index.events();
    let at = events
        .binary_search_by_key(&seq.get(), |e| e.seq.get())
        .ok()?;
    events.get(at)
}

/// Gathers box `entry`: its closes, challenge openings and records.
fn box_info<'a>(
    index: &LedgerIndex<'a>,
    boxes: &BoxStage<'a>,
    records: &RecordStage<'a>,
    entry: &GenesisBox<'a>,
) -> BoxInfo<'a> {
    let id = entry.box_id.as_bytes();
    let mut skipped: BTreeSet<u64> = boxes
        .report(id)
        .map(|r| r.refusals.iter().map(|f| f.seq.get()).collect())
        .unwrap_or_default();
    let report = records.report(id);
    if let Some(r) = report {
        skipped.extend(r.refused_challenges.iter().map(|s| s.get()));
    }
    let mut info = BoxInfo {
        entry: *entry,
        close: None,
        effective: None,
        resolution: None,
        late: Vec::new(),
        records: Vec::new(),
    };
    let mut challenges: BTreeMap<[u8; 64], Hash512> = BTreeMap::new();
    for e in index.box_events(id) {
        let Some(bytes) = e.bytes else { continue };
        if skipped.contains(&e.seq.get()) {
            continue;
        }
        if e.schema == SCHEMA_BOX_CLOSE {
            if let Some(c) = decode::<BoxClose<'a>>(e.schema, bytes) {
                let body = c.body();
                if info.close.is_none() {
                    info.close = Some((e.seq, body.time_bucket()));
                } else {
                    info.late.push(e.seq);
                }
                info.effective = Some((e.hash, body.counts().without_record));
            }
        } else if e.schema == SCHEMA_BATCH_ATTEST {
            if info.close.is_some() {
                info.late.push(e.seq);
            }
        } else if e.schema == SCHEMA_WITNESSED_EVENT {
            let late_batch = decode::<WitnessedEvent<'a>>(e.schema, bytes)
                .is_some_and(|w| w.body_schema() == SCHEMA_LATE_BATCH_CLOSE_BODY);
            if late_batch {
                info.late.push(e.seq);
            }
        } else if e.schema == SCHEMA_CHALLENGE_OPENING
            && let Some(o) = decode::<ChallengeOpening<'a>>(e.schema, bytes)
        {
            challenges.entry(o.body().record_hash().0).or_insert(e.hash);
        }
    }
    for r in report.map(|r| r.records.as_slice()).unwrap_or_default() {
        let event = event_at(index, r.seq);
        info.records.push(Rec {
            code: r.tracking_code,
            event: event.map_or(Hash512::ZERO, |e| e.hash),
            state: r.state,
            cast: matches!(r.state.primary(), Primary::Cast),
            record: event
                .and_then(|e| e.bytes)
                .and_then(|b| decode::<CastRecord<'a>>(SCHEMA_CAST_RECORD, b)),
            challenge: challenges.get(&r.tracking_code.0).copied(),
            receipt: None,
            legal: None,
        });
    }
    info
}

/// The trustees of the genesis and the access structure of its chambers.
struct Trustees<'a> {
    entries: Vec<Entry<TrusteeEntry<'a>>>,
    structure: Option<AccessStructure>,
}

impl Trustees<'_> {
    /// Whether a qualified quorum of trustees signed `q`.
    fn signed(&self, q: &QuorumSigned<'_>) -> bool {
        let Some(structure) = self.structure.as_ref() else {
            return false;
        };
        let pairs: Option<Vec<(&[u8; HYBRID_SIG_LEN], &[u8; HYBRID_VK_LEN])>> = q
            .sigs()
            .map(|s| {
                self.entries
                    .iter()
                    .map(Entry::get)
                    .find(|t| t.trustee_id.as_bytes() == s.trustee_id.as_bytes())
                    .map(|t| (s.sig, t.key))
            })
            .collect();
        let Some(material) = pairs.and_then(|p| Material::new(p.into_iter())) else {
            return false;
        };
        let Some(purpose) = Purpose::new(q.purpose()) else {
            return false;
        };
        let mut buf = [0u8; MAX_QUORUM_MESSAGE_LEN];
        let Ok(message) = quorum_message(q, &mut buf) else {
            return false;
        };
        let Some(tokens) = material.verify(&purpose, message) else {
            return false;
        };
        let signed = QuorumTokens {
            event: q,
            tokens: &tokens,
        };
        check_quorum(&signed, &self.entries, structure).is_ok()
    }
}

/// What the stage needs throughout.
struct Ctx<'g, 'a> {
    genesis: &'g VerifiedGenesis<'a>,
    index: &'g LedgerIndex<'a>,
    authority: &'g AuthorityStage<'a>,
    trustees: Trustees<'a>,
    /// The valid checkpoints: frame, tree size, time bucket.
    checkpoints: Vec<(u64, u64, TimeBucket)>,
}

impl<'a> Ctx<'_, 'a> {
    /// The witnesses' time at frame `at`: the time bucket of the last valid
    /// checkpoint recorded before it (0 if none), as PROTOCOL.md §11.1
    /// says. Trustees and clerks declare their own buckets; the late-close
    /// window is measured in this one (VC-057). The chain does not require
    /// buckets to grow, so an earlier checkpoint's later bucket does not
    /// count.
    fn witness_time(&self, at: Seq) -> TimeBucket {
        self.checkpoints
            .iter()
            .filter(|(frame, _, _)| *frame < at.get())
            .max_by_key(|(frame, _, _)| *frame)
            .map_or(TimeBucket::new(0), |(_, _, bucket)| *bucket)
    }

    /// The `CRYPTO_TALLY_AID` capability for the day of `bucket`.
    fn cap(&self, bucket: TimeBucket) -> Option<Cap<'a, CryptoTallyAid>> {
        let day = day_of(self.genesis, bucket)?;
        self.authority.authorization()?.grant(day).ok()
    }
}

/// The tally events of the ledger, decoded, in frame order.
#[derive(Default)]
struct Events<'a> {
    receipts: Vec<(
        IndexedEvent<'a>,
        QuorumSigned<'a>,
        ReceiptResolutionParts<'a>,
    )>,
    scopes: Vec<(Seq, QuorumSigned<'a>, TallyScopeParts<'a>)>,
    openings: Vec<(Seq, QuorumSigned<'a>, AggregateOpeningParts<'a>)>,
    papers: Vec<(Seq, WitnessedEvent<'a>, PaperCountParts<'a>)>,
}

fn events<'a>(index: &LedgerIndex<'a>) -> Events<'a> {
    let mut out = Events::default();
    for e in index.events() {
        let Some(bytes) = e.bytes else { continue };
        if e.schema == SCHEMA_QUORUM_SIGNED {
            let Some(q) = decode::<QuorumSigned<'a>>(e.schema, bytes) else {
                continue;
            };
            match q.kind() {
                QuorumKind::ReceiptResolution => {
                    if let Some(b) = q.receipt_resolution() {
                        out.receipts.push((*e, q, *b.parts()));
                    }
                }
                QuorumKind::TallyScope => {
                    if let Some(b) = q.tally_scope() {
                        out.scopes.push((e.seq, q, *b.parts()));
                    }
                }
                QuorumKind::AggregateOpening => {
                    if let Some(b) = q.aggregate_opening() {
                        out.openings.push((e.seq, q, *b.parts()));
                    }
                }
            }
        } else if e.schema == SCHEMA_WITNESSED_EVENT
            && let Some(w) = decode::<WitnessedEvent<'a>>(e.schema, bytes)
            && let Ok(b) = w.body::<PaperCountReportBody<'a>>(SCHEMA_PAPER_COUNT_REPORT_BODY)
        {
            out.papers.push((e.seq, w, *b.parts()));
        }
    }
    out
}

/// The stage's working state.
struct Work<'a> {
    boxes: BTreeMap<&'a [u8], BoxInfo<'a>>,
    refused: Vec<TallyRefused>,
}

impl<'a> Work<'a> {
    fn refuse(&mut self, seq: Seq, event: TallyEvent, refusal: TallyRefusal) {
        self.refused.push(TallyRefused {
            seq,
            event,
            refusal,
        });
    }

    /// Takes each receipt resolution and applies its outcomes.
    fn receipts(
        &mut self,
        ctx: &Ctx<'_, 'a>,
        receipts: &[(
            IndexedEvent<'a>,
            QuorumSigned<'a>,
            ReceiptResolutionParts<'a>,
        )],
    ) {
        for (e, q, p) in receipts {
            match self.take_receipt(ctx, e, q, p) {
                Ok(()) => {}
                Err(refusal) => self.refuse(e.seq, TallyEvent::Receipt, refusal),
            }
        }
    }

    fn take_receipt(
        &mut self,
        ctx: &Ctx<'_, 'a>,
        e: &IndexedEvent<'a>,
        q: &QuorumSigned<'_>,
        p: &ReceiptResolutionParts<'_>,
    ) -> Result<(), TallyRefusal> {
        if !ctx.trustees.signed(q) {
            return Err(TallyRefusal::Signature);
        }
        let _cap = ctx.cap(p.time_bucket).ok_or(TallyRefusal::Capability)?;
        let info = self
            .boxes
            .get_mut(p.box_id.as_bytes())
            .filter(|b| b.absentee())
            .ok_or(TallyRefusal::Subject)?;
        if info
            .close
            .is_none_or(|(close, _)| close.get() >= e.seq.get())
        {
            return Err(TallyRefusal::Premature);
        }
        let body_hash = object_hash(q.body_bytes());
        if let Some((_, taken)) = info.resolution {
            return Err(if taken == body_hash {
                TallyRefusal::Repeated
            } else {
                TallyRefusal::Conflict
            });
        }
        let outcomes: BTreeMap<[u8; 64], ReceiptOutcome> = p
            .entries
            .iter()
            .map(|entry| (entry.record_hash.0, entry.outcome))
            .collect();
        let cast: BTreeSet<[u8; 64]> = info
            .records
            .iter()
            .filter(|r| r.cast)
            .map(|r| r.code.0)
            .collect();
        if outcomes.len() != p.entries.len() || !outcomes.keys().copied().eq(cast) {
            return Err(TallyRefusal::Entries);
        }
        info.resolution = Some((e.seq, body_hash));
        for rec in info.records.iter_mut().filter(|r| r.cast) {
            if let Some(outcome) = outcomes.get(&rec.code.0)
                && let Ok(state) = rec.state.apply(RecordEvent::Receipt(receipt_of(*outcome)))
            {
                rec.state = state;
                rec.receipt = Some((e.seq, e.hash));
            }
        }
        Ok(())
    }

    /// Applies each legal decision with a tally effect, in frame order.
    fn decisions(&mut self, disputes: &DisputeStage<'_>) {
        let mut all: Vec<(Seq, Hash512, TallyEffect, &crate::DisputeEntry<'_>)> = disputes
            .disputes()
            .iter()
            .flat_map(|d| {
                d.decisions
                    .iter()
                    .filter(|x| x.tally_effect != TallyEffect::NoEffect)
                    .map(move |x| (x.seq, x.event_hash, x.tally_effect, d))
            })
            .collect();
        all.sort_by_key(|(seq, ..)| seq.get());
        for (seq, hash, effect, dispute) in all {
            if self.apply_decision(seq, hash, effect, dispute).is_none() {
                self.refuse(seq, TallyEvent::Decision, TallyRefusal::Effect);
            }
        }
    }

    fn apply_decision(
        &mut self,
        seq: Seq,
        hash: Hash512,
        effect: TallyEffect,
        dispute: &crate::DisputeEntry<'_>,
    ) -> Option<()> {
        if dispute.dispute_type != DisputeType::Postal {
            return None;
        }
        let box_id = dispute.box_id?;
        let record_hash = dispute.record_hash?;
        let rec = self
            .boxes
            .get_mut(box_id.as_bytes())?
            .records
            .iter_mut()
            .find(|r| r.code == record_hash)?;
        // The law decides on a record the resolution already found
        // damaged or in the wrong district.
        if !(awaits_law(rec.state) && rec.receipt.is_some_and(|(r, _)| r.get() < seq.get())) {
            return None;
        }
        let include = effect == TallyEffect::Include;
        rec.state = rec
            .state
            .apply(RecordEvent::LegalDecision { include })
            .ok()?;
        rec.legal = Some((seq, hash));
        Some(())
    }

    /// The boxes of ballot style `style`.
    fn style_boxes<'s>(&'s self, style: &'s [u8]) -> impl Iterator<Item = &'s BoxInfo<'a>> + 's {
        self.boxes
            .values()
            .filter(move |b| b.entry.ballot_style_id.as_bytes() == style)
    }

    /// What a scope of `style` recorded at frame `at` with time bucket `now`
    /// waits for.
    fn readiness(&self, style: &[u8], at: Seq, now: TimeBucket) -> TallyReadiness {
        let before = |seq: Seq| seq.get() < at.get();
        let mut ready = TallyReadiness {
            boxes_closed: true,
            receipts_resolved: true,
            legal_resolved: true,
            last_close: TimeBucket::new(0),
            now,
        };
        for b in self.style_boxes(style) {
            match b.close {
                Some((seq, bucket)) if before(seq) => {
                    ready.last_close = TimeBucket::new(ready.last_close.get().max(bucket.get()));
                }
                Some(_) | None => ready.boxes_closed = false,
            }
            let has_cast = b.records.iter().any(|r| r.cast);
            if b.absentee() && has_cast && !b.resolution.is_some_and(|(seq, _)| before(seq)) {
                ready.receipts_resolved = false;
            }
            let undecided = b
                .records
                .iter()
                .any(|r| awaits_law(r.state) && r.legal.is_none_or(|(seq, _)| !before(seq)));
            if undecided {
                ready.legal_resolved = false;
            }
        }
        ready
    }
}

/// A unit under construction: its public tally and the included records.
struct UnitWork<'a> {
    tally: UnitTally<'a>,
    choices: u16,
    records: Vec<CastRecord<'a>>,
    /// The body hash of the scope taken.
    scope_hash: Option<Hash512>,
    /// The digits of each verified opening, by chunk.
    digits: BTreeMap<u8, [u32; DIGITS]>,
    /// The body hash of the opening taken, by chunk.
    opening_hashes: BTreeMap<u8, Hash512>,
    /// The body hash of the paper count taken.
    paper_hash: Option<Hash512>,
}

/// The sorted-set root of `codes` (ascending already).
fn root(codes: &[Hash512]) -> Option<Hash512> {
    sorted_set_root(codes).ok()
}

/// The recomputed tally of style `style` in unit `unit`.
fn unit_work<'a>(
    work: &Work<'a>,
    genesis: &VerifiedGenesis<'a>,
    style: BallotStyleId<'a>,
    unit: ReportingUnitId<'a>,
) -> UnitWork<'a> {
    let entry = genesis.ballot_style(style.as_bytes());
    let mut included: Vec<Hash512> = Vec::new();
    let mut records: Vec<CastRecord<'a>> = Vec::new();
    let mut exclusions: Vec<ExpectedExclusion> = Vec::new();
    let mut no_record = Some(0u64);
    let mut with_paper = 0u64;
    let in_unit = work
        .style_boxes(style.as_bytes())
        .filter(|b| b.entry.reporting_unit_id.as_bytes() == unit.as_bytes());
    for b in in_unit {
        no_record = no_record.and_then(|n| n.checked_add(b.effective.map_or(0, |(_, f)| f)));
        for rec in &b.records {
            match rec.state.disposition() {
                Disposition::Include => {
                    included.push(rec.code);
                    if let Some(r) = rec.record {
                        records.push(r);
                    }
                }
                Disposition::Exclude(exclusion) => {
                    exclusions.push(ExpectedExclusion {
                        record_hash: rec.code,
                        reason: reason_of(exclusion),
                        basis: b.basis(rec, exclusion),
                    });
                    if paper_counted(rec.state) {
                        with_paper = with_paper.saturating_add(1);
                    }
                }
                Disposition::PendingReceipt | Disposition::PendingLegal => {}
            }
        }
    }
    included.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    exclusions.sort_by(|a, b| a.record_hash.as_bytes().cmp(b.record_hash.as_bytes()));
    UnitWork {
        tally: UnitTally {
            ballot_style_id: style,
            reporting_unit_id: unit,
            chunks: entry.map_or(0, ityv_encoding::BallotStyleEntry::chunks),
            included_root: root(&included),
            included,
            exclusions,
            no_record_count: no_record.unwrap_or(u64::MAX),
            excluded_with_paper: with_paper,
            scope: None,
            scope_problems: Vec::new(),
            openings: Vec::new(),
            counts: None,
            paper: None,
            comparison: None,
            holds: HoldSet::empty(),
        },
        choices: entry.map_or(0, ityv_encoding::BallotStyleEntry::choices),
        records,
        scope_hash: None,
        digits: BTreeMap::new(),
        opening_hashes: BTreeMap::new(),
        paper_hash: None,
    }
}

/// How scope `p` differs from the recomputation `t`.
fn compare_scope(t: &UnitTally<'_>, p: &TallyScopeParts<'_>) -> Vec<ScopeProblem> {
    let mut out: Vec<ScopeProblem> = Vec::new();
    if u64::try_from(t.included.len()).ok() != Some(p.included_count) {
        out.push(ScopeProblem::IncludedCount);
    }
    if t.included_root != Some(p.included_root) {
        out.push(ScopeProblem::IncludedRoot);
    }
    if t.no_record_count != p.no_record_count {
        out.push(ScopeProblem::NoRecordCount);
    }
    let mut expected: BTreeMap<[u8; 64], &ExpectedExclusion> =
        t.exclusions.iter().map(|x| (x.record_hash.0, x)).collect();
    for listed in p.exclusions.iter() {
        let code = listed.record_hash;
        match expected.remove(&code.0) {
            None => out.push(ScopeProblem::Unexpected(code)),
            Some(x) if x.reason != listed.reason => out.push(ScopeProblem::Reason(code)),
            Some(x) if x.basis != Some(listed.basis) => out.push(ScopeProblem::Basis(code)),
            Some(_) => {}
        }
    }
    out.extend(
        expected
            .keys()
            .map(|code| ScopeProblem::Missing(Hash512(*code))),
    );
    out
}

/// Checks opening `p` of chunk `p.chunk` against the included records of
/// `u`: the equation, then the digits.
fn open(
    bases: &Bases,
    u: &UnitWork<'_>,
    p: &AggregateOpeningParts<'_>,
) -> Result<[u32; DIGITS], OpeningOutcome> {
    let chunk = usize::from(p.chunk);
    let commitments: Option<Vec<Commitment>> = u
        .records
        .iter()
        .map(|r| {
            let point = r.body().commitments().as_slice().get(chunk).copied()?;
            Commitment::from_point32(point).ok()
        })
        .collect();
    let commitments = commitments
        .filter(|c| c.len() == u.tally.included.len())
        .ok_or(OpeningOutcome::Equation)?;
    let total = sum_commitments(&commitments).map_err(|_| OpeningOutcome::Equation)?;
    let scalar = |s: ityv_encoding::Scalar32| Scalar::from_canonical_bytes(s.0).ok();
    let (Some(packed), Some(rand), Some(id)) =
        (scalar(p.packed_sum), scalar(p.rand_sum), scalar(p.id_sum))
    else {
        return Err(OpeningOutcome::Equation);
    };
    let opened = verify_aggregate(bases, &total, &packed, &id, &rand)
        .map_err(|_| OpeningOutcome::Equation)?;
    let digits = decode_digits(opened.get().packed_sum()).map_err(|_| OpeningOutcome::Digits)?;
    // VC-024: no option has more votes than the unit has records. A digit
    // on an option the style does not have leaves the counts short of the
    // included count, which [`counts`] refuses once every chunk opened.
    let included = u64::try_from(u.tally.included.len()).unwrap_or(u64::MAX);
    if digits.iter().any(|digit| u64::from(*digit) > included) {
        return Err(OpeningOutcome::Digits);
    }
    Ok(digits)
}

/// The counts per option from the digits of every chunk of `u`, if every
/// chunk verified and they sum to the included count.
fn counts(u: &UnitWork<'_>) -> Option<Vec<u64>> {
    let options = usize::from(u.choices).saturating_add(2);
    let mut out: Vec<u64> = Vec::with_capacity(options);
    for t in 0..options {
        let chunk = u8::try_from(t.checked_div(DIGITS)?).ok()?;
        let digit = u.digits.get(&chunk)?.get(t.checked_rem(DIGITS)?)?;
        out.push(u64::from(*digit));
    }
    let total = out.iter().try_fold(0u64, |acc, c| acc.checked_add(*c));
    (total == u64::try_from(u.tally.included.len()).ok()).then_some(out)
}

/// The machine count of §11.5 from the counts per option.
fn machine<'c>(t: &UnitTally<'_>, counts: &'c [u64], choices: u16) -> Option<MachineCount<'c>> {
    let m = usize::from(choices);
    Some(MachineCount {
        candidates: counts.get(1..=m)?,
        blank: *counts.first()?,
        unreadable: *counts.get(m.checked_add(1)?)?,
        without_record: t.no_record_count,
        excluded_with_paper: t.excluded_with_paper,
    })
}

/// Whether the paper count report `event` of unit `unit` is signed by the
/// chair of the unit's commission and by observers, as the roster of the
/// state in force at `seq` registers them.
fn paper_signed(
    ctx: &Ctx<'_, '_>,
    seq: Seq,
    event: &WitnessedEvent<'_>,
    unit: &Entry<ReportingUnitEntry<'_>>,
) -> bool {
    let roster: Vec<RosterEntry<'_>> = ctx.genesis.roster_at(ctx.index.state_at(seq));
    // The roster is keyed by signer: the key of the one entry of each
    // signer. `PaperCount::check` then binds each token to that entry's
    // role (chair or observer) and organisation (the unit's commission
    // for the chair).
    let pairs: Option<Vec<(&[u8; HYBRID_SIG_LEN], &[u8; HYBRID_VK_LEN])>> = event
        .sigs()
        .map(|s| {
            roster
                .iter()
                .map(Entry::get)
                .find(|r| r.signer_id.as_bytes() == s.signer_id.as_bytes())
                .map(|r| (s.sig, r.key))
        })
        .collect();
    let Some(material) = pairs.and_then(|p| Material::new(p.into_iter())) else {
        return false;
    };
    let Some(purpose) = Purpose::new(event.purpose()) else {
        return false;
    };
    let Some(tokens) = material.verify(&purpose, event.body_bytes()) else {
        return false;
    };
    let signed = Signed {
        event,
        tokens: &tokens,
    };
    PaperCount::check(&signed, &roster, unit).is_ok()
}

/// A ballot style and reporting unit, by their identifiers.
type UnitKey<'a> = (&'a [u8], &'a [u8]);

/// The units of the genesis's last state, by (style, unit).
type Units<'a> = BTreeMap<UnitKey<'a>, UnitWork<'a>>;

/// The refusal of a second event for what `taken` (a body hash) already
/// answers: the same body again, or a conflict.
fn again(taken: Hash512, body: &[u8]) -> TallyRefusal {
    if taken == object_hash(body) {
        TallyRefusal::Repeated
    } else {
        TallyRefusal::Conflict
    }
}

/// Whether tally scope `p` (in `q`, at frame `seq`) can be taken for
/// `unit`.
fn take_scope(
    ctx: &Ctx<'_, '_>,
    work: &Work<'_>,
    unit: Option<&UnitWork<'_>>,
    seq: Seq,
    q: &QuorumSigned<'_>,
    p: &TallyScopeParts<'_>,
) -> Result<(), TallyRefusal> {
    if !ctx.trustees.signed(q) {
        return Err(TallyRefusal::Signature);
    }
    let cap = ctx.cap(p.time_bucket).ok_or(TallyRefusal::Capability)?;
    let unit = unit.ok_or(TallyRefusal::Subject)?;
    if let Some(taken) = unit.scope_hash {
        return Err(again(taken, q.body_bytes()));
    }
    let ready = work.readiness(p.ballot_style_id.as_bytes(), seq, ctx.witness_time(seq));
    admit_tally_scope(&cap, p.election_id, &ready).map_err(|_| TallyRefusal::Premature)
}

/// Takes each tally scope.
fn scopes<'a>(
    ctx: &Ctx<'_, 'a>,
    work: &mut Work<'a>,
    units: &mut Units<'a>,
    scopes: &[(Seq, QuorumSigned<'a>, TallyScopeParts<'a>)],
) {
    for (seq, q, p) in scopes {
        let key = (p.ballot_style_id.as_bytes(), p.reporting_unit_id.as_bytes());
        let taken = take_scope(ctx, work, units.get(&key), *seq, q, p);
        let unit = units.get_mut(&key);
        match (taken, unit) {
            (Ok(()), Some(u)) => {
                u.tally.scope = Some(*seq);
                u.scope_hash = Some(object_hash(q.body_bytes()));
                u.tally.scope_problems = compare_scope(&u.tally, p);
                u.tally.holds = u.tally.holds.with_if(
                    !u.tally.scope_problems.is_empty(),
                    HoldReason::TallyScopeMismatch,
                );
            }
            (Ok(()), None) => {}
            (Err(refusal), unit) => {
                if let Some(u) = unit {
                    u.tally.holds = u.tally.holds.with(HoldReason::TallyScopeRefused);
                }
                work.refuse(*seq, TallyEvent::Scope, refusal);
            }
        }
    }
}

/// Whether aggregate opening `p` (in `q`, at frame `seq`) can be taken for
/// `unit`.
fn take_opening(
    ctx: &Ctx<'_, '_>,
    unit: Option<&UnitWork<'_>>,
    seq: Seq,
    q: &QuorumSigned<'_>,
    p: &AggregateOpeningParts<'_>,
) -> Result<(), TallyRefusal> {
    if !ctx.trustees.signed(q) {
        return Err(TallyRefusal::Signature);
    }
    let cap = ctx.cap(p.time_bucket).ok_or(TallyRefusal::Capability)?;
    let unit = unit.ok_or(TallyRefusal::Subject)?;
    if p.chunk >= unit.tally.chunks {
        return Err(TallyRefusal::Subject);
    }
    let scope = unit
        .tally
        .scope
        .filter(|_| unit.scope_hash == Some(p.scope_hash))
        .ok_or(TallyRefusal::NoScope)?;
    let covered = ctx
        .checkpoints
        .iter()
        .map(|(frame, size, _)| (*frame, *size));
    let in_checkpoint = checkpointed_before(covered, scope.get(), seq.get());
    admit_aggregate_opening(&cap, p.election_id, in_checkpoint)
        .map_err(|_| TallyRefusal::Premature)?;
    if let Some(taken) = unit.opening_hashes.get(&p.chunk) {
        return Err(again(*taken, q.body_bytes()));
    }
    Ok(())
}

/// Takes each aggregate opening and checks it.
fn openings<'a>(
    ctx: &Ctx<'_, 'a>,
    work: &mut Work<'a>,
    units: &mut Units<'a>,
    openings: &[(Seq, QuorumSigned<'a>, AggregateOpeningParts<'a>)],
) {
    let bases = Bases::derive();
    for (seq, q, p) in openings {
        let key = (p.ballot_style_id.as_bytes(), p.reporting_unit_id.as_bytes());
        let taken = take_opening(ctx, units.get(&key), *seq, q, p);
        let unit = units.get_mut(&key);
        match (taken, unit) {
            (Ok(()), Some(u)) => {
                let outcome = match open(&bases, u, p) {
                    Ok(digits) => {
                        u.digits.insert(p.chunk, digits);
                        OpeningOutcome::Verified
                    }
                    Err(outcome) => outcome,
                };
                u.tally.holds = u.tally.holds.with_if(
                    outcome != OpeningOutcome::Verified,
                    HoldReason::AggregateMismatch,
                );
                u.opening_hashes
                    .insert(p.chunk, object_hash(q.body_bytes()));
                u.tally.openings.push(ChunkOpening {
                    chunk: p.chunk,
                    seq: *seq,
                    outcome,
                });
            }
            (Ok(()), None) => {}
            (Err(refusal), unit) => {
                if let Some(u) = unit {
                    u.tally.holds = u.tally.holds.with(HoldReason::AggregateRefused);
                }
                work.refuse(*seq, TallyEvent::Opening, refusal);
            }
        }
    }
}

/// Whether paper count report `p` (in `event`, at frame `seq`) can be
/// taken for `unit`: its reporting unit is one of the genesis state in
/// force at `seq`, whose commission's chair signed it.
fn take_paper(
    ctx: &Ctx<'_, '_>,
    unit: Option<&UnitWork<'_>>,
    seq: Seq,
    event: &WitnessedEvent<'_>,
    p: &PaperCountParts<'_>,
) -> Result<(), TallyRefusal> {
    let entry = ctx
        .genesis
        .reporting_unit_entry_at(ctx.index.state_at(seq), p.reporting_unit_id.as_bytes())
        .ok_or(TallyRefusal::Subject)?;
    if !paper_signed(ctx, seq, event, &entry) {
        return Err(TallyRefusal::Signature);
    }
    let unit = unit.ok_or(TallyRefusal::Subject)?;
    if p.votes.len() != usize::from(unit.choices) {
        return Err(TallyRefusal::Subject);
    }
    if let Some(taken) = unit.paper_hash {
        return Err(again(taken, event.body_bytes()));
    }
    Ok(())
}

/// Takes each paper count report.
fn papers<'a>(
    ctx: &Ctx<'_, 'a>,
    work: &mut Work<'a>,
    units: &mut Units<'a>,
    papers: &[(Seq, WitnessedEvent<'a>, PaperCountParts<'a>)],
) -> BTreeMap<UnitKey<'a>, PaperCountParts<'a>> {
    let mut taken_parts: BTreeMap<UnitKey<'a>, PaperCountParts<'a>> = BTreeMap::new();
    for (seq, event, p) in papers {
        let key = (p.ballot_style_id.as_bytes(), p.reporting_unit_id.as_bytes());
        let taken = take_paper(ctx, units.get(&key), *seq, event, p);
        let unit = units.get_mut(&key);
        match (taken, unit) {
            (Ok(()), Some(u)) => {
                u.tally.paper = Some(*seq);
                u.paper_hash = Some(object_hash(event.body_bytes()));
                taken_parts.insert(key, *p);
            }
            (Ok(()), None) => {}
            (Err(refusal), unit) => {
                if let Some(u) = unit {
                    u.tally.holds = u.tally.holds.with(HoldReason::PaperCountRefused);
                }
                work.refuse(*seq, TallyEvent::Paper, refusal);
            }
        }
    }
    taken_parts
}

/// Refuses every late close of a box recorded after a tally scope of the
/// box's ballot style was taken (VC-057, VC-100), and holds the box's
/// unit.
fn late_closes<'a>(work: &mut Work<'a>, units: &mut Units<'a>) {
    let mut refused: Vec<(Seq, UnitKey<'a>)> = Vec::new();
    for b in work.boxes.values() {
        let style = b.entry.ballot_style_id.as_bytes();
        let first_scope = units
            .iter()
            .filter(|((s, _), _)| *s == style)
            .filter_map(|(_, u)| u.tally.scope.map(Seq::get))
            .min();
        let Some(first) = first_scope else { continue };
        for late in b.late.iter().filter(|l| l.get() > first) {
            refused.push((*late, (style, b.entry.reporting_unit_id.as_bytes())));
        }
    }
    for (seq, key) in refused {
        if let Some(u) = units.get_mut(&key) {
            u.tally.holds = u.tally.holds.with(HoldReason::LateCloseAfterScope);
        }
        work.refuse(seq, TallyEvent::LateClose, TallyRefusal::AfterScope);
    }
}

/// Finishes unit `u`: the counts once every chunk verified, and the paper
/// comparison.
fn finish(u: &mut UnitWork<'_>, paper: Option<&PaperCountParts<'_>>) {
    let all_verified = (0..u.tally.chunks).all(|j| u.digits.contains_key(&j));
    if !all_verified {
        return;
    }
    let Some(found) = counts(u) else {
        u.tally.holds = u.tally.holds.with(HoldReason::AggregateMismatch);
        return;
    };
    if let Some(paper) = paper {
        let compared =
            machine(&u.tally, &found, u.choices).and_then(|m| compare_paper(&m, paper).ok());
        u.tally.holds = u.tally.holds.with_if(
            !compared.is_some_and(PaperComparison::agrees),
            HoldReason::PaperCountMismatch,
        );
        u.tally.comparison = compared;
    }
    u.tally.counts = Some(found);
}

/// Recomputes the tally of every ballot style and reporting unit of the
/// genesis and checks the receipt resolutions, legal decisions, tally
/// scopes, aggregate openings and paper count reports against it
/// (PROTOCOL.md §14 item 7).
#[must_use]
pub fn verify_tally<'a>(
    genesis: &VerifiedGenesis<'a>,
    index: &LedgerIndex<'a>,
    authority: &AuthorityStage<'a>,
    checkpoints: &CheckpointChain,
    boxes: &BoxStage<'a>,
    records: &RecordStage<'a>,
    disputes: &DisputeStage<'a>,
) -> TallyStage<'a> {
    let body = genesis.genesis().body();
    let ctx = Ctx {
        genesis,
        index,
        authority,
        trustees: Trustees {
            entries: genesis
                .trustees()
                .filter_map(|t| genesis.trustee_entry(t.trustee_id.as_bytes()))
                .collect(),
            structure: access_structure(body.parties().count(), body.chambers()),
        },
        checkpoints: checkpoints
            .checkpoints()
            .iter()
            .map(|c| (c.frame.get(), c.tree_size, c.time_bucket))
            .collect(),
    };
    let mut work = Work {
        boxes: genesis
            .boxes()
            .map(|b| (b.box_id.as_bytes(), box_info(index, boxes, records, b)))
            .collect(),
        refused: Vec::new(),
    };
    let events = events(index);
    work.receipts(&ctx, &events.receipts);
    work.decisions(disputes);

    let pairs: BTreeMap<UnitKey<'a>, (BallotStyleId<'a>, ReportingUnitId<'a>)> = genesis
        .boxes()
        .map(|b| {
            (
                (b.ballot_style_id.as_bytes(), b.reporting_unit_id.as_bytes()),
                (b.ballot_style_id, b.reporting_unit_id),
            )
        })
        .collect();
    let mut units: Units<'a> = pairs
        .iter()
        .map(|(key, (style, unit))| (*key, unit_work(&work, genesis, *style, *unit)))
        .collect();
    scopes(&ctx, &mut work, &mut units, &events.scopes);
    late_closes(&mut work, &mut units);
    openings(&ctx, &mut work, &mut units, &events.openings);
    let papers = papers(&ctx, &mut work, &mut units, &events.papers);
    for (key, u) in &mut units {
        finish(u, papers.get(key));
    }
    work.refused.sort_by_key(|r| r.seq.get());
    TallyStage {
        units: units.into_values().map(|u| u.tally).collect(),
        refused: work.refused,
    }
}
