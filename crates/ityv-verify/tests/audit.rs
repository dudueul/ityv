//! The audit stage (PROTOCOL.md §12, §14 8; VC-045..047, VC-059, VC-074;
//! ADR-0036): freezes against the recomputed frames, the seed recomputed
//! and bound to its checkpoint and beacon, the sample redrawn, opening
//! references and comparisons, restricted openings reconstructed against
//! the real commitments, escalation and hand counts, full comparisons and
//! findings, custody holds, and the report reaching `PAPER_AUDITED` only
//! when every style's audit concluded. Every record carries a real OR proof
//! over commitments made from known secrets and every signature is a real
//! hybrid signature under a key the genesis registers. The restricted
//! openings never reach the public ledger: they are handed to the verifier
//! as restricted input only.
// Integration tests: outside the TCB. Assertions use unwrap/expect, so these
// lints are relaxed for this file only (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::similar_names
)]

mod common;
mod world;

use std::sync::OnceLock;
use std::vec::Vec;

use common::{BOX_DEVICE_BASE, COMMISSION, COMMITTEE, Draft, ROSTER_BASE, leak, object};
use ityv_crypto::{audit_seed, beacon_value, object_hash};
use ityv_encoding::{
    AuditCommitBody, AuditCommitParts, AuditFindingBody, AuditFindingParts, AuditFreezeParts,
    AuditManifestFreezeBody, AuditRound, AuditRounds, AuditSeedBody, AuditSeedParts, BallotStyleId,
    BoxId, ComparisonCode, EventRole, HandCountReportBody, Hash512, OrgId, PaperCountParts,
    PaperVotes, ReportingUnitEntry, ReportingUnitId, RosterRole, SCHEMA_AUDIT_COMMIT_BODY,
    SCHEMA_AUDIT_FINDING_BODY, SCHEMA_AUDIT_FREEZE_BODY, SCHEMA_AUDIT_SEED_BODY,
    SCHEMA_BATCH_ATTEST, SCHEMA_BOX_CLOSE, SCHEMA_CAST_RECORD, SCHEMA_HAND_COUNT_REPORT_BODY,
    SCHEMA_MODULE_PROVISIONED, SCHEMA_PARTICIPATION_SET, SCHEMA_PARTY_KEY_CEREMONY,
    SCHEMA_SAMPLE_COMPARISON_BODY, SCHEMA_SAMPLE_OPENING_BODY, SCHEMA_SAMPLE_OPENING_REF_BODY,
    SCHEMA_VERSION_1, SampleComparisonBody, SampleComparisonParts, SampleOpeningBody,
    SampleOpeningParts, SampleOpeningRefBody, SampleOpeningRefParts, Scalar32, Scalars, Scope,
    TimeBucket,
};
use ityv_ledger::sorted_set_root;
use ityv_state::{AuditPhase, HoldReason, HoldSet, Publication, Status};
use ityv_verify::{
    AuditEvent, AuditInput, AuditRefusal, BeaconObservation, DeclaredRule, FrameProblem,
    Publications, Reconstruction, Report, draw_sample, verify_ledger, verify_ledger_with,
};

use world::*;

// ---------------------------------------------------------------------
// The worlds: the one-box election of the tally tests, with two auditors.

const AUDIT_SCOPES: [Scope; 6] = [
    Scope::PublicBoard,
    Scope::TrusteeBody,
    Scope::BallotMark,
    Scope::CryptoTallyAid,
    Scope::Rla,
    Scope::ObserverAccess,
];
const AUD_1: u16 = ROSTER_BASE + 32;
const AUD_2: u16 = ROSTER_BASE + 33;
const BEACON_ROUND: u64 = 777;
/// The beacon round's published output (any width).
const BEACON_OUTPUT: &[u8] = b"round 777: 0123456789abcdef";
const DICE: Hash512 = Hash512([0xD1; 64]);
const BEACON_SOURCE: Hash512 = Hash512([0xBE; 64]);
const FREEZE_BUCKET: u64 = READY + 10;
const SEED_BUCKET: u64 = READY + 20;
const COMMIT_BUCKET: u64 = READY + 15;
/// When the beacon round was published: after the commit (READY + 15)
/// and its binding checkpoint (`checkpoint_at(COMMIT_BUCKET)`, three
/// buckets earlier: the least margin, `PUBLISHED − 3`), before the seed.
const PUBLISHED: u64 = READY + 18;

/// The 64-byte beacon value of the round's output.
fn beacon() -> Hash512 {
    beacon_value(&BEACON_SOURCE, BEACON_ROUND, BEACON_OUTPUT)
}

fn with_auditors(d: &mut Draft) {
    d.roster.push(common::roster_signer(
        32,
        b"aud-1",
        RosterRole::Auditor,
        b"AUDIT-A",
        None,
    ));
    d.roster.push(common::roster_signer(
        33,
        b"aud-2",
        RosterRole::Auditor,
        b"AUDIT-B",
        None,
    ));
    d.appointments = d.referenced_appointments();
}

/// BOX-1 at ST-1 in RU-1 (STYLE-1), as [`election_world`], with the
/// auditors, under `scopes`.
fn one_box(scopes: &[Scope]) -> World {
    let mut d = draft();
    d.boxes.retain(|b| b.box_id.as_bytes() == B1.id);
    d.stations.truncate(1);
    d.policies.truncate(1);
    d.units.truncate(1);
    d.modules.retain(|m| {
        ELECTION_MODULES
            .iter()
            .any(|e| e.0 == m.module_id.as_bytes())
    });
    for entry in &mut d.modules {
        let m = ELECTION_MODULES
            .iter()
            .find(|e| e.0 == entry.module_id.as_bytes())
            .unwrap();
        entry.provisioned_hash = object_hash(provisioning(*m));
    }
    with_auditors(&mut d);
    build(&d, scopes)
}

fn audit_world() -> &'static World {
    static WORLD: OnceLock<&'static World> = OnceLock::new();
    WORLD.get_or_init(|| leak(one_box(&AUDIT_SCOPES)))
}

/// Without `OBSERVER_ACCESS`.
fn world_without_view() -> &'static World {
    static WORLD: OnceLock<&'static World> = OnceLock::new();
    WORLD.get_or_init(|| leak(one_box(&AUDIT_SCOPES[..5])))
}

/// Without `RLA` (nor `OBSERVER_ACCESS`).
fn world_without_rla() -> &'static World {
    static WORLD: OnceLock<&'static World> = OnceLock::new();
    WORLD.get_or_init(|| leak(one_box(&TALLY_SCOPES)))
}

// ---------------------------------------------------------------------
// Audit events.

const COMMITTEE_AND_OBSERVERS: [(&[u8], EventRole, &[u8], u16); 3] = [
    (b"committee", EventRole::Committee, b"IVC", COMMITTEE),
    (b"obs-a", EventRole::Observer, b"PARTY-A", ROSTER_BASE + 2),
    (b"obs-b", EventRole::Observer, b"PARTY-B", ROSTER_BASE + 3),
];

const AUDITORS_AND_OBSERVERS: [(&[u8], EventRole, &[u8], u16); 4] = [
    (b"aud-1", EventRole::Auditor, b"AUDIT-A", AUD_1),
    (b"aud-2", EventRole::Auditor, b"AUDIT-B", AUD_2),
    (b"obs-a", EventRole::Observer, b"PARTY-A", ROSTER_BASE + 2),
    (b"obs-b", EventRole::Observer, b"PARTY-B", ROSTER_BASE + 3),
];

fn rounds(list: &[(u64, u32)]) -> AuditRounds {
    let r: Vec<AuditRound> = list
        .iter()
        .map(|&(sample_size, threshold)| AuditRound {
            sample_size,
            threshold,
        })
        .collect();
    AuditRounds::new(&r).unwrap()
}

/// The freeze body of `style` over the records `frame` (any order) with
/// the rounds `list`.
fn freeze_body(style: &'static [u8], frame: &[Hash512], list: &[(u64, u32)]) -> &'static [u8] {
    freeze_body_with(style, frame, list, |_| {})
}

fn freeze_body_with(
    style: &'static [u8],
    frame: &[Hash512],
    list: &[(u64, u32)],
    tweak: impl FnOnce(&mut AuditFreezeParts<'static>),
) -> &'static [u8] {
    let frame = sorted(frame);
    let mut parts = AuditFreezeParts {
        election_id: common::election(),
        ballot_style_id: BallotStyleId::new(style).unwrap(),
        frame_count: frame.len() as u64,
        frame_root: sorted_set_root(&frame).unwrap(),
        rule_hash: Hash512([0x77; 64]),
        risk_limit_ppm: 10_000,
        beacon_source: BEACON_SOURCE,
        beacon_round: BEACON_ROUND,
        rounds: rounds(list),
        time_bucket: TimeBucket::new(FREEZE_BUCKET),
    };
    tweak(&mut parts);
    object(
        SCHEMA_AUDIT_FREEZE_BODY,
        SCHEMA_VERSION_1,
        &AuditManifestFreezeBody::new(&parts).unwrap(),
    )
}

fn freeze(body: &'static [u8]) -> &'static [u8] {
    witnessed(body, &COMMITTEE_AND_OBSERVERS)
}

/// The seed body over the checkpoint `checkpoint`, its seed computed
/// unless `tweak` changes it.
fn seed_body(
    checkpoint: Hash512,
    tweak: impl FnOnce(&mut AuditSeedParts<'static>),
) -> &'static [u8] {
    let mut parts = AuditSeedParts {
        election_id: common::election(),
        dice_hash: DICE,
        beacon_round: BEACON_ROUND,
        beacon_value: beacon(),
        checkpoint_hash: checkpoint,
        seed: Hash512::ZERO,
        time_bucket: TimeBucket::new(SEED_BUCKET),
    };
    parts.seed = audit_seed(
        &parts.dice_hash,
        &parts.beacon_value,
        &parts.checkpoint_hash,
    );
    tweak(&mut parts);
    object(
        SCHEMA_AUDIT_SEED_BODY,
        SCHEMA_VERSION_1,
        &AuditSeedBody::new(&parts).unwrap(),
    )
}

fn seed(body: &'static [u8]) -> &'static [u8] {
    witnessed(body, &COMMITTEE_AND_OBSERVERS)
}

/// The commit body over the freeze bodies `freezes`, unless `tweak`
/// changes it.
fn commit_body(
    freezes: &[&'static [u8]],
    tweak: impl FnOnce(&mut AuditCommitParts<'static>),
) -> &'static [u8] {
    let hashes: Vec<Hash512> = freezes.iter().map(|b| object_hash(b)).collect();
    let mut parts = AuditCommitParts {
        election_id: common::election(),
        dice_hash: DICE,
        beacon_source: BEACON_SOURCE,
        beacon_round: BEACON_ROUND,
        freezes_root: sorted_set_root(&sorted(&hashes)).unwrap(),
        time_bucket: TimeBucket::new(COMMIT_BUCKET),
    };
    tweak(&mut parts);
    object(
        SCHEMA_AUDIT_COMMIT_BODY,
        SCHEMA_VERSION_1,
        &AuditCommitBody::new(&parts).unwrap(),
    )
}

fn commit(body: &'static [u8]) -> &'static [u8] {
    witnessed(body, &COMMITTEE_AND_OBSERVERS)
}

/// The restricted opening of `c` (option `option`): handed to the verifier
/// as restricted input, never put on the ledger.
fn restricted(c: &Cast, option: u16) -> &'static [u8] {
    let list: Vec<Scalar32> = c.rand[..usize::from(c.chunks)]
        .iter()
        .map(|s| Scalar32(s.to_bytes()))
        .collect();
    let rand = Scalars::new(&list).unwrap();
    let body = SampleOpeningBody::new(&SampleOpeningParts {
        election_id: common::election(),
        ballot_style_id: BallotStyleId::new(c.style).unwrap(),
        record_hash: c.code,
        option_index: option,
        cast_id: c.cast_id.token(),
        rand: &rand,
    })
    .unwrap();
    object(SCHEMA_SAMPLE_OPENING_BODY, SCHEMA_VERSION_1, &body)
}

/// The hash the trustees' reference names for `c`: its true opening.
fn opened_hash(c: &Cast) -> Hash512 {
    object_hash(restricted(c, c.option))
}

/// The trustees' public reference to the opening with hash `opening` of
/// record `record` of `style`.
fn reference_of(style: &'static [u8], record: Hash512, opening: Hash512) -> &'static [u8] {
    let body = object(
        SCHEMA_SAMPLE_OPENING_REF_BODY,
        SCHEMA_VERSION_1,
        &SampleOpeningRefBody::new(&SampleOpeningRefParts {
            election_id: common::election(),
            ballot_style_id: BallotStyleId::new(style).unwrap(),
            record_hash: record,
            opening_hash: opening,
        })
        .unwrap(),
    );
    quorum(body, b"sample-opening", &QUORUM)
}

/// The reference to the true opening of `c`.
fn reference(c: &Cast) -> &'static [u8] {
    reference_of(c.style, c.code, opened_hash(c))
}

/// As [`reference`], under other signature bytes (drawn from `seed`): a
/// refused attempt and a later one must not be one event replayed.
fn reference_seeded(c: &Cast, seed: u64) -> &'static [u8] {
    let body = object(
        SCHEMA_SAMPLE_OPENING_REF_BODY,
        SCHEMA_VERSION_1,
        &SampleOpeningRefBody::new(&SampleOpeningRefParts {
            election_id: common::election(),
            ballot_style_id: BallotStyleId::new(c.style).unwrap(),
            record_hash: c.code,
            opening_hash: opened_hash(c),
        })
        .unwrap(),
    );
    quorum_seeded(body, b"sample-opening", &QUORUM, Some(seed))
}

fn comparison_body(
    style: &'static [u8],
    record: Hash512,
    opening: Hash512,
    device: &'static [u8],
    code: ComparisonCode,
    mark: bool,
) -> &'static [u8] {
    object(
        SCHEMA_SAMPLE_COMPARISON_BODY,
        SCHEMA_VERSION_1,
        &SampleComparisonBody::new(&SampleComparisonParts {
            election_id: common::election(),
            ballot_style_id: BallotStyleId::new(style).unwrap(),
            record_hash: record,
            opening_hash: opening,
            device_id: BoxId::new(device).unwrap(),
            code,
            transfer_mark: mark,
        })
        .unwrap(),
    )
}

/// The auditors' comparison of `c` (of box `bx`) with `code`.
fn compare_in(bx: Bx, c: &Cast, code: ComparisonCode, mark: bool) -> &'static [u8] {
    witnessed(
        comparison_body(c.style, c.code, opened_hash(c), bx.id, code, mark),
        &AUDITORS_AND_OBSERVERS,
    )
}

fn compare(c: &Cast, code: ComparisonCode) -> &'static [u8] {
    compare_in(B1, c, code, false)
}

fn finding(style: &'static [u8], device: &'static [u8], doc: u8) -> &'static [u8] {
    witnessed(
        object(
            SCHEMA_AUDIT_FINDING_BODY,
            SCHEMA_VERSION_1,
            &AuditFindingBody::new(&AuditFindingParts {
                election_id: common::election(),
                ballot_style_id: BallotStyleId::new(style).unwrap(),
                device_id: BoxId::new(device).unwrap(),
                finding_hash: Hash512([doc; 64]),
                time_bucket: TimeBucket::new(SEED_BUCKET + 5),
            })
            .unwrap(),
        ),
        &AUDITORS_AND_OBSERVERS,
    )
}

fn hand_count_by(
    style: &'static [u8],
    unit: &'static [u8],
    votes: &[u64],
    invalid: u64,
    who: &[(&'static [u8], EventRole, &'static [u8], u16)],
) -> &'static [u8] {
    witnessed(
        object(
            SCHEMA_HAND_COUNT_REPORT_BODY,
            SCHEMA_VERSION_1,
            &HandCountReportBody::new(&PaperCountParts {
                election_id: common::election(),
                reporting_unit_id: ReportingUnitId::new(unit).unwrap(),
                ballot_style_id: BallotStyleId::new(style).unwrap(),
                votes: PaperVotes::new(votes).unwrap(),
                invalid,
                time_bucket: TimeBucket::new(SEED_BUCKET + 9),
            })
            .unwrap(),
        ),
        who,
    )
}

fn hand_count(style: &'static [u8], unit: &'static [u8], votes: &[u64]) -> &'static [u8] {
    hand_count_by(style, unit, votes, 0, &PAPER_SIGNERS)
}

// ---------------------------------------------------------------------
// Ledgers.

/// The one-box ledger through the tally: three records of BOX-1 for
/// options 1, 2 and 3, the participation ledger, the unit's scope, opening
/// and paper count, and a checkpoint.
fn tallied(world: &'static World) -> (Book, Vec<Cast>) {
    let mut book = through_records(world);
    let casts = std::vec![cast(B1, 1, 1), cast(B1, 2, 2), cast(B1, 3, 3)];
    tally1(
        &mut book,
        &casts,
        &spec(STYLE1, RU1, &codes(&casts)),
        &[1, 1, 1, 0, 0],
        0,
    );
    book.checkpoint();
    (book, casts)
}

/// The one-box ledger before the tally.
fn through_records(world: &'static World) -> Book {
    let mut book = Book::new(world);
    for chamber in [
        ityv_encoding::ChamberCode::P1,
        ityv_encoding::ChamberCode::P2,
    ] {
        book.push(SCHEMA_PARTY_KEY_CEREMONY, ceremony(chamber));
    }
    for m in ELECTION_MODULES {
        book.push(SCHEMA_MODULE_PROVISIONED, provisioning(m));
    }
    box1(&mut book);
    for (schema, event) in station_record(3) {
        book.push(schema, event);
    }
    book.push(SCHEMA_PARTICIPATION_SET, participation(3));
    book
}

/// Freezes STYLE-1 with `list`, commits, checkpoints (the binding
/// checkpoint) and seeds: the seed and the records drawn, in draw order.
fn seeded(book: &mut Book, casts: &[Cast], list: &[(u64, u32)]) -> (Hash512, Vec<Cast>) {
    let body = freeze_body(STYLE1, &codes(casts), list);
    book.w(freeze(body));
    book.w(commit(commit_body(&[body], |_| {})));
    book.checkpoint_at(COMMIT_BUCKET);
    let checkpoint = book.last.unwrap().1;
    book.w(seed(seed_body(checkpoint, |_| {})));
    let s = audit_seed(&DICE, &beacon(), &checkpoint);
    (s, drawn(&s, STYLE1, casts, list))
}

/// The records of `casts` (the whole frame of `style`) drawn under `seed`
/// for the last round of `list`, in draw order.
fn drawn(seed: &Hash512, style: &'static [u8], casts: &[Cast], list: &[(u64, u32)]) -> Vec<Cast> {
    let frame = sorted(&codes(casts));
    let last = list.last().unwrap().0;
    draw_sample(
        seed,
        BallotStyleId::new(style).unwrap(),
        frame.len() as u64,
        last,
    )
    .unwrap()
    .iter()
    .map(|p| *casts.iter().find(|c| c.code == frame[*p as usize]).unwrap())
    .collect()
}

fn anchored() -> Publications {
    Publications {
        anchors: Publication::Satisfied,
        board: Publication::Pending,
    }
}

fn observed() -> AuditInput<'static> {
    observed_at(BEACON_OUTPUT, PUBLISHED)
}

/// The observation of the beacon round's output `output`, published in
/// bucket `published`.
fn observed_at(output: &'static [u8], published: u64) -> AuditInput<'static> {
    AuditInput {
        beacon: Some(BeaconObservation {
            round: BEACON_ROUND,
            output,
            published: TimeBucket::new(published),
        }),
        openings: &[],
    }
}

/// A checkpoint over the whole ledger, and the report with `input`.
fn report(book: &mut Book, input: &AuditInput<'_>) -> Report<'static> {
    book.checkpoint();
    let r = verify_ledger_with(
        book.world.genesis,
        book.ledger.bytes(),
        &book.ledger.events,
        anchored(),
        input,
    );
    // Every frame indexed (no event replayed by accident) and every
    // checkpoint valid: what a test asserts is the audit's.
    assert!(
        r.index().findings().is_empty(),
        "{:?}",
        r.index().findings()
    );
    assert!(r.checkpoints().findings().is_empty());
    r
}

fn audit_refused(r: &Report<'_>) -> Vec<(u64, AuditEvent, AuditRefusal)> {
    r.audit()
        .refused()
        .iter()
        .map(|x| (x.seq.get(), x.event, x.refusal))
        .collect()
}

// ---------------------------------------------------------------------
// A clean audit.

#[test]
fn a_clean_audit_reaches_paper_audited() {
    let (mut book, casts) = tallied(audit_world());
    let (s, sample) = seeded(&mut book, &casts, &[(2, 0), (3, 0)]);
    for c in &sample[..2] {
        book.q(reference(c));
        book.w(compare(c, ComparisonCode::Match));
    }
    let r = report(&mut book, &observed());
    assert_eq!(r.status().holds(), HoldSet::empty(), "{:?}", r.audit());
    assert_eq!(r.status().status(), Status::PaperAudited);
    let audit = r.audit();
    assert!(audit.passed());
    let taken = audit.seed().unwrap();
    assert_eq!(taken.seed, s);
    assert!(taken.beacon_confirmed);
    assert_eq!(taken.beacon_round, BEACON_ROUND);
    let style = audit.style(STYLE1).unwrap();
    assert!(audit.concluded(style));
    assert_eq!(style.frame_count, 3);
    assert_eq!(style.frame_root, Some(root(&codes(&casts))));
    assert!(style.frame_problems.is_empty());
    assert_eq!(style.phase, Some(AuditPhase::Concluded { round: 0 }));
    assert_eq!(
        style.sample,
        sample.iter().map(|c| c.code).collect::<Vec<_>>()
    );
    assert_eq!(style.counts[0].compared, 2);
    assert_eq!(style.counts[0].nonzero, 0);
    assert_eq!(style.counts[1].compared, 2);
    assert_eq!(style.records.len(), 2);
    for rec in &style.records {
        assert_eq!(rec.reconstruction, Reconstruction::NotSupplied);
        assert_eq!(rec.comparison.unwrap().code, ComparisonCode::Match);
        assert!(rec.position.unwrap() < 2);
        assert_eq!(rec.box_id.as_bytes(), B1.id);
    }
    let device = &style.devices[0];
    assert_eq!(device.box_id.as_bytes(), B1.id);
    assert_eq!(device.records, 3);
    assert_eq!(device.compared, 2);
    assert_eq!(device.codes, [2, 0, 0, 0, 0, 0, 0]);
    assert!(device.followed_up());
    assert_eq!(style.units.len(), 1);
    assert_eq!(audit.station_marks().len(), 1);
    assert_eq!(audit.station_marks()[0].2, 2);

    // Without the beacon value the audit cannot conclude: the tally stands
    // and nothing is held.
    let public = verify_ledger(
        book.world.genesis,
        book.ledger.bytes(),
        &book.ledger.events,
        anchored(),
    );
    assert_eq!(public.status().holds(), HoldSet::empty());
    assert_eq!(public.status().status(), Status::CryptoTallyVerified);
    assert!(!public.audit().seed().unwrap().beacon_confirmed);
    assert!(!public.audit().passed());
    // A value for another round is no observation of this one.
    let other_round = AuditInput {
        beacon: Some(BeaconObservation {
            round: BEACON_ROUND + 1,
            output: BEACON_OUTPUT,
            published: TimeBucket::new(PUBLISHED),
        }),
        openings: &[],
    };
    let r = verify_ledger_with(
        book.world.genesis,
        book.ledger.bytes(),
        &book.ledger.events,
        anchored(),
        &other_round,
    );
    assert_eq!(r.status().status(), Status::CryptoTallyVerified);

    // A verifier with access reconstructs both openings (VC-047).
    let bodies: &'static [&'static [u8]] = leak_slice(
        sample[..2]
            .iter()
            .map(|c| restricted(c, c.option))
            .collect(),
    );
    let with_access = AuditInput {
        openings: bodies,
        ..observed()
    };
    let r = verify_ledger_with(
        book.world.genesis,
        book.ledger.bytes(),
        &book.ledger.events,
        anchored(),
        &with_access,
    );
    assert_eq!(r.status().status(), Status::PaperAudited);
    for rec in &r.audit().style(STYLE1).unwrap().records {
        assert_eq!(rec.reconstruction, Reconstruction::Reconstructed);
    }
    // A body no reference names is not checked.
    let stray: &'static [&'static [u8]] = leak_slice(std::vec![restricted(&sample[0], 0)]);
    let r = verify_ledger_with(
        book.world.genesis,
        book.ledger.bytes(),
        &book.ledger.events,
        anchored(),
        &AuditInput {
            openings: stray,
            ..observed()
        },
    );
    assert_eq!(r.status().status(), Status::PaperAudited);
}

fn leak_slice<T>(v: Vec<T>) -> &'static [T] {
    common::leak_slice(v)
}

#[test]
fn an_opening_that_does_not_reconstruct_holds_the_style() {
    let (mut book, casts) = tallied(audit_world());
    let (_, sample) = seeded(&mut book, &casts, &[(1, 0), (3, 0)]);
    let c = sample[0];
    // The trustees reference a body that opens another option.
    let wrong = restricted(&c, (c.option + 1) % 7);
    book.q(reference_of(STYLE1, c.code, object_hash(wrong)));
    book.w(witnessed(
        comparison_body(
            STYLE1,
            c.code,
            object_hash(wrong),
            B1.id,
            ComparisonCode::Match,
            false,
        ),
        &AUDITORS_AND_OBSERVERS,
    ));
    // The public verifier cannot tell.
    let r = report(&mut book, &observed());
    assert_eq!(r.status().status(), Status::PaperAudited);
    // With access it can: the body does not open the commitments.
    let bodies: &'static [&'static [u8]] = leak_slice(std::vec![wrong]);
    let r = verify_ledger_with(
        book.world.genesis,
        book.ledger.bytes(),
        &book.ledger.events,
        anchored(),
        &AuditInput {
            openings: bodies,
            ..observed()
        },
    );
    let style = r.audit().style(STYLE1).unwrap();
    assert_eq!(style.records[0].reconstruction, Reconstruction::Mismatch);
    assert_eq!(style.holds, only(HoldReason::SampleOpeningMismatch));
    assert!(!r.audit().passed());
    assert_eq!(r.status().status(), Status::HoldReview);
    assert!(
        r.status()
            .holds()
            .contains(HoldReason::SampleOpeningMismatch)
    );
}

#[test]
fn a_restricted_body_must_be_the_records_canonical_opening() {
    let (mut book, casts) = tallied(audit_world());
    let (_, sample) = seeded(&mut book, &casts, &[(1, 0), (3, 0)]);
    let c = sample[0];
    let other = casts.iter().find(|x| x.code != c.code).unwrap();
    // Bodies the trustees might reference: another record's opening, one
    // naming another style, one with a chunk too many, and bytes that are
    // no opening at all.
    let of_other = restricted(other, other.option);
    let list: Vec<Scalar32> = c.rand[..2].iter().map(|s| Scalar32(s.to_bytes())).collect();
    let rand = Scalars::new(&list).unwrap();
    let make = |style: &'static [u8], rand: &Scalars<8>| {
        object(
            SCHEMA_SAMPLE_OPENING_BODY,
            SCHEMA_VERSION_1,
            &SampleOpeningBody::new(&SampleOpeningParts {
                election_id: common::election(),
                ballot_style_id: BallotStyleId::new(style).unwrap(),
                record_hash: c.code,
                option_index: c.option,
                cast_id: c.cast_id.token(),
                rand,
            })
            .unwrap(),
        )
    };
    let two_chunks = make(STYLE1, &rand);
    let one = Scalars::new(&list[..1]).unwrap();
    let of_style2 = make(STYLE2, &one);
    let garbage: &'static [u8] = leak_slice(std::vec![0x42u8; 40]);
    for bad in [of_other, two_chunks, of_style2, garbage] {
        let mut book = Book {
            world: book.world,
            ledger: clone_ledger(&book),
            frames: book.frames.clone(),
            closes: book.closes.clone(),
            disputes: book.disputes.clone(),
            last: book.last,
            bucket: book.bucket,
        };
        book.q(reference_of(STYLE1, c.code, object_hash(bad)));
        let bodies: &'static [&'static [u8]] = leak_slice(std::vec![bad]);
        let r = report(
            &mut book,
            &AuditInput {
                openings: bodies,
                ..observed()
            },
        );
        let style = r.audit().style(STYLE1).unwrap();
        assert_eq!(style.records[0].reconstruction, Reconstruction::Mismatch);
        assert!(style.holds.contains(HoldReason::SampleOpeningMismatch));
    }
    // The true opening reconstructs.
    book.q(reference(&c));
    let bodies: &'static [&'static [u8]] = leak_slice(std::vec![restricted(&c, c.option)]);
    let r = report(
        &mut book,
        &AuditInput {
            openings: bodies,
            ..observed()
        },
    );
    let style = r.audit().style(STYLE1).unwrap();
    assert_eq!(
        style.records[0].reconstruction,
        Reconstruction::Reconstructed
    );
    assert!(style.holds.is_empty());
}

/// A copy of `book`'s ledger, to branch it.
fn clone_ledger(book: &Book) -> common::Ledger {
    let mut ledger = common::Ledger::new();
    let stream = book.ledger.bytes();
    let mut at = 0usize;
    let mut index = 0usize;
    while at < stream.len() {
        let len = u32::from_be_bytes(stream[at..at + 4].try_into().unwrap()) as usize;
        let frame: ityv_encoding::LedgerFrame<'_> = ityv_encoding::decode_object(
            ityv_encoding::SCHEMA_LEDGER_FRAME,
            SCHEMA_VERSION_1,
            &stream[at + 4..at + 4 + len],
        )
        .unwrap();
        ledger.push(frame.event_schema_id(), book.ledger.events[index]);
        index += 1;
        at += 4 + len;
    }
    ledger
}

// ---------------------------------------------------------------------
// The freeze.

#[test]
fn a_freeze_follows_the_scopes_and_must_be_the_ledgers_frame() {
    let world = audit_world();
    let mut book = through_records(world);
    let casts = std::vec![cast(B1, 1, 1), cast(B1, 2, 2), cast(B1, 3, 3)];
    let all = codes(&casts);
    // Before the tally scope: too early.
    let early = book.w(freeze(freeze_body(STYLE1, &all, &[(2, 0)])));
    tally1(
        &mut book,
        &casts,
        &spec(STYLE1, RU1, &all),
        &[1, 1, 1, 0, 0],
        0,
    );
    // A style no box has, a forged signature (the committee's place signed
    // by the commission's key), no RLA for the day.
    let stranger = book.w(freeze(freeze_body(STYLE2, &all, &[(2, 0)])));
    let mut forged_who = COMMITTEE_AND_OBSERVERS;
    forged_who[0].3 = COMMISSION;
    let forged = book.w(witnessed(freeze_body(STYLE1, &all, &[(2, 0)]), &forged_who));
    let late = book.w(freeze(freeze_body_with(STYLE1, &all, &[(2, 0)], |p| {
        p.time_bucket = TimeBucket::new(96 * 200);
    })));
    // A frame that is not the ledger's: taken, and the style is held.
    let wrong_body = freeze_body_with(STYLE1, &all, &[(2, 0)], |p| {
        p.frame_root = Hash512([0x99; 64]);
        p.frame_count = 2;
    });
    let taken = book.w(freeze(wrong_body));
    let again = book.w(witnessed_seeded(
        wrong_body,
        &COMMITTEE_AND_OBSERVERS,
        Some(5),
    ));
    let other = book.w(freeze(freeze_body(STYLE1, &all, &[(3, 0)])));
    book.w(commit(commit_body(&[wrong_body], |_| {})));
    book.checkpoint_at(COMMIT_BUCKET);
    let checkpoint = book.last.unwrap().1;
    book.w(seed(seed_body(checkpoint, |_| {})));
    let r = report(&mut book, &observed());
    assert_eq!(
        audit_refused(&r),
        [
            (early, AuditEvent::Freeze, AuditRefusal::Premature),
            (stranger, AuditEvent::Freeze, AuditRefusal::Subject),
            (forged, AuditEvent::Freeze, AuditRefusal::Signature),
            (late, AuditEvent::Freeze, AuditRefusal::Capability),
            (again, AuditEvent::Freeze, AuditRefusal::Repeated),
            (other, AuditEvent::Freeze, AuditRefusal::Conflict),
        ]
    );
    let style = r.audit().style(STYLE1).unwrap();
    assert_eq!(style.freeze.unwrap().get(), taken);
    assert_eq!(
        style.frame_problems,
        [FrameProblem::Count, FrameProblem::Root]
    );
    assert!(style.holds.contains(HoldReason::AuditFrameMismatch));
    // The seed is taken, but no sample is drawn from a frame that is not
    // the ledger's: nothing can be opened.
    assert!(r.audit().seed().is_some());
    assert!(style.sample.is_empty());
    assert_eq!(style.phase, None);
    assert_eq!(r.status().status(), Status::HoldReview);
    for reason in [
        HoldReason::AuditFreezeRefused,
        HoldReason::AuditFrameMismatch,
    ] {
        assert!(r.status().holds().contains(reason));
    }

    // Only the root wrong.
    let (mut book, casts) = tallied(world);
    book.w(freeze(freeze_body_with(
        STYLE1,
        &codes(&casts),
        &[(2, 0)],
        |p| {
            p.frame_root = Hash512([0x99; 64]);
        },
    )));
    let r = report(&mut book, &observed());
    let style = r.audit().style(STYLE1).unwrap();
    assert_eq!(style.frame_problems, [FrameProblem::Root]);
}

#[test]
fn without_rla_nothing_of_the_audit_is_taken() {
    let (mut book, casts) = tallied(world_without_rla());
    let body = freeze_body(STYLE1, &codes(&casts), &[(2, 0)]);
    let at = book.w(freeze(body));
    let commit_at = book.w(commit(commit_body(&[body], |_| {})));
    book.checkpoint_at(COMMIT_BUCKET);
    let checkpoint = book.last.unwrap().1;
    let seed_at = book.w(seed(seed_body(checkpoint, |_| {})));
    let finding_at = book.w(finding(STYLE1, B1.id, 0x0F));
    let r = report(&mut book, &observed());
    assert_eq!(
        audit_refused(&r),
        [
            (at, AuditEvent::Freeze, AuditRefusal::Capability),
            (commit_at, AuditEvent::Commit, AuditRefusal::Capability),
            (seed_at, AuditEvent::Seed, AuditRefusal::Capability),
            (finding_at, AuditEvent::Finding, AuditRefusal::Capability),
        ]
    );
    assert_eq!(r.status().status(), Status::HoldReview);
}

// ---------------------------------------------------------------------
// The seed.

#[test]
fn the_seed_is_recomputed_and_bound_to_the_commit_and_its_binding_checkpoint() {
    let (mut book, casts) = tallied(audit_world());
    let first = book.last.unwrap().1;
    // Before any freeze or commit: too early.
    let no_commit = book.w(seed(seed_body(first, |_| {})));
    let body = freeze_body(STYLE1, &codes(&casts), &[(2, 0)]);
    book.w(freeze(body));
    // A freeze but no commit yet (other signature bytes: the same event
    // twice would be a replay).
    let uncommitted = book.w(witnessed_seeded(
        seed_body(first, |_| {}),
        &COMMITTEE_AND_OBSERVERS,
        Some(12),
    ));
    let commit_at = book.w(commit(commit_body(&[body], |_| {})));
    // No checkpoint covers the commit yet.
    let unbound = book.w(witnessed_seeded(
        seed_body(first, |_| {}),
        &COMMITTEE_AND_OBSERVERS,
        Some(13),
    ));
    let binding_frame = book.checkpoint_at(COMMIT_BUCKET);
    let binding = book.last.unwrap().1;
    // A checkpoint cut later, while the seed is being signed, never matters.
    book.checkpoint();
    let later = book.last.unwrap().1;
    let not_binding = book.w(seed(seed_body(later, |_| {})));
    let other_dice = book.w(seed(seed_body(binding, |p| {
        p.dice_hash = Hash512([0xD2; 64]);
        p.seed = audit_seed(&p.dice_hash, &p.beacon_value, &p.checkpoint_hash);
    })));
    let wrong_seed = book.w(seed(seed_body(binding, |p| {
        p.seed = Hash512([0x5A; 64]);
    })));
    let other_round = book.w(seed(seed_body(binding, |p| {
        p.beacon_round = BEACON_ROUND + 1;
    })));
    let mut forged_who = COMMITTEE_AND_OBSERVERS;
    forged_who[0].3 = COMMISSION;
    let forged = book.w(witnessed(seed_body(binding, |_| {}), &forged_who));
    let late = book.w(seed(seed_body(binding, |p| {
        p.time_bucket = TimeBucket::new(96 * 200);
    })));
    let good = seed_body(binding, |_| {});
    let taken = book.w(seed(good));
    let repeated = book.w(witnessed_seeded(good, &COMMITTEE_AND_OBSERVERS, Some(9)));
    let conflict = book.w(seed(seed_body(binding, |p| {
        p.time_bucket = TimeBucket::new(SEED_BUCKET + 1);
    })));
    let r = report(&mut book, &observed());
    assert_eq!(
        audit_refused(&r),
        [
            (no_commit, AuditEvent::Seed, AuditRefusal::Premature),
            (uncommitted, AuditEvent::Seed, AuditRefusal::Premature),
            (unbound, AuditEvent::Seed, AuditRefusal::Premature),
            (not_binding, AuditEvent::Seed, AuditRefusal::Checkpoint),
            (other_dice, AuditEvent::Seed, AuditRefusal::Commit),
            (wrong_seed, AuditEvent::Seed, AuditRefusal::Recompute),
            (other_round, AuditEvent::Seed, AuditRefusal::Beacon),
            (forged, AuditEvent::Seed, AuditRefusal::Signature),
            (late, AuditEvent::Seed, AuditRefusal::Capability),
            (repeated, AuditEvent::Seed, AuditRefusal::Repeated),
            (conflict, AuditEvent::Seed, AuditRefusal::Conflict),
        ]
    );
    let c = r.audit().commit().unwrap();
    assert_eq!(c.seq.get(), commit_at);
    assert_eq!(c.binding.unwrap().get(), binding_frame);
    assert_eq!((c.dice_hash, c.beacon_round), (DICE, BEACON_ROUND));
    let s = r.audit().seed().unwrap();
    assert_eq!(s.seq.get(), taken);
    assert_eq!(s.seed, audit_seed(&DICE, &beacon(), &binding));
    assert_eq!(r.status().status(), Status::HoldReview);
    assert!(r.status().holds().contains(HoldReason::AuditSeedRefused));

    // A beacon value other than the one the caller observed refuses the
    // seed.
    let (mut book, casts) = tallied(audit_world());
    let (_, sample) = seeded(&mut book, &casts, &[(1, 0)]);
    book.q(reference(&sample[0]));
    book.w(compare(&sample[0], ComparisonCode::Match));
    let r = report(&mut book, &observed_at(b"another output", PUBLISHED));
    assert!(r.audit().seed().is_none());
    assert!(
        audit_refused(&r)
            .iter()
            .any(|(_, e, x)| *e == AuditEvent::Seed && *x == AuditRefusal::Beacon)
    );
    // Without the seed nothing after it is taken.
    assert!(
        audit_refused(&r)
            .iter()
            .any(|(_, e, x)| *e == AuditEvent::Opening && *x == AuditRefusal::Premature)
    );
    assert_eq!(r.status().status(), Status::HoldReview);
    // The observed value confirms it.
    let r = report(&mut book, &observed());
    assert_eq!(r.status().status(), Status::PaperAudited);
}

#[test]
fn freezes_must_designate_one_beacon() {
    // Two styles: the freezes disagree on the beacon's source.
    let world = two_style_world();
    let (mut book, c1, c2) = two_style_tallied(world);
    let f1 = freeze_body(STYLE1, &codes(&c1), &[(1, 0)]);
    let f2 = freeze_body_with(STYLE2, &codes(&c2), &[(1, 0)], |p| {
        p.beacon_source = Hash512([0xBF; 64]);
    });
    book.w(freeze(f1));
    book.w(freeze(f2));
    // No commit can name both: the seed has none to follow.
    let at = book.w(commit(commit_body(&[f1, f2], |_| {})));
    book.checkpoint_at(COMMIT_BUCKET);
    let seed_at = book.w(seed(seed_body(book.last.unwrap().1, |_| {})));
    let r = report(&mut book, &observed());
    assert_eq!(
        audit_refused(&r),
        [
            (at, AuditEvent::Commit, AuditRefusal::Beacon),
            (seed_at, AuditEvent::Seed, AuditRefusal::Premature),
        ]
    );
    assert!(r.status().holds().contains(HoldReason::AuditCommitRefused));
}

// ---------------------------------------------------------------------
// Openings and comparisons.

#[test]
fn an_opening_is_taken_only_for_a_record_the_audit_calls_for() {
    let (mut book, casts) = tallied(audit_world());
    let list = [(1, 0), (3, 0)];
    let frame = codes(&casts);
    let body = freeze_body(STYLE1, &frame, &list);
    book.w(freeze(body));
    book.w(commit(commit_body(&[body], |_| {})));
    book.checkpoint_at(COMMIT_BUCKET);
    let checkpoint = book.last.unwrap().1;
    let s = audit_seed(&DICE, &beacon(), &checkpoint);
    let sample = drawn(&s, STYLE1, &casts, &list);
    // Before the seed (under other signature bytes than the one taken
    // later: the same bytes again would be a replay of the frame).
    let early = book.q(reference_seeded(&sample[0], 11));
    book.w(seed(seed_body(checkpoint, |_| {})));
    // Not in the first round's sample.
    let not_called = book.q(reference(&sample[1]));
    // A record of no frame, another style, a quorum of too few trustees.
    let unknown = book.q(reference_of(
        STYLE1,
        Hash512([0x01; 64]),
        Hash512([0x02; 64]),
    ));
    let style2 = book.q(reference_of(
        STYLE2,
        sample[0].code,
        opened_hash(&sample[0]),
    ));
    let ref_body = object(
        SCHEMA_SAMPLE_OPENING_REF_BODY,
        SCHEMA_VERSION_1,
        &SampleOpeningRefBody::new(&SampleOpeningRefParts {
            election_id: common::election(),
            ballot_style_id: BallotStyleId::new(STYLE1).unwrap(),
            record_hash: sample[0].code,
            opening_hash: opened_hash(&sample[0]),
        })
        .unwrap(),
    );
    let short = book.q(quorum(ref_body, b"sample-opening", &QUORUM[..2]));
    let taken = book.q(quorum(ref_body, b"sample-opening", &QUORUM));
    let repeated = book.q(quorum_seeded(ref_body, b"sample-opening", &QUORUM, Some(3)));
    let conflict = book.q(reference_of(STYLE1, sample[0].code, Hash512([0x03; 64])));
    let r = report(&mut book, &observed());
    assert_eq!(
        audit_refused(&r),
        [
            (early, AuditEvent::Opening, AuditRefusal::Premature),
            (not_called, AuditEvent::Opening, AuditRefusal::NotCalled),
            (unknown, AuditEvent::Opening, AuditRefusal::Subject),
            (style2, AuditEvent::Opening, AuditRefusal::Subject),
            (short, AuditEvent::Opening, AuditRefusal::Signature),
            (repeated, AuditEvent::Opening, AuditRefusal::Repeated),
            (conflict, AuditEvent::Opening, AuditRefusal::Conflict),
        ]
    );
    let style = r.audit().style(STYLE1).unwrap();
    assert_eq!(style.records.len(), 1);
    assert_eq!(style.records[0].opening.get(), taken);
    assert_eq!(style.records[0].position, Some(0));
    assert!(style.records[0].comparison.is_none());
    // The first round is not compared yet.
    assert_eq!(style.phase, Some(AuditPhase::Sampling { round: 0 }));
    assert!(
        r.status()
            .holds()
            .contains(HoldReason::SampleOpeningRefused)
    );

    // Without OBSERVER_ACCESS for the seed's day no opening is taken.
    let (mut book, casts) = tallied(world_without_view());
    let (_, sample) = seeded(&mut book, &casts, &[(1, 0)]);
    let at = book.q(reference(&sample[0]));
    let r = report(&mut book, &observed());
    assert_eq!(
        audit_refused(&r),
        [(at, AuditEvent::Opening, AuditRefusal::Capability)]
    );
}

#[test]
fn a_comparison_needs_its_opening_its_device_and_its_signers() {
    let (mut book, casts) = tallied(audit_world());
    let (_, sample) = seeded(&mut book, &casts, &[(1, 0), (3, 0)]);
    let c = sample[0];
    let before = book.w(compare(&c, ComparisonCode::Match));
    book.q(reference(&c));
    let other_opening = book.w(witnessed(
        comparison_body(
            STYLE1,
            c.code,
            Hash512([0x04; 64]),
            B1.id,
            ComparisonCode::Match,
            false,
        ),
        &AUDITORS_AND_OBSERVERS,
    ));
    let other_style = book.w(witnessed(
        comparison_body(
            STYLE2,
            c.code,
            opened_hash(&c),
            B1.id,
            ComparisonCode::Match,
            false,
        ),
        &AUDITORS_AND_OBSERVERS,
    ));
    let unknown = book.w(witnessed(
        comparison_body(
            STYLE1,
            Hash512([0x05; 64]),
            opened_hash(&c),
            B1.id,
            ComparisonCode::Match,
            false,
        ),
        &AUDITORS_AND_OBSERVERS,
    ));
    let mut forged_who = AUDITORS_AND_OBSERVERS;
    forged_who[1].3 = AUD_1;
    let forged = book.w(witnessed(
        comparison_body(
            STYLE1,
            c.code,
            opened_hash(&c),
            B1.id,
            ComparisonCode::Match,
            false,
        ),
        &forged_who,
    ));
    // An auditor not registered as one: the clerk signing as an auditor.
    let mut clerk_who = AUDITORS_AND_OBSERVERS;
    clerk_who[1] = (b"clerk-1", EventRole::Auditor, b"AUDIT-B", ROSTER_BASE);
    let clerk = book.w(witnessed(
        comparison_body(
            STYLE1,
            c.code,
            opened_hash(&c),
            B1.id,
            ComparisonCode::Match,
            false,
        ),
        &clerk_who,
    ));
    let body = comparison_body(
        STYLE1,
        c.code,
        opened_hash(&c),
        B1.id,
        ComparisonCode::Match,
        true,
    );
    let taken = book.w(witnessed(body, &AUDITORS_AND_OBSERVERS));
    let repeated = book.w(witnessed_seeded(body, &AUDITORS_AND_OBSERVERS, Some(4)));
    let conflict = book.w(compare(&c, ComparisonCode::BlankValid));
    let r = report(&mut book, &observed());
    assert_eq!(
        audit_refused(&r),
        [
            (before, AuditEvent::Comparison, AuditRefusal::Premature),
            (other_opening, AuditEvent::Comparison, AuditRefusal::Opening),
            (other_style, AuditEvent::Comparison, AuditRefusal::Subject),
            (unknown, AuditEvent::Comparison, AuditRefusal::Subject),
            (forged, AuditEvent::Comparison, AuditRefusal::Signature),
            (clerk, AuditEvent::Comparison, AuditRefusal::Signature),
            (repeated, AuditEvent::Comparison, AuditRefusal::Repeated),
            (conflict, AuditEvent::Comparison, AuditRefusal::Conflict),
        ]
    );
    let style = r.audit().style(STYLE1).unwrap();
    let rec = style.records[0];
    let taken_comparison = rec.comparison.unwrap();
    assert_eq!(taken_comparison.seq.get(), taken);
    assert!(taken_comparison.transfer_mark);
    assert_eq!(style.devices[0].transfer_marks, 1);
    assert_eq!(r.audit().station_marks()[0].1, 1);
    // The first round concluded despite the refused events, which hold.
    assert_eq!(style.phase, Some(AuditPhase::Concluded { round: 0 }));
    assert!(r.audit().concluded(style));
    assert!(!r.audit().passed());
    assert!(
        r.status()
            .holds()
            .contains(HoldReason::SampleComparisonRefused)
    );
}

#[test]
fn a_comparison_of_a_device_another_box_holds_is_refused() {
    // Two styles: BOX-2's comparison cannot name BOX-1 as its device.
    let world = two_style_world();
    let (mut book, c1, c2) = two_style_tallied(world);
    let (_, s1, s2) = two_style_seeded(&mut book, &c1, &c2, &[(1, 0)]);
    book.q(reference(&s2[0]));
    let wrong = book.w(compare_in(B1, &s2[0], ComparisonCode::Match, false));
    // A finding naming a box of the other style.
    let finding_at = book.w(finding(STYLE1, B2S.id, 0x0F));
    let r = report(&mut book, &observed());
    assert_eq!(
        audit_refused(&r),
        [
            (wrong, AuditEvent::Comparison, AuditRefusal::Subject),
            (finding_at, AuditEvent::Finding, AuditRefusal::Subject),
        ]
    );
    assert_eq!(s1.len(), 1);
}

// ---------------------------------------------------------------------
// Escalation and the hand count.

#[test]
fn discrepancies_expand_the_sample_then_call_for_a_hand_count() {
    let (mut book, casts) = tallied(audit_world());
    let (_, sample) = seeded(&mut book, &casts, &[(1, 0), (2, 1)]);
    // A hand count before the escalation is too early.
    let early = book.w(hand_count(STYLE1, RU1, &[1, 1, 1, 0, 0]));
    book.q(reference(&sample[0]));
    book.w(compare(&sample[0], ComparisonCode::UnreadableValid));
    // The first round's threshold is exceeded: the second record is now
    // called for.
    book.q(reference(&sample[1]));
    let r = report(&mut book, &observed());
    let style = r.audit().style(STYLE1).unwrap();
    assert_eq!(style.phase, Some(AuditPhase::Sampling { round: 1 }));
    assert_eq!(style.counts[0].nonzero, 1);
    assert_eq!(r.status().status(), Status::HoldReview);
    // The second discrepancy exceeds the last round: a hand count.
    let escalated = book.w(compare(&sample[1], ComparisonCode::BlankValid));
    // The record no round draws is not called for.
    let third = *casts
        .iter()
        .find(|c| !sample.iter().any(|s| s.code == c.code))
        .unwrap();
    let not_called = book.q(reference(&third));
    let stranger = book.w(hand_count(STYLE1, RU2, &[1, 1, 1, 0, 0]));
    let wrong_candidates = book.w(hand_count(STYLE1, RU1, &[1, 1, 1, 0]));
    let mut chair_x = PAPER_SIGNERS;
    chair_x[0] = (b"chair-x", EventRole::Chair, b"NEC-X", ROSTER_BASE + 31);
    let other_chair = book.w(hand_count_by(STYLE1, RU1, &[1, 1, 1, 0, 0], 0, &chair_x));
    let body_event = hand_count(STYLE1, RU1, &[1, 2, 0, 0, 0]);
    let taken = book.w(body_event);
    let conflict = book.w(hand_count(STYLE1, RU1, &[1, 1, 0, 1, 0]));
    let r = report(&mut book, &observed());
    assert_eq!(
        audit_refused(&r),
        [
            (early, AuditEvent::HandCount, AuditRefusal::Premature),
            (not_called, AuditEvent::Opening, AuditRefusal::NotCalled),
            (stranger, AuditEvent::HandCount, AuditRefusal::Subject),
            (
                wrong_candidates,
                AuditEvent::HandCount,
                AuditRefusal::Subject
            ),
            (other_chair, AuditEvent::HandCount, AuditRefusal::Signature),
            (conflict, AuditEvent::HandCount, AuditRefusal::Conflict),
        ]
    );
    let style = r.audit().style(STYLE1).unwrap();
    assert_eq!(style.phase, Some(AuditPhase::HandCount));
    assert_eq!(style.hand_count_from.unwrap().get(), escalated);
    assert_eq!(style.hand_counts.len(), 1);
    assert_eq!(style.hand_counts[0].1.get(), taken);
    assert_eq!(style.devices[0].codes, [0, 0, 0, 1, 1, 0, 0]);
    // Concluded by the hand count; the refused events hold.
    assert!(r.audit().concluded(style));
    assert!(!r.audit().passed());
    assert!(r.status().holds().contains(HoldReason::HandCountRefused));

    // The same, cleanly: the hand count of the one unit concludes.
    let (mut book, casts) = tallied(audit_world());
    let (_, sample) = seeded(&mut book, &casts, &[(1, 0), (2, 1)]);
    for c in &sample[..2] {
        book.q(reference(c));
        book.w(compare(c, ComparisonCode::UnreadableValid));
    }
    let r = report(&mut book, &observed());
    assert_eq!(r.status().status(), Status::CryptoTallyVerified);
    let hand = hand_count(STYLE1, RU1, &[1, 1, 1, 0, 0]);
    book.w(hand);
    let r = report(&mut book, &observed());
    assert_eq!(r.status().holds(), HoldSet::empty());
    assert_eq!(r.status().status(), Status::PaperAudited);
    // The same hand count again is a repeat.
    let again = book.w(witnessed_seeded(
        ityv_encoding::decode_object::<ityv_encoding::WitnessedEvent<'_>>(
            ityv_encoding::SCHEMA_WITNESSED_EVENT,
            ityv_encoding::SCHEMA_VERSION_WITNESSED,
            hand,
        )
        .unwrap()
        .body_bytes(),
        &PAPER_SIGNERS,
        Some(8),
    ));
    let r = report(&mut book, &observed());
    assert_eq!(
        audit_refused(&r),
        [(again, AuditEvent::HandCount, AuditRefusal::Repeated)]
    );
}

#[test]
fn a_round_concludes_within_its_threshold_and_calls_for_no_more() {
    // One discrepancy allowed: a code 3 then two matches conclude the
    // first round; the expansion is never called for.
    let (mut book, casts) = tallied(audit_world());
    let (_, sample) = seeded(&mut book, &casts, &[(2, 1), (3, 1)]);
    book.q(reference(&sample[0]));
    book.w(compare(&sample[0], ComparisonCode::BlankValid));
    let r = report(&mut book, &observed());
    let style = r.audit().style(STYLE1).unwrap();
    assert_eq!(style.phase, Some(AuditPhase::Sampling { round: 0 }));
    assert_eq!(r.status().status(), Status::CryptoTallyVerified);
    book.q(reference(&sample[1]));
    book.w(compare(&sample[1], ComparisonCode::Match));
    let after = book.q(reference(&sample[2]));
    let r = report(&mut book, &observed());
    let style = r.audit().style(STYLE1).unwrap();
    assert_eq!(style.phase, Some(AuditPhase::Concluded { round: 0 }));
    assert_eq!(
        audit_refused(&r),
        [(after, AuditEvent::Opening, AuditRefusal::NotCalled)]
    );
}

// ---------------------------------------------------------------------
// Full comparison, findings, custody.

#[test]
fn codes_1_and_2_call_for_a_full_comparison_and_a_finding() {
    let (mut book, casts) = tallied(audit_world());
    let (_, sample) = seeded(&mut book, &casts, &[(2, 1), (3, 1)]);
    // Before any discrepancy the records past the first round are not
    // called for.
    let not_yet = book.q(reference_seeded(&sample[2], 12));
    // A finding recorded before the discrepancy does not answer it.
    book.w(finding(STYLE1, B1.id, 0x0E));
    book.q(reference(&sample[0]));
    book.w(compare(&sample[0], ComparisonCode::OtherCandidate));
    book.q(reference(&sample[1]));
    book.w(compare(&sample[1], ComparisonCode::Match));
    let r = report(&mut book, &observed());
    let style = r.audit().style(STYLE1).unwrap();
    // The first round concluded within its threshold, but the device is
    // under full comparison.
    assert_eq!(style.phase, Some(AuditPhase::Concluded { round: 0 }));
    let device = &style.devices[0];
    assert!(device.full_comparison_from.is_some());
    assert!(!device.followed_up());
    assert!(!r.audit().concluded(style));
    // Now every record of the device is called for (VC-074).
    book.q(reference(&sample[2]));
    book.w(compare(&sample[2], ComparisonCode::Match));
    let r = report(&mut book, &observed());
    let style = r.audit().style(STYLE1).unwrap();
    assert_eq!(style.devices[0].compared, 3);
    // Still no finding after the discrepancy.
    assert!(!style.devices[0].followed_up());
    assert!(!r.audit().passed());
    let wrong_style = book.w(finding(STYLE2, B1.id, 0x0F));
    let body = ityv_encoding::decode_object::<ityv_encoding::WitnessedEvent<'_>>(
        ityv_encoding::SCHEMA_WITNESSED_EVENT,
        ityv_encoding::SCHEMA_VERSION_WITNESSED,
        finding(STYLE1, B1.id, 0x0F),
    )
    .unwrap()
    .body_bytes();
    let taken = book.w(witnessed(body, &AUDITORS_AND_OBSERVERS));
    let repeated = book.w(witnessed_seeded(body, &AUDITORS_AND_OBSERVERS, Some(2)));
    let mut forged_who = AUDITORS_AND_OBSERVERS;
    forged_who[0].3 = AUD_2;
    let forged = book.w(witnessed(
        object(
            SCHEMA_AUDIT_FINDING_BODY,
            SCHEMA_VERSION_1,
            &AuditFindingBody::new(&AuditFindingParts {
                election_id: common::election(),
                ballot_style_id: BallotStyleId::new(STYLE1).unwrap(),
                device_id: BoxId::new(B1.id).unwrap(),
                finding_hash: Hash512([0x10; 64]),
                time_bucket: TimeBucket::new(SEED_BUCKET + 5),
            })
            .unwrap(),
        ),
        &forged_who,
    ));
    let r = report(&mut book, &observed());
    let refused = audit_refused(&r);
    assert_eq!(
        refused,
        [
            (not_yet, AuditEvent::Opening, AuditRefusal::NotCalled),
            (wrong_style, AuditEvent::Finding, AuditRefusal::Subject),
            (repeated, AuditEvent::Finding, AuditRefusal::Repeated),
            (forged, AuditEvent::Finding, AuditRefusal::Signature),
        ]
    );
    let style = r.audit().style(STYLE1).unwrap();
    let device = &style.devices[0];
    assert!(device.findings.iter().any(|f| f.get() == taken));
    assert!(device.followed_up());
    assert!(r.audit().concluded(style));
    assert_eq!(device.codes, [2, 1, 0, 0, 0, 0, 0]);

    // Cleanly: the full comparison and the finding reach `PAPER_AUDITED`.
    let (mut book, casts) = tallied(audit_world());
    let (_, sample) = seeded(&mut book, &casts, &[(2, 1), (3, 1)]);
    book.q(reference(&sample[0]));
    book.w(compare(&sample[0], ComparisonCode::CandidateInvalid));
    for c in casts.iter().filter(|c| c.code != sample[0].code) {
        book.q(reference(c));
        book.w(compare(c, ComparisonCode::Match));
    }
    let r = report(&mut book, &observed());
    assert_eq!(r.status().status(), Status::CryptoTallyVerified);
    book.w(finding(STYLE1, B1.id, 0x0F));
    let r = report(&mut book, &observed());
    assert_eq!(r.status().holds(), HoldSet::empty());
    assert_eq!(r.status().status(), Status::PaperAudited);
}

#[test]
fn a_full_comparison_counts_a_drawn_record_only_in_the_rounds_that_hold_it() {
    // Round 0 is the first two drawn records, round 1 all three.
    let (mut book, casts) = tallied(audit_world());
    let (_, sample) = seeded(&mut book, &casts, &[(2, 1), (3, 2)]);
    book.q(reference(&sample[0]));
    book.w(compare(&sample[0], ComparisonCode::OtherCandidate));
    // Under the full comparison the third drawn record disagrees too: it
    // counts in round 1, not in round 0, which stays within its threshold.
    book.q(reference(&sample[2]));
    book.w(compare(&sample[2], ComparisonCode::CandidateInvalid));
    let r = report(&mut book, &observed());
    let style = r.audit().style(STYLE1).unwrap();
    assert_eq!((style.counts[0].compared, style.counts[0].nonzero), (1, 1));
    assert_eq!((style.counts[1].compared, style.counts[1].nonzero), (2, 2));
    assert_eq!(style.phase, Some(AuditPhase::Sampling { round: 0 }));
    assert_eq!(style.hand_count_from, None);
}

#[test]
fn codes_5_and_6_hold_the_box() {
    for code in [
        ComparisonCode::BallotMissing,
        ComparisonCode::ImprintMismatch,
    ] {
        let (mut book, casts) = tallied(audit_world());
        let (_, sample) = seeded(&mut book, &casts, &[(2, 1)]);
        book.q(reference(&sample[0]));
        book.w(compare(&sample[0], code));
        book.q(reference(&sample[1]));
        book.w(compare(&sample[1], ComparisonCode::Match));
        let r = report(&mut book, &observed());
        let style = r.audit().style(STYLE1).unwrap();
        assert_eq!(style.phase, Some(AuditPhase::Concluded { round: 0 }));
        assert_eq!(style.devices[0].holds, only(HoldReason::AuditCustody));
        assert_eq!(style.holds, only(HoldReason::AuditCustody));
        assert!(!r.audit().concluded(style));
        assert_eq!(r.status().status(), Status::HoldReview);
        assert!(r.status().holds().contains(HoldReason::AuditCustody));
    }
}

// ---------------------------------------------------------------------
// Two ballot styles: a partial audit never passes.

/// BOX-2 for STYLE-2 (nine candidates, two chunks).
const B2S: Bx = Bx {
    id: b"BOX-2",
    device: BOX_DEVICE_BASE + 1,
    style: STYLE2,
    options: 11,
    mods: &[(b"M-B2-J", 4), (b"M-B2-P1", 2), (b"M-B2-P2", 3)],
    absentee: false,
};

/// ST-1 with BOX-1 (STYLE-1, RU-1) and BOX-2 (STYLE-2, RU-2).
fn two_style_world() -> &'static World {
    static WORLD: OnceLock<&'static World> = OnceLock::new();
    WORLD.get_or_init(|| leak(two_box_world(STYLE2)))
}

/// ST-1 with BOX-1 (STYLE-1, RU-1) and BOX-2 (`style2`, RU-2), with the
/// district chair and the auditors.
fn two_box_world(style2: &'static [u8]) -> World {
    {
        let mut d = Draft::standard();
        let mut box2 = common::genesis_box(
            1,
            b"BOX-2",
            b"ST-1",
            RU2,
            &[b"M-B2-P1", b"M-B2-P2", b"M-B2-J"],
        );
        box2.ballot_style_id = BallotStyleId::new(style2).unwrap();
        d.boxes = std::vec![
            common::genesis_box(0, b"BOX-1", b"ST-1", RU1, &[b"M-B1-P1", b"M-B1-P2"]),
            box2,
        ];
        d.stations.truncate(1);
        d.policies.truncate(1);
        d.units = std::vec![
            ReportingUnitEntry::new(
                ReportingUnitId::new(RU1).unwrap(),
                1,
                OrgId::new(b"NEC-D").unwrap()
            )
            .unwrap(),
            ReportingUnitEntry::new(
                ReportingUnitId::new(RU2).unwrap(),
                1,
                OrgId::new(b"NEC-D").unwrap()
            )
            .unwrap(),
        ];
        d.modules.retain(|m| {
            TWO_UNIT_MODULES
                .iter()
                .any(|e| e.0 == m.module_id.as_bytes())
        });
        for entry in &mut d.modules {
            let m = TWO_UNIT_MODULES
                .iter()
                .find(|e| e.0 == entry.module_id.as_bytes())
                .unwrap();
            entry.provisioned_hash = object_hash(provisioning(*m));
        }
        d.roster.push(common::roster_signer(
            30,
            b"chair",
            RosterRole::Chair,
            b"NEC-D",
            None,
        ));
        with_auditors(&mut d);
        build(&d, &AUDIT_SCOPES)
    }
}

/// The two-style ledger through the tally of both units.
fn two_style_tallied(world: &'static World) -> (Book, Vec<Cast>, Vec<Cast>) {
    let mut book = Book::new(world);
    for chamber in [
        ityv_encoding::ChamberCode::P1,
        ityv_encoding::ChamberCode::P2,
    ] {
        book.push(SCHEMA_PARTY_KEY_CEREMONY, ceremony(chamber));
    }
    for m in TWO_UNIT_MODULES {
        book.push(SCHEMA_MODULE_PROVISIONED, provisioning(m));
    }
    let c1 = box1_closed(&mut book);
    let c2 = std::vec![cast(B2S, 1, 1), cast(B2S, 2, 9)];
    book.w(opened(B2S));
    for c in &c2 {
        book.push(SCHEMA_CAST_RECORD, c.event);
    }
    book.push(SCHEMA_BATCH_ATTEST, batch(B2S, 0, 1, 2, &codes(&c2)));
    book.push(SCHEMA_BOX_CLOSE, close(B2S, 2, 2, 0, &codes(&c2)));
    for (schema, event) in station_record_of(&[(B1, 3), (B2S, 2)]) {
        book.push(schema, event);
    }
    book.push(SCHEMA_PARTICIPATION_SET, participation(5));
    book.checkpoint();
    tally1(
        &mut book,
        &c1,
        &spec(STYLE1, RU1, &codes(&c1)),
        &[1, 1, 1, 0, 0],
        0,
    );
    let body = scope_body(&spec(STYLE2, RU2, &codes(&c2)));
    book.q(scope(body));
    book.checkpoint();
    for chunk in 0..2 {
        book.q(opening(opening_body(
            STYLE2,
            RU2,
            body,
            chunk,
            sums(&c2, chunk),
        )));
    }
    // Options 1 and 9: candidates 1 and 9.
    book.w(paper(STYLE2, RU2, &[1, 0, 0, 0, 0, 0, 0, 0, 1], 0));
    book.checkpoint();
    (book, c1, c2)
}

/// Freezes both styles with `list`, checkpoints and seeds: the seed and
/// each style's draws.
fn two_style_seeded(
    book: &mut Book,
    c1: &[Cast],
    c2: &[Cast],
    list: &[(u64, u32)],
) -> (Hash512, Vec<Cast>, Vec<Cast>) {
    let f1 = freeze_body(STYLE1, &codes(c1), list);
    let f2 = freeze_body(STYLE2, &codes(c2), list);
    book.w(freeze(f1));
    book.w(freeze(f2));
    book.w(commit(commit_body(&[f1, f2], |_| {})));
    book.checkpoint_at(COMMIT_BUCKET);
    let checkpoint = book.last.unwrap().1;
    book.w(seed(seed_body(checkpoint, |_| {})));
    let s = audit_seed(&DICE, &beacon(), &checkpoint);
    (s, drawn(&s, STYLE1, c1, list), drawn(&s, STYLE2, c2, list))
}

#[test]
fn every_style_must_conclude_for_paper_audited() {
    let world = two_style_world();
    let (mut book, c1, _) = two_style_tallied(world);
    let r = report(&mut book, &observed());
    assert_eq!(r.status().holds(), HoldSet::empty(), "{:?}", r.tally());
    assert_eq!(r.status().status(), Status::CryptoTallyVerified);
    assert_eq!(r.audit().styles().len(), 2);
    // A commit before STYLE-2's freeze is too early, and so the seed.
    let f1 = freeze_body(STYLE1, &codes(&c1), &[(1, 0)]);
    book.w(freeze(f1));
    let early_commit = book.w(commit(commit_body(&[f1], |_| {})));
    book.checkpoint_at(COMMIT_BUCKET);
    let early = book.w(seed(seed_body(book.last.unwrap().1, |_| {})));
    let r = report(&mut book, &observed());
    assert_eq!(
        audit_refused(&r),
        [
            (early_commit, AuditEvent::Commit, AuditRefusal::Premature),
            (early, AuditEvent::Seed, AuditRefusal::Premature),
        ]
    );

    let (mut book, c1, c2) = two_style_tallied(world);
    let (_, s1, s2) = two_style_seeded(&mut book, &c1, &c2, &[(1, 0)]);
    // STYLE-1 audited, STYLE-2 not: nothing held, and no `PAPER_AUDITED`.
    book.q(reference(&s1[0]));
    book.w(compare(&s1[0], ComparisonCode::Match));
    let r = report(&mut book, &observed());
    let audit = r.audit();
    assert!(audit.concluded(audit.style(STYLE1).unwrap()));
    assert!(!audit.concluded(audit.style(STYLE2).unwrap()));
    assert!(!audit.passed());
    assert_eq!(r.status().holds(), HoldSet::empty());
    assert_eq!(r.status().status(), Status::CryptoTallyVerified);
    // Each style's frame is its own: STYLE-2's two records.
    assert_eq!(audit.style(STYLE2).unwrap().frame_count, 2);
    // STYLE-2 audited too: `PAPER_AUDITED`.
    book.q(reference(&s2[0]));
    book.w(compare_in(B2S, &s2[0], ComparisonCode::Match, false));
    let r = report(&mut book, &observed());
    assert_eq!(r.status().holds(), HoldSet::empty());
    assert!(r.audit().passed());
    assert_eq!(r.status().status(), Status::PaperAudited);
    // And with access, STYLE-2's two-chunk opening reconstructs.
    let bodies: &'static [&'static [u8]] = leak_slice(std::vec![
        restricted(&s1[0], s1[0].option),
        restricted(&s2[0], s2[0].option),
    ]);
    let r = verify_ledger_with(
        world.genesis,
        book.ledger.bytes(),
        &book.ledger.events,
        anchored(),
        &AuditInput {
            openings: bodies,
            ..observed()
        },
    );
    assert_eq!(r.status().status(), Status::PaperAudited);
    for style in r.audit().styles() {
        assert_eq!(
            style.records[0].reconstruction,
            Reconstruction::Reconstructed
        );
    }
}

// ---------------------------------------------------------------------
// The index.

#[test]
fn the_index_scopes_the_audit_events_and_keeps_restricted_bodies_off_the_ledger() {
    let (mut book, casts) = tallied(audit_world());
    let (_, sample) = seeded(&mut book, &casts, &[(1, 0)]);
    book.q(reference(&sample[0]));
    let at = book.w(compare(&sample[0], ComparisonCode::Match));
    let finding_at = book.w(finding(STYLE1, B1.id, 0x0F));
    let index =
        ityv_verify::build_index(book.world.genesis, book.ledger.bytes(), &book.ledger.events);
    assert!(index.findings().is_empty());
    let box_frames: Vec<u64> = index.box_events(B1.id).map(|e| e.seq.get()).collect();
    assert!(box_frames.contains(&at));
    assert!(box_frames.contains(&finding_at));
    // A frame of the restricted schema is no opaque frame: without its
    // event it is missing and holds the ledger (its body would be refused
    // as unknown; it never goes on the ledger).
    let mut ledger = clone_ledger(&book);
    let unsupplied = leak_slice(std::vec![0x44u8; 8]);
    ledger.push(SCHEMA_SAMPLE_OPENING_BODY, unsupplied);
    let mut events = ledger.events.clone();
    events.pop();
    let index = ityv_verify::build_index(book.world.genesis, ledger.bytes(), &events);
    assert_eq!(
        index.findings().last().unwrap().kind,
        ityv_verify::FindingKind::EventMissing
    );
    assert!(!index.ledger_holds().is_empty());
}

// ---------------------------------------------------------------------
// The commit: no input of the seed is left to choose once the beacon is
// public (ADR-0036).

/// After the beacon value is public the operator cuts checkpoints until
/// the seed over the latest one draws a sample that avoids a record of its
/// choosing, or tries other dice records. The seed must name the binding
/// checkpoint (the first that covers the commit) and the commit's dice, so
/// neither is taken; the honest seed is, whatever checkpoints are cut while
/// it is signed.
#[test]
fn the_operator_cannot_grind_the_seed() {
    let list = [(1u64, 0u32)];
    let (mut book, casts) = tallied(audit_world());
    let body = freeze_body(STYLE1, &codes(&casts), &list);
    book.w(freeze(body));
    book.w(commit(commit_body(&[body], |_| {})));
    book.checkpoint_at(COMMIT_BUCKET);
    let binding = book.last.unwrap().1;
    let honest = drawn(
        &audit_seed(&DICE, &beacon(), &binding),
        STYLE1,
        &casts,
        &list,
    );
    let target = honest[0].code;
    let mut tries = 0;
    let (ground, sample) = loop {
        book.checkpoint();
        tries += 1;
        let cp = book.last.unwrap().1;
        let sample = drawn(&audit_seed(&DICE, &beacon(), &cp), STYLE1, &casts, &list);
        if sample[0].code != target {
            break (cp, sample);
        }
        assert!(tries < 50);
    };
    let by_checkpoint = book.w(seed(seed_body(ground, |_| {})));
    let other_dice = Hash512([0xD7; 64]);
    let by_dice = book.w(seed(seed_body(binding, |p| {
        p.dice_hash = other_dice;
        p.seed = audit_seed(&p.dice_hash, &p.beacon_value, &p.checkpoint_hash);
    })));
    // What the operator wanted compared instead: refused, never called.
    book.q(reference(&sample[0]));
    let r = report(&mut book, &observed());
    assert!(r.audit().seed().is_none());
    assert_eq!(
        audit_refused(&r)[..2],
        [
            (by_checkpoint, AuditEvent::Seed, AuditRefusal::Checkpoint),
            (by_dice, AuditEvent::Seed, AuditRefusal::Commit),
        ]
    );
    assert_ne!(r.status().status(), Status::PaperAudited);
    assert!(r.status().holds().contains(HoldReason::AuditSeedRefused));

    // The honest seed: checkpoints cut after the binding one, while the
    // seed is signed, do not break it.
    let (mut book, casts) = tallied(audit_world());
    let body = freeze_body(STYLE1, &codes(&casts), &list);
    book.w(freeze(body));
    book.w(commit(commit_body(&[body], |_| {})));
    book.checkpoint_at(COMMIT_BUCKET);
    let binding = book.last.unwrap().1;
    book.checkpoint();
    book.checkpoint();
    book.w(seed(seed_body(binding, |_| {})));
    let sample = drawn(
        &audit_seed(&DICE, &beacon(), &binding),
        STYLE1,
        &casts,
        &list,
    );
    book.q(reference(&sample[0]));
    book.w(compare(&sample[0], ComparisonCode::Match));
    let r = report(&mut book, &observed());
    assert_eq!(r.status().holds(), HoldSet::empty(), "{:?}", r.audit());
    assert_eq!(r.status().status(), Status::PaperAudited);
}

#[test]
fn the_commit_fixes_the_dice_and_the_freezes_before_the_beacon() {
    let (mut book, casts) = tallied(audit_world());
    let body = freeze_body(STYLE1, &codes(&casts), &[(1, 0)]);
    // Before the freeze: too early (other signature bytes than the one
    // taken later).
    let early = book.w(witnessed_seeded(
        commit_body(&[body], |_| {}),
        &COMMITTEE_AND_OBSERVERS,
        Some(20),
    ));
    book.w(freeze(body));
    let other_round = book.w(commit(commit_body(&[body], |p| {
        p.beacon_round = BEACON_ROUND + 1;
    })));
    let other_source = book.w(commit(commit_body(&[body], |p| {
        p.beacon_source = Hash512([0xBF; 64]);
    })));
    let other_freezes = book.w(commit(commit_body(&[body], |p| {
        p.freezes_root = Hash512([0x44; 64]);
    })));
    // Dated when the beacon round was published: the value could be known.
    let after_beacon = book.w(commit(commit_body(&[body], |p| {
        p.time_bucket = TimeBucket::new(PUBLISHED);
    })));
    let mut forged_who = COMMITTEE_AND_OBSERVERS;
    forged_who[0].3 = COMMISSION;
    let forged = book.w(witnessed(commit_body(&[body], |_| {}), &forged_who));
    let good = commit_body(&[body], |_| {});
    let taken = book.w(commit(good));
    let repeated = book.w(witnessed_seeded(good, &COMMITTEE_AND_OBSERVERS, Some(21)));
    let conflict = book.w(commit(commit_body(&[body], |p| {
        p.dice_hash = Hash512([0xD3; 64]);
    })));
    book.checkpoint_at(COMMIT_BUCKET);
    let binding = book.last.unwrap().1;
    book.w(seed(seed_body(binding, |_| {})));
    let r = report(&mut book, &observed());
    assert_eq!(
        audit_refused(&r),
        [
            (early, AuditEvent::Commit, AuditRefusal::Premature),
            (other_round, AuditEvent::Commit, AuditRefusal::Beacon),
            (other_source, AuditEvent::Commit, AuditRefusal::Beacon),
            (other_freezes, AuditEvent::Commit, AuditRefusal::Freezes),
            (after_beacon, AuditEvent::Commit, AuditRefusal::Late),
            (forged, AuditEvent::Commit, AuditRefusal::Signature),
            (repeated, AuditEvent::Commit, AuditRefusal::Repeated),
            (conflict, AuditEvent::Commit, AuditRefusal::Conflict),
        ]
    );
    assert_eq!(r.audit().commit().unwrap().seq.get(), taken);
    assert!(r.audit().seed().is_some());
    assert_eq!(r.status().status(), Status::HoldReview);
    assert!(r.status().holds().contains(HoldReason::AuditCommitRefused));

    // Without a commit no seed is taken.
    let (mut book, casts) = tallied(audit_world());
    book.w(freeze(freeze_body(STYLE1, &codes(&casts), &[(1, 0)])));
    book.checkpoint();
    let at = book.w(seed(seed_body(book.last.unwrap().1, |_| {})));
    let r = report(&mut book, &observed());
    assert_eq!(
        audit_refused(&r),
        [(at, AuditEvent::Seed, AuditRefusal::Premature)]
    );
    assert!(r.audit().commit().is_none());
    assert_eq!(r.status().status(), Status::HoldReview);

    // A binding checkpoint witnessed within the witnesses' tolerance and
    // clock error of the publication (`published − 2` and later) refuses the
    // seed: an honest witness whose clock lags by under a minute still reads
    // `published − 1` just after the publication and attests one below.
    // Three buckets before is in time.
    for (bucket, late) in [
        (PUBLISHED, true),
        (PUBLISHED - 1, true),
        (PUBLISHED - 2, true),
        (PUBLISHED - 3, false),
    ] {
        let (mut book, casts) = tallied(audit_world());
        let body = freeze_body(STYLE1, &codes(&casts), &[(1, 0)]);
        book.w(freeze(body));
        book.w(commit(commit_body(&[body], |_| {})));
        book.checkpoint_at(bucket);
        let binding = book.last.unwrap().1;
        let at = book.w(seed(seed_body(binding, |_| {})));
        let r = report(&mut book, &observed());
        if late {
            assert_eq!(
                audit_refused(&r),
                [(at, AuditEvent::Seed, AuditRefusal::Late)],
                "{bucket}"
            );
        } else {
            assert!(audit_refused(&r).is_empty(), "{bucket}");
            assert!(r.audit().seed().unwrap().beacon_confirmed);
        }
    }
}

/// P1 of the second review: once the beacon is public the operator would
/// have one more checkpoint signed at whatever time bucket gives the sample
/// it wants. An honest witness signs only its own clock's bucket or the one
/// before (VC-012), and its clock is off by at most a minute, so after the
/// publication it reads at least `published − CLOCK_ERROR_BUCKETS` and
/// attests at least `published − 2`; the verifier takes a binding
/// checkpoint only below that, and only at or after the commit. No bucket
/// is both, for exact, lagging and leading clocks.
#[test]
fn a_binding_checkpoint_cannot_be_backdated_after_the_beacon() {
    let tolerance = ityv_ledger::WITNESS_TIME_TOLERANCE;
    let error = ityv_ledger::CLOCK_ERROR_BUCKETS;
    let (mut book, casts) = tallied(audit_world());
    let body = freeze_body(STYLE1, &codes(&casts), &[(1, 0)]);
    book.w(freeze(body));
    book.w(commit(commit_body(&[body], |_| {})));
    for bucket in (READY + 1)..PUBLISHED + 2 {
        let accepted = bucket >= COMMIT_BUCKET && bucket + tolerance + error < PUBLISHED;
        // An honest witness after the publication: its clock reads the
        // publication's bucket or later, or one bucket earlier if it lags.
        for now in PUBLISHED - error..PUBLISHED + 3 {
            let signs = ityv_ledger::witness_time_ok(now, bucket, None);
            assert!(!(accepted && signs), "bucket {bucket} at {now}");
        }
    }
    // The verifier's side, on the ledger: a binding checkpoint timed
    // before the commit it covers is refused, whatever its sample.
    let (mut book, casts) = tallied(audit_world());
    let body = freeze_body(STYLE1, &codes(&casts), &[(1, 0)]);
    book.w(freeze(body));
    book.w(commit(commit_body(&[body], |_| {})));
    book.checkpoint_at(COMMIT_BUCKET - 1);
    let binding = book.last.unwrap().1;
    let at = book.w(seed(seed_body(binding, |_| {})));
    let sample = drawn(
        &audit_seed(&DICE, &beacon(), &binding),
        STYLE1,
        &casts,
        &[(1, 0)],
    );
    book.q(reference(&sample[0]));
    book.w(compare(&sample[0], ComparisonCode::Match));
    let r = report(&mut book, &observed());
    assert_eq!(
        audit_refused(&r)[0],
        (at, AuditEvent::Seed, AuditRefusal::Backdated)
    );
    assert_ne!(r.status().status(), Status::PaperAudited);
    // Without an observation the rule still holds (it needs no beacon).
    let r = report(&mut book, &AuditInput::default());
    assert_eq!(
        audit_refused(&r)[0],
        (at, AuditEvent::Seed, AuditRefusal::Backdated)
    );
    // The commit's own bucket is fine.
    let (mut book, casts) = tallied(audit_world());
    let body = freeze_body(STYLE1, &codes(&casts), &[(1, 0)]);
    book.w(freeze(body));
    book.w(commit(commit_body(&[body], |_| {})));
    book.checkpoint_at(COMMIT_BUCKET);
    book.w(seed(seed_body(book.last.unwrap().1, |_| {})));
    let r = report(&mut book, &observed());
    assert!(audit_refused(&r).is_empty());
}

/// P1b of the second review: a checkpoint chain whose time goes back is
/// invalid (VC-012): the chain ends there and the ledger is held.
#[test]
fn a_checkpoint_chain_whose_time_goes_back_is_invalid() {
    let (mut book, casts) = tallied(audit_world());
    let body = freeze_body(STYLE1, &codes(&casts), &[(1, 0)]);
    book.w(freeze(body));
    book.w(commit(commit_body(&[body], |_| {})));
    book.checkpoint_at(PUBLISHED - 2);
    let binding = book.last.unwrap().1;
    book.checkpoint_at(READY + 2);
    book.w(seed(seed_body(binding, |_| {})));
    let r = verify_ledger_with(
        book.world.genesis,
        book.ledger.bytes(),
        &book.ledger.events,
        anchored(),
        &observed(),
    );
    let findings = r.checkpoints().findings();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(
        findings[0].kind,
        ityv_verify::CheckpointFindingKind::Successor(ityv_ledger::Error::TimeWentBack)
    );
    assert_eq!(r.status().status(), Status::HoldReview);
}

#[test]
fn a_rule_must_bind_within_the_frame() {
    // One round of 10 tolerating 5 is a valid encoding, but the frame has
    // three records: every sample of the frame passes.
    let (mut book, casts) = tallied(audit_world());
    let at = book.w(freeze(freeze_body(STYLE1, &codes(&casts), &[(10, 5)])));
    let r = report(&mut book, &observed());
    assert_eq!(
        audit_refused(&r),
        [(at, AuditEvent::Freeze, AuditRefusal::Rule)]
    );
    assert!(r.audit().style(STYLE1).unwrap().freeze.is_none());
    assert!(r.status().holds().contains(HoldReason::AuditFreezeRefused));
    // A later round may be clipped by the frame as long as it still rules:
    // two discrepancies of three.
    let (mut book, casts) = tallied(audit_world());
    let body = freeze_body(STYLE1, &codes(&casts), &[(1, 0), (10, 2)]);
    book.w(freeze(body));
    let r = report(&mut book, &observed());
    assert!(audit_refused(&r).is_empty());
    // Three of three does not.
    let (mut book, casts) = tallied(audit_world());
    let at = book.w(freeze(freeze_body(
        STYLE1,
        &codes(&casts),
        &[(1, 0), (10, 3)],
    )));
    let r = report(&mut book, &observed());
    assert_eq!(
        audit_refused(&r),
        [(at, AuditEvent::Freeze, AuditRefusal::Rule)]
    );
}

#[test]
fn an_empty_beacon_output_observes_nothing() {
    let (mut book, casts) = tallied(audit_world());
    let (_, sample) = seeded(&mut book, &casts, &[(1, 0)]);
    book.q(reference(&sample[0]));
    book.w(compare(&sample[0], ComparisonCode::Match));
    let r = report(&mut book, &observed_at(b"", PUBLISHED));
    assert!(r.audit().seed().is_none());
    assert_eq!(audit_refused(&r)[0].2, AuditRefusal::Beacon);
    assert_eq!(r.status().status(), Status::HoldReview);
}

#[test]
fn debug_output_never_shows_a_restricted_opening() {
    let (mut book, casts) = tallied(audit_world());
    let (_, sample) = seeded(&mut book, &casts, &[(1, 0)]);
    let body = restricted(&sample[0], sample[0].option);
    let input = AuditInput {
        openings: leak_slice(std::vec![body]),
        ..observed()
    };
    let text = std::format!("{input:?}");
    // The body's bytes (its cast id among them) never appear, only their
    // number.
    let tail = std::format!("{:?}", &body[body.len() - 64..]);
    assert!(!text.contains(&tail[1..tail.len() - 1]), "{text}");
    assert!(text.contains("openings: 1"), "{text}");
    // Two inputs that differ only in the opened option print alike.
    let other = AuditInput {
        openings: leak_slice(std::vec![restricted(&sample[0], sample[0].option + 1)]),
        ..observed()
    };
    assert_eq!(text, std::format!("{other:?}"));
}

#[test]
fn the_stage_shows_the_declared_rule_and_how_the_openings_were_supplied() {
    let (mut book, casts) = tallied(audit_world());
    let (_, sample) = seeded(&mut book, &casts, &[(2, 0)]);
    for c in &sample[..2] {
        book.q(reference(c));
        book.w(compare(c, ComparisonCode::Match));
    }
    let r = report(&mut book, &observed());
    let style = r.audit().style(STYLE1).unwrap();
    assert_eq!(
        style.rule,
        Some(DeclaredRule {
            rule_hash: Hash512([0x77; 64]),
            risk_limit_ppm: 10_000,
            beacon_source: BEACON_SOURCE,
            beacon_round: BEACON_ROUND,
        })
    );
    // Before anything is opened nothing is established.
    let (mut nothing, c) = tallied(audit_world());
    seeded(&mut nothing, &c, &[(2, 0)]);
    let empty = report(&mut nothing, &observed());
    assert!(!empty.audit().all_reconstructed());
    // The public verifier: nothing supplied.
    let n = style.reconstructions();
    assert_eq!((n.opened, n.not_supplied, n.reconstructed), (2, 2, 0));
    assert!(!n.complete());
    assert!(!r.audit().all_reconstructed());
    assert_eq!(r.status().status(), Status::PaperAudited);
    // A partial supply is told from a full one.
    let one = AuditInput {
        openings: leak_slice(std::vec![restricted(&sample[0], sample[0].option)]),
        ..observed()
    };
    let r = report(&mut book, &one);
    let n = r.audit().style(STYLE1).unwrap().reconstructions();
    assert_eq!((n.reconstructed, n.not_supplied, n.mismatched), (1, 1, 0));
    assert!(!r.audit().all_reconstructed());
    let both = AuditInput {
        openings: leak_slice(
            sample[..2]
                .iter()
                .map(|c| restricted(c, c.option))
                .collect(),
        ),
        ..observed()
    };
    let r = report(&mut book, &both);
    assert!(
        r.audit()
            .style(STYLE1)
            .unwrap()
            .reconstructions()
            .complete()
    );
    assert!(r.audit().all_reconstructed());
    // A body the reference names that does not open the record is a
    // mismatch.
    let (mut book, casts) = tallied(audit_world());
    let (_, sample) = seeded(&mut book, &casts, &[(2, 0)]);
    let wrong = restricted(&sample[0], sample[0].option + 1);
    book.q(reference_of(STYLE1, sample[0].code, object_hash(wrong)));
    let input = AuditInput {
        openings: leak_slice(std::vec![wrong]),
        ..observed()
    };
    let r = report(&mut book, &input);
    let n = r.audit().style(STYLE1).unwrap().reconstructions();
    assert_eq!((n.opened, n.mismatched, n.reconstructed), (1, 1, 0));
    assert!(!r.audit().all_reconstructed());
}

#[test]
fn a_restricted_body_on_the_ledger_is_an_invalid_event() {
    let (mut book, casts) = tallied(audit_world());
    let (_, sample) = seeded(&mut book, &casts, &[(1, 0)]);
    // A canonical restricted body with its bytes, put on the ledger.
    let mut ledger = clone_ledger(&book);
    ledger.push(
        SCHEMA_SAMPLE_OPENING_BODY,
        restricted(&sample[0], sample[0].option),
    );
    let index = ityv_verify::build_index(book.world.genesis, ledger.bytes(), &ledger.events);
    assert_eq!(
        index.findings().last().unwrap().kind,
        ityv_verify::FindingKind::EventInvalid
    );
    assert!(!index.ledger_holds().is_empty());
}

// ---------------------------------------------------------------------
// One ballot style over two reporting units.

/// ST-1 with BOX-1 (RU-1) and BOX-2 (RU-2), both STYLE-1.
fn two_unit_audit_world() -> &'static World {
    static WORLD: OnceLock<&'static World> = OnceLock::new();
    WORLD.get_or_init(|| leak(two_box_world(STYLE1)))
}

/// The two-unit ledger through the tally of both units: BOX-1's three
/// records and BOX-2's two (options 1 and 4).
fn two_unit_tallied(world: &'static World) -> (Book, Vec<Cast>) {
    let mut book = Book::new(world);
    for chamber in [
        ityv_encoding::ChamberCode::P1,
        ityv_encoding::ChamberCode::P2,
    ] {
        book.push(SCHEMA_PARTY_KEY_CEREMONY, ceremony(chamber));
    }
    for m in TWO_UNIT_MODULES {
        book.push(SCHEMA_MODULE_PROVISIONED, provisioning(m));
    }
    let c1 = box1_closed(&mut book);
    let c2 = std::vec![cast(B2, 1, 1), cast(B2, 2, 4)];
    book.w(opened(B2));
    for c in &c2 {
        book.push(SCHEMA_CAST_RECORD, c.event);
    }
    book.push(SCHEMA_BATCH_ATTEST, batch(B2, 0, 1, 2, &codes(&c2)));
    book.push(SCHEMA_BOX_CLOSE, close(B2, 2, 2, 0, &codes(&c2)));
    for (schema, event) in station_record_of(&[(B1, 3), (B2, 2)]) {
        book.push(schema, event);
    }
    book.push(SCHEMA_PARTICIPATION_SET, participation(5));
    book.checkpoint();
    tally1(
        &mut book,
        &c1,
        &spec(STYLE1, RU1, &codes(&c1)),
        &[1, 1, 1, 0, 0],
        0,
    );
    let body = scope_body(&spec(STYLE1, RU2, &codes(&c2)));
    book.q(scope(body));
    book.checkpoint();
    book.q(opening(opening_body(STYLE1, RU2, body, 0, sums(&c2, 0))));
    book.w(paper(STYLE1, RU2, &[1, 0, 0, 1, 0], 0));
    book.checkpoint();
    let mut all = c1;
    all.extend(c2);
    (book, all)
}

/// The box of `c` among the two-unit boxes.
fn box_of(c: &Cast, box2: &[Cast]) -> Bx {
    if box2.iter().any(|b| b.code == c.code) {
        B2
    } else {
        B1
    }
}

#[test]
fn a_style_of_two_units_is_one_frame_counted_by_hand_in_every_unit() {
    let world = two_unit_audit_world();
    let (mut book, all) = two_unit_tallied(world);
    let box2 = &all[3..];
    let (_, sample) = seeded(&mut book, &all, &[(1, 0)]);
    // An unreadable record that is a valid vote: a discrepancy past the
    // last round, so the whole style is counted by hand.
    book.q(reference(&sample[0]));
    book.w(compare_in(
        box_of(&sample[0], box2),
        &sample[0],
        ComparisonCode::UnreadableValid,
        false,
    ));
    let r = report(&mut book, &observed());
    let style = r.audit().style(STYLE1).unwrap();
    assert_eq!(style.units.len(), 2);
    assert_eq!(style.frame_count, 5);
    assert_eq!(style.frame_root, Some(root(&codes(&all))));
    assert_eq!(style.devices.len(), 2);
    assert_eq!(
        style.devices.iter().map(|d| d.records).collect::<Vec<_>>(),
        [3, 2]
    );
    assert_eq!(style.phase, Some(AuditPhase::HandCount));
    // One unit's hand count is not the style's.
    book.w(hand_count(STYLE1, RU1, &[1, 1, 1, 0, 0]));
    let r = report(&mut book, &observed());
    assert!(!r.audit().passed());
    assert_eq!(r.status().status(), Status::CryptoTallyVerified);
    book.w(hand_count(STYLE1, RU2, &[1, 0, 0, 1, 0]));
    let r = report(&mut book, &observed());
    assert_eq!(r.audit().style(STYLE1).unwrap().hand_counts.len(), 2);
    assert_eq!(r.status().holds(), HoldSet::empty(), "{:?}", r.audit());
    assert_eq!(r.status().status(), Status::PaperAudited);
}

#[test]
fn every_device_with_a_code_1_or_2_is_compared_in_full() {
    let world = two_unit_audit_world();
    let (mut book, all) = two_unit_tallied(world);
    let box2 = &all[3..];
    let (_, sample) = seeded(&mut book, &all, &[(5, 4)]);
    // The first drawn record of each box disagrees; the rest agree.
    let mut seen: Vec<&[u8]> = Vec::new();
    for c in &sample {
        let bx = box_of(c, box2);
        let code = if seen.contains(&bx.id) {
            ComparisonCode::Match
        } else {
            seen.push(bx.id);
            if bx.id == B1.id {
                ComparisonCode::OtherCandidate
            } else {
                ComparisonCode::CandidateInvalid
            }
        };
        book.q(reference(c));
        book.w(compare_in(bx, c, code, false));
    }
    let r = report(&mut book, &observed());
    let style = r.audit().style(STYLE1).unwrap();
    assert_eq!(style.phase, Some(AuditPhase::Concluded { round: 0 }));
    assert!(
        style
            .devices
            .iter()
            .all(|d| d.full_comparison_from.is_some() && d.compared == d.records)
    );
    // Compared in full, but a finding is still missing for each.
    assert!(!r.audit().passed());
    book.w(finding(STYLE1, B1.id, 0x0F));
    let r = report(&mut book, &observed());
    assert!(!r.audit().passed());
    book.w(finding(STYLE1, B2.id, 0x0F));
    let r = report(&mut book, &observed());
    let style = r.audit().style(STYLE1).unwrap();
    assert!(
        style
            .devices
            .iter()
            .all(ityv_verify::DeviceAudit::followed_up)
    );
    assert_eq!(r.status().holds(), HoldSet::empty(), "{:?}", r.audit());
    assert_eq!(r.status().status(), Status::PaperAudited);
}

// ---------------------------------------------------------------------
// A large frame.

/// BOX-1 with `n` records (options 1 to 3 in turn), through the tally.
fn large_tallied(world: &'static World, n: u64) -> (Book, Vec<Cast>) {
    let mut book = Book::new(world);
    for chamber in [
        ityv_encoding::ChamberCode::P1,
        ityv_encoding::ChamberCode::P2,
    ] {
        book.push(SCHEMA_PARTY_KEY_CEREMONY, ceremony(chamber));
    }
    for m in ELECTION_MODULES {
        book.push(SCHEMA_MODULE_PROVISIONED, provisioning(m));
    }
    let casts: Vec<Cast> = (1..=n).map(|i| cast(B1, i, (i % 3 + 1) as u16)).collect();
    book.w(opened(B1));
    for c in &casts {
        book.push(SCHEMA_CAST_RECORD, c.event);
    }
    for (index, chunk) in casts.chunks(64).enumerate() {
        let first = index as u64 * 64 + 1;
        let last = first + chunk.len() as u64 - 1;
        book.push(
            SCHEMA_BATCH_ATTEST,
            batch(B1, index as u32, first, last, &codes(chunk)),
        );
    }
    book.push(SCHEMA_BOX_CLOSE, close(B1, n, n, 0, &codes(&casts)));
    for (schema, event) in station_record(n) {
        book.push(schema, event);
    }
    book.push(SCHEMA_PARTICIPATION_SET, participation(n as u8));
    book.checkpoint();
    let mut votes = [0u64; 5];
    for c in &casts {
        votes[usize::from(c.option) - 1] += 1;
    }
    tally1(
        &mut book,
        &casts,
        &spec(STYLE1, RU1, &codes(&casts)),
        &votes,
        0,
    );
    book.checkpoint();
    (book, casts)
}

/// A frame of 200 records: the stage indexes records and devices and
/// decodes only what it opens, so its cost follows the events, not the
/// frame times the events.
#[test]
fn a_large_frame_is_audited() {
    let n = 200;
    let (mut book, casts) = large_tallied(audit_world(), n);
    let (_, sample) = seeded(&mut book, &casts, &[(20, 0)]);
    for c in &sample {
        book.q(reference(c));
        book.w(compare(c, ComparisonCode::Match));
    }
    let start = std::time::Instant::now();
    let r = report(&mut book, &observed());
    std::println!("{n} records, 20 compared: {:?}", start.elapsed());
    let style = r.audit().style(STYLE1).unwrap();
    assert_eq!(style.frame_count, n);
    assert_eq!(style.sample.len(), 20);
    assert_eq!(style.records.len(), 20);
    assert_eq!(r.status().holds(), HoldSet::empty(), "{:?}", r.audit());
    assert_eq!(r.status().status(), Status::PaperAudited);
}

/// A style whose frame is empty (a box that received no ballot) has
/// nothing to sample: its rule is not refused for being clipped to zero,
/// and its audit concludes with nothing drawn.
#[test]
fn an_empty_frame_is_not_a_vacuous_rule() {
    let world = two_style_world();
    let mut book = Book::new(world);
    for chamber in [
        ityv_encoding::ChamberCode::P1,
        ityv_encoding::ChamberCode::P2,
    ] {
        book.push(SCHEMA_PARTY_KEY_CEREMONY, ceremony(chamber));
    }
    for m in TWO_UNIT_MODULES {
        book.push(SCHEMA_MODULE_PROVISIONED, provisioning(m));
    }
    let c1 = box1_closed(&mut book);
    book.w(opened(B2S));
    book.push(SCHEMA_BOX_CLOSE, close(B2S, 0, 0, 0, &[]));
    for (schema, event) in station_record_of(&[(B1, 3), (B2S, 0)]) {
        book.push(schema, event);
    }
    book.push(SCHEMA_PARTICIPATION_SET, participation(3));
    book.checkpoint();
    tally1(
        &mut book,
        &c1,
        &spec(STYLE1, RU1, &codes(&c1)),
        &[1, 1, 1, 0, 0],
        0,
    );
    let body = scope_body(&spec(STYLE2, RU2, &[]));
    book.q(scope(body));
    book.checkpoint();
    for chunk in 0..2 {
        book.q(opening(opening_body(
            STYLE2,
            RU2,
            body,
            chunk,
            sums(&[], chunk),
        )));
    }
    book.w(paper(STYLE2, RU2, &[0; 9], 0));
    book.checkpoint();
    let (_, s1, s2) = two_style_seeded(&mut book, &c1, &[], &[(1, 0)]);
    assert!(s2.is_empty());
    book.q(reference(&s1[0]));
    book.w(compare(&s1[0], ComparisonCode::Match));
    let r = report(&mut book, &observed());
    assert!(audit_refused(&r).is_empty(), "{:?}", audit_refused(&r));
    let style2 = r.audit().style(STYLE2).unwrap();
    assert_eq!(style2.frame_count, 0);
    assert!(r.audit().concluded(style2));
    assert_eq!(
        r.status().status(),
        Status::PaperAudited,
        "{:?}",
        r.status()
    );
}

/// P6 and P6b of the third review: honest witnesses whose clocks lag by
/// under a minute still read `PUBLISHED − 1` just after the publication,
/// so they sign `PUBLISHED − 2`, the operator having chosen the body (filler
/// checkpoints, or a commit declared at that bucket) once the beacon value
/// is known. The verifier refuses such a binding checkpoint, so neither
/// reaches `PAPER_AUDITED`.
#[test]
fn lagging_honest_witnesses_after_the_beacon_cannot_fix_the_seed() {
    let lag_now = PUBLISHED - ityv_ledger::CLOCK_ERROR_BUCKETS;
    let bucket = PUBLISHED - 2;
    assert!(ityv_ledger::witness_time_ok(lag_now, bucket, None));
    let list = [(1u64, 0u32)];
    // P6: an honest commit before the beacon; after it, the binding
    // checkpoint at `PUBLISHED − 2` (any body the operator likes: filler
    // checkpoints before it change its hash, not its bucket).
    let (mut book, casts) = tallied(audit_world());
    let body = freeze_body(STYLE1, &codes(&casts), &list);
    book.w(freeze(body));
    book.w(commit(commit_body(&[body], |_| {})));
    book.checkpoint_at(bucket);
    let binding = book.last.unwrap().1;
    let at = book.w(seed(seed_body(binding, |_| {})));
    let sample = drawn(
        &audit_seed(&DICE, &beacon(), &binding),
        STYLE1,
        &casts,
        &list,
    );
    book.q(reference(&sample[0]));
    book.w(compare(&sample[0], ComparisonCode::Match));
    let r = report(&mut book, &observed());
    assert_eq!(
        audit_refused(&r)[0],
        (at, AuditEvent::Seed, AuditRefusal::Late)
    );
    assert_ne!(r.status().status(), Status::PaperAudited);
    // P6b: the commit itself declared at `PUBLISHED − 2` with a dice record
    // chosen after the beacon, and its binding checkpoint at the same bucket.
    let (mut book, casts) = tallied(audit_world());
    let body = freeze_body(STYLE1, &codes(&casts), &list);
    book.w(freeze(body));
    let dice = Hash512([0xD7; 64]);
    book.w(commit(commit_body(&[body], |p| {
        p.time_bucket = TimeBucket::new(bucket);
        p.dice_hash = dice;
    })));
    book.checkpoint_at(bucket);
    let binding = book.last.unwrap().1;
    let s = audit_seed(&dice, &beacon(), &binding);
    let at = book.w(seed(seed_body(binding, |p| {
        p.dice_hash = dice;
        p.seed = s;
    })));
    let sample = drawn(&s, STYLE1, &casts, &list);
    book.q(reference(&sample[0]));
    book.w(compare(&sample[0], ComparisonCode::Match));
    let r = report(&mut book, &observed());
    assert_eq!(
        audit_refused(&r)[0],
        (at, AuditEvent::Seed, AuditRefusal::Late)
    );
    assert_ne!(r.status().status(), Status::PaperAudited);
    // At `PUBLISHED − 3` both commit and binding are in time.
    let (mut book, casts) = tallied(audit_world());
    let body = freeze_body(STYLE1, &codes(&casts), &list);
    book.w(freeze(body));
    book.w(commit(commit_body(&[body], |p| {
        p.time_bucket = TimeBucket::new(PUBLISHED - 3);
    })));
    book.checkpoint_at(PUBLISHED - 3);
    let binding = book.last.unwrap().1;
    book.w(seed(seed_body(binding, |_| {})));
    let sample = drawn(
        &audit_seed(&DICE, &beacon(), &binding),
        STYLE1,
        &casts,
        &list,
    );
    book.q(reference(&sample[0]));
    book.w(compare(&sample[0], ComparisonCode::Match));
    let r = report(&mut book, &observed());
    assert!(audit_refused(&r).is_empty());
    assert_eq!(r.status().status(), Status::PaperAudited);
}
