//! Kani bounded model-checking harnesses (verification ladder V2).
//!
//! Compiled only under `cargo kani`, as `crate::proofs` via a `#[path]`
//! attribute in `src/lib.rs`. Each harness states one property of the
//! state machines against an independently written statement, mostly in
//! 128-bit arithmetic so that the reference cannot overflow where the
//! implementation must use checked 64-bit arithmetic:
//!
//! * the sticky hold set: adding never loses a reason, removal removes
//!   exactly one;
//! * the scope prerequisites of VC-008 and the stage rule, over all 512
//!   scope sets, and the capability grant's scope and window;
//! * every count invariant of VC-038 on arbitrary 64-bit counts;
//! * the issuance and participation identities;
//! * the record status machine: total, terminal states final, the
//!   disposition precedence, and no inclusion without attestation;
//! * the dispute life cycle: forward only, never back to `OPEN`;
//! * the status vocabulary: `HOLD_REVIEW` exactly on a failure or hold, and
//!   each status only with its steps passed;
//! * the custody chain's first link: index, previous hash, organisations
//!   and route.
//!
//! Kani additionally checks every harness for panics, overflow and
//! out-of-bounds access on all explored inputs.
//!
//! Run with `cargo kani -p ityv-state` from the workspace root.
// Harness file: outside the TCB and outside `src/` (CONSTITUTION.md §1.1).
// A harness states expected values with plain indexing, 128-bit arithmetic
// and `as` casts on bounded symbolic inputs, and Kani itself reports any
// panic or overflow in them, so these restriction lints are relaxed for
// this file only.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::missing_panics_doc,
    clippy::panic,
    clippy::wildcard_enum_match_arm
)]

use ityv_encoding::{
    BoxId, CloseCounts, CustodyHandoffParts, Day, ElectionId, Hash512, IssuanceCountParts, OrgId,
    Scope, ScopeSet, SignerId, StationId, TimeBucket,
};

use crate::auth::{Authorization, BallotMark, check_scope_rules, stage};
use crate::close::{CountFacts, Observed, count_verdict};
use crate::custody::CustodyChain;
use crate::dispute::{Dispute, DisputeEvent, DisputeStatus, DisputeType};
use crate::error::Error;
use crate::hold::{HoldReason, HoldSet};
use crate::issuance::{EnvelopeIssuance, IssuanceCount, IssuanceTotals, issuance_verdict};
use crate::record::{Disposition, Exclusion, Primary, Profile, Receipt, RecordEvent, RecordState};
use crate::status::{Evidence, Outcome, Publication, Status, Step, evaluate};

fn any_reason() -> HoldReason {
    let index: usize = kani::any();
    kani::assume(index < HoldReason::ALL.len());
    HoldReason::ALL[index]
}

fn any_profile() -> Profile {
    match kani::any::<u8>() % 3 {
        0 => Profile::InPerson,
        1 => Profile::Absentee,
        _ => Profile::ReceiptScan,
    }
}

fn any_receipt() -> Receipt {
    match kani::any::<u8>() % 5 {
        0 => Receipt::Received,
        1 => Receipt::Damaged,
        2 => Receipt::Late,
        3 => Receipt::WrongDistrict,
        _ => Receipt::NotReceived,
    }
}

fn any_primary() -> Primary {
    match kani::any::<u8>() % 4 {
        0 => Primary::Cast,
        1 => Primary::ChallengedSpoiled,
        2 => Primary::Quarantined,
        _ => Primary::Receipt(any_receipt()),
    }
}

fn any_event() -> RecordEvent {
    match kani::any::<u8>() % 6 {
        0 => RecordEvent::BatchAttested,
        1 => RecordEvent::Challenged,
        2 => RecordEvent::Quarantined,
        3 => RecordEvent::ShareMissing,
        4 => RecordEvent::LegalDecision {
            include: kani::any(),
        },
        _ => RecordEvent::Receipt(any_receipt()),
    }
}

fn any_legal() -> Option<bool> {
    if kani::any() { Some(kani::any()) } else { None }
}

// Identifiers are built at compile time, so no harness unwinds the
// identifier validation loop.
static ELECTION: ElectionId<'static> = match ElectionId::new(b"E1") {
    Some(id) => id,
    None => panic!("valid identifier"),
};

static STATION: StationId<'static> = match StationId::new(b"S1") {
    Some(id) => id,
    None => panic!("valid identifier"),
};

fn election() -> ElectionId<'static> {
    ELECTION
}

fn scope_set(mask: u16) -> ScopeSet {
    let mut set = ScopeSet::empty();
    let mut code = 1u8;
    while code <= 9 {
        if mask & (1 << code) != 0 {
            if let Some(scope) = Scope::from_code(code) {
                set = set.with(scope);
            }
        }
        code += 1;
    }
    set
}

/// Adding a reason never loses another; removing removes exactly one.
#[kani::proof]
fn hold_set_is_sticky() {
    let mask: u64 = kani::any();
    let mut set = HoldSet::empty();
    for (i, reason) in HoldReason::ALL.iter().enumerate() {
        if mask & (1u64 << i) != 0 {
            set = set.with(*reason);
        }
    }
    let a = any_reason();
    let b = any_reason();
    let added = set.with(a);
    assert!(added.contains(a));
    assert!(added.is_superset_of(set));
    assert_eq!(added.contains(b), set.contains(b) || a == b);
    let removed = added.without(a);
    assert!(!removed.contains(a));
    assert_eq!(removed.contains(b), a != b && added.contains(b));
    assert_eq!(set.union(added), added);
    assert!(added.len() >= set.len() && added.len() <= set.len() + 1);
}

/// The scope rule over every scope set: `PUBLIC_BOARD` under every higher
/// stage, `TRUSTEE_BODY` under stages 2 and 3, every stage-2 scope under
/// `VOTER_CODE`, and `CRYPTO_TALLY_AID` under `RLA`.
#[kani::proof]
#[kani::unwind(12)]
fn scope_rules_are_exact() {
    let mask: u16 = kani::any();
    let set = scope_set(mask);
    let has = |s| set.contains(s);
    let mut above0 = false;
    let mut above1 = false;
    let mut stage2_complete = true;
    for s in Scope::ALL {
        if has(s) && stage(s) >= 1 {
            above0 = true;
        }
        if has(s) && stage(s) >= 2 {
            above1 = true;
        }
        if stage(s) == 2 && !has(s) {
            stage2_complete = false;
        }
    }
    let expected = (!above0 || has(Scope::PublicBoard))
        && (!above1 || has(Scope::TrusteeBody))
        && (!has(Scope::VoterCode) || stage2_complete)
        && (!has(Scope::Rla) || has(Scope::CryptoTallyAid));
    assert_eq!(check_scope_rules(set).is_ok(), expected);
}

/// A capability exists exactly for an authorized scope inside the window.
#[kani::proof]
#[kani::unwind(12)]
fn grant_is_exact() {
    let mask: u16 = kani::any();
    let from: u64 = kani::any();
    let until: u64 = kani::any();
    let today: u64 = kani::any();
    kani::assume(from <= until);
    let auth =
        Authorization::unsigned(election(), scope_set(mask), Day::new(from), Day::new(until));
    let granted = auth.grant::<BallotMark>(Day::new(today));
    let expected = scope_set(mask).contains(Scope::BallotMark) && from <= today && today <= until;
    assert_eq!(granted.is_ok(), expected);
}

/// Every count invariant of VC-038 on arbitrary counts.
#[kani::proof]
fn count_verdict_is_exact() {
    let c = CloseCounts {
        paper: kani::any(),
        records: kani::any(),
        attested: kani::any(),
        without_record: kani::any(),
        challenged: kani::any(),
        quarantined: kani::any(),
        visits: kani::any(),
        envelopes: kani::any(),
        stickers: kani::any(),
        spoil_envelopes: kani::any(),
    };
    let facts = CountFacts {
        profile: any_profile(),
        counts: c,
        open_batches: kani::any(),
        observed: Observed {
            records: kani::any(),
            challenged: kani::any(),
            attested: kani::any(),
        },
        fallback_declared: kani::any(),
        envelopes: if kani::any() {
            Some(EnvelopeIssuance {
                issued: kani::any(),
                returned_empty: kani::any(),
            })
        } else {
            None
        },
    };
    let h = count_verdict(&facts);
    let w = |x: u64| x as u128;
    let absentee = facts.profile == Profile::Absentee;
    let paper_bad = !absentee && w(c.paper) != w(c.records) + w(c.without_record);
    assert_eq!(h.contains(HoldReason::PaperRecordMismatch), paper_bad);
    assert_eq!(
        h.contains(HoldReason::AbsenteePaperNonZero),
        absentee && c.paper != 0
    );
    let stickers_bad = if absentee {
        c.stickers != c.visits
    } else {
        c.stickers != 0
    };
    assert_eq!(h.contains(HoldReason::StickerVisitMismatch), stickers_bad);
    let envelopes_bad = match (absentee, facts.envelopes) {
        (false, _) => c.envelopes != 0,
        (true, None) => false,
        (true, Some(e)) => {
            w(e.issued) < w(e.returned_empty) || w(e.issued) - w(e.returned_empty) != w(c.envelopes)
        }
    };
    assert_eq!(h.contains(HoldReason::EnvelopeMismatch), envelopes_bad);
    assert_eq!(
        h.contains(HoldReason::IssuanceMissing),
        absentee && facts.envelopes.is_none()
    );
    assert_eq!(
        h.contains(HoldReason::AttestedMismatch),
        c.attested > c.records || (facts.open_batches == 0 && c.attested != c.records)
    );
    assert_eq!(h.contains(HoldReason::OpenBatches), facts.open_batches != 0);
    assert_eq!(
        h.contains(HoldReason::SpoilEnvelopeMismatch),
        w(c.challenged) + w(c.quarantined) != w(c.spoil_envelopes)
    );
    assert_eq!(
        h.contains(HoldReason::VisitBounds),
        !(w(c.visits) <= w(c.records) && w(c.records) <= 8 * w(c.visits))
    );
    assert_eq!(
        h.contains(HoldReason::FallbackUndeclared),
        c.without_record != 0 && !facts.fallback_declared
    );
    assert_eq!(
        h.contains(HoldReason::ObservedCountMismatch),
        c.records != facts.observed.records
            || c.challenged != facts.observed.challenged
            || c.attested != facts.observed.attested
    );
}

/// The stock, issuance and participation identities on arbitrary counts.
#[kani::proof]
fn issuance_verdict_is_exact() {
    let parts = IssuanceCountParts {
        election_id: election(),
        station_id: STATION,
        stock_received: kani::any(),
        issued: kani::any(),
        voter_spoiled: kani::any(),
        returned: kani::any(),
        unused: kani::any(),
        printer_waste: kani::any(),
        envelopes: None,
        time_bucket: TimeBucket::new(0),
    };
    let issuance = IssuanceCount::unsigned(parts);
    let totals = IssuanceTotals {
        records: kani::any(),
        without_record: kani::any(),
        challenged: kani::any(),
        quarantined: kani::any(),
    };
    let checkin: Option<u64> = if kani::any() { Some(kani::any()) } else { None };
    let h = issuance_verdict(&issuance, &totals, checkin);
    let w = |x: u64| x as i128;
    assert_eq!(
        h.contains(HoldReason::IssuanceStockMismatch),
        w(parts.issued) + w(parts.unused) + w(parts.printer_waste) != w(parts.stock_received)
    );
    let accounted = w(totals.records)
        + w(totals.without_record)
        + w(totals.challenged)
        + w(totals.quarantined)
        + w(parts.voter_spoiled)
        + w(parts.returned);
    assert_eq!(
        h.contains(HoldReason::IssuanceMismatch),
        accounted != w(parts.issued)
    );
    let participation_bad = match checkin {
        None => false,
        Some(c) => w(parts.issued) - w(parts.voter_spoiled) - w(totals.challenged) != w(c),
    };
    assert_eq!(
        h.contains(HoldReason::ParticipationMismatch),
        participation_bad
    );
}

/// The record machine is total; spoiled and quarantined records are
/// final; the disposition follows its precedence and never includes an
/// unattested, incomplete or test record.
#[kani::proof]
fn record_machine() {
    let state = RecordState::from_parts(
        any_profile(),
        any_primary(),
        kani::any(),
        kani::any(),
        kani::any(),
    )
    .with_legal(any_legal());
    let event = any_event();
    match state.apply(event) {
        Ok(next) => {
            assert!(!matches!(
                state.primary(),
                Primary::ChallengedSpoiled | Primary::Quarantined
            ));
            assert!(!state.is_attested() || next.is_attested());
            assert!(!state.is_share_missing() || next.is_share_missing());
            assert_eq!(next.is_test(), state.is_test());
            assert_eq!(next.profile(), state.profile());
            if matches!(event, RecordEvent::Challenged) {
                assert!(state.profile() != Profile::ReceiptScan);
                assert!(!state.is_attested());
            }
            if matches!(event, RecordEvent::Receipt(_)) {
                assert_eq!(state.profile(), Profile::Absentee);
            }
            if let RecordEvent::LegalDecision { include } = event {
                assert!(matches!(
                    state.primary(),
                    Primary::Receipt(Receipt::Damaged | Receipt::WrongDistrict)
                ));
                assert_eq!(state.legal_decision(), None);
                assert_eq!(next.legal_decision(), Some(include));
                assert_eq!(next.primary(), state.primary());
            } else {
                assert_eq!(next.legal_decision(), state.legal_decision());
            }
        }
        Err(Error::Profile) => {
            assert!(matches!(
                event,
                RecordEvent::Challenged | RecordEvent::Receipt(_)
            ));
        }
        Err(Error::RecordTransition {
            from,
            event: refused,
        }) => {
            assert_eq!(from, state.primary());
            assert_eq!(refused, event);
        }
        Err(_) => panic!("no other error"),
    }
    let d = state.disposition();
    let awaits_law = matches!(
        state.primary(),
        Primary::Receipt(Receipt::Damaged | Receipt::WrongDistrict)
    );
    if d == Disposition::Include {
        assert!(state.is_attested() && !state.is_share_missing() && !state.is_test());
        assert!(
            matches!(
                state.primary(),
                Primary::Cast | Primary::Receipt(Receipt::Received)
            ) || (awaits_law && state.legal_decision() == Some(true))
        );
        assert!(!(state.profile() == Profile::Absentee && state.primary() == Primary::Cast));
    }
    if state.is_test() {
        assert_eq!(d, Disposition::Exclude(Exclusion::TestBallot));
    }
    if d == Disposition::PendingLegal {
        assert!(awaits_law && state.legal_decision().is_none());
    }
    if d == Disposition::Exclude(Exclusion::LegalExcluded) {
        assert!(awaits_law && state.legal_decision() == Some(false) && !state.is_test());
    }
}

/// From a filed dispute, any three events move the status forward only and
/// never back to `OPEN`; a technical resolution can still be appealed.
#[kani::proof]
#[kani::unwind(4)]
fn dispute_moves_forward() {
    let mut dispute = Dispute::unsigned(election(), DisputeType::Other);
    let rank = |s: DisputeStatus| match s {
        DisputeStatus::Open => 0u8,
        DisputeStatus::Investigating => 1,
        DisputeStatus::ResolvedTechnical => 2,
        DisputeStatus::ReferredLegal => 3,
    };
    for _ in 0..3 {
        let event = match kani::any::<u8>() % 3 {
            0 => DisputeEvent::Investigate,
            1 => DisputeEvent::ResolveTechnical,
            _ => DisputeEvent::ReferLegal,
        };
        let before = dispute.status();
        if let Ok(next) = dispute.apply(event) {
            assert!(rank(next.status()) > rank(before));
            dispute = next;
        } else {
            assert!(
                !(before == DisputeStatus::ResolvedTechnical && event == DisputeEvent::ReferLegal)
            );
        }
    }
    assert_eq!(
        dispute.is_unresolved(),
        dispute.status() != DisputeStatus::ResolvedTechnical
    );
}

/// The status vocabulary: `HOLD_REVIEW` exactly on a failure or a hold,
/// and every other status only with its steps passed.
#[kani::proof]
#[kani::unwind(13)]
fn status_is_exact() {
    let mut evidence = Evidence::new(ScopeSet::empty().with(Scope::PublicBoard));
    let mut failed = false;
    for step in Step::ALL {
        let outcome = match kani::any::<u8>() % 3 {
            0 => Outcome::NotRun,
            1 => Outcome::Passed,
            _ => Outcome::Failed,
        };
        failed |= outcome == Outcome::Failed;
        evidence = evidence.with_step(step, outcome);
    }
    let anchored: bool = kani::any();
    if anchored {
        evidence = evidence.with_anchors(Publication::Satisfied);
    }
    let held: bool = kani::any();
    if held {
        evidence = evidence.with_holds(HoldSet::empty().with(any_reason()));
    }
    let concluded: bool = kani::any();
    if concluded {
        evidence = evidence.with_audit_concluded();
    }
    let report = evaluate(&evidence);
    assert_eq!(report.status() == Status::HoldReview, failed || held);
    let passed = |s: Step| evidence.step(s) == Outcome::Passed;
    let log = passed(Step::Genesis)
        && passed(Step::Checkpoints)
        && passed(Step::Frames)
        && passed(Step::BoxInvariants)
        && passed(Step::Records)
        && anchored;
    let complete = log && passed(Step::BoxCompleteness);
    let tally = complete && passed(Step::Participation) && passed(Step::Tally);
    let audited = tally && passed(Step::Audit) && concluded;
    let expected = if failed || held {
        Status::HoldReview
    } else if audited {
        Status::PaperAudited
    } else if tally {
        Status::CryptoTallyVerified
    } else if complete {
        Status::SourceCompletenessChecked
    } else if log {
        Status::LogConsistent
    } else {
        Status::Unverified
    };
    assert_eq!(report.status(), expected);
}

/// Four organisations with names of one length, so that a symbolic choice
/// among them compares a fixed number of bytes.
static ORGS: [OrgId<'static>; 4] = [
    match OrgId::new(b"ORG-A") {
        Some(id) => id,
        None => panic!("valid identifier"),
    },
    match OrgId::new(b"ORG-B") {
        Some(id) => id,
        None => panic!("valid identifier"),
    },
    match OrgId::new(b"ORG-C") {
        Some(id) => id,
        None => panic!("valid identifier"),
    },
    match OrgId::new(b"ORG-D") {
        Some(id) => id,
        None => panic!("valid identifier"),
    },
];

/// The first custody link is accepted exactly with index 1, the zero
/// previous hash, two organisations, and the first leg of the route
/// `ORG-A → ORG-B → ORG-C` (the link rules; the signatures are bound to
/// the roster by `CustodyChain::handoff`, tested with real keys in V1).
#[kani::proof]
#[kani::unwind(66)]
fn custody_first_link_is_exact() {
    static ROUTE: [OrgId<'static>; 3] = [ORGS[0], ORGS[1], ORGS[2]];
    static BOX: BoxId<'static> = match BoxId::new(b"B1") {
        Some(id) => id,
        None => panic!("valid identifier"),
    };
    static SIGNER: SignerId<'static> = match SignerId::new(b"P") {
        Some(id) => id,
        None => panic!("valid identifier"),
    };
    let Ok(mut chain) = CustodyChain::new(ELECTION, BOX, &ROUTE, Hash512::ZERO, 5) else {
        panic!("route of three")
    };
    let from_org: usize = kani::any();
    let to_org: usize = kani::any();
    kani::assume(from_org < 4 && to_org < 4);
    let index: u32 = kani::any();
    let zero_previous: bool = kani::any();
    let handoff = CustodyHandoffParts {
        election_id: ELECTION,
        box_id: BOX,
        index,
        from_signer: SIGNER,
        from_org: ORGS[from_org],
        to_signer: SIGNER,
        to_org: ORGS[to_org],
        previous_handoff_hash: if zero_previous {
            Hash512::ZERO
        } else {
            Hash512([2; 64])
        },
        seal_digest: Hash512::ZERO,
        count: 5,
        time_bucket: TimeBucket::new(0),
    };
    let result = chain.link(&handoff, Hash512([1; 64]));
    let expected = index == 1 && zero_previous && from_org == 0 && to_org == 1;
    assert_eq!(result.is_ok(), expected);
    assert_eq!(chain.handoffs(), u32::from(expected));
    assert!(chain.holds().is_empty());
}

// ---------------------------------------------------------------------------
// The voting progress record (ADR-0027, VC-102, VC-103)

use ityv_encoding::{
    BoxProgressBody, BoxProgressParts, BoxProgressState, CheckinProgressBody, CheckinProgressParts,
    CheckinProgressState, ProgressAlarm, StationProgressPolicy, UnitId,
};

use crate::progress::{StationProgress, Stream, out_of};

static PBOX: BoxId<'static> = match BoxId::new(b"B1") {
    Some(id) => id,
    None => panic!("valid identifier"),
};

static UNIT: UnitId<'static> = match UnitId::new(b"U1") {
    Some(id) => id,
    None => panic!("valid identifier"),
};

/// The sheets outside are computed exactly for every count: no overflow,
/// and the value of the signed expression.
#[kani::proof]
fn progress_out_is_exact() {
    let issued: u64 = kani::any();
    let sheets_in: u64 = kani::any();
    let spoiled: u64 = kani::any();
    let returned: u64 = kani::any();
    let carried: u64 = kani::any();
    let expected =
        issued as i128 - sheets_in as i128 - spoiled as i128 - returned as i128 - carried as i128;
    assert_eq!(
        out_of(issued, sheets_in, spoiled, returned, carried),
        Some(expected)
    );
}

/// A device stream holds exactly when a tick comes for a slot already
/// taken, before opening or after the closing tick, skips a slot, or
/// lowers the count; at close it also holds without a closing tick or with
/// a last count that differs from the close (VC-102). Counts are taken in
/// the same cases the reference takes them.
#[kani::proof]
#[kani::unwind(10)]
fn progress_stream_rules_are_exact() {
    let first: u64 = kani::any();
    kani::assume(first < 8);
    let mut stream = Stream::<1>::new(first, [0]);
    let mut next = first;
    let mut last = 0u64;
    let mut closed = false;
    let mut held = false;
    for _ in 0..3 {
        let slot: u64 = kani::any();
        kani::assume(slot < 16);
        let count: u64 = kani::any();
        kani::assume(count < 4);
        let closing: bool = kani::any();
        let taken = stream.accept(slot, [count], closing);
        if closed || slot < next {
            held = true;
            assert_eq!(taken, Ok(false));
        } else {
            held = held || slot > next || count < last;
            last = count;
            next = slot + 1;
            closed = closing;
            assert_eq!(taken, Ok(true));
        }
        assert_eq!(
            stream.finish([last]).contains(HoldReason::ProgressStream),
            held || !closed
        );
    }
    let expected: u64 = kani::any();
    kani::assume(expected < 4);
    assert_eq!(
        stream
            .finish([expected])
            .contains(HoldReason::ProgressStream),
        held || !closed || expected != last
    );
}

/// Over four slots of symbolic counts, each alarm is raised exactly in
/// the first slot of a run of its condition: negative and high after two
/// slots beyond the bound, floor after two quiet slots with sheets outside
/// (PROTOCOL.md §7.10 item 4, VC-103).
#[kani::proof]
#[kani::unwind(9)]
fn progress_alarms_fire_once_per_run() {
    const SLOTS: usize = 4;
    let Ok(policy) = StationProgressPolicy::new(STATION, 1, 1) else {
        panic!("valid policy");
    };
    let Ok(mut station) = StationProgress::new(ELECTION, &policy, &[PBOX]) else {
        panic!("one box");
    };
    let mut issued = [0u64; SLOTS];
    let mut sheets_in = [0u64; SLOTS];
    for t in 0..SLOTS {
        issued[t] = u64::from(kani::any::<u8>() % 4);
        sheets_in[t] = u64::from(kani::any::<u8>() % 4);
    }
    let mut before = [false; 3];
    for t in 0..SLOTS {
        let Ok(checkin) = CheckinProgressBody::new(&CheckinProgressParts {
            election_id: ELECTION,
            station_id: STATION,
            unit_id: UNIT,
            slot: t as u64,
            checkins: issued[t],
            issued: issued[t],
            spoiled: 0,
            returned: 0,
            state: CheckinProgressState::Checking,
        }) else {
            panic!("no sheets back");
        };
        assert!(station.record_checkin(&checkin).is_ok());
        let tick = BoxProgressBody::new(&BoxProgressParts {
            election_id: ELECTION,
            box_id: PBOX,
            slot: t as u64,
            sheets_in: sheets_in[t],
            state: BoxProgressState::Casting,
        });
        assert!(station.record_box(&tick).is_ok());
        let Ok(outcome) = station.close_slot(t as u64) else {
            panic!("slots in order");
        };
        let out = |i: usize| issued[i] as i128 - sheets_in[i] as i128;
        let quiet =
            |i: usize| i > 0 && issued[i] == issued[i - 1] && sheets_in[i] == sheets_in[i - 1];
        assert_eq!(outcome.out, out(t));
        let now = [
            t > 0 && out(t) < 0 && out(t - 1) < 0,
            t > 0 && out(t) > 1 && out(t - 1) > 1,
            t > 1 && quiet(t) && quiet(t - 1) && out(t) > 0,
        ];
        assert_eq!(
            outcome.raised.contains(ProgressAlarm::Negative),
            now[0] && !before[0]
        );
        assert_eq!(
            outcome.raised.contains(ProgressAlarm::High),
            now[1] && !before[1]
        );
        assert_eq!(
            outcome.raised.contains(ProgressAlarm::Floor),
            now[2] && !before[2]
        );
        before = now;
    }
}
