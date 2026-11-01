//! Property tests (verification ladder V1; ITYV-BEH-063, ITYV-BEH-101):
//! random event sequences and random counts against independently written
//! reference rules.
// Integration tests: outside the TCB. Reference models use plain 128-bit
// arithmetic and indexing, so these lints are relaxed for this file only
// (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::many_single_char_names,
    clippy::wildcard_enum_match_arm
)]

use ityv_encoding::{CloseCounts, Scope, ScopeSet};
use ityv_state::{
    CountFacts, Disposition, EnvelopeIssuance, Evidence, Exclusion, HoldReason, HoldSet, Observed,
    Outcome, Primary, Profile, Receipt, RecordEvent, RecordState, Status, Step, count_verdict,
    evaluate,
};
use proptest::prelude::*;

fn profile() -> impl Strategy<Value = Profile> {
    prop_oneof![
        Just(Profile::InPerson),
        Just(Profile::Absentee),
        Just(Profile::ReceiptScan)
    ]
}

fn receipt() -> impl Strategy<Value = Receipt> {
    prop_oneof![
        Just(Receipt::Received),
        Just(Receipt::Damaged),
        Just(Receipt::Late),
        Just(Receipt::WrongDistrict),
        Just(Receipt::NotReceived)
    ]
}

fn record_event() -> impl Strategy<Value = RecordEvent> {
    prop_oneof![
        Just(RecordEvent::BatchAttested),
        Just(RecordEvent::Challenged),
        Just(RecordEvent::Quarantined),
        Just(RecordEvent::ShareMissing),
        receipt().prop_map(RecordEvent::Receipt),
        any::<bool>().prop_map(|include| RecordEvent::LegalDecision { include })
    ]
}

/// Small values most of the time, so that equalities happen.
fn count() -> impl Strategy<Value = u64> {
    prop_oneof![4 => 0u64..20, 1 => any::<u64>()]
}

fn close_counts() -> impl Strategy<Value = CloseCounts> {
    (
        (count(), count(), count(), count(), count()),
        (count(), count(), count(), count(), count()),
    )
        .prop_map(
            |(
                (paper, records, attested, without_record, challenged),
                (quarantined, visits, envelopes, stickers, spoil_envelopes),
            )| {
                CloseCounts {
                    paper,
                    records,
                    attested,
                    without_record,
                    challenged,
                    quarantined,
                    visits,
                    envelopes,
                    stickers,
                    spoil_envelopes,
                }
            },
        )
}

/// The count invariants written again, in 128-bit arithmetic.
fn reference_holds(f: &CountFacts) -> HoldSet {
    let c = &f.counts;
    let w = |x: u64| u128::from(x);
    let mut h = HoldSet::empty();
    if f.profile == Profile::Absentee {
        if c.paper != 0 {
            h = h.with(HoldReason::AbsenteePaperNonZero);
        }
        if c.stickers != c.visits {
            h = h.with(HoldReason::StickerVisitMismatch);
        }
        match f.envelopes {
            None => h = h.with(HoldReason::IssuanceMissing),
            Some(e) => {
                if w(e.issued) < w(e.returned_empty)
                    || w(e.issued) - w(e.returned_empty) != w(c.envelopes)
                {
                    h = h.with(HoldReason::EnvelopeMismatch);
                }
            }
        }
    } else {
        if w(c.paper) != w(c.records) + w(c.without_record) {
            h = h.with(HoldReason::PaperRecordMismatch);
        }
        if c.envelopes != 0 {
            h = h.with(HoldReason::EnvelopeMismatch);
        }
        if c.stickers != 0 {
            h = h.with(HoldReason::StickerVisitMismatch);
        }
    }
    if c.attested > c.records || (f.open_batches == 0 && c.attested != c.records) {
        h = h.with(HoldReason::AttestedMismatch);
    }
    if f.open_batches != 0 {
        h = h.with(HoldReason::OpenBatches);
    }
    if w(c.challenged) + w(c.quarantined) != w(c.spoil_envelopes) {
        h = h.with(HoldReason::SpoilEnvelopeMismatch);
    }
    if !(w(c.visits) <= w(c.records) && w(c.records) <= 8 * w(c.visits)) {
        h = h.with(HoldReason::VisitBounds);
    }
    if c.without_record != 0 && !f.fallback_declared {
        h = h.with(HoldReason::FallbackUndeclared);
    }
    if c.records != f.observed.records
        || c.challenged != f.observed.challenged
        || c.attested != f.observed.attested
    {
        h = h.with(HoldReason::ObservedCountMismatch);
    }
    h
}

/// Independent statement of the disposition rule.
fn reference_disposition(state: RecordState) -> Disposition {
    if state.is_test() {
        return Disposition::Exclude(Exclusion::TestBallot);
    }
    match state.primary() {
        Primary::ChallengedSpoiled => return Disposition::Exclude(Exclusion::ChallengedSpoiled),
        Primary::Quarantined => return Disposition::Exclude(Exclusion::Quarantined),
        Primary::Receipt(Receipt::NotReceived) => {
            return Disposition::Exclude(Exclusion::CastNotReceived);
        }
        Primary::Receipt(Receipt::Late) => return Disposition::Exclude(Exclusion::ReceivedLate),
        Primary::Receipt(Receipt::Damaged | Receipt::WrongDistrict)
            if state.legal_decision() == Some(false) =>
        {
            return Disposition::Exclude(Exclusion::LegalExcluded);
        }
        _ => {}
    }
    if state.is_share_missing() {
        return Disposition::Exclude(Exclusion::ShareMissing);
    }
    if !state.is_attested() {
        return Disposition::Exclude(Exclusion::Unattested);
    }
    match state.primary() {
        Primary::Receipt(Receipt::Damaged | Receipt::WrongDistrict)
            if state.legal_decision().is_none() =>
        {
            Disposition::PendingLegal
        }
        Primary::Cast if state.profile() == Profile::Absentee => Disposition::PendingReceipt,
        _ => Disposition::Include,
    }
}

proptest! {
    #[test]
    fn record_sequences(
        profile in profile(),
        test in any::<bool>(),
        events in proptest::collection::vec(record_event(), 0..12),
    ) {
        let mut state = RecordState::new(profile, test);
        for event in events {
            let before = state;
            if let Ok(next) = state.apply(event) {
                // Monotone: attestation and share loss never revert, the
                // test flag and profile never change, and a spoiled or
                // quarantined record never moves.
                prop_assert!(!before.is_attested() || next.is_attested());
                prop_assert!(!before.is_share_missing() || next.is_share_missing());
                prop_assert_eq!(next.is_test(), test);
                prop_assert_eq!(next.profile(), profile);
                prop_assert!(!matches!(
                    before.primary(),
                    Primary::ChallengedSpoiled | Primary::Quarantined
                ));
                prop_assert!(next != before);
                state = next;
            }
            prop_assert_eq!(state.disposition(), reference_disposition(state));
            // No record is included unless attested and complete.
            if state.disposition() == Disposition::Include {
                prop_assert!(state.is_attested() && !state.is_share_missing() && !state.is_test());
            }
        }
    }

    #[test]
    fn count_verdict_matches_reference(
        profile in profile(),
        counts in close_counts(),
        open_batches in prop_oneof![4 => Just(0u8), 1 => any::<u8>()],
        observed in (count(), count(), count()),
        fallback_declared in any::<bool>(),
        envelopes in proptest::option::of((count(), count())),
        consistent in any::<bool>(),
    ) {
        let mut facts = CountFacts {
            profile,
            counts,
            open_batches,
            observed: Observed { records: observed.0, challenged: observed.1, attested: observed.2 },
            fallback_declared,
            envelopes: envelopes.map(|(issued, returned_empty)| EnvelopeIssuance { issued, returned_empty }),
        };
        if consistent {
            facts.observed = Observed {
                records: counts.records,
                challenged: counts.challenged,
                attested: counts.attested,
            };
        }
        prop_assert_eq!(count_verdict(&facts), reference_holds(&facts));
    }

    #[test]
    fn status_rules(
        outcomes in proptest::collection::vec(0u8..3, 11),
        audit_concluded in any::<bool>(),
        anchored in any::<bool>(),
        hold in proptest::option::of(0usize..HoldReason::ALL.len()),
        ballot_mark in any::<bool>(),
    ) {
        let scopes = if ballot_mark {
            ScopeSet::from_slice(&[Scope::PublicBoard, Scope::TrusteeBody, Scope::BallotMark])
        } else {
            ScopeSet::from_slice(&[Scope::PublicBoard])
        };
        let mut e = Evidence::new(scopes);
        let outcome = |o: u8| match o {
            0 => Outcome::NotRun,
            1 => Outcome::Passed,
            _ => Outcome::Failed,
        };
        for (step, o) in Step::ALL.iter().zip(&outcomes) {
            e = e.with_step(*step, outcome(*o));
        }
        if audit_concluded {
            e = e.with_audit_concluded();
        }
        if anchored {
            e = e.with_anchors(ityv_state::Publication::Satisfied);
        }
        if let Some(i) = hold {
            e = e.with_holds(HoldSet::empty().with(HoldReason::ALL[i]));
        }
        let report = evaluate(&e);
        let any_failed = outcomes.contains(&2);
        prop_assert_eq!(report.status() == Status::HoldReview, any_failed || hold.is_some());
        prop_assert_eq!(report.holds().is_empty(), report.status() != Status::HoldReview);
        prop_assert_eq!(report.count_only(), !ballot_mark);
        let passed = |s: Step| e.step(s) == Outcome::Passed;
        let log = [Step::Genesis, Step::Checkpoints, Step::Frames, Step::BoxInvariants, Step::Records];
        match report.status() {
            Status::Unverified | Status::HoldReview => {}
            Status::LogConsistent => {
                prop_assert!(anchored && log.iter().all(|s| passed(*s)));
            }
            Status::SourceCompletenessChecked => {
                prop_assert!(anchored && passed(Step::BoxCompleteness));
            }
            Status::CryptoTallyVerified => {
                prop_assert!(passed(Step::Participation) && passed(Step::Tally));
            }
            Status::PaperAudited => {
                prop_assert!(anchored && audit_concluded);
                for s in log.iter().chain(&[Step::BoxCompleteness, Step::Participation, Step::Tally, Step::Audit]) {
                    prop_assert!(passed(*s));
                }
            }
        }
    }
}
