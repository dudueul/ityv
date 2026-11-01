//! Close invariants and independent signers (PROTOCOL.md §10.1, §10.2,
//! VC-037, VC-038).
//!
//! The device side checks the same invariants before it signs
//! (`ityv-cunit`); this module checks what the ledger shows: the counts of
//! the `BoxCloseBody`, the records, challenges and batch attestations
//! observed for the box, and the physical counts people report. A violated
//! invariant does not refuse the close: the close is recorded and the box
//! is `HOLD_REVIEW` (§10.2).

use ityv_encoding::{
    Attestation, BoxClose, CloseCounts, MAX_ATTESTATIONS, MIN_CLERKS, MIN_OBSERVERS,
    ModuleCounters, ModuleId, OrgId, SignerId, SignerRole,
};

use crate::error::Error;
use crate::hold::{HoldReason, HoldSet};
use crate::issuance::EnvelopeIssuance;
use crate::record::Profile;

/// Ballots in one visit at most (ADR-0021): `record_count ≤ 8·visit_count`.
pub const MAX_VISIT_BALLOTS: u64 = 8;

/// What the ledger shows for a box, counted by the state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Observed {
    /// Cast records with the box's identifier.
    pub records: u64,
    /// Challenge openings with the box's identifier.
    pub challenged: u64,
    /// Records covered by the box's batch attestations.
    pub attested: u64,
}

impl Observed {
    /// Nothing observed.
    pub const ZERO: Self = Self {
        records: 0,
        challenged: 0,
        attested: 0,
    };
}

/// Everything the count invariants compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CountFacts {
    /// The box's collection profile.
    pub profile: Profile,
    /// The counts the close reports.
    pub counts: CloseCounts,
    /// Batches still open at close.
    pub open_batches: u8,
    /// What the ledger shows for the box.
    pub observed: Observed,
    /// Physical envelopes in the spoil and quarantine bag. The
    /// `BoxCloseBody` has no such field; the caller supplies the human
    /// count (ADR-0025, M5 encoding task).
    pub spoil_envelopes: u64,
    /// Whether a `FallbackDeclared` event exists for the box.
    pub fallback_declared: bool,
    /// Out-of-district box: the station's return-envelope accounting from
    /// its `IssuanceCount`; `None` if there is none.
    pub envelopes: Option<EnvelopeIssuance>,
}

/// Checks the count invariants of VC-038 and returns the violated ones.
/// An overflowing sum counts as a violation of its invariant.
///
/// * In person and receipt scan: `paper == records + without_record`,
///   `envelopes == 0`, `stickers == 0`. The receipt-scan box follows the
///   in-person rules (ADR-0025, spec gap 4).
/// * Out of district: `paper == 0`, `stickers == visits`, `envelopes ==
///   issued − returned_empty` (missing issuance:
///   [`HoldReason::IssuanceMissing`]).
/// * `attested ≤ records`, and `attested == records` when no batch is open
///   (`record_count == attested_count + open batch records`).
/// * `open_batches == 0`.
/// * `spoil_envelopes == challenged + quarantined`.
/// * `visits ≤ records ≤ 8·visits`.
/// * `without_record > 0` only with a `FallbackDeclared`.
/// * The reported records, challenges and attested records equal what the
///   ledger shows (the record-set root of §14 step 4 fixes the count).
#[must_use]
pub fn count_verdict(facts: &CountFacts) -> HoldSet {
    let c = &facts.counts;
    let mut holds = HoldSet::empty();
    match facts.profile {
        Profile::InPerson | Profile::ReceiptScan => {
            let paper_ok = c.records.checked_add(c.without_record) == Some(c.paper);
            holds = holds
                .with_if(!paper_ok, HoldReason::PaperRecordMismatch)
                .with_if(c.envelopes != 0, HoldReason::EnvelopeMismatch)
                .with_if(c.stickers != 0, HoldReason::StickerVisitMismatch);
        }
        Profile::Absentee => {
            holds = holds
                .with_if(c.paper != 0, HoldReason::AbsenteePaperNonZero)
                .with_if(c.stickers != c.visits, HoldReason::StickerVisitMismatch);
            holds = match facts.envelopes {
                Some(issuance) => holds.with_if(
                    issuance.expected_in_box() != Some(c.envelopes),
                    HoldReason::EnvelopeMismatch,
                ),
                None => holds.with(HoldReason::IssuanceMissing),
            };
        }
    }
    let attested_ok = if facts.open_batches == 0 {
        c.attested == c.records
    } else {
        c.attested <= c.records
    };
    let spoil_ok = c.challenged.checked_add(c.quarantined) == Some(facts.spoil_envelopes);
    // `visits ≤ records ≤ 8·visits`; the product saturates, which keeps the
    // comparison exact because `records` is itself a u64.
    let visits_ok =
        c.visits <= c.records && c.records <= c.visits.saturating_mul(MAX_VISIT_BALLOTS);
    let observed_ok = c.records == facts.observed.records
        && c.challenged == facts.observed.challenged
        && c.attested == facts.observed.attested;
    holds
        .with_if(!attested_ok, HoldReason::AttestedMismatch)
        .with_if(facts.open_batches != 0, HoldReason::OpenBatches)
        .with_if(!spoil_ok, HoldReason::SpoilEnvelopeMismatch)
        .with_if(!visits_ok, HoldReason::VisitBounds)
        .with_if(
            c.without_record != 0 && !facts.fallback_declared,
            HoldReason::FallbackUndeclared,
        )
        .with_if(!observed_ok, HoldReason::ObservedCountMismatch)
}

/// Returns `true` if the close's module counters name exactly the modules
/// opened in the box and each final counter equals `records + challenged +
/// quarantined` (no gap, VC-038).
#[must_use]
pub fn modules_gap_free(
    counts: &CloseCounts,
    counters: &ModuleCounters<'_>,
    opened: &[ModuleId<'_>],
) -> bool {
    let Some(consumed) = counts
        .records
        .checked_add(counts.challenged)
        .and_then(|sum| sum.checked_add(counts.quarantined))
    else {
        return false;
    };
    counters.len() == opened.len()
        && opened
            .iter()
            .all(|module| counters.get(*module) == Some(consumed))
}

/// A registered signer: a clerk or an observer whose appointment the
/// genesis references (PROTOCOL.md §4.5, VC-009).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RosterEntry<'a> {
    /// The signer.
    pub signer_id: SignerId<'a>,
    /// The registered role.
    pub role: SignerRole,
    /// The registered organisation.
    pub org_id: OrgId<'a>,
}

/// Checks a set of human attestations: every signer is registered with the
/// stated role and organisation, no signer appears twice, and there are at
/// least two clerks and observers from at least two organisations (VC-016,
/// VC-038; two people of one organisation are one independent observer,
/// ITYV-BEH-025).
///
/// What it does not prove: that the signatures are valid (M5 verifies them
/// against the appointment keys).
///
/// # Errors
/// [`Error::NotRegistered`] for an unregistered signer, role or
/// organisation; [`Error::SignersShort`] for a repeated signer or too few
/// independent signers.
pub fn check_witnesses(
    witnesses: &[Attestation<'_>],
    roster: &[RosterEntry<'_>],
) -> Result<(), Error> {
    check_witness_iter(|| witnesses.iter().copied(), roster)
}

/// [`check_witnesses`] over the attestations of a `BoxClose`.
pub(crate) fn check_close_witnesses(
    close: &BoxClose<'_>,
    roster: &[RosterEntry<'_>],
) -> Result<(), Error> {
    check_witness_iter(|| close.attestations(), roster)
}

fn check_witness_iter<'w, I, F>(witnesses: F, roster: &[RosterEntry<'_>]) -> Result<(), Error>
where
    F: Fn() -> I,
    I: Iterator<Item = Attestation<'w>>,
{
    let mut clerks = 0usize;
    let mut orgs: [Option<&[u8]>; MAX_ATTESTATIONS] = [None; MAX_ATTESTATIONS];
    let mut distinct = 0usize;
    for (index, a) in witnesses().enumerate() {
        let registered = roster.iter().any(|r| {
            r.signer_id.as_bytes() == a.signer_id.as_bytes()
                && r.role == a.role
                && r.org_id.as_bytes() == a.org_id.as_bytes()
        });
        if !registered {
            return Err(Error::NotRegistered);
        }
        let repeated = witnesses()
            .take(index)
            .any(|b| b.signer_id.as_bytes() == a.signer_id.as_bytes());
        if repeated {
            return Err(Error::SignersShort);
        }
        match a.role {
            SignerRole::Clerk => clerks = clerks.saturating_add(1),
            SignerRole::Observer => {
                let org = a.org_id.as_bytes();
                let seen = orgs.iter().take(distinct).flatten().any(|o| *o == org);
                if !seen {
                    if let Some(slot) = orgs.get_mut(distinct) {
                        *slot = Some(org);
                    }
                    distinct = distinct.saturating_add(1);
                }
            }
        }
    }
    if clerks >= MIN_CLERKS && distinct >= MIN_OBSERVERS {
        Ok(())
    } else {
        Err(Error::SignersShort)
    }
}

#[cfg(test)]
mod tests {
    use ityv_encoding::{
        Attestation, CloseCounts, HYBRID_SIG_LEN, ModuleCounter, ModuleCounters, ModuleId, OrgId,
        SignerId, SignerRole,
    };

    use super::{
        CountFacts, Observed, RosterEntry, check_witnesses, count_verdict, modules_gap_free,
    };
    use crate::error::Error;
    use crate::hold::{HoldReason, HoldSet};
    use crate::issuance::EnvelopeIssuance;
    use crate::record::Profile;

    static SIG: [u8; HYBRID_SIG_LEN] = [0; HYBRID_SIG_LEN];

    fn counts() -> CloseCounts {
        CloseCounts {
            paper: 12,
            records: 10,
            attested: 10,
            without_record: 2,
            challenged: 1,
            quarantined: 1,
            visits: 4,
            envelopes: 0,
            stickers: 0,
        }
    }

    fn facts() -> CountFacts {
        CountFacts {
            profile: Profile::InPerson,
            counts: counts(),
            open_batches: 0,
            observed: Observed {
                records: 10,
                challenged: 1,
                attested: 10,
            },
            spoil_envelopes: 2,
            fallback_declared: true,
            envelopes: None,
        }
    }

    fn envelopes(issued: u64, returned_empty: u64) -> EnvelopeIssuance {
        EnvelopeIssuance {
            issued,
            returned_empty,
        }
    }

    fn only(reason: HoldReason) -> HoldSet {
        HoldSet::empty().with(reason)
    }

    #[test]
    fn clean_close_has_no_hold() {
        assert!(count_verdict(&facts()).is_empty());
        let mut scan = facts();
        scan.profile = Profile::ReceiptScan;
        assert!(count_verdict(&scan).is_empty());
        assert_eq!(Observed::ZERO.records, 0);
        assert_eq!(Observed::ZERO.challenged, 0);
        assert_eq!(Observed::ZERO.attested, 0);
    }

    #[test]
    fn each_in_person_invariant() {
        let mut f = facts();
        f.counts.paper = 13;
        assert_eq!(count_verdict(&f), only(HoldReason::PaperRecordMismatch));
        f.counts.paper = 11;
        assert_eq!(count_verdict(&f), only(HoldReason::PaperRecordMismatch));
        let mut f = facts();
        f.counts.records = u64::MAX;
        f.observed.records = u64::MAX;
        f.counts.attested = u64::MAX;
        f.observed.attested = u64::MAX;
        assert!(count_verdict(&f).contains(HoldReason::PaperRecordMismatch));
        let mut f = facts();
        f.counts.envelopes = 1;
        assert_eq!(count_verdict(&f), only(HoldReason::EnvelopeMismatch));
        let mut f = facts();
        f.counts.stickers = 1;
        assert_eq!(count_verdict(&f), only(HoldReason::StickerVisitMismatch));
        let mut f = facts();
        f.spoil_envelopes = 3;
        assert_eq!(count_verdict(&f), only(HoldReason::SpoilEnvelopeMismatch));
        f.spoil_envelopes = 1;
        assert_eq!(count_verdict(&f), only(HoldReason::SpoilEnvelopeMismatch));
        let mut f = facts();
        f.counts.challenged = u64::MAX;
        f.observed.challenged = u64::MAX;
        assert_eq!(count_verdict(&f), only(HoldReason::SpoilEnvelopeMismatch));
        let mut f = facts();
        f.fallback_declared = false;
        assert_eq!(count_verdict(&f), only(HoldReason::FallbackUndeclared));
        f.counts.without_record = 0;
        f.counts.paper = 10;
        assert!(count_verdict(&f).is_empty());
    }

    #[test]
    fn attestation_and_batches() {
        let mut f = facts();
        f.open_batches = 1;
        assert_eq!(count_verdict(&f), only(HoldReason::OpenBatches));
        f.counts.attested = 8;
        f.observed.attested = 8;
        assert_eq!(count_verdict(&f), only(HoldReason::OpenBatches));
        f.counts.attested = 11;
        f.observed.attested = 11;
        assert_eq!(
            count_verdict(&f),
            only(HoldReason::OpenBatches).with(HoldReason::AttestedMismatch)
        );
        let mut f = facts();
        f.counts.attested = 9;
        f.observed.attested = 9;
        assert_eq!(count_verdict(&f), only(HoldReason::AttestedMismatch));
    }

    #[test]
    fn visit_bounds() {
        let mut f = facts();
        f.counts.visits = 10;
        assert!(count_verdict(&f).is_empty());
        f.counts.visits = 11;
        assert_eq!(count_verdict(&f), only(HoldReason::VisitBounds));
        f.counts.visits = 2;
        assert!(count_verdict(&f).is_empty());
        // One visit casts at most eight ballots.
        f.counts.visits = 1;
        assert_eq!(count_verdict(&f), only(HoldReason::VisitBounds));
        let mut f = facts();
        f.counts.records = 16;
        f.observed.records = 16;
        f.counts.attested = 16;
        f.observed.attested = 16;
        f.counts.paper = 18;
        f.counts.visits = 2;
        assert!(count_verdict(&f).is_empty());
        f.counts.visits = u64::MAX;
        assert_eq!(count_verdict(&f), only(HoldReason::VisitBounds));
    }

    #[test]
    fn observed_counts() {
        for change in 0..3 {
            let mut f = facts();
            match change {
                0 => f.observed.records = 9,
                1 => f.observed.challenged = 0,
                _ => f.observed.attested = 9,
            }
            assert_eq!(count_verdict(&f), only(HoldReason::ObservedCountMismatch));
        }
    }

    fn absentee() -> CountFacts {
        let mut f = facts();
        f.profile = Profile::Absentee;
        f.counts.paper = 0;
        f.counts.envelopes = 4;
        f.counts.stickers = 4;
        f.envelopes = Some(envelopes(6, 2));
        f
    }

    #[test]
    fn absentee_invariants() {
        assert!(count_verdict(&absentee()).is_empty());
        let mut f = absentee();
        f.counts.paper = 1;
        assert_eq!(count_verdict(&f), only(HoldReason::AbsenteePaperNonZero));
        let mut f = absentee();
        f.counts.stickers = 5;
        assert_eq!(count_verdict(&f), only(HoldReason::StickerVisitMismatch));
        let mut f = absentee();
        f.envelopes = Some(envelopes(6, 1));
        assert_eq!(count_verdict(&f), only(HoldReason::EnvelopeMismatch));
        let mut f = absentee();
        f.envelopes = Some(envelopes(2, 3));
        assert_eq!(count_verdict(&f), only(HoldReason::EnvelopeMismatch));
        let mut f = absentee();
        f.envelopes = None;
        assert_eq!(count_verdict(&f), only(HoldReason::IssuanceMissing));
    }

    #[test]
    fn module_counters() {
        let a = ModuleId::new(b"M-A").unwrap();
        let b = ModuleId::new(b"M-B").unwrap();
        let c = ModuleId::new(b"M-C").unwrap();
        let entry = |module_id, counter| ModuleCounter { module_id, counter };
        let good = ModuleCounters::new(&[entry(a, 12), entry(b, 12)]).unwrap();
        assert!(modules_gap_free(&counts(), &good, &[a, b]));
        let gap = ModuleCounters::new(&[entry(a, 12), entry(b, 11)]).unwrap();
        assert!(!modules_gap_free(&counts(), &gap, &[a, b]));
        let extra = ModuleCounters::new(&[entry(a, 12), entry(b, 12), entry(c, 12)]).unwrap();
        assert!(!modules_gap_free(&counts(), &extra, &[a, b]));
        let missing = ModuleCounters::new(&[entry(a, 12)]).unwrap();
        assert!(!modules_gap_free(&counts(), &missing, &[a, b]));
        let other = ModuleCounters::new(&[entry(a, 12), entry(c, 12)]).unwrap();
        assert!(!modules_gap_free(&counts(), &other, &[a, b]));
        let mut overflow = counts();
        overflow.quarantined = u64::MAX;
        assert!(!modules_gap_free(&overflow, &good, &[a, b]));
        let mut overflow = counts();
        overflow.challenged = u64::MAX;
        assert!(!modules_gap_free(&overflow, &good, &[a, b]));
    }

    fn person(id: &'static [u8], role: SignerRole, org: &'static [u8]) -> RosterEntry<'static> {
        RosterEntry {
            signer_id: SignerId::new(id).unwrap(),
            role,
            org_id: OrgId::new(org).unwrap(),
        }
    }

    fn attest(entry: RosterEntry<'static>) -> Attestation<'static> {
        Attestation {
            signer_id: entry.signer_id,
            role: entry.role,
            org_id: entry.org_id,
            sig: &SIG,
        }
    }

    #[test]
    fn witnesses() {
        let c1 = person(b"c1", SignerRole::Clerk, b"NEC");
        let c2 = person(b"c2", SignerRole::Clerk, b"NEC");
        let o1 = person(b"o1", SignerRole::Observer, b"PARTY-A");
        let o2 = person(b"o2", SignerRole::Observer, b"PARTY-B");
        let o3 = person(b"o3", SignerRole::Observer, b"PARTY-A");
        let roster = [c1, c2, o1, o2, o3];
        let check = |set: &[RosterEntry<'static>]| {
            let attestations: std::vec::Vec<_> = set.iter().map(|e| attest(*e)).collect();
            check_witnesses(&attestations, &roster)
        };
        assert_eq!(check(&[c1, c2, o1, o2]), Ok(()));
        assert_eq!(check(&[c1, c2, o1, o3, o2]), Ok(()));
        assert_eq!(check(&[c1, c2, o1, o3]), Err(Error::SignersShort));
        assert_eq!(check(&[c1, o1, o2]), Err(Error::SignersShort));
        assert_eq!(check(&[c1, c1, o1, o2]), Err(Error::SignersShort));
        assert_eq!(check(&[c1, c2, o1, o1, o2]), Err(Error::SignersShort));
        assert_eq!(check(&[]), Err(Error::SignersShort));
        // Registered with another role or organisation.
        let wrong_role = person(b"c1", SignerRole::Observer, b"NEC");
        assert_eq!(check(&[wrong_role, c2, o1, o2]), Err(Error::NotRegistered));
        let wrong_org = person(b"o3", SignerRole::Observer, b"PARTY-C");
        assert_eq!(check(&[c1, c2, o1, wrong_org]), Err(Error::NotRegistered));
        let stranger = person(b"x", SignerRole::Clerk, b"NEC");
        assert_eq!(
            check(&[c1, c2, o1, o2, stranger]),
            Err(Error::NotRegistered)
        );
        // Eight observers of eight organisations still count.
        let many: std::vec::Vec<RosterEntry<'static>> =
            [&b"p1"[..], b"p2", b"p3", b"p4", b"p5", b"p6", b"p7", b"p8"]
                .iter()
                .map(|id| person(id, SignerRole::Observer, id))
                .collect();
        let mut roster_many = std::vec![c1, c2];
        roster_many.extend(many.iter().copied());
        let mut set: std::vec::Vec<_> = std::vec![attest(c1), attest(c2)];
        set.extend(many.iter().map(|e| attest(*e)));
        assert_eq!(check_witnesses(&set, &roster_many), Ok(()));
    }
}
