//! Close invariants and independent signers (PROTOCOL.md §10.1, §10.2,
//! VC-037, VC-038).
//!
//! The device side checks the same invariants before it signs
//! (`ityv-cunit`); this module checks what the ledger shows: the counts of
//! the `BoxCloseBody` (the human count of the spoil and quarantine bag
//! included), and the records, challenges and batch attestations observed
//! for the box. A violated invariant does not refuse the close: the close
//! is recorded and the box is `HOLD_REVIEW` (§10.2).
//!
//! Human signers are bound to the roster: each signature on an event needs
//! a verification token from the key the genesis registers for that
//! person, role and organisation, and no two signers may share a key half
//! (VC-016, VC-098).

use ityv_crypto::{HybridSigned, HybridVerifyingKey, Verified};
use ityv_encoding::{
    BoxClose, CloseCounts, EventRole, MAX_ATTESTATIONS, MIN_CLERKS, MIN_OBSERVERS, ModuleCounters,
    ModuleIds, OrgId, RosterRole, SignerId, SignerRole,
};

use crate::error::Error;
use crate::hold::{HoldReason, HoldSet};
use crate::issuance::EnvelopeIssuance;
use crate::record::Profile;
use crate::sig::{Signed, check_event, check_pairs};

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
///   `envelopes == 0`, `stickers == 0`. A receipt-scan box follows the
///   in-person rules (PROTOCOL.md §10.2).
/// * Out of district: `paper == 0`, `stickers == visits`, `envelopes ==
///   issued − returned_empty` (missing issuance:
///   [`HoldReason::IssuanceMissing`]).
/// * `attested ≤ records`, and `attested == records` when no batch is open
///   (`record_count == attested_count + open batch records`).
/// * `open_batches == 0`.
/// * `spoil_envelopes == challenged + quarantined` (the human count of the
///   spoil and quarantine bag, `spoil_envelope_count`).
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
    let spoil_ok = c.challenged.checked_add(c.quarantined) == Some(c.spoil_envelopes);
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
/// quarantined` (no gap, VC-038). The quarantine count is checked only
/// through this identity and the spoil-bag count: quarantines have no
/// public event of their own (PROTOCOL.md §10.2).
#[must_use]
pub fn modules_gap_free(
    counts: &CloseCounts,
    counters: &ModuleCounters<'_>,
    opened: &ModuleIds<'_>,
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
            .all(|module| counters.get(module) == Some(consumed))
}

/// A registered signer: a clerk, an observer or a custodian whose
/// appointment the genesis references (PROTOCOL.md §4.5, VC-009), with
/// the key the genesis registers (`RosterSigner`, ENCODING.md §8.43).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RosterEntry<'a> {
    /// The signer.
    pub signer_id: SignerId<'a>,
    /// The registered role.
    pub role: RosterRole,
    /// The registered organisation.
    pub org_id: OrgId<'a>,
    /// The registered hybrid verifying key.
    pub key: &'a HybridVerifyingKey,
}

/// A signer as an event names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Named<'a> {
    /// The signer.
    pub signer_id: SignerId<'a>,
    /// The role the event names.
    pub role: RosterRole,
    /// The organisation the event names.
    pub org_id: OrgId<'a>,
}

/// The key `roster` registers for `id` in `role` and `org`.
///
/// # Errors
/// [`Error::NotRegistered`] if no entry matches all three.
pub fn roster_key<'r>(
    roster: &'r [RosterEntry<'r>],
    id: SignerId<'_>,
    role: RosterRole,
    org: OrgId<'_>,
) -> Result<&'r HybridVerifyingKey, Error> {
    roster
        .iter()
        .find(|r| {
            r.signer_id.as_bytes() == id.as_bytes()
                && r.role == role
                && r.org_id.as_bytes() == org.as_bytes()
        })
        .map(|r| r.key)
        .ok_or(Error::NotRegistered)
}

/// Checks the shape of a set of human signers: every signer is registered
/// with the stated role and organisation, no signer appears twice, only
/// clerks and observers sign, and there are at least two clerks and
/// observers from at least two organisations (VC-016, VC-038; two people
/// of one organisation are one independent observer, ITYV-BEH-025).
///
/// What it does not prove: that anyone signed. [`check_witnesses`] and
/// the box methods bind each signature to a verification token.
///
/// # Errors
/// [`Error::NotRegistered`] for an unregistered signer, role or
/// organisation, or a custodian; [`Error::SignersShort`] for a repeated
/// signer or too few independent signers.
pub fn check_witness_set(witnesses: &[Named<'_>], roster: &[RosterEntry<'_>]) -> Result<(), Error> {
    check_witness_iter(|| witnesses.iter().copied(), roster)
}

fn check_witness_iter<'w, I, F>(witnesses: F, roster: &[RosterEntry<'_>]) -> Result<(), Error>
where
    F: Fn() -> I,
    I: Iterator<Item = Named<'w>>,
{
    let mut clerks = 0usize;
    let mut orgs: [Option<&[u8]>; MAX_ATTESTATIONS] = [None; MAX_ATTESTATIONS];
    let mut distinct = 0usize;
    for (index, a) in witnesses().enumerate() {
        roster_key(roster, a.signer_id, a.role, a.org_id)?;
        let repeated = witnesses()
            .take(index)
            .any(|b| b.signer_id.as_bytes() == a.signer_id.as_bytes());
        if repeated {
            return Err(Error::SignersShort);
        }
        match a.role {
            RosterRole::Clerk => clerks = clerks.saturating_add(1),
            RosterRole::Observer => {
                let org = a.org_id.as_bytes();
                let seen = orgs.iter().take(distinct).flatten().any(|o| *o == org);
                if !seen {
                    if let Some(slot) = orgs.get_mut(distinct) {
                        *slot = Some(org);
                    }
                    distinct = distinct.saturating_add(1);
                }
            }
            RosterRole::Custodian => return Err(Error::NotRegistered),
        }
    }
    if clerks >= MIN_CLERKS && distinct >= MIN_OBSERVERS {
        Ok(())
    } else {
        Err(Error::SignersShort)
    }
}

/// The roster role a clerk-or-observer event signature names, if any.
const fn witness_role(role: EventRole) -> Option<RosterRole> {
    match role {
        EventRole::Clerk => Some(RosterRole::Clerk),
        EventRole::Observer => Some(RosterRole::Observer),
        EventRole::Commission
        | EventRole::Committee
        | EventRole::Sender
        | EventRole::Receiver
        | EventRole::Authority
        | EventRole::Device => None,
    }
}

/// Checks a clerk-and-observer event: the shape of its human signers
/// ([`check_witness_set`]) and a matching token for every signature, from
/// the key the roster registers. A device signature is required exactly
/// when `device` is given, and must come from that key.
///
/// # Errors
/// As [`check_witness_set`], [`Error::NotRegistered`] for a signer in
/// another role or a missing or unexpected device signature, and the
/// errors of [`crate::sig::check_event`].
pub fn check_witnesses(
    signed: &Signed<'_>,
    roster: &[RosterEntry<'_>],
    device: Option<&HybridVerifyingKey>,
) -> Result<(), Error> {
    let event = signed.event;
    let humans = || {
        event.sigs().filter_map(|s| {
            witness_role(s.role).map(|role| Named {
                signer_id: s.signer_id,
                role,
                org_id: s.org_id,
            })
        })
    };
    check_witness_iter(humans, roster)?;
    let devices = event.sigs().filter(|s| s.role == EventRole::Device).count();
    if devices != usize::from(device.is_some()) {
        return Err(Error::NotRegistered);
    }
    check_event(signed, |s| match (witness_role(s.role), s.role) {
        (Some(role), _) => roster_key(roster, s.signer_id, role, s.org_id),
        (None, EventRole::Device) => device.ok_or(Error::NotRegistered),
        (None, _) => Err(Error::NotRegistered),
    })
}

const fn close_role(role: SignerRole) -> RosterRole {
    match role {
        SignerRole::Clerk => RosterRole::Clerk,
        SignerRole::Observer => RosterRole::Observer,
    }
}

/// Checks the human attestations of a `BoxClose`: their shape and one
/// token per attestation (purpose `purpose`, the close body bytes, the
/// attestation's signature bytes, the registered key), with no two signers
/// sharing a key half.
pub(crate) fn check_close_witnesses(
    close: &BoxClose<'_>,
    tokens: &[Verified<HybridSigned<'_>>],
    roster: &[RosterEntry<'_>],
    purpose: &[u8],
) -> Result<(), Error> {
    let named = || {
        close.attestations().map(|a| Named {
            signer_id: a.signer_id,
            role: close_role(a.role),
            org_id: a.org_id,
        })
    };
    check_witness_iter(named, roster)?;
    let pairs = close.attestations().map(|a| {
        roster_key(roster, a.signer_id, close_role(a.role), a.org_id).map(|key| (a.sig, key))
    });
    check_pairs(
        close.body_bytes(),
        purpose,
        tokens,
        close.attestations().count(),
        pairs,
    )
}

#[cfg(test)]
mod tests {
    use std::boxed::Box;

    use ityv_crypto::{HybridSigningKey, HybridVerifyingKey};
    use ityv_encoding::{
        CloseCounts, ModuleCounter, ModuleCounters, ModuleId, ModuleIds, OrgId, RosterRole,
        SignerId,
    };

    use super::{
        CountFacts, Named, Observed, RosterEntry, check_witness_set, count_verdict,
        modules_gap_free, roster_key,
    };
    use crate::error::Error;
    use crate::hold::{HoldReason, HoldSet};
    use crate::issuance::EnvelopeIssuance;
    use crate::record::Profile;

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
            spoil_envelopes: 2,
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
        f.counts.spoil_envelopes = 3;
        assert_eq!(count_verdict(&f), only(HoldReason::SpoilEnvelopeMismatch));
        f.counts.spoil_envelopes = 1;
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
        let ab = ModuleIds::new(&[a, b]).unwrap();
        let good = ModuleCounters::new(&[entry(a, 12), entry(b, 12)]).unwrap();
        assert!(modules_gap_free(&counts(), &good, &ab));
        let gap = ModuleCounters::new(&[entry(a, 12), entry(b, 11)]).unwrap();
        assert!(!modules_gap_free(&counts(), &gap, &ab));
        let extra = ModuleCounters::new(&[entry(a, 12), entry(b, 12), entry(c, 12)]).unwrap();
        assert!(!modules_gap_free(&counts(), &extra, &ab));
        let missing = ModuleCounters::new(&[entry(a, 12)]).unwrap();
        assert!(!modules_gap_free(&counts(), &missing, &ab));
        let other = ModuleCounters::new(&[entry(a, 12), entry(c, 12)]).unwrap();
        assert!(!modules_gap_free(&counts(), &other, &ab));
        let mut overflow = counts();
        overflow.quarantined = u64::MAX;
        assert!(!modules_gap_free(&overflow, &good, &ab));
        let mut overflow = counts();
        overflow.challenged = u64::MAX;
        assert!(!modules_gap_free(&overflow, &good, &ab));
    }

    fn key(seed: u8) -> &'static HybridVerifyingKey {
        Box::leak(Box::new(
            HybridSigningKey::from_seeds([seed; 32], [seed.wrapping_add(1); 32]).verifying_key(),
        ))
    }

    fn person(id: &'static [u8], role: RosterRole, org: &'static [u8]) -> RosterEntry<'static> {
        RosterEntry {
            signer_id: SignerId::new(id).unwrap(),
            role,
            org_id: OrgId::new(org).unwrap(),
            key: key(id.first().copied().unwrap_or(0)),
        }
    }

    fn named(entry: RosterEntry<'static>) -> Named<'static> {
        Named {
            signer_id: entry.signer_id,
            role: entry.role,
            org_id: entry.org_id,
        }
    }

    #[test]
    fn witnesses() {
        let c1 = person(b"c1", RosterRole::Clerk, b"NEC");
        let c2 = person(b"c2", RosterRole::Clerk, b"NEC");
        let o1 = person(b"o1", RosterRole::Observer, b"PARTY-A");
        let o2 = person(b"o2", RosterRole::Observer, b"PARTY-B");
        let o3 = person(b"o3", RosterRole::Observer, b"PARTY-A");
        let k1 = person(b"k1", RosterRole::Custodian, b"POLICE");
        let roster = [c1, c2, o1, o2, o3, k1];
        let check = |set: &[RosterEntry<'static>]| {
            let named: std::vec::Vec<_> = set.iter().map(|e| named(*e)).collect();
            check_witness_set(&named, &roster)
        };
        assert_eq!(check(&[c1, c2, o1, o2]), Ok(()));
        assert_eq!(check(&[c1, c2, o1, o3, o2]), Ok(()));
        assert_eq!(check(&[c1, c2, o1, o3]), Err(Error::SignersShort));
        assert_eq!(check(&[c1, o1, o2]), Err(Error::SignersShort));
        assert_eq!(check(&[c1, c1, o1, o2]), Err(Error::SignersShort));
        assert_eq!(check(&[c1, c2, o1, o1, o2]), Err(Error::SignersShort));
        assert_eq!(check(&[]), Err(Error::SignersShort));
        // A custodian does not witness a box event.
        assert_eq!(check(&[c1, c2, o1, o2, k1]), Err(Error::NotRegistered));
        // Registered with another role or organisation.
        let wrong_role = person(b"c1", RosterRole::Observer, b"NEC");
        assert_eq!(check(&[wrong_role, c2, o1, o2]), Err(Error::NotRegistered));
        let wrong_org = person(b"o3", RosterRole::Observer, b"PARTY-C");
        assert_eq!(check(&[c1, c2, o1, wrong_org]), Err(Error::NotRegistered));
        let stranger = person(b"x", RosterRole::Clerk, b"NEC");
        assert_eq!(
            check(&[c1, c2, o1, o2, stranger]),
            Err(Error::NotRegistered)
        );
        // Eight observers of eight organisations still count.
        let many: std::vec::Vec<RosterEntry<'static>> =
            [&b"p1"[..], b"p2", b"p3", b"p4", b"p5", b"p6", b"p7", b"p8"]
                .iter()
                .map(|id| person(id, RosterRole::Observer, id))
                .collect();
        let mut roster_many = std::vec![c1, c2];
        roster_many.extend(many.iter().copied());
        let mut set: std::vec::Vec<_> = std::vec![named(c1), named(c2)];
        set.extend(many.iter().map(|e| named(*e)));
        assert_eq!(check_witness_set(&set, &roster_many), Ok(()));
        // The registered key is found by all three of id, role, organisation.
        assert_eq!(
            roster_key(&roster, c1.signer_id, RosterRole::Clerk, c1.org_id),
            Ok(c1.key)
        );
        assert_eq!(
            roster_key(&roster, c1.signer_id, RosterRole::Observer, c1.org_id),
            Err(Error::NotRegistered)
        );
    }
}
