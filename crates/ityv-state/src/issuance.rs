//! Issuance and participation identities (PROTOCOL.md §10.2,
//! `FAILURE_CASES.md` §0).
//!
//! Before close a polling station records an `IssuanceCount`: ballots
//! issued, spoiled by voters, returned and unused, and at an
//! out-of-district station the return envelopes issued and the empty ones
//! handed back. Two identities tie it to the boxes and to the check-in
//! counter:
//!
//! * `issued = records + without_record + challenged + quarantined +
//!   voter_spoiled + returned`;
//! * `checkin = issued − voter_spoiled − challenged` (a re-issue after a
//!   challenge or a voter's spoiled ballot is the same voter's second
//!   ballot).
//!
//! `IssuanceCount` has no schema yet: this is a minimal typed input (an M5
//! encoding task, ADR-0025). A station may hold several boxes; the caller
//! sums the station's closes into [`IssuanceTotals`].

use ityv_encoding::{Attestation, ElectionId, StationId};

use crate::hold::{HoldReason, HoldSet};

/// Return-envelope accounting of an out-of-district station.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnvelopeIssuance {
    /// Return envelopes issued.
    pub issued: u64,
    /// Empty return envelopes handed back.
    pub returned_empty: u64,
}

impl EnvelopeIssuance {
    /// Envelopes that should be in the box: `issued − returned_empty`, or
    /// `None` if more were returned than issued.
    #[must_use]
    pub const fn expected_in_box(&self) -> Option<u64> {
        self.issued.checked_sub(self.returned_empty)
    }
}

/// A station's issuance count (minimal input).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuanceCount<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The station.
    pub station_id: StationId<'a>,
    /// Ballots issued.
    pub issued: u64,
    /// Ballots the voter spoiled and had re-issued.
    pub voter_spoiled: u64,
    /// Ballots returned unused by voters.
    pub returned: u64,
    /// Ballots never issued. The printing-stock identity it belongs to is
    /// not specified, so it is carried but not checked (ADR-0025, spec gap
    /// 7).
    pub unused: u64,
    /// Out-of-district station: return-envelope accounting.
    pub envelopes: Option<EnvelopeIssuance>,
    /// The signers: two clerks and two observers of different
    /// organisations ([`crate::close::check_witnesses`]).
    pub witnesses: &'a [Attestation<'a>],
}

/// The sums over a station's box closes that the identities compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IssuanceTotals {
    /// Cast records.
    pub records: u64,
    /// Ballots without a record.
    pub without_record: u64,
    /// Challenged ballots.
    pub challenged: u64,
    /// Quarantined ballots.
    pub quarantined: u64,
}

fn sum(values: &[u64]) -> Option<u64> {
    values.iter().try_fold(0u64, |acc, v| acc.checked_add(*v))
}

/// Checks the issuance identity and, if the check-in count is known, the
/// participation identity. An overflowing or negative term is a violation.
///
/// What it does not prove: that the counts are true; equal counts do not
/// exclude a substitution of equal numbers (ITYV-BEH-170).
#[must_use]
pub fn issuance_verdict(
    issuance: &IssuanceCount<'_>,
    totals: &IssuanceTotals,
    checkin: Option<u64>,
) -> HoldSet {
    let accounted = sum(&[
        totals.records,
        totals.without_record,
        totals.challenged,
        totals.quarantined,
        issuance.voter_spoiled,
        issuance.returned,
    ]);
    let participation = checkin.map(|count| {
        issuance
            .issued
            .checked_sub(issuance.voter_spoiled)
            .and_then(|v| v.checked_sub(totals.challenged))
            == Some(count)
    });
    HoldSet::empty()
        .with_if(
            accounted != Some(issuance.issued),
            HoldReason::IssuanceMismatch,
        )
        .with_if(
            participation == Some(false),
            HoldReason::ParticipationMismatch,
        )
}

#[cfg(test)]
mod tests {
    use ityv_encoding::{ElectionId, StationId};

    use super::{EnvelopeIssuance, IssuanceCount, IssuanceTotals, issuance_verdict};
    use crate::hold::{HoldReason, HoldSet};

    fn issuance() -> IssuanceCount<'static> {
        IssuanceCount {
            election_id: ElectionId::new(b"E1").unwrap(),
            station_id: StationId::new(b"S1").unwrap(),
            issued: 20,
            voter_spoiled: 2,
            returned: 1,
            unused: 80,
            envelopes: None,
            witnesses: &[],
        }
    }

    fn totals() -> IssuanceTotals {
        IssuanceTotals {
            records: 12,
            without_record: 2,
            challenged: 2,
            quarantined: 1,
        }
    }

    #[test]
    fn identities_hold() {
        // 12 + 2 + 2 + 1 + 2 + 1 = 20; check-in 20 − 2 − 2 = 16.
        assert!(issuance_verdict(&issuance(), &totals(), Some(16)).is_empty());
        assert!(issuance_verdict(&issuance(), &totals(), None).is_empty());
    }

    #[test]
    fn issuance_mismatch() {
        let only = HoldSet::empty().with(HoldReason::IssuanceMismatch);
        for issued in [19, 21] {
            let i = IssuanceCount {
                issued,
                ..issuance()
            };
            assert_eq!(issuance_verdict(&i, &totals(), None), only);
        }
        for field in 0..6 {
            let mut t = totals();
            let mut i = issuance();
            match field {
                0 => t.records = 13,
                1 => t.without_record = 3,
                2 => t.quarantined = 2,
                3 => i.voter_spoiled = 3,
                4 => i.returned = 2,
                _ => t.records = u64::MAX,
            }
            assert!(issuance_verdict(&i, &t, None).contains(HoldReason::IssuanceMismatch));
        }
    }

    #[test]
    fn participation_mismatch() {
        let only = HoldSet::empty().with(HoldReason::ParticipationMismatch);
        assert_eq!(issuance_verdict(&issuance(), &totals(), Some(15)), only);
        assert_eq!(issuance_verdict(&issuance(), &totals(), Some(17)), only);
        let underflow = IssuanceCount {
            issued: 1,
            ..issuance()
        };
        assert!(
            issuance_verdict(&underflow, &totals(), Some(0))
                .contains(HoldReason::ParticipationMismatch)
        );
        let challenged_underflow = IssuanceCount {
            issued: 3,
            voter_spoiled: 2,
            ..issuance()
        };
        assert!(
            issuance_verdict(&challenged_underflow, &totals(), Some(0))
                .contains(HoldReason::ParticipationMismatch)
        );
    }

    #[test]
    fn envelopes_expected() {
        let e = EnvelopeIssuance {
            issued: 10,
            returned_empty: 3,
        };
        assert_eq!(e.expected_in_box(), Some(7));
        let e = EnvelopeIssuance {
            issued: 3,
            returned_empty: 4,
        };
        assert_eq!(e.expected_in_box(), None);
    }
}
