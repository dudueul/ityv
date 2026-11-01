//! Issuance and participation identities (PROTOCOL.md §10.2,
//! `FAILURE_CASES.md` §0).
//!
//! Before close a polling station records an `IssuanceCount`
//! (`IssuanceCountBody`, schema `0x002B`, signed by two clerks and
//! observers of two organisations): paper stock received, ballots issued,
//! spoiled by voters, returned, unused, sheets the printer wasted, and at an
//! out-of-district station the return envelopes issued and the empty ones
//! handed back. Three identities tie it to the paper stock, the boxes and
//! the check-in counter:
//!
//! * `stock_received = issued + unused + printer_waste`;
//! * `issued = records + without_record + challenged + quarantined +
//!   voter_spoiled + returned`;
//! * `checkin = issued − voter_spoiled − challenged` (a re-issue after a
//!   challenge or a voter's spoiled ballot is the same voter's second
//!   ballot).
//!
//! A station may hold several boxes; the caller sums the closes of every
//! genesis box with that `station_id` into [`IssuanceTotals`].

use ityv_encoding::{IssuanceCountBody, IssuanceCountParts, SCHEMA_ISSUANCE_COUNT_BODY};

pub use ityv_encoding::EnvelopeIssuance;

use crate::close::{RosterEntry, check_witnesses};
use crate::error::Error;
use crate::hold::{HoldReason, HoldSet};
use crate::sig::Signed;

/// A station's issuance count whose signatures were bound to the roster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuanceCount<'a> {
    parts: IssuanceCountParts<'a>,
}

impl<'a> IssuanceCount<'a> {
    /// Checks a signed issuance count: the body schema and a matching token
    /// for each of its clerk and observer signatures.
    ///
    /// # Errors
    /// [`Error::Decode`] if the event is not an issuance count, and the
    /// errors of [`check_witnesses`].
    pub fn check(signed: &Signed<'a>, roster: &[RosterEntry<'_>]) -> Result<Self, Error> {
        let body: IssuanceCountBody<'a> = signed
            .event
            .body(SCHEMA_ISSUANCE_COUNT_BODY)
            .map_err(|_| Error::Decode)?;
        check_witnesses(signed, roster, None)?;
        Ok(Self {
            parts: *body.parts(),
        })
    }

    /// An issuance count without signatures, for unit tests and Kani
    /// harnesses only.
    #[cfg(any(test, kani))]
    pub(crate) const fn unsigned(parts: IssuanceCountParts<'a>) -> Self {
        Self { parts }
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &IssuanceCountParts<'a> {
        &self.parts
    }
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

/// Checks the stock and issuance identities and, if the check-in count is
/// known, the participation identity. An overflowing or negative term is a
/// violation.
///
/// What it does not prove: that the counts are true; equal counts do not
/// exclude a substitution of equal numbers (ITYV-BEH-170).
#[must_use]
pub fn issuance_verdict(
    issuance: &IssuanceCount<'_>,
    totals: &IssuanceTotals,
    checkin: Option<u64>,
) -> HoldSet {
    let p = &issuance.parts;
    let stock = sum(&[p.issued, p.unused, p.printer_waste]);
    let accounted = sum(&[
        totals.records,
        totals.without_record,
        totals.challenged,
        totals.quarantined,
        p.voter_spoiled,
        p.returned,
    ]);
    let participation = checkin.map(|count| {
        p.issued
            .checked_sub(p.voter_spoiled)
            .and_then(|v| v.checked_sub(totals.challenged))
            == Some(count)
    });
    HoldSet::empty()
        .with_if(
            stock != Some(p.stock_received),
            HoldReason::IssuanceStockMismatch,
        )
        .with_if(accounted != Some(p.issued), HoldReason::IssuanceMismatch)
        .with_if(
            participation == Some(false),
            HoldReason::ParticipationMismatch,
        )
}

#[cfg(test)]
mod tests {
    use ityv_encoding::{ElectionId, IssuanceCountParts, StationId, TimeBucket};

    use super::{EnvelopeIssuance, IssuanceCount, IssuanceTotals, issuance_verdict};
    use crate::hold::{HoldReason, HoldSet};

    fn parts() -> IssuanceCountParts<'static> {
        IssuanceCountParts {
            election_id: ElectionId::new(b"E1").unwrap(),
            station_id: StationId::new(b"S1").unwrap(),
            stock_received: 102,
            issued: 20,
            voter_spoiled: 2,
            returned: 1,
            unused: 80,
            printer_waste: 2,
            envelopes: None,
            time_bucket: TimeBucket::new(1),
        }
    }

    fn issuance() -> IssuanceCount<'static> {
        IssuanceCount::unsigned(parts())
    }

    fn with(f: impl FnOnce(&mut IssuanceCountParts<'static>)) -> IssuanceCount<'static> {
        let mut p = parts();
        f(&mut p);
        IssuanceCount::unsigned(p)
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
        // Stock 20 + 80 + 2 = 102; 12 + 2 + 2 + 1 + 2 + 1 = 20; check-in
        // 20 − 2 − 2 = 16.
        assert!(issuance_verdict(&issuance(), &totals(), Some(16)).is_empty());
        assert!(issuance_verdict(&issuance(), &totals(), None).is_empty());
        assert_eq!(issuance().parts().issued, 20);
    }

    #[test]
    fn stock_mismatch() {
        let only = HoldSet::empty().with(HoldReason::IssuanceStockMismatch);
        for (stock, unused, waste) in [(101, 80, 2), (103, 80, 2), (102, 79, 2), (102, 80, 3)] {
            let i = with(|p| {
                p.stock_received = stock;
                p.unused = unused;
                p.printer_waste = waste;
            });
            assert_eq!(issuance_verdict(&i, &totals(), None), only);
        }
        let overflow = with(|p| p.unused = u64::MAX);
        assert_eq!(issuance_verdict(&overflow, &totals(), None), only);
    }

    #[test]
    fn issuance_mismatch() {
        for issued in [19, 21] {
            let i = with(|p| {
                p.issued = issued;
                p.stock_received = issued + 82;
            });
            assert_eq!(
                issuance_verdict(&i, &totals(), None),
                HoldSet::empty().with(HoldReason::IssuanceMismatch)
            );
        }
        for field in 0..6 {
            let mut t = totals();
            let mut p = parts();
            match field {
                0 => t.records = 13,
                1 => t.without_record = 3,
                2 => t.quarantined = 2,
                3 => p.voter_spoiled = 3,
                4 => p.returned = 2,
                _ => t.records = u64::MAX,
            }
            let i = IssuanceCount::unsigned(p);
            assert!(issuance_verdict(&i, &t, None).contains(HoldReason::IssuanceMismatch));
        }
    }

    #[test]
    fn participation_mismatch() {
        let only = HoldSet::empty().with(HoldReason::ParticipationMismatch);
        assert_eq!(issuance_verdict(&issuance(), &totals(), Some(15)), only);
        assert_eq!(issuance_verdict(&issuance(), &totals(), Some(17)), only);
        let underflow = with(|p| p.issued = 1);
        assert!(
            issuance_verdict(&underflow, &totals(), Some(0))
                .contains(HoldReason::ParticipationMismatch)
        );
        let challenged_underflow = with(|p| {
            p.issued = 3;
            p.voter_spoiled = 2;
        });
        assert!(
            issuance_verdict(&challenged_underflow, &totals(), Some(0))
                .contains(HoldReason::ParticipationMismatch)
        );
    }

    proptest::proptest! {
        /// The three identities against a reference in 128-bit arithmetic.
        #[test]
        fn matches_reference(
            stock in 0u64..400, issued in 0u64..200, voter_spoiled in 0u64..20,
            returned in 0u64..20, unused in 0u64..200, waste in 0u64..5,
            records in 0u64..100, without_record in 0u64..10, challenged in 0u64..10,
            quarantined in 0u64..10, checkin in proptest::option::of(0u64..200),
        ) {
            let i = with(|p| {
                p.stock_received = stock;
                p.issued = issued;
                p.voter_spoiled = voter_spoiled;
                p.returned = returned;
                p.unused = unused;
                p.printer_waste = waste;
            });
            let totals = IssuanceTotals { records, without_record, challenged, quarantined };
            let holds = issuance_verdict(&i, &totals, checkin);
            // Sums of at most six u64 terms in i128 cannot wrap, so the
            // wrapping operations are exact here.
            let sum = |xs: &[u64]| xs.iter().fold(0i128, |a, x| a.wrapping_add(i128::from(*x)));
            proptest::prop_assert_eq!(
                holds.contains(HoldReason::IssuanceStockMismatch),
                sum(&[issued, unused, waste]) != i128::from(stock)
            );
            let accounted =
                sum(&[records, without_record, challenged, quarantined, voter_spoiled, returned]);
            proptest::prop_assert_eq!(
                holds.contains(HoldReason::IssuanceMismatch),
                accounted != i128::from(issued)
            );
            let expected = checkin.is_some_and(|c| {
                i128::from(issued)
                    .wrapping_sub(i128::from(voter_spoiled))
                    .wrapping_sub(i128::from(challenged))
                    != i128::from(c)
            });
            proptest::prop_assert_eq!(holds.contains(HoldReason::ParticipationMismatch), expected);
            proptest::prop_assert!(holds.len() <= 3);
        }
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
