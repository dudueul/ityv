//! Gates of the cryptographic tally (PROTOCOL.md §11.1, §11.2).
//!
//! Both gates require the `CRYPTO_TALLY_AID` capability (VC-007) of the
//! same election. A tally scope is recorded only after every box of the
//! ballot style is closed, after the receipt resolution when there are
//! out-of-district records, after a legal decision with a tally effect for
//! every damaged or wrong-district record (VC-099), and after the
//! late-close window counted from the last close of the ballot style, so
//! that `UNATTESTED` is final (VC-057). An aggregate opening is recorded
//! only after its tally scope is in a witness checkpoint (VC-063).

use ityv_encoding::{ElectionId, TimeBucket};

use crate::auth::{Cap, CryptoTallyAid};
use crate::error::Error;

/// Buckets after the last box close during which a late batch close may
/// still attest records (24 hours, PROTOCOL.md §7.2.1).
pub const LATE_CLOSE_WINDOW: u64 = 96;

/// What a tally scope waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TallyReadiness {
    /// Every box of the ballot style has a `BoxClose` or `BoxCloseManual`.
    pub boxes_closed: bool,
    /// The receipt resolution is recorded, or there are no out-of-district
    /// records.
    pub receipts_resolved: bool,
    /// Every record awaiting the law (`RECEIVED_DAMAGED`,
    /// `WRONG_DISTRICT`) has a legal decision with a tally effect, or there
    /// is none ([`crate::record::Disposition::PendingLegal`]).
    pub legal_resolved: bool,
    /// The bucket of the last box close of the ballot style.
    pub last_close: TimeBucket,
    /// The current bucket.
    pub now: TimeBucket,
}

/// Admits a `TallyScope` event.
///
/// # Errors
/// [`Error::Mismatch`] if the capability belongs to another election,
/// [`Error::TallyPremature`] if a box is open, the receipts are
/// unresolved, a record still waits for the law, or the late-close window
/// has not passed; [`Error::Overflow`].
pub fn admit_tally_scope(
    cap: &Cap<'_, CryptoTallyAid>,
    election_id: ElectionId<'_>,
    readiness: &TallyReadiness,
) -> Result<(), Error> {
    cap.check_election(election_id)?;
    let deadline = readiness
        .last_close
        .get()
        .checked_add(LATE_CLOSE_WINDOW)
        .ok_or(Error::Overflow)?;
    if readiness.boxes_closed
        && readiness.receipts_resolved
        && readiness.legal_resolved
        && readiness.now.get() > deadline
    {
        Ok(())
    } else {
        Err(Error::TallyPremature)
    }
}

/// Admits an `AggregateOpening` event.
///
/// # Errors
/// [`Error::Mismatch`] if the capability belongs to another election,
/// [`Error::TallyPremature`] if the tally scope is not yet in a witness
/// checkpoint (VC-063).
pub fn admit_aggregate_opening(
    cap: &Cap<'_, CryptoTallyAid>,
    election_id: ElectionId<'_>,
    scope_checkpointed: bool,
) -> Result<(), Error> {
    cap.check_election(election_id)?;
    if scope_checkpointed {
        Ok(())
    } else {
        Err(Error::TallyPremature)
    }
}

#[cfg(test)]
mod tests {
    use ityv_encoding::{Day, ElectionId, Scope, ScopeSet, TimeBucket};

    use super::{LATE_CLOSE_WINDOW, TallyReadiness, admit_aggregate_opening, admit_tally_scope};
    use crate::auth::{Authorization, CryptoTallyAid};
    use crate::error::Error;

    #[test]
    fn gates() {
        let auth = Authorization::unsigned(
            ElectionId::new(b"E1").unwrap(),
            ScopeSet::from_slice(&[
                Scope::PublicBoard,
                Scope::TrusteeBody,
                Scope::CryptoTallyAid,
            ]),
            Day::new(0),
            Day::new(9),
        );
        let cap = auth.grant::<CryptoTallyAid>(Day::new(1)).unwrap();
        let e1 = ElectionId::new(b"E1").unwrap();
        let e2 = ElectionId::new(b"E2").unwrap();
        let ready = TallyReadiness {
            boxes_closed: true,
            receipts_resolved: true,
            legal_resolved: true,
            last_close: TimeBucket::new(100),
            now: TimeBucket::new(100 + LATE_CLOSE_WINDOW + 1),
        };
        assert_eq!(admit_tally_scope(&cap, e1, &ready), Ok(()));
        let at_deadline = TallyReadiness {
            now: TimeBucket::new(100 + LATE_CLOSE_WINDOW),
            ..ready
        };
        assert_eq!(
            admit_tally_scope(&cap, e1, &at_deadline),
            Err(Error::TallyPremature)
        );
        let open = TallyReadiness {
            boxes_closed: false,
            ..ready
        };
        assert_eq!(
            admit_tally_scope(&cap, e1, &open),
            Err(Error::TallyPremature)
        );
        let unresolved = TallyReadiness {
            receipts_resolved: false,
            ..ready
        };
        assert_eq!(
            admit_tally_scope(&cap, e1, &unresolved),
            Err(Error::TallyPremature)
        );
        let undecided = TallyReadiness {
            legal_resolved: false,
            ..ready
        };
        assert_eq!(
            admit_tally_scope(&cap, e1, &undecided),
            Err(Error::TallyPremature)
        );
        let overflow = TallyReadiness {
            last_close: TimeBucket::new(u64::MAX),
            ..ready
        };
        assert_eq!(admit_tally_scope(&cap, e1, &overflow), Err(Error::Overflow));
        assert_eq!(admit_aggregate_opening(&cap, e1, true), Ok(()));
        assert_eq!(
            admit_aggregate_opening(&cap, e1, false),
            Err(Error::TallyPremature)
        );
        assert_eq!(admit_tally_scope(&cap, e2, &ready), Err(Error::Mismatch));
        assert_eq!(
            admit_aggregate_opening(&cap, e2, true),
            Err(Error::Mismatch)
        );
        assert_eq!(LATE_CLOSE_WINDOW, 96);
    }
}
