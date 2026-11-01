//! Record statuses and their tally disposition.
//!
//! A cast record on the ledger starts `UNATTESTED` (its record signature is
//! valid but no `BatchAttest` covers it yet, PROTOCOL.md §7.2.1) and
//! becomes `CAST_COMMITTED` when a batch or a late batch close attests it
//! (VC-053, VC-057). Before attestation it may instead be challenged
//! (`CHALLENGED_SPOILED`, §8) or quarantined (`QUARANTINED`, §7.3,
//! VC-023): batches cover cast ballots only, so the three are disjoint, as
//! the module counter identity of §10.2 requires. Out-of-district records
//! are then resolved against the received envelopes (`RECEIVED`,
//! `RECEIVED_DAMAGED`, `RECEIVED_LATE`, `WRONG_DISTRICT`,
//! `CAST_NOT_RECEIVED`, §10.6). `SHARE_MISSING` (VC-036) and the test
//! ballot style (VC-055) are flags beside the primary status.
//!
//! [`RecordState::disposition`] says whether the record enters the tally
//! scope (§11.1), is excluded with a reason, or waits. A record never waits
//! on a machine decision where the law decides: damaged and wrong-district
//! records wait for a legal decision that this crate cannot make (VC-049,
//! ITYV-BEH-140).

use ityv_encoding::BallotStyleId;

use crate::error::Error;

/// Prefix of the ballot-style identifier of test ballots (PROTOCOL.md §8,
/// VC-055).
pub const TEST_STYLE_PREFIX: &[u8] = b"TEST-";

/// Returns `true` if `style` is a test ballot style.
#[must_use]
pub fn is_test_style(style: BallotStyleId<'_>) -> bool {
    style.as_bytes().starts_with(TEST_STYLE_PREFIX)
}

/// The collection profile of a box (PROTOCOL.md §17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    /// A polling-station box (in district, early or election day).
    InPerson,
    /// An out-of-district or overseas box: ballots travel in return
    /// envelopes and are resolved at the receiving commission (§10.6).
    Absentee,
    /// `RECEIPT_SCAN` (home and ship voting): the receiving commission's
    /// scanner makes the records; no pre-cast challenge, no slip.
    ReceiptScan,
}

/// The receipt-resolution outcome of an out-of-district record (§10.6
/// step 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Receipt {
    /// `RECEIVED`: matches a normal label.
    Received,
    /// `RECEIVED_DAMAGED`: matches the label of a damaged envelope.
    Damaged,
    /// `RECEIVED_LATE`: matches the label of an envelope that arrived after
    /// the deadline.
    Late,
    /// `WRONG_DISTRICT`: matches, but the ballot style is not of the
    /// receiving district.
    WrongDistrict,
    /// `CAST_NOT_RECEIVED`: no label matches.
    NotReceived,
}

/// The primary state of a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Primary {
    /// Cast (in a polling-station or receipt-scan box, or not yet resolved
    /// at the receiving commission).
    Cast,
    /// `CHALLENGED_SPOILED`: opened by a pre-cast challenge.
    ChallengedSpoiled,
    /// `QUARANTINED`.
    Quarantined,
    /// Resolved at the receiving commission.
    Receipt(Receipt),
}

/// An event that changes a record's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordEvent {
    /// A `BatchAttest` or `LateBatchClose` covers the record.
    BatchAttested,
    /// A `ChallengeOpening` opens the record.
    Challenged,
    /// A quarantine entry names the record.
    Quarantined,
    /// The share-receipt reconciliation found a member share missing.
    ShareMissing,
    /// The receipt-resolution procedure classified the record.
    Receipt(Receipt),
}

/// The status-vocabulary name of a record's primary state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordStatus {
    /// `CAST_COMMITTED`.
    CastCommitted,
    /// `UNATTESTED`.
    Unattested,
    /// `RECEIVED`.
    Received,
    /// `RECEIVED_DAMAGED`.
    ReceivedDamaged,
    /// `RECEIVED_LATE`.
    ReceivedLate,
    /// `WRONG_DISTRICT`.
    WrongDistrict,
    /// `CAST_NOT_RECEIVED`.
    CastNotReceived,
    /// `CHALLENGED_SPOILED`.
    ChallengedSpoiled,
    /// `QUARANTINED`.
    Quarantined,
}

impl RecordStatus {
    /// The vocabulary name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CastCommitted => "CAST_COMMITTED",
            Self::Unattested => "UNATTESTED",
            Self::Received => "RECEIVED",
            Self::ReceivedDamaged => "RECEIVED_DAMAGED",
            Self::ReceivedLate => "RECEIVED_LATE",
            Self::WrongDistrict => "WRONG_DISTRICT",
            Self::CastNotReceived => "CAST_NOT_RECEIVED",
            Self::ChallengedSpoiled => "CHALLENGED_SPOILED",
            Self::Quarantined => "QUARANTINED",
        }
    }
}

/// Why a record is excluded from the tally scope.
///
/// The first six are the exclusion reasons of PROTOCOL.md §11.1;
/// `ReceivedLate` is the exclusion of §10.6 step 6, which §11.1 does not
/// list (ADR-0025, spec gap 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Exclusion {
    /// `TEST_BALLOT` (VC-055).
    TestBallot,
    /// `CHALLENGED_SPOILED`.
    ChallengedSpoiled,
    /// `QUARANTINED`.
    Quarantined,
    /// `CAST_NOT_RECEIVED`.
    CastNotReceived,
    /// `RECEIVED_LATE`: excluded by the statutory arrival deadline.
    ReceivedLate,
    /// `SHARE_MISSING`.
    ShareMissing,
    /// `UNATTESTED`.
    Unattested,
}

/// Where a record stands for the tally scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Disposition {
    /// Included.
    Include,
    /// Excluded for this reason.
    Exclude(Exclusion),
    /// Out-of-district record not yet resolved against the envelopes; the
    /// tally scope waits for the receipt resolution (§11.1).
    PendingReceipt,
    /// `RECEIVED_DAMAGED` or `WRONG_DISTRICT`: the district is under
    /// review and the law decides (§10.6 step 6). No machine transition
    /// resolves it.
    PendingLegal,
}

/// The state of one record on the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordState {
    profile: Profile,
    primary: Primary,
    attested: bool,
    share_missing: bool,
    test: bool,
}

impl RecordState {
    /// A record just observed: cast and not yet attested (`UNATTESTED`).
    /// `test` is whether its ballot style is a test style
    /// ([`is_test_style`]).
    #[must_use]
    pub const fn new(profile: Profile, test: bool) -> Self {
        Self {
            profile,
            primary: Primary::Cast,
            attested: false,
            share_missing: false,
            test,
        }
    }

    /// Any state, including unreachable ones, for unit tests and Kani
    /// harnesses only.
    #[cfg(any(test, kani))]
    pub(crate) const fn from_parts(
        profile: Profile,
        primary: Primary,
        attested: bool,
        share_missing: bool,
        test: bool,
    ) -> Self {
        Self {
            profile,
            primary,
            attested,
            share_missing,
            test,
        }
    }

    /// The box's collection profile.
    #[must_use]
    pub const fn profile(self) -> Profile {
        self.profile
    }

    /// The primary state.
    #[must_use]
    pub const fn primary(self) -> Primary {
        self.primary
    }

    /// Whether a batch attests the record.
    #[must_use]
    pub const fn is_attested(self) -> bool {
        self.attested
    }

    /// Whether a member share is missing (`SHARE_MISSING`).
    #[must_use]
    pub const fn is_share_missing(self) -> bool {
        self.share_missing
    }

    /// Whether the record is of a test ballot style (`TEST_BALLOT`).
    #[must_use]
    pub const fn is_test(self) -> bool {
        self.test
    }

    /// The status-vocabulary name of the primary state.
    #[must_use]
    pub const fn status(self) -> RecordStatus {
        match self.primary {
            Primary::Cast => {
                if self.attested {
                    RecordStatus::CastCommitted
                } else {
                    RecordStatus::Unattested
                }
            }
            Primary::ChallengedSpoiled => RecordStatus::ChallengedSpoiled,
            Primary::Quarantined => RecordStatus::Quarantined,
            Primary::Receipt(Receipt::Received) => RecordStatus::Received,
            Primary::Receipt(Receipt::Damaged) => RecordStatus::ReceivedDamaged,
            Primary::Receipt(Receipt::Late) => RecordStatus::ReceivedLate,
            Primary::Receipt(Receipt::WrongDistrict) => RecordStatus::WrongDistrict,
            Primary::Receipt(Receipt::NotReceived) => RecordStatus::CastNotReceived,
        }
    }

    /// Applies `event`.
    ///
    /// * `BatchAttested`: a cast or resolved record not yet attested
    ///   (exactly one batch per record, VC-053).
    /// * `Challenged`, `Quarantined`: a cast record not yet attested;
    ///   a receipt-scan record cannot be challenged (§17).
    /// * `ShareMissing`: a cast or resolved record, once.
    /// * `Receipt`: an unresolved out-of-district record.
    ///
    /// What it does not prove: that the event's evidence is genuine; the
    /// caller applies an event only after verifying its object.
    ///
    /// # Errors
    /// [`Error::Profile`] for a challenge in a receipt-scan box or a
    /// receipt outside the out-of-district profile,
    /// [`Error::RecordTransition`] for any other event that does not apply.
    pub const fn apply(self, event: RecordEvent) -> Result<Self, Error> {
        let refused = Err(Error::RecordTransition {
            from: self.primary,
            event,
        });
        let live = matches!(self.primary, Primary::Cast | Primary::Receipt(_));
        let fresh = matches!(self.primary, Primary::Cast) && !self.attested;
        match event {
            RecordEvent::BatchAttested => {
                if live && !self.attested {
                    Ok(Self {
                        attested: true,
                        ..self
                    })
                } else {
                    refused
                }
            }
            RecordEvent::Challenged => {
                if matches!(self.profile, Profile::ReceiptScan) {
                    Err(Error::Profile)
                } else if fresh {
                    Ok(Self {
                        primary: Primary::ChallengedSpoiled,
                        ..self
                    })
                } else {
                    refused
                }
            }
            RecordEvent::Quarantined => {
                if fresh {
                    Ok(Self {
                        primary: Primary::Quarantined,
                        ..self
                    })
                } else {
                    refused
                }
            }
            RecordEvent::ShareMissing => {
                if live && !self.share_missing {
                    Ok(Self {
                        share_missing: true,
                        ..self
                    })
                } else {
                    refused
                }
            }
            RecordEvent::Receipt(receipt) => {
                if !matches!(self.profile, Profile::Absentee) {
                    Err(Error::Profile)
                } else if matches!(self.primary, Primary::Cast) {
                    Ok(Self {
                        primary: Primary::Receipt(receipt),
                        ..self
                    })
                } else {
                    refused
                }
            }
        }
    }

    /// The record's tally disposition.
    ///
    /// Precedence: a test ballot is excluded first (VC-055); then the
    /// primary-state exclusions; then `SHARE_MISSING`, then `UNATTESTED`;
    /// only a record that every exclusion would admit can be pending. When
    /// several reasons hold, §11.1 does not say which one the tally scope
    /// cites (ADR-0025, spec gap 3).
    ///
    /// `UNATTESTED` is final only after the late-close window
    /// ([`crate::tally::admit_tally_scope`], VC-057).
    #[must_use]
    pub const fn disposition(self) -> Disposition {
        if self.test {
            return Disposition::Exclude(Exclusion::TestBallot);
        }
        let pending = match self.primary {
            Primary::ChallengedSpoiled => {
                return Disposition::Exclude(Exclusion::ChallengedSpoiled);
            }
            Primary::Quarantined => return Disposition::Exclude(Exclusion::Quarantined),
            Primary::Receipt(Receipt::NotReceived) => {
                return Disposition::Exclude(Exclusion::CastNotReceived);
            }
            Primary::Receipt(Receipt::Late) => {
                return Disposition::Exclude(Exclusion::ReceivedLate);
            }
            Primary::Receipt(Receipt::Damaged | Receipt::WrongDistrict) => {
                Some(Disposition::PendingLegal)
            }
            Primary::Receipt(Receipt::Received) => None,
            Primary::Cast => {
                if matches!(self.profile, Profile::Absentee) {
                    Some(Disposition::PendingReceipt)
                } else {
                    None
                }
            }
        };
        if self.share_missing {
            Disposition::Exclude(Exclusion::ShareMissing)
        } else if !self.attested {
            Disposition::Exclude(Exclusion::Unattested)
        } else if let Some(pending) = pending {
            pending
        } else {
            Disposition::Include
        }
    }
}

#[cfg(test)]
mod tests {
    use ityv_encoding::BallotStyleId;

    use super::{
        Disposition, Exclusion, Primary, Profile, Receipt, RecordEvent, RecordState, RecordStatus,
        is_test_style,
    };
    use crate::error::Error;

    const PROFILES: [Profile; 3] = [Profile::InPerson, Profile::Absentee, Profile::ReceiptScan];
    const RECEIPTS: [Receipt; 5] = [
        Receipt::Received,
        Receipt::Damaged,
        Receipt::Late,
        Receipt::WrongDistrict,
        Receipt::NotReceived,
    ];

    fn events() -> std::vec::Vec<RecordEvent> {
        let mut all = std::vec![
            RecordEvent::BatchAttested,
            RecordEvent::Challenged,
            RecordEvent::Quarantined,
            RecordEvent::ShareMissing,
        ];
        all.extend(RECEIPTS.iter().map(|r| RecordEvent::Receipt(*r)));
        all
    }

    fn apply(state: RecordState, event: RecordEvent) -> RecordState {
        state.apply(event).unwrap()
    }

    #[test]
    fn test_styles() {
        assert!(is_test_style(BallotStyleId::new(b"TEST-1").unwrap()));
        assert!(!is_test_style(BallotStyleId::new(b"S-1").unwrap()));
        assert!(!is_test_style(BallotStyleId::new(b"TEST").unwrap()));
        assert!(!is_test_style(BallotStyleId::new(b"XTEST-1").unwrap()));
    }

    #[test]
    fn new_record_is_unattested() {
        for profile in PROFILES {
            let state = RecordState::new(profile, false);
            assert_eq!(state.profile(), profile);
            assert_eq!(state.primary(), Primary::Cast);
            assert!(!state.is_attested());
            assert!(!state.is_share_missing());
            assert!(!state.is_test());
            assert_eq!(state.status(), RecordStatus::Unattested);
            assert_eq!(
                state.disposition(),
                Disposition::Exclude(Exclusion::Unattested)
            );
            assert!(RecordState::new(profile, true).is_test());
        }
    }

    #[test]
    fn in_person_paths() {
        let cast = RecordState::new(Profile::InPerson, false);
        let committed = apply(cast, RecordEvent::BatchAttested);
        assert!(committed.is_attested());
        assert_eq!(committed.status(), RecordStatus::CastCommitted);
        assert_eq!(committed.disposition(), Disposition::Include);
        let spoiled = apply(cast, RecordEvent::Challenged);
        assert_eq!(spoiled.status(), RecordStatus::ChallengedSpoiled);
        assert_eq!(
            spoiled.disposition(),
            Disposition::Exclude(Exclusion::ChallengedSpoiled)
        );
        let quarantined = apply(cast, RecordEvent::Quarantined);
        assert_eq!(quarantined.status(), RecordStatus::Quarantined);
        assert_eq!(
            quarantined.disposition(),
            Disposition::Exclude(Exclusion::Quarantined)
        );
        let missing = apply(committed, RecordEvent::ShareMissing);
        assert!(missing.is_share_missing());
        assert_eq!(missing.status(), RecordStatus::CastCommitted);
        assert_eq!(
            missing.disposition(),
            Disposition::Exclude(Exclusion::ShareMissing)
        );
        let missing_unattested = apply(cast, RecordEvent::ShareMissing);
        assert_eq!(
            missing_unattested.disposition(),
            Disposition::Exclude(Exclusion::ShareMissing)
        );
        assert_eq!(
            apply(missing_unattested, RecordEvent::BatchAttested).disposition(),
            Disposition::Exclude(Exclusion::ShareMissing)
        );
        let test = apply(
            RecordState::new(Profile::InPerson, true),
            RecordEvent::BatchAttested,
        );
        assert_eq!(
            test.disposition(),
            Disposition::Exclude(Exclusion::TestBallot)
        );
    }

    #[test]
    fn refused_transitions() {
        let cast = RecordState::new(Profile::InPerson, false);
        let committed = apply(cast, RecordEvent::BatchAttested);
        for event in [
            RecordEvent::BatchAttested,
            RecordEvent::Challenged,
            RecordEvent::Quarantined,
        ] {
            assert_eq!(
                committed.apply(event),
                Err(Error::RecordTransition {
                    from: Primary::Cast,
                    event
                })
            );
        }
        let missing = apply(committed, RecordEvent::ShareMissing);
        assert!(missing.apply(RecordEvent::ShareMissing).is_err());
        for terminal in [
            apply(cast, RecordEvent::Challenged),
            apply(cast, RecordEvent::Quarantined),
        ] {
            for event in events() {
                if matches!(event, RecordEvent::Receipt(_)) {
                    assert_eq!(terminal.apply(event), Err(Error::Profile));
                } else {
                    assert_eq!(
                        terminal.apply(event),
                        Err(Error::RecordTransition {
                            from: terminal.primary(),
                            event
                        })
                    );
                }
            }
        }
        for receipt in RECEIPTS {
            assert_eq!(
                cast.apply(RecordEvent::Receipt(receipt)),
                Err(Error::Profile)
            );
            assert_eq!(
                RecordState::new(Profile::ReceiptScan, false).apply(RecordEvent::Receipt(receipt)),
                Err(Error::Profile)
            );
        }
        let scan = RecordState::new(Profile::ReceiptScan, false);
        assert_eq!(scan.apply(RecordEvent::Challenged), Err(Error::Profile));
        assert_eq!(
            apply(scan, RecordEvent::BatchAttested).disposition(),
            Disposition::Include
        );
        assert_eq!(
            apply(scan, RecordEvent::Quarantined).status(),
            RecordStatus::Quarantined
        );
    }

    #[test]
    fn absentee_paths() {
        let cast = RecordState::new(Profile::Absentee, false);
        let committed = apply(cast, RecordEvent::BatchAttested);
        assert_eq!(committed.disposition(), Disposition::PendingReceipt);
        let expected = [
            (
                Receipt::Received,
                RecordStatus::Received,
                Disposition::Include,
            ),
            (
                Receipt::Damaged,
                RecordStatus::ReceivedDamaged,
                Disposition::PendingLegal,
            ),
            (
                Receipt::Late,
                RecordStatus::ReceivedLate,
                Disposition::Exclude(Exclusion::ReceivedLate),
            ),
            (
                Receipt::WrongDistrict,
                RecordStatus::WrongDistrict,
                Disposition::PendingLegal,
            ),
            (
                Receipt::NotReceived,
                RecordStatus::CastNotReceived,
                Disposition::Exclude(Exclusion::CastNotReceived),
            ),
        ];
        for (receipt, status, disposition) in expected {
            let resolved = apply(committed, RecordEvent::Receipt(receipt));
            assert_eq!(resolved.primary(), Primary::Receipt(receipt));
            assert_eq!(resolved.status(), status);
            assert_eq!(resolved.disposition(), disposition);
            assert!(!status.name().is_empty());
            // Resolved once only.
            assert!(resolved.apply(RecordEvent::Receipt(receipt)).is_err());
            assert!(resolved.apply(RecordEvent::Challenged).is_err());
            assert!(resolved.apply(RecordEvent::Quarantined).is_err());
            // A resolved record can still lose a share.
            let missing = apply(resolved, RecordEvent::ShareMissing);
            assert!(missing.is_share_missing());
            // Resolution before the (late) batch, then the batch.
            let early = apply(cast, RecordEvent::Receipt(receipt));
            let late = apply(early, RecordEvent::BatchAttested);
            assert_eq!(late.disposition(), disposition);
        }
        // Unattested damaged record: the hard exclusion wins over pending.
        let unattested = apply(cast, RecordEvent::Receipt(Receipt::Damaged));
        assert_eq!(
            unattested.disposition(),
            Disposition::Exclude(Exclusion::Unattested)
        );
        assert_eq!(
            apply(cast, RecordEvent::Challenged).status(),
            RecordStatus::ChallengedSpoiled
        );
    }

    #[test]
    fn from_parts_builds_the_given_state() {
        let reached = apply(
            apply(
                RecordState::new(Profile::Absentee, true),
                RecordEvent::BatchAttested,
            ),
            RecordEvent::ShareMissing,
        );
        let built = RecordState::from_parts(Profile::Absentee, Primary::Cast, true, true, true);
        assert_eq!(built, reached);
        let built =
            RecordState::from_parts(Profile::InPerson, Primary::Quarantined, false, false, false);
        assert_eq!(built.primary(), Primary::Quarantined);
        assert_eq!(built.profile(), Profile::InPerson);
    }

    #[test]
    fn status_names() {
        let names = [
            (RecordStatus::CastCommitted, "CAST_COMMITTED"),
            (RecordStatus::Unattested, "UNATTESTED"),
            (RecordStatus::Received, "RECEIVED"),
            (RecordStatus::ReceivedDamaged, "RECEIVED_DAMAGED"),
            (RecordStatus::ReceivedLate, "RECEIVED_LATE"),
            (RecordStatus::WrongDistrict, "WRONG_DISTRICT"),
            (RecordStatus::CastNotReceived, "CAST_NOT_RECEIVED"),
            (RecordStatus::ChallengedSpoiled, "CHALLENGED_SPOILED"),
            (RecordStatus::Quarantined, "QUARANTINED"),
        ];
        for (status, name) in names {
            assert_eq!(status.name(), name);
        }
    }
}
