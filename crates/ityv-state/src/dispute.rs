//! The dispute life cycle (PROTOCOL.md §13).
//!
//! A dispute is filed only with the receipt signatures of both the election
//! commission and the Independent Verification Committee (ITYV-BEH-135),
//! always starts `OPEN` (ITYV-BEH-133), and moves forward only:
//!
//! ```text
//! OPEN ──investigate──▶ INVESTIGATING
//!  │                        │
//!  ├──resolve_technical─────┼──▶ RESOLVED_TECHNICAL ──refer_legal (appeal)──┐
//!  └──refer_legal───────────┴──────────────────────────────────────────────▶ REFERRED_LEGAL
//! ```
//!
//! A technical resolution can still be appealed to the legal track
//! (ITYV-BEH-136, ITYV-BEH-138). `REFERRED_LEGAL` is final for the
//! machine: the legal decision enters only as a `LegalDecisionRef`
//! ([`crate::status::LegalReference`]), and no machine transition produces
//! `LEGAL_CERTIFIED` or invalidates a record (VC-049, ITYV-BEH-140,
//! ITYV-BEH-279).
//!
//! An inclusion dispute (`INCLUSION_MISSING`) exists only from stage 3 and
//! takes the `VOTER_CODE` capability; every other type takes
//! `PUBLIC_BOARD` (§17).
//!
//! `DisputeEvent` (schema `0x000E`) has no canonical encoding yet; the
//! filing is a minimal typed input (ADR-0025).

use ityv_encoding::{BoxId, ElectionId, Hash512, Scope};

use crate::auth::{Cap, PublicBoard, VoterCode};
use crate::error::Error;

/// The dispute types of §13.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DisputeType {
    /// `INCLUSION_MISSING`: a slip's tracking code is not on the board.
    InclusionMissing = 1,
    /// `COUNT_MISMATCH`.
    CountMismatch = 2,
    /// `CUSTODY`.
    Custody = 3,
    /// `CHALLENGE_FAIL`.
    ChallengeFail = 4,
    /// `POSTAL`.
    Postal = 5,
    /// `OTHER`.
    Other = 6,
    /// `SPLIT_VIEW` (VC-065).
    SplitView = 7,
    /// `BUILD_MISMATCH` (VC-091).
    BuildMismatch = 8,
}

impl DisputeType {
    /// Every type in code order.
    pub const ALL: [Self; 8] = [
        Self::InclusionMissing,
        Self::CountMismatch,
        Self::Custody,
        Self::ChallengeFail,
        Self::Postal,
        Self::Other,
        Self::SplitView,
        Self::BuildMismatch,
    ];

    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Returns the type with wire code `code`, if defined.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::InclusionMissing),
            2 => Some(Self::CountMismatch),
            3 => Some(Self::Custody),
            4 => Some(Self::ChallengeFail),
            5 => Some(Self::Postal),
            6 => Some(Self::Other),
            7 => Some(Self::SplitView),
            8 => Some(Self::BuildMismatch),
            _ => None,
        }
    }
}

/// The dispute statuses of §13.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisputeStatus {
    /// `OPEN`.
    Open,
    /// `INVESTIGATING`.
    Investigating,
    /// `RESOLVED_TECHNICAL`.
    ResolvedTechnical,
    /// `REFERRED_LEGAL`.
    ReferredLegal,
}

impl DisputeStatus {
    /// The vocabulary name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Open => "OPEN",
            Self::Investigating => "INVESTIGATING",
            Self::ResolvedTechnical => "RESOLVED_TECHNICAL",
            Self::ReferredLegal => "REFERRED_LEGAL",
        }
    }
}

/// A status change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DisputeEvent {
    /// Start the investigation.
    Investigate,
    /// Close as a technical matter.
    ResolveTechnical,
    /// Refer to the legal track (also the appeal of a technical
    /// resolution).
    ReferLegal,
}

/// A dispute filing (minimal input).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DisputeFiling<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The type.
    pub dispute_type: DisputeType,
    /// The box concerned, if any.
    pub box_id: Option<BoxId<'a>>,
    /// The record concerned, if any.
    pub record_hash: Option<Hash512>,
    /// Hash of the evidence (the original is restricted).
    pub evidence_hash: Hash512,
    /// Whether the election commission's receipt signature verified.
    pub commission_signed: bool,
    /// Whether the committee's receipt signature verified.
    pub committee_signed: bool,
}

/// A dispute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dispute<'a> {
    election_id: ElectionId<'a>,
    kind: DisputeType,
    box_id: Option<BoxId<'a>>,
    record_hash: Option<Hash512>,
    evidence_hash: Hash512,
    status: DisputeStatus,
}

impl<'a> Dispute<'a> {
    fn filed(filing: &DisputeFiling<'a>, election_id: ElectionId<'_>) -> Result<Self, Error> {
        if filing.election_id.as_bytes() != election_id.as_bytes() {
            return Err(Error::Mismatch);
        }
        if !(filing.commission_signed && filing.committee_signed) {
            return Err(Error::DisputeFiling);
        }
        Ok(Self {
            election_id: filing.election_id,
            kind: filing.dispute_type,
            box_id: filing.box_id,
            record_hash: filing.record_hash,
            evidence_hash: filing.evidence_hash,
            status: DisputeStatus::Open,
        })
    }

    /// Files a dispute of any type but `INCLUSION_MISSING`.
    ///
    /// # Errors
    /// [`Error::ScopeMissing`] with `VOTER_CODE` for an inclusion dispute
    /// (use [`Self::file_inclusion`]), [`Error::Mismatch`] if the
    /// capability belongs to another election, [`Error::DisputeFiling`]
    /// unless both bodies signed the receipt.
    pub fn file(filing: &DisputeFiling<'a>, cap: &Cap<'_, PublicBoard>) -> Result<Self, Error> {
        if matches!(filing.dispute_type, DisputeType::InclusionMissing) {
            return Err(Error::ScopeMissing(Scope::VoterCode));
        }
        Self::filed(filing, cap.election_id())
    }

    /// Files an inclusion dispute (stage 3, VC-048).
    ///
    /// # Errors
    /// [`Error::Mismatch`] for another type or another election,
    /// [`Error::DisputeFiling`] unless both bodies signed the receipt.
    pub fn file_inclusion(
        filing: &DisputeFiling<'a>,
        cap: &Cap<'_, VoterCode>,
    ) -> Result<Self, Error> {
        if !matches!(filing.dispute_type, DisputeType::InclusionMissing) {
            return Err(Error::Mismatch);
        }
        Self::filed(filing, cap.election_id())
    }

    /// Applies a status change.
    ///
    /// # Errors
    /// [`Error::DisputeTransition`] if the change does not apply.
    pub const fn apply(self, event: DisputeEvent) -> Result<Self, Error> {
        let next = match (self.status, event) {
            (DisputeStatus::Open, DisputeEvent::Investigate) => DisputeStatus::Investigating,
            (
                DisputeStatus::Open | DisputeStatus::Investigating,
                DisputeEvent::ResolveTechnical,
            ) => DisputeStatus::ResolvedTechnical,
            (
                DisputeStatus::Open
                | DisputeStatus::Investigating
                | DisputeStatus::ResolvedTechnical,
                DisputeEvent::ReferLegal,
            ) => DisputeStatus::ReferredLegal,
            (
                DisputeStatus::Investigating
                | DisputeStatus::ResolvedTechnical
                | DisputeStatus::ReferredLegal,
                DisputeEvent::Investigate,
            )
            | (
                DisputeStatus::ResolvedTechnical | DisputeStatus::ReferredLegal,
                DisputeEvent::ResolveTechnical,
            )
            | (DisputeStatus::ReferredLegal, DisputeEvent::ReferLegal) => {
                return Err(Error::DisputeTransition {
                    from: self.status,
                    event,
                });
            }
        };
        Ok(Self {
            status: next,
            ..self
        })
    }

    /// The election.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.election_id
    }

    /// The type.
    #[must_use]
    pub const fn dispute_type(&self) -> DisputeType {
        self.kind
    }

    /// The box concerned.
    #[must_use]
    pub const fn box_id(&self) -> Option<BoxId<'a>> {
        self.box_id
    }

    /// The record concerned.
    #[must_use]
    pub const fn record_hash(&self) -> Option<&Hash512> {
        self.record_hash.as_ref()
    }

    /// The evidence hash.
    #[must_use]
    pub const fn evidence_hash(&self) -> &Hash512 {
        &self.evidence_hash
    }

    /// The status.
    #[must_use]
    pub const fn status(&self) -> DisputeStatus {
        self.status
    }

    /// Whether the dispute keeps the verifier in `HOLD_REVIEW` (§14 step
    /// 9). Only a technical resolution ends that; a dispute referred to the
    /// legal track stays unresolved for the machine, whose status never
    /// becomes `LEGAL_CERTIFIED` (ADR-0025, spec gap 8).
    #[must_use]
    pub const fn is_unresolved(&self) -> bool {
        !matches!(self.status, DisputeStatus::ResolvedTechnical)
    }
}

#[cfg(test)]
mod tests {
    use ityv_encoding::{BoxId, Day, ElectionId, Hash512, Scope, ScopeSet};

    use super::{Dispute, DisputeEvent, DisputeFiling, DisputeStatus, DisputeType};
    use crate::auth::{Authorization, PublicBoard, VoterCode};
    use crate::error::Error;

    fn auth() -> Authorization<'static> {
        Authorization::unsigned(
            ElectionId::new(b"E1").unwrap(),
            ScopeSet::from_slice(&[
                Scope::PublicBoard,
                Scope::TrusteeBody,
                Scope::BallotMark,
                Scope::VoterCode,
            ]),
            Day::new(0),
            Day::new(9),
        )
    }

    fn filing(dispute_type: DisputeType) -> DisputeFiling<'static> {
        DisputeFiling {
            election_id: ElectionId::new(b"E1").unwrap(),
            dispute_type,
            box_id: Some(BoxId::new(b"B1").unwrap()),
            record_hash: Some(Hash512([3; 64])),
            evidence_hash: Hash512([4; 64]),
            commission_signed: true,
            committee_signed: true,
        }
    }

    #[test]
    fn codes() {
        for (index, t) in DisputeType::ALL.iter().enumerate() {
            assert_eq!(usize::from(t.code()), index + 1);
            assert_eq!(DisputeType::from_code(t.code()), Some(*t));
        }
        assert_eq!(DisputeType::from_code(0), None);
        assert_eq!(DisputeType::from_code(9), None);
        assert_eq!(DisputeStatus::Open.name(), "OPEN");
        assert_eq!(DisputeStatus::Investigating.name(), "INVESTIGATING");
        assert_eq!(
            DisputeStatus::ResolvedTechnical.name(),
            "RESOLVED_TECHNICAL"
        );
        assert_eq!(DisputeStatus::ReferredLegal.name(), "REFERRED_LEGAL");
    }

    #[test]
    fn filing_rules() {
        let a = auth();
        let board = a.grant::<PublicBoard>(Day::new(1)).unwrap();
        let code = a.grant::<VoterCode>(Day::new(1)).unwrap();
        for t in DisputeType::ALL {
            let f = filing(t);
            if t == DisputeType::InclusionMissing {
                assert_eq!(
                    Dispute::file(&f, &board),
                    Err(Error::ScopeMissing(Scope::VoterCode))
                );
                let d = Dispute::file_inclusion(&f, &code).unwrap();
                assert_eq!(d.status(), DisputeStatus::Open);
                assert_eq!(d.dispute_type(), t);
            } else {
                assert_eq!(Dispute::file_inclusion(&f, &code), Err(Error::Mismatch));
                let d = Dispute::file(&f, &board).unwrap();
                assert_eq!(d.status(), DisputeStatus::Open);
                assert!(d.is_unresolved());
                assert_eq!(d.election_id(), f.election_id);
                assert_eq!(d.box_id(), f.box_id);
                assert_eq!(d.record_hash(), f.record_hash.as_ref());
                assert_eq!(d.evidence_hash(), &f.evidence_hash);
            }
        }
        for (commission, committee) in [(false, true), (true, false), (false, false)] {
            let f = DisputeFiling {
                commission_signed: commission,
                committee_signed: committee,
                ..filing(DisputeType::Other)
            };
            assert_eq!(Dispute::file(&f, &board), Err(Error::DisputeFiling));
            let f = DisputeFiling {
                dispute_type: DisputeType::InclusionMissing,
                ..f
            };
            assert_eq!(
                Dispute::file_inclusion(&f, &code),
                Err(Error::DisputeFiling)
            );
        }
        let elsewhere = DisputeFiling {
            election_id: ElectionId::new(b"E2").unwrap(),
            ..filing(DisputeType::Other)
        };
        assert_eq!(Dispute::file(&elsewhere, &board), Err(Error::Mismatch));
        let elsewhere = DisputeFiling {
            dispute_type: DisputeType::InclusionMissing,
            ..elsewhere
        };
        assert_eq!(
            Dispute::file_inclusion(&elsewhere, &code),
            Err(Error::Mismatch)
        );
    }

    #[test]
    fn transitions() {
        use DisputeEvent::{Investigate, ReferLegal, ResolveTechnical};
        use DisputeStatus::{Investigating, Open, ReferredLegal, ResolvedTechnical};
        let table = [
            (Open, Investigate, Some(Investigating)),
            (Open, ResolveTechnical, Some(ResolvedTechnical)),
            (Open, ReferLegal, Some(ReferredLegal)),
            (Investigating, Investigate, None),
            (Investigating, ResolveTechnical, Some(ResolvedTechnical)),
            (Investigating, ReferLegal, Some(ReferredLegal)),
            (ResolvedTechnical, Investigate, None),
            (ResolvedTechnical, ResolveTechnical, None),
            (ResolvedTechnical, ReferLegal, Some(ReferredLegal)),
            (ReferredLegal, Investigate, None),
            (ReferredLegal, ResolveTechnical, None),
            (ReferredLegal, ReferLegal, None),
        ];
        let a = auth();
        let board = a.grant::<PublicBoard>(Day::new(1)).unwrap();
        let open = Dispute::file(&filing(DisputeType::Custody), &board).unwrap();
        for (from, event, to) in table {
            let path: &[DisputeEvent] = match from {
                Open => &[],
                Investigating => &[Investigate],
                ResolvedTechnical => &[ResolveTechnical],
                ReferredLegal => &[ReferLegal],
            };
            let start = path.iter().fold(open, |d, e| d.apply(*e).unwrap());
            assert_eq!(start.status(), from);
            match to {
                Some(to) => {
                    let next = start.apply(event).unwrap();
                    assert_eq!(next.status(), to);
                    assert_eq!(next.is_unresolved(), to != ResolvedTechnical);
                }
                None => assert_eq!(
                    start.apply(event),
                    Err(Error::DisputeTransition { from, event })
                ),
            }
        }
    }
}
