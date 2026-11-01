//! The dispute life cycle (PROTOCOL.md §13).
//!
//! A dispute is filed only with the signatures of both the election
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
//! Every step is a `DisputeEvent` (`DisputeEventBody`, schema `0x000E`)
//! signed by both bodies, whose keys share no half (VC-006, VC-098). A
//! later event names the filing by the object hash of its body and repeats
//! its type and target. A technical resolution can still be appealed to the
//! legal track (ITYV-BEH-136, ITYV-BEH-138). `REFERRED_LEGAL` is final for
//! the machine and stays unresolved for it: the legal decision enters only
//! as a `LegalDecisionRef` ([`crate::status::LegalReference`]), shown next
//! to the status, and no machine transition produces `LEGAL_CERTIFIED` or
//! invalidates a record (VC-049, ITYV-BEH-140, ITYV-BEH-279).
//!
//! An inclusion dispute (`INCLUSION_MISSING`) exists only from stage 3 and
//! takes the `VOTER_CODE` capability; every other type takes `PUBLIC_BOARD`
//! from stage 0 (§17).

use ityv_crypto::HybridVerifyingKey;
use ityv_crypto::hash::object_hash;
use ityv_encoding::{
    BoxId, DisputeAction, DisputeEventBody, DisputeEventParts, ElectionId, EventRole, Hash512,
    SCHEMA_DISPUTE_EVENT_BODY, Scope,
};

pub use ityv_encoding::DisputeType;

use crate::auth::{Cap, PublicBoard, VoterCode};
use crate::error::Error;
use crate::sig::{Signed, check_event, halves_differ};

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

/// The keys the genesis registers for the two bodies that sign every
/// dispute event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bodies<'k> {
    /// The election commission (선관위).
    pub commission: &'k HybridVerifyingKey,
    /// The Independent Verification Committee (독립검증위원회).
    pub committee: &'k HybridVerifyingKey,
}

/// A dispute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dispute<'a> {
    election_id: ElectionId<'a>,
    kind: DisputeType,
    box_id: Option<BoxId<'a>>,
    record_hash: Option<Hash512>,
    evidence_hash: Hash512,
    filing_hash: Hash512,
    status: DisputeStatus,
}

/// Checks both bodies' signatures on a dispute event.
fn check_bodies(signed: &Signed<'_>, bodies: &Bodies<'_>) -> Result<(), Error> {
    if !halves_differ(bodies.commission, bodies.committee) {
        return Err(Error::SignatureSigner);
    }
    // The envelope admits a dispute event only with exactly one commission
    // and one committee signature (`ityv_encoding::roles_satisfied`).
    check_event(signed, |s| match s.role {
        EventRole::Commission => Ok(bodies.commission),
        EventRole::Committee => Ok(bodies.committee),
        EventRole::Clerk
        | EventRole::Observer
        | EventRole::Sender
        | EventRole::Receiver
        | EventRole::Authority
        | EventRole::Device => Err(Error::NotRegistered),
    })
}

fn decode<'a>(signed: &Signed<'a>) -> Result<DisputeEventParts<'a>, Error> {
    let body: DisputeEventBody<'a> = signed
        .event
        .body(SCHEMA_DISPUTE_EVENT_BODY)
        .map_err(|_| Error::Decode)?;
    Ok(*body.parts())
}

impl<'a> Dispute<'a> {
    fn filed(
        signed: &Signed<'a>,
        bodies: &Bodies<'_>,
        election_id: ElectionId<'_>,
        inclusion: bool,
    ) -> Result<Self, Error> {
        let p = decode(signed)?;
        if p.election_id.as_bytes() != election_id.as_bytes() {
            return Err(Error::Mismatch);
        }
        if !matches!(p.action, DisputeAction::Filed) {
            return Err(Error::DisputeFiling);
        }
        match (
            inclusion,
            matches!(p.dispute_type, DisputeType::InclusionMissing),
        ) {
            (false, true) => return Err(Error::ScopeMissing(Scope::VoterCode)),
            (true, false) => return Err(Error::Mismatch),
            (false, false) | (true, true) => {}
        }
        check_bodies(signed, bodies)?;
        Ok(Self {
            election_id: p.election_id,
            kind: p.dispute_type,
            box_id: p.box_id,
            record_hash: p.record_hash,
            evidence_hash: p.evidence_hash,
            filing_hash: object_hash(signed.event.body_bytes()),
            status: DisputeStatus::Open,
        })
    }

    /// Files a dispute of any type but `INCLUSION_MISSING`.
    ///
    /// # Errors
    /// [`Error::Decode`] if the event is not a dispute event,
    /// [`Error::Mismatch`] if the capability belongs to another election,
    /// [`Error::DisputeFiling`] unless it is a filing (the envelope admits
    /// only one signature of each body), [`Error::ScopeMissing`] with
    /// `VOTER_CODE` for an inclusion
    /// dispute (use [`Self::file_inclusion`]), [`Error::SignatureSigner`]
    /// if the two bodies' keys share a half, and the errors of
    /// [`check_event`].
    pub fn file(
        signed: &Signed<'a>,
        bodies: &Bodies<'_>,
        cap: &Cap<'_, PublicBoard>,
    ) -> Result<Self, Error> {
        Self::filed(signed, bodies, cap.election_id(), false)
    }

    /// Files an inclusion dispute (stage 3, VC-048).
    ///
    /// # Errors
    /// As [`Self::file`]; [`Error::Mismatch`] for another type.
    pub fn file_inclusion(
        signed: &Signed<'a>,
        bodies: &Bodies<'_>,
        cap: &Cap<'_, VoterCode>,
    ) -> Result<Self, Error> {
        Self::filed(signed, bodies, cap.election_id(), true)
    }

    /// Applies a signed status change.
    ///
    /// # Errors
    /// [`Error::Decode`] if the event is not a dispute event,
    /// [`Error::Mismatch`] if it names another filing or changes the
    /// election, type, target or evidence, [`Error::DisputeFiling`] for a
    /// second filing, the signature errors of [`Self::file`], and
    /// [`Error::DisputeTransition`] if the change does not apply.
    pub fn record(self, signed: &Signed<'_>, bodies: &Bodies<'_>) -> Result<Self, Error> {
        let p = decode(signed)?;
        let same = p.election_id.as_bytes() == self.election_id.as_bytes()
            && p.filing_hash == self.filing_hash
            && p.dispute_type == self.kind
            && p.box_id.map(|b| b.as_bytes()) == self.box_id.map(|b| b.as_bytes())
            && p.record_hash == self.record_hash
            && p.evidence_hash == self.evidence_hash;
        if !same {
            return Err(Error::Mismatch);
        }
        let event = match p.action {
            DisputeAction::Filed => return Err(Error::DisputeFiling),
            DisputeAction::Investigating => DisputeEvent::Investigate,
            DisputeAction::ResolvedTechnical => DisputeEvent::ResolveTechnical,
            DisputeAction::ReferredLegal => DisputeEvent::ReferLegal,
        };
        check_bodies(signed, bodies)?;
        self.apply(event)
    }

    /// An open dispute without signatures, for unit tests and Kani
    /// harnesses only.
    #[cfg(any(test, kani))]
    pub(crate) const fn unsigned(election_id: ElectionId<'a>, kind: DisputeType) -> Self {
        Self {
            election_id,
            kind,
            box_id: None,
            record_hash: None,
            evidence_hash: Hash512::ZERO,
            filing_hash: Hash512([1; 64]),
            status: DisputeStatus::Open,
        }
    }

    /// The transition rule (no signature).
    ///
    /// # Errors
    /// [`Error::DisputeTransition`] if the change does not apply.
    pub(crate) const fn apply(self, event: DisputeEvent) -> Result<Self, Error> {
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

    /// The object hash of the filing body, by which later events and a
    /// `LegalDecisionRef` name the dispute.
    #[must_use]
    pub const fn filing_hash(&self) -> &Hash512 {
        &self.filing_hash
    }

    /// The status.
    #[must_use]
    pub const fn status(&self) -> DisputeStatus {
        self.status
    }

    /// Whether the dispute keeps the verifier in `HOLD_REVIEW` (§14 step
    /// 9). Only a technical resolution ends that; a dispute referred to the
    /// legal track stays unresolved for the machine whatever the court
    /// decides, and the machine status never becomes `LEGAL_CERTIFIED`
    /// (PROTOCOL.md §13).
    #[must_use]
    pub const fn is_unresolved(&self) -> bool {
        !matches!(self.status, DisputeStatus::ResolvedTechnical)
    }
}

#[cfg(test)]
mod tests {
    use ityv_encoding::ElectionId;

    use super::{Dispute, DisputeEvent, DisputeStatus, DisputeType};
    use crate::error::Error;

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

    proptest::proptest! {
        /// Random event sequences only move forward and never reopen.
        #[test]
        fn sequences(events in proptest::collection::vec(0u8..3, 0..8)) {
            let rank = |s: DisputeStatus| match s {
                DisputeStatus::Open => 0,
                DisputeStatus::Investigating => 1,
                DisputeStatus::ResolvedTechnical => 2,
                DisputeStatus::ReferredLegal => 3,
            };
            let mut dispute =
                Dispute::unsigned(ElectionId::new(b"E1").unwrap(), DisputeType::Other);
            for code in events {
                let event = match code {
                    0 => DisputeEvent::Investigate,
                    1 => DisputeEvent::ResolveTechnical,
                    _ => DisputeEvent::ReferLegal,
                };
                if let Ok(next) = dispute.apply(event) {
                    proptest::prop_assert!(rank(next.status()) > rank(dispute.status()));
                    proptest::prop_assert!(next.status() != DisputeStatus::Open);
                    dispute = next;
                }
            }
        }
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
        let open = Dispute::unsigned(ElectionId::new(b"E1").unwrap(), DisputeType::Custody);
        assert!(open.is_unresolved());
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
