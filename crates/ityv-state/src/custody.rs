//! The custody chain of a closed box (PROTOCOL.md §10.3, VC-040).
//!
//! Handoffs are numbered from 1, each names the previous one by its body's
//! object hash (the first names zero), sender and receiver belong to
//! different organisations, both sign, and the organisations follow the
//! route the genesis fixes for the box. The receiver of one handoff is the
//! sender of the next, as the same person of the same organisation. A
//! malformed link is refused; a count or seal that does not match is
//! accepted and leaves a sticky hold, because the paper still has to be
//! found (§10.3: "그 이벤트가 없는 봉인 불일치는 `HOLD_REVIEW`").
//!
//! A handoff is a [`WitnessedEvent`](ityv_encoding::WitnessedEvent) with a
//! `CustodyHandoffBody` (schema `0x0008`), signed by the sender and the
//! receiver; a seal change carries a `SealChangeBody` (`0x002D`) signed by
//! two clerks and observers of two organisations. Every signature must
//! come with a verification token from the key the roster registers.

use ityv_crypto::HybridVerifyingKey;
use ityv_crypto::hash::object_hash;
use ityv_encoding::{
    BoxId, CustodyHandoffBody, CustodyHandoffParts, ElectionId, EventRole, Hash512, OrgId,
    RosterRole, SCHEMA_CUSTODY_HANDOFF_BODY, SCHEMA_SEAL_CHANGE_BODY, SealChangeBody,
    SealChangeParts, SealChangeReason, SignerId,
};

use crate::close::{RosterEntry, check_witnesses};
use crate::error::Error;
use crate::hold::{HoldReason, HoldSet};
use crate::sig::{Signed, check_event};

/// The key of a person who may sign a custody handoff: registered with
/// that identifier and organisation as a clerk or a custodian.
fn custody_key<'r>(
    roster: &'r [RosterEntry<'r>],
    id: SignerId<'_>,
    org: OrgId<'_>,
) -> Result<&'r HybridVerifyingKey, Error> {
    roster
        .iter()
        .find(|r| {
            r.signer_id.as_bytes() == id.as_bytes()
                && r.org_id.as_bytes() == org.as_bytes()
                && matches!(r.role, RosterRole::Clerk | RosterRole::Custodian)
        })
        .map(|r| r.key)
        .ok_or(Error::NotRegistered)
}

/// The custody chain of one box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyChain<'a> {
    election_id: ElectionId<'a>,
    box_id: BoxId<'a>,
    route: &'a [OrgId<'a>],
    handoffs: u32,
    last_hash: Hash512,
    last_receiver: Option<(SignerId<'a>, OrgId<'a>)>,
    seal: Hash512,
    announced_seal: Option<Hash512>,
    expected_count: u64,
    holds: HoldSet,
}

impl<'a> CustodyChain<'a> {
    /// A chain for a box closed with `seal` and `expected_count`, along
    /// `route` (the organisations in order, from the polling station to the
    /// counting centre).
    ///
    /// # Errors
    /// [`Error::CustodyRoute`] if the route has fewer than two stops.
    pub const fn new(
        election_id: ElectionId<'a>,
        box_id: BoxId<'a>,
        route: &'a [OrgId<'a>],
        seal: Hash512,
        expected_count: u64,
    ) -> Result<Self, Error> {
        if route.len() < 2 {
            return Err(Error::CustodyRoute);
        }
        Ok(Self {
            election_id,
            box_id,
            route,
            handoffs: 0,
            last_hash: Hash512::ZERO,
            last_receiver: None,
            seal,
            announced_seal: None,
            expected_count,
            holds: HoldSet::empty(),
        })
    }

    fn check_target(&self, election_id: ElectionId<'_>, box_id: BoxId<'_>) -> Result<(), Error> {
        if election_id.as_bytes() == self.election_id.as_bytes()
            && box_id.as_bytes() == self.box_id.as_bytes()
        {
            Ok(())
        } else {
            Err(Error::Mismatch)
        }
    }

    /// Records a signed seal change, which explains the next handoff whose
    /// seal digest is the new one. A seal found broken leaves
    /// [`HoldReason::SealBroken`].
    ///
    /// # Errors
    /// [`Error::Decode`] if the event is not a seal change,
    /// [`Error::Mismatch`] for another box, the errors of
    /// [`check_witnesses`], [`Error::CustodySeal`] if the previous digest
    /// is not the chain's current seal.
    pub fn seal_change(
        &mut self,
        signed: &Signed<'_>,
        roster: &[RosterEntry<'_>],
    ) -> Result<(), Error> {
        let body: SealChangeBody<'_> = signed
            .event
            .body(SCHEMA_SEAL_CHANGE_BODY)
            .map_err(|_| Error::Decode)?;
        let parts = body.parts();
        self.check_target(parts.election_id, parts.box_id)?;
        check_witnesses(signed, roster, None)?;
        self.announce(parts)
    }

    /// The link rules of a seal change, without signatures.
    pub(crate) fn announce(&mut self, change: &SealChangeParts<'_>) -> Result<(), Error> {
        self.check_target(change.election_id, change.box_id)?;
        if change.previous_seal_digest != self.seal {
            return Err(Error::CustodySeal);
        }
        self.announced_seal = Some(change.new_seal_digest);
        self.holds = self.holds.with_if(
            matches!(change.reason, SealChangeReason::Broken),
            HoldReason::SealBroken,
        );
        Ok(())
    }

    /// Appends a signed handoff: the sender's and the receiver's
    /// signatures with tokens from the keys the roster registers for the
    /// persons and organisations the body names.
    ///
    /// # Errors
    /// [`Error::Decode`] if the event is not a handoff,
    /// [`Error::NotRegistered`] for a signer the roster does not register
    /// as that person of that organisation (clerk or custodian), the errors
    /// of [`check_event`], and those of the link rules:
    /// [`Error::Mismatch`] for another box, [`Error::CustodyIndex`] if the
    /// index is not the next one, [`Error::CustodyPrevious`] if it does not
    /// name the previous handoff or its sender is not the previous
    /// receiver, [`Error::CustodySameOrganisation`] if both sides are one
    /// organisation, [`Error::CustodyRoute`] if it leaves the route,
    /// [`Error::Overflow`].
    pub fn handoff(
        &mut self,
        signed: &Signed<'a>,
        roster: &[RosterEntry<'_>],
    ) -> Result<(), Error> {
        let event = signed.event;
        let body: CustodyHandoffBody<'a> = event
            .body(SCHEMA_CUSTODY_HANDOFF_BODY)
            .map_err(|_| Error::Decode)?;
        let parts = *body.parts();
        self.check_target(parts.election_id, parts.box_id)?;
        check_event(signed, |s| {
            let (id, org) = match s.role {
                EventRole::Sender => (parts.from_signer, parts.from_org),
                EventRole::Receiver => (parts.to_signer, parts.to_org),
                EventRole::Clerk
                | EventRole::Observer
                | EventRole::Commission
                | EventRole::Committee
                | EventRole::Authority
                | EventRole::Device => return Err(Error::NotRegistered),
            };
            if s.signer_id.as_bytes() != id.as_bytes() || s.org_id.as_bytes() != org.as_bytes() {
                return Err(Error::NotRegistered);
            }
            custody_key(roster, id, org)
        })?;
        // The envelope admits a handoff only with exactly one sender and one
        // receiver signature (`ityv_encoding::roles_satisfied`).
        self.link(&parts, object_hash(event.body_bytes()))
    }

    /// The link rules of a handoff whose body has object hash `hash`,
    /// without signatures.
    pub(crate) fn link(&mut self, h: &CustodyHandoffParts<'a>, hash: Hash512) -> Result<(), Error> {
        self.check_target(h.election_id, h.box_id)?;
        let expected = self.handoffs.checked_add(1).ok_or(Error::Overflow)?;
        if h.index != expected {
            return Err(Error::CustodyIndex {
                expected,
                got: h.index,
            });
        }
        if h.previous_handoff_hash != self.last_hash {
            return Err(Error::CustodyPrevious);
        }
        if let Some((id, org)) = &self.last_receiver
            && (id.as_bytes() != h.from_signer.as_bytes()
                || org.as_bytes() != h.from_org.as_bytes())
        {
            return Err(Error::CustodyPrevious);
        }
        if h.from_org.as_bytes() == h.to_org.as_bytes() {
            return Err(Error::CustodySameOrganisation);
        }
        let stop = usize::try_from(self.handoffs).map_err(|_| Error::Overflow)?;
        let next = stop.checked_add(1).ok_or(Error::Overflow)?;
        let on_route = if let (Some(from), Some(to)) = (self.route.get(stop), self.route.get(next))
        {
            from.as_bytes() == h.from_org.as_bytes() && to.as_bytes() == h.to_org.as_bytes()
        } else {
            false
        };
        if !on_route {
            return Err(Error::CustodyRoute);
        }
        if h.seal_digest != self.seal {
            let explained = self.announced_seal == Some(h.seal_digest);
            self.holds = self
                .holds
                .with_if(!explained, HoldReason::CustodySealUnexplained);
            self.seal = h.seal_digest;
            self.announced_seal = None;
        }
        self.holds = self.holds.with_if(
            h.count != self.expected_count,
            HoldReason::CustodyCountMismatch,
        );
        self.handoffs = expected;
        self.last_hash = hash;
        self.last_receiver = Some((h.to_signer, h.to_org));
        Ok(())
    }

    /// Number of handoffs so far.
    #[must_use]
    pub const fn handoffs(&self) -> u32 {
        self.handoffs
    }

    /// The current seal digest.
    #[must_use]
    pub const fn seal(&self) -> &Hash512 {
        &self.seal
    }

    /// Whether the chain has reached the end of the route.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        usize::try_from(self.handoffs)
            .ok()
            .and_then(|h| h.checked_add(1))
            == Some(self.route.len())
    }

    /// The custody holds so far.
    #[must_use]
    pub const fn holds(&self) -> HoldSet {
        self.holds
    }
}

#[cfg(test)]
mod tests {
    use ityv_encoding::{
        BoxId, CustodyHandoffParts, ElectionId, Hash512, OrgId, SealChangeParts, SealChangeReason,
        SignerId, TimeBucket,
    };

    use super::CustodyChain;
    use crate::error::Error;
    use crate::hold::{HoldReason, HoldSet};

    fn election() -> ElectionId<'static> {
        ElectionId::new(b"E1").unwrap()
    }

    fn box_id() -> BoxId<'static> {
        BoxId::new(b"B1").unwrap()
    }

    fn org(name: &'static [u8]) -> OrgId<'static> {
        OrgId::new(name).unwrap()
    }

    fn id(name: &'static [u8]) -> SignerId<'static> {
        SignerId::new(name).unwrap()
    }

    static ROUTE: [OrgId<'static>; 3] = [
        OrgId::new(b"STATION").unwrap(),
        OrgId::new(b"POLICE").unwrap(),
        OrgId::new(b"CENTRE").unwrap(),
    ];

    const SEAL: Hash512 = Hash512([7; 64]);
    const H1: Hash512 = Hash512([1; 64]);
    const H2: Hash512 = Hash512([2; 64]);

    fn chain() -> CustodyChain<'static> {
        CustodyChain::new(election(), box_id(), &ROUTE, SEAL, 100).unwrap()
    }

    fn first() -> CustodyHandoffParts<'static> {
        CustodyHandoffParts {
            election_id: election(),
            box_id: box_id(),
            index: 1,
            from_signer: id(b"clerk"),
            from_org: org(b"STATION"),
            to_signer: id(b"officer"),
            to_org: org(b"POLICE"),
            previous_handoff_hash: Hash512::ZERO,
            seal_digest: SEAL,
            count: 100,
            time_bucket: TimeBucket::new(10),
        }
    }

    fn second() -> CustodyHandoffParts<'static> {
        CustodyHandoffParts {
            index: 2,
            from_signer: id(b"officer"),
            from_org: org(b"POLICE"),
            to_signer: id(b"counter"),
            to_org: org(b"CENTRE"),
            previous_handoff_hash: H1,
            time_bucket: TimeBucket::new(11),
            ..first()
        }
    }

    fn change(reason: SealChangeReason) -> SealChangeParts<'static> {
        SealChangeParts {
            election_id: election(),
            box_id: box_id(),
            reason,
            previous_seal_digest: SEAL,
            new_seal_digest: Hash512([8; 64]),
            statement_hash: Hash512([9; 64]),
            time_bucket: TimeBucket::new(10),
        }
    }

    #[test]
    fn route_needs_two_stops() {
        assert_eq!(
            CustodyChain::new(election(), box_id(), &ROUTE[..1], SEAL, 1).unwrap_err(),
            Error::CustodyRoute
        );
        assert_eq!(
            CustodyChain::new(election(), box_id(), &[], SEAL, 1).unwrap_err(),
            Error::CustodyRoute
        );
        assert!(CustodyChain::new(election(), box_id(), &ROUTE[..2], SEAL, 1).is_ok());
    }

    #[test]
    fn complete_chain() {
        let mut c = chain();
        assert_eq!(c.handoffs(), 0);
        assert!(!c.is_complete());
        c.link(&first(), H1).unwrap();
        assert_eq!(c.handoffs(), 1);
        assert!(!c.is_complete());
        c.link(&second(), H2).unwrap();
        assert_eq!(c.handoffs(), 2);
        assert!(c.is_complete());
        assert!(c.holds().is_empty());
        assert_eq!(c.seal(), &SEAL);
        // Past the end of the route.
        let third = CustodyHandoffParts {
            index: 3,
            from_signer: id(b"counter"),
            from_org: org(b"CENTRE"),
            to_signer: id(b"x"),
            to_org: org(b"OTHER"),
            previous_handoff_hash: H2,
            ..first()
        };
        assert_eq!(c.link(&third, Hash512([3; 64])), Err(Error::CustodyRoute));
    }

    #[test]
    fn refusals() {
        let mut c = chain();
        let other_box = CustodyHandoffParts {
            box_id: BoxId::new(b"B2").unwrap(),
            ..first()
        };
        assert_eq!(c.link(&other_box, H1), Err(Error::Mismatch));
        let other_election = CustodyHandoffParts {
            election_id: ElectionId::new(b"E2").unwrap(),
            ..first()
        };
        assert_eq!(c.link(&other_election, H1), Err(Error::Mismatch));
        assert_eq!(
            c.link(&second(), H2),
            Err(Error::CustodyIndex {
                expected: 1,
                got: 2
            })
        );
        let unlinked = CustodyHandoffParts {
            previous_handoff_hash: Hash512([9; 64]),
            ..first()
        };
        assert_eq!(c.link(&unlinked, H1), Err(Error::CustodyPrevious));
        let same_org = CustodyHandoffParts {
            to_signer: id(b"clerk2"),
            to_org: org(b"STATION"),
            ..first()
        };
        assert_eq!(c.link(&same_org, H1), Err(Error::CustodySameOrganisation));
        let off_route = CustodyHandoffParts {
            to_org: org(b"CENTRE"),
            ..first()
        };
        assert_eq!(c.link(&off_route, H1), Err(Error::CustodyRoute));
        let wrong_sender = CustodyHandoffParts {
            from_org: org(b"POLICE"),
            to_org: org(b"CENTRE"),
            ..first()
        };
        assert_eq!(c.link(&wrong_sender, H1), Err(Error::CustodyRoute));
        assert_eq!(c.handoffs(), 0);
        c.link(&first(), H1).unwrap();
        // The next sender must be the previous receiver: the same person of
        // the same organisation.
        let swapped_person = CustodyHandoffParts {
            from_signer: id(b"someone"),
            ..second()
        };
        assert_eq!(c.link(&swapped_person, H2), Err(Error::CustodyPrevious));
        let swapped_org = CustodyHandoffParts {
            from_org: org(b"STATION"),
            ..second()
        };
        assert_eq!(c.link(&swapped_org, H2), Err(Error::CustodyPrevious));
        let replay = CustodyHandoffParts {
            previous_handoff_hash: Hash512::ZERO,
            ..second()
        };
        assert_eq!(c.link(&replay, H2), Err(Error::CustodyPrevious));
        assert_eq!(
            c.link(&first(), H1),
            Err(Error::CustodyIndex {
                expected: 2,
                got: 1
            })
        );
        assert_eq!(c.handoffs(), 1);
    }

    #[test]
    fn holds_for_count_and_seal() {
        let mut c = chain();
        let short = CustodyHandoffParts {
            count: 99,
            ..first()
        };
        c.link(&short, H1).unwrap();
        assert_eq!(
            c.holds(),
            HoldSet::empty().with(HoldReason::CustodyCountMismatch)
        );
        let resealed = CustodyHandoffParts {
            seal_digest: Hash512([8; 64]),
            ..second()
        };
        c.link(&resealed, H2).unwrap();
        assert!(c.holds().contains(HoldReason::CustodySealUnexplained));
        assert_eq!(c.seal(), &Hash512([8; 64]));
        assert!(c.is_complete());
    }

    #[test]
    fn seal_change_explains_the_next_handoff() {
        let mut c = chain();
        c.link(&first(), H1).unwrap();
        let ok = change(SealChangeReason::Inspection);
        assert_eq!(
            c.announce(&SealChangeParts {
                previous_seal_digest: Hash512([5; 64]),
                ..ok
            }),
            Err(Error::CustodySeal)
        );
        assert_eq!(
            c.announce(&SealChangeParts {
                box_id: BoxId::new(b"B2").unwrap(),
                ..ok
            }),
            Err(Error::Mismatch)
        );
        c.announce(&ok).unwrap();
        let resealed = CustodyHandoffParts {
            seal_digest: Hash512([8; 64]),
            ..second()
        };
        c.link(&resealed, H2).unwrap();
        assert!(c.holds().is_empty());
        assert_eq!(c.seal(), &Hash512([8; 64]));
    }

    #[test]
    fn a_broken_seal_holds_even_when_announced() {
        let mut c = chain();
        c.announce(&change(SealChangeReason::Broken)).unwrap();
        assert_eq!(c.holds(), HoldSet::empty().with(HoldReason::SealBroken));
        for reason in [
            SealChangeReason::Inspection,
            SealChangeReason::Container,
            SealChangeReason::Order,
            SealChangeReason::Other,
        ] {
            let mut c = chain();
            c.announce(&change(reason)).unwrap();
            assert!(c.holds().is_empty());
        }
    }

    #[test]
    fn announced_seal_must_match() {
        let mut c = chain();
        c.announce(&change(SealChangeReason::Container)).unwrap();
        let other_seal = CustodyHandoffParts {
            seal_digest: Hash512([6; 64]),
            ..first()
        };
        c.link(&other_seal, H1).unwrap();
        assert_eq!(
            c.holds(),
            HoldSet::empty().with(HoldReason::CustodySealUnexplained)
        );
    }

    #[test]
    fn unused_announcement_is_kept_for_an_unchanged_seal() {
        let mut c = chain();
        c.announce(&change(SealChangeReason::Container)).unwrap();
        c.link(&first(), H1).unwrap();
        let resealed = CustodyHandoffParts {
            seal_digest: Hash512([8; 64]),
            ..second()
        };
        c.link(&resealed, H2).unwrap();
        assert!(c.holds().is_empty());
    }
}
