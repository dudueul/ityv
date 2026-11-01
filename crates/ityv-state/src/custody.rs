//! The custody chain of a closed box (PROTOCOL.md §10.3, VC-040).
//!
//! Handoffs are numbered from 1, each names the previous one, sender and
//! receiver belong to different organisations, both sign, and the
//! organisations follow the route the genesis fixes for the box. The
//! receiver of one handoff is the sender of the next. A malformed link is
//! refused; a count or seal that does not match is accepted and leaves a
//! sticky hold, because the paper still has to be found (§10.3: "그
//! 이벤트가 없는 봉인 불일치는 `HOLD_REVIEW`").
//!
//! `CustodyHandoff` and `SealChange` (schema `0x0008`) have no canonical
//! encoding yet. Until M5 adds them, the caller supplies the handoff's
//! object hash and whether each side's signature verified (ADR-0025).

use ityv_encoding::{BoxId, ElectionId, Hash512, OrgId, SignerId, TimeBucket};

use crate::error::Error;
use crate::hold::{HoldReason, HoldSet};

/// A person in the custody chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Actor<'a> {
    /// The person.
    pub id: SignerId<'a>,
    /// The person's organisation.
    pub org: OrgId<'a>,
}

impl Actor<'_> {
    fn same(&self, other: &Actor<'_>) -> bool {
        self.id.as_bytes() == other.id.as_bytes() && self.org.as_bytes() == other.org.as_bytes()
    }
}

/// One custody handoff (minimal input; schema `0x0008` is an M5 encoding
/// task).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CustodyHandoff<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The box.
    pub box_id: BoxId<'a>,
    /// Position in the chain, from 1.
    pub index: u32,
    /// The sender.
    pub from: Actor<'a>,
    /// The receiver.
    pub to: Actor<'a>,
    /// This handoff's object hash, computed by the caller.
    pub hash: Hash512,
    /// The previous handoff's object hash (zero for the first).
    pub previous: Hash512,
    /// Digest of the seal numbers on the box at handoff.
    pub seal_digest: Hash512,
    /// Ballots (in-person, receipt scan) or return envelopes
    /// (out-of-district) handed over.
    pub paper_count: u64,
    /// When.
    pub time_bucket: TimeBucket,
    /// Whether the sender's signature verified.
    pub sender_signed: bool,
    /// Whether the receiver's signature verified.
    pub receiver_signed: bool,
}

/// A nonzero reason code. The codes themselves are not yet specified
/// (ADR-0025, spec gap 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReasonCode(u16);

impl ReasonCode {
    /// Returns `None` for 0.
    #[must_use]
    pub const fn new(code: u16) -> Option<Self> {
        if code == 0 { None } else { Some(Self(code)) }
    }

    /// The code.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// A seal change with its reason (minimal input, schema `0x0008`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SealChange<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The box.
    pub box_id: BoxId<'a>,
    /// Why the seals changed.
    pub reason: ReasonCode,
    /// The seal digest before the change.
    pub previous_seal: Hash512,
    /// The seal digest after the change.
    pub new_seal: Hash512,
    /// Whether both parties' signatures verified.
    pub signed: bool,
}

/// The custody chain of one box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyChain<'a> {
    election_id: ElectionId<'a>,
    box_id: BoxId<'a>,
    route: &'a [OrgId<'a>],
    handoffs: u32,
    last_hash: Hash512,
    last_receiver: Option<Actor<'a>>,
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

    /// Records a seal change, which explains the next handoff whose seal
    /// digest is `new_seal`.
    ///
    /// # Errors
    /// [`Error::Mismatch`] for another box, [`Error::CustodyUnsigned`] if
    /// unsigned, [`Error::CustodySeal`] if `previous_seal` is not the
    /// chain's current seal.
    pub fn seal_change(&mut self, change: &SealChange<'_>) -> Result<(), Error> {
        self.check_target(change.election_id, change.box_id)?;
        if !change.signed {
            return Err(Error::CustodyUnsigned);
        }
        if change.previous_seal != self.seal {
            return Err(Error::CustodySeal);
        }
        self.announced_seal = Some(change.new_seal);
        Ok(())
    }

    /// Appends a handoff.
    ///
    /// # Errors
    /// [`Error::Mismatch`] for another box, [`Error::CustodyUnsigned`] if a
    /// side did not sign, [`Error::CustodyIndex`] if the index is not the
    /// next one, [`Error::CustodyPrevious`] if it does not name the previous
    /// handoff or its sender is not the previous receiver,
    /// [`Error::CustodySameOrganisation`] if both sides are one
    /// organisation, [`Error::CustodyRoute`] if it leaves the route,
    /// [`Error::Overflow`].
    pub fn handoff(&mut self, h: &CustodyHandoff<'a>) -> Result<(), Error> {
        self.check_target(h.election_id, h.box_id)?;
        if !(h.sender_signed && h.receiver_signed) {
            return Err(Error::CustodyUnsigned);
        }
        let expected = self.handoffs.checked_add(1).ok_or(Error::Overflow)?;
        if h.index != expected {
            return Err(Error::CustodyIndex {
                expected,
                got: h.index,
            });
        }
        if h.previous != self.last_hash {
            return Err(Error::CustodyPrevious);
        }
        if let Some(last) = &self.last_receiver
            && !last.same(&h.from)
        {
            return Err(Error::CustodyPrevious);
        }
        if h.from.org.as_bytes() == h.to.org.as_bytes() {
            return Err(Error::CustodySameOrganisation);
        }
        let stop = usize::try_from(self.handoffs).map_err(|_| Error::Overflow)?;
        let next = stop.checked_add(1).ok_or(Error::Overflow)?;
        let on_route = if let (Some(from), Some(to)) = (self.route.get(stop), self.route.get(next))
        {
            from.as_bytes() == h.from.org.as_bytes() && to.as_bytes() == h.to.org.as_bytes()
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
            h.paper_count != self.expected_count,
            HoldReason::CustodyCountMismatch,
        );
        self.handoffs = expected;
        self.last_hash = h.hash;
        self.last_receiver = Some(h.to);
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
    use ityv_encoding::{BoxId, ElectionId, Hash512, OrgId, SignerId, TimeBucket};

    use super::{Actor, CustodyChain, CustodyHandoff, ReasonCode, SealChange};
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

    fn actor(id: &'static [u8], name: &'static [u8]) -> Actor<'static> {
        Actor {
            id: SignerId::new(id).unwrap(),
            org: org(name),
        }
    }

    static ROUTE: [OrgId<'static>; 3] = [
        OrgId::new(b"STATION").unwrap(),
        OrgId::new(b"POLICE").unwrap(),
        OrgId::new(b"CENTRE").unwrap(),
    ];

    const SEAL: Hash512 = Hash512([7; 64]);

    fn chain() -> CustodyChain<'static> {
        CustodyChain::new(election(), box_id(), &ROUTE, SEAL, 100).unwrap()
    }

    fn first() -> CustodyHandoff<'static> {
        CustodyHandoff {
            election_id: election(),
            box_id: box_id(),
            index: 1,
            from: actor(b"clerk", b"STATION"),
            to: actor(b"officer", b"POLICE"),
            hash: Hash512([1; 64]),
            previous: Hash512::ZERO,
            seal_digest: SEAL,
            paper_count: 100,
            time_bucket: TimeBucket::new(10),
            sender_signed: true,
            receiver_signed: true,
        }
    }

    fn second() -> CustodyHandoff<'static> {
        CustodyHandoff {
            index: 2,
            from: actor(b"officer", b"POLICE"),
            to: actor(b"counter", b"CENTRE"),
            hash: Hash512([2; 64]),
            previous: Hash512([1; 64]),
            time_bucket: TimeBucket::new(11),
            ..first()
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
        c.handoff(&first()).unwrap();
        assert_eq!(c.handoffs(), 1);
        assert!(!c.is_complete());
        c.handoff(&second()).unwrap();
        assert_eq!(c.handoffs(), 2);
        assert!(c.is_complete());
        assert!(c.holds().is_empty());
        assert_eq!(c.seal(), &SEAL);
        // Past the end of the route.
        let third = CustodyHandoff {
            index: 3,
            from: actor(b"counter", b"CENTRE"),
            to: actor(b"x", b"OTHER"),
            previous: Hash512([2; 64]),
            ..first()
        };
        assert_eq!(c.handoff(&third), Err(Error::CustodyRoute));
    }

    #[test]
    fn refusals() {
        let mut c = chain();
        let other_box = CustodyHandoff {
            box_id: BoxId::new(b"B2").unwrap(),
            ..first()
        };
        assert_eq!(c.handoff(&other_box), Err(Error::Mismatch));
        let other_election = CustodyHandoff {
            election_id: ElectionId::new(b"E2").unwrap(),
            ..first()
        };
        assert_eq!(c.handoff(&other_election), Err(Error::Mismatch));
        for (sender, receiver) in [(false, true), (true, false), (false, false)] {
            let unsigned = CustodyHandoff {
                sender_signed: sender,
                receiver_signed: receiver,
                ..first()
            };
            assert_eq!(c.handoff(&unsigned), Err(Error::CustodyUnsigned));
        }
        assert_eq!(
            c.handoff(&second()),
            Err(Error::CustodyIndex {
                expected: 1,
                got: 2
            })
        );
        let unlinked = CustodyHandoff {
            previous: Hash512([9; 64]),
            ..first()
        };
        assert_eq!(c.handoff(&unlinked), Err(Error::CustodyPrevious));
        let same_org = CustodyHandoff {
            to: actor(b"clerk2", b"STATION"),
            ..first()
        };
        assert_eq!(c.handoff(&same_org), Err(Error::CustodySameOrganisation));
        let off_route = CustodyHandoff {
            to: actor(b"officer", b"CENTRE"),
            ..first()
        };
        assert_eq!(c.handoff(&off_route), Err(Error::CustodyRoute));
        let wrong_sender = CustodyHandoff {
            from: actor(b"clerk", b"POLICE"),
            to: actor(b"officer", b"CENTRE"),
            ..first()
        };
        assert_eq!(c.handoff(&wrong_sender), Err(Error::CustodyRoute));
        assert_eq!(c.handoffs(), 0);
        c.handoff(&first()).unwrap();
        // The next sender must be the previous receiver.
        let swapped_person = CustodyHandoff {
            from: actor(b"someone", b"POLICE"),
            ..second()
        };
        assert_eq!(c.handoff(&swapped_person), Err(Error::CustodyPrevious));
        let replay = CustodyHandoff {
            previous: Hash512::ZERO,
            ..second()
        };
        assert_eq!(c.handoff(&replay), Err(Error::CustodyPrevious));
        assert_eq!(
            c.handoff(&first()),
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
        let short = CustodyHandoff {
            paper_count: 99,
            ..first()
        };
        c.handoff(&short).unwrap();
        assert_eq!(
            c.holds(),
            HoldSet::empty().with(HoldReason::CustodyCountMismatch)
        );
        let resealed = CustodyHandoff {
            seal_digest: Hash512([8; 64]),
            ..second()
        };
        c.handoff(&resealed).unwrap();
        assert!(c.holds().contains(HoldReason::CustodySealUnexplained));
        assert_eq!(c.seal(), &Hash512([8; 64]));
        assert!(c.is_complete());
    }

    #[test]
    fn seal_change_explains_the_next_handoff() {
        let mut c = chain();
        c.handoff(&first()).unwrap();
        let change = SealChange {
            election_id: election(),
            box_id: box_id(),
            reason: ReasonCode::new(3).unwrap(),
            previous_seal: SEAL,
            new_seal: Hash512([8; 64]),
            signed: true,
        };
        assert_eq!(
            c.seal_change(&SealChange {
                signed: false,
                ..change
            }),
            Err(Error::CustodyUnsigned)
        );
        assert_eq!(
            c.seal_change(&SealChange {
                previous_seal: Hash512([5; 64]),
                ..change
            }),
            Err(Error::CustodySeal)
        );
        assert_eq!(
            c.seal_change(&SealChange {
                box_id: BoxId::new(b"B2").unwrap(),
                ..change
            }),
            Err(Error::Mismatch)
        );
        c.seal_change(&change).unwrap();
        let resealed = CustodyHandoff {
            seal_digest: Hash512([8; 64]),
            ..second()
        };
        c.handoff(&resealed).unwrap();
        assert!(c.holds().is_empty());
        assert_eq!(c.seal(), &Hash512([8; 64]));
    }

    #[test]
    fn announced_seal_must_match() {
        let mut c = chain();
        let change = SealChange {
            election_id: election(),
            box_id: box_id(),
            reason: ReasonCode::new(1).unwrap(),
            previous_seal: SEAL,
            new_seal: Hash512([8; 64]),
            signed: true,
        };
        c.seal_change(&change).unwrap();
        let other_seal = CustodyHandoff {
            seal_digest: Hash512([6; 64]),
            ..first()
        };
        c.handoff(&other_seal).unwrap();
        assert_eq!(
            c.holds(),
            HoldSet::empty().with(HoldReason::CustodySealUnexplained)
        );
    }

    #[test]
    fn unused_announcement_is_kept_for_an_unchanged_seal() {
        let mut c = chain();
        let change = SealChange {
            election_id: election(),
            box_id: box_id(),
            reason: ReasonCode::new(1).unwrap(),
            previous_seal: SEAL,
            new_seal: Hash512([8; 64]),
            signed: true,
        };
        c.seal_change(&change).unwrap();
        c.handoff(&first()).unwrap();
        let resealed = CustodyHandoff {
            seal_digest: Hash512([8; 64]),
            ..second()
        };
        c.handoff(&resealed).unwrap();
        assert!(c.holds().is_empty());
    }

    #[test]
    fn reason_codes() {
        assert!(ReasonCode::new(0).is_none());
        assert_eq!(ReasonCode::new(7).unwrap().get(), 7);
    }
}
