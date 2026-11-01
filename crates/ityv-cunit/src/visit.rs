//! Visit-level casting (ADR-0021; PROTOCOL.md §7.2.1, §7.3, §7.7, §8).
//!
//! A voter inserts every ballot they received (one to eight) at once. Each
//! ballot is built as one position ([`crate::ballot`]) and bound to the
//! open visit, which makes its bound entry (kind 9: record hash and
//! consumed counters) durable; the interpretation unit then sends
//! `VisitEnd`, and only once every position is bound, with its device and
//! module record signatures, does the unit take the voter's cast-or-check
//! decision (VC-068). The decision journals every position's decision
//! entry (kind 1 or 2, repeating its bound entry), then the decision entry
//! (kind 7) with one fsync, and only then may papers move (VC-054).
//!
//! ```text
//! interpret … bind (per position, kind 9) ─▶ OpenBox::end_visit ─▶ ReadyVisit ─decide─▶ DecidedVisit
//!     DecidedVisit: per position in order, imprint (kind 6) / imprint failed (kind 3) / open a check
//!     DecidedVisit ─finish_positions─▶ ProcessedVisit: label sticker (kind 8), slip ─finish─▶ done
//! ```
//!
//! The decision exists only on a [`ReadyVisit`], which only
//! [`OpenBox::end_visit`] creates, and only when every position of the
//! visit is bound. A caller cannot build one:
//!
//! ```compile_fail
//! # use ityv_cunit::visit::ReadyVisit;
//! fn forge<'c, 'v>(work: &'v mut ityv_cunit::visit::VisitWork) -> ReadyVisit<'c, 'v> {
//!     ReadyVisit { ticket: 1, work }
//! }
//! ```
//!
//! A ballot that is built but not yet bound has no decision:
//!
//! ```compile_fail
//! # use ityv_cunit::ballot::{Ballot, Built};
//! # use ityv_cunit::visit::Decision;
//! fn decide_one<'c>(ballot: Ballot<'c, '_, Built<'_>>) {
//!     let _ = ballot.decide(Decision::CAST_ALL);
//! }
//! ```
//!
//! Nothing is imprinted before the decision, and no sticker or slip is
//! printed before every position is processed:
//!
//! ```compile_fail
//! # use ityv_cunit::visit::ReadyVisit;
//! # use ityv_cunit::boxstate::OpenBox;
//! fn imprint_before_decision<'c>(ready: &ReadyVisit<'c, '_>, open: &OpenBox<'c>) {
//!     let _ = ready.imprint_command(open);
//! }
//! ```
//!
//! ```compile_fail
//! # use ityv_cunit::visit::DecidedVisit;
//! # use ityv_cunit::boxstate::{OpenBox, Signer};
//! # use ityv_encoding::TimeBucket;
//! fn slip_before_processing<'c>(
//!     decided: &DecidedVisit<'c, '_>,
//!     open: &OpenBox<'c>,
//!     signer: Signer<'_>,
//! ) {
//!     let mut out = [0u8; 8];
//!     let _ = decided.slip(open, signer, TimeBucket::new(0), &mut out);
//! }
//! ```
//!
//! ```compile_fail
//! # use ityv_cunit::visit::DecidedVisit;
//! # use ityv_cunit::boxstate::OpenBox;
//! fn label_before_processing<'c>(decided: &DecidedVisit<'c, '_>, open: &OpenBox<'c>) {
//!     let _ = decided.label_command(open);
//! }
//! ```
//!
//! The same steps compile in the states that allow them:
//!
//! ```
//! # use ityv_cunit::visit::{DecidedVisit, Decision, ProcessedVisit, ReadyVisit};
//! # use ityv_cunit::boxstate::{OpenBox, Signer};
//! # use ityv_cunit::port::{JournalSink, StagingPort};
//! # use ityv_encoding::TimeBucket;
//! fn steps<'c>(
//!     ready: ReadyVisit<'c, '_>,
//!     open: &mut OpenBox<'c>,
//!     sink: &mut dyn JournalSink,
//!     staging: &mut dyn StagingPort,
//!     signer: Signer<'_>,
//! ) {
//!     let mut package = [0u8; 8];
//!     let Ok(decided) =
//!         ready.decide(open, Decision::CAST_ALL, sink, staging, &mut package, TimeBucket::new(0))
//!     else {
//!         return;
//!     };
//!     let _ = decided.imprint_command(open);
//!     let Ok(processed) = decided.finish_positions(open) else { return };
//!     let _ = processed.label_command(open);
//!     let mut out = [0u8; 8];
//!     let _ = processed.slip(open, signer, TimeBucket::new(0), &mut out);
//! }
//! ```
//!
//! # Memory
//!
//! A position's public objects (the `CastRecord`, up to 22 KB, and the
//! `SharePackage`, up to 269 KB) go to the host's [`StagingPort`] as soon
//! as the position is bound; the unit keeps only their hashes and checks
//! whatever comes back against them before it is journaled or published.
//! What stays in the unit per position is what the decision and a
//! challenge opening need: the choice, the cast id, the envelope label,
//! the summed randomness and each module's randomness and cast-id part, in
//! the caller's [`VisitWork`] (about 24 KB for eight positions, wiped when
//! the visit ends, fails or is dropped), plus the public hashes and
//! counters in the box.

use core::fmt;

use ityv_crypto::{CastId, Scalar, object_hash};
use ityv_encoding::{
    ChallengeOpening, ChallengeOpeningBody, ChallengeOpeningParts, HYBRID_SIG_LEN, Hash512,
    MAX_CHALLENGE_BODY_LEN, MAX_SLIP_BODY_LEN, ModuleOpening, SCHEMA_CHALLENGE_OPENING,
    SCHEMA_CHALLENGE_OPENING_BODY, SCHEMA_SLIP, SCHEMA_SLIP_BODY, SCHEMA_VERSION_1, Scalar32,
    Scalars, Slip, SlipBody, TimeBucket, Token192, decode_object, encode_object,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::ballot::{PURPOSE_CHALLENGE, PURPOSE_SLIP, scalars_clear, wipe_scalars};
use crate::boxstate::{EntryFields, NO_COUNTERS, OpenBox, Signer};
use crate::config::{BallotStyle, ElectionConfig, MAX_MODULES, Profile};
use crate::error::Error;
use crate::link::{JournalKind, SCHEMA_VISIT_END, VisitEnd, visit_digest};
use crate::port::{JournalSink, Staged, StagingPort};
use crate::rules::{Choice, Settlement, VISIT_POSITIONS};

/// Positions in one visit at most (ADR-0021).
pub const MAX_VISIT_POSITIONS: usize = VISIT_POSITIONS;

/// Each module's randomness `r_{c,0..k−1}` of one position.
pub(crate) type ModuleRand = [[Scalar; ityv_crypto::MAX_CHUNKS]; MAX_MODULES];

/// What the visit keeps of one bound position besides the module
/// randomness: what a challenge opening and the imprint and the sticker
/// need.
pub(crate) struct PositionSecrets {
    pub(crate) option: u16,
    pub(crate) cast_id: CastId,
    pub(crate) env_label: Option<[u8; 24]>,
    pub(crate) rand: [Scalar; ityv_crypto::MAX_CHUNKS],
    pub(crate) cids: [[u8; 24]; MAX_MODULES],
}

impl PositionSecrets {
    const EMPTY: Self = Self {
        option: 0,
        cast_id: CastId::new(Token192([0; 24])),
        env_label: None,
        rand: [Scalar::ZERO; ityv_crypto::MAX_CHUNKS],
        cids: [[0; 24]; MAX_MODULES],
    };

    fn is_clear(&self) -> bool {
        self.option == 0
            && self.cast_id.token().0 == [0; 24]
            && self.env_label.is_none()
            && self.rand.iter().all(Scalar::is_zero)
            && self.cids.iter().flatten().all(|&b| b == 0)
    }
}

impl Zeroize for PositionSecrets {
    fn zeroize(&mut self) {
        self.option.zeroize();
        self.cast_id.zeroize();
        self.env_label.zeroize();
        self.rand.zeroize();
        self.cids.zeroize();
    }
}

/// The empty module randomness of one position.
const NO_MODULE_RAND: ModuleRand = [[Scalar::ZERO; ityv_crypto::MAX_CHUNKS]; MAX_MODULES];

/// The scratch of a challenge opening, which reveals the choice.
struct OpeningScratch {
    rand: [Scalar32; ityv_crypto::MAX_CHUNKS],
    module_rand: [[Scalar32; ityv_crypto::MAX_CHUNKS]; MAX_MODULES],
    body: [u8; MAX_CHALLENGE_BODY_LEN],
}

impl OpeningScratch {
    const EMPTY: Self = Self {
        rand: [Scalar32([0; 32]); ityv_crypto::MAX_CHUNKS],
        module_rand: [[Scalar32([0; 32]); ityv_crypto::MAX_CHUNKS]; MAX_MODULES],
        body: [0; MAX_CHALLENGE_BODY_LEN],
    };

    fn is_clear(&self) -> bool {
        scalars_clear(&self.rand)
            && self.module_rand.iter().all(|row| scalars_clear(row))
            && self.body.iter().all(|&b| b == 0)
    }
}

impl Zeroize for OpeningScratch {
    fn zeroize(&mut self) {
        wipe_scalars(&mut self.rand);
        for row in &mut self.module_rand {
            wipe_scalars(row);
        }
        self.body.zeroize();
    }
}

/// The caller-provided work area of one visit: the small secrets of each
/// bound position and the scratch of a challenge opening (about 24 KB).
/// A host keeps one (the constructor is `const`) and lends it to every
/// visit in turn. Not `Clone`; `Debug` shows nothing; wiped when a visit
/// takes it, when the visit ends or fails, and on drop.
pub struct VisitWork {
    ticket: u64,
    bound: u8,
    positions: [PositionSecrets; MAX_VISIT_POSITIONS],
    module_rand: [ModuleRand; MAX_VISIT_POSITIONS],
    opening: OpeningScratch,
}

impl VisitWork {
    /// An empty work area.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ticket: 0,
            bound: 0,
            positions: [const { PositionSecrets::EMPTY }; MAX_VISIT_POSITIONS],
            module_rand: [NO_MODULE_RAND; MAX_VISIT_POSITIONS],
            opening: OpeningScratch::EMPTY,
        }
    }

    /// `true` if nothing is left in the work area. A host may check it
    /// after each visit; the tests use it to observe the wipes.
    #[must_use]
    pub fn is_clear(&self) -> bool {
        self.ticket == 0
            && self.bound == 0
            && self.positions.iter().all(PositionSecrets::is_clear)
            && self
                .module_rand
                .iter()
                .flatten()
                .flatten()
                .all(Scalar::is_zero)
            && self.opening.is_clear()
    }

    /// The slot of position `position` of visit `ticket`: the first
    /// position takes (and wipes) the work area, later ones must find it
    /// holding exactly the positions bound so far.
    pub(crate) fn slot_for(
        &mut self,
        ticket: u64,
        position: u8,
    ) -> Result<(&mut PositionSecrets, &mut ModuleRand), Error> {
        if position == 0 {
            self.zeroize();
            self.ticket = ticket;
        } else if self.ticket != ticket || self.bound != position {
            return Err(Error::StaleVisit);
        }
        let index = usize::from(position);
        let secrets = self.positions.get_mut(index).ok_or(Error::VisitFull)?;
        let rand = self.module_rand.get_mut(index).ok_or(Error::VisitFull)?;
        Ok((secrets, rand))
    }

    /// Counts the position just moved into its slot.
    pub(crate) fn note_bound(&mut self) {
        self.bound = self.bound.saturating_add(1);
    }

    fn position(&self, position: u8) -> Result<&PositionSecrets, Error> {
        self.positions
            .get(usize::from(position))
            .ok_or(Error::Capacity)
    }
}

impl Default for VisitWork {
    fn default() -> Self {
        Self::new()
    }
}

impl Zeroize for VisitWork {
    fn zeroize(&mut self) {
        self.ticket.zeroize();
        self.bound.zeroize();
        self.positions.zeroize();
        for rand in &mut self.module_rand {
            for row in rand {
                row.zeroize();
            }
        }
        self.opening.zeroize();
    }
}

impl Drop for VisitWork {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for VisitWork {}

impl fmt::Debug for VisitWork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VisitWork(..)")
    }
}

/// The work area as lent to a visit after its end: wiped when the visit
/// state is dropped, whatever the state.
struct VisitGuard<'v>(&'v mut VisitWork);

impl Drop for VisitGuard<'_> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The hashes the box keeps of a bound position's staged objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PositionHashes {
    /// The tracking code: the record body's object hash.
    pub(crate) record: Hash512,
    /// The object hash of the staged `CastRecord`.
    pub(crate) record_object: Hash512,
    /// The object hash of the staged `SharePackage`.
    pub(crate) package: Hash512,
}

/// The public facts of one bound position, kept in the box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Position<'c> {
    pub(crate) style: &'c BallotStyle<'c>,
    pub(crate) counters: [u64; MAX_MODULES],
    pub(crate) issued: [bool; MAX_MODULES],
    pub(crate) hashes: PositionHashes,
    pub(crate) choice: Choice,
    pub(crate) settled: Settlement,
}

/// Where the open visit stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    /// Positions are being built and bound.
    Building,
    /// `VisitEnd` matched: waiting for the decision.
    Ended,
    /// The decision failed part way: some position entries may be
    /// journaled, the decision entry is not.
    Deciding,
    /// The decision entry is durable; positions are being processed.
    Decided,
    /// Every position is processed; the sticker and the slip remain.
    Processed,
}

/// The out-of-district label sticker of a decided visit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Label {
    /// In person.
    NotNeeded,
    /// Out of district, not yet printed: the sticker is owed while a cast
    /// ballot of the visit is live (see `Visit::label_owed`).
    Pending,
    /// The label-printed entry (kind 8) is durable.
    Printed,
}

/// The open visit, kept in the box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Visit<'c> {
    pub(crate) ticket: u64,
    pub(crate) step: Step,
    pub(crate) positions: [Option<Position<'c>>; MAX_VISIT_POSITIONS],
    pub(crate) count: u8,
    pub(crate) digest: Hash512,
    pub(crate) cursor: u8,
    pub(crate) live: u8,
    pub(crate) label: Label,
}

impl<'c> Visit<'c> {
    pub(crate) const fn new(ticket: u64) -> Self {
        Self {
            ticket,
            step: Step::Building,
            positions: [None; MAX_VISIT_POSITIONS],
            count: 0,
            digest: Hash512::ZERO,
            cursor: 0,
            live: 0,
            label: Label::NotNeeded,
        }
    }

    /// `Ok` if one more position may be built.
    pub(crate) fn accepts_position(&self) -> Result<(), Error> {
        if !matches!(self.step, Step::Building) {
            return Err(Error::VisitInProgress);
        }
        if usize::from(self.count) >= MAX_VISIT_POSITIONS {
            return Err(Error::VisitFull);
        }
        Ok(())
    }

    fn position(&self, index: u8) -> Result<Position<'c>, Error> {
        self.positions
            .get(usize::from(index))
            .copied()
            .flatten()
            .ok_or(Error::Capacity)
    }

    fn position_mut(&mut self, index: u8) -> Result<&mut Position<'c>, Error> {
        self.positions
            .get_mut(usize::from(index))
            .and_then(Option::as_mut)
            .ok_or(Error::Capacity)
    }

    /// The bound positions, in order.
    fn bound(&self) -> impl Iterator<Item = &Position<'c>> {
        self.positions
            .iter()
            .take(usize::from(self.count))
            .flatten()
    }

    /// `true` while a cast record of the visit is neither quarantined nor
    /// covered by its sticker entry, out of district.
    const fn label_owed(&self) -> bool {
        matches!(self.label, Label::Pending) && self.live > 0
    }
}

/// The voter's decision (PROTOCOL.md §7.3 step 6): cast or check, per
/// position. Every subset may be checked, from none to all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Decision {
    checks: u8,
}

impl Decision {
    /// Cast every position.
    pub const CAST_ALL: Self = Self { checks: 0 };

    /// Check the positions whose bits are set (bit 0 = the first
    /// position); the others are cast.
    #[must_use]
    pub const fn from_checks(checks: u8) -> Self {
        Self { checks }
    }

    /// Check every listed position (0-based); `None` if one is beyond
    /// the eighth.
    #[must_use]
    pub fn checking(positions: &[u8]) -> Option<Self> {
        let mut checks = 0u8;
        for &position in positions {
            checks |= 1u8.checked_shl(u32::from(position))?;
        }
        Some(Self { checks })
    }

    /// What position `position` was decided to be.
    #[must_use]
    pub fn choice(self, position: u8) -> Choice {
        match self.checks.checked_shr(u32::from(position)) {
            Some(bits) if bits & 1 == 1 => Choice::Check,
            _ => Choice::Cast,
        }
    }

    /// `true` if every set bit names one of `count` positions.
    fn fits(self, count: u8) -> bool {
        self.checks
            .checked_shr(u32::from(count))
            .is_none_or(|rest| rest == 0)
    }
}

/// What the imprinter prints on a cast ballot (PROTOCOL.md §7.3 step 8):
/// the cast id, as digits and a 2-D barcode. Not `Clone`; `Debug` shows
/// nothing; zeroized on drop.
pub struct ImprintCommand {
    cast_id: [u8; 24],
}

impl ImprintCommand {
    /// The cast id.
    #[must_use]
    pub const fn cast_id(&self) -> &[u8; 24] {
        &self.cast_id
    }
}

impl Zeroize for ImprintCommand {
    fn zeroize(&mut self) {
        self.cast_id.zeroize();
    }
}

impl Drop for ImprintCommand {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for ImprintCommand {}

impl fmt::Debug for ImprintCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ImprintCommand(..)")
    }
}

/// What the sticker printer prints for an out-of-district visit
/// (PROTOCOL.md §7.3 step 9): the envelope labels of the visit's cast
/// ballots, in position order, 1–8. Not `Clone`; `Debug` shows nothing;
/// zeroized on drop.
pub struct LabelCommand {
    labels: [[u8; 24]; MAX_VISIT_POSITIONS],
    count: u8,
}

impl LabelCommand {
    /// The labels.
    #[must_use]
    pub fn labels(&self) -> &[[u8; 24]] {
        self.labels.get(..usize::from(self.count)).unwrap_or(&[])
    }
}

impl Zeroize for LabelCommand {
    fn zeroize(&mut self) {
        self.labels.zeroize();
        self.count.zeroize();
    }
}

impl Drop for LabelCommand {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for LabelCommand {}

impl fmt::Debug for LabelCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LabelCommand(..)")
    }
}

/// A visit whose positions are all bound and whose `VisitEnd` matched:
/// the only state with a decision (VC-068). Wipes the visit's work area
/// when dropped; the box then holds the visit until it is decided or
/// abandoned ([`OpenBox::abandon_visit`]).
pub struct ReadyVisit<'c, 'v> {
    config: &'c ElectionConfig<'c>,
    ticket: u64,
    work: VisitGuard<'v>,
}

/// A decided visit: every position and the decision are durable. Its
/// positions are processed in order.
pub struct DecidedVisit<'c, 'v> {
    config: &'c ElectionConfig<'c>,
    ticket: u64,
    work: VisitGuard<'v>,
}

/// A visit whose positions are all processed: the sticker (out of
/// district) and the slip remain.
pub struct ProcessedVisit<'c, 'v> {
    config: &'c ElectionConfig<'c>,
    ticket: u64,
    work: VisitGuard<'v>,
}

impl fmt::Debug for ReadyVisit<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadyVisit")
            .field("ticket", &self.ticket)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DecidedVisit<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecidedVisit")
            .field("ticket", &self.ticket)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ProcessedVisit<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessedVisit")
            .field("ticket", &self.ticket)
            .finish_non_exhaustive()
    }
}

impl<'c> OpenBox<'c> {
    /// The open visit with ticket `ticket`.
    fn visit_at(&self, ticket: u64) -> Result<Visit<'c>, Error> {
        match self.visit {
            Some(visit) if visit.ticket == ticket => Ok(visit),
            Some(_) => Err(Error::StaleVisit),
            None => Err(Error::NoVisit),
        }
    }

    fn visit_mut(&mut self, ticket: u64) -> Result<&mut Visit<'c>, Error> {
        match &mut self.visit {
            Some(visit) if visit.ticket == ticket => Ok(visit),
            Some(_) => Err(Error::StaleVisit),
            None => Err(Error::NoVisit),
        }
    }

    /// The open visit's ticket and the index the next bound position gets.
    pub(crate) fn next_position(&self) -> Result<(u64, u8), Error> {
        let visit = self.visit.ok_or(Error::NoVisit)?;
        visit.accepts_position()?;
        Ok((visit.ticket, visit.count))
    }

    /// Binds the ballot in flight `ticket` as the next position of the open
    /// visit: its bound entry (kind 9: the record hash and the counters
    /// the ballot consumed) is made durable first, then the position
    /// counts as bound (PROTOCOL.md §7.3 step 5). Nothing changes if this
    /// fails; the ballot stays in flight.
    pub(crate) fn bind_position(
        &mut self,
        ticket: u64,
        style: &'c BallotStyle<'c>,
        hashes: &PositionHashes,
        sink: &mut dyn JournalSink,
        time_bucket: TimeBucket,
    ) -> Result<(), Error> {
        self.usable()?;
        let flight = self.check_ticket(ticket)?;
        let visit = self.visit.ok_or(Error::NoVisit)?;
        visit.accepts_position()?;
        self.journal(
            sink,
            &EntryFields {
                kind: JournalKind::Bound,
                record_hash: hashes.record,
                share_package_hash: Hash512::ZERO,
                counters: &flight.counters,
                include: flight.issued,
                time_bucket,
            },
            None,
        )?;
        let visit = self.visit.as_mut().ok_or(Error::NoVisit)?;
        let slot = visit
            .positions
            .get_mut(usize::from(visit.count))
            .ok_or(Error::VisitFull)?;
        *slot = Some(Position {
            style,
            counters: flight.counters,
            issued: flight.issued,
            hashes: *hashes,
            choice: Choice::Cast,
            settled: Settlement::Open,
        });
        visit.count = visit.count.checked_add(1).ok_or(Error::Overflow)?;
        self.in_flight = None;
        Ok(())
    }

    /// The interpretation unit's `VisitEnd` (schema 0x0104): if its ballot
    /// count equals the visit's bound positions, every position is bound
    /// and no ballot is in flight, the visit is ready for the decision
    /// (PROTOCOL.md §7.3 after step 5). `work` must be the visit's work
    /// area. On a count mismatch the visit is quarantined without a
    /// decision: the host calls [`Self::abandon_visit`] once two clerks and
    /// two observers confirmed.
    ///
    /// # Errors
    /// The decoder's error, [`Error::WrongElection`], [`Error::NoVisit`],
    /// [`Error::VisitInProgress`], [`Error::BallotInFlight`],
    /// [`Error::VisitCountMismatch`], [`Error::StaleVisit`].
    pub fn end_visit<'v>(
        &mut self,
        link: &[u8],
        work: &'v mut VisitWork,
    ) -> Result<ReadyVisit<'c, 'v>, Error> {
        let notice: VisitEnd<'_> = decode_object(SCHEMA_VISIT_END, SCHEMA_VERSION_1, link)?;
        if notice.election_id().as_bytes() != self.config.election_id().as_bytes() {
            return Err(Error::WrongElection);
        }
        if self.in_flight.is_some() {
            return Err(Error::BallotInFlight);
        }
        let visit = self.visit.as_mut().ok_or(Error::NoVisit)?;
        if !matches!(visit.step, Step::Building) {
            return Err(Error::VisitInProgress);
        }
        if notice.ballot_count() != visit.count {
            return Err(Error::VisitCountMismatch);
        }
        if work.ticket != visit.ticket || work.bound != visit.count {
            return Err(Error::StaleVisit);
        }
        visit.step = Step::Ended;
        Ok(ReadyVisit {
            config: self.config,
            ticket: visit.ticket,
            work: VisitGuard(work),
        })
    }

    /// Journals the decision of visit `ticket` (PROTOCOL.md §7.3 step 7):
    /// each position's entry in order (a record entry with its staged and
    /// re-checked share package, or a challenge entry), deferred, then the
    /// decision entry, durable with all of them. Then the records join the
    /// open batch and the totals.
    fn decide_visit(
        &mut self,
        ticket: u64,
        decision: Decision,
        io: &mut VisitIo<'_>,
        time_bucket: TimeBucket,
    ) -> Result<(), Error> {
        self.usable()?;
        self.check_time(time_bucket)?;
        let visit = self.visit_at(ticket)?;
        if !matches!(visit.step, Step::Ended) {
            return Err(Error::VisitInProgress);
        }
        if !decision.fits(visit.count) {
            return Err(Error::InvalidDecision);
        }
        let mut entries = [(0u8, Hash512::ZERO); MAX_VISIT_POSITIONS];
        for (index, (position, entry)) in visit.bound().zip(entries.iter_mut()).enumerate() {
            let index = u8::try_from(index).map_err(|_| Error::Capacity)?;
            let choice = decision.choice(index);
            let kind = match choice {
                Choice::Cast => JournalKind::Record,
                Choice::Check => JournalKind::Challenge,
            };
            let package = match choice {
                Choice::Cast => Some(fetch_checked(
                    io.staging,
                    index,
                    Staged::Package,
                    &position.hashes.package,
                    io.package,
                )?),
                Choice::Check => None,
            };
            let fields = EntryFields {
                kind,
                record_hash: position.hashes.record,
                share_package_hash: package.map_or(Hash512::ZERO, |_| position.hashes.package),
                counters: &position.counters,
                include: position.issued,
                time_bucket,
            };
            self.journal_with(io.sink, &fields, package, true)?;
            let visit = self.visit_mut(ticket)?;
            visit.step = Step::Deciding;
            visit.position_mut(index)?.choice = choice;
            *entry = (kind.code(), position.hashes.record);
        }
        let digest = visit_digest(entries.get(..usize::from(visit.count)).unwrap_or(&[]));
        self.journal(
            io.sink,
            &EntryFields {
                kind: JournalKind::VisitDecision,
                record_hash: digest,
                share_package_hash: Hash512::ZERO,
                counters: &NO_COUNTERS,
                include: [false; MAX_MODULES],
                time_bucket,
            },
            None,
        )?;
        self.apply_decision(ticket, digest, time_bucket)
    }

    /// Applies a durable decision to the batch and the totals (live and at
    /// resume).
    pub(crate) fn apply_decision(
        &mut self,
        ticket: u64,
        digest: Hash512,
        time_bucket: TimeBucket,
    ) -> Result<(), Error> {
        let visit = self.visit_at(ticket)?;
        let mut cast = 0u8;
        for position in visit.bound() {
            match position.choice {
                Choice::Cast => {
                    self.push_record(position.hashes.record, time_bucket)?;
                    cast = cast.checked_add(1).ok_or(Error::Overflow)?;
                }
                Choice::Check => {
                    self.totals.challenged = self
                        .totals
                        .challenged
                        .checked_add(1)
                        .ok_or(Error::Overflow)?;
                }
            }
        }
        if cast > 0 {
            self.totals.visits = self.totals.visits.checked_add(1).ok_or(Error::Overflow)?;
        }
        let absentee = matches!(self.config.profile(), Profile::Absentee);
        let visit = self.visit_mut(ticket)?;
        visit.step = Step::Decided;
        visit.digest = digest;
        visit.cursor = 0;
        visit.live = cast;
        visit.label = if absentee {
            Label::Pending
        } else {
            Label::NotNeeded
        };
        Ok(())
    }

    /// The position the decided visit `ticket` processes next.
    fn current(&self, ticket: u64) -> Result<(u8, Position<'c>), Error> {
        let visit = self.visit_at(ticket)?;
        if !matches!(visit.step, Step::Decided) {
            return Err(Error::VisitInProgress);
        }
        if visit.cursor >= visit.count {
            return Err(Error::WrongPosition);
        }
        Ok((visit.cursor, visit.position(visit.cursor)?))
    }

    /// Moves the decided visit past its current position.
    fn advance(&mut self, ticket: u64) -> Result<(), Error> {
        let visit = self.visit_mut(ticket)?;
        visit.cursor = visit.cursor.checked_add(1).ok_or(Error::Overflow)?;
        Ok(())
    }

    /// Quarantines cast position `index` of visit `ticket` by its record
    /// hash (kind 3, repeating its counters): the record leaves the batch
    /// and the records, and the visit stops counting once nothing of it is
    /// cast.
    pub(crate) fn quarantine_position(
        &mut self,
        ticket: u64,
        index: u8,
        sink: &mut dyn JournalSink,
        time_bucket: TimeBucket,
    ) -> Result<(), Error> {
        let position = self.visit_at(ticket)?.position(index)?;
        self.journal(
            sink,
            &EntryFields {
                kind: JournalKind::Quarantine,
                record_hash: position.hashes.record,
                share_package_hash: Hash512::ZERO,
                counters: &position.counters,
                include: position.issued,
                time_bucket,
            },
            None,
        )?;
        self.settle_quarantined(ticket, index)
    }

    /// The accounting of [`Self::quarantine_position`] once its entry is
    /// durable (also used at resume).
    pub(crate) fn settle_quarantined(&mut self, ticket: u64, index: u8) -> Result<(), Error> {
        let record = self.visit_at(ticket)?.position(index)?.hashes.record;
        self.withdraw_record(&record)?;
        let visit = self.visit_mut(ticket)?;
        visit.position_mut(index)?.settled = Settlement::Quarantined;
        visit.live = visit.live.checked_sub(1).ok_or(Error::Overflow)?;
        if visit.live == 0 {
            self.totals.visits = self.totals.visits.checked_sub(1).ok_or(Error::Overflow)?;
        }
        Ok(())
    }

    /// Journals the imprint entry (kind 6) of cast position `index`,
    /// repeating its record hash and counters.
    pub(crate) fn imprint_position(
        &mut self,
        ticket: u64,
        index: u8,
        sink: &mut dyn JournalSink,
        time_bucket: TimeBucket,
    ) -> Result<(), Error> {
        let position = self.visit_at(ticket)?.position(index)?;
        self.journal(
            sink,
            &EntryFields {
                kind: JournalKind::Imprinted,
                record_hash: position.hashes.record,
                share_package_hash: Hash512::ZERO,
                counters: &position.counters,
                include: position.issued,
                time_bucket,
            },
            None,
        )?;
        self.visit_mut(ticket)?.position_mut(index)?.settled = Settlement::Imprinted;
        Ok(())
    }

    /// Journals the label-printed entry (kind 8): the visit's decision
    /// digest, no counters.
    fn print_label(
        &mut self,
        ticket: u64,
        sink: &mut dyn JournalSink,
        time_bucket: TimeBucket,
    ) -> Result<(), Error> {
        let visit = self.visit_at(ticket)?;
        if !matches!(visit.step, Step::Processed) {
            return Err(Error::VisitInProgress);
        }
        if !visit.label_owed() {
            return Err(Error::NoLabel);
        }
        self.journal(
            sink,
            &EntryFields {
                kind: JournalKind::LabelPrinted,
                record_hash: visit.digest,
                share_package_hash: Hash512::ZERO,
                counters: &NO_COUNTERS,
                include: [false; MAX_MODULES],
                time_bucket,
            },
            None,
        )?;
        self.visit_mut(ticket)?.label = Label::Printed;
        Ok(())
    }

    /// Quarantines every cast position of the visit still counted as cast.
    fn quarantine_live(
        &mut self,
        ticket: u64,
        sink: &mut dyn JournalSink,
        time_bucket: TimeBucket,
    ) -> Result<(), Error> {
        let visit = self.visit_at(ticket)?;
        for (index, position) in visit.bound().enumerate() {
            if matches!(position.choice, Choice::Cast)
                && !matches!(position.settled, Settlement::Quarantined)
            {
                let index = u8::try_from(index).map_err(|_| Error::Capacity)?;
                self.quarantine_position(ticket, index, sink, time_bucket)?;
            }
        }
        Ok(())
    }

    /// Ends the open visit as it stands, whatever its step, when it cannot
    /// be completed: the voter left without deciding, `VisitEnd` did not
    /// match, a position failed to build or bind, the decision failed, the
    /// visit state was dropped (PROTOCOL.md §7.3, 결정 없이 끝난 방문).
    ///
    /// * Before the decision: every bound position is quarantined by its
    ///   record hash (kind 3, repeating the counters of its bound entry).
    ///   Then the ballot in flight, if it consumed counters, gets a
    ///   quarantine entry without record (kind 3, hash zero) with them;
    ///   one that consumed none is returned to the voter.
    /// * After the decision: every cast position not yet imprinted, and out
    ///   of district every cast position while the sticker entry is
    ///   missing, is quarantined by its record hash.
    ///
    /// Every paper of the visit not yet in the box goes to the quarantine
    /// envelope (checked papers to the spoil chute). The visit's work area
    /// should be dropped by the host; nothing in it is used again.
    ///
    /// # Errors
    /// [`Error::NoVisit`], [`Error::TimeRegression`], the journal's error;
    /// the visit stays open and the call can be repeated.
    pub fn abandon_visit(
        &mut self,
        sink: &mut dyn JournalSink,
        time_bucket: TimeBucket,
    ) -> Result<(), Error> {
        self.check_time(time_bucket)?;
        if self.visit.is_none() && self.in_flight.is_none() {
            return Err(Error::NoVisit);
        }
        // (an in-flight ballot without a visit cannot exist; the visit
        // opens with its first interpretation)
        if let Some(visit) = self.visit {
            match visit.step {
                Step::Building | Step::Ended | Step::Deciding => {
                    for (index, position) in visit.bound().enumerate() {
                        let index = u8::try_from(index).map_err(|_| Error::Capacity)?;
                        if matches!(position.settled, Settlement::Quarantined) {
                            continue;
                        }
                        self.quarantine_undecided(sink, position, time_bucket)?;
                        self.visit_mut(visit.ticket)?.position_mut(index)?.settled =
                            Settlement::Quarantined;
                    }
                }
                Step::Decided | Step::Processed => {
                    for (index, position) in visit.bound().enumerate() {
                        let index = u8::try_from(index).map_err(|_| Error::Capacity)?;
                        let owed = match position.settled {
                            Settlement::Open => true,
                            Settlement::Imprinted => visit.label_owed(),
                            Settlement::Quarantined => false,
                        };
                        if matches!(position.choice, Choice::Cast) && owed {
                            self.quarantine_position(visit.ticket, index, sink, time_bucket)?;
                        }
                    }
                }
            }
        }
        if let Some(flight) = self.in_flight {
            if flight.issued.contains(&true) {
                self.quarantine_unrecorded(sink, &flight.counters, flight.issued, time_bucket)?;
            }
            self.in_flight = None;
        }
        self.visit = None;
        Ok(())
    }

    /// A quarantine entry without record (kind 3, hash zero) consuming
    /// `counters`.
    fn quarantine_unrecorded(
        &mut self,
        sink: &mut dyn JournalSink,
        counters: &[u64; MAX_MODULES],
        include: [bool; MAX_MODULES],
        time_bucket: TimeBucket,
    ) -> Result<(), Error> {
        self.journal(
            sink,
            &EntryFields {
                kind: JournalKind::Quarantine,
                record_hash: Hash512::ZERO,
                share_package_hash: Hash512::ZERO,
                counters,
                include,
                time_bucket,
            },
            None,
        )?;
        self.count_quarantine()
    }

    /// A quarantine entry naming an undecided position's record (its bound
    /// entry is journaled, the decision entry is not), repeating its
    /// counters.
    fn quarantine_undecided(
        &mut self,
        sink: &mut dyn JournalSink,
        position: &Position<'c>,
        time_bucket: TimeBucket,
    ) -> Result<(), Error> {
        self.journal(
            sink,
            &EntryFields {
                kind: JournalKind::Quarantine,
                record_hash: position.hashes.record,
                share_package_hash: Hash512::ZERO,
                counters: &position.counters,
                include: position.issued,
                time_bucket,
            },
            None,
        )?;
        self.count_quarantine()
    }

    /// The staged `CastRecord` of position `index`, checked against its
    /// hash, for the uplink (only decided visits are published,
    /// PROTOCOL.md §7.8).
    fn staged_record<'o>(
        &self,
        ticket: u64,
        index: u8,
        staging: &mut dyn StagingPort,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], Error> {
        let visit = self.visit_at(ticket)?;
        if !matches!(visit.step, Step::Decided | Step::Processed) {
            return Err(Error::VisitInProgress);
        }
        let position = visit.position(index)?;
        fetch_checked(
            staging,
            index,
            Staged::Record,
            &position.hashes.record_object,
            out,
        )
    }
}

/// Fetches a staged object into `out` and checks it against its hash.
fn fetch_checked<'o>(
    staging: &mut dyn StagingPort,
    position: u8,
    kind: Staged,
    expected: &Hash512,
    out: &'o mut [u8],
) -> Result<&'o [u8], Error> {
    let len = staging.fetch(position, kind, out)?;
    let bytes: &'o [u8] = out;
    let bytes = bytes.get(..len).ok_or(Error::BufferTooSmall)?;
    if object_hash(bytes) == *expected {
        Ok(bytes)
    } else {
        Err(Error::StagedMismatch)
    }
}

/// The host's journal and staging store for a decision.
struct VisitIo<'a> {
    sink: &'a mut dyn JournalSink,
    staging: &'a mut dyn StagingPort,
    package: &'a mut [u8],
}

impl<'c, 'v> ReadyVisit<'c, 'v> {
    /// The visit's positions.
    #[must_use]
    pub fn positions(&self, open_box: &OpenBox<'c>) -> u8 {
        open_box
            .visit_at(self.ticket)
            .map_or(0, |visit| visit.count)
    }

    /// The ballot style of position `index`, for the decision screen, which
    /// shows the kinds of ballots in position order and never the choices.
    #[must_use]
    pub fn style(&self, open_box: &OpenBox<'c>, index: u8) -> Option<&'c BallotStyle<'c>> {
        let visit = open_box.visit_at(self.ticket).ok()?;
        visit.position(index).ok().map(|position| position.style)
    }

    /// Takes the voter's decision (PROTOCOL.md §7.3 steps 6–7): journals
    /// each position's entry in order (a cast position's record entry
    /// carries its share package, fetched from `staging` into `package`
    /// and checked against its hash), then the decision entry (kind 7,
    /// `record_hash` = `SHA3-512("ityv:visit:v1" ‖ 0x00 ‖ n ‖ (kind ‖
    /// record_hash)…)`), durable with them in one fsync. Only then do the
    /// records join the batch and the totals, and only the returned
    /// [`DecidedVisit`] can imprint or open (VC-054).
    ///
    /// # Errors
    /// [`Error::StaleVisit`], [`Error::InvalidDecision`] if a checked
    /// position is beyond the visit, [`Error::StagedMismatch`] if a staged
    /// package differs from the one bound, [`Error::TimeRegression`], the
    /// staging port's and the journal's errors. On error the visit's work
    /// area is wiped and the visit must be abandoned
    /// ([`OpenBox::abandon_visit`]).
    pub fn decide(
        self,
        open_box: &mut OpenBox<'c>,
        decision: Decision,
        sink: &mut dyn JournalSink,
        staging: &mut dyn StagingPort,
        package: &mut [u8],
        time_bucket: TimeBucket,
    ) -> Result<DecidedVisit<'c, 'v>, Error> {
        let Self {
            config,
            ticket,
            work,
        } = self;
        let mut io = VisitIo {
            sink,
            staging,
            package,
        };
        open_box.decide_visit(ticket, decision, &mut io, time_bucket)?;
        Ok(DecidedVisit {
            config,
            ticket,
            work,
        })
    }
}

impl<'c, 'v> DecidedVisit<'c, 'v> {
    /// The position to process next and what it was decided to be, or
    /// `None` once every position is processed.
    #[must_use]
    pub fn current(&self, open_box: &OpenBox<'c>) -> Option<(u8, Choice)> {
        open_box
            .current(self.ticket)
            .ok()
            .map(|(index, position)| (index, position.choice))
    }

    /// What the imprinter prints on the current position, which must be
    /// cast.
    ///
    /// # Errors
    /// [`Error::StaleVisit`], [`Error::WrongPosition`] if the current
    /// position is checked or none is left.
    pub fn imprint_command(&self, open_box: &OpenBox<'c>) -> Result<ImprintCommand, Error> {
        let (index, position) = open_box.current(self.ticket)?;
        if !matches!(position.choice, Choice::Cast) {
            return Err(Error::WrongPosition);
        }
        Ok(ImprintCommand {
            cast_id: self.work.0.position(index)?.cast_id.token().0,
        })
    }

    /// The imprinter printed the current position's cast id: journals the
    /// imprint entry (kind 6) and only then may the paper drop into the box
    /// (or the return tray). On error the paper must not move; the host
    /// abandons the visit.
    ///
    /// # Errors
    /// [`Error::StaleVisit`], [`Error::WrongPosition`],
    /// [`Error::TimeRegression`], the journal's error.
    pub fn imprinted(
        &mut self,
        open_box: &mut OpenBox<'c>,
        sink: &mut dyn JournalSink,
        time_bucket: TimeBucket,
    ) -> Result<(), Error> {
        let (index, position) = open_box.current(self.ticket)?;
        if !matches!(position.choice, Choice::Cast) {
            return Err(Error::WrongPosition);
        }
        open_box.imprint_position(self.ticket, index, sink, time_bucket)?;
        open_box.advance(self.ticket)
    }

    /// The imprint of the current cast position failed (VC-023): journals a
    /// quarantine entry naming its record, which leaves the batch; the
    /// paper goes to the quarantine envelope and the other positions go on.
    ///
    /// # Errors
    /// As [`Self::imprinted`].
    pub fn imprint_failed(
        &mut self,
        open_box: &mut OpenBox<'c>,
        sink: &mut dyn JournalSink,
        time_bucket: TimeBucket,
    ) -> Result<(), Error> {
        let (index, position) = open_box.current(self.ticket)?;
        if !matches!(position.choice, Choice::Cast) {
            return Err(Error::WrongPosition);
        }
        open_box.quarantine_position(self.ticket, index, sink, time_bucket)?;
        open_box.advance(self.ticket)
    }

    /// Opens the current position, which must be checked (PROTOCOL.md §8):
    /// writes the signed `ChallengeOpening` into `out`; its challenge entry
    /// is already durable, and the paper goes to the spoil chute without an
    /// imprint.
    ///
    /// # Errors
    /// [`Error::StaleVisit`], [`Error::WrongPosition`], signing and
    /// encoding errors.
    pub fn open_challenge<'o>(
        &mut self,
        open_box: &mut OpenBox<'c>,
        signer: Signer<'_>,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], Error> {
        let (index, position) = open_box.current(self.ticket)?;
        if !matches!(position.choice, Choice::Check) {
            return Err(Error::WrongPosition);
        }
        let len = write_opening(self.config, &position, self.work.0, index, signer, out)?;
        open_box.advance(self.ticket)?;
        let written: &'o [u8] = out;
        written.get(..len).ok_or(Error::BufferTooSmall)
    }

    /// The staged `CastRecord` of position `index` (cast or checked),
    /// checked against its hash, for publication.
    ///
    /// # Errors
    /// [`Error::StagedMismatch`] if the staged record differs from the one
    /// bound; the staging port's errors.
    pub fn record<'o>(
        &self,
        open_box: &OpenBox<'c>,
        staging: &mut dyn StagingPort,
        index: u8,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], Error> {
        open_box.staged_record(self.ticket, index, staging, out)
    }

    /// Every position is processed: the visit moves on to its sticker and
    /// slip.
    ///
    /// # Errors
    /// [`Error::StaleVisit`], [`Error::VisitIncomplete`] if a position is
    /// left.
    pub fn finish_positions(
        self,
        open_box: &mut OpenBox<'c>,
    ) -> Result<ProcessedVisit<'c, 'v>, Error> {
        let visit = open_box.visit_mut(self.ticket)?;
        if !matches!(visit.step, Step::Decided) || visit.cursor != visit.count {
            return Err(Error::VisitIncomplete);
        }
        visit.step = Step::Processed;
        let Self {
            config,
            ticket,
            work,
        } = self;
        Ok(ProcessedVisit {
            config,
            ticket,
            work,
        })
    }
}

impl<'c> ProcessedVisit<'c, '_> {
    /// What the sticker printer prints (out of district, PROTOCOL.md §7.3
    /// step 9): the envelope labels of the visit's cast ballots that are
    /// still cast, in position order.
    ///
    /// # Errors
    /// [`Error::StaleVisit`], [`Error::NoLabel`] in person, when nothing is
    /// cast, or once the sticker entry is durable.
    pub fn label_command(&self, open_box: &OpenBox<'c>) -> Result<LabelCommand, Error> {
        let visit = open_box.visit_at(self.ticket)?;
        if !visit.label_owed() {
            return Err(Error::NoLabel);
        }
        let mut command = LabelCommand {
            labels: [[0; 24]; MAX_VISIT_POSITIONS],
            count: 0,
        };
        for (index, position) in visit.bound().enumerate() {
            if matches!(position.choice, Choice::Cast)
                && matches!(position.settled, Settlement::Imprinted)
            {
                let index = u8::try_from(index).map_err(|_| Error::Capacity)?;
                let label = self
                    .work
                    .0
                    .position(index)?
                    .env_label
                    .ok_or(Error::NoLabel)?;
                *command
                    .labels
                    .get_mut(usize::from(command.count))
                    .ok_or(Error::Capacity)? = label;
                command.count = command.count.checked_add(1).ok_or(Error::Overflow)?;
            }
        }
        Ok(command)
    }

    /// The sticker came out: journals the label-printed entry (kind 8,
    /// `record_hash` = the visit's decision digest; the labels themselves
    /// are not journaled).
    ///
    /// # Errors
    /// [`Error::StaleVisit`], [`Error::NoLabel`],
    /// [`Error::TimeRegression`], the journal's error.
    pub fn label_printed(
        &mut self,
        open_box: &mut OpenBox<'c>,
        sink: &mut dyn JournalSink,
        time_bucket: TimeBucket,
    ) -> Result<(), Error> {
        open_box.print_label(self.ticket, sink, time_bucket)
    }

    /// The sticker could not be printed: the labels cannot be printed again
    /// later, so every cast record of the visit is quarantined and the
    /// return tray goes to the quarantine envelope (PROTOCOL.md §7.3,
    /// 재개 (3)).
    ///
    /// # Errors
    /// [`Error::StaleVisit`], [`Error::NoLabel`],
    /// [`Error::TimeRegression`], the journal's error.
    pub fn label_failed(
        &mut self,
        open_box: &mut OpenBox<'c>,
        sink: &mut dyn JournalSink,
        time_bucket: TimeBucket,
    ) -> Result<(), Error> {
        if !open_box.visit_at(self.ticket)?.label_owed() {
            return Err(Error::NoLabel);
        }
        open_box.quarantine_live(self.ticket, sink, time_bucket)
    }

    /// Writes the visit's signed `Slip` (PROTOCOL.md §7.7, VC-070): the
    /// tracking codes of the ballots cast in this visit, in position order,
    /// under one hybrid signature. Out of district only after the sticker
    /// entry.
    ///
    /// # Errors
    /// [`Error::StaleVisit`], [`Error::VoterCodeDisabled`],
    /// [`Error::NothingCast`], [`Error::LabelPending`], signing and
    /// encoding errors.
    pub fn slip<'o>(
        &self,
        open_box: &OpenBox<'c>,
        signer: Signer<'_>,
        time_bucket: TimeBucket,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], Error> {
        if !self.config.voter_code_enabled() {
            return Err(Error::VoterCodeDisabled);
        }
        let visit = open_box.visit_at(self.ticket)?;
        if visit.label_owed() {
            return Err(Error::LabelPending);
        }
        let mut codes = [Hash512::ZERO; MAX_VISIT_POSITIONS];
        let mut n = 0usize;
        for position in visit.bound() {
            if matches!(position.choice, Choice::Cast)
                && matches!(position.settled, Settlement::Imprinted)
            {
                *codes.get_mut(n).ok_or(Error::Capacity)? = position.hashes.record;
                n = n.checked_add(1).ok_or(Error::Overflow)?;
            }
        }
        let body = SlipBody::new(
            self.config.election_id(),
            self.config.station_id(),
            time_bucket,
            codes.get(..n).unwrap_or(&[]),
        )
        .ok_or(Error::NothingCast)?;
        let mut body_buf = [0u8; MAX_SLIP_BODY_LEN];
        let body_len = encode_object(SCHEMA_SLIP_BODY, SCHEMA_VERSION_1, &body, &mut body_buf)?;
        let body_bytes = body_buf.get(..body_len).ok_or(Error::BufferTooSmall)?;
        let mut sig = [0u8; HYBRID_SIG_LEN];
        signer.sign_into(PURPOSE_SLIP, body_bytes, &mut sig)?;
        let slip = Slip::new(body_bytes, &sig)?;
        let len = encode_object(SCHEMA_SLIP, SCHEMA_VERSION_1, &slip, out)?;
        let written: &'o [u8] = out;
        written.get(..len).ok_or(Error::BufferTooSmall)
    }

    /// The staged `CastRecord` of position `index`, checked against its
    /// hash, for publication.
    ///
    /// # Errors
    /// As [`DecidedVisit::record`].
    pub fn record<'o>(
        &self,
        open_box: &OpenBox<'c>,
        staging: &mut dyn StagingPort,
        index: u8,
        out: &'o mut [u8],
    ) -> Result<&'o [u8], Error> {
        open_box.staged_record(self.ticket, index, staging, out)
    }

    /// Ends the visit (PROTOCOL.md §7.3 step 11): the box takes the next
    /// visit and the visit's work area is wiped.
    ///
    /// # Errors
    /// [`Error::StaleVisit`], [`Error::LabelPending`] while the sticker is
    /// owed (print it, or report it failed).
    pub fn finish(self, open_box: &mut OpenBox<'c>) -> Result<(), Error> {
        let visit = open_box.visit_at(self.ticket)?;
        if visit.label_owed() {
            return Err(Error::LabelPending);
        }
        open_box.visit = None;
        drop(self);
        Ok(())
    }
}

/// Writes the `ChallengeOpening` object of position `index` (PROTOCOL.md
/// §8) into `out` and returns its length; the body is built in the visit's
/// opening scratch, which is wiped afterwards.
fn write_opening(
    config: &ElectionConfig<'_>,
    position: &Position<'_>,
    work: &mut VisitWork,
    index: u8,
    signer: Signer<'_>,
    out: &mut [u8],
) -> Result<usize, Error> {
    let result = write_opening_into(config, position, work, index, signer, out);
    work.opening.zeroize();
    result
}

fn write_opening_into(
    config: &ElectionConfig<'_>,
    position: &Position<'_>,
    work: &mut VisitWork,
    index: u8,
    signer: Signer<'_>,
    out: &mut [u8],
) -> Result<usize, Error> {
    let style = position.style;
    let k = usize::from(style.chunk_count());
    let VisitWork {
        positions,
        module_rand,
        opening,
        ..
    } = work;
    let secrets = positions.get(usize::from(index)).ok_or(Error::Capacity)?;
    let secret_rand = module_rand.get(usize::from(index)).ok_or(Error::Capacity)?;
    for (dst, src) in opening.rand.iter_mut().zip(secrets.rand.iter()).take(k) {
        dst.0 = src.to_bytes();
    }
    let rand =
        Scalars::new(opening.rand.get(..k).ok_or(Error::Capacity)?).ok_or(Error::Capacity)?;
    let modules = config.modules();
    let first = modules.first().ok_or(Error::Capacity)?;
    let mut openings: [ModuleOpening<'_>; MAX_MODULES] = core::array::from_fn(|_| ModuleOpening {
        module_id: first.module_id(),
        counter: 0,
        rand: rand.duplicate(),
        cid: Token192([0; 24]),
    });
    for (((((slot, module), cid), module_rand), row), &counter) in openings
        .iter_mut()
        .zip(modules)
        .zip(secrets.cids.iter())
        .zip(secret_rand.iter())
        .zip(opening.module_rand.iter_mut())
        .zip(position.counters.iter())
    {
        for (dst, src) in row.iter_mut().zip(module_rand.iter()).take(k) {
            dst.0 = src.to_bytes();
        }
        *slot = ModuleOpening {
            module_id: module.module_id(),
            counter,
            rand: Scalars::new(row.get(..k).ok_or(Error::Capacity)?).ok_or(Error::Capacity)?,
            cid: Token192(*cid),
        };
    }
    let body = ChallengeOpeningBody::new(&ChallengeOpeningParts {
        election_id: config.election_id(),
        box_id: config.box_id(),
        ballot_style_id: style.id(),
        record_hash: position.hashes.record,
        option_index: secrets.option,
        cast_id: secrets.cast_id.token(),
        rand: &rand,
        modules: openings.get(..modules.len()).ok_or(Error::Capacity)?,
    })
    .ok_or(Error::Capacity)?;
    let body_len = encode_object(
        SCHEMA_CHALLENGE_OPENING_BODY,
        SCHEMA_VERSION_1,
        &body,
        &mut opening.body,
    )?;
    let body_bytes = opening.body.get(..body_len).ok_or(Error::BufferTooSmall)?;
    let mut sig = [0u8; HYBRID_SIG_LEN];
    signer.sign_into(PURPOSE_CHALLENGE, body_bytes, &mut sig)?;
    let challenge = ChallengeOpening::new(body_bytes, &sig)?;
    Ok(encode_object(
        SCHEMA_CHALLENGE_OPENING,
        SCHEMA_VERSION_1,
        &challenge,
        out,
    )?)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::boxed::Box;

    pub(crate) const fn empty_slot() -> PositionSecrets {
        PositionSecrets::EMPTY
    }

    fn filled() -> Box<VisitWork> {
        let mut work = Box::new(VisitWork::new());
        work.ticket = 3;
        work.bound = 2;
        for slot in &mut work.positions {
            slot.option = 5;
            slot.cast_id = CastId::new(Token192([1; 24]));
            slot.env_label = Some([2; 24]);
            slot.rand = [Scalar::from_u64(3); ityv_crypto::MAX_CHUNKS];
            slot.cids = [[4; 24]; MAX_MODULES];
        }
        work.module_rand =
            [[[Scalar::from_u64(5); ityv_crypto::MAX_CHUNKS]; MAX_MODULES]; MAX_VISIT_POSITIONS];
        work.opening.rand = [Scalar32([6; 32]); ityv_crypto::MAX_CHUNKS];
        work.opening.module_rand = [[Scalar32([7; 32]); ityv_crypto::MAX_CHUNKS]; MAX_MODULES];
        work.opening.body = [8; MAX_CHALLENGE_BODY_LEN];
        work
    }

    #[test]
    fn is_clear_sees_every_field_and_zeroize_clears_it() {
        assert!(VisitWork::new().is_clear());
        assert!(VisitWork::default().is_clear());
        let dirty: [fn(&mut VisitWork); 11] = [
            |w| w.ticket = 1,
            |w| w.bound = 1,
            |w| w.positions[7].option = 1,
            |w| w.positions[7].cast_id = CastId::new(Token192([1; 24])),
            |w| w.positions[7].env_label = Some([0; 24]),
            |w| w.positions[7].rand[7] = Scalar::ONE,
            |w| w.positions[7].cids[6][23] = 1,
            |w| w.module_rand[7][6][7] = Scalar::ONE,
            |w| w.opening.rand[7].0[31] = 1,
            |w| w.opening.module_rand[6][7].0[31] = 1,
            |w| w.opening.body[MAX_CHALLENGE_BODY_LEN - 1] = 1,
        ];
        for (i, make_dirty) in dirty.iter().enumerate() {
            let mut work = Box::new(VisitWork::new());
            make_dirty(&mut work);
            assert!(!work.is_clear(), "field {i}");
            work.zeroize();
            assert!(work.is_clear(), "field {i} after zeroize");
        }
        let mut work = filled();
        work.zeroize();
        assert!(work.is_clear());
        assert_eq!(std::format!("{work:?}"), "VisitWork(..)");
    }

    #[test]
    fn the_guard_and_the_first_slot_wipe_the_work_area() {
        let mut work = filled();
        drop(VisitGuard(&mut work));
        assert!(work.is_clear());
        let mut work = filled();
        work.ticket = 9;
        let (slot, rand) = work.slot_for(4, 0).unwrap();
        assert!(slot.is_clear() && rand.iter().flatten().all(Scalar::is_zero));
        assert!(work.positions.iter().all(PositionSecrets::is_clear));
        assert_eq!((work.ticket, work.bound), (4, 0));
        // later positions need the same visit and the next index
        work.note_bound();
        assert!(work.slot_for(4, 1).is_ok());
        assert_eq!(work.slot_for(5, 1).err(), Some(Error::StaleVisit));
        assert_eq!(work.slot_for(4, 2).err(), Some(Error::StaleVisit));
    }

    #[test]
    fn decisions_name_positions_by_bit() {
        assert_eq!(Decision::CAST_ALL.choice(0), Choice::Cast);
        let d = Decision::checking(&[0, 2, 7]).unwrap();
        assert_eq!(d, Decision::from_checks(0b1000_0101));
        let choices: std::vec::Vec<Choice> = (0..8).map(|p| d.choice(p)).collect();
        assert_eq!(
            choices,
            [
                Choice::Check,
                Choice::Cast,
                Choice::Check,
                Choice::Cast,
                Choice::Cast,
                Choice::Cast,
                Choice::Cast,
                Choice::Check
            ]
        );
        assert_eq!(d.choice(8), Choice::Cast);
        assert_eq!(d.choice(200), Choice::Cast);
        assert!(Decision::checking(&[8]).is_none());
        assert!(Decision::checking(&[1, 255]).is_none());
        assert!(d.fits(8));
        assert!(!d.fits(7));
        assert!(Decision::from_checks(0b11).fits(2));
        assert!(!Decision::from_checks(0b100).fits(2));
        assert!(Decision::CAST_ALL.fits(0));
    }

    #[test]
    fn commands_redact_and_zeroize() {
        let mut imprint = ImprintCommand { cast_id: [1; 24] };
        assert_eq!(std::format!("{imprint:?}"), "ImprintCommand(..)");
        imprint.zeroize();
        assert_eq!(imprint.cast_id(), &[0; 24]);
        let mut label = LabelCommand {
            labels: [[2; 24]; MAX_VISIT_POSITIONS],
            count: 3,
        };
        assert_eq!(label.labels().len(), 3);
        assert_eq!(std::format!("{label:?}"), "LabelCommand(..)");
        label.zeroize();
        assert!(label.labels().is_empty());
        assert!(label.labels.iter().flatten().all(|&b| b == 0));
    }

    #[test]
    fn a_visit_takes_eight_positions_while_building() {
        let mut visit = Visit::new(1);
        assert!(visit.accepts_position().is_ok());
        visit.count = 7;
        assert!(visit.accepts_position().is_ok());
        visit.count = 8;
        assert_eq!(visit.accepts_position(), Err(Error::VisitFull));
        visit.count = 1;
        for step in [Step::Ended, Step::Deciding, Step::Decided, Step::Processed] {
            visit.step = step;
            assert_eq!(visit.accepts_position(), Err(Error::VisitInProgress));
        }
        visit.label = Label::Pending;
        assert!(!visit.label_owed(), "nothing live");
        visit.live = 1;
        assert!(visit.label_owed());
        visit.label = Label::Printed;
        assert!(!visit.label_owed());
    }
}

#[cfg(test)]
mod memory {
    use super::*;
    use crate::ballot::BallotWork;

    /// The unit's memory for a full visit of eight ballots, beyond one
    /// ballot's work area (which positions borrow in turn): the visit's
    /// work area and its bookkeeping in the box. The staged records and
    /// packages live with the host.
    #[test]
    fn a_full_visit_costs_well_under_its_budget() {
        let visit_work = core::mem::size_of::<VisitWork>();
        let bookkeeping = core::mem::size_of::<Option<Visit<'static>>>();
        let state = core::mem::size_of::<DecidedVisit<'static, 'static>>();
        let ballot = core::mem::size_of::<BallotWork>();
        let beyond_one_ballot = visit_work + bookkeeping + state;
        std::println!(
            "BallotWork {ballot} B; VisitWork {visit_work} B; visit bookkeeping {bookkeeping} B; \
             visit state {state} B; a full visit beyond one ballot: {beyond_one_ballot} B"
        );
        assert!(beyond_one_ballot <= 32 * 1024, "{beyond_one_ballot}");
        assert!(ballot <= 30 * 1024, "{ballot}");
        // one position's share of the visit work area
        let per_position =
            core::mem::size_of::<PositionSecrets>() + core::mem::size_of::<ModuleRand>();
        assert!(per_position <= 2_400, "{per_position}");
    }
}
