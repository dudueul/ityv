//! The ballot-box life cycle as typestate (PROTOCOL.md §10, VC-037..040).
//!
//! ```text
//! Provisioned ──open──▶ Open ◀──end_fallback── Fallback
//!                        │  └──declare_fallback──▶ │
//!                        └──────close──────────────┴──▶ Closed ──count──▶ Counted ──audited──▶ Audited
//! ```
//!
//! Each transition consumes the box and returns a [`Transition`]: the box
//! in its next state, or the unchanged box with the reason for refusal, so
//! that a malformed event never loses the state. Events inside a state
//! (records, challenges, batches, custody handoffs) borrow the box mutably.
//!
//! A close is recorded whatever its counts say; violated invariants become
//! sticky holds ([`crate::close::count_verdict`]). A close without the
//! device signature is a `BoxCloseManual` and holds until a `LateBoxClose`
//! with matching human counts replaces its verdict; a late batch close that
//! attests every remaining record resolves the open-batch hold. Nothing
//! else removes a hold.
//!
//! After close the box takes no record (VC-039): a closed box has no
//! `record` method.
//!
//! ```compile_fail
//! # use ityv_state::boxes::{BallotBox, Closed};
//! # use ityv_state::auth::{BallotMark, Cap};
//! # use ityv_encoding::CastRecordBody;
//! fn record_after_close<'a>(
//!     closed: &mut BallotBox<'a, Closed<'a>>,
//!     cap: &Cap<'a, BallotMark>,
//!     record: &CastRecordBody<'a>,
//! ) {
//!     let _ = closed.record(cap, record);
//! }
//! ```
//!
//! The same call compiles on an open box:
//!
//! ```
//! # use ityv_state::boxes::{BallotBox, Open};
//! # use ityv_state::auth::{BallotMark, Cap};
//! # use ityv_encoding::CastRecordBody;
//! fn record_while_open<'a>(
//!     open: &mut BallotBox<'a, Open>,
//!     cap: &Cap<'a, BallotMark>,
//!     record: &CastRecordBody<'a>,
//! ) {
//!     let _ = open.record(cap, record);
//! }
//! ```
//!
//! A box is opened once: `open` consumes the provisioned box, and an open
//! box has no `open` method (ITYV-BEH-034, ITYV-BEH-048).
//!
//! ```compile_fail
//! # use ityv_state::boxes::{BallotBox, BoxOpening, Open};
//! fn reopen<'a>(open: BallotBox<'a, Open>, opening: &BoxOpening<'a>) {
//!     let _ = open.open(opening);
//! }
//! ```

use ityv_crypto::sig::MLDSA87_SIG_LEN;
use ityv_crypto::{HybridSignature, HybridSigned, HybridVerifyingKey, Verified};
use ityv_encoding::{
    Attestation, BatchAttestBody, BoxClose, BoxId, CastRecordBody, ChallengeOpeningBody,
    CloseCounts, ElectionId, HYBRID_SIG_LEN, MAX_MODULES, ModuleId, OrgId,
};

use crate::auth::{BallotMark, Cap, PublicBoard, Rla};
use crate::close::{
    CountFacts, Observed, RosterEntry, check_close_witnesses, check_witnesses, count_verdict,
    modules_gap_free,
};
use crate::custody::{CustodyChain, CustodyHandoff, SealChange};
use crate::error::Error;
use crate::hold::{HoldReason, HoldSet};
use crate::issuance::{EnvelopeIssuance, IssuanceCount};
use crate::record::{Profile, RecordState, is_test_style};

/// Signature purpose of the device's box-close signature.
pub const PURPOSE_BOX_CLOSE: &[u8] = b"box-close";

/// Signature purpose of the device's late box-close signature.
pub const PURPOSE_LATE_BOX_CLOSE: &[u8] = b"late-box-close";

/// What the genesis fixes for one box (minimal input; the genesis schema
/// is an M5 encoding task).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoxSpec<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The box.
    pub box_id: BoxId<'a>,
    /// The collection profile.
    pub profile: Profile,
    /// The chamber modules registered in the genesis.
    pub registered_modules: &'a [ModuleId<'a>],
    /// The box's commitment-unit key.
    pub device_key: &'a HybridVerifyingKey,
    /// The registered clerks and observers.
    pub roster: &'a [RosterEntry<'a>],
    /// The custody route: organisations from the station to the counting
    /// centre.
    pub route: &'a [OrgId<'a>],
}

/// A `BoxOpened` event (minimal input).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoxOpening<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The box.
    pub box_id: BoxId<'a>,
    /// The modules attached to the box (none before stage 2).
    pub modules: &'a [ModuleId<'a>],
    /// Whether every seal number matched.
    pub seals_match: bool,
    /// What the box held when opened (must be 0).
    pub initial_count: u64,
    /// Two clerks and two observers of different organisations.
    pub witnesses: &'a [Attestation<'a>],
}

/// A `FallbackDeclared` or `FallbackEnded` event (minimal input).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FallbackEvent<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The box.
    pub box_id: BoxId<'a>,
    /// Two clerks and two observers of different organisations.
    pub witnesses: &'a [Attestation<'a>],
}

/// What people count at close beyond the `BoxCloseBody` (ADR-0025, M5
/// encoding task).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PhysicalCounts {
    /// Envelopes in the spoil and quarantine bag.
    pub spoil_envelopes: u64,
}

/// A `LateBatchClose` event: the batch body and its witnesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LateBatchClose<'a, 'b> {
    /// The batch body.
    pub batch: &'b BatchAttestBody<'b>,
    /// Two clerks and two observers of different organisations.
    pub witnesses: &'a [Attestation<'a>],
}

/// An `ImprintAudit` event from the counting centre (minimal input).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImprintAudit<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The box.
    pub box_id: BoxId<'a>,
    /// Ballots without an imprint.
    pub unimprinted: u64,
    /// Repeated cast identifiers.
    pub duplicate_cast_ids: u64,
    /// The signers.
    pub witnesses: &'a [Attestation<'a>],
}

/// State: provisioned in the genesis, not yet opened.
#[derive(Debug)]
pub struct Provisioned(());

/// State: open, taking records.
#[derive(Debug)]
pub struct Open(());

/// State: open in fallback (no scanner; ballots go through the emergency
/// slot without records).
#[derive(Debug)]
pub struct Fallback(());

/// State: closed, in custody.
#[derive(Debug)]
pub struct Closed<'a> {
    counts: CloseCounts,
    open_batches: u8,
    manual: bool,
    physical: PhysicalCounts,
    envelopes: Option<EnvelopeIssuance>,
    close_holds: HoldSet,
    custody: CustodyChain<'a>,
}

/// State: counted at the counting centre.
#[derive(Debug)]
pub struct Counted<'a>(Closed<'a>);

/// State: audited.
#[derive(Debug)]
pub struct Audited<'a>(Closed<'a>);

/// The result of a state-changing transition.
#[must_use = "a refused transition returns the unchanged box"]
#[derive(Debug)]
pub enum Transition<A, B> {
    /// The box in its next state.
    Done(B),
    /// The unchanged box and why the transition was refused.
    Refused(A, Error),
}

impl<A, B> Transition<A, B> {
    /// The next state, dropping the unchanged box on refusal.
    ///
    /// # Errors
    /// The refusal's error.
    pub fn into_result(self) -> Result<B, Error> {
        match self {
            Self::Done(next) => Ok(next),
            Self::Refused(_, error) => Err(error),
        }
    }

    /// The refusal's error, if refused.
    #[must_use]
    pub const fn error(&self) -> Option<Error> {
        match self {
            Self::Done(_) => None,
            Self::Refused(_, error) => Some(*error),
        }
    }
}

/// A ballot box in state `S`.
#[derive(Debug)]
pub struct BallotBox<'a, S> {
    base: Base<'a>,
    state: S,
}

/// What every state shares.
#[derive(Debug)]
struct Base<'a> {
    spec: BoxSpec<'a>,
    modules: &'a [ModuleId<'a>],
    observed: Observed,
    fallback_declared: bool,
    holds: HoldSet,
}

fn same_signature(bytes: &[u8; HYBRID_SIG_LEN], signature: &HybridSignature) -> bool {
    match bytes.split_first_chunk::<MLDSA87_SIG_LEN>() {
        Some((mldsa87, ed25519)) => {
            mldsa87 == signature.mldsa87() && ed25519 == signature.ed25519().as_slice()
        }
        None => false,
    }
}

/// Whether the close carries a device signature that `token` verified
/// under `key` and `purpose`.
fn device_signed(
    close: &BoxClose<'_>,
    token: Option<&Verified<HybridSigned<'_>>>,
    key: &HybridVerifyingKey,
    purpose: &[u8],
) -> Result<bool, Error> {
    match (close.device_sig(), token) {
        (None, None) => Ok(false),
        (Some(_), None) => Err(Error::Unverified),
        (None, Some(_)) => Err(Error::SignatureObject),
        (Some(bytes), Some(token)) => {
            let signed = token.get();
            if signed.purpose().as_bytes() != purpose
                || signed.object() != close.body_bytes()
                || !same_signature(bytes, signed.signature())
            {
                return Err(Error::SignatureObject);
            }
            if signed.key() != key {
                return Err(Error::SignatureSigner);
            }
            Ok(true)
        }
    }
}

impl<'a> Base<'a> {
    fn check_target(&self, election_id: ElectionId<'_>, box_id: BoxId<'_>) -> Result<(), Error> {
        if election_id.as_bytes() == self.spec.election_id.as_bytes()
            && box_id.as_bytes() == self.spec.box_id.as_bytes()
        {
            Ok(())
        } else {
            Err(Error::Mismatch)
        }
    }

    fn check_witnesses(&self, witnesses: &[Attestation<'_>]) -> Result<(), Error> {
        check_witnesses(witnesses, self.spec.roster)
    }

    fn opening(&self, opening: &BoxOpening<'a>) -> Result<HoldSet, Error> {
        self.check_target(opening.election_id, opening.box_id)?;
        if opening.modules.len() > MAX_MODULES {
            return Err(Error::NotRegistered);
        }
        for (index, module) in opening.modules.iter().enumerate() {
            let registered = self
                .spec
                .registered_modules
                .iter()
                .any(|r| r.as_bytes() == module.as_bytes());
            if !registered {
                return Err(Error::NotRegistered);
            }
            let repeated = opening
                .modules
                .iter()
                .take(index)
                .any(|m| m.as_bytes() == module.as_bytes());
            if repeated {
                return Err(Error::Duplicate);
            }
        }
        self.check_witnesses(opening.witnesses)?;
        Ok(HoldSet::empty()
            .with_if(!opening.seals_match, HoldReason::SealMismatch)
            .with_if(opening.initial_count != 0, HoldReason::OpeningNonZero))
    }

    fn record(
        &mut self,
        cap: &Cap<'_, BallotMark>,
        record: &CastRecordBody<'_>,
    ) -> Result<RecordState, Error> {
        cap.check_election(self.spec.election_id)?;
        self.check_target(record.election_id(), record.box_id())?;
        let modules = self.modules;
        let opened = record.module_counters().iter().all(|c| {
            modules
                .iter()
                .any(|m| m.as_bytes() == c.module_id.as_bytes())
        });
        if !opened {
            return Err(Error::NotRegistered);
        }
        self.observed.records = self
            .observed
            .records
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        Ok(RecordState::new(
            self.spec.profile,
            is_test_style(record.ballot_style_id()),
        ))
    }

    fn challenge(&mut self, opening: &ChallengeOpeningBody<'_>) -> Result<(), Error> {
        if matches!(self.spec.profile, Profile::ReceiptScan) {
            return Err(Error::Profile);
        }
        self.check_target(opening.election_id(), opening.box_id())?;
        self.observed.challenged = self
            .observed
            .challenged
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        Ok(())
    }

    fn batch(&mut self, batch: &BatchAttestBody<'_>) -> Result<(), Error> {
        self.check_target(batch.election_id(), batch.box_id())?;
        self.observed.attested = self
            .observed
            .attested
            .checked_add(u64::from(batch.record_count()))
            .ok_or(Error::Overflow)?;
        Ok(())
    }

    fn fallback(&self, event: &FallbackEvent<'_>) -> Result<(), Error> {
        self.check_target(event.election_id, event.box_id)?;
        self.check_witnesses(event.witnesses)
    }

    fn verdict(
        &self,
        counts: &CloseCounts,
        close: &BoxClose<'_>,
        physical: PhysicalCounts,
        envelopes: Option<EnvelopeIssuance>,
    ) -> HoldSet {
        let body = close.body();
        let facts = CountFacts {
            profile: self.spec.profile,
            counts: *counts,
            open_batches: body.open_batches(),
            observed: self.observed,
            spoil_envelopes: physical.spoil_envelopes,
            fallback_declared: self.fallback_declared,
            envelopes,
        };
        count_verdict(&facts).with_if(
            !modules_gap_free(counts, body.module_counters(), self.modules),
            HoldReason::ModuleCounterGap,
        )
    }

    fn close(
        &self,
        close: &BoxClose<'_>,
        device: Option<&Verified<HybridSigned<'_>>>,
        physical: PhysicalCounts,
        issuance: Option<&IssuanceCount<'_>>,
    ) -> Result<Closed<'a>, Error> {
        let body = close.body();
        self.check_target(body.election_id(), body.box_id())?;
        check_close_witnesses(close, self.spec.roster)?;
        if let Some(issuance) = issuance {
            if issuance.election_id.as_bytes() != self.spec.election_id.as_bytes() {
                return Err(Error::Mismatch);
            }
            self.check_witnesses(issuance.witnesses)?;
        }
        let signed = device_signed(close, device, self.spec.device_key, PURPOSE_BOX_CLOSE)?;
        let envelopes = issuance.and_then(|i| i.envelopes);
        let counts = *body.counts();
        let verdict = self
            .verdict(&counts, close, physical, envelopes)
            .with_if(!signed, HoldReason::ManualClose);
        let expected = match self.spec.profile {
            Profile::Absentee => counts.envelopes,
            Profile::InPerson | Profile::ReceiptScan => counts.paper,
        };
        let custody = CustodyChain::new(
            self.spec.election_id,
            self.spec.box_id,
            self.spec.route,
            *body.seal_digest(),
            expected,
        )?;
        Ok(Closed {
            counts,
            open_batches: body.open_batches(),
            manual: !signed,
            physical,
            envelopes,
            close_holds: verdict,
            custody,
        })
    }

    fn late_close(
        &self,
        closed: &mut Closed<'a>,
        close: &BoxClose<'_>,
        device: &Verified<HybridSigned<'_>>,
    ) -> Result<(), Error> {
        if !closed.manual || close.device_sig().is_none() {
            return Err(Error::LateClose);
        }
        let body = close.body();
        self.check_target(body.election_id(), body.box_id())?;
        check_close_witnesses(close, self.spec.roster)?;
        device_signed(
            close,
            Some(device),
            self.spec.device_key,
            PURPOSE_LATE_BOX_CLOSE,
        )?;
        let late = *body.counts();
        let verdict = self.verdict(&late, close, closed.physical, closed.envelopes);
        let humans_match = late.paper == closed.counts.paper
            && late.envelopes == closed.counts.envelopes
            && late.stickers == closed.counts.stickers;
        if humans_match {
            closed.counts = late;
            closed.open_batches = body.open_batches();
            closed.manual = false;
            closed.close_holds = verdict;
        } else {
            closed.close_holds = closed
                .close_holds
                .union(verdict)
                .with(HoldReason::LateCloseDiffers);
        }
        Ok(())
    }

    fn late_batch(
        &mut self,
        closed: &mut Closed<'a>,
        late: &LateBatchClose<'_, '_>,
    ) -> Result<(), Error> {
        let batch = late.batch;
        self.check_target(batch.election_id(), batch.box_id())?;
        self.check_witnesses(late.witnesses)?;
        let attested = self
            .observed
            .attested
            .checked_add(u64::from(batch.record_count()))
            .ok_or(Error::Overflow)?;
        if attested > self.observed.records {
            return Err(Error::BatchExceedsRecords);
        }
        self.observed.attested = attested;
        if attested == self.observed.records {
            closed.close_holds = closed.close_holds.without(HoldReason::OpenBatches);
        }
        Ok(())
    }
}

impl<'a, S> BallotBox<'a, S> {
    /// The election.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.base.spec.election_id
    }

    /// The box.
    #[must_use]
    pub const fn box_id(&self) -> BoxId<'a> {
        self.base.spec.box_id
    }

    /// The collection profile.
    #[must_use]
    pub const fn profile(&self) -> Profile {
        self.base.spec.profile
    }

    /// The modules opened in the box.
    #[must_use]
    pub const fn modules(&self) -> &'a [ModuleId<'a>] {
        self.base.modules
    }

    /// What the ledger shows for the box so far.
    #[must_use]
    pub const fn observed(&self) -> Observed {
        self.base.observed
    }

    /// Whether a fallback was declared.
    #[must_use]
    pub const fn fallback_declared(&self) -> bool {
        self.base.fallback_declared
    }

    fn with_state<T>(self, state: T) -> BallotBox<'a, T> {
        BallotBox {
            base: self.base,
            state,
        }
    }
}

impl<'a> BallotBox<'a, Provisioned> {
    /// A box the genesis provisions.
    ///
    /// # Errors
    /// [`Error::Mismatch`] if the capability is for another election,
    /// [`Error::CustodyRoute`] if the route has fewer than two stops.
    pub fn provision(spec: BoxSpec<'a>, cap: &Cap<'_, PublicBoard>) -> Result<Self, Error> {
        cap.check_election(spec.election_id)?;
        if spec.route.len() < 2 {
            return Err(Error::CustodyRoute);
        }
        Ok(Self {
            base: Base {
                spec,
                modules: &[],
                observed: Observed::ZERO,
                fallback_declared: false,
                holds: HoldSet::empty(),
            },
            state: Provisioned(()),
        })
    }

    /// The holds so far.
    #[must_use]
    pub const fn holds(&self) -> HoldSet {
        self.base.holds
    }

    /// Opens the box (`BoxOpened`). A seal mismatch or a non-empty box
    /// opens under hold.
    ///
    /// Refused with [`Error::Mismatch`] for another box,
    /// [`Error::NotRegistered`] for a module not in the genesis or more
    /// than seven modules (VC-037), [`Error::Duplicate`] for a repeated
    /// module, and the errors of [`check_witnesses`].
    pub fn open(self, opening: &BoxOpening<'a>) -> Transition<Self, BallotBox<'a, Open>> {
        match self.base.opening(opening) {
            Ok(holds) => {
                let mut open = self.with_state(Open(()));
                open.base.modules = opening.modules;
                open.base.holds = open.base.holds.union(holds);
                Transition::Done(open)
            }
            Err(error) => Transition::Refused(self, error),
        }
    }
}

impl<'a> BallotBox<'a, Open> {
    /// The holds so far.
    #[must_use]
    pub const fn holds(&self) -> HoldSet {
        self.base.holds
    }

    /// Records a cast record for this box and returns its initial state.
    ///
    /// # Errors
    /// [`Error::Mismatch`] for another election or box,
    /// [`Error::NotRegistered`] if a module counter names a module not
    /// opened in the box, [`Error::Overflow`].
    pub fn record(
        &mut self,
        cap: &Cap<'_, BallotMark>,
        record: &CastRecordBody<'_>,
    ) -> Result<RecordState, Error> {
        self.base.record(cap, record)
    }

    /// Records a challenge opening.
    ///
    /// # Errors
    /// [`Error::Profile`] in a receipt-scan box, [`Error::Mismatch`] for
    /// another box, [`Error::Overflow`].
    pub fn challenge(&mut self, opening: &ChallengeOpeningBody<'_>) -> Result<(), Error> {
        self.base.challenge(opening)
    }

    /// Records a batch attestation.
    ///
    /// # Errors
    /// [`Error::Mismatch`] for another box, [`Error::Overflow`].
    pub fn batch(&mut self, batch: &BatchAttestBody<'_>) -> Result<(), Error> {
        self.base.batch(batch)
    }

    /// Declares a fallback (`FallbackDeclared`, §7.3).
    ///
    /// Refused with [`Error::Mismatch`] for another box and the errors of
    /// [`check_witnesses`].
    pub fn declare_fallback(
        self,
        event: &FallbackEvent<'_>,
    ) -> Transition<Self, BallotBox<'a, Fallback>> {
        match self.base.fallback(event) {
            Ok(()) => {
                let mut fallback = self.with_state(Fallback(()));
                fallback.base.fallback_declared = true;
                Transition::Done(fallback)
            }
            Err(error) => Transition::Refused(self, error),
        }
    }

    /// Closes the box (`BoxClose`, or `BoxCloseManual` without a device
    /// signature). `device` is the verification token of the close's
    /// device signature (purpose `box-close`, the box's device key);
    /// `issuance` is the station's `IssuanceCount`, which an
    /// out-of-district box needs for its envelope count.
    ///
    /// Refused with [`Error::Mismatch`] for another box or election, the
    /// errors of [`check_witnesses`], [`Error::Unverified`] for a device
    /// signature without token, [`Error::SignatureObject`] or
    /// [`Error::SignatureSigner`] for a token that does not cover it.
    pub fn close(
        self,
        close: &BoxClose<'_>,
        device: Option<&Verified<HybridSigned<'_>>>,
        physical: PhysicalCounts,
        issuance: Option<&IssuanceCount<'_>>,
    ) -> Transition<Self, BallotBox<'a, Closed<'a>>> {
        match self.base.close(close, device, physical, issuance) {
            Ok(closed) => Transition::Done(self.with_state(closed)),
            Err(error) => Transition::Refused(self, error),
        }
    }
}

impl<'a> BallotBox<'a, Fallback> {
    /// The holds so far.
    #[must_use]
    pub const fn holds(&self) -> HoldSet {
        self.base.holds
    }

    /// Records a cast record made before the fallback. Uplinks store and
    /// forward (PROTOCOL.md §5.8), so a record signed before the
    /// declaration can reach the ledger after it; no record is made while
    /// the scanner is down, which the close's counts then show.
    ///
    /// # Errors
    /// As the open box's `record`.
    pub fn record(
        &mut self,
        cap: &Cap<'_, BallotMark>,
        record: &CastRecordBody<'_>,
    ) -> Result<RecordState, Error> {
        self.base.record(cap, record)
    }

    /// Records a challenge opening made before the fallback.
    ///
    /// # Errors
    /// As the open box's `challenge`.
    pub fn challenge(&mut self, opening: &ChallengeOpeningBody<'_>) -> Result<(), Error> {
        self.base.challenge(opening)
    }

    /// Records a batch attestation of records made before the fallback.
    ///
    /// # Errors
    /// [`Error::Mismatch`] for another box, [`Error::Overflow`].
    pub fn batch(&mut self, batch: &BatchAttestBody<'_>) -> Result<(), Error> {
        self.base.batch(batch)
    }

    /// Ends the fallback (`FallbackEnded`).
    ///
    /// Refused with [`Error::Mismatch`] for another box and the errors of
    /// [`check_witnesses`].
    pub fn end_fallback(self, event: &FallbackEvent<'_>) -> Transition<Self, BallotBox<'a, Open>> {
        match self.base.fallback(event) {
            Ok(()) => Transition::Done(self.with_state(Open(()))),
            Err(error) => Transition::Refused(self, error),
        }
    }

    /// Closes the box while in fallback, as the open box's `close`.
    pub fn close(
        self,
        close: &BoxClose<'_>,
        device: Option<&Verified<HybridSigned<'_>>>,
        physical: PhysicalCounts,
        issuance: Option<&IssuanceCount<'_>>,
    ) -> Transition<Self, BallotBox<'a, Closed<'a>>> {
        match self.base.close(close, device, physical, issuance) {
            Ok(closed) => Transition::Done(self.with_state(closed)),
            Err(error) => Transition::Refused(self, error),
        }
    }
}

impl Closed<'_> {
    fn holds(&self) -> HoldSet {
        self.close_holds.union(self.custody.holds())
    }
}

impl<'a> BallotBox<'a, Closed<'a>> {
    /// Every hold: opening, close and custody.
    #[must_use]
    pub fn holds(&self) -> HoldSet {
        self.base.holds.union(self.state.holds())
    }

    /// The counts of the close in force (the late close's once it resolved
    /// a manual close).
    #[must_use]
    pub const fn counts(&self) -> &CloseCounts {
        &self.state.counts
    }

    /// Whether the close in force lacks the device signature.
    #[must_use]
    pub const fn is_manual(&self) -> bool {
        self.state.manual
    }

    /// Batches open at the close in force.
    #[must_use]
    pub const fn open_batches(&self) -> u8 {
        self.state.open_batches
    }

    /// The custody chain.
    #[must_use]
    pub const fn custody(&self) -> &CustodyChain<'a> {
        &self.state.custody
    }

    /// Records a `LateBoxClose` for a manual close. `device` must verify
    /// its device signature with purpose `late-box-close`. If the human
    /// counts (paper, envelopes, stickers) match the manual close, the late
    /// close's verdict replaces the manual close's, which removes
    /// [`HoldReason::ManualClose`]; otherwise every earlier reason stays and
    /// [`HoldReason::LateCloseDiffers`] is added.
    ///
    /// # Errors
    /// [`Error::LateClose`] if the close in force is not manual or the late
    /// close has no device signature, [`Error::Mismatch`], the errors of
    /// [`check_witnesses`], [`Error::SignatureObject`],
    /// [`Error::SignatureSigner`].
    pub fn late_close(
        &mut self,
        close: &BoxClose<'_>,
        device: &Verified<HybridSigned<'_>>,
    ) -> Result<(), Error> {
        self.base.late_close(&mut self.state, close, device)
    }

    /// Records a `LateBatchClose`. Once every observed record is attested,
    /// [`HoldReason::OpenBatches`] is resolved.
    ///
    /// # Errors
    /// [`Error::Mismatch`], the errors of [`check_witnesses`],
    /// [`Error::BatchExceedsRecords`], [`Error::Overflow`].
    pub fn late_batch(&mut self, late: &LateBatchClose<'_, '_>) -> Result<(), Error> {
        self.base.late_batch(&mut self.state, late)
    }

    /// Records a seal change ([`CustodyChain::seal_change`]).
    ///
    /// # Errors
    /// As [`CustodyChain::seal_change`].
    pub fn seal_change(&mut self, change: &SealChange<'_>) -> Result<(), Error> {
        self.state.custody.seal_change(change)
    }

    /// Records a custody handoff ([`CustodyChain::handoff`]).
    ///
    /// # Errors
    /// As [`CustodyChain::handoff`].
    pub fn handoff(&mut self, handoff: &CustodyHandoff<'a>) -> Result<(), Error> {
        self.state.custody.handoff(handoff)
    }

    /// Counts the box at the counting centre (`ImprintAudit`). Unimprinted
    /// ballots, repeated cast identifiers or an incomplete custody chain
    /// hold (ITYV-BEH-171).
    ///
    /// Refused with [`Error::Mismatch`] for another box and the errors of
    /// [`check_witnesses`].
    pub fn count(self, audit: &ImprintAudit<'_>) -> Transition<Self, BallotBox<'a, Counted<'a>>> {
        let checked = self
            .base
            .check_target(audit.election_id, audit.box_id)
            .and_then(|()| self.base.check_witnesses(audit.witnesses));
        match checked {
            Ok(()) => {
                let complete = self.state.custody.is_complete();
                let BallotBox { mut base, state } = self;
                base.holds = base
                    .holds
                    .with_if(
                        audit.unimprinted != 0 || audit.duplicate_cast_ids != 0,
                        HoldReason::ImprintAudit,
                    )
                    .with_if(!complete, HoldReason::CustodyIncomplete);
                Transition::Done(BallotBox {
                    base,
                    state: Counted(state),
                })
            }
            Err(error) => Transition::Refused(self, error),
        }
    }
}

impl<'a> BallotBox<'a, Counted<'a>> {
    /// Every hold.
    #[must_use]
    pub fn holds(&self) -> HoldSet {
        self.base.holds.union(self.state.0.holds())
    }

    /// The counts of the close in force.
    #[must_use]
    pub const fn counts(&self) -> &CloseCounts {
        &self.state.0.counts
    }

    /// Whether the close in force lacks the device signature.
    #[must_use]
    pub const fn is_manual(&self) -> bool {
        self.state.0.manual
    }

    /// The custody chain.
    #[must_use]
    pub const fn custody(&self) -> &CustodyChain<'a> {
        &self.state.0.custody
    }

    /// Records a `LateBoxClose` within the late-close window, as on a
    /// closed box.
    ///
    /// # Errors
    /// As the closed box's `late_close`.
    pub fn late_close(
        &mut self,
        close: &BoxClose<'_>,
        device: &Verified<HybridSigned<'_>>,
    ) -> Result<(), Error> {
        self.base.late_close(&mut self.state.0, close, device)
    }

    /// Records a `LateBatchClose` within the late-close window, as on a
    /// closed box.
    ///
    /// # Errors
    /// As the closed box's `late_batch`.
    pub fn late_batch(&mut self, late: &LateBatchClose<'_, '_>) -> Result<(), Error> {
        self.base.late_batch(&mut self.state.0, late)
    }

    /// Marks the box audited. Sampling and comparison are rules of the
    /// audit (§12, M5); this transition records only that the box's audit
    /// concluded, which needs the `RLA` capability (VC-007).
    ///
    /// Refused with [`Error::Mismatch`] for a capability of another
    /// election.
    pub fn audited(self, cap: &Cap<'_, Rla>) -> Transition<Self, BallotBox<'a, Audited<'a>>> {
        match cap.check_election(self.base.spec.election_id) {
            Ok(()) => Transition::Done(BallotBox {
                base: self.base,
                state: Audited(self.state.0),
            }),
            Err(error) => Transition::Refused(self, error),
        }
    }
}

impl<'a> BallotBox<'a, Audited<'a>> {
    /// Every hold.
    #[must_use]
    pub fn holds(&self) -> HoldSet {
        self.base.holds.union(self.state.0.holds())
    }

    /// The counts of the close in force.
    #[must_use]
    pub const fn counts(&self) -> &CloseCounts {
        &self.state.0.counts
    }
}
