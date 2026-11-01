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
//! Every human-signed event arrives as a [`Signed`] event: a
//! `WitnessedEvent` and one verification token per signature, each bound
//! to the key the genesis registers for that signer (ADR-0025). A close
//! carries its device token and one token per human attestation
//! ([`CloseTokens`]).
//!
//! A close is recorded whatever its counts say; violated invariants become
//! sticky holds ([`crate::close::count_verdict`]). A close without the
//! device signature is a `BoxCloseManual` and holds until a `LateBoxClose`
//! within 24 hours with matching human counts replaces its verdict; a late
//! batch close within 24 hours that attests every remaining record
//! resolves the open-batch hold. Nothing else removes a hold.
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
//! # use ityv_state::boxes::{BallotBox, Open};
//! # use ityv_state::sig::Signed;
//! fn reopen<'a>(open: BallotBox<'a, Open>, opening: &Signed<'a>) {
//!     let _ = open.open(opening);
//! }
//! ```

use ityv_crypto::hash::object_hash;
use ityv_crypto::{HybridSigned, HybridVerifyingKey, Verified};
use ityv_encoding::{
    BatchAttest, BatchAttestBody, BoxClose, BoxId, BoxOpenedBody, CastRecordBody,
    ChallengeOpeningBody, CloseCounts, CustodyRoute, ElectionId, FallbackBody, FallbackKind,
    GenesisBox, ImprintAuditBody, LateBatchCloseBody, ModuleId, ModuleIds, OrgId,
    SCHEMA_BOX_OPENED_BODY, SCHEMA_FALLBACK_BODY, SCHEMA_IMPRINT_AUDIT_BODY,
    SCHEMA_LATE_BATCH_CLOSE_BODY, StationId, TimeBucket,
};

use crate::auth::{BallotMark, Cap, PublicBoard, Rla};
use crate::close::{
    CountFacts, Observed, RosterEntry, check_close_witnesses, check_witnesses, count_verdict,
    modules_gap_free,
};
use crate::custody::CustodyChain;
use crate::error::Error;
use crate::hold::{HoldReason, HoldSet};
use crate::issuance::{EnvelopeIssuance, IssuanceCount};
use crate::record::{Profile, RecordState, is_test_style};
use crate::sig::{Signed, same_signature};
use crate::tally::LATE_CLOSE_WINDOW;

/// Signature purpose of the box-close signatures (device and people).
pub const PURPOSE_BOX_CLOSE: &[u8] = b"box-close";

/// Signature purpose of the late box-close signatures.
pub const PURPOSE_LATE_BOX_CLOSE: &[u8] = b"late-box-close";

/// What the genesis fixes for one box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoxSpec<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The box.
    pub box_id: BoxId<'a>,
    /// The box's station.
    pub station_id: StationId<'a>,
    /// The collection profile.
    pub profile: Profile,
    /// The chamber modules registered in the genesis.
    pub registered_modules: &'a [ModuleId<'a>],
    /// The box's commitment-unit key.
    pub device_key: &'a HybridVerifyingKey,
    /// The registered clerks, observers and custodians, with their keys.
    pub roster: &'a [RosterEntry<'a>],
    /// The custody route: organisations from the station to the counting
    /// centre.
    pub route: &'a [OrgId<'a>],
}

impl BoxSpec<'_> {
    /// Checks that the spec is exactly what the genesis entry and its
    /// custody route say: box, station, profile, device key bytes, modules
    /// and route stops.
    ///
    /// # Errors
    /// [`Error::Mismatch`] for any difference.
    pub fn check_genesis(
        &self,
        entry: &GenesisBox<'_>,
        route: &CustodyRoute<'_>,
    ) -> Result<(), Error> {
        let key = entry
            .device_key
            .split_first_chunk::<{ ityv_crypto::sig::MLDSA87_VK_LEN }>();
        let key_ok = key.is_some_and(|(mldsa87, ed25519)| {
            mldsa87 == self.device_key.mldsa87() && ed25519 == self.device_key.ed25519().as_slice()
        });
        let modules_ok = entry.modules.len() == self.registered_modules.len()
            && entry
                .modules
                .iter()
                .zip(self.registered_modules)
                .all(|(a, b)| a.as_bytes() == b.as_bytes());
        let route_ok = route.route_id().as_bytes() == entry.route_id.as_bytes()
            && route.stop_count() == self.route.len()
            && route
                .stops()
                .zip(self.route)
                .all(|(a, b)| a.as_bytes() == b.as_bytes());
        let same = entry.box_id.as_bytes() == self.box_id.as_bytes()
            && entry.station_id.as_bytes() == self.station_id.as_bytes()
            && Profile::from_capture(entry.profile) == self.profile
            && key_ok
            && modules_ok
            && route_ok;
        if same { Ok(()) } else { Err(Error::Mismatch) }
    }
}

/// The verification tokens of a close: the device signature's (absent for
/// a `BoxCloseManual`) and one per human attestation, in attestation
/// order.
#[derive(Debug, Clone, Copy)]
pub struct CloseTokens<'t> {
    /// The device signature's token.
    pub device: Option<&'t Verified<HybridSigned<'t>>>,
    /// The human attestations' tokens.
    pub humans: &'t [Verified<HybridSigned<'t>>],
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
    close_bucket: TimeBucket,
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
    /// The unchanged box and the reason for refusal.
    Refused(A, Error),
}

impl<A, B> Transition<A, B> {
    /// The next state, or the error (dropping the unchanged box).
    ///
    /// # Errors
    /// The reason for refusal.
    pub fn into_result(self) -> Result<B, Error> {
        match self {
            Self::Done(next) => Ok(next),
            Self::Refused(_, error) => Err(error),
        }
    }

    /// The reason for refusal, if refused.
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
    modules: ModuleIds<'a>,
    observed: Observed,
    fallback_declared: bool,
    holds: HoldSet,
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

/// Whether `at` is within the late-close window after `close_bucket`.
fn within_window(close_bucket: TimeBucket, at: TimeBucket) -> Result<(), Error> {
    let deadline = close_bucket
        .get()
        .checked_add(LATE_CLOSE_WINDOW)
        .ok_or(Error::Overflow)?;
    if at.get() <= deadline {
        Ok(())
    } else {
        Err(Error::LateWindow)
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

    fn opening(&self, signed: &Signed<'a>) -> Result<(ModuleIds<'a>, HoldSet), Error> {
        let body: BoxOpenedBody<'a> = signed
            .event
            .body(SCHEMA_BOX_OPENED_BODY)
            .map_err(|_| Error::Decode)?;
        let p = body.parts();
        self.check_target(p.election_id, p.box_id)?;
        let registered = p.modules.iter().all(|module| {
            self.spec
                .registered_modules
                .iter()
                .any(|r| r.as_bytes() == module.as_bytes())
        });
        if !registered {
            return Err(Error::NotRegistered);
        }
        check_witnesses(signed, self.spec.roster, Some(self.spec.device_key))?;
        let holds = HoldSet::empty()
            .with_if(!p.seals_match, HoldReason::SealMismatch)
            .with_if(p.initial_count != 0, HoldReason::OpeningNonZero);
        Ok((p.modules, holds))
    }

    fn record(
        &mut self,
        cap: &Cap<'_, BallotMark>,
        record: &CastRecordBody<'_>,
    ) -> Result<RecordState, Error> {
        cap.check_election(self.spec.election_id)?;
        self.check_target(record.election_id(), record.box_id())?;
        let modules = &self.modules;
        let opened = record
            .module_counters()
            .iter()
            .all(|c| modules.contains(c.module_id));
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

    fn fallback(&self, signed: &Signed<'_>, kind: FallbackKind) -> Result<(), Error> {
        let body: FallbackBody<'_> = signed
            .event
            .body(SCHEMA_FALLBACK_BODY)
            .map_err(|_| Error::Decode)?;
        let p = body.parts();
        self.check_target(p.election_id, p.box_id)?;
        if p.kind != kind {
            return Err(Error::Mismatch);
        }
        check_witnesses(signed, self.spec.roster, None)
    }

    fn verdict(
        &self,
        counts: &CloseCounts,
        close: &BoxClose<'_>,
        envelopes: Option<EnvelopeIssuance>,
    ) -> HoldSet {
        let body = close.body();
        let facts = CountFacts {
            profile: self.spec.profile,
            counts: *counts,
            open_batches: body.open_batches(),
            observed: self.observed,
            fallback_declared: self.fallback_declared,
            envelopes,
        };
        count_verdict(&facts).with_if(
            !modules_gap_free(counts, body.module_counters(), &self.modules),
            HoldReason::ModuleCounterGap,
        )
    }

    fn close(
        &self,
        close: &BoxClose<'_>,
        tokens: &CloseTokens<'_>,
        issuance: Option<&Signed<'_>>,
    ) -> Result<Closed<'a>, Error> {
        let body = close.body();
        self.check_target(body.election_id(), body.box_id())?;
        check_close_witnesses(close, tokens.humans, self.spec.roster, PURPOSE_BOX_CLOSE)?;
        let envelopes = match issuance {
            Some(signed) => {
                let checked = IssuanceCount::check(signed, self.spec.roster)?;
                let p = checked.parts();
                if p.election_id.as_bytes() != self.spec.election_id.as_bytes()
                    || p.station_id.as_bytes() != self.spec.station_id.as_bytes()
                {
                    return Err(Error::Mismatch);
                }
                p.envelopes
            }
            None => None,
        };
        let signed = device_signed(
            close,
            tokens.device,
            self.spec.device_key,
            PURPOSE_BOX_CLOSE,
        )?;
        let counts = *body.counts();
        let verdict = self
            .verdict(&counts, close, envelopes)
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
            close_bucket: body.time_bucket(),
            envelopes,
            close_holds: verdict,
            custody,
        })
    }

    fn late_close(
        &self,
        closed: &mut Closed<'a>,
        close: &BoxClose<'_>,
        tokens: &CloseTokens<'_>,
    ) -> Result<(), Error> {
        if !closed.manual || close.device_sig().is_none() {
            return Err(Error::LateClose);
        }
        let body = close.body();
        self.check_target(body.election_id(), body.box_id())?;
        within_window(closed.close_bucket, body.time_bucket())?;
        check_close_witnesses(
            close,
            tokens.humans,
            self.spec.roster,
            PURPOSE_LATE_BOX_CLOSE,
        )?;
        let device = tokens.device.ok_or(Error::Unverified)?;
        device_signed(
            close,
            Some(device),
            self.spec.device_key,
            PURPOSE_LATE_BOX_CLOSE,
        )?;
        let late = *body.counts();
        let verdict = self.verdict(&late, close, closed.envelopes);
        let humans_match = late.paper == closed.counts.paper
            && late.envelopes == closed.counts.envelopes
            && late.stickers == closed.counts.stickers
            && late.spoil_envelopes == closed.counts.spoil_envelopes;
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
        batch: &BatchAttest<'_>,
        late: &Signed<'_>,
    ) -> Result<(), Error> {
        let body: LateBatchCloseBody<'_> = late
            .event
            .body(SCHEMA_LATE_BATCH_CLOSE_BODY)
            .map_err(|_| Error::Decode)?;
        let p = body.parts();
        let b = batch.body();
        self.check_target(p.election_id, p.box_id)?;
        self.check_target(b.election_id(), b.box_id())?;
        if p.batch_body_hash != object_hash(batch.body_bytes()) {
            return Err(Error::Mismatch);
        }
        within_window(closed.close_bucket, p.time_bucket)?;
        check_witnesses(late, self.spec.roster, None)?;
        let attested = self
            .observed
            .attested
            .checked_add(u64::from(b.record_count()))
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
    pub const fn modules(&self) -> &ModuleIds<'a> {
        &self.base.modules
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
    /// [`Error::Mismatch`] if the capability belongs to another election,
    /// [`Error::CustodyRoute`] if the route has fewer than two stops.
    pub fn provision(spec: BoxSpec<'a>, cap: &Cap<'_, PublicBoard>) -> Result<Self, Error> {
        cap.check_election(spec.election_id)?;
        if spec.route.len() < 2 {
            return Err(Error::CustodyRoute);
        }
        Ok(Self {
            base: Base {
                spec,
                modules: ModuleIds::EMPTY,
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

    /// Opens the box with a signed `BoxOpened` (device, two clerks,
    /// observers of two organisations; VC-037, VC-089). A seal mismatch or
    /// a nonzero initial count opens the box under a hold.
    ///
    /// # Errors
    /// [`Error::Decode`] if the event is not a box opening,
    /// [`Error::Mismatch`] for another box, [`Error::NotRegistered`] for a
    /// module the genesis does not register for the box, and the errors of
    /// [`check_witnesses`] with the box's device key.
    pub fn open(self, opening: &Signed<'a>) -> Transition<Self, BallotBox<'a, Open>> {
        match self.base.opening(opening) {
            Ok((modules, holds)) => {
                let mut open = self.with_state(Open(()));
                open.base.modules = modules;
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

    /// Records a cast record (requires `BALLOT_MARK`, VC-007) and returns
    /// its initial state.
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

    /// Declares the fallback with a signed `FallbackDeclared` (§7.3).
    ///
    /// # Errors
    /// [`Error::Decode`] if the event is not a fallback event,
    /// [`Error::Mismatch`] for another box or a `FallbackEnded`, and the
    /// errors of [`check_witnesses`].
    pub fn declare_fallback(self, event: &Signed<'_>) -> Transition<Self, BallotBox<'a, Fallback>> {
        match self.base.fallback(event, FallbackKind::Declared) {
            Ok(()) => {
                let mut fallback = self.with_state(Fallback(()));
                fallback.base.fallback_declared = true;
                Transition::Done(fallback)
            }
            Err(error) => Transition::Refused(self, error),
        }
    }

    /// Closes the box. The close is recorded whatever its counts say; see
    /// [`Closed`] for the holds. `issuance` is the station's signed
    /// `IssuanceCount`, required for an out-of-district box's envelope
    /// accounting.
    ///
    /// # Errors
    /// [`Error::Mismatch`] for another box or an issuance count of another
    /// election or station, the errors of the human attestations' token
    /// check, of [`IssuanceCount::check`], and of the device token
    /// ([`Error::Unverified`] if the close carries a device signature but
    /// no token is given).
    pub fn close(
        self,
        close: &BoxClose<'_>,
        tokens: &CloseTokens<'_>,
        issuance: Option<&Signed<'_>>,
    ) -> Transition<Self, BallotBox<'a, Closed<'a>>> {
        match self.base.close(close, tokens, issuance) {
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

    /// Records a cast record that the device signed before the fallback
    /// and that reached the ledger late (store-and-forward uplink, §5.8).
    /// Whether the fallback slot took ballots without records is checked
    /// at close by the counts and the module counters only (PROTOCOL.md
    /// §7.3).
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

    /// Ends the fallback with a signed `FallbackEnded`.
    ///
    /// # Errors
    /// As [`BallotBox::declare_fallback`], with a `FallbackDeclared`
    /// refused.
    pub fn end_fallback(self, event: &Signed<'_>) -> Transition<Self, BallotBox<'a, Open>> {
        match self.base.fallback(event, FallbackKind::Ended) {
            Ok(()) => Transition::Done(self.with_state(Open(()))),
            Err(error) => Transition::Refused(self, error),
        }
    }

    /// Closes the box while in fallback.
    ///
    /// # Errors
    /// As the open box's `close`.
    pub fn close(
        self,
        close: &BoxClose<'_>,
        tokens: &CloseTokens<'_>,
        issuance: Option<&Signed<'_>>,
    ) -> Transition<Self, BallotBox<'a, Closed<'a>>> {
        match self.base.close(close, tokens, issuance) {
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

    /// The counts the (late) close reports.
    #[must_use]
    pub const fn counts(&self) -> &CloseCounts {
        &self.state.counts
    }

    /// Whether the close is a `BoxCloseManual` not yet replaced.
    #[must_use]
    pub const fn is_manual(&self) -> bool {
        self.state.manual
    }

    /// Batches open at close.
    #[must_use]
    pub const fn open_batches(&self) -> u8 {
        self.state.open_batches
    }

    /// The time bucket of the close, from which the late-close window
    /// counts.
    #[must_use]
    pub const fn closed_at(&self) -> TimeBucket {
        self.state.close_bucket
    }

    /// The custody chain.
    #[must_use]
    pub const fn custody(&self) -> &CustodyChain<'a> {
        &self.state.custody
    }

    /// Records a `LateBoxClose` for a manual close: with the device
    /// signature (purpose `late-box-close`), human attestations under the
    /// same purpose, and within 24 hours of the close. If the human counts
    /// (paper, envelopes, stickers, spoil bag) equal the manual close's,
    /// its verdict replaces the manual one; otherwise every earlier hold
    /// stays and [`HoldReason::LateCloseDiffers`] is added.
    ///
    /// # Errors
    /// [`Error::LateClose`] if the close was not manual or the late close
    /// has no device signature, [`Error::Mismatch`] for another box,
    /// [`Error::LateWindow`] after the window, and the token errors.
    pub fn late_close(
        &mut self,
        close: &BoxClose<'_>,
        tokens: &CloseTokens<'_>,
    ) -> Result<(), Error> {
        self.base.late_close(&mut self.state, close, tokens)
    }

    /// Records a `LateBatchClose`: the batch it closes (its body hash must
    /// match) and the witnesses' signed event, within 24 hours of the
    /// close. If every record is then attested, the open-batch hold is
    /// resolved.
    ///
    /// # Errors
    /// [`Error::Decode`] if the event is not a late batch close,
    /// [`Error::Mismatch`] for another box or batch, [`Error::LateWindow`]
    /// after the window, the errors of [`check_witnesses`],
    /// [`Error::BatchExceedsRecords`], [`Error::Overflow`].
    pub fn late_batch(&mut self, batch: &BatchAttest<'_>, late: &Signed<'_>) -> Result<(), Error> {
        self.base.late_batch(&mut self.state, batch, late)
    }

    /// Records a signed seal change ([`CustodyChain::seal_change`]).
    ///
    /// # Errors
    /// As [`CustodyChain::seal_change`].
    pub fn seal_change(&mut self, change: &Signed<'_>) -> Result<(), Error> {
        self.state
            .custody
            .seal_change(change, self.base.spec.roster)
    }

    /// Appends a signed custody handoff ([`CustodyChain::handoff`]).
    ///
    /// # Errors
    /// As [`CustodyChain::handoff`].
    pub fn handoff(&mut self, handoff: &Signed<'a>) -> Result<(), Error> {
        self.state.custody.handoff(handoff, self.base.spec.roster)
    }

    /// Counts the box with a signed `ImprintAudit`. Ballots without an
    /// imprint or repeated cast identifiers, or a custody chain that has
    /// not reached the counting centre, leave holds.
    ///
    /// # Errors
    /// [`Error::Decode`] if the event is not an imprint audit,
    /// [`Error::Mismatch`] for another box, the errors of
    /// [`check_witnesses`].
    pub fn count(self, audit: &Signed<'_>) -> Transition<Self, BallotBox<'a, Counted<'a>>> {
        let checked = audit
            .event
            .body::<ImprintAuditBody<'_>>(SCHEMA_IMPRINT_AUDIT_BODY)
            .map_err(|_| Error::Decode)
            .and_then(|body| {
                let p = *body.parts();
                self.base.check_target(p.election_id, p.box_id)?;
                check_witnesses(audit, self.base.spec.roster, None)?;
                Ok(p)
            });
        match checked {
            Ok(p) => {
                let complete = self.state.custody.is_complete();
                let BallotBox { mut base, state } = self;
                base.holds = base
                    .holds
                    .with_if(
                        p.unimprinted != 0 || p.duplicate_cast_ids != 0,
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
    /// Every hold so far.
    #[must_use]
    pub fn holds(&self) -> HoldSet {
        self.base.holds.union(self.state.0.holds())
    }

    /// The counts the (late) close reports.
    #[must_use]
    pub const fn counts(&self) -> &CloseCounts {
        &self.state.0.counts
    }

    /// Whether the close is a `BoxCloseManual` not yet replaced.
    #[must_use]
    pub const fn is_manual(&self) -> bool {
        self.state.0.manual
    }

    /// The custody chain.
    #[must_use]
    pub const fn custody(&self) -> &CustodyChain<'a> {
        &self.state.0.custody
    }

    /// A late box close after counting, within the late-close window.
    ///
    /// # Errors
    /// As the closed box's `late_close`.
    pub fn late_close(
        &mut self,
        close: &BoxClose<'_>,
        tokens: &CloseTokens<'_>,
    ) -> Result<(), Error> {
        self.base.late_close(&mut self.state.0, close, tokens)
    }

    /// A late batch close after counting, within the late-close window.
    ///
    /// # Errors
    /// As the closed box's `late_batch`.
    pub fn late_batch(&mut self, batch: &BatchAttest<'_>, late: &Signed<'_>) -> Result<(), Error> {
        self.base.late_batch(&mut self.state.0, batch, late)
    }

    /// Marks the box audited (requires `RLA`).
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

    /// The counts.
    #[must_use]
    pub const fn counts(&self) -> &CloseCounts {
        &self.state.0.counts
    }
}
