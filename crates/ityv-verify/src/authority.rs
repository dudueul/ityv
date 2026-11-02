//! The legal authorization the ledger carries (PROTOCOL.md §4.4; VC-006,
//! VC-007, VC-008).
//!
//! The genesis pins the object hash of one `LegalAuthorizationBody`. The
//! ledger carries it as a `SignedLegalAuthorization` (schema `0x0042`): the
//! body bytes with the election commission's and the committee's hybrid
//! signatures under purpose `legal-auth`. [`authorize_ledger`] takes the
//! first such event the index accepted (the index already refused one
//! whose body is not the pinned one), verifies both signatures under the
//! two keys the genesis body registers, and hands the tokens to
//! `ityv_state::authorize`, which checks the scope rules and makes the
//! [`Authorization`] that alone grants capabilities.
//!
//! Without a valid authorization no gated stage can run, and the whole
//! ledger is under `HOLD_REVIEW` ([`HoldReason::AuthorizationMissing`]).
//! A copy that cannot be taken (a signature that does not verify, scopes
//! that break the prerequisite rules) is evidence of a forgery or a broken
//! ceremony: its frame is listed and the whole ledger is held
//! ([`HoldReason::AuthorizationInvalid`]) even when a valid copy is also on
//! the ledger.
//!
//! A capability is granted for a day (the authorization's effective
//! days). The day of an event is the genesis's epoch day plus its time
//! bucket over 96 (PROTOCOL.md §3).
//!
//! What this stage does not prove: that the authorization is lawful (the
//! statute references are a hash of documents a person must read); that a
//! capability is used on the right day (each stage grants it for the day of
//! the event it gates).

use alloc::vec::Vec;

use ityv_crypto::Purpose;
use ityv_encoding::{
    Day, PURPOSE_LEGAL_AUTHORIZATION, SCHEMA_SIGNED_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, Seq,
    SignedLegalAuthorization, TimeBucket, decode_object,
};
use ityv_state::{Authorization, HoldReason, HoldSet, authorize};

use crate::genesis::VerifiedGenesis;
use crate::index::LedgerIndex;
use crate::sigs::Material;

/// Time buckets per day (fifteen-minute buckets, PROTOCOL.md §3).
const BUCKETS_PER_DAY: u64 = 96;

/// The day of `bucket`, counted from the genesis's epoch day.
pub(crate) fn day_of(genesis: &VerifiedGenesis<'_>, bucket: TimeBucket) -> Option<Day> {
    let epoch = genesis.genesis().body().election_epoch_day().get();
    bucket
        .get()
        .checked_div(BUCKETS_PER_DAY)
        .and_then(|d| epoch.checked_add(d))
        .map(Day::new)
}

/// The outcome of the authorization stage.
#[derive(Debug, Clone)]
pub struct AuthorityStage<'a> {
    authorization: Option<Authorization<'a>>,
    seq: Option<Seq>,
    refused: Vec<Seq>,
    holds: HoldSet,
}

impl<'a> AuthorityStage<'a> {
    /// The authorization, if the ledger carries a valid one.
    #[must_use]
    pub const fn authorization(&self) -> Option<&Authorization<'a>> {
        self.authorization.as_ref()
    }

    /// The frame that carries it.
    #[must_use]
    pub const fn seq(&self) -> Option<Seq> {
        self.seq
    }

    /// The frames of the authorization objects that could not be taken.
    #[must_use]
    pub fn refused(&self) -> &[Seq] {
        &self.refused
    }

    /// The holds the stage puts on the whole ledger.
    #[must_use]
    pub const fn holds(&self) -> HoldSet {
        self.holds
    }
}

/// Checks one signed authorization object; `None` if it does not decode,
/// a signature does not verify, or `ityv-state` refuses it.
fn check<'a>(genesis: &VerifiedGenesis<'a>, bytes: &'a [u8]) -> Option<Authorization<'a>> {
    let signed: SignedLegalAuthorization<'a> =
        decode_object(SCHEMA_SIGNED_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, bytes).ok()?;
    let g = genesis.genesis();
    let pairs = [
        (signed.commission_sig(), g.commission_key()),
        (signed.committee_sig(), g.committee_key()),
    ];
    let material = Material::new(pairs.into_iter())?;
    let purpose = Purpose::new(PURPOSE_LEGAL_AUTHORIZATION)?;
    let tokens = material.verify(&purpose, signed.body_bytes())?;
    match tokens.as_slice() {
        [commission, committee] => authorize(g, signed.body_bytes(), commission, committee).ok(),
        _ => None,
    }
}

/// Finds and checks the legal authorization on the ledger: the first
/// object that can be taken is the authorization; every other one that
/// cannot is listed and held.
#[must_use]
pub fn authorize_ledger<'a>(
    genesis: &VerifiedGenesis<'a>,
    index: &LedgerIndex<'a>,
) -> AuthorityStage<'a> {
    let mut authorization = None;
    let mut seq = None;
    let mut refused = Vec::new();
    let objects = index
        .events()
        .iter()
        .filter(|e| e.schema == SCHEMA_SIGNED_LEGAL_AUTHORIZATION);
    for e in objects {
        match e.bytes.and_then(|bytes| check(genesis, bytes)) {
            Some(a) => {
                if authorization.is_none() {
                    authorization = Some(a);
                    seq = Some(e.seq);
                }
            }
            None => refused.push(e.seq),
        }
    }
    let holds = HoldSet::empty()
        .with_if(authorization.is_none(), HoldReason::AuthorizationMissing)
        .with_if(!refused.is_empty(), HoldReason::AuthorizationInvalid);
    AuthorityStage {
        authorization,
        seq,
        refused,
        holds,
    }
}
