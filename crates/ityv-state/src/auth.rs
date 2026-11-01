//! Legal-scope capabilities (PROTOCOL.md §4.4, ADR-0002, CONSTITUTION.md
//! §1.7).
//!
//! A [`LegalAuthorizationBody`] names the scopes the law currently permits.
//! [`authorize`] turns it into an [`Authorization`] only if both the
//! election commission and the Independent Verification Committee signed
//! that exact object with purpose `legal-auth` (VC-006) and its scope set
//! respects the stage prerequisites (VC-008, `LEGAL_ANNEX.md` §3.3 rule 3).
//! An authorization then grants one [`Cap`] per scope; operations that the
//! law gates take the matching capability by reference, so an operation
//! outside the authorized scopes does not type-check without one (VC-007).
//!
//! The capability's constructor is private: [`Authorization::grant`] is the
//! only way to obtain one.
//!
//! ```compile_fail
//! use core::marker::PhantomData;
//! use ityv_encoding::ElectionId;
//! use ityv_state::auth::{BallotMark, Cap};
//! fn forge<'a>(election_id: ElectionId<'a>) -> Cap<'a, BallotMark> {
//!     Cap { election_id, scope: PhantomData }
//! }
//! ```

use core::marker::PhantomData;

use ityv_crypto::{HybridSigned, HybridVerifyingKey, Verified};
use ityv_encoding::{
    Day, ElectionId, LegalAuthorizationBody, SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, Scope,
    ScopeSet, decode_object,
};

use crate::error::Error;

/// Signature purpose of the legal authorization (PROTOCOL.md Appendix B).
pub const PURPOSE_LEGAL_AUTH: &[u8] = b"legal-auth";

/// The activation stage of a scope (`LEGAL_ANNEX.md` §3.2).
#[must_use]
pub const fn stage(scope: Scope) -> u8 {
    match scope {
        Scope::PublicBoard => 0,
        Scope::TrusteeBody => 1,
        Scope::BallotMark
        | Scope::CryptoTallyAid
        | Scope::Rla
        | Scope::ObserverAccess
        | Scope::DeployAuth
        | Scope::StageGate => 2,
        Scope::VoterCode => 3,
    }
}

/// The scopes that `scope` presupposes.
///
/// Stages are not skipped (`LEGAL_ANNEX.md` §3.3 rule 3, VC-008): every
/// scope above stage 0 requires `PUBLIC_BOARD`, every scope above stage 1
/// requires `TRUSTEE_BODY`, and `VOTER_CODE` requires every stage-2 scope
/// (`BALLOT_MARK`, `CRYPTO_TALLY_AID`, `RLA`, `OBSERVER_ACCESS`,
/// `DEPLOY_AUTH`, `STAGE_GATE`): stage 3 begins only on a complete stage 2.
/// `RLA` also requires `CRYPTO_TALLY_AID`, because the audit draws its
/// sample from the tally scope's included records (PROTOCOL.md §12.1), so
/// the status ladder `CRYPTO_TALLY_VERIFIED → PAPER_AUDITED` is never
/// skipped.
#[must_use]
pub const fn prerequisites(scope: Scope) -> ScopeSet {
    let board = ScopeSet::empty().with(Scope::PublicBoard);
    let trustees = board.with(Scope::TrusteeBody);
    match scope {
        Scope::PublicBoard => ScopeSet::empty(),
        Scope::TrusteeBody => board,
        Scope::BallotMark
        | Scope::CryptoTallyAid
        | Scope::ObserverAccess
        | Scope::DeployAuth
        | Scope::StageGate => trustees,
        Scope::Rla => trustees.with(Scope::CryptoTallyAid),
        Scope::VoterCode => trustees
            .with(Scope::BallotMark)
            .with(Scope::CryptoTallyAid)
            .with(Scope::Rla)
            .with(Scope::ObserverAccess)
            .with(Scope::DeployAuth)
            .with(Scope::StageGate),
    }
}

/// Checks that every scope in `scopes` comes with its prerequisites.
///
/// # Errors
/// [`Error::ScopePrerequisite`] for the first scope (in code order) that
/// lacks a prerequisite, naming the first missing one.
pub fn check_scope_rules(scopes: ScopeSet) -> Result<(), Error> {
    for scope in scopes.iter() {
        if let Some(requires) = prerequisites(scope).iter().find(|r| !scopes.contains(*r)) {
            return Err(Error::ScopePrerequisite { scope, requires });
        }
    }
    Ok(())
}

/// A checked legal authorization: the decoded body, signed by both
/// authorities, with a valid scope set.
///
/// What it does not prove: that the two keys are the ones the genesis pins
/// (the caller passes them from the verified genesis, M5), or that the
/// statutes behind `statute_refs_hash` say what the scopes claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Authorization<'a> {
    election_id: ElectionId<'a>,
    scopes: ScopeSet,
    from: Day,
    until: Day,
}

fn check_token(
    token: &Verified<HybridSigned<'_>>,
    object: &[u8],
    key: &HybridVerifyingKey,
    purpose: &[u8],
) -> Result<(), Error> {
    let signed = token.get();
    if signed.purpose().as_bytes() != purpose || signed.object() != object {
        return Err(Error::SignatureObject);
    }
    if signed.key() != key {
        return Err(Error::SignatureSigner);
    }
    Ok(())
}

/// Checks a legal authorization object (`LegalAuthorizationBody`, schema
/// `0x0003`) and its two signatures (VC-006).
///
/// `commission` and `committee` are verification tokens from
/// `ityv_crypto::verify_hybrid`; each must cover exactly `object` with
/// purpose `legal-auth` and come from the matching key. The two keys must
/// differ in both halves (ML-DSA-87 and Ed25519).
///
/// # Errors
/// [`Error::SignatureSigner`] if the keys share a half or a token comes from
/// another key, [`Error::SignatureObject`] if a token covers other bytes or
/// another purpose, [`Error::Decode`] if the object is not a canonical
/// `LegalAuthorizationBody`, [`Error::ScopePrerequisite`] (VC-008).
pub fn authorize<'a>(
    object: &'a [u8],
    commission: &Verified<HybridSigned<'_>>,
    commission_key: &HybridVerifyingKey,
    committee: &Verified<HybridSigned<'_>>,
    committee_key: &HybridVerifyingKey,
) -> Result<Authorization<'a>, Error> {
    // Both halves must differ: a shared Ed25519 or ML-DSA-87 half would let
    // one holder produce that half of both signatures.
    if commission_key.mldsa87() == committee_key.mldsa87()
        || commission_key.ed25519() == committee_key.ed25519()
    {
        return Err(Error::SignatureSigner);
    }
    check_token(commission, object, commission_key, PURPOSE_LEGAL_AUTH)?;
    check_token(committee, object, committee_key, PURPOSE_LEGAL_AUTH)?;
    let body: LegalAuthorizationBody<'a> =
        decode_object(SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, object)
            .map_err(|_| Error::Decode)?;
    check_scope_rules(body.scopes())?;
    Ok(Authorization {
        election_id: body.election_id(),
        scopes: body.scopes(),
        from: body.effective_from_day(),
        until: body.effective_until_day(),
    })
}

impl<'a> Authorization<'a> {
    /// Builds an authorization without signatures, for unit tests and Kani
    /// harnesses only.
    #[cfg(any(test, kani))]
    pub(crate) const fn unsigned(
        election_id: ElectionId<'a>,
        scopes: ScopeSet,
        from: Day,
        until: Day,
    ) -> Self {
        Self {
            election_id,
            scopes,
            from,
            until,
        }
    }

    /// The election.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.election_id
    }

    /// The authorized scopes.
    #[must_use]
    pub const fn scopes(&self) -> ScopeSet {
        self.scopes
    }

    /// First effective day.
    #[must_use]
    pub const fn effective_from_day(&self) -> Day {
        self.from
    }

    /// Last effective day (inclusive).
    #[must_use]
    pub const fn effective_until_day(&self) -> Day {
        self.until
    }

    /// Grants the capability for scope `S` on `today`.
    ///
    /// # Errors
    /// [`Error::ScopeMissing`] if `S` is not authorized,
    /// [`Error::OutsideEffectiveWindow`] if `today` is outside the
    /// effective window.
    pub fn grant<S: ScopeMarker>(&self, today: Day) -> Result<Cap<'a, S>, Error> {
        if !self.scopes.contains(S::SCOPE) {
            return Err(Error::ScopeMissing(S::SCOPE));
        }
        if today.get() < self.from.get() || today.get() > self.until.get() {
            return Err(Error::OutsideEffectiveWindow);
        }
        Ok(Cap {
            election_id: self.election_id,
            scope: PhantomData,
        })
    }
}

/// A type naming one scope. Operations name the marker they require, so
/// implementing this trait for another type yields a capability no
/// operation accepts.
pub trait ScopeMarker {
    /// The scope this marker stands for.
    const SCOPE: Scope;
}

macro_rules! markers {
    ($($(#[$doc:meta])* $name:ident => $scope:ident;)*) => {
        $(
            $(#[$doc])*
            #[derive(Debug)]
            pub enum $name {}

            impl ScopeMarker for $name {
                const SCOPE: Scope = Scope::$scope;
            }
        )*
    };
}

markers! {
    /// Marker for `PUBLIC_BOARD` (stage 0).
    PublicBoard => PublicBoard;
    /// Marker for `TRUSTEE_BODY` (stage 1).
    TrusteeBody => TrusteeBody;
    /// Marker for `BALLOT_MARK` (stage 2): cast records.
    BallotMark => BallotMark;
    /// Marker for `CRYPTO_TALLY_AID` (stage 2): tally scope and aggregate
    /// openings.
    CryptoTallyAid => CryptoTallyAid;
    /// Marker for `RLA` (stage 2): sampling and audits.
    Rla => Rla;
    /// Marker for `OBSERVER_ACCESS` (stage 2).
    ObserverAccess => ObserverAccess;
    /// Marker for `DEPLOY_AUTH` (stage 2).
    DeployAuth => DeployAuth;
    /// Marker for `STAGE_GATE` (stage 2).
    StageGate => StageGate;
    /// Marker for `VOTER_CODE` (stage 3): slips and inclusion disputes.
    VoterCode => VoterCode;
}

/// The capability to perform operations of scope `S` in one election.
/// Only [`Authorization::grant`] creates one; it is neither `Clone` nor
/// `Copy`, and operations borrow it.
#[derive(Debug)]
pub struct Cap<'a, S: ScopeMarker> {
    election_id: ElectionId<'a>,
    scope: PhantomData<S>,
}

impl<'a, S: ScopeMarker> Cap<'a, S> {
    /// The election the capability belongs to.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.election_id
    }

    /// Checks that the capability belongs to `election_id`.
    ///
    /// # Errors
    /// [`Error::Mismatch`] otherwise.
    pub fn check_election(&self, election_id: ElectionId<'_>) -> Result<(), Error> {
        if self.election_id.as_bytes() == election_id.as_bytes() {
            Ok(())
        } else {
            Err(Error::Mismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use ityv_encoding::{Day, ElectionId, Scope, ScopeSet};

    use super::{
        Authorization, BallotMark, CryptoTallyAid, DeployAuth, ObserverAccess, PublicBoard, Rla,
        ScopeMarker, StageGate, TrusteeBody, VoterCode, check_scope_rules, prerequisites, stage,
    };
    use crate::error::Error;

    fn reference_ok(scopes: ScopeSet) -> bool {
        let has = |s| scopes.contains(s);
        let above0 = Scope::ALL
            .iter()
            .any(|s| *s != Scope::PublicBoard && has(*s));
        let above1 = Scope::ALL.iter().any(|s| stage(*s) >= 2 && has(*s));
        let stage2_complete = Scope::ALL
            .iter()
            .filter(|s| stage(**s) == 2)
            .all(|s| has(*s));
        (!above0 || has(Scope::PublicBoard))
            && (!above1 || has(Scope::TrusteeBody))
            && (!has(Scope::VoterCode) || stage2_complete)
            && (!has(Scope::Rla) || has(Scope::CryptoTallyAid))
    }

    #[test]
    fn stages() {
        let stages: std::vec::Vec<u8> = Scope::ALL.iter().map(|s| stage(*s)).collect();
        assert_eq!(stages, [0, 1, 2, 2, 2, 2, 2, 2, 3]);
    }

    #[test]
    fn prerequisite_table() {
        assert!(prerequisites(Scope::PublicBoard).is_empty());
        assert_eq!(
            prerequisites(Scope::TrusteeBody),
            ScopeSet::from_slice(&[Scope::PublicBoard])
        );
        for scope in [
            Scope::BallotMark,
            Scope::CryptoTallyAid,
            Scope::ObserverAccess,
            Scope::DeployAuth,
            Scope::StageGate,
        ] {
            assert_eq!(
                prerequisites(scope),
                ScopeSet::from_slice(&[Scope::PublicBoard, Scope::TrusteeBody])
            );
        }
        assert_eq!(
            prerequisites(Scope::Rla),
            ScopeSet::from_slice(&[
                Scope::PublicBoard,
                Scope::TrusteeBody,
                Scope::CryptoTallyAid
            ])
        );
        assert_eq!(
            prerequisites(Scope::VoterCode),
            ScopeSet::from_slice(&[
                Scope::PublicBoard,
                Scope::TrusteeBody,
                Scope::BallotMark,
                Scope::CryptoTallyAid,
                Scope::Rla,
                Scope::ObserverAccess,
                Scope::DeployAuth,
                Scope::StageGate,
            ])
        );
    }

    #[test]
    fn every_scope_set_matches_reference() {
        for mask in 0u16..512 {
            let scopes = Scope::ALL
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .fold(ScopeSet::empty(), |set, (_, s)| set.with(*s));
            assert_eq!(
                check_scope_rules(scopes).is_ok(),
                reference_ok(scopes),
                "{mask}"
            );
        }
    }

    #[test]
    fn first_missing_prerequisite_is_named() {
        assert_eq!(
            check_scope_rules(ScopeSet::from_slice(&[Scope::VoterCode])),
            Err(Error::ScopePrerequisite {
                scope: Scope::VoterCode,
                requires: Scope::PublicBoard
            })
        );
        assert_eq!(
            check_scope_rules(ScopeSet::from_slice(&[
                Scope::PublicBoard,
                Scope::TrusteeBody,
                Scope::VoterCode
            ])),
            Err(Error::ScopePrerequisite {
                scope: Scope::VoterCode,
                requires: Scope::BallotMark
            })
        );
        assert_eq!(
            check_scope_rules(ScopeSet::from_slice(&[Scope::PublicBoard, Scope::Rla])),
            Err(Error::ScopePrerequisite {
                scope: Scope::Rla,
                requires: Scope::TrusteeBody
            })
        );
        assert_eq!(
            check_scope_rules(ScopeSet::from_slice(&[
                Scope::PublicBoard,
                Scope::TrusteeBody,
                Scope::Rla
            ])),
            Err(Error::ScopePrerequisite {
                scope: Scope::Rla,
                requires: Scope::CryptoTallyAid
            })
        );
        // Stage 3 on a partial stage 2.
        assert_eq!(
            check_scope_rules(ScopeSet::from_slice(&[
                Scope::PublicBoard,
                Scope::TrusteeBody,
                Scope::BallotMark,
                Scope::CryptoTallyAid,
                Scope::Rla,
                Scope::ObserverAccess,
                Scope::DeployAuth,
                Scope::VoterCode
            ])),
            Err(Error::ScopePrerequisite {
                scope: Scope::VoterCode,
                requires: Scope::StageGate
            })
        );
    }

    #[test]
    fn markers_name_their_scopes() {
        assert_eq!(PublicBoard::SCOPE, Scope::PublicBoard);
        assert_eq!(TrusteeBody::SCOPE, Scope::TrusteeBody);
        assert_eq!(BallotMark::SCOPE, Scope::BallotMark);
        assert_eq!(CryptoTallyAid::SCOPE, Scope::CryptoTallyAid);
        assert_eq!(Rla::SCOPE, Scope::Rla);
        assert_eq!(ObserverAccess::SCOPE, Scope::ObserverAccess);
        assert_eq!(DeployAuth::SCOPE, Scope::DeployAuth);
        assert_eq!(StageGate::SCOPE, Scope::StageGate);
        assert_eq!(VoterCode::SCOPE, Scope::VoterCode);
    }

    #[test]
    fn grant_checks_scope_and_window() {
        let election = ElectionId::new(b"E1").unwrap();
        let other = ElectionId::new(b"E2").unwrap();
        let auth = Authorization::unsigned(
            election,
            ScopeSet::from_slice(&[Scope::PublicBoard, Scope::TrusteeBody, Scope::BallotMark]),
            Day::new(10),
            Day::new(20),
        );
        assert_eq!(auth.election_id(), election);
        assert_eq!(auth.effective_from_day(), Day::new(10));
        assert_eq!(auth.effective_until_day(), Day::new(20));
        assert_eq!(auth.scopes().len(), 3);
        for day in [10, 15, 20] {
            let cap = auth.grant::<BallotMark>(Day::new(day)).unwrap();
            assert_eq!(BallotMark::SCOPE, Scope::BallotMark);
            assert_eq!(cap.election_id(), election);
            assert_eq!(cap.check_election(election), Ok(()));
            assert_eq!(cap.check_election(other), Err(Error::Mismatch));
        }
        for day in [9, 21] {
            assert_eq!(
                auth.grant::<BallotMark>(Day::new(day)).unwrap_err(),
                Error::OutsideEffectiveWindow
            );
        }
        assert_eq!(
            auth.grant::<Rla>(Day::new(15)).unwrap_err(),
            Error::ScopeMissing(Scope::Rla)
        );
    }
}
