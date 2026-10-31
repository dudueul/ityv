//! Witness quorum and diversity policy (PROTOCOL.md §5.4 VC-014, ADR-0012
//! §1, ADR-0016 §6).
//!
//! A quorum profile `(n, q, f)` is valid only if `q <= n` and
//! `2q − n > f`: any two sets of `q` witnesses out of `n` share at least
//! `2q − n` members, so if fewer than that can be Byzantine, every pair of
//! quorums contains an honest witness, and honest witnesses never sign two
//! bodies at one sequence number (`docs/models/LedgerWitness.tla`).
//!
//! A published checkpoint is valid only when **every** signature on it
//! verifies under the roster key of a listed witness, no identifier is
//! unknown or repeated, the distinct signers reach the quorum, and the
//! signers span the required numbers of organisations, providers and
//! regions. A single bad signature invalidates the object: an operator who
//! wants to publish drops it first, and a verifier never counts around it.

use ityv_crypto::{HybridVerifyingKey, PURPOSE_CHECKPOINT, verify_hybrid};
use ityv_encoding::Ident;

use crate::checkpoint::{MAX_SIGNATURES, SignedCheckpoint};
use crate::error::{Dimension, Error};
use crate::verified::Verified;

/// Maximum number of witnesses on a roster.
pub const MAX_WITNESSES: usize = MAX_SIGNATURES;

/// A witness quorum profile: roster size, quorum, and the largest number of
/// Byzantine witnesses the profile tolerates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QuorumProfile {
    witnesses: u8,
    quorum: u8,
    byzantine_max: u8,
}

impl QuorumProfile {
    /// The default profile: 13 witnesses, quorum 9, up to 4 Byzantine
    /// (`18 − 13 = 5 > 4`).
    pub const DEFAULT_13_9_4: Self = Self {
        witnesses: 13,
        quorum: 9,
        byzantine_max: 4,
    };
    /// The alternative profile: 19 witnesses, quorum 13, up to 6 Byzantine
    /// (`26 − 19 = 7 > 6`).
    pub const ALT_19_13_6: Self = Self {
        witnesses: 19,
        quorum: 13,
        byzantine_max: 6,
    };

    /// Returns `Some` if the profile is valid: `quorum <= witnesses`,
    /// `witnesses <= 64`, and `2·quorum − witnesses > byzantine_max`.
    #[must_use]
    pub const fn new(witnesses: u8, quorum: u8, byzantine_max: u8) -> Option<Self> {
        if Self::is_valid(witnesses, quorum, byzantine_max) {
            Some(Self {
                witnesses,
                quorum,
                byzantine_max,
            })
        } else {
            None
        }
    }

    /// The validity rule, on raw values.
    #[must_use]
    pub const fn is_valid(witnesses: u8, quorum: u8, byzantine_max: u8) -> bool {
        if quorum > witnesses || quorum == 0 || (witnesses as usize) > MAX_WITNESSES {
            return false;
        }
        // 2q − n > f  ⇔  2q > n + f, evaluated without overflow in u16.
        let twice_quorum = (quorum as u16).saturating_mul(2);
        let n_plus_f = (witnesses as u16).saturating_add(byzantine_max as u16);
        twice_quorum > n_plus_f
    }

    /// Roster size.
    #[must_use]
    pub const fn witnesses(self) -> u8 {
        self.witnesses
    }

    /// Signatures required.
    #[must_use]
    pub const fn quorum(self) -> u8 {
        self.quorum
    }

    /// Byzantine witnesses tolerated.
    #[must_use]
    pub const fn byzantine_max(self) -> u8 {
        self.byzantine_max
    }

    /// Guaranteed overlap of any two quorums: `2·quorum − witnesses`.
    #[must_use]
    pub const fn quorum_intersection(self) -> u8 {
        // Valid profiles have 2q > n, so the subtraction cannot underflow;
        // saturation keeps the function total.
        self.quorum.saturating_mul(2).saturating_sub(self.witnesses)
    }
}

/// Minimum numbers of distinct organisations, providers and regions among
/// the signers of a checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DiversityPolicy {
    orgs: u8,
    providers: u8,
    regions: u8,
}

impl DiversityPolicy {
    /// The protocol's policy: 7 organisations, 4 providers, 3 regions.
    pub const DEFAULT: Self = Self {
        orgs: 7,
        providers: 4,
        regions: 3,
    };

    /// Builds a policy.
    #[must_use]
    pub const fn new(min_orgs: u8, min_providers: u8, min_regions: u8) -> Self {
        Self {
            orgs: min_orgs,
            providers: min_providers,
            regions: min_regions,
        }
    }

    /// Minimum distinct organisations.
    #[must_use]
    pub const fn min_orgs(self) -> u8 {
        self.orgs
    }
    /// Minimum distinct providers.
    #[must_use]
    pub const fn min_providers(self) -> u8 {
        self.providers
    }
    /// Minimum distinct regions.
    #[must_use]
    pub const fn min_regions(self) -> u8 {
        self.regions
    }
}

/// One witness of the genesis roster.
#[derive(Debug, Clone)]
pub struct WitnessEntry<'a> {
    /// Witness identifier.
    pub id: Ident<'a>,
    /// Organisation.
    pub org: Ident<'a>,
    /// Infrastructure provider.
    pub provider: Ident<'a>,
    /// Region.
    pub region: Ident<'a>,
    /// Verifying key for purpose `checkpoint`.
    pub key: HybridVerifyingKey,
}

/// The witness roster: at most [`MAX_WITNESSES`] entries, strictly ascending
/// by identifier.
#[derive(Debug, Clone, Copy)]
pub struct Roster<'a> {
    entries: &'a [WitnessEntry<'a>],
}

impl<'a> Roster<'a> {
    /// Validates order, uniqueness and capacity.
    ///
    /// # Errors
    /// [`Error::RosterInvalid`].
    pub fn new(entries: &'a [WitnessEntry<'a>]) -> Result<Self, Error> {
        if entries.len() > MAX_WITNESSES {
            return Err(Error::RosterInvalid);
        }
        for pair in entries.windows(2) {
            if let [a, b] = pair
                && a.id.as_bytes() >= b.id.as_bytes()
            {
                return Err(Error::RosterInvalid);
            }
        }
        Ok(Self { entries })
    }

    /// The entries.
    #[must_use]
    pub const fn entries(&self) -> &'a [WitnessEntry<'a>] {
        self.entries
    }

    /// Number of witnesses.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if the roster is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Looks up a witness by identifier.
    #[must_use]
    pub fn find(&self, id: &Ident<'_>) -> Option<&'a WitnessEntry<'a>> {
        let i = self
            .entries
            .binary_search_by(|e| e.id.as_bytes().cmp(id.as_bytes()))
            .ok()?;
        self.entries.get(i)
    }
}

/// `true` if the profile's roster size equals the roster's length.
#[must_use]
pub fn profile_matches_roster(profile: QuorumProfile, roster: &Roster<'_>) -> bool {
    usize::from(profile.witnesses) == roster.len()
}

/// What [`evaluate`] verified: a checkpoint that a valid quorum published.
#[derive(Debug, Clone, Copy)]
pub struct Published<'a> {
    roster: &'a Roster<'a>,
    profile: &'a QuorumProfile,
    diversity: &'a DiversityPolicy,
    signed: &'a SignedCheckpoint<'a>,
    signers: usize,
    orgs: usize,
    providers: usize,
    regions: usize,
}

impl<'a> Published<'a> {
    /// The roster.
    #[must_use]
    pub const fn roster(&self) -> &'a Roster<'a> {
        self.roster
    }
    /// The profile.
    #[must_use]
    pub const fn profile(&self) -> &'a QuorumProfile {
        self.profile
    }
    /// The diversity policy.
    #[must_use]
    pub const fn diversity(&self) -> &'a DiversityPolicy {
        self.diversity
    }
    /// The signed checkpoint.
    #[must_use]
    pub const fn signed(&self) -> &'a SignedCheckpoint<'a> {
        self.signed
    }
    /// Distinct valid signers.
    #[must_use]
    pub const fn signers(&self) -> usize {
        self.signers
    }
    /// Distinct organisations among the signers.
    #[must_use]
    pub const fn orgs(&self) -> usize {
        self.orgs
    }
    /// Distinct providers among the signers.
    #[must_use]
    pub const fn providers(&self) -> usize {
        self.providers
    }
    /// Distinct regions among the signers.
    #[must_use]
    pub const fn regions(&self) -> usize {
        self.regions
    }
}

/// A fixed-capacity set of byte strings for counting distinct attributes.
struct Distinct<'a> {
    seen: [Option<&'a [u8]>; MAX_WITNESSES],
    len: usize,
}

impl<'a> Distinct<'a> {
    const fn new() -> Self {
        Self {
            seen: [None; MAX_WITNESSES],
            len: 0,
        }
    }

    fn insert(&mut self, value: &'a [u8]) -> Result<(), Error> {
        if self
            .seen
            .iter()
            .take(self.len)
            .flatten()
            .any(|v| *v == value)
        {
            return Ok(());
        }
        let slot = self.seen.get_mut(self.len).ok_or(Error::Capacity)?;
        *slot = Some(value);
        self.len = self.len.checked_add(1).ok_or(Error::Capacity)?;
        Ok(())
    }

    const fn len(&self) -> usize {
        self.len
    }
}

fn check_dimension(dimension: Dimension, have: usize, need: u8) -> Result<(), Error> {
    let need = usize::from(need);
    if have < need {
        Err(Error::DiversityShort {
            dimension,
            have,
            need,
        })
    } else {
        Ok(())
    }
}

/// Decides whether `signed` is a validly published checkpoint under
/// `roster`, `profile` and `diversity`.
///
/// # Errors
/// [`Error::ProfileInvalid`] if the profile does not match the roster,
/// [`Error::UnknownWitness`] for an identifier not on the roster,
/// [`Error::InvalidSignature`] for a signature that does not verify over
/// the body bytes under purpose `checkpoint`, [`Error::Duplicate`] for a
/// repeated identifier, [`Error::QuorumShort`], [`Error::DiversityShort`].
pub fn evaluate<'a>(
    roster: &'a Roster<'a>,
    profile: &'a QuorumProfile,
    diversity: &'a DiversityPolicy,
    signed: &'a SignedCheckpoint<'a>,
) -> Result<Verified<Published<'a>>, Error> {
    if !profile_matches_roster(*profile, roster) {
        return Err(Error::ProfileInvalid);
    }
    let body_bytes = signed.body_bytes();
    let mut signers = Distinct::new();
    let mut orgs = Distinct::new();
    let mut providers = Distinct::new();
    let mut regions = Distinct::new();
    for (index, entry) in signed.signatures().enumerate() {
        let id = entry.witness_id();
        let witness = roster.find(&id).ok_or(Error::UnknownWitness { index })?;
        let before = signers.len();
        signers.insert(witness.id.as_bytes())?;
        if signers.len() == before {
            return Err(Error::Duplicate);
        }
        // The crypto token is consumed here; this crate's own token below
        // carries the whole evaluation.
        let _signed = verify_hybrid(
            &witness.key,
            &PURPOSE_CHECKPOINT,
            body_bytes,
            entry.signature(),
        )
        .map_err(|_| Error::InvalidSignature { index })?;
        orgs.insert(witness.org.as_bytes())?;
        providers.insert(witness.provider.as_bytes())?;
        regions.insert(witness.region.as_bytes())?;
    }
    let need = usize::from(profile.quorum);
    if signers.len() < need {
        return Err(Error::QuorumShort {
            have: signers.len(),
            need,
        });
    }
    check_dimension(Dimension::Organisations, orgs.len(), diversity.orgs)?;
    check_dimension(Dimension::Providers, providers.len(), diversity.providers)?;
    check_dimension(Dimension::Regions, regions.len(), diversity.regions)?;
    Ok(Verified::new(Published {
        roster,
        profile,
        diversity,
        signed,
        signers: signers.len(),
        orgs: orgs.len(),
        providers: providers.len(),
        regions: regions.len(),
    }))
}
