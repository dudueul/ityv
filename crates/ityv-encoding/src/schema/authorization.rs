//! `LegalAuthorization` body (schema `0x0003`, version 1): the legal gate
//! object carried by the genesis (ADR-0002).
//!
//! Field order: `election_id`, `scopes`, `statute_refs_hash`,
//! `effective_from_day`, `effective_until_day`.
//!
//! The signatures of the election commission and the Independent
//! Verification Committee are not part of this body; they are carried by the
//! enclosing genesis object and verified by the cryptographic crate. Decoding
//! this body proves nothing about authorization: it only yields a well-formed
//! statement of what *would* be authorized if the signatures verify.

use crate::codec::{Decode, Encode};
use crate::error::{Error, Kind};
use crate::primitives::{Day, ElectionId, Hash512};
use crate::reader::Reader;
use crate::writer::Writer;

/// Maximum number of scope codes in the `scopes` array.
pub const MAX_SCOPES: usize = 16;

/// Smallest defined scope code.
pub const SCOPE_CODE_MIN: u8 = 1;

/// Largest defined scope code.
pub const SCOPE_CODE_MAX: u8 = 9;

/// An authorization scope (GLOSSARY: 승인 범위).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum Scope {
    /// Publication of custody evidence on the public board (stage 0).
    PublicBoard = 1,
    /// Constitution of the trustee body with threshold keys (stage 1).
    TrusteeBody = 2,
    /// Cast-id imprint and ballot commitments (stage 2).
    BallotMark = 3,
    /// Cryptographic tally as a verification aid (stage 2).
    CryptoTallyAid = 4,
    /// Risk-limiting audit (stage 2).
    Rla = 5,
    /// Observer access to electronic evidence and ceremonies (stage 2).
    ObserverAccess = 6,
    /// Deployment authorization after certification (stage 2).
    DeployAuth = 7,
    /// Staged pilot gates and sunset (stage 2).
    StageGate = 8,
    /// Voter tracking-code slips (stage 3).
    VoterCode = 9,
}

impl Scope {
    /// Every scope in ascending code order.
    pub const ALL: [Self; 9] = [
        Self::PublicBoard,
        Self::TrusteeBody,
        Self::BallotMark,
        Self::CryptoTallyAid,
        Self::Rla,
        Self::ObserverAccess,
        Self::DeployAuth,
        Self::StageGate,
        Self::VoterCode,
    ];

    /// The wire code of this scope.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Returns the scope with wire code `code`, if one is defined.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::PublicBoard),
            2 => Some(Self::TrusteeBody),
            3 => Some(Self::BallotMark),
            4 => Some(Self::CryptoTallyAid),
            5 => Some(Self::Rla),
            6 => Some(Self::ObserverAccess),
            7 => Some(Self::DeployAuth),
            8 => Some(Self::StageGate),
            9 => Some(Self::VoterCode),
            _ => None,
        }
    }

    const fn bit(self) -> u16 {
        // Codes are 1..=9, so the shift is at most 9 and cannot overflow.
        1u16 << self.code()
    }
}

/// A set of scopes. Its canonical encoding is the ascending, duplicate-free
/// array of scope codes, so the set representation makes non-canonical
/// encodings unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScopeSet {
    mask: u16,
}

impl ScopeSet {
    /// The empty set.
    #[must_use]
    pub const fn empty() -> Self {
        Self { mask: 0 }
    }

    /// Builds a set from any slice of scopes; order and repeats are ignored.
    #[must_use]
    pub const fn from_slice(scopes: &[Scope]) -> Self {
        let mut set = Self::empty();
        let mut cursor = scopes;
        while let Some((first, rest)) = cursor.split_first() {
            set = set.with(*first);
            cursor = rest;
        }
        set
    }

    /// Returns this set with `scope` added.
    #[must_use]
    pub const fn with(self, scope: Scope) -> Self {
        Self {
            mask: self.mask | scope.bit(),
        }
    }

    /// Returns `true` if `scope` is in the set.
    #[must_use]
    pub const fn contains(self, scope: Scope) -> bool {
        self.mask & scope.bit() != 0
    }

    /// Number of scopes in the set.
    #[must_use]
    pub const fn len(self) -> usize {
        // `count_ones` of a u16 is at most 16, which always fits in usize.
        self.mask.count_ones() as usize
    }

    /// Returns `true` if no scope is in the set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.mask == 0
    }

    /// Iterates over the scopes in ascending code order.
    pub fn iter(self) -> impl Iterator<Item = Scope> {
        Scope::ALL.into_iter().filter(move |s| self.contains(*s))
    }
}

impl Encode for ScopeSet {
    fn encoded_len(&self) -> usize {
        // 4-byte count prefix plus one byte per scope.
        self.len().saturating_add(4)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_count(self.len(), MAX_SCOPES)?;
        for scope in self.iter() {
            w.write_u8(scope.code())?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for ScopeSet {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let count = r.read_count(MAX_SCOPES)?;
        let mut set = Self::empty();
        let mut previous: Option<u8> = None;
        for _ in 0..count {
            let at = r.position();
            let code = r.read_u8()?;
            let scope =
                Scope::from_code(code).ok_or_else(|| Error::new(Kind::InvalidScopeCode, at))?;
            Reader::check_ascending(previous.as_ref().map(core::slice::from_ref), &[code], at)?;
            set = set.with(scope);
            previous = Some(code);
        }
        Ok(set)
    }
}

/// The body of a legal authorization object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LegalAuthorizationBody<'a> {
    election_id: ElectionId<'a>,
    scopes: ScopeSet,
    statute_refs_hash: Hash512,
    effective_from_day: Day,
    effective_until_day: Day,
}

impl<'a> LegalAuthorizationBody<'a> {
    /// Builds a body. Returns `None` if `effective_until_day` precedes
    /// `effective_from_day`.
    #[must_use]
    pub const fn new(
        election_id: ElectionId<'a>,
        scopes: ScopeSet,
        statute_refs_hash: Hash512,
        effective_from_day: Day,
        effective_until_day: Day,
    ) -> Option<Self> {
        if effective_until_day.get() < effective_from_day.get() {
            return None;
        }
        Some(Self {
            election_id,
            scopes,
            statute_refs_hash,
            effective_from_day,
            effective_until_day,
        })
    }

    /// The election this authorization applies to.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.election_id
    }

    /// The authorized scopes.
    #[must_use]
    pub const fn scopes(&self) -> ScopeSet {
        self.scopes
    }

    /// Hash of the canonical list of statute references.
    #[must_use]
    pub const fn statute_refs_hash(&self) -> &Hash512 {
        &self.statute_refs_hash
    }

    /// First day on which the authorization is effective.
    #[must_use]
    pub const fn effective_from_day(&self) -> Day {
        self.effective_from_day
    }

    /// Last day on which the authorization is effective (inclusive).
    #[must_use]
    pub const fn effective_until_day(&self) -> Day {
        self.effective_until_day
    }
}

impl Encode for LegalAuthorizationBody<'_> {
    fn encoded_len(&self) -> usize {
        self.election_id
            .encoded_len()
            .saturating_add(self.scopes.encoded_len())
            .saturating_add(self.statute_refs_hash.encoded_len())
            .saturating_add(self.effective_from_day.encoded_len())
            .saturating_add(self.effective_until_day.encoded_len())
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.election_id.encode(w)?;
        self.scopes.encode(w)?;
        self.statute_refs_hash.encode(w)?;
        self.effective_from_day.encode(w)?;
        self.effective_until_day.encode(w)
    }
}

impl<'a> Decode<'a> for LegalAuthorizationBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let scopes = ScopeSet::decode(r)?;
        let statute_refs_hash = Hash512::decode(r)?;
        let effective_from_day = Day::decode(r)?;
        let until_at = r.position();
        let effective_until_day = Day::decode(r)?;
        Self::new(
            election_id,
            scopes,
            statute_refs_hash,
            effective_from_day,
            effective_until_day,
        )
        .ok_or_else(|| Error::new(Kind::ValueOutOfRange, until_at))
    }
}
