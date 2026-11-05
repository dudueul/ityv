//! Voter-roll custody (ADR-0033, ADR-0040; PROTOCOL.md §6.1, §6.2;
//! ENCODING.md §8.76–§8.81).
//!
//! * [`RollAuthorityEntry`] (schema `0x0051`, genesis set 13, fixed for the
//!   election): an authority the roll answers to, with its organisation,
//!   its one function and its hybrid key. A source signs the facts it
//!   owns (resident registration extracts per precinct, the national
//!   snapshot, deaths, disqualifications, overseas voters and loss of
//!   nationality, appeal decisions); a custodian keeps a copy of the
//!   frozen roll and signs what it recomputed from it. One entry has one
//!   function and one key: an organisation with two functions has two
//!   entries.
//! * In a `WitnessedEvent` (version 4): [`RollSourceExtractBody`]
//!   (`0x0052`, signed by its source), [`RollFreezeBody`] (`0x0053`, the
//!   commission and the committee), [`RollCustodyReceiptBody`] (`0x0054`,
//!   its custodian) and [`RollAmendmentBody`] (`0x0055`, the commission,
//!   the committee and the source of its reason).
//! * [`ContestedCheckin`] (`0x0056`, restricted): the pseudonym of a voter
//!   the integrated roll marks as having voted and who denies it, with the
//!   label of the envelope their ballot went into, signed by the check-in
//!   unit and its party modules over the header-less field group (fields
//!   1–5, purpose `contested-checkin`). Its frame is public, its body is
//!   not.
//!
//! The encoding checks form only. Whether a signer is the authority it
//! names, whether the extracts merge into the freeze, whether the
//! custodians agree, and every rule between events are the verifier's.

use core::fmt;

use crate::codec::{Decode, Encode};
use crate::error::{Error, Kind};
use crate::primitives::{
    AuthorityId, Day, ElectionId, Hash512, ModuleId, OrgId, StationId, TimeBucket, Token192, UnitId,
};
use crate::reader::Reader;
use crate::schema::genesis::{EntrySet, GenesisEntry, read_nonzero_hash};
use crate::schema::participation::{MAX_PARTY_MODULES, PSEUDONYM_LEN, ParticipationModuleSig};
use crate::schema::util::{HYBRID_SIG_LEN, HYBRID_VK_LEN, read_fixed};
use crate::writer::Writer;

/// Signature purpose of a source extract.
pub const PURPOSE_ROLL_SOURCE: &[u8] = b"roll-source";

/// Signature purpose of the roll freeze.
pub const PURPOSE_ROLL_FREEZE: &[u8] = b"roll-freeze";

/// Signature purpose of a custody receipt.
pub const PURPOSE_ROLL_RECEIPT: &[u8] = b"roll-receipt";

/// Signature purpose of a roll amendment.
pub const PURPOSE_ROLL_AMENDMENT: &[u8] = b"roll-amendment";

/// Signature purpose of a contested check-in (a header-less field group).
pub const PURPOSE_CONTESTED_CHECKIN: &[u8] = b"contested-checkin";

/// The smallest custody quorum a genesis may set: the statutory floor
/// (`LEGAL_ANNEX.md` amendment 14, §44-3 ④).
pub const MIN_CUSTODY_QUORUM: u8 = 3;

fn out_of_range(at: usize) -> Error {
    Error::new(Kind::ValueOutOfRange, at)
}

fn read_code<T>(r: &mut Reader<'_>, from: impl Fn(u8) -> Option<T>) -> Result<T, Error> {
    let at = r.position();
    from(r.read_u8()?).ok_or_else(|| out_of_range(at))
}

/// The one function of a roll authority (ADR-0033 decisions 1, 2, 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum RollAuthorityKind {
    /// A district head (구·시·군의 장): the resident registration extract
    /// of each precinct, and the decisions on objections to it.
    ResidentExtract = 1,
    /// The Ministry of the Interior (행정안전부): the hash of the national
    /// resident registration snapshot at the reference time.
    ResidentSnapshot = 2,
    /// The court administration (법원행정처), keeper of family
    /// registration: deaths.
    Deaths = 3,
    /// The prosecution or the courts: disqualifications (공직선거법 제18조).
    Disqualification = 4,
    /// The Ministries of Foreign Affairs and of Justice: overseas voters
    /// and loss of nationality.
    Overseas = 5,
    /// A court deciding an appeal against an objection decision.
    AppealCourt = 6,
    /// Custodian: the court administration (법원행정처, judiciary).
    CustodianJudiciary = 11,
    /// Custodian: the Ministry of the Interior (행정안전부, executive).
    CustodianInterior = 12,
    /// Custodian: the Independent Verification Committee.
    CustodianCommittee = 13,
    /// Custodian: a party entitled to roll copies that asked for custody.
    CustodianParty = 14,
}

impl RollAuthorityKind {
    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Returns the kind with wire code `code`, if defined.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::ResidentExtract),
            2 => Some(Self::ResidentSnapshot),
            3 => Some(Self::Deaths),
            4 => Some(Self::Disqualification),
            5 => Some(Self::Overseas),
            6 => Some(Self::AppealCourt),
            11 => Some(Self::CustodianJudiciary),
            12 => Some(Self::CustodianInterior),
            13 => Some(Self::CustodianCommittee),
            14 => Some(Self::CustodianParty),
            _ => None,
        }
    }

    /// Whether the authority keeps a copy of the roll and signs receipts.
    #[must_use]
    pub const fn is_custodian(self) -> bool {
        matches!(
            self,
            Self::CustodianJudiciary
                | Self::CustodianInterior
                | Self::CustodianCommittee
                | Self::CustodianParty
        )
    }
}

/// One authority of the roll (schema `0x0051`, genesis set 13, key
/// `authority_id`; ADR-0040).
///
/// Rule: the kind is one of [`RollAuthorityKind`] (`ValueOutOfRange`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RollAuthorityEntry<'a> {
    /// The authority, as roll events and their signatures name it.
    pub authority_id: AuthorityId<'a>,
    /// Its organisation.
    pub org_id: OrgId<'a>,
    /// Its one function.
    pub kind: RollAuthorityKind,
    /// Its hybrid verifying key.
    pub key: &'a [u8; HYBRID_VK_LEN],
}

impl Encode for RollAuthorityEntry<'_> {
    fn encoded_len(&self) -> usize {
        self.authority_id
            .encoded_len()
            .saturating_add(self.org_id.encoded_len())
            .saturating_add(1)
            .saturating_add(HYBRID_VK_LEN)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.authority_id.encode(w)?;
        self.org_id.encode(w)?;
        w.write_u8(self.kind.code())?;
        w.write_array(self.key)
    }
}

impl<'a> Decode<'a> for RollAuthorityEntry<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            authority_id: AuthorityId::decode(r)?,
            org_id: OrgId::decode(r)?,
            kind: read_code(r, RollAuthorityKind::from_code)?,
            key: read_fixed::<HYBRID_VK_LEN>(r)?,
        })
    }
}

impl<'a> GenesisEntry<'a> for RollAuthorityEntry<'a> {
    const SET: EntrySet = EntrySet::RollAuthorities;

    fn key(&self) -> &'a [u8] {
        self.authority_id.as_bytes()
    }
}

/// What a source extract lists (ADR-0033 decision 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum RollSourceKind {
    /// The resident registration extract of one precinct.
    Residents = 1,
    /// The national resident registration snapshot.
    Snapshot = 2,
    /// Deaths.
    Deaths = 3,
    /// Disqualifications.
    Disqualifications = 4,
    /// Overseas voters and loss of nationality.
    Overseas = 5,
}

impl RollSourceKind {
    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Returns the kind with wire code `code`, if defined.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Residents),
            2 => Some(Self::Snapshot),
            3 => Some(Self::Deaths),
            4 => Some(Self::Disqualifications),
            5 => Some(Self::Overseas),
            _ => None,
        }
    }

    /// The authority that signs extracts of this kind.
    #[must_use]
    pub const fn authority(self) -> RollAuthorityKind {
        match self {
            Self::Residents => RollAuthorityKind::ResidentExtract,
            Self::Snapshot => RollAuthorityKind::ResidentSnapshot,
            Self::Deaths => RollAuthorityKind::Deaths,
            Self::Disqualifications => RollAuthorityKind::Disqualification,
            Self::Overseas => RollAuthorityKind::Overseas,
        }
    }
}

/// The public part of one source extract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RollSourceExtractParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The source that signs it.
    pub authority_id: AuthorityId<'a>,
    /// What it lists.
    pub kind: RollSourceKind,
    /// The precinct (its election-day station), for a resident extract
    /// only.
    pub precinct: Option<StationId<'a>>,
    /// The reference day (기준 시점), days since the Unix epoch.
    pub reference_day: Day,
    /// The number of entries.
    pub entry_count: u64,
    /// The sorted-set root of the entry commitments (the snapshot's hash
    /// for the national snapshot).
    pub entries_root: Hash512,
}

/// A source extract (schema `0x0052`, in a `WitnessedEvent` signed by its
/// source, purpose `roll-source`).
///
/// Rules: the kind is 1–5 (`ValueOutOfRange`); a precinct is present
/// exactly for a resident extract (`InvariantViolation`); the root is
/// nonzero (`InvalidPreviousHash`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RollSourceExtractBody<'a> {
    parts: RollSourceExtractParts<'a>,
}

impl<'a> RollSourceExtractBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// `InvariantViolation` at 0 if a rule is broken.
    pub fn new(parts: &RollSourceExtractParts<'a>) -> Result<Self, Error> {
        let precinct_ok = parts.precinct.is_some() == (parts.kind == RollSourceKind::Residents);
        if !precinct_ok || parts.entries_root.is_zero() {
            return Err(Error::new(Kind::InvariantViolation, 0));
        }
        Ok(Self { parts: *parts })
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &RollSourceExtractParts<'a> {
        &self.parts
    }
}

impl Encode for RollSourceExtractBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        let precinct = p.precinct.map_or(1, |s| s.encoded_len().saturating_add(1));
        p.election_id
            .encoded_len()
            .saturating_add(p.authority_id.encoded_len())
            .saturating_add(1)
            .saturating_add(precinct)
            .saturating_add(8 + 8 + 64)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.authority_id.encode(w)?;
        w.write_u8(p.kind.code())?;
        p.precinct.encode(w)?;
        p.reference_day.encode(w)?;
        w.write_u64(p.entry_count)?;
        p.entries_root.encode(w)
    }
}

impl<'a> Decode<'a> for RollSourceExtractBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let authority_id = AuthorityId::decode(r)?;
        let kind = read_code(r, RollSourceKind::from_code)?;
        let precinct_at = r.position();
        let precinct = Option::<StationId<'a>>::decode(r)?;
        if precinct.is_some() != (kind == RollSourceKind::Residents) {
            return Err(Error::new(Kind::InvariantViolation, precinct_at));
        }
        Ok(Self {
            parts: RollSourceExtractParts {
                election_id,
                authority_id,
                kind,
                precinct,
                reference_day: Day::decode(r)?,
                entry_count: r.read_u64()?,
                entries_root: read_nonzero_hash(r)?,
            },
        })
    }
}

/// The values of a roll state that the custodians recompute (ADR-0033
/// decisions 2–4): the entry commitments' sorted-set root and count, the
/// hash of the counts table (per precinct and age band) and the root of
/// the roll's pseudonym multiset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RollState {
    /// The sorted-set root of the entry commitments `C_i`.
    pub entries_root: Hash512,
    /// The number of entries.
    pub entry_count: u64,
    /// The hash of the published counts table: entries per precinct and
    /// per age band (ADR-0033 decision 4; the table's form and its small
    /// cell rule are a sub-regulation's).
    pub counts_hash: Hash512,
    /// The Merkle root of the roll's pseudonym multiset (PROTOCOL.md
    /// §6.5), as a custodian computed it (VC-109).
    pub pseudonym_root: Hash512,
}

impl RollState {
    fn hashes_nonzero(&self) -> bool {
        !self.entries_root.is_zero()
            && !self.counts_hash.is_zero()
            && !self.pseudonym_root.is_zero()
    }

    const LEN: usize = 64 + 8 + 64 + 64;

    fn write(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.entries_root.encode(w)?;
        w.write_u64(self.entry_count)?;
        self.counts_hash.encode(w)?;
        self.pseudonym_root.encode(w)
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            entries_root: read_nonzero_hash(r)?,
            entry_count: r.read_u64()?,
            counts_hash: read_nonzero_hash(r)?,
            pseudonym_root: read_nonzero_hash(r)?,
        })
    }
}

/// The fields of the roll freeze.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RollFreezeParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The frozen roll.
    pub state: RollState,
    /// The sorted-set root of the object hashes of the source extract
    /// bodies it merges (VC-107).
    pub sources_root: Hash512,
    /// How many extracts it merges (one or more).
    pub source_count: u32,
    /// When the roll was frozen.
    pub time_bucket: TimeBucket,
}

/// The roll freeze (schema `0x0053`, in a `WitnessedEvent` signed by the
/// commission and the committee, purpose `roll-freeze`).
///
/// Rules: the four hashes are nonzero (`InvalidPreviousHash`); at least
/// one source (`ValueOutOfRange`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RollFreezeBody<'a> {
    parts: RollFreezeParts<'a>,
}

impl<'a> RollFreezeBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// `InvariantViolation` at 0 if a rule is broken.
    pub fn new(parts: &RollFreezeParts<'a>) -> Result<Self, Error> {
        if !parts.state.hashes_nonzero() || parts.sources_root.is_zero() || parts.source_count == 0
        {
            return Err(Error::new(Kind::InvariantViolation, 0));
        }
        Ok(Self { parts: *parts })
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &RollFreezeParts<'a> {
        &self.parts
    }
}

impl Encode for RollFreezeBody<'_> {
    fn encoded_len(&self) -> usize {
        self.parts
            .election_id
            .encoded_len()
            .saturating_add(RollState::LEN + 64 + 4 + 8)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.state.write(w)?;
        p.sources_root.encode(w)?;
        w.write_u32(p.source_count)?;
        p.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for RollFreezeBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let state = RollState::read(r)?;
        let sources_root = read_nonzero_hash(r)?;
        let count_at = r.position();
        let source_count = r.read_u32()?;
        if source_count == 0 {
            return Err(out_of_range(count_at));
        }
        Ok(Self {
            parts: RollFreezeParts {
                election_id,
                state,
                sources_root,
                source_count,
                time_bucket: TimeBucket::decode(r)?,
            },
        })
    }
}

/// The fields of a custody receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RollCustodyReceiptParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The custodian that signs it.
    pub custodian: AuthorityId<'a>,
    /// The object hash of the freeze or amendment body it answers.
    pub subject_hash: Hash512,
    /// The entry commitments' root it recomputed.
    pub entries_root: Hash512,
    /// The entry count it recomputed.
    pub entry_count: u64,
    /// The counts table hash it recomputed.
    pub counts_hash: Hash512,
    /// For a freeze: the root of the source extracts whose merge it
    /// recomputed. `None` for an amendment.
    pub sources_root: Option<Hash512>,
    /// The roll's pseudonym root, when this custodian computed it on a
    /// certified check-in unit with every party module before observers
    /// (or recomputed it); `None` otherwise (VC-109).
    pub pseudonym_root: Option<Hash512>,
    /// When it was signed.
    pub time_bucket: TimeBucket,
}

/// A custody receipt (schema `0x0054`, in a `WitnessedEvent` signed by its
/// custodian, purpose `roll-receipt`).
///
/// Rule: every hash present is nonzero (`InvalidPreviousHash`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RollCustodyReceiptBody<'a> {
    parts: RollCustodyReceiptParts<'a>,
}

fn read_optional_hash(r: &mut Reader<'_>) -> Result<Option<Hash512>, Error> {
    if r.read_presence()? {
        Ok(Some(read_nonzero_hash(r)?))
    } else {
        Ok(None)
    }
}

impl<'a> RollCustodyReceiptBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// `InvariantViolation` at 0 if a hash is zero.
    pub fn new(parts: &RollCustodyReceiptParts<'a>) -> Result<Self, Error> {
        let optional_ok = |h: Option<Hash512>| h.is_none_or(|h| !h.is_zero());
        if parts.subject_hash.is_zero()
            || parts.entries_root.is_zero()
            || parts.counts_hash.is_zero()
            || !optional_ok(parts.sources_root)
            || !optional_ok(parts.pseudonym_root)
        {
            return Err(Error::new(Kind::InvariantViolation, 0));
        }
        Ok(Self { parts: *parts })
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &RollCustodyReceiptParts<'a> {
        &self.parts
    }
}

impl Encode for RollCustodyReceiptBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        let optional = |h: Option<Hash512>| h.map_or(1, |_| 65);
        p.election_id
            .encoded_len()
            .saturating_add(p.custodian.encoded_len())
            .saturating_add(64 + 64 + 8 + 64 + 8)
            .saturating_add(optional(p.sources_root))
            .saturating_add(optional(p.pseudonym_root))
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.custodian.encode(w)?;
        p.subject_hash.encode(w)?;
        p.entries_root.encode(w)?;
        w.write_u64(p.entry_count)?;
        p.counts_hash.encode(w)?;
        p.sources_root.encode(w)?;
        p.pseudonym_root.encode(w)?;
        p.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for RollCustodyReceiptBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            parts: RollCustodyReceiptParts {
                election_id: ElectionId::decode(r)?,
                custodian: AuthorityId::decode(r)?,
                subject_hash: read_nonzero_hash(r)?,
                entries_root: read_nonzero_hash(r)?,
                entry_count: r.read_u64()?,
                counts_hash: read_nonzero_hash(r)?,
                sources_root: read_optional_hash(r)?,
                pseudonym_root: read_optional_hash(r)?,
                time_bucket: TimeBucket::decode(r)?,
            },
        })
    }
}

/// Why the roll was changed after the freeze (ADR-0033 decision 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RollAmendmentReason {
    /// A decision on an objection (이의신청 결정), by the district head.
    ObjectionDecision = 1,
    /// A court's decision on an appeal (불복 결정).
    AppealDecision = 2,
    /// A death, notified by the court administration.
    Death = 3,
    /// A disqualification, notified by the prosecution or a court.
    Disqualification = 4,
    /// An overseas voter or a loss of nationality.
    Overseas = 5,
}

impl RollAmendmentReason {
    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Returns the reason with wire code `code`, if defined.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::ObjectionDecision),
            2 => Some(Self::AppealDecision),
            3 => Some(Self::Death),
            4 => Some(Self::Disqualification),
            5 => Some(Self::Overseas),
            _ => None,
        }
    }

    /// The source whose signature the reason needs (ADR-0033 decision 5:
    /// an objection decision its deciding body, an appeal the court, a
    /// death the court administration).
    #[must_use]
    pub const fn source(self) -> RollAuthorityKind {
        match self {
            Self::ObjectionDecision => RollAuthorityKind::ResidentExtract,
            Self::AppealDecision => RollAuthorityKind::AppealCourt,
            Self::Death => RollAuthorityKind::Deaths,
            Self::Disqualification => RollAuthorityKind::Disqualification,
            Self::Overseas => RollAuthorityKind::Overseas,
        }
    }
}

/// The fields of a roll amendment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RollAmendmentParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// One-based amendment number.
    pub seq: u64,
    /// The object hash of the freeze body (for `seq` 1) or of the previous
    /// amendment body.
    pub previous_hash: Hash512,
    /// Why.
    pub reason: RollAmendmentReason,
    /// The source whose signature the reason needs.
    pub authority_id: AuthorityId<'a>,
    /// The hash of the source's decision or notice.
    pub basis_hash: Hash512,
    /// The roll after the change.
    pub state: RollState,
    /// When it was recorded.
    pub time_bucket: TimeBucket,
}

/// A roll amendment (schema `0x0055`, in a `WitnessedEvent` signed by the
/// commission, the committee and the source of its reason, purpose
/// `roll-amendment`).
///
/// Rules: `seq ≥ 1` (`ValueOutOfRange`); the reason is 1–5
/// (`ValueOutOfRange`); every hash is nonzero (`InvalidPreviousHash`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RollAmendmentBody<'a> {
    parts: RollAmendmentParts<'a>,
}

impl<'a> RollAmendmentBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// `InvariantViolation` at 0 if a rule is broken.
    pub fn new(parts: &RollAmendmentParts<'a>) -> Result<Self, Error> {
        if parts.seq == 0
            || parts.previous_hash.is_zero()
            || parts.basis_hash.is_zero()
            || !parts.state.hashes_nonzero()
        {
            return Err(Error::new(Kind::InvariantViolation, 0));
        }
        Ok(Self { parts: *parts })
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &RollAmendmentParts<'a> {
        &self.parts
    }
}

impl Encode for RollAmendmentBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(8 + 64 + 1)
            .saturating_add(p.authority_id.encoded_len())
            .saturating_add(64 + RollState::LEN + 8)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        w.write_u64(p.seq)?;
        p.previous_hash.encode(w)?;
        w.write_u8(p.reason.code())?;
        p.authority_id.encode(w)?;
        p.basis_hash.encode(w)?;
        p.state.write(w)?;
        p.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for RollAmendmentBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let seq_at = r.position();
        let seq = r.read_u64()?;
        if seq == 0 {
            return Err(out_of_range(seq_at));
        }
        Ok(Self {
            parts: RollAmendmentParts {
                election_id,
                seq,
                previous_hash: read_nonzero_hash(r)?,
                reason: read_code(r, RollAmendmentReason::from_code)?,
                authority_id: AuthorityId::decode(r)?,
                basis_hash: read_nonzero_hash(r)?,
                state: RollState::read(r)?,
                time_bucket: TimeBucket::decode(r)?,
            },
        })
    }
}

/// The signed field group of a contested check-in (fields 1–5), without an
/// object header.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContestedMessage<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The polling station.
    pub station_id: StationId<'a>,
    /// The check-in unit that computed the pseudonym.
    pub unit_id: UnitId<'a>,
    /// The voter's pseudonym (PROTOCOL.md §6.4), kept out of the
    /// station's participation set.
    pub pseudonym: &'a [u8; PSEUDONYM_LEN],
    /// The label of the envelope the ballot went into.
    pub envelope_label: Token192,
}

/// Shows the station and unit only: the pseudonym next to the envelope
/// label is what the restricted level protects.
impl fmt::Debug for ContestedMessage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContestedMessage")
            .field("election_id", &self.election_id)
            .field("station_id", &self.station_id)
            .field("unit_id", &self.unit_id)
            .finish_non_exhaustive()
    }
}

impl Encode for ContestedMessage<'_> {
    fn encoded_len(&self) -> usize {
        self.election_id
            .encoded_len()
            .saturating_add(self.station_id.encoded_len())
            .saturating_add(self.unit_id.encoded_len())
            .saturating_add(PSEUDONYM_LEN + 24)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.election_id.encode(w)?;
        self.station_id.encode(w)?;
        self.unit_id.encode(w)?;
        w.write_array(self.pseudonym)?;
        self.envelope_label.encode(w)
    }
}

impl<'a> Decode<'a> for ContestedMessage<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            election_id: ElectionId::decode(r)?,
            station_id: StationId::decode(r)?,
            unit_id: UnitId::decode(r)?,
            pseudonym: read_fixed::<PSEUDONYM_LEN>(r)?,
            envelope_label: Token192::decode(r)?,
        })
    }
}

/// A contested check-in (schema `0x0056`, restricted; ADR-0033 decision 6,
/// PROTOCOL.md §6.2): the field group, the check-in unit's signature and
/// the party modules' signatures, all over the field group's bytes with
/// purpose `contested-checkin`.
///
/// Rules: the field group is canonical; at most four module signatures
/// (`CountExceedsMax`) of distinct modules (`Duplicate`). Their order and
/// number, and the keys, are the verifier's. `Debug` shows the station and
/// unit only.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContestedCheckin<'a> {
    message_bytes: &'a [u8],
    message: ContestedMessage<'a>,
    unit_sig: &'a [u8; HYBRID_SIG_LEN],
    module_sigs: [Option<ParticipationModuleSig<'a>>; MAX_PARTY_MODULES],
    module_sig_count: u8,
}

impl fmt::Debug for ContestedCheckin<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContestedCheckin")
            .field("message", &self.message)
            .field("module_sigs", &self.module_sig_count)
            .finish_non_exhaustive()
    }
}

impl<'a> ContestedCheckin<'a> {
    /// Builds a contested check-in from its field group (the encoding of a
    /// [`ContestedMessage`]) and its signatures.
    ///
    /// # Errors
    /// The decoding error of `message_bytes` (`TrailingBytes` for bytes
    /// after it), `CountExceedsMax` at 0 for more than four module
    /// signatures, `Duplicate` at 0 for two of one module.
    pub fn new(
        message_bytes: &'a [u8],
        unit_sig: &'a [u8; HYBRID_SIG_LEN],
        module_sigs: &[ParticipationModuleSig<'a>],
    ) -> Result<Self, Error> {
        let mut r = Reader::new(message_bytes);
        let message = ContestedMessage::decode(&mut r)?;
        r.finish()?;
        if module_sigs.len() > MAX_PARTY_MODULES {
            return Err(Error::new(Kind::CountExceedsMax, 0));
        }
        let mut slots = [None; MAX_PARTY_MODULES];
        for (i, (slot, sig)) in slots.iter_mut().zip(module_sigs).enumerate() {
            if module_sigs
                .iter()
                .take(i)
                .any(|s| s.module_id.as_bytes() == sig.module_id.as_bytes())
            {
                return Err(Error::new(Kind::Duplicate, 0));
            }
            *slot = Some(*sig);
        }
        Ok(Self {
            message_bytes,
            message,
            unit_sig,
            module_sigs: slots,
            module_sig_count: u8::try_from(module_sigs.len())
                .map_err(|_| Error::new(Kind::CountExceedsMax, 0))?,
        })
    }

    /// The signed field group (fields 1–5), as it came.
    #[must_use]
    pub const fn message_bytes(&self) -> &'a [u8] {
        self.message_bytes
    }

    /// The decoded field group.
    #[must_use]
    pub const fn message(&self) -> &ContestedMessage<'a> {
        &self.message
    }

    /// The check-in unit's signature.
    #[must_use]
    pub const fn unit_sig(&self) -> &'a [u8; HYBRID_SIG_LEN] {
        self.unit_sig
    }

    /// The party modules' signatures, in the order given.
    pub fn module_sigs(&self) -> impl Iterator<Item = ParticipationModuleSig<'a>> + '_ {
        self.module_sigs
            .iter()
            .take(usize::from(self.module_sig_count))
            .flatten()
            .copied()
    }

    /// The number of module signatures.
    #[must_use]
    pub fn module_sig_count(&self) -> usize {
        usize::from(self.module_sig_count)
    }
}

impl Encode for ContestedCheckin<'_> {
    fn encoded_len(&self) -> usize {
        let sigs = self.module_sigs().fold(4usize, |acc, s| {
            acc.saturating_add(s.module_id.encoded_len())
                .saturating_add(HYBRID_SIG_LEN)
        });
        self.message_bytes
            .len()
            .saturating_add(HYBRID_SIG_LEN)
            .saturating_add(sigs)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_slice(self.message_bytes)?;
        w.write_array(self.unit_sig)?;
        w.write_count(self.module_sig_count(), MAX_PARTY_MODULES)?;
        for sig in self.module_sigs() {
            sig.module_id.encode(w)?;
            w.write_array(sig.sig)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for ContestedCheckin<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let start = r.position();
        let message = ContestedMessage::decode(r)?;
        let message_bytes = r.consumed_from(start)?;
        let unit_sig = read_fixed::<HYBRID_SIG_LEN>(r)?;
        let sigs_at = r.position();
        let count = r.read_count(MAX_PARTY_MODULES)?;
        let mut module_sigs: [Option<ParticipationModuleSig<'a>>; MAX_PARTY_MODULES] =
            [None; MAX_PARTY_MODULES];
        for i in 0..count {
            let at = r.position();
            let module_id = ModuleId::decode(r)?;
            if module_sigs
                .iter()
                .take(i)
                .flatten()
                .any(|s| s.module_id.as_bytes() == module_id.as_bytes())
            {
                return Err(Error::new(Kind::Duplicate, at));
            }
            let sig = read_fixed::<HYBRID_SIG_LEN>(r)?;
            if let Some(slot) = module_sigs.get_mut(i) {
                *slot = Some(ParticipationModuleSig { module_id, sig });
            }
        }
        Ok(Self {
            message_bytes,
            message,
            unit_sig,
            module_sigs,
            module_sig_count: u8::try_from(count)
                .map_err(|_| Error::new(Kind::CountExceedsMax, sigs_at))?,
        })
    }
}
