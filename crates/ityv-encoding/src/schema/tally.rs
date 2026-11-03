//! The tally (PROTOCOL.md §10.6, §11; ENCODING.md §8.61–§8.65), version
//! 1: `TallyScopeBody` (schema `0x0043`), `AggregateOpeningBody`
//! (`0x0044`), `ReceiptResolutionBody` (`0x0047`), the trustee-quorum
//! envelope `QuorumSigned` (`0x0045`) that carries any of the three with the
//! signatures of the trustees who made it, and `PaperCountReportBody`
//! (`0x0046`), the body of a [`crate::WitnessedEvent`] (ADR-0035).
//!
//! `TallyScopeBody` field order: `election_id`, `ballot_style_id`,
//! `reporting_unit_id`, `included_count` (at most [`MAX_TALLY_COUNT`]),
//! `included_root`, `no_record_count` (at most [`MAX_TALLY_COUNT`]),
//! `exclusions` (at most [`MAX_EXCLUSIONS`] entries of `record_hash ‖
//! reason ‖ basis`, strictly ascending by record hash, reason code 1–8 in
//! the order of PROTOCOL.md §11.1, basis not zero), `time_bucket`.
//!
//! `AggregateOpeningBody`: `election_id`, `ballot_style_id`,
//! `reporting_unit_id`, `scope_hash` (the object hash of the
//! `TallyScopeBody` it opens, not zero), `chunk` (below 8), `packed_sum`
//! `T_j`, `rand_sum` `R_j`, `id_sum` `S` (three 32-byte scalars, canonical
//! form checked by `ityv-crypto`), `time_bucket`.
//!
//! `ReceiptResolutionBody`: `election_id`, `box_id` (an out-of-district
//! box), `entries` (at most [`MAX_RECEIPT_ENTRIES`] entries of
//! `record_hash ‖ outcome`, strictly ascending by record hash, outcome code
//! 1–5: `RECEIVED`, `RECEIVED_DAMAGED`, `RECEIVED_LATE`, `WRONG_DISTRICT`,
//! `CAST_NOT_RECEIVED`), `time_bucket`.
//!
//! `QuorumSigned`: `body` (a complete `TallyScopeBody`,
//! `AggregateOpeningBody` or `ReceiptResolutionBody` object of at most
//! [`MAX_QUORUM_BODY_LEN`] bytes),
//! `sigs` (one to [`MAX_QUORUM_SIGS`] entries of `trustee_id ‖ sig`,
//! strictly ascending by trustee). Every signature is a hybrid signature
//! over exactly the body bytes, purpose `tally-scope`, `aggregate-opening`
//! or `receipt-resolution` by the body's schema. The signers are the
//! participating members (PROTOCOL.md §10.6 item 2, §11.2).
//!
//! `PaperCountReportBody`: `election_id`, `reporting_unit_id`,
//! `ballot_style_id`, `votes` (one to [`MAX_CANDIDATES`] counts, candidate
//! 1 first), `invalid`, `time_bucket`; every count at most
//! [`MAX_TALLY_COUNT`]. Purpose `paper-count`; the chair of the district
//! commission and observers of two or more organisations sign
//! ([`crate::roles_satisfied`]).
//!
//! The encoding checks form only. That a signer is a trustee, that the
//! signers form a qualified set of the chamber access structure, that the
//! scope agrees with the ledger, that the opening opens the sum of the
//! commitments and that the paper agrees with it are the verifier's
//! (PROTOCOL.md §14 item 7).

use crate::codec::{Decode, Encode};
use crate::envelope::{Header, decode as decode_object};
use crate::error::{Error, Kind};
use crate::primitives::{
    BallotStyleId, BoxId, ElectionId, Hash512, IDENT_MAX_STANDARD, ReportingUnitId, Scalar32,
    TimeBucket, TrusteeId,
};
use crate::reader::Reader;
use crate::schema::util::{HYBRID_SIG_LEN, MAX_CHUNKS, ascending_by, read_fixed};
use crate::schema::{
    SCHEMA_AGGREGATE_OPENING_BODY, SCHEMA_RECEIPT_RESOLUTION_BODY, SCHEMA_TALLY_SCOPE_BODY,
    SCHEMA_VERSION_1,
};
use crate::writer::Writer;

/// Purpose of the trustees' signatures on a tally scope.
pub const PURPOSE_TALLY_SCOPE: &[u8] = b"tally-scope";

/// Purpose of the trustees' signatures on an aggregate opening.
pub const PURPOSE_AGGREGATE_OPENING: &[u8] = b"aggregate-opening";

/// Purpose of the trustees' signatures on a receipt resolution.
pub const PURPOSE_RECEIPT_RESOLUTION: &[u8] = b"receipt-resolution";

/// Purpose of the signatures on a paper count report.
pub const PURPOSE_PAPER_COUNT: &[u8] = b"paper-count";

/// The largest count a tally scope or a paper count report carries:
/// `2^26 − 1`, so that no 26-bit digit of an aggregate can carry into the
/// next (PROTOCOL.md §7.4).
pub const MAX_TALLY_COUNT: u64 = 67_108_863;

/// Most exclusions in one tally scope.
pub const MAX_EXCLUSIONS: usize = 65_536;

/// Length of one exclusion: `record_hash[64] ‖ reason[1] ‖ basis[64]`.
pub const EXCLUSION_LEN: usize = 129;

/// Most trustee signatures on one quorum-signed event: eight chambers of at
/// most eight members.
pub const MAX_QUORUM_SIGS: usize = 64;

/// Longest body a `QuorumSigned` carries: a `TallyScopeBody` with three
/// 64-byte identifiers and [`MAX_EXCLUSIONS`] exclusions.
pub const MAX_QUORUM_BODY_LEN: usize = 8_454_456;

/// Most candidates of a ballot style (PROTOCOL.md §7.4, `choices ≤ 70`).
pub const MAX_CANDIDATES: usize = 70;

fn invalid(at: usize) -> Error {
    Error::new(Kind::InvariantViolation, at)
}

fn out_of_range(at: usize) -> Error {
    Error::new(Kind::ValueOutOfRange, at)
}

/// Reads a count of at most [`MAX_TALLY_COUNT`].
fn read_tally_count(r: &mut Reader<'_>) -> Result<u64, Error> {
    let at = r.position();
    let value = r.read_u64()?;
    if value > MAX_TALLY_COUNT {
        return Err(out_of_range(at));
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// Exclusions

/// Why a record is left out of a tally scope (PROTOCOL.md §11.1). The codes
/// follow the order of §11.1: a record with several reasons is excluded
/// with the one of the smallest code (VC-042).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ExclusionReason {
    /// `TEST_BALLOT` (VC-055).
    TestBallot = 1,
    /// `CHALLENGED_SPOILED`.
    ChallengedSpoiled = 2,
    /// `QUARANTINED`.
    Quarantined = 3,
    /// `CAST_NOT_RECEIVED`.
    CastNotReceived = 4,
    /// `RECEIVED_LATE`.
    ReceivedLate = 5,
    /// `LEGAL_EXCLUDED` (VC-099).
    LegalExcluded = 6,
    /// `SHARE_MISSING`.
    ShareMissing = 7,
    /// `UNATTESTED` (VC-057).
    Unattested = 8,
}

impl ExclusionReason {
    /// Every reason in code order, which is the order of PROTOCOL.md §11.1.
    pub const ALL: [Self; 8] = [
        Self::TestBallot,
        Self::ChallengedSpoiled,
        Self::Quarantined,
        Self::CastNotReceived,
        Self::ReceivedLate,
        Self::LegalExcluded,
        Self::ShareMissing,
        Self::Unattested,
    ];

    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Returns the reason with wire code `code`, if defined.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::TestBallot),
            2 => Some(Self::ChallengedSpoiled),
            3 => Some(Self::Quarantined),
            4 => Some(Self::CastNotReceived),
            5 => Some(Self::ReceivedLate),
            6 => Some(Self::LegalExcluded),
            7 => Some(Self::ShareMissing),
            8 => Some(Self::Unattested),
            _ => None,
        }
    }

    /// The vocabulary name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::TestBallot => "TEST_BALLOT",
            Self::ChallengedSpoiled => "CHALLENGED_SPOILED",
            Self::Quarantined => "QUARANTINED",
            Self::CastNotReceived => "CAST_NOT_RECEIVED",
            Self::ReceivedLate => "RECEIVED_LATE",
            Self::LegalExcluded => "LEGAL_EXCLUDED",
            Self::ShareMissing => "SHARE_MISSING",
            Self::Unattested => "UNATTESTED",
        }
    }
}

/// One record left out of a tally scope: its tracking code, the reason and
/// the object hash of the ledger event that gives the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExclusionEntry {
    /// The record's tracking code (the object hash of its body).
    pub record_hash: Hash512,
    /// The first reason of PROTOCOL.md §11.1 that applies.
    pub reason: ExclusionReason,
    /// The object hash of the event that gives the reason; not zero.
    pub basis: Hash512,
}

impl Encode for ExclusionEntry {
    fn encoded_len(&self) -> usize {
        EXCLUSION_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.record_hash.encode(w)?;
        w.write_u8(self.reason.code())?;
        self.basis.encode(w)
    }
}

impl<'a> Decode<'a> for ExclusionEntry {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let record_hash = Hash512::decode(r)?;
        let reason_at = r.position();
        let reason =
            ExclusionReason::from_code(r.read_u8()?).ok_or_else(|| out_of_range(reason_at))?;
        let basis_at = r.position();
        let basis = Hash512::decode(r)?;
        if basis.is_zero() {
            return Err(Error::new(Kind::InvalidPreviousHash, basis_at));
        }
        Ok(Self {
            record_hash,
            reason,
            basis,
        })
    }
}

/// The exclusions of a tally scope, borrowed as one slice of
/// [`EXCLUSION_LEN`]-byte entries, strictly ascending by record hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Exclusions<'a> {
    bytes: &'a [u8],
}

impl<'a> Exclusions<'a> {
    /// No exclusion.
    pub const EMPTY: Exclusions<'static> = Exclusions { bytes: &[] };

    /// The exclusions encoded in `bytes`. `None` unless `bytes` is a whole
    /// number, at most [`MAX_EXCLUSIONS`], of canonical entries strictly
    /// ascending by record hash.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        let count = bytes.len().checked_div(EXCLUSION_LEN)?;
        if bytes.len().checked_rem(EXCLUSION_LEN) != Some(0) || count > MAX_EXCLUSIONS {
            return None;
        }
        let mut r = Reader::new(bytes);
        read_entries(&mut r, count).ok()?;
        r.finish().ok()?;
        Some(Self { bytes })
    }

    /// The entries as one slice of `129 · len` bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The number of exclusions.
    #[must_use]
    pub const fn len(&self) -> usize {
        // `bytes` holds whole entries; the divisor is not zero.
        match self.bytes.len().checked_div(EXCLUSION_LEN) {
            Some(n) => n,
            None => 0,
        }
    }

    /// Whether there is none.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The exclusions in ascending record-hash order.
    pub fn iter(&self) -> impl Iterator<Item = ExclusionEntry> + use<'a> {
        self.bytes.chunks_exact(EXCLUSION_LEN).filter_map(|chunk| {
            let mut r = Reader::new(chunk);
            ExclusionEntry::decode(&mut r).ok()
        })
    }
}

/// Reads `count` entries, each record hash above the one before.
fn read_entries(r: &mut Reader<'_>, count: usize) -> Result<(), Error> {
    let mut previous: Option<[u8; 64]> = None;
    for _ in 0..count {
        let at = r.position();
        let entry = ExclusionEntry::decode(r)?;
        Reader::check_ascending(
            previous.as_ref().map(<[u8; 64]>::as_slice),
            entry.record_hash.as_bytes(),
            at,
        )?;
        previous = Some(entry.record_hash.0);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 0x0043 TallyScopeBody

/// The fields of a tally scope (PROTOCOL.md §11.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TallyScopeParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The ballot style.
    pub ballot_style_id: BallotStyleId<'a>,
    /// The reporting unit (genesis `reporting_units[]`).
    pub reporting_unit_id: ReportingUnitId<'a>,
    /// The number of records in the tally.
    pub included_count: u64,
    /// The sorted-set root of their tracking codes.
    pub included_root: Hash512,
    /// Ballots of the style cast in the unit without a record (the
    /// emergency slot).
    pub no_record_count: u64,
    /// The records left out, each with its reason and basis.
    pub exclusions: Exclusions<'a>,
    /// When the scope was recorded.
    pub time_bucket: TimeBucket,
}

/// A tally scope body (schema `0x0043`). Rules: `included_count` and
/// `no_record_count` at most [`MAX_TALLY_COUNT`] (`ValueOutOfRange`), the
/// exclusions as [`Exclusions::new`] requires (`CountExceedsMax`,
/// `ValueOutOfRange` for a reason code, `InvalidPreviousHash` for a zero
/// basis, `NotSorted`, `Duplicate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TallyScopeBody<'a> {
    parts: TallyScopeParts<'a>,
}

impl<'a> TallyScopeBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// `ValueOutOfRange` at 0 if a count is above [`MAX_TALLY_COUNT`].
    pub fn new(parts: &TallyScopeParts<'a>) -> Result<Self, Error> {
        if parts.included_count > MAX_TALLY_COUNT || parts.no_record_count > MAX_TALLY_COUNT {
            return Err(out_of_range(0));
        }
        Ok(Self { parts: *parts })
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &TallyScopeParts<'a> {
        &self.parts
    }
}

impl Encode for TallyScopeBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.ballot_style_id.encoded_len())
            .saturating_add(p.reporting_unit_id.encoded_len())
            .saturating_add(8 + 64 + 8 + 4)
            .saturating_add(p.exclusions.bytes.len())
            .saturating_add(8)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.ballot_style_id.encode(w)?;
        p.reporting_unit_id.encode(w)?;
        w.write_u64(p.included_count)?;
        p.included_root.encode(w)?;
        w.write_u64(p.no_record_count)?;
        w.write_count(p.exclusions.len(), MAX_EXCLUSIONS)?;
        w.write_slice(p.exclusions.bytes)?;
        p.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for TallyScopeBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let ballot_style_id = BallotStyleId::decode(r)?;
        let reporting_unit_id = ReportingUnitId::decode(r)?;
        let included_count = read_tally_count(r)?;
        let included_root = Hash512::decode(r)?;
        let no_record_count = read_tally_count(r)?;
        let count = r.read_count(MAX_EXCLUSIONS)?;
        let start = r.position();
        read_entries(r, count)?;
        let exclusions = Exclusions {
            bytes: r.consumed_from(start)?,
        };
        Ok(Self {
            parts: TallyScopeParts {
                election_id,
                ballot_style_id,
                reporting_unit_id,
                included_count,
                included_root,
                no_record_count,
                exclusions,
                time_bucket: TimeBucket::decode(r)?,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// 0x0044 AggregateOpeningBody

/// The fields of an aggregate opening of one chunk (PROTOCOL.md §11.2):
/// `C_total,j == T_j·G_val + S·G_id + R_j·H`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AggregateOpeningParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The ballot style.
    pub ballot_style_id: BallotStyleId<'a>,
    /// The reporting unit.
    pub reporting_unit_id: ReportingUnitId<'a>,
    /// The object hash of the `TallyScopeBody` whose records are summed.
    pub scope_hash: Hash512,
    /// The chunk `j`.
    pub chunk: u8,
    /// `T_j`, the packed digit sum.
    pub packed_sum: Scalar32,
    /// `R_j`, the sum of the randomness.
    pub rand_sum: Scalar32,
    /// `S`, the sum of the cast identifiers.
    pub id_sum: Scalar32,
    /// When the opening was recorded.
    pub time_bucket: TimeBucket,
}

/// An aggregate opening body (schema `0x0044`). Rules: `scope_hash` not
/// zero (`InvalidPreviousHash`), `chunk` below 8 (`ValueOutOfRange`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AggregateOpeningBody<'a> {
    parts: AggregateOpeningParts<'a>,
}

impl<'a> AggregateOpeningBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// `InvalidPreviousHash` at 0 for a zero scope hash, `ValueOutOfRange`
    /// at 0 for a chunk of 8 or more.
    pub fn new(parts: &AggregateOpeningParts<'a>) -> Result<Self, Error> {
        Self::check(parts, [0; 2])?;
        Ok(Self { parts: *parts })
    }

    fn check(p: &AggregateOpeningParts<'_>, at: [usize; 2]) -> Result<(), Error> {
        let [scope_at, chunk_at] = at;
        if p.scope_hash.is_zero() {
            return Err(Error::new(Kind::InvalidPreviousHash, scope_at));
        }
        if usize::from(p.chunk) >= MAX_CHUNKS {
            return Err(out_of_range(chunk_at));
        }
        Ok(())
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &AggregateOpeningParts<'a> {
        &self.parts
    }
}

impl Encode for AggregateOpeningBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.ballot_style_id.encoded_len())
            .saturating_add(p.reporting_unit_id.encoded_len())
            .saturating_add(64 + 1 + 3 * 32 + 8)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.ballot_style_id.encode(w)?;
        p.reporting_unit_id.encode(w)?;
        p.scope_hash.encode(w)?;
        w.write_u8(p.chunk)?;
        p.packed_sum.encode(w)?;
        p.rand_sum.encode(w)?;
        p.id_sum.encode(w)?;
        p.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for AggregateOpeningBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let ballot_style_id = BallotStyleId::decode(r)?;
        let reporting_unit_id = ReportingUnitId::decode(r)?;
        let scope_at = r.position();
        let scope_hash = Hash512::decode(r)?;
        let chunk_at = r.position();
        let parts = AggregateOpeningParts {
            election_id,
            ballot_style_id,
            reporting_unit_id,
            scope_hash,
            chunk: r.read_u8()?,
            packed_sum: Scalar32::decode(r)?,
            rand_sum: Scalar32::decode(r)?,
            id_sum: Scalar32::decode(r)?,
            time_bucket: TimeBucket::decode(r)?,
        };
        Self::check(&parts, [scope_at, chunk_at])?;
        Ok(Self { parts })
    }
}

// ---------------------------------------------------------------------------
// 0x0047 ReceiptResolutionBody

/// The outcome of the receipt resolution for one out-of-district record
/// (PROTOCOL.md §10.6 item 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ReceiptOutcome {
    /// `RECEIVED`: a normal envelope carried its label.
    Received = 1,
    /// `RECEIVED_DAMAGED`: a damaged envelope carried its label.
    Damaged = 2,
    /// `RECEIVED_LATE`: an envelope past the deadline carried its label.
    Late = 3,
    /// `WRONG_DISTRICT`: the label arrived, but the record's ballot style
    /// is not the receiving district's.
    WrongDistrict = 4,
    /// `CAST_NOT_RECEIVED`: no envelope carried its label.
    NotReceived = 5,
}

impl ReceiptOutcome {
    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Returns the outcome with wire code `code`, if defined.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Received),
            2 => Some(Self::Damaged),
            3 => Some(Self::Late),
            4 => Some(Self::WrongDistrict),
            5 => Some(Self::NotReceived),
            _ => None,
        }
    }
}

/// One record's outcome in a receipt resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReceiptEntry {
    /// The record's tracking code.
    pub record_hash: Hash512,
    /// What the receipt resolution found.
    pub outcome: ReceiptOutcome,
}

/// Length of one receipt entry: `record_hash[64] ‖ outcome[1]`.
pub const RECEIPT_ENTRY_LEN: usize = 65;

/// Most records one receipt resolution resolves.
pub const MAX_RECEIPT_ENTRIES: usize = 65_536;

impl Encode for ReceiptEntry {
    fn encoded_len(&self) -> usize {
        RECEIPT_ENTRY_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.record_hash.encode(w)?;
        w.write_u8(self.outcome.code())
    }
}

impl<'a> Decode<'a> for ReceiptEntry {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let record_hash = Hash512::decode(r)?;
        let at = r.position();
        let outcome = ReceiptOutcome::from_code(r.read_u8()?).ok_or_else(|| out_of_range(at))?;
        Ok(Self {
            record_hash,
            outcome,
        })
    }
}

/// The entries of a receipt resolution, borrowed as one slice of
/// [`RECEIPT_ENTRY_LEN`]-byte entries, strictly ascending by record hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReceiptEntries<'a> {
    bytes: &'a [u8],
}

impl<'a> ReceiptEntries<'a> {
    /// The entries encoded in `bytes`. `None` unless `bytes` is a whole
    /// number, at most [`MAX_RECEIPT_ENTRIES`], of canonical entries
    /// strictly ascending by record hash.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        let count = bytes.len().checked_div(RECEIPT_ENTRY_LEN)?;
        if bytes.len().checked_rem(RECEIPT_ENTRY_LEN) != Some(0) || count > MAX_RECEIPT_ENTRIES {
            return None;
        }
        let mut r = Reader::new(bytes);
        read_receipts(&mut r, count).ok()?;
        r.finish().ok()?;
        Some(Self { bytes })
    }

    /// The number of entries.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self.bytes.len().checked_div(RECEIPT_ENTRY_LEN) {
            Some(n) => n,
            None => 0,
        }
    }

    /// Whether there is none.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// The entries in ascending record-hash order.
    pub fn iter(&self) -> impl Iterator<Item = ReceiptEntry> + use<'a> {
        self.bytes
            .chunks_exact(RECEIPT_ENTRY_LEN)
            .filter_map(|chunk| {
                let mut r = Reader::new(chunk);
                ReceiptEntry::decode(&mut r).ok()
            })
    }
}

/// Reads `count` receipt entries, each record hash above the one before.
fn read_receipts(r: &mut Reader<'_>, count: usize) -> Result<(), Error> {
    let mut previous: Option<[u8; 64]> = None;
    for _ in 0..count {
        let at = r.position();
        let entry = ReceiptEntry::decode(r)?;
        Reader::check_ascending(
            previous.as_ref().map(<[u8; 64]>::as_slice),
            entry.record_hash.as_bytes(),
            at,
        )?;
        previous = Some(entry.record_hash.0);
    }
    Ok(())
}

/// The fields of a receipt resolution (PROTOCOL.md §10.6 items 2 and 5):
/// the outcome of every cast record of one out-of-district box.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReceiptResolutionParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The out-of-district box whose records are resolved.
    pub box_id: BoxId<'a>,
    /// One outcome per record, ascending by record hash.
    pub entries: ReceiptEntries<'a>,
    /// When the resolution was recorded.
    pub time_bucket: TimeBucket,
}

/// A receipt resolution body (schema `0x0047`). Rules: at most
/// [`MAX_RECEIPT_ENTRIES`] entries (`CountExceedsMax`), outcome codes 1–5
/// (`ValueOutOfRange`), strictly ascending by record hash (`NotSorted`,
/// `Duplicate`). Labels that match no record belong to the receiving
/// commission's count, not to a box, and are not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReceiptResolutionBody<'a> {
    parts: ReceiptResolutionParts<'a>,
}

impl<'a> ReceiptResolutionBody<'a> {
    /// Builds the body (the entries were checked by
    /// [`ReceiptEntries::new`]).
    #[must_use]
    pub const fn new(parts: &ReceiptResolutionParts<'a>) -> Self {
        Self { parts: *parts }
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &ReceiptResolutionParts<'a> {
        &self.parts
    }
}

impl Encode for ReceiptResolutionBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.box_id.encoded_len())
            .saturating_add(4)
            .saturating_add(p.entries.bytes.len())
            .saturating_add(8)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.box_id.encode(w)?;
        w.write_count(p.entries.len(), MAX_RECEIPT_ENTRIES)?;
        w.write_slice(p.entries.bytes)?;
        p.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for ReceiptResolutionBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let box_id = BoxId::decode(r)?;
        let count = r.read_count(MAX_RECEIPT_ENTRIES)?;
        let start = r.position();
        read_receipts(r, count)?;
        let entries = ReceiptEntries {
            bytes: r.consumed_from(start)?,
        };
        Ok(Self {
            parts: ReceiptResolutionParts {
                election_id,
                box_id,
                entries,
                time_bucket: TimeBucket::decode(r)?,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// 0x0045 QuorumSigned

/// Which body a [`QuorumSigned`] carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuorumKind {
    /// A `TallyScopeBody` (`0x0043`), purpose `tally-scope`.
    TallyScope,
    /// An `AggregateOpeningBody` (`0x0044`), purpose `aggregate-opening`.
    AggregateOpening,
    /// A `ReceiptResolutionBody` (`0x0047`), purpose `receipt-resolution`.
    ReceiptResolution,
}

impl QuorumKind {
    /// The signature purpose of the body.
    #[must_use]
    pub const fn purpose(self) -> &'static [u8] {
        match self {
            Self::TallyScope => PURPOSE_TALLY_SCOPE,
            Self::AggregateOpening => PURPOSE_AGGREGATE_OPENING,
            Self::ReceiptResolution => PURPOSE_RECEIPT_RESOLUTION,
        }
    }
}

/// One trustee's signature on a quorum-signed event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QuorumSig<'a> {
    /// The trustee (genesis `trustees[]`).
    pub trustee_id: TrusteeId<'a>,
    /// The hybrid signature over the body bytes.
    pub sig: &'a [u8; HYBRID_SIG_LEN],
}

/// Reads the schema of an embedded body and validates it completely.
fn classify(bytes: &[u8]) -> Result<QuorumKind, Error> {
    if bytes.len() > MAX_QUORUM_BODY_LEN {
        return Err(Error::new(Kind::LengthExceedsMax, 0));
    }
    let header = Header::read(&mut Reader::new(bytes))?;
    match header.schema_id() {
        SCHEMA_TALLY_SCOPE_BODY => {
            decode_object::<TallyScopeBody<'_>>(SCHEMA_TALLY_SCOPE_BODY, SCHEMA_VERSION_1, bytes)
                .map(|_| QuorumKind::TallyScope)
        }
        SCHEMA_AGGREGATE_OPENING_BODY => decode_object::<AggregateOpeningBody<'_>>(
            SCHEMA_AGGREGATE_OPENING_BODY,
            SCHEMA_VERSION_1,
            bytes,
        )
        .map(|_| QuorumKind::AggregateOpening),
        SCHEMA_RECEIPT_RESOLUTION_BODY => decode_object::<ReceiptResolutionBody<'_>>(
            SCHEMA_RECEIPT_RESOLUTION_BODY,
            SCHEMA_VERSION_1,
            bytes,
        )
        .map(|_| QuorumKind::ReceiptResolution),
        _ => Err(Error::new(Kind::SchemaMismatch, 4)),
    }
}

/// An event a quorum of trustees signs: a tally scope, an aggregate
/// opening or a receipt resolution, with each participating member's
/// signature (PROTOCOL.md §10.6, §11.1, §11.2; Appendix A "정족수").
///
/// Rules: the body is a complete object of one of the three schemas (its own
/// errors, rebased; `SchemaMismatch` for another schema, `LengthExceedsMax`
/// for a longer body); one to [`MAX_QUORUM_SIGS`] signatures
/// (`InvariantViolation` for none, `CountExceedsMax` for more), strictly
/// ascending by trustee (`NotSorted`, `Duplicate`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuorumSigned<'a> {
    body_bytes: &'a [u8],
    kind: QuorumKind,
    sigs: [Option<QuorumSig<'a>>; MAX_QUORUM_SIGS],
    count: u8,
}

impl<'a> QuorumSigned<'a> {
    /// Builds the event.
    ///
    /// # Errors
    /// The body's error as [`QuorumSigned`] states it, or
    /// `InvariantViolation` at 0 if the signatures are none, too many or
    /// not strictly ascending.
    pub fn new(body_bytes: &'a [u8], sigs: &[QuorumSig<'a>]) -> Result<Self, Error> {
        let kind = classify(body_bytes)?;
        if sigs.is_empty()
            || sigs.len() > MAX_QUORUM_SIGS
            || !ascending_by(sigs, |s| s.trustee_id.as_bytes())
        {
            return Err(invalid(0));
        }
        let mut slots = [None; MAX_QUORUM_SIGS];
        for (slot, s) in slots.iter_mut().zip(sigs) {
            *slot = Some(*s);
        }
        Ok(Self {
            body_bytes,
            kind,
            sigs: slots,
            count: u8::try_from(sigs.len()).map_err(|_| invalid(0))?,
        })
    }

    /// The body object bytes (the signed message).
    #[must_use]
    pub const fn body_bytes(&self) -> &'a [u8] {
        self.body_bytes
    }

    /// Which body it carries.
    #[must_use]
    pub const fn kind(&self) -> QuorumKind {
        self.kind
    }

    /// The signature purpose.
    #[must_use]
    pub const fn purpose(&self) -> &'static [u8] {
        self.kind.purpose()
    }

    /// The tally scope, if it carries one.
    #[must_use]
    pub fn tally_scope(&self) -> Option<TallyScopeBody<'a>> {
        decode_object(SCHEMA_TALLY_SCOPE_BODY, SCHEMA_VERSION_1, self.body_bytes).ok()
    }

    /// The aggregate opening, if it carries one.
    #[must_use]
    pub fn aggregate_opening(&self) -> Option<AggregateOpeningBody<'a>> {
        decode_object(
            SCHEMA_AGGREGATE_OPENING_BODY,
            SCHEMA_VERSION_1,
            self.body_bytes,
        )
        .ok()
    }

    /// The receipt resolution, if it carries one.
    #[must_use]
    pub fn receipt_resolution(&self) -> Option<ReceiptResolutionBody<'a>> {
        decode_object(
            SCHEMA_RECEIPT_RESOLUTION_BODY,
            SCHEMA_VERSION_1,
            self.body_bytes,
        )
        .ok()
    }

    /// The signatures in ascending trustee order.
    pub fn sigs(&self) -> impl Iterator<Item = QuorumSig<'a>> + '_ {
        self.sigs
            .iter()
            .take(usize::from(self.count))
            .flatten()
            .copied()
    }

    /// The number of signatures.
    #[must_use]
    pub fn sig_count(&self) -> usize {
        usize::from(self.count)
    }
}

impl Encode for QuorumSigned<'_> {
    fn encoded_len(&self) -> usize {
        let sigs = self.sigs().fold(4usize, |acc, s| {
            acc.saturating_add(s.trustee_id.encoded_len())
                .saturating_add(HYBRID_SIG_LEN)
        });
        self.body_bytes.len().saturating_add(4).saturating_add(sigs)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_bytes(self.body_bytes, MAX_QUORUM_BODY_LEN)?;
        w.write_count(usize::from(self.count), MAX_QUORUM_SIGS)?;
        for s in self.sigs() {
            w.write_ident(&s.trustee_id.ident(), IDENT_MAX_STANDARD)?;
            w.write_array(s.sig)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for QuorumSigned<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let at = r.position();
        let body_bytes = r.read_bytes(MAX_QUORUM_BODY_LEN)?;
        let kind = classify(body_bytes).map_err(|inner| {
            let offset = at
                .checked_add(4)
                .and_then(|p| p.checked_add(inner.offset()))
                .unwrap_or(at);
            Error::new(inner.kind(), offset)
        })?;
        let count_at = r.position();
        let count = r.read_count(MAX_QUORUM_SIGS)?;
        if count == 0 {
            return Err(invalid(count_at));
        }
        let mut sigs = [None; MAX_QUORUM_SIGS];
        let mut previous: Option<&[u8]> = None;
        for slot in sigs.iter_mut().take(count) {
            let id_at = r.position();
            let trustee_id = TrusteeId::decode(r)?;
            Reader::check_ascending(previous, trustee_id.as_bytes(), id_at)?;
            previous = Some(trustee_id.as_bytes());
            *slot = Some(QuorumSig {
                trustee_id,
                sig: read_fixed::<HYBRID_SIG_LEN>(r)?,
            });
        }
        Ok(Self {
            body_bytes,
            kind,
            sigs,
            count: u8::try_from(count).map_err(|_| Error::new(Kind::CountExceedsMax, count_at))?,
        })
    }
}

// ---------------------------------------------------------------------------
// 0x0046 PaperCountReportBody

/// The paper votes of a report: one count per candidate, candidate 1 first,
/// one to [`MAX_CANDIDATES`] of them, each at most [`MAX_TALLY_COUNT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PaperVotes {
    items: [u64; MAX_CANDIDATES],
    count: u8,
}

impl PaperVotes {
    /// The votes `votes`. `None` if there are none, more than
    /// [`MAX_CANDIDATES`], or one is above [`MAX_TALLY_COUNT`].
    #[must_use]
    pub fn new(votes: &[u64]) -> Option<Self> {
        if votes.is_empty()
            || votes.len() > MAX_CANDIDATES
            || votes.iter().any(|v| *v > MAX_TALLY_COUNT)
        {
            return None;
        }
        let mut items = [0u64; MAX_CANDIDATES];
        for (slot, v) in items.iter_mut().zip(votes) {
            *slot = *v;
        }
        Some(Self {
            items,
            count: u8::try_from(votes.len()).ok()?,
        })
    }

    /// The votes, candidate 1 first.
    #[must_use]
    pub fn as_slice(&self) -> &[u64] {
        self.items
            .get(..usize::from(self.count))
            .unwrap_or_default()
    }

    /// The number of candidates.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.count)
    }

    /// Always `false`: a report has at least one candidate.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// The fields of a paper count report (PROTOCOL.md §11.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PaperCountParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The reporting unit.
    pub reporting_unit_id: ReportingUnitId<'a>,
    /// The ballot style.
    pub ballot_style_id: BallotStyleId<'a>,
    /// The paper votes per candidate.
    pub votes: PaperVotes,
    /// Ballots the count found invalid.
    pub invalid: u64,
    /// When.
    pub time_bucket: TimeBucket,
}

/// A paper count report body (schema `0x0046`). Rules: one to
/// [`MAX_CANDIDATES`] votes (`InvariantViolation` for none,
/// `CountExceedsMax` for more), every count at most [`MAX_TALLY_COUNT`]
/// (`ValueOutOfRange`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PaperCountReportBody<'a> {
    parts: PaperCountParts<'a>,
}

impl<'a> PaperCountReportBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// `ValueOutOfRange` at 0 if `invalid` is above [`MAX_TALLY_COUNT`].
    pub fn new(parts: &PaperCountParts<'a>) -> Result<Self, Error> {
        if parts.invalid > MAX_TALLY_COUNT {
            return Err(out_of_range(0));
        }
        Ok(Self { parts: *parts })
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &PaperCountParts<'a> {
        &self.parts
    }
}

impl Encode for PaperCountReportBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.reporting_unit_id.encoded_len())
            .saturating_add(p.ballot_style_id.encoded_len())
            .saturating_add(4)
            .saturating_add(p.votes.len().saturating_mul(8))
            .saturating_add(16)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.reporting_unit_id.encode(w)?;
        p.ballot_style_id.encode(w)?;
        w.write_count(p.votes.len(), MAX_CANDIDATES)?;
        for v in p.votes.as_slice() {
            w.write_u64(*v)?;
        }
        w.write_u64(p.invalid)?;
        p.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for PaperCountReportBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let reporting_unit_id = ReportingUnitId::decode(r)?;
        let ballot_style_id = BallotStyleId::decode(r)?;
        let count_at = r.position();
        let count = r.read_count(MAX_CANDIDATES)?;
        if count == 0 {
            return Err(invalid(count_at));
        }
        let mut items = [0u64; MAX_CANDIDATES];
        for slot in items.iter_mut().take(count) {
            *slot = read_tally_count(r)?;
        }
        let votes = PaperVotes {
            items,
            count: u8::try_from(count).map_err(|_| Error::new(Kind::CountExceedsMax, count_at))?,
        };
        Ok(Self {
            parts: PaperCountParts {
                election_id,
                reporting_unit_id,
                ballot_style_id,
                votes,
                invalid: read_tally_count(r)?,
                time_bucket: TimeBucket::decode(r)?,
            },
        })
    }
}
