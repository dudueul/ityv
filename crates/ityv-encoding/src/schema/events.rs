//! Bodies of the human-signed ledger events (PROTOCOL.md §7.2.1, §7.3,
//! §10, §13; ENCODING.md §8.33–§8.41), version 1.
//!
//! Each body is signed as a whole by the people the event names; the
//! signatures travel in a [`crate::WitnessedEvent`] (schema `0x0028`),
//! which embeds the body object bytes, so the signed message is exactly
//! the body bytes (ADR-0017 §2). Field order of every body is the order of
//! its `Parts` struct.
//!
//! | schema | body | purpose |
//! |---|---|---|
//! | `0x0008` | [`CustodyHandoffBody`] | `handoff` |
//! | `0x000E` | [`DisputeEventBody`] | `dispute` |
//! | `0x000F` | [`LegalDecisionRefBody`] | `legal-decision` |
//! | `0x0029` | [`BoxOpenedBody`] | `box-open` |
//! | `0x002A` | [`FallbackBody`] | `fallback` |
//! | `0x002B` | [`IssuanceCountBody`] | `issuance-count` |
//! | `0x002C` | [`ImprintAuditBody`] | `imprint-audit` |
//! | `0x002D` | [`SealChangeBody`] | `seal-change` |
//! | `0x002E` | [`LateBatchCloseBody`] | `late-batch-close` |
//!
//! Counts are not checked against each other here: an event whose counts
//! disagree is still recorded and judged by `ityv-state` (PROTOCOL.md
//! §10.2). The rules below are only the ones that make a body malformed.

use crate::codec::{Decode, Encode};
use crate::error::{Error, Kind};
use crate::primitives::{BoxId, Day, ElectionId, Hash512, OrgId, SignerId, StationId, TimeBucket};
use crate::reader::Reader;
use crate::schema::util::ModuleIds;
use crate::writer::Writer;

fn invalid(at: usize) -> Error {
    Error::new(Kind::InvariantViolation, at)
}

fn out_of_range(at: usize) -> Error {
    Error::new(Kind::ValueOutOfRange, at)
}

fn option_len<T: Encode>(value: Option<&T>) -> usize {
    value.map_or(1, |v| v.encoded_len().saturating_add(1))
}

fn write_option<T: Encode>(w: &mut Writer<'_>, value: Option<&T>) -> Result<(), Error> {
    match value {
        None => w.write_presence(false),
        Some(v) => {
            w.write_presence(true)?;
            v.encode(w)
        }
    }
}

fn read_option<'a, T: Decode<'a>>(r: &mut Reader<'a>) -> Result<Option<T>, Error> {
    if r.read_presence()? {
        Ok(Some(T::decode(r)?))
    } else {
        Ok(None)
    }
}

macro_rules! code_enum {
    (
        $(#[$meta:meta])*
        $name:ident { $( $(#[$vmeta:meta])* $variant:ident = $code:literal ),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(u8)]
        pub enum $name {
            $( $(#[$vmeta])* $variant = $code ),+
        }

        impl $name {
            /// Every value in code order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The wire code.
            #[must_use]
            pub const fn code(self) -> u8 {
                self as u8
            }

            /// Returns the value with wire code `code`, if defined.
            #[must_use]
            pub const fn from_code(code: u8) -> Option<Self> {
                match code {
                    $( $code => Some(Self::$variant), )+
                    _ => None,
                }
            }
        }
    };
}

fn read_code<T>(r: &mut Reader<'_>, from: impl Fn(u8) -> Option<T>) -> Result<T, Error> {
    let at = r.position();
    from(r.read_u8()?).ok_or_else(|| out_of_range(at))
}

// ---------------------------------------------------------------------------
// 0x0008 CustodyHandoffBody

/// The fields of a custody handoff (PROTOCOL.md §10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CustodyHandoffParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The box (or container) handed over.
    pub box_id: BoxId<'a>,
    /// Position in the chain, from 1.
    pub index: u32,
    /// The sender.
    pub from_signer: SignerId<'a>,
    /// The sender's organisation.
    pub from_org: OrgId<'a>,
    /// The receiver.
    pub to_signer: SignerId<'a>,
    /// The receiver's organisation.
    pub to_org: OrgId<'a>,
    /// Object hash of the previous handoff body; zero exactly for index 1.
    pub previous_handoff_hash: Hash512,
    /// Digest of the seal numbers on the box at handoff.
    pub seal_digest: Hash512,
    /// Ballots handed over (return envelopes for an out-of-district box).
    pub count: u64,
    /// When.
    pub time_bucket: TimeBucket,
}

/// A custody handoff body (schema `0x0008`).
///
/// Rules: `index ≥ 1` (`ValueOutOfRange`); `previous_handoff_hash` is zero
/// exactly when `index == 1` (`InvalidPreviousHash`); sender and receiver
/// organisations differ (`InvariantViolation`, VC-040).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CustodyHandoffBody<'a> {
    parts: CustodyHandoffParts<'a>,
}

impl<'a> CustodyHandoffBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// The rule violated, at offset 0.
    pub fn new(parts: &CustodyHandoffParts<'a>) -> Result<Self, Error> {
        Self::check(parts, [0; 3])?;
        Ok(Self { parts: *parts })
    }

    fn check(p: &CustodyHandoffParts<'_>, at: [usize; 3]) -> Result<(), Error> {
        let [index_at, previous_at, to_org_at] = at;
        if p.index == 0 {
            return Err(out_of_range(index_at));
        }
        if (p.index == 1) != p.previous_handoff_hash.is_zero() {
            return Err(Error::new(Kind::InvalidPreviousHash, previous_at));
        }
        if p.from_org.as_bytes() == p.to_org.as_bytes() {
            return Err(invalid(to_org_at));
        }
        Ok(())
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &CustodyHandoffParts<'a> {
        &self.parts
    }
}

impl Encode for CustodyHandoffBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.box_id.encoded_len())
            .saturating_add(4)
            .saturating_add(p.from_signer.encoded_len())
            .saturating_add(p.from_org.encoded_len())
            .saturating_add(p.to_signer.encoded_len())
            .saturating_add(p.to_org.encoded_len())
            .saturating_add(128)
            .saturating_add(16)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.box_id.encode(w)?;
        w.write_u32(p.index)?;
        p.from_signer.encode(w)?;
        p.from_org.encode(w)?;
        p.to_signer.encode(w)?;
        p.to_org.encode(w)?;
        p.previous_handoff_hash.encode(w)?;
        p.seal_digest.encode(w)?;
        w.write_u64(p.count)?;
        p.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for CustodyHandoffBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let box_id = BoxId::decode(r)?;
        let index_at = r.position();
        let index = r.read_u32()?;
        let from_signer = SignerId::decode(r)?;
        let from_org = OrgId::decode(r)?;
        let to_signer = SignerId::decode(r)?;
        let to_org_at = r.position();
        let to_org = OrgId::decode(r)?;
        let previous_at = r.position();
        let parts = CustodyHandoffParts {
            election_id,
            box_id,
            index,
            from_signer,
            from_org,
            to_signer,
            to_org,
            previous_handoff_hash: Hash512::decode(r)?,
            seal_digest: Hash512::decode(r)?,
            count: r.read_u64()?,
            time_bucket: TimeBucket::decode(r)?,
        };
        Self::check(&parts, [index_at, previous_at, to_org_at])?;
        Ok(Self { parts })
    }
}

// ---------------------------------------------------------------------------
// 0x000E DisputeEventBody

code_enum! {
    /// The dispute types of PROTOCOL.md §13.
    DisputeType {
        /// `INCLUSION_MISSING`: a slip's tracking code is not on the ledger.
        InclusionMissing = 1,
        /// `COUNT_MISMATCH`.
        CountMismatch = 2,
        /// `CUSTODY`.
        Custody = 3,
        /// `CHALLENGE_FAIL`.
        ChallengeFail = 4,
        /// `POSTAL`.
        Postal = 5,
        /// `OTHER`.
        Other = 6,
        /// `SPLIT_VIEW` (VC-065).
        SplitView = 7,
        /// `BUILD_MISMATCH` (VC-091).
        BuildMismatch = 8,
    }
}

code_enum! {
    /// What a dispute event records (PROTOCOL.md §13).
    DisputeAction {
        /// The filing; the dispute starts `OPEN`.
        Filed = 1,
        /// `OPEN → INVESTIGATING`.
        Investigating = 2,
        /// `→ RESOLVED_TECHNICAL`, with the result hash.
        ResolvedTechnical = 3,
        /// `→ REFERRED_LEGAL`, with the result hash.
        ReferredLegal = 4,
    }
}

/// The fields of a dispute event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DisputeEventParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// What this event records.
    pub action: DisputeAction,
    /// The dispute type (repeated from the filing in later events).
    pub dispute_type: DisputeType,
    /// The box concerned.
    pub box_id: Option<BoxId<'a>>,
    /// The record concerned; requires `box_id`.
    pub record_hash: Option<Hash512>,
    /// Hash of the evidence (the original is restricted).
    pub evidence_hash: Hash512,
    /// Object hash of the filing body; zero exactly for the filing.
    pub filing_hash: Hash512,
    /// Hash of the result document; nonzero exactly for
    /// `RESOLVED_TECHNICAL` and `REFERRED_LEGAL`.
    pub result_hash: Hash512,
    /// When.
    pub time_bucket: TimeBucket,
}

/// A dispute event body (schema `0x000E`).
///
/// Rules: codes in range (`ValueOutOfRange`); `filing_hash` zero exactly
/// for `FILED` (`InvalidPreviousHash`); `result_hash` nonzero exactly for
/// `RESOLVED_TECHNICAL` and `REFERRED_LEGAL`, and `record_hash` only with
/// `box_id` (`InvariantViolation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DisputeEventBody<'a> {
    parts: DisputeEventParts<'a>,
}

impl<'a> DisputeEventBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// The rule violated, at offset 0.
    pub fn new(parts: &DisputeEventParts<'a>) -> Result<Self, Error> {
        Self::check(parts, [0; 3])?;
        Ok(Self { parts: *parts })
    }

    fn check(p: &DisputeEventParts<'_>, at: [usize; 3]) -> Result<(), Error> {
        let [record_at, filing_at, result_at] = at;
        if p.record_hash.is_some() && p.box_id.is_none() {
            return Err(invalid(record_at));
        }
        let filed = matches!(p.action, DisputeAction::Filed);
        if filed != p.filing_hash.is_zero() {
            return Err(Error::new(Kind::InvalidPreviousHash, filing_at));
        }
        let resolved = matches!(
            p.action,
            DisputeAction::ResolvedTechnical | DisputeAction::ReferredLegal
        );
        if resolved == p.result_hash.is_zero() {
            return Err(invalid(result_at));
        }
        Ok(())
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &DisputeEventParts<'a> {
        &self.parts
    }
}

impl Encode for DisputeEventBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(2)
            .saturating_add(option_len(p.box_id.as_ref()))
            .saturating_add(option_len(p.record_hash.as_ref()))
            .saturating_add(192)
            .saturating_add(8)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        w.write_u8(p.action.code())?;
        w.write_u8(p.dispute_type.code())?;
        write_option(w, p.box_id.as_ref())?;
        write_option(w, p.record_hash.as_ref())?;
        p.evidence_hash.encode(w)?;
        p.filing_hash.encode(w)?;
        p.result_hash.encode(w)?;
        p.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for DisputeEventBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let action = read_code(r, DisputeAction::from_code)?;
        let dispute_type = read_code(r, DisputeType::from_code)?;
        let box_id = read_option(r)?;
        let record_at = r.position();
        let record_hash = read_option(r)?;
        let evidence_hash = Hash512::decode(r)?;
        let filing_at = r.position();
        let filing_hash = Hash512::decode(r)?;
        let result_at = r.position();
        let parts = DisputeEventParts {
            election_id,
            action,
            dispute_type,
            box_id,
            record_hash,
            evidence_hash,
            filing_hash,
            result_hash: Hash512::decode(r)?,
            time_bucket: TimeBucket::decode(r)?,
        };
        Self::check(&parts, [record_at, filing_at, result_at])?;
        Ok(Self { parts })
    }
}

// ---------------------------------------------------------------------------
// 0x000F LegalDecisionRefBody

code_enum! {
    /// The outcome of a legal decision on a dispute.
    LegalOutcome {
        /// The claim is upheld (인용).
        Upheld = 1,
        /// The claim is partly upheld (일부 인용).
        PartlyUpheld = 2,
        /// The claim is rejected on the merits (기각).
        Rejected = 3,
        /// The claim is dismissed without a ruling on the merits (각하).
        Dismissed = 4,
        /// Another outcome; the decision document says which.
        Other = 5,
    }
}

code_enum! {
    /// What a decision does to the record the dispute names in the tally
    /// scope (PROTOCOL.md §10.6 6항, §11.1).
    TallyEffect {
        /// No effect on the tally scope.
        NoEffect = 0,
        /// The record is counted.
        Include = 1,
        /// The record is excluded with reason `LEGAL_EXCLUDED`.
        Exclude = 2,
    }
}

/// The fields of a legal decision reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LegalDecisionRefParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The deciding authority.
    pub authority_id: OrgId<'a>,
    /// Hash of the decision document.
    pub decision_doc_hash: Hash512,
    /// Object hash of the filing body of the dispute decided (nonzero).
    pub dispute_hash: Hash512,
    /// The outcome.
    pub outcome: LegalOutcome,
    /// The effect on the tally scope.
    pub tally_effect: TallyEffect,
    /// The day of the decision.
    pub decided_day: Day,
}

/// A legal decision reference body (schema `0x000F`).
///
/// Rules: codes in range (`ValueOutOfRange`); `dispute_hash` nonzero
/// (`InvalidPreviousHash`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LegalDecisionRefBody<'a> {
    parts: LegalDecisionRefParts<'a>,
}

impl<'a> LegalDecisionRefBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// `InvalidPreviousHash` at 0 if `dispute_hash` is zero.
    pub fn new(parts: &LegalDecisionRefParts<'a>) -> Result<Self, Error> {
        if parts.dispute_hash.is_zero() {
            return Err(Error::new(Kind::InvalidPreviousHash, 0));
        }
        Ok(Self { parts: *parts })
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &LegalDecisionRefParts<'a> {
        &self.parts
    }
}

impl Encode for LegalDecisionRefBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.authority_id.encoded_len())
            .saturating_add(128)
            .saturating_add(2)
            .saturating_add(8)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.authority_id.encode(w)?;
        p.decision_doc_hash.encode(w)?;
        p.dispute_hash.encode(w)?;
        w.write_u8(p.outcome.code())?;
        w.write_u8(p.tally_effect.code())?;
        p.decided_day.encode(w)
    }
}

impl<'a> Decode<'a> for LegalDecisionRefBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let authority_id = OrgId::decode(r)?;
        let decision_doc_hash = Hash512::decode(r)?;
        let dispute_at = r.position();
        let dispute_hash = Hash512::decode(r)?;
        if dispute_hash.is_zero() {
            return Err(Error::new(Kind::InvalidPreviousHash, dispute_at));
        }
        Ok(Self {
            parts: LegalDecisionRefParts {
                election_id,
                authority_id,
                decision_doc_hash,
                dispute_hash,
                outcome: read_code(r, LegalOutcome::from_code)?,
                tally_effect: read_code(r, TallyEffect::from_code)?,
                decided_day: Day::decode(r)?,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// 0x0029 BoxOpenedBody

/// The fields of a box opening (PROTOCOL.md §10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoxOpenedParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The box.
    pub box_id: BoxId<'a>,
    /// The chamber modules attached (ascending; none before stage 2).
    pub modules: ModuleIds<'a>,
    /// Digest of the seal numbers found on the box.
    pub seal_digest: Hash512,
    /// Whether every seal number matched the provisioning record.
    pub seals_match: bool,
    /// What the box held when opened (0 when nothing is wrong).
    pub initial_count: u64,
    /// When.
    pub time_bucket: TimeBucket,
}

/// A box-opening body (schema `0x0029`). No rule beyond the field types:
/// a seal mismatch or a nonzero initial count is recorded and held, not
/// refused (PROTOCOL.md §10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BoxOpenedBody<'a> {
    parts: BoxOpenedParts<'a>,
}

impl<'a> BoxOpenedBody<'a> {
    /// Builds the body.
    #[must_use]
    pub const fn new(parts: &BoxOpenedParts<'a>) -> Self {
        Self { parts: *parts }
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &BoxOpenedParts<'a> {
        &self.parts
    }
}

impl Encode for BoxOpenedBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.box_id.encoded_len())
            .saturating_add(p.modules.encoded_len())
            .saturating_add(64)
            .saturating_add(1)
            .saturating_add(16)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.box_id.encode(w)?;
        p.modules.encode(w)?;
        p.seal_digest.encode(w)?;
        w.write_bool(p.seals_match)?;
        w.write_u64(p.initial_count)?;
        p.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for BoxOpenedBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            parts: BoxOpenedParts {
                election_id: ElectionId::decode(r)?,
                box_id: BoxId::decode(r)?,
                modules: ModuleIds::decode(r)?,
                seal_digest: Hash512::decode(r)?,
                seals_match: r.read_bool()?,
                initial_count: r.read_u64()?,
                time_bucket: TimeBucket::decode(r)?,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// 0x002A FallbackBody

code_enum! {
    /// Whether a fallback event starts or ends the fallback slot.
    FallbackKind {
        /// `FallbackDeclared`.
        Declared = 1,
        /// `FallbackEnded`.
        Ended = 2,
    }
}

code_enum! {
    /// Why the fallback slot was opened (PROTOCOL.md §7.3).
    FallbackReason {
        /// Only for `FallbackEnded`.
        NotApplicable = 0,
        /// The scanner failed and no spare was on site.
        ScannerFault = 1,
        /// Power failed.
        Power = 2,
        /// A chamber module failed.
        ModuleFault = 3,
        /// Another reason, in the observers' statement.
        Other = 4,
    }
}

/// A range of preprinted emergency marker serials (out-of-district boxes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MarkerRange {
    /// First serial.
    pub first: u64,
    /// Last serial (inclusive, `≥ first`).
    pub last: u64,
}

impl Encode for MarkerRange {
    fn encoded_len(&self) -> usize {
        16
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_u64(self.first)?;
        w.write_u64(self.last)
    }
}

impl<'a> Decode<'a> for MarkerRange {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let at = r.position();
        let first = r.read_u64()?;
        let last = r.read_u64()?;
        if last < first {
            return Err(invalid(at));
        }
        Ok(Self { first, last })
    }
}

/// The fields of a fallback event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FallbackParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The box.
    pub box_id: BoxId<'a>,
    /// Start or end.
    pub kind: FallbackKind,
    /// Why (`NotApplicable` exactly for `Ended`).
    pub reason: FallbackReason,
    /// Hash of the observers' statement.
    pub statement_hash: Hash512,
    /// Emergency marker serials used (out-of-district boxes only).
    pub markers: Option<MarkerRange>,
    /// When.
    pub time_bucket: TimeBucket,
}

/// A fallback event body (schema `0x002A`).
///
/// Rules: codes in range (`ValueOutOfRange`); `reason` is
/// `NotApplicable` exactly for `Ended`, and a marker range has
/// `first ≤ last` (`InvariantViolation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FallbackBody<'a> {
    parts: FallbackParts<'a>,
}

impl<'a> FallbackBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// `InvariantViolation` at 0 if a rule is violated.
    pub fn new(parts: &FallbackParts<'a>) -> Result<Self, Error> {
        Self::check(parts, 0)?;
        if let Some(m) = parts.markers
            && m.last < m.first
        {
            return Err(invalid(0));
        }
        Ok(Self { parts: *parts })
    }

    fn check(p: &FallbackParts<'_>, reason_at: usize) -> Result<(), Error> {
        let ended = matches!(p.kind, FallbackKind::Ended);
        if ended != matches!(p.reason, FallbackReason::NotApplicable) {
            return Err(invalid(reason_at));
        }
        Ok(())
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &FallbackParts<'a> {
        &self.parts
    }
}

impl Encode for FallbackBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.box_id.encoded_len())
            .saturating_add(2)
            .saturating_add(64)
            .saturating_add(option_len(p.markers.as_ref()))
            .saturating_add(8)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.box_id.encode(w)?;
        w.write_u8(p.kind.code())?;
        w.write_u8(p.reason.code())?;
        p.statement_hash.encode(w)?;
        write_option(w, p.markers.as_ref())?;
        p.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for FallbackBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let box_id = BoxId::decode(r)?;
        let kind = read_code(r, FallbackKind::from_code)?;
        let reason_at = r.position();
        let parts = FallbackParts {
            election_id,
            box_id,
            kind,
            reason: read_code(r, FallbackReason::from_code)?,
            statement_hash: Hash512::decode(r)?,
            markers: read_option(r)?,
            time_bucket: TimeBucket::decode(r)?,
        };
        Self::check(&parts, reason_at)?;
        Ok(Self { parts })
    }
}

// ---------------------------------------------------------------------------
// 0x002B IssuanceCountBody

/// Return-envelope accounting of an out-of-district station.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EnvelopeIssuance {
    /// Return envelopes issued.
    pub issued: u64,
    /// Empty return envelopes handed back.
    pub returned_empty: u64,
}

impl EnvelopeIssuance {
    /// Envelopes that should be in the box: `issued − returned_empty`, or
    /// `None` if more were returned than issued.
    #[must_use]
    pub const fn expected_in_box(&self) -> Option<u64> {
        self.issued.checked_sub(self.returned_empty)
    }
}

impl Encode for EnvelopeIssuance {
    fn encoded_len(&self) -> usize {
        16
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_u64(self.issued)?;
        w.write_u64(self.returned_empty)
    }
}

impl<'a> Decode<'a> for EnvelopeIssuance {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            issued: r.read_u64()?,
            returned_empty: r.read_u64()?,
        })
    }
}

/// The fields of a station's issuance count (PROTOCOL.md §10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IssuanceCountParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The station.
    pub station_id: StationId<'a>,
    /// Ballot paper received by the station: printed ballots, or blank
    /// sheets for a print-on-demand station.
    pub stock_received: u64,
    /// Ballots issued (re-issues included).
    pub issued: u64,
    /// Ballots the voter spoiled and had re-issued.
    pub voter_spoiled: u64,
    /// Ballots returned unused by voters.
    pub returned: u64,
    /// Stock never issued.
    pub unused: u64,
    /// Sheets wasted by the printer (jams, misprints), kept sealed.
    pub printer_waste: u64,
    /// Out-of-district station: return-envelope accounting.
    pub envelopes: Option<EnvelopeIssuance>,
    /// When.
    pub time_bucket: TimeBucket,
}

/// An issuance-count body (schema `0x002B`). No rule beyond the field
/// types: the identities are judged by `ityv-state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IssuanceCountBody<'a> {
    parts: IssuanceCountParts<'a>,
}

impl<'a> IssuanceCountBody<'a> {
    /// Builds the body.
    #[must_use]
    pub const fn new(parts: &IssuanceCountParts<'a>) -> Self {
        Self { parts: *parts }
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &IssuanceCountParts<'a> {
        &self.parts
    }
}

impl Encode for IssuanceCountBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.station_id.encoded_len())
            .saturating_add(48)
            .saturating_add(option_len(p.envelopes.as_ref()))
            .saturating_add(8)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.station_id.encode(w)?;
        w.write_u64(p.stock_received)?;
        w.write_u64(p.issued)?;
        w.write_u64(p.voter_spoiled)?;
        w.write_u64(p.returned)?;
        w.write_u64(p.unused)?;
        w.write_u64(p.printer_waste)?;
        write_option(w, p.envelopes.as_ref())?;
        p.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for IssuanceCountBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            parts: IssuanceCountParts {
                election_id: ElectionId::decode(r)?,
                station_id: StationId::decode(r)?,
                stock_received: r.read_u64()?,
                issued: r.read_u64()?,
                voter_spoiled: r.read_u64()?,
                returned: r.read_u64()?,
                unused: r.read_u64()?,
                printer_waste: r.read_u64()?,
                envelopes: read_option(r)?,
                time_bucket: TimeBucket::decode(r)?,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// 0x002C ImprintAuditBody

/// The fields of an imprint audit at the counting centre (PROTOCOL.md
/// §10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ImprintAuditParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The box.
    pub box_id: BoxId<'a>,
    /// Ballots without an imprint.
    pub unimprinted: u64,
    /// Repeated cast identifiers.
    pub duplicate_cast_ids: u64,
    /// When.
    pub time_bucket: TimeBucket,
}

/// An imprint-audit body (schema `0x002C`). No rule beyond the field
/// types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ImprintAuditBody<'a> {
    parts: ImprintAuditParts<'a>,
}

impl<'a> ImprintAuditBody<'a> {
    /// Builds the body.
    #[must_use]
    pub const fn new(parts: &ImprintAuditParts<'a>) -> Self {
        Self { parts: *parts }
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &ImprintAuditParts<'a> {
        &self.parts
    }
}

impl Encode for ImprintAuditBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.box_id.encoded_len())
            .saturating_add(24)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.box_id.encode(w)?;
        w.write_u64(p.unimprinted)?;
        w.write_u64(p.duplicate_cast_ids)?;
        p.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for ImprintAuditBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            parts: ImprintAuditParts {
                election_id: ElectionId::decode(r)?,
                box_id: BoxId::decode(r)?,
                unimprinted: r.read_u64()?,
                duplicate_cast_ids: r.read_u64()?,
                time_bucket: TimeBucket::decode(r)?,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// 0x002D SealChangeBody

code_enum! {
    /// Why the seals on a box changed (PROTOCOL.md §10.3).
    SealChangeReason {
        /// A seal was found broken and replaced; always `HOLD_REVIEW`.
        Broken = 1,
        /// Opened for an inspection in front of observers and resealed.
        Inspection = 2,
        /// The contents were moved to another container or merged.
        Container = 3,
        /// Opened on an order of a court or the election commission.
        Order = 4,
        /// Another reason, in the statement.
        Other = 5,
    }
}

/// The fields of a seal change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SealChangeParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The box.
    pub box_id: BoxId<'a>,
    /// Why.
    pub reason: SealChangeReason,
    /// The seal digest before the change.
    pub previous_seal_digest: Hash512,
    /// The seal digest after the change (differs from the previous one).
    pub new_seal_digest: Hash512,
    /// Hash of the signers' statement.
    pub statement_hash: Hash512,
    /// When.
    pub time_bucket: TimeBucket,
}

/// A seal-change body (schema `0x002D`).
///
/// Rules: reason code in range (`ValueOutOfRange`); the new digest differs
/// from the previous one (`InvariantViolation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SealChangeBody<'a> {
    parts: SealChangeParts<'a>,
}

impl<'a> SealChangeBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// `InvariantViolation` at 0 if the digests are equal.
    pub fn new(parts: &SealChangeParts<'a>) -> Result<Self, Error> {
        if parts.previous_seal_digest == parts.new_seal_digest {
            return Err(invalid(0));
        }
        Ok(Self { parts: *parts })
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &SealChangeParts<'a> {
        &self.parts
    }
}

impl Encode for SealChangeBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.box_id.encoded_len())
            .saturating_add(1)
            .saturating_add(192)
            .saturating_add(8)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.box_id.encode(w)?;
        w.write_u8(p.reason.code())?;
        p.previous_seal_digest.encode(w)?;
        p.new_seal_digest.encode(w)?;
        p.statement_hash.encode(w)?;
        p.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for SealChangeBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let box_id = BoxId::decode(r)?;
        let reason = read_code(r, SealChangeReason::from_code)?;
        let previous_seal_digest = Hash512::decode(r)?;
        let new_at = r.position();
        let new_seal_digest = Hash512::decode(r)?;
        if new_seal_digest == previous_seal_digest {
            return Err(invalid(new_at));
        }
        Ok(Self {
            parts: SealChangeParts {
                election_id,
                box_id,
                reason,
                previous_seal_digest,
                new_seal_digest,
                statement_hash: Hash512::decode(r)?,
                time_bucket: TimeBucket::decode(r)?,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// 0x002E LateBatchCloseBody

code_enum! {
    /// Why a batch was closed late (PROTOCOL.md §7.2.1).
    LateBatchReason {
        /// The unit stopped before closing the batch and was restarted.
        DeviceRestart = 1,
        /// Power came back.
        PowerRestored = 2,
        /// A chamber module was replaced.
        ModuleReplaced = 3,
        /// Another reason, in the witnesses' statement.
        Other = 4,
    }
}

/// The fields of a late batch close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LateBatchCloseParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The box.
    pub box_id: BoxId<'a>,
    /// Object hash of the `BatchAttestBody` it closes (nonzero).
    pub batch_body_hash: Hash512,
    /// Why.
    pub reason: LateBatchReason,
    /// When.
    pub time_bucket: TimeBucket,
}

/// A late-batch-close body (schema `0x002E`).
///
/// Rules: reason code in range (`ValueOutOfRange`); `batch_body_hash`
/// nonzero (`InvalidPreviousHash`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LateBatchCloseBody<'a> {
    parts: LateBatchCloseParts<'a>,
}

impl<'a> LateBatchCloseBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// `InvalidPreviousHash` at 0 if the batch hash is zero.
    pub fn new(parts: &LateBatchCloseParts<'a>) -> Result<Self, Error> {
        if parts.batch_body_hash.is_zero() {
            return Err(Error::new(Kind::InvalidPreviousHash, 0));
        }
        Ok(Self { parts: *parts })
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &LateBatchCloseParts<'a> {
        &self.parts
    }
}

impl Encode for LateBatchCloseBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.box_id.encoded_len())
            .saturating_add(64)
            .saturating_add(1)
            .saturating_add(8)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.box_id.encode(w)?;
        p.batch_body_hash.encode(w)?;
        w.write_u8(p.reason.code())?;
        p.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for LateBatchCloseBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let box_id = BoxId::decode(r)?;
        let hash_at = r.position();
        let batch_body_hash = Hash512::decode(r)?;
        if batch_body_hash.is_zero() {
            return Err(Error::new(Kind::InvalidPreviousHash, hash_at));
        }
        Ok(Self {
            parts: LateBatchCloseParts {
                election_id,
                box_id,
                batch_body_hash,
                reason: read_code(r, LateBatchReason::from_code)?,
                time_bucket: TimeBucket::decode(r)?,
            },
        })
    }
}
