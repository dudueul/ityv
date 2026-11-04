//! The paper audit (PROTOCOL.md §12; ENCODING.md §8.66–§8.72; ADR-0036),
//! version 1 of every schema here.
//!
//! * `AuditManifestFreezeBody` (`0x0048`): one ballot style's sample frame
//!   (the count and sorted-set root of its included records) and sampling
//!   rule (rule document, risk limit, the designated beacon round and the
//!   rounds of declared sample sizes and escalation thresholds), frozen
//!   before the seed. A [`crate::WitnessedEvent`] body, purpose
//!   `audit-freeze`.
//! * `AuditSeedBody` (`0x000D`): the dice transcript hash, the beacon
//!   round and value, the checkpoint hash and the seed they give
//!   (`SHA3-512("ityv:seed:v1" ‖ 0x00 ‖ dice ‖ beacon ‖ checkpoint)`, the
//!   verifier recomputes it). A `WitnessedEvent` body, purpose
//!   `audit-seed`.
//! * `SampleOpeningBody` (`0x0049`): the opened `(option_index, cast_id,
//!   r_0..r_{k−1})` of one sampled record. **Restricted**: never on the
//!   public ledger, held by the viewers PROTOCOL.md §12.3 names; secret,
//!   so neither `Clone` nor `Copy`, `Debug` shows only the public fields,
//!   and the opened values are zeroized on drop.
//! * `SampleOpeningRefBody` (`0x004A`): what the public ledger carries of
//!   an opening, the record and the object hash of its restricted body. A
//!   [`crate::QuorumSigned`] body, purpose `sample-opening`.
//! * `SampleComparisonBody` (`0x004B`): the auditors' comparison of one
//!   opened record with its paper, reason code 0–6 and the transfer mark.
//!   A `WitnessedEvent` body, purpose `sample-comparison`.
//! * `AuditFindingBody` (`0x004C`): a pattern of discrepancies of one
//!   device, by the hash of its finding document. A `WitnessedEvent` body,
//!   purpose `audit-finding`.
//! * `HandCountReportBody` (`0x004D`): a full hand count of one ballot
//!   style in one reporting unit after the sample escalated past its last
//!   round, the legal result (§12.4). The fields of a
//!   [`crate::PaperCountReportBody`]; a `WitnessedEvent` body, purpose
//!   `hand-count`.
//!
//! The per-record objects (opening, reference, comparison) carry no time
//! bucket: no record gets a time (VC-001).
//!
//! The encoding checks form only. That the frame is the ledger's, the seed
//! recomputes, the sample is the seed's, the opening reconstructs the
//! record and the signers are the roster's are the verifier's (PROTOCOL.md
//! §14 item 8).

use core::cmp::Ordering;
use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::codec::{Decode, Encode};
use crate::error::{Error, Kind};
use crate::primitives::{BallotStyleId, BoxId, ElectionId, Hash512, TimeBucket, Token192};
use crate::reader::Reader;
use crate::schema::challenge::MAX_OPTION_INDEX;
use crate::schema::genesis::read_nonzero_hash;
use crate::schema::tally::{
    MAX_TALLY_COUNT, PaperCountParts, decode_paper_count, encode_paper_count, paper_count_len,
};
use crate::schema::util::{MAX_CHUNKS, Scalars};
use crate::writer::Writer;

/// Purpose of the signatures on an audit manifest freeze.
pub const PURPOSE_AUDIT_FREEZE: &[u8] = b"audit-freeze";

/// Purpose of the signatures on an audit seed.
pub const PURPOSE_AUDIT_SEED: &[u8] = b"audit-seed";

/// Purpose of the trustees' signatures on a sample opening reference.
pub const PURPOSE_SAMPLE_OPENING: &[u8] = b"sample-opening";

/// Purpose of the signatures on a sample comparison.
pub const PURPOSE_SAMPLE_COMPARISON: &[u8] = b"sample-comparison";

/// Purpose of the signatures on an audit finding.
pub const PURPOSE_AUDIT_FINDING: &[u8] = b"audit-finding";

/// Purpose of the signatures on a hand count report.
pub const PURPOSE_HAND_COUNT: &[u8] = b"hand-count";

/// Most rounds of one sampling rule: the first sample and its expansions.
pub const MAX_AUDIT_ROUNDS: usize = 8;

/// The largest risk limit, in parts per million (below 100 %).
pub const MAX_RISK_LIMIT_PPM: u32 = 999_999;

fn out_of_range(at: usize) -> Error {
    Error::new(Kind::ValueOutOfRange, at)
}

fn invalid(at: usize) -> Error {
    Error::new(Kind::InvariantViolation, at)
}

fn zero_hash(at: usize) -> Error {
    Error::new(Kind::InvalidPreviousHash, at)
}

// ---------------------------------------------------------------------------
// Rounds

/// One round of a sampling rule: the cumulative sample size the round
/// compares and the most discrepancies (nonzero reason codes) among them
/// with which the audit concludes at that round (PROTOCOL.md §12.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditRound {
    /// The number of records the sample holds once this round is drawn,
    /// from the start (`1..=2^26 − 1`).
    pub sample_size: u64,
    /// The most nonzero reason codes among those records for which the
    /// audit concludes at this round; more escalate to the next round, or
    /// to a full hand count after the last.
    pub threshold: u32,
}

/// Why `round` cannot follow `previous` (`None` for the first round): the
/// size is 0 or above [`MAX_TALLY_COUNT`] (`ValueOutOfRange`), not above
/// the previous size (`Duplicate` if equal, `NotSorted` if below), or the
/// threshold is below the previous threshold (`InvariantViolation`).
fn round_error(previous: Option<AuditRound>, round: AuditRound) -> Option<Kind> {
    if round.sample_size == 0 || round.sample_size > MAX_TALLY_COUNT {
        return Some(Kind::ValueOutOfRange);
    }
    let p = previous?;
    match round.sample_size.cmp(&p.sample_size) {
        Ordering::Equal => Some(Kind::Duplicate),
        Ordering::Less => Some(Kind::NotSorted),
        Ordering::Greater => (round.threshold < p.threshold).then_some(Kind::InvariantViolation),
    }
}

/// The rounds of a sampling rule: one to [`MAX_AUDIT_ROUNDS`], sample
/// sizes strictly ascending, thresholds not descending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditRounds {
    items: [AuditRound; MAX_AUDIT_ROUNDS],
    count: u8,
}

const NO_ROUND: AuditRound = AuditRound {
    sample_size: 0,
    threshold: 0,
};

impl AuditRounds {
    /// The rounds `rounds`. `None` unless there are one to
    /// [`MAX_AUDIT_ROUNDS`] of them and each may follow the one before
    /// (sizes `1..=2^26 − 1` strictly ascending, thresholds not
    /// descending).
    #[must_use]
    pub fn new(rounds: &[AuditRound]) -> Option<Self> {
        if rounds.is_empty() || rounds.len() > MAX_AUDIT_ROUNDS {
            return None;
        }
        let mut items = [NO_ROUND; MAX_AUDIT_ROUNDS];
        let mut previous = None;
        for (slot, round) in items.iter_mut().zip(rounds) {
            if round_error(previous, *round).is_some() {
                return None;
            }
            *slot = *round;
            previous = Some(*round);
        }
        Some(Self {
            items,
            count: u8::try_from(rounds.len()).ok()?,
        })
    }

    /// The rounds, the first sample first.
    #[must_use]
    pub fn as_slice(&self) -> &[AuditRound] {
        self.items
            .get(..usize::from(self.count))
            .unwrap_or_default()
    }

    /// The number of rounds (one or more).
    #[must_use]
    pub const fn count(&self) -> u8 {
        self.count
    }

    /// Round `index` (0 is the first sample).
    #[must_use]
    pub fn get(&self, index: usize) -> Option<AuditRound> {
        self.as_slice().get(index).copied()
    }
}

impl Encode for AuditRounds {
    fn encoded_len(&self) -> usize {
        usize::from(self.count).saturating_mul(12).saturating_add(4)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_count(usize::from(self.count), MAX_AUDIT_ROUNDS)?;
        for round in self.as_slice() {
            w.write_u64(round.sample_size)?;
            w.write_u32(round.threshold)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for AuditRounds {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let count_at = r.position();
        let count = r.read_count(MAX_AUDIT_ROUNDS)?;
        if count == 0 {
            return Err(invalid(count_at));
        }
        let mut items = [NO_ROUND; MAX_AUDIT_ROUNDS];
        let mut previous = None;
        for slot in items.iter_mut().take(count) {
            let at = r.position();
            let round = AuditRound {
                sample_size: r.read_u64()?,
                threshold: r.read_u32()?,
            };
            if let Some(kind) = round_error(previous, round) {
                return Err(Error::new(kind, at));
            }
            *slot = round;
            previous = Some(round);
        }
        Ok(Self {
            items,
            count: u8::try_from(count).map_err(|_| Error::new(Kind::CountExceedsMax, count_at))?,
        })
    }
}

// ---------------------------------------------------------------------------
// 0x0048 AuditManifestFreezeBody

/// The fields of an audit manifest freeze (PROTOCOL.md §12.1): one ballot
/// style's sample frame and sampling rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditFreezeParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The ballot style audited.
    pub ballot_style_id: BallotStyleId<'a>,
    /// The number of records in the sample frame: the style's included
    /// records over every reporting unit.
    pub frame_count: u64,
    /// Their sorted-set root.
    pub frame_root: Hash512,
    /// The hash of the sampling rule document (the sample-size formula and
    /// the escalation rule) in the `policy_hash` bundle; not zero.
    pub rule_hash: Hash512,
    /// The risk limit, in parts per million (`1..=999_999`).
    pub risk_limit_ppm: u32,
    /// The hash of the document designating the public randomness beacon;
    /// not zero.
    pub beacon_source: Hash512,
    /// The beacon round whose value the seed takes.
    pub beacon_round: u64,
    /// The rounds: declared sample sizes and escalation thresholds.
    pub rounds: AuditRounds,
    /// When the freeze was recorded.
    pub time_bucket: TimeBucket,
}

/// An audit manifest freeze body (schema `0x0048`). Rules: `frame_count`
/// at most `2^26 − 1` (`ValueOutOfRange`), `rule_hash` and `beacon_source`
/// not zero (`InvalidPreviousHash`), `risk_limit_ppm` in `1..=999_999`
/// (`ValueOutOfRange`), the rounds as [`AuditRounds::new`] requires
/// (`InvariantViolation` for none, `CountExceedsMax` for more than eight,
/// `ValueOutOfRange`, `Duplicate`, `NotSorted`, `InvariantViolation`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditManifestFreezeBody<'a> {
    parts: AuditFreezeParts<'a>,
}

impl<'a> AuditManifestFreezeBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// At offset 0: `ValueOutOfRange` for a frame count or risk limit out
    /// of range, `InvalidPreviousHash` for a zero rule or beacon hash.
    pub fn new(parts: &AuditFreezeParts<'a>) -> Result<Self, Error> {
        if parts.frame_count > MAX_TALLY_COUNT
            || parts.risk_limit_ppm == 0
            || parts.risk_limit_ppm > MAX_RISK_LIMIT_PPM
        {
            return Err(out_of_range(0));
        }
        if parts.rule_hash.is_zero() || parts.beacon_source.is_zero() {
            return Err(zero_hash(0));
        }
        Ok(Self { parts: *parts })
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &AuditFreezeParts<'a> {
        &self.parts
    }
}

impl Encode for AuditManifestFreezeBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.ballot_style_id.encoded_len())
            .saturating_add(8 + 64 + 64 + 4 + 64 + 8)
            .saturating_add(p.rounds.encoded_len())
            .saturating_add(8)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.ballot_style_id.encode(w)?;
        w.write_u64(p.frame_count)?;
        p.frame_root.encode(w)?;
        p.rule_hash.encode(w)?;
        w.write_u32(p.risk_limit_ppm)?;
        p.beacon_source.encode(w)?;
        w.write_u64(p.beacon_round)?;
        p.rounds.encode(w)?;
        p.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for AuditManifestFreezeBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let ballot_style_id = BallotStyleId::decode(r)?;
        let count_at = r.position();
        let frame_count = r.read_u64()?;
        if frame_count > MAX_TALLY_COUNT {
            return Err(out_of_range(count_at));
        }
        let frame_root = Hash512::decode(r)?;
        let rule_hash = read_nonzero_hash(r)?;
        let risk_at = r.position();
        let risk_limit_ppm = r.read_u32()?;
        if risk_limit_ppm == 0 || risk_limit_ppm > MAX_RISK_LIMIT_PPM {
            return Err(out_of_range(risk_at));
        }
        Ok(Self {
            parts: AuditFreezeParts {
                election_id,
                ballot_style_id,
                frame_count,
                frame_root,
                rule_hash,
                risk_limit_ppm,
                beacon_source: read_nonzero_hash(r)?,
                beacon_round: r.read_u64()?,
                rounds: AuditRounds::decode(r)?,
                time_bucket: TimeBucket::decode(r)?,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// 0x000D AuditSeedBody

/// The fields of an audit seed (PROTOCOL.md §12.1): the three inputs and
/// the seed they give.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditSeedParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The hash of the public record of the dice ceremony; not zero.
    pub dice_hash: Hash512,
    /// The beacon round the freezes designated.
    pub beacon_round: u64,
    /// The beacon's published value for that round.
    pub beacon_value: Hash512,
    /// The object hash of the checkpoint body the seed takes; not zero.
    pub checkpoint_hash: Hash512,
    /// `SHA3-512("ityv:seed:v1" ‖ 0x00 ‖ dice_hash ‖ beacon_value ‖
    /// checkpoint_hash)`.
    pub seed: Hash512,
    /// When the seed was recorded.
    pub time_bucket: TimeBucket,
}

/// An audit seed body (schema `0x000D`). Rules: `dice_hash` and
/// `checkpoint_hash` not zero (`InvalidPreviousHash`). The seed itself is
/// recomputed by the verifier (VC-045), not by the decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditSeedBody<'a> {
    parts: AuditSeedParts<'a>,
}

impl<'a> AuditSeedBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// `InvalidPreviousHash` at 0 for a zero dice or checkpoint hash.
    pub fn new(parts: &AuditSeedParts<'a>) -> Result<Self, Error> {
        if parts.dice_hash.is_zero() || parts.checkpoint_hash.is_zero() {
            return Err(zero_hash(0));
        }
        Ok(Self { parts: *parts })
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &AuditSeedParts<'a> {
        &self.parts
    }
}

impl Encode for AuditSeedBody<'_> {
    fn encoded_len(&self) -> usize {
        self.parts
            .election_id
            .encoded_len()
            .saturating_add(64 + 8 + 64 + 64 + 64 + 8)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.dice_hash.encode(w)?;
        w.write_u64(p.beacon_round)?;
        p.beacon_value.encode(w)?;
        p.checkpoint_hash.encode(w)?;
        p.seed.encode(w)?;
        p.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for AuditSeedBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            parts: AuditSeedParts {
                election_id: ElectionId::decode(r)?,
                dice_hash: read_nonzero_hash(r)?,
                beacon_round: r.read_u64()?,
                beacon_value: Hash512::decode(r)?,
                checkpoint_hash: read_nonzero_hash(r)?,
                seed: Hash512::decode(r)?,
                time_bucket: TimeBucket::decode(r)?,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// 0x0049 SampleOpeningBody (restricted)

/// Unvalidated inputs for [`SampleOpeningBody::new`].
#[derive(Debug, Clone, Copy)]
pub struct SampleOpeningParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The ballot style of the record.
    pub ballot_style_id: BallotStyleId<'a>,
    /// The tracking code of the sampled record.
    pub record_hash: Hash512,
    /// The opened option index (`0..=63`).
    pub option_index: u16,
    /// The opened cast id.
    pub cast_id: Token192,
    /// The opened randomness `r_0..r_{k−1}` (one scalar per chunk).
    pub rand: &'a Scalars<MAX_CHUNKS>,
}

/// The restricted opening of one sampled record (PROTOCOL.md §12.3): it
/// reveals the choice, so it never reaches the public ledger. Neither
/// `Clone` nor `Copy`, `Debug` shows only the public fields, and the
/// option, the cast id and every scalar are zeroized on drop.
#[derive(PartialEq, Eq, Hash)]
pub struct SampleOpeningBody<'a> {
    election_id: ElectionId<'a>,
    ballot_style_id: BallotStyleId<'a>,
    record_hash: Hash512,
    option_index: u16,
    cast_id: Token192,
    rand: Scalars<MAX_CHUNKS>,
}

impl<'a> SampleOpeningBody<'a> {
    /// Builds a body. `None` if `option_index > 63` or `rand` is empty.
    #[must_use]
    pub fn new(parts: &SampleOpeningParts<'a>) -> Option<Self> {
        if parts.option_index > MAX_OPTION_INDEX || parts.rand.count() == 0 {
            return None;
        }
        Some(Self {
            election_id: parts.election_id,
            ballot_style_id: parts.ballot_style_id,
            record_hash: parts.record_hash,
            option_index: parts.option_index,
            cast_id: parts.cast_id,
            rand: parts.rand.duplicate(),
        })
    }

    /// The election.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.election_id
    }

    /// The ballot style of the record.
    #[must_use]
    pub const fn ballot_style_id(&self) -> BallotStyleId<'a> {
        self.ballot_style_id
    }

    /// The tracking code of the sampled record.
    #[must_use]
    pub const fn record_hash(&self) -> &Hash512 {
        &self.record_hash
    }

    /// The opened option index.
    #[must_use]
    pub const fn option_index(&self) -> u16 {
        self.option_index
    }

    /// The opened cast id.
    #[must_use]
    pub const fn cast_id(&self) -> &Token192 {
        &self.cast_id
    }

    /// The opened randomness.
    #[must_use]
    pub const fn rand(&self) -> &Scalars<MAX_CHUNKS> {
        &self.rand
    }
}

impl Zeroize for SampleOpeningBody<'_> {
    fn zeroize(&mut self) {
        self.option_index.zeroize();
        self.cast_id.0.zeroize();
        self.rand.zeroize();
    }
}

impl Drop for SampleOpeningBody<'_> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SampleOpeningBody<'_> {}

impl fmt::Debug for SampleOpeningBody<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SampleOpeningBody")
            .field("election_id", &self.election_id)
            .field("ballot_style_id", &self.ballot_style_id)
            .field("record_hash", &self.record_hash)
            .finish_non_exhaustive()
    }
}

impl Encode for SampleOpeningBody<'_> {
    fn encoded_len(&self) -> usize {
        self.election_id
            .encoded_len()
            .saturating_add(self.ballot_style_id.encoded_len())
            .saturating_add(64 + 2 + 24)
            .saturating_add(self.rand.encoded_len())
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        self.election_id.encode(w)?;
        self.ballot_style_id.encode(w)?;
        self.record_hash.encode(w)?;
        w.write_u16(self.option_index)?;
        self.cast_id.encode(w)?;
        self.rand.encode(w)
    }
}

impl<'a> Decode<'a> for SampleOpeningBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let ballot_style_id = BallotStyleId::decode(r)?;
        let record_hash = Hash512::decode(r)?;
        let index_at = r.position();
        let option_index = r.read_u16()?;
        if option_index > MAX_OPTION_INDEX {
            return Err(out_of_range(index_at));
        }
        // Decoded straight into the value, whose drop wipes it: an error
        // leaves no copy of what was read.
        let mut body = Self {
            election_id,
            ballot_style_id,
            record_hash,
            option_index,
            cast_id: Token192([0; 24]),
            rand: Scalars::empty(),
        };
        body.cast_id = Token192::decode(r)?;
        let rand_at = r.position();
        body.rand = Scalars::<MAX_CHUNKS>::decode(r)?;
        if body.rand.count() == 0 {
            return Err(out_of_range(rand_at));
        }
        Ok(body)
    }
}

// ---------------------------------------------------------------------------
// 0x004A SampleOpeningRefBody

/// The fields of a sample opening reference: what the public ledger
/// carries of a restricted opening (PROTOCOL.md §12.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SampleOpeningRefParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The ballot style of the record.
    pub ballot_style_id: BallotStyleId<'a>,
    /// The tracking code of the opened record.
    pub record_hash: Hash512,
    /// The object hash of the restricted `SampleOpeningBody`; not zero.
    pub opening_hash: Hash512,
}

/// A sample opening reference body (schema `0x004A`). Rule:
/// `opening_hash` not zero (`InvalidPreviousHash`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SampleOpeningRefBody<'a> {
    parts: SampleOpeningRefParts<'a>,
}

impl<'a> SampleOpeningRefBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// `InvalidPreviousHash` at 0 for a zero opening hash.
    pub fn new(parts: &SampleOpeningRefParts<'a>) -> Result<Self, Error> {
        if parts.opening_hash.is_zero() {
            return Err(zero_hash(0));
        }
        Ok(Self { parts: *parts })
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &SampleOpeningRefParts<'a> {
        &self.parts
    }
}

impl Encode for SampleOpeningRefBody<'_> {
    fn encoded_len(&self) -> usize {
        self.parts
            .election_id
            .encoded_len()
            .saturating_add(self.parts.ballot_style_id.encoded_len())
            .saturating_add(64 + 64)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.ballot_style_id.encode(w)?;
        p.record_hash.encode(w)?;
        p.opening_hash.encode(w)
    }
}

impl<'a> Decode<'a> for SampleOpeningRefBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            parts: SampleOpeningRefParts {
                election_id: ElectionId::decode(r)?,
                ballot_style_id: BallotStyleId::decode(r)?,
                record_hash: Hash512::decode(r)?,
                opening_hash: read_nonzero_hash(r)?,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// 0x004B SampleComparisonBody

/// The reason code of a sample comparison (PROTOCOL.md §12.3, ADR-0020).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ComparisonCode {
    /// 0: the record's candidate is the paper's, or the record is `BLANK`
    /// or `UNREADABLE` and the paper invalid.
    Match = 0,
    /// 1: the record is candidate `t`, the paper another candidate.
    OtherCandidate = 1,
    /// 2: the record is candidate `t`, the paper invalid.
    CandidateInvalid = 2,
    /// 3: the record is `UNREADABLE`, the paper valid.
    UnreadableValid = 3,
    /// 4: the record is `BLANK`, the paper valid.
    BlankValid = 4,
    /// 5: no ballot with the imprinted cast id was found.
    BallotMissing = 5,
    /// 6: the cast id is on more than one ballot, or the imprint differs
    /// from the record.
    ImprintMismatch = 6,
}

impl ComparisonCode {
    /// Every code in order.
    pub const ALL: [Self; 7] = [
        Self::Match,
        Self::OtherCandidate,
        Self::CandidateInvalid,
        Self::UnreadableValid,
        Self::BlankValid,
        Self::BallotMissing,
        Self::ImprintMismatch,
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
            0 => Some(Self::Match),
            1 => Some(Self::OtherCandidate),
            2 => Some(Self::CandidateInvalid),
            3 => Some(Self::UnreadableValid),
            4 => Some(Self::BlankValid),
            5 => Some(Self::BallotMissing),
            6 => Some(Self::ImprintMismatch),
            _ => None,
        }
    }
}

/// The fields of a sample comparison (PROTOCOL.md §12.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SampleComparisonParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The ballot style of the record.
    pub ballot_style_id: BallotStyleId<'a>,
    /// The tracking code of the compared record.
    pub record_hash: Hash512,
    /// The object hash of the restricted opening the auditors compared;
    /// not zero.
    pub opening_hash: Hash512,
    /// The device whose record it is (its box).
    pub device_id: BoxId<'a>,
    /// The reason code.
    pub code: ComparisonCode,
    /// Whether the paper carries ink transferred from another ballot or the
    /// privacy sleeve.
    pub transfer_mark: bool,
}

/// A sample comparison body (schema `0x004B`). Rules: `opening_hash` not
/// zero (`InvalidPreviousHash`), `code` 0–6 (`ValueOutOfRange`),
/// `transfer_mark` a `bool` (`InvalidBool`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SampleComparisonBody<'a> {
    parts: SampleComparisonParts<'a>,
}

impl<'a> SampleComparisonBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// `InvalidPreviousHash` at 0 for a zero opening hash.
    pub fn new(parts: &SampleComparisonParts<'a>) -> Result<Self, Error> {
        if parts.opening_hash.is_zero() {
            return Err(zero_hash(0));
        }
        Ok(Self { parts: *parts })
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &SampleComparisonParts<'a> {
        &self.parts
    }
}

impl Encode for SampleComparisonBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.ballot_style_id.encoded_len())
            .saturating_add(64 + 64)
            .saturating_add(p.device_id.encoded_len())
            .saturating_add(2)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.ballot_style_id.encode(w)?;
        p.record_hash.encode(w)?;
        p.opening_hash.encode(w)?;
        p.device_id.encode(w)?;
        w.write_u8(p.code.code())?;
        w.write_bool(p.transfer_mark)
    }
}

impl<'a> Decode<'a> for SampleComparisonBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let election_id = ElectionId::decode(r)?;
        let ballot_style_id = BallotStyleId::decode(r)?;
        let record_hash = Hash512::decode(r)?;
        let opening_hash = read_nonzero_hash(r)?;
        let device_id = BoxId::decode(r)?;
        let code_at = r.position();
        let code = ComparisonCode::from_code(r.read_u8()?).ok_or_else(|| out_of_range(code_at))?;
        Ok(Self {
            parts: SampleComparisonParts {
                election_id,
                ballot_style_id,
                record_hash,
                opening_hash,
                device_id,
                code,
                transfer_mark: r.read_bool()?,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// 0x004C AuditFindingBody

/// The fields of an audit finding (PROTOCOL.md §12.4): a pattern of
/// discrepancies of one device, recorded as evidence for the legal track.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditFindingParts<'a> {
    /// The election.
    pub election_id: ElectionId<'a>,
    /// The ballot style audited.
    pub ballot_style_id: BallotStyleId<'a>,
    /// The device (its box).
    pub device_id: BoxId<'a>,
    /// The hash of the finding document; not zero.
    pub finding_hash: Hash512,
    /// When the finding was recorded.
    pub time_bucket: TimeBucket,
}

/// An audit finding body (schema `0x004C`). Rule: `finding_hash` not zero
/// (`InvalidPreviousHash`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditFindingBody<'a> {
    parts: AuditFindingParts<'a>,
}

impl<'a> AuditFindingBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// `InvalidPreviousHash` at 0 for a zero finding hash.
    pub fn new(parts: &AuditFindingParts<'a>) -> Result<Self, Error> {
        if parts.finding_hash.is_zero() {
            return Err(zero_hash(0));
        }
        Ok(Self { parts: *parts })
    }

    /// The fields.
    #[must_use]
    pub const fn parts(&self) -> &AuditFindingParts<'a> {
        &self.parts
    }
}

impl Encode for AuditFindingBody<'_> {
    fn encoded_len(&self) -> usize {
        let p = &self.parts;
        p.election_id
            .encoded_len()
            .saturating_add(p.ballot_style_id.encoded_len())
            .saturating_add(p.device_id.encoded_len())
            .saturating_add(64 + 8)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        let p = &self.parts;
        p.election_id.encode(w)?;
        p.ballot_style_id.encode(w)?;
        p.device_id.encode(w)?;
        p.finding_hash.encode(w)?;
        p.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for AuditFindingBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            parts: AuditFindingParts {
                election_id: ElectionId::decode(r)?,
                ballot_style_id: BallotStyleId::decode(r)?,
                device_id: BoxId::decode(r)?,
                finding_hash: read_nonzero_hash(r)?,
                time_bucket: TimeBucket::decode(r)?,
            },
        })
    }
}

// ---------------------------------------------------------------------------
// 0x004D HandCountReportBody

/// A full hand count report body (schema `0x004D`): the paper votes per
/// candidate and the invalid ballots of one ballot style in one reporting
/// unit, counted by hand after the sample escalated past its last round
/// (PROTOCOL.md §12.4). The fields and rules of a
/// [`crate::PaperCountReportBody`] (one to 70 votes, every count at most
/// `2^26 − 1`); a separate schema, because the hand count is the legal
/// result and answers another question than the first paper count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HandCountReportBody<'a> {
    parts: PaperCountParts<'a>,
}

impl<'a> HandCountReportBody<'a> {
    /// Builds the body.
    ///
    /// # Errors
    /// `ValueOutOfRange` at 0 if `invalid` is above `2^26 − 1`.
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

impl Encode for HandCountReportBody<'_> {
    fn encoded_len(&self) -> usize {
        paper_count_len(&self.parts)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        encode_paper_count(&self.parts, w)
    }
}

impl<'a> Decode<'a> for HandCountReportBody<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            parts: decode_paper_count(r)?,
        })
    }
}
