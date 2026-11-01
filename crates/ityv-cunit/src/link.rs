//! Device-link and journal objects implemented by this crate
//! (ENCODING.md §8.19, ADR-0017 §3 and §7).
//!
//! * [`Interpretation`] (schema 0x0101): the only object the unit accepts
//!   from the interpretation unit.
//! * [`ModuleIssue`] (schema 0x0103): a chamber module's answer to an
//!   issue request; its private part never leaves the link.
//! * [`VisitEnd`] (schema 0x0104): the interpretation unit's notice that a
//!   voter's visit has ended (ADR-0021).
//! * [`AttestChallenge`] (schema 0x0105): an observer's signed challenge,
//!   read from a check card or handed over by an observer token
//!   (ADR-0023).
//! * [`JournalEntry`] (schema 0x0014): one link of the sealed journal.
//!
//! Decoders apply the fixed-width rules of ENCODING.md and report the
//! first violation with its absolute offset, like every other schema.

use ityv_crypto::Sha3Hasher;
use ityv_encoding::{
    BallotStyleId, Decode, ED25519_SIG_LEN, ElectionId, Encode, Error as EncodingError, ErrorKind,
    Hash512, MAX_CHUNKS, ModuleCounters, ModuleId, NONCE_LEN, ObserverId, Reader, Scalar32,
    SchemaId, TAG_LEN, TimeBucket, Token192, Writer,
};
use zeroize::Zeroize;

/// Schema identifier of [`Interpretation`].
pub const SCHEMA_INTERPRETATION: SchemaId = SchemaId::new(0x0101);
/// Schema identifier of [`ModuleIssue`].
pub const SCHEMA_MODULE_ISSUE: SchemaId = SchemaId::new(0x0103);
/// Schema identifier of [`VisitEnd`].
pub const SCHEMA_VISIT_END: SchemaId = SchemaId::new(0x0104);
/// Schema identifier of [`AttestChallenge`].
pub const SCHEMA_ATTEST_CHALLENGE: SchemaId = SchemaId::new(0x0105);
/// Schema identifier of [`JournalEntry`].
pub const SCHEMA_JOURNAL_ENTRY: SchemaId = SchemaId::new(0x0014);

/// Maximum members of one chamber (tags per issue).
pub const MAX_TAGS: usize = ityv_crypto::MAX_MEMBERS;
/// Largest chamber code a module may report: 1–4 P1–P4, 5 J, 6 A, 7 C
/// (N, code 8, has no module).
pub const MAX_MODULE_CHAMBER_CODE: u8 = 7;
/// Maximum ballots in one visit (ADR-0021): one per slip tracking code.
pub const MAX_VISIT_BALLOTS: u8 = 8;
const _: () = assert!(MAX_VISIT_BALLOTS == 8 && ityv_encoding::MAX_TRACKING_CODES == 8);

/// Maximum encoded length of a `ModuleIssue` object, header included:
/// 16 + 68 + 1 + 8 + (4 + 8·32) + 24 + 25 + (4 + 8·16).
pub const MAX_MODULE_ISSUE_LEN: usize = 16 + 68 + 1 + 8 + 260 + 24 + 25 + 132;
/// Maximum encoded length of an `Interpretation` object, header included.
pub const MAX_INTERPRETATION_LEN: usize = 16 + 68 + 68 + 2;
/// Maximum encoded length of a `VisitEnd` object, header included.
pub const MAX_VISIT_END_LEN: usize = 16 + 68 + 1;
/// Maximum encoded length of an `AttestChallenge` object, header included.
pub const MAX_ATTEST_CHALLENGE_LEN: usize = 16 + 68 + 68 + 32 + 64;
/// Maximum encoded length of a `JournalEntry` object, header included:
/// 16 + 64 + 1 + 64 + 64 + (4 + 7·76) + 8.
pub const MAX_JOURNAL_ENTRY_LEN: usize = 16 + 64 + 1 + 64 + 64 + 536 + 8;

/// `Interpretation` (schema 0x0101): what the interpretation unit sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Interpretation<'a> {
    election_id: ElectionId<'a>,
    ballot_style_id: BallotStyleId<'a>,
    option_index: u16,
}

impl<'a> Interpretation<'a> {
    /// Builds an interpretation. The option bound against the ballot style
    /// is checked when the unit accepts it, not here.
    #[must_use]
    pub const fn new(
        election_id: ElectionId<'a>,
        ballot_style_id: BallotStyleId<'a>,
        option_index: u16,
    ) -> Self {
        Self {
            election_id,
            ballot_style_id,
            option_index,
        }
    }

    /// The election.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.election_id
    }

    /// The ballot style.
    #[must_use]
    pub const fn ballot_style_id(&self) -> BallotStyleId<'a> {
        self.ballot_style_id
    }

    /// The option index `t` (0 BLANK, `1..=m` candidates, `m+1` UNREADABLE).
    #[must_use]
    pub const fn option_index(&self) -> u16 {
        self.option_index
    }
}

impl Encode for Interpretation<'_> {
    fn encoded_len(&self) -> usize {
        self.election_id
            .encoded_len()
            .saturating_add(self.ballot_style_id.encoded_len())
            .saturating_add(2)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        self.election_id.encode(w)?;
        self.ballot_style_id.encode(w)?;
        w.write_u16(self.option_index)
    }
}

impl<'a> Decode<'a> for Interpretation<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        Ok(Self {
            election_id: ElectionId::decode(r)?,
            ballot_style_id: BallotStyleId::decode(r)?,
            option_index: r.read_u16()?,
        })
    }
}

/// `VisitEnd` (schema 0x0104): the interpretation unit sends it after the
/// last ballot of a visit (ENCODING.md §8.19, ADR-0021). `ballot_count`
/// is the number of `Interpretation` objects it sent since the previous
/// `VisitEnd`, 1 to [`MAX_VISIT_BALLOTS`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VisitEnd<'a> {
    election_id: ElectionId<'a>,
    ballot_count: u8,
}

impl<'a> VisitEnd<'a> {
    /// Builds a notice; `None` unless `1 <= ballot_count <= 8`.
    #[must_use]
    pub const fn new(election_id: ElectionId<'a>, ballot_count: u8) -> Option<Self> {
        if ballot_count == 0 || ballot_count > MAX_VISIT_BALLOTS {
            return None;
        }
        Some(Self {
            election_id,
            ballot_count,
        })
    }

    /// The election.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.election_id
    }

    /// The number of ballots the interpretation unit sent in the visit.
    #[must_use]
    pub const fn ballot_count(&self) -> u8 {
        self.ballot_count
    }
}

impl Encode for VisitEnd<'_> {
    fn encoded_len(&self) -> usize {
        self.election_id.encoded_len().saturating_add(1)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        self.election_id.encode(w)?;
        w.write_u8(self.ballot_count)
    }
}

impl<'a> Decode<'a> for VisitEnd<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        let election_id = ElectionId::decode(r)?;
        let count_at = r.position();
        Self::new(election_id, r.read_u8()?)
            .ok_or_else(|| EncodingError::new(ErrorKind::ValueOutOfRange, count_at))
    }
}

/// `AttestChallenge` (schema 0x0105): an observer's challenge for a field
/// attestation (ENCODING.md §8.19, PROTOCOL.md §7.9). The check card's QR
/// or the observer token supplies all four fields; `challenge_sig` is the
/// observer's Ed25519 signature (purpose `attest-challenge`) over the
/// field encodings of `election_id ‖ station_id ‖ observer_id ‖ nonce`,
/// with the station taken from the unit's own configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AttestChallenge<'a> {
    election_id: ElectionId<'a>,
    observer_id: ObserverId<'a>,
    nonce: &'a [u8; NONCE_LEN],
    challenge_sig: &'a [u8; ED25519_SIG_LEN],
}

impl<'a> AttestChallenge<'a> {
    /// Builds a challenge.
    #[must_use]
    pub const fn new(
        election_id: ElectionId<'a>,
        observer_id: ObserverId<'a>,
        nonce: &'a [u8; NONCE_LEN],
        challenge_sig: &'a [u8; ED25519_SIG_LEN],
    ) -> Self {
        Self {
            election_id,
            observer_id,
            nonce,
            challenge_sig,
        }
    }

    /// The election.
    #[must_use]
    pub const fn election_id(&self) -> ElectionId<'a> {
        self.election_id
    }

    /// The observer.
    #[must_use]
    pub const fn observer_id(&self) -> ObserverId<'a> {
        self.observer_id
    }

    /// The observer's random value.
    #[must_use]
    pub const fn nonce(&self) -> &'a [u8; NONCE_LEN] {
        self.nonce
    }

    /// The observer's signature.
    #[must_use]
    pub const fn challenge_sig(&self) -> &'a [u8; ED25519_SIG_LEN] {
        self.challenge_sig
    }
}

impl Encode for AttestChallenge<'_> {
    fn encoded_len(&self) -> usize {
        self.election_id
            .encoded_len()
            .saturating_add(self.observer_id.encoded_len())
            .saturating_add(NONCE_LEN)
            .saturating_add(ED25519_SIG_LEN)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        self.election_id.encode(w)?;
        self.observer_id.encode(w)?;
        w.write_array(self.nonce)?;
        w.write_array(self.challenge_sig)
    }
}

impl<'a> Decode<'a> for AttestChallenge<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        let election_id = ElectionId::decode(r)?;
        let observer_id = ObserverId::decode(r)?;
        let nonce = read_borrowed::<NONCE_LEN>(r)?;
        let challenge_sig = read_borrowed::<ED25519_SIG_LEN>(r)?;
        Ok(Self::new(election_id, observer_id, nonce, challenge_sig))
    }
}

/// Reads exactly `N` bytes and borrows them as a fixed array.
fn read_borrowed<'a, const N: usize>(r: &mut Reader<'a>) -> Result<&'a [u8; N], EncodingError> {
    let at = r.position();
    r.take(N)?
        .try_into()
        .map_err(|_| EncodingError::new(ErrorKind::UnexpectedEnd, at))
}

/// `ModuleIssue` (schema 0x0103): a module's per-ballot contribution. The
/// private part (`rand`, `cid`, `lab`, `tags`) is zeroized on drop; the
/// value is neither `Clone` nor `Copy`.
pub struct ModuleIssue<'a> {
    module_id: ModuleId<'a>,
    chamber: u8,
    counter: u64,
    rand: [Scalar32; MAX_CHUNKS],
    rand_count: u8,
    cid: Token192,
    lab: Option<Token192>,
    tags: [[u8; TAG_LEN]; MAX_TAGS],
    tag_count: u8,
}

/// Unvalidated inputs for [`ModuleIssue::new`]. Its `Debug` output shows
/// only the public fields.
pub struct ModuleIssueParts<'a> {
    /// The module.
    pub module_id: ModuleId<'a>,
    /// The chamber code served (`1..=5`).
    pub chamber: u8,
    /// The module counter (`>= 1`).
    pub counter: u64,
    /// The randomness contributions, one per chunk (`1..=8`).
    pub rand: &'a [Scalar32],
    /// The cast-id contribution.
    pub cid: Token192,
    /// The envelope-label contribution (absentee profile only).
    pub lab: Option<Token192>,
    /// The one-time MAC tags, one per chamber member (`<= 8`).
    pub tags: &'a [[u8; TAG_LEN]],
}

impl core::fmt::Debug for ModuleIssueParts<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ModuleIssueParts")
            .field("module_id", &self.module_id)
            .field("chamber", &self.chamber)
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl<'a> ModuleIssue<'a> {
    /// Builds an issue. Returns `None` if the chamber code is not `1..=5`,
    /// the counter is zero, `rand` is empty or longer than eight, or
    /// `tags` is longer than eight.
    #[must_use]
    pub fn new(parts: &ModuleIssueParts<'a>) -> Option<Self> {
        if parts.chamber == 0
            || parts.chamber > MAX_MODULE_CHAMBER_CODE
            || parts.counter == 0
            || parts.rand.is_empty()
            || parts.rand.len() > MAX_CHUNKS
            || parts.tags.len() > MAX_TAGS
        {
            return None;
        }
        let mut rand = [Scalar32([0; 32]); MAX_CHUNKS];
        for (slot, value) in rand.iter_mut().zip(parts.rand) {
            *slot = *value;
        }
        let mut tags = [[0u8; TAG_LEN]; MAX_TAGS];
        for (slot, value) in tags.iter_mut().zip(parts.tags) {
            *slot = *value;
        }
        Some(Self {
            module_id: parts.module_id,
            chamber: parts.chamber,
            counter: parts.counter,
            rand,
            rand_count: u8::try_from(parts.rand.len()).ok()?,
            cid: parts.cid,
            lab: parts.lab,
            tags,
            tag_count: u8::try_from(parts.tags.len()).ok()?,
        })
    }

    /// The module.
    #[must_use]
    pub const fn module_id(&self) -> ModuleId<'a> {
        self.module_id
    }

    /// The chamber code.
    #[must_use]
    pub const fn chamber(&self) -> u8 {
        self.chamber
    }

    /// The counter.
    #[must_use]
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// The randomness contributions.
    #[must_use]
    pub fn rand(&self) -> &[Scalar32] {
        self.rand.get(..usize::from(self.rand_count)).unwrap_or(&[])
    }

    /// The cast-id contribution.
    #[must_use]
    pub const fn cid(&self) -> &Token192 {
        &self.cid
    }

    /// The envelope-label contribution.
    #[must_use]
    pub const fn lab(&self) -> Option<&Token192> {
        self.lab.as_ref()
    }

    /// The member tags.
    #[must_use]
    pub fn tags(&self) -> &[[u8; TAG_LEN]] {
        self.tags.get(..usize::from(self.tag_count)).unwrap_or(&[])
    }
}

impl ModuleIssue<'_> {
    /// Overwrites the private part with zeros.
    fn wipe(&mut self) {
        for scalar in &mut self.rand {
            scalar.0.zeroize();
        }
        self.cid.0.zeroize();
        if let Some(lab) = self.lab.as_mut() {
            lab.0.zeroize();
        }
        for tag in &mut self.tags {
            tag.zeroize();
        }
    }
}

impl Drop for ModuleIssue<'_> {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl core::fmt::Debug for ModuleIssue<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ModuleIssue")
            .field("module_id", &self.module_id)
            .field("chamber", &self.chamber)
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl Encode for ModuleIssue<'_> {
    fn encoded_len(&self) -> usize {
        let rand = usize::from(self.rand_count)
            .saturating_mul(32)
            .saturating_add(4);
        let tags = usize::from(self.tag_count)
            .saturating_mul(TAG_LEN)
            .saturating_add(4);
        self.module_id
            .encoded_len()
            .saturating_add(1)
            .saturating_add(8)
            .saturating_add(rand)
            .saturating_add(24)
            .saturating_add(self.lab.encoded_len())
            .saturating_add(tags)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        self.module_id.encode(w)?;
        w.write_u8(self.chamber)?;
        w.write_u64(self.counter)?;
        w.write_count(usize::from(self.rand_count), MAX_CHUNKS)?;
        for scalar in self.rand() {
            scalar.encode(w)?;
        }
        self.cid.encode(w)?;
        self.lab.encode(w)?;
        w.write_count(usize::from(self.tag_count), MAX_TAGS)?;
        for tag in self.tags() {
            w.write_array(tag)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for ModuleIssue<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        let module_id = ModuleId::decode(r)?;
        let chamber_at = r.position();
        let chamber = r.read_u8()?;
        if chamber == 0 || chamber > MAX_MODULE_CHAMBER_CODE {
            return Err(EncodingError::new(ErrorKind::ValueOutOfRange, chamber_at));
        }
        let counter_at = r.position();
        let counter = r.read_u64()?;
        if counter == 0 {
            return Err(EncodingError::new(ErrorKind::ValueOutOfRange, counter_at));
        }
        // The private part is decoded straight into the value, whose drop
        // wipes it: a decoding error after this point leaves no copy of the
        // part already read.
        let mut issue = Self {
            module_id,
            chamber,
            counter,
            rand: [Scalar32([0; 32]); MAX_CHUNKS],
            rand_count: 0,
            cid: Token192([0; 24]),
            lab: None,
            tags: [[0u8; TAG_LEN]; MAX_TAGS],
            tag_count: 0,
        };
        let rand_at = r.position();
        let rand_count = r.read_count(MAX_CHUNKS)?;
        if rand_count == 0 {
            return Err(EncodingError::new(ErrorKind::ValueOutOfRange, rand_at));
        }
        for slot in issue.rand.iter_mut().take(rand_count) {
            *slot = Scalar32::decode(r)?;
        }
        issue.rand_count = u8::try_from(rand_count)
            .map_err(|_| EncodingError::new(ErrorKind::CountExceedsMax, rand_at))?;
        issue.cid = Token192::decode(r)?;
        issue.lab = Option::<Token192>::decode(r)?;
        let tags_at = r.position();
        let tag_count = r.read_count(MAX_TAGS)?;
        for slot in issue.tags.iter_mut().take(tag_count) {
            *slot = r.read_array::<TAG_LEN>()?;
        }
        issue.tag_count = u8::try_from(tag_count)
            .map_err(|_| EncodingError::new(ErrorKind::CountExceedsMax, tags_at))?;
        Ok(issue)
    }
}

/// The kind of a journal entry (ADR-0017 §7, ADR-0021).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum JournalKind {
    /// A visit position decided cast: the record, followed in the stream
    /// by its share package. Its counters repeat the position's bound
    /// entry (kind 9).
    Record = 1,
    /// A visit position decided checked (spoiled by a pre-cast
    /// challenge). Its counters repeat the position's bound entry.
    Challenge = 2,
    /// A ballot quarantined: naming a bound record (repeating its
    /// counters), or without record (hash zero) consuming the counters of
    /// a ballot stopped before it was bound.
    Quarantine = 3,
    /// A batch closed.
    BatchClose = 4,
    /// The box closed.
    BoxClose = 5,
    /// A record's imprint completed; the paper may drop into the box
    /// (PROTOCOL.md §7.3 step 8).
    Imprinted = 6,
    /// A visit's cast or check decision, after every position's record
    /// signatures (ADR-0021, VC-068). `record_hash` holds the visit
    /// decision digest; no share package and no counters.
    VisitDecision = 7,
    /// An out-of-district visit's label sticker printed. `record_hash`
    /// holds the visit decision digest; the label value itself is not
    /// journaled; no share package and no counters.
    LabelPrinted = 8,
    /// A visit position bound before the decision (PROTOCOL.md §7.3 step
    /// 5): its record hash and the counters it consumed, durable before
    /// the position counts as bound, so a resume knows every counter the
    /// visit used. No share package.
    Bound = 9,
}

impl JournalKind {
    /// The wire code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// The kind with wire code `code`, if defined.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Record),
            2 => Some(Self::Challenge),
            3 => Some(Self::Quarantine),
            4 => Some(Self::BatchClose),
            5 => Some(Self::BoxClose),
            6 => Some(Self::Imprinted),
            7 => Some(Self::VisitDecision),
            8 => Some(Self::LabelPrinted),
            9 => Some(Self::Bound),
            _ => None,
        }
    }
}

/// Label of the visit decision digest (ENCODING.md §8.19).
pub const LABEL_VISIT: &[u8] = b"ityv:visit:v1";

/// The visit decision digest a kind-7 entry carries (ENCODING.md §8.19):
/// `SHA3-512("ityv:visit:v1" ‖ 0x00 ‖ n: u8 ‖ (kind_i: u8 ‖
/// record_hash_i)…)` over the visit's `n` position entries in position
/// order. A kind-8 entry repeats it.
#[must_use]
pub fn visit_digest(positions: &[(u8, Hash512)]) -> Hash512 {
    let mut hasher = Sha3Hasher::new();
    hasher.absorb(LABEL_VISIT);
    hasher.absorb(&[0x00]);
    hasher.absorb(&[u8::try_from(positions.len()).unwrap_or(u8::MAX)]);
    for (kind, record_hash) in positions {
        hasher.absorb(&[*kind]);
        hasher.absorb(&record_hash.0);
    }
    Hash512(hasher.finish())
}

/// `JournalEntry` (schema 0x0014): one link of the sealed journal chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JournalEntry<'a> {
    prev_head: Hash512,
    kind: JournalKind,
    record_hash: Hash512,
    share_package_hash: Hash512,
    module_counters: ModuleCounters<'a>,
    time_bucket: TimeBucket,
}

impl<'a> JournalEntry<'a> {
    /// Builds an entry. `record_hash` and `share_package_hash` are zero for
    /// kinds that have none.
    #[must_use]
    pub const fn new(
        prev_head: Hash512,
        kind: JournalKind,
        record_hash: Hash512,
        share_package_hash: Hash512,
        module_counters: ModuleCounters<'a>,
        time_bucket: TimeBucket,
    ) -> Self {
        Self {
            prev_head,
            kind,
            record_hash,
            share_package_hash,
            module_counters,
            time_bucket,
        }
    }

    /// The previous head (zero for the first entry).
    #[must_use]
    pub const fn prev_head(&self) -> &Hash512 {
        &self.prev_head
    }

    /// The kind.
    #[must_use]
    pub const fn kind(&self) -> JournalKind {
        self.kind
    }

    /// The record hash (tracking code), or zero.
    #[must_use]
    pub const fn record_hash(&self) -> &Hash512 {
        &self.record_hash
    }

    /// The share package hash, or zero.
    #[must_use]
    pub const fn share_package_hash(&self) -> &Hash512 {
        &self.share_package_hash
    }

    /// The module counters consumed.
    #[must_use]
    pub const fn module_counters(&self) -> &ModuleCounters<'a> {
        &self.module_counters
    }

    /// The time bucket.
    #[must_use]
    pub const fn time_bucket(&self) -> TimeBucket {
        self.time_bucket
    }
}

impl Encode for JournalEntry<'_> {
    fn encoded_len(&self) -> usize {
        64usize
            .saturating_add(1)
            .saturating_add(64)
            .saturating_add(64)
            .saturating_add(self.module_counters.encoded_len())
            .saturating_add(8)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        self.prev_head.encode(w)?;
        w.write_u8(self.kind.code())?;
        self.record_hash.encode(w)?;
        self.share_package_hash.encode(w)?;
        self.module_counters.encode(w)?;
        self.time_bucket.encode(w)
    }
}

impl<'a> Decode<'a> for JournalEntry<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        let prev_head = Hash512::decode(r)?;
        let kind_at = r.position();
        let kind = JournalKind::from_code(r.read_u8()?)
            .ok_or_else(|| EncodingError::new(ErrorKind::ValueOutOfRange, kind_at))?;
        Ok(Self {
            prev_head,
            kind,
            record_hash: Hash512::decode(r)?,
            share_package_hash: Hash512::decode(r)?,
            module_counters: ModuleCounters::decode(r)?,
            time_bucket: TimeBucket::decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_clears_the_private_part() {
        let rand = [Scalar32([1; 32]); MAX_CHUNKS];
        let tags = [[2u8; TAG_LEN]; MAX_TAGS];
        let mut issue = ModuleIssue::new(&ModuleIssueParts {
            module_id: ModuleId::new(b"mod-p1").expect("a valid identifier"),
            chamber: 1,
            counter: 3,
            rand: &rand,
            cid: Token192([3; 24]),
            lab: Some(Token192([4; 24])),
            tags: &tags,
        })
        .expect("valid parts");
        issue.wipe();
        assert!(issue.rand.iter().all(|s| s.0 == [0; 32]));
        assert_eq!(issue.cid.0, [0; 24]);
        assert_eq!(issue.lab.map(|l| l.0), Some([0; 24]));
        assert!(issue.tags.iter().flatten().all(|&b| b == 0));
        assert_eq!((issue.chamber, issue.counter), (1, 3), "public fields stay");
    }
}
