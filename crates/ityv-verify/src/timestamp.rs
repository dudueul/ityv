//! External timestamps (PROTOCOL.md §5.5, §14 2; ADR-0034, ADR-0037,
//! ADR-0039; VC-114..118).
//!
//! The genesis pins the timestamp authorities (set 12, fixed for the
//! election). The genesis stage checks the set (`verify_genesis`): every pin is
//! a valid `ityv-tsa` pin that allows SHA-512 (the digest of every imprint),
//! carries its certificate and allows a signature algorithm the
//! certificate's key makes over an allowed digest
//! (`PinnedTsa::signer_key`), so that some token could verify under it;
//! no signing certificate and no public key is pinned twice; every declared
//! accuracy is between [`MIN_POLICY_ACCURACY_MS`] and
//! [`MAX_TIMESTAMP_ACCURACY_MS`]; an operator's authorities are all of one
//! kind, operators compared without regard to ASCII case; the set has a
//! government-run and a non-government authority (VC-114); and, for every
//! genesis state, no operator is a witness's organisation or an election
//! commission's that a reporting unit names. Which operator is the
//! government's is the genesis's declaration, co-signed by the commission
//! and the committee: the verifier cannot check it (ADR-0039 한계).
//!
//! [`verify_timestamps`] reads every `TimestampRecord` of the ledger. A
//! record is taken when its authority is pinned, it stamps an event the
//! index accepted in an earlier frame, of a kind that is stamped (a signed
//! checkpoint, a signed genesis or amendment, a witnessed legal decision,
//! roll freeze or custody receipt; never a record, check-in counter or
//! progress tick, VC-117), and its
//! token verifies (`ityv_tsa::verify_token`) under one of the authority's
//! pins over the imprint SHA-512 of the stamped event's object hash
//! (ADR-0034 §3). A record without a token is the operator's note that the
//! authority did not answer: listed, not a hold, once its authority and
//! target pass the same checks. A record that cannot be taken is listed
//! and holds the ledger ([`HoldReason::TimestampInvalid`]).
//!
//! The time of a taken token is the latest instant its authority's
//! assertion allows: `genTime` plus the larger of the token's stated
//! accuracy and the accuracy the genesis declares for the authority, which
//! must cover every policy its pins allow (ADR-0037 §9, ADR-0039 5). A
//! token that states more than [`MAX_TIMESTAMP_ACCURACY_MS`] is refused
//! ([`TimestampProblem::Accuracy`]). Every rule uses that latest instant,
//! which is the conservative direction for each (ADR-0039):
//!
//! * backdating (VC-116): the token says the checkpoint existed earlier
//!   than its witnesses attest when even its latest instant falls more than
//!   `CLOCK_ERROR_BUCKETS` buckets before the checkpoint's bucket. The
//!   honest bound: an honest witness's clock is at most a minute fast, so
//!   it signs bucket `B` no earlier than a minute before `B` starts, and a
//!   token requested afterwards is issued, by an honest authority, no
//!   earlier than that; its latest instant is in bucket `B − 1` or later.
//!   The token's accuracy only widens the interval upward, so it never
//!   makes an honest checkpoint look backdated (the "widen the tolerance"
//!   branch of PROTOCOL.md §5.5);
//! * the anchor window (VC-115): a token anchors a checkpoint when its
//!   latest instant is within the checkpoint's bucket plus `ANCHOR_WINDOW`
//!   buckets;
//! * the audit's binding checkpoint (ADR-0039): a token proves the
//!   checkpoint existed before the beacon publication when its latest
//!   instant is before the start of the publication bucket.
//!
//! Tokens are counted per authority and per operator, never per token
//! bytes: the unsigned parts of a token and an ECDSA `s` can change
//! without changing what the authority signed (ADR-0037 §9). A rule that
//! needs timestamps needs [`Anchoring::satisfied`]: tokens of a
//! government-run and of a non-government authority, of two operators.
//!
//! What this stage does not prove: that an authority's time is true (it
//! asserts it; two operators of two kinds must agree to backdate), that a
//! certificate is unrevoked, or anything about the stamped event beyond its
//! hash. A token is corroboration: without tokens the witness chain stands
//! as it is (ADR-0034 §5).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use ityv_encoding::{
    AuthorityId, Day, EntrySet, Hash512, OrgId, PolicyAccuracy, ReportingUnitEntry,
    SCHEMA_LEGAL_DECISION_REF_BODY, SCHEMA_ROLL_CUSTODY_RECEIPT_BODY, SCHEMA_ROLL_FREEZE_BODY,
    SCHEMA_SIGNED_GENESIS, SCHEMA_TIMESTAMP_RECORD, SCHEMA_WITNESSED_EVENT, SchemaId, Seq,
    TimeBucket, TimestampAuthorityEntry, TimestampAuthorityKind, TimestampRecord,
    WitnessRosterEntry, WitnessedEvent, decode_object, schema_version,
};
use ityv_ledger::{ANCHOR_WINDOW, CLOCK_ERROR_BUCKETS, SCHEMA_SIGNED_CHECKPOINT};
use ityv_state::{HoldReason, HoldSet};
use ityv_tsa::{DigestAlgorithm, Imprint, PinnedTsa, TsaError, VerifiedTimestamp, verify_token};

use crate::error::{Error, Rule};
use crate::genesis::VerifiedGenesis;
use crate::index::{IndexedEvent, LedgerIndex};
use crate::sets::Set;

/// Seconds in a day.
const DAY_SECONDS: i128 = 86_400;

/// Seconds in a time bucket (fifteen minutes, PROTOCOL.md §2).
const BUCKET_SECONDS: i128 = 900;

/// Nanoseconds in a second.
const NANOS: u32 = 1_000_000_000;

/// The least accuracy, in milliseconds, a genesis may declare for a
/// timestamp authority (ADR-0039 1, 5): no authority's time is exact, and
/// a declared zero would make a token that states no accuracy a point.
pub const MIN_POLICY_ACCURACY_MS: u32 = 1_000;

/// The most accuracy, in milliseconds, a genesis may declare for a
/// timestamp authority or a token may state (ADR-0039 5): the minute that
/// also bounds an honest witness's clock. It keeps the anchor window and
/// the audit's 45 minutes before the publication (ADR-0039 8) open to an
/// honest authority.
pub const MAX_TIMESTAMP_ACCURACY_MS: u32 = 60_000;

/// Whether `operator` is `other`, without regard to ASCII case: an
/// organisation identifier is ASCII, and two spellings of one name are one
/// organisation.
fn same_org(operator: OrgId<'_>, other: OrgId<'_>) -> bool {
    operator.as_bytes().eq_ignore_ascii_case(other.as_bytes())
}

/// Checks the genesis's timestamp authority set (VC-114): every declared
/// accuracy within bounds; pins that allow SHA-512 and name a signer key
/// some token could verify under; no certificate and no key pinned twice;
/// one kind per operator, operators compared without regard to ASCII case;
/// and a government-run and a non-government authority.
///
/// # Errors
/// [`Rule::TimestampAccuracy`], [`Rule::TimestampPin`],
/// [`Rule::TimestampCertificate`], [`Rule::TimestampKey`],
/// [`Rule::TimestampOperator`] at the entry, [`Rule::TimestampAuthorities`]
/// for the set.
pub(crate) fn check_authorities(
    state: u64,
    set: &Set<'_, TimestampAuthorityEntry<'_>>,
) -> Result<(), Error> {
    let at = |index: usize, rule| Error::entry(state, EntrySet::TimestampAuthorities, index, rule);
    let mut certificates: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut keys: BTreeSet<&[u8]> = BTreeSet::new();
    let mut operators: Vec<(OrgId<'_>, TimestampAuthorityKind)> = Vec::new();
    for (index, item) in set.items().iter().enumerate() {
        let entry = &item.value;
        let declared = entry.policy_accuracy.millis();
        if !(MIN_POLICY_ACCURACY_MS..=MAX_TIMESTAMP_ACCURACY_MS).contains(&declared) {
            return Err(at(index, Rule::TimestampAccuracy));
        }
        for bytes in entry.pins.iter() {
            let pin = PinnedTsa::from_bytes(bytes).map_err(|_| at(index, Rule::TimestampPin))?;
            if !pin.digests().contains(DigestAlgorithm::Sha512) {
                return Err(at(index, Rule::TimestampPin));
            }
            let key = pin
                .signer_key()
                .map_err(|_| at(index, Rule::TimestampPin))?;
            if !certificates.insert(*pin.certificate_sha256()) {
                return Err(at(index, Rule::TimestampCertificate));
            }
            if !keys.insert(key) {
                return Err(at(index, Rule::TimestampKey));
            }
        }
        match operators
            .iter()
            .find(|(operator, _)| same_org(*operator, entry.operator))
        {
            Some((_, kind)) if *kind != entry.kind => {
                return Err(at(index, Rule::TimestampOperator));
            }
            Some(_) => {}
            None => operators.push((entry.operator, entry.kind)),
        }
    }
    // Each kind by its own pattern: with two kinds, `k != Government` is
    // `k == NonGovernment`, so a comparison would read the same turned
    // around.
    let government = operators
        .iter()
        .any(|(_, k)| matches!(k, TimestampAuthorityKind::Government));
    let non_government = operators
        .iter()
        .any(|(_, k)| matches!(k, TimestampAuthorityKind::NonGovernment));
    if government && non_government {
        Ok(())
    } else {
        Err(Error::set(
            state,
            EntrySet::TimestampAuthorities,
            Rule::TimestampAuthorities,
        ))
    }
}

/// Checks that no timestamp authority's operator is a witness's
/// organisation or an election commission's that a reporting unit names,
/// without regard to ASCII case (ADR-0039 2): the tokens corroborate the
/// witnesses' time and the commission's events, so their operators must be
/// others. Runs for every genesis state, since reporting units can change.
///
/// # Errors
/// [`Rule::TimestampOperatorConflict`] at the timestamp authority.
pub(crate) fn check_operators_apart(
    state: u64,
    authorities: &Set<'_, TimestampAuthorityEntry<'_>>,
    witnesses: &Set<'_, WitnessRosterEntry<'_>>,
    units: &Set<'_, ReportingUnitEntry<'_>>,
) -> Result<(), Error> {
    for (index, item) in authorities.items().iter().enumerate() {
        let operator = item.value.operator;
        let witness = witnesses
            .items()
            .iter()
            .any(|w| same_org(operator, w.value.org_id));
        let commission = units
            .items()
            .iter()
            .any(|u| same_org(operator, u.value.commission_org()));
        if witness || commission {
            return Err(Error::entry(
                state,
                EntrySet::TimestampAuthorities,
                index,
                Rule::TimestampOperatorConflict,
            ));
        }
    }
    Ok(())
}

/// Why a timestamp record was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimestampProblem {
    /// The record names an authority the genesis does not pin.
    Authority,
    /// The record stamps no event the index accepted in an earlier frame
    /// with that schema and hash, or an event of a kind that is not
    /// stamped (VC-117).
    Target,
    /// The token does not verify under any pin of the authority over the
    /// SHA-512 of the target's object hash, with the first error that does
    /// not merely say the pin is another signer's (`CertificateNotPinned`,
    /// or `SignerIdentifierMismatch` once the pin's own certificate copy
    /// stands in), or the first error when every pin gives one of those.
    Token(TsaError),
    /// The token verifies but states an accuracy above
    /// [`MAX_TIMESTAMP_ACCURACY_MS`]: its time is too vague for the rules
    /// that read it (ADR-0039 5).
    Accuracy,
}

/// A timestamp record that was not taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimestampRefusal<'a> {
    /// The frame that carries it.
    pub frame: Seq,
    /// The authority it names.
    pub authority: AuthorityId<'a>,
    /// The object hash it stamps.
    pub target: Hash512,
    /// Why it was not taken.
    pub problem: TimestampProblem,
}

/// A record of an authority that did not answer (ADR-0034 §3): the
/// operator's note, not evidence of a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Unanswered<'a> {
    /// The frame that carries it.
    pub frame: Seq,
    /// The authority that did not answer.
    pub authority: AuthorityId<'a>,
    /// The object hash it was asked to stamp.
    pub target: Hash512,
}

/// A token that verified, over an earlier event of the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StampedToken<'a> {
    /// The frame of the timestamp record.
    pub frame: Seq,
    /// The stamped event's object hash.
    pub target: Hash512,
    /// The stamped event's schema.
    pub target_schema: SchemaId,
    /// The frame of the stamped event.
    pub target_frame: Seq,
    /// The authority.
    pub authority: AuthorityId<'a>,
    /// Its operator.
    pub operator: OrgId<'a>,
    /// Whether the government runs it.
    pub kind: TimestampAuthorityKind,
    /// `genTime`, in whole Unix seconds.
    pub gen_time: u64,
    /// The latest instant the assertion allows (`genTime` plus the
    /// token's accuracy, or plus the policy accuracy of the genesis entry
    /// for a token that states none), in whole Unix seconds rounded down.
    /// Bucket boundaries are whole seconds, so the seconds alone place the
    /// instant.
    pub latest: u64,
    /// The SHA-256 of the certificate whose pin verified it.
    pub certificate_sha256: [u8; 32],
}

/// The start of bucket `bucket` of the election epoch `epoch`, in Unix
/// seconds (negative before 1970). `None` never happens for a `u64` day
/// and a bucket near a `u64` (the product fits an `i128` by far); it keeps
/// the arithmetic checked.
fn bucket_start(epoch: Day, bucket: i128) -> Option<i128> {
    i128::from(epoch.get())
        .checked_mul(DAY_SECONDS)?
        .checked_add(bucket.checked_mul(BUCKET_SECONDS)?)
}

/// Whether the instant `seconds` (Unix, whole seconds) is before the start
/// of bucket `bucket`; `false` if the arithmetic cannot be done.
pub(crate) fn before_start(seconds: u64, epoch: Day, bucket: i128) -> bool {
    bucket_start(epoch, bucket).is_some_and(|start| i128::from(seconds) < start)
}

impl StampedToken<'_> {
    /// Whether the token's latest instant is before the start of bucket
    /// `bucket` (the token proves its target existed before that bucket
    /// began).
    #[must_use]
    pub fn before(&self, epoch: Day, bucket: TimeBucket) -> bool {
        before_start(self.latest, epoch, i128::from(bucket.get()))
    }

    /// Whether the token says its target existed more than
    /// `CLOCK_ERROR_BUCKETS` buckets before bucket `bucket`: its latest
    /// instant's bucket plus the tolerance is below `bucket` (VC-116).
    #[must_use]
    pub fn backdates(&self, epoch: Day, bucket: TimeBucket) -> bool {
        // `b(latest) + c < B` ⇔ `b(latest) ≤ B − c − 1` ⇔
        // `latest < start(B − c)`.
        let edge = i128::from(bucket.get()).checked_sub(i128::from(CLOCK_ERROR_BUCKETS));
        edge.is_some_and(|edge| before_start(self.latest, epoch, edge))
    }

    /// Whether the token's latest instant is within bucket `bucket` plus
    /// the anchor window (`b(latest) ≤ B + ANCHOR_WINDOW`, VC-115).
    #[must_use]
    pub fn within_window(&self, epoch: Day, bucket: TimeBucket) -> bool {
        // `b(latest) ≤ B + w` ⇔ `latest < start(B + w + 1)`.
        let edge = i128::from(bucket.get())
            .checked_add(i128::from(ANCHOR_WINDOW))
            .and_then(|e| e.checked_add(1));
        edge.is_some_and(|edge| before_start(self.latest, epoch, edge))
    }
}

/// Which kinds of authority, and how many operators, stand behind a set of
/// tokens (VC-115).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Anchoring {
    /// A token of a government-run authority is among them.
    pub government: bool,
    /// A token of a non-government authority is among them.
    pub non_government: bool,
    /// The number of distinct operators.
    pub operators: usize,
}

impl Anchoring {
    /// Nothing stands behind it.
    pub(crate) const NONE: Self = Self {
        government: false,
        non_government: false,
        operators: 0,
    };

    /// Whether the tokens satisfy the anchor rule: a government-run and a
    /// non-government authority, of two or more operators (VC-115).
    #[must_use]
    pub const fn satisfied(&self) -> bool {
        self.government && self.non_government && self.operators >= 2
    }

    /// How many of the two required kinds are present (for the shortfall a
    /// deadline reports).
    #[must_use]
    pub fn kinds(&self) -> usize {
        // Two booleans: the sum is at most two.
        usize::from(self.government).saturating_add(usize::from(self.non_government))
    }
}

/// The anchoring of `tokens`. Operators are counted without regard to
/// ASCII case, as the genesis compares them.
pub(crate) fn anchoring<'t, 'a: 't>(
    tokens: impl Iterator<Item = &'t StampedToken<'a>>,
) -> Anchoring {
    let mut operators: Vec<OrgId<'a>> = Vec::new();
    let mut a = Anchoring::NONE;
    for t in tokens {
        if !operators.iter().any(|o| same_org(*o, t.operator)) {
            operators.push(t.operator);
        }
        match t.kind {
            TimestampAuthorityKind::Government => a.government = true,
            TimestampAuthorityKind::NonGovernment => a.non_government = true,
        }
    }
    a.operators = operators.len();
    a
}

/// Every timestamp record of a ledger.
#[derive(Debug, Clone)]
pub struct TimestampStage<'a> {
    tokens: Vec<StampedToken<'a>>,
    by_target: BTreeMap<[u8; 64], Vec<usize>>,
    refusals: Vec<TimestampRefusal<'a>>,
    unanswered: Vec<Unanswered<'a>>,
    epoch: Day,
    holds: HoldSet,
}

impl<'a> TimestampStage<'a> {
    /// The tokens taken, in frame order.
    #[must_use]
    pub fn tokens(&self) -> &[StampedToken<'a>] {
        &self.tokens
    }

    /// The tokens taken over the event with object hash `target`, in frame
    /// order.
    pub fn tokens_for<'s>(
        &'s self,
        target: &Hash512,
    ) -> impl Iterator<Item = &'s StampedToken<'a>> + 's {
        self.by_target
            .get(&target.0)
            .into_iter()
            .flatten()
            .filter_map(|&i| self.tokens.get(i))
    }

    /// The records not taken, in frame order.
    #[must_use]
    pub fn refusals(&self) -> &[TimestampRefusal<'a>] {
        &self.refusals
    }

    /// The records of authorities that did not answer, in frame order.
    #[must_use]
    pub fn unanswered(&self) -> &[Unanswered<'a>] {
        &self.unanswered
    }

    /// The genesis's `election_epoch_day`, from which buckets count.
    #[must_use]
    pub const fn epoch(&self) -> Day {
        self.epoch
    }

    /// The hold reasons the records put on the whole ledger.
    #[must_use]
    pub const fn holds(&self) -> HoldSet {
        self.holds
    }
}

/// Whether `schema` is one a timestamp record can name: a signed
/// checkpoint, a signed genesis or amendment, or a witnessed event.
fn stamped_schema(schema: SchemaId) -> bool {
    schema == SCHEMA_SIGNED_CHECKPOINT
        || schema == SCHEMA_SIGNED_GENESIS
        || schema == SCHEMA_WITNESSED_EVENT
}

/// Whether `event` is of a kind that is stamped (ADR-0034 §2, VC-117): a
/// signed checkpoint, a signed genesis or amendment, or a witnessed legal
/// decision, roll freeze or custody receipt (ADR-0040).
fn stamped_kind(event: &IndexedEvent<'_>) -> bool {
    if event.schema == SCHEMA_SIGNED_CHECKPOINT || event.schema == SCHEMA_SIGNED_GENESIS {
        return true;
    }
    if event.schema != SCHEMA_WITNESSED_EVENT {
        return false;
    }
    event
        .bytes
        .and_then(|bytes| {
            decode_object::<WitnessedEvent<'_>>(
                SCHEMA_WITNESSED_EVENT,
                schema_version(SCHEMA_WITNESSED_EVENT),
                bytes,
            )
            .ok()
        })
        .is_some_and(|w| {
            let body = w.body_schema();
            body == SCHEMA_LEGAL_DECISION_REF_BODY
                || body == SCHEMA_ROLL_FREEZE_BODY
                || body == SCHEMA_ROLL_CUSTODY_RECEIPT_BODY
        })
}

/// The latest instant `token` allows, in whole Unix seconds: `genTime`
/// plus the larger of its stated accuracy and `declared`, the accuracy the
/// genesis declares for its authority (ADR-0039 5). Whole seconds round
/// down, and rounding down keeps the larger of two instants the larger.
fn latest_seconds(token: &VerifiedTimestamp<'_>, declared: PolicyAccuracy) -> Option<u64> {
    let issued = token.gen_time();
    let by_declared = plus_millis(issued.unix_seconds(), issued.nanos(), declared.millis())?;
    // `genTime` itself when the token states no accuracy.
    let by_token = token.latest()?.unix_seconds();
    Some(by_declared.max(by_token))
}

/// Whether an accuracy of `seconds`, `millis` and `micros` is at most
/// [`MAX_TIMESTAMP_ACCURACY_MS`], a part of a millisecond counting as a
/// whole one.
fn within_accuracy_cap(seconds: u64, millis: u16, micros: u16) -> bool {
    let whole = seconds
        .saturating_mul(1000)
        .saturating_add(u64::from(millis))
        .saturating_add(u64::from(micros > 0));
    whole <= u64::from(MAX_TIMESTAMP_ACCURACY_MS)
}

/// The whole seconds of the instant `seconds` + `nanos` ns + `millis` ms;
/// `None` if `nanos` is not below a second or the sum overflows.
fn plus_millis(seconds: u64, nanos: u32, millis: u32) -> Option<u64> {
    if nanos >= NANOS {
        return None;
    }
    let whole = u64::from(millis.checked_div(1000)?);
    let part = millis.checked_rem(1000)?.checked_mul(1_000_000)?;
    let carry = u64::from(nanos.checked_add(part)? >= NANOS);
    seconds.checked_add(whole)?.checked_add(carry)
}

/// Whether `error` says only that a pin is not the token's signer: the
/// token embeds no certificate the pin names (`CertificateNotPinned`), or
/// the pin's own copy then stands in and is not the signer the token names
/// (`SignerIdentifierMismatch`).
fn another_signer(error: TsaError) -> bool {
    matches!(
        error,
        TsaError::CertificateNotPinned | TsaError::SignerIdentifierMismatch
    )
}

/// The first pin of `entry` that verifies `token` over `imprint`, or the
/// error to report: the first that does not say only that the pin is
/// another signer's ([`another_signer`]), so that a rotated authority's
/// token is judged by its own pin; else the first.
fn verify_under<'t>(
    token: &'t [u8],
    entry: &TimestampAuthorityEntry<'_>,
    imprint: &Imprint,
) -> Result<VerifiedTimestamp<'t>, TsaError> {
    let mut errors = Vec::new();
    for bytes in entry.pins.iter() {
        match PinnedTsa::from_bytes(bytes).and_then(|pin| verify_token(token, &pin, imprint)) {
            Ok(verified) => return Ok(verified),
            Err(e) => errors.push(e),
        }
    }
    // A genesis entry has at least one pin, so `errors` is not empty.
    Err(errors
        .iter()
        .copied()
        .find(|e| !another_signer(*e))
        .or_else(|| errors.first().copied())
        .unwrap_or(TsaError::CertificateNotPinned))
}

/// Reads every timestamp record of `index` against `genesis` (module
/// documentation).
#[must_use]
pub fn verify_timestamps<'a>(
    genesis: &VerifiedGenesis<'a>,
    index: &LedgerIndex<'a>,
) -> TimestampStage<'a> {
    // Only events of the three schemas a record can name (VC-117).
    let events: BTreeMap<[u8; 64], &IndexedEvent<'a>> = index
        .events()
        .iter()
        .filter(|e| stamped_schema(e.schema))
        .map(|e| (e.hash.0, e))
        .collect();
    let mut stage = TimestampStage {
        tokens: Vec::new(),
        by_target: BTreeMap::new(),
        refusals: Vec::new(),
        unanswered: Vec::new(),
        epoch: genesis.genesis().body().election_epoch_day(),
        holds: HoldSet::empty(),
    };
    for event in index
        .events()
        .iter()
        .filter(|e| e.schema == SCHEMA_TIMESTAMP_RECORD)
    {
        // The index decoded every accepted event of this schema.
        let Some(record) = event.bytes.and_then(|bytes| {
            decode_object::<TimestampRecord<'a>>(
                SCHEMA_TIMESTAMP_RECORD,
                schema_version(SCHEMA_TIMESTAMP_RECORD),
                bytes,
            )
            .ok()
        }) else {
            continue;
        };
        let p = *record.parts();
        let refuse = |problem| TimestampRefusal {
            frame: event.seq,
            authority: p.authority_id,
            target: p.target_hash,
            problem,
        };
        let Some(entry) = genesis.timestamp_authority(p.authority_id.as_bytes()) else {
            stage.refusals.push(refuse(TimestampProblem::Authority));
            continue;
        };
        // The target first, with or without a token: a note that the
        // authority did not answer names an event as a token would.
        let target = events.get(&p.target_hash.0).filter(|t| {
            t.schema == p.target_schema && t.seq.get() < event.seq.get() && stamped_kind(t)
        });
        let Some(target) = target else {
            stage.refusals.push(refuse(TimestampProblem::Target));
            continue;
        };
        let Some(token) = p.token else {
            stage.unanswered.push(Unanswered {
                frame: event.seq,
                authority: p.authority_id,
                target: p.target_hash,
            });
            continue;
        };
        let imprint = Imprint::of(DigestAlgorithm::Sha512, p.target_hash.as_bytes());
        match verify_under(token, entry, &imprint) {
            Ok(verified)
                if verified
                    .accuracy()
                    .is_some_and(|a| !within_accuracy_cap(a.seconds(), a.millis(), a.micros())) =>
            {
                stage.refusals.push(refuse(TimestampProblem::Accuracy));
            }
            Ok(verified) => {
                let at = stage.tokens.len();
                stage.tokens.push(StampedToken {
                    frame: event.seq,
                    target: p.target_hash,
                    target_schema: p.target_schema,
                    target_frame: target.seq,
                    authority: p.authority_id,
                    operator: entry.operator,
                    kind: entry.kind,
                    gen_time: verified.gen_time().unix_seconds(),
                    // A verified token always has a latest instant; the
                    // fallback is the latest possible, which anchors
                    // nothing and proves nothing early.
                    latest: latest_seconds(&verified, entry.policy_accuracy).unwrap_or(u64::MAX),
                    certificate_sha256: *verified.certificate_sha256(),
                });
                stage.by_target.entry(p.target_hash.0).or_default().push(at);
            }
            Err(e) => stage.refusals.push(refuse(TimestampProblem::Token(e))),
        }
    }
    stage.holds =
        HoldSet::empty().with_if(!stage.refusals.is_empty(), HoldReason::TimestampInvalid);
    stage
}

#[cfg(test)]
mod tests {
    use ityv_encoding::{
        AuthorityId, Day, Hash512, OrgId, SchemaId, Seq, TimeBucket, TimestampAuthorityKind,
    };

    use super::{
        Anchoring, MAX_TIMESTAMP_ACCURACY_MS, MIN_POLICY_ACCURACY_MS, StampedToken, anchoring,
        before_start, bucket_start, plus_millis, same_org, within_accuracy_cap,
    };

    const EPOCH: Day = Day::new(20_000);
    const E: u64 = 20_000 * 86_400;

    fn token(
        latest: u64,
        kind: TimestampAuthorityKind,
        operator: &'static [u8],
    ) -> StampedToken<'static> {
        StampedToken {
            frame: Seq::new(2).unwrap(),
            target: Hash512([1; 64]),
            target_schema: SchemaId::new(0x0010),
            target_frame: Seq::new(1).unwrap(),
            authority: AuthorityId::new(b"TSA").unwrap(),
            operator: OrgId::new(operator).unwrap(),
            kind,
            gen_time: latest,
            latest,
            certificate_sha256: [0; 32],
        }
    }

    fn at(latest: u64) -> StampedToken<'static> {
        token(latest, TimestampAuthorityKind::Government, b"OP")
    }

    /// Bucket starts are the epoch day plus 900-second steps, before 1970
    /// too.
    #[test]
    fn buckets_start_on_the_epoch_grid() {
        assert_eq!(bucket_start(EPOCH, 0), Some(i128::from(E)));
        assert_eq!(bucket_start(EPOCH, 3), Some(i128::from(E) + 2700));
        assert_eq!(bucket_start(EPOCH, -1), Some(i128::from(E) - 900));
        assert_eq!(bucket_start(Day::new(0), -2), Some(-1800));
        assert_eq!(
            bucket_start(Day::new(u64::MAX), i128::from(u64::MAX)),
            Some(i128::from(u64::MAX) * 86_400 + i128::from(u64::MAX) * 900)
        );
        assert!(before_start(E - 1, EPOCH, 0));
        assert!(!before_start(E, EPOCH, 0));
        assert!(!before_start(0, Day::new(0), 0));
        assert!(before_start(0, Day::new(0), 1));
    }

    /// `before` is the start of the bucket, `backdates` two buckets back
    /// (VC-116), `within_window` the end of bucket `B + 4` (VC-115).
    #[test]
    fn the_three_comparisons_meet_their_edges() {
        let b = TimeBucket::new(10);
        let start = |k: u64| E + k * 900;
        assert!(at(start(10) - 1).before(EPOCH, b));
        assert!(!at(start(10)).before(EPOCH, b));
        // Backdated: the latest instant's bucket plus one below 10, that
        // is, bucket 8 or earlier.
        assert!(at(start(9) - 1).backdates(EPOCH, b));
        assert!(!at(start(9)).backdates(EPOCH, b));
        assert!(!at(start(10)).backdates(EPOCH, b));
        // Within the window: bucket 14 at the latest.
        assert!(at(start(15) - 1).within_window(EPOCH, b));
        assert!(!at(start(15)).within_window(EPOCH, b));
        assert!(at(start(0)).within_window(EPOCH, b));
        // At bucket 0 a token in bucket −1 is within the tolerance, one in
        // bucket −2 is not.
        let zero = TimeBucket::new(0);
        assert!(!at(E - 900).backdates(EPOCH, zero));
        assert!(at(E - 901).backdates(EPOCH, zero));
        // The edges near the ends of `u64`.
        let far = TimeBucket::new(u64::MAX);
        assert!(at(u64::MAX).before(EPOCH, far));
        assert!(at(u64::MAX).within_window(EPOCH, far));
        assert!(at(0).backdates(EPOCH, far));
    }

    #[test]
    fn a_policy_accuracy_moves_the_latest_instant() {
        assert_eq!(plus_millis(100, 0, 0), Some(100));
        assert_eq!(plus_millis(100, 0, 500), Some(100));
        assert_eq!(plus_millis(100, 0, 999), Some(100));
        assert_eq!(plus_millis(100, 0, 1000), Some(101));
        assert_eq!(plus_millis(100, 0, 1500), Some(101));
        assert_eq!(plus_millis(100, 499_999_999, 500), Some(100));
        assert_eq!(plus_millis(100, 500_000_000, 500), Some(101));
        assert_eq!(plus_millis(100, 999_999_999, 1), Some(101));
        assert_eq!(plus_millis(100, 999_999_999, 0), Some(100));
        assert_eq!(plus_millis(100, 1_000_000_000, 0), None);
        assert_eq!(plus_millis(u64::MAX, 0, 999), Some(u64::MAX));
        assert_eq!(plus_millis(u64::MAX, 0, 1000), None);
        assert_eq!(plus_millis(u64::MAX, 999_999_999, 1), None);
        assert_eq!(plus_millis(7, 0, 3_600_000), Some(3607));
    }

    #[test]
    fn anchoring_counts_kinds_and_operators() {
        let gov = token(1, TimestampAuthorityKind::Government, b"GOV");
        let gov2 = token(2, TimestampAuthorityKind::Government, b"GOV");
        let free = token(3, TimestampAuthorityKind::NonGovernment, b"FREE");
        let free2 = token(3, TimestampAuthorityKind::NonGovernment, b"OTHER");
        let none = anchoring([].iter());
        assert_eq!(none, Anchoring::NONE);
        assert_eq!(none.kinds(), 0);
        assert!(!none.satisfied());
        let one = anchoring([gov, gov2].iter());
        assert_eq!(
            one,
            Anchoring {
                government: true,
                non_government: false,
                operators: 1
            }
        );
        assert_eq!(one.kinds(), 1);
        assert!(!one.satisfied());
        let both = anchoring([gov, free].iter());
        assert_eq!(both.kinds(), 2);
        assert_eq!(both.operators, 2);
        assert!(both.satisfied());
        let both_free = anchoring([free, free2].iter());
        assert_eq!(both_free.kinds(), 1);
        assert_eq!(both_free.operators, 2);
        assert!(!both_free.satisfied());
        // The kind rule alone is not enough when one operator ran both
        // kinds (the genesis refuses that; the count is still checked).
        let one_operator =
            anchoring([gov, token(4, TimestampAuthorityKind::NonGovernment, b"GOV")].iter());
        assert_eq!(one_operator.kinds(), 2);
        assert!(!one_operator.satisfied());
        // Two spellings of one operator are one operator.
        let one_spelled_twice =
            anchoring([gov, token(4, TimestampAuthorityKind::NonGovernment, b"gov")].iter());
        assert_eq!(one_spelled_twice.operators, 1);
        assert!(!one_spelled_twice.satisfied());
        assert_eq!(anchoring([free, free2, free].iter()).operators, 2);
    }

    #[test]
    fn operators_compare_without_ascii_case() {
        let org = |b: &'static [u8]| OrgId::new(b).unwrap();
        assert!(same_org(org(b"MOIS-GPKI"), org(b"mois-gpki")));
        assert!(same_org(org(b"Mois-Gpki"), org(b"MOIS-GPKI")));
        assert!(!same_org(org(b"MOIS-GPKI"), org(b"MOIS-GPKI2")));
        assert!(!same_org(org(b"MOIS-GPKI"), org(b"MOIS_GPKI")));
    }

    #[test]
    fn a_stated_accuracy_is_capped_at_a_minute() {
        assert!(within_accuracy_cap(0, 0, 0));
        assert!(within_accuracy_cap(1, 0, 0));
        assert!(within_accuracy_cap(59, 999, 999));
        assert!(within_accuracy_cap(60, 0, 0));
        assert!(!within_accuracy_cap(60, 0, 1));
        assert!(!within_accuracy_cap(60, 1, 0));
        assert!(!within_accuracy_cap(61, 0, 0));
        assert!(!within_accuracy_cap(u64::MAX, 999, 999));
        assert_eq!(MAX_TIMESTAMP_ACCURACY_MS, 60_000);
        assert_eq!(MIN_POLICY_ACCURACY_MS, 1_000);
    }
}
