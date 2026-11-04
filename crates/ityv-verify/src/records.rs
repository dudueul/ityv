//! The record stage (PROTOCOL.md §7.2.1, §7.5, §7.6, §14 5; VC-025..027,
//! VC-053, VC-057).
//!
//! For every box the box stage reported, [`verify_records`] reads the box's
//! events from the [`LedgerIndex`] that the box stage did not refuse (so
//! repeated bodies, events out of order and events of a box the genesis no
//! longer expects are already gone) and checks:
//!
//! 1. every cast record: its ballot style is in the genesis and fixes the
//!    option count, and it is the box's style (in the last genesis state,
//!    where the tally files the box, and in a state up to the record's
//!    frame) or a test style: a record of another style could be in no
//!    tally scope of this box (§11.1);
//!    its commitments are valid points and its OR proof of representation
//!    verifies (VC-025, VC-026); the device's Ed25519 record
//!    signature (purpose `cast-record`) over the body object bytes; and for
//!    each module counter, that module's Ed25519 record signature (purpose
//!    `module-record`) over `body_hash ‖ module_id ‖ counter`, the module
//!    being one of the box's modules. A record that fails is rejected
//!    ([`RecordRefusal`]). Two accepted records with the same module counter
//!    are both rejected: a module signs one body per counter (VC-068);
//! 2. every batch attestation: the device's and every signing module's
//!    hybrid signature (purpose `batch-attest`), every range on a module of
//!    the box; two different bodies under one `batch_index` (device double
//!    signing) set both aside; per module, the ranges in `batch_index`
//!    order run from counter 1 without a gap or an overlap and end within
//!    the close's final counter; the records whose counters fall in a
//!    batch's ranges are its members, `record_count` is their number and
//!    `records_root` the sorted-set root of their tracking codes (VC-053);
//! 3. every challenge opening: the device's hybrid signature (purpose
//!    `challenge`) over its body, and its record among the box's accepted
//!    records. The record it names is `CHALLENGED_SPOILED`: the device
//!    publishes it so anyone can re-verify its proof (§8.3), but no batch
//!    attests it and the close's record set leaves it out, as the device
//!    does. A challenge opening that does not verify, or names no accepted
//!    record of the box, is refused;
//! 4. every other accepted record is `CAST_COMMITTED` if exactly one valid
//!    batch has it as a member, otherwise `UNATTESTED` (VC-057);
//! 5. the box's effective close (its last accepted `BoxClose`: a late close
//!    replaces a manual one) carries as `record_set_root` the sorted-set
//!    root of the tracking codes of every accepted cast (not challenged)
//!    record (VC-027).
//!
//! A batch that records module refusals (`module_refusals`: a module would
//! not sign, a counter gap, VC-021) still attests its records with the
//! signatures it has, but it is a finding: the device is suspected and the
//! box's paper must be compared in full (`FAILURE_CASES.md` §4).
//!
//! The key that verifies a signature at frame `seq` is the box's device key
//! (or the module's key) in any genesis state from 0 to the state in force
//! at `seq` ([`LedgerIndex::state_at`]) in which the box (with the module)
//! exists: a replaced device's past records stay valid (§4.3), but a key an
//! amendment registers later cannot sign an earlier frame. Record
//! signatures are Ed25519 under the Ed25519 half of the registered hybrid
//! key (ENCODING.md §8.43, §8.51).
//!
//! A rejected record leaves [`HoldReason::RecordRejected`], a refused
//! challenge opening [`HoldReason::ChallengeRejected`], a batch finding
//! [`HoldReason::BatchInvalid`], a close whose record set root differs
//! [`HoldReason::RecordSetMismatch`]. An `UNATTESTED` record is
//! listed, not held: the tally scope excludes it (§11.1), the box stage
//! holds an open batch, and a late batch close can still attest it.
//!
//! A challenge opening that verifies is also reconstructed (PROTOCOL.md §8
//! item 3, VC-028): the opened option, cast id and summed randomness must
//! open every commitment of the record, the modules' contributions must sum
//! to that randomness, derive that cast id, and carry the record's module
//! counters. One that does not is a device fault: the record stays
//! challenged and the box is held ([`HoldReason::OpeningMismatch`]); §8
//! item 5 then quarantines the device and compares its paper in full.
//!
//! What this stage does not prove: the state of a record a quarantine entry names (`ImprintFailure`
//! has no ledger schema yet, so such a record is counted as cast); that a record's share package
//! reached the trustees (VC-036); anything about a box with no accepted
//! close beyond its records and batches (the box stage holds it).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use ityv_crypto::hash::object_hash;
use ityv_crypto::{
    Bases, CastId, Commitment, MAX_CHUNKS as CRYPTO_MAX_CHUNKS, Opening, OptionCount, OptionIndex,
    Proof, Purpose, RecordPurpose, RecordSignature, RecordVerifyingKey, Scalar, Sha3Hasher,
    Statement, verify, verify_opening, verify_record,
};
use ityv_encoding::schema_version;
use ityv_encoding::{
    BatchAttest, BoxClose, BoxId, CastRecord, ChallengeOpening, Decode, Encode, GenesisBox,
    HYBRID_SIG_LEN, HYBRID_VK_LEN, Hash512, MLDSA87_VK_HALF, ModuleId, Reader, SCHEMA_BATCH_ATTEST,
    SCHEMA_BOX_CLOSE, SCHEMA_CAST_RECORD, SCHEMA_CHALLENGE_OPENING, SchemaId, Seq, Writer,
    decode_object,
};
use ityv_ledger::sorted_set_root;
use ityv_state::{
    HoldReason, HoldSet, Profile, RecordEvent, RecordState, RecordStatus, is_test_style,
};

use crate::boxes::{BoxReport, BoxStage};
use crate::genesis::VerifiedGenesis;
use crate::index::{IndexedEvent, LedgerIndex};
use crate::sigs::Material;

/// Length of a module record message: `body_hash` (64), `module_id` (a
/// 4-byte length and at most 64 bytes), `counter` (8).
const MODULE_RECORD_MESSAGE_LEN: usize = 140;

/// Why a cast record was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordRefusal {
    /// Its ballot style is not in the genesis, or is neither the box's
    /// ballot style (in the genesis's last state and in a state up to its
    /// frame) nor a test style: no tally scope of the box could count it
    /// (§11.1).
    Style,
    /// A commitment is not a valid point, or the OR proof does not decode
    /// or does not verify (VC-025, VC-026).
    Proof,
    /// The device's record signature does not verify under a device key
    /// the box had by the record's frame.
    DeviceSignature,
    /// A module of its counters is not a module of the box by the record's
    /// frame.
    Module,
    /// A module's record signature does not verify.
    ModuleSignature,
    /// Another accepted record carries the same module counter.
    CounterReused,
}

/// A rejected cast record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RejectedRecord {
    /// The frame that carries it.
    pub seq: Seq,
    /// Its tracking code (the object hash of its body).
    pub tracking_code: Hash512,
    /// Why.
    pub refusal: RecordRefusal,
}

/// An accepted cast record and its state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AcceptedRecord {
    /// The frame that carries it.
    pub seq: Seq,
    /// Its tracking code.
    pub tracking_code: Hash512,
    /// Its state: `CAST_COMMITTED` once a batch attests it, `UNATTESTED`
    /// otherwise.
    pub state: RecordState,
}

/// What is wrong with a batch attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BatchProblem {
    /// The device's or a module's signature does not verify under a key
    /// the box had by the batch's frame. The batch attests nothing.
    Signature,
    /// A range names a module that is not a module of the box by the
    /// batch's frame. The batch attests nothing.
    Module,
    /// Another body carries the same `batch_index` (device double
    /// signing). Neither attests anything.
    DoubleIndex,
    /// A module's range does not start where the previous batch's range
    /// ended (or at counter 1): a gap or an overlap.
    CounterRange,
    /// A range ends beyond the close's final counter of the module.
    BeyondClose,
    /// A record's counters fall in this batch's ranges for some modules
    /// but not all of them, or in more than one batch.
    Straddle,
    /// `record_count` is not the number of its member records. The batch
    /// attests nothing.
    RecordCount,
    /// `records_root` is not the root of its member records. The batch
    /// attests nothing.
    RecordsRoot,
    /// The batch records modules that refused to sign it (a counter gap,
    /// VC-021). It attests its records with the signatures it has.
    ModuleRefused,
}

/// A finding about a batch attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BatchFinding {
    /// The frame that carries the batch.
    pub seq: Seq,
    /// What is wrong.
    pub problem: BatchProblem,
}

/// What the record stage concluded about one box.
#[derive(Debug, Clone)]
pub struct BoxRecords<'a> {
    /// The box.
    pub box_id: BoxId<'a>,
    /// The accepted records, in frame order.
    pub records: Vec<AcceptedRecord>,
    /// The rejected records, in frame order.
    pub rejected: Vec<RejectedRecord>,
    /// The tracking codes of the accepted records no valid batch attests
    /// (`UNATTESTED`), in frame order.
    pub unattested: Vec<Hash512>,
    /// The batch findings, in frame order.
    pub batches: Vec<BatchFinding>,
    /// The frames of the challenge openings refused: a signature that does
    /// not verify, or no accepted record of the box with the hash it
    /// names.
    pub refused_challenges: Vec<Seq>,
    /// The frames of the challenge openings that verify but do not
    /// reconstruct their record (VC-028): the device is at fault.
    pub failed_openings: Vec<Seq>,
    /// The sorted-set root of the accepted records' tracking codes, when
    /// the box has an accepted close to compare it with.
    pub record_set_root: Option<Hash512>,
    /// The record stage's holds on the box.
    pub holds: HoldSet,
}

/// The record stage over every box the box stage reported.
#[derive(Debug, Clone)]
pub struct RecordStage<'a> {
    reports: Vec<BoxRecords<'a>>,
    holds: HoldSet,
}

impl<'a> RecordStage<'a> {
    /// One report per box of the box stage, in the same order.
    #[must_use]
    pub fn reports(&self) -> &[BoxRecords<'a>] {
        &self.reports
    }

    /// The report of box `box_id`.
    #[must_use]
    pub fn report(&self, box_id: &[u8]) -> Option<&BoxRecords<'a>> {
        self.reports.iter().find(|r| r.box_id.as_bytes() == box_id)
    }

    /// The union of every box's record holds.
    #[must_use]
    pub const fn holds(&self) -> HoldSet {
        self.holds
    }
}

/// The Ed25519 record key of a registered hybrid key.
fn record_key(key: &[u8; HYBRID_VK_LEN]) -> Option<RecordVerifyingKey> {
    let half: [u8; 32] = key.get(MLDSA87_VK_HALF..)?.try_into().ok()?;
    RecordVerifyingKey::from_bytes(half).ok()
}

/// Whether `sig` is a record signature over `object` under one of `keys`.
fn record_verifies(
    sig: &[u8; 64],
    keys: &[&[u8; HYBRID_VK_LEN]],
    purpose: RecordPurpose,
    object: &[u8],
) -> bool {
    let sig = RecordSignature::from_bytes(*sig);
    keys.iter()
        .any(|k| record_key(k).is_some_and(|vk| verify_record(&vk, purpose, object, &sig).is_ok()))
}

/// Whether `sig` is a hybrid signature over `object` under one of `keys`.
fn hybrid_verifies(
    sig: &[u8; HYBRID_SIG_LEN],
    keys: &[&[u8; HYBRID_VK_LEN]],
    purpose: &Purpose<'_>,
    object: &[u8],
) -> bool {
    keys.iter()
        .any(|k| match Material::new(core::iter::once((sig, *k))) {
            Some(m) => m.verify(purpose, object).is_some(),
            None => false,
        })
}

/// The module record message `body_hash ‖ module_id ‖ counter` (PROTOCOL.md
/// §7.2.1, the encoding `ityv-cunit` signs).
fn module_message(
    body_hash: &Hash512,
    module_id: ModuleId<'_>,
    counter: u64,
    buf: &mut [u8; MODULE_RECORD_MESSAGE_LEN],
) -> Option<usize> {
    let mut w = Writer::new(buf);
    body_hash.encode(&mut w).ok()?;
    module_id.encode(&mut w).ok()?;
    w.write_u64(counter).ok()?;
    Some(w.finish())
}

fn decode<'a, T: Decode<'a>>(schema: SchemaId, bytes: &'a [u8]) -> Option<T> {
    decode_object(schema, schema_version(schema), bytes).ok()
}

/// What checking one box needs.
struct Ctx<'g, 'a> {
    genesis: &'g VerifiedGenesis<'a>,
    index: &'g LedgerIndex<'a>,
    bases: &'g Bases,
    box_id: &'a [u8],
}

impl<'a> Ctx<'_, 'a> {
    /// The states a signature at frame `seq` may come from.
    fn states(&self, seq: Seq) -> core::ops::RangeInclusive<usize> {
        0..=self.index.state_at(seq)
    }

    /// The device keys the box had in the states up to `seq`'s.
    fn device_keys(&self, seq: Seq) -> Vec<&'a [u8; HYBRID_VK_LEN]> {
        let mut keys: Vec<&'a [u8; HYBRID_VK_LEN]> = Vec::new();
        for state in self.states(seq) {
            if let Some(entry) = self.genesis.expected_box_at(state, self.box_id)
                && !keys.contains(&entry.device_key)
            {
                keys.push(entry.device_key);
            }
        }
        keys
    }

    /// The keys of module `module_id` in the states up to `seq`'s in which
    /// it is a module of the box (empty if it never was).
    fn module_keys(&self, seq: Seq, module_id: ModuleId<'_>) -> Vec<&'a [u8; HYBRID_VK_LEN]> {
        let mut keys: Vec<&'a [u8; HYBRID_VK_LEN]> = Vec::new();
        for state in self.states(seq) {
            let in_box = self
                .genesis
                .expected_box_at(state, self.box_id)
                .is_some_and(|b| b.modules.contains(module_id));
            if let Some(module) = self.genesis.module_at(state, module_id.as_bytes())
                && in_box
                && !keys.contains(&module.key)
            {
                keys.push(module.key);
            }
        }
        keys
    }

    /// Whether `style_id` is the box's ballot style in the genesis's last
    /// state, where the tally files the box (an amendment that changes the
    /// box's style must not relabel the records cast under the old one),
    /// and in a genesis state up to `seq`'s.
    fn box_style(&self, seq: Seq, style_id: &[u8]) -> bool {
        let style_of = |b: &GenesisBox<'_>| b.ballot_style_id.as_bytes() == style_id;
        self.genesis.expected_box(self.box_id).is_some_and(style_of)
            && self.states(seq).any(|state| {
                self.genesis
                    .expected_box_at(state, self.box_id)
                    .is_some_and(style_of)
            })
    }

    /// The option count of ballot style `style_id` in the genesis.
    fn options(&self, style_id: &[u8]) -> Option<OptionCount> {
        self.genesis
            .ballot_style(style_id)?
            .choices()
            .checked_add(2)
            .and_then(OptionCount::new)
    }

    /// Checks one cast record.
    fn record(&self, seq: Seq, record: &CastRecord<'_>) -> Result<(), RecordRefusal> {
        let body = record.body();
        let style = body.ballot_style_id();
        let options = self.options(style.as_bytes()).ok_or(RecordRefusal::Style)?;
        if !is_test_style(style) && !self.box_style(seq, style.as_bytes()) {
            return Err(RecordRefusal::Style);
        }
        let commitments = commitments_of(record).ok_or(RecordRefusal::Proof)?;
        let statement = Statement::new(
            body.election_id(),
            body.box_id().ident(),
            body.ballot_style_id().ident(),
            options,
            &commitments,
        )
        .map_err(|_| RecordRefusal::Proof)?;
        let mut reader = Reader::new(body.proof());
        let proof = Proof::decode(&mut reader).map_err(|_| RecordRefusal::Proof)?;
        reader.finish().map_err(|_| RecordRefusal::Proof)?;
        let _proven = verify(self.bases, &statement, &proof).map_err(|_| RecordRefusal::Proof)?;

        let devices = self.device_keys(seq);
        if !record_verifies(
            record.device_sig_ed25519(),
            &devices,
            RecordPurpose::CastRecord,
            record.body_bytes(),
        ) {
            return Err(RecordRefusal::DeviceSignature);
        }
        let body_hash = object_hash(record.body_bytes());
        // The encoding admits exactly one signature per module counter, in
        // the same order.
        for (sig, counter) in record.module_sigs().zip(body.module_counters().iter()) {
            if sig.module_id.as_bytes() != counter.module_id.as_bytes() {
                return Err(RecordRefusal::ModuleSignature);
            }
            let keys = self.module_keys(seq, counter.module_id);
            if keys.is_empty() {
                return Err(RecordRefusal::Module);
            }
            let mut buf = [0u8; MODULE_RECORD_MESSAGE_LEN];
            let len = module_message(&body_hash, counter.module_id, counter.counter, &mut buf)
                .ok_or(RecordRefusal::ModuleSignature)?;
            let message = buf.get(..len).ok_or(RecordRefusal::ModuleSignature)?;
            if !record_verifies(sig.ed25519, &keys, RecordPurpose::ModuleRecord, message) {
                return Err(RecordRefusal::ModuleSignature);
            }
        }
        Ok(())
    }

    /// Whether the device's hybrid signature of a batch verifies.
    fn device_signed(&self, seq: Seq, batch: &BatchAttest<'_>) -> bool {
        Purpose::new(b"batch-attest").is_some_and(|purpose| {
            hybrid_verifies(
                batch.device_sig(),
                &self.device_keys(seq),
                &purpose,
                batch.body_bytes(),
            )
        })
    }

    /// Whether the device's hybrid signature of a challenge opening
    /// verifies (purpose `challenge`).
    fn challenge_signed(&self, seq: Seq, opening: &ChallengeOpening<'_>) -> bool {
        Purpose::new(b"challenge").is_some_and(|purpose| {
            hybrid_verifies(
                opening.device_sig(),
                &self.device_keys(seq),
                &purpose,
                opening.body_bytes(),
            )
        })
    }

    /// Checks one batch's signatures and modules.
    fn batch(&self, seq: Seq, batch: &BatchAttest<'_>) -> Result<(), BatchProblem> {
        let body = batch.body();
        for range in body.module_ranges() {
            if self.module_keys(seq, range.module_id).is_empty() {
                return Err(BatchProblem::Module);
            }
        }
        let purpose = Purpose::new(b"batch-attest").ok_or(BatchProblem::Signature)?;
        if !hybrid_verifies(
            batch.device_sig(),
            &self.device_keys(seq),
            &purpose,
            batch.body_bytes(),
        ) {
            return Err(BatchProblem::Signature);
        }
        for sig in batch.module_sigs() {
            let keys = self.module_keys(seq, sig.module_id);
            if !hybrid_verifies(sig.sig, &keys, &purpose, batch.body_bytes()) {
                return Err(BatchProblem::Signature);
            }
        }
        Ok(())
    }
}

/// The commitments of a record, as group elements.
fn commitments_of(record: &CastRecord<'_>) -> Option<Vec<Commitment>> {
    record
        .body()
        .commitments()
        .as_slice()
        .iter()
        .map(|p| Commitment::from_point32(*p).ok())
        .collect()
}

/// Label of the cast-id derivation (PROTOCOL.md §7.3 step 2).
const LABEL_CAST_ID: &[u8] = b"ityv:castid:v1";

/// Whether the challenge opening `opening` reconstructs the record `record`
/// (PROTOCOL.md §8 item 3, VC-028): the same ballot style; the opened
/// option, cast id and summed randomness open every commitment; the modules' contributions sum to that randomness chunk by
/// chunk; the cast id is the one their contributions derive; and the
/// modules and counters are the record's.
fn opening_reconstructs(
    bases: &Bases,
    options: OptionCount,
    record: &CastRecord<'_>,
    opening: &ChallengeOpening<'_>,
) -> bool {
    let o = opening.body();
    let r = record.body();
    // The index put the opening and the record in the same box of the
    // election; the style is the opening's own claim.
    let same_style = o.ballot_style_id().as_bytes() == r.ballot_style_id().as_bytes();
    // The modules and their counters are the record's, in the same order
    // (both ascending by module identifier).
    let same_counters = o
        .modules()
        .map(|m| (m.module_id.as_bytes(), m.counter))
        .eq(r
            .module_counters()
            .iter()
            .map(|c| (c.module_id.as_bytes(), c.counter)));
    if !(same_style && same_counters) {
        return false;
    }
    // The summed randomness, and each module's share of it, chunk by chunk.
    let chunks = usize::from(options.chunk_count());
    let Some(rand) = scalars(o.rand().as_slice(), chunks) else {
        return false;
    };
    let mut sums = [Scalar::ZERO; CRYPTO_MAX_CHUNKS];
    for m in o.modules() {
        let Some(part) = scalars(m.rand.as_slice(), chunks) else {
            return false;
        };
        for (sum, p) in sums.iter_mut().zip(part.iter()) {
            *sum = sum.add(p);
        }
    }
    if sums != rand {
        return false;
    }
    // The cast id the modules' contributions derive.
    let mut hasher = Sha3Hasher::new();
    hasher.absorb(LABEL_CAST_ID);
    hasher.absorb(&[0x00]);
    for m in o.modules() {
        hasher.absorb(&m.cid.0);
    }
    let digest = hasher.finish();
    if digest.get(..24) != Some(o.cast_id().0.as_slice()) {
        return false;
    }
    let (Some(option), Some(commitments)) =
        (OptionIndex::new(o.option_index()), commitments_of(record))
    else {
        return false;
    };
    let opened = Opening::new(option, CastId::new(*o.cast_id()), rand);
    verify_opening(bases, options, &commitments, &opened).is_ok()
}

/// Exactly `chunks` canonical scalars, padded with zero to the chunk
/// capacity.
fn scalars(raw: &[ityv_encoding::Scalar32], chunks: usize) -> Option<[Scalar; CRYPTO_MAX_CHUNKS]> {
    let mut out = [Scalar::ZERO; CRYPTO_MAX_CHUNKS];
    if raw.len() != chunks {
        return None;
    }
    for (slot, s) in out.get_mut(..chunks)?.iter_mut().zip(raw) {
        *slot = Scalar::from_canonical_bytes(s.0).ok()?;
    }
    Some(out)
}

/// A record the stage accepted, with its counters.
struct Counted<'a> {
    seq: Seq,
    tracking_code: Hash512,
    counters: Vec<(&'a [u8], u64)>,
    style_test: bool,
    /// The record, to reconstruct a challenge of it.
    record: CastRecord<'a>,
}

/// A batch whose signatures and modules held and whose batch index no
/// other body carries.
struct Candidate<'a> {
    seq: Seq,
    batch: BatchAttest<'a>,
}

impl Candidate<'_> {
    /// The range of module `module_id`, if the batch has one.
    fn range(&self, module_id: &[u8]) -> Option<(u64, u64)> {
        self.batch
            .body()
            .module_ranges()
            .find(|r| r.module_id.as_bytes() == module_id)
            .map(|r| (r.counter_first, r.counter_last))
    }

    /// Whether every counter of `record` is in this batch's ranges.
    fn covers(&self, record: &Counted<'_>) -> bool {
        !record.counters.is_empty()
            && record.counters.iter().all(|(m, c)| {
                self.range(m)
                    .is_some_and(|(first, last)| first <= *c && *c <= last)
            })
    }

    /// Whether some counter of `record` is in this batch's ranges.
    fn touches(&self, record: &Counted<'_>) -> bool {
        record.counters.iter().any(|(m, c)| {
            self.range(m)
                .is_some_and(|(first, last)| first <= *c && *c <= last)
        })
    }
}

/// The sorted-set root of `codes`.
fn set_root(mut codes: Vec<Hash512>) -> Option<Hash512> {
    codes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    sorted_set_root(&codes).ok()
}

/// Checks the ranges of every module across the candidates in
/// `batch_index` order: from counter 1, no gap, no overlap, and within the
/// close's final counter.
fn ranges(
    candidates: &[Candidate<'_>],
    close: Option<&BoxClose<'_>>,
    findings: &mut Vec<BatchFinding>,
) {
    let mut order: Vec<&Candidate<'_>> = candidates.iter().collect();
    order.sort_by_key(|c| c.batch.body().batch_index());
    let mut next: BTreeMap<&[u8], u64> = BTreeMap::new();
    for c in order {
        let mut problem = None;
        for r in c.batch.body().module_ranges() {
            let expected = next.get(r.module_id.as_bytes()).copied().unwrap_or(1);
            if r.counter_first != expected {
                problem = Some(BatchProblem::CounterRange);
            }
            next.insert(r.module_id.as_bytes(), r.counter_last.saturating_add(1));
            let beyond = close.is_some_and(|close| {
                close
                    .body()
                    .module_counters()
                    .get(r.module_id)
                    .is_none_or(|final_counter| r.counter_last > final_counter)
            });
            if beyond && problem.is_none() {
                problem = Some(BatchProblem::BeyondClose);
            }
        }
        if let Some(problem) = problem {
            findings.push(BatchFinding {
                seq: c.seq,
                problem,
            });
        }
    }
}

/// The profile and test flag of a record of the box.
fn record_state(profile: Profile, test: bool, attested: bool) -> RecordState {
    let state = RecordState::new(profile, test);
    if attested {
        state.apply(RecordEvent::BatchAttested).unwrap_or(state)
    } else {
        state
    }
}

/// The record, batch and close events of a box, decoded; records checked.
struct Collected<'a> {
    counted: Vec<Counted<'a>>,
    rejected: Vec<RejectedRecord>,
    batches: Vec<(Seq, BatchAttest<'a>)>,
    /// Each challenge opening's frame, the opening, and whether its device
    /// signature verifies.
    challenges: Vec<(Seq, ChallengeOpening<'a>, bool)>,
    close: Option<BoxClose<'a>>,
}

/// What the challenge openings of a box did.
#[derive(Default)]
struct Judged {
    /// The tracking codes of the records the device opened.
    challenged: BTreeSet<[u8; 64]>,
    /// The openings refused: no valid device signature, or no accepted
    /// record of the box by that hash.
    refused: Vec<Seq>,
    /// The openings taken that do not reconstruct their record.
    failed: Vec<Seq>,
}

/// Takes each challenge opening of a box against its accepted records.
fn judge_challenges<'a>(
    ctx: &Ctx<'_, 'a>,
    accepted: &[Counted<'a>],
    challenges: &[(Seq, ChallengeOpening<'a>, bool)],
) -> Judged {
    let mut out = Judged::default();
    for (seq, opening, signed) in challenges {
        let record_hash = *opening.body().record_hash();
        let record = accepted
            .iter()
            .find(|r| r.tracking_code == record_hash)
            .map(|r| &r.record);
        if let (true, Some(record)) = (*signed, record) {
            // The device opened the record: it is challenged. An opening
            // that does not reconstruct it is a device fault (VC-028).
            out.challenged.insert(record_hash.0);
            let reconstructs = ctx
                .options(record.body().ballot_style_id().as_bytes())
                .is_some_and(|options| opening_reconstructs(ctx.bases, options, record, opening));
            if !reconstructs {
                out.failed.push(*seq);
            }
        } else {
            out.refused.push(*seq);
        }
    }
    out
}

/// Decodes the box's events and checks each record.
fn collect<'a>(ctx: &Ctx<'_, 'a>, events: &[&IndexedEvent<'a>]) -> Collected<'a> {
    let mut out = Collected {
        counted: Vec::new(),
        rejected: Vec::new(),
        batches: Vec::new(),
        challenges: Vec::new(),
        close: None,
    };
    for e in events {
        let Some(bytes) = e.bytes else { continue };
        if e.schema == SCHEMA_CAST_RECORD {
            let Some(record) = decode::<CastRecord<'a>>(e.schema, bytes) else {
                continue;
            };
            let tracking_code = object_hash(record.body_bytes());
            match ctx.record(e.seq, &record) {
                Ok(()) => out.counted.push(Counted {
                    seq: e.seq,
                    tracking_code,
                    counters: record
                        .body()
                        .module_counters()
                        .iter()
                        .map(|c| (c.module_id.as_bytes(), c.counter))
                        .collect(),
                    style_test: is_test_style(record.body().ballot_style_id()),
                    record,
                }),
                Err(refusal) => out.rejected.push(RejectedRecord {
                    seq: e.seq,
                    tracking_code,
                    refusal,
                }),
            }
        } else if e.schema == SCHEMA_BATCH_ATTEST {
            if let Some(batch) = decode::<BatchAttest<'a>>(e.schema, bytes) {
                out.batches.push((e.seq, batch));
            }
        } else if e.schema == SCHEMA_CHALLENGE_OPENING {
            if let Some(opening) = decode::<ChallengeOpening<'a>>(e.schema, bytes) {
                let signed = ctx.challenge_signed(e.seq, &opening);
                out.challenges.push((e.seq, opening, signed));
            }
        } else if e.schema == SCHEMA_BOX_CLOSE
            && let Some(c) = decode::<BoxClose<'a>>(e.schema, bytes)
        {
            // The last accepted close is the effective one.
            out.close = Some(c);
        }
    }
    out
}

/// Rejects every record that shares a module counter with another, and
/// returns the rest.
fn unique_counters<'a>(
    counted: Vec<Counted<'a>>,
    rejected: &mut Vec<RejectedRecord>,
) -> Vec<Counted<'a>> {
    let mut uses: BTreeMap<(&[u8], u64), u32> = BTreeMap::new();
    for r in &counted {
        for key in &r.counters {
            let n = uses.entry(*key).or_insert(0);
            *n = n.saturating_add(1);
        }
    }
    let (shared, unique): (Vec<Counted<'a>>, Vec<Counted<'a>>) =
        counted.into_iter().partition(|r| {
            r.counters
                .iter()
                .any(|k| uses.get(k).is_some_and(|n| *n > 1))
        });
    rejected.extend(shared.iter().map(|r| RejectedRecord {
        seq: r.seq,
        tracking_code: r.tracking_code,
        refusal: RecordRefusal::CounterReused,
    }));
    unique
}

/// The batches whose signatures and modules hold and whose batch index no
/// other body carries.
fn screen<'a>(
    ctx: &Ctx<'_, 'a>,
    batches: Vec<(Seq, BatchAttest<'a>)>,
    findings: &mut Vec<BatchFinding>,
) -> Vec<Candidate<'a>> {
    // Device double signing: two bodies the device signed under one batch
    // index, whatever their module signatures.
    let mut per_index: BTreeMap<u32, u32> = BTreeMap::new();
    let signed: Vec<bool> = batches
        .iter()
        .map(|(seq, batch)| ctx.device_signed(*seq, batch))
        .collect();
    for ((_, batch), device) in batches.iter().zip(&signed) {
        if *device {
            let n = per_index.entry(batch.body().batch_index()).or_insert(0);
            *n = n.saturating_add(1);
        }
    }
    let mut candidates: Vec<Candidate<'a>> = Vec::new();
    for (seq, batch) in batches {
        let doubled = per_index
            .get(&batch.body().batch_index())
            .is_some_and(|n| *n > 1);
        let checked = if doubled {
            Err(BatchProblem::DoubleIndex)
        } else {
            ctx.batch(seq, &batch)
        };
        match checked {
            Ok(()) => {
                if batch.body().module_refusals().iter().next().is_some() {
                    findings.push(BatchFinding {
                        seq,
                        problem: BatchProblem::ModuleRefused,
                    });
                }
                candidates.push(Candidate { seq, batch });
            }
            Err(problem) => findings.push(BatchFinding { seq, problem }),
        }
    }
    candidates
}

/// Which records the batches attest: a record is a member of the one batch
/// whose ranges hold all its counters, and is attested if that batch's
/// count and root hold. Returns, per record, whether it is attested.
fn attest(
    records: &[Counted<'_>],
    batches: &[Candidate<'_>],
    findings: &mut Vec<BatchFinding>,
) -> Vec<bool> {
    let mut member_of: Vec<Option<usize>> = Vec::with_capacity(records.len());
    for r in records {
        let covering: Vec<usize> = batches
            .iter()
            .enumerate()
            .filter(|(_, b)| b.covers(r))
            .map(|(i, _)| i)
            .collect();
        if let [one] = covering.as_slice() {
            member_of.push(Some(*one));
        } else {
            if let Some(b) = batches.iter().find(|b| b.touches(r)) {
                findings.push(BatchFinding {
                    seq: b.seq,
                    problem: BatchProblem::Straddle,
                });
            }
            member_of.push(None);
        }
    }
    let mut holds_up: Vec<bool> = Vec::with_capacity(batches.len());
    for (i, b) in batches.iter().enumerate() {
        let members: Vec<Hash512> = records
            .iter()
            .zip(&member_of)
            .filter(|(_, m)| **m == Some(i))
            .map(|(r, _)| r.tracking_code)
            .collect();
        let body = b.batch.body();
        let problem = if u16::try_from(members.len()).ok() != Some(body.record_count()) {
            Some(BatchProblem::RecordCount)
        } else if set_root(members).as_ref() != Some(body.records_root()) {
            Some(BatchProblem::RecordsRoot)
        } else {
            None
        };
        if let Some(problem) = problem {
            findings.push(BatchFinding {
                seq: b.seq,
                problem,
            });
        }
        holds_up.push(problem.is_none());
    }
    member_of
        .iter()
        .map(|m| m.is_some_and(|i| holds_up.get(i).copied().unwrap_or(false)))
        .collect()
}

/// Runs one box.
fn run_box<'a>(
    genesis: &VerifiedGenesis<'a>,
    index: &LedgerIndex<'a>,
    bases: &Bases,
    report: &BoxReport<'a>,
) -> BoxRecords<'a> {
    let box_id = report.box_id;
    let skipped: BTreeSet<u64> = report.refusals.iter().map(|r| r.seq.get()).collect();
    let events: Vec<&IndexedEvent<'a>> = index
        .box_events(box_id.as_bytes())
        .filter(|e| !skipped.contains(&e.seq.get()))
        .collect();
    let ctx = Ctx {
        genesis,
        index,
        bases,
        box_id: box_id.as_bytes(),
    };
    let profile = (0..genesis.state_count())
        .rev()
        .find_map(|s| genesis.expected_box_at(s, box_id.as_bytes()))
        .map_or(Profile::InPerson, |b| Profile::from_capture(b.profile));

    let Collected {
        counted,
        mut rejected,
        batches,
        challenges,
        close,
    } = collect(&ctx, &events);
    let accepted = unique_counters(counted, &mut rejected);
    rejected.sort_by_key(|r| r.seq.get());

    // The records the device opened for a challenge: never attested, not in
    // the close's record set.
    let Judged {
        challenged,
        refused: refused_challenges,
        failed: failed_openings,
    } = judge_challenges(&ctx, &accepted, &challenges);
    let (opened, accepted): (Vec<Counted<'a>>, Vec<Counted<'a>>) = accepted
        .into_iter()
        .partition(|r| challenged.contains(&r.tracking_code.0));

    let mut findings: Vec<BatchFinding> = Vec::new();
    let candidates = screen(&ctx, batches, &mut findings);
    ranges(&candidates, close.as_ref(), &mut findings);
    let attested = attest(&accepted, &candidates, &mut findings);

    let mut records: Vec<AcceptedRecord> = accepted
        .iter()
        .zip(&attested)
        .map(|(r, a)| AcceptedRecord {
            seq: r.seq,
            tracking_code: r.tracking_code,
            state: record_state(profile, r.style_test, *a),
        })
        .collect();
    // The record set of the close: the cast records, before the challenged
    // ones join the list.
    let cast_codes: Vec<Hash512> = records.iter().map(|r| r.tracking_code).collect();
    records.extend(opened.iter().map(|r| {
        let state = RecordState::new(profile, r.style_test);
        AcceptedRecord {
            seq: r.seq,
            tracking_code: r.tracking_code,
            state: state.apply(RecordEvent::Challenged).unwrap_or(state),
        }
    }));
    records.sort_by_key(|r| r.seq.get());
    let unattested: Vec<Hash512> = records
        .iter()
        .filter(|r| r.state.status() == RecordStatus::Unattested)
        .map(|r| r.tracking_code)
        .collect();

    // The record set root of the effective close.
    let record_set_root = close.as_ref().and_then(|_| set_root(cast_codes));
    let root_differs = close
        .as_ref()
        .is_some_and(|c| record_set_root.as_ref() != Some(c.body().record_set_root()));

    findings.sort_by_key(|f| f.seq.get());
    findings.dedup();
    let holds = HoldSet::empty()
        .with_if(!rejected.is_empty(), HoldReason::RecordRejected)
        .with_if(
            !refused_challenges.is_empty(),
            HoldReason::ChallengeRejected,
        )
        .with_if(!failed_openings.is_empty(), HoldReason::OpeningMismatch)
        .with_if(!findings.is_empty(), HoldReason::BatchInvalid)
        .with_if(root_differs, HoldReason::RecordSetMismatch);
    BoxRecords {
        box_id,
        records,
        rejected,
        unattested,
        batches: findings,
        refused_challenges,
        failed_openings,
        record_set_root,
        holds,
    }
}

/// Checks the records and batches of every box the box stage reported.
#[must_use]
pub fn verify_records<'a>(
    genesis: &VerifiedGenesis<'a>,
    index: &LedgerIndex<'a>,
    boxes: &BoxStage<'a>,
) -> RecordStage<'a> {
    let bases = Bases::derive();
    let reports: Vec<BoxRecords<'a>> = boxes
        .reports()
        .iter()
        .map(|r| run_box(genesis, index, &bases, r))
        .collect();
    let holds = reports
        .iter()
        .fold(HoldSet::empty(), |h, r| h.union(r.holds));
    RecordStage { reports, holds }
}
