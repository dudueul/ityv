//! The checkpoint chain (PROTOCOL.md §5.3, §5.4, §14 2; VC-011..014).
//!
//! [`verify_checkpoints`] walks the `SignedCheckpoint` events of a
//! [`LedgerIndex`] in frame order. Each checkpoint must:
//!
//! 1. be signed over its body bytes by at least `q` distinct witnesses of
//!    the genesis witness set, under the purpose `checkpoint`, with the
//!    organisations, providers and regions the genesis requires
//!    (`ityv_ledger::evaluate`, VC-014);
//! 2. follow the previous valid checkpoint: sequence one more (or 1 with a
//!    zero previous hash), previous hash the previous body's object hash,
//!    tree size and time bucket not smaller (the witnesses attest the
//!    time), the same election, ledger and key set, and the pinned genesis
//!    (`ityv_ledger::validate_successor`, VC-012);
//! 3. commit to frames strictly before its own: `tree_size` is less than
//!    the sequence number of the frame that carries it;
//! 4. carry the root of the ledger tree over the first `tree_size` frame
//!    hashes (VC-011);
//! 5. carry the sorted-set root of the object hashes of every accepted
//!    `BoxClose` (device, manual or late) in those frames;
//! 6. carry the sorted-set root of the filing-body object hashes of every
//!    dispute still unresolved after the dispute events in those frames,
//!    run through `ityv_state`'s dispute state machine with their
//!    signatures verified (`crate::disputes`): a filing under the
//!    capability for its day opens a dispute, a later event changes it
//!    only when the machine takes it (same filing, type, target and
//!    evidence, both authorities' signatures, a forward transition), and
//!    an event it does not take changes nothing.
//!
//! The external timestamps of the ledger ([`crate::verify_timestamps`],
//! ADR-0034, ADR-0039) then judge each checkpoint that passed:
//!
//! 7. no valid token over the signed checkpoint (the `SignedCheckpoint`
//!    event's object hash) says it existed more than `CLOCK_ERROR_BUCKETS`
//!    buckets before the bucket its witnesses attest (VC-116): otherwise
//!    the checkpoint's time is false, the chain ends there as at a broken
//!    rule, and the ledger is held (`TimestampMismatch`);
//! 8. its anchoring ([`VerifiedCheckpoint::anchoring`], VC-115): the tokens
//!    whose latest instant is within its bucket plus the anchor window, by
//!    kind and operator.
//!
//! The first checkpoint that breaks a rule ends the chain: it becomes a
//! [`CheckpointFinding`], the ledger is held (`CheckpointInvalid`, or
//! `TimestampMismatch` for rule 7), and no later checkpoint is trusted,
//! because each one vouches for the ones before it. The frames covered by
//! the last valid checkpoint are the witnessed part of the ledger
//! ([`CheckpointChain::covered`]); the ledger's anchor deadline follows the
//! last valid checkpoint ([`CheckpointChain::anchor_deadline`]), which
//! covers every earlier one. A timestamp record that cannot be taken holds
//! the ledger (`TimestampInvalid`) without ending the chain: a token is
//! corroboration, never the root of trust (ADR-0034 §5).
//!
//! What this stage does not prove: that no other checkpoint with the same
//! sequence was signed elsewhere (split view, stage 10), that frames after
//! the last checkpoint will ever be covered, that a timestamp authority's
//! time is true, or anything about the events beyond their hashes, closes
//! and dispute actions.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use ityv_crypto::hash::object_hash;
use ityv_encoding::{
    CheckpointBody, Hash512, KeysetId, LedgerId, SCHEMA_BOX_CLOSE, SCHEMA_VERSION_1, Seq,
    TimeBucket, decode_object,
};
use ityv_ledger::{
    Accumulator, Breach, DiversityPolicy, Error as LedgerError, QuorumProfile, Roster,
    SCHEMA_SIGNED_CHECKPOINT, SignedCheckpoint, WitnessEntry, WitnessSet, anchor_deadline,
    evaluate, sorted_set_root, validate_successor,
};
use ityv_state::{HoldReason, HoldSet, Publication};

use crate::authority::AuthorityStage;
use crate::disputes::{DisputeStep, verify_disputes};
use crate::genesis::VerifiedGenesis;
use crate::index::{IndexedEvent, LedgerIndex};
use crate::sigs::verifying_key;
use crate::timestamp::{Anchoring, TimestampStage, anchoring, verify_timestamps};

/// A checkpoint that passed every rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VerifiedCheckpoint {
    /// The frame that carries the checkpoint.
    pub frame: Seq,
    /// The checkpoint's own sequence number.
    pub checkpoint_seq: Seq,
    /// The number of frames it commits to.
    pub tree_size: u64,
    /// The ledger root at `tree_size`.
    pub root: Hash512,
    /// The object hash of its body (the next checkpoint's previous hash).
    pub body_hash: Hash512,
    /// The time bucket the witnesses signed: the verifier's only time
    /// that no single operator declares (the tally's late-close window is
    /// measured in it, PROTOCOL.md §11.1).
    pub time_bucket: TimeBucket,
    /// The object hash of the `SignedCheckpoint` event, the hash its
    /// timestamp tokens stamp (ADR-0039).
    pub event_hash: Hash512,
    /// The valid tokens over it whose latest instant is within its bucket
    /// plus the anchor window, by kind and operator (VC-115).
    pub anchoring: Anchoring,
}

/// The rule a checkpoint broke.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CheckpointFindingKind {
    /// The event is not a canonical `SignedCheckpoint`.
    Undecodable,
    /// The witness signatures fall short: an unknown or repeated witness,
    /// a signature that does not verify, too few signers or too little
    /// diversity (VC-014), with `ityv-ledger`'s error.
    Signatures(LedgerError),
    /// The checkpoint does not follow the previous valid one (VC-012),
    /// with `ityv-ledger`'s error.
    Successor(LedgerError),
    /// The checkpoint commits to its own frame or later ones.
    BeyondOwnFrame,
    /// The root is not the ledger root at `tree_size` (VC-011).
    Root,
    /// The box close root is not the root of the closes in its frames.
    BoxCloseRoot,
    /// The dispute root is not the root of the disputes unresolved in its
    /// frames.
    DisputeRoot,
    /// A valid timestamp token says the checkpoint existed more than
    /// `CLOCK_ERROR_BUCKETS` buckets before its time bucket (VC-116).
    Backdated,
}

/// A checkpoint that broke a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CheckpointFinding {
    /// The frame that carries the checkpoint.
    pub frame: Seq,
    /// The rule broken.
    pub kind: CheckpointFindingKind,
}

/// The checkpoint chain of a ledger.
#[derive(Debug, Clone)]
pub struct CheckpointChain<'a> {
    checkpoints: Vec<VerifiedCheckpoint>,
    findings: Vec<CheckpointFinding>,
    unchecked: usize,
    holds: HoldSet,
    timestamps: TimestampStage<'a>,
}

impl<'a> CheckpointChain<'a> {
    /// The valid checkpoints, in chain order.
    #[must_use]
    pub fn checkpoints(&self) -> &[VerifiedCheckpoint] {
        &self.checkpoints
    }

    /// The checkpoint that broke the chain, if any.
    #[must_use]
    pub fn findings(&self) -> &[CheckpointFinding] {
        &self.findings
    }

    /// The checkpoints after the one that broke the chain, not checked.
    #[must_use]
    pub const fn unchecked(&self) -> usize {
        self.unchecked
    }

    /// The hold reasons the chain puts on the whole ledger.
    #[must_use]
    pub const fn holds(&self) -> HoldSet {
        self.holds
    }

    /// The last valid checkpoint.
    #[must_use]
    pub fn last(&self) -> Option<&VerifiedCheckpoint> {
        self.checkpoints.last()
    }

    /// The number of frames the last valid checkpoint covers (0 if none).
    #[must_use]
    pub fn covered(&self) -> u64 {
        self.last().map_or(0, |c| c.tree_size)
    }

    /// Every timestamp record of the ledger ([`crate::verify_timestamps`]).
    #[must_use]
    pub const fn timestamps(&self) -> &TimestampStage<'a> {
        &self.timestamps
    }

    /// The anchor deadline of the ledger (PROTOCOL.md §5.5, VC-115),
    /// decided from the timestamp tokens of the last valid checkpoint,
    /// which covers every earlier one: met when its tokens satisfy the
    /// anchor rule; otherwise still open while `now` (the caller's clock,
    /// the only input this needs it for) is within its window, and missed
    /// after, with the number of the two required authority kinds present
    /// out of two. Pending when there is no valid checkpoint.
    #[must_use]
    pub fn anchor_deadline(&self, now: TimeBucket) -> Publication {
        let Some(last) = self.last() else {
            return Publication::Pending;
        };
        if last.anchoring.satisfied() {
            return Publication::Satisfied;
        }
        match anchor_deadline(last.time_bucket) {
            Ok(deadline) if now.get() <= deadline.get() => Publication::Pending,
            Ok(_) => Publication::Breached(Breach::AnchorsShort {
                have: last.anchoring.kinds(),
                need: 2,
            }),
            Err(_) => Publication::Failed,
        }
    }
}

/// The ledger contents up to a tree size, built as tree sizes grow.
struct Prefix<'i, 'a> {
    tree: Accumulator,
    /// The next event of the index to fold in.
    cursor: usize,
    closes: BTreeSet<[u8; 64]>,
    /// The next dispute step to fold in.
    step: usize,
    /// Filing-body hash to "unresolved".
    disputes: BTreeMap<[u8; 64], bool>,
    events: &'i [IndexedEvent<'a>],
    frames: &'i [Hash512],
    steps: &'i [DisputeStep],
}

impl<'i, 'a> Prefix<'i, 'a> {
    fn new(index: &'i LedgerIndex<'a>, steps: &'i [DisputeStep]) -> Self {
        Self {
            tree: Accumulator::empty(),
            cursor: 0,
            closes: BTreeSet::new(),
            step: 0,
            disputes: BTreeMap::new(),
            events: index.events(),
            frames: index.frame_hashes(),
            steps,
        }
    }

    /// Folds in every frame and accepted event up to `size` frames. Sizes
    /// never shrink along a valid chain; a smaller size folds nothing.
    fn advance(&mut self, size: u64) -> Option<()> {
        let have = usize::try_from(self.tree.size()).ok()?;
        let want = usize::try_from(size).ok()?;
        // Bounded by the frame list: at most one push per frame.
        for hash in self.frames.iter().take(want).skip(have) {
            self.tree.push(hash).ok()?;
        }
        // Bounded by the event list: the cursor only moves forward.
        for event in self.events.iter().skip(self.cursor) {
            if event.seq.get() > size {
                break;
            }
            self.cursor = self.cursor.checked_add(1)?;
            if event.schema == SCHEMA_BOX_CLOSE {
                self.closes.insert(event.hash.0);
            }
        }
        // Bounded by the step list: the cursor only moves forward.
        for step in self.steps.iter().skip(self.step) {
            if step.seq.get() > size {
                break;
            }
            self.step = self.step.checked_add(1)?;
            self.disputes.insert(step.filing, step.unresolved);
        }
        Some(())
    }

    fn root(&self) -> Hash512 {
        self.tree.root()
    }

    fn close_root(&self) -> Option<Hash512> {
        let hashes: Vec<Hash512> = self.closes.iter().map(|h| Hash512(*h)).collect();
        sorted_set_root(&hashes).ok()
    }

    fn dispute_root(&self) -> Option<Hash512> {
        let hashes: Vec<Hash512> = self
            .disputes
            .iter()
            .filter(|(_, open)| **open)
            .map(|(h, _)| Hash512(*h))
            .collect();
        sorted_set_root(&hashes).ok()
    }
}

/// The pinned genesis's witness roster as `ityv-ledger` entries, for
/// [`witness_set`]. `None` if a witness key does not decode.
#[must_use]
pub fn witness_entries<'a>(genesis: &VerifiedGenesis<'a>) -> Option<Vec<WitnessEntry<'a>>> {
    roster_entries(genesis)
}

/// The witness set a witness tool adopts published checkpoints under
/// (`ityv_ledger::WitnessMemory::adopt`, PROTOCOL.md §5.4): the pinned
/// genesis's hash, election, witness roster (`entries`, from
/// [`witness_entries`]), quorum profile and diversity policy, with the
/// ledger and key-set identifiers the deployment uses (the genesis does not
/// fix them; they are those of the first checkpoint the witness signed).
/// This is how a witness tool should build its set: `WitnessSet::new`
/// trusts whatever roster it is handed. `None` if the genesis's profile or
/// roster is not valid.
#[must_use]
pub fn witness_set<'e>(
    genesis: &VerifiedGenesis<'_>,
    entries: &'e [WitnessEntry<'e>],
    ledger_id: LedgerId<'_>,
    keyset_id: KeysetId<'_>,
) -> Option<WitnessSet<'e>> {
    let q = genesis.genesis().body().quorum();
    WitnessSet::new(
        *genesis.genesis().hash(),
        (genesis.election_id(), ledger_id, keyset_id),
        Roster::new(entries).ok()?,
        QuorumProfile::new(q.witnesses, q.quorum, q.byzantine_max)?,
        DiversityPolicy::new(q.min_orgs, q.min_providers, q.min_regions),
    )
    .ok()
}

/// The genesis witness set as `ityv-ledger`'s roster entries.
fn roster_entries<'a>(genesis: &VerifiedGenesis<'a>) -> Option<Vec<WitnessEntry<'a>>> {
    genesis
        .witnesses()
        .map(|w| {
            Some(WitnessEntry {
                id: w.witness_id,
                org: w.org_id.ident(),
                provider: w.provider,
                region: w.region,
                key: verifying_key(w.key)?,
            })
        })
        .collect()
}

/// Checks one checkpoint against the rules of the module docs, given the
/// previous valid one.
#[allow(clippy::too_many_arguments)] // The rules of the module docs, one input each.
fn check<'a>(
    signed: &SignedCheckpoint<'a>,
    signed_bytes: &[u8],
    frame: Seq,
    prev: Option<(&CheckpointBody<'a>, &Hash512)>,
    genesis: &VerifiedGenesis<'a>,
    policy: &Policy<'_>,
    prefix: &mut Prefix<'_, 'a>,
    timestamps: &TimestampStage<'a>,
) -> Result<VerifiedCheckpoint, CheckpointFindingKind> {
    let roster = policy.roster.map_err(CheckpointFindingKind::Signatures)?;
    let profile = policy.profile.ok_or(CheckpointFindingKind::Signatures(
        LedgerError::ProfileInvalid,
    ))?;
    let published = evaluate(&roster, &profile, &policy.diversity, signed)
        .map_err(CheckpointFindingKind::Signatures)?;
    // The successor rules run on the body the quorum signed.
    let successor = validate_successor(
        prev,
        published.get().signed().body(),
        genesis.genesis().hash(),
    )
    .map_err(CheckpointFindingKind::Successor)?;
    let parts = successor.get().body().parts();
    let tree_size = parts.tree_size.get();
    if tree_size >= frame.get() {
        return Err(CheckpointFindingKind::BeyondOwnFrame);
    }
    prefix
        .advance(tree_size)
        .ok_or(CheckpointFindingKind::Root)?;
    if prefix.root() != parts.root_hash {
        return Err(CheckpointFindingKind::Root);
    }
    if prefix.close_root() != Some(parts.box_close_root) {
        return Err(CheckpointFindingKind::BoxCloseRoot);
    }
    if prefix.dispute_root() != Some(parts.dispute_root) {
        return Err(CheckpointFindingKind::DisputeRoot);
    }
    let event_hash = object_hash(signed_bytes);
    let epoch = timestamps.epoch();
    if timestamps
        .tokens_for(&event_hash)
        .any(|t| t.backdates(epoch, parts.time_bucket))
    {
        return Err(CheckpointFindingKind::Backdated);
    }
    let anchoring = anchoring(
        timestamps
            .tokens_for(&event_hash)
            .filter(|t| t.within_window(epoch, parts.time_bucket)),
    );
    Ok(VerifiedCheckpoint {
        frame,
        checkpoint_seq: parts.checkpoint_seq,
        tree_size,
        root: parts.root_hash,
        body_hash: signed.body_hash(),
        time_bucket: parts.time_bucket,
        event_hash,
        anchoring,
    })
}

/// The witness roster and quorum rule of the genesis.
struct Policy<'r> {
    roster: Result<Roster<'r>, LedgerError>,
    profile: Option<QuorumProfile>,
    diversity: DiversityPolicy,
}

/// Verifies the checkpoint chain of `index` against `genesis`
/// (PROTOCOL.md §14 2).
#[must_use]
pub fn verify_checkpoints<'a>(
    genesis: &VerifiedGenesis<'a>,
    index: &LedgerIndex<'a>,
    authority: &AuthorityStage<'a>,
) -> CheckpointChain<'a> {
    let timestamps = verify_timestamps(genesis, index);
    let mut chain = CheckpointChain {
        checkpoints: Vec::new(),
        findings: Vec::new(),
        unchecked: 0,
        holds: timestamps.holds(),
        timestamps,
    };
    let q = genesis.genesis().body().quorum();
    let entries = roster_entries(genesis).unwrap_or_default();
    let policy = Policy {
        roster: Roster::new(&entries),
        profile: QuorumProfile::new(q.witnesses, q.quorum, q.byzantine_max),
        diversity: DiversityPolicy::new(q.min_orgs, q.min_providers, q.min_regions),
    };
    let steps = verify_disputes(genesis, index, authority).steps;
    let mut prefix = Prefix::new(index, &steps);
    let mut prev: Option<(SignedCheckpoint<'a>, Hash512)> = None;
    let checkpoints = index
        .events()
        .iter()
        .filter(|e| e.schema == SCHEMA_SIGNED_CHECKPOINT);
    for event in checkpoints {
        if !chain.findings.is_empty() {
            chain.unchecked = chain.unchecked.saturating_add(1);
            continue;
        }
        let decoded = event.bytes.and_then(|bytes| {
            decode_object::<SignedCheckpoint<'a>>(SCHEMA_SIGNED_CHECKPOINT, SCHEMA_VERSION_1, bytes)
                .ok()
                .map(|signed| (signed, bytes))
        });
        let result =
            decoded
                .ok_or(CheckpointFindingKind::Undecodable)
                .and_then(|(signed, bytes)| {
                    let before = prev.as_ref().map(|(s, h)| (s.body(), h));
                    check(
                        &signed,
                        bytes,
                        event.seq,
                        before,
                        genesis,
                        &policy,
                        &mut prefix,
                        &chain.timestamps,
                    )
                    .map(|verified| (signed, verified))
                });
        match result {
            Ok((signed, verified)) => {
                prev = Some((signed, verified.body_hash));
                chain.checkpoints.push(verified);
            }
            Err(kind) => {
                chain.findings.push(CheckpointFinding {
                    frame: event.seq,
                    kind,
                });
                let reason = if kind == CheckpointFindingKind::Backdated {
                    HoldReason::TimestampMismatch
                } else {
                    HoldReason::CheckpointInvalid
                };
                chain.holds = chain.holds.with(reason);
            }
        }
    }
    chain
}
