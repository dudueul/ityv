//! The checkpoint chain (PROTOCOL.md §5.3, §5.4, §14 2; VC-011..014): a
//! valid chain over a ledger with a close and a dispute, then one test per
//! rule, each on a chain valid except for that rule, with real hybrid
//! witness signatures.
// Integration tests: outside the TCB. Assertions use unwrap/expect, so these
// lints are relaxed for this file only (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::arithmetic_side_effects
)]

mod common;

use std::sync::OnceLock;
use std::vec::Vec;

use common::{
    COMMISSION, COMMITTEE, NARROW_SIGNERS, SIGNERS, SPARE_BASE, authorized, hybrid_signature, id,
    leak, leak_slice, object, sign, signing, witness_signing,
};
use ityv_crypto::object_hash;
use ityv_encoding::{
    Attestation, BoxClose, BoxCloseBody, BoxCloseParts, BoxId, CheckpointBody, CheckpointParts,
    CloseCounts, DisputeAction, DisputeEventBody, DisputeEventParts, DisputeType, ElectionId,
    EventRole, EventSig, Hash512, KeysetId, LedgerFrame, LedgerId, ModuleCounter, ModuleCounters,
    OrgId, SCHEMA_BOX_CLOSE, SCHEMA_BOX_CLOSE_BODY, SCHEMA_CHECKPOINT_BODY,
    SCHEMA_DISPUTE_EVENT_BODY, SCHEMA_LEDGER_FRAME, SCHEMA_SIGNED_GENESIS,
    SCHEMA_SIGNED_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, SCHEMA_WITNESSED_EVENT, SchemaId, Seq,
    SignerId, SignerRole, TimeBucket, TreeSize, WitnessedEvent,
};
use ityv_ledger::{
    EMPTY_ROOT, Error as LedgerError, SCHEMA_SIGNED_CHECKPOINT, SignedCheckpointParts,
    WitnessSignatureEntry, root_of_leaves, sorted_set_root,
};
use ityv_state::HoldReason;
use ityv_verify::{
    CheckpointChain, CheckpointFindingKind, VerifiedGenesis, authorize_ledger, build_index,
    verify_checkpoints, verify_genesis,
};

/// The standard genesis, pinning a legal authorization (disputes are filed
/// under its `PUBLIC_BOARD` capability), verified once.
fn verified() -> &'static VerifiedGenesis<'static> {
    static VERIFIED: OnceLock<&'static VerifiedGenesis<'static>> = OnceLock::new();
    VERIFIED.get_or_init(|| {
        let built = &authorized().0;
        leak(verify_genesis(&built.pin, &built.input(), &[]).unwrap())
    })
}

fn election() -> ElectionId<'static> {
    common::election()
}

/// A device-signed close of `BOX-1`.
fn close() -> &'static [u8] {
    let mods: [&'static [u8]; 2] = [b"M-B1-P1", b"M-B1-P2"];
    let counters: Vec<ModuleCounter<'static>> = mods
        .iter()
        .map(|m| ModuleCounter {
            module_id: common::module(m),
            counter: 3,
        })
        .collect();
    let body = BoxCloseBody::new(&BoxCloseParts {
        election_id: election(),
        box_id: BoxId::new(b"BOX-1").unwrap(),
        counts: CloseCounts {
            paper: 3,
            records: 3,
            attested: 3,
            without_record: 0,
            challenged: 0,
            quarantined: 0,
            visits: 1,
            envelopes: 0,
            stickers: 0,
            spoil_envelopes: 0,
        },
        record_set_root: Hash512([0x23; 64]),
        journal_head: Hash512([0x24; 64]),
        seal_digest: Hash512([0x25; 64]),
        module_counters: ModuleCounters::new(&counters).unwrap(),
        open_batches: 0,
        time_bucket: TimeBucket::new(50),
    });
    let body = object(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, &body);
    let device = sign(signing(100), b"box-close", body);
    let person = |id: &'static [u8], role, o: &'static [u8]| Attestation {
        signer_id: SignerId::new(id).unwrap(),
        role,
        org_id: OrgId::new(o).unwrap(),
        sig: device,
    };
    let attestations = [
        person(b"clerk-1", SignerRole::Clerk, b"ORG-ST"),
        person(b"clerk-2", SignerRole::Clerk, b"ORG-ST2"),
        person(b"obs-a", SignerRole::Observer, b"PARTY-A"),
        person(b"obs-b", SignerRole::Observer, b"PARTY-B"),
    ];
    let close = BoxClose::new(body, Some(device), &attestations).unwrap();
    object(SCHEMA_BOX_CLOSE, SCHEMA_VERSION_1, &close)
}

/// A dispute event body: the filing when `filing` is `None`, otherwise a
/// later event of `action` naming it, signed by the commission and the
/// committee. Returns (body bytes, event bytes).
fn dispute(action: DisputeAction, filing: Option<Hash512>) -> (&'static [u8], &'static [u8]) {
    dispute_with(action, filing, Hash512([0x3E; 64]), false)
}

/// As [`dispute`], with the evidence hash `evidence`; `forged` signs with
/// keys of its own instead of the two authorities'.
fn dispute_with(
    action: DisputeAction,
    filing: Option<Hash512>,
    evidence: Hash512,
    forged: bool,
) -> (&'static [u8], &'static [u8]) {
    let result = match action {
        DisputeAction::ResolvedTechnical | DisputeAction::ReferredLegal => Hash512([0x3A; 64]),
        DisputeAction::Filed | DisputeAction::Investigating => Hash512::ZERO,
    };
    let body = DisputeEventBody::new(&DisputeEventParts {
        election_id: election(),
        action,
        dispute_type: DisputeType::Custody,
        box_id: Some(BoxId::new(b"BOX-1").unwrap()),
        record_hash: None,
        evidence_hash: evidence,
        filing_hash: filing.unwrap_or(Hash512::ZERO),
        result_hash: result,
        time_bucket: TimeBucket::new(60),
    })
    .unwrap();
    let body = object(SCHEMA_DISPUTE_EVENT_BODY, SCHEMA_VERSION_1, &body);
    let (commission, committee) = if forged {
        (SPARE_BASE, SPARE_BASE + 1)
    } else {
        (COMMISSION, COMMITTEE)
    };
    let sigs = [
        EventSig {
            signer_id: SignerId::new(b"commission").unwrap(),
            role: EventRole::Commission,
            org_id: OrgId::new(b"NEC").unwrap(),
            sig: sign(signing(commission), b"dispute", body),
        },
        EventSig {
            signer_id: SignerId::new(b"committee").unwrap(),
            role: EventRole::Committee,
            org_id: OrgId::new(b"IVC").unwrap(),
            sig: sign(signing(committee), b"dispute", body),
        },
    ];
    let event = WitnessedEvent::new(body, &sigs).unwrap();
    (
        body,
        object(
            SCHEMA_WITNESSED_EVENT,
            ityv_encoding::SCHEMA_VERSION_WITNESSED,
            &event,
        ),
    )
}

/// A frame stream builder: frames chained in order.
struct Ledger {
    stream: Vec<u8>,
    frames: Vec<&'static [u8]>,
    events: Vec<&'static [u8]>,
    prev: Hash512,
    seq: u64,
}

impl Ledger {
    fn new() -> Self {
        Self {
            stream: Vec::new(),
            frames: Vec::new(),
            events: Vec::new(),
            prev: Hash512::ZERO,
            seq: 0,
        }
    }

    /// Appends a frame carrying `event` as `schema`; returns its seq.
    fn push(&mut self, schema: SchemaId, event: &'static [u8]) -> u64 {
        self.seq += 1;
        let frame = LedgerFrame::new(
            election(),
            Seq::new(self.seq).unwrap(),
            self.prev,
            schema,
            object_hash(event),
        );
        let bytes = object(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &frame);
        self.prev = object_hash(bytes);
        self.stream
            .extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
        self.stream.extend_from_slice(bytes);
        self.frames.push(bytes);
        self.events.push(event);
        self.seq
    }

    /// The ledger root over the first `size` frames.
    fn root(&self, size: usize) -> Hash512 {
        let hashes: Vec<Hash512> = self.frames[..size].iter().map(|f| object_hash(f)).collect();
        root_of_leaves(&hashes.as_slice(), size as u64).unwrap()
    }

    /// The chain of the ledger with the legal authorization appended after
    /// every frame the test pushed, so that the frame numbers a test names
    /// are those of its own frames.
    fn chain(&self) -> CheckpointChain {
        let mut ledger = Ledger {
            stream: self.stream.clone(),
            frames: self.frames.clone(),
            events: self.events.clone(),
            prev: self.prev,
            seq: self.seq,
        };
        ledger.push(SCHEMA_SIGNED_LEGAL_AUTHORIZATION, authorized().1);
        let index = leak(build_index(
            verified(),
            leak_slice(ledger.stream.clone()),
            &ledger.events,
        ));
        assert!(index.findings().is_empty(), "{:?}", index.findings());
        let authority = leak(authorize_ledger(verified(), index));
        assert!(authority.holds().is_empty(), "{:?}", authority.holds());
        verify_checkpoints(verified(), index, authority)
    }
}

/// The sorted-set root of `hashes`.
fn set_root(mut hashes: Vec<Hash512>) -> Hash512 {
    hashes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    sorted_set_root(&hashes).unwrap()
}

/// What a checkpoint body says.
#[derive(Clone, Copy)]
struct Claim {
    seq: u64,
    tree_size: u64,
    root: Hash512,
    previous: Hash512,
    box_close_root: Hash512,
    dispute_root: Hash512,
    genesis: Hash512,
    election: ElectionId<'static>,
    ledger: &'static [u8],
}

/// The checkpoint body bytes of `claim`.
fn body(claim: &Claim) -> &'static [u8] {
    let body = CheckpointBody::new(&CheckpointParts {
        election_id: claim.election,
        ledger_id: LedgerId::new(claim.ledger).unwrap(),
        keyset_id: KeysetId::new(b"K-1").unwrap(),
        checkpoint_seq: Seq::new(claim.seq).unwrap(),
        tree_size: TreeSize::new(claim.tree_size),
        root_hash: claim.root,
        previous_checkpoint_hash: claim.previous,
        box_close_root: claim.box_close_root,
        dispute_root: claim.dispute_root,
        genesis_hash: claim.genesis,
        time_bucket: TimeBucket::new(70),
    })
    .unwrap();
    object(SCHEMA_CHECKPOINT_BODY, SCHEMA_VERSION_1, &body)
}

/// `body` signed by the witnesses `who` (identifiers ascending), each entry
/// a (witness identifier, signing witness index) pair.
fn signed_by(body: &'static [u8], who: &[(&'static [u8], usize)]) -> &'static [u8] {
    let entries: Vec<WitnessSignatureEntry<'static>> = who
        .iter()
        .map(|&(name, signer)| WitnessSignatureEntry {
            witness_id: id(name),
            signature: hybrid_signature(witness_signing(signer), b"checkpoint", body),
        })
        .collect();
    let entries = leak_slice(entries);
    let parts = SignedCheckpointParts::new(body, entries).unwrap();
    object(SCHEMA_SIGNED_CHECKPOINT, SCHEMA_VERSION_1, &parts)
}

/// The witness identifiers of the indices `who`, each signing itself.
fn witnesses(who: &[usize]) -> Vec<(&'static [u8], usize)> {
    who.iter().map(|&i| (common::WITNESS_IDS[i], i)).collect()
}

/// The checkpoint of `claim`, signed by the default nine witnesses.
fn checkpoint(claim: &Claim) -> &'static [u8] {
    signed_by(body(claim), &witnesses(&SIGNERS))
}

/// The object hash of a checkpoint body.
fn body_hash(claim: &Claim) -> Hash512 {
    object_hash(body(claim))
}

/// A ledger of: the genesis, a close of BOX-1, a dispute filing, and the
/// first checkpoint's claim over those three frames.
struct Scene {
    ledger: Ledger,
    close: Hash512,
    filing: Hash512,
    first: Claim,
}

fn scene() -> Scene {
    let mut ledger = Ledger::new();
    ledger.push(SCHEMA_SIGNED_GENESIS, authorized().0.signed);
    let close = close();
    ledger.push(SCHEMA_BOX_CLOSE, close);
    let (filing_body, filing) = dispute(DisputeAction::Filed, None);
    ledger.push(SCHEMA_WITNESSED_EVENT, filing);
    let filing = object_hash(filing_body);
    let close = object_hash(close);
    let first = Claim {
        seq: 1,
        tree_size: 3,
        root: ledger.root(3),
        previous: Hash512::ZERO,
        box_close_root: set_root(std::vec![close]),
        dispute_root: set_root(std::vec![filing]),
        genesis: authorized().0.pin,
        election: election(),
        ledger: b"L-1",
    };
    Scene {
        ledger,
        close,
        filing,
        first,
    }
}

/// The finding of a chain whose only checkpoint is `claim` signed by
/// `signed` (on top of the scene).
fn first_finding(signed: &'static [u8]) -> (CheckpointChain, u64) {
    let mut s = scene();
    let frame = s.ledger.push(SCHEMA_SIGNED_CHECKPOINT, signed);
    (s.ledger.chain(), frame)
}

fn kind_of(chain: &CheckpointChain) -> CheckpointFindingKind {
    assert_eq!(chain.findings().len(), 1, "{chain:?}");
    assert!(chain.holds().contains(HoldReason::CheckpointInvalid));
    chain.findings()[0].kind
}

#[test]
fn accepts_a_chain_whose_roots_the_ledger_gives() {
    let mut s = scene();
    let first = s.first;
    let f1 = s.ledger.push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&first));
    let (_, resolution) = dispute(DisputeAction::ResolvedTechnical, Some(s.filing));
    s.ledger.push(SCHEMA_WITNESSED_EVENT, resolution);
    let second = Claim {
        seq: 2,
        tree_size: 5,
        root: s.ledger.root(5),
        previous: body_hash(&first),
        box_close_root: set_root(std::vec![s.close]),
        dispute_root: EMPTY_ROOT,
        ..first
    };
    let f2 = s.ledger.push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&second));
    let chain = s.ledger.chain();
    assert!(chain.findings().is_empty(), "{chain:?}");
    assert!(chain.holds().is_empty());
    assert_eq!(chain.unchecked(), 0);
    assert_eq!(chain.checkpoints().len(), 2);
    let c = chain.checkpoints();
    assert_eq!(
        (c[0].frame.get(), c[0].checkpoint_seq.get(), c[0].tree_size),
        (f1, 1, 3)
    );
    assert_eq!(
        (c[1].frame.get(), c[1].checkpoint_seq.get(), c[1].tree_size),
        (f2, 2, 5)
    );
    assert_eq!(c[0].root, first.root);
    assert_eq!(c[1].body_hash, body_hash(&second));
    assert_eq!(chain.covered(), 5);
    assert_eq!(chain.last(), Some(&c[1]));
}

#[test]
fn an_empty_ledger_has_no_chain_and_nothing_wrong() {
    let ledger = Ledger::new();
    let chain = ledger.chain();
    assert_eq!(chain.covered(), 0);
    assert!(chain.last().is_none());
    assert!(chain.findings().is_empty());
    assert!(chain.holds().is_empty());
    // A ledger without checkpoints is no different.
    let s = scene();
    assert_eq!(s.ledger.chain().covered(), 0);
}

#[test]
fn refuses_a_signature_that_does_not_verify() {
    let s = scene();
    let b = body(&s.first);
    // W02's entry carries W03's signature.
    let mut who = witnesses(&SIGNERS);
    who[1].1 = 2;
    let (chain, frame) = first_finding(signed_by(b, &who));
    assert_eq!(
        kind_of(&chain),
        CheckpointFindingKind::Signatures(LedgerError::InvalidSignature { index: 1 })
    );
    assert_eq!(chain.findings()[0].frame.get(), frame);
    assert!(chain.checkpoints().is_empty());
}

#[test]
fn refuses_too_few_or_too_narrow_or_unknown_signers() {
    let s = scene();
    let b = body(&s.first);
    let (chain, _) = first_finding(signed_by(b, &witnesses(&SIGNERS[..8])));
    assert!(matches!(
        kind_of(&chain),
        CheckpointFindingKind::Signatures(LedgerError::QuorumShort { .. })
    ));
    let (chain, _) = first_finding(signed_by(b, &witnesses(&NARROW_SIGNERS)));
    assert!(matches!(
        kind_of(&chain),
        CheckpointFindingKind::Signatures(LedgerError::DiversityShort { .. })
    ));
    let mut who = witnesses(&SIGNERS);
    who.push((b"W99", 9));
    let (chain, _) = first_finding(signed_by(b, &who));
    assert_eq!(
        kind_of(&chain),
        CheckpointFindingKind::Signatures(LedgerError::UnknownWitness { index: 9 })
    );
}

/// The finding of a second checkpoint `second` after a valid first.
fn second_finding(second: impl FnOnce(&Scene, &Claim) -> Claim) -> CheckpointChain {
    let mut s = scene();
    let first = s.first;
    s.ledger.push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&first));
    let next = second(&s, &first);
    s.ledger.push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&next));
    let chain = s.ledger.chain();
    assert_eq!(chain.checkpoints().len(), 1, "{chain:?}");
    chain
}

/// A valid second checkpoint over the scene (the first one's frame
/// included).
fn valid_second(s: &Scene, first: &Claim) -> Claim {
    Claim {
        seq: 2,
        tree_size: 4,
        root: s.ledger.root(4),
        previous: body_hash(first),
        ..*first
    }
}

#[test]
fn refuses_a_checkpoint_that_does_not_follow() {
    let chain = second_finding(|s, f| Claim {
        seq: 3,
        ..valid_second(s, f)
    });
    assert_eq!(
        kind_of(&chain),
        CheckpointFindingKind::Successor(LedgerError::SequenceGap)
    );
    let chain = second_finding(|s, f| Claim {
        previous: Hash512([0x44; 64]),
        ..valid_second(s, f)
    });
    assert_eq!(
        kind_of(&chain),
        CheckpointFindingKind::Successor(LedgerError::PreviousHashMismatch)
    );
    let chain = second_finding(|s, f| Claim {
        tree_size: 2,
        root: s.ledger.root(2),
        ..valid_second(s, f)
    });
    assert_eq!(
        kind_of(&chain),
        CheckpointFindingKind::Successor(LedgerError::TreeShrank)
    );
    let chain = second_finding(|s, f| Claim {
        ledger: b"L-2",
        ..valid_second(s, f)
    });
    assert_eq!(
        kind_of(&chain),
        CheckpointFindingKind::Successor(LedgerError::LedgerMismatch)
    );
    // A checkpoint of another election never reaches this stage: the
    // index refuses it (OtherElection).
}

#[test]
fn refuses_a_checkpoint_of_another_genesis() {
    let s = scene();
    let (chain, _) = first_finding(checkpoint(&Claim {
        genesis: Hash512([0x55; 64]),
        ..s.first
    }));
    assert_eq!(
        kind_of(&chain),
        CheckpointFindingKind::Successor(LedgerError::GenesisMismatch)
    );
    // A first checkpoint with a previous hash cannot be built: the body
    // constructor and decoder refuse it.
}

#[test]
fn refuses_a_checkpoint_of_its_own_frame() {
    // The checkpoint is frame 5: it may cover at most frames 1..=4.
    let mut s = scene();
    let filler = dispute(DisputeAction::Investigating, Some(s.filing)).1;
    s.ledger.push(SCHEMA_WITNESSED_EVENT, filler);
    let claim = Claim {
        tree_size: 5,
        root: Hash512([0x66; 64]),
        ..s.first
    };
    let frame = s.ledger.push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&claim));
    assert_eq!(frame, 5);
    let chain = s.ledger.chain();
    assert_eq!(kind_of(&chain), CheckpointFindingKind::BeyondOwnFrame);
    // One frame before its own is fine.
    let mut s = scene();
    let claim = Claim {
        tree_size: 3,
        ..s.first
    };
    s.ledger.push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&claim));
    assert_eq!(s.ledger.chain().covered(), 3);
}

#[test]
fn refuses_roots_the_ledger_does_not_give() {
    let s = scene();
    let (chain, _) = first_finding(checkpoint(&Claim {
        root: s.ledger.root(2),
        ..s.first
    }));
    assert_eq!(kind_of(&chain), CheckpointFindingKind::Root);
    let (chain, _) = first_finding(checkpoint(&Claim {
        box_close_root: EMPTY_ROOT,
        ..s.first
    }));
    assert_eq!(kind_of(&chain), CheckpointFindingKind::BoxCloseRoot);
    let (chain, _) = first_finding(checkpoint(&Claim {
        dispute_root: EMPTY_ROOT,
        ..s.first
    }));
    assert_eq!(kind_of(&chain), CheckpointFindingKind::DisputeRoot);
    // Frames up to the tree size count, later ones do not: a close in a
    // frame after the claimed size is not in the root.
    let (chain, _) = first_finding(checkpoint(&Claim {
        tree_size: 2,
        root: s.ledger.root(2),
        dispute_root: EMPTY_ROOT,
        ..s.first
    }));
    assert!(chain.findings().is_empty(), "{chain:?}");
}

#[test]
fn a_resolved_dispute_leaves_the_root_and_a_referral_brings_it_back() {
    // Resolved: still claiming the filing is open is wrong.
    let mut s = scene();
    let first = s.first;
    s.ledger.push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&first));
    let (_, resolution) = dispute(DisputeAction::ResolvedTechnical, Some(s.filing));
    s.ledger.push(SCHEMA_WITNESSED_EVENT, resolution);
    let still_open = Claim {
        seq: 2,
        tree_size: 5,
        root: s.ledger.root(5),
        previous: body_hash(&first),
        ..first
    };
    s.ledger
        .push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&still_open));
    assert_eq!(
        kind_of(&s.ledger.chain()),
        CheckpointFindingKind::DisputeRoot
    );

    // Resolved, then referred: unresolved again.
    let mut s = scene();
    let first = s.first;
    s.ledger.push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&first));
    let (_, resolution) = dispute(DisputeAction::ResolvedTechnical, Some(s.filing));
    s.ledger.push(SCHEMA_WITNESSED_EVENT, resolution);
    let (_, referral) = dispute(DisputeAction::ReferredLegal, Some(s.filing));
    s.ledger.push(SCHEMA_WITNESSED_EVENT, referral);
    let reopened = Claim {
        seq: 2,
        tree_size: 6,
        root: s.ledger.root(6),
        previous: body_hash(&first),
        ..first
    };
    s.ledger
        .push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&reopened));
    let chain = s.ledger.chain();
    assert!(chain.findings().is_empty(), "{chain:?}");
    assert_eq!(chain.covered(), 6);

    let mut s = scene();
    let first = s.first;
    s.ledger.push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&first));
    s.ledger.push(SCHEMA_WITNESSED_EVENT, resolution);
    s.ledger.push(SCHEMA_WITNESSED_EVENT, referral);
    let wrong = Claim {
        dispute_root: EMPTY_ROOT,
        ..reopened
    };
    s.ledger.push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&wrong));
    assert_eq!(
        kind_of(&s.ledger.chain()),
        CheckpointFindingKind::DisputeRoot
    );

    // An investigation changes nothing, and an event naming a filing never
    // seen is left to the dispute stage.
    let mut s = scene();
    let first = s.first;
    s.ledger.push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&first));
    let (_, investigating) = dispute(DisputeAction::Investigating, Some(s.filing));
    s.ledger.push(SCHEMA_WITNESSED_EVENT, investigating);
    let (_, stray) = dispute(DisputeAction::ResolvedTechnical, Some(Hash512([0x77; 64])));
    s.ledger.push(SCHEMA_WITNESSED_EVENT, stray);
    let open = Claim {
        seq: 2,
        tree_size: 6,
        root: s.ledger.root(6),
        previous: body_hash(&first),
        ..first
    };
    s.ledger.push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&open));
    assert!(s.ledger.chain().findings().is_empty());
}

#[test]
fn the_chain_stops_at_the_first_invalid_checkpoint() {
    let mut s = scene();
    let first = s.first;
    // The first checkpoint has a wrong root.
    let bad = Claim {
        root: Hash512([0x66; 64]),
        ..first
    };
    s.ledger.push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&bad));
    // Two more checkpoints that would be valid after a valid first.
    let second = Claim {
        seq: 2,
        tree_size: 4,
        root: s.ledger.root(4),
        previous: body_hash(&bad),
        ..first
    };
    s.ledger.push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&second));
    let third = Claim {
        seq: 3,
        tree_size: 5,
        root: s.ledger.root(5),
        previous: body_hash(&second),
        ..first
    };
    s.ledger.push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&third));
    let chain = s.ledger.chain();
    assert_eq!(kind_of(&chain), CheckpointFindingKind::Root);
    assert_eq!(chain.findings()[0].frame.get(), 4);
    assert!(chain.checkpoints().is_empty());
    assert_eq!(chain.unchecked(), 2);
    assert_eq!(chain.covered(), 0);
}

#[test]
fn a_checkpoint_after_a_valid_one_is_checked_from_where_the_first_stopped() {
    // The second checkpoint covers frames the first did not; its roots
    // fold in the frames between the two tree sizes only once.
    let mut s = scene();
    let first = Claim {
        tree_size: 1,
        root: s.ledger.root(1),
        box_close_root: EMPTY_ROOT,
        dispute_root: EMPTY_ROOT,
        ..s.first
    };
    s.ledger.push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&first));
    let second = Claim {
        seq: 2,
        tree_size: 4,
        root: s.ledger.root(4),
        previous: body_hash(&first),
        box_close_root: set_root(std::vec![s.close]),
        dispute_root: set_root(std::vec![s.filing]),
        ..first
    };
    s.ledger.push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&second));
    let chain = s.ledger.chain();
    assert!(chain.findings().is_empty(), "{chain:?}");
    assert_eq!(chain.covered(), 4);
}

#[test]
fn a_dispute_leaves_the_root_only_by_a_signed_forward_transition() {
    // Each case: events after the scene's filing that must leave the
    // dispute unresolved. A checkpoint claiming it unresolved is valid; one
    // claiming it gone is refused.
    let filing = scene().filing;
    let referral = dispute(DisputeAction::ReferredLegal, Some(filing)).1;
    let resolution = dispute(DisputeAction::ResolvedTechnical, Some(filing)).1;
    let forged = dispute_with(
        DisputeAction::ResolvedTechnical,
        Some(filing),
        Hash512([0x3E; 64]),
        true,
    )
    .1;
    let other_evidence = dispute_with(
        DisputeAction::ResolvedTechnical,
        Some(filing),
        Hash512([0x3F; 64]),
        false,
    )
    .1;
    let cases: [&[&'static [u8]]; 3] = [
        // Referred to the legal track, then "resolved": forward only.
        &[referral, resolution],
        // A resolution the two authorities did not sign.
        &[forged],
        // A resolution that changes the evidence.
        &[other_evidence],
    ];
    for events in cases {
        for still_open in [true, false] {
            let mut s = scene();
            let first = s.first;
            s.ledger.push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&first));
            for e in events {
                s.ledger.push(SCHEMA_WITNESSED_EVENT, e);
            }
            let size = s.ledger.seq;
            let claim = Claim {
                seq: 2,
                tree_size: size,
                root: s.ledger.root(usize::try_from(size).unwrap()),
                previous: body_hash(&first),
                dispute_root: if still_open {
                    set_root(std::vec![filing])
                } else {
                    EMPTY_ROOT
                },
                ..first
            };
            s.ledger.push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&claim));
            let chain = s.ledger.chain();
            if still_open {
                assert!(chain.findings().is_empty(), "{chain:?}");
                assert_eq!(chain.covered(), size);
            } else {
                assert_eq!(kind_of(&chain), CheckpointFindingKind::DisputeRoot);
            }
        }
    }
}

#[test]
fn a_filing_the_authorities_did_not_sign_opens_no_dispute() {
    let mut s = scene();
    let (body, forged) = dispute_with(DisputeAction::Filed, None, Hash512([0x40; 64]), true);
    s.ledger.push(SCHEMA_WITNESSED_EVENT, forged);
    let claim = Claim {
        tree_size: 4,
        root: s.ledger.root(4),
        ..s.first
    };
    s.ledger.push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&claim));
    assert!(s.ledger.chain().findings().is_empty());
    // Claiming it open is wrong.
    let mut s = scene();
    s.ledger.push(SCHEMA_WITNESSED_EVENT, forged);
    let claim = Claim {
        tree_size: 4,
        root: s.ledger.root(4),
        dispute_root: set_root(std::vec![s.filing, object_hash(body)]),
        ..s.first
    };
    s.ledger.push(SCHEMA_SIGNED_CHECKPOINT, checkpoint(&claim));
    assert_eq!(
        kind_of(&s.ledger.chain()),
        CheckpointFindingKind::DisputeRoot
    );
}
