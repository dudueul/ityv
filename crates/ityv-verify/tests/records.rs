//! The record stage (PROTOCOL.md §7.2.1, §7.5, §7.6, §14 5; VC-025..027,
//! VC-053, VC-057): every cast record's OR proof and record signatures,
//! every batch attestation's signatures, membership, count, root and
//! counter ranges, the `UNATTESTED` list and the close's record set root,
//! on records built with real proofs and real signatures.
// Integration tests: outside the TCB. Assertions use unwrap/expect, so these
// lints are relaxed for this file only (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

mod common;

use std::sync::OnceLock;
use std::vec::Vec;

use common::{
    BOX_DEVICE_BASE, Draft, Ledger, ROSTER_BASE, SIGNERS, leak, leak_slice, module_signing,
    modules, object, sign, sign_genesis_with, signing,
};
use ityv_crypto::{
    Bases, CastId, ChunkIndex, Commitment, MAX_CHUNKS, Opening, OptionCount, OptionIndex,
    RecordPurpose, Scalar, Sha3Hasher, Statement, commit, object_hash, prove, sign_ed25519_half,
};
use ityv_encoding::{
    Attestation, BallotStyleId, BatchAttest, BatchAttestBody, BatchAttestParts, BoxClose,
    BoxCloseBody, BoxCloseParts, BoxId, BoxOpenedBody, BoxOpenedParts, CastRecord, CastRecordBody,
    CastRecordParts, ChamberCode, CloseCounts, Commitments, ElectionId, Encode, EventRole,
    EventSig, Hash512, Ident, LateBatchCloseBody, LateBatchCloseParts, LateBatchReason,
    ModuleBatchSig, ModuleCounter, ModuleCounters, ModuleIds, ModuleRange, ModuleRecordSig, OrgId,
    Point32, SCHEMA_BATCH_ATTEST, SCHEMA_BATCH_ATTEST_BODY, SCHEMA_BOX_CLOSE,
    SCHEMA_BOX_CLOSE_BODY, SCHEMA_BOX_OPENED_BODY, SCHEMA_CAST_RECORD, SCHEMA_CAST_RECORD_BODY,
    SCHEMA_LATE_BATCH_CLOSE_BODY, SCHEMA_SIGNED_GENESIS, SCHEMA_SIGNED_LEGAL_AUTHORIZATION,
    SCHEMA_VERSION_1, SCHEMA_WITNESSED_EVENT, SchemaId, Scope, SignerId, SignerRole, TimeBucket,
    Token192, WitnessedEvent, Writer, purpose_of,
};
use ityv_ledger::sorted_set_root;
use ityv_state::{HoldReason, HoldSet, RecordStatus};
use ityv_verify::{
    AuthorityStage, BatchFinding, BatchProblem, BoxRecords, BoxStage, LedgerIndex, RecordRefusal,
    RecordStage, VerifiedGenesis, authorize_ledger, build_index, verify_boxes, verify_genesis,
    verify_records,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};

const BOX: &[u8] = b"BOX-1";
const P1: &[u8] = b"M-B1-P1";
const P2: &[u8] = b"M-B1-P2";
const J: &[u8] = b"M-B1-J";
const SEAL: Hash512 = Hash512([0x5e; 64]);
const STYLE: &[u8] = b"STYLE-1";
/// `STYLE-1` has five choices: seven options, one chunk.
const OPTIONS: u16 = 7;
/// The key numbers of the module entries (`module_entry(n, …)`).
const P1_KEY: u16 = 0;
const P2_KEY: u16 = 1;
const B2_P1_KEY: u16 = 2;
/// A module entry added by the amendments of these tests.
const J_KEY: u16 = 16;
/// A key the amendments of these tests register for `M-B1-P2`.
const NEW_P2: u16 = 920;
const CLOSE_BUCKET: u64 = 140;

fn election() -> ElectionId<'static> {
    common::election()
}

fn box_id() -> BoxId<'static> {
    BoxId::new(BOX).unwrap()
}

/// The people of the roster: identifier, organisation, key number.
const PEOPLE: [(&[u8], &[u8], u16); 4] = [
    (b"clerk-1", b"ORG-ST", 0),
    (b"clerk-2", b"ORG-ST", 1),
    (b"obs-a", b"PARTY-A", 2),
    (b"obs-b", b"PARTY-B", 3),
];

fn person(id: &[u8]) -> (&'static [u8], u16) {
    let p = PEOPLE.iter().find(|p| p.0 == id).unwrap();
    (p.1, ROSTER_BASE + p.2)
}

/// The genesis (and amendments) a test runs on.
struct World {
    genesis: &'static VerifiedGenesis<'static>,
    signed_genesis: &'static [u8],
    authorization: &'static [u8],
    amendment: Option<&'static [u8]>,
}

/// The standard genesis pinning a legal authorization of `PUBLIC_BOARD`,
/// `TRUSTEE_BODY` and `BALLOT_MARK`, with one amendment made by `amend`
/// when given.
fn world_with(amend: Option<fn(&mut Draft)>) -> World {
    let draft = Draft::standard();
    let (body, authorization) = common::legal_authorization(
        &[Scope::PublicBoard, Scope::TrusteeBody, Scope::BallotMark],
        20_000,
        20_100,
    );
    let built = leak(sign_genesis_with(&draft, draft.raw(), &SIGNERS, |p| {
        p.legal_authorization_hash = object_hash(body);
    }));
    let (amendments, amendment) = match amend {
        Some(f) => {
            let mut next = draft.clone();
            f(&mut next);
            next.appointments = next.referenced_appointments();
            let a = common::amendment(1, built.pin, &next.raw(), &SIGNERS);
            (std::vec![a], Some(a.signed))
        }
        None => (Vec::new(), None),
    };
    let genesis = leak(verify_genesis(&built.pin, &built.input(), &amendments).unwrap());
    World {
        genesis,
        signed_genesis: built.signed,
        authorization,
        amendment,
    }
}

fn world() -> &'static World {
    static WORLD: OnceLock<&'static World> = OnceLock::new();
    WORLD.get_or_init(|| leak(world_with(None)))
}

// ---------------------------------------------------------------------
// Events, with real proofs and signatures.

const WITNESSES: [(&[u8], EventRole); 4] = [
    (b"clerk-1", EventRole::Clerk),
    (b"clerk-2", EventRole::Clerk),
    (b"obs-a", EventRole::Observer),
    (b"obs-b", EventRole::Observer),
];

/// A `WitnessedEvent` over `body` of `schema`, signed by the four
/// witnesses and, when `device`, by the box's device.
fn witnessed(schema: SchemaId, body: &'static [u8], device: bool) -> &'static [u8] {
    let purpose = purpose_of(schema).unwrap();
    let mut parts: Vec<(&'static [u8], EventRole, &'static [u8], u16)> = WITNESSES
        .iter()
        .map(|&(id, role)| {
            let (o, n) = person(id);
            (id, role, o, n)
        })
        .collect();
    if device {
        parts.push((BOX, EventRole::Device, b"ORG-ST", BOX_DEVICE_BASE));
    }
    parts.sort_by(|a, b| a.0.cmp(b.0));
    let sigs: Vec<EventSig<'static>> = parts
        .iter()
        .map(|&(id, role, o, n)| EventSig {
            signer_id: SignerId::new(id).unwrap(),
            role,
            org_id: OrgId::new(o).unwrap(),
            sig: sign(signing(n), purpose, body),
        })
        .collect();
    object(
        SCHEMA_WITNESSED_EVENT,
        SCHEMA_VERSION_1,
        &WitnessedEvent::new(body, &sigs).unwrap(),
    )
}

fn opened_with(mods: &[&'static [u8]]) -> &'static [u8] {
    let body = BoxOpenedBody::new(&BoxOpenedParts {
        election_id: election(),
        box_id: box_id(),
        modules: modules(mods),
        seal_digest: SEAL,
        seals_match: true,
        initial_count: 0,
        time_bucket: TimeBucket::new(100),
    });
    let body = object(SCHEMA_BOX_OPENED_BODY, SCHEMA_VERSION_1, &body);
    witnessed(SCHEMA_BOX_OPENED_BODY, body, true)
}

fn opened() -> &'static [u8] {
    opened_with(&[P1, P2])
}

/// A cast record to build.
#[derive(Clone, Copy)]
struct Rec {
    /// The option the proof proves.
    option: u16,
    /// Seeds the cast identifier, the randomness and the proof.
    seed: u64,
    /// The ballot style the body names.
    style: &'static [u8],
    /// The box the proof's statement names.
    proof_box: &'static [u8],
    /// The key number of the device's record signature.
    device: u16,
    /// (module, counter, key number of its record signature), ascending.
    mods: &'static [(&'static [u8], u64, u16)],
}

/// A clean record of the box with both module counters `counter`.
fn rec(counter: u64) -> Rec {
    Rec {
        option: 2,
        seed: counter,
        style: STYLE,
        proof_box: BOX,
        device: BOX_DEVICE_BASE,
        mods: leak_slice(std::vec![(P1, counter, P1_KEY), (P2, counter, P2_KEY)]),
    }
}

/// The module record message `body_hash ‖ module_id ‖ counter`.
fn module_message(body_hash: &Hash512, module: &'static [u8], counter: u64) -> Vec<u8> {
    let mut buf = [0u8; 140];
    let mut w = Writer::new(&mut buf);
    body_hash.encode(&mut w).unwrap();
    common::module(module).encode(&mut w).unwrap();
    w.write_u64(counter).unwrap();
    let len = w.finish();
    buf[..len].to_vec()
}

/// The secrets of a record as the device derives them (PROTOCOL.md §7.3):
/// each module's cast-id contribution and randomness, the cast id
/// `SHA3-512("ityv:castid:v1" ‖ 0x00 ‖ cid_1 ‖ …)[0..24]` and the summed
/// randomness.
struct Secrets {
    cids: Vec<[u8; 24]>,
    rands: Vec<Vec<Scalar>>,
    cast_id: CastId,
    rand: [Scalar; MAX_CHUNKS],
    /// The stream, to go on with the proof.
    rng: ChaCha20Rng,
}

fn secrets(r: &Rec) -> Secrets {
    let mut rng = ChaCha20Rng::seed_from_u64(r.seed);
    let chunks = usize::from(OptionCount::new(OPTIONS).unwrap().chunk_count());
    let mut hasher = Sha3Hasher::new();
    hasher.absorb(b"ityv:castid:v1");
    hasher.absorb(&[0x00]);
    let mut cids = Vec::new();
    let mut rands = Vec::new();
    let mut rand = [Scalar::ZERO; MAX_CHUNKS];
    for _ in r.mods {
        let mut cid = [0u8; 24];
        rng.fill_bytes(&mut cid);
        hasher.absorb(&cid);
        let part: Vec<Scalar> = (0..chunks).map(|_| Scalar::random(&mut rng)).collect();
        for (sum, p) in rand.iter_mut().zip(&part) {
            *sum = sum.add(p);
        }
        cids.push(cid);
        rands.push(part);
    }
    let digest = hasher.finish();
    Secrets {
        cids,
        rands,
        cast_id: CastId::new(Token192(digest[..24].try_into().unwrap())),
        rand,
        rng,
    }
}

/// The record object of `r`.
fn record(r: &Rec) -> &'static [u8] {
    let bases = Bases::derive();
    let Secrets {
        cast_id,
        rand,
        mut rng,
        ..
    } = secrets(r);
    let options = OptionCount::new(OPTIONS).unwrap();
    let chunks = options.chunk_count();
    let option = OptionIndex::new(r.option).unwrap();
    let commitments: Vec<Commitment> = (0..chunks)
        .map(|j| {
            commit(
                &bases,
                option,
                &cast_id,
                &rand[usize::from(j)],
                ChunkIndex::new(j).unwrap(),
            )
        })
        .collect();
    let statement = Statement::new(
        election(),
        Ident::new(r.proof_box, 64).unwrap(),
        Ident::new(r.style, 64).unwrap(),
        options,
        &commitments,
    )
    .unwrap();
    let proof = prove(
        &bases,
        &statement,
        &Opening::new(option, cast_id, rand),
        &mut rng,
    )
    .unwrap();
    let mut buf = std::vec![0u8; proof.encoded_len()];
    let mut w = Writer::new(&mut buf);
    proof.encode(&mut w).unwrap();
    let proof_bytes = leak_slice(buf);
    let points: Vec<Point32> = commitments.iter().map(|c| c.to_point32()).collect();
    let counters: Vec<ModuleCounter<'static>> = r
        .mods
        .iter()
        .map(|&(m, counter, _)| ModuleCounter {
            module_id: common::module(m),
            counter,
        })
        .collect();
    let body = CastRecordBody::new(&CastRecordParts {
        election_id: election(),
        box_id: box_id(),
        ballot_style_id: BallotStyleId::new(r.style).unwrap(),
        proof_system_id: 1,
        commitments: Commitments::new(&points).unwrap(),
        proof: proof_bytes,
        module_counters: ModuleCounters::new(&counters).unwrap(),
        share_package_hash: Hash512([6; 64]),
        transport_flags: 0,
    })
    .unwrap();
    let body = object(SCHEMA_CAST_RECORD_BODY, SCHEMA_VERSION_1, &body);
    let body_hash = object_hash(body);
    let device = leak(
        *sign_ed25519_half(signing(r.device), RecordPurpose::CastRecord, body)
            .unwrap()
            .as_bytes(),
    );
    let sigs: Vec<ModuleRecordSig<'static>> = r
        .mods
        .iter()
        .map(|&(m, counter, key)| {
            let message = module_message(&body_hash, m, counter);
            ModuleRecordSig {
                module_id: common::module(m),
                ed25519: leak(
                    *sign_ed25519_half(module_signing(key), RecordPurpose::ModuleRecord, &message)
                        .unwrap()
                        .as_bytes(),
                ),
            }
        })
        .collect();
    object(
        SCHEMA_CAST_RECORD,
        SCHEMA_VERSION_1,
        &CastRecord::new(body, device, &sigs).unwrap(),
    )
}

/// The tracking code of a record object.
fn code(record: &[u8]) -> Hash512 {
    let r: CastRecord<'_> =
        ityv_encoding::decode_object(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, record).unwrap();
    object_hash(r.body_bytes())
}

/// The sorted-set root of `codes`.
fn root(codes: &[Hash512]) -> Hash512 {
    let mut codes = codes.to_vec();
    codes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    sorted_set_root(&codes).unwrap()
}

/// A batch attestation to build.
#[derive(Clone)]
struct Bat {
    index: u32,
    /// (module, first, last, key number of its batch signature), ascending.
    ranges: Vec<(&'static [u8], u64, u64, u16)>,
    /// The member records' tracking codes.
    members: Vec<Hash512>,
    record_count: Option<u16>,
    records_root: Option<Hash512>,
    device: u16,
    bucket: u64,
}

fn bat(index: u32, first: u64, last: u64, members: &[Hash512]) -> Bat {
    Bat {
        index,
        ranges: std::vec![(P1, first, last, P1_KEY), (P2, first, last, P2_KEY)],
        members: members.to_vec(),
        record_count: None,
        records_root: None,
        device: BOX_DEVICE_BASE,
        bucket: 120,
    }
}

fn batch(b: &Bat) -> &'static [u8] {
    let ranges = leak_slice(
        b.ranges
            .iter()
            .map(|&(m, first, last, _)| ModuleRange {
                module_id: common::module(m),
                counter_first: first,
                counter_last: last,
            })
            .collect(),
    );
    let body = BatchAttestBody::new(&BatchAttestParts {
        election_id: election(),
        box_id: box_id(),
        batch_index: b.index,
        record_count: b
            .record_count
            .unwrap_or(u16::try_from(b.members.len()).unwrap()),
        records_root: b.records_root.unwrap_or_else(|| root(&b.members)),
        module_ranges: ranges,
        module_refusals: ModuleIds::EMPTY,
        journal_head: Hash512([0x22; 64]),
        time_bucket: TimeBucket::new(b.bucket),
    })
    .unwrap();
    let body = object(SCHEMA_BATCH_ATTEST_BODY, SCHEMA_VERSION_1, &body);
    let sigs: Vec<ModuleBatchSig<'static>> = b
        .ranges
        .iter()
        .map(|&(m, _, _, key)| ModuleBatchSig {
            module_id: common::module(m),
            sig: sign(module_signing(key), b"batch-attest", body),
        })
        .collect();
    let device = sign(signing(b.device), b"batch-attest", body);
    object(
        SCHEMA_BATCH_ATTEST,
        SCHEMA_VERSION_1,
        &BatchAttest::new(body, &sigs, device).unwrap(),
    )
}

/// A device-signed close of `records` records and `attested` attested ones
/// with module counters `last` and `record_set_root`.
fn close_with(
    records: u64,
    attested: u64,
    open_batches: u8,
    last: u64,
    set: Hash512,
) -> &'static [u8] {
    close_counts(
        CloseCounts {
            paper: records,
            records,
            attested,
            without_record: 0,
            challenged: 0,
            quarantined: 0,
            visits: records,
            envelopes: 0,
            stickers: 0,
            spoil_envelopes: 0,
        },
        open_batches,
        last,
        set,
    )
}

/// A device-signed close with `counts`, module counters `last` and
/// `record_set_root`.
fn close_counts(counts: CloseCounts, open_batches: u8, last: u64, set: Hash512) -> &'static [u8] {
    let counters: Vec<ModuleCounter<'static>> = [P1, P2]
        .iter()
        .map(|m| ModuleCounter {
            module_id: common::module(m),
            counter: last,
        })
        .collect();
    let body = BoxCloseBody::new(&BoxCloseParts {
        election_id: election(),
        box_id: box_id(),
        counts,
        record_set_root: set,
        journal_head: Hash512([0x24; 64]),
        seal_digest: SEAL,
        module_counters: ModuleCounters::new(&counters).unwrap(),
        open_batches,
        time_bucket: TimeBucket::new(CLOSE_BUCKET),
    });
    let body = object(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, &body);
    let attestations: Vec<Attestation<'static>> = [
        (b"clerk-1".as_slice(), SignerRole::Clerk),
        (b"clerk-2", SignerRole::Clerk),
        (b"obs-a", SignerRole::Observer),
        (b"obs-b", SignerRole::Observer),
    ]
    .iter()
    .map(|&(id, role)| {
        let (o, n) = person(id);
        Attestation {
            signer_id: SignerId::new(id).unwrap(),
            role,
            org_id: OrgId::new(o).unwrap(),
            sig: sign(signing(n), b"box-close", body),
        }
    })
    .collect();
    let device = sign(signing(BOX_DEVICE_BASE), b"box-close", body);
    object(
        SCHEMA_BOX_CLOSE,
        SCHEMA_VERSION_1,
        &BoxClose::new(body, Some(device), &attestations).unwrap(),
    )
}

/// A clean close of the records `codes`.
fn close(codes: &[Hash512]) -> &'static [u8] {
    let n = codes.len() as u64;
    close_with(n, n, 0, n, root(codes))
}

fn late_batch_close(batch_event: &'static [u8], bucket: u64) -> &'static [u8] {
    let b: BatchAttest<'static> =
        ityv_encoding::decode_object(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, batch_event).unwrap();
    let body = LateBatchCloseBody::new(&LateBatchCloseParts {
        election_id: election(),
        box_id: box_id(),
        batch_body_hash: object_hash(b.body_bytes()),
        reason: LateBatchReason::DeviceRestart,
        time_bucket: TimeBucket::new(bucket),
    })
    .unwrap();
    let body = object(SCHEMA_LATE_BATCH_CLOSE_BODY, SCHEMA_VERSION_1, &body);
    witnessed(SCHEMA_LATE_BATCH_CLOSE_BODY, body, false)
}

// ---------------------------------------------------------------------
// Running the stages.

struct Run {
    index: &'static LedgerIndex<'static>,
    boxes: &'static BoxStage<'static>,
    records: RecordStage<'static>,
}

fn run_in(world: &World, events: &[(SchemaId, &'static [u8])]) -> Run {
    let mut ledger = Ledger::new();
    ledger
        .push(SCHEMA_SIGNED_GENESIS, world.signed_genesis)
        .push(SCHEMA_SIGNED_LEGAL_AUTHORIZATION, world.authorization);
    for &(schema, event) in events {
        ledger.push(schema, event);
    }
    let index = leak(build_index(world.genesis, ledger.bytes(), &ledger.events));
    let authority: &'static AuthorityStage<'static> = leak(authorize_ledger(world.genesis, index));
    let boxes = leak(verify_boxes(world.genesis, index, authority));
    let records = verify_records(world.genesis, index, boxes);
    Run {
        index,
        boxes,
        records,
    }
}

fn go(events: &[(SchemaId, &'static [u8])]) -> Run {
    run_in(world(), events)
}

fn w(e: &'static [u8]) -> (SchemaId, &'static [u8]) {
    (SCHEMA_WITNESSED_EVENT, e)
}

fn r(e: &'static [u8]) -> (SchemaId, &'static [u8]) {
    (SCHEMA_CAST_RECORD, e)
}

fn b(e: &'static [u8]) -> (SchemaId, &'static [u8]) {
    (SCHEMA_BATCH_ATTEST, e)
}

fn c(e: &'static [u8]) -> (SchemaId, &'static [u8]) {
    (SCHEMA_BOX_CLOSE, e)
}

fn report(run: &Run) -> &BoxRecords<'static> {
    run.records.report(BOX).unwrap()
}

fn rejected(run: &Run) -> Vec<(u64, RecordRefusal)> {
    report(run)
        .rejected
        .iter()
        .map(|x| (x.seq.get(), x.refusal))
        .collect()
}

fn findings(run: &Run) -> Vec<(u64, BatchProblem)> {
    report(run)
        .batches
        .iter()
        .map(|f: &BatchFinding| (f.seq.get(), f.problem))
        .collect()
}

fn statuses(run: &Run) -> Vec<(u64, RecordStatus)> {
    report(run)
        .records
        .iter()
        .map(|x| (x.seq.get(), x.state.status()))
        .collect()
}

/// Three clean records, each with both module counters equal to its number.
fn three() -> ([&'static [u8]; 3], [Hash512; 3]) {
    let recs = [record(&rec(1)), record(&rec(2)), record(&rec(3))];
    let codes = [code(recs[0]), code(recs[1]), code(recs[2])];
    (recs, codes)
}

// Frames: genesis 1, authorization 2, then the events from 3.

#[test]
fn a_clean_box_passes() {
    let (recs, codes) = three();
    let run = go(&[
        w(opened()),
        r(recs[0]),
        r(recs[1]),
        r(recs[2]),
        b(batch(&bat(0, 1, 3, &codes))),
        c(close(&codes)),
    ]);
    assert!(
        run.index.findings().is_empty(),
        "{:?}",
        run.index.findings()
    );
    let box_report = run.boxes.report(BOX).unwrap();
    assert!(box_report.holds.is_empty(), "{:?}", box_report.holds);
    let rep = report(&run);
    assert!(rep.holds.is_empty(), "{rep:?}");
    assert!(rep.rejected.is_empty());
    assert!(rep.unattested.is_empty());
    assert!(rep.batches.is_empty());
    assert_eq!(
        statuses(&run),
        [
            (4, RecordStatus::CastCommitted),
            (5, RecordStatus::CastCommitted),
            (6, RecordStatus::CastCommitted)
        ]
    );
    assert_eq!(rep.records[0].tracking_code, codes[0]);
    assert_eq!(rep.record_set_root, Some(root(&codes)));
    assert!(run.records.holds().is_empty());
    // One report per box of the box stage, in the same order; the boxes
    // that never opened have no records.
    assert_eq!(run.records.reports().len(), run.boxes.reports().len());
    for (x, y) in run.records.reports().iter().zip(run.boxes.reports()) {
        assert_eq!(x.box_id, y.box_id);
    }
    let other = run.records.report(b"BOX-2").unwrap();
    assert!(other.records.is_empty() && other.holds.is_empty());
    assert_eq!(other.record_set_root, None);
    assert!(run.records.report(b"BOX-9").is_none());
}

#[test]
fn a_record_whose_proof_or_style_fails_is_rejected() {
    let (recs, codes) = three();
    // A proof made for another box's statement, and a style the genesis
    // does not have.
    let other_box = record(&Rec {
        proof_box: b"BOX-2",
        ..rec(4)
    });
    let unknown_style = record(&Rec {
        style: b"STYLE-9",
        ..rec(5)
    });
    let run = go(&[
        w(opened()),
        r(recs[0]),
        r(recs[1]),
        r(recs[2]),
        r(other_box),
        r(unknown_style),
        b(batch(&bat(0, 1, 3, &codes))),
    ]);
    assert_eq!(
        rejected(&run),
        [(7, RecordRefusal::Proof), (8, RecordRefusal::Style)]
    );
    let rep = report(&run);
    assert_eq!(rep.rejected[0].tracking_code, code(other_box));
    assert!(rep.holds.contains(HoldReason::RecordRejected));
    assert_eq!(rep.records.len(), 3);
    assert!(run.records.holds().contains(HoldReason::RecordRejected));
}

#[test]
fn a_record_signature_that_does_not_verify_is_rejected() {
    // The device signature by another box's device; a module signature by
    // another module.
    let device = record(&Rec {
        device: BOX_DEVICE_BASE + 1,
        ..rec(1)
    });
    let module = record(&Rec {
        mods: leak_slice(std::vec![(P1, 2, P1_KEY), (P2, 2, B2_P1_KEY)]),
        ..rec(2)
    });
    let run = go(&[w(opened()), r(device), r(module)]);
    assert_eq!(
        rejected(&run),
        [
            (4, RecordRefusal::DeviceSignature),
            (5, RecordRefusal::ModuleSignature)
        ]
    );
    assert!(report(&run).records.is_empty());
}

#[test]
fn records_sharing_a_module_counter_are_both_rejected() {
    let (recs, codes) = three();
    // Another body under counter 2.
    let again = record(&Rec {
        option: 4,
        seed: 99,
        ..rec(2)
    });
    let run = go(&[
        w(opened()),
        r(recs[0]),
        r(recs[1]),
        r(recs[2]),
        r(again),
        b(batch(&bat(0, 1, 3, &[codes[0], codes[2]]))),
    ]);
    assert_eq!(
        rejected(&run),
        [
            (5, RecordRefusal::CounterReused),
            (7, RecordRefusal::CounterReused)
        ]
    );
    assert_eq!(
        statuses(&run),
        [
            (4, RecordStatus::CastCommitted),
            (6, RecordStatus::CastCommitted)
        ]
    );
}

#[test]
fn a_record_in_no_batch_is_unattested_until_a_late_batch_attests_it() {
    let (recs, codes) = three();
    let first = batch(&bat(0, 1, 2, &codes[..2]));
    let mut events = std::vec![
        w(opened()),
        r(recs[0]),
        r(recs[1]),
        r(recs[2]),
        b(first),
        c(close_with(3, 2, 1, 3, root(&codes))),
    ];
    let run = go(&events);
    let rep = report(&run);
    assert_eq!(rep.unattested, [codes[2]]);
    assert_eq!(statuses(&run)[2], (6, RecordStatus::Unattested));
    // Unattested is listed, not held.
    assert!(rep.holds.is_empty(), "{rep:?}");

    let late = batch(&Bat {
        bucket: CLOSE_BUCKET + 5,
        ..bat(1, 3, 3, &codes[2..])
    });
    events.push(b(late));
    events.push(w(late_batch_close(late, CLOSE_BUCKET + 5)));
    let run = go(&events);
    let box_report = run.boxes.report(BOX).unwrap();
    assert!(box_report.refusals.is_empty(), "{:?}", box_report.refusals);
    let rep = report(&run);
    assert!(rep.unattested.is_empty());
    assert!(rep.holds.is_empty(), "{rep:?}");
    assert_eq!(statuses(&run)[2], (6, RecordStatus::CastCommitted));
}

#[test]
fn a_batch_whose_count_or_root_is_wrong_attests_nothing() {
    let (recs, codes) = three();
    let events = |bat: &Bat| {
        std::vec![
            w(opened()),
            r(recs[0]),
            r(recs[1]),
            r(recs[2]),
            b(batch(bat)),
        ]
    };
    let wrong_count = Bat {
        record_count: Some(2),
        ..bat(0, 1, 3, &codes)
    };
    let run = go(&events(&wrong_count));
    assert_eq!(findings(&run), [(7, BatchProblem::RecordCount)]);
    assert_eq!(report(&run).unattested.len(), 3);
    assert!(report(&run).holds.contains(HoldReason::BatchInvalid));

    let wrong_root = Bat {
        records_root: Some(root(&codes[..2])),
        ..bat(0, 1, 3, &codes)
    };
    let run = go(&events(&wrong_root));
    assert_eq!(findings(&run), [(7, BatchProblem::RecordsRoot)]);
    assert_eq!(report(&run).unattested.len(), 3);
}

#[test]
fn a_batch_signature_or_module_that_fails_attests_nothing() {
    let (recs, codes) = three();
    let events = |bat: &Bat| {
        std::vec![
            w(opened()),
            r(recs[0]),
            r(recs[1]),
            r(recs[2]),
            b(batch(bat)),
        ]
    };
    // The device's batch signature by another device.
    let device = Bat {
        device: BOX_DEVICE_BASE + 1,
        ..bat(0, 1, 3, &codes)
    };
    let run = go(&events(&device));
    assert_eq!(findings(&run), [(7, BatchProblem::Signature)]);
    assert_eq!(report(&run).unattested.len(), 3);
    // A module's batch signature by another module.
    let mut module = bat(0, 1, 3, &codes);
    module.ranges[1].3 = B2_P1_KEY;
    let run = go(&events(&module));
    assert_eq!(findings(&run), [(7, BatchProblem::Signature)]);
    // A range on a module of another box.
    let mut foreign = bat(0, 1, 3, &codes);
    foreign
        .ranges
        .push((b"M-B2-P1".as_slice(), 1, 3, B2_P1_KEY));
    let run = go(&events(&foreign));
    assert_eq!(findings(&run), [(7, BatchProblem::Module)]);
    assert_eq!(report(&run).unattested.len(), 3);
}

#[test]
fn two_bodies_under_one_batch_index_attest_nothing() {
    let (recs, codes) = three();
    let one = batch(&bat(0, 1, 3, &codes));
    let other = batch(&Bat {
        bucket: 121,
        ..bat(0, 1, 3, &codes)
    });
    let run = go(&[
        w(opened()),
        r(recs[0]),
        r(recs[1]),
        r(recs[2]),
        b(one),
        b(other),
    ]);
    assert_eq!(
        findings(&run),
        [
            (7, BatchProblem::DoubleIndex),
            (8, BatchProblem::DoubleIndex)
        ]
    );
    assert_eq!(report(&run).unattested.len(), 3);
}

#[test]
fn counter_ranges_run_from_one_without_gap_or_overlap() {
    let (recs, codes) = three();
    let base = || std::vec![w(opened()), r(recs[0]), r(recs[1]), r(recs[2])];
    // A gap: counter 3 is in no batch, and the second batch starts at 4.
    let mut events = base();
    events.push(b(batch(&bat(0, 1, 2, &codes[..2]))));
    events.push(b(batch(&bat(1, 4, 4, &[]).with_count(Some(1)))));
    let run = go(&events);
    assert!(findings(&run).contains(&(8, BatchProblem::CounterRange)));
    // A first batch that does not start at 1.
    let mut events = base();
    events.push(b(batch(&bat(0, 2, 3, &codes[1..]))));
    let run = go(&events);
    assert_eq!(findings(&run), [(7, BatchProblem::CounterRange)]);
    // An overlap: counter 2 in both batches; record 2 is in two batches.
    let mut events = base();
    events.push(b(batch(&bat(0, 1, 2, &codes[..2]))));
    events.push(b(batch(&bat(1, 2, 3, &codes[1..]))));
    let run = go(&events);
    let got = findings(&run);
    assert!(got.contains(&(8, BatchProblem::CounterRange)), "{got:?}");
    assert!(got.contains(&(7, BatchProblem::Straddle)), "{got:?}");
    assert!(report(&run).unattested.contains(&codes[1]));
    // Batches in index order, not frame order.
    let mut events = base();
    events.push(b(batch(&bat(1, 3, 3, &codes[2..]))));
    events.push(b(batch(&bat(0, 1, 2, &codes[..2]))));
    let run = go(&events);
    assert!(findings(&run).is_empty(), "{:?}", findings(&run));
    assert!(report(&run).unattested.is_empty());
}

#[test]
fn a_record_whose_counters_straddle_two_batches_is_unattested() {
    // Record 2 has counter 2 for P1 and 3 for P2; record 3 the reverse.
    let r1 = record(&rec(1));
    let r2 = record(&Rec {
        mods: leak_slice(std::vec![(P1, 2, P1_KEY), (P2, 3, P2_KEY)]),
        ..rec(2)
    });
    let r3 = record(&Rec {
        mods: leak_slice(std::vec![(P1, 3, P1_KEY), (P2, 2, P2_KEY)]),
        ..rec(3)
    });
    let run = go(&[
        w(opened()),
        r(r1),
        r(r2),
        r(r3),
        b(batch(&bat(0, 1, 2, &[code(r1)]))),
        b(batch(&bat(1, 3, 3, &[]).with_count(Some(1)))),
    ]);
    let got = findings(&run);
    assert!(got.contains(&(7, BatchProblem::Straddle)), "{got:?}");
    let rep = report(&run);
    assert!(rep.unattested.contains(&code(r2)));
    assert!(rep.unattested.contains(&code(r3)));
}

#[test]
fn a_range_beyond_the_close_is_a_finding() {
    let (recs, codes) = three();
    let run = go(&[
        w(opened()),
        r(recs[0]),
        r(recs[1]),
        r(recs[2]),
        // The close reports final counter 2 although the batch ends at 3.
        b(batch(&bat(0, 1, 3, &codes))),
        c(close_with(3, 3, 0, 2, root(&codes))),
    ]);
    assert_eq!(findings(&run), [(7, BatchProblem::BeyondClose)]);
    // The records are still attested.
    assert!(report(&run).unattested.is_empty());
}

#[test]
fn the_close_must_carry_the_root_of_the_records() {
    let (recs, codes) = three();
    let run = go(&[
        w(opened()),
        r(recs[0]),
        r(recs[1]),
        r(recs[2]),
        b(batch(&bat(0, 1, 3, &codes))),
        c(close_with(3, 3, 0, 3, root(&codes[..2]))),
    ]);
    let rep = report(&run);
    assert_eq!(
        rep.holds,
        ityv_state::HoldSet::empty().with(HoldReason::RecordSetMismatch)
    );
    assert_eq!(rep.record_set_root, Some(root(&codes)));
    assert!(run.records.holds().contains(HoldReason::RecordSetMismatch));
}

/// The amendment of the key tests: `M-B1-P2` gets a new key.
fn new_p2_key(d: &mut Draft) {
    for m in &mut d.modules {
        if m.module_id.as_bytes() == P2 {
            m.key = common::registered(common::SPARE_BASE + 20);
        }
    }
}

#[test]
fn a_key_counts_from_the_frame_of_its_state_and_stays_valid_after() {
    assert_eq!(NEW_P2, common::SPARE_BASE + 20);
    let world = world_with(Some(new_p2_key));
    // Module keys: P2 signs with the new key (the module key number is
    // relative to the module base, so it is given as a signing key here).
    let with_p2 = |counter: u64, p2: u16| Rec {
        mods: leak_slice(std::vec![(P1, counter, P1_KEY), (P2, counter, p2)]),
        ..rec(counter)
    };
    let new_key = NEW_P2 - 400;
    let before = record(&with_p2(1, new_key));
    let old_after = record(&with_p2(2, P2_KEY));
    let new_after = record(&with_p2(3, new_key));
    let codes = [code(old_after), code(new_after)];
    let run = run_in(
        &world,
        &[
            w(opened()),
            r(before),
            (SCHEMA_SIGNED_GENESIS, world.amendment.unwrap()),
            r(old_after),
            r(new_after),
            b(batch(&Bat {
                record_count: Some(2),
                ..bat(0, 1, 3, &codes)
            })),
        ],
    );
    assert!(
        run.index.ledger_holds().is_empty(),
        "{:?}",
        run.index.ledger_holds()
    );
    // Before the amendment's frame only the old key verifies.
    assert_eq!(rejected(&run), [(4, RecordRefusal::ModuleSignature)]);
    // After it, both: a replaced key's signatures stay valid.
    assert_eq!(
        statuses(&run),
        [
            (6, RecordStatus::CastCommitted),
            (7, RecordStatus::CastCommitted)
        ]
    );
}

/// The amendment that adds the module `M-B1-J` to `BOX-1`.
fn add_j(d: &mut Draft) {
    d.modules
        .push(common::module_entry(J_KEY, J, ChamberCode::J));
    for b in &mut d.boxes {
        if b.box_id.as_bytes() == BOX {
            b.modules = modules(&[J, P1, P2]);
        }
    }
}

#[test]
fn a_record_naming_a_module_the_box_had_not_by_its_frame_is_rejected() {
    let world = world_with(Some(add_j));
    let with_j = record(&Rec {
        mods: leak_slice(std::vec![(J, 1, J_KEY), (P1, 1, P1_KEY), (P2, 1, P2_KEY)]),
        ..rec(1)
    });
    let run = run_in(
        &world,
        &[
            w(opened_with(&[J, P1, P2])),
            r(with_j),
            (SCHEMA_SIGNED_GENESIS, world.amendment.unwrap()),
        ],
    );
    // A box stage that checks the opening against the state in force at its
    // frame refuses the opening, and the record never reaches this stage.
    let refused_by_box = run
        .boxes
        .report(BOX)
        .unwrap()
        .refusals
        .iter()
        .any(|x| x.seq.get() == 4);
    if refused_by_box {
        assert!(report(&run).rejected.is_empty());
        assert!(report(&run).records.is_empty());
    } else {
        assert_eq!(rejected(&run), [(4, RecordRefusal::Module)]);
    }
}

#[test]
fn ranges_are_per_module() {
    // M-B1-P2 consumed one counter more than M-B1-P1 before the second
    // record: the batch's ranges differ by module.
    let r1 = record(&rec(1));
    let r2 = record(&Rec {
        mods: leak_slice(std::vec![(P1, 2, P1_KEY), (P2, 3, P2_KEY)]),
        ..rec(2)
    });
    let mut per_module = bat(0, 1, 2, &[code(r1), code(r2)]);
    per_module.ranges[1].2 = 3;
    let run = go(&[w(opened()), r(r1), r(r2), b(batch(&per_module))]);
    assert!(findings(&run).is_empty(), "{:?}", findings(&run));
    assert!(report(&run).unattested.is_empty());
    assert_eq!(
        statuses(&run),
        [
            (4, RecordStatus::CastCommitted),
            (5, RecordStatus::CastCommitted)
        ]
    );
}

trait WithCount {
    fn with_count(self, count: Option<u16>) -> Self;
}

impl WithCount for Bat {
    fn with_count(self, count: Option<u16>) -> Self {
        Self {
            record_count: count,
            ..self
        }
    }
}

/// What a challenge opening changes from the device's genuine values.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tamper {
    /// None: the opening reconstructs its record.
    Genuine,
    /// Names another ballot style.
    Style,
    /// The first module's counter is off by one.
    Counter,
    /// The first module's randomness is off: the sum no longer holds.
    ModuleRand,
    /// The first module's cast-id contribution is changed: it no longer
    /// derives the cast id.
    Cid,
    /// Opens another option.
    Option,
    /// A second, zero chunk on every randomness list.
    ExtraChunk,
    /// The last module's entry left out.
    DropModule,
    /// The summed randomness not a canonical scalar.
    NonCanonical,
}

/// A `ChallengeOpening` of the record `r`, device-signed with key number
/// `device`, changed by `tamper`.
fn opening_of(r: &Rec, device: u16, tamper: Tamper) -> &'static [u8] {
    use ityv_encoding::{
        ChallengeOpening, ChallengeOpeningBody, ChallengeOpeningParts, MAX_CHUNKS as ENC_CHUNKS,
        ModuleOpening, SCHEMA_CHALLENGE_OPENING_BODY, Scalar32, Scalars,
    };
    let secrets = secrets(r);
    let raw = |values: &[Scalar]| -> Scalars<ENC_CHUNKS> {
        let mut out: Vec<Scalar32> = values.iter().map(|v| Scalar32(v.to_bytes())).collect();
        if tamper == Tamper::ExtraChunk {
            out.push(Scalar32([0; 32]));
        }
        Scalars::new(&out).unwrap()
    };
    let chunks = secrets.rands[0].len();
    let rand: &'static Scalars<ENC_CHUNKS> = leak(if tamper == Tamper::NonCanonical {
        Scalars::new(&[Scalar32([0xFF; 32])]).unwrap()
    } else {
        raw(&secrets.rand[..chunks])
    });
    let kept = r.mods.len() - usize::from(tamper == Tamper::DropModule);
    let mods: Vec<ModuleOpening<'static>> = r
        .mods
        .iter()
        .zip(secrets.cids.iter().zip(&secrets.rands))
        .take(kept)
        .enumerate()
        .map(|(i, (&(m, counter, _), (cid, part)))| {
            let first = i == 0;
            let mut part = part.clone();
            if first && tamper == Tamper::ModuleRand {
                part[0] = part[0].add(&Scalar::ONE);
            }
            let mut cid = *cid;
            if first && tamper == Tamper::Cid {
                cid[0] ^= 1;
            }
            // (A module list of another length than the summed one does not
            // encode: `ChallengeOpeningBody::new` refuses it.)
            let rand = raw(&part);
            ModuleOpening {
                module_id: common::module(m),
                counter: if first && tamper == Tamper::Counter {
                    counter + 1
                } else {
                    counter
                },
                rand,
                cid: Token192(cid),
            }
        })
        .collect();
    let body = ChallengeOpeningBody::new(&ChallengeOpeningParts {
        election_id: election(),
        box_id: box_id(),
        ballot_style_id: BallotStyleId::new(if tamper == Tamper::Style {
            b"STYLE-2"
        } else {
            r.style
        })
        .unwrap(),
        record_hash: code(record(r)),
        option_index: if tamper == Tamper::Option {
            r.option + 1
        } else {
            r.option
        },
        cast_id: secrets.cast_id.token(),
        rand,
        modules: leak_slice(mods),
    })
    .unwrap();
    let body = object(SCHEMA_CHALLENGE_OPENING_BODY, SCHEMA_VERSION_1, &body);
    let sig = sign(signing(device), b"challenge", body);
    object(
        ityv_encoding::SCHEMA_CHALLENGE_OPENING,
        SCHEMA_VERSION_1,
        &ChallengeOpening::new(body, sig).unwrap(),
    )
}

fn ch(e: &'static [u8]) -> (SchemaId, &'static [u8]) {
    (ityv_encoding::SCHEMA_CHALLENGE_OPENING, e)
}

/// The close of a box whose second record was challenged: two cast records
/// attested, one challenged, every counter at 3.
fn close_after_challenge(cast: &[Hash512]) -> &'static [u8] {
    close_counts(
        CloseCounts {
            paper: 2,
            records: 2,
            attested: 2,
            without_record: 0,
            challenged: 1,
            quarantined: 0,
            visits: 2,
            envelopes: 0,
            stickers: 0,
            spoil_envelopes: 1,
        },
        0,
        3,
        root(cast),
    )
}

#[test]
fn a_challenged_record_is_published_but_not_cast() {
    // Visit 1 casts counter 1, visit 2 checks counter 2 (its record and the
    // opening are published, PROTOCOL.md §8), visit 3 casts counter 3. The
    // batch covers counters 1..3 with the two cast records, and the close's
    // record set is the cast records.
    let (recs, codes) = three();
    let cast = [codes[0], codes[2]];
    let run = go(&[
        w(opened()),
        r(recs[0]),
        r(recs[1]),
        ch(opening_of(&rec(2), BOX_DEVICE_BASE, Tamper::Genuine)),
        r(recs[2]),
        b(batch(&bat(0, 1, 3, &cast))),
        c(close_after_challenge(&cast)),
    ]);
    let box_report = run.boxes.report(BOX).unwrap();
    assert!(box_report.holds.is_empty(), "{:?}", box_report.holds);
    assert!(box_report.refusals.is_empty(), "{:?}", box_report.refusals);
    let rep = report(&run);
    assert!(rep.holds.is_empty(), "{rep:?}");
    assert!(rep.refused_challenges.is_empty());
    assert!(rep.failed_openings.is_empty());
    assert_eq!(
        statuses(&run),
        [
            (4, RecordStatus::CastCommitted),
            (5, RecordStatus::ChallengedSpoiled),
            (7, RecordStatus::CastCommitted)
        ]
    );
    assert_eq!(rep.record_set_root, Some(root(&cast)));
    // The opening may come before its record.
    let run = go(&[
        w(opened()),
        r(recs[0]),
        ch(opening_of(&rec(2), BOX_DEVICE_BASE, Tamper::Genuine)),
        r(recs[1]),
        r(recs[2]),
        b(batch(&bat(0, 1, 3, &cast))),
        c(close_after_challenge(&cast)),
    ]);
    assert!(report(&run).holds.is_empty(), "{:?}", report(&run));
    assert!(run.boxes.report(BOX).unwrap().holds.is_empty());
}

#[test]
fn a_challenge_opening_must_reconstruct_its_record() {
    // VC-028: the device signed the opening, so the record is challenged
    // and not cast whatever the opening says; one that does not reconstruct
    // the record holds the box (the device is quarantined, §8 item 5).
    let (recs, codes) = three();
    let cast = [codes[0], codes[2]];
    for tamper in [
        Tamper::Style,
        Tamper::Counter,
        Tamper::ModuleRand,
        Tamper::Cid,
        Tamper::Option,
        Tamper::ExtraChunk,
        Tamper::DropModule,
        Tamper::NonCanonical,
    ] {
        let run = go(&[
            w(opened()),
            r(recs[0]),
            r(recs[1]),
            ch(opening_of(&rec(2), BOX_DEVICE_BASE, tamper)),
            r(recs[2]),
            b(batch(&bat(0, 1, 3, &cast))),
            c(close_after_challenge(&cast)),
        ]);
        let rep = report(&run);
        assert_eq!(
            rep.failed_openings,
            [ityv_encoding::Seq::new(6).unwrap()],
            "{tamper:?}"
        );
        assert!(rep.refused_challenges.is_empty(), "{tamper:?}");
        assert_eq!(
            rep.holds,
            HoldSet::empty().with(HoldReason::OpeningMismatch),
            "{tamper:?}"
        );
        assert_eq!(
            statuses(&run)[1],
            (5, RecordStatus::ChallengedSpoiled),
            "{tamper:?}"
        );
        assert_eq!(rep.record_set_root, Some(root(&cast)), "{tamper:?}");
    }
}

#[test]
fn a_challenge_opening_must_verify_and_name_a_record_of_the_box() {
    let (recs, codes) = three();
    let cast = [codes[0], codes[2]];
    // Signed by a key the box never had: refused, and the record it names
    // counts as cast, so the batch and the close no longer agree with it.
    let run = go(&[
        w(opened()),
        r(recs[0]),
        r(recs[1]),
        ch(opening_of(&rec(2), common::SPARE_BASE, Tamper::Genuine)),
        r(recs[2]),
        b(batch(&bat(0, 1, 3, &cast))),
        c(close_after_challenge(&cast)),
    ]);
    let rep = report(&run);
    assert_eq!(
        rep.refused_challenges,
        [ityv_encoding::Seq::new(6).unwrap()]
    );
    assert!(rep.holds.contains(HoldReason::ChallengeRejected));
    assert!(rep.holds.contains(HoldReason::BatchInvalid));
    assert!(rep.holds.contains(HoldReason::RecordSetMismatch));
    // Naming a record that is not on the ledger.
    let run = go(&[
        w(opened()),
        r(recs[0]),
        ch(opening_of(&rec(2), BOX_DEVICE_BASE, Tamper::Genuine)),
        r(recs[2]),
        b(batch(&bat(0, 1, 3, &cast))),
        c(close_after_challenge(&cast)),
    ]);
    let rep = report(&run);
    assert_eq!(
        rep.refused_challenges,
        [ityv_encoding::Seq::new(5).unwrap()]
    );
    assert!(rep.holds.contains(HoldReason::ChallengeRejected));
}

#[test]
fn a_batch_with_module_refusals_attests_but_is_a_finding() {
    let (recs, codes) = three();
    let ranges = leak_slice(
        [P1, P2]
            .iter()
            .map(|&m| ModuleRange {
                module_id: common::module(m),
                counter_first: 1,
                counter_last: 3,
            })
            .collect(),
    );
    let body = BatchAttestBody::new(&BatchAttestParts {
        election_id: election(),
        box_id: box_id(),
        batch_index: 0,
        record_count: 3,
        records_root: root(&codes),
        module_ranges: ranges,
        module_refusals: modules(&[P2]),
        journal_head: Hash512([0x22; 64]),
        time_bucket: TimeBucket::new(120),
    })
    .unwrap();
    let body = object(SCHEMA_BATCH_ATTEST_BODY, SCHEMA_VERSION_1, &body);
    let sigs = [ModuleBatchSig {
        module_id: common::module(P1),
        sig: sign(module_signing(P1_KEY), b"batch-attest", body),
    }];
    let device = sign(signing(BOX_DEVICE_BASE), b"batch-attest", body);
    let refused = object(
        SCHEMA_BATCH_ATTEST,
        SCHEMA_VERSION_1,
        &BatchAttest::new(body, &sigs, device).unwrap(),
    );
    let run = go(&[
        w(opened()),
        r(recs[0]),
        r(recs[1]),
        r(recs[2]),
        b(refused),
        c(close(&codes)),
    ]);
    assert_eq!(findings(&run), [(7, BatchProblem::ModuleRefused)]);
    assert!(report(&run).holds.contains(HoldReason::BatchInvalid));
    assert!(
        statuses(&run)
            .iter()
            .all(|(_, s)| *s == RecordStatus::CastCommitted)
    );
}

#[test]
fn device_double_signing_is_found_whatever_the_module_signatures() {
    // Two bodies under batch index 0, both signed by the device; one also
    // carries a module signature that does not verify.
    let (recs, codes) = three();
    let mut forged = bat(0, 1, 3, &codes);
    forged.ranges = std::vec![(P1, 1, 3, P2_KEY), (P2, 1, 3, P2_KEY)];
    let other = bat(0, 1, 2, &codes[..2]);
    let run = go(&[
        w(opened()),
        r(recs[0]),
        r(recs[1]),
        r(recs[2]),
        b(batch(&forged)),
        b(batch(&other)),
        c(close(&codes)),
    ]);
    assert_eq!(
        findings(&run),
        [
            (7, BatchProblem::DoubleIndex),
            (8, BatchProblem::DoubleIndex)
        ]
    );
}

#[test]
fn a_body_the_device_did_not_sign_is_no_double_signing() {
    // A second body under batch index 0 whose device signature is forged:
    // a signature finding for it, not device double signing, and the
    // device's own batch still attests.
    let (recs, codes) = three();
    let mut forged = bat(0, 1, 2, &codes[..2]);
    forged.device = common::SPARE_BASE;
    let run = go(&[
        w(opened()),
        r(recs[0]),
        r(recs[1]),
        r(recs[2]),
        b(batch(&bat(0, 1, 3, &codes))),
        b(batch(&forged)),
        c(close(&codes)),
    ]);
    assert_eq!(findings(&run), [(8, BatchProblem::Signature)]);
    assert!(
        statuses(&run)
            .iter()
            .all(|(_, s)| *s == RecordStatus::CastCommitted)
    );
}
