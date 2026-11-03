//! The legal authorization and the box stage (PROTOCOL.md §4.4, §7, §14 4;
//! VC-006..008, VC-037..040, VC-100): every expected box driven through
//! its state machine with signatures verified under the keys the genesis
//! registers, and every box without its close held.
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
    BOX_DEVICE_BASE, Draft, Ledger, ROSTER_BASE, SIGNERS, leak, leak_slice, modules, object,
    roster_signer, sign, sign_genesis_with, signing,
};
use ityv_crypto::object_hash;
use ityv_encoding::{
    Attestation, BallotStyleId, BatchAttest, BatchAttestBody, BatchAttestParts, BoxClose,
    BoxCloseBody, BoxCloseParts, BoxId, BoxOpenedBody, BoxOpenedParts, CaptureProfile, CastRecord,
    CastRecordBody, CastRecordParts, CloseCounts, Commitments, CustodyHandoffBody,
    CustodyHandoffParts, ElectionId, EnvelopeIssuance, EventRole, EventSig, FallbackBody,
    FallbackKind, FallbackParts, FallbackReason, Hash512, ImprintAuditBody, ImprintAuditParts,
    IssuanceCountBody, IssuanceCountParts, LateBatchCloseBody, LateBatchCloseParts,
    LateBatchReason, ModuleBatchSig, ModuleCounter, ModuleCounters, ModuleId, ModuleIds,
    ModuleRange, ModuleRecordSig, OrgId, Point32, RosterRole, SCHEMA_BATCH_ATTEST,
    SCHEMA_BATCH_ATTEST_BODY, SCHEMA_BOX_CLOSE, SCHEMA_BOX_CLOSE_BODY, SCHEMA_BOX_OPENED_BODY,
    SCHEMA_CAST_RECORD, SCHEMA_CAST_RECORD_BODY, SCHEMA_CUSTODY_HANDOFF_BODY, SCHEMA_FALLBACK_BODY,
    SCHEMA_IMPRINT_AUDIT_BODY, SCHEMA_ISSUANCE_COUNT_BODY, SCHEMA_LATE_BATCH_CLOSE_BODY,
    SCHEMA_SEAL_CHANGE_BODY, SCHEMA_SIGNED_GENESIS, SCHEMA_SIGNED_LEGAL_AUTHORIZATION,
    SCHEMA_VERSION_1, SCHEMA_WITNESSED_EVENT, SchemaId, Scope, SealChangeBody, SealChangeParts,
    SealChangeReason, Seq, SignerId, SignerRole, StationId, TimeBucket, WitnessedEvent, purpose_of,
};
use ityv_state::{HoldReason, HoldSet};
use ityv_verify::{
    AuthorityStage, BoxStage, LedgerIndex, Phase, Refusal, VerifiedGenesis, authorize_ledger,
    build_index, verify_boxes, verify_genesis,
};

const BOX: &[u8] = b"BOX-1";
const STATION: &[u8] = b"ST-1";
const MODULES: [&[u8]; 2] = [b"M-B1-P1", b"M-B1-P2"];
const SEAL: Hash512 = Hash512([0x5e; 64]);
/// Day 20 000 is the epoch day; bucket 100 is on day 20 001.
const OPEN_BUCKET: u64 = 100;
const CLOSE_BUCKET: u64 = 140;

fn election() -> ElectionId<'static> {
    common::election()
}

fn box_id() -> BoxId<'static> {
    BoxId::new(BOX).unwrap()
}

fn module(id: &'static [u8]) -> ModuleId<'static> {
    common::module(id)
}

/// The people of the roster: identifier, organisation, key number
/// (`clerk-3` is on the roster only after an amendment).
const PEOPLE: [(&[u8], &[u8], u16); 8] = [
    (b"cc-1", b"ORG-CC", 6),
    (b"clerk-1", b"ORG-ST", 0),
    (b"clerk-2", b"ORG-ST", 1),
    (b"clerk-3", b"ORG-ST", 7),
    (b"obs-a", b"PARTY-A", 2),
    (b"obs-b", b"PARTY-B", 3),
    (b"police-1", b"POLICE", 4),
    (b"court", b"COURT", 5),
];

fn person(id: &[u8]) -> (&'static [u8], u16) {
    let p = PEOPLE.iter().find(|p| p.0 == id).unwrap();
    (p.1, ROSTER_BASE + p.2)
}

/// A genesis whose roster also has a counting-centre custodian (so a
/// custody chain can reach the end of route `R-1`), pinning a legal
/// authorization of `scopes` for days 20 000..20 100; `tweak` may change
/// the draft first.
struct World {
    genesis: &'static VerifiedGenesis<'static>,
    signed_genesis: &'static [u8],
    authorization: &'static [u8],
}

fn world_with(scopes: &[Scope], tweak: impl FnOnce(&mut Draft)) -> World {
    let mut draft = Draft::standard();
    draft.roster.push(roster_signer(
        6,
        b"cc-1",
        RosterRole::Custodian,
        b"ORG-CC",
        None,
    ));
    tweak(&mut draft);
    draft.appointments = draft.referenced_appointments();
    let (body, authorization) = common::legal_authorization(scopes, 20_000, 20_100);
    let built = leak(sign_genesis_with(&draft, draft.raw(), &SIGNERS, |p| {
        p.legal_authorization_hash = object_hash(body);
    }));
    let genesis = leak(verify_genesis(&built.pin, &built.input(), &[]).unwrap());
    World {
        genesis,
        signed_genesis: built.signed,
        authorization,
    }
}

/// The world most tests use, built once.
fn world() -> &'static World {
    static WORLD: OnceLock<&'static World> = OnceLock::new();
    WORLD.get_or_init(|| {
        leak(world_with(
            &[Scope::PublicBoard, Scope::TrusteeBody, Scope::BallotMark],
            |_| {},
        ))
    })
}

// ---------------------------------------------------------------------
// Events, with real signatures.

/// The key number of the spare commitment unit an amendment registers
/// for `BOX-1`.
const SPARE_DEVICE: u16 = common::SPARE_BASE + 10;

/// Who signs a witnessed event.
#[derive(Clone, Copy)]
enum By {
    Person(&'static [u8], EventRole),
    Device,
    /// The spare commitment unit of `BOX-1`.
    Spare,
    /// A key of its own under a roster identifier: a forged signature.
    Forger(&'static [u8], EventRole),
}

const WITNESSES: [By; 4] = [
    By::Person(b"clerk-1", EventRole::Clerk),
    By::Person(b"clerk-2", EventRole::Clerk),
    By::Person(b"obs-a", EventRole::Observer),
    By::Person(b"obs-b", EventRole::Observer),
];

fn with_device(signers: &[By]) -> Vec<By> {
    let mut all = std::vec![By::Device];
    all.extend_from_slice(signers);
    all
}

/// A `WitnessedEvent` over the body object `body` of `schema`, signed by
/// `signers` under the body's purpose.
fn witnessed(schema: SchemaId, body: &'static [u8], signers: &[By]) -> &'static [u8] {
    let purpose = purpose_of(schema).unwrap();
    let mut parts: Vec<(&'static [u8], EventRole, &'static [u8], u16)> = signers
        .iter()
        .map(|b| match *b {
            By::Person(id, role) => {
                let (o, n) = person(id);
                (id, role, o, n)
            }
            By::Device => (
                BOX,
                EventRole::Device,
                b"ORG-ST".as_slice(),
                BOX_DEVICE_BASE,
            ),
            By::Spare => (BOX, EventRole::Device, b"ORG-ST".as_slice(), SPARE_DEVICE),
            By::Forger(id, role) => (id, role, person(id).0, common::SPARE_BASE),
        })
        .collect();
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

fn opened_at(bucket: u64, signers: &[By]) -> &'static [u8] {
    opened_with(bucket, &MODULES, signers)
}

fn opened_with(bucket: u64, mods: &[&'static [u8]], signers: &[By]) -> &'static [u8] {
    let body = BoxOpenedBody::new(&BoxOpenedParts {
        election_id: election(),
        box_id: box_id(),
        modules: modules(mods),
        seal_digest: SEAL,
        seals_match: true,
        initial_count: 0,
        time_bucket: TimeBucket::new(bucket),
    });
    let body = object(SCHEMA_BOX_OPENED_BODY, SCHEMA_VERSION_1, &body);
    witnessed(SCHEMA_BOX_OPENED_BODY, body, signers)
}

fn opened() -> &'static [u8] {
    opened_at(OPEN_BUCKET, &with_device(&WITNESSES))
}

fn proof_bytes(option_count: u16, chunk_count: u8) -> &'static [u8] {
    let len = 3 + usize::from(option_count) * (usize::from(chunk_count) + 2) * 32;
    let mut out = std::vec![0xab; len];
    out[0..2].copy_from_slice(&option_count.to_be_bytes());
    out[2] = chunk_count;
    leak_slice(out)
}

/// Cast record `n` of the box (its module counters are `n`). The record
/// stage checks its signatures; this one only counts it.
fn record(n: u64) -> &'static [u8] {
    let counters: Vec<ModuleCounter<'static>> = MODULES
        .iter()
        .map(|m| ModuleCounter {
            module_id: module(m),
            counter: n,
        })
        .collect();
    let body = CastRecordBody::new(&CastRecordParts {
        election_id: election(),
        box_id: box_id(),
        ballot_style_id: BallotStyleId::new(b"STYLE-1").unwrap(),
        proof_system_id: 1,
        commitments: Commitments::new(&[Point32([n as u8; 32]), Point32([0x77; 32])]).unwrap(),
        proof: proof_bytes(16, 2),
        module_counters: ModuleCounters::new(&counters).unwrap(),
        share_package_hash: Hash512([6; 64]),
        transport_flags: 0,
    })
    .unwrap();
    let body = object(SCHEMA_CAST_RECORD_BODY, SCHEMA_VERSION_1, &body);
    let sig = leak([0x44u8; 64]);
    let sigs: Vec<ModuleRecordSig<'static>> = MODULES
        .iter()
        .map(|m| ModuleRecordSig {
            module_id: module(m),
            ed25519: sig,
        })
        .collect();
    object(
        SCHEMA_CAST_RECORD,
        SCHEMA_VERSION_1,
        &CastRecord::new(body, sig, &sigs).unwrap(),
    )
}

/// Batch attestation `index` of `records` records.
fn batch(index: u32, records: u16) -> &'static [u8] {
    let ranges = leak_slice(
        MODULES
            .iter()
            .map(|m| ModuleRange {
                module_id: module(m),
                counter_first: 1,
                counter_last: u64::from(records),
            })
            .collect(),
    );
    let body = BatchAttestBody::new(&BatchAttestParts {
        election_id: election(),
        box_id: box_id(),
        batch_index: index,
        record_count: records,
        records_root: Hash512([0x21; 64]),
        module_ranges: ranges,
        module_refusals: ModuleIds::EMPTY,
        journal_head: Hash512([0x22; 64]),
        time_bucket: TimeBucket::new(120),
    })
    .unwrap();
    let body = object(SCHEMA_BATCH_ATTEST_BODY, SCHEMA_VERSION_1, &body);
    let device = sign(signing(BOX_DEVICE_BASE), b"batch-attest", body);
    let sigs: Vec<ModuleBatchSig<'static>> = MODULES
        .iter()
        .map(|m| ModuleBatchSig {
            module_id: module(m),
            sig: device,
        })
        .collect();
    object(
        SCHEMA_BATCH_ATTEST,
        SCHEMA_VERSION_1,
        &BatchAttest::new(body, &sigs, device).unwrap(),
    )
}

/// Clean in-person counts of `records` ballots.
fn counts(records: u64) -> CloseCounts {
    CloseCounts {
        paper: records,
        records,
        attested: records,
        without_record: 0,
        challenged: 0,
        quarantined: 0,
        visits: records,
        envelopes: 0,
        stickers: 0,
        spoil_envelopes: 0,
    }
}

/// How a close is signed.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sealed {
    /// By the device and the four witnesses, under `purpose`.
    Device(&'static [u8]),
    /// By the four witnesses only (`BoxCloseManual`).
    Manual,
    /// By the device under a key of its own (a forged device signature).
    Forged,
    /// By the spare commitment unit, under `purpose`.
    Spare(&'static [u8]),
}

fn close_with(counts: CloseCounts, open_batches: u8, bucket: u64, sealed: Sealed) -> &'static [u8] {
    let consumed = counts.records + counts.challenged + counts.quarantined;
    let counters: Vec<ModuleCounter<'static>> = MODULES
        .iter()
        .map(|m| ModuleCounter {
            module_id: module(m),
            counter: consumed,
        })
        .collect();
    let body = BoxCloseBody::new(&BoxCloseParts {
        election_id: election(),
        box_id: box_id(),
        counts,
        record_set_root: Hash512([0x23; 64]),
        journal_head: Hash512([0x24; 64]),
        seal_digest: SEAL,
        module_counters: ModuleCounters::new(&counters).unwrap(),
        open_batches,
        time_bucket: TimeBucket::new(bucket),
    });
    let body = object(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, &body);
    let purpose: &[u8] = match sealed {
        Sealed::Device(p) | Sealed::Spare(p) => p,
        Sealed::Manual | Sealed::Forged => b"box-close",
    };
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
            sig: sign(signing(n), purpose, body),
        }
    })
    .collect();
    let device = match sealed {
        Sealed::Device(p) => Some(sign(signing(BOX_DEVICE_BASE), p, body)),
        Sealed::Forged => Some(sign(signing(common::SPARE_BASE), purpose, body)),
        Sealed::Spare(p) => Some(sign(signing(SPARE_DEVICE), p, body)),
        Sealed::Manual => None,
    };
    object(
        SCHEMA_BOX_CLOSE,
        SCHEMA_VERSION_1,
        &BoxClose::new(body, device, &attestations).unwrap(),
    )
}

fn close(records: u64) -> &'static [u8] {
    close_with(
        counts(records),
        0,
        CLOSE_BUCKET,
        Sealed::Device(b"box-close"),
    )
}

fn handoff_body(
    index: u32,
    from: &'static [u8],
    to: &'static [u8],
    previous: Hash512,
    count: u64,
) -> &'static [u8] {
    let body = CustodyHandoffBody::new(&CustodyHandoffParts {
        election_id: election(),
        box_id: box_id(),
        index,
        from_signer: SignerId::new(from).unwrap(),
        from_org: OrgId::new(person(from).0).unwrap(),
        to_signer: SignerId::new(to).unwrap(),
        to_org: OrgId::new(person(to).0).unwrap(),
        previous_handoff_hash: previous,
        seal_digest: SEAL,
        count,
        time_bucket: TimeBucket::new(150),
    })
    .unwrap();
    object(SCHEMA_CUSTODY_HANDOFF_BODY, SCHEMA_VERSION_1, &body)
}

/// The two handoffs of route `R-1`: station → police → counting centre.
fn handoffs(count: u64) -> [&'static [u8]; 2] {
    let first = handoff_body(1, b"clerk-1", b"police-1", Hash512::ZERO, count);
    let second = handoff_body(2, b"police-1", b"cc-1", object_hash(first), count);
    [first, second].map(|body| {
        let parts = CustodyHandoffBody::decode_parts(body);
        witnessed(
            SCHEMA_CUSTODY_HANDOFF_BODY,
            body,
            &[
                By::Person(parts.0, EventRole::Sender),
                By::Person(parts.1, EventRole::Receiver),
            ],
        )
    })
}

/// Reads the sender and receiver back from a handoff body object.
trait HandoffParts {
    fn decode_parts(body: &'static [u8]) -> (&'static [u8], &'static [u8]);
}

impl HandoffParts for CustodyHandoffBody<'static> {
    fn decode_parts(body: &'static [u8]) -> (&'static [u8], &'static [u8]) {
        let b: CustodyHandoffBody<'static> =
            ityv_encoding::decode_object(SCHEMA_CUSTODY_HANDOFF_BODY, SCHEMA_VERSION_1, body)
                .unwrap();
        (
            b.parts().from_signer.as_bytes(),
            b.parts().to_signer.as_bytes(),
        )
    }
}

fn audit() -> &'static [u8] {
    audit_at(200)
}

fn audit_at(bucket: u64) -> &'static [u8] {
    let body = ImprintAuditBody::new(&ImprintAuditParts {
        election_id: election(),
        box_id: box_id(),
        unimprinted: 0,
        duplicate_cast_ids: 0,
        time_bucket: TimeBucket::new(bucket),
    });
    let body = object(SCHEMA_IMPRINT_AUDIT_BODY, SCHEMA_VERSION_1, &body);
    witnessed(SCHEMA_IMPRINT_AUDIT_BODY, body, &WITNESSES)
}

fn fallback(kind: FallbackKind) -> &'static [u8] {
    fallback_at(kind, 110)
}

fn fallback_at(kind: FallbackKind, bucket: u64) -> &'static [u8] {
    let reason = match kind {
        FallbackKind::Declared => FallbackReason::ScannerFault,
        FallbackKind::Ended => FallbackReason::NotApplicable,
    };
    let body = FallbackBody::new(&FallbackParts {
        election_id: election(),
        box_id: box_id(),
        kind,
        reason,
        statement_hash: Hash512([0x51; 64]),
        markers: None,
        time_bucket: TimeBucket::new(bucket),
    })
    .unwrap();
    let body = object(SCHEMA_FALLBACK_BODY, SCHEMA_VERSION_1, &body);
    witnessed(SCHEMA_FALLBACK_BODY, body, &WITNESSES)
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
    witnessed(SCHEMA_LATE_BATCH_CLOSE_BODY, body, &WITNESSES)
}

fn seal_change(reason: SealChangeReason) -> &'static [u8] {
    let body = SealChangeBody::new(&SealChangeParts {
        election_id: election(),
        box_id: box_id(),
        reason,
        previous_seal_digest: SEAL,
        new_seal_digest: Hash512([0x5f; 64]),
        statement_hash: Hash512([0x52; 64]),
        time_bucket: TimeBucket::new(145),
    })
    .unwrap();
    let body = object(SCHEMA_SEAL_CHANGE_BODY, SCHEMA_VERSION_1, &body);
    witnessed(SCHEMA_SEAL_CHANGE_BODY, body, &WITNESSES)
}

fn issuance(issued: u64, returned_empty: u64, bucket: u64) -> &'static [u8] {
    let body = IssuanceCountBody::new(&IssuanceCountParts {
        election_id: election(),
        station_id: StationId::new(STATION).unwrap(),
        stock_received: 50,
        issued: 40,
        voter_spoiled: 0,
        returned: 0,
        unused: 10,
        printer_waste: 0,
        envelopes: Some(EnvelopeIssuance {
            issued,
            returned_empty,
        }),
        time_bucket: TimeBucket::new(bucket),
    });
    let body = object(SCHEMA_ISSUANCE_COUNT_BODY, SCHEMA_VERSION_1, &body);
    witnessed(SCHEMA_ISSUANCE_COUNT_BODY, body, &WITNESSES)
}

// ---------------------------------------------------------------------
// Running the stages.

/// A ledger of `world`: the genesis, its authorization, then `events`
/// (schema, object) in order.
fn ledger(world: &World, events: &[(SchemaId, &'static [u8])]) -> Ledger {
    let mut ledger = Ledger::new();
    ledger
        .push(SCHEMA_SIGNED_GENESIS, world.signed_genesis)
        .push(SCHEMA_SIGNED_LEGAL_AUTHORIZATION, world.authorization);
    for &(schema, event) in events {
        ledger.push(schema, event);
    }
    ledger
}

struct Run {
    index: &'static LedgerIndex<'static>,
    authority: &'static AuthorityStage<'static>,
    boxes: BoxStage<'static>,
}

fn run_ledger(world: &World, ledger: &Ledger) -> Run {
    let index = leak(build_index(world.genesis, ledger.bytes(), &ledger.events));
    let authority = leak(authorize_ledger(world.genesis, index));
    let boxes = verify_boxes(world.genesis, index, authority);
    Run {
        index,
        authority,
        boxes,
    }
}

fn run_in(world: &World, events: &[(SchemaId, &'static [u8])]) -> Run {
    run_ledger(world, &ledger(world, events))
}

fn go(events: &[(SchemaId, &'static [u8])]) -> Run {
    run_in(world(), events)
}

fn w(event: &'static [u8]) -> (SchemaId, &'static [u8]) {
    (SCHEMA_WITNESSED_EVENT, event)
}

fn r(event: &'static [u8]) -> (SchemaId, &'static [u8]) {
    (SCHEMA_CAST_RECORD, event)
}

fn b(event: &'static [u8]) -> (SchemaId, &'static [u8]) {
    (SCHEMA_BATCH_ATTEST, event)
}

fn c(event: &'static [u8]) -> (SchemaId, &'static [u8]) {
    (SCHEMA_BOX_CLOSE, event)
}

/// Opening, `n` records and one batch of them.
fn voting(n: u64) -> Vec<(SchemaId, &'static [u8])> {
    let mut events = std::vec![w(opened())];
    events.extend((1..=n).map(|i| r(record(i))));
    events.push(b(batch(0, n as u16)));
    events
}

/// The whole life of the box: voting, close, custody, count.
fn life() -> Vec<(SchemaId, &'static [u8])> {
    let mut events = voting(3);
    events.push(c(close(3)));
    events.extend(handoffs(3).map(w));
    events.push(w(audit()));
    events
}

fn report(run: &Run) -> &ityv_verify::BoxReport<'static> {
    run.boxes.report(BOX).unwrap()
}

fn refusals(run: &Run) -> Vec<(u64, Refusal)> {
    report(run)
        .refusals
        .iter()
        .map(|x| (x.seq.get(), x.refusal))
        .collect()
}

fn seq(n: u64) -> Seq {
    Seq::new(n).unwrap()
}

// ---------------------------------------------------------------------
// The legal authorization.

#[test]
fn the_ledger_carries_a_valid_authorization() {
    let run = go(&[]);
    assert!(
        run.index.findings().is_empty(),
        "{:?}",
        run.index.findings()
    );
    let a = run.authority.authorization().unwrap();
    assert!(a.scopes().contains(Scope::PublicBoard));
    assert!(a.scopes().contains(Scope::BallotMark));
    assert!(!a.scopes().contains(Scope::Rla));
    assert_eq!(run.authority.seq(), Some(seq(2)));
    assert!(run.authority.holds().is_empty());
}

#[test]
fn without_an_authorization_the_ledger_is_held_and_no_box_opens() {
    let world = world();
    let mut ledger = Ledger::new();
    ledger
        .push(SCHEMA_SIGNED_GENESIS, world.signed_genesis)
        .push(SCHEMA_WITNESSED_EVENT, opened());
    let run = run_ledger(world, &ledger);
    assert!(run.authority.authorization().is_none());
    assert_eq!(run.authority.seq(), None);
    assert!(
        run.authority
            .holds()
            .contains(HoldReason::AuthorizationMissing)
    );
    let rep = report(&run);
    assert_eq!(rep.phase, Phase::Provisioned);
    assert_eq!(refusals(&run), [(2, Refusal::Capability)]);
    for r in run.boxes.reports() {
        assert!(r.holds.contains(HoldReason::AuthorizationMissing));
    }
}

#[test]
fn an_authorization_whose_signature_does_not_verify_is_not_taken() {
    // The committee signature is the commission's: the index accepts the
    // object (the body is the pinned one), the stage refuses it, and a
    // valid one later in the ledger is taken.
    let world = world();
    let signed: ityv_encoding::SignedLegalAuthorization<'static> = ityv_encoding::decode_object(
        SCHEMA_SIGNED_LEGAL_AUTHORIZATION,
        SCHEMA_VERSION_1,
        world.authorization,
    )
    .unwrap();
    let swapped = ityv_encoding::SignedLegalAuthorization::new(
        signed.body_bytes(),
        signed.commission_sig(),
        signed.commission_sig(),
    )
    .unwrap();
    let bad = object(
        SCHEMA_SIGNED_LEGAL_AUTHORIZATION,
        SCHEMA_VERSION_1,
        &swapped,
    );
    let mut ledger = Ledger::new();
    ledger
        .push(SCHEMA_SIGNED_GENESIS, world.signed_genesis)
        .push(SCHEMA_SIGNED_LEGAL_AUTHORIZATION, bad);
    let run = run_ledger(world, &ledger);
    assert!(
        run.index.findings().is_empty(),
        "{:?}",
        run.index.findings()
    );
    assert!(run.authority.authorization().is_none());
    assert!(
        run.authority
            .holds()
            .contains(HoldReason::AuthorizationMissing)
    );
    assert!(
        run.authority
            .holds()
            .contains(HoldReason::AuthorizationInvalid)
    );
    assert_eq!(run.authority.refused(), [seq(2)]);

    // A valid copy later grants the capabilities, and the forged one stays
    // on record as evidence.
    ledger.push(SCHEMA_SIGNED_LEGAL_AUTHORIZATION, world.authorization);
    let run = run_ledger(world, &ledger);
    assert!(run.authority.authorization().is_some());
    assert_eq!(run.authority.seq(), Some(seq(3)));
    assert_eq!(
        run.authority.holds(),
        HoldSet::empty().with(HoldReason::AuthorizationInvalid)
    );
    assert_eq!(run.authority.refused(), [seq(2)]);
}

// ---------------------------------------------------------------------
// The box stage.

#[test]
fn a_clean_box_runs_from_opening_to_count() {
    let run = go(&life());
    assert!(
        run.index.findings().is_empty(),
        "{:?}",
        run.index.findings()
    );
    let rep = report(&run);
    assert_eq!(rep.phase, Phase::Counted);
    assert!(rep.refusals.is_empty(), "{:?}", rep.refusals);
    assert!(rep.holds.is_empty(), "{:?}", rep.holds);
    assert_eq!(rep.counts, Some(counts(3)));
    assert_eq!(rep.box_id, box_id());
    // The other two boxes never opened: no close, so the ledger is not
    // complete.
    assert_eq!(run.boxes.reports().len(), 3);
    for other in [b"BOX-2".as_slice(), b"BOX-3"] {
        let r = run.boxes.report(other).unwrap();
        assert_eq!(r.phase, Phase::Provisioned);
        assert!(r.holds.contains(HoldReason::CloseMissing));
        assert_eq!(r.counts, None);
    }
    assert!(!run.boxes.complete());
    assert!(run.boxes.report(b"BOX-9").is_none());
}

#[test]
fn every_box_closed_is_complete() {
    // A genesis with BOX-1 alone.
    let world = world_with(
        &[Scope::PublicBoard, Scope::TrusteeBody, Scope::BallotMark],
        |d| {
            d.boxes.retain(|b| b.box_id.as_bytes() == BOX);
            d.stations = std::vec![common::station(
                STATION,
                ityv_encoding::StationKind::ElectionDay,
                common::checkin_unit(0, b"U-1A", &[b"M-U1A-P1", b"M-U1A-P2"]),
                common::checkin_unit(1, b"U-1B", &[b"M-U1B-P1", b"M-U1B-P2"]),
                &[BOX],
                &[
                    common::token(b"obs-a", b"PARTY-A", 0xC1),
                    common::token(b"obs-b", b"PARTY-B", 0xC2),
                ],
            )];
            d.policies.truncate(1);
            d.units = std::vec![
                ityv_encoding::ReportingUnitEntry::new(
                    ityv_encoding::ReportingUnitId::new(b"RU-1").unwrap(),
                    1
                )
                .unwrap()
            ];
        },
    );
    let mut events = voting(3);
    events.push(c(close(3)));
    let run = run_in(&world, &events);
    assert!(
        run.index.findings().is_empty(),
        "{:?}",
        run.index.findings()
    );
    assert_eq!(report(&run).phase, Phase::Closed);
    assert!(run.boxes.complete());
    // Not yet counted: the custody chain has not reached the counting
    // centre, which the count would hold.
    assert!(report(&run).holds.is_empty(), "{:?}", report(&run).holds);
}

#[test]
fn an_open_box_without_a_close_is_held() {
    let run = go(&voting(3));
    let rep = report(&run);
    assert_eq!(rep.phase, Phase::Open);
    assert!(rep.holds.contains(HoldReason::CloseMissing));
    assert!(rep.refusals.is_empty());
    assert_eq!(rep.counts, None);
}

#[test]
fn an_opening_needs_the_capability_for_its_day() {
    // Day 20 000 + 200 is after the authorization's last day.
    let late = opened_at(96 * 200, &with_device(&WITNESSES));
    let run = go(&[w(late), r(record(1))]);
    assert_eq!(report(&run).phase, Phase::Provisioned);
    assert_eq!(
        refusals(&run),
        [(3, Refusal::Capability), (4, Refusal::OutOfOrder)]
    );
    assert!(report(&run).holds.contains(HoldReason::BoxEventRefused));
    assert!(report(&run).holds.contains(HoldReason::CloseMissing));
}

#[test]
fn records_need_the_ballot_mark_capability() {
    let world = world_with(&[Scope::PublicBoard], |_| {});
    let run = run_in(&world, &[w(opened()), r(record(1))]);
    assert_eq!(report(&run).phase, Phase::Open);
    assert_eq!(refusals(&run), [(4, Refusal::Capability)]);
}

#[test]
fn a_forged_or_unregistered_signature_is_refused() {
    let forged = opened_at(
        OPEN_BUCKET,
        &[
            By::Device,
            By::Person(b"clerk-1", EventRole::Clerk),
            By::Forger(b"clerk-2", EventRole::Clerk),
            By::Person(b"obs-a", EventRole::Observer),
            By::Person(b"obs-b", EventRole::Observer),
        ],
    );
    // A device key other than the box's.
    let wrong_device = {
        let body = BoxOpenedBody::new(&BoxOpenedParts {
            election_id: election(),
            box_id: box_id(),
            modules: modules(&MODULES),
            seal_digest: SEAL,
            seals_match: true,
            initial_count: 0,
            time_bucket: TimeBucket::new(OPEN_BUCKET),
        });
        let body = object(SCHEMA_BOX_OPENED_BODY, SCHEMA_VERSION_1, &body);
        let mut signers: Vec<(&[u8], EventRole, &[u8], u16)> = std::vec![
            (BOX, EventRole::Device, b"ORG-ST", BOX_DEVICE_BASE + 1),
            (b"clerk-1", EventRole::Clerk, b"ORG-ST", ROSTER_BASE),
            (b"clerk-2", EventRole::Clerk, b"ORG-ST", ROSTER_BASE + 1),
            (b"obs-a", EventRole::Observer, b"PARTY-A", ROSTER_BASE + 2),
            (b"obs-b", EventRole::Observer, b"PARTY-B", ROSTER_BASE + 3),
        ];
        signers.sort_by(|a, b| a.0.cmp(b.0));
        let sigs: Vec<EventSig<'static>> = signers
            .iter()
            .map(|&(id, role, o, n)| EventSig {
                signer_id: SignerId::new(id).unwrap(),
                role,
                org_id: OrgId::new(o).unwrap(),
                sig: sign(signing(n), b"box-open", body),
            })
            .collect();
        object(
            SCHEMA_WITNESSED_EVENT,
            SCHEMA_VERSION_1,
            &WitnessedEvent::new(body, &sigs).unwrap(),
        )
    };
    let stranger = opened_at(
        OPEN_BUCKET,
        &[
            By::Device,
            By::Person(b"clerk-1", EventRole::Clerk),
            By::Person(b"clerk-2", EventRole::Clerk),
            By::Person(b"obs-a", EventRole::Observer),
            By::Person(b"obs-b", EventRole::Observer),
            // Not on the roster as a person of this identifier.
            By::Person(b"court", EventRole::Observer),
        ],
    );
    let run = go(&[w(forged), w(wrong_device), w(stranger), w(opened())]);
    assert_eq!(report(&run).phase, Phase::Open);
    let got = refusals(&run);
    assert_eq!(got.len(), 3, "{got:?}");
    assert_eq!(got[0], (3, Refusal::Signature));
    assert_eq!(got[1], (4, Refusal::Signature));
    assert_eq!(got[2].0, 5);
    assert!(matches!(got[2].1, Refusal::State(_)), "{got:?}");
    assert!(report(&run).holds.contains(HoldReason::BoxEventRefused));
}

#[test]
fn a_signer_unknown_to_the_roster_leaves_no_tokens() {
    let unknown = {
        let body = BoxOpenedBody::new(&BoxOpenedParts {
            election_id: election(),
            box_id: box_id(),
            modules: modules(&MODULES),
            seal_digest: SEAL,
            seals_match: true,
            initial_count: 0,
            time_bucket: TimeBucket::new(OPEN_BUCKET),
        });
        let body = object(SCHEMA_BOX_OPENED_BODY, SCHEMA_VERSION_1, &body);
        let mut signers: Vec<(&[u8], EventRole, &[u8], u16)> = std::vec![
            (BOX, EventRole::Device, b"ORG-ST", BOX_DEVICE_BASE),
            (b"clerk-1", EventRole::Clerk, b"ORG-ST", ROSTER_BASE),
            (b"clerk-9", EventRole::Clerk, b"ORG-ST", ROSTER_BASE + 1),
            (b"obs-a", EventRole::Observer, b"PARTY-A", ROSTER_BASE + 2),
            (b"obs-b", EventRole::Observer, b"PARTY-B", ROSTER_BASE + 3),
        ];
        signers.sort_by(|a, b| a.0.cmp(b.0));
        let sigs: Vec<EventSig<'static>> = signers
            .iter()
            .map(|&(id, role, o, n)| EventSig {
                signer_id: SignerId::new(id).unwrap(),
                role,
                org_id: OrgId::new(o).unwrap(),
                sig: sign(signing(n), b"box-open", body),
            })
            .collect();
        object(
            SCHEMA_WITNESSED_EVENT,
            SCHEMA_VERSION_1,
            &WitnessedEvent::new(body, &sigs).unwrap(),
        )
    };
    let run = go(&[w(unknown)]);
    assert_eq!(refusals(&run), [(3, Refusal::Signature)]);
    assert_eq!(report(&run).phase, Phase::Provisioned);
}

#[test]
fn a_refused_opening_leaves_the_box_to_the_next_one() {
    // An opening with a module the box does not have is refused by the
    // state machine after provisioning; the next opening opens the
    // provisioned box.
    let run = go(&[
        w(opened_with(
            OPEN_BUCKET,
            &[b"M-B1-P1", b"M-B2-P1"],
            &with_device(&WITNESSES),
        )),
        w(opened()),
        w(opened_at(101, &with_device(&WITNESSES))),
    ]);
    assert_eq!(report(&run).phase, Phase::Open);
    let got = refusals(&run);
    assert_eq!(got.len(), 2, "{got:?}");
    assert!(matches!(got[0], (3, Refusal::State(_))));
    // A second opening of an open box.
    assert_eq!(got[1], (5, Refusal::OutOfOrder));
}

#[test]
fn counts_that_disagree_with_the_ledger_hold_the_close() {
    // The close reports four records; the ledger shows three.
    let mut events = voting(3);
    events.push(c(close(4)));
    let run = go(&events);
    let rep = report(&run);
    assert_eq!(rep.phase, Phase::Closed);
    assert!(rep.refusals.is_empty());
    assert!(rep.holds.contains(HoldReason::ObservedCountMismatch));
    assert!(!rep.holds.contains(HoldReason::CloseMissing));
}

#[test]
fn a_refused_close_leaves_the_box_open_for_the_next() {
    // A forged device signature is refused, and so is a close signed for
    // a late close while the box is open; the next close is the box's
    // close (purpose `box-close`).
    let forged = close_with(counts(3), 0, CLOSE_BUCKET, Sealed::Forged);
    let late_purpose = close_with(
        counts(3),
        0,
        CLOSE_BUCKET,
        Sealed::Device(b"late-box-close"),
    );
    let mut events = voting(3);
    events.extend([c(forged), c(late_purpose), c(close(3))]);
    let run = go(&events);
    let rep = report(&run);
    assert_eq!(rep.phase, Phase::Closed);
    // Frames: genesis 1, authorization 2, opening 3, records 4–6, batch 7.
    let got = refusals(&run);
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(got[0], (8, Refusal::Signature));
    assert_eq!(got[1], (9, Refusal::Signature));
    assert_eq!(rep.counts, Some(counts(3)));
}

#[test]
fn a_manual_close_is_held_until_its_late_close() {
    let mut events = voting(3);
    events.push(c(close_with(counts(3), 0, CLOSE_BUCKET, Sealed::Manual)));
    let run = go(&events);
    assert_eq!(report(&run).phase, Phase::Closed);
    assert!(report(&run).holds.contains(HoldReason::ManualClose));

    let late = close_with(
        counts(3),
        0,
        CLOSE_BUCKET + 10,
        Sealed::Device(b"late-box-close"),
    );
    events.push(c(late));
    let run = go(&events);
    assert!(
        report(&run).refusals.is_empty(),
        "{:?}",
        report(&run).refusals
    );
    assert!(!report(&run).holds.contains(HoldReason::ManualClose));
    assert!(report(&run).holds.is_empty(), "{:?}", report(&run).holds);

    // A late close under `box-close` does not verify as a late close.
    events.pop();
    events.push(c(close_with(
        counts(3),
        0,
        CLOSE_BUCKET + 10,
        Sealed::Device(b"box-close"),
    )));
    let run = go(&events);
    assert_eq!(refusals(&run), [(9, Refusal::Signature)]);
    assert!(report(&run).holds.contains(HoldReason::ManualClose));
}

#[test]
fn a_late_batch_close_resolves_the_open_batch() {
    // Three records, a batch of two, a close with one batch open; after
    // the close the third record's batch and its LateBatchClose.
    let mut events = std::vec![w(opened())];
    events.extend((1..=3).map(|i| r(record(i))));
    events.push(b(batch(0, 2)));
    let mut open = counts(3);
    open.attested = 2;
    events.push(c(close_with(
        open,
        1,
        CLOSE_BUCKET,
        Sealed::Device(b"box-close"),
    )));
    let run1 = go(&events);
    assert!(report(&run1).holds.contains(HoldReason::OpenBatches));

    let late = batch(1, 1);
    // The LateBatchClose may come before or after its batch.
    for order in [
        [b(late), w(late_batch_close(late, CLOSE_BUCKET + 5))],
        [w(late_batch_close(late, CLOSE_BUCKET + 5)), b(late)],
    ] {
        let mut all = events.clone();
        all.extend(order);
        let run = go(&all);
        assert!(
            run.index.findings().is_empty(),
            "{:?}",
            run.index.findings()
        );
        assert!(
            report(&run).refusals.is_empty(),
            "{:?}",
            report(&run).refusals
        );
        assert!(!report(&run).holds.contains(HoldReason::OpenBatches));
    }

    // A batch after the close without its LateBatchClose, and a
    // LateBatchClose naming another batch: both unmatched.
    let mut all = events.clone();
    all.push(b(late));
    all.push(w(late_batch_close(batch(7, 1), CLOSE_BUCKET + 5)));
    let run = go(&all);
    assert_eq!(
        refusals(&run),
        [(9, Refusal::Unmatched), (10, Refusal::Unmatched)]
    );
    assert!(report(&run).holds.contains(HoldReason::OpenBatches));

    // Outside the 24-hour window the state machine refuses the pair.
    let mut all = events.clone();
    all.extend([b(late), w(late_batch_close(late, CLOSE_BUCKET + 97))]);
    let run = go(&all);
    assert!(
        matches!(
            refusals(&run)[..],
            [(9, Refusal::State(_)), (10, Refusal::State(_))]
        ),
        "{:?}",
        refusals(&run)
    );

    // One batch body twice (the copy differs only in signature bytes, so
    // the ledger takes both objects): the second is refused and cannot
    // cover a record twice.
    let copy = {
        let a: BatchAttest<'static> =
            ityv_encoding::decode_object(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, late).unwrap();
        let flipped = leak([0x01u8; ityv_encoding::HYBRID_SIG_LEN]);
        let sigs: Vec<ModuleBatchSig<'static>> = a.module_sigs().collect();
        object(
            SCHEMA_BATCH_ATTEST,
            SCHEMA_VERSION_1,
            &BatchAttest::new(a.body_bytes(), &sigs, flipped).unwrap(),
        )
    };
    let mut all = events.clone();
    all.extend([
        b(late),
        w(late_batch_close(late, CLOSE_BUCKET + 5)),
        b(copy),
        w(late_batch_close(late, CLOSE_BUCKET + 6)),
    ]);
    let run = go(&all);
    assert_eq!(
        refusals(&run),
        [(11, Refusal::Duplicate), (12, Refusal::Unmatched)]
    );
    assert!(!report(&run).holds.contains(HoldReason::OpenBatches));
    assert!(report(&run).holds.contains(HoldReason::BoxEventRefused));

    // A LateBatchClose while the box is still open is out of order, and
    // cannot later pair with the batch.
    let mut all = std::vec![w(opened())];
    all.extend((1..=3).map(|i| r(record(i))));
    all.push(b(batch(0, 2)));
    all.push(w(late_batch_close(late, CLOSE_BUCKET + 5)));
    all.push(events[5]);
    all.push(b(late));
    let run = go(&all);
    assert_eq!(
        refusals(&run),
        [(8, Refusal::OutOfOrder), (10, Refusal::Unmatched)]
    );
    assert!(report(&run).holds.contains(HoldReason::OpenBatches));
}

#[test]
fn a_record_or_challenge_body_counts_once() {
    // A cast record whose body is on the ledger already, under other
    // signature bytes.
    let first = record(1);
    let copy = {
        let rec: CastRecord<'static> =
            ityv_encoding::decode_object(SCHEMA_CAST_RECORD, SCHEMA_VERSION_1, first).unwrap();
        let other = leak([0x45u8; 64]);
        let sigs: Vec<ModuleRecordSig<'static>> = MODULES
            .iter()
            .map(|m| ModuleRecordSig {
                module_id: module(m),
                ed25519: other,
            })
            .collect();
        object(
            SCHEMA_CAST_RECORD,
            SCHEMA_VERSION_1,
            &CastRecord::new(rec.body_bytes(), other, &sigs).unwrap(),
        )
    };
    let run = go(&[w(opened()), r(first), r(copy), b(batch(0, 1)), c(close(1))]);
    assert_eq!(refusals(&run), [(5, Refusal::Duplicate)]);
    assert_eq!(report(&run).phase, Phase::Closed);
    assert_eq!(report(&run).counts, Some(counts(1)));
}

#[test]
fn a_box_takes_one_late_close() {
    // A late close whose human counts differ holds the box; a second one
    // whose counts match cannot erase that.
    let mut events = voting(3);
    events.push(c(close_with(counts(3), 0, CLOSE_BUCKET, Sealed::Manual)));
    let mut differs = counts(3);
    differs.paper = 4;
    events.push(c(close_with(
        differs,
        0,
        CLOSE_BUCKET + 1,
        Sealed::Device(b"late-box-close"),
    )));
    events.push(c(close_with(
        counts(3),
        0,
        CLOSE_BUCKET + 2,
        Sealed::Device(b"late-box-close"),
    )));
    let run = go(&events);
    let rep = report(&run);
    assert!(rep.holds.contains(HoldReason::LateCloseDiffers));
    assert!(rep.holds.contains(HoldReason::ManualClose));
    assert!(matches!(
        refusals(&run)[..],
        [(10, Refusal::State(ityv_state::Error::LateClose))]
    ));
    // A late close dated before the close is refused.
    let mut events = voting(3);
    events.push(c(close_with(counts(3), 0, CLOSE_BUCKET, Sealed::Manual)));
    events.push(c(close_with(
        counts(3),
        0,
        CLOSE_BUCKET - 1,
        Sealed::Device(b"late-box-close"),
    )));
    let run = go(&events);
    assert!(matches!(
        refusals(&run)[..],
        [(9, Refusal::State(ityv_state::Error::LateWindow))]
    ));
    assert!(report(&run).holds.contains(HoldReason::ManualClose));
}

#[test]
fn a_fallback_comes_and_goes_while_the_box_is_open() {
    let events = std::vec![
        w(opened()),
        r(record(1)),
        w(fallback(FallbackKind::Declared)),
        r(record(2)),
        w(fallback_at(FallbackKind::Declared, 111)),
        w(fallback(FallbackKind::Ended)),
        r(record(3)),
        b(batch(0, 3)),
        w(fallback_at(FallbackKind::Ended, 112)),
        c(close(3)),
    ];
    let run = go(&events);
    let rep = report(&run);
    assert_eq!(rep.phase, Phase::Closed);
    // A second declaration while in fallback and an end while open.
    assert_eq!(
        refusals(&run),
        [(7, Refusal::OutOfOrder), (11, Refusal::OutOfOrder)]
    );

    // A close while in fallback closes the box.
    let run = go(&[
        w(opened()),
        w(fallback(FallbackKind::Declared)),
        r(record(1)),
        b(batch(0, 1)),
        c(close(1)),
    ]);
    assert_eq!(report(&run).phase, Phase::Closed);
    assert!(report(&run).refusals.is_empty());
}

#[test]
fn events_out_of_their_state_are_refused() {
    let run = go(&[
        r(record(1)),
        b(batch(0, 1)),
        w(audit()),
        handoffs(3).map(w)[0],
        w(seal_change(SealChangeReason::Broken)),
        w(fallback(FallbackKind::Declared)),
        c(close(0)),
    ]);
    assert_eq!(report(&run).phase, Phase::Provisioned);
    let got: Vec<Refusal> = refusals(&run).iter().map(|x| x.1).collect();
    assert_eq!(got, std::vec![Refusal::OutOfOrder; 7]);

    // After the count, custody events are out of order too, and a late
    // close of a counted box needs a manual close first.
    let mut events = life();
    events.extend([
        w(seal_change(SealChangeReason::Broken)),
        handoffs(4).map(w)[0],
        w(audit_at(201)),
        c(close_with(
            counts(3),
            0,
            CLOSE_BUCKET + 1,
            Sealed::Device(b"late-box-close"),
        )),
    ]);
    let run = go(&events);
    assert_eq!(report(&run).phase, Phase::Counted);
    let got = refusals(&run);
    assert_eq!(got.len(), 4, "{got:?}");
    assert_eq!(got[0].1, Refusal::OutOfOrder);
    assert_eq!(got[1].1, Refusal::OutOfOrder);
    assert_eq!(got[2].1, Refusal::OutOfOrder);
    assert!(matches!(got[3].1, Refusal::State(_)));
}

#[test]
fn custody_and_seal_changes_follow_the_close() {
    // A broken seal and an incomplete chain leave holds at the count.
    let mut events = voting(3);
    events.push(c(close(3)));
    events.push(w(seal_change(SealChangeReason::Broken)));
    events.push(handoffs(3).map(w)[0]);
    events.push(w(audit()));
    let run = go(&events);
    let rep = report(&run);
    assert_eq!(rep.phase, Phase::Counted);
    assert!(rep.holds.contains(HoldReason::SealBroken));
    assert!(rep.holds.contains(HoldReason::CustodyIncomplete));
    assert!(rep.refusals.is_empty(), "{:?}", rep.refusals);

    // A handoff out of order (the second first) is refused.
    let mut events = voting(3);
    events.push(c(close(3)));
    events.push(handoffs(3).map(w)[1]);
    let run = go(&events);
    assert!(matches!(refusals(&run)[..], [(9, Refusal::State(_))]));
}

#[test]
fn an_out_of_district_box_closes_with_its_station_issuance() {
    let world = world_with(
        &[Scope::PublicBoard, Scope::TrusteeBody, Scope::BallotMark],
        |d| {
            for b in &mut d.boxes {
                if b.box_id.as_bytes() == BOX {
                    b.profile = CaptureProfile::Absentee;
                }
            }
        },
    );
    let mut absentee = counts(3);
    absentee.paper = 0;
    absentee.envelopes = 3;
    absentee.stickers = 3;
    let absentee_close = close_with(absentee, 0, CLOSE_BUCKET, Sealed::Device(b"box-close"));
    let mut events = voting(3);
    // An issuance count that does not match, then one that does: the last
    // before the close counts. One after the close does not.
    events.push(w(issuance(9, 0, 130)));
    events.push(w(issuance(4, 1, 131)));
    events.push(c(absentee_close));
    events.push(w(issuance(9, 0, 150)));
    let run = run_in(&world, &events);
    assert!(
        run.index.findings().is_empty(),
        "{:?}",
        run.index.findings()
    );
    let rep = report(&run);
    assert_eq!(rep.phase, Phase::Closed);
    assert!(rep.refusals.is_empty(), "{:?}", rep.refusals);
    assert!(rep.holds.is_empty(), "{:?}", rep.holds);

    // Without an issuance count before the close.
    let mut events = voting(3);
    events.push(c(absentee_close));
    events.push(w(issuance(4, 1, 150)));
    let run = run_in(&world, &events);
    assert!(report(&run).holds.contains(HoldReason::IssuanceMissing));

    // With the last one mismatched.
    let mut events = voting(3);
    events.push(w(issuance(4, 1, 130)));
    events.push(w(issuance(9, 0, 131)));
    events.push(c(absentee_close));
    let run = run_in(&world, &events);
    assert!(report(&run).holds.contains(HoldReason::EnvelopeMismatch));
}

#[test]
fn the_index_holds_reach_the_box() {
    // A replayed record is refused by the index and held on the box.
    let rec = record(1);
    let run = go(&[w(opened()), r(rec), r(rec), b(batch(0, 1)), c(close(1))]);
    assert!(report(&run).holds.contains(HoldReason::EventReplayed));
    assert_eq!(report(&run).phase, Phase::Closed);
}

#[test]
fn events_of_a_box_an_amendment_removed_are_held() {
    // The genesis has BOX-3 at ST-2; an amendment removes the box, its
    // station and its reporting unit. The index still knows the box (an
    // earlier state had it), but the box stage does not run it: each of its
    // events is refused and the box is held.
    let mut draft = Draft::standard();
    draft.roster.push(roster_signer(
        6,
        b"cc-1",
        RosterRole::Custodian,
        b"ORG-CC",
        None,
    ));
    draft.appointments = draft.referenced_appointments();
    let (body, authorization) = common::legal_authorization(
        &[Scope::PublicBoard, Scope::TrusteeBody, Scope::BallotMark],
        20_000,
        20_100,
    );
    let built = leak(sign_genesis_with(&draft, draft.raw(), &SIGNERS, |p| {
        p.legal_authorization_hash = object_hash(body);
    }));
    let mut amended = draft.clone();
    amended.boxes.retain(|b| b.box_id.as_bytes() != b"BOX-3");
    amended
        .stations
        .retain(|s| s.station_id().as_bytes() != b"ST-2");
    amended
        .policies
        .retain(|p| p.station_id().as_bytes() != b"ST-2");
    amended.units.retain(|u| u.unit_id().as_bytes() != b"RU-2");
    amended.appointments = amended.referenced_appointments();
    let amendment = common::amendment(1, built.pin, &amended.raw(), &SIGNERS);
    let genesis = leak(verify_genesis(&built.pin, &built.input(), &[amendment]).unwrap());
    assert!(genesis.expected_box(b"BOX-3").is_none());
    assert!(genesis.knows_box(b"BOX-3"));
    let world = World {
        genesis,
        signed_genesis: built.signed,
        authorization,
    };
    let stray = {
        let body = BatchAttestBody::new(&BatchAttestParts {
            election_id: election(),
            box_id: BoxId::new(b"BOX-3").unwrap(),
            batch_index: 0,
            record_count: 1,
            records_root: Hash512([0x21; 64]),
            module_ranges: leak_slice(std::vec![ModuleRange {
                module_id: module(b"M-B3-P1"),
                counter_first: 1,
                counter_last: 1,
            }]),
            module_refusals: ModuleIds::EMPTY,
            journal_head: Hash512([0x22; 64]),
            time_bucket: TimeBucket::new(120),
        })
        .unwrap();
        let body = object(SCHEMA_BATCH_ATTEST_BODY, SCHEMA_VERSION_1, &body);
        let sig = sign(signing(BOX_DEVICE_BASE + 2), b"batch-attest", body);
        let sigs = [ModuleBatchSig {
            module_id: module(b"M-B3-P1"),
            sig,
        }];
        object(
            SCHEMA_BATCH_ATTEST,
            SCHEMA_VERSION_1,
            &BatchAttest::new(body, &sigs, sig).unwrap(),
        )
    };
    let run = run_in(&world, &[b(stray)]);
    assert!(
        run.index.findings().is_empty(),
        "{:?}",
        run.index.findings()
    );
    // BOX-1 and BOX-2 are expected; BOX-3 is reported after them.
    let reports = run.boxes.reports();
    assert_eq!(reports.len(), 3);
    let r = run.boxes.report(b"BOX-3").unwrap();
    assert_eq!(r.phase, Phase::Provisioned);
    assert_eq!(
        r.refusals,
        [ityv_verify::BoxRefusal {
            seq: seq(3),
            refusal: Refusal::Unexpected
        }]
    );
    assert!(r.holds.contains(HoldReason::BoxEventRefused));
    assert!(!r.holds.contains(HoldReason::CloseMissing));
    assert_eq!(reports[2].box_id, BoxId::new(b"BOX-3").unwrap());
}

// ---------------------------------------------------------------------
// Amendments: a spare commitment unit and a new clerk.

/// A world whose genesis has one amendment, for the ledger to carry: it
/// registers a spare commitment unit for `BOX-1` (a new device key) and
/// adds `clerk-3` to the roster at `ST-1`.
struct Amended {
    world: World,
    amendment: &'static [u8],
}

fn amended() -> &'static Amended {
    static AMENDED: OnceLock<&'static Amended> = OnceLock::new();
    AMENDED.get_or_init(|| leak(amended_with(true)))
}

/// As [`amended`]; `new_device` false keeps `BOX-1`'s device key (the
/// amendment only adds `clerk-3`).
fn amended_with(new_device: bool) -> Amended {
    let mut draft = Draft::standard();
    draft.roster.push(roster_signer(
        6,
        b"cc-1",
        RosterRole::Custodian,
        b"ORG-CC",
        None,
    ));
    draft.appointments = draft.referenced_appointments();
    let (body, authorization) = common::legal_authorization(
        &[Scope::PublicBoard, Scope::TrusteeBody, Scope::BallotMark],
        20_000,
        20_100,
    );
    let built = leak(sign_genesis_with(&draft, draft.raw(), &SIGNERS, |p| {
        p.legal_authorization_hash = object_hash(body);
    }));
    let mut next = draft.clone();
    if new_device {
        for b in &mut next.boxes {
            if b.box_id.as_bytes() == BOX {
                b.device_key = common::registered(SPARE_DEVICE);
            }
        }
    }
    next.roster.push(roster_signer(
        7,
        b"clerk-3",
        RosterRole::Clerk,
        b"ORG-ST",
        Some(STATION),
    ));
    next.appointments = next.referenced_appointments();
    let amendment = common::amendment(1, built.pin, &next.raw(), &SIGNERS);
    let genesis = leak(verify_genesis(&built.pin, &built.input(), &[amendment]).unwrap());
    Amended {
        world: World {
            genesis,
            signed_genesis: built.signed,
            authorization,
        },
        amendment: amendment.signed,
    }
}

fn g(event: &'static [u8]) -> (SchemaId, &'static [u8]) {
    (SCHEMA_SIGNED_GENESIS, event)
}

/// A `BoxUnitSwap` of `BOX-1` at slot `slot`, signed by `signers`.
fn swap_with(slot: u64, signers: &[By]) -> &'static [u8] {
    use ityv_encoding::{BoxUnitSwapBody, BoxUnitSwapParts, SCHEMA_BOX_UNIT_SWAP_BODY};
    let body = BoxUnitSwapBody::new(&BoxUnitSwapParts {
        election_id: election(),
        box_id: box_id(),
        at_slot: slot,
        confirmed: true,
        sheets_in: 2,
    })
    .unwrap();
    let body = object(SCHEMA_BOX_UNIT_SWAP_BODY, SCHEMA_VERSION_1, &body);
    witnessed(SCHEMA_BOX_UNIT_SWAP_BODY, body, signers)
}

fn swap(slot: u64) -> &'static [u8] {
    swap_with(slot, &WITNESSES)
}

fn spare_close(records: u64) -> &'static [u8] {
    close_with(
        counts(records),
        0,
        CLOSE_BUCKET,
        Sealed::Spare(b"box-close"),
    )
}

#[test]
fn a_box_follows_a_device_swap_witnessed_on_site() {
    // Frames: genesis 1, authorization 2, opening 3, records 4–5,
    // amendment 6, swap 7, a record the replaced device uploads late 8,
    // batch 9, the spare's close 10, custody and count after it.
    let a = amended();
    let mut events = std::vec![
        w(opened()),
        r(record(1)),
        r(record(2)),
        g(a.amendment),
        w(swap(7)),
        r(record(3)),
        b(batch(0, 3)),
        c(spare_close(3)),
    ];
    events.extend(handoffs(3).map(w));
    events.push(w(audit()));
    let run = run_in(&a.world, &events);
    assert!(
        run.index.findings().is_empty(),
        "{:?}",
        run.index.findings()
    );
    assert_eq!(run.index.amendment_frames(), [seq(6)]);
    let rep = report(&run);
    assert!(rep.refusals.is_empty(), "{:?}", rep.refusals);
    assert_eq!(rep.phase, Phase::Counted);
    assert!(rep.holds.is_empty(), "{:?}", rep.holds);
    assert_eq!(rep.counts, Some(counts(3)));
}

#[test]
fn a_new_device_closes_only_after_its_amendment_and_the_swap() {
    let a = amended();
    // Before the amendment's frame the spare's key is not the box's.
    let run = run_in(
        &a.world,
        &[
            w(opened()),
            r(record(1)),
            b(batch(0, 1)),
            c(spare_close(1)),
            g(a.amendment),
            w(swap(7)),
            c(close_with(
                counts(1),
                0,
                CLOSE_BUCKET + 1,
                Sealed::Spare(b"box-close"),
            )),
        ],
    );
    assert_eq!(refusals(&run), [(6, Refusal::Signature)]);
    assert_eq!(report(&run).phase, Phase::Closed);

    // After the amendment but before the swap: out of order; a manual
    // close is not held back.
    let run = run_in(
        &a.world,
        &[
            w(opened()),
            r(record(1)),
            b(batch(0, 1)),
            g(a.amendment),
            c(spare_close(1)),
            w(swap(7)),
            c(close_with(
                counts(1),
                0,
                CLOSE_BUCKET + 1,
                Sealed::Spare(b"box-close"),
            )),
        ],
    );
    assert_eq!(refusals(&run), [(7, Refusal::OutOfOrder)]);
    assert_eq!(report(&run).phase, Phase::Closed);
    let run = run_in(
        &a.world,
        &[
            w(opened()),
            r(record(1)),
            b(batch(0, 1)),
            g(a.amendment),
            c(close_with(counts(1), 0, CLOSE_BUCKET, Sealed::Manual)),
        ],
    );
    assert!(report(&run).refusals.is_empty());
    assert_eq!(report(&run).phase, Phase::Closed);
    assert!(report(&run).holds.contains(HoldReason::ManualClose));

    // The replaced device cannot close after the amendment, swap or not.
    let run = run_in(
        &a.world,
        &[
            w(opened()),
            r(record(1)),
            b(batch(0, 1)),
            g(a.amendment),
            w(swap(7)),
            c(close(1)),
        ],
    );
    assert_eq!(refusals(&run), [(8, Refusal::Signature)]);
    assert_eq!(report(&run).phase, Phase::Open);
}

#[test]
fn a_swap_needs_an_amendment_and_an_open_box() {
    let a = amended();
    // Before the amendment: no new key to swap to.
    let run = run_in(&a.world, &[w(opened()), w(swap(7)), g(a.amendment)]);
    assert_eq!(refusals(&run), [(4, Refusal::OutOfOrder)]);
    // Before the opening: the spare opens the box itself, no swap needed.
    let run = run_in(
        &a.world,
        &[
            g(a.amendment),
            w(swap(7)),
            w(opened_at(OPEN_BUCKET, &with_device_spare())),
            r(record(1)),
            b(batch(0, 1)),
            c(spare_close(1)),
        ],
    );
    assert_eq!(refusals(&run), [(4, Refusal::OutOfOrder)]);
    assert_eq!(report(&run).phase, Phase::Closed);
    // After the close, and a second swap.
    let run = run_in(
        &a.world,
        &[
            w(opened()),
            r(record(1)),
            b(batch(0, 1)),
            c(close_with(counts(1), 0, CLOSE_BUCKET, Sealed::Manual)),
            g(a.amendment),
            w(swap(7)),
        ],
    );
    assert_eq!(refusals(&run), [(8, Refusal::OutOfOrder)]);
    let run = run_in(
        &a.world,
        &[w(opened()), g(a.amendment), w(swap(7)), w(swap(8))],
    );
    assert_eq!(refusals(&run), [(6, Refusal::OutOfOrder)]);
    // A swap with a forged signature, or signed as a clerk by someone the
    // roster registers in another role, is refused and leaves the swap
    // due.
    let forged = swap_with(
        7,
        &[
            By::Person(b"clerk-1", EventRole::Clerk),
            By::Forger(b"clerk-2", EventRole::Clerk),
            By::Person(b"obs-a", EventRole::Observer),
            By::Person(b"obs-b", EventRole::Observer),
        ],
    );
    let wrong_role = swap_with(
        9,
        &[
            By::Person(b"clerk-1", EventRole::Clerk),
            By::Person(b"court", EventRole::Clerk),
            By::Person(b"obs-a", EventRole::Observer),
            By::Person(b"obs-b", EventRole::Observer),
        ],
    );
    let run = run_in(
        &a.world,
        &[
            w(opened()),
            g(a.amendment),
            w(forged),
            w(wrong_role),
            r(record(1)),
            b(batch(0, 1)),
            c(spare_close(1)),
        ],
    );
    let got = refusals(&run);
    assert_eq!(got.len(), 3, "{got:?}");
    assert_eq!(got[0], (5, Refusal::Signature));
    assert!(matches!(got[1], (6, Refusal::State(_))), "{got:?}");
    assert_eq!(got[2], (9, Refusal::OutOfOrder));
}

fn with_device_spare() -> Vec<By> {
    let mut all = std::vec![By::Spare];
    all.extend_from_slice(&WITNESSES);
    all
}

#[test]
fn a_roster_change_applies_from_the_amendment_frame() {
    // The amendment only adds clerk-3: no device swap is due.
    let a = leak(amended_with(false));
    let signed_by_clerk_3 = |bucket| {
        fallback_signed(
            FallbackKind::Declared,
            bucket,
            &[
                By::Person(b"clerk-1", EventRole::Clerk),
                By::Person(b"clerk-3", EventRole::Clerk),
                By::Person(b"obs-a", EventRole::Observer),
                By::Person(b"obs-b", EventRole::Observer),
            ],
        )
    };
    let run = run_in(
        &a.world,
        &[
            w(opened()),
            w(signed_by_clerk_3(110)),
            g(a.amendment),
            w(signed_by_clerk_3(111)),
            r(record(1)),
            b(batch(0, 1)),
            c(close(1)),
        ],
    );
    assert_eq!(refusals(&run), [(4, Refusal::Signature)]);
    assert_eq!(report(&run).phase, Phase::Closed);
}

/// A fallback event at `bucket` signed by `signers`.
fn fallback_signed(kind: FallbackKind, bucket: u64, signers: &[By]) -> &'static [u8] {
    let reason = match kind {
        FallbackKind::Declared => FallbackReason::ScannerFault,
        FallbackKind::Ended => FallbackReason::NotApplicable,
    };
    let body = FallbackBody::new(&FallbackParts {
        election_id: election(),
        box_id: box_id(),
        kind,
        reason,
        statement_hash: Hash512([0x51; 64]),
        markers: None,
        time_bucket: TimeBucket::new(bucket),
    })
    .unwrap();
    let body = object(SCHEMA_FALLBACK_BODY, SCHEMA_VERSION_1, &body);
    witnessed(SCHEMA_FALLBACK_BODY, body, signers)
}

#[test]
fn an_amendment_missing_from_the_ledger_holds_the_box() {
    // The verifier applied the amendment but the ledger does not carry
    // it: every event is checked under the genesis, and the hold reaches
    // the box.
    let a = amended();
    let run = run_in(&a.world, &life());
    assert!(run.index.amendment_frames().is_empty());
    let rep = report(&run);
    assert!(rep.refusals.is_empty(), "{:?}", rep.refusals);
    assert_eq!(rep.phase, Phase::Counted);
    assert!(rep.holds.contains(HoldReason::AmendmentMissing));
}

#[test]
fn an_amendment_after_the_close_is_followed_without_a_swap() {
    let a = amended();
    let mut events = voting(3);
    events.push(c(close(3)));
    events.push(g(a.amendment));
    events.extend(handoffs(3).map(w));
    events.push(w(audit()));
    let run = run_in(&a.world, &events);
    let rep = report(&run);
    assert!(rep.refusals.is_empty(), "{:?}", rep.refusals);
    assert_eq!(rep.phase, Phase::Counted);
    assert!(rep.holds.is_empty(), "{:?}", rep.holds);
}

#[test]
fn a_box_an_amendment_adds_runs_from_the_amendment_frame() {
    // The genesis has no BOX-1 (ST-1 has BOX-2 alone); the amendment adds
    // it. Its opening before the amendment's frame is refused; the box
    // opens and closes after it.
    let mut draft = Draft::standard();
    draft.roster.push(roster_signer(
        6,
        b"cc-1",
        RosterRole::Custodian,
        b"ORG-CC",
        None,
    ));
    draft.appointments = draft.referenced_appointments();
    let full = draft.clone();
    draft.boxes.retain(|b| b.box_id.as_bytes() != BOX);
    let second = draft.stations[1];
    draft.stations = std::vec![
        common::station(
            STATION,
            ityv_encoding::StationKind::ElectionDay,
            common::checkin_unit(0, b"U-1A", &[b"M-U1A-P1", b"M-U1A-P2"]),
            common::checkin_unit(1, b"U-1B", &[b"M-U1B-P1", b"M-U1B-P2"]),
            &[b"BOX-2"],
            &[
                common::token(b"obs-a", b"PARTY-A", 0xC1),
                common::token(b"obs-b", b"PARTY-B", 0xC2),
            ],
        ),
        second,
    ];
    draft.units[0] = ityv_encoding::ReportingUnitEntry::new(
        ityv_encoding::ReportingUnitId::new(b"RU-1").unwrap(),
        1,
    )
    .unwrap();
    let (body, authorization) = common::legal_authorization(
        &[Scope::PublicBoard, Scope::TrusteeBody, Scope::BallotMark],
        20_000,
        20_100,
    );
    let built = leak(sign_genesis_with(&draft, draft.raw(), &SIGNERS, |p| {
        p.legal_authorization_hash = object_hash(body);
    }));
    let amendment = common::amendment(1, built.pin, &full.raw(), &SIGNERS);
    let genesis = leak(verify_genesis(&built.pin, &built.input(), &[amendment]).unwrap());
    assert!(genesis.expected_box_at(0, BOX).is_none());
    let world = World {
        genesis,
        signed_genesis: built.signed,
        authorization,
    };
    let early = opened_at(OPEN_BUCKET - 1, &with_device(&WITNESSES));
    let mut events = std::vec![w(early), g(amendment.signed)];
    events.extend(voting(3));
    events.push(c(close(3)));
    let run = run_in(&world, &events);
    assert!(
        run.index.findings().is_empty(),
        "{:?}",
        run.index.findings()
    );
    assert_eq!(refusals(&run), [(3, Refusal::Unexpected)]);
    assert_eq!(report(&run).phase, Phase::Closed);
    assert_eq!(report(&run).counts, Some(counts(3)));
}
