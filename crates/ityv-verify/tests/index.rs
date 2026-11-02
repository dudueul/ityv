//! The ledger index (PROTOCOL.md §5.1, §14 3; VC-010, VC-039, VC-101):
//! frames linked into a chain, events found by hash and decoded as their
//! schema, replayed events and records after close refused, and every
//! refusal held on the box, the station's boxes or the whole ledger.
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

use std::vec::Vec;

use common::{
    Draft, SIGNERS, amendment, checkin_unit, leak_slice, object, sign, sign_genesis,
    sign_genesis_with, signing, standard, station,
};
use ityv_crypto::object_hash;
use ityv_encoding::{
    Attestation, BatchAttest, BatchAttestBody, BatchAttestParts, BoxClose, BoxCloseBody,
    BoxCloseParts, BoxId, CheckinProgressBody, CheckinProgressParts, CheckinProgressState,
    CloseCounts, Day, ElectionId, EventRole, EventSig, HYBRID_SIG_LEN, Hash512, LedgerFrame,
    LegalAuthorizationBody, ModuleBatchSig, ModuleCounter, ModuleCounters, ModuleIds, ModuleRange,
    OrgId, ProgressTick, SCHEMA_BATCH_ATTEST, SCHEMA_BATCH_ATTEST_BODY, SCHEMA_BOX_CLOSE,
    SCHEMA_BOX_CLOSE_BODY, SCHEMA_CAST_RECORD, SCHEMA_CHECKIN_PROGRESS_BODY, SCHEMA_LEDGER_FRAME,
    SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_PROGRESS_TICK, SCHEMA_SIGNED_GENESIS, SCHEMA_VERSION_1,
    SCHEMA_WITNESSED_EVENT, SchemaId, ScopeSet, Seq, SignerId, SignerRole, StationId, StationKind,
    TimeBucket, UnitId, WitnessedEvent,
};
use ityv_ledger::Accumulator;
use ityv_state::HoldReason;
use ityv_verify::{FindingKind, LedgerIndex, Scope, VerifiedGenesis, build_index, verify_genesis};

fn verified() -> &'static VerifiedGenesis<'static> {
    let built = standard();
    common::leak(verify_genesis(&built.pin, &built.input(), &[]).unwrap())
}

fn election() -> ElectionId<'static> {
    common::election()
}

fn module(id: &'static [u8]) -> ityv_encoding::ModuleId<'static> {
    common::module(id)
}

/// A batch attestation of `box_id` (whose modules are `mods`) numbered
/// `batch`.
fn batch(box_id: &'static [u8], mods: [&'static [u8]; 2], batch: u32) -> &'static [u8] {
    let ranges = leak_slice(
        mods.iter()
            .map(|m| ModuleRange {
                module_id: module(m),
                counter_first: 1,
                counter_last: 3,
            })
            .collect(),
    );
    let body = BatchAttestBody::new(&BatchAttestParts {
        election_id: election(),
        box_id: BoxId::new(box_id).unwrap(),
        batch_index: batch,
        record_count: 3,
        records_root: Hash512([0x21; 64]),
        module_ranges: ranges,
        module_refusals: ModuleIds::EMPTY,
        journal_head: Hash512([0x22; 64]),
        time_bucket: TimeBucket::new(40),
    })
    .unwrap();
    let body = object(SCHEMA_BATCH_ATTEST_BODY, SCHEMA_VERSION_1, &body);
    let device = sign(signing(100), b"batch-attest", body);
    let sigs: Vec<ModuleBatchSig<'static>> = mods
        .iter()
        .map(|m| ModuleBatchSig {
            module_id: module(m),
            sig: device,
        })
        .collect();
    let attest = BatchAttest::new(body, &sigs, device).unwrap();
    object(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, &attest)
}

/// A device-signed close of `box_id`.
fn close(box_id: &'static [u8], mods: [&'static [u8]; 2], bucket: u64) -> &'static [u8] {
    let counters: Vec<ModuleCounter<'static>> = mods
        .iter()
        .map(|m| ModuleCounter {
            module_id: module(m),
            counter: 3,
        })
        .collect();
    let body = BoxCloseBody::new(&BoxCloseParts {
        election_id: election(),
        box_id: BoxId::new(box_id).unwrap(),
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
        time_bucket: TimeBucket::new(bucket),
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

/// A check-in progress tick of station `station` for `slot`.
fn tick(station: &'static [u8], unit: &'static [u8], slot: u64) -> &'static [u8] {
    let body = CheckinProgressBody::new(&CheckinProgressParts {
        election_id: election(),
        station_id: StationId::new(station).unwrap(),
        unit_id: UnitId::new(unit).unwrap(),
        slot,
        checkins: 10,
        issued: 10,
        spoiled: 0,
        returned: 0,
        state: CheckinProgressState::Checking,
    })
    .unwrap();
    let body = object(SCHEMA_CHECKIN_PROGRESS_BODY, SCHEMA_VERSION_1, &body);
    let sig = sign(signing(200), b"checkin-progress", body);
    object(
        SCHEMA_PROGRESS_TICK,
        SCHEMA_VERSION_1,
        &ProgressTick::new(body, sig).unwrap(),
    )
}

const B1: [&[u8]; 2] = [b"M-B1-P1", b"M-B1-P2"];
const B2: [&[u8]; 2] = [b"M-B2-P1", b"M-B2-P2"];

/// A frame stream builder: frames chained in order.
struct Ledger {
    election: ElectionId<'static>,
    stream: Vec<u8>,
    frames: Vec<&'static [u8]>,
    prev: Hash512,
    seq: u64,
}

impl Ledger {
    fn new() -> Self {
        Self {
            election: election(),
            stream: Vec::new(),
            frames: Vec::new(),
            prev: Hash512::ZERO,
            seq: 0,
        }
    }

    /// Appends a frame carrying `event` as `schema`.
    fn push_as(&mut self, schema: SchemaId, event: &[u8]) -> &mut Self {
        self.push_raw(schema, object_hash(event), self.prev)
    }

    fn push_raw(&mut self, schema: SchemaId, hash: Hash512, prev: Hash512) -> &mut Self {
        self.seq += 1;
        let frame = LedgerFrame::new(
            self.election,
            Seq::new(self.seq).unwrap(),
            prev,
            schema,
            hash,
        );
        let bytes = object(SCHEMA_LEDGER_FRAME, SCHEMA_VERSION_1, &frame);
        self.prev = object_hash(bytes);
        self.stream
            .extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
        self.stream.extend_from_slice(bytes);
        self.frames.push(bytes);
        self
    }

    fn bytes(&self) -> &'static [u8] {
        leak_slice(self.stream.clone())
    }
}

fn genesis_event() -> &'static [u8] {
    standard().signed
}

fn index(ledger: &Ledger, events: &[&'static [u8]]) -> LedgerIndex<'static> {
    build_index(verified(), ledger.bytes(), events)
}

#[test]
fn indexes_a_clean_ledger() {
    let g = genesis_event();
    let b = batch(b"BOX-1", B1, 0);
    let c = close(b"BOX-1", B1, 50);
    let t = tick(b"ST-1", b"U-1A", 3);
    let mut ledger = Ledger::new();
    ledger
        .push_as(SCHEMA_SIGNED_GENESIS, g)
        .push_as(SCHEMA_BATCH_ATTEST, b)
        .push_as(SCHEMA_BOX_CLOSE, c)
        .push_as(SCHEMA_PROGRESS_TICK, t);
    // The supply order does not matter, and a duplicate in the supply is
    // harmless.
    let idx = index(&ledger, &[t, c, b, g, b]);
    assert!(idx.findings().is_empty(), "{:?}", idx.findings());
    assert_eq!(idx.events().len(), 4);
    assert!(idx.ledger_holds().is_empty());
    assert!(idx.box_holds(b"BOX-1").is_empty());
    assert_eq!(idx.box_events(b"BOX-1").count(), 2);
    assert_eq!(
        idx.events()[3].scope,
        Scope::Station(StationId::new(b"ST-1").unwrap())
    );
    assert_eq!(idx.events()[0].scope, Scope::Election);
    assert_eq!(idx.events()[1].bytes, b);
    assert_eq!(idx.tree_size(), 4);
    assert_eq!(idx.head().unwrap().seq().get(), 4);
    let mut acc = Accumulator::empty();
    for f in &ledger.frames {
        acc.push(&object_hash(f)).unwrap();
    }
    assert_eq!(idx.root(), acc.root());
    assert_eq!(idx.events()[2].frame_hash, object_hash(ledger.frames[2]));
}

#[test]
fn refuses_a_replayed_box_event_and_holds_only_that_box() {
    let b = batch(b"BOX-1", B1, 0);
    let other = batch(b"BOX-2", B2, 0);
    let mut ledger = Ledger::new();
    ledger
        .push_as(SCHEMA_BATCH_ATTEST, b)
        .push_as(SCHEMA_BATCH_ATTEST, other)
        .push_as(SCHEMA_BATCH_ATTEST, b);
    let idx = index(&ledger, &[b, other]);
    assert_eq!(idx.events().len(), 2);
    let f = idx.findings();
    assert_eq!(f.len(), 1);
    assert_eq!(
        f[0].kind,
        FindingKind::Replayed {
            first: Seq::new(1).unwrap()
        }
    );
    assert_eq!(f[0].seq, Seq::new(3));
    assert_eq!(f[0].scope, Scope::Box(BoxId::new(b"BOX-1").unwrap()));
    assert!(idx.box_holds(b"BOX-1").contains(HoldReason::EventReplayed));
    assert!(idx.box_holds(b"BOX-2").is_empty());
    assert!(idx.ledger_holds().is_empty());
    // The chain still counts the refused frame.
    assert_eq!(idx.tree_size(), 3);
}

#[test]
fn a_replayed_election_event_holds_the_ledger() {
    let g = genesis_event();
    let mut ledger = Ledger::new();
    ledger
        .push_as(SCHEMA_SIGNED_GENESIS, g)
        .push_as(SCHEMA_SIGNED_GENESIS, g);
    let idx = index(&ledger, &[g]);
    assert!(idx.ledger_holds().contains(HoldReason::EventReplayed));
    assert_eq!(idx.events().len(), 1);
}

#[test]
fn a_replayed_station_event_holds_every_box_of_the_station() {
    let t = tick(b"ST-1", b"U-1A", 3);
    let mut ledger = Ledger::new();
    ledger
        .push_as(SCHEMA_PROGRESS_TICK, t)
        .push_as(SCHEMA_PROGRESS_TICK, t);
    let idx = index(&ledger, &[t]);
    assert!(idx.box_holds(b"BOX-1").contains(HoldReason::EventReplayed));
    assert!(idx.box_holds(b"BOX-2").contains(HoldReason::EventReplayed));
    assert!(idx.box_holds(b"BOX-3").is_empty());
    assert!(idx.ledger_holds().is_empty());
}

#[test]
fn refuses_a_record_after_its_box_closed() {
    let c = close(b"BOX-1", B1, 50);
    let late = batch(b"BOX-1", B1, 1);
    let elsewhere = batch(b"BOX-2", B2, 0);
    let second_close = close(b"BOX-1", B1, 51);
    let mut ledger = Ledger::new();
    ledger
        .push_as(SCHEMA_BOX_CLOSE, c)
        .push_as(SCHEMA_BATCH_ATTEST, late)
        .push_as(SCHEMA_BATCH_ATTEST, elsewhere)
        .push_as(SCHEMA_BOX_CLOSE, second_close);
    let idx = index(&ledger, &[c, late, elsewhere, second_close]);
    let f = idx.findings();
    assert_eq!(f.len(), 1);
    assert_eq!(
        f[0].kind,
        FindingKind::AfterClose {
            close: Seq::new(1).unwrap()
        }
    );
    assert_eq!(f[0].seq, Seq::new(2));
    assert!(
        idx.box_holds(b"BOX-1")
            .contains(HoldReason::RecordAfterClose)
    );
    assert!(!idx.box_holds(b"BOX-1").contains(HoldReason::EventReplayed));
    assert!(idx.box_holds(b"BOX-2").is_empty());
    // A record of another box, and a second close, are indexed: the
    // second close is the state machine's to judge.
    assert_eq!(idx.events().len(), 3);
}

#[test]
fn a_missing_or_invalid_event_holds_the_ledger_and_the_index_goes_on() {
    let b = batch(b"BOX-1", B1, 0);
    let c = close(b"BOX-2", B2, 50);
    let t = tick(b"ST-2", b"U-2A", 1);
    let mut ledger = Ledger::new();
    ledger
        .push_as(SCHEMA_BATCH_ATTEST, b) // not supplied
        .push_as(SCHEMA_CAST_RECORD, c) // a close presented as a cast record
        .push_as(SchemaId::new(0x0009), t) // not a ledger event schema
        .push_as(SCHEMA_PROGRESS_TICK, t);
    let idx = index(&ledger, &[c, t]);
    let kinds: Vec<FindingKind> = idx.findings().iter().map(|f| f.kind).collect();
    assert_eq!(
        kinds,
        [
            FindingKind::EventMissing,
            FindingKind::EventInvalid,
            FindingKind::EventInvalid
        ]
    );
    assert!(idx.ledger_holds().contains(HoldReason::LedgerUnchecked));
    assert_eq!(idx.events().len(), 1);
    assert_eq!(idx.events()[0].seq.get(), 4);
}

#[test]
fn an_event_of_a_box_the_genesis_does_not_have_holds_the_ledger() {
    let stray = batch(b"BOX-9", B1, 0);
    let mut ledger = Ledger::new();
    ledger.push_as(SCHEMA_BATCH_ATTEST, stray);
    let idx = index(&ledger, &[stray]);
    assert_eq!(idx.findings()[0].kind, FindingKind::UnknownSubject);
    assert_eq!(idx.findings()[0].scope, Scope::Election);
    assert!(idx.ledger_holds().contains(HoldReason::LedgerUnchecked));
    assert!(idx.events().is_empty());

    let stray = tick(b"ST-9", b"U-9", 1);
    let mut ledger = Ledger::new();
    ledger.push_as(SCHEMA_PROGRESS_TICK, stray);
    let idx = index(&ledger, &[stray]);
    assert_eq!(idx.findings()[0].kind, FindingKind::UnknownSubject);
}

#[test]
fn a_broken_chain_ends_the_index() {
    let b = batch(b"BOX-1", B1, 0);
    let c = close(b"BOX-1", B1, 50);
    let mut ledger = Ledger::new();
    ledger.push_as(SCHEMA_BATCH_ATTEST, b);
    // The second frame names a wrong previous hash; the third is fine
    // after it but cannot be reached.
    ledger.push_raw(SCHEMA_BOX_CLOSE, object_hash(c), Hash512([0x66; 64]));
    ledger.push_as(SCHEMA_BOX_CLOSE, c);
    let idx = index(&ledger, &[b, c]);
    assert_eq!(idx.events().len(), 1);
    assert_eq!(idx.findings().len(), 1);
    assert_eq!(idx.findings()[0].kind, FindingKind::ChainBroken);
    assert_eq!(idx.findings()[0].seq, Seq::new(2));
    assert!(idx.ledger_holds().contains(HoldReason::LedgerUnchecked));
    assert_eq!(idx.tree_size(), 1);
}

#[test]
fn a_frame_of_another_election_ends_the_index() {
    let b = batch(b"BOX-1", B1, 0);
    let mut ledger = Ledger::new();
    ledger.election = ElectionId::new(b"E-OTHER").unwrap();
    ledger.push_as(SCHEMA_BATCH_ATTEST, b);
    let idx = index(&ledger, &[b]);
    assert!(idx.events().is_empty());
    assert_eq!(idx.findings()[0].kind, FindingKind::ChainBroken);
    assert!(idx.head().is_none());
}

#[test]
fn a_torn_tail_is_isolated_without_a_hold() {
    let b = batch(b"BOX-1", B1, 0);
    let c = close(b"BOX-1", B1, 50);
    let mut ledger = Ledger::new();
    ledger
        .push_as(SCHEMA_BATCH_ATTEST, b)
        .push_as(SCHEMA_BOX_CLOSE, c);
    let full = ledger.bytes();
    let torn = &full[..full.len() - 7];
    let idx = build_index(verified(), torn, &[b, c]);
    assert_eq!(idx.events().len(), 1);
    assert_eq!(idx.findings().len(), 1);
    assert_eq!(idx.findings()[0].kind, FindingKind::TornTail);
    assert_eq!(idx.findings()[0].offset, 4 + ledger.frames[0].len());
    assert!(idx.ledger_holds().is_empty());
}

#[test]
fn a_corrupt_record_ends_the_index_with_a_hold() {
    let b = batch(b"BOX-1", B1, 0);
    let mut ledger = Ledger::new();
    ledger.push_as(SCHEMA_BATCH_ATTEST, b);
    let mut bytes = ledger.bytes().to_vec();
    // A zero length prefix is impossible.
    bytes.extend_from_slice(&[0, 0, 0, 0, 1, 2, 3]);
    let idx = build_index(verified(), leak_slice(bytes), &[b]);
    assert_eq!(idx.events().len(), 1);
    assert_eq!(idx.findings()[0].kind, FindingKind::ChainBroken);
    assert!(idx.ledger_holds().contains(HoldReason::LedgerUnchecked));
}

#[test]
fn an_empty_ledger_has_nothing() {
    let idx = build_index(verified(), &[], &[]);
    assert!(idx.events().is_empty());
    assert!(idx.findings().is_empty());
    assert!(idx.head().is_none());
    assert_eq!(idx.tree_size(), 0);
}

fn authorization() -> &'static [u8] {
    let body = LegalAuthorizationBody::new(
        election(),
        ScopeSet::empty(),
        Hash512([0x31; 64]),
        Day::new(20_000),
        Day::new(20_100),
    )
    .unwrap();
    object(SCHEMA_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1, &body)
}

#[test]
fn a_genesis_or_authorization_the_pin_does_not_name_holds_the_ledger() {
    // A genesis with another body.
    let draft = Draft::standard();
    let other = sign_genesis_with(&draft, draft.raw(), &SIGNERS, |p| {
        p.policy_hash = Hash512([0x09; 64]);
    });
    // A legal authorization the genesis does not pin (it pins 0x02…).
    let auth = authorization();
    let mut ledger = Ledger::new();
    ledger
        .push_as(SCHEMA_SIGNED_GENESIS, other.signed)
        .push_as(SCHEMA_LEGAL_AUTHORIZATION, auth);
    let idx = index(&ledger, &[other.signed, auth]);
    let kinds: Vec<FindingKind> = idx.findings().iter().map(|f| f.kind).collect();
    assert_eq!(kinds, [FindingKind::NotPinned, FindingKind::NotPinned]);
    assert!(idx.ledger_holds().contains(HoldReason::LedgerUnchecked));
    assert!(idx.events().is_empty());
}

#[test]
fn the_pinned_genesis_its_amendments_and_its_authorization_are_indexed() {
    let draft = Draft::standard();
    let auth = authorization();
    let built = common::leak(sign_genesis_with(&draft, draft.raw(), &SIGNERS, |p| {
        p.legal_authorization_hash = object_hash(auth);
    }));
    let amended = amendment(1, built.pin, &built.raw, &SIGNERS);
    let verified = common::leak(verify_genesis(&built.pin, &built.input(), &[amended]).unwrap());
    // The same genesis body under another set of witness signatures is
    // still the pinned genesis.
    let resigned = common::seal(built.body, b"genesis", &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    let mut ledger = Ledger::new();
    ledger
        .push_as(SCHEMA_SIGNED_GENESIS, built.signed)
        .push_as(SCHEMA_LEGAL_AUTHORIZATION, auth)
        .push_as(SCHEMA_SIGNED_GENESIS, amended.signed)
        .push_as(SCHEMA_SIGNED_GENESIS, resigned);
    let idx = build_index(
        verified,
        ledger.bytes(),
        &[built.signed, auth, amended.signed, resigned],
    );
    assert!(idx.findings().is_empty(), "{:?}", idx.findings());
    assert_eq!(idx.events().len(), 4);
}

#[test]
fn a_device_attestation_is_held_on_its_device() {
    // The scope of a device is found by identifier: a box, a check-in
    // unit's station, or the election.
    let v = verified();
    assert_eq!(
        v.unit_station(b"U-2B"),
        Some(StationId::new(b"ST-2").unwrap())
    );
    assert_eq!(v.unit_station(b"BOX-1"), None);
    assert!(v.expected_box(b"BOX-1").is_some());
}

/// The first valid object of an `ityv-encoding` test-vector file.
fn vector(name: &str) -> &'static [u8] {
    let path = std::format!(
        "{}/../ityv-encoding/vectors/{name}.txt",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(path).unwrap();
    let line = text.lines().find(|l| l.starts_with("VALID")).unwrap();
    let hex = line.split_whitespace().last().unwrap();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    leak_slice(bytes)
}

/// A genesis whose first box and station carry the identifiers the
/// encoding vectors use (`box-11-0042` at `st-11-0042`).
fn vector_genesis() -> &'static VerifiedGenesis<'static> {
    let mut draft = Draft::standard();
    let st = StationId::new(b"st-11-0042").unwrap();
    draft.boxes[0].box_id = BoxId::new(b"box-11-0042").unwrap();
    draft.boxes[0].station_id = st;
    draft.boxes[1].station_id = st;
    draft.stations[0] = station(
        b"st-11-0042",
        StationKind::ElectionDay,
        checkin_unit(0, b"U-1A", &[b"M-U1A-P1", b"M-U1A-P2"]),
        checkin_unit(1, b"U-1B", &[b"M-U1B-P1", b"M-U1B-P2"]),
        &[b"BOX-2", b"box-11-0042"],
        &[],
    );
    draft.policies[0] = ityv_encoding::StationProgressPolicy::new(st, 4, 12).unwrap();
    for r in &mut draft.roster {
        if r.station_id.is_some() {
            r.station_id = Some(st);
        }
    }
    let built = common::leak(sign_genesis(&draft, draft.raw()));
    common::leak(verify_genesis(&built.pin, &built.input(), &[]).unwrap())
}

/// `body` in a witnessed event signed by the role set its schema needs.
fn witnessed(
    body: &'static [u8],
    signers: &[(&'static [u8], EventRole, &'static [u8])],
) -> &'static [u8] {
    let sig: &'static [u8; HYBRID_SIG_LEN] = common::leak([0x5A; HYBRID_SIG_LEN]);
    let sigs: Vec<EventSig<'static>> = signers
        .iter()
        .map(|(id, role, o)| EventSig {
            signer_id: SignerId::new(id).unwrap(),
            role: *role,
            org_id: OrgId::new(o).unwrap(),
            sig,
        })
        .collect();
    let event = WitnessedEvent::new(body, &sigs).unwrap();
    object(SCHEMA_WITNESSED_EVENT, SCHEMA_VERSION_1, &event)
}

#[test]
fn every_witnessed_body_is_scoped_to_its_box_station_or_election() {
    const CLERKS_OBSERVERS: &[(&[u8], EventRole, &[u8])] = &[
        (b"clerk-1", EventRole::Clerk, b"ORG-ST"),
        (b"clerk-2", EventRole::Clerk, b"ORG-ST"),
        (b"obs-a", EventRole::Observer, b"PARTY-A"),
        (b"obs-b", EventRole::Observer, b"PARTY-B"),
    ];
    const OPENING: &[(&[u8], EventRole, &[u8])] = &[
        (b"box-11-0042", EventRole::Device, b"NEC"),
        (b"clerk-1", EventRole::Clerk, b"ORG-ST"),
        (b"clerk-2", EventRole::Clerk, b"ORG-ST"),
        (b"obs-a", EventRole::Observer, b"PARTY-A"),
        (b"obs-b", EventRole::Observer, b"PARTY-B"),
    ];
    const OBSERVERS: &[(&[u8], EventRole, &[u8])] = &[
        (b"obs-a", EventRole::Observer, b"PARTY-A"),
        (b"obs-b", EventRole::Observer, b"PARTY-B"),
    ];
    const HANDOFF: &[(&[u8], EventRole, &[u8])] = &[
        (b"clerk-1", EventRole::Sender, b"ORG-ST"),
        (b"police-1", EventRole::Receiver, b"POLICE"),
    ];
    const AUTHORITIES: &[(&[u8], EventRole, &[u8])] = &[
        (b"commission", EventRole::Commission, b"NEC"),
        (b"committee", EventRole::Committee, b"IVC"),
    ];
    const COURT: &[(&[u8], EventRole, &[u8])] = &[(b"court", EventRole::Authority, b"COURT")];
    let the_box = Scope::Box(BoxId::new(b"box-11-0042").unwrap());
    let the_station = Scope::Station(StationId::new(b"st-11-0042").unwrap());
    let cases: [(&str, &[(&[u8], EventRole, &[u8])], Scope<'static>); 13] = [
        ("custody_handoff_body", HANDOFF, the_box),
        ("dispute_event_body", AUTHORITIES, the_box),
        ("legal_decision_ref_body", COURT, Scope::Election),
        ("box_opened_body", OPENING, the_box),
        ("fallback_body", CLERKS_OBSERVERS, the_box),
        ("issuance_count_body", CLERKS_OBSERVERS, the_station),
        ("imprint_audit_body", CLERKS_OBSERVERS, the_box),
        ("seal_change_body", CLERKS_OBSERVERS, the_box),
        ("late_batch_close_body", CLERKS_OBSERVERS, the_box),
        ("progress_check_body", CLERKS_OBSERVERS, the_station),
        ("observer_count_attest_body", OBSERVERS, the_station),
        ("checkin_unit_swap_body", CLERKS_OBSERVERS, the_station),
        ("box_unit_swap_body", CLERKS_OBSERVERS, the_box),
    ];
    let events: Vec<&'static [u8]> = cases
        .iter()
        .map(|(name, signers, _)| witnessed(vector(name), signers))
        .collect();
    let mut ledger = Ledger::new();
    for e in &events {
        ledger.push_as(SCHEMA_WITNESSED_EVENT, e);
    }
    let idx = build_index(vector_genesis(), ledger.bytes(), &events);
    assert!(idx.findings().is_empty(), "{:?}", idx.findings());
    let scopes: Vec<Scope<'static>> = idx.events().iter().map(|e| e.scope).collect();
    let expected: Vec<Scope<'static>> = cases.iter().map(|c| c.2).collect();
    assert_eq!(scopes, expected);
}
