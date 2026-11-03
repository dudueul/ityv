//! The progress stage (PROTOCOL.md §7.10; ADR-0027; VC-102, VC-103,
//! VC-106): device streams in slot order, device swaps, the station's
//! alarms and on-site checks, and the close comparisons, over ledgers with
//! real hybrid signatures.
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
    BOX_DEVICE_BASE, Draft, Ledger, ROSTER_BASE, SIGNERS, leak, modules, object, sign,
    sign_genesis_with, signing, unit_signing,
};
use ityv_crypto::object_hash;
use ityv_encoding::{
    BallotStyleId, BatchAttest, BatchAttestBody, BatchAttestParts, BoxClose, BoxCloseBody,
    BoxCloseParts, BoxId, BoxOpenedBody, BoxOpenedParts, BoxProgressBody, BoxProgressParts,
    BoxProgressState, BoxUnitSwapBody, BoxUnitSwapParts, CastRecord, CastRecordBody,
    CastRecordParts, CheckinProgressBody, CheckinProgressParts, CheckinProgressState,
    CheckinUnitSwapBody, CheckinUnitSwapParts, CloseCounts, Commitments, ElectionId, EventRole,
    EventSig, FallbackBody, FallbackKind, FallbackParts, FallbackReason, Hash512,
    IssuanceCountBody, IssuanceCountParts, ModuleBatchSig, ModuleCounter, ModuleCounters,
    ModuleIds, ModuleRange, ModuleRecordSig, ObserverCountAttestBody, ObserverCountKind,
    ObserverCountParts, OrgId, Point32, ProgressAlarm, ProgressCheckBody, ProgressCheckParts,
    ProgressFinding, ProgressTick, SCHEMA_BATCH_ATTEST, SCHEMA_BATCH_ATTEST_BODY, SCHEMA_BOX_CLOSE,
    SCHEMA_BOX_CLOSE_BODY, SCHEMA_BOX_OPENED_BODY, SCHEMA_BOX_PROGRESS_BODY,
    SCHEMA_BOX_UNIT_SWAP_BODY, SCHEMA_CAST_RECORD, SCHEMA_CAST_RECORD_BODY,
    SCHEMA_CHECKIN_PROGRESS_BODY, SCHEMA_CHECKIN_UNIT_SWAP_BODY, SCHEMA_FALLBACK_BODY,
    SCHEMA_ISSUANCE_COUNT_BODY, SCHEMA_OBSERVER_COUNT_ATTEST_BODY, SCHEMA_PROGRESS_CHECK_BODY,
    SCHEMA_PROGRESS_TICK, SCHEMA_SIGNED_GENESIS, SCHEMA_SIGNED_LEGAL_AUTHORIZATION,
    SCHEMA_VERSION_1, SCHEMA_WITNESSED_EVENT, SchemaId, Scope, Seq, SignerId, SignerRole,
    StationId, TimeBucket, UnitId, WitnessedEvent, purpose_of,
};
use ityv_state::{Error, HoldReason, HoldSet};
use ityv_verify::{
    BoxProgressReport, BoxStage, CloseCheck, LedgerIndex, MAX_PROGRESS_SLOTS, Phase,
    ProgressReason, ProgressRefusal, ProgressStage, RaisedAlarm, StationProgressReport,
    VerifiedGenesis, authorize_ledger, bucket_slots, build_index, verify_boxes, verify_genesis,
    verify_progress,
};

const STATION: &[u8] = b"ST-1";
const SEAL: Hash512 = Hash512([0x5e; 64]);
/// Bucket 100 (day 20 001) overlaps slots 150 and 151: a box opened in it
/// starts its stream at 150, 151 or 152.
const OPEN: u64 = 100;
const CLOSE_BUCKET: u64 = 140;
/// The key number of the spare commitment unit an amendment registers for
/// `BOX-1`.
const SPARE_DEVICE: u16 = common::SPARE_BASE + 10;

fn election() -> ElectionId<'static> {
    common::election()
}

fn station_id() -> StationId<'static> {
    StationId::new(STATION).unwrap()
}

/// A box of `ST-1`.
#[derive(Clone, Copy)]
struct Bx {
    id: &'static [u8],
    device: u16,
    modules: &'static [&'static [u8]],
    style: &'static [u8],
}

const B1: Bx = Bx {
    id: b"BOX-1",
    device: BOX_DEVICE_BASE,
    modules: &[b"M-B1-P1", b"M-B1-P2"],
    style: b"STYLE-1",
};

const B2: Bx = Bx {
    id: b"BOX-2",
    device: BOX_DEVICE_BASE + 1,
    modules: &[b"M-B2-J", b"M-B2-P1", b"M-B2-P2"],
    style: b"STYLE-2",
};

impl Bx {
    fn box_id(self) -> BoxId<'static> {
        BoxId::new(self.id).unwrap()
    }
}

// ---------------------------------------------------------------------
// Worlds.

struct World {
    genesis: &'static VerifiedGenesis<'static>,
    signed_genesis: &'static [u8],
    authorization: &'static [u8],
    /// The signed amendment, for the ledger to carry.
    amendment: Option<&'static [u8]>,
}

/// The standard genesis pinning an authorization of `PUBLIC_BOARD`,
/// `TRUSTEE_BODY` and `BALLOT_MARK` for days 20 000..20 100; with `change`,
/// one amendment that applies it to the draft.
fn build(change: Option<fn(&mut Draft)>) -> World {
    let draft = Draft::standard();
    let (body, authorization) = common::legal_authorization(
        &[Scope::PublicBoard, Scope::TrusteeBody, Scope::BallotMark],
        20_000,
        20_100,
    );
    let built = leak(sign_genesis_with(&draft, draft.raw(), &SIGNERS, |p| {
        p.legal_authorization_hash = object_hash(body);
    }));
    let amendment = change.map(|change| {
        let mut next = draft.clone();
        change(&mut next);
        next.appointments = next.referenced_appointments();
        common::amendment(1, built.pin, &next.raw(), &SIGNERS)
    });
    let amendments: Vec<_> = amendment.into_iter().collect();
    let genesis = leak(verify_genesis(&built.pin, &built.input(), &amendments).unwrap());
    World {
        genesis,
        signed_genesis: built.signed,
        authorization,
        amendment: amendment.map(|a| a.signed),
    }
}

fn world() -> &'static World {
    static WORLD: OnceLock<&'static World> = OnceLock::new();
    WORLD.get_or_init(|| leak(build(None)))
}

/// One amendment registers a spare commitment unit for `BOX-1`.
fn amended() -> &'static World {
    static WORLD: OnceLock<&'static World> = OnceLock::new();
    WORLD.get_or_init(|| {
        leak(build(Some(|d: &mut Draft| {
            for b in &mut d.boxes {
                if b.box_id.as_bytes() == B1.id {
                    b.device_key = common::registered(SPARE_DEVICE);
                }
            }
        })))
    })
}

/// One amendment removes `ST-2`, its box `BOX-3` and its reporting unit.
fn removed() -> &'static World {
    static WORLD: OnceLock<&'static World> = OnceLock::new();
    WORLD.get_or_init(|| {
        leak(build(Some(|d: &mut Draft| {
            d.boxes.retain(|b| b.box_id.as_bytes() != b"BOX-3");
            d.stations.retain(|s| s.station_id().as_bytes() != b"ST-2");
            d.policies.retain(|p| p.station_id().as_bytes() != b"ST-2");
            d.units.retain(|u| u.unit_id().as_bytes() != b"RU-2");
        })))
    })
}

// ---------------------------------------------------------------------
// Events, with real signatures.

/// The roster people: identifier, organisation, key number.
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

#[derive(Clone, Copy)]
enum By {
    Person(&'static [u8], EventRole),
    /// A box's device under key number `n`.
    Device(&'static [u8], u16),
    /// A key of its own under a roster identifier.
    Forger(&'static [u8], EventRole),
}

const WITNESSES: [By; 4] = [
    By::Person(b"clerk-1", EventRole::Clerk),
    By::Person(b"clerk-2", EventRole::Clerk),
    By::Person(b"obs-a", EventRole::Observer),
    By::Person(b"obs-b", EventRole::Observer),
];

/// Real keys under roles the roster does not give them.
const MISROLED: [By; 4] = [
    By::Person(b"clerk-1", EventRole::Clerk),
    By::Person(b"clerk-2", EventRole::Observer),
    By::Person(b"obs-a", EventRole::Observer),
    By::Person(b"obs-b", EventRole::Clerk),
];

const OBSERVERS: [By; 2] = [
    By::Person(b"obs-a", EventRole::Observer),
    By::Person(b"obs-b", EventRole::Observer),
];

const FORGED: [By; 4] = [
    By::Person(b"clerk-1", EventRole::Clerk),
    By::Forger(b"clerk-2", EventRole::Clerk),
    By::Person(b"obs-a", EventRole::Observer),
    By::Person(b"obs-b", EventRole::Observer),
];

/// A `WitnessedEvent` over the body object `body` of `schema`.
fn witnessed(schema: SchemaId, body: &'static [u8], signers: &[By]) -> &'static [u8] {
    let purpose = purpose_of(schema).unwrap();
    let mut parts: Vec<(&'static [u8], EventRole, &'static [u8], u16)> = signers
        .iter()
        .map(|b| match *b {
            By::Person(id, role) => {
                let (o, n) = person(id);
                (id, role, o, n)
            }
            By::Device(id, n) => (id, EventRole::Device, b"ORG-ST".as_slice(), n),
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

fn opened(bx: Bx, bucket: u64) -> &'static [u8] {
    let body = BoxOpenedBody::new(&BoxOpenedParts {
        election_id: election(),
        box_id: bx.box_id(),
        modules: modules(bx.modules),
        seal_digest: SEAL,
        seals_match: true,
        initial_count: 0,
        time_bucket: TimeBucket::new(bucket),
    });
    let body = object(SCHEMA_BOX_OPENED_BODY, SCHEMA_VERSION_1, &body);
    let mut signers = std::vec![By::Device(bx.id, bx.device)];
    signers.extend_from_slice(&WITNESSES);
    witnessed(SCHEMA_BOX_OPENED_BODY, body, &signers)
}

/// Cast record `n` of the box (the box stage only counts it).
fn record(bx: Bx, n: u64) -> &'static [u8] {
    let counters: Vec<ModuleCounter<'static>> = bx
        .modules
        .iter()
        .map(|m| ModuleCounter {
            module_id: common::module(m),
            counter: n,
        })
        .collect();
    let mut proof = std::vec![0xab; 3 + 16 * 4 * 32];
    proof[0..2].copy_from_slice(&16u16.to_be_bytes());
    proof[2] = 2;
    let body = CastRecordBody::new(&CastRecordParts {
        election_id: election(),
        box_id: bx.box_id(),
        ballot_style_id: BallotStyleId::new(bx.style).unwrap(),
        proof_system_id: 1,
        commitments: Commitments::new(&[Point32([n as u8; 32]), Point32([0x77; 32])]).unwrap(),
        proof: common::leak_slice(proof),
        module_counters: ModuleCounters::new(&counters).unwrap(),
        share_package_hash: Hash512([6; 64]),
        transport_flags: 0,
    })
    .unwrap();
    let body = object(SCHEMA_CAST_RECORD_BODY, SCHEMA_VERSION_1, &body);
    let sig = leak([0x44u8; 64]);
    let sigs: Vec<ModuleRecordSig<'static>> = bx
        .modules
        .iter()
        .map(|m| ModuleRecordSig {
            module_id: common::module(m),
            ed25519: sig,
        })
        .collect();
    object(
        SCHEMA_CAST_RECORD,
        SCHEMA_VERSION_1,
        &CastRecord::new(body, sig, &sigs).unwrap(),
    )
}

fn batch(bx: Bx, records: u16) -> &'static [u8] {
    let ranges = common::leak_slice(
        bx.modules
            .iter()
            .map(|m| ModuleRange {
                module_id: common::module(m),
                counter_first: 1,
                counter_last: u64::from(records),
            })
            .collect(),
    );
    let body = BatchAttestBody::new(&BatchAttestParts {
        election_id: election(),
        box_id: bx.box_id(),
        batch_index: 0,
        record_count: records,
        records_root: Hash512([0x21; 64]),
        module_ranges: ranges,
        module_refusals: ModuleIds::EMPTY,
        journal_head: Hash512([0x22; 64]),
        time_bucket: TimeBucket::new(120),
    })
    .unwrap();
    let body = object(SCHEMA_BATCH_ATTEST_BODY, SCHEMA_VERSION_1, &body);
    let device = sign(signing(bx.device), b"batch-attest", body);
    let sigs: Vec<ModuleBatchSig<'static>> = bx
        .modules
        .iter()
        .map(|m| ModuleBatchSig {
            module_id: common::module(m),
            sig: device,
        })
        .collect();
    object(
        SCHEMA_BATCH_ATTEST,
        SCHEMA_VERSION_1,
        &BatchAttest::new(body, &sigs, device).unwrap(),
    )
}

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

/// Who signs a close besides the four witnesses: the device under key
/// number `n`, or nobody (`BoxCloseManual`).
fn close_by(bx: Bx, records: u64, device: Option<u16>) -> &'static [u8] {
    let counters: Vec<ModuleCounter<'static>> = bx
        .modules
        .iter()
        .map(|m| ModuleCounter {
            module_id: common::module(m),
            counter: records,
        })
        .collect();
    let body = BoxCloseBody::new(&BoxCloseParts {
        election_id: election(),
        box_id: bx.box_id(),
        counts: counts(records),
        record_set_root: Hash512([0x23; 64]),
        journal_head: Hash512([0x24; 64]),
        seal_digest: SEAL,
        module_counters: ModuleCounters::new(&counters).unwrap(),
        open_batches: 0,
        time_bucket: TimeBucket::new(CLOSE_BUCKET),
    });
    let body = object(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, &body);
    let attestations: Vec<ityv_encoding::Attestation<'static>> = [
        (b"clerk-1".as_slice(), SignerRole::Clerk),
        (b"clerk-2", SignerRole::Clerk),
        (b"obs-a", SignerRole::Observer),
        (b"obs-b", SignerRole::Observer),
    ]
    .iter()
    .map(|&(id, role)| {
        let (o, n) = person(id);
        ityv_encoding::Attestation {
            signer_id: SignerId::new(id).unwrap(),
            role,
            org_id: OrgId::new(o).unwrap(),
            sig: sign(signing(n), b"box-close", body),
        }
    })
    .collect();
    let device = device.map(|n| sign(signing(n), b"box-close", body));
    object(
        SCHEMA_BOX_CLOSE,
        SCHEMA_VERSION_1,
        &BoxClose::new(body, device, &attestations).unwrap(),
    )
}

fn fallback(bx: Bx, bucket: u64) -> &'static [u8] {
    let body = FallbackBody::new(&FallbackParts {
        election_id: election(),
        box_id: bx.box_id(),
        kind: FallbackKind::Declared,
        reason: FallbackReason::ScannerFault,
        statement_hash: Hash512([0x51; 64]),
        markers: None,
        time_bucket: TimeBucket::new(bucket),
    })
    .unwrap();
    let body = object(SCHEMA_FALLBACK_BODY, SCHEMA_VERSION_1, &body);
    witnessed(SCHEMA_FALLBACK_BODY, body, &WITNESSES)
}

fn box_swap(bx: Bx, at_slot: u64, sheets_in: u64, signers: &[By]) -> &'static [u8] {
    let body = BoxUnitSwapBody::new(&BoxUnitSwapParts {
        election_id: election(),
        box_id: bx.box_id(),
        at_slot,
        confirmed: true,
        sheets_in,
    })
    .unwrap();
    let body = object(SCHEMA_BOX_UNIT_SWAP_BODY, SCHEMA_VERSION_1, &body);
    witnessed(SCHEMA_BOX_UNIT_SWAP_BODY, body, signers)
}

/// A commitment-unit tick of `bx` signed by key number `key`.
fn box_tick_by(
    key: u16,
    bx: Bx,
    slot: u64,
    sheets_in: u64,
    state: BoxProgressState,
) -> &'static [u8] {
    let body = BoxProgressBody::new(&BoxProgressParts {
        election_id: election(),
        box_id: bx.box_id(),
        slot,
        sheets_in,
        state,
    });
    let body = object(SCHEMA_BOX_PROGRESS_BODY, SCHEMA_VERSION_1, &body);
    let sig = sign(signing(key), b"box-progress", body);
    object(
        SCHEMA_PROGRESS_TICK,
        SCHEMA_VERSION_1,
        &ProgressTick::new(body, sig).unwrap(),
    )
}

fn box_tick(bx: Bx, slot: u64, sheets_in: u64, state: BoxProgressState) -> &'static [u8] {
    box_tick_by(bx.device, bx, slot, sheets_in, state)
}

/// A check-in tick of unit `unit` signed by unit key `n` under `purpose`;
/// counts `[checkins, issued, spoiled, returned]`.
fn checkin_tick_with(
    n: u16,
    unit: &'static [u8],
    slot: u64,
    c: [u64; 4],
    state: CheckinProgressState,
    purpose: &[u8],
) -> &'static [u8] {
    let body = CheckinProgressBody::new(&CheckinProgressParts {
        election_id: election(),
        station_id: station_id(),
        unit_id: UnitId::new(unit).unwrap(),
        slot,
        checkins: c[0],
        issued: c[1],
        spoiled: c[2],
        returned: c[3],
        state,
    })
    .unwrap();
    let body = object(SCHEMA_CHECKIN_PROGRESS_BODY, SCHEMA_VERSION_1, &body);
    let sig = sign(unit_signing(n), purpose, body);
    object(
        SCHEMA_PROGRESS_TICK,
        SCHEMA_VERSION_1,
        &ProgressTick::new(body, sig).unwrap(),
    )
}

/// A tick of the station's unit in service, `U-1A`.
fn checkin_tick(slot: u64, c: [u64; 4], state: CheckinProgressState) -> &'static [u8] {
    checkin_tick_with(0, b"U-1A", slot, c, state, b"checkin-progress")
}

/// A tick of the station's spare unit, `U-1B`.
fn spare_tick(slot: u64, c: [u64; 4], state: CheckinProgressState) -> &'static [u8] {
    checkin_tick_with(1, b"U-1B", slot, c, state, b"checkin-progress")
}

fn checkin_swap(at_slot: u64, c: [u64; 4], signers: &[By]) -> &'static [u8] {
    let body = CheckinUnitSwapBody::new(&CheckinUnitSwapParts {
        election_id: election(),
        station_id: station_id(),
        failed_unit: UnitId::new(b"U-1A").unwrap(),
        spare_unit: UnitId::new(b"U-1B").unwrap(),
        at_slot,
        confirmed: true,
        next_seq: c[0] + 1,
        issued: c[1],
        spoiled: c[2],
        returned: c[3],
    })
    .unwrap();
    let body = object(SCHEMA_CHECKIN_UNIT_SWAP_BODY, SCHEMA_VERSION_1, &body);
    witnessed(SCHEMA_CHECKIN_UNIT_SWAP_BODY, body, signers)
}

/// The on-site check of `alarm` raised at `alarm_slot`, in time bucket
/// `bucket`.
fn check_by(
    alarm_slot: u64,
    alarm: ProgressAlarm,
    finding: ProgressFinding,
    bucket: u64,
    signers: &[By],
) -> &'static [u8] {
    let body = ProgressCheckBody::new(&ProgressCheckParts {
        election_id: election(),
        station_id: station_id(),
        alarm_slot,
        alarm,
        holding: 0,
        finding,
        carried_out: u64::from(finding == ProgressFinding::CarriedOut),
        statement_hash: Hash512([0x71; 64]),
        time_bucket: TimeBucket::new(bucket),
    })
    .unwrap();
    let body = object(SCHEMA_PROGRESS_CHECK_BODY, SCHEMA_VERSION_1, &body);
    witnessed(SCHEMA_PROGRESS_CHECK_BODY, body, signers)
}

fn check(
    alarm_slot: u64,
    alarm: ProgressAlarm,
    finding: ProgressFinding,
    bucket: u64,
) -> &'static [u8] {
    check_by(alarm_slot, alarm, finding, bucket, &WITNESSES)
}

fn observers_by(count: u64, kind: ObserverCountKind, signers: &[By]) -> &'static [u8] {
    let body = ObserverCountAttestBody::new(&ObserverCountParts {
        election_id: election(),
        station_id: station_id(),
        unit_id: UnitId::new(b"U-1A").unwrap(),
        count,
        kind,
        time_bucket: TimeBucket::new(CLOSE_BUCKET),
    });
    let body = object(SCHEMA_OBSERVER_COUNT_ATTEST_BODY, SCHEMA_VERSION_1, &body);
    witnessed(SCHEMA_OBSERVER_COUNT_ATTEST_BODY, body, signers)
}

fn observers(count: u64) -> &'static [u8] {
    observers_by(count, ObserverCountKind::Final, &OBSERVERS)
}

fn issuance_by(issued: u64, signers: &[By]) -> &'static [u8] {
    let body = IssuanceCountBody::new(&IssuanceCountParts {
        election_id: election(),
        station_id: station_id(),
        stock_received: 50,
        issued,
        voter_spoiled: 0,
        returned: 0,
        unused: 50 - issued,
        printer_waste: 0,
        envelopes: None,
        time_bucket: TimeBucket::new(CLOSE_BUCKET),
    });
    let body = object(SCHEMA_ISSUANCE_COUNT_BODY, SCHEMA_VERSION_1, &body);
    witnessed(SCHEMA_ISSUANCE_COUNT_BODY, body, signers)
}

fn issuance(issued: u64) -> &'static [u8] {
    issuance_by(issued, &WITNESSES)
}

// ---------------------------------------------------------------------
// Ledgers.

type Ev = (SchemaId, &'static [u8]);

fn w(event: &'static [u8]) -> Ev {
    (SCHEMA_WITNESSED_EVENT, event)
}

fn t(event: &'static [u8]) -> Ev {
    (SCHEMA_PROGRESS_TICK, event)
}

fn g(event: &'static [u8]) -> Ev {
    (SCHEMA_SIGNED_GENESIS, event)
}

/// Both boxes opened in bucket [`OPEN`].
fn openings() -> Vec<Ev> {
    std::vec![w(opened(B1, OPEN)), w(opened(B2, OPEN))]
}

/// `n` records of `bx`, their batch and the device's close.
fn closed(bx: Bx, n: u64) -> Vec<Ev> {
    let mut events: Vec<Ev> = (1..=n)
        .map(|i| (SCHEMA_CAST_RECORD, record(bx, i)))
        .collect();
    events.push((SCHEMA_BATCH_ATTEST, batch(bx, n as u16)));
    events.push((SCHEMA_BOX_CLOSE, close_by(bx, n, Some(bx.device))));
    events
}

/// One row of ticks: the slot, the check-in counts, each box's sheets in.
type Row = (u64, [u64; 4], u64, u64);

/// The ticks of `rows`, the last row closing.
fn ticks(rows: &[Row]) -> Vec<Ev> {
    ticks_closing(rows, true)
}

/// The ticks of `rows`, none closing.
fn open_ticks(rows: &[Row]) -> Vec<Ev> {
    ticks_closing(rows, false)
}

fn ticks_closing(rows: &[Row], closing: bool) -> Vec<Ev> {
    let mut events = Vec::new();
    for (i, &(slot, c, b1, b2)) in rows.iter().enumerate() {
        let last = closing && i + 1 == rows.len();
        let (cs, bs) = if last {
            (CheckinProgressState::Closed, BoxProgressState::Closed)
        } else {
            (CheckinProgressState::Checking, BoxProgressState::Casting)
        };
        events.push(t(checkin_tick(slot, c, cs)));
        events.push(t(box_tick(B1, slot, b1, bs)));
        events.push(t(box_tick(B2, slot, b2, bs)));
    }
    events
}

/// The clean day: three voters, two ballots in `BOX-1` and one in `BOX-2`.
const CLEAN: [Row; 4] = [
    (150, [1, 1, 0, 0], 0, 0),
    (151, [2, 2, 0, 0], 1, 0),
    (152, [3, 3, 0, 0], 2, 1),
    (153, [3, 3, 0, 0], 2, 1),
];

/// Both boxes closed (two and one records), the issuance count and the
/// observers' final count of three.
fn station_close() -> Vec<Ev> {
    let mut events = closed(B1, 2);
    events.extend(closed(B2, 1));
    events.push(w(issuance(3)));
    events.push(w(observers(3)));
    events
}

/// The clean day with `extra` before the closes.
fn day_with(extra: &[Ev]) -> Vec<Ev> {
    let mut events = openings();
    events.extend(ticks(&CLEAN));
    events.extend_from_slice(extra);
    events.extend(station_close());
    events
}

struct Run {
    index: &'static LedgerIndex<'static>,
    boxes: &'static BoxStage<'static>,
    progress: ProgressStage<'static>,
}

fn run_in(world: &World, events: &[Ev]) -> Run {
    let mut ledger = Ledger::new();
    ledger
        .push(SCHEMA_SIGNED_GENESIS, world.signed_genesis)
        .push(SCHEMA_SIGNED_LEGAL_AUTHORIZATION, world.authorization);
    for &(schema, event) in events {
        ledger.push(schema, event);
    }
    let index = leak(build_index(world.genesis, ledger.bytes(), &ledger.events));
    let authority = leak(authorize_ledger(world.genesis, index));
    let boxes = leak(verify_boxes(world.genesis, index, authority));
    let progress = verify_progress(world.genesis, index, boxes);
    Run {
        index,
        boxes,
        progress,
    }
}

fn go(events: &[Ev]) -> Run {
    run_in(world(), events)
}

impl Run {
    fn station(&self) -> &StationProgressReport<'static> {
        self.progress.station(STATION).unwrap()
    }

    fn of(&self, bx: Bx) -> &BoxProgressReport<'static> {
        self.progress.report(bx.id).unwrap()
    }

    /// The frame that carries `event`.
    fn seq_of(&self, event: &'static [u8]) -> Seq {
        let hash = object_hash(event);
        self.index
            .events()
            .iter()
            .find(|e| e.hash == hash)
            .unwrap()
            .seq
    }

    fn refused(&self, event: &'static [u8], reason: ProgressReason) -> ProgressRefusal {
        ProgressRefusal {
            seq: self.seq_of(event),
            reason,
        }
    }

    /// The index and the box stage took the ledger whole.
    fn clean_below(&self) {
        assert!(
            self.index.findings().is_empty(),
            "{:?}",
            self.index.findings()
        );
        for r in self.boxes.reports() {
            assert!(r.refusals.is_empty(), "{:?}", r.refusals);
        }
    }
}

fn hold(reason: HoldReason) -> HoldSet {
    HoldSet::empty().with(reason)
}

fn alarm(slot: u64, alarm: ProgressAlarm) -> RaisedAlarm {
    RaisedAlarm { slot, alarm }
}

// ---------------------------------------------------------------------
// Slots and time buckets.

#[test]
fn time_buckets_map_to_the_slots_they_overlap() {
    assert_eq!(bucket_slots(TimeBucket::new(0)), Some((0, 1)));
    assert_eq!(bucket_slots(TimeBucket::new(1)), Some((1, 2)));
    assert_eq!(bucket_slots(TimeBucket::new(2)), Some((3, 4)));
    assert_eq!(bucket_slots(TimeBucket::new(3)), Some((4, 5)));
    assert_eq!(bucket_slots(TimeBucket::new(OPEN)), Some((150, 151)));
    assert_eq!(bucket_slots(TimeBucket::new(101)), Some((151, 152)));
    // 3 × top is u64::MAX: its last slot does not exist.
    let top = u64::MAX / 3;
    assert_eq!(
        bucket_slots(TimeBucket::new(top - 1)),
        Some(((u64::MAX - 3) / 2, (u64::MAX - 1) / 2))
    );
    assert_eq!(bucket_slots(TimeBucket::new(top)), None);
    assert_eq!(bucket_slots(TimeBucket::new(u64::MAX)), None);
    assert_eq!(MAX_PROGRESS_SLOTS, 4464);
}

// ---------------------------------------------------------------------
// A clean day.

#[test]
fn a_clean_station_runs_from_opening_to_close() {
    let run = go(&day_with(&[]));
    run.clean_below();
    let st = run.station();
    assert_eq!(st.station_id.as_bytes(), STATION);
    assert!(st.refusals.is_empty(), "{:?}", st.refusals);
    assert_eq!(st.holds, HoldSet::empty());
    assert_eq!(st.first_slot, Some(150));
    assert_eq!(st.last_slot, Some(153));
    assert_eq!(st.ticks, 4);
    assert!(st.alarms.is_empty(), "{:?}", st.alarms);
    assert!(st.checks.is_empty(), "{:?}", st.checks);
    assert!(!st.suspended);
    assert!(!st.counterfoil);
    assert_eq!(st.close, CloseCheck::Compared);
    for bx in [B1, B2] {
        let r = run.of(bx);
        assert_eq!(r.station_id.as_bytes(), STATION);
        assert_eq!(r.first_slot, Some(150));
        assert_eq!(r.ticks, 4);
        assert_eq!(r.close, CloseCheck::Compared);
        assert_eq!(r.holds, HoldSet::empty());
        assert!(r.refusals.is_empty(), "{:?}", r.refusals);
        assert_eq!(run.progress.box_holds(bx.id), HoldSet::empty());
    }
    assert_eq!(run.progress.holds(), HoldSet::empty());
    // Every box of the last state's stations is reported, in order; the
    // other station never opened.
    let ids: Vec<&[u8]> = run
        .progress
        .boxes()
        .iter()
        .map(|r| r.box_id.as_bytes())
        .collect();
    assert_eq!(ids, [b"BOX-1".as_slice(), b"BOX-2", b"BOX-3"]);
    let ids: Vec<&[u8]> = run
        .progress
        .stations()
        .iter()
        .map(|r| r.station_id.as_bytes())
        .collect();
    assert_eq!(ids, [b"ST-1".as_slice(), b"ST-2"]);
    let other = run.progress.station(b"ST-2").unwrap();
    assert_eq!(other.first_slot, None);
    assert_eq!(other.close, CloseCheck::Open);
    assert_eq!(other.holds, HoldSet::empty());
    assert_eq!(run.progress.report(b"BOX-3").unwrap().first_slot, None);
    assert!(run.progress.report(b"BOX-9").is_none());
    assert!(run.progress.station(b"ST-9").is_none());
    assert_eq!(run.progress.box_holds(b"BOX-9"), HoldSet::empty());
}

#[test]
fn ticks_count_in_slot_order_whatever_their_frames() {
    // The same day with every tick in reverse frame order: a late tick is
    // counted as if on time.
    let mut events = openings();
    let mut late = ticks(&CLEAN);
    late.reverse();
    events.extend(late);
    events.extend(station_close());
    let run = go(&events);
    run.clean_below();
    assert!(
        run.station().refusals.is_empty(),
        "{:?}",
        run.station().refusals
    );
    assert_eq!(run.progress.holds(), HoldSet::empty());
    assert_eq!(run.station().close, CloseCheck::Compared);
}

#[test]
fn a_station_still_voting_is_not_held_for_what_has_not_come() {
    let mut events = openings();
    events.extend(open_ticks(&CLEAN[..3]));
    let run = go(&events);
    let st = run.station();
    assert_eq!(st.close, CloseCheck::Open);
    assert_eq!(st.holds, HoldSet::empty());
    assert_eq!(st.last_slot, Some(152));
    for bx in [B1, B2] {
        assert_eq!(run.of(bx).close, CloseCheck::Open);
        assert_eq!(run.of(bx).holds, HoldSet::empty());
    }
}

// ---------------------------------------------------------------------
// Device streams (VC-102).

#[test]
fn the_first_slot_follows_the_opening_window() {
    // Bucket 100 overlaps slots 150 and 151; the stream may start at 152.
    for (first, held) in [(150, false), (151, false), (152, false), (153, true)] {
        let mut events = std::vec![w(opened(B1, OPEN))];
        events.push(t(box_tick(B1, first, 0, BoxProgressState::Casting)));
        let run = go(&events);
        let r = run.of(B1);
        assert_eq!(r.first_slot, Some(first.min(152)), "first tick {first}");
        assert!(
            r.refusals.is_empty(),
            "first tick {first}: {:?}",
            r.refusals
        );
        assert_eq!(r.ticks, 1);
        assert_eq!(r.holds.contains(HoldReason::ProgressStream), held);
        // The check-in unit, without a tick, starts at the window's start.
        assert_eq!(run.station().first_slot, Some(150));
    }
    // A tick before the window is before opening; the stream starts at the
    // window's first slot.
    let early = box_tick(B1, 149, 0, BoxProgressState::Casting);
    let run = go(&[
        w(opened(B1, OPEN)),
        t(early),
        t(box_tick(B1, 150, 0, BoxProgressState::Casting)),
    ]);
    let r = run.of(B1);
    assert_eq!(r.first_slot, Some(150));
    assert_eq!(r.refusals, [run.refused(early, ProgressReason::Unused)]);
    assert_eq!(r.holds, hold(HoldReason::ProgressStream));
    // Bucket 101 overlaps slots 151 and 152.
    let early = box_tick(B1, 150, 0, BoxProgressState::Casting);
    let run = go(&[w(opened(B1, 101)), t(early)]);
    assert_eq!(run.of(B1).first_slot, Some(151));
    assert_eq!(
        run.of(B1).refusals,
        [run.refused(early, ProgressReason::Unused)]
    );
    // Without a tick, the stream starts at the window's first slot.
    let run = go(&[w(opened(B1, 101))]);
    assert_eq!(run.of(B1).first_slot, Some(151));
    assert_eq!(run.of(B1).ticks, 0);
    // The station starts with its earliest stream; the check-in unit
    // opens with the station's first opening.
    let run = go(&[
        w(opened(B2, 101)),
        w(opened(B1, OPEN)),
        t(box_tick(B1, 152, 0, BoxProgressState::Casting)),
        t(box_tick(B2, 153, 0, BoxProgressState::Casting)),
        t(checkin_tick(
            151,
            [0, 0, 0, 0],
            CheckinProgressState::Checking,
        )),
    ]);
    assert_eq!(run.of(B1).first_slot, Some(152));
    assert_eq!(run.of(B2).first_slot, Some(153));
    assert_eq!(run.station().first_slot, Some(151));
    assert_eq!(run.station().last_slot, Some(153));
    assert_eq!(run.progress.holds(), HoldSet::empty());
}

#[test]
fn a_tick_of_a_box_that_never_opened_is_refused() {
    let tick = box_tick(B1, 150, 0, BoxProgressState::Casting);
    let ci = checkin_tick(150, [0, 0, 0, 0], CheckinProgressState::Checking);
    let swap = checkin_swap(151, [0, 0, 0, 0], &WITNESSES);
    let chk = check(150, ProgressAlarm::Floor, ProgressFinding::Explained, OPEN);
    let run = go(&[t(tick), t(ci), w(swap), w(chk)]);
    let r = run.of(B1);
    assert_eq!(r.first_slot, None);
    assert_eq!(r.refusals, [run.refused(tick, ProgressReason::NotOpened)]);
    assert_eq!(r.holds, hold(HoldReason::ProgressStream));
    let st = run.station();
    assert_eq!(st.first_slot, None);
    assert_eq!(
        st.refusals,
        [
            run.refused(ci, ProgressReason::NotOpened),
            run.refused(swap, ProgressReason::NotOpened),
            run.refused(chk, ProgressReason::NotOpened),
        ]
    );
    assert_eq!(
        st.holds,
        hold(HoldReason::ProgressStream).with(HoldReason::ProgressUnresolved)
    );
    // A tick of the other box, opened, is fine; the station opened.
    let run = go(&[w(opened(B2, OPEN)), t(tick)]);
    assert_eq!(
        run.of(B1).refusals,
        [run.refused(tick, ProgressReason::NotOpened)]
    );
    assert_eq!(run.of(B2).first_slot, Some(150));
    assert_eq!(run.station().first_slot, Some(150));
    assert_eq!(run.station().holds, HoldSet::empty());
    assert_eq!(run.progress.box_holds(b"BOX-2"), HoldSet::empty());
    assert_eq!(
        run.progress.box_holds(b"BOX-1"),
        hold(HoldReason::ProgressStream)
    );
}

#[test]
fn the_stream_rules_hold_the_box() {
    // A second tick for a slot: not used.
    let second = box_tick(B1, 151, 2, BoxProgressState::Casting);
    let run = go(&day_with(&[t(second)]));
    run.clean_below();
    assert_eq!(
        run.of(B1).refusals,
        [run.refused(second, ProgressReason::Unused)]
    );
    assert_eq!(run.of(B1).holds, hold(HoldReason::ProgressStream));
    assert_eq!(run.of(B1).ticks, 4);
    assert_eq!(run.of(B2).holds, HoldSet::empty());
    assert_eq!(run.station().holds, HoldSet::empty());
    assert_eq!(run.progress.holds(), hold(HoldReason::ProgressStream));
    // After the closing tick: not used.
    let after = box_tick(B1, 154, 2, BoxProgressState::Closed);
    let run = go(&day_with(&[t(after)]));
    assert_eq!(
        run.of(B1).refusals,
        [run.refused(after, ProgressReason::Unused)]
    );
    assert_eq!(run.of(B1).holds, hold(HoldReason::ProgressStream));
    // A count going down: used, held.
    let rows = [
        (150, [1, 1, 0, 0], 1, 0),
        (151, [2, 2, 0, 0], 0, 1),
        (152, [3, 3, 0, 0], 2, 1),
        (153, [3, 3, 0, 0], 2, 1),
    ];
    let mut events = openings();
    events.extend(ticks(&rows));
    events.extend(station_close());
    let run = go(&events);
    run.clean_below();
    assert!(run.of(B1).refusals.is_empty(), "{:?}", run.of(B1).refusals);
    assert_eq!(run.of(B1).holds, hold(HoldReason::ProgressStream));
    assert_eq!(run.of(B2).holds, HoldSet::empty());
    // A missing slot: the later tick is used, the box held.
    let mut events = openings();
    events.extend(
        ticks(&CLEAN)
            .into_iter()
            .filter(|e| e.1 != box_tick(B2, 151, 0, BoxProgressState::Casting)),
    );
    events.extend(station_close());
    let run = go(&events);
    assert!(run.of(B2).refusals.is_empty(), "{:?}", run.of(B2).refusals);
    assert_eq!(run.of(B2).ticks, 3);
    assert_eq!(run.of(B2).holds, hold(HoldReason::ProgressStream));
    assert_eq!(run.of(B1).holds, HoldSet::empty());
    // A last tick that is not the close's count.
    let rows = [
        (150, [1, 1, 0, 0], 0, 0),
        (151, [2, 2, 0, 0], 1, 0),
        (152, [3, 3, 0, 0], 2, 1),
        (153, [3, 3, 0, 0], 3, 1),
    ];
    let mut events = openings();
    events.extend(ticks(&rows));
    events.extend(station_close());
    let run = go(&events);
    assert_eq!(run.of(B1).close, CloseCheck::Compared);
    assert_eq!(run.of(B1).holds, hold(HoldReason::ProgressStream));
    assert_eq!(run.of(B2).holds, HoldSet::empty());
    // A stream that never sent its closing tick.
    let mut events = openings();
    events.extend(open_ticks(&CLEAN[..3]));
    events.extend(station_close());
    let run = go(&events);
    for bx in [B1, B2] {
        assert_eq!(run.of(bx).close, CloseCheck::Compared);
        assert_eq!(run.of(bx).holds, hold(HoldReason::ProgressStream));
    }
    assert_eq!(run.station().close, CloseCheck::Compared);
    assert!(run.station().holds.contains(HoldReason::ProgressStream));
}

#[test]
fn a_tick_no_registered_key_signed_is_refused() {
    // Another box's device, the unit's key, the right key under the other
    // purpose.
    let wrong = box_tick_by(B2.device, B1, 151, 1, BoxProgressState::Casting);
    let unit = checkin_tick_with(
        1,
        b"U-1A",
        151,
        [2, 2, 0, 0],
        CheckinProgressState::Checking,
        b"checkin-progress",
    );
    let purpose = checkin_tick_with(
        0,
        b"U-1A",
        151,
        [2, 2, 0, 1],
        CheckinProgressState::Checking,
        b"box-progress",
    );
    let run = go(&day_with(&[t(wrong), t(unit), t(purpose)]));
    assert_eq!(
        run.of(B1).refusals,
        [run.refused(wrong, ProgressReason::Signature)]
    );
    assert_eq!(run.of(B1).holds, hold(HoldReason::ProgressStream));
    assert_eq!(
        run.station().refusals,
        [
            run.refused(unit, ProgressReason::State(Error::SignatureSigner)),
            run.refused(purpose, ProgressReason::Signature),
        ]
    );
    assert_eq!(run.station().holds, hold(HoldReason::ProgressStream));
    assert_eq!(run.station().close, CloseCheck::Compared);
    assert_eq!(
        run.progress.box_holds(b"BOX-2"),
        hold(HoldReason::ProgressStream)
    );
}

#[test]
fn a_tick_past_the_last_slot_is_refused() {
    let far = box_tick(
        B1,
        150 + MAX_PROGRESS_SLOTS + 1,
        2,
        BoxProgressState::Casting,
    );
    let edge = box_tick(B2, 150 + MAX_PROGRESS_SLOTS, 1, BoxProgressState::Casting);
    let mut events = openings();
    events.extend(open_ticks(&CLEAN[..3]));
    events.push(t(far));
    events.push(t(edge));
    let run = go(&events);
    assert_eq!(
        run.of(B1).refusals,
        [run.refused(far, ProgressReason::OutOfRange)]
    );
    assert_eq!(run.of(B1).holds, hold(HoldReason::ProgressStream));
    // The last slot itself is taken (with its gap).
    assert!(run.of(B2).refusals.is_empty(), "{:?}", run.of(B2).refusals);
    assert_eq!(run.of(B2).ticks, 4);
    assert_eq!(run.station().last_slot, Some(150 + MAX_PROGRESS_SLOTS));
}

#[test]
fn a_manual_close_is_not_compared() {
    let mut events = openings();
    events.extend(open_ticks(&CLEAN[..2]));
    events.extend((1..=2).map(|i| (SCHEMA_CAST_RECORD, record(B1, i))));
    events.push((SCHEMA_BATCH_ATTEST, batch(B1, 2)));
    events.push((SCHEMA_BOX_CLOSE, close_by(B1, 2, None)));
    let run = go(&events);
    run.clean_below();
    assert_eq!(run.boxes.report(B1.id).unwrap().phase, Phase::Closed);
    let r = run.of(B1);
    assert_eq!(r.close, CloseCheck::Manual);
    // The stream never closed, but a manual close is not compared.
    assert_eq!(r.holds, HoldSet::empty());
    assert_eq!(run.of(B2).close, CloseCheck::Open);
    assert_eq!(run.station().close, CloseCheck::Open);
}

// ---------------------------------------------------------------------
// The check-in stream at close.

#[test]
fn the_check_in_stream_is_compared_at_close() {
    // A final count that disagrees with the last check-in tick.
    let mut events = openings();
    events.extend(ticks(&CLEAN));
    events.extend(closed(B1, 2));
    events.extend(closed(B2, 1));
    events.push(w(issuance(3)));
    events.push(w(observers(4)));
    let run = go(&events);
    run.clean_below();
    assert_eq!(run.station().close, CloseCheck::Compared);
    assert_eq!(run.station().holds, hold(HoldReason::ProgressStream));
    assert_eq!(run.of(B1).holds, HoldSet::empty());
    assert_eq!(
        run.progress.box_holds(b"BOX-1"),
        hold(HoldReason::ProgressStream)
    );
    // An issuance count that disagrees.
    let mut events = openings();
    events.extend(ticks(&CLEAN));
    events.extend(closed(B1, 2));
    events.extend(closed(B2, 1));
    events.push(w(issuance(4)));
    events.push(w(observers(3)));
    let run = go(&events);
    assert_eq!(run.station().close, CloseCheck::Compared);
    assert_eq!(run.station().holds, hold(HoldReason::ProgressStream));
    // The last of each counts: a periodic count is not a final one.
    let mut events = openings();
    events.extend(ticks(&CLEAN));
    events.extend(closed(B1, 2));
    events.extend(closed(B2, 1));
    events.push(w(issuance(4)));
    events.push(w(issuance(3)));
    events.push(w(observers(5)));
    events.push(w(observers(3)));
    events.push(w(observers_by(7, ObserverCountKind::Periodic, &OBSERVERS)));
    let run = go(&events);
    assert_eq!(run.station().close, CloseCheck::Compared);
    assert_eq!(run.station().holds, HoldSet::empty());
}

#[test]
fn a_station_closed_without_its_counts_is_held() {
    for (with_issuance, with_observers) in [(false, true), (true, false), (false, false)] {
        let mut events = openings();
        events.extend(ticks(&CLEAN));
        events.extend(closed(B1, 2));
        events.extend(closed(B2, 1));
        if with_issuance {
            events.push(w(issuance(3)));
        }
        if with_observers {
            events.push(w(observers(3)));
        }
        let run = go(&events);
        assert_eq!(run.station().close, CloseCheck::Missing);
        assert!(
            run.station().refusals.is_empty(),
            "{:?}",
            run.station().refusals
        );
        assert_eq!(run.station().holds, hold(HoldReason::ProgressStream));
    }
    // Counts whose signatures do not verify, or whose signers do not fit,
    // are refused.
    let bad_issuance = issuance_by(3, &FORGED);
    let bad_observers = observers_by(
        3,
        ObserverCountKind::Final,
        &[
            By::Person(b"clerk-1", EventRole::Observer),
            By::Person(b"obs-a", EventRole::Observer),
        ],
    );
    let mut events = openings();
    events.extend(ticks(&CLEAN));
    events.extend(closed(B1, 2));
    events.extend(closed(B2, 1));
    events.push(w(bad_issuance));
    events.push(w(bad_observers));
    let run = go(&events);
    assert_eq!(run.station().close, CloseCheck::Missing);
    assert_eq!(
        run.station().refusals,
        [
            run.refused(bad_issuance, ProgressReason::Signature),
            run.refused(bad_observers, ProgressReason::State(Error::NotRegistered)),
        ]
    );
    assert_eq!(run.station().holds, hold(HoldReason::ProgressStream));
    // An issuance count whose signers claim roles they do not hold.
    let thin = issuance_by(3, &MISROLED);
    let mut events = openings();
    events.extend(ticks(&CLEAN));
    events.extend(closed(B1, 2));
    events.extend(closed(B2, 1));
    events.push(w(thin));
    events.push(w(observers(3)));
    let run = go(&events);
    assert_eq!(run.station().close, CloseCheck::Missing);
    assert_eq!(run.station().refusals.len(), 1);
    assert_eq!(run.station().refusals[0].seq, run.seq_of(thin));
    assert!(matches!(
        run.station().refusals[0].reason,
        ProgressReason::State(_)
    ));
}

// ---------------------------------------------------------------------
// Alarms and checks (VC-103).

/// The rows of a station where one sheet stays outside: issued 1, nothing
/// in, for slots 150–155 (the floor alarm at 152).
fn quiet_rows() -> Vec<Row> {
    (150..=155).map(|s| (s, [1, 1, 0, 0], 0, 0)).collect()
}

/// A running station (no close) with `rows` and `extra`.
fn running(rows: &[Row], extra: &[Ev]) -> Run {
    let mut events = openings();
    for &(slot, c, b1, b2) in rows {
        events.push(t(checkin_tick(slot, c, CheckinProgressState::Checking)));
        events.push(t(box_tick(B1, slot, b1, BoxProgressState::Casting)));
        events.push(t(box_tick(B2, slot, b2, BoxProgressState::Casting)));
    }
    events.extend_from_slice(extra);
    go(&events)
}

#[test]
fn a_floor_alarm_without_a_check_holds_the_station() {
    let run = running(&quiet_rows(), &[]);
    let st = run.station();
    assert_eq!(st.alarms, [alarm(152, ProgressAlarm::Floor)]);
    assert_eq!(st.holds, hold(HoldReason::ProgressUnresolved));
    assert!(st.counterfoil);
    for bx in [B1, B2] {
        assert_eq!(run.of(bx).holds, HoldSet::empty());
        assert_eq!(
            run.progress.box_holds(bx.id),
            hold(HoldReason::ProgressUnresolved)
        );
    }
    // Within the window the alarm still waits: not yet held while voting.
    let run = running(&quiet_rows()[..4], &[]);
    assert_eq!(run.station().alarms, [alarm(152, ProgressAlarm::Floor)]);
    assert_eq!(run.station().holds, HoldSet::empty());
    assert!(!run.station().counterfoil);
}

#[test]
fn checks_answer_alarms_by_their_findings() {
    // Bucket 101 ends in slot 152, bucket 102 in 154 (153–154).
    let explained = check(152, ProgressAlarm::Floor, ProgressFinding::Explained, 101);
    let run = running(&quiet_rows(), &[w(explained)]);
    let st = run.station();
    assert_eq!(st.alarms, [alarm(152, ProgressAlarm::Floor)]);
    assert_eq!(st.checks, [run.seq_of(explained)]);
    assert!(st.refusals.is_empty(), "{:?}", st.refusals);
    assert_eq!(st.holds, HoldSet::empty());
    assert!(!st.counterfoil);
    // Carried out: the sheet leaves the count, the station holds.
    let carried = check(152, ProgressAlarm::Floor, ProgressFinding::CarriedOut, 102);
    let run = running(&quiet_rows(), &[w(carried)]);
    assert_eq!(run.station().checks, [run.seq_of(carried)]);
    assert_eq!(run.station().holds, hold(HoldReason::CarryOut));
    assert!(run.station().counterfoil);
    assert_eq!(run.station().alarms, [alarm(152, ProgressAlarm::Floor)]);
    // Unexplained.
    let unexplained = check(152, ProgressAlarm::Floor, ProgressFinding::Unexplained, 101);
    let run = running(&quiet_rows(), &[w(unexplained)]);
    assert_eq!(run.station().checks, [run.seq_of(unexplained)]);
    assert_eq!(run.station().holds, hold(HoldReason::ProgressUnresolved));
}

#[test]
fn a_check_is_recorded_in_the_last_slot_of_its_bucket() {
    // Bucket 102 overlaps slots 153 and 154: in the window of an alarm at
    // 152. Bucket 103 overlaps 154 and 155: its last slot is too late.
    // The station's ticks end at 154, so the alarm still waits when the
    // check comes.
    let late = check(152, ProgressAlarm::Floor, ProgressFinding::Explained, 103);
    let run = running(&quiet_rows()[..5], &[w(late)]);
    assert_eq!(
        run.station().refusals,
        [run.refused(late, ProgressReason::State(Error::LateWindow))]
    );
    assert!(run.station().checks.is_empty());
    assert_eq!(run.station().holds, hold(HoldReason::ProgressUnresolved));
    // A check recorded before its alarm finds no alarm waiting.
    let early = check(152, ProgressAlarm::Floor, ProgressFinding::Explained, OPEN);
    let run = running(&quiet_rows(), &[w(early)]);
    assert_eq!(
        run.station().refusals,
        [run.refused(early, ProgressReason::State(Error::Mismatch))]
    );
    // A correction is judged by the slot after its last slot: bucket 101
    // ends in 152, so slot 153 must no longer be quiet.
    let fixed = |last: u64| -> Vec<Row> {
        (150..=last)
            .map(|s| {
                if s < 153 {
                    (s, [1, 1, 0, 0], 0, 0)
                } else {
                    (s, [2, 2, 0, 0], 1, 0)
                }
            })
            .collect()
    };
    let corrected = check(152, ProgressAlarm::Floor, ProgressFinding::Corrected, 101);
    let run = running(&fixed(154), &[w(corrected)]);
    assert_eq!(run.station().checks, [run.seq_of(corrected)]);
    assert_eq!(run.station().alarms, [alarm(152, ProgressAlarm::Floor)]);
    assert_eq!(run.station().holds, HoldSet::empty());
    // Recorded in bucket 102 (last slot 154), the same correction is
    // judged by slot 155, which is quiet again: unresolved.
    let corrected = check(152, ProgressAlarm::Floor, ProgressFinding::Corrected, 102);
    let run = running(&fixed(155), &[w(corrected)]);
    assert_eq!(run.station().checks, [run.seq_of(corrected)]);
    assert_eq!(run.station().holds, hold(HoldReason::ProgressUnresolved));
}

#[test]
fn a_check_without_its_alarm_is_refused() {
    // No alarm, a forged signature, and a stray check before a good one.
    // Bucket 98 ends in slot 148, before the station's first slot.
    let stray = check(150, ProgressAlarm::High, ProgressFinding::Explained, 98);
    let forged = check_by(
        152,
        ProgressAlarm::Floor,
        ProgressFinding::Explained,
        101,
        &FORGED,
    );
    let good = check(152, ProgressAlarm::Floor, ProgressFinding::Explained, 101);
    let run = running(&quiet_rows(), &[w(stray), w(forged), w(good)]);
    let st = run.station();
    assert_eq!(
        st.refusals,
        [
            run.refused(stray, ProgressReason::State(Error::Mismatch)),
            run.refused(forged, ProgressReason::Signature),
        ]
    );
    assert_eq!(st.checks, [run.seq_of(good)]);
    assert_eq!(st.holds, hold(HoldReason::ProgressUnresolved));
    // A check past the station's last slot is still taken in its window.
    let later = check(152, ProgressAlarm::Floor, ProgressFinding::Explained, 102);
    let run = running(&quiet_rows()[..3], &[w(later)]);
    assert_eq!(run.station().last_slot, Some(152));
    assert_eq!(run.station().checks, [run.seq_of(later)]);
    assert_eq!(run.station().holds, HoldSet::empty());
    // A check whose bucket has no slot.
    let nowhere = check(
        152,
        ProgressAlarm::Floor,
        ProgressFinding::Explained,
        u64::MAX,
    );
    let run = running(&quiet_rows()[..3], &[w(nowhere)]);
    assert_eq!(
        run.station().refusals,
        [run.refused(nowhere, ProgressReason::OutOfRange)]
    );
    assert_eq!(run.station().holds, hold(HoldReason::ProgressUnresolved));
}

#[test]
fn negative_and_high_alarms_are_raised_by_the_station() {
    // A sheet entered `BOX-2` that was never issued, for two slots.
    let rows: Vec<Row> = (150..=153).map(|s| (s, [0, 0, 0, 0], 0, 1)).collect();
    let run = running(&rows, &[]);
    assert_eq!(run.station().alarms, [alarm(151, ProgressAlarm::Negative)]);
    assert_eq!(run.station().holds, HoldSet::empty());
    // Thirteen sheets outside (the limit is twelve) for two slots, with
    // people moving.
    let rows: Vec<Row> = (150..=153)
        .map(|s| (s, [13 + s - 150, 13 + s - 150, 0, 0], s - 150, 0))
        .collect();
    let run = running(&rows, &[]);
    assert_eq!(run.station().alarms, [alarm(151, ProgressAlarm::High)]);
    // Each alarm in its slot, in the order negative, high, floor.
    let rows: Vec<Row> = (150..=153).map(|s| (s, [13, 13, 0, 0], 0, 0)).collect();
    let run = running(&rows, &[]);
    assert_eq!(
        run.station().alarms,
        [
            alarm(151, ProgressAlarm::High),
            alarm(152, ProgressAlarm::Floor)
        ]
    );
}

// ---------------------------------------------------------------------
// Suspension and swaps (§7.10 items 5 and 8, VC-106).

#[test]
fn a_fallback_suspends_the_station() {
    // Declared in bucket 100: from slot 150, no alarm.
    let run = running(&quiet_rows(), &[w(fallback(B1, OPEN))]);
    run.clean_below();
    assert!(
        run.station().alarms.is_empty(),
        "{:?}",
        run.station().alarms
    );
    assert!(run.station().suspended);
    assert_eq!(run.station().holds, HoldSet::empty());
    // Declared in bucket 101 (slot 151): the floor alarm at 152 is not
    // raised either.
    let run = running(&quiet_rows(), &[w(fallback(B1, 101))]);
    assert!(
        run.station().alarms.is_empty(),
        "{:?}",
        run.station().alarms
    );
    // Declared in bucket 102 (slot 153): the alarm at 152 stands.
    let run = running(&quiet_rows(), &[w(fallback(B1, 102))]);
    assert_eq!(run.station().alarms, [alarm(152, ProgressAlarm::Floor)]);
    assert!(run.station().suspended);
    // Declared later than every slot: reported, nothing changes.
    let run = running(&quiet_rows()[..4], &[w(fallback(B1, 120))]);
    assert_eq!(run.station().alarms, [alarm(152, ProgressAlarm::Floor)]);
    assert!(run.station().suspended);
    // A fallback with no slot does not suspend.
    let run = running(&quiet_rows()[..4], &[w(fallback(B1, u64::MAX))]);
    assert!(!run.station().suspended);
    // A tick in fallback suspends nothing by itself (a device cannot turn
    // the alarms off by saying so): with no fallback of its box declared by
    // its slot it is refused and holds its box, and the alarm stands.
    let fallback_tick = box_tick(B1, 151, 0, BoxProgressState::Fallback);
    let day = |declared: Option<u64>| {
        let mut events = openings();
        events.extend(declared.map(|bucket| w(fallback(B1, bucket))));
        for s in 150..=155 {
            events.push(t(checkin_tick(
                s,
                [1, 1, 0, 0],
                CheckinProgressState::Checking,
            )));
            events.push(t(if s == 151 {
                fallback_tick
            } else {
                box_tick(B1, s, 0, BoxProgressState::Casting)
            }));
            events.push(t(box_tick(B2, s, 0, BoxProgressState::Casting)));
        }
        go(&events)
    };
    let run = day(None);
    assert_eq!(run.station().alarms, [alarm(152, ProgressAlarm::Floor)]);
    assert!(!run.station().suspended);
    assert_eq!(
        run.of(B1).refusals,
        [run.refused(fallback_tick, ProgressReason::Undeclared)]
    );
    assert!(run.of(B1).holds.contains(HoldReason::ProgressStream));
    // Declared in bucket 102 (from slot 153): still too late for the tick.
    let run = day(Some(102));
    assert_eq!(
        run.of(B1).refusals,
        [run.refused(fallback_tick, ProgressReason::Undeclared)]
    );
    // Declared in bucket 101 (from slot 151): the tick is taken.
    let run = day(Some(101));
    assert!(run.of(B1).refusals.is_empty(), "{:?}", run.of(B1).refusals);
    assert!(
        run.station().alarms.is_empty(),
        "{:?}",
        run.station().alarms
    );
    assert!(run.station().suspended);
}

#[test]
fn the_check_in_unit_hands_over_to_its_spare() {
    // `U-1A` fails after slot 151; the witnesses read its counts (two
    // voters) and the spare `U-1B` reports from 152.
    let swap = checkin_swap(152, [2, 2, 0, 0], &WITNESSES);
    let old = checkin_tick(152, [2, 2, 0, 0], CheckinProgressState::Checking);
    let mut events = openings();
    for &(slot, c, b1, b2) in &CLEAN {
        let closing = slot == 153;
        if slot < 152 {
            events.push(t(checkin_tick(slot, c, CheckinProgressState::Checking)));
        } else {
            let state = if closing {
                CheckinProgressState::Closed
            } else {
                CheckinProgressState::AfterSwap
            };
            events.push(t(spare_tick(slot, c, state)));
        }
        let bs = if closing {
            BoxProgressState::Closed
        } else {
            BoxProgressState::Casting
        };
        events.push(t(box_tick(B1, slot, b1, bs)));
        events.push(t(box_tick(B2, slot, b2, bs)));
    }
    events.push(w(swap));
    events.extend(station_close());
    let run = go(&events);
    run.clean_below();
    let st = run.station();
    assert!(st.refusals.is_empty(), "{:?}", st.refusals);
    assert_eq!(st.ticks, 4);
    assert_eq!(st.close, CloseCheck::Compared);
    assert_eq!(st.holds, HoldSet::empty());
    assert!(st.suspended);
    // The failed unit's tick after the swap is refused.
    let mut late = events.clone();
    let at = late.iter().position(|e| e.1 == swap).unwrap();
    late.insert(at + 1, t(old));
    let run = go(&late);
    assert_eq!(
        run.station().refusals,
        [run.refused(old, ProgressReason::State(Error::SignatureSigner))]
    );
    assert_eq!(run.station().holds, hold(HoldReason::ProgressStream));
    // A swap the witnesses did not sign is refused, and the spare's ticks
    // with it: the one after the swap says so with no swap taken
    // (`Undeclared`), the closing one is not the bound unit's.
    let forged = checkin_swap(152, [2, 2, 0, 0], &FORGED);
    let mut bad = events.clone();
    let at = bad.iter().position(|e| e.1 == swap).unwrap();
    bad[at] = w(forged);
    let run = go(&bad);
    let reasons: Vec<ProgressReason> = run.station().refusals.iter().map(|r| r.reason).collect();
    assert_eq!(
        reasons,
        [
            ProgressReason::Undeclared,
            ProgressReason::State(Error::SignatureSigner),
            ProgressReason::Signature,
        ]
    );
    assert!(!run.station().suspended);
    assert!(run.station().holds.contains(HoldReason::ProgressStream));
    // A swap that does not fit the stream (from the spare, a second time).
    let again = checkin_swap(153, [3, 3, 0, 0], &WITNESSES);
    let mut twice = events.clone();
    twice.insert(at + 1, w(again));
    let run = go(&twice);
    assert_eq!(
        run.station().refusals,
        [run.refused(again, ProgressReason::State(Error::Mismatch))]
    );
}

#[test]
fn a_swap_suspends_the_alarms_from_its_slot() {
    // The quiet station hands its check-in unit over at slot 152.
    let mut rows = quiet_rows();
    rows.truncate(5);
    let mut events = openings();
    for &(slot, c, b1, b2) in &rows {
        if slot < 152 {
            events.push(t(checkin_tick(slot, c, CheckinProgressState::Checking)));
        } else {
            events.push(t(spare_tick(slot, c, CheckinProgressState::Checking)));
        }
        events.push(t(box_tick(B1, slot, b1, BoxProgressState::Casting)));
        events.push(t(box_tick(B2, slot, b2, BoxProgressState::Casting)));
    }
    events.push(w(checkin_swap(152, [1, 1, 0, 0], &WITNESSES)));
    let run = go(&events);
    assert!(
        run.station().refusals.is_empty(),
        "{:?}",
        run.station().refusals
    );
    assert!(
        run.station().alarms.is_empty(),
        "{:?}",
        run.station().alarms
    );
    assert!(run.station().suspended);
    // At slot 153 the alarm at 152 is already raised.
    let mut events = openings();
    for &(slot, c, b1, b2) in &rows {
        if slot < 153 {
            events.push(t(checkin_tick(slot, c, CheckinProgressState::Checking)));
        } else {
            events.push(t(spare_tick(slot, c, CheckinProgressState::Checking)));
        }
        events.push(t(box_tick(B1, slot, b1, BoxProgressState::Casting)));
        events.push(t(box_tick(B2, slot, b2, BoxProgressState::Casting)));
    }
    events.push(w(checkin_swap(153, [1, 1, 0, 0], &WITNESSES)));
    let run = go(&events);
    assert!(
        run.station().refusals.is_empty(),
        "{:?}",
        run.station().refusals
    );
    assert_eq!(run.station().alarms, [alarm(152, ProgressAlarm::Floor)]);
}

#[test]
fn a_box_continues_on_its_spare_device_after_the_amendment() {
    // Frames: genesis 1, authorization 2, openings 3–4, ticks of slots
    // 150–151, the amendment, the swap at slot 152 (two sheets in), the
    // spare's ticks from 152, closes.
    let a = amended();
    let amendment = a.amendment.unwrap();
    let mut events = openings();
    events.extend(open_ticks(&CLEAN[..2]));
    events.push(g(amendment));
    let swap = box_swap(B1, 152, 1, &WITNESSES);
    events.push(w(swap));
    for &(slot, c, b1, b2) in &CLEAN[2..] {
        let closing = slot == 153;
        let (cs, bs) = if closing {
            (CheckinProgressState::Closed, BoxProgressState::Closed)
        } else {
            (CheckinProgressState::Checking, BoxProgressState::Casting)
        };
        events.push(t(checkin_tick(slot, c, cs)));
        events.push(t(box_tick_by(SPARE_DEVICE, B1, slot, b1, bs)));
        events.push(t(box_tick(B2, slot, b2, bs)));
    }
    let mut closes: Vec<Ev> = (1..=2)
        .map(|i| (SCHEMA_CAST_RECORD, record(B1, i)))
        .collect();
    closes.push((SCHEMA_BATCH_ATTEST, batch(B1, 2)));
    closes.push((SCHEMA_BOX_CLOSE, close_by(B1, 2, Some(SPARE_DEVICE))));
    closes.extend(closed(B2, 1));
    closes.push(w(issuance(3)));
    closes.push(w(observers(3)));
    events.extend(closes.iter().copied());
    let run = run_in(a, &events);
    run.clean_below();
    let r = run.of(B1);
    assert!(r.refusals.is_empty(), "{:?}", r.refusals);
    assert_eq!(r.ticks, 4);
    assert_eq!(r.close, CloseCheck::Compared);
    assert_eq!(r.holds, HoldSet::empty());
    assert!(run.station().suspended);
    assert_eq!(run.progress.holds(), HoldSet::empty());

    // The replaced device's tick after the swap, and the spare's tick in a
    // frame before the amendment, are refused.
    let old = box_tick(B1, 153, 2, BoxProgressState::Casting);
    let early = box_tick_by(SPARE_DEVICE, B1, 151, 1, BoxProgressState::Casting);
    let mut bad = std::vec![events[0], events[1], t(early)];
    bad.extend_from_slice(&events[2..]);
    // Before the closes (after them it would be refused as after the close).
    let at = bad.iter().position(|e| e.0 == SCHEMA_CAST_RECORD).unwrap();
    bad.insert(at, t(old));
    let run = run_in(a, &bad);
    assert_eq!(
        run.of(B1).refusals,
        [
            run.refused(early, ProgressReason::Signature),
            run.refused(old, ProgressReason::State(Error::SignatureSigner)),
        ]
    );
    assert_eq!(run.of(B1).holds, hold(HoldReason::ProgressStream));

    // A swap whose signers do not fit is refused by the box stage, so the
    // stream keeps the old key and the spare's ticks are refused.
    let forged = box_swap(B1, 152, 1, &FORGED);
    let mut bad = events.clone();
    let at = bad.iter().position(|e| e.1 == swap).unwrap();
    bad[at] = w(forged);
    let run = run_in(a, &bad);
    let reasons: Vec<ProgressReason> = run.of(B1).refusals.iter().map(|r| r.reason).collect();
    assert_eq!(
        reasons,
        [
            ProgressReason::State(Error::SignatureSigner),
            ProgressReason::State(Error::SignatureSigner),
        ]
    );
    assert!(!run.station().suspended);
}

// ---------------------------------------------------------------------
// A station an amendment removed.

#[test]
fn progress_events_of_a_removed_station_are_held() {
    let world = removed();
    let body = CheckinProgressBody::new(&CheckinProgressParts {
        election_id: election(),
        station_id: StationId::new(b"ST-2").unwrap(),
        unit_id: UnitId::new(b"U-2A").unwrap(),
        slot: 150,
        checkins: 0,
        issued: 0,
        spoiled: 0,
        returned: 0,
        state: CheckinProgressState::Checking,
    })
    .unwrap();
    let body = object(SCHEMA_CHECKIN_PROGRESS_BODY, SCHEMA_VERSION_1, &body);
    let tick = object(
        SCHEMA_PROGRESS_TICK,
        SCHEMA_VERSION_1,
        &ProgressTick::new(body, sign(unit_signing(2), b"checkin-progress", body)).unwrap(),
    );
    let chk = {
        let body = ProgressCheckBody::new(&ProgressCheckParts {
            election_id: election(),
            station_id: StationId::new(b"ST-2").unwrap(),
            alarm_slot: 150,
            alarm: ProgressAlarm::Floor,
            holding: 0,
            finding: ProgressFinding::Explained,
            carried_out: 0,
            statement_hash: Hash512([0x71; 64]),
            time_bucket: TimeBucket::new(OPEN),
        })
        .unwrap();
        let body = object(SCHEMA_PROGRESS_CHECK_BODY, SCHEMA_VERSION_1, &body);
        witnessed(SCHEMA_PROGRESS_CHECK_BODY, body, &WITNESSES)
    };
    let count = {
        let body = ObserverCountAttestBody::new(&ObserverCountParts {
            election_id: election(),
            station_id: StationId::new(b"ST-2").unwrap(),
            unit_id: UnitId::new(b"U-2A").unwrap(),
            count: 1,
            kind: ObserverCountKind::Final,
            time_bucket: TimeBucket::new(CLOSE_BUCKET),
        });
        let body = object(SCHEMA_OBSERVER_COUNT_ATTEST_BODY, SCHEMA_VERSION_1, &body);
        witnessed(SCHEMA_OBSERVER_COUNT_ATTEST_BODY, body, &OBSERVERS)
    };
    let run = run_in(world, &[t(tick), w(chk), w(count)]);
    assert!(
        run.index.findings().is_empty(),
        "{:?}",
        run.index.findings()
    );
    let st = run.progress.station(b"ST-2").unwrap();
    assert_eq!(
        st.refusals,
        [
            run.refused(tick, ProgressReason::Unexpected),
            run.refused(chk, ProgressReason::Unexpected),
        ]
    );
    assert_eq!(st.holds, hold(HoldReason::ProgressStream));
    assert_eq!(st.first_slot, None);
    assert_eq!(st.close, CloseCheck::Open);
    assert_eq!(run.progress.stations().len(), 2);
    assert_eq!(run.progress.holds(), hold(HoldReason::ProgressStream));
    // ST-1 is unaffected.
    assert_eq!(run.station().holds, HoldSet::empty());
}

#[test]
fn only_the_closing_tick_comes_after_the_close() {
    // The device's closing tick after its close is taken (the device sends
    // it after closing, ADR-0027).
    let mut events = openings();
    events.extend(open_ticks(&CLEAN[..3]));
    events.extend(station_close());
    events.extend(ticks(&CLEAN[3..]));
    let run = go(&events);
    run.clean_below();
    assert_eq!(run.progress.holds(), HoldSet::empty());
    // A slot left out is held, and filling it in after the close does not
    // help (§7.10 item 8): the box's tick and the check-in unit's.
    let gap = box_tick(B1, 151, 1, BoxProgressState::Casting);
    let checkin_gap = checkin_tick(151, [2, 2, 0, 0], CheckinProgressState::Checking);
    let mut events: Vec<Ev> = day_with(&[])
        .into_iter()
        .filter(|e| e.1 != gap && e.1 != checkin_gap)
        .collect();
    let run = go(&events);
    assert!(run.of(B1).holds.contains(HoldReason::ProgressStream));
    events.push(t(gap));
    events.push(t(checkin_gap));
    let run = go(&events);
    assert_eq!(
        run.of(B1).refusals,
        [run.refused(gap, ProgressReason::AfterClose)]
    );
    assert!(run.of(B1).holds.contains(HoldReason::ProgressStream));
    assert_eq!(
        run.station().refusals,
        [run.refused(checkin_gap, ProgressReason::AfterClose)]
    );
    assert!(run.station().holds.contains(HoldReason::ProgressStream));
    // A check-in tick after one box closed but before the station's last
    // box did is still on time.
    let mut events = openings();
    events.extend(open_ticks(&CLEAN[..3]));
    events.extend(closed(B1, 2));
    events.extend(ticks(&CLEAN[3..]));
    events.extend(closed(B2, 1));
    events.push(w(issuance(3)));
    events.push(w(observers(3)));
    let run = go(&events);
    assert!(
        run.station().refusals.is_empty(),
        "{:?}",
        run.station().refusals
    );
    assert!(run.of(B1).refusals.is_empty(), "{:?}", run.of(B1).refusals);
}

#[test]
fn a_huge_count_does_not_stop_the_station() {
    // One box reports u64::MAX sheets: the station's sum is exact, the
    // slots go on being closed and the alarms raised (a device cannot end
    // the evaluation, and with it the holds so far).
    let rows: [Row; 4] = [
        (150, [1, 1, 0, 0], 0, 0),
        (151, [2, 2, 0, 0], u64::MAX, 1),
        (152, [3, 3, 0, 0], u64::MAX, 1),
        (153, [3, 3, 0, 0], u64::MAX, 1),
    ];
    let mut events = openings();
    events.extend(ticks(&rows));
    let run = go(&events);
    assert_eq!(run.station().last_slot, Some(153));
    assert_eq!(run.station().alarms, [alarm(152, ProgressAlarm::Negative)]);
}

#[test]
fn the_spare_reports_after_the_swap_in_later_slots() {
    // `U-1A` fails after slot 150; the spare reports "after swap" from 151
    // on, in every slot after the swap's, and closes at 153.
    let swap = checkin_swap(151, [1, 1, 0, 0], &WITNESSES);
    let mut events = openings();
    events.push(t(checkin_tick(
        150,
        [1, 1, 0, 0],
        CheckinProgressState::Checking,
    )));
    for (slot, c, state) in [
        (151, [2, 2, 0, 0], CheckinProgressState::AfterSwap),
        (152, [3, 3, 0, 0], CheckinProgressState::AfterSwap),
        (153, [3, 3, 0, 0], CheckinProgressState::Closed),
    ] {
        events.push(t(spare_tick(slot, c, state)));
    }
    for (i, &(slot, _, b1, b2)) in CLEAN.iter().enumerate() {
        let bs = if i + 1 == CLEAN.len() {
            BoxProgressState::Closed
        } else {
            BoxProgressState::Casting
        };
        events.push(t(box_tick(B1, slot, b1, bs)));
        events.push(t(box_tick(B2, slot, b2, bs)));
    }
    events.push(w(swap));
    events.extend(station_close());
    let run = go(&events);
    assert!(
        run.station().refusals.is_empty(),
        "{:?}",
        run.station().refusals
    );
    assert_eq!(run.station().ticks, 4);
    assert!(run.station().suspended);
    assert_eq!(run.station().holds, HoldSet::empty());
}
