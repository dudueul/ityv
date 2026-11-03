//! The status ladder (PROTOCOL.md §14, end): `verify_ledger` runs every
//! stage over one ledger and `ityv_state::status::evaluate` gives one
//! status. A one-box election, real signatures throughout.
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
    BOX_DEVICE_BASE, COMMISSION, COMMITTEE, Draft, Ledger, ROSTER_BASE, SIGNERS, WITNESS_IDS,
    hybrid_signature, id, leak, leak_slice, modules, object, sign, sign_genesis_with, signing,
    unit_signing, witness_signing,
};
use ityv_crypto::object_hash;
use ityv_encoding::{
    Attestation, BoxClose, BoxCloseBody, BoxCloseParts, BoxId, BoxOpenedBody, BoxOpenedParts,
    CheckpointBody, CheckpointParts, CloseCounts, DisputeAction, DisputeEventBody,
    DisputeEventParts, DisputeType, EventRole, EventSig, Hash512, KeysetId, LedgerId,
    ModuleCounter, ModuleCounters, OrgId, SCHEMA_BOX_CLOSE, SCHEMA_BOX_CLOSE_BODY,
    SCHEMA_BOX_OPENED_BODY, SCHEMA_CHECKPOINT_BODY, SCHEMA_DISPUTE_EVENT_BODY,
    SCHEMA_SIGNED_GENESIS, SCHEMA_SIGNED_LEGAL_AUTHORIZATION, SCHEMA_VERSION_1,
    SCHEMA_WITNESSED_EVENT, SchemaId, Scope, Seq, SignerId, SignerRole, TimeBucket, TreeSize,
    WitnessedEvent,
};
use ityv_encoding::{
    BoxProgressBody, BoxProgressParts, BoxProgressState, CheckinProgressBody, CheckinProgressParts,
    CheckinProgressState, IssuanceCountBody, IssuanceCountParts, ObserverCountAttestBody,
    ObserverCountKind, ObserverCountParts, ProgressTick, SCHEMA_BOX_PROGRESS_BODY,
    SCHEMA_CHECKIN_PROGRESS_BODY, SCHEMA_ISSUANCE_COUNT_BODY, SCHEMA_OBSERVER_COUNT_ATTEST_BODY,
    SCHEMA_PROGRESS_TICK, StationId, UnitId, purpose_of,
};
use ityv_ledger::{
    Breach, EMPTY_ROOT, SCHEMA_SIGNED_CHECKPOINT, SignedCheckpointParts, WitnessSignatureEntry,
    root_of_leaves, sorted_set_root,
};
use ityv_state::{HoldReason, Publication, Status};
use ityv_verify::{Publications, Report, VerifiedGenesis, verify_genesis, verify_ledger};

const BOX: &[u8] = b"BOX-1";
const MODULES: [&[u8]; 2] = [b"M-B1-P1", b"M-B1-P2"];
const SEAL: Hash512 = Hash512([0x5e; 64]);

/// A genesis with BOX-1 alone, pinning an authorization of
/// `PUBLIC_BOARD`, `TRUSTEE_BODY` and `BALLOT_MARK`, built once.
struct World {
    genesis: &'static VerifiedGenesis<'static>,
    pin: Hash512,
    signed: &'static [u8],
    authorization: &'static [u8],
}

fn world() -> &'static World {
    static WORLD: OnceLock<&'static World> = OnceLock::new();
    WORLD.get_or_init(|| {
        let mut d = Draft::standard();
        d.boxes.retain(|b| b.box_id.as_bytes() == BOX);
        d.stations = std::vec![common::station(
            b"ST-1",
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
        d.appointments = d.referenced_appointments();
        let (body, authorization) = common::legal_authorization(
            &[Scope::PublicBoard, Scope::TrusteeBody, Scope::BallotMark],
            20_000,
            20_100,
        );
        let built = leak(sign_genesis_with(&d, d.raw(), &SIGNERS, |p| {
            p.legal_authorization_hash = object_hash(body);
        }));
        let genesis = leak(verify_genesis(&built.pin, &built.input(), &[]).unwrap());
        leak(World {
            genesis,
            pin: built.pin,
            signed: built.signed,
            authorization,
        })
    })
}

/// The people of the roster: identifier, organisation, key number.
fn person(id: &[u8]) -> (&'static [u8], u16) {
    match id {
        b"clerk-1" => (b"ORG-ST", ROSTER_BASE),
        b"clerk-2" => (b"ORG-ST", ROSTER_BASE + 1),
        b"obs-a" => (b"PARTY-A", ROSTER_BASE + 2),
        _ => (b"PARTY-B", ROSTER_BASE + 3),
    }
}

const PEOPLE: [(&[u8], EventRole); 4] = [
    (b"clerk-1", EventRole::Clerk),
    (b"clerk-2", EventRole::Clerk),
    (b"obs-a", EventRole::Observer),
    (b"obs-b", EventRole::Observer),
];

fn opened() -> &'static [u8] {
    let body = BoxOpenedBody::new(&BoxOpenedParts {
        election_id: common::election(),
        box_id: BoxId::new(BOX).unwrap(),
        modules: modules(&MODULES),
        seal_digest: SEAL,
        seals_match: true,
        initial_count: 0,
        time_bucket: TimeBucket::new(100),
    });
    let body = object(SCHEMA_BOX_OPENED_BODY, SCHEMA_VERSION_1, &body);
    let mut sigs: Vec<EventSig<'static>> = PEOPLE
        .iter()
        .map(|&(who, role)| {
            let (o, n) = person(who);
            EventSig {
                signer_id: SignerId::new(who).unwrap(),
                role,
                org_id: OrgId::new(o).unwrap(),
                sig: sign(signing(n), b"box-open", body),
            }
        })
        .collect();
    sigs.insert(
        0,
        EventSig {
            signer_id: SignerId::new(BOX).unwrap(),
            role: EventRole::Device,
            org_id: OrgId::new(b"ORG-ST").unwrap(),
            sig: sign(signing(BOX_DEVICE_BASE), b"box-open", body),
        },
    );
    object(
        SCHEMA_WITNESSED_EVENT,
        SCHEMA_VERSION_1,
        &WitnessedEvent::new(body, &sigs).unwrap(),
    )
}

/// A device-signed close of an empty box.
fn close() -> &'static [u8] {
    close_with(true)
}

/// A close of an empty box, device-signed or manual.
fn close_with(device_signed: bool) -> &'static [u8] {
    close_of(device_signed, EMPTY_ROOT)
}

/// A close of an empty box with record set root `set`.
fn close_of(device_signed: bool, set: Hash512) -> &'static [u8] {
    let counters: Vec<ModuleCounter<'static>> = MODULES
        .iter()
        .map(|m| ModuleCounter {
            module_id: common::module(m),
            counter: 0,
        })
        .collect();
    let body = BoxCloseBody::new(&BoxCloseParts {
        election_id: common::election(),
        box_id: BoxId::new(BOX).unwrap(),
        counts: CloseCounts {
            paper: 0,
            records: 0,
            attested: 0,
            without_record: 0,
            challenged: 0,
            quarantined: 0,
            visits: 0,
            envelopes: 0,
            stickers: 0,
            spoil_envelopes: 0,
        },
        record_set_root: set,
        journal_head: Hash512([0x24; 64]),
        seal_digest: SEAL,
        module_counters: ModuleCounters::new(&counters).unwrap(),
        open_batches: 0,
        time_bucket: TimeBucket::new(140),
    });
    let body = object(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, &body);
    let attestations: Vec<Attestation<'static>> = PEOPLE
        .iter()
        .map(|&(who, role)| {
            let (o, n) = person(who);
            Attestation {
                signer_id: SignerId::new(who).unwrap(),
                role: if role == EventRole::Clerk {
                    SignerRole::Clerk
                } else {
                    SignerRole::Observer
                },
                org_id: OrgId::new(o).unwrap(),
                sig: sign(signing(n), b"box-close", body),
            }
        })
        .collect();
    let device = device_signed.then(|| sign(signing(BOX_DEVICE_BASE), b"box-close", body));
    object(
        SCHEMA_BOX_CLOSE,
        SCHEMA_VERSION_1,
        &BoxClose::new(body, device, &attestations).unwrap(),
    )
}

/// A `WitnessedEvent` over `body` of `schema`, signed by `people` (in
/// ascending identifier order).
fn witnessed(
    schema: SchemaId,
    body: &'static [u8],
    people: &[(&[u8], EventRole)],
) -> &'static [u8] {
    let purpose = purpose_of(schema).unwrap();
    let sigs: Vec<EventSig<'static>> = people
        .iter()
        .map(|&(who, role)| {
            let (o, n) = person(who);
            EventSig {
                signer_id: SignerId::new(leak_slice(who.to_vec())).unwrap(),
                role,
                org_id: OrgId::new(o).unwrap(),
                sig: sign(signing(n), purpose, body),
            }
        })
        .collect();
    object(
        SCHEMA_WITNESSED_EVENT,
        SCHEMA_VERSION_1,
        &WitnessedEvent::new(body, &sigs).unwrap(),
    )
}

/// The voting progress record of a day on which nobody voted: one closing
/// tick of the box's device and of the station's check-in unit in the
/// opening's slot, the station's issuance count and the observers' final
/// count (PROTOCOL.md §7.10).
fn progress() -> [(SchemaId, &'static [u8]); 4] {
    let station = StationId::new(b"ST-1").unwrap();
    let body = BoxProgressBody::new(&BoxProgressParts {
        election_id: common::election(),
        box_id: BoxId::new(BOX).unwrap(),
        slot: 150,
        sheets_in: 0,
        state: BoxProgressState::Closed,
    });
    let body = object(SCHEMA_BOX_PROGRESS_BODY, SCHEMA_VERSION_1, &body);
    let sig = sign(signing(BOX_DEVICE_BASE), b"box-progress", body);
    let box_tick = object(
        SCHEMA_PROGRESS_TICK,
        SCHEMA_VERSION_1,
        &ProgressTick::new(body, sig).unwrap(),
    );
    let body = CheckinProgressBody::new(&CheckinProgressParts {
        election_id: common::election(),
        station_id: station,
        unit_id: UnitId::new(b"U-1A").unwrap(),
        slot: 150,
        checkins: 0,
        issued: 0,
        spoiled: 0,
        returned: 0,
        state: CheckinProgressState::Closed,
    })
    .unwrap();
    let body = object(SCHEMA_CHECKIN_PROGRESS_BODY, SCHEMA_VERSION_1, &body);
    let sig = sign(unit_signing(0), b"checkin-progress", body);
    let checkin_tick = object(
        SCHEMA_PROGRESS_TICK,
        SCHEMA_VERSION_1,
        &ProgressTick::new(body, sig).unwrap(),
    );
    let body = IssuanceCountBody::new(&IssuanceCountParts {
        election_id: common::election(),
        station_id: station,
        stock_received: 50,
        issued: 0,
        voter_spoiled: 0,
        returned: 0,
        unused: 50,
        printer_waste: 0,
        envelopes: None,
        time_bucket: TimeBucket::new(140),
    });
    let body = object(SCHEMA_ISSUANCE_COUNT_BODY, SCHEMA_VERSION_1, &body);
    let issuance = witnessed(SCHEMA_ISSUANCE_COUNT_BODY, body, &PEOPLE);
    let body = ObserverCountAttestBody::new(&ObserverCountParts {
        election_id: common::election(),
        station_id: station,
        unit_id: UnitId::new(b"U-1A").unwrap(),
        count: 0,
        kind: ObserverCountKind::Final,
        time_bucket: TimeBucket::new(140),
    });
    let body = object(SCHEMA_OBSERVER_COUNT_ATTEST_BODY, SCHEMA_VERSION_1, &body);
    let observers = witnessed(
        SCHEMA_OBSERVER_COUNT_ATTEST_BODY,
        body,
        &[
            (b"obs-a", EventRole::Observer),
            (b"obs-b", EventRole::Observer),
        ],
    );
    [
        (SCHEMA_PROGRESS_TICK, box_tick),
        (SCHEMA_PROGRESS_TICK, checkin_tick),
        (SCHEMA_WITNESSED_EVENT, issuance),
        (SCHEMA_WITNESSED_EVENT, observers),
    ]
}

/// A dispute filing signed by the commission and the committee.
fn filing() -> &'static [u8] {
    filing_at(120)
}

/// As [`filing`], filed in time bucket `bucket`.
fn filing_at(bucket: u64) -> &'static [u8] {
    let body = DisputeEventBody::new(&DisputeEventParts {
        election_id: common::election(),
        action: DisputeAction::Filed,
        dispute_type: DisputeType::Custody,
        box_id: Some(BoxId::new(BOX).unwrap()),
        record_hash: None,
        evidence_hash: Hash512([0x3E; 64]),
        filing_hash: Hash512::ZERO,
        result_hash: Hash512::ZERO,
        time_bucket: TimeBucket::new(bucket),
    })
    .unwrap();
    let body = object(SCHEMA_DISPUTE_EVENT_BODY, SCHEMA_VERSION_1, &body);
    let sigs = [
        EventSig {
            signer_id: SignerId::new(b"commission").unwrap(),
            role: EventRole::Commission,
            org_id: OrgId::new(b"NEC").unwrap(),
            sig: sign(signing(COMMISSION), b"dispute", body),
        },
        EventSig {
            signer_id: SignerId::new(b"committee").unwrap(),
            role: EventRole::Committee,
            org_id: OrgId::new(b"IVC").unwrap(),
            sig: sign(signing(COMMITTEE), b"dispute", body),
        },
    ];
    object(
        SCHEMA_WITNESSED_EVENT,
        SCHEMA_VERSION_1,
        &WitnessedEvent::new(body, &sigs).unwrap(),
    )
}

/// A ledger whose frames the test pushes, keeping the frame objects for
/// the checkpoint roots.
struct Book {
    ledger: Ledger,
    frames: Vec<Hash512>,
    closes: Vec<Hash512>,
    disputes: Vec<Hash512>,
    /// The sequence number and body hash of the last checkpoint pushed.
    last: Option<(u64, Hash512)>,
}

impl Book {
    fn new() -> Self {
        let w = world();
        let mut book = Self {
            ledger: Ledger::new(),
            frames: Vec::new(),
            closes: Vec::new(),
            disputes: Vec::new(),
            last: None,
        };
        book.push(SCHEMA_SIGNED_GENESIS, w.signed);
        book.push(SCHEMA_SIGNED_LEGAL_AUTHORIZATION, w.authorization);
        book
    }

    /// Pushes the day's progress record ([`progress`]).
    fn progress(&mut self) {
        for (schema, event) in progress() {
            self.push(schema, event);
        }
    }

    fn push(&mut self, schema: SchemaId, event: &'static [u8]) {
        self.ledger.push(schema, event);
        let stream = self.ledger.bytes();
        // The last frame of the stream: its length prefix and bytes.
        let mut at = 0usize;
        let mut last = &stream[0..0];
        while at < stream.len() {
            let len = u32::from_be_bytes(stream[at..at + 4].try_into().unwrap()) as usize;
            last = &stream[at + 4..at + 4 + len];
            at += 4 + len;
        }
        self.frames.push(object_hash(last));
        if schema == SCHEMA_BOX_CLOSE {
            self.closes.push(object_hash(event));
        }
    }

    /// A checkpoint over every frame so far, signed by nine witnesses,
    /// following the last one.
    fn checkpoint(&mut self) {
        let (seq, previous) = self
            .last
            .map_or((1, Hash512::ZERO), |(seq, hash)| (seq + 1, hash));
        let size = self.frames.len() as u64;
        let mut closes = self.closes.clone();
        closes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let mut disputes = self.disputes.clone();
        disputes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let body = CheckpointBody::new(&CheckpointParts {
            election_id: common::election(),
            ledger_id: LedgerId::new(b"L-1").unwrap(),
            keyset_id: KeysetId::new(b"K-1").unwrap(),
            checkpoint_seq: Seq::new(seq).unwrap(),
            tree_size: TreeSize::new(size),
            root_hash: root_of_leaves(&self.frames.as_slice(), size).unwrap(),
            previous_checkpoint_hash: previous,
            box_close_root: sorted_set_root(&closes).unwrap(),
            dispute_root: sorted_set_root(&disputes).unwrap(),
            genesis_hash: world().pin,
            time_bucket: TimeBucket::new(150),
        })
        .unwrap();
        let body = object(SCHEMA_CHECKPOINT_BODY, SCHEMA_VERSION_1, &body);
        self.last = Some((seq, object_hash(body)));
        let entries: Vec<WitnessSignatureEntry<'static>> = SIGNERS
            .iter()
            .map(|&i| WitnessSignatureEntry {
                witness_id: id(WITNESS_IDS[i]),
                signature: hybrid_signature(witness_signing(i), b"checkpoint", body),
            })
            .collect();
        let signed = SignedCheckpointParts::new(body, leak_slice(entries)).unwrap();
        self.push(
            SCHEMA_SIGNED_CHECKPOINT,
            object(SCHEMA_SIGNED_CHECKPOINT, SCHEMA_VERSION_1, &signed),
        );
    }

    fn report(&self, publications: Publications) -> Report<'static> {
        verify_ledger(
            world().genesis,
            self.ledger.bytes(),
            &self.ledger.events,
            publications,
        )
    }
}

const ANCHORED: Publications = Publications {
    anchors: Publication::Satisfied,
    board: Publication::Pending,
};

#[test]
fn nothing_anchored_is_unverified() {
    let mut book = Book::new();
    book.push(SCHEMA_WITNESSED_EVENT, opened());
    book.checkpoint();
    let report = book.report(Publications {
        anchors: Publication::Pending,
        board: Publication::Pending,
    });
    assert_eq!(report.status().status(), Status::Unverified);
    assert!(report.status().holds().is_empty());
}

#[test]
fn an_open_box_under_an_anchored_checkpoint_is_log_consistent() {
    let mut book = Book::new();
    book.push(SCHEMA_WITNESSED_EVENT, opened());
    book.checkpoint();
    let report = book.report(ANCHORED);
    assert!(report.index().findings().is_empty());
    assert!(report.checkpoints().findings().is_empty());
    assert_eq!(report.status().status(), Status::LogConsistent);
    assert!(!report.boxes().complete());
    assert!(!report.status().count_only());
    assert_eq!(report.disputes().unresolved().count(), 0);
    // A second checkpoint right after the first covers the first's frame.
    book.checkpoint();
    let report = book.report(ANCHORED);
    assert!(report.checkpoints().findings().is_empty());
    assert_eq!(report.checkpoints().checkpoints().len(), 2);
    assert_eq!(report.status().status(), Status::LogConsistent);
}

#[test]
fn a_hold_of_a_box_reaches_the_status() {
    // A close without the device signature: the box is held (ManualClose)
    // and nothing else is wrong.
    let mut book = Book::new();
    book.push(SCHEMA_WITNESSED_EVENT, opened());
    book.progress();
    book.push(SCHEMA_BOX_CLOSE, close_with(false));
    book.checkpoint();
    let report = book.report(ANCHORED);
    assert!(report.boxes().complete());
    assert_eq!(report.status().status(), Status::HoldReview);
    assert_eq!(
        report.status().holds(),
        ityv_state::HoldSet::empty().with(HoldReason::ManualClose)
    );
}

#[test]
fn every_box_closed_is_source_completeness_checked() {
    let mut book = Book::new();
    book.push(SCHEMA_WITNESSED_EVENT, opened());
    book.progress();
    book.push(SCHEMA_BOX_CLOSE, close());
    book.checkpoint();
    let report = book.report(ANCHORED);
    assert!(
        report.status().holds().is_empty(),
        "{:?}",
        report.status().holds()
    );
    assert_eq!(report.status().status(), Status::SourceCompletenessChecked);
}

#[test]
fn frames_no_checkpoint_covers_keep_the_ledger_unverified() {
    let mut book = Book::new();
    book.push(SCHEMA_WITNESSED_EVENT, opened());
    book.checkpoint();
    book.progress();
    book.push(SCHEMA_BOX_CLOSE, close());
    let report = book.report(ANCHORED);
    assert_eq!(report.status().status(), Status::Unverified);
    // And with no checkpoint at all.
    let mut book = Book::new();
    book.push(SCHEMA_WITNESSED_EVENT, opened());
    assert_eq!(book.report(ANCHORED).status().status(), Status::Unverified);
}

#[test]
fn a_hold_anywhere_is_hold_review() {
    // An open dispute.
    let mut book = Book::new();
    book.push(SCHEMA_WITNESSED_EVENT, opened());
    let f = filing();
    book.push(SCHEMA_WITNESSED_EVENT, f);
    let w: WitnessedEvent<'static> =
        ityv_encoding::decode_object(SCHEMA_WITNESSED_EVENT, SCHEMA_VERSION_1, f).unwrap();
    book.disputes.push(object_hash(w.body_bytes()));
    book.checkpoint();
    let report = book.report(ANCHORED);
    assert!(report.checkpoints().findings().is_empty());
    assert_eq!(report.disputes().unresolved().count(), 1);
    assert_eq!(report.status().status(), Status::HoldReview);
    assert!(report.status().holds().contains(HoldReason::OpenDispute));

    // A board published late.
    let mut book = Book::new();
    book.push(SCHEMA_WITNESSED_EVENT, opened());
    book.checkpoint();
    let report = book.report(Publications {
        anchors: Publication::Satisfied,
        board: Publication::Breached(Breach::BoardLate {
            published: TimeBucket::new(300),
            deadline: TimeBucket::new(200),
        }),
    });
    assert_eq!(report.status().status(), Status::HoldReview);
    assert!(
        report
            .status()
            .holds()
            .contains(HoldReason::PublicationLate)
    );

    // A checkpoint whose roots the ledger does not give.
    let mut book = Book::new();
    book.push(SCHEMA_WITNESSED_EVENT, opened());
    book.closes.push(Hash512([0x77; 64]));
    book.checkpoint();
    let report = book.report(ANCHORED);
    assert_eq!(report.status().status(), Status::HoldReview);
    assert!(
        report
            .status()
            .holds()
            .contains(HoldReason::CheckpointInvalid)
    );
    assert!(report.status().holds().contains(HoldReason::StepFailed));

    // No authorization on the ledger.
    let mut book = Book {
        ledger: Ledger::new(),
        frames: Vec::new(),
        closes: Vec::new(),
        disputes: Vec::new(),
        last: None,
    };
    book.push(SCHEMA_SIGNED_GENESIS, world().signed);
    book.push(SCHEMA_WITNESSED_EVENT, opened());
    book.checkpoint();
    let report = book.report(ANCHORED);
    assert_eq!(report.status().status(), Status::HoldReview);
    assert!(
        report
            .status()
            .holds()
            .contains(HoldReason::AuthorizationMissing)
    );
    // Without BALLOT_MARK only counts back a result.
    assert!(report.status().count_only());
}

#[test]
fn a_dispute_event_that_cannot_be_taken_holds_the_ledger() {
    // A filing both authorities signed, dated after the authorization's
    // last day: no PUBLIC_BOARD for it, so it is refused, and held.
    let mut book = Book::new();
    book.push(SCHEMA_WITNESSED_EVENT, opened());
    let late = filing_at(96 * 200);
    book.push(SCHEMA_WITNESSED_EVENT, late);
    book.checkpoint();
    let report = book.report(ANCHORED);
    assert_eq!(report.disputes().unresolved().count(), 0);
    assert_eq!(report.disputes().refused(), [Seq::new(4).unwrap()]);
    assert_eq!(report.status().status(), Status::HoldReview);
    assert!(report.status().holds().contains(HoldReason::DisputeRefused));
}

#[test]
fn holds_of_the_record_stage_and_the_index_reach_the_status() {
    // A close whose record set root is not the root of the box's records.
    let mut book = Book::new();
    book.push(SCHEMA_WITNESSED_EVENT, opened());
    book.progress();
    book.push(SCHEMA_BOX_CLOSE, close_of(true, Hash512([0x01; 64])));
    book.checkpoint();
    let report = book.report(ANCHORED);
    assert!(
        report
            .records()
            .holds()
            .contains(HoldReason::RecordSetMismatch)
    );
    assert_eq!(report.status().status(), Status::HoldReview);
    assert!(
        report
            .status()
            .holds()
            .contains(HoldReason::RecordSetMismatch)
    );
    // An election event recorded twice: the index holds the whole ledger.
    let mut book = Book::new();
    book.push(SCHEMA_SIGNED_GENESIS, world().signed);
    book.push(SCHEMA_WITNESSED_EVENT, opened());
    book.checkpoint();
    let report = book.report(ANCHORED);
    assert!(
        report
            .index()
            .ledger_holds()
            .contains(HoldReason::EventReplayed)
    );
    assert_eq!(report.status().status(), Status::HoldReview);
    assert!(report.status().holds().contains(HoldReason::EventReplayed));
    assert!(report.status().holds().contains(HoldReason::StepFailed));
}

#[test]
fn a_box_closed_without_its_progress_record_is_held() {
    // VC-102: the device's last tick is compared with its close; with no
    // tick at all the box (and its station) is held.
    let mut book = Book::new();
    book.push(SCHEMA_WITNESSED_EVENT, opened());
    book.push(SCHEMA_BOX_CLOSE, close());
    book.checkpoint();
    let report = book.report(ANCHORED);
    assert!(report.boxes().complete());
    assert!(report.boxes().reports()[0].holds.is_empty());
    assert!(
        report
            .progress()
            .holds()
            .contains(HoldReason::ProgressStream)
    );
    assert_eq!(report.status().status(), Status::HoldReview);
    assert_eq!(report.status().holds(), report.progress().holds());
}
