//! The tally stage (PROTOCOL.md §10.6, §11, §14 7; VC-024, VC-042..044,
//! VC-057, VC-063, VC-075, VC-099): receipt resolutions, legal tally
//! effects, tally scopes against the recomputation, aggregate openings
//! against the sum of real commitments, paper counts per reporting unit,
//! and the report reaching `CRYPTO_TALLY_VERIFIED`. Every record carries a
//! real OR proof over commitments made from known secrets, every opening
//! opens their real sum, and every signature is a real hybrid signature
//! under a key the genesis registers.
// Integration tests: outside the TCB. Assertions use unwrap/expect, so these
// lints are relaxed for this file only (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::similar_names,
    clippy::struct_field_names,
    clippy::type_complexity
)]

mod common;

use std::sync::OnceLock;
use std::vec::Vec;

use common::{
    BOX_DEVICE_BASE, COMMISSION, COMMITTEE, Draft, Ledger, ROSTER_BASE, SIGNERS, WITNESS_IDS,
    hybrid_signature, id, leak, leak_slice, module_signing, modules, object, sign,
    sign_genesis_with, signing, trustee_signing, unit_signing, witness_signing,
};
use ityv_crypto::{
    Bases, CastId, ChunkIndex, Commitment, MAX_CHUNKS, Opening, OptionCount, OptionIndex,
    RecordPurpose, Scalar, Sha3Hasher, Statement, commit, object_hash, packed_value, prove,
    sign_ed25519_half,
};
use ityv_encoding::{
    ActorSig, AggregateOpeningBody, AggregateOpeningParts, Attestation, BallotStyleEntry,
    BallotStyleId, BatchAttest, BatchAttestBody, BatchAttestParts, BoxClose, BoxCloseBody,
    BoxCloseParts, BoxId, BoxOpenedBody, BoxOpenedParts, BoxProgressBody, BoxProgressParts,
    BoxProgressState, CaptureProfile, CastRecord, CastRecordBody, CastRecordParts, ChamberCode,
    CheckinProgressBody, CheckinProgressParts, CheckinProgressState, CheckpointBody,
    CheckpointParts, CloseCounts, Commitments, Day, DisputeAction, DisputeEventBody,
    DisputeEventParts, DisputeType, Encode, EventRole, EventSig, ExclusionEntry, ExclusionReason,
    Exclusions, Hash512, Ident, IssuanceCountBody, IssuanceCountParts, KEM_EK_LEN, KeysetId,
    LedgerId, LegalDecisionRefBody, LegalDecisionRefParts, LegalOutcome, ModuleBatchSig,
    ModuleCounter, ModuleCounters, ModuleId, ModuleIds, ModuleProvisioned,
    ModuleProvisionedMessage, ModuleProvisionedParts, ModuleRange, ModuleRecordSig,
    ObserverCountAttestBody, ObserverCountKind, ObserverCountParts, OrgId, PaperCountParts,
    PaperCountReportBody, PaperVotes, ParticipationMessage, ParticipationModuleSig,
    ParticipationSet, PartyKeyCeremony, PartyKeyMessage, PartyKeyParts, Point32, ProgressTick,
    Pseudonyms, QuorumSig, QuorumSigned, ReceiptEntries, ReceiptEntry, ReceiptOutcome,
    ReceiptResolutionBody, ReceiptResolutionParts, ReportingUnitEntry, ReportingUnitId, RosterRole,
    SCHEMA_AGGREGATE_OPENING_BODY, SCHEMA_BATCH_ATTEST, SCHEMA_BATCH_ATTEST_BODY, SCHEMA_BOX_CLOSE,
    SCHEMA_BOX_CLOSE_BODY, SCHEMA_BOX_OPENED_BODY, SCHEMA_BOX_PROGRESS_BODY, SCHEMA_CAST_RECORD,
    SCHEMA_CAST_RECORD_BODY, SCHEMA_CHECKIN_PROGRESS_BODY, SCHEMA_CHECKPOINT_BODY,
    SCHEMA_DISPUTE_EVENT_BODY, SCHEMA_ISSUANCE_COUNT_BODY, SCHEMA_LEGAL_DECISION_REF_BODY,
    SCHEMA_MODULE_PROVISIONED, SCHEMA_OBSERVER_COUNT_ATTEST_BODY, SCHEMA_PAPER_COUNT_REPORT_BODY,
    SCHEMA_PARTICIPATION_SET, SCHEMA_PARTY_KEY_CEREMONY, SCHEMA_PROGRESS_TICK,
    SCHEMA_QUORUM_SIGNED, SCHEMA_RECEIPT_RESOLUTION_BODY, SCHEMA_SIGNED_GENESIS,
    SCHEMA_SIGNED_LEGAL_AUTHORIZATION, SCHEMA_TALLY_SCOPE_BODY, SCHEMA_VERSION_1,
    SCHEMA_WITNESSED_EVENT, Scalar32, SchemaId, Scope, Seq, ShareHolder, SignerId, SignerRole,
    StationId, StationKind, TallyEffect, TallyScopeBody, TallyScopeParts, TimeBucket, Token192,
    TreeSize, TrusteeId, UnitId, WitnessedEvent, Writer, purpose_of,
};
use ityv_encoding::{
    ChallengeOpening, ChallengeOpeningBody, ChallengeOpeningParts, LateBatchCloseBody,
    LateBatchCloseParts, LateBatchReason, MAX_QUORUM_MESSAGE_LEN, ModuleOpening,
    SCHEMA_CHALLENGE_OPENING, SCHEMA_CHALLENGE_OPENING_BODY, SCHEMA_LATE_BATCH_CLOSE_BODY, Scalars,
    write_quorum_message,
};
use ityv_ledger::{
    SCHEMA_SIGNED_CHECKPOINT, SignedCheckpointParts, WitnessSignatureEntry, root_of_leaves,
    sorted_set_root,
};
use ityv_state::{HoldReason, HoldSet, Publication, Status};
use ityv_verify::{
    ExpectedExclusion, LedgerIndex, OpeningOutcome, Publications, ScopeProblem, TallyEvent,
    TallyRefusal, TallyRefused, TallyStage, UnitTally, VerifiedGenesis, authorize_ledger,
    build_index, verify_boxes, verify_checkpoints, verify_disputes, verify_genesis, verify_ledger,
    verify_records, verify_tally,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};

const OPEN_BUCKET: u64 = 100;
const CLOSE_BUCKET: u64 = 140;
/// The first bucket a tally scope may carry: more than 96 after the last
/// close.
const READY: u64 = CLOSE_BUCKET + 97;
const SEAL: Hash512 = Hash512([0x5e; 64]);
const CHAIR_KEY: u16 = ROSTER_BASE + 30;
const COURT_KEY: u16 = ROSTER_BASE + 5;
const RU1: &[u8] = b"RU-1";
const RU2: &[u8] = b"RU-2";
const STYLE1: &[u8] = b"STYLE-1";
const STYLE2: &[u8] = b"STYLE-2";

// ---------------------------------------------------------------------
// The worlds.

/// A genesis and its signed objects.
struct World {
    genesis: &'static VerifiedGenesis<'static>,
    pin: Hash512,
    signed: &'static [u8],
    authorization: &'static [u8],
}

/// The standard genesis without BOX-2, BOX-3 out of district, a test
/// style `TEST-1` and a district commission chair on the roster.
fn draft() -> Draft {
    let mut d = Draft::standard();
    d.boxes.retain(|b| b.box_id.as_bytes() != b"BOX-2");
    for b in &mut d.boxes {
        if b.box_id.as_bytes() == b"BOX-3" {
            b.profile = CaptureProfile::Absentee;
        }
    }
    d.stations[0] = common::station(
        b"ST-1",
        StationKind::ElectionDay,
        common::checkin_unit(0, b"U-1A", &[b"M-U1A-P1", b"M-U1A-P2"]),
        common::checkin_unit(1, b"U-1B", &[b"M-U1B-P1", b"M-U1B-P2"]),
        &[b"BOX-1"],
        &[
            common::token(b"obs-a", b"PARTY-A", 0xC1),
            common::token(b"obs-b", b"PARTY-B", 0xC2),
        ],
    );
    d.units[0] = ReportingUnitEntry::new(
        ReportingUnitId::new(RU1).unwrap(),
        1,
        ityv_encoding::OrgId::new(b"NEC-D").unwrap(),
    )
    .unwrap();
    d.modules
        .retain(|m| !m.module_id.as_bytes().starts_with(b"M-B2"));
    d.styles.push(
        BallotStyleEntry::new(
            BallotStyleId::new(b"TEST-1").unwrap(),
            5,
            Hash512([0x53; 64]),
        )
        .unwrap(),
    );
    d.roster.push(common::roster_signer(
        30,
        b"chair",
        RosterRole::Chair,
        b"NEC-D",
        None,
    ));
    // The chair of a district commission no unit names.
    d.roster.push(common::roster_signer(
        31,
        b"chair-x",
        RosterRole::Chair,
        b"NEC-X",
        None,
    ));
    d.appointments = d.referenced_appointments();
    d
}

fn build(draft: &Draft, scopes: &[Scope]) -> World {
    let (body, authorization) = common::legal_authorization(scopes, 20_000, 20_100);
    let built = leak(sign_genesis_with(draft, draft.raw(), &SIGNERS, |p| {
        p.legal_authorization_hash = object_hash(body);
    }));
    let genesis = leak(verify_genesis(&built.pin, &built.input(), &[]).unwrap());
    World {
        genesis,
        pin: built.pin,
        signed: built.signed,
        authorization,
    }
}

const TALLY_SCOPES: [Scope; 4] = [
    Scope::PublicBoard,
    Scope::TrusteeBody,
    Scope::BallotMark,
    Scope::CryptoTallyAid,
];

fn world() -> &'static World {
    static WORLD: OnceLock<&'static World> = OnceLock::new();
    WORLD.get_or_init(|| leak(build(&draft(), &TALLY_SCOPES)))
}

/// As [`world`], without `CRYPTO_TALLY_AID`.
fn world_without_aid() -> &'static World {
    static WORLD: OnceLock<&'static World> = OnceLock::new();
    WORLD.get_or_init(|| {
        leak(build(
            &draft(),
            &[Scope::PublicBoard, Scope::TrusteeBody, Scope::BallotMark],
        ))
    })
}

// ---------------------------------------------------------------------
// Boxes, records, batches, closes.

/// A box of the world: its device and modules (with key numbers).
#[derive(Clone, Copy)]
struct Bx {
    id: &'static [u8],
    device: u16,
    style: &'static [u8],
    options: u16,
    /// (module, key number), ascending by module.
    mods: &'static [(&'static [u8], u16)],
    absentee: bool,
}

const B1: Bx = Bx {
    id: b"BOX-1",
    device: BOX_DEVICE_BASE,
    style: STYLE1,
    options: 7,
    mods: &[(b"M-B1-P1", 0), (b"M-B1-P2", 1)],
    absentee: false,
};

const B3: Bx = Bx {
    id: b"BOX-3",
    device: BOX_DEVICE_BASE + 2,
    style: STYLE2,
    options: 11,
    mods: &[(b"M-B3-A", 7), (b"M-B3-P1", 5), (b"M-B3-P2", 6)],
    absentee: true,
};

const PEOPLE: [(&[u8], EventRole, &[u8], u16); 4] = [
    (b"clerk-1", EventRole::Clerk, b"ORG-ST", ROSTER_BASE),
    (b"clerk-2", EventRole::Clerk, b"ORG-ST", ROSTER_BASE + 1),
    (b"obs-a", EventRole::Observer, b"PARTY-A", ROSTER_BASE + 2),
    (b"obs-b", EventRole::Observer, b"PARTY-B", ROSTER_BASE + 3),
];

/// A `WitnessedEvent` over `body` signed by `who` (identifier, role,
/// organisation, key number), sorted here.
fn witnessed(
    body: &'static [u8],
    who: &[(&'static [u8], EventRole, &'static [u8], u16)],
) -> &'static [u8] {
    let schema = ityv_encoding::ObjectHeader::read(&mut ityv_encoding::Reader::new(body))
        .unwrap()
        .schema_id();
    let purpose = purpose_of(schema).unwrap();
    let mut who = who.to_vec();
    who.sort_by(|a, b| a.0.cmp(b.0));
    let sigs: Vec<EventSig<'static>> = who
        .iter()
        .map(|&(signer, role, o, n)| EventSig {
            signer_id: SignerId::new(signer).unwrap(),
            role,
            org_id: OrgId::new(o).unwrap(),
            sig: sign(signing(n), purpose, body),
        })
        .collect();
    object(
        SCHEMA_WITNESSED_EVENT,
        ityv_encoding::SCHEMA_VERSION_WITNESSED,
        &WitnessedEvent::new(body, &sigs).unwrap(),
    )
}

fn opened(bx: Bx) -> &'static [u8] {
    let names: Vec<&'static [u8]> = bx.mods.iter().map(|m| m.0).collect();
    let body = BoxOpenedBody::new(&BoxOpenedParts {
        election_id: common::election(),
        box_id: BoxId::new(bx.id).unwrap(),
        modules: modules(&names),
        seal_digest: SEAL,
        seals_match: true,
        initial_count: 0,
        time_bucket: TimeBucket::new(OPEN_BUCKET),
    });
    let body = object(SCHEMA_BOX_OPENED_BODY, SCHEMA_VERSION_1, &body);
    let mut who = PEOPLE.to_vec();
    who.push((bx.id, EventRole::Device, b"ORG-ST", bx.device));
    witnessed(body, &who)
}

/// A cast record and the secrets it was made from.
#[derive(Clone, Copy)]
struct Cast {
    event: &'static [u8],
    code: Hash512,
    option: u16,
    cast_id: CastId,
    rand: [Scalar; MAX_CHUNKS],
    /// Each module's cast-id contribution and randomness, in module order.
    parts: &'static [([u8; 24], [Scalar; MAX_CHUNKS])],
    counter: u64,
    style: &'static [u8],
    chunks: u8,
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

/// Record `counter` of `bx` for `option`, of the box's style.
fn cast(bx: Bx, counter: u64, option: u16) -> Cast {
    cast_styled(bx, counter, option, bx.style, bx.options)
}

/// Record `counter` of `bx` for `option`, naming ballot style `style` of
/// `options` options. Its secrets come from a stream seeded by the box and
/// counter (PROTOCOL.md §7.3).
fn cast_styled(bx: Bx, counter: u64, option: u16, style: &'static [u8], options: u16) -> Cast {
    let bases = Bases::derive();
    let mut rng = ChaCha20Rng::seed_from_u64((u64::from(bx.device) << 16) | counter);
    let options = OptionCount::new(options).unwrap();
    let chunks = options.chunk_count();
    let mut hasher = Sha3Hasher::new();
    hasher.absorb(b"ityv:castid:v1");
    hasher.absorb(&[0x00]);
    let mut rand = [Scalar::ZERO; MAX_CHUNKS];
    let mut parts: Vec<([u8; 24], [Scalar; MAX_CHUNKS])> = Vec::new();
    for _ in bx.mods {
        let mut cid = [0u8; 24];
        rng.fill_bytes(&mut cid);
        hasher.absorb(&cid);
        let mut part = [Scalar::ZERO; MAX_CHUNKS];
        for (sum, p) in rand
            .iter_mut()
            .zip(part.iter_mut())
            .take(usize::from(chunks))
        {
            *p = Scalar::random(&mut rng);
            *sum = sum.add(p);
        }
        parts.push((cid, part));
    }
    let digest = hasher.finish();
    let cast_id = CastId::new(Token192(digest[..24].try_into().unwrap()));
    let index = OptionIndex::new(option).unwrap();
    let commitments: Vec<Commitment> = (0..chunks)
        .map(|j| {
            commit(
                &bases,
                index,
                &cast_id,
                &rand[usize::from(j)],
                ChunkIndex::new(j).unwrap(),
            )
        })
        .collect();
    let statement = Statement::new(
        common::election(),
        Ident::new(bx.id, 64).unwrap(),
        Ident::new(style, 64).unwrap(),
        options,
        &commitments,
    )
    .unwrap();
    let proof = prove(
        &bases,
        &statement,
        &Opening::new(index, cast_id, rand),
        &mut rng,
    )
    .unwrap();
    let mut buf = std::vec![0u8; proof.encoded_len()];
    let mut w = Writer::new(&mut buf);
    proof.encode(&mut w).unwrap();
    let points: Vec<Point32> = commitments.iter().map(|c| c.to_point32()).collect();
    let counters: Vec<ModuleCounter<'static>> = bx
        .mods
        .iter()
        .map(|&(m, _)| ModuleCounter {
            module_id: common::module(m),
            counter,
        })
        .collect();
    let body = CastRecordBody::new(&CastRecordParts {
        election_id: common::election(),
        box_id: BoxId::new(bx.id).unwrap(),
        ballot_style_id: BallotStyleId::new(style).unwrap(),
        proof_system_id: 1,
        commitments: Commitments::new(&points).unwrap(),
        proof: leak_slice(buf),
        module_counters: ModuleCounters::new(&counters).unwrap(),
        share_package_hash: Hash512([6; 64]),
        transport_flags: 0,
    })
    .unwrap();
    let body = object(SCHEMA_CAST_RECORD_BODY, SCHEMA_VERSION_1, &body);
    let body_hash = object_hash(body);
    let device = leak(
        *sign_ed25519_half(signing(bx.device), RecordPurpose::CastRecord, body)
            .unwrap()
            .as_bytes(),
    );
    let sigs: Vec<ModuleRecordSig<'static>> = bx
        .mods
        .iter()
        .map(|&(m, key)| ModuleRecordSig {
            module_id: common::module(m),
            ed25519: leak(
                *sign_ed25519_half(
                    module_signing(key),
                    RecordPurpose::ModuleRecord,
                    &module_message(&body_hash, m, counter),
                )
                .unwrap()
                .as_bytes(),
            ),
        })
        .collect();
    let event = object(
        SCHEMA_CAST_RECORD,
        SCHEMA_VERSION_1,
        &CastRecord::new(body, device, &sigs).unwrap(),
    );
    Cast {
        event,
        code: body_hash,
        option,
        cast_id,
        rand,
        parts: leak_slice(parts),
        counter,
        style,
        chunks,
    }
}

/// The device's challenge opening of `c` in `bx` (PROTOCOL.md §8), which
/// reconstructs the record.
fn challenge(bx: Bx, c: &Cast) -> &'static [u8] {
    let chunks = usize::from(c.chunks);
    let raw = |values: &[Scalar]| -> Scalars<MAX_CHUNKS> {
        let out: Vec<Scalar32> = values.iter().map(|v| Scalar32(v.to_bytes())).collect();
        Scalars::new(&out).unwrap()
    };
    let mods: Vec<ModuleOpening<'static>> = bx
        .mods
        .iter()
        .zip(c.parts)
        .map(|(&(m, _), (cid, part))| ModuleOpening {
            module_id: common::module(m),
            counter: c.counter,
            rand: raw(&part[..chunks]),
            cid: Token192(*cid),
        })
        .collect();
    let body = ChallengeOpeningBody::new(&ChallengeOpeningParts {
        election_id: common::election(),
        box_id: BoxId::new(bx.id).unwrap(),
        ballot_style_id: BallotStyleId::new(c.style).unwrap(),
        record_hash: c.code,
        option_index: c.option,
        cast_id: c.cast_id.token(),
        rand: leak(raw(&c.rand[..chunks])),
        modules: leak_slice(mods),
    })
    .unwrap();
    let body = object(SCHEMA_CHALLENGE_OPENING_BODY, SCHEMA_VERSION_1, &body);
    object(
        SCHEMA_CHALLENGE_OPENING,
        SCHEMA_VERSION_1,
        &ChallengeOpening::new(body, sign(signing(bx.device), b"challenge", body)).unwrap(),
    )
}

/// The sorted-set root of `codes`.
fn root(codes: &[Hash512]) -> Hash512 {
    let mut codes = codes.to_vec();
    codes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    sorted_set_root(&codes).unwrap()
}

fn sorted(codes: &[Hash512]) -> Vec<Hash512> {
    let mut codes = codes.to_vec();
    codes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    codes
}

/// The batch `index` of `bx` over counters `first..=last` of every module,
/// attesting `members`.
fn batch(bx: Bx, index: u32, first: u64, last: u64, members: &[Hash512]) -> &'static [u8] {
    batch_at(bx, index, first, last, members, 120)
}

/// As [`batch`], in time bucket `bucket`.
fn batch_at(
    bx: Bx,
    index: u32,
    first: u64,
    last: u64,
    members: &[Hash512],
    bucket: u64,
) -> &'static [u8] {
    let ranges = leak_slice(
        bx.mods
            .iter()
            .map(|&(m, _)| ModuleRange {
                module_id: common::module(m),
                counter_first: first,
                counter_last: last,
            })
            .collect(),
    );
    let body = BatchAttestBody::new(&BatchAttestParts {
        election_id: common::election(),
        box_id: BoxId::new(bx.id).unwrap(),
        batch_index: index,
        record_count: u16::try_from(members.len()).unwrap(),
        records_root: root(members),
        module_ranges: ranges,
        module_refusals: ModuleIds::EMPTY,
        journal_head: Hash512([0x22; 64]),
        time_bucket: TimeBucket::new(bucket),
    })
    .unwrap();
    let body = object(SCHEMA_BATCH_ATTEST_BODY, SCHEMA_VERSION_1, &body);
    let sigs: Vec<ModuleBatchSig<'static>> = bx
        .mods
        .iter()
        .map(|&(m, key)| ModuleBatchSig {
            module_id: common::module(m),
            sig: sign(module_signing(key), b"batch-attest", body),
        })
        .collect();
    object(
        SCHEMA_BATCH_ATTEST,
        SCHEMA_VERSION_1,
        &BatchAttest::new(body, &sigs, sign(signing(bx.device), b"batch-attest", body)).unwrap(),
    )
}

/// A device-signed close of `bx` with `records` records (counters up to
/// `records`), `attested` of them attested, `without` ballots without a
/// record, and the record set `codes`.
fn close(bx: Bx, records: u64, attested: u64, without: u64, codes: &[Hash512]) -> &'static [u8] {
    close_as(bx, (records, attested, without), codes, Some(b"box-close"))
}

/// As [`close`]: `device` names the purpose the device and the people sign
/// under (`box-close`, `late-box-close`), `None` for a manual close.
fn close_as(
    bx: Bx,
    (records, attested, without): (u64, u64, u64),
    codes: &[Hash512],
    device: Option<&[u8]>,
) -> &'static [u8] {
    let counts = CloseCounts {
        paper: if bx.absentee { 0 } else { records + without },
        records,
        attested,
        without_record: without,
        challenged: 0,
        quarantined: 0,
        visits: records,
        envelopes: if bx.absentee { records } else { 0 },
        stickers: if bx.absentee { records } else { 0 },
        spoil_envelopes: 0,
    };
    close_full(bx, counts, records, codes, device)
}

/// A close of `bx` with `counts`, every module's final counter `last`.
fn close_full(
    bx: Bx,
    counts: CloseCounts,
    last: u64,
    codes: &[Hash512],
    device: Option<&[u8]>,
) -> &'static [u8] {
    let purpose = device.unwrap_or(b"box-close");
    let (records, attested) = (counts.records, counts.attested);
    let counters: Vec<ModuleCounter<'static>> = bx
        .mods
        .iter()
        .map(|&(m, _)| ModuleCounter {
            module_id: common::module(m),
            counter: last,
        })
        .collect();
    let body = BoxCloseBody::new(&BoxCloseParts {
        election_id: common::election(),
        box_id: BoxId::new(bx.id).unwrap(),
        counts,
        record_set_root: root(codes),
        journal_head: Hash512([0x24; 64]),
        seal_digest: SEAL,
        module_counters: ModuleCounters::new(&counters).unwrap(),
        open_batches: u8::from(attested < records),
        time_bucket: TimeBucket::new(CLOSE_BUCKET),
    });
    let body = object(SCHEMA_BOX_CLOSE_BODY, SCHEMA_VERSION_1, &body);
    let attestations: Vec<Attestation<'static>> = PEOPLE
        .iter()
        .map(|&(who, role, o, n)| Attestation {
            signer_id: SignerId::new(who).unwrap(),
            role: if role == EventRole::Clerk {
                SignerRole::Clerk
            } else {
                SignerRole::Observer
            },
            org_id: OrgId::new(o).unwrap(),
            sig: sign(signing(n), purpose, body),
        })
        .collect();
    object(
        SCHEMA_BOX_CLOSE,
        SCHEMA_VERSION_1,
        &BoxClose::new(
            body,
            device.map(|p| sign(signing(bx.device), p, body)),
            &attestations,
        )
        .unwrap(),
    )
}

// ---------------------------------------------------------------------
// Tally events.

/// The qualified quorum: P1, P2 and three of J, A, C, N (ascending).
const QUORUM: [(&[u8], u16); 5] = [
    (b"T-A", 5),
    (b"T-C", 6),
    (b"T-J", 4),
    (b"T-P1-1", 0),
    (b"T-P2-1", 2),
];

/// `body` signed by the trustees `who` (identifier, key number,
/// ascending) under `purpose`.
fn quorum(body: &'static [u8], purpose: &[u8], who: &[(&'static [u8], u16)]) -> &'static [u8] {
    quorum_seeded(body, purpose, who, None)
}

/// The quorum message of `body` signed by `who` (ENCODING.md §8.63).
fn quorum_message(body: &[u8], who: &[(&'static [u8], u16)]) -> &'static [u8] {
    let ids: Vec<TrusteeId<'static>> = who
        .iter()
        .map(|(t, _)| TrusteeId::new(t).unwrap())
        .collect();
    let mut out = std::vec![0u8; MAX_QUORUM_MESSAGE_LEN];
    let mut w = Writer::new(&mut out);
    write_quorum_message(&object_hash(body), &ids, &mut w).unwrap();
    let n = w.finish();
    out.truncate(n);
    leak_slice(out)
}

/// As [`quorum`], with signing randomness drawn from `seed` when given:
/// the same body and trustees under other signature bytes.
fn quorum_seeded(
    body: &'static [u8],
    purpose: &[u8],
    who: &[(&'static [u8], u16)],
    seed: Option<u64>,
) -> &'static [u8] {
    let message = quorum_message(body, who);
    let sigs: Vec<QuorumSig<'static>> = who
        .iter()
        .map(|&(t, n)| QuorumSig {
            trustee_id: TrusteeId::new(t).unwrap(),
            sig: match seed {
                Some(seed) => common::sign_seeded(trustee_signing(n), purpose, message, seed),
                None => sign(trustee_signing(n), purpose, message),
            },
        })
        .collect();
    object(
        SCHEMA_QUORUM_SIGNED,
        SCHEMA_VERSION_1,
        &QuorumSigned::new(body, &sigs).unwrap(),
    )
}

/// What a tally scope says.
#[derive(Clone)]
struct ScopeSpec {
    style: &'static [u8],
    unit: &'static [u8],
    included: Vec<Hash512>,
    exclusions: Vec<ExclusionEntry>,
    no_record: u64,
    bucket: u64,
    count: Option<u64>,
    root: Option<Hash512>,
}

fn spec(style: &'static [u8], unit: &'static [u8], included: &[Hash512]) -> ScopeSpec {
    ScopeSpec {
        style,
        unit,
        included: included.to_vec(),
        exclusions: Vec::new(),
        no_record: 0,
        bucket: READY,
        count: None,
        root: None,
    }
}

fn exclusion(record: Hash512, reason: ExclusionReason, basis: Hash512) -> ExclusionEntry {
    ExclusionEntry {
        record_hash: record,
        reason,
        basis,
    }
}

/// The tally scope body object of `s`.
fn scope_body(s: &ScopeSpec) -> &'static [u8] {
    let mut list = s.exclusions.clone();
    list.sort_by(|a, b| a.record_hash.as_bytes().cmp(b.record_hash.as_bytes()));
    let mut bytes = std::vec![0u8; list.len() * 129];
    let mut w = Writer::new(&mut bytes);
    for e in &list {
        e.encode(&mut w).unwrap();
    }
    let body = TallyScopeBody::new(&TallyScopeParts {
        election_id: common::election(),
        ballot_style_id: BallotStyleId::new(s.style).unwrap(),
        reporting_unit_id: ReportingUnitId::new(s.unit).unwrap(),
        included_count: s.count.unwrap_or(s.included.len() as u64),
        included_root: s.root.unwrap_or_else(|| root(&s.included)),
        no_record_count: s.no_record,
        exclusions: Exclusions::new(leak_slice(bytes)).unwrap(),
        time_bucket: TimeBucket::new(s.bucket),
    })
    .unwrap();
    object(SCHEMA_TALLY_SCOPE_BODY, SCHEMA_VERSION_1, &body)
}

fn scope(body: &'static [u8]) -> &'static [u8] {
    quorum(body, b"tally-scope", &QUORUM)
}

/// `T_j`, `R_j` and `S` of `casts` for chunk `chunk`.
fn sums(casts: &[Cast], chunk: u8) -> (Scalar, Scalar, Scalar) {
    let j = ChunkIndex::new(chunk).unwrap();
    casts.iter().fold(
        (Scalar::ZERO, Scalar::ZERO, Scalar::ZERO),
        |(t, r, s), c| {
            (
                t.add(&packed_value(OptionIndex::new(c.option).unwrap(), j)),
                r.add(&c.rand[usize::from(chunk)]),
                s.add(&c.cast_id.to_scalar()),
            )
        },
    )
}

/// The aggregate opening body of chunk `chunk` of the scope `scope`, with
/// the sums `(t, r, s)`.
fn opening_body(
    style: &'static [u8],
    unit: &'static [u8],
    scope: &'static [u8],
    chunk: u8,
    sums: (Scalar, Scalar, Scalar),
) -> &'static [u8] {
    opening_at(style, unit, scope, chunk, sums, READY + 2)
}

/// As [`opening_body`], recorded in time bucket `bucket`.
fn opening_at(
    style: &'static [u8],
    unit: &'static [u8],
    scope: &'static [u8],
    chunk: u8,
    (t, r, s): (Scalar, Scalar, Scalar),
    bucket: u64,
) -> &'static [u8] {
    let body = AggregateOpeningBody::new(&AggregateOpeningParts {
        election_id: common::election(),
        ballot_style_id: BallotStyleId::new(style).unwrap(),
        reporting_unit_id: ReportingUnitId::new(unit).unwrap(),
        scope_hash: object_hash(scope),
        chunk,
        packed_sum: Scalar32(t.to_bytes()),
        rand_sum: Scalar32(r.to_bytes()),
        id_sum: Scalar32(s.to_bytes()),
        time_bucket: TimeBucket::new(bucket),
    })
    .unwrap();
    object(SCHEMA_AGGREGATE_OPENING_BODY, SCHEMA_VERSION_1, &body)
}

fn opening(body: &'static [u8]) -> &'static [u8] {
    quorum(body, b"aggregate-opening", &QUORUM)
}

/// The chair and observers of two organisations.
const PAPER_SIGNERS: [(&[u8], EventRole, &[u8], u16); 3] = [
    (b"chair", EventRole::Chair, b"NEC-D", CHAIR_KEY),
    (b"obs-a", EventRole::Observer, b"PARTY-A", ROSTER_BASE + 2),
    (b"obs-b", EventRole::Observer, b"PARTY-B", ROSTER_BASE + 3),
];

/// The paper count of `style` in `unit`.
fn paper_by(
    style: &'static [u8],
    unit: &'static [u8],
    votes: &[u64],
    invalid: u64,
    who: &[(&'static [u8], EventRole, &'static [u8], u16)],
) -> &'static [u8] {
    let body = PaperCountReportBody::new(&PaperCountParts {
        election_id: common::election(),
        reporting_unit_id: ReportingUnitId::new(unit).unwrap(),
        ballot_style_id: BallotStyleId::new(style).unwrap(),
        votes: PaperVotes::new(votes).unwrap(),
        invalid,
        time_bucket: TimeBucket::new(READY + 3),
    })
    .unwrap();
    witnessed(
        object(SCHEMA_PAPER_COUNT_REPORT_BODY, SCHEMA_VERSION_1, &body),
        who,
    )
}

fn paper(style: &'static [u8], unit: &'static [u8], votes: &[u64], invalid: u64) -> &'static [u8] {
    paper_by(style, unit, votes, invalid, &PAPER_SIGNERS)
}

/// The receipt resolution of `bx`, one outcome per record, signed by the
/// quorum.
fn resolution(bx: Bx, outcomes: &[(Hash512, ReceiptOutcome)], bucket: u64) -> &'static [u8] {
    let mut list = outcomes.to_vec();
    list.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let mut bytes = std::vec![0u8; list.len() * 65];
    let mut w = Writer::new(&mut bytes);
    for (record_hash, outcome) in &list {
        ReceiptEntry {
            record_hash: *record_hash,
            outcome: *outcome,
        }
        .encode(&mut w)
        .unwrap();
    }
    let body = ReceiptResolutionBody::new(&ReceiptResolutionParts {
        election_id: common::election(),
        box_id: BoxId::new(bx.id).unwrap(),
        entries: ReceiptEntries::new(leak_slice(bytes)).unwrap(),
        time_bucket: TimeBucket::new(bucket),
    });
    quorum(
        object(SCHEMA_RECEIPT_RESOLUTION_BODY, SCHEMA_VERSION_1, &body),
        b"receipt-resolution",
        &QUORUM,
    )
}

/// A dispute filing of `kind` naming `record` of `bx`, with evidence
/// `evidence`: the filing body's hash and the event.
fn filing(kind: DisputeType, bx: Bx, record: Hash512, evidence: u8) -> (Hash512, &'static [u8]) {
    let body = DisputeEventBody::new(&DisputeEventParts {
        election_id: common::election(),
        action: DisputeAction::Filed,
        dispute_type: kind,
        box_id: Some(BoxId::new(bx.id).unwrap()),
        record_hash: Some(record),
        evidence_hash: Hash512([evidence; 64]),
        filing_hash: Hash512::ZERO,
        result_hash: Hash512::ZERO,
        time_bucket: TimeBucket::new(CLOSE_BUCKET + 10),
    })
    .unwrap();
    let body = object(SCHEMA_DISPUTE_EVENT_BODY, SCHEMA_VERSION_1, &body);
    let event = witnessed(
        body,
        &[
            (b"commission", EventRole::Commission, b"NEC", COMMISSION),
            (b"committee", EventRole::Committee, b"IVC", COMMITTEE),
        ],
    );
    (object_hash(body), event)
}

/// The court's decision on the dispute `dispute` with `effect`.
fn decision(dispute: Hash512, effect: TallyEffect) -> &'static [u8] {
    let body = LegalDecisionRefBody::new(&LegalDecisionRefParts {
        election_id: common::election(),
        authority_id: OrgId::new(b"COURT").unwrap(),
        decision_doc_hash: Hash512([0x5D; 64]),
        dispute_hash: dispute,
        outcome: LegalOutcome::Upheld,
        tally_effect: effect,
        decided_day: Day::new(20_001),
    })
    .unwrap();
    witnessed(
        object(SCHEMA_LEGAL_DECISION_REF_BODY, SCHEMA_VERSION_1, &body),
        &[(b"court", EventRole::Authority, b"COURT", COURT_KEY)],
    )
}

// ---------------------------------------------------------------------
// The ledger, with checkpoints over it.

struct Book {
    world: &'static World,
    ledger: Ledger,
    frames: Vec<Hash512>,
    closes: Vec<Hash512>,
    /// The filings of the disputes still open.
    disputes: Vec<Hash512>,
    last: Option<(u64, Hash512)>,
}

impl Book {
    fn new(world: &'static World) -> Self {
        let mut book = Self {
            world,
            ledger: Ledger::new(),
            frames: Vec::new(),
            closes: Vec::new(),
            disputes: Vec::new(),
            last: None,
        };
        book.push(SCHEMA_SIGNED_GENESIS, world.signed);
        book.push(SCHEMA_SIGNED_LEGAL_AUTHORIZATION, world.authorization);
        book
    }

    fn push(&mut self, schema: SchemaId, event: &'static [u8]) -> u64 {
        self.ledger.push(schema, event);
        let stream = self.ledger.bytes();
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
        self.frames.len() as u64
    }

    fn w(&mut self, event: &'static [u8]) -> u64 {
        self.push(SCHEMA_WITNESSED_EVENT, event)
    }

    fn q(&mut self, event: &'static [u8]) -> u64 {
        self.push(SCHEMA_QUORUM_SIGNED, event)
    }

    /// A checkpoint over every frame so far, after the last one, in the
    /// first bucket after the late-close window.
    fn checkpoint(&mut self) -> u64 {
        self.checkpoint_at(READY + 1)
    }

    /// A checkpoint over every frame so far, the witnesses' time
    /// `bucket`.
    fn checkpoint_at(&mut self, bucket: u64) -> u64 {
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
            genesis_hash: self.world.pin,
            time_bucket: TimeBucket::new(bucket),
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
        )
    }

    fn run(&self) -> TallyStage<'static> {
        let g = self.world.genesis;
        let index: &'static LedgerIndex<'static> =
            leak(build_index(g, self.ledger.bytes(), &self.ledger.events));
        assert!(index.ledger_holds().is_empty(), "{:?}", index.findings());
        let authority = leak(authorize_ledger(g, index));
        let checkpoints = leak(verify_checkpoints(g, index, authority));
        assert!(
            checkpoints.findings().is_empty(),
            "{:?}",
            checkpoints.findings()
        );
        let boxes = leak(verify_boxes(g, index, authority));
        let records = leak(verify_records(g, index, boxes));
        let disputes = leak(verify_disputes(g, index, authority));
        verify_tally(g, index, authority, checkpoints, boxes, records, disputes)
    }
}

/// BOX-1 opened with records for options 1, 2 and 3 in one batch, closed,
/// and a checkpoint after the late-close window: the witnesses' time from
/// which a tally scope may be taken.
fn box1(book: &mut Book) -> Vec<Cast> {
    let casts = box1_closed(book);
    book.checkpoint();
    casts
}

/// As [`box1`], without the checkpoint.
fn box1_closed(book: &mut Book) -> Vec<Cast> {
    let casts = std::vec![cast(B1, 1, 1), cast(B1, 2, 2), cast(B1, 3, 3)];
    book.w(opened(B1));
    for c in &casts {
        book.push(SCHEMA_CAST_RECORD, c.event);
    }
    let codes: Vec<Hash512> = casts.iter().map(|c| c.code).collect();
    book.push(SCHEMA_BATCH_ATTEST, batch(B1, 0, 1, 3, &codes));
    book.push(SCHEMA_BOX_CLOSE, close(B1, 3, 3, 0, &codes));
    casts
}

fn codes(casts: &[Cast]) -> Vec<Hash512> {
    casts.iter().map(|c| c.code).collect()
}

/// The scope of unit 1, a checkpoint, the opening of its one chunk and
/// its paper count: frames of the scope and the opening.
fn tally1(
    book: &mut Book,
    casts: &[Cast],
    s: &ScopeSpec,
    votes: &[u64],
    invalid: u64,
) -> (u64, u64) {
    let body = scope_body(s);
    let at = book.q(scope(body));
    book.checkpoint();
    let opened_at = book.q(opening(opening_body(STYLE1, RU1, body, 0, sums(casts, 0))));
    book.w(paper(STYLE1, RU1, votes, invalid));
    (at, opened_at)
}

fn unit1(stage: &TallyStage<'static>) -> UnitTally<'static> {
    stage.unit(STYLE1, RU1).unwrap().clone()
}

fn refused(stage: &TallyStage<'_>) -> Vec<(u64, TallyEvent, TallyRefusal)> {
    stage
        .refused()
        .iter()
        .map(|r: &TallyRefused| (r.seq.get(), r.event, r.refusal))
        .collect()
}

fn only(reason: HoldReason) -> HoldSet {
    HoldSet::empty().with(reason)
}

// ---------------------------------------------------------------------
// A clean unit.

#[test]
fn a_clean_unit_is_tallied_and_agrees_with_its_paper() {
    let mut book = Book::new(world());
    let casts = box1(&mut book);
    let (at, opened_at) = tally1(
        &mut book,
        &casts,
        &spec(STYLE1, RU1, &codes(&casts)),
        &[1, 1, 1, 0, 0],
        0,
    );
    let stage = book.run();
    assert!(stage.refused().is_empty(), "{:?}", stage.refused());
    let u = unit1(&stage);
    assert_eq!(u.included, sorted(&codes(&casts)));
    assert_eq!(u.included_root, Some(root(&codes(&casts))));
    assert!(u.exclusions.is_empty());
    assert_eq!(u.scope, Some(Seq::new(at).unwrap()));
    assert!(u.scope_problems.is_empty(), "{:?}", u.scope_problems);
    assert_eq!(u.chunks, 1);
    assert_eq!(u.openings.len(), 1);
    assert_eq!(u.openings[0].seq.get(), opened_at);
    assert_eq!(u.openings[0].outcome, OpeningOutcome::Verified);
    // BLANK, five candidates, UNREADABLE.
    assert_eq!(u.counts, Some(std::vec![0, 1, 1, 1, 0, 0, 0]));
    assert_eq!(u.paper.map(Seq::get), Some(opened_at + 1));
    assert!(u.comparison.unwrap().agrees());
    assert_eq!(u.holds, HoldSet::empty());
    assert!(u.complete());
    assert!(u.passed());
    // The out-of-district unit has nothing yet: incomplete, not held.
    let u2 = stage.unit(STYLE2, RU2).unwrap();
    assert!(!u2.complete());
    assert!(!u2.passed());
    assert_eq!(u2.chunks, 2);
    assert_eq!(stage.holds(), HoldSet::empty());
    assert!(!stage.complete());
    assert!(!stage.passed());
    assert_eq!(stage.units().len(), 2);
    assert!(stage.unit(STYLE1, RU2).is_none());
}

#[test]
fn the_index_scopes_the_tally_events_to_the_election() {
    let mut book = Book::new(world());
    let casts = box1(&mut book);
    tally1(
        &mut book,
        &casts,
        &spec(STYLE1, RU1, &codes(&casts)),
        &[1, 1, 1, 0, 0],
        0,
    );
    book.q(resolution(B3, &[], READY));
    let g = world().genesis;
    let index = build_index(g, book.ledger.bytes(), &book.ledger.events);
    assert!(index.findings().is_empty(), "{:?}", index.findings());
    let election: Vec<SchemaId> = index
        .events()
        .iter()
        .filter(|e| e.scope == ityv_verify::Scope::Election)
        .map(|e| e.schema)
        .collect();
    let quorum = election
        .iter()
        .filter(|s| **s == SCHEMA_QUORUM_SIGNED)
        .count();
    assert_eq!(quorum, 3);
    assert!(election.contains(&SCHEMA_WITNESSED_EVENT));
}

// ---------------------------------------------------------------------
// The scope.

#[test]
fn a_scope_with_a_wrong_count_root_or_no_record_count_is_a_mismatch() {
    let casts_codes = |book: &mut Book| codes(&box1(book));
    let cases: [(fn(&mut ScopeSpec), &[ScopeProblem]); 3] = [
        (|s| s.count = Some(2), &[ScopeProblem::IncludedCount]),
        (
            |s| s.root = Some(Hash512([0x77; 64])),
            &[ScopeProblem::IncludedRoot],
        ),
        (|s| s.no_record = 1, &[ScopeProblem::NoRecordCount]),
    ];
    for (change, problems) in cases {
        let mut book = Book::new(world());
        let c = casts_codes(&mut book);
        let mut s = spec(STYLE1, RU1, &c);
        change(&mut s);
        book.q(scope(scope_body(&s)));
        let stage = book.run();
        let u = unit1(&stage);
        assert_eq!(u.scope_problems, problems);
        assert_eq!(u.holds, only(HoldReason::TallyScopeMismatch));
        assert!(!u.passed());
        assert!(stage.holds().contains(HoldReason::TallyScopeMismatch));
    }
    // A record left out of the included set.
    let mut book = Book::new(world());
    let c = casts_codes(&mut book);
    book.q(scope(scope_body(&spec(STYLE1, RU1, &c[..2]))));
    let u = unit1(&book.run());
    assert_eq!(
        u.scope_problems,
        [ScopeProblem::IncludedCount, ScopeProblem::IncludedRoot]
    );
}

/// BOX-1 with a cast record (option 1) attested, a test ballot and a cast
/// record (option 0, BLANK) in no batch, and one ballot without a record:
/// the test ballot is `TEST_BALLOT` (first of §11.1, though also
/// unattested), the other `UNATTESTED`.
fn mixed(book: &mut Book) -> (Cast, Cast, Cast, Hash512) {
    let kept = cast(B1, 1, 1);
    let test = cast_styled(B1, 2, 4, b"TEST-1", 7);
    let late = cast(B1, 3, 0);
    book.w(opened(B1));
    for c in [kept, test, late] {
        book.push(SCHEMA_CAST_RECORD, c.event);
    }
    book.push(SCHEMA_BATCH_ATTEST, batch(B1, 0, 1, 1, &[kept.code]));
    let closed = close(B1, 3, 1, 1, &[kept.code, test.code, late.code]);
    book.push(SCHEMA_BOX_CLOSE, closed);
    book.checkpoint();
    (kept, test, late, object_hash(closed))
}

#[test]
fn an_exclusion_cites_the_first_reason_and_its_basis() {
    let mut book = Book::new(world());
    let (kept, test, late, closed) = mixed(&mut book);
    let mut s = spec(STYLE1, RU1, &[kept.code]);
    s.no_record = 1;
    s.exclusions = std::vec![
        exclusion(
            test.code,
            ExclusionReason::TestBallot,
            object_hash(test.event)
        ),
        exclusion(late.code, ExclusionReason::Unattested, closed),
    ];
    let good = s.clone();
    tally1(&mut book, &[kept], &s, &[2, 0, 0, 0, 0], 2);
    let stage = book.run();
    let u = unit1(&stage);
    assert!(u.scope_problems.is_empty(), "{:?}", u.scope_problems);
    let mut expected = std::vec![
        ExpectedExclusion {
            record_hash: test.code,
            reason: ExclusionReason::TestBallot,
            basis: Some(object_hash(test.event)),
        },
        ExpectedExclusion {
            record_hash: late.code,
            reason: ExclusionReason::Unattested,
            basis: Some(closed),
        },
    ];
    expected.sort_by(|a, b| a.record_hash.as_bytes().cmp(b.record_hash.as_bytes()));
    assert_eq!(u.exclusions, expected);
    assert_eq!(u.no_record_count, 1);
    // Both excluded ballots are in the box: the paper counts them.
    assert_eq!(u.excluded_with_paper, 2);
    // Paper: candidate 1 twice (the emergency ballot), the blank and test
    // ballots invalid: 2 + 2 = D + B + U + F + X = 1 + 0 + 0 + 1 + 2.
    assert_eq!(u.counts, Some(std::vec![0, 1, 0, 0, 0, 0, 0]));
    assert!(u.comparison.unwrap().agrees(), "{:?}", u.comparison);
    assert!(u.passed(), "{u:?}");

    // A later reason of §11.1 for the test ballot, a basis that is not
    // the event, a record missing, a record the verifier includes.
    let cases: [(
        fn(&mut ScopeSpec, Cast, Cast, Cast),
        fn(Cast, Cast, Cast) -> ScopeProblem,
    ); 4] = [
        (
            |s, _, _, _| s.exclusions[0].reason = ExclusionReason::Unattested,
            |_, test, _| ScopeProblem::Reason(test.code),
        ),
        (
            |s, _, _, late| s.exclusions[1].basis = object_hash(late.event),
            |_, _, late| ScopeProblem::Basis(late.code),
        ),
        (
            |s, _, _, _| {
                s.exclusions.remove(1);
            },
            |_, _, late| ScopeProblem::Missing(late.code),
        ),
        (
            |s, kept, _, _| {
                s.exclusions.push(exclusion(
                    kept.code,
                    ExclusionReason::Unattested,
                    Hash512([1; 64]),
                ));
            },
            |kept, _, _| ScopeProblem::Unexpected(kept.code),
        ),
    ];
    for (change, problem) in cases {
        let mut book = Book::new(world());
        let (kept, test, late, _) = mixed(&mut book);
        let mut s = good.clone();
        change(&mut s, kept, test, late);
        book.q(scope(scope_body(&s)));
        let u = unit1(&book.run());
        assert_eq!(u.scope_problems, [problem(kept, test, late)]);
        assert_eq!(u.holds, only(HoldReason::TallyScopeMismatch));
    }
}

#[test]
fn a_challenged_record_cites_its_challenge_opening() {
    let mut book = Book::new(world());
    let kept = cast(B1, 1, 1);
    let opened_one = cast(B1, 2, 3);
    book.w(opened(B1));
    book.push(SCHEMA_CAST_RECORD, kept.event);
    book.push(SCHEMA_CAST_RECORD, opened_one.event);
    let shown = challenge(B1, &opened_one);
    book.push(SCHEMA_CHALLENGE_OPENING, shown);
    book.push(SCHEMA_BATCH_ATTEST, batch(B1, 0, 1, 1, &[kept.code]));
    let counts = CloseCounts {
        paper: 1,
        records: 1,
        attested: 1,
        without_record: 0,
        challenged: 1,
        quarantined: 0,
        visits: 1,
        envelopes: 0,
        stickers: 0,
        spoil_envelopes: 1,
    };
    book.push(
        SCHEMA_BOX_CLOSE,
        close_full(B1, counts, 2, &[kept.code], Some(b"box-close")),
    );
    book.checkpoint();
    let mut s = spec(STYLE1, RU1, &[kept.code]);
    s.exclusions = std::vec![exclusion(
        opened_one.code,
        ExclusionReason::ChallengedSpoiled,
        object_hash(shown)
    )];
    tally1(&mut book, &[kept], &s, &[1, 0, 0, 0, 0], 0);
    let stage = book.run();
    let u = unit1(&stage);
    assert_eq!(
        u.exclusions,
        [ExpectedExclusion {
            record_hash: opened_one.code,
            reason: ExclusionReason::ChallengedSpoiled,
            basis: Some(object_hash(shown)),
        }]
    );
    // The spoiled ballot is not in the box: nothing to count on paper.
    assert_eq!(u.excluded_with_paper, 0);
    assert!(u.passed(), "{u:?}");
}

#[test]
fn a_scope_before_its_time_is_refused() {
    // BOX-1 still open.
    let mut book = Book::new(world());
    book.w(opened(B1));
    let early = book.q(scope(scope_body(&spec(STYLE1, RU1, &[]))));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [(early, TallyEvent::Scope, TallyRefusal::Premature)]
    );
    assert_eq!(unit1(&stage).scope, None);
    assert_eq!(unit1(&stage).holds, only(HoldReason::TallyScopeRefused));
    assert_eq!(stage.holds(), only(HoldReason::TallyScopeRefused));

    // The witnesses' time is past the window, but the box's close is in a
    // later frame than the scope.
    let mut book = Book::new(world());
    book.w(opened(B1));
    let c = cast(B1, 1, 1);
    book.push(SCHEMA_CAST_RECORD, c.event);
    book.push(SCHEMA_BATCH_ATTEST, batch(B1, 0, 1, 1, &[c.code]));
    book.checkpoint();
    let before_close = book.q(scope(scope_body(&spec(STYLE1, RU1, &[c.code]))));
    book.push(SCHEMA_BOX_CLOSE, close(B1, 1, 1, 0, &[c.code]));
    assert_eq!(
        refused(&book.run()),
        [(before_close, TallyEvent::Scope, TallyRefusal::Premature)]
    );

    // Within the late-close window by the witnesses' time, though the
    // trustees date the scope after it; then after it: the second is
    // taken.
    let mut book = Book::new(world());
    let casts = box1_closed(&mut book);
    book.checkpoint_at(CLOSE_BUCKET + 96);
    let mut s = spec(STYLE1, RU1, &codes(&casts));
    s.bucket = READY + 50;
    let early = book.q(scope(scope_body(&s)));
    book.checkpoint();
    let (at, _) = tally1(
        &mut book,
        &casts,
        &spec(STYLE1, RU1, &codes(&casts)),
        &[1, 1, 1, 0, 0],
        0,
    );
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [(early, TallyEvent::Scope, TallyRefusal::Premature)]
    );
    let u = unit1(&stage);
    assert_eq!(u.scope.map(Seq::get), Some(at));
    assert!(u.counts.is_some());
    assert_eq!(u.holds, only(HoldReason::TallyScopeRefused));
    assert!(!u.passed());
    assert!(!stage.passed());

    // A second scope after one was taken: the same body under other
    // signature bytes, and another body (a conflict, never silently
    // "already has one").
    let mut book = Book::new(world());
    let casts = box1(&mut book);
    let s = spec(STYLE1, RU1, &codes(&casts));
    let body = scope_body(&s);
    book.q(scope(body));
    let again = book.q(quorum_seeded(body, b"tally-scope", &QUORUM, Some(9)));
    let other = book.q(scope(scope_body(&ScopeSpec {
        bucket: READY + 5,
        ..s
    })));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [
            (again, TallyEvent::Scope, TallyRefusal::Repeated),
            (other, TallyEvent::Scope, TallyRefusal::Conflict),
        ]
    );
    assert_eq!(unit1(&stage).holds, only(HoldReason::TallyScopeRefused));
}

#[test]
fn a_scope_of_no_unit_of_the_genesis_is_refused() {
    let mut book = Book::new(world());
    box1(&mut book);
    let other = book.q(scope(scope_body(&spec(STYLE1, RU2, &[]))));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [(other, TallyEvent::Scope, TallyRefusal::Subject)]
    );
    // Held, though no unit names it.
    assert_eq!(stage.holds(), only(HoldReason::TallyScopeRefused));
    assert_eq!(unit1(&stage).holds, HoldSet::empty());
}

/// The late batch close naming the batch `batch_event` (PROTOCOL.md
/// §7.2.1), signed by the clerks and observers.
fn late_batch_close(batch_event: &'static [u8], bucket: u64) -> &'static [u8] {
    let b: BatchAttest<'static> =
        ityv_encoding::decode_object(SCHEMA_BATCH_ATTEST, SCHEMA_VERSION_1, batch_event).unwrap();
    let body = LateBatchCloseBody::new(&LateBatchCloseParts {
        election_id: common::election(),
        box_id: BoxId::new(b"BOX-1").unwrap(),
        batch_body_hash: object_hash(b.body_bytes()),
        reason: LateBatchReason::DeviceRestart,
        time_bucket: TimeBucket::new(bucket),
    })
    .unwrap();
    witnessed(
        object(SCHEMA_LATE_BATCH_CLOSE_BODY, SCHEMA_VERSION_1, &body),
        &PEOPLE,
    )
}

#[test]
fn a_late_close_after_a_scope_of_its_style_is_refused() {
    let mut book = Book::new(world());
    let (kept, test, late, closed) = mixed(&mut book);
    let mut s = spec(STYLE1, RU1, &[kept.code]);
    s.no_record = 1;
    s.exclusions = std::vec![
        exclusion(
            test.code,
            ExclusionReason::TestBallot,
            object_hash(test.event)
        ),
        exclusion(late.code, ExclusionReason::Unattested, closed),
    ];
    // Before the scope a late batch close would still attest (within
    // the window it declares); after it, the scope has fixed UNATTESTED.
    let at = book.q(scope(scope_body(&s)));
    let late_batch = batch_at(B1, 1, 2, 3, &[test.code, late.code], CLOSE_BUCKET + 5);
    book.push(SCHEMA_BATCH_ATTEST, late_batch);
    let late_close = book.w(late_batch_close(late_batch, CLOSE_BUCKET + 5));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [(late_close, TallyEvent::LateClose, TallyRefusal::AfterScope)]
    );
    let u = unit1(&stage);
    assert_eq!(u.scope.map(Seq::get), Some(at));
    assert!(u.holds.contains(HoldReason::LateCloseAfterScope));
    assert!(stage.holds().contains(HoldReason::LateCloseAfterScope));
    // The record stage took the late batch: the scope no longer agrees.
    assert!(u.holds.contains(HoldReason::TallyScopeMismatch));
    // A scope of another style does not refuse BOX-1's late closes.
    let mut book = Book::new(world());
    mixed(&mut book);
    box3(&mut book, &[1]);
    let late_batch = batch_at(B1, 1, 2, 3, &[test.code, late.code], CLOSE_BUCKET + 5);
    book.q(scope(scope_body(&spec(STYLE2, RU2, &[]))));
    book.push(SCHEMA_BATCH_ATTEST, late_batch);
    book.w(late_batch_close(late_batch, CLOSE_BUCKET + 5));
    let stage = book.run();
    assert!(
        stage
            .refused()
            .iter()
            .all(|r| r.event != TallyEvent::LateClose),
        "{:?}",
        stage.refused()
    );

    // A late box close replacing a manual close, after the scope.
    let mut book = Book::new(world());
    let casts = std::vec![cast(B1, 1, 1)];
    book.w(opened(B1));
    book.push(SCHEMA_CAST_RECORD, casts[0].event);
    book.push(SCHEMA_BATCH_ATTEST, batch(B1, 0, 1, 1, &codes(&casts)));
    book.push(
        SCHEMA_BOX_CLOSE,
        close_as(B1, (1, 1, 0), &codes(&casts), None),
    );
    book.checkpoint();
    let at = book.q(scope(scope_body(&spec(STYLE1, RU1, &codes(&casts)))));
    let late_close = book.push(
        SCHEMA_BOX_CLOSE,
        close_as(B1, (1, 1, 0), &codes(&casts), Some(b"late-box-close")),
    );
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [(late_close, TallyEvent::LateClose, TallyRefusal::AfterScope)]
    );
    assert_eq!(unit1(&stage).scope.map(Seq::get), Some(at));
}

// ---------------------------------------------------------------------
// The quorum and the capability.

#[test]
fn a_forged_or_insufficient_quorum_is_refused() {
    let mut book = Book::new(world());
    let casts = box1(&mut book);
    let body = scope_body(&spec(STYLE1, RU1, &codes(&casts)));
    // Two of J, A, C, N.
    let short = book.q(quorum(
        body,
        b"tally-scope",
        &[(b"T-A", 5), (b"T-J", 4), (b"T-P1-1", 0), (b"T-P2-1", 2)],
    ));
    // No P2 member.
    let no_party = book.q(quorum(
        body,
        b"tally-scope",
        &[(b"T-A", 5), (b"T-C", 6), (b"T-J", 4), (b"T-P1-1", 0)],
    ));
    // T-C's signature by another key.
    let forged = book.q(quorum(
        body,
        b"tally-scope",
        &[
            (b"T-A", 5),
            (b"T-C", 7),
            (b"T-J", 4),
            (b"T-P1-1", 0),
            (b"T-P2-1", 2),
        ],
    ));
    // A signer who is not a trustee.
    let stranger = book.q(quorum(
        body,
        b"tally-scope",
        &[
            (b"T-A", 5),
            (b"T-C", 6),
            (b"T-J", 4),
            (b"T-P1-1", 0),
            (b"T-P2-1", 2),
            (b"T-X", 7),
        ],
    ));
    // The opening's purpose on a scope.
    let purpose = book.q(quorum(body, b"aggregate-opening", &QUORUM));
    let taken = book.q(scope(body));
    book.checkpoint();
    let obody = opening_body(STYLE1, RU1, body, 0, sums(&casts, 0));
    let weak = book.q(quorum(
        obody,
        b"aggregate-opening",
        &[(b"T-A", 5), (b"T-P1-1", 0), (b"T-P2-1", 2)],
    ));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [
            (short, TallyEvent::Scope, TallyRefusal::Signature),
            (no_party, TallyEvent::Scope, TallyRefusal::Signature),
            (forged, TallyEvent::Scope, TallyRefusal::Signature),
            (stranger, TallyEvent::Scope, TallyRefusal::Signature),
            (purpose, TallyEvent::Scope, TallyRefusal::Signature),
            (weak, TallyEvent::Opening, TallyRefusal::Signature),
        ]
    );
    let u = unit1(&stage);
    assert_eq!(u.scope.map(Seq::get), Some(taken));
    assert!(u.openings.is_empty());
    assert_eq!(
        stage.holds(),
        HoldSet::empty()
            .with(HoldReason::TallyScopeRefused)
            .with(HoldReason::AggregateRefused)
    );
}

#[test]
fn a_tally_without_crypto_tally_aid_is_refused() {
    let mut book = Book::new(world_without_aid());
    let casts = box1(&mut book);
    let body = scope_body(&spec(STYLE1, RU1, &codes(&casts)));
    let at = book.q(scope(body));
    book.checkpoint();
    let opened_at = book.q(opening(opening_body(STYLE1, RU1, body, 0, sums(&casts, 0))));
    let receipt = book.q(resolution(B3, &[], READY));
    assert_eq!(
        refused(&book.run()),
        [
            (at, TallyEvent::Scope, TallyRefusal::Capability),
            (opened_at, TallyEvent::Opening, TallyRefusal::Capability),
            (receipt, TallyEvent::Receipt, TallyRefusal::Capability),
        ]
    );
}

// ---------------------------------------------------------------------
// The opening.

#[test]
fn an_opening_before_a_checkpoint_covers_its_scope_is_refused() {
    let mut book = Book::new(world());
    let casts = box1(&mut book);
    let body = scope_body(&spec(STYLE1, RU1, &codes(&casts)));
    // A checkpoint that does not reach the scope's frame.
    book.checkpoint();
    book.q(scope(body));
    let sums0 = sums(&casts, 0);
    let early = book.q(opening(opening_at(STYLE1, RU1, body, 0, sums0, READY + 2)));
    book.checkpoint();
    let taken_body = opening_at(STYLE1, RU1, body, 0, sums0, READY + 3);
    let taken = book.q(opening(taken_body));
    let again = book.q(quorum_seeded(
        taken_body,
        b"aggregate-opening",
        &QUORUM,
        Some(9),
    ));
    let other = book.q(opening(opening_at(STYLE1, RU1, body, 0, sums0, READY + 4)));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [
            (early, TallyEvent::Opening, TallyRefusal::Premature),
            (again, TallyEvent::Opening, TallyRefusal::Repeated),
            (other, TallyEvent::Opening, TallyRefusal::Conflict),
        ]
    );
    let u = unit1(&stage);
    assert_eq!(u.openings.len(), 1);
    assert_eq!(u.openings[0].seq.get(), taken);
    assert_eq!(u.holds, only(HoldReason::AggregateRefused));
}

#[test]
fn an_opening_must_name_the_scope_taken_and_a_chunk_of_the_style() {
    let mut book = Book::new(world());
    let casts = box1(&mut book);
    let s = spec(STYLE1, RU1, &codes(&casts));
    let body = scope_body(&s);
    let sums0 = sums(&casts, 0);
    // Before its scope (premature: no checkpoint before it can cover a
    // later frame), for a scope not taken, for chunk 1 of a one-chunk
    // style, for a unit of no box.
    let none = book.q(opening(opening_body(STYLE1, RU1, body, 0, sums0)));
    book.q(scope(body));
    book.checkpoint();
    let other = scope_body(&ScopeSpec {
        bucket: READY + 9,
        ..s
    });
    let wrong = book.q(opening(opening_body(STYLE1, RU1, other, 0, sums0)));
    let chunk = book.q(opening(opening_body(STYLE1, RU1, body, 1, sums0)));
    let unit = book.q(opening(opening_body(STYLE1, RU2, body, 0, sums0)));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [
            (none, TallyEvent::Opening, TallyRefusal::Premature),
            (wrong, TallyEvent::Opening, TallyRefusal::NoScope),
            (chunk, TallyEvent::Opening, TallyRefusal::Subject),
            (unit, TallyEvent::Opening, TallyRefusal::Subject),
        ]
    );
    assert!(unit1(&stage).openings.is_empty());
}

#[test]
fn an_opening_with_a_wrong_sum_does_not_open() {
    let one = Scalar::from_u64(1);
    let cases: [fn((Scalar, Scalar, Scalar), Scalar) -> (Scalar, Scalar, Scalar); 3] = [
        |(t, r, s), one| (t.add(&one), r, s),
        |(t, r, s), one| (t, r.add(&one), s),
        |(t, r, s), one| (t, r, s.add(&one)),
    ];
    for change in cases {
        let mut book = Book::new(world());
        let casts = box1(&mut book);
        let body = scope_body(&spec(STYLE1, RU1, &codes(&casts)));
        book.q(scope(body));
        book.checkpoint();
        book.q(opening(opening_body(
            STYLE1,
            RU1,
            body,
            0,
            change(sums(&casts, 0), one),
        )));
        book.w(paper(STYLE1, RU1, &[1, 1, 1, 0, 0], 0));
        let stage = book.run();
        assert!(stage.refused().is_empty(), "{:?}", stage.refused());
        let u = unit1(&stage);
        assert_eq!(u.openings[0].outcome, OpeningOutcome::Equation);
        assert_eq!(u.counts, None);
        assert_eq!(u.comparison, None);
        assert_eq!(u.holds, only(HoldReason::AggregateMismatch));
        assert!(u.complete());
        assert!(!u.passed());
    }
    // The sums of only two of the three records.
    let mut book = Book::new(world());
    let casts = box1(&mut book);
    let body = scope_body(&spec(STYLE1, RU1, &codes(&casts)));
    book.q(scope(body));
    book.checkpoint();
    book.q(opening(opening_body(
        STYLE1,
        RU1,
        body,
        0,
        sums(&casts[..2], 0),
    )));
    let u = unit1(&book.run());
    assert_eq!(u.openings[0].outcome, OpeningOutcome::Equation);
}

#[test]
fn every_chunk_must_open_before_the_counts() {
    // Unit 2 has two chunks: BOX-3, all three records received.
    let mut book = Book::new(world());
    let casts = box3(&mut book, &[1, 9, 10]);
    let all = codes(&casts);
    book.q(resolution(
        B3,
        &all.iter()
            .map(|c| (*c, ReceiptOutcome::Received))
            .collect::<Vec<_>>(),
        CLOSE_BUCKET + 20,
    ));
    let body = scope_body(&spec(STYLE2, RU2, &all));
    book.q(scope(body));
    book.checkpoint();
    book.q(opening(opening_body(STYLE2, RU2, body, 1, sums(&casts, 1))));
    // The unreadable mark is invalid on paper.
    book.w(paper(STYLE2, RU2, &[1, 0, 0, 0, 0, 0, 0, 0, 1], 1));
    let stage = book.run();
    let u = stage.unit(STYLE2, RU2).unwrap();
    assert!(u.scope_problems.is_empty(), "{:?}", u.scope_problems);
    assert_eq!(u.openings.len(), 1);
    assert!(!u.complete());
    assert_eq!(u.counts, None);
    assert_eq!(u.holds, HoldSet::empty());
    // Chunk 0 then: options 0..=8, then 9 and 10 in chunk 1.
    book.q(opening(opening_body(STYLE2, RU2, body, 0, sums(&casts, 0))));
    let stage = book.run();
    let u = stage.unit(STYLE2, RU2).unwrap();
    assert_eq!(u.counts, Some(std::vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1]));
    assert!(u.comparison.unwrap().agrees());
    assert!(u.passed(), "{u:?}");
}

// ---------------------------------------------------------------------
// The paper count.

#[test]
fn paper_below_the_machine_or_with_other_totals_holds_the_unit() {
    let cases: [(&[u64], u64, Option<u16>, bool); 4] = [
        // Candidate 2 below the machine's one vote; totals still equal.
        (&[2, 0, 1, 0, 0], 0, Some(2), true),
        // One invalid ballot more than the machine accounts for.
        (&[1, 1, 1, 0, 0], 1, None, false),
        // A vote for candidate 5 the machine has not.
        (&[1, 1, 1, 0, 1], 0, None, false),
        // Both.
        (&[0, 1, 1, 0, 0], 0, Some(1), false),
    ];
    for (votes, invalid, below, totals) in cases {
        let mut book = Book::new(world());
        let casts = box1(&mut book);
        let body = scope_body(&spec(STYLE1, RU1, &codes(&casts)));
        book.q(scope(body));
        book.checkpoint();
        book.q(opening(opening_body(STYLE1, RU1, body, 0, sums(&casts, 0))));
        book.w(paper(STYLE1, RU1, votes, invalid));
        let u = unit1(&book.run());
        let c = u.comparison.unwrap();
        assert_eq!(c.first_below, below, "{votes:?}");
        assert_eq!(c.totals_agree, totals, "{votes:?}");
        assert_eq!(u.holds, only(HoldReason::PaperCountMismatch));
        assert!(!u.passed());
    }
}

#[test]
fn a_paper_count_must_be_signed_by_the_chair_and_name_the_style() {
    let mut book = Book::new(world());
    let casts = box1(&mut book);
    let body = scope_body(&spec(STYLE1, RU1, &codes(&casts)));
    book.q(scope(body));
    book.checkpoint();
    book.q(opening(opening_body(STYLE1, RU1, body, 0, sums(&casts, 0))));
    // The chair's signature by an observer's key; a clerk for the chair
    // (the envelope admits only the chair and observers, so the clerk
    // signs in the chair role); the chair of a commission the unit does
    // not name, filing first; four candidates; a unit of no box; a second,
    // different report after the one taken (a conflict).
    let forged = book.w(paper_by(
        STYLE1,
        RU1,
        &[1, 1, 1, 0, 0],
        0,
        &[
            (b"chair", EventRole::Chair, b"NEC-D", ROSTER_BASE + 2),
            PAPER_SIGNERS[1],
            PAPER_SIGNERS[2],
        ],
    ));
    let clerk = book.w(paper_by(
        STYLE1,
        RU1,
        &[1, 1, 1, 0, 0],
        0,
        &[
            (b"clerk-1", EventRole::Chair, b"ORG-ST", ROSTER_BASE),
            PAPER_SIGNERS[1],
            PAPER_SIGNERS[2],
        ],
    ));
    let elsewhere = book.w(paper_by(
        STYLE1,
        RU1,
        &[1, 1, 1, 0, 0],
        0,
        &[
            (b"chair-x", EventRole::Chair, b"NEC-X", ROSTER_BASE + 31),
            PAPER_SIGNERS[1],
            PAPER_SIGNERS[2],
        ],
    ));
    let short = book.w(paper(STYLE1, RU1, &[1, 1, 1, 0], 0));
    let nowhere = book.w(paper(STYLE1, RU2, &[1, 1, 1, 0, 0], 0));
    let taken = book.w(paper(STYLE1, RU1, &[1, 1, 1, 0, 0], 0));
    let again = book.w(paper(STYLE1, RU1, &[1, 1, 1, 0, 0], 1));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [
            (forged, TallyEvent::Paper, TallyRefusal::Signature),
            (clerk, TallyEvent::Paper, TallyRefusal::Signature),
            (elsewhere, TallyEvent::Paper, TallyRefusal::Signature),
            (short, TallyEvent::Paper, TallyRefusal::Subject),
            (nowhere, TallyEvent::Paper, TallyRefusal::Subject),
            (again, TallyEvent::Paper, TallyRefusal::Conflict),
        ]
    );
    let u = unit1(&stage);
    assert_eq!(u.paper.map(Seq::get), Some(taken));
    assert!(u.comparison.unwrap().agrees());
    assert_eq!(u.holds, only(HoldReason::PaperCountRefused));
}

// ---------------------------------------------------------------------
// Out-of-district records: receipts and the law.

/// BOX-3 opened with one record per option of `options`, all attested,
/// closed.
fn box3(book: &mut Book, options: &[u16]) -> Vec<Cast> {
    let casts: Vec<Cast> = options
        .iter()
        .enumerate()
        .map(|(i, o)| cast(B3, i as u64 + 1, *o))
        .collect();
    book.w(opened(B3));
    for c in &casts {
        book.push(SCHEMA_CAST_RECORD, c.event);
    }
    let all = codes(&casts);
    let n = all.len() as u64;
    book.push(SCHEMA_BATCH_ATTEST, batch(B3, 0, 1, n, &all));
    book.push(SCHEMA_BOX_CLOSE, close(B3, n, n, 0, &all));
    book.checkpoint();
    casts
}

#[test]
fn a_legal_exclude_decision_applies_to_a_damaged_record() {
    let mut book = Book::new(world());
    // Received (option 1), damaged (option 9), not received (option 10).
    let casts = box3(&mut book, &[1, 9, 10]);
    let (received, damaged, lost) = (casts[0], casts[1], casts[2]);
    let receipt = resolution(
        B3,
        &[
            (received.code, ReceiptOutcome::Received),
            (damaged.code, ReceiptOutcome::Damaged),
            (lost.code, ReceiptOutcome::NotReceived),
        ],
        CLOSE_BUCKET + 20,
    );
    book.q(receipt);
    let (filed, filed_event) = filing(DisputeType::Postal, B3, damaged.code, 1);
    book.w(filed_event);
    book.disputes.push(filed);
    let mut s = spec(STYLE2, RU2, &[received.code]);
    // Before the decision, the scope waits for the law (VC-099).
    let early = book.q(scope(scope_body(&s)));
    let decided = decision(filed, TallyEffect::Exclude);
    book.w(decided);
    s.exclusions = std::vec![
        exclusion(
            damaged.code,
            ExclusionReason::LegalExcluded,
            object_hash(decided)
        ),
        exclusion(
            lost.code,
            ExclusionReason::CastNotReceived,
            object_hash(receipt)
        ),
    ];
    s.bucket = READY + 4;
    let body = scope_body(&s);
    book.q(scope(body));
    book.checkpoint();
    for j in 0..2 {
        book.q(opening(opening_body(
            STYLE2,
            RU2,
            body,
            j,
            sums(&[received], j),
        )));
    }
    book.w(paper(STYLE2, RU2, &[1, 0, 0, 0, 0, 0, 0, 0, 0], 0));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [(early, TallyEvent::Scope, TallyRefusal::Premature)]
    );
    let u = stage.unit(STYLE2, RU2).unwrap();
    assert!(u.scope_problems.is_empty(), "{:?}", u.scope_problems);
    assert_eq!(u.included, [received.code]);
    assert_eq!(u.counts, Some(std::vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    // Neither excluded ballot is counted on paper.
    assert_eq!(u.excluded_with_paper, 0);
    assert!(u.comparison.unwrap().agrees());
    assert!(u.complete());
    // The premature scope holds the unit.
    assert_eq!(u.holds, only(HoldReason::TallyScopeRefused));
    assert_eq!(stage.holds(), only(HoldReason::TallyScopeRefused));
}

#[test]
fn a_legal_include_decision_counts_the_record() {
    let mut book = Book::new(world());
    let casts = box3(&mut book, &[1, 9]);
    let (received, wrong) = (casts[0], casts[1]);
    book.q(resolution(
        B3,
        &[
            (received.code, ReceiptOutcome::Received),
            (wrong.code, ReceiptOutcome::WrongDistrict),
        ],
        CLOSE_BUCKET + 20,
    ));
    let (filed, filed_event) = filing(DisputeType::Postal, B3, wrong.code, 1);
    book.w(filed_event);
    book.disputes.push(filed);
    book.w(decision(filed, TallyEffect::Include));
    let body = scope_body(&spec(STYLE2, RU2, &[received.code, wrong.code]));
    book.q(scope(body));
    book.checkpoint();
    for j in 0..2 {
        book.q(opening(opening_body(STYLE2, RU2, body, j, sums(&casts, j))));
    }
    book.w(paper(STYLE2, RU2, &[1, 0, 0, 0, 0, 0, 0, 0, 1], 0));
    let stage = book.run();
    assert!(stage.refused().is_empty(), "{:?}", stage.refused());
    let u = stage.unit(STYLE2, RU2).unwrap();
    assert!(u.passed(), "{u:?}");
    assert_eq!(u.counts.as_ref().unwrap()[9], 1);
}

#[test]
fn a_scope_waits_for_the_receipts_and_a_late_one_is_excluded() {
    let mut book = Book::new(world());
    let casts = box3(&mut book, &[1, 2]);
    let (on_time, late) = (casts[0], casts[1]);
    let mut s = spec(STYLE2, RU2, &[on_time.code]);
    let early = book.q(scope(scope_body(&s)));
    let receipt = resolution(
        B3,
        &[
            (on_time.code, ReceiptOutcome::Received),
            (late.code, ReceiptOutcome::Late),
        ],
        READY,
    );
    book.q(receipt);
    s.exclusions = std::vec![exclusion(
        late.code,
        ExclusionReason::ReceivedLate,
        object_hash(receipt)
    )];
    s.bucket = READY + 1;
    book.q(scope(scope_body(&s)));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [(early, TallyEvent::Scope, TallyRefusal::Premature)]
    );
    let u = stage.unit(STYLE2, RU2).unwrap();
    assert!(u.scope.is_some());
    assert!(u.scope_problems.is_empty(), "{:?}", u.scope_problems);
}

#[test]
fn a_receipt_resolution_must_resolve_exactly_a_closed_out_of_district_box() {
    let mut book = Book::new(world());
    book.w(opened(B3));
    let c1 = cast(B3, 1, 1);
    let c2 = cast(B3, 2, 2);
    book.push(SCHEMA_CAST_RECORD, c1.event);
    book.push(SCHEMA_CAST_RECORD, c2.event);
    let both = [
        (c1.code, ReceiptOutcome::Received),
        (c2.code, ReceiptOutcome::Received),
    ];
    // Before the close.
    let open = book.q(resolution(B3, &both, CLOSE_BUCKET));
    book.push(SCHEMA_BATCH_ATTEST, batch(B3, 0, 1, 2, &[c1.code, c2.code]));
    book.push(SCHEMA_BOX_CLOSE, close(B3, 2, 2, 0, &[c1.code, c2.code]));
    book.w(opened(B1));
    // An in-person box; one record missing; a record of no box.
    let in_person = book.q(resolution(B1, &[], READY));
    let missing = book.q(resolution(B3, &both[..1], READY));
    let extra = book.q(resolution(
        B3,
        &[
            both[0],
            both[1],
            (Hash512([0x99; 64]), ReceiptOutcome::Late),
        ],
        READY,
    ));
    let taken_event = resolution(B3, &both, READY);
    let taken = book.q(taken_event);
    let taken_body = ityv_encoding::decode_object::<QuorumSigned<'_>>(
        SCHEMA_QUORUM_SIGNED,
        SCHEMA_VERSION_1,
        taken_event,
    )
    .unwrap()
    .body_bytes();
    let same = book.q(quorum_seeded(
        taken_body,
        b"receipt-resolution",
        &QUORUM,
        Some(9),
    ));
    let again = book.q(resolution(B3, &both, READY + 1));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [
            (open, TallyEvent::Receipt, TallyRefusal::Premature),
            (in_person, TallyEvent::Receipt, TallyRefusal::Subject),
            (missing, TallyEvent::Receipt, TallyRefusal::Entries),
            (extra, TallyEvent::Receipt, TallyRefusal::Entries),
            (same, TallyEvent::Receipt, TallyRefusal::Repeated),
            (again, TallyEvent::Receipt, TallyRefusal::Conflict),
        ]
    );
    assert!(taken > extra);
    assert_eq!(stage.holds(), only(HoldReason::ReceiptResolutionRefused));
    // A forged quorum.
    let mut book = Book::new(world());
    book.w(opened(B3));
    book.push(SCHEMA_CAST_RECORD, c1.event);
    book.push(SCHEMA_BATCH_ATTEST, batch(B3, 0, 1, 1, &[c1.code]));
    book.push(SCHEMA_BOX_CLOSE, close(B3, 1, 1, 0, &[c1.code]));
    let body = ityv_encoding::decode_object::<QuorumSigned<'_>>(
        SCHEMA_QUORUM_SIGNED,
        SCHEMA_VERSION_1,
        resolution(B3, &both[..1], READY),
    )
    .unwrap()
    .body_bytes();
    let forged = book.q(quorum(
        body,
        b"receipt-resolution",
        &[(b"T-A", 5), (b"T-J", 4), (b"T-P1-1", 0), (b"T-P2-1", 2)],
    ));
    assert_eq!(
        refused(&book.run()),
        [(forged, TallyEvent::Receipt, TallyRefusal::Signature)]
    );
}

#[test]
fn a_tally_effect_that_cannot_apply_is_refused() {
    let mut book = Book::new(world());
    let casts = box3(&mut book, &[1, 2]);
    let (received, damaged) = (casts[0], casts[1]);
    // A decision on a damaged record before the resolution that finds it
    // damaged.
    let (early_filed, early_event) = filing(DisputeType::Postal, B3, damaged.code, 1);
    book.w(early_event);
    let before = book.w(decision(early_filed, TallyEffect::Exclude));
    book.q(resolution(
        B3,
        &[
            (received.code, ReceiptOutcome::Received),
            (damaged.code, ReceiptOutcome::Damaged),
        ],
        CLOSE_BUCKET + 20,
    ));
    // A decision on a record received normally; on a custody dispute; on a
    // record of no box; the first that applies; a second on the same
    // record.
    let (normal, normal_event) = filing(DisputeType::Postal, B3, received.code, 2);
    book.w(normal_event);
    let on_received = book.w(decision(normal, TallyEffect::Exclude));
    let (custody, custody_event) = filing(DisputeType::Custody, B3, damaged.code, 3);
    book.w(custody_event);
    let on_custody = book.w(decision(custody, TallyEffect::Exclude));
    let (stray, stray_event) = filing(DisputeType::Postal, B3, Hash512([0x42; 64]), 4);
    book.w(stray_event);
    let on_stray = book.w(decision(stray, TallyEffect::Include));
    let (filed, filed_event) = filing(DisputeType::Postal, B3, damaged.code, 5);
    book.w(filed_event);
    // A decision without effect changes nothing and is not refused.
    book.w(decision(filed, TallyEffect::NoEffect));
    book.w(decision(filed, TallyEffect::Include));
    let second = book.w(decision(filed, TallyEffect::Exclude));
    let stage = book.run();
    assert_eq!(
        refused(&stage),
        [
            (before, TallyEvent::Decision, TallyRefusal::Effect),
            (on_received, TallyEvent::Decision, TallyRefusal::Effect),
            (on_custody, TallyEvent::Decision, TallyRefusal::Effect),
            (on_stray, TallyEvent::Decision, TallyRefusal::Effect),
            (second, TallyEvent::Decision, TallyRefusal::Effect),
        ]
    );
    assert_eq!(stage.holds(), only(HoldReason::TallyEffectRefused));
    // The include applied: both records are in the recomputed scope.
    let u = stage.unit(STYLE2, RU2).unwrap();
    assert_eq!(u.included, sorted(&[received.code, damaged.code]));
    assert!(u.exclusions.is_empty());
}

// ---------------------------------------------------------------------
// The report: a small clean election reaches `CRYPTO_TALLY_VERIFIED`.

/// The modules of the one-box election: name, chamber, device, key
/// number, whether a check-in unit's.
const ELECTION_MODULES: [(&[u8], ChamberCode, &[u8], u16, bool); 6] = [
    (b"M-B1-P1", ChamberCode::P1, b"BOX-1", 0, false),
    (b"M-B1-P2", ChamberCode::P2, b"BOX-1", 1, false),
    (b"M-U1A-P1", ChamberCode::P1, b"U-1A", 8, true),
    (b"M-U1A-P2", ChamberCode::P2, b"U-1A", 9, true),
    (b"M-U1B-P1", ChamberCode::P1, b"U-1B", 10, true),
    (b"M-U1B-P2", ChamberCode::P2, b"U-1B", 11, true),
];

static KEM: [u8; KEM_EK_LEN] = [0x6B; KEM_EK_LEN];
static PRF_P1: [u8; 32] = [0x11; 32];
static PRF_P2: [u8; 32] = [0x22; 32];

fn prf(chamber: ChamberCode) -> &'static [u8; 32] {
    if chamber == ChamberCode::P1 {
        &PRF_P1
    } else {
        &PRF_P2
    }
}

/// A field group's encoding, without an object header.
fn group<T: Encode>(value: &T) -> &'static [u8] {
    let mut out = std::vec![0u8; value.encoded_len()];
    let mut w = Writer::new(&mut out);
    value.encode(&mut w).unwrap();
    leak_slice(out)
}

/// Signatures of `signers` (identifier, key) over `message`, ascending.
fn actor_sigs(
    signers: &[(&'static [u8], u16, bool)],
    purpose: &[u8],
    message: &[u8],
) -> Vec<ActorSig<'static>> {
    let mut sorted = signers.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    sorted
        .iter()
        .map(|&(name, n, trustee)| ActorSig {
            actor_id: id(name),
            sig: sign(
                if trustee {
                    trustee_signing(n)
                } else {
                    signing(n)
                },
                purpose,
                message,
            ),
        })
        .collect()
}

/// The provisioning record of module `m` (VC-095, VC-093).
fn provisioning(m: (&'static [u8], ChamberCode, &'static [u8], u16, bool)) -> &'static [u8] {
    let (name, chamber, device, _, unit) = m;
    let message = group(
        &ModuleProvisionedMessage::new(&ModuleProvisionedParts {
            election_id: common::election(),
            module_id: ModuleId::new(name).unwrap(),
            device_id: id(device),
            chamber,
            member_count: 2,
            pad_length: 1 << 20,
            chassis_id: id(b"CH-1"),
            pad_card_id: id(b"PAD-1"),
            reprovision_count: 0,
            chassis_check_hash: Hash512([0x4C; 64]),
            kem_ek: &KEM,
            entropy_commitment: Hash512([0x5D; 64]),
            se_present: unit,
            prf_key_check: unit.then(|| prf(chamber)),
        })
        .unwrap(),
    );
    let member: (&'static [u8], u16) = if chamber == ChamberCode::P1 {
        (b"T-P1-1", 0)
    } else {
        (b"T-P2-1", 2)
    };
    let sigs = actor_sigs(
        &[
            (b"committee", COMMITTEE, false),
            (member.0, member.1, true),
            (b"obs-a", ROSTER_BASE + 2, false),
            (b"obs-b", ROSTER_BASE + 3, false),
        ],
        b"module-provisioned",
        message,
    );
    object(
        SCHEMA_MODULE_PROVISIONED,
        SCHEMA_VERSION_1,
        &ModuleProvisioned::new(message, &sigs).unwrap(),
    )
}

/// The key ceremony of party `chamber` (VC-092).
fn ceremony(chamber: ChamberCode) -> &'static [u8] {
    let (first, second): ((&'static [u8], u16), (&'static [u8], u16)) =
        if chamber == ChamberCode::P1 {
            ((b"T-P1-1", 0), (b"T-P1-2", 1))
        } else {
            ((b"T-P2-1", 2), (b"T-P2-2", 3))
        };
    let holders = [
        ShareHolder {
            trustee_id: TrusteeId::new(first.0).unwrap(),
            hsm_model: id(b"YubiHSM2"),
            hsm_serial_hash: Hash512([0x81; 64]),
        },
        ShareHolder {
            trustee_id: TrusteeId::new(second.0).unwrap(),
            hsm_model: id(b"NitrokeyHSM2"),
            hsm_serial_hash: Hash512([0x82; 64]),
        },
    ];
    let message = group(
        &PartyKeyMessage::new(&PartyKeyParts {
            election_id: common::election(),
            chamber,
            wrapped_module_count: 2,
            share_threshold: 2,
            share_holders: &holders,
            prf_key_check: prf(chamber),
            time_bucket: TimeBucket::new(50),
        })
        .unwrap(),
    );
    let sigs = actor_sigs(
        &[
            (first.0, first.1, true),
            (second.0, second.1, true),
            (b"committee", COMMITTEE, false),
            (b"obs-a", ROSTER_BASE + 2, false),
            (b"obs-b", ROSTER_BASE + 3, false),
        ],
        b"party-key",
        message,
    );
    object(
        SCHEMA_PARTY_KEY_CEREMONY,
        SCHEMA_VERSION_1,
        &PartyKeyCeremony::new(message, &sigs).unwrap(),
    )
}

/// The participation set of ST-1 with `n` pseudonyms, signed by U-1A and
/// its party modules.
fn participation(n: u8) -> &'static [u8] {
    let bytes: Vec<u8> = (1..=n).flat_map(|f| [f; 64]).collect();
    let message = group(&ParticipationMessage {
        election_id: common::election(),
        station_id: StationId::new(b"ST-1").unwrap(),
        pseudonyms: Pseudonyms::new(leak_slice(bytes)).unwrap(),
    });
    let sigs: Vec<ParticipationModuleSig<'static>> =
        [(b"M-U1A-P1".as_slice(), 8u16), (b"M-U1A-P2", 9)]
            .iter()
            .map(|&(m, key)| ParticipationModuleSig {
                module_id: ModuleId::new(m).unwrap(),
                sig: sign(module_signing(key), b"participation-set", message),
            })
            .collect();
    object(
        SCHEMA_PARTICIPATION_SET,
        SCHEMA_VERSION_1,
        &ParticipationSet::new(
            message,
            sign(unit_signing(0), b"participation-set", message),
            &sigs,
        )
        .unwrap(),
    )
}

/// The day's progress record and station counts with `n` voters: the
/// closing ticks of BOX-1 and U-1A, the issuance count and the observers'
/// final count (PROTOCOL.md §7.10, §10.2).
fn station_record(n: u64) -> Vec<(SchemaId, &'static [u8])> {
    let station = StationId::new(b"ST-1").unwrap();
    let body = object(
        SCHEMA_BOX_PROGRESS_BODY,
        SCHEMA_VERSION_1,
        &BoxProgressBody::new(&BoxProgressParts {
            election_id: common::election(),
            box_id: BoxId::new(B1.id).unwrap(),
            slot: 150,
            sheets_in: n,
            state: BoxProgressState::Closed,
        }),
    );
    let box_tick = object(
        SCHEMA_PROGRESS_TICK,
        SCHEMA_VERSION_1,
        &ProgressTick::new(body, sign(signing(B1.device), b"box-progress", body)).unwrap(),
    );
    let body = object(
        SCHEMA_CHECKIN_PROGRESS_BODY,
        SCHEMA_VERSION_1,
        &CheckinProgressBody::new(&CheckinProgressParts {
            election_id: common::election(),
            station_id: station,
            unit_id: UnitId::new(b"U-1A").unwrap(),
            slot: 150,
            checkins: n,
            issued: n,
            spoiled: 0,
            returned: 0,
            state: CheckinProgressState::Closed,
        })
        .unwrap(),
    );
    let checkin_tick = object(
        SCHEMA_PROGRESS_TICK,
        SCHEMA_VERSION_1,
        &ProgressTick::new(body, sign(unit_signing(0), b"checkin-progress", body)).unwrap(),
    );
    let issuance = witnessed(
        object(
            SCHEMA_ISSUANCE_COUNT_BODY,
            SCHEMA_VERSION_1,
            &IssuanceCountBody::new(&IssuanceCountParts {
                election_id: common::election(),
                station_id: station,
                stock_received: 50,
                issued: n,
                voter_spoiled: 0,
                returned: 0,
                unused: 50 - n,
                printer_waste: 0,
                envelopes: None,
                time_bucket: TimeBucket::new(CLOSE_BUCKET),
            }),
        ),
        &PEOPLE,
    );
    let observers = witnessed(
        object(
            SCHEMA_OBSERVER_COUNT_ATTEST_BODY,
            SCHEMA_VERSION_1,
            &ObserverCountAttestBody::new(&ObserverCountParts {
                election_id: common::election(),
                station_id: station,
                unit_id: UnitId::new(b"U-1A").unwrap(),
                count: n,
                kind: ObserverCountKind::Final,
                time_bucket: TimeBucket::new(CLOSE_BUCKET),
            }),
        ),
        &PEOPLE[2..],
    );
    std::vec![
        (SCHEMA_PROGRESS_TICK, box_tick),
        (SCHEMA_PROGRESS_TICK, checkin_tick),
        (SCHEMA_WITNESSED_EVENT, issuance),
        (SCHEMA_WITNESSED_EVENT, observers),
    ]
}

/// A one-box election (BOX-1 at ST-1 in RU-1) whose module entries pin
/// their provisioning records.
fn election_world() -> &'static World {
    static WORLD: OnceLock<&'static World> = OnceLock::new();
    WORLD.get_or_init(|| {
        let mut d = draft();
        d.boxes.retain(|b| b.box_id.as_bytes() == B1.id);
        d.stations.truncate(1);
        d.policies.truncate(1);
        d.units.truncate(1);
        d.modules.retain(|m| {
            ELECTION_MODULES
                .iter()
                .any(|e| e.0 == m.module_id.as_bytes())
        });
        for entry in &mut d.modules {
            let m = ELECTION_MODULES
                .iter()
                .find(|e| e.0 == entry.module_id.as_bytes())
                .unwrap();
            entry.provisioned_hash = object_hash(provisioning(*m));
        }
        d.appointments = d.referenced_appointments();
        leak(build(&d, &TALLY_SCOPES))
    })
}

#[test]
fn a_clean_election_reaches_crypto_tally_verified() {
    let world = election_world();
    let mut book = Book::new(world);
    for chamber in [ChamberCode::P1, ChamberCode::P2] {
        book.push(SCHEMA_PARTY_KEY_CEREMONY, ceremony(chamber));
    }
    for m in ELECTION_MODULES {
        book.push(SCHEMA_MODULE_PROVISIONED, provisioning(m));
    }
    let casts = box1(&mut book);
    for (schema, event) in station_record(3) {
        book.push(schema, event);
    }
    book.push(SCHEMA_PARTICIPATION_SET, participation(3));
    tally1(
        &mut book,
        &casts,
        &spec(STYLE1, RU1, &codes(&casts)),
        &[1, 1, 1, 0, 0],
        0,
    );
    book.checkpoint();
    let anchored = Publications {
        anchors: Publication::Satisfied,
        board: Publication::Pending,
    };
    let report = verify_ledger(
        world.genesis,
        book.ledger.bytes(),
        &book.ledger.events,
        anchored,
    );
    assert!(report.participation().complete());
    assert!(report.tally().complete());
    assert!(report.tally().passed(), "{:?}", report.tally());
    assert_eq!(report.tally().holds(), HoldSet::empty());
    assert_eq!(
        report.status().holds(),
        HoldSet::empty(),
        "{:?}",
        report.status()
    );
    assert_eq!(report.status().status(), Status::CryptoTallyVerified);

    // A refused event that names no unit holds the ledger though the unit
    // passed.
    let unit_passed = |r: &ityv_verify::Report<'_>| r.tally().unit(STYLE1, RU1).unwrap().passed();
    book.q(scope(scope_body(&spec(STYLE1, RU2, &[]))));
    book.checkpoint();
    let report = verify_ledger(
        world.genesis,
        book.ledger.bytes(),
        &book.ledger.events,
        anchored,
    );
    assert!(unit_passed(&report));
    assert!(report.tally().complete());
    assert!(!report.tally().passed());
    assert_eq!(report.status().status(), Status::HoldReview);
    assert!(
        report
            .status()
            .holds()
            .contains(HoldReason::TallyScopeRefused)
    );

    // Without the paper count the tally step is not run.
    let mut book = Book::new(world);
    for chamber in [ChamberCode::P1, ChamberCode::P2] {
        book.push(SCHEMA_PARTY_KEY_CEREMONY, ceremony(chamber));
    }
    for m in ELECTION_MODULES {
        book.push(SCHEMA_MODULE_PROVISIONED, provisioning(m));
    }
    let casts = box1(&mut book);
    for (schema, event) in station_record(3) {
        book.push(schema, event);
    }
    book.push(SCHEMA_PARTICIPATION_SET, participation(3));
    let body = scope_body(&spec(STYLE1, RU1, &codes(&casts)));
    book.q(scope(body));
    book.checkpoint();
    book.q(opening(opening_body(STYLE1, RU1, body, 0, sums(&casts, 0))));
    book.checkpoint();
    let report = verify_ledger(
        world.genesis,
        book.ledger.bytes(),
        &book.ledger.events,
        anchored,
    );
    assert!(!report.tally().complete());
    assert_eq!(report.status().status(), Status::SourceCompletenessChecked);

    // A paper count that does not agree holds the ledger.
    book.w(paper(STYLE1, RU1, &[1, 1, 1, 0, 0], 1));
    book.checkpoint();
    let report = verify_ledger(
        world.genesis,
        book.ledger.bytes(),
        &book.ledger.events,
        anchored,
    );
    assert_eq!(report.status().status(), Status::HoldReview);
    assert!(
        report
            .status()
            .holds()
            .contains(HoldReason::PaperCountMismatch)
    );
}
