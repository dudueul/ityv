//! The election worlds of the tally and audit tests (PROTOCOL.md §10.6,
//! §11, §12): genesis drafts, boxes, real cast records made from known
//! secrets (OR proofs, commitments, record signatures), batches, closes,
//! trustee-quorum and human-signed events, checkpoints over the ledger,
//! and the complete one-box and two-unit elections. Every signature is a
//! real hybrid signature under a key the genesis registers.
// Integration tests: outside the TCB. Assertions use unwrap/expect, and
// each test file uses a different part of this module, so these lints are
// relaxed for this file only (CONSTITUTION.md §1.1).
#![allow(
    dead_code,
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

use std::sync::OnceLock;
use std::vec::Vec;

use crate::common;
use crate::common::{
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
    SCHEMA_SIGNED_LEGAL_AUTHORIZATION, SCHEMA_TALLY_SCOPE_BODY, SCHEMA_TIMESTAMP_RECORD,
    SCHEMA_VERSION_1, SCHEMA_WITNESSED_EVENT, Scalar32, SchemaId, Scope, Seq, ShareHolder,
    SignerId, SignerRole, StationId, StationKind, TallyEffect, TallyScopeBody, TallyScopeParts,
    TimeBucket, Token192, TreeSize, TrusteeId, UnitId, WitnessedEvent, Writer, purpose_of,
};
use ityv_encoding::{
    ChallengeOpening, ChallengeOpeningBody, ChallengeOpeningParts, MAX_QUORUM_MESSAGE_LEN,
    ModuleOpening, SCHEMA_CHALLENGE_OPENING, SCHEMA_CHALLENGE_OPENING_BODY, Scalars,
    write_quorum_message,
};
use ityv_ledger::{
    SCHEMA_SIGNED_CHECKPOINT, SignedCheckpointParts, WitnessSignatureEntry, root_of_leaves,
    sorted_set_root,
};
use ityv_state::{HoldReason, HoldSet};
use ityv_verify::{
    LedgerIndex, TallyEvent, TallyRefusal, TallyRefused, TallyStage, UnitTally, VerifiedGenesis,
    authorize_ledger, build_index, verify_boxes, verify_checkpoints, verify_disputes,
    verify_genesis, verify_records, verify_tally,
};
use rand_chacha::ChaCha20Rng;
use rand_core::{Rng, SeedableRng};

pub(crate) const OPEN_BUCKET: u64 = 100;
pub(crate) const CLOSE_BUCKET: u64 = 140;
/// The first bucket a tally scope may carry: more than 96 after the last
/// close.
pub(crate) const READY: u64 = CLOSE_BUCKET + 97;
pub(crate) const SEAL: Hash512 = Hash512([0x5e; 64]);
pub(crate) const CHAIR_KEY: u16 = ROSTER_BASE + 30;
pub(crate) const COURT_KEY: u16 = ROSTER_BASE + 5;
pub(crate) const RU1: &[u8] = b"RU-1";
pub(crate) const RU2: &[u8] = b"RU-2";
pub(crate) const STYLE1: &[u8] = b"STYLE-1";
pub(crate) const STYLE2: &[u8] = b"STYLE-2";

// ---------------------------------------------------------------------
// The worlds.

/// A genesis and its signed objects.
pub(crate) struct World {
    pub(crate) genesis: &'static VerifiedGenesis<'static>,
    pub(crate) pin: Hash512,
    pub(crate) signed: &'static [u8],
    pub(crate) authorization: &'static [u8],
}

/// The standard genesis without BOX-2, BOX-3 out of district, a test
/// style `TEST-1` and a district commission chair on the roster.
pub(crate) fn draft() -> Draft {
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

pub(crate) fn build(draft: &Draft, scopes: &[Scope]) -> World {
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

pub(crate) const TALLY_SCOPES: [Scope; 4] = [
    Scope::PublicBoard,
    Scope::TrusteeBody,
    Scope::BallotMark,
    Scope::CryptoTallyAid,
];

pub(crate) fn world() -> &'static World {
    static WORLD: OnceLock<&'static World> = OnceLock::new();
    WORLD.get_or_init(|| leak(build(&draft(), &TALLY_SCOPES)))
}

/// As [`world`], with one amendment: observer obs-a gets a new key and
/// RU-1 is reported by commission NEC-X; with the signed amendment.
pub(crate) fn amended_world() -> &'static (World, &'static [u8]) {
    static WORLD: OnceLock<&'static (World, &'static [u8])> = OnceLock::new();
    WORLD.get_or_init(|| {
        leak(amend(|next| {
            for r in &mut next.roster {
                if r.signer_id.as_bytes() == b"obs-a" {
                    r.key = common::registered(ROSTER_BASE + 40);
                }
            }
            next.units[0] = ReportingUnitEntry::new(
                ReportingUnitId::new(RU1).unwrap(),
                1,
                OrgId::new(b"NEC-X").unwrap(),
            )
            .unwrap();
        }))
    })
}

/// As [`world`], with one amendment that `change` makes to its draft;
/// with the signed amendment.
pub(crate) fn amend(change: impl FnOnce(&mut Draft)) -> (World, &'static [u8]) {
    let d = draft();
    let (body, authorization) = common::legal_authorization(&TALLY_SCOPES, 20_000, 20_100);
    let built = leak(sign_genesis_with(&d, d.raw(), &SIGNERS, |p| {
        p.legal_authorization_hash = object_hash(body);
    }));
    let mut next = d.clone();
    change(&mut next);
    next.appointments = next.referenced_appointments();
    let amendment = common::amendment(1, built.pin, &next.raw(), &SIGNERS);
    let genesis = leak(verify_genesis(&built.pin, &built.input(), &[amendment]).unwrap());
    (
        World {
            genesis,
            pin: built.pin,
            signed: built.signed,
            authorization,
        },
        amendment.signed,
    )
}

/// As [`world`], without `CRYPTO_TALLY_AID`.
pub(crate) fn world_without_aid() -> &'static World {
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
pub(crate) struct Bx {
    pub(crate) id: &'static [u8],
    pub(crate) device: u16,
    pub(crate) style: &'static [u8],
    pub(crate) options: u16,
    /// (module, key number), ascending by module.
    pub(crate) mods: &'static [(&'static [u8], u16)],
    pub(crate) absentee: bool,
}

pub(crate) const B1: Bx = Bx {
    id: b"BOX-1",
    device: BOX_DEVICE_BASE,
    style: STYLE1,
    options: 7,
    mods: &[(b"M-B1-P1", 0), (b"M-B1-P2", 1)],
    absentee: false,
};

pub(crate) const B3: Bx = Bx {
    id: b"BOX-3",
    device: BOX_DEVICE_BASE + 2,
    style: STYLE2,
    options: 11,
    mods: &[(b"M-B3-A", 7), (b"M-B3-P1", 5), (b"M-B3-P2", 6)],
    absentee: true,
};

pub(crate) const PEOPLE: [(&[u8], EventRole, &[u8], u16); 4] = [
    (b"clerk-1", EventRole::Clerk, b"ORG-ST", ROSTER_BASE),
    (b"clerk-2", EventRole::Clerk, b"ORG-ST", ROSTER_BASE + 1),
    (b"obs-a", EventRole::Observer, b"PARTY-A", ROSTER_BASE + 2),
    (b"obs-b", EventRole::Observer, b"PARTY-B", ROSTER_BASE + 3),
];

/// A `WitnessedEvent` over `body` signed by `who` (identifier, role,
/// organisation, key number), sorted here.
pub(crate) fn witnessed(
    body: &'static [u8],
    who: &[(&'static [u8], EventRole, &'static [u8], u16)],
) -> &'static [u8] {
    witnessed_seeded(body, who, None)
}

/// As [`witnessed`], the signing randomness drawn from `seed` when given:
/// the same body and signers under other signature bytes.
pub(crate) fn witnessed_seeded(
    body: &'static [u8],
    who: &[(&'static [u8], EventRole, &'static [u8], u16)],
    seed: Option<u64>,
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
            sig: match seed {
                Some(seed) => common::sign_seeded(signing(n), purpose, body, seed),
                None => sign(signing(n), purpose, body),
            },
        })
        .collect();
    object(
        SCHEMA_WITNESSED_EVENT,
        ityv_encoding::SCHEMA_VERSION_WITNESSED,
        &WitnessedEvent::new(body, &sigs).unwrap(),
    )
}

pub(crate) fn opened(bx: Bx) -> &'static [u8] {
    opened_at(bx, OPEN_BUCKET)
}

/// As [`opened`], in time bucket `bucket`.
pub(crate) fn opened_at(bx: Bx, bucket: u64) -> &'static [u8] {
    let names: Vec<&'static [u8]> = bx.mods.iter().map(|m| m.0).collect();
    let body = BoxOpenedBody::new(&BoxOpenedParts {
        election_id: common::election(),
        box_id: BoxId::new(bx.id).unwrap(),
        modules: modules(&names),
        seal_digest: SEAL,
        seals_match: true,
        initial_count: 0,
        time_bucket: TimeBucket::new(bucket),
    });
    let body = object(SCHEMA_BOX_OPENED_BODY, SCHEMA_VERSION_1, &body);
    let mut who = PEOPLE.to_vec();
    who.push((bx.id, EventRole::Device, b"ORG-ST", bx.device));
    witnessed(body, &who)
}

/// A cast record and the secrets it was made from.
#[derive(Clone, Copy)]
pub(crate) struct Cast {
    pub(crate) event: &'static [u8],
    pub(crate) code: Hash512,
    pub(crate) option: u16,
    pub(crate) cast_id: CastId,
    pub(crate) rand: [Scalar; MAX_CHUNKS],
    /// Each module's cast-id contribution and randomness, in module order.
    pub(crate) parts: &'static [([u8; 24], [Scalar; MAX_CHUNKS])],
    pub(crate) counter: u64,
    pub(crate) style: &'static [u8],
    pub(crate) chunks: u8,
}

/// The stand-in for the sealed share package of box `box_id`'s record
/// `counter`: an object of the share package's schema the record names by
/// hash (the tests never open it; the connectivity tests send it after its
/// record).
pub(crate) fn share_package(box_id: &[u8], counter: u64) -> &'static [u8] {
    let mut body = box_id.to_vec();
    body.extend_from_slice(&counter.to_be_bytes());
    common::uplink::fake_object(ityv_encoding::SCHEMA_SHARE_PACKAGE, &body)
}

/// The module record message `body_hash ‖ module_id ‖ counter`.
pub(crate) fn module_message(body_hash: &Hash512, module: &'static [u8], counter: u64) -> Vec<u8> {
    let mut buf = [0u8; 140];
    let mut w = Writer::new(&mut buf);
    body_hash.encode(&mut w).unwrap();
    common::module(module).encode(&mut w).unwrap();
    w.write_u64(counter).unwrap();
    let len = w.finish();
    buf[..len].to_vec()
}

/// Record `counter` of `bx` for `option`, of the box's style.
pub(crate) fn cast(bx: Bx, counter: u64, option: u16) -> Cast {
    cast_styled(bx, counter, option, bx.style, bx.options)
}

/// Record `counter` of `bx` for `option`, naming ballot style `style` of
/// `options` options. Its secrets come from a stream seeded by the box and
/// counter (PROTOCOL.md §7.3).
pub(crate) fn cast_styled(
    bx: Bx,
    counter: u64,
    option: u16,
    style: &'static [u8],
    options: u16,
) -> Cast {
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
        share_package_hash: object_hash(share_package(bx.id, counter)),
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
pub(crate) fn challenge(bx: Bx, c: &Cast) -> &'static [u8] {
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
pub(crate) fn root(codes: &[Hash512]) -> Hash512 {
    let mut codes = codes.to_vec();
    codes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    sorted_set_root(&codes).unwrap()
}

pub(crate) fn sorted(codes: &[Hash512]) -> Vec<Hash512> {
    let mut codes = codes.to_vec();
    codes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    codes
}

/// The batch `index` of `bx` over counters `first..=last` of every module,
/// attesting `members`, closed in the opening's time bucket (the uplink
/// tests send the whole day in the opening's slot, and a batch goes out no
/// earlier than its bucket, ADR-0041 decision 6).
pub(crate) fn batch(
    bx: Bx,
    index: u32,
    first: u64,
    last: u64,
    members: &[Hash512],
) -> &'static [u8] {
    batch_at(bx, index, first, last, members, OPEN_BUCKET)
}

/// As [`batch`], in time bucket `bucket`.
pub(crate) fn batch_at(
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
pub(crate) fn close(
    bx: Bx,
    records: u64,
    attested: u64,
    without: u64,
    codes: &[Hash512],
) -> &'static [u8] {
    close_as(bx, (records, attested, without), codes, Some(b"box-close"))
}

/// As [`close`]: `device` names the purpose the device and the people sign
/// under (`box-close`, `late-box-close`), `None` for a manual close.
pub(crate) fn close_as(
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
pub(crate) fn close_full(
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
pub(crate) const QUORUM: [(&[u8], u16); 5] = [
    (b"T-A", 5),
    (b"T-C", 6),
    (b"T-J", 4),
    (b"T-P1-1", 0),
    (b"T-P2-1", 2),
];

/// `body` signed by the trustees `who` (identifier, key number,
/// ascending) under `purpose`.
pub(crate) fn quorum(
    body: &'static [u8],
    purpose: &[u8],
    who: &[(&'static [u8], u16)],
) -> &'static [u8] {
    quorum_seeded(body, purpose, who, None)
}

/// The quorum message of `body` signed by `who` (ENCODING.md §8.63).
pub(crate) fn quorum_message(body: &[u8], who: &[(&'static [u8], u16)]) -> &'static [u8] {
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
pub(crate) fn quorum_seeded(
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
        ityv_encoding::SCHEMA_VERSION_QUORUM_SIGNED,
        &QuorumSigned::new(body, &sigs).unwrap(),
    )
}

/// What a tally scope says.
#[derive(Clone)]
pub(crate) struct ScopeSpec {
    pub(crate) style: &'static [u8],
    pub(crate) unit: &'static [u8],
    pub(crate) included: Vec<Hash512>,
    pub(crate) exclusions: Vec<ExclusionEntry>,
    pub(crate) no_record: u64,
    pub(crate) bucket: u64,
    pub(crate) count: Option<u64>,
    pub(crate) root: Option<Hash512>,
}

pub(crate) fn spec(style: &'static [u8], unit: &'static [u8], included: &[Hash512]) -> ScopeSpec {
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

pub(crate) fn exclusion(
    record: Hash512,
    reason: ExclusionReason,
    basis: Hash512,
) -> ExclusionEntry {
    ExclusionEntry {
        record_hash: record,
        reason,
        basis,
    }
}

/// The tally scope body object of `s`.
pub(crate) fn scope_body(s: &ScopeSpec) -> &'static [u8] {
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

pub(crate) fn scope(body: &'static [u8]) -> &'static [u8] {
    quorum(body, b"tally-scope", &QUORUM)
}

/// `T_j`, `R_j` and `S` of `casts` for chunk `chunk`.
pub(crate) fn sums(casts: &[Cast], chunk: u8) -> (Scalar, Scalar, Scalar) {
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
pub(crate) fn opening_body(
    style: &'static [u8],
    unit: &'static [u8],
    scope: &'static [u8],
    chunk: u8,
    sums: (Scalar, Scalar, Scalar),
) -> &'static [u8] {
    opening_at(style, unit, scope, chunk, sums, READY + 2)
}

/// As [`opening_body`], recorded in time bucket `bucket`.
pub(crate) fn opening_at(
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

pub(crate) fn opening(body: &'static [u8]) -> &'static [u8] {
    quorum(body, b"aggregate-opening", &QUORUM)
}

/// The chair and observers of two organisations.
pub(crate) const PAPER_SIGNERS: [(&[u8], EventRole, &[u8], u16); 3] = [
    (b"chair", EventRole::Chair, b"NEC-D", CHAIR_KEY),
    (b"obs-a", EventRole::Observer, b"PARTY-A", ROSTER_BASE + 2),
    (b"obs-b", EventRole::Observer, b"PARTY-B", ROSTER_BASE + 3),
];

/// The paper count of `style` in `unit`.
pub(crate) fn paper_by(
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

pub(crate) fn paper(
    style: &'static [u8],
    unit: &'static [u8],
    votes: &[u64],
    invalid: u64,
) -> &'static [u8] {
    paper_by(style, unit, votes, invalid, &PAPER_SIGNERS)
}

/// The receipt resolution of `bx`, one outcome per record, signed by the
/// quorum.
pub(crate) fn resolution(
    bx: Bx,
    outcomes: &[(Hash512, ReceiptOutcome)],
    bucket: u64,
) -> &'static [u8] {
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
pub(crate) fn filing(
    kind: DisputeType,
    bx: Bx,
    record: Hash512,
    evidence: u8,
) -> (Hash512, &'static [u8]) {
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
pub(crate) fn decision(dispute: Hash512, effect: TallyEffect) -> &'static [u8] {
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

pub(crate) struct Book {
    pub(crate) world: &'static World,
    pub(crate) ledger: Ledger,
    pub(crate) frames: Vec<Hash512>,
    pub(crate) closes: Vec<Hash512>,
    /// The filings of the disputes still open.
    pub(crate) disputes: Vec<Hash512>,
    pub(crate) last: Option<(u64, Hash512)>,
    /// The witnesses' time of the last checkpoint: the chain's buckets
    /// never decrease (VC-012).
    pub(crate) bucket: u64,
}

impl Book {
    pub(crate) fn new(world: &'static World) -> Self {
        let mut book = Self {
            world,
            ledger: Ledger::new(),
            frames: Vec::new(),
            closes: Vec::new(),
            disputes: Vec::new(),
            last: None,
            bucket: 0,
        };
        book.push(SCHEMA_SIGNED_GENESIS, world.signed);
        book.push(SCHEMA_SIGNED_LEGAL_AUTHORIZATION, world.authorization);
        book
    }

    pub(crate) fn push(&mut self, schema: SchemaId, event: &'static [u8]) -> u64 {
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

    pub(crate) fn w(&mut self, event: &'static [u8]) -> u64 {
        self.push(SCHEMA_WITNESSED_EVENT, event)
    }

    pub(crate) fn q(&mut self, event: &'static [u8]) -> u64 {
        self.push(SCHEMA_QUORUM_SIGNED, event)
    }

    /// The gateways' frame logs and sessions over every device event so
    /// far, each station's last session final (ADR-0041): the uplink the
    /// status ladder needs for `SOURCE_COMPLETENESS_CHECKED`.
    pub(crate) fn uplink(&mut self) {
        let events = self.ledger.events.clone();
        for (schema, event) in common::uplink::for_ledger(self.world.genesis, &events) {
            self.push(schema, event);
        }
    }

    /// A checkpoint over every frame so far, after the last one, in the
    /// first bucket after the late-close window.
    pub(crate) fn checkpoint(&mut self) -> u64 {
        self.checkpoint_at((READY + 1).max(self.bucket))
    }

    /// A checkpoint over every frame so far, the witnesses' time
    /// `bucket`, anchored: the government's and the non-government
    /// authority's real tokens a minute into its bucket follow it (the
    /// returned frame is the checkpoint's).
    pub(crate) fn checkpoint_at(&mut self, bucket: u64) -> u64 {
        let frame = self.checkpoint_bare_at(bucket);
        let event = *self.ledger.events.last().unwrap();
        for record in common::tsa::anchor(SCHEMA_SIGNED_CHECKPOINT, event, bucket) {
            self.push(SCHEMA_TIMESTAMP_RECORD, record);
        }
        frame
    }

    /// As [`Self::checkpoint_at`], without timestamp tokens.
    pub(crate) fn checkpoint_bare_at(&mut self, bucket: u64) -> u64 {
        let body = self.checkpoint_body_at(bucket);
        let seq = self.last.map_or(1, |(seq, _)| seq + 1);
        self.last = Some((seq, object_hash(body)));
        self.bucket = bucket;
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

    /// The body the next checkpoint over every frame so far would carry at
    /// the witnesses' time `bucket`, without signing or recording it.
    pub(crate) fn checkpoint_body_at(&self, bucket: u64) -> &'static [u8] {
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
        object(SCHEMA_CHECKPOINT_BODY, SCHEMA_VERSION_1, &body)
    }

    pub(crate) fn run(&self) -> TallyStage<'static> {
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
pub(crate) fn box1(book: &mut Book) -> Vec<Cast> {
    let casts = box1_closed(book);
    book.checkpoint();
    casts
}

/// As [`box1`], without the checkpoint.
pub(crate) fn box1_closed(book: &mut Book) -> Vec<Cast> {
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

pub(crate) fn codes(casts: &[Cast]) -> Vec<Hash512> {
    casts.iter().map(|c| c.code).collect()
}

/// The scope of unit 1, a checkpoint, the opening of its one chunk and
/// its paper count: frames of the scope and the opening.
pub(crate) fn tally1(
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

pub(crate) fn unit1(stage: &TallyStage<'static>) -> UnitTally<'static> {
    stage.unit(STYLE1, RU1).unwrap().clone()
}

pub(crate) fn refused(stage: &TallyStage<'_>) -> Vec<(u64, TallyEvent, TallyRefusal)> {
    stage
        .refused()
        .iter()
        .map(|r: &TallyRefused| (r.seq.get(), r.event, r.refusal))
        .collect()
}

pub(crate) fn only(reason: HoldReason) -> HoldSet {
    HoldSet::empty().with(reason)
}

// ---------------------------------------------------------------------
// The report: a small clean election reaches `CRYPTO_TALLY_VERIFIED`.

/// The modules of the one-box election: name, chamber, device, key
/// number, whether a check-in unit's.
pub(crate) const ELECTION_MODULES: [(&[u8], ChamberCode, &[u8], u16, bool); 6] = [
    (b"M-B1-P1", ChamberCode::P1, b"BOX-1", 0, false),
    (b"M-B1-P2", ChamberCode::P2, b"BOX-1", 1, false),
    (b"M-U1A-P1", ChamberCode::P1, b"U-1A", 8, true),
    (b"M-U1A-P2", ChamberCode::P2, b"U-1A", 9, true),
    (b"M-U1B-P1", ChamberCode::P1, b"U-1B", 10, true),
    (b"M-U1B-P2", ChamberCode::P2, b"U-1B", 11, true),
];

pub(crate) static KEM: [u8; KEM_EK_LEN] = [0x6B; KEM_EK_LEN];
pub(crate) static PRF_P1: [u8; 32] = [0x11; 32];
pub(crate) static PRF_P2: [u8; 32] = [0x22; 32];

pub(crate) fn prf(chamber: ChamberCode) -> &'static [u8; 32] {
    if chamber == ChamberCode::P1 {
        &PRF_P1
    } else {
        &PRF_P2
    }
}

/// A field group's encoding, without an object header.
pub(crate) fn group<T: Encode>(value: &T) -> &'static [u8] {
    let mut out = std::vec![0u8; value.encoded_len()];
    let mut w = Writer::new(&mut out);
    value.encode(&mut w).unwrap();
    leak_slice(out)
}

/// Signatures of `signers` (identifier, key) over `message`, ascending.
pub(crate) fn actor_sigs(
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
pub(crate) fn provisioning(
    m: (&'static [u8], ChamberCode, &'static [u8], u16, bool),
) -> &'static [u8] {
    let (name, chamber, device, _, unit) = m;
    let message = group(
        &ModuleProvisionedMessage::new(&ModuleProvisionedParts {
            election_id: common::election(),
            module_id: ModuleId::new(name).unwrap(),
            device_id: id(device),
            chamber,
            member_count: if chamber == ChamberCode::J { 1 } else { 2 },
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
    let member: (&'static [u8], u16) = match chamber {
        ChamberCode::P1 => (b"T-P1-1", 0),
        ChamberCode::J => (b"T-J", 4),
        ChamberCode::P2
        | ChamberCode::P3
        | ChamberCode::P4
        | ChamberCode::A
        | ChamberCode::C
        | ChamberCode::N => (b"T-P2-1", 2),
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
pub(crate) fn ceremony(chamber: ChamberCode) -> &'static [u8] {
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
pub(crate) fn participation(n: u8) -> &'static [u8] {
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
pub(crate) fn station_record(n: u64) -> Vec<(SchemaId, &'static [u8])> {
    station_record_of(&[(B1, n)])
}

/// As [`station_record`] for ST-1 with the boxes `boxes` and their voters.
pub(crate) fn station_record_of(boxes: &[(Bx, u64)]) -> Vec<(SchemaId, &'static [u8])> {
    let station = StationId::new(b"ST-1").unwrap();
    let n: u64 = boxes.iter().map(|(_, k)| k).sum();
    let mut ticks: Vec<(SchemaId, &'static [u8])> = Vec::new();
    for (bx, k) in boxes {
        let body = object(
            SCHEMA_BOX_PROGRESS_BODY,
            SCHEMA_VERSION_1,
            &BoxProgressBody::new(&BoxProgressParts {
                election_id: common::election(),
                box_id: BoxId::new(bx.id).unwrap(),
                slot: 150,
                sheets_in: *k,
                state: BoxProgressState::Closed,
            }),
        );
        ticks.push((
            SCHEMA_PROGRESS_TICK,
            object(
                SCHEMA_PROGRESS_TICK,
                SCHEMA_VERSION_1,
                &ProgressTick::new(body, sign(signing(bx.device), b"box-progress", body)).unwrap(),
            ),
        ));
    }
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
                stock_received: n.max(50),
                issued: n,
                voter_spoiled: 0,
                returned: 0,
                unused: n.max(50) - n,
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
    ticks.extend([
        (SCHEMA_PROGRESS_TICK, checkin_tick),
        (SCHEMA_WITNESSED_EVENT, issuance),
        (SCHEMA_WITNESSED_EVENT, observers),
    ]);
    ticks
}

/// The complete roll of the one-station worlds (ADR-0040): ST-1's
/// resident extract, the national snapshot, the freeze and three
/// custodians' receipts, the court administration's with the pseudonym
/// root.
pub(crate) fn roll() -> Vec<(SchemaId, &'static [u8])> {
    common::roll::standard(&[b"ST-1"])
}

/// The draft of [`election_world`].
pub(crate) fn election_draft() -> Draft {
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
    d
}

/// A one-box election (BOX-1 at ST-1 in RU-1) whose module entries pin
/// their provisioning records.
pub(crate) fn election_world() -> &'static World {
    static WORLD: OnceLock<&'static World> = OnceLock::new();
    WORLD.get_or_init(|| leak(build(&election_draft(), &TALLY_SCOPES)))
}

/// As [`election_world`], with one amendment that `change` makes to its
/// draft; with the signed amendment.
pub(crate) fn election_amended(change: impl FnOnce(&mut Draft)) -> (World, &'static [u8]) {
    let d = election_draft();
    let (body, authorization) = common::legal_authorization(&TALLY_SCOPES, 20_000, 20_100);
    let built = leak(sign_genesis_with(&d, d.raw(), &SIGNERS, |p| {
        p.legal_authorization_hash = object_hash(body);
    }));
    let mut next = d.clone();
    change(&mut next);
    next.appointments = next.referenced_appointments();
    let amendment = common::amendment(1, built.pin, &next.raw(), &SIGNERS);
    let genesis = leak(verify_genesis(&built.pin, &built.input(), &[amendment]).unwrap());
    (
        World {
            genesis,
            pin: built.pin,
            signed: built.signed,
            authorization,
        },
        amendment.signed,
    )
}

// ---------------------------------------------------------------------
// The report over two units: one without its opening or paper count keeps
// the ledger below `CRYPTO_TALLY_VERIFIED`.

pub(crate) const B2: Bx = Bx {
    id: b"BOX-2",
    device: BOX_DEVICE_BASE + 1,
    style: STYLE1,
    options: 7,
    mods: &[(b"M-B2-J", 4), (b"M-B2-P1", 2), (b"M-B2-P2", 3)],
    absentee: false,
};

/// The modules of the two-unit election, as [`ELECTION_MODULES`].
pub(crate) const TWO_UNIT_MODULES: [(&[u8], ChamberCode, &[u8], u16, bool); 9] = [
    (b"M-B1-P1", ChamberCode::P1, b"BOX-1", 0, false),
    (b"M-B1-P2", ChamberCode::P2, b"BOX-1", 1, false),
    (b"M-B2-P1", ChamberCode::P1, b"BOX-2", 2, false),
    (b"M-B2-P2", ChamberCode::P2, b"BOX-2", 3, false),
    (b"M-B2-J", ChamberCode::J, b"BOX-2", 4, false),
    (b"M-U1A-P1", ChamberCode::P1, b"U-1A", 8, true),
    (b"M-U1A-P2", ChamberCode::P2, b"U-1A", 9, true),
    (b"M-U1B-P1", ChamberCode::P1, b"U-1B", 10, true),
    (b"M-U1B-P2", ChamberCode::P2, b"U-1B", 11, true),
];

/// ST-1 with BOX-1 in RU-1 and BOX-2 in RU-2, both STYLE-1: two units.
pub(crate) fn two_unit_world() -> &'static World {
    static WORLD: OnceLock<&'static World> = OnceLock::new();
    WORLD.get_or_init(|| {
        let mut d = Draft::standard();
        d.boxes = std::vec![
            common::genesis_box(0, b"BOX-1", b"ST-1", RU1, &[b"M-B1-P1", b"M-B1-P2"]),
            common::genesis_box(
                1,
                b"BOX-2",
                b"ST-1",
                RU2,
                &[b"M-B2-P1", b"M-B2-P2", b"M-B2-J"]
            ),
        ];
        d.stations.truncate(1);
        d.policies.truncate(1);
        d.units = std::vec![
            ReportingUnitEntry::new(
                ReportingUnitId::new(RU1).unwrap(),
                1,
                OrgId::new(b"NEC-D").unwrap()
            )
            .unwrap(),
            ReportingUnitEntry::new(
                ReportingUnitId::new(RU2).unwrap(),
                1,
                OrgId::new(b"NEC-D").unwrap()
            )
            .unwrap(),
        ];
        d.modules.retain(|m| {
            TWO_UNIT_MODULES
                .iter()
                .any(|e| e.0 == m.module_id.as_bytes())
        });
        for entry in &mut d.modules {
            let m = TWO_UNIT_MODULES
                .iter()
                .find(|e| e.0 == entry.module_id.as_bytes())
                .unwrap();
            entry.provisioned_hash = object_hash(provisioning(*m));
        }
        d.roster.push(common::roster_signer(
            30,
            b"chair",
            RosterRole::Chair,
            b"NEC-D",
            None,
        ));
        d.appointments = d.referenced_appointments();
        leak(build(&d, &TALLY_SCOPES))
    })
}
