//! The human-signed event bodies (0x0008, 0x000E, 0x000F, 0x0029–0x002E),
//! the `WitnessedEvent` envelope (0x0028) and the genesis entry types:
//! golden vectors (ENCODING.md §7), round trips, and one rejection per
//! rule.
//!
//! Signatures here are patterned bytes: the encoding layer treats them as
//! opaque fixed-width fields.
// Integration-test crate: outside the TCB. Test code expresses "this must
// hold" with unwrap/expect/panic/indexing and does small arithmetic on test
// sizes, so those restriction lints are relaxed for this file only
// (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]

mod common;

use common::{
    Vector, check_file, encode_to_vec, ident_len, patterned, patterned64, render, self_check,
};
use ityv_encoding::{
    BallotStyleId, BoxId, BoxOpenedBody, BoxOpenedParts, CaptureProfile, CustodyHandoffBody,
    CustodyHandoffParts, CustodyRoute, Day, Decode, DisputeAction, DisputeEventBody,
    DisputeEventParts, DisputeType, ElectionId, Encode, EnvelopeIssuance, ErrorKind, EventRole,
    EventSig, FallbackBody, FallbackKind, FallbackParts, FallbackReason, GenesisBox, HEADER_LEN,
    HYBRID_SIG_LEN, HYBRID_VK_LEN, Hash512, ImprintAuditBody, ImprintAuditParts, IssuanceCountBody,
    IssuanceCountParts, LateBatchCloseBody, LateBatchCloseParts, LateBatchReason,
    LegalDecisionRefBody, LegalDecisionRefParts, LegalOutcome, MarkerRange, ModuleId, ModuleIds,
    OrgId, Reader, RosterRole, RosterSigner, RouteId, SCHEMA_BOX_OPENED_BODY,
    SCHEMA_CUSTODY_HANDOFF_BODY, SCHEMA_DISPUTE_EVENT_BODY, SCHEMA_FALLBACK_BODY,
    SCHEMA_IMPRINT_AUDIT_BODY, SCHEMA_ISSUANCE_COUNT_BODY, SCHEMA_LATE_BATCH_CLOSE_BODY,
    SCHEMA_LEGAL_DECISION_REF_BODY, SCHEMA_SEAL_CHANGE_BODY, SCHEMA_VERSION_1,
    SCHEMA_WITNESSED_EVENT, SchemaId, SealChangeBody, SealChangeParts, SealChangeReason, SignerId,
    StationId, TallyEffect, TimeBucket, WITNESSED_BODY_SCHEMAS, WitnessedEvent, Writer,
    decode_object, purpose_of,
};
use std::vec::Vec;

const E: &[u8] = b"KR-2030-PRES";
const BOX: &[u8] = b"box-11-0042";

static SIG_A: [u8; HYBRID_SIG_LEN] = [0xA1; HYBRID_SIG_LEN];
static SIG_B: [u8; HYBRID_SIG_LEN] = [0xB2; HYBRID_SIG_LEN];
static SIG_C: [u8; HYBRID_SIG_LEN] = [0xC3; HYBRID_SIG_LEN];
static SIG_D: [u8; HYBRID_SIG_LEN] = [0xD4; HYBRID_SIG_LEN];
static SIG_E: [u8; HYBRID_SIG_LEN] = [0xE5; HYBRID_SIG_LEN];
static VK: [u8; HYBRID_VK_LEN] = [0x5A; HYBRID_VK_LEN];

fn e() -> ElectionId<'static> {
    ElectionId::new(E).unwrap()
}

fn bx() -> BoxId<'static> {
    BoxId::new(BOX).unwrap()
}

fn signer(id: &'static [u8]) -> SignerId<'static> {
    SignerId::new(id).unwrap()
}

fn org(id: &'static [u8]) -> OrgId<'static> {
    OrgId::new(id).unwrap()
}

fn valid(label: &'static str, bytes: Vec<u8>) -> Vector {
    Vector {
        label,
        bytes,
        expected: None,
    }
}

fn invalid(label: &'static str, bytes: Vec<u8>, kind: &'static str, offset: usize) -> Vector {
    Vector {
        label,
        bytes,
        expected: Some((kind, offset)),
    }
}

fn fix_len(v: &mut [u8]) {
    let body_len = u32::try_from(v.len() - HEADER_LEN).unwrap();
    v[12..16].copy_from_slice(&body_len.to_be_bytes());
}

macro_rules! check {
    ($ty:ty, $name:expr, $title:expr, $schema:expr, $vectors:expr $(,)?) => {{
        let content = render($title, $schema, $vectors);
        check_file($name, &content);
        self_check(&content, |b| {
            let v: $ty = decode_object($schema, SCHEMA_VERSION_1, b)?;
            Ok(encode_to_vec($schema, SCHEMA_VERSION_1, &v))
        });
    }};
}

fn kind<'a, T: Decode<'a> + core::fmt::Debug>(
    schema: SchemaId,
    bytes: &'a [u8],
) -> (ErrorKind, usize) {
    let err = decode_object::<T>(schema, SCHEMA_VERSION_1, bytes).unwrap_err();
    (err.kind(), err.offset())
}

// --- bodies ----------------------------------------------------------------

fn handoff_parts(index: u32) -> CustodyHandoffParts<'static> {
    CustodyHandoffParts {
        election_id: e(),
        box_id: bx(),
        index,
        from_signer: signer(b"clerk-1"),
        from_org: org(b"NEC-11"),
        to_signer: signer(b"police-7"),
        to_org: org(b"POLICE-11"),
        previous_handoff_hash: if index == 1 {
            Hash512::ZERO
        } else {
            patterned64(0x40)
        },
        seal_digest: patterned64(0x41),
        count: 1_000,
        time_bucket: TimeBucket::new(901),
    }
}

fn handoff_bytes() -> Vec<u8> {
    let body = CustodyHandoffBody::new(&handoff_parts(1)).unwrap();
    encode_to_vec(SCHEMA_CUSTODY_HANDOFF_BODY, SCHEMA_VERSION_1, &body)
}

fn filing_parts() -> DisputeEventParts<'static> {
    DisputeEventParts {
        election_id: e(),
        action: DisputeAction::Filed,
        dispute_type: DisputeType::Custody,
        box_id: Some(bx()),
        record_hash: Some(patterned64(0x50)),
        evidence_hash: patterned64(0x51),
        filing_hash: Hash512::ZERO,
        result_hash: Hash512::ZERO,
        time_bucket: TimeBucket::new(950),
    }
}

fn dispute_bytes() -> Vec<u8> {
    let body = DisputeEventBody::new(&filing_parts()).unwrap();
    encode_to_vec(SCHEMA_DISPUTE_EVENT_BODY, SCHEMA_VERSION_1, &body)
}

fn legal_parts() -> LegalDecisionRefParts<'static> {
    LegalDecisionRefParts {
        election_id: e(),
        authority_id: org(b"SEOUL-HIGH-COURT"),
        decision_doc_hash: patterned64(0x60),
        dispute_hash: patterned64(0x61),
        outcome: LegalOutcome::Rejected,
        tally_effect: TallyEffect::NoEffect,
        decided_day: Day::new(120),
    }
}

fn legal_bytes() -> Vec<u8> {
    let body = LegalDecisionRefBody::new(&legal_parts()).unwrap();
    encode_to_vec(SCHEMA_LEGAL_DECISION_REF_BODY, SCHEMA_VERSION_1, &body)
}

fn modules() -> ModuleIds<'static> {
    ModuleIds::new(&[
        ModuleId::new(b"mod-X").unwrap(),
        ModuleId::new(b"mod-Y").unwrap(),
    ])
    .unwrap()
}

fn opened_bytes() -> Vec<u8> {
    let body = BoxOpenedBody::new(&BoxOpenedParts {
        election_id: e(),
        box_id: bx(),
        modules: modules(),
        seal_digest: patterned64(0x70),
        seals_match: true,
        initial_count: 0,
        time_bucket: TimeBucket::new(400),
    });
    encode_to_vec(SCHEMA_BOX_OPENED_BODY, SCHEMA_VERSION_1, &body)
}

fn fallback_parts() -> FallbackParts<'static> {
    FallbackParts {
        election_id: e(),
        box_id: bx(),
        kind: FallbackKind::Declared,
        reason: FallbackReason::ScannerFault,
        statement_hash: patterned64(0x71),
        markers: Some(MarkerRange {
            first: 5_000,
            last: 5_099,
        }),
        time_bucket: TimeBucket::new(500),
    }
}

fn fallback_bytes() -> Vec<u8> {
    let body = FallbackBody::new(&fallback_parts()).unwrap();
    encode_to_vec(SCHEMA_FALLBACK_BODY, SCHEMA_VERSION_1, &body)
}

fn issuance_bytes() -> Vec<u8> {
    let body = IssuanceCountBody::new(&IssuanceCountParts {
        election_id: e(),
        station_id: StationId::new(b"st-11-0042").unwrap(),
        stock_received: 1_200,
        issued: 1_010,
        voter_spoiled: 6,
        returned: 0,
        unused: 188,
        printer_waste: 2,
        envelopes: Some(EnvelopeIssuance {
            issued: 300,
            returned_empty: 4,
        }),
        time_bucket: TimeBucket::new(899),
    });
    encode_to_vec(SCHEMA_ISSUANCE_COUNT_BODY, SCHEMA_VERSION_1, &body)
}

fn imprint_bytes() -> Vec<u8> {
    let body = ImprintAuditBody::new(&ImprintAuditParts {
        election_id: e(),
        box_id: bx(),
        unimprinted: 10,
        duplicate_cast_ids: 0,
        time_bucket: TimeBucket::new(1_000),
    });
    encode_to_vec(SCHEMA_IMPRINT_AUDIT_BODY, SCHEMA_VERSION_1, &body)
}

fn seal_bytes() -> Vec<u8> {
    let body = SealChangeBody::new(&SealChangeParts {
        election_id: e(),
        box_id: bx(),
        reason: SealChangeReason::Inspection,
        previous_seal_digest: patterned64(0x41),
        new_seal_digest: patterned64(0x42),
        statement_hash: patterned64(0x43),
        time_bucket: TimeBucket::new(905),
    })
    .unwrap();
    encode_to_vec(SCHEMA_SEAL_CHANGE_BODY, SCHEMA_VERSION_1, &body)
}

fn late_batch_bytes() -> Vec<u8> {
    let body = LateBatchCloseBody::new(&LateBatchCloseParts {
        election_id: e(),
        box_id: bx(),
        batch_body_hash: patterned64(0x44),
        reason: LateBatchReason::DeviceRestart,
        time_bucket: TimeBucket::new(930),
    })
    .unwrap();
    encode_to_vec(SCHEMA_LATE_BATCH_CLOSE_BODY, SCHEMA_VERSION_1, &body)
}

#[test]
fn custody_handoff_vectors() {
    let bytes = handoff_bytes();
    let index_at = HEADER_LEN + ident_len(E) + ident_len(BOX);
    let previous_at = index_at
        + 4
        + ident_len(b"clerk-1")
        + ident_len(b"NEC-11")
        + ident_len(b"police-7")
        + ident_len(b"POLICE-11");
    let to_org_at = previous_at - ident_len(b"POLICE-11");
    let mut v = std::vec![valid("first handoff", bytes.clone())];
    let mut b = bytes.clone();
    b[index_at..index_at + 4].copy_from_slice(&0u32.to_be_bytes());
    v.push(invalid("index 0", b, "ValueOutOfRange", index_at));
    let mut b = bytes.clone();
    b[index_at..index_at + 4].copy_from_slice(&2u32.to_be_bytes());
    v.push(invalid(
        "index 2 with zero previous",
        b,
        "InvalidPreviousHash",
        previous_at,
    ));
    let same = CustodyHandoffParts {
        to_org: org(b"NEC-11"),
        ..handoff_parts(1)
    };
    assert!(CustodyHandoffBody::new(&same).is_err());
    let mut b = bytes.clone();
    // Rewrite the receiver's organisation to the sender's (same length).
    let sender = b"NEC-11";
    let to_body = to_org_at + 4;
    let mut spliced = b[..to_org_at].to_vec();
    spliced.extend_from_slice(&u32::try_from(sender.len()).unwrap().to_be_bytes());
    spliced.extend_from_slice(sender);
    spliced.extend_from_slice(&b[to_body + b"POLICE-11".len()..]);
    b = spliced;
    fix_len(&mut b);
    v.push(invalid(
        "sender and receiver of one organisation",
        b,
        "InvariantViolation",
        to_org_at,
    ));
    check!(
        CustodyHandoffBody<'_>,
        "custody_handoff_body.txt",
        "CustodyHandoffBody",
        SCHEMA_CUSTODY_HANDOFF_BODY,
        &v,
    );
}

#[test]
fn dispute_event_vectors() {
    let bytes = dispute_bytes();
    let action_at = HEADER_LEN + ident_len(E);
    let mut v = std::vec![valid("custody filing", bytes.clone())];
    let mut b = bytes.clone();
    b[action_at] = 5;
    v.push(invalid("action 5", b, "ValueOutOfRange", action_at));
    let mut b = bytes.clone();
    b[action_at + 1] = 9;
    v.push(invalid("type 9", b, "ValueOutOfRange", action_at + 1));
    let mut b = bytes.clone();
    b[action_at] = 2;
    let filing_at = action_at + 2 + 1 + ident_len(BOX) + 1 + 64 + 64;
    v.push(invalid(
        "investigation without filing hash",
        b,
        "InvalidPreviousHash",
        filing_at,
    ));
    check!(
        DisputeEventBody<'_>,
        "dispute_event_body.txt",
        "DisputeEventBody",
        SCHEMA_DISPUTE_EVENT_BODY,
        &v,
    );
}

#[test]
fn dispute_rules() {
    let resolved = DisputeEventParts {
        action: DisputeAction::ResolvedTechnical,
        filing_hash: patterned64(1),
        result_hash: patterned64(2),
        ..filing_parts()
    };
    assert!(DisputeEventBody::new(&resolved).is_ok());
    let no_result = DisputeEventParts {
        result_hash: Hash512::ZERO,
        ..resolved
    };
    assert!(DisputeEventBody::new(&no_result).is_err());
    let investigating_with_result = DisputeEventParts {
        action: DisputeAction::Investigating,
        ..resolved
    };
    assert!(DisputeEventBody::new(&investigating_with_result).is_err());
    let filed_with_previous = DisputeEventParts {
        filing_hash: patterned64(1),
        ..filing_parts()
    };
    assert!(DisputeEventBody::new(&filed_with_previous).is_err());
    let record_without_box = DisputeEventParts {
        box_id: None,
        ..filing_parts()
    };
    assert!(DisputeEventBody::new(&record_without_box).is_err());
    let neither = DisputeEventParts {
        box_id: None,
        record_hash: None,
        ..filing_parts()
    };
    let body = DisputeEventBody::new(&neither).unwrap();
    let bytes = encode_to_vec(SCHEMA_DISPUTE_EVENT_BODY, SCHEMA_VERSION_1, &body);
    let back: DisputeEventBody<'_> =
        decode_object(SCHEMA_DISPUTE_EVENT_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(back, body);
    for t in DisputeType::ALL {
        assert_eq!(DisputeType::from_code(t.code()), Some(*t));
    }
    for a in DisputeAction::ALL {
        assert_eq!(DisputeAction::from_code(a.code()), Some(*a));
    }
}

#[test]
fn legal_decision_vectors() {
    let bytes = legal_bytes();
    let hash_at = HEADER_LEN + ident_len(E) + ident_len(b"SEOUL-HIGH-COURT") + 64;
    let mut v = std::vec![valid("rejected, no tally effect", bytes.clone())];
    let mut b = bytes.clone();
    b[hash_at..hash_at + 64].fill(0);
    v.push(invalid(
        "zero dispute hash",
        b,
        "InvalidPreviousHash",
        hash_at,
    ));
    let mut b = bytes.clone();
    b[hash_at + 64] = 6;
    v.push(invalid("outcome 6", b, "ValueOutOfRange", hash_at + 64));
    let mut b = bytes.clone();
    b[hash_at + 65] = 3;
    v.push(invalid(
        "tally effect 3",
        b,
        "ValueOutOfRange",
        hash_at + 65,
    ));
    check!(
        LegalDecisionRefBody<'_>,
        "legal_decision_ref_body.txt",
        "LegalDecisionRefBody",
        SCHEMA_LEGAL_DECISION_REF_BODY,
        &v,
    );
    let zero = LegalDecisionRefParts {
        dispute_hash: Hash512::ZERO,
        ..legal_parts()
    };
    assert!(LegalDecisionRefBody::new(&zero).is_err());
    for o in LegalOutcome::ALL {
        assert_eq!(LegalOutcome::from_code(o.code()), Some(*o));
    }
    for t in TallyEffect::ALL {
        assert_eq!(TallyEffect::from_code(t.code()), Some(*t));
    }
}

#[test]
fn box_opened_vectors() {
    let bytes = opened_bytes();
    let modules_len = 4 + ident_len(b"mod-X") + ident_len(b"mod-Y");
    let match_at = HEADER_LEN + ident_len(E) + ident_len(BOX) + modules_len + 64;
    let mut v = std::vec![valid("clean opening", bytes.clone())];
    let mut b = bytes.clone();
    b[match_at] = 2;
    v.push(invalid("seals_match 2", b, "InvalidBool", match_at));
    check!(
        BoxOpenedBody<'_>,
        "box_opened_body.txt",
        "BoxOpenedBody",
        SCHEMA_BOX_OPENED_BODY,
        &v,
    );
}

#[test]
fn fallback_vectors() {
    let bytes = fallback_bytes();
    let kind_at = HEADER_LEN + ident_len(E) + ident_len(BOX);
    let mut v = std::vec![valid("declared, scanner fault, markers", bytes.clone())];
    let mut b = bytes.clone();
    b[kind_at + 1] = 0;
    v.push(invalid(
        "declared without reason",
        b,
        "InvariantViolation",
        kind_at + 1,
    ));
    let mut b = bytes.clone();
    b[kind_at] = 2;
    v.push(invalid(
        "ended with reason",
        b,
        "InvariantViolation",
        kind_at + 1,
    ));
    let markers_at = kind_at + 2 + 64 + 1;
    let mut b = bytes.clone();
    b[markers_at..markers_at + 8].copy_from_slice(&6_000u64.to_be_bytes());
    v.push(invalid(
        "marker range backwards",
        b,
        "InvariantViolation",
        markers_at,
    ));
    let mut b = bytes.clone();
    b[kind_at + 1] = 5;
    v.push(invalid("reason 5", b, "ValueOutOfRange", kind_at + 1));
    check!(
        FallbackBody<'_>,
        "fallback_body.txt",
        "FallbackBody",
        SCHEMA_FALLBACK_BODY,
        &v,
    );
    let ended = FallbackParts {
        kind: FallbackKind::Ended,
        reason: FallbackReason::NotApplicable,
        markers: None,
        ..fallback_parts()
    };
    assert!(FallbackBody::new(&ended).is_ok());
    let backwards = FallbackParts {
        markers: Some(MarkerRange { first: 2, last: 1 }),
        ..fallback_parts()
    };
    assert!(FallbackBody::new(&backwards).is_err());
    // A single marker is a range of one.
    let single = FallbackParts {
        markers: Some(MarkerRange { first: 7, last: 7 }),
        ..fallback_parts()
    };
    let body = FallbackBody::new(&single).unwrap();
    let bytes = encode_to_vec(SCHEMA_FALLBACK_BODY, SCHEMA_VERSION_1, &body);
    let back: FallbackBody<'_> =
        decode_object(SCHEMA_FALLBACK_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(back, body);
    let ended_with_reason = FallbackParts {
        kind: FallbackKind::Ended,
        ..fallback_parts()
    };
    assert!(FallbackBody::new(&ended_with_reason).is_err());
}

#[test]
fn issuance_imprint_seal_late_vectors() {
    let v = std::vec![valid("out-of-district station", issuance_bytes())];
    check!(
        IssuanceCountBody<'_>,
        "issuance_count_body.txt",
        "IssuanceCountBody",
        SCHEMA_ISSUANCE_COUNT_BODY,
        &v,
    );
    let v = std::vec![valid("ten without imprint", imprint_bytes())];
    check!(
        ImprintAuditBody<'_>,
        "imprint_audit_body.txt",
        "ImprintAuditBody",
        SCHEMA_IMPRINT_AUDIT_BODY,
        &v,
    );
    let bytes = seal_bytes();
    let reason_at = HEADER_LEN + ident_len(E) + ident_len(BOX);
    let mut v = std::vec![valid("inspection", bytes.clone())];
    let mut b = bytes.clone();
    b[reason_at] = 6;
    v.push(invalid("reason 6", b, "ValueOutOfRange", reason_at));
    let mut b = bytes.clone();
    let prev = b[reason_at + 1..reason_at + 65].to_vec();
    b[reason_at + 65..reason_at + 129].copy_from_slice(&prev);
    v.push(invalid(
        "same digest",
        b,
        "InvariantViolation",
        reason_at + 65,
    ));
    check!(
        SealChangeBody<'_>,
        "seal_change_body.txt",
        "SealChangeBody",
        SCHEMA_SEAL_CHANGE_BODY,
        &v,
    );
    let bytes = late_batch_bytes();
    let hash_at = HEADER_LEN + ident_len(E) + ident_len(BOX);
    let mut v = std::vec![valid("after restart", bytes.clone())];
    let mut b = bytes.clone();
    b[hash_at..hash_at + 64].fill(0);
    v.push(invalid(
        "zero batch hash",
        b,
        "InvalidPreviousHash",
        hash_at,
    ));
    let mut b = bytes.clone();
    b[hash_at + 64] = 0;
    v.push(invalid("reason 0", b, "ValueOutOfRange", hash_at + 64));
    check!(
        LateBatchCloseBody<'_>,
        "late_batch_close_body.txt",
        "LateBatchCloseBody",
        SCHEMA_LATE_BATCH_CLOSE_BODY,
        &v,
    );
    let same = SealChangeParts {
        election_id: e(),
        box_id: bx(),
        reason: SealChangeReason::Broken,
        previous_seal_digest: patterned64(1),
        new_seal_digest: patterned64(1),
        statement_hash: patterned64(2),
        time_bucket: TimeBucket::new(1),
    };
    assert!(SealChangeBody::new(&same).is_err());
    let zero = LateBatchCloseParts {
        election_id: e(),
        box_id: bx(),
        batch_body_hash: Hash512::ZERO,
        reason: LateBatchReason::Other,
        time_bucket: TimeBucket::new(1),
    };
    assert!(LateBatchCloseBody::new(&zero).is_err());
    for r in SealChangeReason::ALL {
        assert_eq!(SealChangeReason::from_code(r.code()), Some(*r));
    }
    for r in LateBatchReason::ALL {
        assert_eq!(LateBatchReason::from_code(r.code()), Some(*r));
    }
    for r in FallbackReason::ALL {
        assert_eq!(FallbackReason::from_code(r.code()), Some(*r));
    }
    for k in FallbackKind::ALL {
        assert_eq!(FallbackKind::from_code(k.code()), Some(*k));
    }
}

// --- WitnessedEvent --------------------------------------------------------

fn sig(
    id: &'static [u8],
    role: EventRole,
    o: &'static [u8],
    s: &'static [u8; HYBRID_SIG_LEN],
) -> EventSig<'static> {
    EventSig {
        signer_id: signer(id),
        role,
        org_id: org(o),
        sig: s,
    }
}

fn witnesses() -> [EventSig<'static>; 4] {
    [
        sig(b"c1", EventRole::Clerk, b"NEC-11", &SIG_A),
        sig(b"c2", EventRole::Clerk, b"NEC-11", &SIG_B),
        sig(b"o1", EventRole::Observer, b"PARTY-A", &SIG_C),
        sig(b"o2", EventRole::Observer, b"PARTY-B", &SIG_D),
    ]
}

fn event_bytes(body: &[u8], sigs: &[EventSig<'_>]) -> Vec<u8> {
    let event = WitnessedEvent::new(body, sigs).unwrap();
    encode_to_vec(SCHEMA_WITNESSED_EVENT, SCHEMA_VERSION_1, &event)
}

#[test]
fn witnessed_event_vectors() {
    let opened = opened_bytes();
    let mut sigs = std::vec![sig(b"box-11-0042", EventRole::Device, b"NEC-11", &SIG_E)];
    sigs.extend_from_slice(&witnesses());
    sigs.sort_by(|a, b| a.signer_id.as_bytes().cmp(b.signer_id.as_bytes()));
    let bytes = event_bytes(&opened, &sigs);
    let sigs_at = HEADER_LEN + 4 + opened.len();
    let mut v = std::vec![valid(
        "box opened: device, two clerks, two observers",
        bytes.clone()
    )];
    // Second signature's role byte: a clerk turned observer of the first
    // observer's organisation leaves one clerk.
    let first = 4 + ident_len(b"box-11-0042") + 1 + ident_len(b"NEC-11") + HYBRID_SIG_LEN;
    let c1_role_at = sigs_at + first + ident_len(b"c1");
    let mut b = bytes.clone();
    b[c1_role_at] = EventRole::Observer.code();
    v.push(invalid("one clerk", b, "InvariantViolation", sigs_at));
    let mut b = bytes.clone();
    b[c1_role_at] = 9;
    v.push(invalid("role 9", b, "ValueOutOfRange", c1_role_at));
    let mut b = bytes.clone();
    b[c1_role_at] = EventRole::Commission.code();
    v.push(invalid(
        "commission on a box opening",
        b,
        "InvariantViolation",
        sigs_at,
    ));
    check!(
        WitnessedEvent<'_>,
        "witnessed_event.txt",
        "WitnessedEvent",
        SCHEMA_WITNESSED_EVENT,
        &v,
    );
}

#[test]
fn witnessed_role_rules() {
    let w = witnesses();
    let device = sig(b"box-11-0042", EventRole::Device, b"NEC-11", &SIG_E);
    // A box opening needs the device.
    assert!(WitnessedEvent::new(&opened_bytes(), &w).is_err());
    let mut with_device = std::vec![device];
    with_device.extend_from_slice(&w);
    with_device.sort_by(|a, b| a.signer_id.as_bytes().cmp(b.signer_id.as_bytes()));
    assert!(WitnessedEvent::new(&opened_bytes(), &with_device).is_ok());
    // Clerk-and-observer events.
    for body in [
        fallback_bytes(),
        issuance_bytes(),
        imprint_bytes(),
        seal_bytes(),
        late_batch_bytes(),
    ] {
        let event = WitnessedEvent::new(&body, &w).unwrap();
        assert_eq!(event.sig_count(), 4);
        let bytes = encode_to_vec(SCHEMA_WITNESSED_EVENT, SCHEMA_VERSION_1, &event);
        let back: WitnessedEvent<'_> =
            decode_object(SCHEMA_WITNESSED_EVENT, SCHEMA_VERSION_1, &bytes).unwrap();
        assert_eq!(back, event);
        assert!(WitnessedEvent::new(&body, &with_device).is_err());
        assert!(WitnessedEvent::new(&body, &w[..3]).is_err());
        // Observers of one organisation are one.
        let one_org = [
            w[0],
            w[1],
            sig(b"o1", EventRole::Observer, b"PARTY-A", &SIG_C),
            sig(b"o2", EventRole::Observer, b"PARTY-A", &SIG_D),
        ];
        assert!(WitnessedEvent::new(&body, &one_org).is_err());
        // Not ascending.
        let swapped = [w[1], w[0], w[2], w[3]];
        assert!(WitnessedEvent::new(&body, &swapped).is_err());
    }
    // Custody: exactly a sender and a receiver.
    let pair = [
        sig(b"clerk-1", EventRole::Sender, b"NEC-11", &SIG_A),
        sig(b"police-7", EventRole::Receiver, b"POLICE-11", &SIG_B),
    ];
    let handoff_body = handoff_bytes();
    let event = WitnessedEvent::new(&handoff_body, &pair).unwrap();
    assert_eq!(event.purpose(), b"handoff");
    let handoff: CustodyHandoffBody<'_> = event.body(SCHEMA_CUSTODY_HANDOFF_BODY).unwrap();
    assert_eq!(handoff.parts().index, 1);
    assert_eq!(
        event
            .body::<DisputeEventBody<'_>>(SCHEMA_DISPUTE_EVENT_BODY)
            .unwrap_err()
            .kind(),
        ErrorKind::SchemaMismatch
    );
    assert!(WitnessedEvent::new(&handoff_bytes(), &pair[..1]).is_err());
    assert!(WitnessedEvent::new(&handoff_bytes(), &w).is_err());
    // Dispute: exactly the commission and the committee.
    let bodies = [
        sig(b"ivc", EventRole::Committee, b"IVC", &SIG_A),
        sig(b"nec", EventRole::Commission, b"NEC", &SIG_B),
    ];
    assert!(WitnessedEvent::new(&dispute_bytes(), &bodies).is_ok());
    let twice = [
        sig(b"ivc", EventRole::Committee, b"IVC", &SIG_A),
        sig(b"ivc2", EventRole::Committee, b"IVC", &SIG_B),
    ];
    assert!(WitnessedEvent::new(&dispute_bytes(), &twice).is_err());
    // Legal decision: exactly one authority.
    let court = [sig(
        b"court",
        EventRole::Authority,
        b"SEOUL-HIGH-COURT",
        &SIG_A,
    )];
    assert!(WitnessedEvent::new(&legal_bytes(), &court).is_ok());
    assert!(WitnessedEvent::new(&legal_bytes(), &bodies).is_err());
    // A body schema the envelope does not carry.
    let mut other = legal_bytes();
    other[4..8].copy_from_slice(&0x0003u32.to_be_bytes());
    assert_eq!(
        WitnessedEvent::new(&other, &court).unwrap_err().kind(),
        ErrorKind::SchemaMismatch
    );
    // Every carried schema has a purpose; others have none.
    for s in WITNESSED_BODY_SCHEMAS {
        assert!(purpose_of(s).is_some());
    }
    assert!(purpose_of(SchemaId::new(0x0007)).is_none());
    // The body bound: over 2048 bytes is refused by length; exactly 2048
    // bytes passes the length check and fails as an object.
    let long = std::vec![0u8; 2049];
    assert_eq!(
        WitnessedEvent::new(&long, &court).unwrap_err().kind(),
        ErrorKind::LengthExceedsMax
    );
    let at_max = std::vec![0u8; 2048];
    assert_ne!(
        WitnessedEvent::new(&at_max, &court).unwrap_err().kind(),
        ErrorKind::LengthExceedsMax
    );
    // Embedded body errors are rebased into the envelope.
    let mut body = late_batch_bytes();
    let hash_at = HEADER_LEN + ident_len(E) + ident_len(BOX);
    body[hash_at..hash_at + 64].fill(0);
    let mut env = std::vec![0u8; 0];
    env.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
    env.extend_from_slice(&body);
    env.extend_from_slice(&0u32.to_be_bytes());
    let mut obj = std::vec![0u8; HEADER_LEN];
    obj[..4].copy_from_slice(b"ITYV");
    obj[4..8].copy_from_slice(&0x0028u32.to_be_bytes());
    obj[8..10].copy_from_slice(&1u16.to_be_bytes());
    obj.extend_from_slice(&env);
    fix_len(&mut obj);
    let (k, at) = kind::<WitnessedEvent<'_>>(SCHEMA_WITNESSED_EVENT, &obj);
    assert_eq!(k, ErrorKind::InvalidPreviousHash);
    assert_eq!(at, HEADER_LEN + 4 + hash_at);
}

// --- genesis entries -------------------------------------------------------

fn round_trip<'a, T: Encode + Decode<'a> + PartialEq + core::fmt::Debug>(
    value: &T,
    buf: &'a mut Vec<u8>,
) -> T {
    buf.resize(value.encoded_len(), 0);
    let mut w = Writer::new(buf);
    value.encode(&mut w).unwrap();
    assert_eq!(w.position(), value.encoded_len());
    let mut r = Reader::new(buf);
    let back = T::decode(&mut r).unwrap();
    r.finish().unwrap();
    back
}

#[test]
fn genesis_entries() {
    let entry = GenesisBox {
        box_id: bx(),
        station_id: StationId::new(b"st-11-0042").unwrap(),
        ballot_style_id: BallotStyleId::new(b"pres-2030").unwrap(),
        profile: CaptureProfile::Absentee,
        route_id: RouteId::new(b"route-11").unwrap(),
        device_key: &VK,
        modules: modules(),
    };
    let mut buf = Vec::new();
    assert_eq!(round_trip(&entry, &mut buf), entry);
    let route = CustodyRoute::new(
        RouteId::new(b"route-11").unwrap(),
        false,
        &[org(b"NEC-11"), org(b"POLICE-11"), org(b"CENTRE-11")],
    )
    .unwrap();
    let mut buf = Vec::new();
    assert_eq!(round_trip(&route, &mut buf), route);
    assert_eq!(route.stop_count(), 3);
    assert_eq!(route.stop(2), Some(org(b"CENTRE-11")));
    assert_eq!(route.stop(3), None);
    assert!(!route.count_at_origin());
    // Two stops, counted at origin, survive a round trip.
    let short = CustodyRoute::new(
        RouteId::new(b"route-12").unwrap(),
        true,
        &[org(b"NEC-12"), org(b"CENTRE-12")],
    )
    .unwrap();
    assert!(short.count_at_origin());
    let mut buf = Vec::new();
    let back = round_trip(&short, &mut buf);
    assert_eq!(back, short);
    assert!(back.count_at_origin());
    assert_eq!(back.stop_count(), 2);
    assert!(CustodyRoute::new(RouteId::new(b"r").unwrap(), false, &[org(b"A")]).is_err());
    assert!(
        CustodyRoute::new(RouteId::new(b"r").unwrap(), false, &[org(b"A"), org(b"A")]).is_err()
    );
    // The decoder refuses a repeated stop and a one-stop route.
    let mut bytes = std::vec![0u8; 0];
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.push(b'r');
    bytes.push(0);
    bytes.extend_from_slice(&2u32.to_be_bytes());
    for _ in 0..2 {
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(b'A');
    }
    let err = CustodyRoute::decode(&mut Reader::new(&bytes)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvariantViolation);
    assert_eq!(err.offset(), 4 + 1 + 1 + 4 + 5);
    let mut one = bytes[..6].to_vec();
    one.extend_from_slice(&1u32.to_be_bytes());
    one.extend_from_slice(&1u32.to_be_bytes());
    one.push(b'A');
    let err = CustodyRoute::decode(&mut Reader::new(&one)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvariantViolation);
    let person = RosterSigner {
        signer_id: signer(b"c1"),
        role: RosterRole::Clerk,
        org_id: org(b"NEC-11"),
        station_id: Some(StationId::new(b"st-11-0042").unwrap()),
        key: &VK,
        appointment_hash: patterned64(0x77),
    };
    let mut buf = Vec::new();
    assert_eq!(round_trip(&person, &mut buf), person);
    let custodian = RosterSigner {
        role: RosterRole::Custodian,
        station_id: None,
        ..person
    };
    let mut buf = Vec::new();
    assert_eq!(round_trip(&custodian, &mut buf), custodian);
    let unappointed = RosterSigner {
        appointment_hash: Hash512::ZERO,
        ..person
    };
    let mut buf = std::vec![0u8; unappointed.encoded_len()];
    unappointed.encode(&mut Writer::new(&mut buf)).unwrap();
    let err = RosterSigner::decode(&mut Reader::new(&buf)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidPreviousHash);
    for (code, profile) in [
        (1, CaptureProfile::InPerson),
        (2, CaptureProfile::Absentee),
        (3, CaptureProfile::ReceiptScan),
    ] {
        assert_eq!(CaptureProfile::from_code(code), Some(profile));
        assert_eq!(profile.code(), code);
    }
    assert_eq!(CaptureProfile::from_code(4), None);
    for (code, role) in [
        (1, RosterRole::Clerk),
        (2, RosterRole::Observer),
        (3, RosterRole::Custodian),
    ] {
        assert_eq!(RosterRole::from_code(code), Some(role));
        assert_eq!(role.code(), code);
    }
    assert_eq!(RosterRole::from_code(0), None);
    let _ = patterned::<1>(0);
}

#[test]
fn envelopes_expected_in_box() {
    let e = |issued, returned_empty| EnvelopeIssuance {
        issued,
        returned_empty,
    };
    assert_eq!(e(10, 3).expected_in_box(), Some(7));
    assert_eq!(e(5, 5).expected_in_box(), Some(0));
    assert_eq!(e(3, 4).expected_in_box(), None);
}

#[test]
fn every_role_code() {
    for code in 0u8..=255 {
        match EventRole::from_code(code) {
            Some(role) => assert_eq!(role.code(), code),
            None => assert!(code == 0 || code > 8),
        }
    }
}
