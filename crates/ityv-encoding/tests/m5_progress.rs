//! The voting progress record (ADR-0027): `BoxProgressBody` (0x002F),
//! `CheckinProgressBody` (0x0030), `ProgressTick` (0x0031),
//! `ProgressCheckBody` (0x0032) and the genesis `StationProgressPolicy`:
//! golden vectors (ENCODING.md §7), round trips and one rejection per
//! rule. Signatures are patterned bytes.
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

use common::{Vector, check_file, encode_to_vec, ident_len, patterned64, render, self_check};
use ityv_encoding::{
    BoxId, BoxProgressBody, BoxProgressParts, BoxProgressState, CheckinProgressBody,
    CheckinProgressParts, CheckinProgressState, Decode, ElectionId, Encode, ErrorKind, EventRole,
    EventSig, HEADER_LEN, HYBRID_SIG_LEN, ImprintAuditBody, ImprintAuditParts,
    MAX_PROGRESS_BODY_LEN, OrgId, PURPOSE_BOX_PROGRESS, PURPOSE_CHECKIN_PROGRESS, ProgressAlarm,
    ProgressBody, ProgressCheckBody, ProgressCheckParts, ProgressFinding, ProgressTick, Reader,
    SCHEMA_BOX_PROGRESS_BODY, SCHEMA_CHECKIN_PROGRESS_BODY, SCHEMA_IMPRINT_AUDIT_BODY,
    SCHEMA_PROGRESS_CHECK_BODY, SCHEMA_PROGRESS_TICK, SCHEMA_VERSION_1, SCHEMA_WITNESSED_EVENT,
    SchemaId, SignerId, StationId, StationProgressPolicy, TimeBucket, UnitId,
    WITNESSED_BODY_SCHEMAS, WitnessedEvent, Writer, decode_object, purpose_of,
};
use proptest::prelude::*;
use std::vec::Vec;

const E: &[u8] = b"KR-2030-PRES";
const BOX: &[u8] = b"box-11-0042";
const ST: &[u8] = b"st-11-0042";
const UNIT: &[u8] = b"unit-11-0042";

static SIG_A: [u8; HYBRID_SIG_LEN] = [0xA1; HYBRID_SIG_LEN];
static SIG_B: [u8; HYBRID_SIG_LEN] = [0xB2; HYBRID_SIG_LEN];
static SIG_C: [u8; HYBRID_SIG_LEN] = [0xC3; HYBRID_SIG_LEN];
static SIG_D: [u8; HYBRID_SIG_LEN] = [0xD4; HYBRID_SIG_LEN];
static SIG_T: [u8; HYBRID_SIG_LEN] = [0x7E; HYBRID_SIG_LEN];

fn e() -> ElectionId<'static> {
    ElectionId::new(E).unwrap()
}

fn st() -> StationId<'static> {
    StationId::new(ST).unwrap()
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

fn box_parts() -> BoxProgressParts<'static> {
    BoxProgressParts {
        election_id: e(),
        box_id: BoxId::new(BOX).unwrap(),
        slot: 4_321,
        sheets_in: 405,
        state: BoxProgressState::Casting,
    }
}

fn box_bytes() -> Vec<u8> {
    let body = BoxProgressBody::new(&box_parts());
    encode_to_vec(SCHEMA_BOX_PROGRESS_BODY, SCHEMA_VERSION_1, &body)
}

fn checkin_parts() -> CheckinProgressParts<'static> {
    CheckinProgressParts {
        election_id: e(),
        station_id: st(),
        unit_id: UnitId::new(UNIT).unwrap(),
        slot: 4_321,
        checkins: 203,
        issued: 412,
        spoiled: 2,
        returned: 1,
        state: CheckinProgressState::Checking,
    }
}

fn checkin_bytes() -> Vec<u8> {
    let body = CheckinProgressBody::new(&checkin_parts()).unwrap();
    encode_to_vec(SCHEMA_CHECKIN_PROGRESS_BODY, SCHEMA_VERSION_1, &body)
}

fn check_parts(finding: ProgressFinding, carried_out: u64) -> ProgressCheckParts<'static> {
    ProgressCheckParts {
        election_id: e(),
        station_id: st(),
        alarm_slot: 4_318,
        alarm: ProgressAlarm::Floor,
        holding: 0,
        finding,
        carried_out,
        statement_hash: patterned64(0x51),
        time_bucket: TimeBucket::new(2_881),
    }
}

fn check_bytes(finding: ProgressFinding, carried_out: u64) -> Vec<u8> {
    let body = ProgressCheckBody::new(&check_parts(finding, carried_out)).unwrap();
    encode_to_vec(SCHEMA_PROGRESS_CHECK_BODY, SCHEMA_VERSION_1, &body)
}

fn tick_bytes(body: &[u8]) -> Vec<u8> {
    let tick = ProgressTick::new(body, &SIG_T).unwrap();
    encode_to_vec(SCHEMA_PROGRESS_TICK, SCHEMA_VERSION_1, &tick)
}

/// Offset of the first `u64` after the election and the second
/// identifier.
fn after_ids(second: &[u8]) -> usize {
    HEADER_LEN + ident_len(E) + ident_len(second)
}

#[test]
fn box_progress_vectors() {
    let bytes = box_bytes();
    let state_at = after_ids(BOX) + 16;
    let mut v = std::vec![valid("casting, 405 sheets in", bytes.clone())];
    let closed = BoxProgressBody::new(&BoxProgressParts {
        state: BoxProgressState::Closed,
        ..box_parts()
    });
    v.push(valid(
        "closed",
        encode_to_vec(SCHEMA_BOX_PROGRESS_BODY, SCHEMA_VERSION_1, &closed),
    ));
    for (label, code) in [("state 0", 0u8), ("state 4", 4)] {
        let mut b = bytes.clone();
        b[state_at] = code;
        v.push(invalid(label, b, "ValueOutOfRange", state_at));
    }
    check!(
        BoxProgressBody<'_>,
        "box_progress_body.txt",
        "BoxProgressBody",
        SCHEMA_BOX_PROGRESS_BODY,
        &v,
    );
    let back: BoxProgressBody<'_> =
        decode_object(SCHEMA_BOX_PROGRESS_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(*back.parts(), box_parts());
}

#[test]
fn checkin_progress_vectors() {
    let bytes = checkin_bytes();
    let counts_at = HEADER_LEN + ident_len(E) + ident_len(ST) + ident_len(UNIT) + 8;
    let issued_at = counts_at + 8;
    let spoiled_at = issued_at + 8;
    let returned_at = spoiled_at + 8;
    let state_at = returned_at + 8;
    let mut v = std::vec![valid("412 issued, 2 spoiled, 1 returned", bytes.clone())];
    // spoiled 413 > issued 412.
    let mut b = bytes.clone();
    b[spoiled_at..spoiled_at + 8].copy_from_slice(&413u64.to_be_bytes());
    v.push(invalid(
        "spoiled above issued",
        b,
        "InvariantViolation",
        spoiled_at,
    ));
    // spoiled 2 + returned 411 = 413 > 412.
    let mut b = bytes.clone();
    b[returned_at..returned_at + 8].copy_from_slice(&411u64.to_be_bytes());
    v.push(invalid(
        "spoiled and returned above issued",
        b,
        "InvariantViolation",
        returned_at,
    ));
    // spoiled + returned overflows.
    let mut b = bytes.clone();
    b[issued_at..issued_at + 8].copy_from_slice(&u64::MAX.to_be_bytes());
    b[spoiled_at..spoiled_at + 8].copy_from_slice(&u64::MAX.to_be_bytes());
    v.push(invalid(
        "sum overflows",
        b,
        "InvariantViolation",
        returned_at,
    ));
    let mut b = bytes.clone();
    b[state_at] = 4;
    v.push(invalid("state 4", b, "ValueOutOfRange", state_at));
    check!(
        CheckinProgressBody<'_>,
        "checkin_progress_body.txt",
        "CheckinProgressBody",
        SCHEMA_CHECKIN_PROGRESS_BODY,
        &v,
    );
    let back: CheckinProgressBody<'_> =
        decode_object(SCHEMA_CHECKIN_PROGRESS_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(*back.parts(), checkin_parts());
    // Exactly at the bound is accepted.
    let edge = CheckinProgressParts {
        issued: 3,
        spoiled: 2,
        returned: 1,
        ..checkin_parts()
    };
    assert!(CheckinProgressBody::new(&edge).is_ok());
    let over = CheckinProgressParts {
        returned: 2,
        ..edge
    };
    assert_eq!(
        CheckinProgressBody::new(&over).unwrap_err().kind(),
        ErrorKind::InvariantViolation
    );
    let overflow = CheckinProgressParts {
        issued: u64::MAX,
        spoiled: u64::MAX,
        returned: 1,
        ..checkin_parts()
    };
    assert!(!overflow.sheets_consistent());
}

#[test]
fn progress_tick_vectors() {
    let boxed = tick_bytes(&box_bytes());
    let checkin = tick_bytes(&checkin_bytes());
    let mut v = std::vec![
        valid("box tick", boxed.clone()),
        valid("check-in tick", checkin.clone()),
    ];
    // Another schema inside: an imprint audit body.
    let imprint = ImprintAuditBody::new(&ImprintAuditParts {
        election_id: e(),
        box_id: BoxId::new(BOX).unwrap(),
        unimprinted: 0,
        duplicate_cast_ids: 0,
        time_bucket: TimeBucket::new(1),
    });
    let imprint = encode_to_vec(SCHEMA_IMPRINT_AUDIT_BODY, SCHEMA_VERSION_1, &imprint);
    let mut b = Vec::new();
    {
        let mut w = Vec::new();
        w.extend_from_slice(&u32::try_from(imprint.len()).unwrap().to_be_bytes());
        w.extend_from_slice(&imprint);
        w.extend_from_slice(&SIG_T);
        b.extend_from_slice(&boxed[..HEADER_LEN]);
        b.extend_from_slice(&w);
        let body_len = u32::try_from(b.len() - HEADER_LEN).unwrap();
        b[12..16].copy_from_slice(&body_len.to_be_bytes());
    }
    v.push(invalid(
        "imprint audit inside",
        b,
        "SchemaMismatch",
        HEADER_LEN + 4 + 4,
    ));
    // A malformed box body inside: state 9.
    let mut b = boxed.clone();
    let inner_state = after_ids(BOX) + 16;
    b[HEADER_LEN + 4 + inner_state] = 9;
    v.push(invalid(
        "box state 9 inside",
        b,
        "ValueOutOfRange",
        HEADER_LEN + 4 + inner_state,
    ));
    check!(
        ProgressTick<'_>,
        "progress_tick.txt",
        "ProgressTick",
        SCHEMA_PROGRESS_TICK,
        &v,
    );

    let box_body = box_bytes();
    let tick = ProgressTick::new(&box_body, &SIG_T).unwrap();
    assert_eq!(tick.purpose(), PURPOSE_BOX_PROGRESS);
    assert_eq!(tick.body_bytes(), box_body.as_slice());
    assert_eq!(tick.sig(), &SIG_T);
    assert_eq!(tick.body().slot(), 4_321);
    assert!(matches!(tick.body(), ProgressBody::Box(b) if *b.parts() == box_parts()));
    let checkin_body = checkin_bytes();
    let tick = ProgressTick::new(&checkin_body, &SIG_T).unwrap();
    assert_eq!(tick.purpose(), PURPOSE_CHECKIN_PROGRESS);
    assert_eq!(tick.body().slot(), 4_321);
    assert!(matches!(tick.body(), ProgressBody::Checkin(c) if *c.parts() == checkin_parts()));
    assert_eq!(PURPOSE_BOX_PROGRESS, b"box-progress");
    assert_eq!(PURPOSE_CHECKIN_PROGRESS, b"checkin-progress");
    // Constructor errors.
    assert_eq!(
        ProgressTick::new(&imprint, &SIG_T).unwrap_err().kind(),
        ErrorKind::SchemaMismatch
    );
    let mut long = box_body.clone();
    long.resize(MAX_PROGRESS_BODY_LEN + 1, 0);
    assert_eq!(
        ProgressTick::new(&long, &SIG_T).unwrap_err().kind(),
        ErrorKind::LengthExceedsMax
    );
    let mut exact = box_body.clone();
    exact.resize(MAX_PROGRESS_BODY_LEN, 0);
    // At the limit the length is fine; the trailing zeros fail decoding.
    assert_ne!(
        ProgressTick::new(&exact, &SIG_T).unwrap_err().kind(),
        ErrorKind::LengthExceedsMax
    );
    // encoded_len matches the encoding.
    let tick = ProgressTick::new(&box_body, &SIG_T).unwrap();
    assert_eq!(
        encode_to_vec(SCHEMA_PROGRESS_TICK, SCHEMA_VERSION_1, &tick).len(),
        HEADER_LEN + tick.encoded_len()
    );
}

#[test]
fn progress_check_vectors() {
    let explained = check_bytes(ProgressFinding::Explained, 0);
    let carried = check_bytes(ProgressFinding::CarriedOut, 1);
    let alarm_at = after_ids(ST) + 8;
    let finding_at = alarm_at + 1 + 8;
    let carried_at = finding_at + 1;
    let mut v = std::vec![
        valid("floor, explained", explained.clone()),
        valid("floor, one sheet carried out", carried.clone()),
    ];
    let mut b = carried.clone();
    b[carried_at..carried_at + 8].copy_from_slice(&0u64.to_be_bytes());
    v.push(invalid(
        "carried out without sheets",
        b,
        "InvariantViolation",
        carried_at,
    ));
    let mut b = explained.clone();
    b[carried_at..carried_at + 8].copy_from_slice(&3u64.to_be_bytes());
    v.push(invalid(
        "explained with sheets",
        b,
        "InvariantViolation",
        carried_at,
    ));
    let mut b = explained.clone();
    b[alarm_at] = 4;
    v.push(invalid("alarm 4", b, "ValueOutOfRange", alarm_at));
    let mut b = explained.clone();
    b[finding_at] = 5;
    v.push(invalid("finding 5", b, "ValueOutOfRange", finding_at));
    check!(
        ProgressCheckBody<'_>,
        "progress_check_body.txt",
        "ProgressCheckBody",
        SCHEMA_PROGRESS_CHECK_BODY,
        &v,
    );
    let back: ProgressCheckBody<'_> =
        decode_object(SCHEMA_PROGRESS_CHECK_BODY, SCHEMA_VERSION_1, &carried).unwrap();
    assert_eq!(*back.parts(), check_parts(ProgressFinding::CarriedOut, 1));
    for finding in ProgressFinding::ALL {
        let ok = u64::from(*finding == ProgressFinding::CarriedOut);
        assert!(ProgressCheckBody::new(&check_parts(*finding, ok)).is_ok());
        assert_eq!(
            ProgressCheckBody::new(&check_parts(*finding, 1 - ok))
                .unwrap_err()
                .kind(),
            ErrorKind::InvariantViolation
        );
    }
    let mut b = explained.clone();
    b[carried_at..carried_at + 8].copy_from_slice(&3u64.to_be_bytes());
    assert_eq!(
        kind::<ProgressCheckBody<'_>>(SCHEMA_PROGRESS_CHECK_BODY, &b),
        (ErrorKind::InvariantViolation, carried_at)
    );
}

fn sig(
    id: &'static [u8],
    role: EventRole,
    o: &'static [u8],
    s: &'static [u8; HYBRID_SIG_LEN],
) -> EventSig<'static> {
    EventSig {
        signer_id: SignerId::new(id).unwrap(),
        role,
        org_id: OrgId::new(o).unwrap(),
        sig: s,
    }
}

#[test]
fn progress_check_in_witnessed_event() {
    let body = check_bytes(ProgressFinding::Explained, 0);
    let witnesses = [
        sig(b"c1", EventRole::Clerk, b"NEC-11", &SIG_A),
        sig(b"c2", EventRole::Clerk, b"NEC-11", &SIG_B),
        sig(b"o1", EventRole::Observer, b"PARTY-A", &SIG_C),
        sig(b"o2", EventRole::Observer, b"PARTY-B", &SIG_D),
    ];
    let event = WitnessedEvent::new(&body, &witnesses).unwrap();
    assert_eq!(event.purpose(), b"progress-check");
    assert_eq!(event.body_schema(), SCHEMA_PROGRESS_CHECK_BODY);
    let bytes = encode_to_vec(SCHEMA_WITNESSED_EVENT, SCHEMA_VERSION_1, &event);
    let back: WitnessedEvent<'_> =
        decode_object(SCHEMA_WITNESSED_EVENT, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(back, event);
    // One clerk, one observer organisation, or a device: refused.
    assert!(WitnessedEvent::new(&body, &witnesses[1..]).is_err());
    let same_org = [
        witnesses[0],
        witnesses[1],
        sig(b"o1", EventRole::Observer, b"PARTY-A", &SIG_C),
        sig(b"o2", EventRole::Observer, b"PARTY-A", &SIG_D),
    ];
    assert!(WitnessedEvent::new(&body, &same_org).is_err());
    let with_device = [
        witnesses[0],
        witnesses[1],
        sig(b"d", EventRole::Device, b"NEC-11", &SIG_T),
        witnesses[2],
        witnesses[3],
    ];
    assert!(WitnessedEvent::new(&body, &with_device).is_err());
    assert!(WITNESSED_BODY_SCHEMAS.contains(&SCHEMA_PROGRESS_CHECK_BODY));
    assert_eq!(
        purpose_of(SCHEMA_PROGRESS_CHECK_BODY),
        Some(&b"progress-check"[..])
    );
    // The device-signed bodies never travel in a witnessed event.
    assert!(purpose_of(SCHEMA_BOX_PROGRESS_BODY).is_none());
    assert!(purpose_of(SCHEMA_CHECKIN_PROGRESS_BODY).is_none());
    assert!(WitnessedEvent::new(&box_bytes(), &witnesses).is_err());
}

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
fn station_progress_policy() {
    let policy = StationProgressPolicy::new(st(), 6, 84).unwrap();
    assert_eq!(policy.station_id(), st());
    assert_eq!(policy.booth_count(), 6);
    assert_eq!(policy.limit_sheets(), 84);
    let mut buf = Vec::new();
    assert_eq!(round_trip(&policy, &mut buf), policy);
    for (booths, limit) in [(0u16, 84u32), (6, 0), (0, 0)] {
        assert_eq!(
            StationProgressPolicy::new(st(), booths, limit)
                .unwrap_err()
                .kind(),
            ErrorKind::ValueOutOfRange
        );
    }
    let booth_at = ident_len(ST);
    let mut bad = buf.clone();
    bad[booth_at..booth_at + 2].copy_from_slice(&0u16.to_be_bytes());
    let err = StationProgressPolicy::decode(&mut Reader::new(&bad)).unwrap_err();
    assert_eq!(
        (err.kind(), err.offset()),
        (ErrorKind::ValueOutOfRange, booth_at)
    );
    let mut bad = buf.clone();
    bad[booth_at + 2..booth_at + 6].copy_from_slice(&0u32.to_be_bytes());
    let err = StationProgressPolicy::decode(&mut Reader::new(&bad)).unwrap_err();
    assert_eq!(
        (err.kind(), err.offset()),
        (ErrorKind::ValueOutOfRange, booth_at + 2)
    );
    // One booth, one sheet: the smallest valid policy.
    let small = StationProgressPolicy::new(st(), 1, 1).unwrap();
    let mut buf = Vec::new();
    assert_eq!(round_trip(&small, &mut buf), small);
}

proptest! {
    /// Every valid check-in progress body survives an object round trip,
    /// and a body whose counts break the rule is refused by both the
    /// constructor and the decoder.
    #[test]
    fn checkin_progress_round_trip(
        unit in common::ident_bytes(64),
        slot in any::<u64>(),
        checkins in any::<u64>(),
        issued in any::<u64>(),
        spoiled in any::<u64>(),
        returned in any::<u64>(),
        state in 1u8..=3,
    ) {
        let parts = CheckinProgressParts {
            unit_id: UnitId::new(&unit).unwrap(),
            slot,
            checkins,
            issued,
            spoiled,
            returned,
            state: CheckinProgressState::from_code(state).unwrap(),
            ..checkin_parts()
        };
        let ok = u128::from(spoiled) + u128::from(returned) <= u128::from(issued);
        match CheckinProgressBody::new(&parts) {
            Ok(body) => {
                prop_assert!(ok);
                let bytes = encode_to_vec(SCHEMA_CHECKIN_PROGRESS_BODY, SCHEMA_VERSION_1, &body);
                let back: CheckinProgressBody<'_> =
                    decode_object(SCHEMA_CHECKIN_PROGRESS_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
                prop_assert_eq!(back, body);
            }
            Err(_) => prop_assert!(!ok),
        }
    }

    /// Every box progress body and progress-check body survives an object
    /// round trip, and a tick carries either progress body unchanged.
    #[test]
    fn box_progress_and_check_round_trip(
        slot in any::<u64>(),
        sheets_in in any::<u64>(),
        state in 1u8..=3,
        alarm in 1u8..=3,
        finding in 1u8..=4,
        holding in any::<u64>(),
        carried in 1u64..,
    ) {
        let body = BoxProgressBody::new(&BoxProgressParts {
            slot,
            sheets_in,
            state: BoxProgressState::from_code(state).unwrap(),
            ..box_parts()
        });
        let bytes = encode_to_vec(SCHEMA_BOX_PROGRESS_BODY, SCHEMA_VERSION_1, &body);
        let back: BoxProgressBody<'_> =
            decode_object(SCHEMA_BOX_PROGRESS_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back, body);
        let tick = ProgressTick::new(&bytes, &SIG_T).unwrap();
        let tick_bytes = encode_to_vec(SCHEMA_PROGRESS_TICK, SCHEMA_VERSION_1, &tick);
        let tick_back: ProgressTick<'_> =
            decode_object(SCHEMA_PROGRESS_TICK, SCHEMA_VERSION_1, &tick_bytes).unwrap();
        prop_assert_eq!(tick_back, tick);
        prop_assert_eq!(tick_back.body().slot(), slot);

        let finding = ProgressFinding::from_code(finding).unwrap();
        let carried_out = if finding == ProgressFinding::CarriedOut { carried } else { 0 };
        let check = ProgressCheckBody::new(&ProgressCheckParts {
            alarm: ProgressAlarm::from_code(alarm).unwrap(),
            holding,
            finding,
            carried_out,
            ..check_parts(ProgressFinding::Explained, 0)
        })
        .unwrap();
        let bytes = encode_to_vec(SCHEMA_PROGRESS_CHECK_BODY, SCHEMA_VERSION_1, &check);
        let back: ProgressCheckBody<'_> =
            decode_object(SCHEMA_PROGRESS_CHECK_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back, check);
    }
}

#[test]
fn every_progress_code() {
    for code in 0u8..=255 {
        match BoxProgressState::from_code(code) {
            Some(s) => assert_eq!(s.code(), code),
            None => assert!(code == 0 || code > 3),
        }
        match CheckinProgressState::from_code(code) {
            Some(s) => assert_eq!(s.code(), code),
            None => assert!(code == 0 || code > 3),
        }
        match ProgressAlarm::from_code(code) {
            Some(a) => assert_eq!(a.code(), code),
            None => assert!(code == 0 || code > 3),
        }
        match ProgressFinding::from_code(code) {
            Some(f) => assert_eq!(f.code(), code),
            None => assert!(code == 0 || code > 4),
        }
    }
    assert_eq!(BoxProgressState::ALL.len(), 3);
    assert_eq!(CheckinProgressState::ALL.len(), 3);
    assert_eq!(ProgressAlarm::ALL.len(), 3);
    assert_eq!(ProgressFinding::ALL.len(), 4);
}
