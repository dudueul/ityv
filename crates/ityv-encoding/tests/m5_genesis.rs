//! The genesis (ADR-0028, ADR-0039, ADR-0040): `GenesisBody` (0x0002,
//! version 8),
//! `SignedGenesis` (0x0033), `GenesisAmendmentBody` (0x0034), the entry
//! objects 0x0035–0x003E, and the check-in events `ObserverCountAttestBody`
//! (0x003F), `CheckinUnitSwapBody` (0x0040), `BoxUnitSwapBody` (0x0041):
//! golden vectors (ENCODING.md §7), round trips and one rejection per rule.
//! Keys and signatures are patterned bytes.
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
    clippy::too_many_lines,
    clippy::cast_possible_truncation
)]

mod common;

use common::{
    Vector, check_file, encode_to_vec, ident_len, patterned64, render_version, self_check,
};
use ityv_encoding::{
    AMENDABLE_SET_COUNT, AmendmentReason, BallotStyleEntry, BallotStyleId, BoxId, BoxUnitSwapBody,
    BoxUnitSwapParts, CaptureProfile, ChamberCode, ChamberThreshold, CheckinUnit,
    CheckinUnitSwapBody, CheckinUnitSwapParts, CustodyRoute, Day, Decode, ENTRY_SET_COUNT,
    ElectionId, Encode, EntrySet, ErrorKind, EventRole, EventSig, GenesisAmendmentBody,
    GenesisAmendmentParts, GenesisBody, GenesisBox, GenesisEntry, GenesisKind, GenesisParts,
    GenesisWitnessSig, HEADER_LEN, HYBRID_SIG_LEN, HYBRID_VK_LEN, Hash512, Ident,
    MAX_GENESIS_WITNESSES, MIN_QUORUM, ModuleEntry, ModuleId, ModuleIds, ObserverCountAttestBody,
    ObserverCountKind, ObserverCountParts, ObserverToken, OrgId, PURPOSE_GENESIS,
    PURPOSE_GENESIS_AMENDMENT, PartyEntry, Reader, ReportingUnitEntry, ReportingUnitId, RosterRole,
    RosterSigner, RouteId, SCHEMA_BALLOT_STYLE_ENTRY, SCHEMA_BOX_UNIT_SWAP_BODY,
    SCHEMA_CHECKIN_UNIT_SWAP_BODY, SCHEMA_CUSTODY_ROUTE, SCHEMA_GENESIS_AMENDMENT_BODY,
    SCHEMA_GENESIS_BODY, SCHEMA_GENESIS_BOX, SCHEMA_MODULE_ENTRY,
    SCHEMA_OBSERVER_COUNT_ATTEST_BODY, SCHEMA_REPORTING_UNIT_ENTRY, SCHEMA_ROLL_AUTHORITY_ENTRY,
    SCHEMA_ROSTER_SIGNER, SCHEMA_SIGNED_GENESIS, SCHEMA_STATION_ENTRY,
    SCHEMA_STATION_PROGRESS_POLICY, SCHEMA_TIMESTAMP_AUTHORITY_ENTRY, SCHEMA_TRUSTEE_ENTRY,
    SCHEMA_VERSION_1, SCHEMA_VERSION_GENESIS, SCHEMA_WITNESS_ROSTER_ENTRY, SchemaId, SetCommitment,
    SignedGenesis, SignerId, StationEntry, StationId, StationKind, StationParts,
    StationProgressPolicy, TimeBucket, TrusteeEntry, TrusteeId, UnitId, WitnessQuorum,
    WitnessRosterEntry, WitnessedEvent, chunks_for, decode_object, keys_share_half, purpose_of,
};
use proptest::prelude::*;
use std::vec::Vec;

const E: &[u8] = b"KR-2030-PRES";
const BOX: &[u8] = b"box-11-0042";
const BOX2: &[u8] = b"box-11-0043";
const ST: &[u8] = b"st-11-0042";

static VK_A: [u8; HYBRID_VK_LEN] = [0xA1; HYBRID_VK_LEN];
static VK_B: [u8; HYBRID_VK_LEN] = [0xB2; HYBRID_VK_LEN];
static VK_C: [u8; HYBRID_VK_LEN] = [0xC3; HYBRID_VK_LEN];
static VK_D: [u8; HYBRID_VK_LEN] = [0xD4; HYBRID_VK_LEN];
static CHECK: [u8; 32] = [0x3C; 32];
static SIG_X: [u8; HYBRID_SIG_LEN] = [0x5A; HYBRID_SIG_LEN];
static SIG_Y: [u8; HYBRID_SIG_LEN] = [0x6B; HYBRID_SIG_LEN];
static SIG_W: [u8; HYBRID_SIG_LEN] = [0x7C; HYBRID_SIG_LEN];
static SIG_C: [u8; HYBRID_SIG_LEN] = [0x8D; HYBRID_SIG_LEN];

const WITNESS_IDS: [&[u8]; 9] = [
    b"w01", b"w02", b"w03", b"w04", b"w05", b"w06", b"w07", b"w08", b"w09",
];

fn e() -> ElectionId<'static> {
    ElectionId::new(E).unwrap()
}

fn st() -> StationId<'static> {
    StationId::new(ST).unwrap()
}

fn bx(id: &'static [u8]) -> BoxId<'static> {
    BoxId::new(id).unwrap()
}

fn org(id: &'static [u8]) -> OrgId<'static> {
    OrgId::new(id).unwrap()
}

fn signer(id: &'static [u8]) -> SignerId<'static> {
    SignerId::new(id).unwrap()
}

fn unit(id: &'static [u8]) -> UnitId<'static> {
    UnitId::new(id).unwrap()
}

fn ident(id: &'static [u8]) -> Ident<'static> {
    Ident::new(id, 64).unwrap()
}

fn modules() -> ModuleIds<'static> {
    ModuleIds::new(&[
        ModuleId::new(b"mod-p1").unwrap(),
        ModuleId::new(b"mod-p2").unwrap(),
    ])
    .unwrap()
}

const MODULES_LEN: usize = 4 + 10 + 10;

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

fn kind<'a, T: Decode<'a> + core::fmt::Debug>(
    schema: SchemaId,
    version: u16,
    bytes: &'a [u8],
) -> (ErrorKind, usize) {
    let err = decode_object::<T>(schema, version, bytes).unwrap_err();
    (err.kind(), err.offset())
}

/// Writes the vector file and re-reads it through the decoder, checking
/// every rejection against the listed kind and offset.
macro_rules! publish {
    ($ty:ty, $name:expr, $title:expr, $schema:expr, $version:expr, $vectors:expr $(,)?) => {{
        let (schema, version, vectors): (SchemaId, u16, &[Vector]) = ($schema, $version, $vectors);
        for v in vectors {
            match v.expected {
                None => {
                    let value: $ty = decode_object(schema, version, &v.bytes)
                        .unwrap_or_else(|e| panic!("{}: {e}", v.label));
                    assert_eq!(
                        encode_to_vec(schema, version, &value),
                        v.bytes,
                        "{}",
                        v.label
                    );
                }
                Some((kind, offset)) => {
                    let err = decode_object::<$ty>(schema, version, &v.bytes).unwrap_err();
                    assert_eq!(
                        (std::format!("{:?}", err.kind()).as_str(), err.offset()),
                        (kind, offset),
                        "{}",
                        v.label
                    );
                }
            }
        }
        let content = render_version($title, schema, version, vectors);
        check_file($name, &content);
        self_check(&content, |b| {
            let v: $ty = decode_object(schema, version, b)?;
            Ok(encode_to_vec(schema, version, &v))
        });
    }};
}

fn round_trip<'a, T: Encode + Decode<'a> + PartialEq + core::fmt::Debug>(
    schema: SchemaId,
    version: u16,
    value: &T,
    buf: &'a mut Vec<u8>,
) -> T {
    *buf = encode_to_vec(schema, version, value);
    assert_eq!(buf.len(), HEADER_LEN + value.encoded_len());
    decode_object(schema, version, buf).unwrap()
}

// --- entries ---------------------------------------------------------------

fn genesis_box() -> GenesisBox<'static> {
    GenesisBox {
        box_id: bx(BOX),
        station_id: st(),
        ballot_style_id: BallotStyleId::new(b"pres-2030").unwrap(),
        profile: CaptureProfile::InPerson,
        route_id: RouteId::new(b"route-11").unwrap(),
        reporting_unit_id: ReportingUnitId::new(b"ru-11-0042").unwrap(),
        device_key: &VK_A,
        attest_key: &VK_B,
        modules: modules(),
    }
}

#[test]
fn genesis_box_vectors() {
    let entry = genesis_box();
    let bytes = encode_to_vec(SCHEMA_GENESIS_BOX, SCHEMA_VERSION_1, &entry);
    let mut buf = Vec::new();
    assert_eq!(
        round_trip(SCHEMA_GENESIS_BOX, SCHEMA_VERSION_1, &entry, &mut buf),
        entry
    );
    assert_eq!(entry.key(), BOX);
    let profile_at = HEADER_LEN + ident_len(BOX) + ident_len(ST) + ident_len(b"pres-2030");
    let modules_at =
        profile_at + 1 + ident_len(b"route-11") + ident_len(b"ru-11-0042") + 2 * HYBRID_VK_LEN;
    let mut v = std::vec![valid("in-person box with two modules", bytes.clone())];
    let mut b = bytes.clone();
    b[profile_at] = 4;
    v.push(invalid("profile 4", b, "ValueOutOfRange", profile_at));
    let mut b = bytes.clone();
    let second = modules_at + 4 + ident_len(b"mod-p1");
    b[second - 1] = b'2';
    b[second + 4 + 5] = b'1';
    v.push(invalid("modules out of order", b, "NotSorted", second));
    publish!(
        GenesisBox<'_>,
        "genesis_box.txt",
        "GenesisBox",
        SCHEMA_GENESIS_BOX,
        SCHEMA_VERSION_1,
        &v,
    );
}

fn checkin_unit(id: &'static [u8], key: &'static [u8; HYBRID_VK_LEN]) -> CheckinUnit<'static> {
    CheckinUnit {
        unit_id: unit(id),
        key,
        attest_key: &VK_D,
        modules: modules(),
    }
}

static BOXES: [BoxId<'static>; 2] = [BoxId::new(BOX).unwrap(), BoxId::new(BOX2).unwrap()];

static TOKENS: [ObserverToken<'static>; 2] = [
    ObserverToken {
        observer_id: SignerId::new(b"obs-a").unwrap(),
        org_id: OrgId::new(b"PARTY-A").unwrap(),
        check_key: &CHECK,
    },
    ObserverToken {
        observer_id: SignerId::new(b"obs-b").unwrap(),
        org_id: OrgId::new(b"PARTY-B").unwrap(),
        check_key: &CHECK,
    },
];

fn station_parts() -> StationParts<'static> {
    StationParts {
        station_id: st(),
        kind: StationKind::ElectionDay,
        primary: checkin_unit(b"unit-a", &VK_A),
        spare: checkin_unit(b"unit-b", &VK_C),
        boxes: &BOXES,
        id_terminals_hash: patterned64(0x44),
        tokens: &TOKENS,
    }
}

#[test]
fn station_entry_vectors() {
    let entry = StationEntry::new(&station_parts()).unwrap();
    assert_eq!(entry.station_id(), st());
    assert_eq!(entry.kind(), StationKind::ElectionDay);
    assert_eq!(entry.primary(), &checkin_unit(b"unit-a", &VK_A));
    assert_eq!(entry.spare(), &checkin_unit(b"unit-b", &VK_C));
    assert_eq!(entry.boxes().collect::<Vec<_>>(), BOXES.to_vec());
    assert_eq!(entry.id_terminals_hash(), &patterned64(0x44));
    assert_eq!(entry.tokens().collect::<Vec<_>>(), TOKENS.to_vec());
    assert_eq!(entry.key(), ST);
    let bytes = encode_to_vec(SCHEMA_STATION_ENTRY, SCHEMA_VERSION_1, &entry);
    let mut buf = Vec::new();
    assert_eq!(
        round_trip(SCHEMA_STATION_ENTRY, SCHEMA_VERSION_1, &entry, &mut buf),
        entry
    );
    let unit_len = ident_len(b"unit-a") + 2 * HYBRID_VK_LEN + MODULES_LEN;
    let kind_at = HEADER_LEN + ident_len(ST);
    let spare_at = kind_at + 1 + unit_len;
    let boxes_at = spare_at + unit_len;
    let second_box = boxes_at + 4 + ident_len(BOX);
    let tokens_at = second_box + ident_len(BOX2) + 64;
    let second_token = tokens_at + 4 + ident_len(b"obs-a") + ident_len(b"PARTY-A") + 32;
    let mut v = std::vec![valid(
        "election-day station, two boxes, two tokens",
        bytes.clone()
    )];
    let mut b = bytes.clone();
    b[kind_at] = 4;
    v.push(invalid("kind 4", b, "ValueOutOfRange", kind_at));
    let mut b = bytes.clone();
    b[spare_at + 4 + 5] = b'a';
    v.push(invalid(
        "spare is the unit in service",
        b,
        "InvariantViolation",
        spare_at,
    ));
    let mut b = bytes.clone();
    let spare_ed = spare_at + ident_len(b"unit-b") + HYBRID_VK_LEN - 32;
    b[spare_ed..spare_ed + 32].fill(0xA1);
    v.push(invalid(
        "spare shares the Ed25519 half",
        b,
        "InvariantViolation",
        spare_at,
    ));
    let mut b = bytes[..boxes_at].to_vec();
    b.extend_from_slice(&0u32.to_be_bytes());
    fix_len(&mut b);
    v.push(invalid("no boxes", b, "InvariantViolation", boxes_at));
    let mut b = bytes.clone();
    b[second_box - 1] = b'3';
    b[second_box + 4 + 10] = b'2';
    v.push(invalid("boxes out of order", b, "NotSorted", second_box));
    let mut b = bytes.clone();
    b[second_token + 4 + 4] = b'a';
    v.push(invalid("one observer twice", b, "Duplicate", second_token));
    publish!(
        StationEntry<'_>,
        "station_entry.txt",
        "StationEntry",
        SCHEMA_STATION_ENTRY,
        SCHEMA_VERSION_1,
        &v,
    );
}

#[test]
fn station_entry_rules() {
    let ok = station_parts();
    assert!(StationEntry::new(&ok).is_ok());
    let same_unit = StationParts {
        spare: checkin_unit(b"unit-a", &VK_C),
        ..ok
    };
    let static_shared: &'static [u8; HYBRID_VK_LEN] = Box::leak(Box::new({
        let mut k = VK_C;
        k[HYBRID_VK_LEN - 32..].copy_from_slice(&VK_A[HYBRID_VK_LEN - 32..]);
        k
    }));
    let shared_ed = StationParts {
        spare: checkin_unit(b"unit-b", static_shared),
        ..ok
    };
    let shared_ml: &'static [u8; HYBRID_VK_LEN] = Box::leak(Box::new({
        let mut k = VK_A;
        k[HYBRID_VK_LEN - 32..].fill(0xEE);
        k
    }));
    let shared_ml = StationParts {
        spare: checkin_unit(b"unit-b", shared_ml),
        ..ok
    };
    let no_boxes = StationParts { boxes: &[], ..ok };
    let nine: &'static [BoxId<'static>] = Box::leak(
        (0..9)
            .map(|i| {
                BoxId::new(Box::leak(std::format!("b{i}").into_boxed_str()).as_bytes()).unwrap()
            })
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    );
    let too_many = StationParts { boxes: nine, ..ok };
    let eight = StationParts {
        boxes: &nine[..8],
        ..ok
    };
    assert!(StationEntry::new(&eight).is_ok());
    let reversed: &'static [BoxId<'static>] = Box::leak(Box::new([BOXES[1], BOXES[0]]));
    let unsorted = StationParts {
        boxes: reversed,
        ..ok
    };
    let rev_tokens: &'static [ObserverToken<'static>] = Box::leak(Box::new([TOKENS[1], TOKENS[0]]));
    let unsorted_tokens = StationParts {
        tokens: rev_tokens,
        ..ok
    };
    let many_tokens: &'static [ObserverToken<'static>] = Box::leak(
        (0..17)
            .map(|i| ObserverToken {
                observer_id: SignerId::new(
                    Box::leak(std::format!("o{i:02}").into_boxed_str()).as_bytes(),
                )
                .unwrap(),
                org_id: org(b"PARTY-A"),
                check_key: &CHECK,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    );
    let too_many_tokens = StationParts {
        tokens: many_tokens,
        ..ok
    };
    let sixteen = StationParts {
        tokens: &many_tokens[..16],
        ..ok
    };
    assert!(StationEntry::new(&sixteen).is_ok());
    let no_tokens = StationParts { tokens: &[], ..ok };
    assert!(StationEntry::new(&no_tokens).is_ok());
    for bad in [
        same_unit,
        shared_ed,
        shared_ml,
        no_boxes,
        too_many,
        unsorted,
        unsorted_tokens,
        too_many_tokens,
    ] {
        let err = StationEntry::new(&bad).unwrap_err();
        assert_eq!(
            (err.kind(), err.offset()),
            (ErrorKind::InvariantViolation, 0)
        );
    }
    for (code, kind) in [
        (1, StationKind::ElectionDay),
        (2, StationKind::EarlyVoting),
        (3, StationKind::Receiving),
    ] {
        assert_eq!(StationKind::from_code(code), Some(kind));
        assert_eq!(kind.code(), code);
    }
    assert_eq!(StationKind::from_code(0), None);
    assert_eq!(StationKind::from_code(4), None);
}

#[test]
fn small_entry_vectors() {
    // StationProgressPolicy (0x0037).
    let policy = StationProgressPolicy::new(st(), 4, 30).unwrap();
    assert_eq!(policy.key(), ST);
    let bytes = encode_to_vec(SCHEMA_STATION_PROGRESS_POLICY, SCHEMA_VERSION_1, &policy);
    let booth_at = HEADER_LEN + ident_len(ST);
    let mut v = std::vec![valid("four booths, limit 30", bytes.clone())];
    let mut b = bytes.clone();
    b[booth_at..booth_at + 2].fill(0);
    v.push(invalid("no booth", b, "ValueOutOfRange", booth_at));
    let mut b = bytes.clone();
    b[booth_at + 2..booth_at + 6].fill(0);
    v.push(invalid("limit 0", b, "ValueOutOfRange", booth_at + 2));
    publish!(
        StationProgressPolicy<'_>,
        "station_progress_policy.txt",
        "StationProgressPolicy",
        SCHEMA_STATION_PROGRESS_POLICY,
        SCHEMA_VERSION_1,
        &v,
    );

    // ReportingUnitEntry (0x0038).
    let ru = ReportingUnitId::new(b"ru-11-0042").unwrap();
    let unit_entry =
        ReportingUnitEntry::new(ru, 3, ityv_encoding::OrgId::new(b"NEC-D").unwrap()).unwrap();
    assert_eq!(unit_entry.unit_id(), ru);
    assert_eq!(unit_entry.box_count(), 3);
    assert_eq!(unit_entry.commission_org().as_bytes(), b"NEC-D");
    assert_eq!(unit_entry.key(), b"ru-11-0042");
    assert_eq!(
        ReportingUnitEntry::new(ru, 0, ityv_encoding::OrgId::new(b"NEC-D").unwrap())
            .unwrap_err()
            .kind(),
        ErrorKind::ValueOutOfRange
    );
    let bytes = encode_to_vec(
        SCHEMA_REPORTING_UNIT_ENTRY,
        ityv_encoding::SCHEMA_VERSION_REPORTING_UNIT,
        &unit_entry,
    );
    let count_at = HEADER_LEN + ident_len(b"ru-11-0042");
    let mut v = std::vec![valid("three boxes", bytes.clone())];
    let mut b = bytes.clone();
    b[count_at..count_at + 4].fill(0);
    v.push(invalid("no box", b, "ValueOutOfRange", count_at));
    publish!(
        ReportingUnitEntry<'_>,
        "reporting_unit_entry.txt",
        "ReportingUnitEntry",
        SCHEMA_REPORTING_UNIT_ENTRY,
        ityv_encoding::SCHEMA_VERSION_REPORTING_UNIT,
        &v,
    );

    // CustodyRoute (0x0039).
    let route = CustodyRoute::new(
        RouteId::new(b"route-11").unwrap(),
        false,
        &[org(b"NEC-11"), org(b"POLICE-11"), org(b"CENTRE-11")],
    )
    .unwrap();
    assert_eq!(route.key(), b"route-11");
    let bytes = encode_to_vec(SCHEMA_CUSTODY_ROUTE, SCHEMA_VERSION_1, &route);
    let count_at = HEADER_LEN + ident_len(b"route-11") + 1;
    let second = count_at + 4 + ident_len(b"NEC-11");
    let mut v = std::vec![valid("three stops", bytes.clone())];
    let mut b = bytes[..second].to_vec();
    b.extend_from_slice(&6u32.to_be_bytes());
    b.extend_from_slice(b"NEC-11");
    b[count_at..count_at + 4].copy_from_slice(&2u32.to_be_bytes());
    fix_len(&mut b);
    v.push(invalid("one stop twice", b, "InvariantViolation", second));
    let mut b = bytes[..second].to_vec();
    b[count_at..count_at + 4].copy_from_slice(&1u32.to_be_bytes());
    fix_len(&mut b);
    v.push(invalid("one stop", b, "InvariantViolation", count_at));
    publish!(
        CustodyRoute<'_>,
        "custody_route.txt",
        "CustodyRoute",
        SCHEMA_CUSTODY_ROUTE,
        SCHEMA_VERSION_1,
        &v,
    );

    // RosterSigner (0x003A).
    let clerk = RosterSigner {
        signer_id: signer(b"c1"),
        role: RosterRole::Clerk,
        org_id: org(b"NEC-11"),
        station_id: Some(st()),
        key: &VK_A,
        appointment_hash: patterned64(0x77),
    };
    let court = RosterSigner {
        signer_id: signer(b"court-seoul"),
        role: RosterRole::Authority,
        org_id: org(b"COURT"),
        station_id: None,
        key: &VK_B,
        appointment_hash: patterned64(0x78),
    };
    assert_eq!(clerk.key(), b"c1");
    let bytes = encode_to_vec(
        SCHEMA_ROSTER_SIGNER,
        ityv_encoding::SCHEMA_VERSION_ROSTER_SIGNER,
        &clerk,
    );
    let role_at = HEADER_LEN + ident_len(b"c1");
    let mut v = std::vec![
        valid("clerk of a station", bytes.clone()),
        valid(
            "legal authority",
            encode_to_vec(
                SCHEMA_ROSTER_SIGNER,
                ityv_encoding::SCHEMA_VERSION_ROSTER_SIGNER,
                &court
            )
        ),
        valid(
            "district commission chair (version 2)",
            encode_to_vec(
                SCHEMA_ROSTER_SIGNER,
                ityv_encoding::SCHEMA_VERSION_ROSTER_SIGNER,
                &RosterSigner {
                    signer_id: signer(b"chair-11"),
                    role: RosterRole::Chair,
                    org_id: org(b"NEC-11"),
                    station_id: None,
                    key: &VK_B,
                    appointment_hash: patterned64(0x79),
                }
            )
        ),
        valid(
            "auditor (version 3)",
            encode_to_vec(
                SCHEMA_ROSTER_SIGNER,
                ityv_encoding::SCHEMA_VERSION_ROSTER_SIGNER,
                &RosterSigner {
                    signer_id: signer(b"aud-1"),
                    role: RosterRole::Auditor,
                    org_id: org(b"AUDIT-A"),
                    station_id: None,
                    key: &VK_B,
                    appointment_hash: patterned64(0x7A),
                }
            )
        ),
    ];
    let mut b = bytes.clone();
    b[role_at] = 7;
    v.push(invalid("role 7", b, "ValueOutOfRange", role_at));
    let mut b = bytes.clone();
    let n = b.len();
    b[n - 64..].fill(0);
    v.push(invalid("no appointment", b, "InvalidPreviousHash", n - 64));
    publish!(
        RosterSigner<'_>,
        "roster_signer.txt",
        "RosterSigner",
        SCHEMA_ROSTER_SIGNER,
        ityv_encoding::SCHEMA_VERSION_ROSTER_SIGNER,
        &v,
    );

    // ModuleEntry (0x003B).
    let module = ModuleEntry {
        module_id: ModuleId::new(b"mod-p1").unwrap(),
        chamber: ChamberCode::P1,
        key: &VK_A,
        attest_key: &VK_B,
        provisioned_hash: patterned64(0x55),
    };
    assert_eq!(module.key(), b"mod-p1");
    let bytes = encode_to_vec(SCHEMA_MODULE_ENTRY, SCHEMA_VERSION_1, &module);
    let mut buf = Vec::new();
    assert_eq!(
        round_trip(SCHEMA_MODULE_ENTRY, SCHEMA_VERSION_1, &module, &mut buf),
        module
    );
    let chamber_at = HEADER_LEN + ident_len(b"mod-p1");
    let mut v = std::vec![valid("party module P1", bytes.clone())];
    for (label, code) in [("chamber N", 8u8), ("chamber 0", 0), ("chamber 9", 9)] {
        let mut b = bytes.clone();
        b[chamber_at] = code;
        v.push(invalid(label, b, "ValueOutOfRange", chamber_at));
    }
    let mut b = bytes.clone();
    let n = b.len();
    b[n - 64..].fill(0);
    v.push(invalid("not provisioned", b, "InvalidPreviousHash", n - 64));
    publish!(
        ModuleEntry<'_>,
        "module_entry.txt",
        "ModuleEntry",
        SCHEMA_MODULE_ENTRY,
        SCHEMA_VERSION_1,
        &v,
    );
    for chamber in [
        ChamberCode::P1,
        ChamberCode::P4,
        ChamberCode::J,
        ChamberCode::A,
        ChamberCode::C,
    ] {
        let m = ModuleEntry { chamber, ..module };
        let mut buf = Vec::new();
        assert_eq!(
            round_trip(SCHEMA_MODULE_ENTRY, SCHEMA_VERSION_1, &m, &mut buf),
            m
        );
    }
}

#[test]
fn ballot_style_vectors() {
    let id = BallotStyleId::new(b"pres-2030").unwrap();
    let five = BallotStyleEntry::new(id, 5, patterned64(0x22)).unwrap();
    assert_eq!(five.ballot_style_id(), id);
    assert_eq!(five.choices(), 5);
    assert_eq!(five.chunks(), 1);
    assert_eq!(five.layout_hash(), &patterned64(0x22));
    assert_eq!(five.key(), b"pres-2030");
    let seventy = BallotStyleEntry::new(id, 70, patterned64(0x23)).unwrap();
    assert_eq!(seventy.chunks(), 8);
    let one = BallotStyleEntry::new(id, 1, patterned64(0x24)).unwrap();
    assert_eq!((one.choices(), one.chunks()), (1, 1));
    for (m, k) in [
        (1u16, 1u32),
        (7, 1),
        (8, 2),
        (16, 2),
        (17, 3),
        (70, 8),
        (71, 9),
    ] {
        assert_eq!(chunks_for(m), k, "m = {m}");
    }
    assert_eq!(chunks_for(u16::MAX), (u32::from(u16::MAX) + 2).div_ceil(9));
    for bad in [0u16, 71, u16::MAX] {
        let err = BallotStyleEntry::new(id, bad, patterned64(0)).unwrap_err();
        assert_eq!((err.kind(), err.offset()), (ErrorKind::ValueOutOfRange, 0));
    }
    let bytes = encode_to_vec(SCHEMA_BALLOT_STYLE_ENTRY, SCHEMA_VERSION_1, &five);
    let choices_at = HEADER_LEN + ident_len(b"pres-2030");
    let mut v = std::vec![
        valid("five choices, one chunk", bytes.clone()),
        valid(
            "seventy choices, eight chunks",
            encode_to_vec(SCHEMA_BALLOT_STYLE_ENTRY, SCHEMA_VERSION_1, &seventy)
        ),
    ];
    let mut b = bytes.clone();
    b[choices_at..choices_at + 2].fill(0);
    v.push(invalid("no choice", b, "ValueOutOfRange", choices_at));
    let mut b = bytes.clone();
    b[choices_at..choices_at + 2].copy_from_slice(&71u16.to_be_bytes());
    v.push(invalid("nine chunks", b, "ValueOutOfRange", choices_at));
    let mut b = bytes.clone();
    b[choices_at + 2] = 2;
    v.push(invalid(
        "wrong chunk count",
        b,
        "InvariantViolation",
        choices_at + 2,
    ));
    publish!(
        BallotStyleEntry<'_>,
        "ballot_style_entry.txt",
        "BallotStyleEntry",
        SCHEMA_BALLOT_STYLE_ENTRY,
        SCHEMA_VERSION_1,
        &v,
    );
}

#[test]
fn trustee_and_witness_vectors() {
    let trustee = TrusteeEntry {
        trustee_id: TrusteeId::new(b"t-p1-1").unwrap(),
        chamber: ChamberCode::P1,
        org_id: org(b"PARTY-A"),
        key: &VK_C,
        appointment_hash: patterned64(0x31),
    };
    assert_eq!(trustee.key(), b"t-p1-1");
    let bytes = encode_to_vec(SCHEMA_TRUSTEE_ENTRY, SCHEMA_VERSION_1, &trustee);
    let mut buf = Vec::new();
    assert_eq!(
        round_trip(SCHEMA_TRUSTEE_ENTRY, SCHEMA_VERSION_1, &trustee, &mut buf),
        trustee
    );
    let chamber_at = HEADER_LEN + ident_len(b"t-p1-1");
    let mut v = std::vec![valid("party chamber member", bytes.clone())];
    let mut b = bytes.clone();
    b[chamber_at] = 9;
    v.push(invalid("chamber 9", b, "ValueOutOfRange", chamber_at));
    let mut b = bytes.clone();
    let n = b.len();
    b[n - 64..].fill(0);
    v.push(invalid("no appointment", b, "InvalidPreviousHash", n - 64));
    publish!(
        TrusteeEntry<'_>,
        "trustee_entry.txt",
        "TrusteeEntry",
        SCHEMA_TRUSTEE_ENTRY,
        SCHEMA_VERSION_1,
        &v,
    );

    let witness = WitnessRosterEntry {
        witness_id: ident(b"w01"),
        org_id: org(b"UNIV-A"),
        provider: ident(b"cloud-x"),
        region: ident(b"seoul"),
        key: &VK_D,
        appointment_hash: patterned64(0x32),
    };
    assert_eq!(witness.key(), b"w01");
    let bytes = encode_to_vec(SCHEMA_WITNESS_ROSTER_ENTRY, SCHEMA_VERSION_1, &witness);
    let mut buf = Vec::new();
    assert_eq!(
        round_trip(
            SCHEMA_WITNESS_ROSTER_ENTRY,
            SCHEMA_VERSION_1,
            &witness,
            &mut buf
        ),
        witness
    );
    let provider_at = HEADER_LEN + ident_len(b"w01") + ident_len(b"UNIV-A");
    let mut v = std::vec![valid("university witness", bytes.clone())];
    let mut b = bytes[..provider_at].to_vec();
    b.extend_from_slice(&0u32.to_be_bytes());
    fix_len(&mut b);
    v.push(invalid("no provider", b, "EmptyIdent", provider_at));
    let mut b = bytes.clone();
    let n = b.len();
    b[n - 64..].fill(0);
    v.push(invalid("no appointment", b, "InvalidPreviousHash", n - 64));
    publish!(
        WitnessRosterEntry<'_>,
        "witness_roster_entry.txt",
        "WitnessRosterEntry",
        SCHEMA_WITNESS_ROSTER_ENTRY,
        SCHEMA_VERSION_1,
        &v,
    );
}

#[test]
fn entry_sets() {
    let codes: Vec<u8> = EntrySet::ALL.iter().map(|s| s.code()).collect();
    assert_eq!(codes, (1..=13).collect::<Vec<u8>>());
    for (i, set) in EntrySet::ALL.iter().enumerate() {
        assert_eq!(set.index(), i);
        assert_eq!(set.amendable(), i < AMENDABLE_SET_COUNT);
    }
    assert_eq!(EntrySet::ALL.len(), ENTRY_SET_COUNT);
    let schemas: Vec<Option<SchemaId>> = EntrySet::ALL.iter().map(|s| s.schema()).collect();
    assert_eq!(
        schemas,
        std::vec![
            Some(SCHEMA_GENESIS_BOX),
            Some(SCHEMA_STATION_ENTRY),
            Some(SCHEMA_STATION_PROGRESS_POLICY),
            Some(SCHEMA_REPORTING_UNIT_ENTRY),
            Some(SCHEMA_CUSTODY_ROUTE),
            Some(SCHEMA_ROSTER_SIGNER),
            Some(SCHEMA_MODULE_ENTRY),
            None,
            Some(SCHEMA_BALLOT_STYLE_ENTRY),
            Some(SCHEMA_TRUSTEE_ENTRY),
            Some(SCHEMA_WITNESS_ROSTER_ENTRY),
            Some(SCHEMA_TIMESTAMP_AUTHORITY_ENTRY),
            Some(SCHEMA_ROLL_AUTHORITY_ENTRY),
        ]
    );
    assert_eq!(GenesisBox::SET, EntrySet::Boxes);
    assert_eq!(StationEntry::SET, EntrySet::Stations);
    assert_eq!(StationProgressPolicy::SET, EntrySet::ProgressPolicies);
    assert_eq!(ReportingUnitEntry::SET, EntrySet::ReportingUnits);
    assert_eq!(CustodyRoute::SET, EntrySet::Routes);
    assert_eq!(RosterSigner::SET, EntrySet::Roster);
    assert_eq!(ModuleEntry::SET, EntrySet::Modules);
    assert_eq!(BallotStyleEntry::SET, EntrySet::BallotStyles);
    assert_eq!(TrusteeEntry::SET, EntrySet::Trustees);
    assert_eq!(WitnessRosterEntry::SET, EntrySet::Witnesses);
    // Key halves.
    assert!(!keys_share_half(&VK_A, &VK_B));
    assert!(keys_share_half(&VK_A, &VK_A));
    let mut ed_only = VK_B;
    ed_only[HYBRID_VK_LEN - 32..].fill(0xA1);
    assert!(keys_share_half(&VK_A, &ed_only));
    let mut ml_only = VK_A;
    ml_only[HYBRID_VK_LEN - 1] = 0;
    assert!(keys_share_half(&VK_A, &ml_only));
}

// --- the genesis body ------------------------------------------------------

static PARTIES: [PartyEntry<'static>; 2] = [
    PartyEntry {
        chamber: ChamberCode::P1,
        name: "더불어민주당",
        seats: 170,
        evidence_hash: Hash512([0x61; 64]),
    },
    PartyEntry {
        chamber: ChamberCode::P2,
        name: "국민의힘",
        seats: 108,
        evidence_hash: Hash512([0x62; 64]),
    },
];

const fn threshold(chamber: ChamberCode, threshold: u8, members: u8) -> ChamberThreshold {
    ChamberThreshold {
        chamber,
        threshold,
        members,
    }
}

static CHAMBERS: [ChamberThreshold; 6] = [
    threshold(ChamberCode::P1, 2, 3),
    threshold(ChamberCode::P2, 2, 3),
    threshold(ChamberCode::J, 2, 3),
    threshold(ChamberCode::A, 2, 3),
    threshold(ChamberCode::C, 2, 3),
    threshold(ChamberCode::N, 3, 5),
];

const QUORUM: WitnessQuorum = WitnessQuorum {
    witnesses: 13,
    quorum: 9,
    byzantine_max: 4,
    min_orgs: 7,
    min_providers: 4,
    min_regions: 3,
};

fn sets() -> [SetCommitment; ENTRY_SET_COUNT] {
    let mut sets = [SetCommitment {
        count: 0,
        root: Hash512([0; 64]),
    }; ENTRY_SET_COUNT];
    for (i, s) in sets.iter_mut().enumerate() {
        s.count = 100 + i as u64;
        s.root = patterned64(0x90 + i as u8);
    }
    sets[EntrySet::Witnesses.index()].count = 13;
    sets
}

fn genesis_parts() -> GenesisParts<'static> {
    GenesisParts {
        election_id: e(),
        election_epoch_day: Day::new(22_000),
        policy_hash: patterned64(0x10),
        proof_system_id: ident(b"PS-OR-1"),
        legal_authorization_hash: patterned64(0x11),
        connectivity_manifest_hash: patterned64(0x12),
        release_manifest_hash: patterned64(0x13),
        commission_key: &VK_A,
        committee_key: &VK_B,
        quorum: QUORUM,
        custody_quorum: 3,
        parties: &PARTIES,
        chambers: &CHAMBERS,
        sets: sets(),
    }
}

fn genesis_bytes() -> Vec<u8> {
    let body = GenesisBody::new(&genesis_parts()).unwrap();
    encode_to_vec(SCHEMA_GENESIS_BODY, SCHEMA_VERSION_GENESIS, &body)
}

#[test]
fn genesis_body_vectors() {
    let parts = genesis_parts();
    let body = GenesisBody::new(&parts).unwrap();
    assert_eq!(body.election_id(), e());
    assert_eq!(body.election_epoch_day(), Day::new(22_000));
    assert_eq!(body.policy_hash(), &patterned64(0x10));
    assert_eq!(body.proof_system_id(), ident(b"PS-OR-1"));
    assert_eq!(body.legal_authorization_hash(), &patterned64(0x11));
    assert_eq!(body.connectivity_manifest_hash(), &patterned64(0x12));
    assert_eq!(body.release_manifest_hash(), &patterned64(0x13));
    assert_eq!(body.commission_key(), &VK_A);
    assert_eq!(body.committee_key(), &VK_B);
    assert_eq!(body.quorum(), &QUORUM);
    assert_eq!(body.custody_quorum(), 3);
    assert_eq!(body.parties().collect::<Vec<_>>(), PARTIES.to_vec());
    assert_eq!(body.chambers().collect::<Vec<_>>(), CHAMBERS.to_vec());
    assert_eq!(body.sets(), &sets());
    let bytes = genesis_bytes();
    let mut buf = Vec::new();
    assert_eq!(
        round_trip(SCHEMA_GENESIS_BODY, SCHEMA_VERSION_GENESIS, &body, &mut buf),
        body
    );
    let policy_at = HEADER_LEN + ident_len(E) + 8;
    let committee_at = policy_at + 64 + ident_len(b"PS-OR-1") + 3 * 64 + HYBRID_VK_LEN;
    let quorum_at = committee_at + HYBRID_VK_LEN;
    let custody_at = quorum_at + 6;
    let parties_at = custody_at + 1;
    let party_len = |name: &str| 1 + 4 + name.len() + 2 + 64;
    let first_party = parties_at + 4;
    let name_at = first_party + 1;
    let second_party = first_party + party_len(PARTIES[0].name);
    let chambers_at = second_party + party_len(PARTIES[1].name);
    let sets_at = chambers_at + 4 + 6 * 3;
    assert_eq!(bytes.len(), sets_at + ENTRY_SET_COUNT * 72);
    let mut v = std::vec![valid("two parties, 13/9/4 witnesses", bytes.clone())];
    let mut b = bytes.clone();
    b[policy_at..policy_at + 64].fill(0);
    v.push(invalid(
        "no policy hash",
        b,
        "InvalidPreviousHash",
        policy_at,
    ));
    let mut b = bytes.clone();
    b.copy_within(committee_at - HYBRID_VK_LEN..committee_at, committee_at);
    v.push(invalid(
        "committee uses the commission key",
        b,
        "InvariantViolation",
        committee_at,
    ));
    let mut b = bytes.clone();
    b[quorum_at + 1] = 8;
    v.push(invalid("quorum 8", b, "ValueOutOfRange", quorum_at));
    let mut b = bytes.clone();
    b[custody_at] = 2;
    v.push(invalid(
        "custody quorum 2",
        b,
        "ValueOutOfRange",
        custody_at,
    ));
    let mut b = bytes.clone();
    b[parties_at..parties_at + 4].copy_from_slice(&1u32.to_be_bytes());
    v.push(invalid("one party", b, "InvariantViolation", parties_at));
    let mut b = bytes.clone();
    b[second_party] = ChamberCode::P3.code();
    v.push(invalid(
        "P3 after P1",
        b,
        "InvariantViolation",
        second_party,
    ));
    let mut b = bytes.clone();
    let seats_offset = second_party + 1 + 4 + PARTIES[1].name.len();
    b[seats_offset..seats_offset + 2].copy_from_slice(&200u16.to_be_bytes());
    v.push(invalid("seats rise", b, "InvariantViolation", second_party));
    let mut b = bytes.clone();
    b[name_at + 4] = 0xFF;
    v.push(invalid("name not UTF-8", b, "ValueOutOfRange", name_at));
    let mut b = bytes.clone();
    b[chambers_at..chambers_at + 4].copy_from_slice(&5u32.to_be_bytes());
    v.push(invalid("N missing", b, "InvariantViolation", chambers_at));
    let mut b = bytes.clone();
    let j_at = chambers_at + 4 + 2 * 3;
    b[j_at + 1] = 0;
    v.push(invalid("J threshold 0", b, "InvariantViolation", j_at));
    let mut b = bytes.clone();
    let witnesses_at = sets_at + EntrySet::Witnesses.index() * 72;
    b[witnesses_at + 7] = 14;
    v.push(invalid(
        "fourteen witnesses for n = 13",
        b,
        "InvariantViolation",
        sets_at,
    ));
    publish!(
        GenesisBody<'_>,
        "genesis_body.txt",
        "GenesisBody",
        SCHEMA_GENESIS_BODY,
        SCHEMA_VERSION_GENESIS,
        &v,
    );
    // Version 1 is not this schema's version, nor is version 6, the
    // eleven-set body before the timestamp authorities (ADR-0039), nor
    // version 7, the twelve-set body before the roll's authorities and
    // the custody quorum (ADR-0040).
    for version in [SCHEMA_VERSION_1, 6, 7] {
        assert_eq!(
            kind::<GenesisBody<'_>>(SCHEMA_GENESIS_BODY, version, &bytes).0,
            ErrorKind::UnsupportedVersion
        );
    }
}

#[test]
fn genesis_body_rules() {
    let ok = genesis_parts();
    let check = |p: &GenesisParts<'static>| GenesisBody::new(p).map(drop);
    assert_eq!(check(&ok), Ok(()));
    let mut bad = Vec::new();
    for field in 0..4 {
        let mut p = ok;
        match field {
            0 => p.policy_hash = Hash512::ZERO,
            1 => p.legal_authorization_hash = Hash512::ZERO,
            2 => p.connectivity_manifest_hash = Hash512::ZERO,
            _ => p.release_manifest_hash = Hash512::ZERO,
        }
        bad.push(p);
    }
    bad.push(GenesisParts {
        committee_key: &VK_A,
        ..ok
    });
    bad.push(GenesisParts {
        custody_quorum: 2,
        ..ok
    });
    bad.push(GenesisParts {
        quorum: WitnessQuorum {
            quorum: 8,
            ..QUORUM
        },
        ..ok
    });
    bad.push(GenesisParts {
        parties: &PARTIES[..1],
        chambers: Box::leak(Box::new([
            CHAMBERS[0],
            CHAMBERS[2],
            CHAMBERS[3],
            CHAMBERS[4],
            CHAMBERS[5],
        ])),
        ..ok
    });
    let five: &'static [PartyEntry<'static>] = Box::leak(Box::new([PARTIES[0]; 5]));
    bad.push(GenesisParts {
        parties: five,
        ..ok
    });
    let swapped: &'static [PartyEntry<'static>] = Box::leak(Box::new([PARTIES[1], PARTIES[0]]));
    bad.push(GenesisParts {
        parties: swapped,
        ..ok
    });
    let rising: &'static [PartyEntry<'static>] = Box::leak(Box::new([
        PARTIES[0],
        PartyEntry {
            seats: 171,
            ..PARTIES[1]
        },
    ]));
    bad.push(GenesisParts {
        parties: rising,
        ..ok
    });
    let unnamed: &'static [PartyEntry<'static>] = Box::leak(Box::new([
        PARTIES[0],
        PartyEntry {
            name: "",
            ..PARTIES[1]
        },
    ]));
    bad.push(GenesisParts {
        parties: unnamed,
        ..ok
    });
    let long_name: &'static str = Box::leak("가".repeat(43).into_boxed_str());
    let long: &'static [PartyEntry<'static>] = Box::leak(Box::new([
        PARTIES[0],
        PartyEntry {
            name: long_name,
            ..PARTIES[1]
        },
    ]));
    bad.push(GenesisParts {
        parties: long,
        ..ok
    });
    bad.push(GenesisParts {
        chambers: &CHAMBERS[..5],
        ..ok
    });
    let mut chambers = CHAMBERS;
    chambers.swap(2, 3);
    let swapped_chambers: &'static [ChamberThreshold] = Box::leak(Box::new(chambers));
    bad.push(GenesisParts {
        chambers: swapped_chambers,
        ..ok
    });
    for (k, n) in [(0u8, 3u8), (4, 3)] {
        let mut chambers = CHAMBERS;
        chambers[5] = threshold(ChamberCode::N, k, n);
        let c: &'static [ChamberThreshold] = Box::leak(Box::new(chambers));
        bad.push(GenesisParts { chambers: c, ..ok });
    }
    let mut wrong_count = sets();
    wrong_count[EntrySet::Witnesses.index()].count = 12;
    bad.push(GenesisParts {
        sets: wrong_count,
        ..ok
    });
    for p in &bad {
        let err = GenesisBody::new(p).unwrap_err();
        assert_eq!(
            (err.kind(), err.offset()),
            (ErrorKind::InvariantViolation, 0)
        );
    }
    // Boundaries that hold: a 128-byte name, equal seats, k = n, four
    // parties.
    let edge_name: &'static str = Box::leak("a".repeat(128).into_boxed_str());
    let edge: &'static [PartyEntry<'static>] = Box::leak(Box::new([
        PARTIES[0],
        PartyEntry {
            name: edge_name,
            seats: 170,
            ..PARTIES[1]
        },
    ]));
    let mut full = CHAMBERS;
    full[0] = threshold(ChamberCode::P1, 3, 3);
    let full: &'static [ChamberThreshold] = Box::leak(Box::new(full));
    assert_eq!(
        check(&GenesisParts {
            parties: edge,
            chambers: full,
            ..ok
        }),
        Ok(())
    );
    let four: &'static [PartyEntry<'static>] = Box::leak(Box::new([
        PARTIES[0],
        PARTIES[1],
        PartyEntry {
            chamber: ChamberCode::P3,
            seats: 12,
            ..PARTIES[1]
        },
        PartyEntry {
            chamber: ChamberCode::P4,
            seats: 6,
            ..PARTIES[1]
        },
    ]));
    let four_chambers: &'static [ChamberThreshold] = Box::leak(Box::new([
        CHAMBERS[0],
        CHAMBERS[1],
        threshold(ChamberCode::P3, 1, 1),
        threshold(ChamberCode::P4, 1, 2),
        CHAMBERS[2],
        CHAMBERS[3],
        CHAMBERS[4],
        CHAMBERS[5],
    ]));
    let body = GenesisBody::new(&GenesisParts {
        parties: four,
        chambers: four_chambers,
        ..ok
    })
    .unwrap();
    let mut buf = Vec::new();
    assert_eq!(
        round_trip(SCHEMA_GENESIS_BODY, SCHEMA_VERSION_GENESIS, &body, &mut buf),
        body
    );
}

#[test]
fn witness_quorum_boundaries() {
    assert!(QUORUM.is_valid());
    let with = |f: fn(&mut WitnessQuorum)| {
        let mut q = QUORUM;
        f(&mut q);
        q.is_valid()
    };
    assert!(!with(|q| q.witnesses = 12));
    assert!(with(|q| {
        q.witnesses = 64;
        q.quorum = 40;
        q.byzantine_max = 15;
    }));
    assert!(!with(|q| {
        q.witnesses = 65;
        q.quorum = 40;
        q.byzantine_max = 14;
    }));
    assert!(!with(|q| q.quorum = 8));
    assert!(!with(|q| q.quorum = 14));
    assert!(with(|q| {
        q.quorum = 13;
        q.byzantine_max = 12;
    }));
    // 2q − n > f: 18 − 13 = 5 > 4 holds, 5 > 5 does not.
    assert!(!with(|q| q.byzantine_max = 5));
    assert!(with(|q| q.byzantine_max = 0));
    assert!(!with(|q| q.min_orgs = 6));
    assert!(with(|q| q.min_orgs = 9));
    assert!(!with(|q| q.min_orgs = 10));
    assert!(!with(|q| q.min_providers = 3));
    assert!(with(|q| q.min_providers = 9));
    assert!(!with(|q| q.min_providers = 10));
    assert!(!with(|q| q.min_regions = 2));
    assert!(with(|q| q.min_regions = 9));
    assert!(!with(|q| q.min_regions = 10));
    assert!(!with(|q| {
        q.witnesses = 255;
        q.quorum = 255;
    }));
}

// --- amendments and the signed wrapper -------------------------------------

fn amendment_parts() -> GenesisAmendmentParts<'static> {
    let mut amended = [SetCommitment {
        count: 0,
        root: Hash512::ZERO,
    }; AMENDABLE_SET_COUNT];
    amended.copy_from_slice(&sets()[..AMENDABLE_SET_COUNT]);
    amended[0].root = patterned64(0xEE);
    GenesisAmendmentParts {
        election_id: e(),
        seq: 1,
        previous_hash: patterned64(0x01),
        reason: AmendmentReason::DeviceReplacement,
        reason_hash: patterned64(0x02),
        time_bucket: TimeBucket::new(4_321),
        release_manifest_hash: patterned64(0x13),
        sets: amended,
    }
}

fn amendment_bytes() -> Vec<u8> {
    let body = GenesisAmendmentBody::new(&amendment_parts()).unwrap();
    encode_to_vec(SCHEMA_GENESIS_AMENDMENT_BODY, SCHEMA_VERSION_1, &body)
}

#[test]
fn amendment_vectors() {
    let body = GenesisAmendmentBody::new(&amendment_parts()).unwrap();
    assert_eq!(body.parts(), &amendment_parts());
    let bytes = amendment_bytes();
    let seq_at = HEADER_LEN + ident_len(E);
    let previous_at = seq_at + 8;
    let reason_at = previous_at + 64;
    let release_at = reason_at + 1 + 64 + 8;
    assert_eq!(bytes.len(), release_at + 64 + AMENDABLE_SET_COUNT * 72);
    let mut v = std::vec![valid("device replacement", bytes.clone())];
    let mut b = bytes.clone();
    b[seq_at..seq_at + 8].fill(0);
    v.push(invalid("number 0", b, "ValueOutOfRange", seq_at));
    let mut b = bytes.clone();
    b[previous_at..previous_at + 64].fill(0);
    v.push(invalid(
        "no previous",
        b,
        "InvalidPreviousHash",
        previous_at,
    ));
    let mut b = bytes.clone();
    b[reason_at] = 5;
    v.push(invalid("reason 5", b, "ValueOutOfRange", reason_at));
    let mut b = bytes.clone();
    b[reason_at + 1..reason_at + 65].fill(0);
    v.push(invalid(
        "no reason document",
        b,
        "InvalidPreviousHash",
        reason_at + 1,
    ));
    let mut b = bytes.clone();
    b[release_at..release_at + 64].fill(0);
    v.push(invalid(
        "no release manifest",
        b,
        "InvalidPreviousHash",
        release_at,
    ));
    publish!(
        GenesisAmendmentBody<'_>,
        "genesis_amendment_body.txt",
        "GenesisAmendmentBody",
        SCHEMA_GENESIS_AMENDMENT_BODY,
        SCHEMA_VERSION_1,
        &v,
    );
    let ok = amendment_parts();
    for p in [
        GenesisAmendmentParts { seq: 0, ..ok },
        GenesisAmendmentParts {
            previous_hash: Hash512::ZERO,
            ..ok
        },
        GenesisAmendmentParts {
            reason_hash: Hash512::ZERO,
            ..ok
        },
        GenesisAmendmentParts {
            release_manifest_hash: Hash512::ZERO,
            ..ok
        },
    ] {
        let err = GenesisAmendmentBody::new(&p).unwrap_err();
        assert_eq!(
            (err.kind(), err.offset()),
            (ErrorKind::InvariantViolation, 0)
        );
    }
    for (code, reason) in [
        (1, AmendmentReason::DeviceReplacement),
        (2, AmendmentReason::RosterChange),
        (3, AmendmentReason::ReleaseChange),
        (4, AmendmentReason::Other),
    ] {
        assert_eq!(AmendmentReason::from_code(code), Some(reason));
        assert_eq!(reason.code(), code);
    }
    assert_eq!(AmendmentReason::from_code(0), None);
}

fn witness_sigs(n: usize) -> Vec<GenesisWitnessSig<'static>> {
    WITNESS_IDS
        .iter()
        .cycle()
        .take(n)
        .map(|id| GenesisWitnessSig {
            witness_id: ident(id),
            sig: &SIG_W,
        })
        .collect()
}

fn signed_bytes(body: &[u8], n: usize) -> Vec<u8> {
    let signed = SignedGenesis::new(body, &SIG_X, &SIG_Y, &witness_sigs(n)).unwrap();
    encode_to_vec(SCHEMA_SIGNED_GENESIS, SCHEMA_VERSION_1, &signed)
}

#[test]
fn signed_genesis_vectors() {
    let genesis = genesis_bytes();
    let amendment = amendment_bytes();
    let signed = SignedGenesis::new(&genesis, &SIG_X, &SIG_Y, &witness_sigs(9)).unwrap();
    assert_eq!(signed.kind(), GenesisKind::Genesis);
    assert_eq!(signed.purpose(), PURPOSE_GENESIS);
    assert_eq!(signed.body_bytes(), genesis.as_slice());
    assert_eq!(
        signed.genesis(),
        Some(GenesisBody::new(&genesis_parts()).unwrap())
    );
    assert_eq!(signed.amendment(), None);
    assert_eq!(signed.commission_sig(), &SIG_X);
    assert_eq!(signed.committee_sig(), &SIG_Y);
    assert_eq!(signed.witness_count(), 9);
    assert_eq!(signed.witness_sigs().collect::<Vec<_>>(), witness_sigs(9));
    let signed_a = SignedGenesis::new(&amendment, &SIG_X, &SIG_Y, &witness_sigs(9)).unwrap();
    assert_eq!(signed_a.kind(), GenesisKind::Amendment);
    assert_eq!(signed_a.purpose(), PURPOSE_GENESIS_AMENDMENT);
    assert_eq!(signed_a.genesis(), None);
    assert_eq!(
        signed_a.amendment(),
        Some(GenesisAmendmentBody::new(&amendment_parts()).unwrap())
    );
    assert_eq!(GenesisKind::Genesis.purpose(), b"genesis");
    assert_eq!(GenesisKind::Amendment.purpose(), b"genesis-amendment");

    let bytes = signed_bytes(&genesis, 9);
    let body_at = HEADER_LEN + 4;
    let count_at = body_at + genesis.len() + 2 * HYBRID_SIG_LEN;
    let second = count_at + 4 + ident_len(b"w01") + HYBRID_SIG_LEN;
    let mut v = std::vec![
        valid("genesis, nine witnesses", bytes.clone()),
        valid("amendment, nine witnesses", signed_bytes(&amendment, 9)),
    ];
    // Each rejection is found before the bytes that follow it are read, so
    // the vectors end there.
    let mut b = bytes[..count_at + 4].to_vec();
    b[count_at..count_at + 4].copy_from_slice(&8u32.to_be_bytes());
    fix_len(&mut b);
    v.push(invalid(
        "eight witnesses",
        b,
        "InvariantViolation",
        count_at,
    ));
    let a = signed_bytes(&amendment, 9);
    let a_count_at = body_at + amendment.len() + 2 * HYBRID_SIG_LEN;
    let mut b = a[..a_count_at + 4].to_vec();
    b[a_count_at..a_count_at + 4].copy_from_slice(&8u32.to_be_bytes());
    fix_len(&mut b);
    v.push(invalid(
        "amendment, eight witnesses",
        b,
        "InvariantViolation",
        a_count_at,
    ));
    let mut b = bytes[..second + ident_len(b"w02")].to_vec();
    b[second + 4 + 2] = b'1';
    fix_len(&mut b);
    v.push(invalid("one witness twice", b, "Duplicate", second));
    let mut b = bytes[..body_at + genesis.len()].to_vec();
    fix_len(&mut b);
    b[body_at + 40..body_at + 104].fill(0);
    v.push(invalid(
        "genesis without a policy hash",
        b,
        "InvalidPreviousHash",
        body_at + 40,
    ));
    let policy = StationProgressPolicy::new(st(), 4, 30).unwrap();
    let other = encode_to_vec(SCHEMA_STATION_PROGRESS_POLICY, SCHEMA_VERSION_1, &policy);
    let mut b = bytes[..HEADER_LEN].to_vec();
    b.extend_from_slice(&u32::try_from(other.len()).unwrap().to_be_bytes());
    b.extend_from_slice(&other);
    fix_len(&mut b);
    v.push(invalid(
        "another schema as body",
        b,
        "SchemaMismatch",
        body_at + 4,
    ));
    publish!(
        SignedGenesis<'_>,
        "signed_genesis.txt",
        "SignedGenesis",
        SCHEMA_SIGNED_GENESIS,
        SCHEMA_VERSION_1,
        &v,
    );
}

#[test]
fn signed_genesis_rules() {
    let genesis = genesis_bytes();
    let amendment = amendment_bytes();
    let new = |body: &[u8], sigs: &[GenesisWitnessSig<'_>]| {
        SignedGenesis::new(body, &SIG_X, &SIG_Y, sigs)
            .map(|_| ())
            .map_err(|e| (e.kind(), e.offset()))
    };
    let bad = Err((ErrorKind::InvariantViolation, 0));
    assert_eq!(new(&genesis, &witness_sigs(9)), Ok(()));
    assert_eq!(new(&genesis, &witness_sigs(8)), bad);
    assert_eq!(new(&amendment, &witness_sigs(9)), Ok(()));
    assert_eq!(new(&amendment, &witness_sigs(8)), bad);
    let mut unsorted = witness_sigs(9);
    unsorted.swap(0, 1);
    assert_eq!(new(&genesis, &unsorted), bad);
    // More than 64 is refused even when ascending.
    let ids: Vec<&'static [u8]> = (0..=MAX_GENESIS_WITNESSES)
        .map(|i| Box::leak(std::format!("w{i:03}").into_boxed_str()).as_bytes())
        .collect();
    let many: Vec<GenesisWitnessSig<'static>> = ids
        .iter()
        .map(|id| GenesisWitnessSig {
            witness_id: ident(id),
            sig: &SIG_C,
        })
        .collect();
    assert_eq!(new(&genesis, &many), bad);
    assert_eq!(new(&genesis, &many[..MAX_GENESIS_WITNESSES]), Ok(()));
    // A body too long or of another schema; at the limit the header is
    // read.
    let long = std::vec![0u8; 16_385];
    assert_eq!(
        new(&long, &witness_sigs(9)),
        Err((ErrorKind::LengthExceedsMax, 0))
    );
    let at_limit = std::vec![0u8; 16_384];
    assert_eq!(
        new(&at_limit, &witness_sigs(9)),
        Err((ErrorKind::BadMagic, 0))
    );
    let commitment = SetCommitment {
        count: 1,
        root: Hash512::ZERO,
    };
    assert_eq!(commitment.encoded_len(), 72);
    let policy = StationProgressPolicy::new(st(), 4, 30).unwrap();
    let other = encode_to_vec(SCHEMA_STATION_PROGRESS_POLICY, SCHEMA_VERSION_1, &policy);
    assert_eq!(
        new(&other, &witness_sigs(9)),
        Err((ErrorKind::SchemaMismatch, 4))
    );
    // A genesis whose quorum is ten needs ten.
    let ten = GenesisBody::new(&GenesisParts {
        quorum: WitnessQuorum {
            quorum: 10,
            ..QUORUM
        },
        ..genesis_parts()
    })
    .unwrap();
    let ten_bytes = encode_to_vec(SCHEMA_GENESIS_BODY, SCHEMA_VERSION_GENESIS, &ten);
    assert_eq!(new(&ten_bytes, &witness_sigs(9)), bad);
    let mut ten_sigs = witness_sigs(9);
    ten_sigs.push(GenesisWitnessSig {
        witness_id: ident(b"w10"),
        sig: &SIG_C,
    });
    assert_eq!(new(&ten_bytes, &ten_sigs), Ok(()));
    let ten_signed = encode_to_vec(
        SCHEMA_SIGNED_GENESIS,
        SCHEMA_VERSION_1,
        &SignedGenesis::new(&ten_bytes, &SIG_X, &SIG_Y, &ten_sigs).unwrap(),
    );
    let decoded: SignedGenesis<'_> =
        decode_object(SCHEMA_SIGNED_GENESIS, SCHEMA_VERSION_1, &ten_signed).unwrap();
    assert_eq!(decoded.witness_count(), 10);
    assert_eq!(decoded.genesis().unwrap().quorum().quorum, 10);
    assert_eq!(MIN_QUORUM, 9);
}

// --- check-in events -------------------------------------------------------

fn count_parts(kind: ObserverCountKind) -> ObserverCountParts<'static> {
    ObserverCountParts {
        election_id: e(),
        station_id: st(),
        unit_id: unit(b"unit-a"),
        count: 203,
        kind,
        time_bucket: TimeBucket::new(4_321),
    }
}

fn swap_parts() -> CheckinUnitSwapParts<'static> {
    CheckinUnitSwapParts {
        election_id: e(),
        station_id: st(),
        failed_unit: unit(b"unit-a"),
        spare_unit: unit(b"unit-b"),
        at_slot: 4_330,
        confirmed: true,
        next_seq: 204,
        issued: 412,
        spoiled: 2,
        returned: 1,
    }
}

fn box_swap_parts() -> BoxUnitSwapParts<'static> {
    BoxUnitSwapParts {
        election_id: e(),
        box_id: bx(BOX),
        at_slot: 4_330,
        confirmed: true,
        sheets_in: 405,
    }
}

#[test]
fn checkin_event_vectors() {
    // ObserverCountAttestBody (0x003F).
    let periodic = ObserverCountAttestBody::new(&count_parts(ObserverCountKind::Periodic));
    let last = ObserverCountAttestBody::new(&count_parts(ObserverCountKind::Final));
    assert_eq!(last.parts(), &count_parts(ObserverCountKind::Final));
    let bytes = encode_to_vec(
        SCHEMA_OBSERVER_COUNT_ATTEST_BODY,
        SCHEMA_VERSION_1,
        &periodic,
    );
    let kind_at = HEADER_LEN + ident_len(E) + ident_len(ST) + ident_len(b"unit-a") + 8;
    let mut v = std::vec![
        valid("periodic, 203 check-ins", bytes.clone()),
        valid(
            "final",
            encode_to_vec(SCHEMA_OBSERVER_COUNT_ATTEST_BODY, SCHEMA_VERSION_1, &last)
        ),
    ];
    let mut b = bytes.clone();
    b[kind_at] = 3;
    v.push(invalid("kind 3", b, "ValueOutOfRange", kind_at));
    publish!(
        ObserverCountAttestBody<'_>,
        "observer_count_attest_body.txt",
        "ObserverCountAttestBody",
        SCHEMA_OBSERVER_COUNT_ATTEST_BODY,
        SCHEMA_VERSION_1,
        &v,
    );
    for (code, k) in [
        (1, ObserverCountKind::Periodic),
        (2, ObserverCountKind::Final),
    ] {
        assert_eq!(ObserverCountKind::from_code(code), Some(k));
        assert_eq!(k.code(), code);
    }
    assert_eq!(ObserverCountKind::from_code(0), None);

    // CheckinUnitSwapBody (0x0040).
    let swap = CheckinUnitSwapBody::new(&swap_parts()).unwrap();
    assert_eq!(swap.parts(), &swap_parts());
    assert_eq!(swap_parts().counts(), [203, 412, 2, 1]);
    let unconfirmed = CheckinUnitSwapParts {
        confirmed: false,
        issued: 0,
        spoiled: 0,
        returned: 0,
        ..swap_parts()
    };
    let bytes = encode_to_vec(SCHEMA_CHECKIN_UNIT_SWAP_BODY, SCHEMA_VERSION_1, &swap);
    let spare_at = HEADER_LEN + ident_len(E) + ident_len(ST) + ident_len(b"unit-a");
    let confirmed_at = spare_at + ident_len(b"unit-b") + 8;
    let seq_at = confirmed_at + 1;
    let counts_at = seq_at + 8;
    let mut v = std::vec![
        valid("confirmed swap", bytes.clone()),
        valid(
            "unconfirmed swap",
            encode_to_vec(
                SCHEMA_CHECKIN_UNIT_SWAP_BODY,
                SCHEMA_VERSION_1,
                &CheckinUnitSwapBody::new(&unconfirmed).unwrap()
            )
        ),
    ];
    let mut b = bytes.clone();
    b[spare_at + 4 + 5] = b'a';
    v.push(invalid(
        "spare is the failed unit",
        b,
        "InvariantViolation",
        spare_at,
    ));
    let mut b = bytes.clone();
    b[seq_at..seq_at + 8].fill(0);
    v.push(invalid("sequence 0", b, "ValueOutOfRange", seq_at));
    let mut b = bytes.clone();
    b[confirmed_at] = 0;
    v.push(invalid(
        "unconfirmed with counts",
        b,
        "InvariantViolation",
        counts_at,
    ));
    let mut b = bytes.clone();
    b[confirmed_at] = 2;
    v.push(invalid("confirmed 2", b, "InvalidBool", confirmed_at));
    publish!(
        CheckinUnitSwapBody<'_>,
        "checkin_unit_swap_body.txt",
        "CheckinUnitSwapBody",
        SCHEMA_CHECKIN_UNIT_SWAP_BODY,
        SCHEMA_VERSION_1,
        &v,
    );
    let ok = swap_parts();
    for p in [
        CheckinUnitSwapParts {
            spare_unit: unit(b"unit-a"),
            ..ok
        },
        CheckinUnitSwapParts { next_seq: 0, ..ok },
        CheckinUnitSwapParts {
            confirmed: false,
            ..ok
        },
        CheckinUnitSwapParts {
            issued: 1,
            ..unconfirmed
        },
        CheckinUnitSwapParts {
            spoiled: 1,
            ..unconfirmed
        },
        CheckinUnitSwapParts {
            returned: 1,
            ..unconfirmed
        },
    ] {
        assert!(!p.is_valid());
        let err = CheckinUnitSwapBody::new(&p).unwrap_err();
        assert_eq!(
            (err.kind(), err.offset()),
            (ErrorKind::InvariantViolation, 0)
        );
    }
    assert_eq!(
        CheckinUnitSwapParts {
            next_seq: 1,
            ..unconfirmed
        }
        .counts(),
        [0, 0, 0, 0]
    );

    // BoxUnitSwapBody (0x0041).
    let box_swap = BoxUnitSwapBody::new(&box_swap_parts()).unwrap();
    assert_eq!(box_swap.parts(), &box_swap_parts());
    let bytes = encode_to_vec(SCHEMA_BOX_UNIT_SWAP_BODY, SCHEMA_VERSION_1, &box_swap);
    let confirmed_at = HEADER_LEN + ident_len(E) + ident_len(BOX) + 8;
    let mut v = std::vec![valid("confirmed box swap", bytes.clone())];
    let unread = BoxUnitSwapParts {
        confirmed: false,
        sheets_in: 0,
        ..box_swap_parts()
    };
    v.push(valid(
        "unconfirmed box swap",
        encode_to_vec(
            SCHEMA_BOX_UNIT_SWAP_BODY,
            SCHEMA_VERSION_1,
            &BoxUnitSwapBody::new(&unread).unwrap(),
        ),
    ));
    let mut b = bytes.clone();
    b[confirmed_at] = 0;
    v.push(invalid(
        "unconfirmed with sheets",
        b,
        "InvariantViolation",
        confirmed_at + 1,
    ));
    publish!(
        BoxUnitSwapBody<'_>,
        "box_unit_swap_body.txt",
        "BoxUnitSwapBody",
        SCHEMA_BOX_UNIT_SWAP_BODY,
        SCHEMA_VERSION_1,
        &v,
    );
    let err = BoxUnitSwapBody::new(&BoxUnitSwapParts {
        confirmed: false,
        ..box_swap_parts()
    })
    .unwrap_err();
    assert_eq!(
        (err.kind(), err.offset()),
        (ErrorKind::InvariantViolation, 0)
    );
}

fn esig(id: &'static [u8], role: EventRole, o: &'static [u8]) -> EventSig<'static> {
    EventSig {
        signer_id: signer(id),
        role,
        org_id: org(o),
        sig: &SIG_C,
    }
}

#[test]
fn checkin_events_are_witnessed() {
    let count = encode_to_vec(
        SCHEMA_OBSERVER_COUNT_ATTEST_BODY,
        SCHEMA_VERSION_1,
        &ObserverCountAttestBody::new(&count_parts(ObserverCountKind::Final)),
    );
    let swap = encode_to_vec(
        SCHEMA_CHECKIN_UNIT_SWAP_BODY,
        SCHEMA_VERSION_1,
        &CheckinUnitSwapBody::new(&swap_parts()).unwrap(),
    );
    let box_swap = encode_to_vec(
        SCHEMA_BOX_UNIT_SWAP_BODY,
        SCHEMA_VERSION_1,
        &BoxUnitSwapBody::new(&box_swap_parts()).unwrap(),
    );
    assert_eq!(
        purpose_of(SCHEMA_OBSERVER_COUNT_ATTEST_BODY),
        Some(&b"observer-count"[..])
    );
    assert_eq!(
        purpose_of(SCHEMA_CHECKIN_UNIT_SWAP_BODY),
        Some(&b"checkin-swap"[..])
    );
    assert_eq!(
        purpose_of(SCHEMA_BOX_UNIT_SWAP_BODY),
        Some(&b"box-swap"[..])
    );
    let o1 = esig(b"o1", EventRole::Observer, b"PARTY-A");
    let o2 = esig(b"o2", EventRole::Observer, b"PARTY-B");
    let o3 = esig(b"o3", EventRole::Observer, b"PARTY-A");
    let c1 = esig(b"c1", EventRole::Clerk, b"NEC-11");
    let c2 = esig(b"c2", EventRole::Clerk, b"NEC-11");
    // Observers of two organisations, and nothing else, sign a count.
    let event = WitnessedEvent::new(&count, &[o1, o2]).unwrap();
    assert_eq!(event.purpose(), b"observer-count");
    assert!(WitnessedEvent::new(&count, &[o1, o2, o3]).is_ok());
    assert!(WitnessedEvent::new(&count, &[o1, o3]).is_err());
    assert!(WitnessedEvent::new(&count, &[o1]).is_err());
    assert!(WitnessedEvent::new(&count, &[c1, o1, o2]).is_err());
    assert!(WitnessedEvent::new(&count, &[]).is_err());
    // Two clerks and observers of two organisations sign a swap.
    for body in [&swap, &box_swap] {
        let event = WitnessedEvent::new(body, &[c1, c2, o1, o2]).unwrap();
        assert_eq!(event.sig_count(), 4);
        assert!(WitnessedEvent::new(body, &[c1, o1, o2]).is_err());
        assert!(WitnessedEvent::new(body, &[c1, c2, o1, o3]).is_err());
        assert!(WitnessedEvent::new(body, &[o1, o2]).is_err());
    }
    // A decoded event keeps the observers-only rule.
    let bytes = encode_to_vec(
        ityv_encoding::SCHEMA_WITNESSED_EVENT,
        ityv_encoding::SCHEMA_VERSION_WITNESSED,
        &WitnessedEvent::new(&count, &[o1, o2]).unwrap(),
    );
    let back: WitnessedEvent<'_> = decode_object(
        ityv_encoding::SCHEMA_WITNESSED_EVENT,
        ityv_encoding::SCHEMA_VERSION_WITNESSED,
        &bytes,
    )
    .unwrap();
    assert_eq!(back.body_schema(), SCHEMA_OBSERVER_COUNT_ATTEST_BODY);
    let decoded: ObserverCountAttestBody<'_> =
        back.body(SCHEMA_OBSERVER_COUNT_ATTEST_BODY).unwrap();
    assert_eq!(decoded.parts().count, 203);
    let swap_back = WitnessedEvent::new(&swap, &[c1, c2, o1, o2]).unwrap();
    let decoded: CheckinUnitSwapBody<'_> = swap_back.body(SCHEMA_CHECKIN_UNIT_SWAP_BODY).unwrap();
    assert_eq!(decoded.parts(), &swap_parts());
    let box_back = WitnessedEvent::new(&box_swap, &[c1, c2, o1, o2]).unwrap();
    let decoded: BoxUnitSwapBody<'_> = box_back.body(SCHEMA_BOX_UNIT_SWAP_BODY).unwrap();
    assert_eq!(decoded.parts(), &box_swap_parts());
    // An invalid body inside an event is refused.
    let mut broken = count.clone();
    let n = broken.len();
    broken[n - 9] = 3;
    assert!(WitnessedEvent::new(&broken, &[o1, o2]).is_err());
}

// --- property tests --------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn genesis_body_round_trips(
        day in any::<u64>(),
        counts in prop::array::uniform13(0u64..1_000_000),
        seats in (0u16..300, 0u16..300),
        q in 9u8..=13,
        f in 0u8..=4,
        custody in any::<u8>(),
    ) {
        let (a, b) = if seats.0 >= seats.1 { seats } else { (seats.1, seats.0) };
        let parties: &'static [PartyEntry<'static>] = Box::leak(Box::new([
            PartyEntry { seats: a, ..PARTIES[0] },
            PartyEntry { seats: b, ..PARTIES[1] },
        ]));
        let mut s = sets();
        for (slot, c) in s.iter_mut().zip(counts) {
            slot.count = c;
        }
        s[EntrySet::Witnesses.index()].count = 13;
        let quorum = WitnessQuorum { quorum: q, byzantine_max: f, ..QUORUM };
        let parts = GenesisParts {
            election_epoch_day: Day::new(day),
            parties,
            quorum,
            custody_quorum: custody,
            sets: s,
            ..genesis_parts()
        };
        let valid = 2 * u16::from(q) > 13 + u16::from(f) && custody >= 3;
        match GenesisBody::new(&parts) {
            Ok(body) => {
                prop_assert!(valid);
                let bytes = encode_to_vec(SCHEMA_GENESIS_BODY, SCHEMA_VERSION_GENESIS, &body);
                let back: GenesisBody<'_> =
                    decode_object(SCHEMA_GENESIS_BODY, SCHEMA_VERSION_GENESIS, &bytes).unwrap();
                prop_assert_eq!(back, body);
            }
            Err(_) => prop_assert!(!valid),
        }
    }

    #[test]
    fn checkin_swap_round_trips(
        at_slot in any::<u64>(),
        next_seq in 1u64..u64::MAX,
        issued in any::<u64>(),
        spoiled in any::<u64>(),
        returned in any::<u64>(),
    ) {
        let parts = CheckinUnitSwapParts {
            at_slot,
            next_seq,
            issued,
            spoiled,
            returned,
            ..swap_parts()
        };
        let body = CheckinUnitSwapBody::new(&parts).unwrap();
        let bytes = encode_to_vec(SCHEMA_CHECKIN_UNIT_SWAP_BODY, SCHEMA_VERSION_1, &body);
        let back: CheckinUnitSwapBody<'_> =
            decode_object(SCHEMA_CHECKIN_UNIT_SWAP_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back, body);
        prop_assert_eq!(parts.counts()[0], next_seq - 1);
    }

    #[test]
    fn witness_quorum_matches_reference(raw in any::<[u8; 6]>()) {
        let [witnesses, quorum, byzantine_max, min_orgs, min_providers, min_regions] = raw;
        let q = WitnessQuorum { witnesses, quorum, byzantine_max, min_orgs, min_providers, min_regions };
        let (n, k, f) = (u32::from(witnesses), u32::from(quorum), u32::from(byzantine_max));
        let within = |v: u8, floor: u8| v >= floor && v <= quorum;
        let expected = (13..=64).contains(&n) && k >= 9 && k <= n && 2 * k > n + f
            && within(min_orgs, 7) && within(min_providers, 4) && within(min_regions, 3);
        prop_assert_eq!(q.is_valid(), expected);
    }
}

#[test]
fn decoders_consume_exactly() {
    // Each entry decodes from a bare reader and leaves nothing behind.
    let entry = genesis_box();
    let mut buf = std::vec![0u8; entry.encoded_len()];
    entry
        .encode(&mut ityv_encoding::Writer::new(&mut buf))
        .unwrap();
    let mut r = Reader::new(&buf);
    assert_eq!(GenesisBox::decode(&mut r).unwrap(), entry);
    assert!(r.finish().is_ok());
}
