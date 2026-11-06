//! The voter roll (ENCODING.md §8.76–§8.81; ADR-0033, ADR-0040): the
//! genesis entry `RollAuthorityEntry` (0x0051, set 13), the witnessed
//! bodies `RollSourceExtractBody` (0x0052), `RollFreezeBody` (0x0053),
//! `RollCustodyReceiptBody` (0x0054), `RollAmendmentBody` (0x0055) and
//! the restricted `ContestedCheckin` (0x0056). Round trips, the
//! constructors' rules (the same as the decoders'), every decoder rule at
//! its offset, the published vector files, the signer sets in a
//! `WitnessedEvent` and property tests.
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

use common::{Vector, check_file, encode_to_vec, ident_len, render, self_check};
use ityv_encoding::{
    AuthorityId, ContestedCheckin, ContestedMessage, Day, Decode, ElectionId, Encode, EntrySet,
    ErrorKind, EventRole, EventSig, GenesisEntry, HEADER_LEN, HYBRID_SIG_LEN, HYBRID_VK_LEN,
    Hash512, MIN_CUSTODY_QUORUM, ModuleId, OrgId, PURPOSE_CONTESTED_CHECKIN,
    PURPOSE_ROLL_AMENDMENT, PURPOSE_ROLL_FREEZE, PURPOSE_ROLL_RECEIPT, PURPOSE_ROLL_SOURCE,
    ParticipationModuleSig, RollAmendmentBody, RollAmendmentParts, RollAmendmentReason,
    RollAuthorityEntry, RollAuthorityKind, RollCustodyReceiptBody, RollCustodyReceiptParts,
    RollFreezeBody, RollFreezeParts, RollSourceExtractBody, RollSourceExtractParts, RollSourceKind,
    RollState, SCHEMA_CONTESTED_CHECKIN, SCHEMA_ROLL_AMENDMENT_BODY, SCHEMA_ROLL_AUTHORITY_ENTRY,
    SCHEMA_ROLL_CUSTODY_RECEIPT_BODY, SCHEMA_ROLL_FREEZE_BODY, SCHEMA_ROLL_SOURCE_EXTRACT_BODY,
    SCHEMA_VERSION_1, SCHEMA_VERSION_WITNESSED, SCHEMA_WITNESSED_EVENT, SchemaId, SignerId,
    StationId, TimeBucket, Token192, UnitId, WITNESSED_BODY_SCHEMAS, WitnessedEvent, decode_object,
    purpose_of, roles_satisfied, schema_version,
};
use proptest::prelude::*;
use std::boxed::Box;
use std::vec::Vec;

fn e() -> ElectionId<'static> {
    ElectionId::new(b"KR-2030-PRES").unwrap()
}

fn aid(id: &'static [u8]) -> AuthorityId<'static> {
    AuthorityId::new(id).unwrap()
}

fn station() -> StationId<'static> {
    StationId::new(b"ST-11-0001").unwrap()
}

fn patterned(seed: u8) -> Hash512 {
    common::patterned64(seed)
}

fn leak(v: Vec<u8>) -> &'static [u8] {
    Box::leak(v.into_boxed_slice())
}

static VK: [u8; HYBRID_VK_LEN] = [0x5A; HYBRID_VK_LEN];
static SIG_A: [u8; HYBRID_SIG_LEN] = [0xA1; HYBRID_SIG_LEN];
static SIG_B: [u8; HYBRID_SIG_LEN] = [0xB2; HYBRID_SIG_LEN];
static SIG_C: [u8; HYBRID_SIG_LEN] = [0xC3; HYBRID_SIG_LEN];
static PSEUDONYM: [u8; 64] = [0x77; 64];

fn authority() -> RollAuthorityEntry<'static> {
    RollAuthorityEntry {
        authority_id: aid(b"ROLL-JUD"),
        org_id: OrgId::new(b"COURT-ADMIN").unwrap(),
        kind: RollAuthorityKind::CustodianJudiciary,
        key: &VK,
    }
}

fn state(seed: u8) -> RollState {
    RollState {
        entries_root: patterned(seed),
        entry_count: 41_000_000,
        counts_hash: patterned(seed.wrapping_add(1)),
        pseudonym_root: patterned(seed.wrapping_add(2)),
    }
}

fn extract_parts() -> RollSourceExtractParts<'static> {
    RollSourceExtractParts {
        election_id: e(),
        authority_id: aid(b"GU-JONGNO"),
        kind: RollSourceKind::Residents,
        precinct: Some(station()),
        reference_day: Day::new(22_000),
        entry_count: 4_210,
        entries_root: patterned(0x20),
    }
}

fn freeze_parts() -> RollFreezeParts<'static> {
    RollFreezeParts {
        election_id: e(),
        state: state(0x30),
        sources_root: patterned(0x40),
        source_count: 3,
        time_bucket: TimeBucket::new(96),
    }
}

fn receipt_parts() -> RollCustodyReceiptParts<'static> {
    let s = state(0x30);
    RollCustodyReceiptParts {
        election_id: e(),
        custodian: aid(b"ROLL-JUD"),
        subject_hash: patterned(0x50),
        entries_root: s.entries_root,
        entry_count: s.entry_count,
        counts_hash: s.counts_hash,
        sources_root: Some(patterned(0x40)),
        pseudonym_root: Some(s.pseudonym_root),
        time_bucket: TimeBucket::new(100),
    }
}

fn amendment_parts() -> RollAmendmentParts<'static> {
    RollAmendmentParts {
        election_id: e(),
        seq: 1,
        previous_hash: patterned(0x50),
        reason: RollAmendmentReason::Death,
        authority_id: aid(b"ROLL-DEATHS"),
        basis_hash: patterned(0x60),
        state: state(0x70),
        time_bucket: TimeBucket::new(200),
    }
}

fn message() -> ContestedMessage<'static> {
    ContestedMessage {
        election_id: e(),
        station_id: station(),
        unit_id: UnitId::new(b"CU-0001").unwrap(),
        pseudonym: &PSEUDONYM,
        envelope_label: Token192([0x42; 24]),
    }
}

fn message_bytes() -> &'static [u8] {
    let m = message();
    let mut buf = std::vec![0u8; m.encoded_len()];
    let mut w = ityv_encoding::Writer::new(&mut buf);
    m.encode(&mut w).unwrap();
    assert_eq!(w.finish(), buf.len());
    leak(buf)
}

fn module_sig(
    id: &'static [u8],
    sig: &'static [u8; HYBRID_SIG_LEN],
) -> ParticipationModuleSig<'static> {
    ParticipationModuleSig {
        module_id: ModuleId::new(id).unwrap(),
        sig,
    }
}

fn contested() -> ContestedCheckin<'static> {
    ContestedCheckin::new(
        message_bytes(),
        &SIG_A,
        &[module_sig(b"MOD-P1", &SIG_B), module_sig(b"MOD-P2", &SIG_C)],
    )
    .unwrap()
}

fn round_trip<'a, T: Encode + Decode<'a> + PartialEq + core::fmt::Debug>(
    schema: SchemaId,
    value: &T,
    buf: &'a mut Vec<u8>,
) -> T {
    *buf = encode_to_vec(schema, SCHEMA_VERSION_1, value);
    let back: T = decode_object(schema, SCHEMA_VERSION_1, buf).unwrap();
    back
}

fn fix_len(v: &mut [u8]) {
    let body_len = u32::try_from(v.len() - HEADER_LEN).unwrap();
    v[12..16].copy_from_slice(&body_len.to_be_bytes());
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

#[test]
fn the_schemas_purposes_and_codes_are_registered() {
    let schemas = [
        (SCHEMA_ROLL_AUTHORITY_ENTRY, 0x0051),
        (SCHEMA_ROLL_SOURCE_EXTRACT_BODY, 0x0052),
        (SCHEMA_ROLL_FREEZE_BODY, 0x0053),
        (SCHEMA_ROLL_CUSTODY_RECEIPT_BODY, 0x0054),
        (SCHEMA_ROLL_AMENDMENT_BODY, 0x0055),
        (SCHEMA_CONTESTED_CHECKIN, 0x0056),
    ];
    for (schema, raw) in schemas {
        assert_eq!(schema.get(), raw);
        assert_eq!(schema_version(schema), SCHEMA_VERSION_1);
    }
    assert_eq!(EntrySet::RollAuthorities.code(), 13);
    assert_eq!(EntrySet::RollAuthorities.index(), 12);
    assert!(!EntrySet::RollAuthorities.amendable());
    assert_eq!(
        EntrySet::RollAuthorities.schema(),
        Some(SCHEMA_ROLL_AUTHORITY_ENTRY)
    );
    assert_eq!(EntrySet::ALL.last(), Some(&EntrySet::RollAuthorities));
    assert_eq!(
        <RollAuthorityEntry<'_> as GenesisEntry<'_>>::SET,
        EntrySet::RollAuthorities
    );
    assert_eq!(authority().key(), b"ROLL-JUD");
    for (schema, purpose, text) in [
        (
            SCHEMA_ROLL_SOURCE_EXTRACT_BODY,
            PURPOSE_ROLL_SOURCE,
            &b"roll-source"[..],
        ),
        (SCHEMA_ROLL_FREEZE_BODY, PURPOSE_ROLL_FREEZE, b"roll-freeze"),
        (
            SCHEMA_ROLL_CUSTODY_RECEIPT_BODY,
            PURPOSE_ROLL_RECEIPT,
            b"roll-receipt",
        ),
        (
            SCHEMA_ROLL_AMENDMENT_BODY,
            PURPOSE_ROLL_AMENDMENT,
            b"roll-amendment",
        ),
    ] {
        assert_eq!(purpose, text);
        assert!(WITNESSED_BODY_SCHEMAS.contains(&schema));
        assert_eq!(purpose_of(schema), Some(purpose));
    }
    // The entry and the restricted check-in are no witnessed bodies.
    for schema in [SCHEMA_ROLL_AUTHORITY_ENTRY, SCHEMA_CONTESTED_CHECKIN] {
        assert!(!WITNESSED_BODY_SCHEMAS.contains(&schema));
        assert_eq!(purpose_of(schema), None);
    }
    assert_eq!(PURPOSE_CONTESTED_CHECKIN, b"contested-checkin");
    assert_eq!(MIN_CUSTODY_QUORUM, 3);
    assert_eq!(EventRole::from_code(11), Some(EventRole::RollSource));
    assert_eq!(EventRole::from_code(12), Some(EventRole::RollCustodian));
    assert_eq!(EventRole::from_code(13), None);
    assert_eq!(EventRole::RollSource.code(), 11);
    assert_eq!(EventRole::RollCustodian.code(), 12);
}

#[test]
fn the_codes_name_their_functions() {
    use RollAuthorityKind as K;
    for code in 0u8..=255 {
        let kind = RollAuthorityKind::from_code(code);
        assert_eq!(
            kind.is_some(),
            (1..=6).contains(&code) || (11..=14).contains(&code)
        );
        if let Some(k) = kind {
            assert_eq!(k.code(), code);
            assert_eq!(k.is_custodian(), code >= 11);
        }
        let source = RollSourceKind::from_code(code);
        assert_eq!(source.is_some(), (1..=5).contains(&code));
        if let Some(s) = source {
            assert_eq!(s.code(), code);
        }
        let reason = RollAmendmentReason::from_code(code);
        assert_eq!(reason.is_some(), (1..=5).contains(&code));
        if let Some(r) = reason {
            assert_eq!(r.code(), code);
        }
    }
    assert_eq!(RollSourceKind::Residents.authority(), K::ResidentExtract);
    assert_eq!(RollSourceKind::Snapshot.authority(), K::ResidentSnapshot);
    assert_eq!(RollSourceKind::Deaths.authority(), K::Deaths);
    assert_eq!(
        RollSourceKind::Disqualifications.authority(),
        K::Disqualification
    );
    assert_eq!(RollSourceKind::Overseas.authority(), K::Overseas);
    assert_eq!(
        RollAmendmentReason::ObjectionDecision.source(),
        K::ResidentExtract
    );
    assert_eq!(RollAmendmentReason::AppealDecision.source(), K::AppealCourt);
    assert_eq!(RollAmendmentReason::Death.source(), K::Deaths);
    assert_eq!(
        RollAmendmentReason::Disqualification.source(),
        K::Disqualification
    );
    assert_eq!(RollAmendmentReason::Overseas.source(), K::Overseas);
}

#[test]
fn every_body_round_trips() {
    let entry = authority();
    let mut buf = Vec::new();
    assert_eq!(
        round_trip(SCHEMA_ROLL_AUTHORITY_ENTRY, &entry, &mut buf),
        entry
    );
    assert_eq!(
        buf.len(),
        HEADER_LEN + ident_len(b"ROLL-JUD") + ident_len(b"COURT-ADMIN") + 1 + HYBRID_VK_LEN
    );

    let extract = RollSourceExtractBody::new(&extract_parts()).unwrap();
    assert_eq!(extract.parts(), &extract_parts());
    let mut buf = Vec::new();
    assert_eq!(
        round_trip(SCHEMA_ROLL_SOURCE_EXTRACT_BODY, &extract, &mut buf),
        extract
    );
    assert_eq!(
        buf.len(),
        HEADER_LEN
            + ident_len(b"KR-2030-PRES")
            + ident_len(b"GU-JONGNO")
            + 1
            + 1
            + ident_len(b"ST-11-0001")
            + 8
            + 8
            + 64
    );
    for kind in [
        RollSourceKind::Snapshot,
        RollSourceKind::Deaths,
        RollSourceKind::Disqualifications,
        RollSourceKind::Overseas,
    ] {
        let extract = RollSourceExtractBody::new(&RollSourceExtractParts {
            kind,
            precinct: None,
            ..extract_parts()
        })
        .unwrap();
        let mut buf = Vec::new();
        assert_eq!(
            round_trip(SCHEMA_ROLL_SOURCE_EXTRACT_BODY, &extract, &mut buf),
            extract
        );
    }

    let freeze = RollFreezeBody::new(&freeze_parts()).unwrap();
    assert_eq!(freeze.parts(), &freeze_parts());
    let mut buf = Vec::new();
    assert_eq!(
        round_trip(SCHEMA_ROLL_FREEZE_BODY, &freeze, &mut buf),
        freeze
    );
    assert_eq!(
        buf.len(),
        HEADER_LEN + ident_len(b"KR-2030-PRES") + 64 + 8 + 64 + 64 + 64 + 4 + 8
    );

    let receipt = RollCustodyReceiptBody::new(&receipt_parts()).unwrap();
    assert_eq!(receipt.parts(), &receipt_parts());
    let mut buf = Vec::new();
    assert_eq!(
        round_trip(SCHEMA_ROLL_CUSTODY_RECEIPT_BODY, &receipt, &mut buf),
        receipt
    );
    assert_eq!(
        buf.len(),
        HEADER_LEN
            + ident_len(b"KR-2030-PRES")
            + ident_len(b"ROLL-JUD")
            + 64
            + 64
            + 8
            + 64
            + 65
            + 65
            + 8
    );
    let bare = RollCustodyReceiptBody::new(&RollCustodyReceiptParts {
        sources_root: None,
        pseudonym_root: None,
        ..receipt_parts()
    })
    .unwrap();
    let mut buf = Vec::new();
    assert_eq!(
        round_trip(SCHEMA_ROLL_CUSTODY_RECEIPT_BODY, &bare, &mut buf),
        bare
    );

    let amendment = RollAmendmentBody::new(&amendment_parts()).unwrap();
    assert_eq!(amendment.parts(), &amendment_parts());
    let mut buf = Vec::new();
    assert_eq!(
        round_trip(SCHEMA_ROLL_AMENDMENT_BODY, &amendment, &mut buf),
        amendment
    );
    assert_eq!(
        buf.len(),
        HEADER_LEN
            + ident_len(b"KR-2030-PRES")
            + 8
            + 64
            + 1
            + ident_len(b"ROLL-DEATHS")
            + 64
            + 64
            + 8
            + 64
            + 64
            + 8
    );

    let checkin = contested();
    assert_eq!(checkin.message(), &message());
    assert_eq!(checkin.message_bytes(), message_bytes());
    assert_eq!(checkin.unit_sig(), &SIG_A);
    assert_eq!(checkin.module_sig_count(), 2);
    assert_eq!(
        checkin
            .module_sigs()
            .map(|s| s.module_id)
            .collect::<Vec<_>>(),
        [
            ModuleId::new(b"MOD-P1").unwrap(),
            ModuleId::new(b"MOD-P2").unwrap()
        ]
    );
    let mut buf = Vec::new();
    assert_eq!(
        round_trip(SCHEMA_CONTESTED_CHECKIN, &checkin, &mut buf),
        checkin
    );
    assert_eq!(
        buf.len(),
        HEADER_LEN
            + message_bytes().len()
            + HYBRID_SIG_LEN
            + 4
            + 2 * HYBRID_SIG_LEN
            + ident_len(b"MOD-P1")
            + ident_len(b"MOD-P2")
    );
    assert_eq!(
        message_bytes().len(),
        ident_len(b"KR-2030-PRES") + ident_len(b"ST-11-0001") + ident_len(b"CU-0001") + 64 + 24
    );
    // `Debug` shows neither the pseudonym nor the label.
    let shown = std::format!("{checkin:?}");
    assert!(shown.contains("ST-11-0001") || shown.contains("station_id"));
    assert!(!shown.contains("119, 119"));
    assert!(!shown.contains("envelope_label"));
}

#[test]
fn the_constructors_keep_the_decoders_rules() {
    // A precinct exactly for a resident extract; a nonzero root.
    for parts in [
        RollSourceExtractParts {
            precinct: None,
            ..extract_parts()
        },
        RollSourceExtractParts {
            kind: RollSourceKind::Deaths,
            ..extract_parts()
        },
        RollSourceExtractParts {
            entries_root: Hash512::ZERO,
            ..extract_parts()
        },
    ] {
        assert_eq!(
            RollSourceExtractBody::new(&parts).unwrap_err().kind(),
            ErrorKind::InvariantViolation
        );
    }
    let zero_state = |which: usize| {
        let mut s = state(0x30);
        match which {
            0 => s.entries_root = Hash512::ZERO,
            1 => s.counts_hash = Hash512::ZERO,
            _ => s.pseudonym_root = Hash512::ZERO,
        }
        s
    };
    let mut freezes: Vec<RollFreezeParts<'static>> = (0..3)
        .map(|i| RollFreezeParts {
            state: zero_state(i),
            ..freeze_parts()
        })
        .collect();
    freezes.push(RollFreezeParts {
        sources_root: Hash512::ZERO,
        ..freeze_parts()
    });
    freezes.push(RollFreezeParts {
        source_count: 0,
        ..freeze_parts()
    });
    for parts in &freezes {
        assert!(RollFreezeBody::new(parts).is_err());
    }
    for parts in [
        RollCustodyReceiptParts {
            subject_hash: Hash512::ZERO,
            ..receipt_parts()
        },
        RollCustodyReceiptParts {
            entries_root: Hash512::ZERO,
            ..receipt_parts()
        },
        RollCustodyReceiptParts {
            counts_hash: Hash512::ZERO,
            ..receipt_parts()
        },
        RollCustodyReceiptParts {
            sources_root: Some(Hash512::ZERO),
            ..receipt_parts()
        },
        RollCustodyReceiptParts {
            pseudonym_root: Some(Hash512::ZERO),
            ..receipt_parts()
        },
    ] {
        assert!(RollCustodyReceiptBody::new(&parts).is_err());
    }
    let mut amendments = std::vec![
        RollAmendmentParts {
            seq: 0,
            ..amendment_parts()
        },
        RollAmendmentParts {
            previous_hash: Hash512::ZERO,
            ..amendment_parts()
        },
        RollAmendmentParts {
            basis_hash: Hash512::ZERO,
            ..amendment_parts()
        },
    ];
    for i in 0..3 {
        amendments.push(RollAmendmentParts {
            state: zero_state(i),
            ..amendment_parts()
        });
    }
    for parts in &amendments {
        assert!(RollAmendmentBody::new(parts).is_err());
    }
    // A contested check-in: a whole field group, at most four distinct
    // modules.
    let mut longer = message_bytes().to_vec();
    longer.push(0);
    let longer = leak(longer);
    assert_eq!(
        ContestedCheckin::new(longer, &SIG_A, &[])
            .unwrap_err()
            .kind(),
        ErrorKind::TrailingBytes
    );
    let five: Vec<ParticipationModuleSig<'static>> = [&b"M1"[..], b"M2", b"M3", b"M4", b"M5"]
        .iter()
        .map(|id| ParticipationModuleSig {
            module_id: ModuleId::new(id).unwrap(),
            sig: &SIG_B,
        })
        .collect();
    assert_eq!(
        ContestedCheckin::new(message_bytes(), &SIG_A, &five)
            .unwrap_err()
            .kind(),
        ErrorKind::CountExceedsMax
    );
    assert_eq!(
        ContestedCheckin::new(message_bytes(), &SIG_A, &five[..4])
            .unwrap()
            .module_sig_count(),
        4
    );
    let twice = [module_sig(b"MOD-P1", &SIG_B), module_sig(b"MOD-P1", &SIG_C)];
    assert_eq!(
        ContestedCheckin::new(message_bytes(), &SIG_A, &twice)
            .unwrap_err()
            .kind(),
        ErrorKind::Duplicate
    );
}

fn authority_vectors() -> Vec<Vector> {
    let bytes = encode_to_vec(SCHEMA_ROLL_AUTHORITY_ENTRY, SCHEMA_VERSION_1, &authority());
    let kind_at = HEADER_LEN + ident_len(b"ROLL-JUD") + ident_len(b"COURT-ADMIN");
    let mut v = std::vec![valid("custodian: the court administration", bytes.clone())];
    let source = RollAuthorityEntry {
        authority_id: aid(b"GU-JONGNO"),
        org_id: OrgId::new(b"JONGNO-GU").unwrap(),
        kind: RollAuthorityKind::ResidentExtract,
        key: &VK,
    };
    v.push(valid(
        "source: a district head",
        encode_to_vec(SCHEMA_ROLL_AUTHORITY_ENTRY, SCHEMA_VERSION_1, &source),
    ));
    for (code, label) in [
        (0u8, "kind 0"),
        (7, "kind 7"),
        (10, "kind 10"),
        (15, "kind 15"),
    ] {
        let mut b = bytes.clone();
        b[kind_at] = code;
        v.push(invalid(label, b, "ValueOutOfRange", kind_at));
    }
    v
}

fn extract_vectors() -> Vec<Vector> {
    let body = RollSourceExtractBody::new(&extract_parts()).unwrap();
    let bytes = encode_to_vec(SCHEMA_ROLL_SOURCE_EXTRACT_BODY, SCHEMA_VERSION_1, &body);
    let kind_at = HEADER_LEN + ident_len(b"KR-2030-PRES") + ident_len(b"GU-JONGNO");
    let precinct_at = kind_at + 1;
    let day_at = precinct_at + 1 + ident_len(b"ST-11-0001");
    let root_at = day_at + 8 + 8;
    let mut v = std::vec![valid("residents of one precinct", bytes.clone())];
    let deaths = RollSourceExtractBody::new(&RollSourceExtractParts {
        authority_id: aid(b"ROLL-DEATHS"),
        kind: RollSourceKind::Deaths,
        precinct: None,
        ..extract_parts()
    })
    .unwrap();
    let deaths_bytes = encode_to_vec(SCHEMA_ROLL_SOURCE_EXTRACT_BODY, SCHEMA_VERSION_1, &deaths);
    v.push(valid("deaths, no precinct", deaths_bytes.clone()));
    for (code, label) in [(0u8, "kind 0"), (6, "kind 6")] {
        let mut b = bytes.clone();
        b[kind_at] = code;
        v.push(invalid(label, b, "ValueOutOfRange", kind_at));
    }
    // A resident extract without its precinct.
    let mut b = bytes[..precinct_at].to_vec();
    b.push(0);
    b.extend_from_slice(&bytes[day_at..]);
    fix_len(&mut b);
    v.push(invalid(
        "residents without a precinct",
        b,
        "InvariantViolation",
        precinct_at,
    ));
    // A list of deaths with a precinct.
    let mut b = bytes.clone();
    b[kind_at] = RollSourceKind::Deaths.code();
    v.push(invalid(
        "deaths with a precinct",
        b,
        "InvariantViolation",
        precinct_at,
    ));
    let mut b = bytes.clone();
    b[precinct_at] = 2;
    v.push(invalid("presence 2", b, "InvalidPresenceTag", precinct_at));
    let mut b = bytes.clone();
    b[root_at..root_at + 64].fill(0);
    v.push(invalid("no root", b, "InvalidPreviousHash", root_at));
    v
}

fn freeze_vectors() -> Vec<Vector> {
    let body = RollFreezeBody::new(&freeze_parts()).unwrap();
    let bytes = encode_to_vec(SCHEMA_ROLL_FREEZE_BODY, SCHEMA_VERSION_1, &body);
    let entries_at = HEADER_LEN + ident_len(b"KR-2030-PRES");
    let counts_at = entries_at + 64 + 8;
    let pseudonyms_at = counts_at + 64;
    let sources_at = pseudonyms_at + 64;
    let source_count_at = sources_at + 64;
    let mut v = std::vec![valid("three sources", bytes.clone())];
    for (at, label) in [
        (entries_at, "no entries root"),
        (counts_at, "no counts hash"),
        (pseudonyms_at, "no pseudonym root"),
        (sources_at, "no sources root"),
    ] {
        let mut b = bytes.clone();
        b[at..at + 64].fill(0);
        v.push(invalid(label, b, "InvalidPreviousHash", at));
    }
    let mut b = bytes.clone();
    b[source_count_at..source_count_at + 4].fill(0);
    v.push(invalid("no source", b, "ValueOutOfRange", source_count_at));
    v
}

fn receipt_vectors() -> Vec<Vector> {
    let body = RollCustodyReceiptBody::new(&receipt_parts()).unwrap();
    let bytes = encode_to_vec(SCHEMA_ROLL_CUSTODY_RECEIPT_BODY, SCHEMA_VERSION_1, &body);
    let subject_at = HEADER_LEN + ident_len(b"KR-2030-PRES") + ident_len(b"ROLL-JUD");
    let entries_at = subject_at + 64;
    let counts_at = entries_at + 64 + 8;
    let sources_at = counts_at + 64;
    let pseudonyms_at = sources_at + 65;
    let mut v = std::vec![valid(
        "for a freeze, with the pseudonym root",
        bytes.clone()
    )];
    let bare = RollCustodyReceiptBody::new(&RollCustodyReceiptParts {
        sources_root: None,
        pseudonym_root: None,
        ..receipt_parts()
    })
    .unwrap();
    v.push(valid(
        "for an amendment, without the pseudonym root",
        encode_to_vec(SCHEMA_ROLL_CUSTODY_RECEIPT_BODY, SCHEMA_VERSION_1, &bare),
    ));
    for (at, label) in [
        (subject_at, "no subject"),
        (entries_at, "no entries root"),
        (counts_at, "no counts hash"),
        (sources_at + 1, "zero sources root"),
        (pseudonyms_at + 1, "zero pseudonym root"),
    ] {
        let mut b = bytes.clone();
        b[at..at + 64].fill(0);
        v.push(invalid(label, b, "InvalidPreviousHash", at));
    }
    for (at, label) in [
        (sources_at, "sources presence 2"),
        (pseudonyms_at, "pseudonym presence 2"),
    ] {
        let mut b = bytes.clone();
        b[at] = 2;
        v.push(invalid(label, b, "InvalidPresenceTag", at));
    }
    v
}

fn amendment_vectors() -> Vec<Vector> {
    let body = RollAmendmentBody::new(&amendment_parts()).unwrap();
    let bytes = encode_to_vec(SCHEMA_ROLL_AMENDMENT_BODY, SCHEMA_VERSION_1, &body);
    let seq_at = HEADER_LEN + ident_len(b"KR-2030-PRES");
    let previous_at = seq_at + 8;
    let reason_at = previous_at + 64;
    let basis_at = reason_at + 1 + ident_len(b"ROLL-DEATHS");
    let entries_at = basis_at + 64;
    let counts_at = entries_at + 64 + 8;
    let pseudonyms_at = counts_at + 64;
    let mut v = std::vec![valid("first amendment: a death", bytes.clone())];
    let mut b = bytes.clone();
    b[seq_at..seq_at + 8].fill(0);
    v.push(invalid("number 0", b, "ValueOutOfRange", seq_at));
    for (code, label) in [(0u8, "reason 0"), (6, "reason 6")] {
        let mut b = bytes.clone();
        b[reason_at] = code;
        v.push(invalid(label, b, "ValueOutOfRange", reason_at));
    }
    for (at, label) in [
        (previous_at, "no previous body"),
        (basis_at, "no basis"),
        (entries_at, "no entries root"),
        (counts_at, "no counts hash"),
        (pseudonyms_at, "no pseudonym root"),
    ] {
        let mut b = bytes.clone();
        b[at..at + 64].fill(0);
        v.push(invalid(label, b, "InvalidPreviousHash", at));
    }
    v
}

fn contested_vectors() -> Vec<Vector> {
    let bytes = encode_to_vec(SCHEMA_CONTESTED_CHECKIN, SCHEMA_VERSION_1, &contested());
    let count_at = HEADER_LEN + message_bytes().len() + HYBRID_SIG_LEN;
    let first_module = count_at + 4;
    let second_module = first_module + ident_len(b"MOD-P1") + HYBRID_SIG_LEN;
    let mut v = std::vec![valid("two party modules", bytes.clone())];
    let mut b = bytes.clone();
    b[count_at..count_at + 4].copy_from_slice(&5u32.to_be_bytes());
    v.push(invalid("five modules", b, "CountExceedsMax", count_at));
    // The first module twice.
    let mut b = bytes[..second_module].to_vec();
    b.extend_from_slice(&bytes[first_module..first_module + ident_len(b"MOD-P1")]);
    b.extend_from_slice(&SIG_C);
    fix_len(&mut b);
    v.push(invalid("module repeated", b, "Duplicate", second_module));
    v
}

#[test]
fn the_vector_files_are_current_and_self_consistent() {
    let files: [(&str, &str, SchemaId, Vec<Vector>); 6] = [
        (
            "roll_authority_entry.txt",
            "RollAuthorityEntry",
            SCHEMA_ROLL_AUTHORITY_ENTRY,
            authority_vectors(),
        ),
        (
            "roll_source_extract_body.txt",
            "RollSourceExtractBody",
            SCHEMA_ROLL_SOURCE_EXTRACT_BODY,
            extract_vectors(),
        ),
        (
            "roll_freeze_body.txt",
            "RollFreezeBody",
            SCHEMA_ROLL_FREEZE_BODY,
            freeze_vectors(),
        ),
        (
            "roll_custody_receipt_body.txt",
            "RollCustodyReceiptBody",
            SCHEMA_ROLL_CUSTODY_RECEIPT_BODY,
            receipt_vectors(),
        ),
        (
            "roll_amendment_body.txt",
            "RollAmendmentBody",
            SCHEMA_ROLL_AMENDMENT_BODY,
            amendment_vectors(),
        ),
        (
            "contested_checkin.txt",
            "ContestedCheckin",
            SCHEMA_CONTESTED_CHECKIN,
            contested_vectors(),
        ),
    ];
    for (file, title, schema, vectors) in files {
        let content = render(title, schema, &vectors);
        check_file(file, &content);
        self_check(&content, |b| {
            Ok(match schema.get() {
                0x0051 => {
                    let v: RollAuthorityEntry<'_> = decode_object(schema, SCHEMA_VERSION_1, b)?;
                    encode_to_vec(schema, SCHEMA_VERSION_1, &v)
                }
                0x0052 => {
                    let v: RollSourceExtractBody<'_> = decode_object(schema, SCHEMA_VERSION_1, b)?;
                    encode_to_vec(schema, SCHEMA_VERSION_1, &v)
                }
                0x0053 => {
                    let v: RollFreezeBody<'_> = decode_object(schema, SCHEMA_VERSION_1, b)?;
                    encode_to_vec(schema, SCHEMA_VERSION_1, &v)
                }
                0x0054 => {
                    let v: RollCustodyReceiptBody<'_> = decode_object(schema, SCHEMA_VERSION_1, b)?;
                    encode_to_vec(schema, SCHEMA_VERSION_1, &v)
                }
                0x0055 => {
                    let v: RollAmendmentBody<'_> = decode_object(schema, SCHEMA_VERSION_1, b)?;
                    encode_to_vec(schema, SCHEMA_VERSION_1, &v)
                }
                _ => {
                    let v: ContestedCheckin<'_> = decode_object(schema, SCHEMA_VERSION_1, b)?;
                    encode_to_vec(schema, SCHEMA_VERSION_1, &v)
                }
            })
        });
    }
}

fn esig(id: &'static [u8], role: EventRole, org: &'static [u8]) -> EventSig<'static> {
    EventSig {
        signer_id: SignerId::new(id).unwrap(),
        role,
        org_id: OrgId::new(org).unwrap(),
        sig: &SIG_A,
    }
}

#[test]
fn each_roll_body_takes_exactly_its_signers() {
    let commission = esig(b"a-nec", EventRole::Commission, b"NEC");
    let committee = esig(b"b-ivc", EventRole::Committee, b"IVC");
    let source = esig(b"c-src", EventRole::RollSource, b"COURT-ADMIN");
    let custodian = esig(b"d-cus", EventRole::RollCustodian, b"COURT-ADMIN");
    let clerk = esig(b"e-clerk", EventRole::Clerk, b"NEC");
    let authority = esig(b"f-auth", EventRole::Authority, b"COURT");
    let ok = |schema: SchemaId, sigs: &[EventSig<'static>]| {
        roles_satisfied(schema, || sigs.iter().copied())
    };
    let wanted: [(SchemaId, Vec<EventSig<'static>>); 4] = [
        (SCHEMA_ROLL_SOURCE_EXTRACT_BODY, std::vec![source]),
        (SCHEMA_ROLL_FREEZE_BODY, std::vec![commission, committee]),
        (SCHEMA_ROLL_CUSTODY_RECEIPT_BODY, std::vec![custodian]),
        (
            SCHEMA_ROLL_AMENDMENT_BODY,
            std::vec![commission, committee, source],
        ),
    ];
    for (schema, sigs) in &wanted {
        assert!(ok(*schema, sigs), "{schema:?}");
        // One signer more, one less, or one in another role: refused.
        for extra in [commission, committee, source, custodian, clerk, authority] {
            let mut more = sigs.clone();
            more.push(extra);
            assert!(!ok(*schema, &more), "{schema:?} + {:?}", extra.role);
        }
        assert!(!ok(*schema, &sigs[1..]));
        for (i, swapped) in [custodian, source, authority].iter().enumerate() {
            let mut other = sigs.clone();
            let last = other.len() - 1;
            if other[last].role != swapped.role {
                other[last] = *swapped;
                assert!(!ok(*schema, &other), "{schema:?} swap {i}");
            }
        }
    }
    // The roll's roles sign nothing else.
    for schema in WITNESSED_BODY_SCHEMAS {
        if wanted.iter().any(|(s, _)| *s == schema) {
            continue;
        }
        for role in [source, custodian] {
            assert!(!ok(schema, &[role]));
            assert!(!ok(schema, &[commission, committee, role]));
        }
    }
    // The commission and the committee alone sign a dispute and a freeze,
    // not an extract, a receipt or an amendment.
    assert!(!ok(SCHEMA_ROLL_AMENDMENT_BODY, &[commission, committee]));
    assert!(!ok(SCHEMA_ROLL_SOURCE_EXTRACT_BODY, &[custodian]));
    assert!(!ok(SCHEMA_ROLL_CUSTODY_RECEIPT_BODY, &[source]));
}

#[test]
fn a_freeze_in_its_envelope_round_trips() {
    let commission = esig(b"a-nec", EventRole::Commission, b"NEC");
    let committee = esig(b"b-ivc", EventRole::Committee, b"IVC");
    let body = leak(encode_to_vec(
        SCHEMA_ROLL_FREEZE_BODY,
        SCHEMA_VERSION_1,
        &RollFreezeBody::new(&freeze_parts()).unwrap(),
    ));
    let event = WitnessedEvent::new(body, &[commission, committee]).unwrap();
    assert_eq!(event.purpose(), PURPOSE_ROLL_FREEZE);
    assert_eq!(event.body_schema(), SCHEMA_ROLL_FREEZE_BODY);
    let bytes = encode_to_vec(SCHEMA_WITNESSED_EVENT, SCHEMA_VERSION_WITNESSED, &event);
    let back: WitnessedEvent<'_> =
        decode_object(SCHEMA_WITNESSED_EVENT, SCHEMA_VERSION_WITNESSED, &bytes).unwrap();
    assert_eq!(back, event);
    assert_eq!(
        back.body::<RollFreezeBody<'_>>(SCHEMA_ROLL_FREEZE_BODY)
            .unwrap()
            .parts(),
        &freeze_parts()
    );
    // A receipt signed by the commission is no receipt.
    let receipt = leak(encode_to_vec(
        SCHEMA_ROLL_CUSTODY_RECEIPT_BODY,
        SCHEMA_VERSION_1,
        &RollCustodyReceiptBody::new(&receipt_parts()).unwrap(),
    ));
    assert_eq!(
        WitnessedEvent::new(receipt, &[commission])
            .unwrap_err()
            .kind(),
        ErrorKind::InvariantViolation
    );
    // A broken body inside the envelope is refused.
    let mut broken = body.to_vec();
    let count_at = HEADER_LEN + ident_len(b"KR-2030-PRES") + 64 + 8 + 64 + 64 + 64;
    broken[count_at..count_at + 4].fill(0);
    assert_eq!(
        WitnessedEvent::new(leak(broken), &[commission, committee])
            .unwrap_err()
            .kind(),
        ErrorKind::ValueOutOfRange
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn authority_entries_round_trip(
        id in common::ident_bytes(64),
        org in common::ident_bytes(64),
        code in prop::sample::select(std::vec![1u8, 2, 3, 4, 5, 6, 11, 12, 13, 14]),
    ) {
        let entry = RollAuthorityEntry {
            authority_id: AuthorityId::new(&id).unwrap(),
            org_id: OrgId::new(&org).unwrap(),
            kind: RollAuthorityKind::from_code(code).unwrap(),
            key: &VK,
        };
        let bytes = encode_to_vec(SCHEMA_ROLL_AUTHORITY_ENTRY, SCHEMA_VERSION_1, &entry);
        let back: RollAuthorityEntry<'_> =
            decode_object(SCHEMA_ROLL_AUTHORITY_ENTRY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back, entry);
        prop_assert_eq!(encode_to_vec(SCHEMA_ROLL_AUTHORITY_ENTRY, SCHEMA_VERSION_1, &back), bytes);
    }

    #[test]
    fn extracts_round_trip(
        code in 1u8..=5,
        day in any::<u64>(),
        count in any::<u64>(),
        root in common::hash64(),
        precinct in common::ident_bytes(32),
    ) {
        prop_assume!(root.iter().any(|b| *b != 0));
        let kind = RollSourceKind::from_code(code).unwrap();
        let parts = RollSourceExtractParts {
            election_id: e(),
            authority_id: aid(b"SRC"),
            kind,
            precinct: (kind == RollSourceKind::Residents)
                .then(|| StationId::new(&precinct).unwrap()),
            reference_day: Day::new(day),
            entry_count: count,
            entries_root: Hash512(root),
        };
        let body = RollSourceExtractBody::new(&parts).unwrap();
        let bytes = encode_to_vec(SCHEMA_ROLL_SOURCE_EXTRACT_BODY, SCHEMA_VERSION_1, &body);
        let back: RollSourceExtractBody<'_> =
            decode_object(SCHEMA_ROLL_SOURCE_EXTRACT_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back, body);
    }

    #[test]
    fn states_round_trip_in_freezes_receipts_and_amendments(
        hashes in prop::array::uniform4(common::hash64()),
        count in any::<u64>(),
        sources in 1u32..,
        bucket in any::<u64>(),
        seq in 1u64..,
        reason in 1u8..=5,
        with_sources in any::<bool>(),
        with_pseudonyms in any::<bool>(),
    ) {
        prop_assume!(hashes.iter().all(|h| h.iter().any(|b| *b != 0)));
        let s = RollState {
            entries_root: Hash512(hashes[0]),
            entry_count: count,
            counts_hash: Hash512(hashes[1]),
            pseudonym_root: Hash512(hashes[2]),
        };
        let freeze = RollFreezeBody::new(&RollFreezeParts {
            election_id: e(),
            state: s,
            sources_root: Hash512(hashes[3]),
            source_count: sources,
            time_bucket: TimeBucket::new(bucket),
        })
        .unwrap();
        let bytes = encode_to_vec(SCHEMA_ROLL_FREEZE_BODY, SCHEMA_VERSION_1, &freeze);
        let back: RollFreezeBody<'_> =
            decode_object(SCHEMA_ROLL_FREEZE_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back, freeze);
        let receipt = RollCustodyReceiptBody::new(&RollCustodyReceiptParts {
            election_id: e(),
            custodian: aid(b"CUS"),
            subject_hash: Hash512(hashes[3]),
            entries_root: s.entries_root,
            entry_count: s.entry_count,
            counts_hash: s.counts_hash,
            sources_root: with_sources.then_some(Hash512(hashes[3])),
            pseudonym_root: with_pseudonyms.then_some(s.pseudonym_root),
            time_bucket: TimeBucket::new(bucket),
        })
        .unwrap();
        let bytes = encode_to_vec(SCHEMA_ROLL_CUSTODY_RECEIPT_BODY, SCHEMA_VERSION_1, &receipt);
        let back: RollCustodyReceiptBody<'_> =
            decode_object(SCHEMA_ROLL_CUSTODY_RECEIPT_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back, receipt);
        let amendment = RollAmendmentBody::new(&RollAmendmentParts {
            election_id: e(),
            seq,
            previous_hash: Hash512(hashes[3]),
            reason: RollAmendmentReason::from_code(reason).unwrap(),
            authority_id: aid(b"SRC"),
            basis_hash: Hash512(hashes[0]),
            state: s,
            time_bucket: TimeBucket::new(bucket),
        })
        .unwrap();
        let bytes = encode_to_vec(SCHEMA_ROLL_AMENDMENT_BODY, SCHEMA_VERSION_1, &amendment);
        let back: RollAmendmentBody<'_> =
            decode_object(SCHEMA_ROLL_AMENDMENT_BODY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back, amendment);
    }

    #[test]
    fn contested_checkins_round_trip(modules in prop::collection::btree_set(common::ident_bytes(16), 0..=4)) {
        let ids: Vec<Vec<u8>> = modules.into_iter().collect();
        let sigs: Vec<ParticipationModuleSig<'_>> = ids
            .iter()
            .map(|id| ParticipationModuleSig { module_id: ModuleId::new(id).unwrap(), sig: &SIG_B })
            .collect();
        let c = ContestedCheckin::new(message_bytes(), &SIG_A, &sigs).unwrap();
        let bytes = encode_to_vec(SCHEMA_CONTESTED_CHECKIN, SCHEMA_VERSION_1, &c);
        let back: ContestedCheckin<'_> =
            decode_object(SCHEMA_CONTESTED_CHECKIN, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back, c);
        prop_assert_eq!(back.module_sig_count(), sigs.len());
    }

    #[test]
    fn decoding_arbitrary_bytes_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..400)) {
        let v = SCHEMA_VERSION_1;
        let _ = decode_object::<RollAuthorityEntry<'_>>(SCHEMA_ROLL_AUTHORITY_ENTRY, v, &bytes);
        let _ = decode_object::<RollSourceExtractBody<'_>>(SCHEMA_ROLL_SOURCE_EXTRACT_BODY, v, &bytes);
        let _ = decode_object::<RollFreezeBody<'_>>(SCHEMA_ROLL_FREEZE_BODY, v, &bytes);
        let _ = decode_object::<RollCustodyReceiptBody<'_>>(SCHEMA_ROLL_CUSTODY_RECEIPT_BODY, v, &bytes);
        let _ = decode_object::<RollAmendmentBody<'_>>(SCHEMA_ROLL_AMENDMENT_BODY, v, &bytes);
        let _ = decode_object::<ContestedCheckin<'_>>(SCHEMA_CONTESTED_CHECKIN, v, &bytes);
    }
}

#[test]
fn every_roll_body_travels_in_its_envelope() {
    let commission = esig(b"a-nec", EventRole::Commission, b"NEC");
    let committee = esig(b"b-ivc", EventRole::Committee, b"IVC");
    let source = esig(b"c-src", EventRole::RollSource, b"COURT-ADMIN");
    let custodian = esig(b"d-cus", EventRole::RollCustodian, b"COURT-ADMIN");
    let bodies: [(SchemaId, &'static [u8], Vec<EventSig<'static>>); 4] = [
        (
            SCHEMA_ROLL_SOURCE_EXTRACT_BODY,
            leak(encode_to_vec(
                SCHEMA_ROLL_SOURCE_EXTRACT_BODY,
                SCHEMA_VERSION_1,
                &RollSourceExtractBody::new(&extract_parts()).unwrap(),
            )),
            std::vec![source],
        ),
        (
            SCHEMA_ROLL_FREEZE_BODY,
            leak(encode_to_vec(
                SCHEMA_ROLL_FREEZE_BODY,
                SCHEMA_VERSION_1,
                &RollFreezeBody::new(&freeze_parts()).unwrap(),
            )),
            std::vec![commission, committee],
        ),
        (
            SCHEMA_ROLL_CUSTODY_RECEIPT_BODY,
            leak(encode_to_vec(
                SCHEMA_ROLL_CUSTODY_RECEIPT_BODY,
                SCHEMA_VERSION_1,
                &RollCustodyReceiptBody::new(&receipt_parts()).unwrap(),
            )),
            std::vec![custodian],
        ),
        (
            SCHEMA_ROLL_AMENDMENT_BODY,
            leak(encode_to_vec(
                SCHEMA_ROLL_AMENDMENT_BODY,
                SCHEMA_VERSION_1,
                &RollAmendmentBody::new(&amendment_parts()).unwrap(),
            )),
            std::vec![commission, committee, source],
        ),
    ];
    for (schema, body, sigs) in &bodies {
        let event = WitnessedEvent::new(body, sigs).unwrap();
        assert_eq!(event.body_schema(), *schema);
        assert_eq!(Some(event.purpose()), purpose_of(*schema));
        let bytes = encode_to_vec(SCHEMA_WITNESSED_EVENT, SCHEMA_VERSION_WITNESSED, &event);
        let back: WitnessedEvent<'_> =
            decode_object(SCHEMA_WITNESSED_EVENT, SCHEMA_VERSION_WITNESSED, &bytes).unwrap();
        assert_eq!(back, event);
        assert_eq!(back.body_bytes(), *body);
    }
}
