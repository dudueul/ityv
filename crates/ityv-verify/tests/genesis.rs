//! The genesis stage (PROTOCOL.md §14 1; ADR-0028; VC-005, VC-009, VC-014,
//! VC-067, VC-104, VC-105): the pin, real hybrid signatures, every set
//! checked whole, the sets against each other, and amendments. One test
//! per rule, each on a genesis that is valid except for that rule.
// Integration tests: outside the TCB. Assertions use unwrap/expect, so these
// lints are relaxed for this file only (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines,
    clippy::missing_panics_doc,
    clippy::type_complexity,
    clippy::arithmetic_side_effects
)]

mod common;

use common::{
    Draft, NARROW_SIGNERS, Raw, SIGNERS, SPARE_BASE, amendment, amendment_for, appointment,
    body_hash, checkin_unit, genesis_box, module_entry, object, registered, sign_genesis,
    sign_genesis_with, standard, station, token,
};
use ityv_encoding::{
    ChamberCode, EntrySet, GenesisBox, HYBRID_VK_LEN, Hash512, MLDSA87_VK_HALF, RouteId,
    SCHEMA_VERSION_1, StationId, StationKind, StationProgressPolicy,
};
use ityv_verify::{Error, Reference, Rule, verify_genesis};

fn verify(draft: &Draft) -> Result<(), Error> {
    let built = sign_genesis(draft, draft.raw());
    verify_genesis(&built.pin, &built.input(), &[]).map(|_| ())
}

fn at(set: EntrySet, index: u64, rule: Rule) -> Error {
    Error {
        state: 0,
        set: Some(set),
        index: Some(index),
        rule,
    }
}

fn body_rule(rule: Rule) -> Error {
    Error {
        state: 0,
        set: None,
        index: None,
        rule,
    }
}

#[test]
fn accepts_the_standard_genesis_and_proves_entries() {
    let built = standard();
    let verified = verify_genesis(&built.pin, &built.input(), &[]).unwrap();
    assert_eq!(verified.anchors().len(), 1);
    assert_eq!(verified.anchors()[0].pin(), &built.pin);
    assert_eq!(verified.boxes().count(), 3);
    assert_eq!(verified.stations().count(), 2);
    let entry = verified.box_entry(b"BOX-2").unwrap();
    assert_eq!(entry.get().box_id.as_bytes(), b"BOX-2");
    assert_eq!(entry.head(), &built.pin);
    assert!(verified.box_entry(b"BOX-9").is_none());
    assert!(verified.station_entry(b"ST-2").is_some());
    assert!(verified.policy_entry(b"ST-1").is_some());
    assert!(verified.reporting_unit_entry(b"RU-1").is_some());
    assert!(verified.route_entry(b"R-2").is_some());
    assert!(verified.module_entry(b"M-B2-J").is_some());
    assert!(verified.ballot_style_entry(b"STYLE-1").is_some());
    assert!(verified.trustee_entry(b"T-N").is_some());
    assert!(verified.witness_entry(b"W13").is_some());
    assert!(verified.roster_entry(b"court").is_some());
    assert_eq!(verified.roster().len(), 6);
    assert_eq!(verified.election_id().as_bytes(), b"E-2028-GEN");
}

#[test]
fn refuses_another_pin() {
    let built = standard();
    let err = verify_genesis(&Hash512([0x99; 64]), &built.input(), &[]).unwrap_err();
    assert_eq!(err, body_rule(Rule::Pin));
}

#[test]
fn refuses_bytes_that_are_not_a_signed_genesis() {
    let built = standard();
    let mut input = built.input();
    input.signed = built.body;
    assert_eq!(
        verify_genesis(&built.pin, &input, &[]).unwrap_err(),
        body_rule(Rule::Decode)
    );
}

#[test]
fn refuses_an_amendment_in_place_of_the_genesis() {
    let built = standard();
    let a = amendment(1, built.pin, &built.raw, &SIGNERS);
    let mut input = built.input();
    input.signed = a.signed;
    let err = verify_genesis(&body_hash(a.signed), &input, &[]).unwrap_err();
    assert_eq!(err, body_rule(Rule::Kind));
}

#[test]
fn refuses_a_signature_that_does_not_verify() {
    let built = standard();
    let mut bytes = built.signed.to_vec();
    // The last byte is in the last witness's Ed25519 signature half.
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let mut input = built.input();
    input.signed = common::leak_slice(bytes);
    assert_eq!(
        verify_genesis(&built.pin, &input, &[]).unwrap_err(),
        body_rule(Rule::Signature)
    );
}

#[test]
fn refuses_a_signing_witness_outside_the_witness_set() {
    let mut draft = Draft::standard();
    // W09 signs but is not in the set; W14 takes its place.
    draft.witnesses[8].witness_id = common::id(b"W14");
    draft.appointments = draft.referenced_appointments();
    let err = verify(&draft).unwrap_err();
    assert_eq!(err, body_rule(Rule::WitnessUnknown));
}

#[test]
fn refuses_too_little_diversity() {
    let draft = Draft::standard();
    let built = sign_genesis_with(&draft, draft.raw(), &NARROW_SIGNERS, |_| {});
    let err = verify_genesis(&built.pin, &built.input(), &[]).unwrap_err();
    assert_eq!(err, body_rule(Rule::Seal(ityv_state::Error::SignersShort)));
}

#[test]
fn refuses_a_set_out_of_order() {
    let draft = Draft::standard();
    let mut raw = draft.raw();
    raw.boxes.swap(0, 1);
    let built = sign_genesis(&draft, raw);
    let err = verify_genesis(&built.pin, &built.input(), &[]).unwrap_err();
    assert_eq!(err, at(EntrySet::Boxes, 1, Rule::NotSorted));
}

#[test]
fn refuses_a_key_twice() {
    let draft = Draft::standard();
    let mut raw = draft.raw();
    let mut twin = draft.boxes[0];
    twin.device_key = registered(SPARE_BASE);
    raw.boxes.insert(
        1,
        object(ityv_encoding::SCHEMA_GENESIS_BOX, SCHEMA_VERSION_1, &twin),
    );
    let built = sign_genesis(&draft, raw);
    let err = verify_genesis(&built.pin, &built.input(), &[]).unwrap_err();
    assert_eq!(err, at(EntrySet::Boxes, 1, Rule::Duplicate));
}

#[test]
fn refuses_appointments_out_of_order_or_twice() {
    let draft = Draft::standard();
    let mut raw = draft.raw();
    raw.appointments.swap(2, 3);
    let built = sign_genesis(&draft, raw);
    let err = verify_genesis(&built.pin, &built.input(), &[]).unwrap_err();
    assert_eq!(err, at(EntrySet::Appointments, 3, Rule::NotSorted));

    let mut raw = draft.raw();
    let first = raw.appointments[0];
    raw.appointments.insert(1, first);
    let built = sign_genesis(&draft, raw);
    let err = verify_genesis(&built.pin, &built.input(), &[]).unwrap_err();
    assert_eq!(err, at(EntrySet::Appointments, 1, Rule::Duplicate));
}

#[test]
fn refuses_a_count_or_root_the_entries_do_not_give() {
    let draft = Draft::standard();
    let built = sign_genesis_with(&draft, draft.raw(), &SIGNERS, |p| {
        p.sets[EntrySet::Routes.index()].count += 1;
    });
    let err = verify_genesis(&built.pin, &built.input(), &[]).unwrap_err();
    assert_eq!(err.rule, Rule::Count);
    assert_eq!(err.set, Some(EntrySet::Routes));

    let built = sign_genesis_with(&draft, draft.raw(), &SIGNERS, |p| {
        p.sets[EntrySet::Modules.index()].root = Hash512([0x77; 64]);
    });
    let err = verify_genesis(&built.pin, &built.input(), &[]).unwrap_err();
    assert_eq!(err.rule, Rule::Root);
    assert_eq!(err.set, Some(EntrySet::Modules));

    let built = sign_genesis_with(&draft, draft.raw(), &SIGNERS, |p| {
        p.sets[EntrySet::Appointments.index()].root = Hash512([0x77; 64]);
    });
    let err = verify_genesis(&built.pin, &built.input(), &[]).unwrap_err();
    assert_eq!(err.rule, Rule::Root);

    let built = sign_genesis_with(&draft, draft.raw(), &SIGNERS, |p| {
        p.sets[EntrySet::Appointments.index()].count += 1;
    });
    let err = verify_genesis(&built.pin, &built.input(), &[]).unwrap_err();
    assert_eq!(err.rule, Rule::Count);
}

#[test]
fn refuses_an_entry_of_another_schema() {
    let draft = Draft::standard();
    let mut raw = draft.raw();
    // A station object placed in the route set.
    raw.routes[1] = raw.stations[0];
    let built = sign_genesis(&draft, raw);
    let err = verify_genesis(&built.pin, &built.input(), &[]).unwrap_err();
    assert_eq!(err, at(EntrySet::Routes, 1, Rule::Decode));
}

#[test]
fn refuses_a_box_whose_references_are_missing() {
    let cases: [(fn(&mut GenesisBox<'static>), Rule); 5] = [
        (
            |b| b.station_id = StationId::new(b"ST-9").unwrap(),
            Rule::Missing(Reference::Station),
        ),
        (
            |b| b.route_id = RouteId::new(b"R-9").unwrap(),
            Rule::Missing(Reference::Route),
        ),
        (
            |b| b.ballot_style_id = ityv_encoding::BallotStyleId::new(b"STYLE-9").unwrap(),
            Rule::Missing(Reference::BallotStyle),
        ),
        (
            |b| b.reporting_unit_id = ityv_encoding::ReportingUnitId::new(b"RU-9").unwrap(),
            Rule::Missing(Reference::ReportingUnit),
        ),
        (
            |b| b.modules = common::modules(&[b"M-B1-P1", b"M-X-P2"]),
            Rule::Missing(Reference::Module),
        ),
    ];
    for (change, rule) in cases {
        let mut draft = Draft::standard();
        change(&mut draft.boxes[0]);
        assert_eq!(verify(&draft).unwrap_err(), at(EntrySet::Boxes, 0, rule));
    }
}

#[test]
fn refuses_a_box_its_station_does_not_list() {
    let mut draft = Draft::standard();
    // BOX-3 moves to ST-1, whose list stays BOX-1, BOX-2.
    draft.boxes[2].station_id = StationId::new(b"ST-1").unwrap();
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Boxes, 2, Rule::StationBoxes)
    );
}

#[test]
fn refuses_a_station_listing_a_box_that_names_another_station() {
    let mut draft = Draft::standard();
    // ST-2 also lists BOX-2, which names ST-1.
    draft.stations[1] = station(
        b"ST-2",
        StationKind::EarlyVoting,
        checkin_unit(2, b"U-2A", &[b"M-U2A-P1", b"M-U2A-P2"]),
        checkin_unit(3, b"U-2B", &[b"M-U2B-P1", b"M-U2B-P2"]),
        &[b"BOX-2", b"BOX-3"],
        &[],
    );
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Stations, 1, Rule::StationBoxes)
    );
}

#[test]
fn refuses_a_station_listing_a_box_that_does_not_exist() {
    let mut draft = Draft::standard();
    draft.stations[1] = station(
        b"ST-2",
        StationKind::EarlyVoting,
        checkin_unit(2, b"U-2A", &[b"M-U2A-P1", b"M-U2A-P2"]),
        checkin_unit(3, b"U-2B", &[b"M-U2B-P1", b"M-U2B-P2"]),
        &[b"BOX-3", b"BOX-4"],
        &[],
    );
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Stations, 1, Rule::Missing(Reference::Box))
    );
}

#[test]
fn refuses_a_station_without_a_policy_and_a_policy_without_a_station() {
    let mut draft = Draft::standard();
    draft.policies.remove(1);
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Stations, 1, Rule::StationPolicy)
    );

    let mut draft = Draft::standard();
    draft
        .policies
        .push(StationProgressPolicy::new(StationId::new(b"ST-3").unwrap(), 1, 1).unwrap());
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::ProgressPolicies, 2, Rule::StationPolicy)
    );
}

#[test]
fn refuses_a_reporting_unit_whose_count_differs() {
    let mut draft = Draft::standard();
    draft.units[0] = ityv_encoding::ReportingUnitEntry::new(
        ityv_encoding::ReportingUnitId::new(b"RU-1").unwrap(),
        3,
        ityv_encoding::OrgId::new(b"NEC-D").unwrap(),
    )
    .unwrap();
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::ReportingUnits, 0, Rule::UnitBoxCount)
    );

    // A unit no box names.
    let mut draft = Draft::standard();
    draft.units.push(
        ityv_encoding::ReportingUnitEntry::new(
            ityv_encoding::ReportingUnitId::new(b"RU-3").unwrap(),
            1,
            ityv_encoding::OrgId::new(b"NEC-D").unwrap(),
        )
        .unwrap(),
    );
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::ReportingUnits, 2, Rule::UnitBoxCount)
    );
}

#[test]
fn refuses_a_roster_signer_at_a_missing_station() {
    let mut draft = Draft::standard();
    draft.roster[0].station_id = Some(StationId::new(b"ST-9").unwrap());
    // clerk-1 sorts first.
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Roster, 0, Rule::Missing(Reference::Station))
    );
}

#[test]
fn refuses_appointments_that_are_not_registered() {
    // Roster (court sorts after clerk-1, clerk-2: index 2).
    let mut draft = Draft::standard();
    let gone = draft.roster[5].appointment_hash;
    draft.appointments.retain(|h| *h != gone);
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Roster, 2, Rule::Appointment)
    );
    // Trustee.
    let mut draft = Draft::standard();
    let gone = draft.trustees[0].appointment_hash;
    draft.appointments.retain(|h| *h != gone);
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Trustees, 4, Rule::Appointment)
    );
    // Witness.
    let mut draft = Draft::standard();
    draft.appointments.retain(|h| *h != appointment(200 + 12));
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Witnesses, 12, Rule::Appointment)
    );
}

#[test]
fn refuses_devices_without_one_module_per_party() {
    // A box without its P2 module.
    let mut draft = Draft::standard();
    draft.boxes[0].modules = common::modules(&[b"M-B1-P1"]);
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Boxes, 0, Rule::Chambers)
    );

    // A box with two P1 modules.
    let mut draft = Draft::standard();
    draft.boxes[0].modules = common::modules(&[b"M-B1-P1", b"M-B1-P2", b"M-B2-P1"]);
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Boxes, 0, Rule::Chambers)
    );

    // A box with two J modules.
    let mut draft = Draft::standard();
    draft
        .modules
        .push(module_entry(60, b"M-B2-J2", ChamberCode::J));
    draft.boxes[1].modules = common::modules(&[b"M-B2-P1", b"M-B2-P2", b"M-B2-J", b"M-B2-J2"]);
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Boxes, 1, Rule::Chambers)
    );

    // A check-in unit with a J module.
    let mut draft = Draft::standard();
    draft
        .modules
        .push(module_entry(64, b"M-U2A-J", ChamberCode::J));
    draft.stations[1] = station(
        b"ST-2",
        StationKind::EarlyVoting,
        checkin_unit(2, b"U-2A", &[b"M-U2A-P1", b"M-U2A-P2", b"M-U2A-J"]),
        checkin_unit(3, b"U-2B", &[b"M-U2B-P1", b"M-U2B-P2"]),
        &[b"BOX-3"],
        &[],
    );
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Stations, 1, Rule::Chambers)
    );

    // A spare check-in unit with only a P1 module.
    let mut draft = Draft::standard();
    draft.stations[1] = station(
        b"ST-2",
        StationKind::EarlyVoting,
        checkin_unit(2, b"U-2A", &[b"M-U2A-P1", b"M-U2A-P2"]),
        checkin_unit(3, b"U-2B", &[b"M-U2B-P1"]),
        &[b"BOX-3"],
        &[],
    );
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Stations, 1, Rule::Chambers)
    );
}

#[test]
fn refuses_modules_of_chambers_without_modules() {
    // N has no module: such an entry does not even decode.
    let mut draft = Draft::standard();
    draft.modules.push(module_entry(61, b"M-N", ChamberCode::N));
    let err = verify(&draft).unwrap_err();
    assert_eq!(err.set, Some(EntrySet::Modules));
    assert_eq!(err.rule, Rule::Decode);

    // P3 is not a chamber of a two-party genesis.
    let mut draft = Draft::standard();
    draft
        .modules
        .push(module_entry(62, b"M-P3", ChamberCode::P3));
    let err = verify(&draft).unwrap_err();
    assert_eq!(err.set, Some(EntrySet::Modules));
    assert_eq!(err.rule, Rule::Chambers);
}

#[test]
fn refuses_trustees_that_do_not_fill_their_chambers() {
    let mut draft = Draft::standard();
    draft.trustees.pop();
    draft.appointments = draft.referenced_appointments();
    let err = verify(&draft).unwrap_err();
    assert_eq!(err.set, Some(EntrySet::Trustees));
    assert_eq!(err.rule, Rule::Trustees);

    let mut draft = Draft::standard();
    draft.trustees[7].chamber = ChamberCode::P1;
    let err = verify(&draft).unwrap_err();
    assert_eq!(err.rule, Rule::Trustees);
}

#[test]
fn refuses_a_chamber_larger_than_threshold_sharing_serves() {
    // J with nine members and nine trustees: every other rule holds, but
    // no quorum of nine could be shared or checked.
    let mut draft = Draft::standard();
    for c in &mut draft.chambers {
        if c.chamber == ChamberCode::J {
            c.members = 9;
        }
    }
    let names: [&'static [u8]; 8] = [
        b"T-J2", b"T-J3", b"T-J4", b"T-J5", b"T-J6", b"T-J7", b"T-J8", b"T-J9",
    ];
    for (i, name) in names.iter().enumerate() {
        draft.trustees.push(ityv_encoding::TrusteeEntry {
            trustee_id: ityv_encoding::TrusteeId::new(name).unwrap(),
            chamber: ChamberCode::J,
            org_id: common::org(b"TRUST-ORG"),
            key: common::registered(common::SPARE_BASE + u16::try_from(i).unwrap()),
            appointment_hash: common::appointment(120 + u8::try_from(i).unwrap()),
        });
    }
    draft.appointments = draft.referenced_appointments();
    let err = verify(&draft).unwrap_err();
    assert_eq!(err.set, Some(EntrySet::Trustees));
    assert_eq!(err.rule, Rule::ChamberSize);
    // Eight is the most.
    let mut draft = Draft::standard();
    for c in &mut draft.chambers {
        if c.chamber == ChamberCode::J {
            c.members = 8;
        }
    }
    for (i, name) in names.iter().take(7).enumerate() {
        draft.trustees.push(ityv_encoding::TrusteeEntry {
            trustee_id: ityv_encoding::TrusteeId::new(name).unwrap(),
            chamber: ChamberCode::J,
            org_id: common::org(b"TRUST-ORG"),
            key: common::registered(common::SPARE_BASE + u16::try_from(i).unwrap()),
            appointment_hash: common::appointment(120 + u8::try_from(i).unwrap()),
        });
    }
    draft.appointments = draft.referenced_appointments();
    assert!(verify(&draft).is_ok());
}

#[test]
fn refuses_an_observer_token_of_someone_else() {
    let mut draft = Draft::standard();
    // The token names clerk-1, who is not an observer.
    draft.stations[0] = station(
        b"ST-1",
        StationKind::ElectionDay,
        checkin_unit(0, b"U-1A", &[b"M-U1A-P1", b"M-U1A-P2"]),
        checkin_unit(1, b"U-1B", &[b"M-U1B-P1", b"M-U1B-P2"]),
        &[b"BOX-1", b"BOX-2"],
        &[
            token(b"clerk-1", b"ORG-ST", 0xC1),
            token(b"obs-b", b"PARTY-B", 0xC2),
        ],
    );
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Stations, 0, Rule::ObserverToken)
    );
    // The token names an observer of another organisation.
    let mut draft = Draft::standard();
    draft.stations[0] = station(
        b"ST-1",
        StationKind::ElectionDay,
        checkin_unit(0, b"U-1A", &[b"M-U1A-P1", b"M-U1A-P2"]),
        checkin_unit(1, b"U-1B", &[b"M-U1B-P1", b"M-U1B-P2"]),
        &[b"BOX-1", b"BOX-2"],
        &[token(b"obs-a", b"PARTY-B", 0xC1)],
    );
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Stations, 0, Rule::ObserverToken)
    );
}

#[test]
fn refuses_two_keys_sharing_a_half() {
    // A roster signer with a box's device key.
    let mut draft = Draft::standard();
    draft.roster[4].key = draft.boxes[0].device_key;
    let err = verify(&draft).unwrap_err();
    assert_eq!(err.rule, Rule::SharedKey);
    assert_eq!(err.set, Some(EntrySet::Roster));

    // A witness with the commission's key.
    let mut draft = Draft::standard();
    draft.witnesses[12].key = registered(common::COMMISSION);
    let err = verify(&draft).unwrap_err();
    assert_eq!(err, at(EntrySet::Witnesses, 12, Rule::SharedKey));

    // A box whose attestation key is its device key.
    let mut draft = Draft::standard();
    draft.boxes[2].attest_key = draft.boxes[2].device_key;
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Boxes, 2, Rule::SharedKey)
    );

    // Two keys sharing only the Ed25519 half.
    let mut draft = Draft::standard();
    let mut mixed = *registered(SPARE_BASE + 1);
    let n = mixed.len();
    mixed[n - 32..].copy_from_slice(&registered(common::COMMITTEE)[n - 32..]);
    draft.modules[0].attest_key = common::leak(mixed);
    let err = verify(&draft).unwrap_err();
    assert_eq!(err, at(EntrySet::Modules, 0, Rule::SharedKey));
}

/// A raw set for the state after an amendment that gives BOX-3 a spare
/// device.
fn amended_raw() -> (Draft, Raw) {
    let mut draft = Draft::standard();
    draft.boxes[2].device_key = registered(SPARE_BASE + 2);
    let raw = draft.raw();
    (draft, raw)
}

#[test]
fn applies_amendments_in_order_and_proves_against_the_last_state() {
    let built = standard();
    let (_, raw) = amended_raw();
    let first = amendment(1, built.pin, &raw, &SIGNERS);
    let second = amendment(2, body_hash(first.signed), &built.raw, &SIGNERS);
    let verified = verify_genesis(&built.pin, &built.input(), &[first, second]).unwrap();
    assert_eq!(verified.anchors().len(), 3);
    assert_eq!(verified.anchors()[2].seq(), 2);
    assert_eq!(verified.genesis().head(), &body_hash(second.signed));
    // The last state is back to the original device.
    let entry = verified.box_entry(b"BOX-3").unwrap();
    assert_eq!(entry.get().device_key, registered(102));
    assert_eq!(entry.head(), &body_hash(second.signed));

    let verified = verify_genesis(&built.pin, &built.input(), &[first]).unwrap();
    let entry = verified.box_entry(b"BOX-3").unwrap();
    assert_eq!(entry.get().device_key, registered(SPARE_BASE + 2));
}

#[test]
fn refuses_an_amendment_out_of_sequence_or_off_the_chain() {
    let built = standard();
    let (_, raw) = amended_raw();
    let skipped = amendment(2, built.pin, &raw, &SIGNERS);
    let err = verify_genesis(&built.pin, &built.input(), &[skipped]).unwrap_err();
    assert_eq!(err.state, 1);
    assert_eq!(err.rule, Rule::Chain(ityv_state::Error::Mismatch));

    let off = amendment(1, Hash512([0x42; 64]), &raw, &SIGNERS);
    let err = verify_genesis(&built.pin, &built.input(), &[off]).unwrap_err();
    assert_eq!(err.rule, Rule::Chain(ityv_state::Error::Mismatch));

    // A genesis in place of an amendment.
    let mut not_amendment = amendment(1, built.pin, &raw, &SIGNERS);
    not_amendment.signed = built.signed;
    let err = verify_genesis(&built.pin, &built.input(), &[not_amendment]).unwrap_err();
    assert_eq!(err.rule, Rule::Kind);
}

#[test]
fn refuses_an_amendment_with_too_little_diversity() {
    let built = standard();
    let (_, raw) = amended_raw();
    let narrow = amendment(1, built.pin, &raw, &NARROW_SIGNERS);
    let err = verify_genesis(&built.pin, &built.input(), &[narrow]).unwrap_err();
    assert_eq!(err.state, 1);
    assert_eq!(err.rule, Rule::Seal(ityv_state::Error::SignersShort));
}

#[test]
fn refuses_an_amendment_whose_sets_break_a_rule() {
    let built = standard();
    // The amended box set moves BOX-3 to a station that does not list it.
    let mut draft = Draft::standard();
    draft.boxes[2].station_id = StationId::new(b"ST-1").unwrap();
    let raw = draft.raw();
    let bad = amendment(1, built.pin, &raw, &SIGNERS);
    let err = verify_genesis(&built.pin, &built.input(), &[bad]).unwrap_err();
    assert_eq!(err.state, 1);
    assert_eq!(err.set, Some(EntrySet::Boxes));
    assert_eq!(err.rule, Rule::StationBoxes);

    // The sets given are not the ones the amendment commits to.
    let (_, raw) = amended_raw();
    let mut lying = amendment(1, built.pin, &raw, &SIGNERS);
    lying.sets = built.raw.amendable();
    let err = verify_genesis(&built.pin, &built.input(), &[lying]).unwrap_err();
    assert_eq!(err.state, 1);
    assert_eq!(err.rule, Rule::Root);
}

#[test]
fn an_amended_state_must_keep_the_appointments_of_the_fixed_sets() {
    let built = standard();
    let mut draft = Draft::standard();
    let gone = draft.witnesses[0].appointment_hash;
    draft.appointments.retain(|h| *h != gone);
    let bad = amendment(1, built.pin, &draft.raw(), &SIGNERS);
    let err = verify_genesis(&built.pin, &built.input(), &[bad]).unwrap_err();
    assert_eq!(err.state, 1);
    assert_eq!(err.set, Some(EntrySet::Witnesses));
    assert_eq!(err.rule, Rule::Appointment);
}

#[test]
fn a_new_box_needs_every_set_to_agree() {
    let mut draft = Draft::standard();
    draft.boxes.push(genesis_box(
        3,
        b"BOX-4",
        b"ST-2",
        b"RU-2",
        &[b"M-B4-P1", b"M-B4-P2"],
    ));
    draft
        .modules
        .push(module_entry(70, b"M-B4-P1", ChamberCode::P1));
    draft
        .modules
        .push(module_entry(71, b"M-B4-P2", ChamberCode::P2));
    // ST-2 does not list it yet.
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Boxes, 3, Rule::StationBoxes)
    );
    draft.stations[1] = station(
        b"ST-2",
        StationKind::EarlyVoting,
        checkin_unit(2, b"U-2A", &[b"M-U2A-P1", b"M-U2A-P2"]),
        checkin_unit(3, b"U-2B", &[b"M-U2B-P1", b"M-U2B-P2"]),
        &[b"BOX-3", b"BOX-4"],
        &[],
    );
    // RU-2 still counts one box.
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::ReportingUnits, 1, Rule::UnitBoxCount)
    );
    draft.units[1] = ityv_encoding::ReportingUnitEntry::new(
        ityv_encoding::ReportingUnitId::new(b"RU-2").unwrap(),
        2,
        ityv_encoding::OrgId::new(b"NEC-D").unwrap(),
    )
    .unwrap();
    verify(&draft).unwrap();
}

#[test]
fn refuses_two_devices_with_one_identifier() {
    // A check-in unit named like a box.
    let mut draft = Draft::standard();
    draft.stations[1] = station(
        b"ST-2",
        StationKind::EarlyVoting,
        checkin_unit(2, b"BOX-1", &[b"M-U2A-P1", b"M-U2A-P2"]),
        checkin_unit(3, b"U-2B", &[b"M-U2B-P1", b"M-U2B-P2"]),
        &[b"BOX-3"],
        &[],
    );
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Stations, 1, Rule::DeviceId)
    );

    // Two stations with one unit.
    let mut draft = Draft::standard();
    draft.stations[1] = station(
        b"ST-2",
        StationKind::EarlyVoting,
        checkin_unit(2, b"U-1A", &[b"M-U2A-P1", b"M-U2A-P2"]),
        checkin_unit(3, b"U-2B", &[b"M-U2B-P1", b"M-U2B-P2"]),
        &[b"BOX-3"],
        &[],
    );
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Stations, 1, Rule::DeviceId)
    );

    // A module named like a box (it sorts first in the module set).
    let mut draft = Draft::standard();
    draft
        .modules
        .push(module_entry(63, b"BOX-2", ChamberCode::C));
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Modules, 0, Rule::DeviceId)
    );
}

#[test]
fn refuses_a_module_listed_by_two_devices() {
    // BOX-2 lists BOX-1's modules.
    let mut draft = Draft::standard();
    draft.boxes[1].modules = common::modules(&[b"M-B1-P1", b"M-B1-P2", b"M-B2-J"]);
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Boxes, 1, Rule::SharedModule)
    );

    // The spare check-in unit lists the primary's modules.
    let mut draft = Draft::standard();
    draft.stations[1] = station(
        b"ST-2",
        StationKind::EarlyVoting,
        checkin_unit(2, b"U-2A", &[b"M-U2A-P1", b"M-U2A-P2"]),
        checkin_unit(3, b"U-2B", &[b"M-U2A-P1", b"M-U2A-P2"]),
        &[b"BOX-3"],
        &[],
    );
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Stations, 1, Rule::SharedModule)
    );

    // A check-in unit lists a box's module.
    let mut draft = Draft::standard();
    draft.stations[1] = station(
        b"ST-2",
        StationKind::EarlyVoting,
        checkin_unit(2, b"U-2A", &[b"M-B3-P1", b"M-U2A-P2"]),
        checkin_unit(3, b"U-2B", &[b"M-U2B-P1", b"M-U2B-P2"]),
        &[b"BOX-3"],
        &[],
    );
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Stations, 1, Rule::SharedModule)
    );
}

#[test]
fn refuses_an_appointment_named_twice() {
    // A trustee (T-P1-1 sorts at 4) with a roster signer's appointment.
    let mut draft = Draft::standard();
    draft.trustees[0].appointment_hash = draft.roster[0].appointment_hash;
    draft.appointments = draft.referenced_appointments();
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Trustees, 4, Rule::AppointmentReused)
    );
    // Two witnesses with one appointment.
    let mut draft = Draft::standard();
    draft.witnesses[5].appointment_hash = draft.witnesses[4].appointment_hash;
    draft.appointments = draft.referenced_appointments();
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Witnesses, 5, Rule::AppointmentReused)
    );
    // Two roster signers with one appointment.
    let mut draft = Draft::standard();
    draft.roster[1].appointment_hash = draft.roster[0].appointment_hash;
    draft.appointments = draft.referenced_appointments();
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Roster, 1, Rule::AppointmentReused)
    );
}

#[test]
fn refuses_a_token_of_an_observer_of_another_station_or_a_shared_check_key() {
    // obs-a is registered at ST-2 but holds a token at ST-1.
    let mut draft = Draft::standard();
    draft.roster[2].station_id = Some(StationId::new(b"ST-2").unwrap());
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Stations, 0, Rule::ObserverToken)
    );
    // Two tokens with one check key.
    let mut draft = Draft::standard();
    draft.stations[0] = station(
        b"ST-1",
        StationKind::ElectionDay,
        checkin_unit(0, b"U-1A", &[b"M-U1A-P1", b"M-U1A-P2"]),
        checkin_unit(1, b"U-1B", &[b"M-U1B-P1", b"M-U1B-P2"]),
        &[b"BOX-1", b"BOX-2"],
        &[
            token(b"obs-a", b"PARTY-A", 0xC1),
            token(b"obs-b", b"PARTY-B", 0xC1),
        ],
    );
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Stations, 0, Rule::ObserverToken)
    );
}

/// `key` with its Ed25519 half replaced by the identity point, a weak key.
fn weak(key: &[u8; HYBRID_VK_LEN]) -> &'static [u8; HYBRID_VK_LEN] {
    let mut out = *key;
    let n = out.len();
    out[n - 32..].copy_from_slice(&[0; 32]);
    out[n - 32] = 1;
    common::leak(out)
}

#[test]
fn refuses_a_key_nothing_could_verify_under() {
    let mut draft = Draft::standard();
    draft.boxes[1].device_key = weak(registered(SPARE_BASE + 3));
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Boxes, 1, Rule::InvalidKey)
    );
    let mut draft = Draft::standard();
    // M-B2-P2 sorts fifth in the module set.
    draft.modules[3].attest_key = weak(registered(SPARE_BASE + 3));
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Modules, 4, Rule::InvalidKey)
    );
}

/// `key` with its ML-DSA-87 half replaced by `donor`'s.
fn ml_dsa_of(
    key: &[u8; HYBRID_VK_LEN],
    donor: &[u8; HYBRID_VK_LEN],
) -> &'static [u8; HYBRID_VK_LEN] {
    let mut out = *key;
    out[..MLDSA87_VK_HALF].copy_from_slice(&donor[..MLDSA87_VK_HALF]);
    common::leak(out)
}

#[test]
fn refuses_keys_sharing_either_half_wherever_they_are() {
    // Only the ML-DSA-87 half shared (a module's key with box 0's).
    let mut draft = Draft::standard();
    draft.modules[0].key = ml_dsa_of(registered(SPARE_BASE + 4), draft.boxes[0].device_key);
    let err = verify(&draft).unwrap_err();
    assert_eq!(
        (err.set, err.rule),
        (Some(EntrySet::Modules), Rule::SharedKey)
    );
    // Two roster signers (sorted: clerk-1, clerk-2).
    let mut draft = Draft::standard();
    draft.roster[1].key = draft.roster[0].key;
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Roster, 1, Rule::SharedKey)
    );
    // A witness that does not sign (W13) with a trustee's key (trustees are
    // checked first).
    let mut draft = Draft::standard();
    draft.witnesses[12].key = draft.trustees[5].key;
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Witnesses, 12, Rule::SharedKey)
    );
    // Two trustees (T-A sorts first, T-C second).
    let mut draft = Draft::standard();
    draft.trustees[6].key = draft.trustees[5].key;
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Trustees, 1, Rule::SharedKey)
    );
    // A roster signer with a check-in unit's key (units come first).
    let mut draft = Draft::standard();
    draft.roster[0].key = registered(200);
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Roster, 0, Rule::SharedKey)
    );
    // A spare unit's attestation key sharing the primary's ML-DSA-87 half.
    let mut draft = Draft::standard();
    let mut spare = checkin_unit(1, b"U-1B", &[b"M-U1B-P1", b"M-U1B-P2"]);
    spare.attest_key = ml_dsa_of(registered(SPARE_BASE + 5), registered(200));
    draft.stations[0] = station(
        b"ST-1",
        StationKind::ElectionDay,
        checkin_unit(0, b"U-1A", &[b"M-U1A-P1", b"M-U1A-P2"]),
        spare,
        &[b"BOX-1", b"BOX-2"],
        &[
            token(b"obs-a", b"PARTY-A", 0xC1),
            token(b"obs-b", b"PARTY-B", 0xC2),
        ],
    );
    assert_eq!(
        verify(&draft).unwrap_err(),
        at(EntrySet::Stations, 0, Rule::SharedKey)
    );
}

#[test]
fn an_amendment_must_be_signed_and_of_this_election() {
    let built = standard();
    let (_, raw) = amended_raw();
    let good = amendment(1, built.pin, &raw, &SIGNERS);
    let mut bytes = good.signed.to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    let forged = ityv_verify::AmendmentInput {
        signed: common::leak_slice(bytes),
        sets: good.sets,
    };
    let err = verify_genesis(&built.pin, &built.input(), &[forged]).unwrap_err();
    assert_eq!(
        err,
        Error {
            state: 1,
            set: None,
            index: None,
            rule: Rule::Signature
        }
    );
    let other = amendment_for(
        ityv_encoding::ElectionId::new(b"E-OTHER").unwrap(),
        1,
        built.pin,
        &raw,
        &SIGNERS,
    );
    let err = verify_genesis(&built.pin, &built.input(), &[other]).unwrap_err();
    assert_eq!(err.rule, Rule::Chain(ityv_state::Error::Mismatch));
}

#[test]
fn an_amended_state_meets_every_cross_set_rule() {
    let built = standard();
    let cases: [(fn(&mut Draft), EntrySet, Rule); 4] = [
        (
            |d| d.roster[4].key = d.boxes[0].device_key,
            EntrySet::Roster,
            Rule::SharedKey,
        ),
        (
            |d| d.modules.push(module_entry(65, b"BOX-2", ChamberCode::C)),
            EntrySet::Modules,
            Rule::DeviceId,
        ),
        (
            |d| d.roster[2].station_id = Some(StationId::new(b"ST-2").unwrap()),
            EntrySet::Stations,
            Rule::ObserverToken,
        ),
        (
            |d| d.boxes[1].modules = common::modules(&[b"M-B1-P1", b"M-B1-P2"]),
            EntrySet::Boxes,
            Rule::SharedModule,
        ),
    ];
    for (change, set, rule) in cases {
        let mut draft = Draft::standard();
        change(&mut draft);
        let bad = amendment(1, built.pin, &draft.raw(), &SIGNERS);
        let err = verify_genesis(&built.pin, &built.input(), &[bad]).unwrap_err();
        assert_eq!((err.state, err.set, err.rule), (1, Some(set), rule));
    }
}

#[test]
fn the_genesis_remembers_every_state_s_boxes_stations_and_units() {
    let built = standard();
    // The amendment replaces BOX-3 by BOX-4 and ST-2's spare unit U-2B by
    // U-2C.
    let mut draft = Draft::standard();
    draft.boxes[2] = genesis_box(
        2,
        b"BOX-4",
        b"ST-2",
        b"RU-2",
        &[b"M-B3-P1", b"M-B3-P2", b"M-B3-A"],
    );
    draft.stations[1] = station(
        b"ST-2",
        StationKind::EarlyVoting,
        checkin_unit(2, b"U-2A", &[b"M-U2A-P1", b"M-U2A-P2"]),
        checkin_unit(3, b"U-2C", &[b"M-U2B-P1", b"M-U2B-P2"]),
        &[b"BOX-4"],
        &[],
    );
    let a = amendment(1, built.pin, &draft.raw(), &SIGNERS);
    let verified = verify_genesis(&built.pin, &built.input(), &[a]).unwrap();
    assert!(verified.expected_box(b"BOX-3").is_none());
    assert!(verified.knows_box(b"BOX-3"));
    assert!(verified.knows_box(b"BOX-4"));
    assert!(!verified.knows_box(b"BOX-9"));
    assert!(verified.knows_station(b"ST-2"));
    assert!(!verified.knows_station(b"ST-9"));
    let st2 = Some(StationId::new(b"ST-2").unwrap());
    assert_eq!(verified.unit_station(b"U-2B"), st2);
    assert_eq!(verified.unit_station(b"U-2C"), st2);
}

/// The timestamp authority set (ADR-0039, VC-114), entries in key order:
/// 0 `TSA-FREE-1`, 1 `TSA-GOV-1` (two pins), 2 `TSA-GOV-2`.
#[test]
fn refuses_a_timestamp_authority_set_that_breaks_a_rule() {
    use common::tsa;
    use ityv_encoding::{OrgId, PolicyAccuracy, TimestampAuthorityKind, TimestampPins};
    use ityv_tsa::{DigestAlgorithm, DigestSet, PinnedTsa, SignatureAlgorithm, SignatureSet};
    let set = EntrySet::TimestampAuthorities;
    let base = Draft::standard();
    assert_eq!(verify(&base), Ok(()));
    let verified = verify_genesis(&standard().pin, &standard().input(), &[]).unwrap();
    assert_eq!(verified.timestamp_authorities().count(), 3);

    // No non-government authority.
    let mut d = base.clone();
    d.timestamps
        .retain(|a| a.kind == TimestampAuthorityKind::Government);
    assert_eq!(
        verify(&d),
        Err(Error {
            state: 0,
            set: Some(set),
            index: None,
            rule: Rule::TimestampAuthorities,
        })
    );
    // No government authority.
    let mut d = base.clone();
    d.timestamps
        .retain(|a| a.kind == TimestampAuthorityKind::NonGovernment);
    assert_eq!(verify(&d).unwrap_err().rule, Rule::TimestampAuthorities);
    // None at all.
    let mut d = base.clone();
    d.timestamps.clear();
    assert_eq!(verify(&d).unwrap_err().rule, Rule::TimestampAuthorities);

    // Pin bytes that are not a pin.
    let mut d = base.clone();
    d.timestamps[2].pins = TimestampPins::new(&[&[0x01, 0x02]]).unwrap();
    assert_eq!(verify(&d), Err(at(set, 2, Rule::TimestampPin)));
    let gov2 = tsa::signer(tsa::GOV_SAME_OPERATOR).cert;
    let sha256 = DigestAlgorithm::Sha256.bit();
    let sha384 = DigestAlgorithm::Sha384.bit();
    let sha512 = DigestAlgorithm::Sha512.bit();
    let rsa256 = SignatureAlgorithm::RsaPkcs1Sha256.bit();
    let with_pin = |pin: &'static [u8]| {
        let mut d = base.clone();
        d.timestamps[2].pins = TimestampPins::new(&[pin]).unwrap();
        verify(&d)
    };
    // A pin that does not allow SHA-512, the digest of every imprint.
    assert_eq!(
        with_pin(tsa::pin_of(gov2, sha256, rsa256)),
        Err(at(set, 2, Rule::TimestampPin))
    );
    // A pin that allows SHA-512 but not the digest of the only signature
    // algorithm it allows (the review's second proof of concept): no
    // token could verify under it.
    assert_eq!(
        with_pin(tsa::pin_of(
            gov2,
            sha512,
            rsa256 | SignatureAlgorithm::EcdsaP256Sha256.bit()
        )),
        Err(at(set, 2, Rule::TimestampPin))
    );
    // A pin whose only algorithms the certificate's RSA key does not make.
    assert_eq!(
        with_pin(tsa::pin_of(
            gov2,
            sha256 | sha384 | sha512,
            SignatureAlgorithm::EcdsaP256Sha256.bit() | SignatureAlgorithm::EcdsaP384Sha384.bit()
        )),
        Err(at(set, 2, Rule::TimestampPin))
    );
    // A pin whose EC point is off its curve (the second review's proof of
    // concept): `ityv-tsa` read it, and no token could verify under it.
    let mut p256 = std::fs::read(
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../ityv-tsa/tests/vectors/p256.crt"),
    )
    .unwrap();
    let point = p256
        .windows(4)
        .position(|w| w == [0x03, 0x42, 0x00, 0x04])
        .unwrap();
    let ecdsa = SignatureAlgorithm::EcdsaP256Sha256.bit();
    let good_p256: &'static [u8] = common::leak_slice(p256.clone());
    assert_eq!(
        with_pin(tsa::pin_of(good_p256, sha256 | sha512, ecdsa)),
        Ok(())
    );
    p256[point + 4 + 63] ^= 0x01;
    let off_curve: &'static [u8] = common::leak_slice(p256);
    assert_eq!(
        with_pin(tsa::pin_of(off_curve, sha256 | sha512, ecdsa)),
        Err(at(set, 2, Rule::TimestampPin))
    );
    // A certificate that ends before the election's epoch day (day 20 000,
    // 2024-10-04) begins: refused; one that ends as it begins is taken
    // (the genesis carries no end of the election to check more).
    assert_eq!(
        with_pin(tsa::recertified_until(
            tsa::GOV_SAME_OPERATOR,
            "20241003235959Z"
        )),
        Err(at(set, 2, Rule::TimestampPin))
    );
    assert_eq!(
        with_pin(tsa::recertified_until(
            tsa::GOV_SAME_OPERATOR,
            "20241004000000Z"
        )),
        Ok(())
    );
    // A pin without its certificate: its key cannot be compared.
    let hash: [u8; 32] = tsa::signer(tsa::GOV_SAME_OPERATOR).pin[1..33]
        .try_into()
        .unwrap();
    let pin = PinnedTsa::new(
        hash,
        DigestSet::from_bits(sha256 | sha512).unwrap(),
        SignatureSet::from_bits(rsa256).unwrap(),
        false,
        &tsa::POLICY,
        None,
    )
    .unwrap();
    let mut bytes = std::vec![0u8; pin.encoded_len()];
    let len = pin.encode(&mut bytes).unwrap();
    bytes.truncate(len);
    assert_eq!(
        with_pin(common::leak_slice(bytes)),
        Err(at(set, 2, Rule::TimestampPin))
    );
    // The same certificate with SHA-512 and the algorithm it signs with is
    // the standard pin, and verifies.
    assert_eq!(with_pin(tsa::pin_of(gov2, sha256 | sha512, rsa256)), Ok(()));
    assert_eq!(
        tsa::pin_of(gov2, sha256 | sha512, rsa256),
        tsa::signer(tsa::GOV_SAME_OPERATOR).pin
    );

    // One certificate pinned for two authorities.
    let mut d = base.clone();
    d.timestamps[2].pins = TimestampPins::new(&[tsa::signer(tsa::FREE).pin]).unwrap();
    assert_eq!(verify(&d), Err(at(set, 2, Rule::TimestampCertificate)));
    // One certificate pinned twice for one authority, under two encodings
    // (another digest set).
    let other_digests = tsa::pin_of(gov2, sha256 | sha384 | sha512, rsa256);
    let mut pins = std::vec![tsa::signer(tsa::GOV_SAME_OPERATOR).pin, other_digests];
    pins.sort();
    let mut d = base.clone();
    d.timestamps[2].pins = TimestampPins::new(&pins).unwrap();
    assert_eq!(verify(&d), Err(at(set, 2, Rule::TimestampCertificate)));
    // One key under two certificates, for two authorities or for one: one
    // signer would count twice (the review's key-reuse case).
    let again = tsa::recertified(tsa::FREE);
    assert_ne!(again[1..33], tsa::signer(tsa::FREE).pin[1..33]);
    let mut d = base.clone();
    d.timestamps[2].pins = TimestampPins::new(&[again]).unwrap();
    assert_eq!(verify(&d), Err(at(set, 2, Rule::TimestampKey)));
    let mut pins = std::vec![
        tsa::signer(tsa::GOV_SAME_OPERATOR).pin,
        tsa::recertified(tsa::GOV_SAME_OPERATOR)
    ];
    pins.sort();
    let mut d = base.clone();
    d.timestamps[2].pins = TimestampPins::new(&pins).unwrap();
    assert_eq!(verify(&d), Err(at(set, 2, Rule::TimestampKey)));

    // One operator, two kinds.
    let mut d = base.clone();
    d.timestamps[2].operator = OrgId::new(b"FREE-TSA").unwrap();
    assert_eq!(verify(&d), Err(at(set, 2, Rule::TimestampOperator)));
    // One operator spelled twice is one operator (the review's third
    // proof of concept): the government's operator in lower case, declared
    // non-government, is refused.
    let mut d = base.clone();
    d.timestamps
        .retain(|a| a.tsa_id.as_bytes() != b"TSA-FREE-1");
    d.timestamps[1].operator = OrgId::new(b"mois-gpki").unwrap();
    d.timestamps[1].kind = TimestampAuthorityKind::NonGovernment;
    assert_eq!(verify(&d), Err(at(set, 1, Rule::TimestampOperator)));
    let mut d = base.clone();
    d.timestamps[0].operator = OrgId::new(b"Mois-Gpki").unwrap();
    assert_eq!(verify(&d), Err(at(set, 1, Rule::TimestampOperator)));
    // The same spelling with the same kind is one operator and fine.
    let mut d = base.clone();
    d.timestamps[2].operator = OrgId::new(b"mois-gpki").unwrap();
    assert_eq!(verify(&d), Ok(()));
    // Names compare with the separators dropped too (the second review's
    // I-b): MOIS_GPKI and mois.gpki are MOIS-GPKI.
    let mut d = base.clone();
    d.timestamps[2].operator = OrgId::new(b"MOIS_GPKI").unwrap();
    d.timestamps[2].kind = TimestampAuthorityKind::NonGovernment;
    assert_eq!(verify(&d), Err(at(set, 2, Rule::TimestampOperator)));
    let mut d = base.clone();
    d.timestamps[2].operator = OrgId::new(b"mois.gpki").unwrap();
    assert_eq!(verify(&d), Ok(()));
    // Many authorities of one operator and one kind are fine (they count
    // as one toward an anchor).
    let mut d = base.clone();
    d.timestamps[2].policy_accuracy = PolicyAccuracy::from_millis(2000).unwrap();
    assert_eq!(verify(&d), Ok(()));

    // The declared accuracy: one second to one minute.
    for (ms, ok) in [
        (0, false),
        (999, false),
        (1000, true),
        (60_000, true),
        (60_001, false),
        (3_600_000, false),
    ] {
        let mut d = base.clone();
        d.timestamps[0].policy_accuracy = PolicyAccuracy::from_millis(ms).unwrap();
        let expected = if ok {
            Ok(())
        } else {
            Err(at(set, 0, Rule::TimestampAccuracy))
        };
        assert_eq!(verify(&d), expected, "{ms} ms");
    }

    // An operator that is a witness's organisation or an election
    // commission's, in any case: refused in the genesis.
    // Every roster organisation too (clerks, observers, custodians of
    // the paper, the court), in any spelling.
    for org in [
        b"ORG-C".as_slice(),
        b"org-c",
        b"ORG_C",
        b"NEC-D",
        b"nec-d",
        b"N.E.C-D",
        b"ORG-ST",
        b"org_st",
        b"Police",
        b"COURT",
    ] {
        let mut d = base.clone();
        d.timestamps[0].operator = OrgId::new(org).unwrap();
        assert_eq!(
            verify(&d),
            Err(at(set, 0, Rule::TimestampOperatorConflict)),
            "{}",
            String::from_utf8_lossy(org)
        );
    }

    // The set's own rules: order, count, root.
    let mut raw = base.raw();
    raw.timestamps.swap(0, 1);
    let built = sign_genesis(&base, raw);
    assert_eq!(
        verify_genesis(&built.pin, &built.input(), &[]).unwrap_err(),
        at(set, 1, Rule::NotSorted)
    );
    let built = sign_genesis_with(&base, base.raw(), &SIGNERS, |p| {
        p.sets[set.index()].count += 1;
    });
    let err = verify_genesis(&built.pin, &built.input(), &[]).unwrap_err();
    assert_eq!((err.set, err.rule), (Some(set), Rule::Count));
    let built = sign_genesis_with(&base, base.raw(), &SIGNERS, |p| {
        p.sets[set.index()].root = Hash512([0x77; 64]);
    });
    let err = verify_genesis(&built.pin, &built.input(), &[]).unwrap_err();
    assert_eq!((err.set, err.rule), (Some(set), Rule::Root));
}

#[test]
fn refuses_a_roll_authority_set_that_breaks_a_rule() {
    use common::roll::{self, ROLL_BASE};
    use ityv_encoding::{OrgId, RollAuthorityKind as K};
    let set = EntrySet::RollAuthorities;
    let base = Draft::standard();
    assert_eq!(verify(&base), Ok(()));
    let verified = verify_genesis(&standard().pin, &standard().input(), &[]).unwrap();
    assert_eq!(verified.roll_authorities().count(), 11);
    assert_eq!(verified.genesis().body().custody_quorum(), 3);
    let jud = verified.roll_authority(roll::C_JUD).unwrap();
    assert_eq!(jud.kind, K::CustodianJudiciary);
    assert_eq!(
        verified.roll_authority_entry(roll::C_JUD).unwrap().get(),
        jud
    );
    assert!(verified.roll_authority(b"R-NOBODY").is_none());
    assert!(verified.roll_authority_entry(b"R-NOBODY").is_none());
    let whole = |rule| Error {
        state: 0,
        set: Some(set),
        index: None,
        rule,
    };
    let without = |id: &[u8]| {
        let mut d = base.clone();
        d.rolls.retain(|a| a.authority_id.as_bytes() != id);
        d
    };

    // Two custodians of one organisation (in key order R-C-PA, then
    // R-C-PB): one would count twice.
    let mut d = base.clone();
    d.rolls[5].org_id = OrgId::new(b"PARTY-A").unwrap();
    assert_eq!(verify(&d), Err(at(set, 5, Rule::RollCustodians)));
    // Also under another spelling (the second review's proof of concept:
    // the Ministry as `MOIS` and again as `mois` met a quorum of three
    // with two organisations).
    for spelling in [b"mois".as_slice(), b"M.O.I.S", b"Mois", b"party_a"] {
        let mut d = base.clone();
        d.rolls[5].org_id = OrgId::new(spelling).unwrap();
        assert_eq!(
            verify(&d),
            Err(at(set, 5, Rule::RollCustodians)),
            "{}",
            String::from_utf8_lossy(spelling)
        );
    }
    let mut d = base.clone();
    d.rolls[5].org_id = OrgId::new(b"MOIS-2").unwrap();
    assert_eq!(verify(&d), Ok(()));
    // A custodian of a reporting unit's election commission, however
    // spelled (the final review's F7): the commission would count toward
    // the quorum that confirms its own roll. A source may be one.
    for spelling in [b"NEC-D".as_slice(), b"nec_d", b"NECD"] {
        let mut d = base.clone();
        d.rolls[5].org_id = OrgId::new(spelling).unwrap();
        assert_eq!(
            verify(&d),
            Err(at(set, 5, Rule::RollCustodians)),
            "{}",
            String::from_utf8_lossy(spelling)
        );
    }
    let mut d = base.clone();
    d.rolls[6].org_id = OrgId::new(b"nec-d").unwrap();
    assert_eq!(verify(&d), Ok(()));
    // A source may share its organisation with a custodian (the court
    // administration keeps the deaths and a copy).
    let mut d = base.clone();
    d.rolls[7].org_id = OrgId::new(b"COURT-ADMIN").unwrap();
    assert_eq!(verify(&d), Ok(()));
    // Fewer custodians than the quorum.
    let mut d = base.clone();
    d.custody_quorum = 6;
    assert_eq!(verify(&d), Err(whole(Rule::RollCustodians)));
    d.custody_quorum = 5;
    assert_eq!(verify(&d), Ok(()));
    // Without the court administration or the Ministry of the Interior.
    for id in [roll::C_JUD, roll::C_INT] {
        assert_eq!(verify(&without(id)), Err(whole(Rule::RollCustodians)));
    }
    // Three custodians make a quorum of three: the court administration,
    // the Ministry and the committee, no party.
    let mut d = base.clone();
    d.rolls.retain(|a| a.kind != K::CustodianParty);
    assert_eq!(verify(&d), Ok(()));
    // The committee is one of them (exactly one each of kinds 11, 12, 13).
    assert_eq!(
        verify(&without(roll::C_IVC)),
        Err(whole(Rule::RollCustodians))
    );
    // A second custodian of the court administration's, the Ministry's or
    // the committee's kind, of another organisation: refused, or it could
    // stand in for the real one (the second review's proof of concept: a
    // party registered as the court administration met the quorum
    // without the court administration's receipt).
    for kind in [
        K::CustodianJudiciary,
        K::CustodianInterior,
        K::CustodianCommittee,
    ] {
        let mut d = base.clone();
        assert_eq!(d.rolls[5].authority_id.as_bytes(), roll::C_PB);
        d.rolls[5].kind = kind;
        assert_eq!(verify(&d), Err(whole(Rule::RollCustodians)), "{kind:?}");
    }
    // Two parties are fine.
    assert_eq!(verify(&base), Ok(()));

    // No district head, no snapshot, two snapshots.
    for d in [without(roll::GU), without(roll::SNAPSHOT)] {
        assert_eq!(verify(&d), Err(whole(Rule::RollSources)));
    }
    let mut d = base.clone();
    d.rolls.push(roll::entry((
        b"R-SNAPSHOT-2",
        b"MOIS-2",
        K::ResidentSnapshot,
        11,
    )));
    assert_eq!(verify(&d), Err(whole(Rule::RollSources)));
    // Other sources are optional.
    for id in [roll::DEATHS, roll::DISQ, roll::OVERSEAS, roll::APPEAL] {
        assert_eq!(verify(&without(id)), Ok(()));
    }

    // A key another authority or the commission has, a key nothing could
    // verify under.
    let mut d = base.clone();
    d.rolls[6].key = registered(ROLL_BASE + 3);
    assert_eq!(verify(&d), Err(at(set, 6, Rule::SharedKey)));
    let mut d = base.clone();
    d.rolls[0].key = registered(common::COMMISSION);
    assert_eq!(verify(&d), Err(at(set, 0, Rule::SharedKey)));
    let mut d = base.clone();
    d.rolls[2].key = weak(registered(SPARE_BASE + 5));
    assert_eq!(verify(&d), Err(at(set, 2, Rule::InvalidKey)));
}
