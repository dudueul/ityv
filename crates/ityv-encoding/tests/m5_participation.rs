//! The participation ledger (ENCODING.md §8.25, §8.31, §8.32):
//! `ParticipationSet` (0x0020), `ModuleProvisioned` (0x0026) and
//! `PartyKeyCeremony` (0x0027). Round trips, the constructors' rules (the
//! same as the decoders'), and the boundaries the golden vectors in
//! `vectors.rs` do not reach. Signatures are patterned bytes.
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

use common::encode_to_vec;
use ityv_encoding::{
    ActorSig, ActorSigs, COMMITTEE_ACTOR, ChamberCode, Decode, ElectionId, Encode, ErrorKind,
    HEADER_LEN, HYBRID_SIG_LEN, Hash512, Ident, KEM_EK_LEN, MAX_ACTOR_SIGS, MAX_PSEUDONYMS,
    ModuleId, ModuleProvisioned, ModuleProvisionedMessage, ModuleProvisionedParts,
    PURPOSE_MODULE_PROVISIONED, PURPOSE_PARTICIPATION_SET, PURPOSE_PARTY_KEY, ParticipationMessage,
    ParticipationModuleSig, ParticipationSet, PartyKeyCeremony, PartyKeyMessage, PartyKeyParts,
    Pseudonyms, Reader, SCHEMA_MODULE_PROVISIONED, SCHEMA_PARTICIPATION_SET,
    SCHEMA_PARTY_KEY_CEREMONY, SCHEMA_VERSION_1, ShareHolder, StationId, TimeBucket, TrusteeId,
    Writer, decode_object, is_party_chamber,
};
use proptest::prelude::*;
use std::vec::Vec;

const E: &[u8] = b"KR-2030-PRES";
static SIG: [u8; HYBRID_SIG_LEN] = [0x5A; HYBRID_SIG_LEN];
static SIG2: [u8; HYBRID_SIG_LEN] = [0x6B; HYBRID_SIG_LEN];
static KEM: [u8; KEM_EK_LEN] = [0x6B; KEM_EK_LEN];
static PRF: [u8; 32] = [0x7C; 32];

fn e() -> ElectionId<'static> {
    ElectionId::new(E).unwrap()
}

fn id(bytes: &'static [u8]) -> Ident<'static> {
    Ident::new(bytes, 64).unwrap()
}

fn leak(v: Vec<u8>) -> &'static [u8] {
    Vec::leak(v)
}

/// A field group's encoding, without an object header.
fn group<T: Encode>(value: &T) -> Vec<u8> {
    let mut out = std::vec![0u8; value.encoded_len()];
    let mut w = Writer::new(&mut out);
    value.encode(&mut w).unwrap();
    assert_eq!(w.finish(), out.len());
    out
}

fn kind_of<'a, T: Decode<'a> + core::fmt::Debug>(
    schema: ityv_encoding::SchemaId,
    bytes: &'a [u8],
) -> (ErrorKind, usize) {
    let err = decode_object::<T>(schema, SCHEMA_VERSION_1, bytes).unwrap_err();
    (err.kind(), err.offset())
}

fn pseudonyms(fills: &[u8]) -> Vec<u8> {
    fills.iter().flat_map(|f| [*f; 64]).collect()
}

fn module_sig(name: &'static [u8]) -> ParticipationModuleSig<'static> {
    ParticipationModuleSig {
        module_id: ModuleId::new(name).unwrap(),
        sig: &SIG2,
    }
}

fn message(fills: &[u8]) -> &'static [u8] {
    let bytes = leak(pseudonyms(fills));
    leak(group(&ParticipationMessage {
        election_id: e(),
        station_id: StationId::new(b"ST-1").unwrap(),
        pseudonyms: Pseudonyms::new(bytes).unwrap(),
    }))
}

#[test]
fn purposes_and_reserved_actor() {
    assert_eq!(PURPOSE_PARTICIPATION_SET, b"participation-set");
    assert_eq!(PURPOSE_MODULE_PROVISIONED, b"module-provisioned");
    assert_eq!(PURPOSE_PARTY_KEY, b"party-key");
    assert_eq!(COMMITTEE_ACTOR, b"committee");
}

#[test]
fn party_chambers_are_p1_to_p4() {
    for code in 1..=8u8 {
        let chamber = ChamberCode::from_code(code).unwrap();
        assert_eq!(is_party_chamber(chamber), code <= 4, "code {code}");
    }
}

#[test]
fn pseudonyms_constructor_rules() {
    let ok = pseudonyms(&[1, 2, 2, 3]);
    let p = Pseudonyms::new(&ok).unwrap();
    assert_eq!(p.len(), 4);
    assert!(!p.is_empty());
    assert_eq!(p.as_bytes(), ok.as_slice());
    let fills: Vec<u8> = p.iter().map(|x| x[0]).collect();
    assert_eq!(fills, [1, 2, 2, 3]);
    assert!(Pseudonyms::new(&[]).unwrap().is_empty());
    assert_eq!(Pseudonyms::new(&[]).unwrap().len(), 0);
    // Not whole pseudonyms.
    assert!(Pseudonyms::new(&ok[..65]).is_none());
    assert!(Pseudonyms::new(&[0u8; 63]).is_none());
    // Descending.
    assert!(Pseudonyms::new(&pseudonyms(&[2, 1])).is_none());
    // At most 65 536.
    let most = std::vec![0u8; MAX_PSEUDONYMS * 64];
    assert_eq!(Pseudonyms::new(&most).unwrap().len(), MAX_PSEUDONYMS);
    let too_many = std::vec![0u8; (MAX_PSEUDONYMS + 1) * 64];
    assert!(Pseudonyms::new(&too_many).is_none());
}

#[test]
fn a_full_participation_set_decodes() {
    let most = leak(std::vec![0u8; MAX_PSEUDONYMS * 64]);
    let m = leak(group(&ParticipationMessage {
        election_id: e(),
        station_id: StationId::new(b"ST-1").unwrap(),
        pseudonyms: Pseudonyms::new(most).unwrap(),
    }));
    let set = ParticipationSet::new(m, &SIG, &[]).unwrap();
    assert_eq!(set.count(), 65_536);
    let bytes = encode_to_vec(SCHEMA_PARTICIPATION_SET, SCHEMA_VERSION_1, &set);
    let back: ParticipationSet<'_> =
        decode_object(SCHEMA_PARTICIPATION_SET, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(back, set);
    assert_eq!(back.module_sig_count(), 0);
}

#[test]
fn participation_set_constructor_rules() {
    let m = message(&[1, 1, 9]);
    let sigs = [
        module_sig(b"P1"),
        module_sig(b"P2"),
        module_sig(b"P3"),
        module_sig(b"P4"),
    ];
    let set = ParticipationSet::new(m, &SIG, &sigs).unwrap();
    assert_eq!(set.election_id().as_bytes(), E);
    assert_eq!(set.station_id().as_bytes(), b"ST-1");
    assert_eq!(set.count(), 3);
    assert_eq!(set.message().count(), 3);
    assert_eq!(set.pseudonyms().len(), 3);
    assert_eq!(set.message_bytes(), m);
    assert_eq!(set.counter_sig(), &SIG);
    assert_eq!(set.module_sig_count(), 4);
    assert_eq!(set.module_sigs().count(), 4);
    let five = [
        module_sig(b"P1"),
        module_sig(b"P2"),
        module_sig(b"P3"),
        module_sig(b"P4"),
        module_sig(b"P5"),
    ];
    let err = ParticipationSet::new(m, &SIG, &five).unwrap_err();
    assert_eq!((err.kind(), err.offset()), (ErrorKind::CountExceedsMax, 0));
    let twice = [module_sig(b"P1"), module_sig(b"P2"), module_sig(b"P1")];
    let err = ParticipationSet::new(m, &SIG, &twice).unwrap_err();
    assert_eq!((err.kind(), err.offset()), (ErrorKind::Duplicate, 0));
    // Distinct modules in any order are the decoder's business only.
    assert!(ParticipationSet::new(m, &SIG, &[module_sig(b"P2"), module_sig(b"P1")]).is_ok());
    // Bytes after the field group.
    let mut longer = m.to_vec();
    longer.push(0);
    let err = ParticipationSet::new(leak(longer), &SIG, &[]).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::TrailingBytes);
    // The decoder takes the same module rule.
    let dup = ParticipationSet::new(m, &SIG, &[module_sig(b"P1"), module_sig(b"P2")]).unwrap();
    let mut bytes = encode_to_vec(SCHEMA_PARTICIPATION_SET, SCHEMA_VERSION_1, &dup);
    let n = bytes.len();
    // `P2` → `P1` in the last module identifier (its last byte sits just
    // before the signature).
    bytes[n - HYBRID_SIG_LEN - 1] = b'1';
    assert_eq!(
        kind_of::<ParticipationSet<'_>>(SCHEMA_PARTICIPATION_SET, &bytes),
        (ErrorKind::Duplicate, n - HYBRID_SIG_LEN - 6)
    );
}

#[test]
fn reader_gives_the_consumed_bytes() {
    let bytes = [1u8, 2, 3, 4];
    let mut r = Reader::new(&bytes);
    let _ = r.take(3).unwrap();
    assert_eq!(r.consumed_from(1).unwrap(), &[2, 3]);
    assert!(r.consumed_from(3).unwrap().is_empty());
    let err = r.consumed_from(4).unwrap_err();
    assert_eq!((err.kind(), err.offset()), (ErrorKind::UnexpectedEnd, 4));
}

fn actor(name: &'static [u8]) -> ActorSig<'static> {
    ActorSig {
        actor_id: id(name),
        sig: &SIG,
    }
}

#[test]
fn actor_signature_rules() {
    let sigs = [actor(b"a"), actor(b"b"), actor(b"committee")];
    let set = ActorSigs::new(&sigs).unwrap();
    assert_eq!(set.len(), 3);
    assert!(!set.is_empty());
    assert!(ActorSigs::new(&[]).unwrap().is_empty());
    let names: Vec<&[u8]> = set.iter().map(|s| s.actor_id.as_bytes()).collect();
    assert_eq!(names, [b"a".as_slice(), b"b", b"committee"]);
    assert!(ActorSigs::new(&[actor(b"b"), actor(b"a")]).is_none());
    assert!(ActorSigs::new(&[actor(b"a"), actor(b"a")]).is_none());
    let long = ActorSig {
        actor_id: Ident::new(&[b'x'; 65], 65).unwrap(),
        sig: &SIG,
    };
    assert!(ActorSigs::new(&[long]).is_none());
    let names: Vec<Vec<u8>> = (0..=MAX_ACTOR_SIGS)
        .map(|i| std::format!("a{i:02}").into_bytes())
        .collect();
    let many: Vec<ActorSig<'_>> = names
        .iter()
        .map(|n| ActorSig {
            actor_id: Ident::new(n, 64).unwrap(),
            sig: &SIG,
        })
        .collect();
    assert!(ActorSigs::new(&many[..MAX_ACTOR_SIGS]).is_some());
    assert!(ActorSigs::new(&many).is_none());
}

fn parts(chamber: ChamberCode, prf: Option<&'static [u8; 32]>) -> ModuleProvisionedParts<'static> {
    ModuleProvisionedParts {
        election_id: e(),
        module_id: ModuleId::new(b"M-1").unwrap(),
        device_id: id(b"U-1"),
        chamber,
        member_count: 1,
        pad_length: 7,
        chassis_id: id(b"C-1"),
        pad_card_id: id(b"PC-1"),
        reprovision_count: 0,
        chassis_check_hash: Hash512([1; 64]),
        kem_ek: &KEM,
        entropy_commitment: Hash512([2; 64]),
        se_present: true,
        prf_key_check: prf,
    }
}

#[test]
fn module_provisioned_constructor_rules() {
    let ok = parts(ChamberCode::P1, Some(&PRF));
    assert!(ModuleProvisionedMessage::new(&ok).is_some());
    for members in [1u8, 8] {
        assert!(
            ModuleProvisionedMessage::new(&ModuleProvisionedParts {
                member_count: members,
                ..ok
            })
            .is_some()
        );
    }
    for members in [0u8, 9] {
        assert!(
            ModuleProvisionedMessage::new(&ModuleProvisionedParts {
                member_count: members,
                ..ok
            })
            .is_none()
        );
    }
    let long = Ident::new(&[b'x'; 65], 65).unwrap();
    for p in [
        ModuleProvisionedParts {
            device_id: long,
            ..ok
        },
        ModuleProvisionedParts {
            chassis_id: long,
            ..ok
        },
        ModuleProvisionedParts {
            pad_card_id: long,
            ..ok
        },
        ModuleProvisionedParts {
            se_present: false,
            ..ok
        },
        parts(ChamberCode::J, Some(&PRF)),
        parts(ChamberCode::N, None),
    ] {
        assert!(ModuleProvisionedMessage::new(&p).is_none(), "{p:?}");
    }
    for p in [
        parts(ChamberCode::P4, Some(&PRF)),
        parts(ChamberCode::P1, None),
        parts(ChamberCode::C, None),
        ModuleProvisionedParts {
            se_present: false,
            ..parts(ChamberCode::A, None)
        },
    ] {
        let m = ModuleProvisionedMessage::new(&p).unwrap();
        assert_eq!(m.parts(), &p);
    }
    // The record's constructor.
    let m = leak(group(&ModuleProvisionedMessage::new(&ok).unwrap()));
    let record = ModuleProvisioned::new(m, &[actor(b"a"), actor(b"b")]).unwrap();
    assert_eq!(record.message_bytes(), m);
    assert_eq!(record.parts(), &ok);
    assert_eq!(record.signatures().len(), 2);
    let err = ModuleProvisioned::new(m, &[actor(b"b"), actor(b"a")]).unwrap_err();
    assert_eq!(
        (err.kind(), err.offset()),
        (ErrorKind::InvariantViolation, 0)
    );
    let mut longer = m.to_vec();
    longer.push(0);
    let err = ModuleProvisioned::new(leak(longer), &[]).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::TrailingBytes);
    // The decoder accepts eight members and refuses a party code on no
    // chamber (code 0).
    let eight = leak(group(
        &ModuleProvisionedMessage::new(&ModuleProvisionedParts {
            member_count: 8,
            ..ok
        })
        .unwrap(),
    ));
    let record = ModuleProvisioned::new(eight, &[]).unwrap();
    let mut bytes = encode_to_vec(SCHEMA_MODULE_PROVISIONED, SCHEMA_VERSION_1, &record);
    assert!(
        decode_object::<ModuleProvisioned<'_>>(SCHEMA_MODULE_PROVISIONED, SCHEMA_VERSION_1, &bytes)
            .is_ok()
    );
    // Chamber at header + election 16 + module 7 + device 7.
    let chamber_at = HEADER_LEN + 16 + 7 + 7;
    bytes[chamber_at] = 0;
    assert_eq!(
        kind_of::<ModuleProvisioned<'_>>(SCHEMA_MODULE_PROVISIONED, &bytes),
        (ErrorKind::ValueOutOfRange, chamber_at)
    );
    bytes[chamber_at] = 7;
    assert_eq!(
        kind_of::<ModuleProvisioned<'_>>(SCHEMA_MODULE_PROVISIONED, &bytes).0,
        ErrorKind::InvariantViolation
    );
}

fn holder(trustee: &'static [u8], model: &'static [u8]) -> ShareHolder<'static> {
    ShareHolder {
        trustee_id: TrusteeId::new(trustee).unwrap(),
        hsm_model: id(model),
        hsm_serial_hash: Hash512([3; 64]),
    }
}

fn key_parts<'s>(
    chamber: ChamberCode,
    threshold: u8,
    holders: &'s [ShareHolder<'static>],
) -> PartyKeyParts<'static, 's> {
    PartyKeyParts {
        election_id: e(),
        chamber,
        wrapped_module_count: 2,
        share_threshold: threshold,
        share_holders: holders,
        prf_key_check: &PRF,
        time_bucket: TimeBucket::new(9),
    }
}

#[test]
fn party_key_constructor_rules() {
    let three = [
        holder(b"t1", b"H1"),
        holder(b"t2", b"H2"),
        holder(b"t3", b"H3"),
    ];
    let m = PartyKeyMessage::new(&key_parts(ChamberCode::P2, 3, &three)).unwrap();
    assert_eq!(m.election_id().as_bytes(), E);
    assert_eq!(m.chamber(), ChamberCode::P2);
    assert_eq!(m.wrapped_module_count(), 2);
    assert_eq!(m.share_threshold(), 3);
    assert_eq!(m.share_count(), 3);
    assert_eq!(m.share_holders().count(), 3);
    assert_eq!(m.prf_key_check(), &PRF);
    assert_eq!(m.time_bucket(), TimeBucket::new(9));
    assert!(PartyKeyMessage::new(&key_parts(ChamberCode::P1, 1, &three[..1])).is_some());
    for p in [
        key_parts(ChamberCode::P1, 0, &three),
        key_parts(ChamberCode::P1, 4, &three),
        key_parts(ChamberCode::J, 2, &three),
        key_parts(ChamberCode::N, 2, &three),
        key_parts(ChamberCode::P1, 1, &[]),
        key_parts(ChamberCode::P1, 2, &[three[1], three[0]]),
        key_parts(ChamberCode::P1, 1, &[three[0], three[0]]),
        key_parts(
            ChamberCode::P1,
            1,
            &[ShareHolder {
                hsm_model: Ident::new(&[b'x'; 65], 65).unwrap(),
                ..three[0]
            }],
        ),
    ] {
        assert!(PartyKeyMessage::new(&p).is_none(), "{p:?}");
    }
    let nine: Vec<ShareHolder<'static>> = [
        b"t1".as_slice(),
        b"t2",
        b"t3",
        b"t4",
        b"t5",
        b"t6",
        b"t7",
        b"t8",
        b"t9",
    ]
    .iter()
    .map(|t| holder(t, b"H"))
    .collect();
    assert!(PartyKeyMessage::new(&key_parts(ChamberCode::P1, 2, &nine[..8])).is_some());
    assert!(PartyKeyMessage::new(&key_parts(ChamberCode::P1, 2, &nine)).is_none());

    // Eight shares, eight of eight, decode.
    let eight = PartyKeyMessage::new(&key_parts(ChamberCode::P3, 8, &nine[..8])).unwrap();
    let mb = leak(group(&eight));
    let record = PartyKeyCeremony::new(mb, &[actor(b"a")]).unwrap();
    assert_eq!(record.message(), &eight);
    assert_eq!(record.message_bytes(), mb);
    assert_eq!(record.signatures().len(), 1);
    let bytes = encode_to_vec(SCHEMA_PARTY_KEY_CEREMONY, SCHEMA_VERSION_1, &record);
    let back: PartyKeyCeremony<'_> =
        decode_object(SCHEMA_PARTY_KEY_CEREMONY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(back, record);
    let err = PartyKeyCeremony::new(mb, &[actor(b"b"), actor(b"a")]).unwrap_err();
    assert_eq!(
        (err.kind(), err.offset()),
        (ErrorKind::InvariantViolation, 0)
    );
    let mut longer = mb.to_vec();
    longer.push(0);
    let err = PartyKeyCeremony::new(leak(longer), &[]).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::TrailingBytes);
}

#[test]
fn seventeen_actor_signatures_are_refused() {
    let m = leak(group(
        &ModuleProvisionedMessage::new(&parts(ChamberCode::J, None)).unwrap(),
    ));
    let record = ModuleProvisioned::new(m, &[]).unwrap();
    let mut bytes = encode_to_vec(SCHEMA_MODULE_PROVISIONED, SCHEMA_VERSION_1, &record);
    let at = bytes.len() - 4;
    bytes[at..].copy_from_slice(&17u32.to_be_bytes());
    assert_eq!(
        kind_of::<ModuleProvisioned<'_>>(SCHEMA_MODULE_PROVISIONED, &bytes),
        (ErrorKind::CountExceedsMax, at)
    );
}

fn chamber_strategy(party: bool) -> impl Strategy<Value = ChamberCode> {
    let max = if party { 4u8 } else { 7 };
    (1u8..=max).prop_map(|c| ChamberCode::from_code(c).unwrap())
}

proptest! {
    /// Every valid participation set survives an object round trip with
    /// its message bytes intact.
    #[test]
    fn participation_set_round_trip(
        mut fills in prop::collection::vec(any::<u8>(), 0..24),
        modules in 0usize..=4,
    ) {
        fills.sort_unstable();
        let m = message(&fills);
        let names: [&'static [u8]; 4] = [b"P1", b"P2", b"P3", b"P4"];
        let sigs: Vec<ParticipationModuleSig<'static>> =
            names[..modules].iter().map(|n| module_sig(n)).collect();
        let set = ParticipationSet::new(m, &SIG, &sigs).unwrap();
        let bytes = encode_to_vec(SCHEMA_PARTICIPATION_SET, SCHEMA_VERSION_1, &set);
        let back: ParticipationSet<'_> =
            decode_object(SCHEMA_PARTICIPATION_SET, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back, set);
        prop_assert_eq!(back.message_bytes(), m);
        prop_assert_eq!(usize::try_from(back.count()).unwrap(), fills.len());
        prop_assert_eq!(back.module_sig_count(), modules);
    }

    /// Every valid module provisioning record survives a round trip.
    #[test]
    fn module_provisioned_round_trip(
        chamber in chamber_strategy(false),
        members in 1u8..=8,
        pad_length in any::<u64>(),
        reprovisions in any::<u32>(),
        se in any::<bool>(),
        with_prf in any::<bool>(),
        actors in 0usize..=4,
    ) {
        let prf = (with_prf && se && is_party_chamber(chamber)).then_some(&PRF);
        let p = ModuleProvisionedParts {
            member_count: members,
            pad_length,
            reprovision_count: reprovisions,
            se_present: se,
            ..parts(chamber, prf)
        };
        let m = leak(group(&ModuleProvisionedMessage::new(&p).unwrap()));
        let names: [&'static [u8]; 4] = [b"T-1", b"committee", b"obs-a", b"obs-b"];
        let sigs: Vec<ActorSig<'static>> = names[..actors].iter().map(|n| actor(n)).collect();
        let record = ModuleProvisioned::new(m, &sigs).unwrap();
        let bytes = encode_to_vec(SCHEMA_MODULE_PROVISIONED, SCHEMA_VERSION_1, &record);
        let back: ModuleProvisioned<'_> =
            decode_object(SCHEMA_MODULE_PROVISIONED, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back, record);
        prop_assert_eq!(back.parts(), &p);
    }

    /// Every valid party key ceremony record survives a round trip.
    #[test]
    fn party_key_round_trip(
        chamber in chamber_strategy(true),
        count in 1usize..=8,
        threshold_seed in any::<u8>(),
        wrapped in any::<u32>(),
        bucket in any::<u64>(),
    ) {
        let names: [&'static [u8]; 8] = [b"t1", b"t2", b"t3", b"t4", b"t5", b"t6", b"t7", b"t8"];
        let holders: Vec<ShareHolder<'static>> =
            names[..count].iter().map(|t| holder(t, b"HSM")).collect();
        let threshold = 1 + threshold_seed % u8::try_from(count).unwrap();
        let m = PartyKeyMessage::new(&PartyKeyParts {
            wrapped_module_count: wrapped,
            time_bucket: TimeBucket::new(bucket),
            ..key_parts(chamber, threshold, &holders)
        })
        .unwrap();
        let mb = leak(group(&m));
        let record = PartyKeyCeremony::new(mb, &[actor(b"committee")]).unwrap();
        let bytes = encode_to_vec(SCHEMA_PARTY_KEY_CEREMONY, SCHEMA_VERSION_1, &record);
        let back: PartyKeyCeremony<'_> =
            decode_object(SCHEMA_PARTY_KEY_CEREMONY, SCHEMA_VERSION_1, &bytes).unwrap();
        prop_assert_eq!(back, record);
        prop_assert_eq!(back.message().share_count(), u8::try_from(count).unwrap());
    }
}
