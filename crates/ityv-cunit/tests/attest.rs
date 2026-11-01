//! Field attestation (ADR-0023, PROTOCOL.md §7.9, VC-088): the challenge
//! checks, the module statements, the signed attestation and summary, and
//! that nothing about the box changes.
// Integration-test crate: outside the TCB. Test code expresses "this must
// hold" with unwrap/expect/panic/indexing and does small arithmetic, so
// those restriction lints are relaxed for this file only (CONSTITUTION.md
// §1.1). The tests name the world, box, modules and journal `w`, `b`, `m`,
// `j` like the other test files, so the single-character name lint is
// relaxed too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    clippy::many_single_char_names
)]

mod common;

use common::{
    MemJournal, STYLE_SMALL, World, cast_one, interpretation, leak, leak_bytes, mocks,
    module_attestation_key, module_boot, ports, tb, work, world,
};
use ityv_crypto::{
    HybridSigningKey, HybridVerifyingKey, Purpose, RecordPurpose, RecordSignature,
    RecordSigningKey, RecordVerifyingKey, Sha3Hasher, object_hash, sign_record, verify_hybrid,
    verify_record,
};
use ityv_cunit::attest::{
    ATTEST_SPACING_SECONDS, ATTEST_WORK_LEN, AttestRequest, AttestationSetup, Attestor,
    BootMeasurements, DEVICE_CLASS_COMMITMENT_UNIT, LABEL_BUNDLE, MAX_OBSERVERS, ObserverKey,
};
use ityv_cunit::boxstate::{OpenBox, Signer};
use ityv_cunit::config::Profile;
use ityv_cunit::link::{AttestChallenge, MAX_ATTEST_CHALLENGE_LEN, SCHEMA_ATTEST_CHALLENGE};
use ityv_cunit::{Error, PortError};
use ityv_encoding::{
    AttestationSummary, ChallengeMessage, ChallengePath, Decode, DeviceAttestation, ElectionId,
    Encode, ErrorKind, Hash512, Ident, MeasuredImage, ModuleId, ModuleStatementMessage, ObserverId,
    SCHEMA_ATTESTATION_SUMMARY, SCHEMA_DEVICE_ATTESTATION, SCHEMA_VERSION_1, Writer, decode_object,
    encode_object,
};
use std::vec::Vec;

const DEVICE: &[u8] = b"cu-0042";
const OBSERVERS: [&[u8]; 2] = [b"obs-1", b"obs-2"];

fn observer_key(id: &[u8]) -> RecordSigningKey {
    let mut seed = [0u8; 32];
    seed[..id.len()].copy_from_slice(id);
    RecordSigningKey::from_seed(seed)
}

fn attestation_key() -> HybridSigningKey {
    HybridSigningKey::from_seeds([21; 32], [22; 32])
}

fn fields<T: Encode>(value: &T) -> Vec<u8> {
    let mut out = std::vec![0u8; value.encoded_len()];
    let mut w = Writer::new(&mut out);
    value.encode(&mut w).unwrap();
    out
}

/// The station's token list and every module's attestation key.
fn setup(w: &World) -> AttestationSetup<'static> {
    let observers: Vec<ObserverKey<'static>> = OBSERVERS
        .iter()
        .map(|id| {
            ObserverKey::new(
                ObserverId::new(id).unwrap(),
                observer_key(id).verifying_key(),
            )
        })
        .collect();
    let module_keys: Vec<HybridVerifyingKey> = w
        .config
        .modules()
        .iter()
        .map(|m| module_attestation_key(m.module_id().as_bytes()).verifying_key())
        .collect();
    AttestationSetup {
        device_id: Ident::new(DEVICE, 64).unwrap(),
        observers: Box::leak(observers.into_boxed_slice()),
        module_keys: Box::leak(module_keys.into_boxed_slice()),
    }
}

/// An `AttestChallenge` object signed by `signer_id`'s key for `observer`.
fn challenge_by(w: &World, observer: &[u8], signer_id: &[u8], nonce: &[u8; 32]) -> Vec<u8> {
    let message = ChallengeMessage {
        election_id: w.config.election_id(),
        station_id: w.config.station_id(),
        observer_id: ObserverId::new(observer).unwrap(),
        nonce,
    };
    let sig = sign_record(
        &observer_key(signer_id),
        RecordPurpose::AttestChallenge,
        &fields(&message),
    )
    .unwrap();
    let sig_bytes: &'static [u8; 64] = leak(*sig.as_bytes());
    let nonce: &'static [u8; 32] = leak(*nonce);
    let observer: &'static [u8] = leak_bytes(observer.to_vec());
    let value = AttestChallenge::new(
        w.config.election_id(),
        ObserverId::new(observer).unwrap(),
        nonce,
        sig_bytes,
    );
    let mut out = std::vec![0u8; MAX_ATTEST_CHALLENGE_LEN];
    let len = encode_object(SCHEMA_ATTEST_CHALLENGE, SCHEMA_VERSION_1, &value, &mut out).unwrap();
    out.truncate(len);
    out
}

fn challenge(w: &World, nonce: &[u8; 32]) -> Vec<u8> {
    challenge_by(w, b"obs-1", b"obs-1", nonce)
}

fn images() -> [MeasuredImage<'static>; 2] {
    [
        MeasuredImage {
            component_id: Ident::new(b"cunit", 64).unwrap(),
            version: Ident::new(b"1.4.2", 32).unwrap(),
            build: 7,
            image_hash: Hash512([0x41; 64]),
        },
        MeasuredImage {
            component_id: Ident::new(b"interp", 64).unwrap(),
            version: Ident::new(b"2.0.0", 32).unwrap(),
            build: 9,
            image_hash: Hash512([0x42; 64]),
        },
    ]
}

fn request<'a>(
    challenge: &'a [u8],
    components: &'a [MeasuredImage<'a>],
    now: u64,
) -> AttestRequest<'a> {
    AttestRequest {
        challenge,
        path: ChallengePath::Card,
        boot: BootMeasurements {
            boot_count: 5,
            components,
        },
        now_seconds: now,
        time_bucket: tb(4),
    }
}

#[test]
fn an_attestation_answers_the_challenge_with_every_module_and_changes_nothing() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut j = MemJournal::default();
    let code = cast_one(&w, &mut b, &mut m, &mut j, 2);
    let mut attestor = Attestor::new(w.config, setup(&w)).unwrap();
    assert_eq!(attestor.last_attestation(), None);
    let before = (
        *b.journal_head(),
        b.totals(),
        b.module_counters().to_vec(),
        j.entries.len(),
        m.iter().map(|x| x.counter).collect::<Vec<_>>(),
    );
    let nonce = [0x5a; 32];
    let link = challenge(&w, &nonce);
    let components = images();
    let key = attestation_key();
    let seed = [3u8; 32];
    let mut out = std::vec![0u8; ATTEST_WORK_LEN];
    let attested = attestor
        .attest(
            &b,
            &request(&link, &components, 1000),
            &mut ports(&mut m),
            Signer::new(&key, &seed),
            &mut out,
        )
        .unwrap();
    let attestation_bytes = attested.attestation().to_vec();
    let summary_bytes = attested.summary().to_vec();
    assert_eq!(attestor.last_attestation(), Some(1000));
    // the box, the journal and the modules' counters are untouched
    let after = (
        *b.journal_head(),
        b.totals(),
        b.module_counters().to_vec(),
        j.entries.len(),
        m.iter().map(|x| x.counter).collect::<Vec<_>>(),
    );
    assert_eq!(before, after);
    assert!(m.iter().all(|x| x.attests == 1));

    // the attestation: signed by the attestation key
    let parsed: DeviceAttestation<'_> = decode_object(
        SCHEMA_DEVICE_ATTESTATION,
        SCHEMA_VERSION_1,
        &attestation_bytes,
    )
    .unwrap();
    let vk = key.verifying_key();
    let sig = ityv_crypto::HybridSignature::decode(&mut ityv_encoding::Reader::new(
        parsed.attestation_sig(),
    ))
    .unwrap();
    let purpose = Purpose::new(b"device-attestation").unwrap();
    assert!(verify_hybrid(&vk, &purpose, parsed.body_bytes(), &sig).is_ok());
    let body = parsed.body();
    assert_eq!(body.election_id().as_bytes(), b"E-2026");
    assert_eq!(body.device_id().as_bytes(), DEVICE);
    assert_eq!(body.device_class(), DEVICE_CLASS_COMMITMENT_UNIT);
    assert_eq!(body.challenge().path, ChallengePath::Card);
    assert_eq!(body.challenge().observer_id.as_bytes(), b"obs-1");
    assert_eq!(body.challenge().nonce, &nonce);
    assert_eq!(body.time_bucket(), tb(4));
    assert_eq!(body.boot_count(), 5);
    assert_eq!(body.components().copied().collect::<Vec<_>>(), components);
    let mut h = Sha3Hasher::new();
    h.absorb(LABEL_BUNDLE);
    h.absorb(&[0]);
    h.absorb(&[0x41; 64]);
    h.absorb(&[0x42; 64]);
    assert_eq!(body.bundle_hash(), &Hash512(h.finish()));
    // one statement per module, in chamber code order, each verifying
    let codes: Vec<u8> = body
        .modules()
        .map(|s| {
            m.iter()
                .find(|x| x.id == s.module_id.as_bytes())
                .unwrap()
                .chamber_code
        })
        .collect();
    let mut sorted = codes.clone();
    sorted.sort_unstable();
    assert_eq!(codes, sorted);
    assert_eq!(codes.len(), m.len());
    let module_purpose = Purpose::new(b"module-attestation").unwrap();
    for statement in body.modules() {
        let mock = m
            .iter()
            .find(|x| x.id == statement.module_id.as_bytes())
            .unwrap();
        let (build, image_hash, boot_count) = module_boot(mock.chamber_code);
        assert_eq!(
            (statement.build, statement.image_hash, statement.boot_count),
            (build, image_hash, boot_count)
        );
        let message = ModuleStatementMessage {
            device_id: body.device_id(),
            challenge: *body.challenge(),
            module_id: statement.module_id,
            build,
            image_hash,
            boot_count,
        };
        let sig =
            ityv_crypto::HybridSignature::decode(&mut ityv_encoding::Reader::new(statement.sig))
                .unwrap();
        let mvk = module_attestation_key(mock.id).verifying_key();
        assert!(verify_hybrid(&mvk, &module_purpose, &fields(&message), &sig).is_ok());
    }
    // no value about votes: neither the tracking code nor the journal head
    let has = |needle: &[u8]| attestation_bytes.windows(needle.len()).any(|x| x == needle);
    assert!(!has(&code.0));
    assert!(!has(&b.journal_head().0));

    // the summary: the Ed25519 half over its first seven fields
    let summary: AttestationSummary<'_> =
        decode_object(SCHEMA_ATTESTATION_SUMMARY, SCHEMA_VERSION_1, &summary_bytes).unwrap();
    let parts = summary.parts();
    assert_eq!(parts.device_id.as_bytes(), DEVICE);
    assert_eq!(parts.observer_id.as_bytes(), b"obs-1");
    assert_eq!(parts.nonce, &nonce);
    assert_eq!(parts.time_bucket, tb(4));
    assert_eq!(parts.boot_count, 5);
    assert_eq!(&parts.bundle_hash, body.bundle_hash());
    assert_eq!(parts.body_hash, object_hash(parsed.body_bytes()));
    let half = RecordVerifyingKey::from_bytes(*vk.ed25519()).unwrap();
    let sig = RecordSignature::from_bytes(*summary.summary_sig());
    assert!(verify_record(&half, RecordPurpose::AttestSummary, &fields(&parts), &sig).is_ok());
    assert!(summary_bytes.len() < 500, "one QR");

    // spacing: 30 seconds by the host's clock; a token challenge later
    let link2 = challenge(&w, &[0x5b; 32]);
    for now in [1000, 1029, 999] {
        assert_eq!(
            attestor
                .attest(
                    &b,
                    &request(&link2, &components, now),
                    &mut ports(&mut m),
                    Signer::new(&key, &seed),
                    &mut out,
                )
                .unwrap_err(),
            Error::AttestTooSoon,
            "{now}"
        );
    }
    assert!(
        m.iter().all(|x| x.attests == 1),
        "refused before any module"
    );
    let token = AttestRequest {
        path: ChallengePath::Token,
        ..request(&link2, &components, 1000 + ATTEST_SPACING_SECONDS)
    };
    let attested = attestor
        .attest(
            &b,
            &token,
            &mut ports(&mut m),
            Signer::new(&key, &seed),
            &mut out,
        )
        .unwrap();
    let parsed: DeviceAttestation<'_> = decode_object(
        SCHEMA_DEVICE_ATTESTATION,
        SCHEMA_VERSION_1,
        attested.attestation(),
    )
    .unwrap();
    assert_eq!(parsed.body().challenge().path, ChallengePath::Token);
    assert_eq!(attestor.last_attestation(), Some(1030));
    assert_eq!(
        attestor
            .attest(
                &b,
                &request(&link2, &components, u64::MAX),
                &mut ports(&mut m),
                Signer::new(&key, &seed),
                &mut out,
            )
            .map(|_| ()),
        Ok(())
    );
    // after an attestation at the clock's end nothing is later
    assert_eq!(
        attestor
            .attest(
                &b,
                &request(&link2, &components, u64::MAX),
                &mut ports(&mut m),
                Signer::new(&key, &seed),
                &mut out,
            )
            .unwrap_err(),
        Error::AttestTooSoon
    );
}

#[test]
fn a_challenge_is_refused_before_any_module_is_asked() {
    let w = world(Profile::InPerson, false);
    let mut b = OpenBox::open(w.config, tb(1));
    let mut m = mocks(&w);
    let mut attestor = Attestor::new(w.config, setup(&w)).unwrap();
    let components = images();
    let key = attestation_key();
    let seed = [3u8; 32];
    let mut out = std::vec![0u8; ATTEST_WORK_LEN];
    let nonce = [1u8; 32];
    let mut try_with = |b: &OpenBox<'static>, m: &mut [common::MockModule], link: &[u8]| {
        attestor
            .attest(
                b,
                &request(link, &components, 50),
                &mut ports(m),
                Signer::new(&key, &seed),
                &mut out,
            )
            .map(|_| ())
    };
    // an observer not on the list, a signature by someone else's key, a
    // flipped signature byte, a flipped nonce
    assert_eq!(
        try_with(&b, &mut m, &challenge_by(&w, b"obs-9", b"obs-9", &nonce)),
        Err(Error::UnknownObserver)
    );
    assert_eq!(
        try_with(&b, &mut m, &challenge_by(&w, b"obs-1", b"obs-2", &nonce)),
        Err(Error::ChallengeSignature)
    );
    let good = challenge(&w, &nonce);
    for at in [good.len() - 1, good.len() - 64 - 1] {
        let mut bad = good.clone();
        bad[at] ^= 1;
        assert_eq!(
            try_with(&b, &mut m, &bad),
            Err(Error::ChallengeSignature),
            "{at}"
        );
    }
    // another election, a broken object
    let other = {
        let message = ChallengeMessage {
            election_id: ElectionId::new(b"E-2027").unwrap(),
            station_id: w.config.station_id(),
            observer_id: ObserverId::new(b"obs-1").unwrap(),
            nonce: &nonce,
        };
        let sig = sign_record(
            &observer_key(b"obs-1"),
            RecordPurpose::AttestChallenge,
            &fields(&message),
        )
        .unwrap();
        let value = AttestChallenge::new(
            ElectionId::new(b"E-2027").unwrap(),
            ObserverId::new(b"obs-1").unwrap(),
            &nonce,
            sig.as_bytes(),
        );
        let mut out = std::vec![0u8; MAX_ATTEST_CHALLENGE_LEN];
        let len =
            encode_object(SCHEMA_ATTEST_CHALLENGE, SCHEMA_VERSION_1, &value, &mut out).unwrap();
        out.truncate(len);
        out
    };
    assert_eq!(try_with(&b, &mut m, &other), Err(Error::WrongElection));
    assert!(matches!(
        try_with(&b, &mut m, &good[..good.len() - 1]),
        Err(Error::Encoding(_))
    ));
    // a visit open: from the first interpretation to the visit's end
    let mut area = work();
    let ballot = b
        .interpret(&interpretation(b"E-2026", STYLE_SMALL, 1), &mut area)
        .unwrap();
    assert!(b.has_visit_open());
    assert_eq!(try_with(&b, &mut m, &good), Err(Error::VisitOpen));
    drop(ballot);
    b.abandon_visit(&mut MemJournal::default(), tb(1)).unwrap();
    assert!(m.iter().all(|x| x.attests == 0), "no module was asked");
    assert_eq!(try_with(&b, &mut m, &good), Ok(()));
    assert!(m.iter().all(|x| x.attests == 1));
}

#[test]
fn module_statements_and_boot_measurements_must_hold() {
    let w = world(Profile::InPerson, false);
    let b = OpenBox::open(w.config, tb(1));
    let mut attestor = Attestor::new(w.config, setup(&w)).unwrap();
    let components = images();
    let key = attestation_key();
    let seed = [3u8; 32];
    let link = challenge(&w, &[2u8; 32]);
    let mut out = std::vec![0u8; ATTEST_WORK_LEN];
    let mut run =
        |m: &mut [common::MockModule], components: &[MeasuredImage<'_>], out: &mut [u8]| {
            attestor
                .attest(
                    &b,
                    &request(&link, components, 100),
                    &mut ports(m),
                    Signer::new(&key, &seed),
                    out,
                )
                .map(|_| ())
        };
    let mut m = mocks(&w);
    m[2].wrong_attest_key = true;
    assert_eq!(
        run(&mut m, &components, &mut out),
        Err(Error::ModuleStatement)
    );
    let mut m = mocks(&w);
    m[0].refuse_attest = true;
    assert_eq!(
        run(&mut m, &components, &mut out),
        Err(Error::Port(PortError::Refused))
    );
    let mut m = mocks(&w);
    let swapped = [components[1], components[0]];
    assert_eq!(
        run(&mut m, &swapped, &mut out),
        Err(Error::BootMeasurements)
    );
    assert_eq!(run(&mut m, &[], &mut out), Err(Error::BootMeasurements));
    // buffers and ports
    let mut small = std::vec![0u8; ATTEST_WORK_LEN - 1];
    assert_eq!(
        run(&mut m, &components, &mut small),
        Err(Error::BufferTooSmall)
    );
    assert_eq!(
        run(&mut m[..4], &components, &mut out),
        Err(Error::PortCount)
    );
    // none of these moved the spacing clock
    assert_eq!(run(&mut m, &components, &mut out), Ok(()));
}

#[test]
fn the_setup_is_checked_against_the_configuration() {
    let w = world(Profile::InPerson, false);
    let good = setup(&w);
    assert!(Attestor::new(w.config, good).is_ok());
    let reversed: Vec<ObserverKey<'static>> = good.observers.iter().rev().copied().collect();
    let twice = [good.observers[0], good.observers[0]];
    for observers in [&reversed[..], &twice[..]] {
        let observers: &'static [ObserverKey<'static>] =
            Box::leak(observers.to_vec().into_boxed_slice());
        assert_eq!(
            Attestor::new(w.config, AttestationSetup { observers, ..good }).unwrap_err(),
            Error::AttestationSetup
        );
    }
    let many: Vec<ObserverKey<'static>> = (0..=MAX_OBSERVERS)
        .map(|i| {
            let id = leak_bytes(std::format!("obs-{i:03}").into_bytes());
            ObserverKey::new(
                ObserverId::new(id).unwrap(),
                observer_key(b"x").verifying_key(),
            )
        })
        .collect();
    let many: &'static [ObserverKey<'static>] = Box::leak(many.into_boxed_slice());
    assert!(
        Attestor::new(
            w.config,
            AttestationSetup {
                observers: &many[..MAX_OBSERVERS],
                ..good
            }
        )
        .is_ok()
    );
    assert_eq!(
        Attestor::new(
            w.config,
            AttestationSetup {
                observers: many,
                ..good
            }
        )
        .unwrap_err(),
        Error::AttestationSetup
    );
    assert_eq!(
        Attestor::new(
            w.config,
            AttestationSetup {
                module_keys: &good.module_keys[1..],
                ..good
            }
        )
        .unwrap_err(),
        Error::AttestationSetup
    );
    assert_eq!(
        Attestor::new(
            w.config,
            AttestationSetup {
                device_id: Ident::new(&[b'd'; 65], 65).unwrap(),
                ..good
            }
        )
        .unwrap_err(),
        Error::AttestationSetup
    );
    assert!(
        Attestor::new(
            w.config,
            AttestationSetup {
                device_id: Ident::new(&[b'd'; 64], 64).unwrap(),
                ..good
            }
        )
        .is_ok()
    );
}

#[test]
fn the_challenge_link_object_round_trips() {
    let w = world(Profile::InPerson, false);
    let bytes = challenge(&w, &[9u8; 32]);
    assert_eq!(bytes.len(), 16 + (4 + 6) + (4 + 5) + 32 + 64);
    let parsed: AttestChallenge<'_> =
        decode_object(SCHEMA_ATTEST_CHALLENGE, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(parsed.election_id().as_bytes(), b"E-2026");
    assert_eq!(parsed.observer_id().as_bytes(), b"obs-1");
    assert_eq!(parsed.nonce(), &[9u8; 32]);
    assert_eq!(parsed.encoded_len(), bytes.len() - 16);
    let err = decode_object::<AttestChallenge<'_>>(
        SCHEMA_ATTEST_CHALLENGE,
        SCHEMA_VERSION_1,
        &bytes[..bytes.len() - 1],
    )
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::BodyLengthMismatch);
    let long = [b'L'; 64];
    let max = AttestChallenge::new(
        ElectionId::new(&long).unwrap(),
        ObserverId::new(&long).unwrap(),
        &[0; 32],
        &[0; 64],
    );
    assert_eq!(16 + max.encoded_len(), MAX_ATTEST_CHALLENGE_LEN);
    let _ = ModuleId::new(b"x");
}
