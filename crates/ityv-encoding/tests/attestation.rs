//! Construction, round-trip and rejection tests for the field attestation
//! schemas and the two signed field groups (ENCODING.md §8.19, §8.28–§8.30).
// Integration-test crate: outside the TCB. Test code expresses "this must
// hold" with unwrap/expect/panic/indexing and does small arithmetic on test
// sizes, so those restriction lints are relaxed for this file only. No TCB
// crate may do this (CONSTITUTION.md §1.1).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::too_many_lines
)]

mod common;

use common::{encode_to_vec, ident_len, patterned, patterned64};
use ityv_encoding::{
    AttestationChallenge, AttestationSummary, ChallengeMessage, ChallengePath, DeviceAttestation,
    DeviceAttestationBody, DeviceAttestationParts, ElectionId, Encode, ErrorKind, HEADER_LEN,
    Ident, MAX_ATTESTATION_BODY_LEN, MAX_COMPONENTS, MAX_DEVICE_CLASS, MAX_DEVICE_ID_LEN,
    MAX_VERSION_LEN, MeasuredImage, ModuleId, ModuleStatement, ModuleStatementMessage, NONCE_LEN,
    ObserverId, SCHEMA_ATTESTATION_SUMMARY, SCHEMA_DEVICE_ATTESTATION,
    SCHEMA_DEVICE_ATTESTATION_BODY, SCHEMA_VERSION_1, StationId, SummaryParts, TimeBucket, Writer,
    decode_object,
};
use std::vec::Vec;

const E: &[u8] = b"KR-2030-PRES";
const DEVICE: &[u8] = b"cu-11-0042";

fn decode_body(b: &[u8]) -> Result<DeviceAttestationBody<'_>, ityv_encoding::Error> {
    decode_object(SCHEMA_DEVICE_ATTESTATION_BODY, SCHEMA_VERSION_1, b)
}

fn ident(bytes: &'static [u8], max: usize) -> Ident<'static> {
    Ident::new(bytes, max).unwrap()
}

fn image(id: &'static [u8], build: u64, fill: u8) -> MeasuredImage<'static> {
    MeasuredImage {
        component_id: ident(id, MAX_DEVICE_ID_LEN),
        version: ident(b"1.4.2", MAX_VERSION_LEN),
        build,
        image_hash: patterned64(fill),
    }
}

fn encode_bare<T: Encode>(value: &T) -> Vec<u8> {
    let mut out = std::vec![0u8; value.encoded_len()];
    let mut w = Writer::new(&mut out);
    value.encode(&mut w).unwrap();
    assert_eq!(w.position(), out.len(), "encoded_len is exact");
    out
}

#[test]
fn challenge_paths_have_fixed_codes() {
    assert_eq!(ChallengePath::Token.code(), 1);
    assert_eq!(ChallengePath::Card.code(), 2);
    for code in [0u8, 3, 255] {
        assert_eq!(ChallengePath::from_code(code), None);
    }
    for path in [ChallengePath::Token, ChallengePath::Card] {
        assert_eq!(ChallengePath::from_code(path.code()), Some(path));
    }
    assert_eq!(NONCE_LEN, 32);
    assert_eq!(MAX_DEVICE_CLASS, 10);
    assert_eq!(MAX_COMPONENTS, 16);
    assert_eq!(MAX_ATTESTATION_BODY_LEN, 40960);
}

#[test]
fn the_signed_field_groups_have_no_header() {
    let nonce = patterned::<32>(0x10);
    let message = ChallengeMessage {
        election_id: ElectionId::new(E).unwrap(),
        station_id: StationId::new(b"st-7").unwrap(),
        observer_id: ObserverId::new(b"obs-3").unwrap(),
        nonce: &nonce,
    };
    let bytes = encode_bare(&message);
    let mut expected = Vec::new();
    for field in [E, b"st-7".as_slice(), b"obs-3".as_slice()] {
        expected.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
        expected.extend_from_slice(field);
    }
    expected.extend_from_slice(&nonce);
    assert_eq!(bytes, expected);

    let sig = patterned::<64>(0x20);
    let challenge = AttestationChallenge {
        path: ChallengePath::Card,
        observer_id: ObserverId::new(b"obs-3").unwrap(),
        nonce: &nonce,
        challenge_sig: &sig,
    };
    let statement = ModuleStatementMessage {
        device_id: ident(DEVICE, MAX_DEVICE_ID_LEN),
        challenge,
        module_id: ModuleId::new(b"mod-p1").unwrap(),
        build: 0x0102_0304_0506_0708,
        image_hash: patterned64(0x30),
        boot_count: 0x0a0b_0c0d,
    };
    let bytes = encode_bare(&statement);
    let mut expected = Vec::new();
    expected.extend_from_slice(&u32::try_from(DEVICE.len()).unwrap().to_be_bytes());
    expected.extend_from_slice(DEVICE);
    expected.push(2);
    expected.extend_from_slice(&5u32.to_be_bytes());
    expected.extend_from_slice(b"obs-3");
    expected.extend_from_slice(&nonce);
    expected.extend_from_slice(&sig);
    expected.extend_from_slice(&6u32.to_be_bytes());
    expected.extend_from_slice(b"mod-p1");
    expected.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
    expected.extend_from_slice(&patterned64(0x30).0);
    expected.extend_from_slice(&0x0a0b_0c0du32.to_be_bytes());
    assert_eq!(bytes, expected);
}

#[test]
fn device_attestation_round_trip_and_rules() {
    let nonce = patterned::<32>(0x10);
    let challenge_sig = patterned::<64>(0x20);
    let challenge = AttestationChallenge {
        path: ChallengePath::Token,
        observer_id: ObserverId::new(b"obs-3").unwrap(),
        nonce: &nonce,
        challenge_sig: &challenge_sig,
    };
    let images = [image(b"cunit", 7, 0x41), image(b"interp", 9, 0x42)];
    let sig_a = patterned::<4691>(0x51);
    let sig_b = patterned::<4691>(0x52);
    let modules = [
        ModuleStatement {
            module_id: ModuleId::new(b"mod-p1").unwrap(),
            build: 3,
            image_hash: patterned64(0x61),
            boot_count: 12,
            sig: &sig_a,
        },
        ModuleStatement {
            module_id: ModuleId::new(b"mod-a").unwrap(),
            build: 4,
            image_hash: patterned64(0x62),
            boot_count: 13,
            sig: &sig_b,
        },
    ];
    let parts = DeviceAttestationParts {
        election_id: ElectionId::new(E).unwrap(),
        device_id: ident(DEVICE, MAX_DEVICE_ID_LEN),
        device_class: 2,
        challenge,
        time_bucket: TimeBucket::new(77),
        boot_count: 5,
        components: &images,
        bundle_hash: patterned64(0x70),
        modules: &modules,
    };
    let body = DeviceAttestationBody::new(&parts).unwrap();
    let body_bytes = encode_to_vec(SCHEMA_DEVICE_ATTESTATION_BODY, SCHEMA_VERSION_1, &body);
    let decoded = decode_body(&body_bytes).unwrap();
    assert_eq!(decoded, body);
    assert_eq!(decoded.election_id().as_bytes(), E);
    assert_eq!(decoded.device_id().as_bytes(), DEVICE);
    assert_eq!(decoded.device_class(), 2);
    assert_eq!(decoded.challenge(), &challenge);
    assert_eq!(decoded.time_bucket().get(), 77);
    assert_eq!(decoded.boot_count(), 5);
    assert_eq!(decoded.components().copied().collect::<Vec<_>>(), images);
    assert_eq!(decoded.bundle_hash(), &patterned64(0x70));
    // module statements keep their order (chamber code order, not sorted)
    assert_eq!(decoded.modules().copied().collect::<Vec<_>>(), modules);

    // offsets of the rule-checked fields
    let class_at = HEADER_LEN + ident_len(E) + ident_len(DEVICE);
    let challenge_at = class_at + 1;
    let count_at = challenge_at + 1 + ident_len(b"obs-3") + 32 + 64 + 8 + 4;
    let first_image = count_at + 4;
    let image_len = ident_len(b"cunit") + ident_len(b"1.4.2") + 8 + 64;
    let second_image = first_image + image_len;
    let modules_count_at = second_image + ident_len(b"interp") + ident_len(b"1.4.2") + 8 + 64 + 64;
    let first_module = modules_count_at + 4;
    let second_module = first_module + ident_len(b"mod-p1") + 8 + 64 + 4 + 4691;
    assert_eq!(
        body_bytes.len(),
        second_module + ident_len(b"mod-a") + 8 + 64 + 4 + 4691
    );
    assert_eq!(body_bytes[class_at], 2);
    assert_eq!(body_bytes[challenge_at], 1);
    assert_eq!(&body_bytes[count_at..count_at + 4], &2u32.to_be_bytes());
    assert_eq!(
        &body_bytes[modules_count_at..modules_count_at + 4],
        &2u32.to_be_bytes()
    );

    // device class 1–10
    for (class, ok) in [(0u8, false), (1, true), (10, true), (11, false)] {
        let mut v = body_bytes.clone();
        v[class_at] = class;
        let result = decode_body(&v);
        if ok {
            assert_eq!(result.unwrap().device_class(), class);
        } else {
            let err = result.unwrap_err();
            assert_eq!(
                (err.kind(), err.offset()),
                (ErrorKind::ValueOutOfRange, class_at)
            );
        }
        let parts = DeviceAttestationParts {
            device_class: class,
            ..parts
        };
        assert_eq!(DeviceAttestationBody::new(&parts).is_some(), ok, "{class}");
    }
    // challenge path 1 or 2
    let mut v = body_bytes.clone();
    v[challenge_at] = 3;
    let err = decode_body(&v).unwrap_err();
    assert_eq!(
        (err.kind(), err.offset()),
        (ErrorKind::ValueOutOfRange, challenge_at)
    );
    // components: at least one, at most sixteen, strictly ascending
    let mut v = body_bytes.clone();
    v[count_at..count_at + 4].copy_from_slice(&0u32.to_be_bytes());
    let err = decode_body(&v).unwrap_err();
    assert_eq!(
        (err.kind(), err.offset()),
        (ErrorKind::ValueOutOfRange, count_at)
    );
    let mut v = body_bytes.clone();
    v[count_at..count_at + 4].copy_from_slice(&17u32.to_be_bytes());
    let err = decode_body(&v).unwrap_err();
    assert_eq!(
        (err.kind(), err.offset()),
        (ErrorKind::CountExceedsMax, count_at)
    );
    let swapped = [images[1], images[0]];
    let same = [images[0], images[0]];
    for bad in [&swapped[..], &same[..], &[][..]] {
        let parts = DeviceAttestationParts {
            components: bad,
            ..parts
        };
        assert!(DeviceAttestationBody::new(&parts).is_none());
    }
    let sorted = DeviceAttestationBody::new(&DeviceAttestationParts {
        components: &[image(b"zb", 1, 1), image(b"zc", 1, 2)],
        ..parts
    })
    .unwrap();
    let sorted_bytes = encode_to_vec(SCHEMA_DEVICE_ATTESTATION_BODY, SCHEMA_VERSION_1, &sorted);
    let second = first_image + ident_len(b"zb") + ident_len(b"1.4.2") + 8 + 64;
    for (last, what) in [(b'a', "below"), (b'b', "equal")] {
        let mut v = sorted_bytes.clone();
        v[second + 4 + 1] = last;
        let err = decode_body(&v).unwrap_err();
        assert_eq!(
            (err.kind(), err.offset()),
            (ErrorKind::NotSorted, second),
            "{what}"
        );
    }
    let mut sixteen = Vec::new();
    let ids: Vec<Vec<u8>> = (0..17u8).map(|i| std::vec![b'a' + i]).collect();
    for (i, id) in ids.iter().enumerate() {
        let id: &'static [u8] = Box::leak(id.clone().into_boxed_slice());
        sixteen.push(image(id, 1, u8::try_from(i).unwrap()));
    }
    assert!(
        DeviceAttestationBody::new(&DeviceAttestationParts {
            components: &sixteen[..16],
            ..parts
        })
        .is_some()
    );
    assert!(
        DeviceAttestationBody::new(&DeviceAttestationParts {
            components: &sixteen,
            ..parts
        })
        .is_none()
    );
    // modules: at most seven, no module twice
    let twice = [modules[0], modules[0]];
    assert!(
        DeviceAttestationBody::new(&DeviceAttestationParts {
            modules: &twice,
            ..parts
        })
        .is_none()
    );
    let mut v = body_bytes.clone();
    let eight: Vec<ModuleStatement<'_>> = (0..8u8)
        .map(|i| ModuleStatement {
            module_id: ModuleId::new(Box::leak(std::vec![b'm', b'0' + i].into_boxed_slice()))
                .unwrap(),
            ..modules[0]
        })
        .collect();
    assert!(
        DeviceAttestationBody::new(&DeviceAttestationParts {
            modules: &eight[..7],
            ..parts
        })
        .is_some()
    );
    assert!(
        DeviceAttestationBody::new(&DeviceAttestationParts {
            modules: &eight,
            ..parts
        })
        .is_none()
    );
    v[modules_count_at..modules_count_at + 4].copy_from_slice(&8u32.to_be_bytes());
    let err = decode_body(&v).unwrap_err();
    assert_eq!(
        (err.kind(), err.offset()),
        (ErrorKind::CountExceedsMax, modules_count_at)
    );
    let same_module = DeviceAttestationBody::new(&DeviceAttestationParts {
        modules: &[eight[0], eight[1]],
        ..parts
    })
    .unwrap();
    let mut v = encode_to_vec(
        SCHEMA_DEVICE_ATTESTATION_BODY,
        SCHEMA_VERSION_1,
        &same_module,
    );
    let one = modules_count_at + 4;
    let two = one + ident_len(b"m0") + 8 + 64 + 4 + 4691;
    v[two + 4 + 1] = b'0';
    let err = decode_body(&v).unwrap_err();
    assert_eq!((err.kind(), err.offset()), (ErrorKind::Duplicate, two));
    // no module at all is a device without chamber modules
    let bare = DeviceAttestationBody::new(&DeviceAttestationParts {
        modules: &[],
        ..parts
    })
    .unwrap();
    let bare_bytes = encode_to_vec(SCHEMA_DEVICE_ATTESTATION_BODY, SCHEMA_VERSION_1, &bare);
    assert_eq!(decode_body(&bare_bytes).unwrap().modules().count(), 0);
    // a device identifier is at most 64 bytes
    assert!(
        DeviceAttestationBody::new(&DeviceAttestationParts {
            device_id: Ident::new(&[b'd'; 65], 65).unwrap(),
            ..parts
        })
        .is_none()
    );

    // the largest body fits its field
    let long: &'static [u8] = &[b'L'; 64];
    let ver: &'static [u8] = &[b'v'; 32];
    let big_images: Vec<MeasuredImage<'_>> = (0..16u8)
        .map(|i| {
            let mut id = [b'L'; 64];
            id[63] = b'A' + i;
            MeasuredImage {
                component_id: Ident::new(Box::leak(Box::new(id)), 64).unwrap(),
                version: Ident::new(ver, 32).unwrap(),
                build: u64::MAX,
                image_hash: patterned64(i),
            }
        })
        .collect();
    let big_modules: Vec<ModuleStatement<'_>> = (0..7u8)
        .map(|i| {
            let mut id = [b'M'; 64];
            id[63] = b'A' + i;
            ModuleStatement {
                module_id: ModuleId::new(Box::leak(Box::new(id))).unwrap(),
                build: u64::MAX,
                image_hash: patterned64(i),
                boot_count: u32::MAX,
                sig: &sig_a,
            }
        })
        .collect();
    let big = DeviceAttestationBody::new(&DeviceAttestationParts {
        election_id: ElectionId::new(long).unwrap(),
        device_id: Ident::new(long, 64).unwrap(),
        device_class: 10,
        challenge: AttestationChallenge {
            observer_id: ObserverId::new(long).unwrap(),
            ..challenge
        },
        time_bucket: TimeBucket::new(u64::MAX),
        boot_count: u32::MAX,
        components: &big_images,
        bundle_hash: patterned64(1),
        modules: &big_modules,
    })
    .unwrap();
    let big_bytes = encode_to_vec(SCHEMA_DEVICE_ATTESTATION_BODY, SCHEMA_VERSION_1, &big);
    assert_eq!(big_bytes.len(), 37_063);
    assert!(big_bytes.len() <= MAX_ATTESTATION_BODY_LEN);

    // the signed wrapper
    let attestation_sig = patterned::<4691>(0x99);
    let attestation = DeviceAttestation::new(&body_bytes, &attestation_sig).unwrap();
    let bytes = encode_to_vec(SCHEMA_DEVICE_ATTESTATION, SCHEMA_VERSION_1, &attestation);
    assert_eq!(bytes.len(), HEADER_LEN + 4 + body_bytes.len() + 4691);
    let decoded: DeviceAttestation<'_> =
        decode_object(SCHEMA_DEVICE_ATTESTATION, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(decoded, attestation);
    assert_eq!(decoded.body(), &body);
    assert_eq!(decoded.body_bytes(), &body_bytes[..]);
    assert_eq!(decoded.attestation_sig(), &attestation_sig);
    let big_attestation = DeviceAttestation::new(&big_bytes, &attestation_sig).unwrap();
    assert_eq!(
        encode_to_vec(
            SCHEMA_DEVICE_ATTESTATION,
            SCHEMA_VERSION_1,
            &big_attestation
        )
        .len(),
        HEADER_LEN + 4 + 37_063 + 4691
    );
    // an inner error is reported at its offset in the wrapper
    let mut v = bytes.clone();
    v[HEADER_LEN + 4 + class_at] = 0;
    let err =
        decode_object::<DeviceAttestation<'_>>(SCHEMA_DEVICE_ATTESTATION, SCHEMA_VERSION_1, &v)
            .unwrap_err();
    assert_eq!(
        (err.kind(), err.offset()),
        (ErrorKind::ValueOutOfRange, HEADER_LEN + 4 + class_at)
    );
    let too_long = std::vec![0u8; MAX_ATTESTATION_BODY_LEN + 1];
    assert_eq!(
        DeviceAttestation::new(&too_long, &attestation_sig)
            .unwrap_err()
            .kind(),
        ErrorKind::LengthExceedsMax
    );
}

#[test]
fn attestation_summary_round_trip_and_signed_part() {
    let nonce = patterned::<32>(0x10);
    let parts = SummaryParts {
        device_id: ident(DEVICE, MAX_DEVICE_ID_LEN),
        observer_id: ObserverId::new(b"obs-3").unwrap(),
        nonce: &nonce,
        time_bucket: TimeBucket::new(77),
        boot_count: 5,
        bundle_hash: patterned64(0x70),
        body_hash: patterned64(0x71),
    };
    let sig = patterned::<64>(0x72);
    let summary = AttestationSummary::new(&parts, &sig).unwrap();
    assert_eq!(summary.parts(), parts);
    assert_eq!(summary.summary_sig(), &sig);
    let bytes = encode_to_vec(SCHEMA_ATTESTATION_SUMMARY, SCHEMA_VERSION_1, &summary);
    let signed = encode_bare(&parts);
    assert_eq!(
        signed.len(),
        ident_len(DEVICE) + ident_len(b"obs-3") + 32 + 8 + 4 + 64 + 64
    );
    // the object is the signed fields then the signature
    assert_eq!(&bytes[HEADER_LEN..HEADER_LEN + signed.len()], &signed[..]);
    assert_eq!(&bytes[HEADER_LEN + signed.len()..], &sig[..]);
    let decoded: AttestationSummary<'_> =
        decode_object(SCHEMA_ATTESTATION_SUMMARY, SCHEMA_VERSION_1, &bytes).unwrap();
    assert_eq!(decoded, summary);
    // with the longest identifiers it still fits one QR (about 450 bytes)
    let long: &'static [u8] = &[b'L'; 64];
    let big = AttestationSummary::new(
        &SummaryParts {
            device_id: Ident::new(long, 64).unwrap(),
            observer_id: ObserverId::new(long).unwrap(),
            ..parts
        },
        &sig,
    )
    .unwrap();
    assert_eq!(
        encode_to_vec(SCHEMA_ATTESTATION_SUMMARY, SCHEMA_VERSION_1, &big).len(),
        HEADER_LEN + 68 + 68 + 32 + 8 + 4 + 64 + 64 + 64
    );
    assert!(
        AttestationSummary::new(
            &SummaryParts {
                device_id: Ident::new(&[b'd'; 65], 65).unwrap(),
                ..parts
            },
            &sig
        )
        .is_none()
    );
}
