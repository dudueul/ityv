//! Property tests (verification ladder V1): `verify_token` is total. It
//! never panics on arbitrary bytes or on random mutations of real tokens,
//! and a mutation it accepts changes nothing it reports (everything it
//! returns is signed or pinned). These are the CI-run stand-in for the
//! fuzz target in `fuzz/`.
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
    clippy::missing_panics_doc
)]

mod common;

use common::{Pin, imprint_of, manifest, vector};
use ityv_tsa::{Imprint, PinnedTsa, VerifiedTimestamp, verify_token};
use proptest::prelude::*;
use std::sync::OnceLock;
use std::vec::Vec;

struct Case {
    token: Vec<u8>,
    pin: Vec<u8>,
    imprint: Imprint,
}

fn cases() -> &'static [Case] {
    static CASES: OnceLock<Vec<Case>> = OnceLock::new();
    CASES.get_or_init(|| {
        manifest("manifest.txt")
            .into_iter()
            .chain(manifest("freetsa/manifest.txt"))
            .map(|expected| Case {
                token: vector(&expected.token),
                // Hash-only pins: an accepted mutation cannot switch to the
                // pin's certificate.
                pin: Pin::for_token(&expected, false).bytes(),
                imprint: imprint_of(expected.imprint),
            })
            .filter(|case| {
                let pin = PinnedTsa::from_bytes(&case.pin).unwrap();
                verify_token(&case.token, &pin, &case.imprint).is_ok()
            })
            .collect()
    })
}

/// Everything a verified token reports.
fn report(verified: &VerifiedTimestamp<'_>) -> impl PartialEq + core::fmt::Debug {
    (
        verified.gen_time(),
        verified.accuracy(),
        verified.ordering(),
        verified.policy().content().to_vec(),
        verified.serial().to_vec(),
        verified.nonce().map(<[u8]>::to_vec),
        *verified.imprint(),
        *verified.certificate_sha256(),
        verified.certificate_source(),
        verified.signature_algorithm(),
    )
}

#[derive(Debug, Clone)]
enum Mutation {
    Set(usize, u8),
    Flip(usize, u8),
    Insert(usize, u8),
    Delete(usize),
    Splice(usize, Vec<u8>),
    Truncate(usize),
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        (any::<usize>(), any::<u8>()).prop_map(|(at, value)| Mutation::Set(at, value)),
        (any::<usize>(), 0u8..8).prop_map(|(at, bit)| Mutation::Flip(at, bit)),
        (any::<usize>(), any::<u8>()).prop_map(|(at, value)| Mutation::Insert(at, value)),
        any::<usize>().prop_map(Mutation::Delete),
        (any::<usize>(), prop::collection::vec(any::<u8>(), 1..16))
            .prop_map(|(at, bytes)| Mutation::Splice(at, bytes)),
        any::<usize>().prop_map(Mutation::Truncate),
    ]
}

fn apply(token: &[u8], mutation: &Mutation) -> Vec<u8> {
    let mut out = token.to_vec();
    let len = out.len();
    match mutation {
        Mutation::Set(at, value) => out[at % len] = *value,
        Mutation::Flip(at, bit) => out[at % len] ^= 1 << bit,
        Mutation::Insert(at, value) => out.insert(at % (len + 1), *value),
        Mutation::Delete(at) => {
            out.remove(at % len);
        }
        Mutation::Splice(at, bytes) => {
            let start = at % len;
            let end = (start + bytes.len()).min(len);
            out.splice(start..end, bytes.iter().copied());
        }
        Mutation::Truncate(at) => out.truncate(at % len),
    }
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_bytes_are_refused(bytes in prop::collection::vec(any::<u8>(), 0..4096), which in any::<usize>()) {
        let case = &cases()[which % cases().len()];
        let pin = PinnedTsa::from_bytes(&case.pin).unwrap();
        prop_assert!(verify_token(&bytes, &pin, &case.imprint).is_err());
    }

    #[test]
    fn arbitrary_bytes_behind_a_der_header_are_refused(
        tag in prop::sample::select(std::vec![0x30u8, 0x31, 0xA0, 0x04, 0x02]),
        body in prop::collection::vec(any::<u8>(), 0..2048),
        which in any::<usize>(),
    ) {
        let case = &cases()[which % cases().len()];
        let pin = PinnedTsa::from_bytes(&case.pin).unwrap();
        let mut bytes = std::vec![tag, 0x82];
        bytes.extend_from_slice(&u16::try_from(body.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(&body);
        prop_assert!(verify_token(&bytes, &pin, &case.imprint).is_err());
    }

    #[test]
    fn mutated_tokens_never_panic_and_never_change_the_result(
        which in any::<usize>(),
        mutations in prop::collection::vec(mutation(), 1..4),
    ) {
        let case = &cases()[which % cases().len()];
        let pin = PinnedTsa::from_bytes(&case.pin).unwrap();
        let original = verify_token(&case.token, &pin, &case.imprint).unwrap();
        let mut token = case.token.clone();
        for mutation in &mutations {
            if token.is_empty() {
                break;
            }
            token = apply(&token, mutation);
        }
        if let Ok(verified) = verify_token(&token, &pin, &case.imprint) {
            prop_assert_eq!(report(&verified), report(&original));
        }
    }

    #[test]
    fn arbitrary_pins_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(pin) = PinnedTsa::from_bytes(&bytes) {
            let mut again = std::vec![0u8; pin.encoded_len()];
            prop_assert_eq!(pin.encode(&mut again), Ok(bytes.len()));
            prop_assert_eq!(again, bytes);
        }
    }
}
