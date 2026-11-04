//! Fuzz target: `verify_token` on arbitrary bytes under the pin of every
//! test authority (all algorithms allowed, the certificate in the pin), so
//! inputs that start from a real token reach every stage. Seed it with the
//! tokens in `../tests/vectors` and `../tests/vectors/freetsa`.
//!
//! The property is that nothing panics; a token that verifies must report
//! the pinned certificate and the expected imprint, and an interval
//! (`earliest` to `latest`) that contains `genTime`.
#![no_main]

use ityv_tsa::{DigestAlgorithm, Imprint, PinnedTsa, verify_token};
use libfuzzer_sys::fuzz_target;
use sha2::Digest as _;
use std::sync::OnceLock;

const CERTIFICATES: [&[u8]; 6] = [
    include_bytes!("../../tests/vectors/rsa2048.crt"),
    include_bytes!("../../tests/vectors/rsa3072.crt"),
    include_bytes!("../../tests/vectors/rsa4096.crt"),
    include_bytes!("../../tests/vectors/p256.crt"),
    include_bytes!("../../tests/vectors/p384.crt"),
    include_bytes!("../../tests/vectors/freetsa/tsa.crt"),
];

/// `1.2.3.4.1` and `1.2.3.4.2`, the test policies.
const POLICIES: &[u8] = &[
    0x06, 0x04, 0x2A, 0x03, 0x04, 0x01, 0x06, 0x04, 0x2A, 0x03, 0x04, 0x02,
];

fn pins() -> &'static [Vec<u8>] {
    static PINS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    PINS.get_or_init(|| {
        CERTIFICATES
            .iter()
            .map(|certificate| {
                let mut pin = vec![1u8];
                pin.extend_from_slice(&sha2::Sha256::digest(certificate));
                pin.extend_from_slice(&[0x07, 0x3F, 0x01]);
                pin.extend_from_slice(&u16::try_from(POLICIES.len()).unwrap().to_be_bytes());
                pin.extend_from_slice(POLICIES);
                pin.extend_from_slice(&u16::try_from(certificate.len()).unwrap().to_be_bytes());
                pin.extend_from_slice(certificate);
                pin
            })
            .collect()
    })
}

fuzz_target!(|data: &[u8]| {
    let object_hash = include_bytes!("../../tests/vectors/object-hash.bin");
    for algorithm in [DigestAlgorithm::Sha512, DigestAlgorithm::Sha256] {
        let imprint = Imprint::of(algorithm, object_hash);
        for bytes in pins() {
            let pin = PinnedTsa::from_bytes(bytes).expect("fuzz pins are well formed");
            if let Ok(verified) = verify_token(data, &pin, &imprint) {
                assert_eq!(verified.certificate_sha256(), pin.certificate_sha256());
                assert_eq!(verified.imprint(), &imprint);
                // genTime ± accuracy: the latest bound always exists, and
                // the interval contains genTime.
                let gen_time = verified.gen_time();
                assert!(verified.latest().is_some_and(|latest| latest >= gen_time));
                assert!(verified.earliest().is_none_or(|earliest| earliest <= gen_time));
            }
        }
    }
});
