//! Fuzz target: `PinnedTsa::from_bytes` on arbitrary bytes. Nothing
//! panics, and an accepted pin encodes back to exactly its input (one
//! encoding per pin).
#![no_main]

use ityv_tsa::PinnedTsa;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(pin) = PinnedTsa::from_bytes(data) {
        let mut again = vec![0u8; pin.encoded_len()];
        assert_eq!(pin.encode(&mut again), Ok(data.len()));
        assert_eq!(again, data);
    }
});
