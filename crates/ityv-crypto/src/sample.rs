//! Public audit randomness (PROTOCOL.md §12.1, §12.2; ADR-0036).
//!
//! | value | input |
//! |---|---|
//! | beacon value | `SHA3-512("ityv:beacon:v1" ‖ 0x00 ‖ u32_be(len(source)) ‖ source ‖ u64_be(round) ‖ output)` |
//! | audit seed | `SHA3-512("ityv:seed:v1" ‖ 0x00 ‖ dice_hash ‖ beacon_value ‖ checkpoint_hash)` |
//! | stream key of a ballot style | `SHA3-512("ityv:sample:v1" ‖ 0x00 ‖ seed ‖ u32_be(len(style)) ‖ style)` |
//! | stream block `i` | `SHA3-512(key ‖ u64_be(i))`, `i = 0, 1, 2, …` |
//!
//! The stream is the blocks one after another; it is read eight bytes at
//! a time as big-endian `u64` words. [`SampleStream::below`] draws a
//! uniform index below a bound by rejection: a word `x` is accepted when
//! `x ≤ accept_limit(bound)` (the largest value below the greatest multiple
//! of `bound` that fits in 64 bits) and gives `x mod bound`; a rejected
//! word is discarded and the next one read. No modulo bias is left: every
//! index has exactly `(accept_limit(bound) + 1) / bound` accepted words.
//!
//! The beacon value maps a beacon's published output of any width to 64
//! bytes, bound to the beacon (the hash of its designation document) and
//! the round. `checkpoint_hash` is the binding checkpoint's: the first valid
//! checkpoint that covers the audit commit (PROTOCOL.md §12.1).
//!
//! The stream is SHA3-512 in counter mode, the construction the commitment
//! unit's generator already uses (`ityv-cunit` `rng`), so the audit keeps
//! one hash primitive, already specified with independent vectors
//! (ADR-0036). Everything here is public: the seed and the sample are
//! recomputed by anyone (VC-045, VC-046).

use ityv_encoding::{BallotStyleId, Hash512};

use crate::hash::Hasher;

/// Label of the audit seed (PROTOCOL.md §12.1).
pub const SEED_LABEL: &[u8] = b"ityv:seed:v1";

/// Label of a ballot style's sample stream (PROTOCOL.md §12.2).
pub const SAMPLE_LABEL: &[u8] = b"ityv:sample:v1";

/// Label of the beacon value (PROTOCOL.md §12.1).
pub const BEACON_LABEL: &[u8] = b"ityv:beacon:v1";

/// Words [`SampleStream::below`] reads for one draw before it gives up.
/// For a bound of at most `2^26` one word is rejected with probability
/// below `2^-38`, so 64 rejections in a row do not happen; the limit keeps
/// the loop bounded.
pub const MAX_TRIES: u32 = 64;

/// `SHA3-512("ityv:beacon:v1" ‖ 0x00 ‖ u32_be(len(source)) ‖ source ‖
/// u64_be(round) ‖ output)`: the 64-byte beacon value of round `round` of
/// the beacon designated by the document hash `source`, whose published
/// output is `output` (any width; PROTOCOL.md §12.1).
#[must_use]
pub fn beacon_value(source: &Hash512, round: u64, output: &[u8]) -> Hash512 {
    let mut hasher = Hasher::new();
    hasher.absorb(BEACON_LABEL);
    hasher.absorb(&[0x00]);
    // A document hash is 64 bytes; the length keeps the encoding the one
    // of a variable source.
    hasher.absorb(&64u32.to_be_bytes());
    hasher.absorb(source.as_bytes());
    hasher.absorb(&round.to_be_bytes());
    hasher.absorb(output);
    Hash512(hasher.finish())
}

/// `SHA3-512("ityv:seed:v1" ‖ 0x00 ‖ dice_hash ‖ beacon_value ‖
/// checkpoint_hash)`: the audit seed (PROTOCOL.md §12.1, VC-045), over the
/// binding checkpoint's body hash.
#[must_use]
pub fn audit_seed(
    dice_hash: &Hash512,
    beacon_value: &Hash512,
    checkpoint_hash: &Hash512,
) -> Hash512 {
    let mut hasher = Hasher::new();
    hasher.absorb(SEED_LABEL);
    hasher.absorb(&[0x00]);
    hasher.absorb(dice_hash.as_bytes());
    hasher.absorb(beacon_value.as_bytes());
    hasher.absorb(checkpoint_hash.as_bytes());
    Hash512(hasher.finish())
}

/// The largest word [`SampleStream::below`] accepts for `bound`:
/// `2^64 − 1 − (2^64 mod bound)`, so that the accepted words
/// `0..=limit` are a whole number of runs of `bound`. `None` for a bound of
/// 0.
#[must_use]
pub const fn accept_limit(bound: u64) -> Option<u64> {
    // 2^64 mod bound, computed without leaving 64 bits:
    // (2^64 − 1) mod bound, plus one, mod bound.
    let Some(rest) = u64::MAX.checked_rem(bound) else {
        return None;
    };
    let Some(next) = rest.checked_add(1) else {
        return None;
    };
    let Some(rem) = next.checked_rem(bound) else {
        return None;
    };
    u64::MAX.checked_sub(rem)
}

/// The sample stream of one ballot style under one seed (PROTOCOL.md
/// §12.2). Public; nothing in it is secret.
#[derive(Debug, Clone)]
pub struct SampleStream {
    key: [u8; 64],
    counter: u64,
    block: [u8; 64],
    used: usize,
}

impl SampleStream {
    /// The stream of ballot style `style` under `seed`.
    #[must_use]
    pub fn new(seed: &Hash512, style: BallotStyleId<'_>) -> Self {
        let bytes = style.as_bytes();
        // An identifier is at most 64 bytes, so its length fits in 32 bits.
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        let mut hasher = Hasher::new();
        hasher.absorb(SAMPLE_LABEL);
        hasher.absorb(&[0x00]);
        hasher.absorb(seed.as_bytes());
        hasher.absorb(&len.to_be_bytes());
        hasher.absorb(bytes);
        Self {
            key: hasher.finish(),
            counter: 0,
            block: [0; 64],
            used: 64,
        }
    }

    /// The next eight bytes of the stream, big-endian.
    pub fn next_word(&mut self) -> u64 {
        let mut word = [0u8; 8];
        for byte in &mut word {
            if self.used >= self.block.len() {
                let mut hasher = Hasher::new();
                hasher.absorb(&self.key);
                hasher.absorb(&self.counter.to_be_bytes());
                self.block = hasher.finish();
                // 2^64 blocks are never read; wrapping keeps the function
                // total.
                self.counter = self.counter.wrapping_add(1);
                self.used = 0;
            }
            *byte = self.block.get(self.used).copied().unwrap_or(0);
            self.used = self.used.saturating_add(1);
        }
        u64::from_be_bytes(word)
    }

    /// A uniform index in `0..bound` by rejection sampling ([`accept_limit`]).
    /// `None` for a bound of 0, or if [`MAX_TRIES`] words in a row are
    /// rejected.
    pub fn below(&mut self, bound: u64) -> Option<u64> {
        let limit = accept_limit(bound)?;
        for _ in 0..MAX_TRIES {
            let word = self.next_word();
            if word <= limit {
                return word.checked_rem(bound);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use ityv_encoding::{BallotStyleId, Hash512};

    use super::{MAX_TRIES, SampleStream, accept_limit, audit_seed, beacon_value};

    fn hex(text: &str) -> std::vec::Vec<u8> {
        text.as_bytes()
            .chunks(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn the_limit_leaves_whole_runs() {
        assert_eq!(accept_limit(0), None);
        assert_eq!(accept_limit(1), Some(u64::MAX));
        assert_eq!(accept_limit(2), Some(u64::MAX));
        assert_eq!(accept_limit(1 << 40), Some(u64::MAX));
        // 2^64 mod 3 = 1.
        assert_eq!(accept_limit(3), Some(u64::MAX - 1));
        // 2^64 mod 10 = 6.
        assert_eq!(accept_limit(10), Some(u64::MAX - 6));
        assert_eq!(accept_limit(u64::MAX), Some(u64::MAX - 1));
        for bound in [3u64, 7, 10, 1000, (1 << 26) + 1, u64::MAX] {
            let limit = accept_limit(bound).unwrap();
            assert_eq!((u128::from(limit) + 1) % u128::from(bound), 0, "{bound}");
            // The next multiple would not fit.
            assert!(u128::from(limit) + 1 + u128::from(bound) > u128::from(u64::MAX) + 1);
        }
    }

    #[test]
    fn a_bound_of_zero_draws_nothing_and_rejection_is_bounded() {
        let mut s = SampleStream::new(&Hash512([1; 64]), BallotStyleId::new(b"S").unwrap());
        assert_eq!(s.below(0), None);
        assert_eq!(MAX_TRIES, 64);
        // A bound of one is always 0 and consumes one word.
        let mut t = s.clone();
        assert_eq!(s.below(1), Some(0));
        t.next_word();
        assert_eq!(s.next_word(), t.next_word());
    }

    /// Known answers computed independently (Python `hashlib.sha3_512`,
    /// ADR-0036): the seed, the stream's first words and draws.
    #[test]
    fn known_answers() {
        let seed = audit_seed(
            &Hash512([0x11; 64]),
            &Hash512([0x22; 64]),
            &Hash512([0x33; 64]),
        );
        assert_eq!(seed.as_bytes().as_slice(), hex(SEED_KAT).as_slice());
        let style = BallotStyleId::new(b"STYLE-1").unwrap();
        let mut s = SampleStream::new(&seed, style);
        let words: std::vec::Vec<u64> = (0..10).map(|_| s.next_word()).collect();
        assert_eq!(words, WORDS_KAT);
        let mut s = SampleStream::new(&seed, style);
        let draws: std::vec::Vec<u64> = (0..6).map(|_| s.below(10).unwrap()).collect();
        assert_eq!(draws, DRAWS_KAT);
        // Another style is another stream.
        let mut other = SampleStream::new(&seed, BallotStyleId::new(b"STYLE-2").unwrap());
        assert_ne!(other.next_word(), WORDS_KAT[0]);
        // Another seed is another stream.
        let mut other = SampleStream::new(&Hash512([0; 64]), style);
        assert_ne!(other.next_word(), WORDS_KAT[0]);
    }

    /// The beacon value of an independently computed example (Python
    /// `hashlib.sha3_512`): source `0xBE` × 64, round 777, a 32-byte output
    /// `0x00..0x1F`; and an empty output.
    #[test]
    fn the_beacon_value_matches_an_independent_answer() {
        let output: std::vec::Vec<u8> = (0u8..32).collect();
        let value = beacon_value(&Hash512([0xBE; 64]), 777, &output);
        assert_eq!(value.as_bytes().as_slice(), hex(BEACON_KAT).as_slice());
        let empty = beacon_value(&Hash512([0xBE; 64]), 777, &[]);
        assert_eq!(
            empty.as_bytes().as_slice(),
            hex(BEACON_EMPTY_KAT).as_slice()
        );
        // Another round or source is another value.
        assert_ne!(beacon_value(&Hash512([0xBE; 64]), 778, &output), value);
        assert_ne!(beacon_value(&Hash512([0xBF; 64]), 777, &output), value);
    }

    const BEACON_KAT: &str = "b0ba24c1f01693439d08ccc4754960ac3b94d885dff83890c2f0a0ee82b65d13e581e270a3d195649db74c6f77ed8516ca7005b389ddadcc552fc5ed8f184250";
    const BEACON_EMPTY_KAT: &str = "7fc044bdbab6167dbdfff8deb2c99c57455df780b2a83da3843f4d2a60e8045a47aab3c0e1ebc57c2c936234e14eebd587a6049cdf89713eb2c5f1be7fa94802";
    const SEED_KAT: &str = "4111580a6c1b945c4172738db4978845806f6924ec6125e78bba7b56a4a7aee1cbe005cf05b3379076f4cc99710ebb9840efb4d6e02375a8ae3aeef8fe318f44";
    const WORDS_KAT: [u64; 10] = [
        16_702_368_632_261_191_237,
        16_467_435_210_481_470_978,
        8_447_201_599_947_092_876,
        16_672_897_258_086_838_221,
        17_227_406_645_379_752_622,
        499_643_684_959_206_155,
        17_520_676_799_241_996_033,
        6_737_900_851_487_417_601,
        1_081_684_601_112_788_008,
        2_413_020_072_807_698_423,
    ];
    const DRAWS_KAT: [u64; 6] = [7, 8, 6, 1, 2, 5];
}
