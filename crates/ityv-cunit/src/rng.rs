//! The unit's deterministic random generator (ADR-0017 §12).
//!
//! The unit never opens an operating-system randomness source. Every
//! ballot's randomness comes from a SHA3-512 counter-mode generator seeded
//! with the host's per-ballot device seed and every module's private
//! randomness, so that neither the device nor any single module controls
//! the proof's simulated branches or the share splitting. Batch, box-close,
//! slip and challenge signatures use a generator seeded from the device
//! seed alone (hedged ML-DSA signing needs randomness; Ed25519 is
//! deterministic).
//!
//! Output block `i` is `SHA3-512(key ‖ u64_be(i))` where `key` is the
//! 64-byte seed digest; [`DeviceRng::fork`] derives an independent key as
//! `SHA3-512(key ‖ "ityv:fork:v1" ‖ 0x00 ‖ domain ‖ u64_be(index))`.

use core::convert::Infallible;
use core::fmt;

use ityv_crypto::Sha3Hasher;
use rand_core::{TryCryptoRng, TryRng};
use zeroize::Zeroize;

/// Label of the ballot generator seed.
pub const LABEL_BALLOT_RNG: &[u8] = b"ityv:ballotrng:v1";
/// Label of the signing generator seed.
pub const LABEL_DEVICE_RNG: &[u8] = b"ityv:devicerng:v1";
/// Label of a forked stream.
pub const LABEL_FORK: &[u8] = b"ityv:fork:v1";

/// A SHA3-512 counter-mode generator. Not `Clone`; zeroized on drop.
pub struct DeviceRng {
    key: [u8; 64],
    counter: u64,
    block: [u8; 64],
    used: usize,
}

impl DeviceRng {
    /// Creates a generator whose key is `SHA3-512(label ‖ 0x00 ‖ parts…)`,
    /// absorbing every slice of `parts` in order.
    pub(crate) fn from_parts(label: &[u8], parts: &[&[u8]]) -> Self {
        let mut hasher = Sha3Hasher::new();
        hasher.absorb(label);
        hasher.absorb(&[0x00]);
        for part in parts {
            hasher.absorb(part);
        }
        Self {
            key: hasher.finish(),
            counter: 0,
            block: [0u8; 64],
            used: 64,
        }
    }

    /// Creates a generator whose key is the digest of `hasher`, which the
    /// caller has already fed with a label and the seed material.
    pub(crate) fn from_hasher(hasher: Sha3Hasher) -> Self {
        Self {
            key: hasher.finish(),
            counter: 0,
            block: [0u8; 64],
            used: 64,
        }
    }

    /// The signing generator for the device: seeded from `device_seed`
    /// only. Use one per operation that needs hedged signing.
    #[must_use]
    pub fn for_signing(device_seed: &[u8; 32]) -> Self {
        Self::from_parts(LABEL_DEVICE_RNG, &[device_seed])
    }

    /// An independent stream derived from this generator's key, `domain`
    /// and `index`. Deterministic: the same parent, domain and index always
    /// give the same stream, which is what the per-secret share splitting
    /// relies on.
    #[must_use]
    pub fn fork(&self, domain: &[u8], index: u64) -> Self {
        let mut hasher = Sha3Hasher::new();
        hasher.absorb(&self.key);
        hasher.absorb(LABEL_FORK);
        hasher.absorb(&[0x00]);
        hasher.absorb(domain);
        hasher.absorb(&index.to_be_bytes());
        Self {
            key: hasher.finish(),
            counter: 0,
            block: [0u8; 64],
            used: 64,
        }
    }

    fn refill(&mut self) {
        let mut hasher = Sha3Hasher::new();
        hasher.absorb(&self.key);
        hasher.absorb(&self.counter.to_be_bytes());
        self.block = hasher.finish();
        self.counter = self.counter.wrapping_add(1);
        self.used = 0;
    }

    fn fill(&mut self, dst: &mut [u8]) {
        let mut remaining = dst;
        while !remaining.is_empty() {
            if self.used >= self.block.len() {
                self.refill();
            }
            let available = self.block.get(self.used..).unwrap_or(&[]);
            let take = available.len().min(remaining.len());
            let (head, tail) = remaining.split_at_mut(take);
            head.copy_from_slice(available.get(..take).unwrap_or(&[]));
            self.used = self.used.saturating_add(take);
            remaining = tail;
        }
    }
}

impl TryRng for DeviceRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut bytes = [0u8; 4];
        self.fill(&mut bytes);
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut bytes = [0u8; 8];
        self.fill(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.fill(dst);
        Ok(())
    }
}

impl TryCryptoRng for DeviceRng {}

impl Drop for DeviceRng {
    fn drop(&mut self) {
        self.key.zeroize();
        self.block.zeroize();
        self.counter = 0;
        self.used = 64;
    }
}

impl fmt::Debug for DeviceRng {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeviceRng(..)")
    }
}
