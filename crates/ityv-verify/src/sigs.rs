//! Turning registered key bytes and signature bytes into `ityv-crypto`
//! values, and verifying them into tokens.
//!
//! The verifier is the only place where a `Verified` token is made from
//! ledger data: it verifies each signature under the key the genesis
//! registers for the signer, then hands the tokens to `ityv-state`, which
//! binds each token to its signature, signer and purpose (ADR-0025
//! decision 2). A caller of this crate never supplies a token.

use alloc::vec::Vec;

use ityv_crypto::sig::{ED25519_SIG_LEN, ED25519_VK_LEN, MLDSA87_SIG_LEN, MLDSA87_VK_LEN};
use ityv_crypto::{
    HybridSignature, HybridSigned, HybridVerifyingKey, Purpose, Verified, verify_hybrid,
};
use ityv_encoding::{HYBRID_SIG_LEN, HYBRID_VK_LEN};

/// The verifying key registered as `bytes` (`mldsa87 ‖ ed25519`), or
/// `None` if the Ed25519 half is not a valid key.
pub(crate) fn verifying_key(bytes: &[u8; HYBRID_VK_LEN]) -> Option<HybridVerifyingKey> {
    let (mldsa87, ed25519) = bytes.split_first_chunk::<MLDSA87_VK_LEN>()?;
    let ed25519: [u8; ED25519_VK_LEN] = ed25519.try_into().ok()?;
    HybridVerifyingKey::from_parts(mldsa87, ed25519).ok()
}

/// The signature encoded as `bytes` (`mldsa87 ‖ ed25519`).
pub(crate) fn signature(bytes: &[u8; HYBRID_SIG_LEN]) -> Option<HybridSignature> {
    let (mldsa87, ed25519) = bytes.split_first_chunk::<MLDSA87_SIG_LEN>()?;
    let ed25519: [u8; ED25519_SIG_LEN] = ed25519.try_into().ok()?;
    Some(HybridSignature::from_parts(mldsa87, ed25519))
}

/// Keys and signatures copied out of an object so that tokens can borrow
/// them, in signature order.
pub(crate) struct Material {
    keys: Vec<HybridVerifyingKey>,
    sigs: Vec<HybridSignature>,
}

impl Material {
    /// Builds the material from (signature bytes, registered key bytes)
    /// pairs. `None` if a key or signature is malformed.
    pub(crate) fn new<'s, I>(pairs: I) -> Option<Self>
    where
        I: Iterator<Item = (&'s [u8; HYBRID_SIG_LEN], &'s [u8; HYBRID_VK_LEN])>,
    {
        let mut keys = Vec::new();
        let mut sigs = Vec::new();
        for (sig, key) in pairs {
            keys.push(verifying_key(key)?);
            sigs.push(signature(sig)?);
        }
        Some(Self { keys, sigs })
    }

    /// Verifies every signature over `object` under `purpose`, in order.
    /// `None` if one does not verify.
    pub(crate) fn verify<'t>(
        &'t self,
        purpose: &'t Purpose<'t>,
        object: &'t [u8],
    ) -> Option<Vec<Verified<HybridSigned<'t>>>> {
        self.keys
            .iter()
            .zip(&self.sigs)
            .map(|(key, sig)| verify_hybrid(key, purpose, object, sig).ok())
            .collect()
    }
}
