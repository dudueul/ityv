//! Algorithm backends (ADR-0015 §4).
//!
//! This module is the only place in the crate that imports an algorithm
//! library. Every primitive is reached through a trait with associated
//! functions, and [`Active`] names the implementation in use. Replacing a
//! backend (for example with a libcrux or HACL* implementation once it meets
//! the `no_std` and API requirements) means adding an implementation here and
//! changing the alias; no caller changes. The Ristretto255 group arithmetic
//! has no trait: `curve25519-dalek` is itself buildable on fiat-crypto's
//! verified field arithmetic (`--cfg curve25519_dalek_backend="fiat"`), so the
//! verified path for the group is a build configuration, not a crate swap.
//!
//! Backend functions take and return fixed-size byte arrays. They validate
//! nothing beyond what the algorithm requires; the public modules own the
//! newtypes and their invariants.

pub(crate) mod ristretto;
pub(crate) mod rustcrypto;

use rand_core::CryptoRng;

use crate::error::Error;
use crate::kem::{MLKEM1024_CT_LEN, MLKEM1024_EK_LEN, MLKEM1024_SEED_LEN};
use crate::sig::{
    ED25519_SIG_LEN, ED25519_VK_LEN, MLDSA87_SIG_LEN, MLDSA87_VK_LEN, SEED_LEN, SLHDSA_SIG_LEN,
    SLHDSA_SK_LEN, SLHDSA_VK_LEN,
};

/// The backend in use.
pub(crate) type Active = rustcrypto::RustCrypto;

/// SHA3-512 as an incremental hasher.
pub(crate) trait Sha3Backend {
    /// Hasher state.
    type State;
    /// A fresh state.
    fn begin() -> Self::State;
    /// Absorbs `data`.
    fn absorb(state: &mut Self::State, data: &[u8]);
    /// The 64-byte digest.
    fn finish(state: Self::State) -> [u8; 64];
}

/// ML-DSA-87 (FIPS 204) with the hedged signing variant.
pub(crate) trait MlDsa87Backend {
    /// The encoded verifying key derived from a 32-byte seed.
    fn verifying_key_from_seed(seed: &[u8; SEED_LEN]) -> [u8; MLDSA87_VK_LEN];
    /// Signs `message` under `context` with fresh randomness from `rng`.
    fn sign<R: CryptoRng + ?Sized>(
        seed: &[u8; SEED_LEN],
        message: &[u8],
        context: &[u8],
        rng: &mut R,
    ) -> Result<[u8; MLDSA87_SIG_LEN], Error>;
    /// `true` if `signature` is valid for `message` under `context`.
    fn verify(
        verifying_key: &[u8; MLDSA87_VK_LEN],
        message: &[u8],
        context: &[u8],
        signature: &[u8; MLDSA87_SIG_LEN],
    ) -> bool;
}

/// Ed25519 (RFC 8032, pure, strict verification).
pub(crate) trait Ed25519Backend {
    /// The verifying key derived from a 32-byte seed.
    fn verifying_key_from_seed(seed: &[u8; SEED_LEN]) -> [u8; ED25519_VK_LEN];
    /// `true` if `verifying_key` decodes to a point that is not of small
    /// order.
    fn is_valid_verifying_key(verifying_key: &[u8; ED25519_VK_LEN]) -> bool;
    /// Deterministic signature over `message`.
    fn sign(seed: &[u8; SEED_LEN], message: &[u8]) -> Result<[u8; ED25519_SIG_LEN], Error>;
    /// Strict verification (rejects small-order components and non-canonical
    /// encodings).
    fn verify(
        verifying_key: &[u8; ED25519_VK_LEN],
        message: &[u8],
        signature: &[u8; ED25519_SIG_LEN],
    ) -> bool;
}

/// SLH-DSA-SHAKE-256s (FIPS 205) with randomized signing.
pub(crate) trait SlhDsaBackend {
    /// A fresh key pair `(signing key, verifying key)`.
    fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> ([u8; SLHDSA_SK_LEN], [u8; SLHDSA_VK_LEN]);
    /// Signs `message` under `context` with 32 bytes of randomness from `rng`.
    fn sign<R: CryptoRng + ?Sized>(
        signing_key: &[u8; SLHDSA_SK_LEN],
        message: &[u8],
        context: &[u8],
        rng: &mut R,
    ) -> Result<[u8; SLHDSA_SIG_LEN], Error>;
    /// `true` if `signature` is valid for `message` under `context`.
    fn verify(
        verifying_key: &[u8; SLHDSA_VK_LEN],
        message: &[u8],
        context: &[u8],
        signature: &[u8; SLHDSA_SIG_LEN],
    ) -> bool;
}

/// ML-KEM-1024 (FIPS 203).
pub(crate) trait MlKem1024Backend {
    /// The encapsulation key derived from the 64-byte seed `d ‖ z`.
    fn encapsulation_key_from_seed(seed: &[u8; MLKEM1024_SEED_LEN]) -> [u8; MLKEM1024_EK_LEN];
    /// `true` if `encapsulation_key` passes the FIPS 203 modulus check.
    fn is_valid_encapsulation_key(encapsulation_key: &[u8; MLKEM1024_EK_LEN]) -> bool;
    /// A fresh `(ciphertext, shared secret)` for `encapsulation_key`.
    fn encapsulate<R: CryptoRng + ?Sized>(
        encapsulation_key: &[u8; MLKEM1024_EK_LEN],
        rng: &mut R,
    ) -> Result<([u8; MLKEM1024_CT_LEN], [u8; 32]), Error>;
    /// The shared secret for `ciphertext` (implicit rejection on failure).
    fn decapsulate(
        seed: &[u8; MLKEM1024_SEED_LEN],
        ciphertext: &[u8; MLKEM1024_CT_LEN],
    ) -> [u8; 32];
}

/// X25519 (RFC 7748).
pub(crate) trait X25519Backend {
    /// The public key of `secret`.
    fn public_key(secret: &[u8; 32]) -> [u8; 32];
    /// The shared secret, or `None` if the peer key is non-contributory (the
    /// result would be the all-zero point).
    fn shared_secret(secret: &[u8; 32], peer: &[u8; 32]) -> Option<[u8; 32]>;
}

/// ChaCha20-Poly1305 (RFC 8439) with a detached tag.
pub(crate) trait AeadBackend {
    /// Encrypts `buffer` in place under `key` with the all-zero nonce and
    /// returns the tag.
    fn seal(key: &[u8; 32], associated_data: &[u8], buffer: &mut [u8]) -> Result<[u8; 16], Error>;
    /// Verifies `tag` and decrypts `buffer` in place. The buffer is untouched
    /// on failure.
    fn open(
        key: &[u8; 32],
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), Error>;
}

/// Poly1305 one-time authenticator (RFC 8439 §2.5).
pub(crate) trait OneTimeMacBackend {
    /// The 16-byte tag of `message` under the one-time `key`.
    fn tag(key: &[u8; 32], message: &[u8]) -> [u8; 16];
}
