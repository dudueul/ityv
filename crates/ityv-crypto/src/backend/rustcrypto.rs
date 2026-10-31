//! The pure-Rust backend: `RustCrypto` (`sha3`, `ml-dsa`, `ml-kem`, `slh-dsa`,
//! `poly1305`, `chacha20poly1305`) and dalek (`ed25519-dalek`,
//! `x25519-dalek`).
//!
//! Constant-time behaviour and side-channel resistance rest on the claims of
//! these libraries (README, "what is not proven").

use chacha20poly1305::{AeadInOut, ChaCha20Poly1305, KeyInit as _};
use ed25519_dalek::Signer as _;
use ml_dsa::{Keypair as _, MlDsa87};
use ml_kem::array::Array;
use ml_kem::{Decapsulate as _, Encapsulate as _, KeyExport as _, MlKem1024};
use rand_core::CryptoRng;
use sha3::{Digest as _, Sha3_512};
use slh_dsa::Shake256s;
use x25519_dalek::{PublicKey, StaticSecret};

use super::{
    AeadBackend, Ed25519Backend, MlDsa87Backend, MlKem1024Backend, OneTimeMacBackend, Sha3Backend,
    SlhDsaBackend, X25519Backend,
};
use crate::error::Error;
use crate::kem::{MLKEM1024_CT_LEN, MLKEM1024_EK_LEN, MLKEM1024_SEED_LEN};
use crate::sig::{
    ED25519_SIG_LEN, ED25519_VK_LEN, MLDSA87_SIG_LEN, MLDSA87_VK_LEN, SEED_LEN, SLHDSA_SIG_LEN,
    SLHDSA_SK_LEN, SLHDSA_VK_LEN,
};

/// Marker for the pure-Rust backend.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RustCrypto;

impl Sha3Backend for RustCrypto {
    type State = Sha3_512;

    fn begin() -> Self::State {
        Sha3_512::new()
    }

    fn absorb(state: &mut Self::State, data: &[u8]) {
        state.update(data);
    }

    fn finish(state: Self::State) -> [u8; 64] {
        state.finalize().into()
    }
}

impl MlDsa87Backend for RustCrypto {
    fn verifying_key_from_seed(seed: &[u8; SEED_LEN]) -> [u8; MLDSA87_VK_LEN] {
        let signing_key = ml_dsa::SigningKey::<MlDsa87>::from_seed(&Array::from(*seed));
        signing_key.verifying_key().encode().into()
    }

    fn sign<R: CryptoRng + ?Sized>(
        seed: &[u8; SEED_LEN],
        message: &[u8],
        context: &[u8],
        rng: &mut R,
    ) -> Result<[u8; MLDSA87_SIG_LEN], Error> {
        let signing_key = ml_dsa::SigningKey::<MlDsa87>::from_seed(&Array::from(*seed));
        let signature = signing_key
            .expanded_key()
            .sign_randomized(message, context, rng)
            .map_err(|_| Error::Backend)?;
        Ok(signature.encode().into())
    }

    fn verify(
        verifying_key: &[u8; MLDSA87_VK_LEN],
        message: &[u8],
        context: &[u8],
        signature: &[u8; MLDSA87_SIG_LEN],
    ) -> bool {
        let verifying_key = ml_dsa::VerifyingKey::<MlDsa87>::decode(&Array::from(*verifying_key));
        let Some(signature) = ml_dsa::Signature::<MlDsa87>::decode(&Array::from(*signature)) else {
            return false;
        };
        verifying_key.verify_with_context(message, context, &signature)
    }
}

impl Ed25519Backend for RustCrypto {
    fn verifying_key_from_seed(seed: &[u8; SEED_LEN]) -> [u8; ED25519_VK_LEN] {
        ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes()
    }

    fn is_valid_verifying_key(verifying_key: &[u8; ED25519_VK_LEN]) -> bool {
        ed25519_dalek::VerifyingKey::from_bytes(verifying_key).is_ok_and(|key| !key.is_weak())
    }

    fn sign(seed: &[u8; SEED_LEN], message: &[u8]) -> Result<[u8; ED25519_SIG_LEN], Error> {
        let signature = ed25519_dalek::SigningKey::from_bytes(seed)
            .try_sign(message)
            .map_err(|_| Error::Backend)?;
        Ok(signature.to_bytes())
    }

    fn verify(
        verifying_key: &[u8; ED25519_VK_LEN],
        message: &[u8],
        signature: &[u8; ED25519_SIG_LEN],
    ) -> bool {
        let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(verifying_key) else {
            return false;
        };
        let signature = ed25519_dalek::Signature::from_bytes(signature);
        verifying_key.verify_strict(message, &signature).is_ok()
    }
}

impl SlhDsaBackend for RustCrypto {
    fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> ([u8; SLHDSA_SK_LEN], [u8; SLHDSA_VK_LEN]) {
        let signing_key = slh_dsa::SigningKey::<Shake256s>::new(rng);
        let verifying_key: &slh_dsa::VerifyingKey<Shake256s> = signing_key.as_ref();
        (
            signing_key.to_bytes().into(),
            verifying_key.to_bytes().into(),
        )
    }

    fn sign<R: CryptoRng + ?Sized>(
        signing_key: &[u8; SLHDSA_SK_LEN],
        message: &[u8],
        context: &[u8],
        rng: &mut R,
    ) -> Result<[u8; SLHDSA_SIG_LEN], Error> {
        let signing_key = slh_dsa::SigningKey::<Shake256s>::try_from(signing_key.as_slice())
            .map_err(|_| Error::InvalidSecretKey)?;
        let mut randomizer = [0u8; 32];
        rng.fill_bytes(&mut randomizer);
        let signature = signing_key
            .try_sign_with_context(message, context, Some(&randomizer))
            .map_err(|_| Error::Backend)?;
        Ok(signature.to_bytes().into())
    }

    fn verify(
        verifying_key: &[u8; SLHDSA_VK_LEN],
        message: &[u8],
        context: &[u8],
        signature: &[u8; SLHDSA_SIG_LEN],
    ) -> bool {
        let Ok(verifying_key) =
            slh_dsa::VerifyingKey::<Shake256s>::try_from(verifying_key.as_slice())
        else {
            return false;
        };
        let Ok(signature) = slh_dsa::Signature::<Shake256s>::try_from(signature.as_slice()) else {
            return false;
        };
        verifying_key
            .try_verify_with_context(message, context, &signature)
            .is_ok()
    }
}

impl MlKem1024Backend for RustCrypto {
    fn encapsulation_key_from_seed(seed: &[u8; MLKEM1024_SEED_LEN]) -> [u8; MLKEM1024_EK_LEN] {
        let decapsulation_key =
            ml_kem::DecapsulationKey::<MlKem1024>::from_seed(Array::from(*seed));
        decapsulation_key.encapsulation_key().to_bytes().into()
    }

    fn is_valid_encapsulation_key(encapsulation_key: &[u8; MLKEM1024_EK_LEN]) -> bool {
        ml_kem::EncapsulationKey::<MlKem1024>::new(&Array::from(*encapsulation_key)).is_ok()
    }

    fn encapsulate<R: CryptoRng + ?Sized>(
        encapsulation_key: &[u8; MLKEM1024_EK_LEN],
        rng: &mut R,
    ) -> Result<([u8; MLKEM1024_CT_LEN], [u8; 32]), Error> {
        let encapsulation_key =
            ml_kem::EncapsulationKey::<MlKem1024>::new(&Array::from(*encapsulation_key))
                .map_err(|_| Error::InvalidPublicKey)?;
        let (ciphertext, shared) = encapsulation_key.encapsulate_with_rng(rng);
        Ok((ciphertext.into(), shared.into()))
    }

    fn decapsulate(
        seed: &[u8; MLKEM1024_SEED_LEN],
        ciphertext: &[u8; MLKEM1024_CT_LEN],
    ) -> [u8; 32] {
        let decapsulation_key =
            ml_kem::DecapsulationKey::<MlKem1024>::from_seed(Array::from(*seed));
        decapsulation_key
            .decapsulate(&Array::from(*ciphertext))
            .into()
    }
}

impl X25519Backend for RustCrypto {
    fn public_key(secret: &[u8; 32]) -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
    }

    fn shared_secret(secret: &[u8; 32], peer: &[u8; 32]) -> Option<[u8; 32]> {
        let shared = StaticSecret::from(*secret).diffie_hellman(&PublicKey::from(*peer));
        if shared.was_contributory() {
            Some(shared.to_bytes())
        } else {
            None
        }
    }
}

impl AeadBackend for RustCrypto {
    fn seal(key: &[u8; 32], associated_data: &[u8], buffer: &mut [u8]) -> Result<[u8; 16], Error> {
        let cipher = ChaCha20Poly1305::new(&chacha20poly1305::Key::from(*key));
        let nonce = chacha20poly1305::Nonce::default();
        let tag = cipher
            .encrypt_inout_detached(&nonce, associated_data, buffer.into())
            .map_err(|_| Error::Backend)?;
        Ok(tag.into())
    }

    fn open(
        key: &[u8; 32],
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), Error> {
        let cipher = ChaCha20Poly1305::new(&chacha20poly1305::Key::from(*key));
        let nonce = chacha20poly1305::Nonce::default();
        cipher
            .decrypt_inout_detached(
                &nonce,
                associated_data,
                buffer.into(),
                &chacha20poly1305::Tag::from(*tag),
            )
            .map_err(|_| Error::AeadInvalid)
    }
}

impl OneTimeMacBackend for RustCrypto {
    fn tag(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
        poly1305::Poly1305::new(&poly1305::Key::from(*key))
            .compute_unpadded(message)
            .into()
    }
}
