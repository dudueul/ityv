//! Hybrid key encapsulation (PROTOCOL.md §9.6): ML-KEM-1024 **and** X25519,
//! combined by SHA3-512, with `ChaCha20-Poly1305` sealing.
//!
//! The derived key is
//! `SHA3-512("ityv:kem:v1" ‖ 0x00 ‖ ss_mlkem ‖ ss_x25519 ‖ ct_mlkem ‖ ct_x25519)[0..32]`,
//! so an attacker must break both ML-KEM-1024 and X25519 to recover it.
//!
//! # Single use and the fixed nonce
//!
//! [`encapsulate`] returns a [`SealKey`] and [`decapsulate`] returns an
//! [`OpenKey`]. Neither can be cloned or read, a `SealKey` can only be
//! consumed by [`seal`], and an `OpenKey` only by [`open`]. Every
//! encapsulation draws fresh randomness, so a key value exists for exactly
//! one message in each direction. That is why the AEAD nonce is the fixed
//! all-zero nonce: nonce uniqueness is provided by key uniqueness, and
//! there is no API through which the same key could seal twice.
//!
//! # Byte layouts
//!
//! | object | encoding |
//! |---|---|
//! | [`HybridKemPublicKey`] | `mlkem1024[1568] ‖ x25519[32]` (1600 bytes) |
//! | [`HybridCiphertext`] | `mlkem1024[1568] ‖ x25519[32]` (1600 bytes) |
//! | [`AeadTag`] | `tag[16]` |

use core::fmt;

use ityv_encoding::{Decode, Encode, Error as EncodingError, ErrorKind, Reader, Writer};
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::backend::{Active, AeadBackend, MlKem1024Backend, X25519Backend};
use crate::error::Error;
use crate::hash::Hasher;
use crate::verified::Verified;

/// ML-KEM-1024 encapsulation key length.
pub const MLKEM1024_EK_LEN: usize = 1568;
/// ML-KEM-1024 ciphertext length.
pub const MLKEM1024_CT_LEN: usize = 1568;
/// ML-KEM-1024 key seed length (`d ‖ z`).
pub const MLKEM1024_SEED_LEN: usize = 64;
/// X25519 key and ciphertext length.
pub const X25519_LEN: usize = 32;
/// Label of the key derivation.
pub const KEM_LABEL: &[u8] = b"ityv:kem:v1";

/// The decapsulation secrets: an ML-KEM-1024 seed and an X25519 secret.
/// Zeroized on drop.
pub struct HybridKemSecretKey {
    mlkem_seed: [u8; MLKEM1024_SEED_LEN],
    x25519: [u8; X25519_LEN],
}

impl HybridKemSecretKey {
    /// Generates both secrets from `rng`.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut mlkem_seed = [0u8; MLKEM1024_SEED_LEN];
        rng.fill_bytes(&mut mlkem_seed);
        let mut x25519 = [0u8; X25519_LEN];
        rng.fill_bytes(&mut x25519);
        Self { mlkem_seed, x25519 }
    }

    /// Rebuilds a key from stored secrets.
    #[must_use]
    pub const fn from_parts(
        mlkem_seed: [u8; MLKEM1024_SEED_LEN],
        x25519: [u8; X25519_LEN],
    ) -> Self {
        Self { mlkem_seed, x25519 }
    }

    /// The secrets, for storage in a key custody device.
    #[must_use]
    pub const fn expose_parts(&self) -> ([u8; MLKEM1024_SEED_LEN], [u8; X25519_LEN]) {
        (self.mlkem_seed, self.x25519)
    }

    /// The corresponding public key.
    #[must_use]
    pub fn public_key(&self) -> HybridKemPublicKey {
        HybridKemPublicKey {
            mlkem1024: <Active as MlKem1024Backend>::encapsulation_key_from_seed(&self.mlkem_seed),
            x25519: <Active as X25519Backend>::public_key(&self.x25519),
        }
    }
}

impl Drop for HybridKemSecretKey {
    fn drop(&mut self) {
        self.mlkem_seed.zeroize();
        self.x25519.zeroize();
    }
}

impl ZeroizeOnDrop for HybridKemSecretKey {}

impl fmt::Debug for HybridKemSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HybridKemSecretKey(..)")
    }
}

/// An ML-KEM-1024 encapsulation key (validated by the FIPS 203 modulus
/// check at construction) and an X25519 public key.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridKemPublicKey {
    mlkem1024: [u8; MLKEM1024_EK_LEN],
    x25519: [u8; X25519_LEN],
}

impl HybridKemPublicKey {
    /// Encoded length.
    pub const ENCODED_LEN: usize = MLKEM1024_EK_LEN + X25519_LEN;

    /// Builds a key from its halves.
    ///
    /// # Errors
    /// [`Error::InvalidPublicKey`] if the ML-KEM half fails the modulus check.
    pub fn from_parts(
        mlkem1024: &[u8; MLKEM1024_EK_LEN],
        x25519: [u8; X25519_LEN],
    ) -> Result<Self, Error> {
        if <Active as MlKem1024Backend>::is_valid_encapsulation_key(mlkem1024) {
            Ok(Self {
                mlkem1024: *mlkem1024,
                x25519,
            })
        } else {
            Err(Error::InvalidPublicKey)
        }
    }

    /// The ML-KEM-1024 half.
    #[must_use]
    pub const fn mlkem1024(&self) -> &[u8; MLKEM1024_EK_LEN] {
        &self.mlkem1024
    }

    /// The X25519 half.
    #[must_use]
    pub const fn x25519(&self) -> &[u8; X25519_LEN] {
        &self.x25519
    }
}

impl fmt::Debug for HybridKemPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridKemPublicKey")
            .field("x25519", &self.x25519)
            .finish_non_exhaustive()
    }
}

impl Encode for HybridKemPublicKey {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        w.write_array(&self.mlkem1024)?;
        w.write_array(&self.x25519)
    }
}

impl<'a> Decode<'a> for HybridKemPublicKey {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        let at = r.position();
        let mlkem1024 = r.read_array::<MLKEM1024_EK_LEN>()?;
        let x25519 = r.read_array::<X25519_LEN>()?;
        Self::from_parts(&mlkem1024, x25519)
            .map_err(|_| EncodingError::new(ErrorKind::ValueOutOfRange, at))
    }
}

/// An ML-KEM-1024 ciphertext and an ephemeral X25519 public key.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridCiphertext {
    mlkem1024: [u8; MLKEM1024_CT_LEN],
    x25519: [u8; X25519_LEN],
}

impl HybridCiphertext {
    /// Encoded length.
    pub const ENCODED_LEN: usize = MLKEM1024_CT_LEN + X25519_LEN;

    /// Builds a ciphertext from its halves.
    #[must_use]
    pub const fn from_parts(mlkem1024: &[u8; MLKEM1024_CT_LEN], x25519: [u8; X25519_LEN]) -> Self {
        Self {
            mlkem1024: *mlkem1024,
            x25519,
        }
    }

    /// The ML-KEM-1024 half.
    #[must_use]
    pub const fn mlkem1024(&self) -> &[u8; MLKEM1024_CT_LEN] {
        &self.mlkem1024
    }

    /// The X25519 half.
    #[must_use]
    pub const fn x25519(&self) -> &[u8; X25519_LEN] {
        &self.x25519
    }
}

impl fmt::Debug for HybridCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridCiphertext")
            .field("x25519", &self.x25519)
            .finish_non_exhaustive()
    }
}

impl Encode for HybridCiphertext {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        w.write_array(&self.mlkem1024)?;
        w.write_array(&self.x25519)
    }
}

impl<'a> Decode<'a> for HybridCiphertext {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        Ok(Self {
            mlkem1024: r.read_array::<MLKEM1024_CT_LEN>()?,
            x25519: r.read_array::<X25519_LEN>()?,
        })
    }
}

/// Derives the 32-byte key of one encapsulation.
fn derive_key(
    ss_mlkem: &[u8; 32],
    ss_x25519: &[u8; 32],
    ct_mlkem: &[u8; MLKEM1024_CT_LEN],
    ct_x25519: &[u8; X25519_LEN],
) -> Zeroizing<[u8; 32]> {
    let mut hasher = Hasher::new();
    hasher.absorb(KEM_LABEL);
    hasher.absorb(&[0x00]);
    hasher.absorb(ss_mlkem);
    hasher.absorb(ss_x25519);
    hasher.absorb(ct_mlkem);
    hasher.absorb(ct_x25519);
    let digest = Zeroizing::new(hasher.finish());
    let mut key = Zeroizing::new([0u8; 32]);
    if let Some((head, _)) = digest.split_first_chunk::<32>() {
        key.copy_from_slice(head);
    }
    key
}

/// The key of one encapsulation on the sender's side. Not `Clone`, not
/// readable; consumed by [`seal`]; zeroized on drop.
pub struct SealKey {
    bytes: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for SealKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SealKey(..)")
    }
}

/// The key of one encapsulation on the recipient's side. Not `Clone`, not
/// readable; consumed by [`open`]; zeroized on drop.
pub struct OpenKey {
    bytes: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for OpenKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OpenKey(..)")
    }
}

/// A 16-byte `ChaCha20-Poly1305` tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AeadTag {
    bytes: [u8; 16],
}

impl AeadTag {
    /// Encoded length.
    pub const ENCODED_LEN: usize = 16;

    /// Wraps tag bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    /// The tag bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.bytes
    }
}

impl Encode for AeadTag {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        w.write_array(&self.bytes)
    }
}

impl<'a> Decode<'a> for AeadTag {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        Ok(Self {
            bytes: r.read_array::<16>()?,
        })
    }
}

/// Encapsulates a fresh key to `public_key`. Every intermediate secret is
/// zeroized on every path, including the error paths.
///
/// # Errors
/// [`Error::NonContributoryKey`] if the X25519 half of `public_key` yields
/// the all-zero shared secret; [`Error::InvalidPublicKey`] or
/// [`Error::Backend`] if the ML-KEM backend rejects the key.
pub fn encapsulate<R: CryptoRng + ?Sized>(
    public_key: &HybridKemPublicKey,
    rng: &mut R,
) -> Result<(HybridCiphertext, SealKey), Error> {
    let mut ephemeral = Zeroizing::new([0u8; X25519_LEN]);
    rng.fill_bytes(ephemeral.as_mut());
    let ct_x25519 = <Active as X25519Backend>::public_key(&ephemeral);
    let ss_x25519 = <Active as X25519Backend>::shared_secret(&ephemeral, &public_key.x25519)
        .map(Zeroizing::new)
        .ok_or(Error::NonContributoryKey)?;
    let (ct_mlkem, ss_mlkem) =
        <Active as MlKem1024Backend>::encapsulate(&public_key.mlkem1024, rng)?;
    let ss_mlkem = Zeroizing::new(ss_mlkem);
    let bytes = derive_key(&ss_mlkem, &ss_x25519, &ct_mlkem, &ct_x25519);
    Ok((
        HybridCiphertext {
            mlkem1024: ct_mlkem,
            x25519: ct_x25519,
        },
        SealKey { bytes },
    ))
}

/// Recovers the key of `ciphertext`. ML-KEM decapsulation never fails
/// (implicit rejection yields a pseudo-random key); X25519 rejects a
/// non-contributory ephemeral key.
///
/// # Errors
/// [`Error::NonContributoryKey`] if the X25519 half yields the all-zero
/// shared secret.
pub fn decapsulate(
    secret_key: &HybridKemSecretKey,
    ciphertext: &HybridCiphertext,
) -> Result<OpenKey, Error> {
    let ss_x25519 =
        <Active as X25519Backend>::shared_secret(&secret_key.x25519, &ciphertext.x25519)
            .map(Zeroizing::new)
            .ok_or(Error::NonContributoryKey)?;
    let ss_mlkem = Zeroizing::new(<Active as MlKem1024Backend>::decapsulate(
        &secret_key.mlkem_seed,
        &ciphertext.mlkem1024,
    ));
    let bytes = derive_key(
        &ss_mlkem,
        &ss_x25519,
        &ciphertext.mlkem1024,
        &ciphertext.x25519,
    );
    Ok(OpenKey { bytes })
}

/// Encrypts `buffer` in place under `key` (consumed) with the fixed zero
/// nonce and returns the tag.
///
/// # Errors
/// [`Error::Backend`] if the AEAD rejects the inputs (a buffer longer than
/// the `ChaCha20` limit of 2^38 bytes).
pub fn seal(key: SealKey, associated_data: &[u8], buffer: &mut [u8]) -> Result<AeadTag, Error> {
    let bytes = <Active as AeadBackend>::seal(&key.bytes, associated_data, buffer)?;
    drop(key);
    Ok(AeadTag { bytes })
}

/// Verifies `tag` and decrypts `buffer` in place under `key` (consumed).
/// The buffer is left unchanged on failure. The token carries the
/// decrypted plaintext.
///
/// # Errors
/// [`Error::AeadInvalid`] if the tag does not verify.
pub fn open<'a>(
    key: OpenKey,
    associated_data: &[u8],
    buffer: &'a mut [u8],
    tag: &AeadTag,
) -> Result<Verified<&'a [u8]>, Error> {
    <Active as AeadBackend>::open(&key.bytes, associated_data, buffer, &tag.bytes)?;
    drop(key);
    Ok(Verified::new(buffer))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counting32() -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::try_from(i).unwrap();
        }
        out
    }

    fn hex(bytes: &[u8]) -> std::string::String {
        use core::fmt::Write as _;
        let mut s = std::string::String::new();
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// `ChaCha20-Poly1305` under the fixed zero nonce: key 0..31, aad
    /// `"aad bytes"`, plaintext `"sealed share package"`; ciphertext and tag
    /// from Python `cryptography`. Uses the private key constructors, which
    /// is why this is a unit test rather than an integration test.
    #[test]
    fn chacha20poly1305_known_answer() {
        let key = SealKey {
            bytes: Zeroizing::new(counting32()),
        };
        let mut buffer = *b"sealed share package";
        let tag = seal(key, b"aad bytes", &mut buffer).unwrap();
        assert_eq!(hex(&buffer), "6bdd235dc88286a27b002e048f332f4493d09490");
        assert_eq!(hex(tag.as_bytes()), "801386794f175fed79317066aaf347df");
        let key = OpenKey {
            bytes: Zeroizing::new(counting32()),
        };
        let plaintext = open(key, b"aad bytes", &mut buffer, &tag).unwrap();
        assert_eq!(plaintext.into_inner(), b"sealed share package");
    }

    /// X25519 with secret 0..31 and peer secret 32..63: public keys and
    /// shared secret from Python `cryptography`.
    #[test]
    fn x25519_shared_secret_known_answer() {
        let mut peer = [0u8; 32];
        for (i, b) in peer.iter_mut().enumerate() {
            *b = u8::try_from(32 + i).unwrap();
        }
        let peer_pk = <Active as X25519Backend>::public_key(&peer);
        assert_eq!(
            hex(&peer_pk),
            "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
        );
        let shared = <Active as X25519Backend>::shared_secret(&counting32(), &peer_pk).unwrap();
        assert_eq!(
            hex(&shared),
            "9663aa1da97e848a914a436d04163dfbb89178f107f1b5b77ed3854203382854"
        );
        let reverse = <Active as X25519Backend>::shared_secret(
            &peer,
            &<Active as X25519Backend>::public_key(&counting32()),
        )
        .unwrap();
        assert_eq!(shared, reverse);
        assert!(<Active as X25519Backend>::shared_secret(&counting32(), &[0u8; 32]).is_none());
    }

    /// The derived key binds both shared secrets and both ciphertexts.
    #[test]
    fn derived_key_depends_on_every_input() {
        let base = derive_key(&[1; 32], &[2; 32], &[3; MLKEM1024_CT_LEN], &[4; X25519_LEN]);
        assert_ne!(
            *base,
            *derive_key(&[9; 32], &[2; 32], &[3; MLKEM1024_CT_LEN], &[4; X25519_LEN])
        );
        assert_ne!(
            *base,
            *derive_key(&[1; 32], &[9; 32], &[3; MLKEM1024_CT_LEN], &[4; X25519_LEN])
        );
        assert_ne!(
            *base,
            *derive_key(&[1; 32], &[2; 32], &[9; MLKEM1024_CT_LEN], &[4; X25519_LEN])
        );
        assert_ne!(
            *base,
            *derive_key(&[1; 32], &[2; 32], &[3; MLKEM1024_CT_LEN], &[9; X25519_LEN])
        );
        assert_eq!(
            *base,
            *derive_key(&[1; 32], &[2; 32], &[3; MLKEM1024_CT_LEN], &[4; X25519_LEN])
        );
    }
}
