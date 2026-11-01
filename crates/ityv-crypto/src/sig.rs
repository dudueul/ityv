//! Signatures (PROTOCOL.md §3.1, §7.2.1; ADR-0006, ADR-0014, ADR-0015).
//!
//! Three signature kinds, each a distinct type so they cannot be confused:
//!
//! * **Hybrid** — ML-DSA-87 **and** Ed25519 over the same digest. Verification
//!   succeeds only if both verify (VC-002). Used for every object signature
//!   except the two below.
//! * **Record** — Ed25519 only, restricted by type to the purposes
//!   `cast-record` and `module-record` (per-record signatures, ADR-0014).
//! * **Archive** — SLH-DSA-SHAKE-256s, restricted to `checkpoint-archive`
//!   (long-term checkpoint co-signature).
//!
//! Every algorithm signs the 64-byte [`signing_digest`] of the purpose and the
//! object (hash-then-sign, ADR-0015 §3). ML-DSA-87 and SLH-DSA additionally
//! receive the purpose as their FIPS 204/205 context string. Secret keys are
//! stored as seeds, zeroized on drop, and never printed.
//!
//! Every verification returns a token that borrows all of its inputs
//! ([`HybridSigned`], [`RecordSigned`], [`ArchiveSigned`]): the token proves
//! that *this* key verified *this* signature over *this* object under
//! *this* purpose, and only this crate can create one.
//!
//! # Byte layouts
//!
//! All fields are fixed width and concatenated without prefixes:
//!
//! | object | encoding |
//! |---|---|
//! | [`HybridVerifyingKey`] | `mldsa87[2592] ‖ ed25519[32]` (2624 bytes) |
//! | [`HybridSignature`] | `mldsa87[4627] ‖ ed25519[64]` (4691 bytes) |
//! | [`RecordVerifyingKey`] | `ed25519[32]` |
//! | [`RecordSignature`] | `ed25519[64]` |
//! | [`ArchiveVerifyingKey`] | `slhdsa[64]` (`pk_seed[32] ‖ pk_root[32]`) |
//! | [`ArchiveSignature`] | `slhdsa[29792]` (FIPS 205 signature encoding) |
//!
//! The ML-DSA-87 halves use the FIPS 204 `pkEncode`/`sigEncode` byte
//! strings; the Ed25519 halves use the RFC 8032 encodings.

use core::fmt;

use ityv_encoding::{Decode, Encode, Error as EncodingError, ErrorKind, Reader, Writer};
use rand_core::CryptoRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::backend::{Active, Ed25519Backend, MlDsa87Backend, SlhDsaBackend};
use crate::error::Error;
use crate::hash::{Purpose, signing_digest};
use crate::verified::Verified;

/// Length of every seed-form secret key.
pub const SEED_LEN: usize = 32;
/// Encoded ML-DSA-87 verifying key length.
pub const MLDSA87_VK_LEN: usize = 2592;
/// Encoded ML-DSA-87 signature length.
pub const MLDSA87_SIG_LEN: usize = 4627;
/// Ed25519 verifying key length.
pub const ED25519_VK_LEN: usize = 32;
/// Ed25519 signature length.
pub const ED25519_SIG_LEN: usize = 64;
/// SLH-DSA-SHAKE-256s verifying key length.
pub const SLHDSA_VK_LEN: usize = 64;
/// SLH-DSA-SHAKE-256s signing key length.
pub const SLHDSA_SK_LEN: usize = 128;
/// SLH-DSA-SHAKE-256s signature length.
pub const SLHDSA_SIG_LEN: usize = 29792;

/// Purpose of the device signature on a cast record.
pub const PURPOSE_CAST_RECORD: Purpose<'static> = Purpose::from_literal(b"cast-record");
/// Purpose of a module signature on `(body_hash, module_id, counter)`.
pub const PURPOSE_MODULE_RECORD: Purpose<'static> = Purpose::from_literal(b"module-record");
/// Purpose of an observer's signature on an attestation challenge.
pub const PURPOSE_ATTEST_CHALLENGE: Purpose<'static> = Purpose::from_literal(b"attest-challenge");
/// Purpose of the Ed25519 signature on an attestation summary QR.
pub const PURPOSE_ATTEST_SUMMARY: Purpose<'static> = Purpose::from_literal(b"attest-summary");
/// Purpose of the SLH-DSA co-signature on an archival checkpoint.
pub const PURPOSE_CHECKPOINT_ARCHIVE: Purpose<'static> =
    Purpose::from_literal(b"checkpoint-archive");
/// Purpose of a witness's hybrid signature on a checkpoint body
/// (PROTOCOL.md §5.4, Appendix B).
pub const PURPOSE_CHECKPOINT: Purpose<'static> = Purpose::from_literal(b"checkpoint");

fn fill<R: CryptoRng + ?Sized>(rng: &mut R) -> [u8; SEED_LEN] {
    let mut seed = [0u8; SEED_LEN];
    rng.fill_bytes(&mut seed);
    seed
}

// ---------------------------------------------------------------------------
// Hybrid
// ---------------------------------------------------------------------------

/// Seeds of an ML-DSA-87 key and an Ed25519 key. Zeroized on drop.
pub struct HybridSigningKey {
    mldsa87_seed: [u8; SEED_LEN],
    ed25519_seed: [u8; SEED_LEN],
}

impl HybridSigningKey {
    /// Generates both seeds from `rng`.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self {
            mldsa87_seed: fill(rng),
            ed25519_seed: fill(rng),
        }
    }

    /// Rebuilds a key from stored seeds.
    #[must_use]
    pub const fn from_seeds(mldsa87_seed: [u8; SEED_LEN], ed25519_seed: [u8; SEED_LEN]) -> Self {
        Self {
            mldsa87_seed,
            ed25519_seed,
        }
    }

    /// The seeds, for storage in a key custody device. The name is a reminder
    /// that the result is secret.
    #[must_use]
    pub const fn expose_seeds(&self) -> ([u8; SEED_LEN], [u8; SEED_LEN]) {
        (self.mldsa87_seed, self.ed25519_seed)
    }

    /// The corresponding verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> HybridVerifyingKey {
        HybridVerifyingKey {
            mldsa87: <Active as MlDsa87Backend>::verifying_key_from_seed(&self.mldsa87_seed),
            ed25519: <Active as Ed25519Backend>::verifying_key_from_seed(&self.ed25519_seed),
        }
    }
}

impl Drop for HybridSigningKey {
    fn drop(&mut self) {
        self.mldsa87_seed.zeroize();
        self.ed25519_seed.zeroize();
    }
}

impl ZeroizeOnDrop for HybridSigningKey {}

impl fmt::Debug for HybridSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HybridSigningKey(..)")
    }
}

/// An ML-DSA-87 verifying key and an Ed25519 verifying key. The Ed25519 half
/// is validated at construction (decodes to a point that is not of small
/// order); ML-DSA-87 keys have no invalid encodings.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridVerifyingKey {
    mldsa87: [u8; MLDSA87_VK_LEN],
    ed25519: [u8; ED25519_VK_LEN],
}

impl HybridVerifyingKey {
    /// Encoded length: `MLDSA87_VK_LEN + ED25519_VK_LEN`.
    pub const ENCODED_LEN: usize = MLDSA87_VK_LEN + ED25519_VK_LEN;

    /// Builds a key from its two halves.
    ///
    /// # Errors
    /// [`Error::InvalidPublicKey`] if the Ed25519 half is not a valid key.
    pub fn from_parts(
        mldsa87: &[u8; MLDSA87_VK_LEN],
        ed25519: [u8; ED25519_VK_LEN],
    ) -> Result<Self, Error> {
        if <Active as Ed25519Backend>::is_valid_verifying_key(&ed25519) {
            Ok(Self {
                mldsa87: *mldsa87,
                ed25519,
            })
        } else {
            Err(Error::InvalidPublicKey)
        }
    }

    /// The ML-DSA-87 half.
    #[must_use]
    pub const fn mldsa87(&self) -> &[u8; MLDSA87_VK_LEN] {
        &self.mldsa87
    }

    /// The Ed25519 half.
    #[must_use]
    pub const fn ed25519(&self) -> &[u8; ED25519_VK_LEN] {
        &self.ed25519
    }
}

impl fmt::Debug for HybridVerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridVerifyingKey")
            .field("ed25519", &self.ed25519)
            .finish_non_exhaustive()
    }
}

impl Encode for HybridVerifyingKey {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        w.write_array(&self.mldsa87)?;
        w.write_array(&self.ed25519)
    }
}

impl<'a> Decode<'a> for HybridVerifyingKey {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        let mldsa87 = r.read_array::<MLDSA87_VK_LEN>()?;
        let at = r.position();
        let ed25519 = r.read_array::<ED25519_VK_LEN>()?;
        Self::from_parts(&mldsa87, ed25519)
            .map_err(|_| EncodingError::new(ErrorKind::ValueOutOfRange, at))
    }
}

/// An ML-DSA-87 signature and an Ed25519 signature over the same digest.
/// Validity is decided by [`verify_hybrid`], never by construction.
#[derive(Clone, PartialEq, Eq)]
pub struct HybridSignature {
    mldsa87: [u8; MLDSA87_SIG_LEN],
    ed25519: [u8; ED25519_SIG_LEN],
}

impl HybridSignature {
    /// Encoded length: `MLDSA87_SIG_LEN + ED25519_SIG_LEN`.
    pub const ENCODED_LEN: usize = MLDSA87_SIG_LEN + ED25519_SIG_LEN;

    /// Builds a signature from its two halves.
    #[must_use]
    pub const fn from_parts(
        mldsa87: &[u8; MLDSA87_SIG_LEN],
        ed25519: [u8; ED25519_SIG_LEN],
    ) -> Self {
        Self {
            mldsa87: *mldsa87,
            ed25519,
        }
    }

    /// The ML-DSA-87 half.
    #[must_use]
    pub const fn mldsa87(&self) -> &[u8; MLDSA87_SIG_LEN] {
        &self.mldsa87
    }

    /// The Ed25519 half.
    #[must_use]
    pub const fn ed25519(&self) -> &[u8; ED25519_SIG_LEN] {
        &self.ed25519
    }
}

impl fmt::Debug for HybridSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HybridSignature")
            .field("ed25519", &self.ed25519)
            .finish_non_exhaustive()
    }
}

impl Encode for HybridSignature {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        w.write_array(&self.mldsa87)?;
        w.write_array(&self.ed25519)
    }
}

impl<'a> Decode<'a> for HybridSignature {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        let mldsa87 = r.read_array::<MLDSA87_SIG_LEN>()?;
        let ed25519 = r.read_array::<ED25519_SIG_LEN>()?;
        Ok(Self { mldsa87, ed25519 })
    }
}

/// What [`verify_hybrid`] verified: the key, purpose, object and signature,
/// borrowed for as long as the token lives.
#[derive(Debug, Clone, Copy)]
pub struct HybridSigned<'a> {
    key: &'a HybridVerifyingKey,
    purpose: &'a Purpose<'a>,
    object: &'a [u8],
    signature: &'a HybridSignature,
}

impl<'a> HybridSigned<'a> {
    /// The verifying key.
    #[must_use]
    pub const fn key(&self) -> &'a HybridVerifyingKey {
        self.key
    }

    /// The purpose.
    #[must_use]
    pub const fn purpose(&self) -> &'a Purpose<'a> {
        self.purpose
    }

    /// The signed object bytes.
    #[must_use]
    pub const fn object(&self) -> &'a [u8] {
        self.object
    }

    /// The signature.
    #[must_use]
    pub const fn signature(&self) -> &'a HybridSignature {
        self.signature
    }
}

/// Signs the digest of `(purpose, obj)` with both algorithms. ML-DSA-87 uses
/// hedged signing with randomness from `rng` and `purpose` as its context;
/// Ed25519 is deterministic.
///
/// # Errors
/// [`Error::Backend`] if a backend rejects the inputs.
pub fn sign_hybrid<R: CryptoRng + ?Sized>(
    key: &HybridSigningKey,
    purpose: &Purpose<'_>,
    obj: &[u8],
    rng: &mut R,
) -> Result<HybridSignature, Error> {
    let digest = signing_digest(purpose, obj);
    let mldsa87 = <Active as MlDsa87Backend>::sign(
        &key.mldsa87_seed,
        digest.as_bytes(),
        purpose.as_bytes(),
        rng,
    )?;
    let ed25519 = <Active as Ed25519Backend>::sign(&key.ed25519_seed, digest.as_bytes())?;
    Ok(HybridSignature { mldsa87, ed25519 })
}

/// Verifies both halves of `signature` over the digest of `(purpose, obj)`.
/// Both are always evaluated; the result is valid only if both are.
///
/// # Errors
/// [`Error::SignatureInvalid`] if either half fails.
pub fn verify_hybrid<'a>(
    verifying_key: &'a HybridVerifyingKey,
    purpose: &'a Purpose<'a>,
    obj: &'a [u8],
    signature: &'a HybridSignature,
) -> Result<Verified<HybridSigned<'a>>, Error> {
    let digest = signing_digest(purpose, obj);
    let mldsa87_ok = <Active as MlDsa87Backend>::verify(
        &verifying_key.mldsa87,
        digest.as_bytes(),
        purpose.as_bytes(),
        &signature.mldsa87,
    );
    let ed25519_ok = <Active as Ed25519Backend>::verify(
        &verifying_key.ed25519,
        digest.as_bytes(),
        &signature.ed25519,
    );
    if mldsa87_ok && ed25519_ok {
        Ok(Verified::new(HybridSigned {
            key: verifying_key,
            purpose,
            object: obj,
            signature,
        }))
    } else {
        Err(Error::SignatureInvalid)
    }
}

// ---------------------------------------------------------------------------
// Record (Ed25519 only)
// ---------------------------------------------------------------------------

/// The purposes a classical-only (Ed25519) signature may carry
/// (PROTOCOL.md Appendix B): the record signatures, whose quantum-safe
/// cover is the batch attestation, and the attestation QR signatures,
/// whose hybrid counterpart is the ledger event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordPurpose {
    /// Device signature on a cast record body hash.
    CastRecord,
    /// Module signature on `(body_hash, module_id, counter)`.
    ModuleRecord,
    /// An observer's check key on an attestation challenge.
    AttestChallenge,
    /// The attestation key's Ed25519 half on an attestation summary.
    AttestSummary,
}

impl RecordPurpose {
    /// The purpose string.
    #[must_use]
    pub const fn purpose(self) -> Purpose<'static> {
        match self {
            Self::CastRecord => PURPOSE_CAST_RECORD,
            Self::ModuleRecord => PURPOSE_MODULE_RECORD,
            Self::AttestChallenge => PURPOSE_ATTEST_CHALLENGE,
            Self::AttestSummary => PURPOSE_ATTEST_SUMMARY,
        }
    }
}

/// An Ed25519 seed for record signatures. Zeroized on drop.
pub struct RecordSigningKey {
    seed: [u8; SEED_LEN],
}

impl RecordSigningKey {
    /// Generates a seed from `rng`.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        Self { seed: fill(rng) }
    }

    /// Rebuilds a key from a stored seed.
    #[must_use]
    pub const fn from_seed(seed: [u8; SEED_LEN]) -> Self {
        Self { seed }
    }

    /// The seed, for storage in a key custody device.
    #[must_use]
    pub const fn expose_seed(&self) -> [u8; SEED_LEN] {
        self.seed
    }

    /// The corresponding verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> RecordVerifyingKey {
        RecordVerifyingKey {
            bytes: <Active as Ed25519Backend>::verifying_key_from_seed(&self.seed),
        }
    }
}

impl Drop for RecordSigningKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

impl ZeroizeOnDrop for RecordSigningKey {}

impl fmt::Debug for RecordSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordSigningKey(..)")
    }
}

/// An Ed25519 verifying key for record signatures, validated at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordVerifyingKey {
    bytes: [u8; ED25519_VK_LEN],
}

impl RecordVerifyingKey {
    /// Encoded length.
    pub const ENCODED_LEN: usize = ED25519_VK_LEN;

    /// Parses a key.
    ///
    /// # Errors
    /// [`Error::InvalidPublicKey`] if `bytes` is not a valid, non-weak key.
    pub fn from_bytes(bytes: [u8; ED25519_VK_LEN]) -> Result<Self, Error> {
        if <Active as Ed25519Backend>::is_valid_verifying_key(&bytes) {
            Ok(Self { bytes })
        } else {
            Err(Error::InvalidPublicKey)
        }
    }

    /// The key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ED25519_VK_LEN] {
        &self.bytes
    }
}

impl Encode for RecordVerifyingKey {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        w.write_array(&self.bytes)
    }
}

impl<'a> Decode<'a> for RecordVerifyingKey {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        let at = r.position();
        let bytes = r.read_array::<ED25519_VK_LEN>()?;
        Self::from_bytes(bytes).map_err(|_| EncodingError::new(ErrorKind::ValueOutOfRange, at))
    }
}

/// An Ed25519 record signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecordSignature {
    bytes: [u8; ED25519_SIG_LEN],
}

impl RecordSignature {
    /// Encoded length.
    pub const ENCODED_LEN: usize = ED25519_SIG_LEN;

    /// Wraps signature bytes. Validity is decided by [`verify_record`].
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ED25519_SIG_LEN]) -> Self {
        Self { bytes }
    }

    /// The signature bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ED25519_SIG_LEN] {
        &self.bytes
    }
}

impl Encode for RecordSignature {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        w.write_array(&self.bytes)
    }
}

impl<'a> Decode<'a> for RecordSignature {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        Ok(Self {
            bytes: r.read_array::<ED25519_SIG_LEN>()?,
        })
    }
}

/// What [`verify_record`] verified.
#[derive(Debug, Clone, Copy)]
pub struct RecordSigned<'a> {
    key: &'a RecordVerifyingKey,
    purpose: RecordPurpose,
    object: &'a [u8],
    signature: &'a RecordSignature,
}

impl<'a> RecordSigned<'a> {
    /// The verifying key.
    #[must_use]
    pub const fn key(&self) -> &'a RecordVerifyingKey {
        self.key
    }

    /// The purpose.
    #[must_use]
    pub const fn purpose(&self) -> RecordPurpose {
        self.purpose
    }

    /// The signed object bytes.
    #[must_use]
    pub const fn object(&self) -> &'a [u8] {
        self.object
    }

    /// The signature.
    #[must_use]
    pub const fn signature(&self) -> &'a RecordSignature {
        self.signature
    }
}

/// Deterministically signs the digest of `(purpose, obj)`.
///
/// # Errors
/// [`Error::Backend`] if the backend rejects the inputs.
pub fn sign_record(
    key: &RecordSigningKey,
    purpose: RecordPurpose,
    obj: &[u8],
) -> Result<RecordSignature, Error> {
    let digest = signing_digest(&purpose.purpose(), obj);
    let bytes = <Active as Ed25519Backend>::sign(&key.seed, digest.as_bytes())?;
    Ok(RecordSignature { bytes })
}

/// Deterministically signs the digest of `(purpose, obj)` with the Ed25519
/// half of a hybrid key alone, for a classical-only purpose (an
/// attestation summary QR). It verifies with [`verify_record`] under the
/// hybrid verifying key's Ed25519 part.
///
/// # Errors
/// [`Error::Backend`] if the backend rejects the inputs.
pub fn sign_ed25519_half(
    key: &HybridSigningKey,
    purpose: RecordPurpose,
    obj: &[u8],
) -> Result<RecordSignature, Error> {
    let digest = signing_digest(&purpose.purpose(), obj);
    let bytes = <Active as Ed25519Backend>::sign(&key.ed25519_seed, digest.as_bytes())?;
    Ok(RecordSignature { bytes })
}

/// Verifies a record signature over the digest of `(purpose, obj)`.
///
/// # Errors
/// [`Error::SignatureInvalid`] if the signature does not verify.
pub fn verify_record<'a>(
    verifying_key: &'a RecordVerifyingKey,
    purpose: RecordPurpose,
    obj: &'a [u8],
    signature: &'a RecordSignature,
) -> Result<Verified<RecordSigned<'a>>, Error> {
    let digest = signing_digest(&purpose.purpose(), obj);
    if <Active as Ed25519Backend>::verify(&verifying_key.bytes, digest.as_bytes(), &signature.bytes)
    {
        Ok(Verified::new(RecordSigned {
            key: verifying_key,
            purpose,
            object: obj,
            signature,
        }))
    } else {
        Err(Error::SignatureInvalid)
    }
}

// ---------------------------------------------------------------------------
// Archive (SLH-DSA-SHAKE-256s)
// ---------------------------------------------------------------------------

/// An SLH-DSA-SHAKE-256s signing key. Zeroized on drop.
pub struct ArchiveSigningKey {
    bytes: [u8; SLHDSA_SK_LEN],
}

impl ArchiveSigningKey {
    /// Generates a key pair from `rng`.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> (Self, ArchiveVerifyingKey) {
        let (signing, verifying) = <Active as SlhDsaBackend>::generate(rng);
        (
            Self { bytes: signing },
            ArchiveVerifyingKey { bytes: verifying },
        )
    }

    /// Rebuilds a key from stored bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SLHDSA_SK_LEN]) -> Self {
        Self { bytes }
    }

    /// The key bytes, for storage in a key custody device.
    #[must_use]
    pub const fn expose_bytes(&self) -> &[u8; SLHDSA_SK_LEN] {
        &self.bytes
    }
}

impl Drop for ArchiveSigningKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for ArchiveSigningKey {}

impl fmt::Debug for ArchiveSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ArchiveSigningKey(..)")
    }
}

/// An SLH-DSA-SHAKE-256s verifying key. Every 64-byte string is a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArchiveVerifyingKey {
    bytes: [u8; SLHDSA_VK_LEN],
}

impl ArchiveVerifyingKey {
    /// Encoded length.
    pub const ENCODED_LEN: usize = SLHDSA_VK_LEN;

    /// Wraps key bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SLHDSA_VK_LEN]) -> Self {
        Self { bytes }
    }

    /// The key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SLHDSA_VK_LEN] {
        &self.bytes
    }
}

impl Encode for ArchiveVerifyingKey {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        w.write_array(&self.bytes)
    }
}

impl<'a> Decode<'a> for ArchiveVerifyingKey {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        Ok(Self {
            bytes: r.read_array::<SLHDSA_VK_LEN>()?,
        })
    }
}

/// An SLH-DSA-SHAKE-256s signature (29 792 bytes, held inline).
#[derive(Clone, PartialEq, Eq)]
pub struct ArchiveSignature {
    bytes: [u8; SLHDSA_SIG_LEN],
}

impl ArchiveSignature {
    /// Encoded length.
    pub const ENCODED_LEN: usize = SLHDSA_SIG_LEN;

    /// Wraps signature bytes. Validity is decided by [`verify_archive`].
    #[must_use]
    pub const fn from_bytes(bytes: &[u8; SLHDSA_SIG_LEN]) -> Self {
        Self { bytes: *bytes }
    }

    /// The signature bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SLHDSA_SIG_LEN] {
        &self.bytes
    }
}

impl fmt::Debug for ArchiveSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ArchiveSignature(..)")
    }
}

impl Encode for ArchiveSignature {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        w.write_array(&self.bytes)
    }
}

impl<'a> Decode<'a> for ArchiveSignature {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        Ok(Self {
            bytes: r.read_array::<SLHDSA_SIG_LEN>()?,
        })
    }
}

/// What [`verify_archive`] verified. The purpose is always
/// [`PURPOSE_CHECKPOINT_ARCHIVE`].
#[derive(Debug, Clone, Copy)]
pub struct ArchiveSigned<'a> {
    key: &'a ArchiveVerifyingKey,
    object: &'a [u8],
    signature: &'a ArchiveSignature,
}

impl<'a> ArchiveSigned<'a> {
    /// The verifying key.
    #[must_use]
    pub const fn key(&self) -> &'a ArchiveVerifyingKey {
        self.key
    }

    /// The signed object bytes.
    #[must_use]
    pub const fn object(&self) -> &'a [u8] {
        self.object
    }

    /// The signature.
    #[must_use]
    pub const fn signature(&self) -> &'a ArchiveSignature {
        self.signature
    }
}

/// Signs the digest of `(checkpoint-archive, obj)` with SLH-DSA, using the
/// purpose as the FIPS 205 context and 32 bytes of `rng` output as the
/// signature randomizer.
///
/// # Errors
/// [`Error::InvalidSecretKey`] if the key bytes are malformed,
/// [`Error::Backend`] if the backend rejects the inputs.
pub fn sign_archive<R: CryptoRng + ?Sized>(
    key: &ArchiveSigningKey,
    obj: &[u8],
    rng: &mut R,
) -> Result<ArchiveSignature, Error> {
    let digest = signing_digest(&PURPOSE_CHECKPOINT_ARCHIVE, obj);
    let bytes = <Active as SlhDsaBackend>::sign(
        &key.bytes,
        digest.as_bytes(),
        PURPOSE_CHECKPOINT_ARCHIVE.as_bytes(),
        rng,
    )?;
    Ok(ArchiveSignature { bytes })
}

/// Verifies an archive signature over the digest of `(checkpoint-archive, obj)`.
///
/// # Errors
/// [`Error::SignatureInvalid`] if the signature does not verify.
pub fn verify_archive<'a>(
    verifying_key: &'a ArchiveVerifyingKey,
    obj: &'a [u8],
    signature: &'a ArchiveSignature,
) -> Result<Verified<ArchiveSigned<'a>>, Error> {
    let digest = signing_digest(&PURPOSE_CHECKPOINT_ARCHIVE, obj);
    if <Active as SlhDsaBackend>::verify(
        &verifying_key.bytes,
        digest.as_bytes(),
        PURPOSE_CHECKPOINT_ARCHIVE.as_bytes(),
        &signature.bytes,
    ) {
        Ok(Verified::new(ArchiveSigned {
            key: verifying_key,
            object: obj,
            signature,
        }))
    } else {
        Err(Error::SignatureInvalid)
    }
}
