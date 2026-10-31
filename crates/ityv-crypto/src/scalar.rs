//! The Ristretto255 scalar field (integers modulo the group order ℓ).
//!
//! [`Scalar`] is the only arithmetic type this crate exposes. Every value is
//! canonical by construction: the public constructors reduce or reject, and
//! the decoder rejects non-canonical encodings (VC-026). Arithmetic is
//! provided as named methods rather than operators so that callers inherit
//! the workspace rule that binary operators are only used on checked integer
//! arithmetic (CONSTITUTION.md §1.1).

use core::ops::{Add, Mul, Neg, Sub};

use curve25519_dalek::scalar::Scalar as Inner;
use ityv_encoding::{Decode, Encode, Error as EncodingError, ErrorKind, Reader, Writer};
use rand_core::CryptoRng;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroize;

use crate::error::Error;

/// An element of the scalar field, always in canonical form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scalar(pub(crate) Inner);

impl Scalar {
    /// Encoded length in bytes.
    pub const LEN: usize = 32;
    /// The additive identity.
    pub const ZERO: Self = Self(Inner::ZERO);
    /// The multiplicative identity.
    pub const ONE: Self = Self(Inner::ONE);

    /// Parses a little-endian 32-byte encoding, rejecting values that are not
    /// less than the group order.
    ///
    /// # Errors
    /// [`Error::NonCanonicalScalar`] if `bytes` is not canonical.
    pub fn from_canonical_bytes(bytes: [u8; 32]) -> Result<Self, Error> {
        Option::<Inner>::from(Inner::from_canonical_bytes(bytes))
            .map(Self)
            .ok_or(Error::NonCanonicalScalar)
    }

    /// Reduces a little-endian 32-byte integer modulo the order. Crate-private
    /// because every public entry point must either reject or document the
    /// reduction; the callers here only pass values already below the order.
    pub(crate) fn from_bytes_mod_order(bytes: [u8; 32]) -> Self {
        Self(Inner::from_bytes_mod_order(bytes))
    }

    /// Reduces a little-endian 64-byte integer modulo the order. The result is
    /// uniform when the input is uniform.
    #[must_use]
    pub fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Self {
        Self(Inner::from_bytes_mod_order_wide(bytes))
    }

    /// The scalar equal to the integer `value`.
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        Self(Inner::from(value))
    }

    /// Little-endian canonical encoding.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// A uniformly random scalar from 64 bytes of `rng` output.
    pub fn random<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        let scalar = Self::from_bytes_mod_order_wide(&wide);
        wide.zeroize();
        scalar
    }

    /// `self + other (mod ℓ)`.
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        Self(Add::add(&self.0, &other.0))
    }

    /// `self − other (mod ℓ)`.
    #[must_use]
    pub fn sub(&self, other: &Self) -> Self {
        Self(Sub::sub(&self.0, &other.0))
    }

    /// `self · other (mod ℓ)`.
    #[must_use]
    pub fn mul(&self, other: &Self) -> Self {
        Self(Mul::mul(&self.0, &other.0))
    }

    /// `−self (mod ℓ)`.
    #[must_use]
    pub fn neg(&self) -> Self {
        Self(Neg::neg(&self.0))
    }

    /// The multiplicative inverse, or `None` for zero.
    #[must_use]
    pub fn invert(&self) -> Option<Self> {
        if self.is_zero() {
            None
        } else {
            Some(Self(self.0.invert()))
        }
    }

    /// `true` if this is the additive identity (constant time).
    #[must_use]
    pub fn is_zero(&self) -> bool {
        bool::from(self.0.ct_eq(&Inner::ZERO))
    }
}

impl Default for Scalar {
    fn default() -> Self {
        Self::ZERO
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Encode for Scalar {
    fn encoded_len(&self) -> usize {
        Self::LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        w.write_array(&self.to_bytes())
    }
}

impl<'a> Decode<'a> for Scalar {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        let at = r.position();
        let bytes = r.read_array::<32>()?;
        Self::from_canonical_bytes(bytes)
            .map_err(|_| EncodingError::new(ErrorKind::ValueOutOfRange, at))
    }
}
