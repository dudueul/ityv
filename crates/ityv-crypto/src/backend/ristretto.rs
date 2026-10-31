//! Ristretto255 group elements, wrapping `curve25519-dalek`.
//!
//! Points never leave this crate: callers see [`crate::commit::Commitment`]
//! (a validated compressed encoding) and opaque base sets.

use core::ops::{Add, Mul, Sub};

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::traits::Identity;

use crate::scalar::Scalar;

/// The backend scalar type, wrapped by [`crate::scalar::Scalar`]. This
/// re-export is the only path through which the scalar module reaches the
/// algorithm crate.
pub(crate) use curve25519_dalek::scalar::Scalar as InnerScalar;

/// A group element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Point(RistrettoPoint);

impl Point {
    /// The neutral element.
    pub(crate) fn identity() -> Self {
        Self(RistrettoPoint::identity())
    }

    /// The uniform map from 64 bytes (two Elligator 2 evaluations), as used
    /// by `hash_to_group`.
    pub(crate) fn from_uniform_bytes(bytes: &[u8; 64]) -> Self {
        Self(RistrettoPoint::from_uniform_bytes(bytes))
    }

    /// Decompresses a 32-byte encoding, or `None` if it is not canonical.
    pub(crate) fn decompress(bytes: &[u8; 32]) -> Option<Self> {
        CompressedRistretto(*bytes).decompress().map(Self)
    }

    /// The canonical 32-byte encoding.
    pub(crate) fn compress(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    /// `scalar · self` (constant time).
    pub(crate) fn mul(&self, scalar: &Scalar) -> Self {
        Self(Mul::mul(&self.0, &scalar.0))
    }

    /// `self + other`.
    pub(crate) fn add(&self, other: &Self) -> Self {
        Self(Add::add(&self.0, &other.0))
    }

    /// `self − other`.
    pub(crate) fn sub(&self, other: &Self) -> Self {
        Self(Sub::sub(&self.0, &other.0))
    }
}
