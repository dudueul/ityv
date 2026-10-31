//! Domain-separated SHA3-512 (ENCODING.md §4) and hash-to-group.
//!
//! Every hash input begins with an ASCII label, a `0x00` terminator and the
//! big-endian 64-bit length of the payload, so that no two purposes ever hash
//! the same byte string:
//!
//! | use | input |
//! |---|---|
//! | object hash | `"ityv:hash:v1" ‖ 0x00 ‖ u64_be(len) ‖ obj` |
//! | signing digest | `"ityv:sig:v1:" ‖ purpose ‖ 0x00 ‖ u64_be(len) ‖ obj` |
//! | Fiat-Shamir | `"ityv:fs:v1:" ‖ proof_system ‖ 0x00 ‖ u64_be(len) ‖ transcript` |
//! | hash to group | `label ‖ 0x00`, then the Ristretto255 uniform map |

use ityv_encoding::{Hash512, Ident};

use crate::backend::ristretto::Point;
use crate::backend::{Active, Sha3Backend};
use crate::error::Error;
use crate::scalar::Scalar;

/// Label of the object hash.
pub const HASH_LABEL: &[u8] = b"ityv:hash:v1";
/// Prefix of the signing message label; the purpose follows it.
pub const SIGNING_LABEL_PREFIX: &[u8] = b"ityv:sig:v1:";
/// Prefix of the Fiat-Shamir label; the proof-system identifier follows it.
pub const FIAT_SHAMIR_LABEL_PREFIX: &[u8] = b"ityv:fs:v1:";

/// A signature purpose: one to 32 bytes over the identifier alphabet
/// (PROTOCOL.md Appendix B).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Purpose<'a> {
    bytes: &'a [u8],
}

impl<'a> Purpose<'a> {
    /// Maximum length in bytes.
    pub const MAX_LEN: usize = 32;

    /// Returns `Some` if `bytes` is an identifier of at most
    /// [`Self::MAX_LEN`] bytes.
    #[must_use]
    pub const fn new(bytes: &'a [u8]) -> Option<Self> {
        match Ident::new(bytes, Self::MAX_LEN) {
            Some(_) => Some(Self { bytes }),
            None => None,
        }
    }

    /// Constructs a purpose from a literal known to be valid. Used only for
    /// the constants in this crate, each of which a unit test checks with
    /// [`Self::new`].
    pub(crate) const fn from_literal(bytes: &'static [u8]) -> Purpose<'static> {
        Purpose { bytes }
    }

    /// The purpose bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// Maximum length of the signing-message prefix: label, purpose, terminator
/// and length.
pub(crate) const SIGNING_PREFIX_MAX_LEN: usize = 12 + Purpose::MAX_LEN + 1 + 8;

/// The bytes that precede the object in the signing message:
/// `"ityv:sig:v1:" ‖ purpose ‖ 0x00 ‖ u64_be(len)`.
pub(crate) struct SigningPrefix {
    buffer: [u8; SIGNING_PREFIX_MAX_LEN],
    used: usize,
}

impl SigningPrefix {
    /// Builds the prefix for `purpose` and an object of `len` bytes. The
    /// result is at most [`SIGNING_PREFIX_MAX_LEN`] bytes because a purpose
    /// is at most [`Purpose::MAX_LEN`] bytes.
    pub(crate) fn new(purpose: &Purpose<'_>, len: usize) -> Self {
        let length = length_prefix(len);
        let mut buffer = [0u8; SIGNING_PREFIX_MAX_LEN];
        let mut used = 0usize;
        let bytes = SIGNING_LABEL_PREFIX
            .iter()
            .chain(purpose.as_bytes())
            .chain(core::iter::once(&0x00))
            .chain(length.iter());
        for (slot, byte) in buffer.iter_mut().zip(bytes) {
            *slot = *byte;
            used = used.saturating_add(1);
        }
        Self { buffer, used }
    }

    /// The prefix bytes. The slice cannot be shorter than `used`, because
    /// `used` counts bytes written into `buffer`; the fallback keeps the
    /// function total.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.buffer.get(..self.used).unwrap_or(&[])
    }
}

/// Incremental SHA3-512.
pub(crate) struct Hasher {
    state: <Active as Sha3Backend>::State,
}

impl Hasher {
    pub(crate) fn new() -> Self {
        Self {
            state: <Active as Sha3Backend>::begin(),
        }
    }

    pub(crate) fn absorb(&mut self, data: &[u8]) {
        <Active as Sha3Backend>::absorb(&mut self.state, data);
    }

    pub(crate) fn finish(self) -> [u8; 64] {
        <Active as Sha3Backend>::finish(self.state)
    }
}

/// The big-endian 64-bit length prefix. `usize` fits in `u64` on every
/// supported target; the saturation only matters on a hypothetical 128-bit
/// target with an object longer than 2^64 bytes, where it makes the hash
/// differ rather than silently truncate.
pub(crate) fn length_prefix(len: usize) -> [u8; 8] {
    u64::try_from(len).unwrap_or(u64::MAX).to_be_bytes()
}

/// `SHA3-512("ityv:hash:v1" ‖ 0x00 ‖ u64_be(len(obj)) ‖ obj)`.
#[must_use]
pub fn object_hash(obj: &[u8]) -> Hash512 {
    let mut hasher = Hasher::new();
    hasher.absorb(HASH_LABEL);
    hasher.absorb(&[0x00]);
    hasher.absorb(&length_prefix(obj.len()));
    hasher.absorb(obj);
    Hash512(hasher.finish())
}

/// `SHA3-512("ityv:sig:v1:" ‖ purpose ‖ 0x00 ‖ u64_be(len(obj)) ‖ obj)`: the
/// 64-byte value every signature algorithm signs (ADR-0015 §3).
#[must_use]
pub fn signing_digest(purpose: &Purpose<'_>, obj: &[u8]) -> Hash512 {
    let mut hasher = Hasher::new();
    hasher.absorb(SigningPrefix::new(purpose, obj.len()).as_bytes());
    hasher.absorb(obj);
    Hash512(hasher.finish())
}

/// A Fiat-Shamir transcript whose total length is declared up front, because
/// the length prefix precedes the transcript bytes in the hash input.
pub(crate) struct Transcript {
    hasher: Hasher,
    declared: u64,
    absorbed: u64,
}

impl Transcript {
    /// Starts a transcript for `proof_system` that will absorb exactly
    /// `transcript_len` bytes.
    pub(crate) fn begin(proof_system: &[u8], transcript_len: usize) -> Self {
        let mut hasher = Hasher::new();
        hasher.absorb(FIAT_SHAMIR_LABEL_PREFIX);
        hasher.absorb(proof_system);
        hasher.absorb(&[0x00]);
        hasher.absorb(&length_prefix(transcript_len));
        Self {
            hasher,
            declared: u64::try_from(transcript_len).unwrap_or(u64::MAX),
            absorbed: 0,
        }
    }

    /// Absorbs transcript bytes.
    pub(crate) fn absorb(&mut self, data: &[u8]) {
        self.hasher.absorb(data);
        self.absorbed = self
            .absorbed
            .saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
    }

    /// The challenge scalar.
    ///
    /// # Errors
    /// [`Error::LengthMismatch`] if the absorbed length differs from the
    /// declared length (an internal invariant; the caller computes both).
    pub(crate) fn finish(self) -> Result<Scalar, Error> {
        if self.absorbed != self.declared {
            return Err(Error::LengthMismatch);
        }
        Ok(Scalar::from_bytes_mod_order_wide(&self.hasher.finish()))
    }
}

/// `SHA3-512("ityv:fs:v1:" ‖ proof_system ‖ 0x00 ‖ u64_be(len) ‖ transcript)`
/// reduced to a scalar.
#[must_use]
pub fn fiat_shamir_challenge(proof_system: &[u8], transcript: &[u8]) -> Scalar {
    let mut hasher = Hasher::new();
    hasher.absorb(FIAT_SHAMIR_LABEL_PREFIX);
    hasher.absorb(proof_system);
    hasher.absorb(&[0x00]);
    hasher.absorb(&length_prefix(transcript.len()));
    hasher.absorb(transcript);
    Scalar::from_bytes_mod_order_wide(&hasher.finish())
}

/// `from_uniform_bytes(SHA3-512(label ‖ 0x00))`: a group element whose
/// discrete logarithm with respect to any other such element is unknown.
pub(crate) fn hash_to_group(label: &[u8]) -> Point {
    let mut hasher = Hasher::new();
    hasher.absorb(label);
    hasher.absorb(&[0x00]);
    Point::from_uniform_bytes(&hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIST FIPS 202 known answer: SHA3-512 of the empty string and of
    /// `"abc"`, checked against the raw hasher that every domain hash uses.
    #[test]
    fn sha3_512_known_answers() {
        let empty = Hasher::new().finish();
        assert_eq!(
            empty.as_slice(),
            &hex_literal(
                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
            )[..]
        );
        let mut hasher = Hasher::new();
        hasher.absorb(b"abc");
        assert_eq!(
            hasher.finish().as_slice(),
            &hex_literal(
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
            )[..]
        );
    }

    #[test]
    fn purpose_constants_are_valid() {
        for purpose in [
            crate::sig::PURPOSE_CAST_RECORD,
            crate::sig::PURPOSE_MODULE_RECORD,
            crate::sig::PURPOSE_CHECKPOINT_ARCHIVE,
        ] {
            assert!(Purpose::new(purpose.as_bytes()).is_some());
        }
    }

    fn hex_literal(text: &str) -> [u8; 64] {
        let mut out = [0u8; 64];
        for (i, pair) in text.as_bytes().chunks(2).enumerate() {
            let s = core::str::from_utf8(pair).unwrap();
            out[i] = u8::from_str_radix(s, 16).unwrap();
        }
        out
    }
}
