//! Poly1305 one-time authentication for pad-encrypted share plaintexts
//! (PROTOCOL.md §9.3, §9.4.3).
//!
//! A [`OneTimeKey`] is 32 bytes taken from the one-time pad and is consumed
//! by [`tag`] or [`verify_tag`]: the type cannot be cloned, so one key value
//! authenticates one message per construction. Single use of the *bytes* is
//! the caller's obligation: the pad position rule of PROTOCOL.md §9.4.3
//! (each pad range is handed out once and then overwritten) is what
//! guarantees that no 32-byte key is ever constructed twice, and Poly1305 is
//! secure only under that guarantee.

use core::fmt;

use ityv_encoding::{Decode, Encode, Error as EncodingError, Reader, Writer};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::backend::{Active, OneTimeMacBackend};
use crate::error::Error;
use crate::verified::Verified;

/// A single-use 32-byte Poly1305 key. Not `Clone`; zeroized on drop.
pub struct OneTimeKey {
    bytes: [u8; 32],
}

impl OneTimeKey {
    /// Wraps 32 pad bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }
}

impl Drop for OneTimeKey {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for OneTimeKey {}

impl fmt::Debug for OneTimeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OneTimeKey(..)")
    }
}

/// A 16-byte Poly1305 tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tag {
    bytes: [u8; 16],
}

impl Tag {
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

impl Encode for Tag {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        w.write_array(&self.bytes)
    }
}

impl<'a> Decode<'a> for Tag {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        Ok(Self {
            bytes: r.read_array::<16>()?,
        })
    }
}

/// The tag of `message` under `key` (consumed).
#[must_use]
pub fn tag(key: OneTimeKey, message: &[u8]) -> Tag {
    let bytes = <Active as OneTimeMacBackend>::tag(&key.bytes, message);
    drop(key);
    Tag { bytes }
}

/// Checks `expected` against `message` under `key` (consumed), in constant
/// time. The token carries the authenticated message.
///
/// # Errors
/// [`Error::TagMismatch`] if the tag does not match.
pub fn verify_tag<'a>(
    key: OneTimeKey,
    message: &'a [u8],
    expected: &Tag,
) -> Result<Verified<&'a [u8]>, Error> {
    let computed = tag(key, message);
    if bool::from(computed.bytes.ct_eq(&expected.bytes)) {
        Ok(Verified::new(message))
    } else {
        Err(Error::TagMismatch)
    }
}
