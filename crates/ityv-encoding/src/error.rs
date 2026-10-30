//! Error type shared by every encoder and decoder in this crate.
//!
//! Errors never carry strings or heap data. They carry a [`Kind`] and the byte
//! offset at which the violation was detected, relative to the start of the
//! buffer handed to the reader or writer.

/// Classification of an encoding or decoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// The input ended before a complete field could be read.
    UnexpectedEnd,
    /// The output buffer is too small for the field being written.
    BufferTooSmall,
    /// The first four bytes are not the `ITYV` magic.
    BadMagic,
    /// The header names a schema other than the one the caller expected.
    SchemaMismatch,
    /// The header names a schema version the caller does not support.
    UnsupportedVersion,
    /// The header `flags` field is not zero.
    NonZeroFlags,
    /// The header `body_len` does not equal the number of bytes that follow.
    BodyLengthMismatch,
    /// Bytes remain after the object was fully decoded.
    TrailingBytes,
    /// A `bool` byte was neither `0x00` nor `0x01`.
    InvalidBool,
    /// An `Option` presence tag was neither `0x00` nor `0x01`.
    InvalidPresenceTag,
    /// A length prefix exceeds the maximum the schema allows for the field.
    LengthExceedsMax,
    /// A length prefix cannot be represented as `usize` on this target.
    LengthNotRepresentable,
    /// An identifier has zero length.
    EmptyIdent,
    /// An identifier contains a byte outside `[A-Za-z0-9._:-]`.
    InvalidIdentByte,
    /// An array count prefix exceeds the maximum the schema allows.
    CountExceedsMax,
    /// An array declared sorted has an element smaller than its predecessor.
    NotSorted,
    /// An array declared unique has an element equal to its predecessor.
    Duplicate,
    /// A numeric field is outside the range the schema declares.
    ValueOutOfRange,
    /// A legal-authorization scope code is not one of the nine defined codes.
    InvalidScopeCode,
    /// A checkpoint's previous hash is zero for `seq > 1` or non-zero for `seq == 1`.
    InvalidPreviousHash,
    /// An internal length computation overflowed `usize`.
    ArithmeticOverflow,
    /// A schema-level invariant between fields does not hold.
    InvariantViolation,
}

/// An encoding or decoding error: what went wrong and where.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Error {
    kind: Kind,
    offset: usize,
}

impl Error {
    /// Creates an error of `kind` detected at byte `offset`.
    #[must_use]
    pub const fn new(kind: Kind, offset: usize) -> Self {
        Self { kind, offset }
    }

    /// The classification of this error.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        self.kind
    }

    /// The byte offset, relative to the start of the buffer, at which the
    /// violation was detected.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let kind = self.kind;
        let offset = self.offset;
        write!(f, "{kind:?} at byte offset {offset}")
    }
}

impl core::error::Error for Error {}
