//! The 16-byte object header and the top-level `encode`/`decode` entry points
//! (ENCODING.md §3).

use crate::codec::{Decode, Encode};
use crate::error::{Error, Kind};
use crate::primitives::SchemaId;
use crate::reader::Reader;
use crate::writer::Writer;

/// The four magic bytes every object starts with.
pub const MAGIC: [u8; 4] = *b"ITYV";

/// Length of the object header in bytes.
pub const HEADER_LEN: usize = 16;

/// Byte offset of the `schema_id` field within the header.
const OFFSET_SCHEMA_ID: usize = 4;
/// Byte offset of the `schema_version` field within the header.
const OFFSET_VERSION: usize = 8;
/// Byte offset of the `flags` field within the header.
const OFFSET_FLAGS: usize = 10;
/// Byte offset of the `body_len` field within the header.
const OFFSET_BODY_LEN: usize = 12;

/// A parsed object header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Header {
    schema_id: SchemaId,
    schema_version: u16,
    body_len: u32,
}

impl Header {
    /// Builds a header for a body of `body_len` bytes.
    #[must_use]
    pub const fn new(schema_id: SchemaId, schema_version: u16, body_len: u32) -> Self {
        Self {
            schema_id,
            schema_version,
            body_len,
        }
    }

    /// The schema identifier.
    #[must_use]
    pub const fn schema_id(&self) -> SchemaId {
        self.schema_id
    }

    /// The schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// The declared body length.
    #[must_use]
    pub const fn body_len(&self) -> u32 {
        self.body_len
    }

    /// Writes the header.
    ///
    /// # Errors
    /// `BufferTooSmall` if fewer than [`HEADER_LEN`] bytes remain.
    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_array(&MAGIC)?;
        w.write_u32(self.schema_id.get())?;
        w.write_u16(self.schema_version)?;
        w.write_u16(0)?;
        w.write_u32(self.body_len)
    }

    /// Reads and checks a header, leaving the reader positioned at the body.
    ///
    /// Checks magic, zero flags, and that `body_len` equals the number of
    /// bytes remaining after the header.
    ///
    /// # Errors
    /// `BadMagic` at 0, `NonZeroFlags` at 10, `BodyLengthMismatch` at 12,
    /// `LengthNotRepresentable` at 12, or `UnexpectedEnd` if the input is
    /// shorter than [`HEADER_LEN`].
    pub fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let start = r.position();
        let magic = r.read_array::<4>()?;
        if magic != MAGIC {
            return Err(Error::new(Kind::BadMagic, start));
        }
        let schema_id = SchemaId::new(r.read_u32()?);
        let schema_version = r.read_u16()?;
        let flags_at = r.position();
        if r.read_u16()? != 0 {
            return Err(Error::new(Kind::NonZeroFlags, flags_at));
        }
        let len_at = r.position();
        let body_len = r.read_u32()?;
        let declared = usize::try_from(body_len)
            .map_err(|_| Error::new(Kind::LengthNotRepresentable, len_at))?;
        if declared != r.remaining() {
            return Err(Error::new(Kind::BodyLengthMismatch, len_at));
        }
        Ok(Self {
            schema_id,
            schema_version,
            body_len,
        })
    }
}

/// Encodes `value` as a complete object (header plus body) into `out`.
///
/// Returns the total number of bytes written.
///
/// # Errors
/// `LengthNotRepresentable` if the body is longer than `u32::MAX`,
/// `BufferTooSmall` if `out` cannot hold header and body, or any encoding
/// error from `value`.
pub fn encode<T: Encode>(
    schema: SchemaId,
    version: u16,
    value: &T,
    out: &mut [u8],
) -> Result<usize, Error> {
    let body_len = value.encoded_len();
    let body_len_u32 =
        u32::try_from(body_len).map_err(|_| Error::new(Kind::LengthNotRepresentable, 0))?;
    let total = HEADER_LEN
        .checked_add(body_len)
        .ok_or_else(|| Error::new(Kind::ArithmeticOverflow, 0))?;
    let mut w = Writer::new(out);
    Header::new(schema, version, body_len_u32).write(&mut w)?;
    value.encode(&mut w)?;
    let written = w.finish();
    if written == total {
        Ok(total)
    } else {
        // `encoded_len` disagreed with `encode`: an implementation defect,
        // reported rather than silently producing an inconsistent object.
        Err(Error::new(Kind::BodyLengthMismatch, written))
    }
}

/// Decodes a complete object of the `expected` schema and `version`.
///
/// Rejects any input that is not the exact canonical encoding: bad header,
/// wrong schema, unsupported version, non-zero flags, length mismatch, any
/// field violation, or trailing bytes.
///
/// # Errors
/// `SchemaMismatch` at 4, `UnsupportedVersion` at 8, any error of
/// [`Header::read`], any decoding error from `T`, or `TrailingBytes`.
pub fn decode<'a, T: Decode<'a>>(
    expected: SchemaId,
    version: u16,
    input: &'a [u8],
) -> Result<T, Error> {
    let mut r = Reader::new(input);
    let header = Header::read(&mut r)?;
    if header.schema_id() != expected {
        return Err(Error::new(Kind::SchemaMismatch, OFFSET_SCHEMA_ID));
    }
    if header.schema_version() != version {
        return Err(Error::new(Kind::UnsupportedVersion, OFFSET_VERSION));
    }
    let value = T::decode(&mut r)?;
    r.finish()?;
    Ok(value)
}

// The offset constants document the header layout; the two unused ones are
// referenced here so the layout stays in one place.
const _: () = {
    assert!(OFFSET_FLAGS == 10);
    assert!(OFFSET_BODY_LEN == 12);
    assert!(HEADER_LEN == 16);
};
