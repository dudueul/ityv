//! Bounds-checked, non-allocating, non-panicking writer into a byte slice.

use crate::error::{Error, Kind};
use crate::primitives::Ident;

/// Writes canonical fields into a caller-provided buffer.
///
/// The writer never panics and never writes past the buffer: every write is
/// preceded by a checked split of the remaining space.
#[derive(Debug)]
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    /// Creates a writer positioned at the start of `buf`.
    #[must_use]
    pub const fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Number of bytes written so far.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Number of bytes still available.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    const fn error(&self, kind: Kind) -> Error {
        Error::new(kind, self.pos)
    }

    fn advance(&mut self, n: usize) -> Result<(), Error> {
        self.pos = self
            .pos
            .checked_add(n)
            .ok_or_else(|| self.error(Kind::ArithmeticOverflow))?;
        Ok(())
    }

    /// Writes `bytes` verbatim.
    ///
    /// # Errors
    /// `BufferTooSmall` if fewer than `bytes.len()` bytes remain.
    pub fn write_slice(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let pos = self.pos;
        let too_small = Error::new(Kind::BufferTooSmall, pos);
        let rest = self.buf.get_mut(pos..).ok_or(too_small)?;
        let (head, _) = rest.split_at_mut_checked(bytes.len()).ok_or(too_small)?;
        // `head.len() == bytes.len()` by construction of the checked split.
        head.copy_from_slice(bytes);
        self.advance(bytes.len())
    }

    /// Writes a fixed array.
    ///
    /// # Errors
    /// `BufferTooSmall` if fewer than `N` bytes remain.
    pub fn write_array<const N: usize>(&mut self, value: &[u8; N]) -> Result<(), Error> {
        let pos = self.pos;
        let too_small = Error::new(Kind::BufferTooSmall, pos);
        let rest = self.buf.get_mut(pos..).ok_or(too_small)?;
        let (chunk, _) = rest.split_first_chunk_mut::<N>().ok_or(too_small)?;
        *chunk = *value;
        self.advance(N)
    }

    /// Writes one byte.
    ///
    /// # Errors
    /// `BufferTooSmall` if no byte remains.
    pub fn write_u8(&mut self, value: u8) -> Result<(), Error> {
        self.write_array(&[value])
    }

    /// Writes a big-endian `u16`.
    ///
    /// # Errors
    /// `BufferTooSmall` if fewer than two bytes remain.
    pub fn write_u16(&mut self, value: u16) -> Result<(), Error> {
        self.write_array(&value.to_be_bytes())
    }

    /// Writes a big-endian `u32`.
    ///
    /// # Errors
    /// `BufferTooSmall` if fewer than four bytes remain.
    pub fn write_u32(&mut self, value: u32) -> Result<(), Error> {
        self.write_array(&value.to_be_bytes())
    }

    /// Writes a big-endian `u64`.
    ///
    /// # Errors
    /// `BufferTooSmall` if fewer than eight bytes remain.
    pub fn write_u64(&mut self, value: u64) -> Result<(), Error> {
        self.write_array(&value.to_be_bytes())
    }

    /// Writes a boolean as `0x00` or `0x01`.
    ///
    /// # Errors
    /// `BufferTooSmall` if no byte remains.
    pub fn write_bool(&mut self, value: bool) -> Result<(), Error> {
        self.write_u8(u8::from(value))
    }

    /// Writes an `Option` presence tag as `0x00` or `0x01`.
    ///
    /// # Errors
    /// `BufferTooSmall` if no byte remains.
    pub fn write_presence(&mut self, present: bool) -> Result<(), Error> {
        self.write_u8(u8::from(present))
    }

    fn write_u32_bounded(&mut self, value: usize, max: usize, too_big: Kind) -> Result<(), Error> {
        if value > max {
            return Err(self.error(too_big));
        }
        let raw = u32::try_from(value).map_err(|_| self.error(Kind::LengthNotRepresentable))?;
        self.write_u32(raw)
    }

    /// Writes a `u32` length prefix after checking it against `max`.
    ///
    /// # Errors
    /// `LengthExceedsMax`, `LengthNotRepresentable`, or `BufferTooSmall`.
    pub fn write_len(&mut self, len: usize, max: usize) -> Result<(), Error> {
        self.write_u32_bounded(len, max, Kind::LengthExceedsMax)
    }

    /// Writes a `u32` element count prefix after checking it against `max`.
    ///
    /// # Errors
    /// `CountExceedsMax`, `LengthNotRepresentable`, or `BufferTooSmall`.
    pub fn write_count(&mut self, count: usize, max: usize) -> Result<(), Error> {
        self.write_u32_bounded(count, max, Kind::CountExceedsMax)
    }

    /// Writes a length-prefixed byte string of at most `max` bytes.
    ///
    /// # Errors
    /// Any error of [`Self::write_len`] or [`Self::write_slice`].
    pub fn write_bytes(&mut self, bytes: &[u8], max: usize) -> Result<(), Error> {
        self.write_len(bytes.len(), max)?;
        self.write_slice(bytes)
    }

    /// Writes a length-prefixed identifier, checking it against the field's
    /// `max` (which may be smaller than the identifier's own bound).
    ///
    /// # Errors
    /// `LengthExceedsMax` if the identifier is longer than `max`, plus any
    /// error of [`Self::write_slice`].
    pub fn write_ident(&mut self, ident: &Ident<'_>, max: usize) -> Result<(), Error> {
        self.write_bytes(ident.as_bytes(), max)
    }

    /// Consumes the writer and returns the number of bytes written.
    #[must_use]
    pub const fn finish(self) -> usize {
        self.pos
    }
}
