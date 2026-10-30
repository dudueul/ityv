//! Bounds-checked, non-allocating, non-panicking reader over a byte slice.

use crate::error::{Error, Kind};
use crate::primitives::Ident;

/// Reads canonical fields from a borrowed byte slice.
///
/// Every method returns an [`Error`] carrying the offset of the first
/// violation. The reader never panics: all slicing goes through checked
/// operations and all offset arithmetic is checked.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Creates a reader positioned at the start of `buf`.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Current offset from the start of the buffer.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Number of bytes not yet consumed.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Returns `true` if every byte has been consumed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn rest(&self) -> &'a [u8] {
        // `pos` never exceeds `buf.len()` (every advance is bounded by a
        // successful split), so `get` cannot fail; the fallback is defensive.
        self.buf.get(self.pos..).unwrap_or(&[])
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

    /// Consumes exactly `n` bytes.
    ///
    /// # Errors
    /// `UnexpectedEnd` if fewer than `n` bytes remain.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let (head, _) = self
            .rest()
            .split_at_checked(n)
            .ok_or_else(|| self.error(Kind::UnexpectedEnd))?;
        self.advance(n)?;
        Ok(head)
    }

    /// Consumes exactly `N` bytes as a fixed array.
    ///
    /// # Errors
    /// `UnexpectedEnd` if fewer than `N` bytes remain.
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let (chunk, _) = self
            .rest()
            .split_first_chunk::<N>()
            .ok_or_else(|| self.error(Kind::UnexpectedEnd))?;
        let out = *chunk;
        self.advance(N)?;
        Ok(out)
    }

    /// Reads one byte.
    ///
    /// # Errors
    /// `UnexpectedEnd` if no byte remains.
    pub fn read_u8(&mut self) -> Result<u8, Error> {
        let [b] = self.read_array::<1>()?;
        Ok(b)
    }

    /// Reads a big-endian `u16`.
    ///
    /// # Errors
    /// `UnexpectedEnd` if fewer than two bytes remain.
    pub fn read_u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.read_array::<2>()?))
    }

    /// Reads a big-endian `u32`.
    ///
    /// # Errors
    /// `UnexpectedEnd` if fewer than four bytes remain.
    pub fn read_u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.read_array::<4>()?))
    }

    /// Reads a big-endian `u64`.
    ///
    /// # Errors
    /// `UnexpectedEnd` if fewer than eight bytes remain.
    pub fn read_u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.read_array::<8>()?))
    }

    /// Reads a strict boolean: `0x00` is `false`, `0x01` is `true`.
    ///
    /// # Errors
    /// `InvalidBool` for any other byte, `UnexpectedEnd` if no byte remains.
    pub fn read_bool(&mut self) -> Result<bool, Error> {
        self.read_strict_flag(Kind::InvalidBool)
    }

    /// Reads a strict presence tag for an `Option` field.
    ///
    /// # Errors
    /// `InvalidPresenceTag` for any byte other than `0x00`/`0x01`.
    pub fn read_presence(&mut self) -> Result<bool, Error> {
        self.read_strict_flag(Kind::InvalidPresenceTag)
    }

    /// Reads one byte that must be `0x00` or `0x01`, without advancing on
    /// failure so the error offset is the byte itself.
    fn read_strict_flag(&mut self, invalid: Kind) -> Result<bool, Error> {
        let flag = match self.rest().first() {
            None => return Err(self.error(Kind::UnexpectedEnd)),
            Some(0) => false,
            Some(1) => true,
            Some(_) => return Err(self.error(invalid)),
        };
        self.advance(1)?;
        Ok(flag)
    }

    fn read_u32_bounded(&mut self, max: usize, too_big: Kind) -> Result<usize, Error> {
        let at = self.pos;
        let raw = self.read_u32()?;
        let value =
            usize::try_from(raw).map_err(|_| Error::new(Kind::LengthNotRepresentable, at))?;
        if value > max {
            return Err(Error::new(too_big, at));
        }
        Ok(value)
    }

    /// Reads a `u32` length prefix and checks it against `max`.
    ///
    /// # Errors
    /// `LengthExceedsMax` if the prefix is larger than `max`,
    /// `LengthNotRepresentable` if it does not fit in `usize`.
    pub fn read_len(&mut self, max: usize) -> Result<usize, Error> {
        self.read_u32_bounded(max, Kind::LengthExceedsMax)
    }

    /// Reads a `u32` element count prefix and checks it against `max`.
    ///
    /// # Errors
    /// `CountExceedsMax` if the prefix is larger than `max`,
    /// `LengthNotRepresentable` if it does not fit in `usize`.
    pub fn read_count(&mut self, max: usize) -> Result<usize, Error> {
        self.read_u32_bounded(max, Kind::CountExceedsMax)
    }

    /// Reads a length-prefixed byte string of at most `max` bytes.
    ///
    /// # Errors
    /// Any error of [`Self::read_len`] or [`Self::take`].
    pub fn read_bytes(&mut self, max: usize) -> Result<&'a [u8], Error> {
        let n = self.read_len(max)?;
        self.take(n)
    }

    /// Reads a length-prefixed identifier of one to `max` bytes.
    ///
    /// # Errors
    /// `EmptyIdent` for a zero length, `InvalidIdentByte` at the offset of the
    /// first byte outside the alphabet, plus any error of [`Self::read_len`].
    pub fn read_ident(&mut self, max: usize) -> Result<Ident<'a>, Error> {
        let at = self.pos;
        let n = self.read_len(max)?;
        if n == 0 {
            return Err(Error::new(Kind::EmptyIdent, at));
        }
        let start = self.pos;
        let bytes = self.take(n)?;
        for (i, b) in bytes.iter().enumerate() {
            if !Ident::is_valid_byte(*b) {
                let offset = start
                    .checked_add(i)
                    .ok_or_else(|| Error::new(Kind::ArithmeticOverflow, start))?;
                return Err(Error::new(Kind::InvalidIdentByte, offset));
            }
        }
        // Every byte was just checked and `1 <= n <= max`, so this cannot
        // fail; the fallback error keeps the function total.
        Ident::new(bytes, max).ok_or_else(|| Error::new(Kind::InvalidIdentByte, start))
    }

    /// Checks that a sorted-unique array element is strictly greater than its
    /// predecessor in lexicographic byte order.
    ///
    /// # Errors
    /// `NotSorted` if `current < previous`, `Duplicate` if equal.
    pub fn check_ascending(
        previous: Option<&[u8]>,
        current: &[u8],
        offset: usize,
    ) -> Result<(), Error> {
        match previous {
            None => Ok(()),
            Some(prev) => match prev.cmp(current) {
                core::cmp::Ordering::Less => Ok(()),
                core::cmp::Ordering::Equal => Err(Error::new(Kind::Duplicate, offset)),
                core::cmp::Ordering::Greater => Err(Error::new(Kind::NotSorted, offset)),
            },
        }
    }

    /// Consumes the reader, requiring that no bytes remain.
    ///
    /// # Errors
    /// `TrailingBytes` at the current offset if any byte remains.
    pub fn finish(self) -> Result<(), Error> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(self.error(Kind::TrailingBytes))
        }
    }
}
