//! The [`Encode`] and [`Decode`] traits and their implementations for
//! primitives and `Option`.
//!
//! Length-bounded fields (`Bytes`, `Ident`, arrays) need a schema-specific
//! maximum, so they are encoded through the explicit `Reader`/`Writer`
//! methods or through the newtypes in [`crate::primitives`] that fix the
//! bound.

use crate::error::{Error, Kind};
use crate::primitives::{
    BallotStyleId, BoxId, Day, ElectionId, Hash512, KeysetId, LedgerId, ModuleId, ObserverId,
    OrgId, Point32, RouteId, Scalar32, SchemaId, Seq, SignerId, StationId, TimeBucket, Token192,
    TreeSize, TrusteeId,
};
use crate::reader::Reader;
use crate::writer::Writer;

/// A value with exactly one canonical byte representation.
pub trait Encode {
    /// Number of bytes [`Self::encode`] will write.
    ///
    /// Implementations compute this with saturating arithmetic: every schema
    /// bounds its fields far below `usize::MAX`, and a saturated result makes
    /// the subsequent encode fail with `BufferTooSmall` rather than succeed
    /// with a wrong length.
    #[must_use]
    fn encoded_len(&self) -> usize;

    /// Writes the canonical representation.
    ///
    /// # Errors
    /// Any error raised by the writer, typically `BufferTooSmall`.
    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error>;
}

/// A value that can be parsed from its canonical byte representation.
pub trait Decode<'a>: Sized {
    /// Parses the value, consuming exactly its canonical bytes.
    ///
    /// # Errors
    /// Any error raised by the reader, or a schema violation at the offset of
    /// the offending field.
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error>;
}

macro_rules! fixed_int {
    ($t:ty, $len:expr, $write:ident, $read:ident) => {
        impl Encode for $t {
            fn encoded_len(&self) -> usize {
                $len
            }
            fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
                w.$write(*self)
            }
        }
        impl<'a> Decode<'a> for $t {
            fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
                r.$read()
            }
        }
    };
}

fixed_int!(u8, 1, write_u8, read_u8);
fixed_int!(u16, 2, write_u16, read_u16);
fixed_int!(u32, 4, write_u32, read_u32);
fixed_int!(u64, 8, write_u64, read_u64);

impl Encode for bool {
    fn encoded_len(&self) -> usize {
        1
    }
    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_bool(*self)
    }
}

impl<'a> Decode<'a> for bool {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        r.read_bool()
    }
}

macro_rules! fixed_bytes {
    ($t:ident, $len:expr) => {
        impl Encode for $t {
            fn encoded_len(&self) -> usize {
                $len
            }
            fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
                w.write_array(&self.0)
            }
        }
        impl<'a> Decode<'a> for $t {
            fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
                Ok($t(r.read_array::<$len>()?))
            }
        }
    };
}

fixed_bytes!(Hash512, 64);
fixed_bytes!(Scalar32, 32);
fixed_bytes!(Point32, 32);
fixed_bytes!(Token192, 24);

macro_rules! u64_newtype {
    ($t:ident) => {
        impl Encode for $t {
            fn encoded_len(&self) -> usize {
                8
            }
            fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
                w.write_u64(self.get())
            }
        }
        impl<'a> Decode<'a> for $t {
            fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
                Ok($t::new(r.read_u64()?))
            }
        }
    };
}

u64_newtype!(TreeSize);
u64_newtype!(TimeBucket);
u64_newtype!(Day);

impl Encode for SchemaId {
    fn encoded_len(&self) -> usize {
        4
    }
    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_u32(self.get())
    }
}

impl<'a> Decode<'a> for SchemaId {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self::new(r.read_u32()?))
    }
}

impl Encode for Seq {
    fn encoded_len(&self) -> usize {
        8
    }
    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_u64(self.get())
    }
}

impl<'a> Decode<'a> for Seq {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let at = r.position();
        Self::new(r.read_u64()?).ok_or_else(|| Error::new(Kind::ValueOutOfRange, at))
    }
}

macro_rules! ident_newtype_codec {
    ($t:ident) => {
        impl Encode for $t<'_> {
            fn encoded_len(&self) -> usize {
                // 4-byte length prefix plus at most MAX_LEN bytes.
                self.as_bytes().len().saturating_add(4)
            }
            fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
                w.write_ident(&self.ident(), Self::MAX_LEN)
            }
        }
        impl<'a> Decode<'a> for $t<'a> {
            fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
                let at = r.position();
                let ident = r.read_ident(Self::MAX_LEN)?;
                Self::from_ident(ident).ok_or_else(|| Error::new(Kind::LengthExceedsMax, at))
            }
        }
    };
}

ident_newtype_codec!(ElectionId);
ident_newtype_codec!(LedgerId);
ident_newtype_codec!(KeysetId);
ident_newtype_codec!(BoxId);
ident_newtype_codec!(BallotStyleId);
ident_newtype_codec!(StationId);
ident_newtype_codec!(ModuleId);
ident_newtype_codec!(TrusteeId);
ident_newtype_codec!(ObserverId);
ident_newtype_codec!(OrgId);
ident_newtype_codec!(SignerId);
ident_newtype_codec!(RouteId);

impl<T: Encode> Encode for Option<T> {
    fn encoded_len(&self) -> usize {
        match self {
            None => 1,
            Some(inner) => inner.encoded_len().saturating_add(1),
        }
    }
    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        match self {
            None => w.write_presence(false),
            Some(inner) => {
                w.write_presence(true)?;
                inner.encode(w)
            }
        }
    }
}

impl<'a, T: Decode<'a>> Decode<'a> for Option<T> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        if r.read_presence()? {
            Ok(Some(T::decode(r)?))
        } else {
            Ok(None)
        }
    }
}

/// Number of bytes [`encode_slice`] will write for `items`.
#[must_use]
pub fn encoded_len_of_slice<T: Encode>(items: &[T]) -> usize {
    items
        .iter()
        .fold(4usize, |acc, item| acc.saturating_add(item.encoded_len()))
}

/// Writes a count-prefixed array of at most `max` elements.
///
/// Sorted-unique arrays are the schema's responsibility: the schema's own
/// `Encode` implementation guarantees ascending order by construction, and its
/// `Decode` implementation checks it with [`Reader::check_ascending`].
///
/// # Errors
/// `CountExceedsMax` if `items.len() > max`, plus any encoding error.
pub fn encode_slice<T: Encode>(w: &mut Writer<'_>, items: &[T], max: usize) -> Result<(), Error> {
    w.write_count(items.len(), max)?;
    for item in items {
        item.encode(w)?;
    }
    Ok(())
}
