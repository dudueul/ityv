//! Helpers shared by the schema modules: fixed-width borrowed fields,
//! embedded body objects with rebased offsets, and the small bounded arrays
//! that several objects carry.

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::codec::{Decode, Encode};
use crate::envelope::decode as decode_object;
use crate::error::{Error, Kind};
use crate::primitives::{ModuleId, Point32, Scalar32, SchemaId};
use crate::reader::Reader;
use crate::schema::SCHEMA_VERSION_1;
use crate::writer::Writer;

/// Length of one hybrid signature (`mldsa87[4627] ‖ ed25519[64]`).
pub const HYBRID_SIG_LEN: usize = 4691;

/// Length of one Ed25519 signature.
pub const ED25519_SIG_LEN: usize = 64;

/// Length of a Poly1305 or AEAD tag.
pub const TAG_LEN: usize = 16;

/// Maximum number of chamber modules on one scanner: the party modules
/// P1–P4 and J, A, C (ADR-0019; N has none).
pub const MAX_MODULES: usize = 7;

/// Maximum number of commitment chunks (`k`).
pub const MAX_CHUNKS: usize = 8;

/// Reads exactly `N` bytes and borrows them as a fixed array.
///
/// # Errors
/// `UnexpectedEnd` at the field offset if fewer than `N` bytes remain.
pub(crate) fn read_fixed<'a, const N: usize>(r: &mut Reader<'a>) -> Result<&'a [u8; N], Error> {
    let at = r.position();
    let raw = r.take(N)?;
    raw.try_into()
        .map_err(|_| Error::new(Kind::UnexpectedEnd, at))
}

/// Reads a `Bytes<max>` field that must itself be a complete object of
/// `schema`, decodes it, and reports any inner error at its offset within
/// the outer object (the `Bytes` length prefix is four bytes).
///
/// # Errors
/// Any error of the `Bytes` read, or the inner decoding error rebased.
pub(crate) fn decode_embedded<'a, T: Decode<'a>>(
    r: &mut Reader<'a>,
    max: usize,
    schema: SchemaId,
) -> Result<(&'a [u8], T), Error> {
    let at = r.position();
    let bytes = r.read_bytes(max)?;
    let value = decode_object(schema, SCHEMA_VERSION_1, bytes).map_err(|inner| {
        let offset = at
            .checked_add(4)
            .and_then(|p| p.checked_add(inner.offset()))
            .unwrap_or(at);
        Error::new(inner.kind(), offset)
    })?;
    Ok((bytes, value))
}

/// Checks that `bytes` is a complete object of `schema` no longer than
/// `max`, for constructors that take an embedded body.
///
/// # Errors
/// `LengthExceedsMax` at 0 if too long, or the inner decoding error.
pub(crate) fn check_embedded<'a, T: Decode<'a>>(
    bytes: &'a [u8],
    max: usize,
    schema: SchemaId,
) -> Result<T, Error> {
    if bytes.len() > max {
        return Err(Error::new(Kind::LengthExceedsMax, 0));
    }
    decode_object(schema, SCHEMA_VERSION_1, bytes)
}

/// Checks that `items` is strictly ascending in byte order under `key`.
pub(crate) fn ascending_by<T>(items: &[T], key: impl Fn(&T) -> &[u8]) -> bool {
    items.windows(2).all(|pair| match pair {
        [a, b] => key(a) < key(b),
        _ => true,
    })
}

/// A commitment vector `C_0..C_{k−1}`: `Array<Point, 8>` with `k >= 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Commitments {
    items: [Point32; MAX_CHUNKS],
    count: u8,
}

impl Commitments {
    /// Builds a vector of `1..=8` points.
    #[must_use]
    pub fn new(points: &[Point32]) -> Option<Self> {
        if points.is_empty() || points.len() > MAX_CHUNKS {
            return None;
        }
        let mut items = [Point32([0; 32]); MAX_CHUNKS];
        for (slot, point) in items.iter_mut().zip(points) {
            *slot = *point;
        }
        Some(Self {
            items,
            count: u8::try_from(points.len()).ok()?,
        })
    }

    /// The points, `1..=8` of them.
    #[must_use]
    pub fn as_slice(&self) -> &[Point32] {
        self.items.get(..usize::from(self.count)).unwrap_or(&[])
    }

    /// Number of chunks `k`.
    #[must_use]
    pub const fn chunk_count(&self) -> u8 {
        self.count
    }
}

impl Encode for Commitments {
    fn encoded_len(&self) -> usize {
        usize::from(self.count).saturating_mul(32).saturating_add(4)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_count(usize::from(self.count), MAX_CHUNKS)?;
        for point in self.as_slice() {
            point.encode(w)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for Commitments {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let at = r.position();
        let count = r.read_count(MAX_CHUNKS)?;
        if count == 0 {
            return Err(Error::new(Kind::ValueOutOfRange, at));
        }
        let mut items = [Point32([0; 32]); MAX_CHUNKS];
        for slot in items.iter_mut().take(count) {
            *slot = Point32::decode(r)?;
        }
        Ok(Self {
            items,
            // `count <= 8` after `read_count`.
            count: u8::try_from(count).map_err(|_| Error::new(Kind::CountExceedsMax, at))?,
        })
    }
}

/// A bounded scalar vector: `Array<Scalar, N>`.
///
/// Every use holds secret values (a challenge opening's randomness before
/// it is published, a member's shares), so the vector is neither `Clone`
/// nor `Copy`, its `Debug` output shows only the count, and it is zeroized
/// on drop. [`Self::duplicate`] makes an explicit copy, itself zeroized on
/// drop.
#[derive(PartialEq, Eq, Hash)]
pub struct Scalars<const N: usize> {
    items: [Scalar32; N],
    count: u8,
}

impl<const N: usize> Scalars<N> {
    /// An empty vector.
    pub(crate) const fn empty() -> Self {
        Self {
            items: [Scalar32([0; 32]); N],
            count: 0,
        }
    }

    /// Builds a vector of at most `N` scalars.
    #[must_use]
    pub fn new(scalars: &[Scalar32]) -> Option<Self> {
        if scalars.len() > N {
            return None;
        }
        let count = u8::try_from(scalars.len()).ok()?;
        let mut out = Self::empty();
        for (slot, scalar) in out.items.iter_mut().zip(scalars) {
            *slot = *scalar;
        }
        out.count = count;
        Some(out)
    }

    /// An explicit copy (zeroized on drop like the original).
    #[must_use]
    pub fn duplicate(&self) -> Self {
        Self {
            items: self.items,
            count: self.count,
        }
    }

    /// The scalars.
    #[must_use]
    pub fn as_slice(&self) -> &[Scalar32] {
        self.items.get(..usize::from(self.count)).unwrap_or(&[])
    }

    /// Number of scalars.
    #[must_use]
    pub const fn count(&self) -> u8 {
        self.count
    }
}

impl<const N: usize> Encode for Scalars<N> {
    fn encoded_len(&self) -> usize {
        usize::from(self.count).saturating_mul(32).saturating_add(4)
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_count(usize::from(self.count), N)?;
        for scalar in self.as_slice() {
            scalar.encode(w)?;
        }
        Ok(())
    }
}

impl<'a, const N: usize> Decode<'a> for Scalars<N> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let at = r.position();
        let count = r.read_count(N)?;
        // Filled in place: an error drops (and wipes) what was read.
        let mut out = Self::empty();
        for slot in out.items.iter_mut().take(count) {
            *slot = Scalar32::decode(r)?;
        }
        out.count = u8::try_from(count).map_err(|_| Error::new(Kind::CountExceedsMax, at))?;
        Ok(out)
    }
}

impl<const N: usize> Zeroize for Scalars<N> {
    fn zeroize(&mut self) {
        for scalar in &mut self.items {
            scalar.0.zeroize();
        }
        self.count.zeroize();
    }
}

impl<const N: usize> Drop for Scalars<N> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<const N: usize> ZeroizeOnDrop for Scalars<N> {}

impl<const N: usize> fmt::Debug for Scalars<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scalars")
            .field("count", &self.count)
            .finish_non_exhaustive()
    }
}

/// One `(module_id, u64)` pair of a module-counter array.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModuleCounter<'a> {
    /// The module.
    pub module_id: ModuleId<'a>,
    /// The counter value (meaning depends on the enclosing object).
    pub counter: u64,
}

/// `Array<{module_id: Ident<64>, counter: u64}, 6>`, ascending by
/// `module_id`, no duplicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModuleCounters<'a> {
    items: [Option<ModuleCounter<'a>>; MAX_MODULES],
    count: u8,
}

impl<'a> ModuleCounters<'a> {
    /// Builds the array; `None` unless the entries are strictly ascending
    /// by identifier and at most six.
    #[must_use]
    pub fn new(entries: &[ModuleCounter<'a>]) -> Option<Self> {
        if entries.len() > MAX_MODULES {
            return None;
        }
        let ok = ascending_by(entries, |x| x.module_id.as_bytes());
        if !ok {
            return None;
        }
        let mut items = [None; MAX_MODULES];
        for (slot, entry) in items.iter_mut().zip(entries) {
            *slot = Some(*entry);
        }
        Some(Self {
            items,
            count: u8::try_from(entries.len()).ok()?,
        })
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.count)
    }

    /// Returns `true` if there are no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterates over the entries in ascending identifier order.
    pub fn iter(&self) -> impl Iterator<Item = ModuleCounter<'a>> + '_ {
        self.items.iter().take(self.len()).flatten().copied()
    }

    /// Returns the counter recorded for `module_id`, if present.
    #[must_use]
    pub fn get(&self, module_id: ModuleId<'_>) -> Option<u64> {
        self.iter()
            .find(|e| e.module_id.as_bytes() == module_id.as_bytes())
            .map(|e| e.counter)
    }

    /// Returns `true` if the identifier sets of `self` and `other` are
    /// equal (both are sorted and unique, so the sequences must match).
    #[must_use]
    pub fn same_ids<I>(&self, other: I) -> bool
    where
        I: IntoIterator<Item = ModuleId<'a>>,
    {
        let mut other = other.into_iter();
        for entry in self.iter() {
            match other.next() {
                Some(id) if id.as_bytes() == entry.module_id.as_bytes() => {}
                _ => return false,
            }
        }
        other.next().is_none()
    }
}

impl Encode for ModuleCounters<'_> {
    fn encoded_len(&self) -> usize {
        self.iter().fold(4usize, |acc, e| {
            acc.saturating_add(e.module_id.encoded_len())
                .saturating_add(8)
        })
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_count(self.len(), MAX_MODULES)?;
        for entry in self.iter() {
            entry.module_id.encode(w)?;
            w.write_u64(entry.counter)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for ModuleCounters<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let at = r.position();
        let count = r.read_count(MAX_MODULES)?;
        let mut items = [None; MAX_MODULES];
        let mut previous: Option<&[u8]> = None;
        for slot in items.iter_mut().take(count) {
            let id_at = r.position();
            let module_id = ModuleId::decode(r)?;
            Reader::check_ascending(previous, module_id.as_bytes(), id_at)?;
            previous = Some(module_id.as_bytes());
            let counter = r.read_u64()?;
            *slot = Some(ModuleCounter { module_id, counter });
        }
        Ok(Self {
            items,
            count: u8::try_from(count).map_err(|_| Error::new(Kind::CountExceedsMax, at))?,
        })
    }
}

/// `Array<Ident<64>, 6>` of module identifiers, ascending, no duplicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModuleIds<'a> {
    items: [Option<ModuleId<'a>>; MAX_MODULES],
    count: u8,
}

impl<'a> ModuleIds<'a> {
    /// Builds the set; `None` unless strictly ascending and at most six.
    #[must_use]
    pub fn new(ids: &[ModuleId<'a>]) -> Option<Self> {
        if ids.len() > MAX_MODULES {
            return None;
        }
        let ok = ascending_by(ids, |x| x.as_bytes());
        if !ok {
            return None;
        }
        let mut items = [None; MAX_MODULES];
        for (slot, id) in items.iter_mut().zip(ids) {
            *slot = Some(*id);
        }
        Some(Self {
            items,
            count: u8::try_from(ids.len()).ok()?,
        })
    }

    /// Number of identifiers.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.count)
    }

    /// Returns `true` if the set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Iterates in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = ModuleId<'a>> + '_ {
        self.items.iter().take(self.len()).flatten().copied()
    }

    /// Returns `true` if `module_id` is in the set.
    #[must_use]
    pub fn contains(&self, module_id: ModuleId<'_>) -> bool {
        self.iter().any(|id| id.as_bytes() == module_id.as_bytes())
    }
}

impl Encode for ModuleIds<'_> {
    fn encoded_len(&self) -> usize {
        self.iter()
            .fold(4usize, |acc, id| acc.saturating_add(id.encoded_len()))
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), Error> {
        w.write_count(self.len(), MAX_MODULES)?;
        for id in self.iter() {
            id.encode(w)?;
        }
        Ok(())
    }
}

impl<'a> Decode<'a> for ModuleIds<'a> {
    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let at = r.position();
        let count = r.read_count(MAX_MODULES)?;
        let mut items = [None; MAX_MODULES];
        let mut previous: Option<&[u8]> = None;
        for slot in items.iter_mut().take(count) {
            let id_at = r.position();
            let id = ModuleId::decode(r)?;
            Reader::check_ascending(previous, id.as_bytes(), id_at)?;
            previous = Some(id.as_bytes());
            *slot = Some(id);
        }
        Ok(Self {
            items,
            count: u8::try_from(count).map_err(|_| Error::new(Kind::CountExceedsMax, at))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars_zeroize_wipes_every_item() {
        let mut s = Scalars::<8>::new(&[Scalar32([9; 32]); 8]).expect("eight fit");
        s.count = 1;
        s.zeroize();
        assert!(s.items.iter().all(|x| x.0 == [0; 32]));
        assert_eq!(s.count, 0);
    }
}
