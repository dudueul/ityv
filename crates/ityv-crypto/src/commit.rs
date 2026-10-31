//! Generalized Pedersen commitments with digit packing (PROTOCOL.md §7.4;
//! ADR-0006).
//!
//! `C_j = val_j(t)·G_val + cast_id·G_id + r_j·H` over Ristretto255, where the
//! three bases are hash-to-group outputs with unknown mutual discrete
//! logarithms. Option `t` of chunk `j` is encoded as `2^(26·(t − 9j))`, so a
//! product of commitments packs per-option counts into 26-bit digits
//! ([`decode_digits`]). The commitment is perfectly hiding: the public
//! board reveals nothing about `t` or `cast_id`, now or ever.

use ityv_encoding::{
    Decode, Encode, Error as EncodingError, ErrorKind, Point32, Reader, Token192, Writer,
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::backend::ristretto::Point;
use crate::error::Error;
use crate::hash::hash_to_group;
use crate::scalar::Scalar;
use crate::verified::Verified;

/// Digit width in bits (`M = 2^26`).
pub const DIGIT_BITS: u32 = 26;
/// Options per chunk.
pub const DIGITS_PER_CHUNK: u16 = 9;
/// Maximum chunks per ballot style (fixed capacity, ADR-0015 §6).
pub const MAX_CHUNKS: usize = 8;
/// Maximum options (`m + 2`) per ballot style (fixed capacity).
pub const MAX_OPTIONS: usize = 64;
/// Label of the value base `G_val`.
pub const LABEL_BASE_VAL: &[u8] = b"ityv:base:val:v1";
/// Label of the identity base `G_id`.
pub const LABEL_BASE_ID: &[u8] = b"ityv:base:id:v1";
/// Label of the randomness base `H`.
pub const LABEL_BASE_RAND: &[u8] = b"ityv:base:rand:v1";

/// An option index `t ∈ [0, MAX_OPTIONS)`. `0` is BLANK, `1..=m` are the
/// candidates, `m + 1` is UNREADABLE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OptionIndex(u16);

impl OptionIndex {
    /// Returns `Some` if `raw < MAX_OPTIONS`.
    #[must_use]
    pub fn new(raw: u16) -> Option<Self> {
        if usize::from(raw) < MAX_OPTIONS {
            Some(Self(raw))
        } else {
            None
        }
    }

    /// The raw index.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// A chunk index `j ∈ [0, MAX_CHUNKS)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChunkIndex(u8);

impl ChunkIndex {
    /// Returns `Some` if `raw < MAX_CHUNKS`.
    #[must_use]
    pub fn new(raw: u8) -> Option<Self> {
        if usize::from(raw) < MAX_CHUNKS {
            Some(Self(raw))
        } else {
            None
        }
    }

    /// The raw index.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// The exponent `26·(t − 9j)` if option `t` belongs to chunk `j`, else
/// `None`.
#[must_use]
pub fn packed_exponent(option: OptionIndex, chunk: ChunkIndex) -> Option<u32> {
    let t = u32::from(option.0);
    let first = u32::from(chunk.0).checked_mul(u32::from(DIGITS_PER_CHUNK))?;
    let position = t.checked_sub(first)?;
    if position >= u32::from(DIGITS_PER_CHUNK) {
        return None;
    }
    position.checked_mul(DIGIT_BITS)
}

/// Sets bit `bit` (little-endian) of a 32-byte integer; a bit beyond 255 is
/// ignored.
pub(crate) fn set_bit(bytes: &mut [u8; 32], bit: u32) {
    let Ok(index) = usize::try_from(bit / 8) else {
        return;
    };
    let mask = 1u8.checked_shl(bit % 8).unwrap_or(0);
    if let Some(byte) = bytes.get_mut(index) {
        *byte |= mask;
    }
}

/// `val_j(t)`: the scalar `2^(26·(t − 9j))` if `t` is in chunk `j`, else
/// zero.
#[must_use]
pub fn packed_value(option: OptionIndex, chunk: ChunkIndex) -> Scalar {
    match packed_exponent(option, chunk) {
        None => Scalar::ZERO,
        Some(exponent) => {
            let mut bytes = [0u8; 32];
            set_bit(&mut bytes, exponent);
            // 2^exponent < 2^209 < ℓ, so this is already canonical.
            Scalar::from_bytes_mod_order(bytes)
        }
    }
}

/// A 192-bit cast identifier, mapped to a scalar as a little-endian integer
/// (`< 2^192 < ℓ`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CastId(Token192);

impl CastId {
    /// Encoded length.
    pub const ENCODED_LEN: usize = 24;

    /// Wraps a token.
    #[must_use]
    pub const fn new(token: Token192) -> Self {
        Self(token)
    }

    /// The token.
    #[must_use]
    pub const fn token(&self) -> Token192 {
        self.0
    }

    /// The scalar `cast_id` as a little-endian integer.
    #[must_use]
    pub fn to_scalar(self) -> Scalar {
        let mut bytes = [0u8; 32];
        if let Some((head, _)) = bytes.split_first_chunk_mut::<24>() {
            *head = self.0.0;
        }
        Scalar::from_bytes_mod_order(bytes)
    }
}

impl Zeroize for CastId {
    fn zeroize(&mut self) {
        self.0.0.zeroize();
    }
}

impl Encode for CastId {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        self.0.encode(w)
    }
}

impl<'a> Decode<'a> for CastId {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        Ok(Self(Token192::decode(r)?))
    }
}

/// The three commitment bases, derived by hash-to-group from fixed labels.
/// Derive once and reuse: derivation costs three hash-to-group evaluations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bases {
    g_val: Point,
    g_id: Point,
    h: Point,
}

impl Bases {
    /// `G_val = HashToGroup("ityv:base:val:v1")`, `G_id = HashToGroup("ityv:base:id:v1")`,
    /// `H = HashToGroup("ityv:base:rand:v1")`.
    #[must_use]
    pub fn derive() -> Self {
        Self {
            g_val: hash_to_group(LABEL_BASE_VAL),
            g_id: hash_to_group(LABEL_BASE_ID),
            h: hash_to_group(LABEL_BASE_RAND),
        }
    }

    /// The compressed encodings of `(G_val, G_id, H)`, for test vectors and
    /// cross-implementation checks.
    #[must_use]
    pub fn compressed(&self) -> [[u8; 32]; 3] {
        [
            self.g_val.compress(),
            self.g_id.compress(),
            self.h.compress(),
        ]
    }

    /// `value·G_val + id·G_id + rand·H`.
    pub(crate) fn pedersen(&self, value: &Scalar, id: &Scalar, rand: &Scalar) -> Point {
        self.g_val
            .mul(value)
            .add(&self.g_id.mul(id))
            .add(&self.h.mul(rand))
    }

    /// `id·G_id + rand·H` (the representation part without the value).
    pub(crate) fn represent(&self, id: &Scalar, rand: &Scalar) -> Point {
        self.g_id.mul(id).add(&self.h.mul(rand))
    }

    /// `value·G_val`.
    pub(crate) fn value_part(&self, value: &Scalar) -> Point {
        self.g_val.mul(value)
    }
}

/// A commitment: a validated compressed Ristretto255 point (VC-026).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Commitment {
    bytes: [u8; 32],
}

impl Commitment {
    /// Encoded length.
    pub const ENCODED_LEN: usize = 32;

    /// Parses a point encoding.
    ///
    /// # Errors
    /// [`Error::InvalidPoint`] if `point` does not decompress.
    pub fn from_point32(point: Point32) -> Result<Self, Error> {
        match Point::decompress(&point.0) {
            Some(_) => Ok(Self { bytes: point.0 }),
            None => Err(Error::InvalidPoint),
        }
    }

    /// The point encoding.
    #[must_use]
    pub const fn to_point32(self) -> Point32 {
        Point32(self.bytes)
    }

    /// The encoded bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub(crate) fn from_point(point: &Point) -> Self {
        Self {
            bytes: point.compress(),
        }
    }

    /// Decompresses. Cannot fail for a value built through the constructors;
    /// the error keeps the function total.
    pub(crate) fn point(&self) -> Result<Point, Error> {
        Point::decompress(&self.bytes).ok_or(Error::InvalidPoint)
    }
}

impl Encode for Commitment {
    fn encoded_len(&self) -> usize {
        Self::ENCODED_LEN
    }

    fn encode(&self, w: &mut Writer<'_>) -> Result<(), EncodingError> {
        w.write_array(&self.bytes)
    }
}

impl<'a> Decode<'a> for Commitment {
    fn decode(r: &mut Reader<'a>) -> Result<Self, EncodingError> {
        let at = r.position();
        let bytes = r.read_array::<32>()?;
        Self::from_point32(Point32(bytes))
            .map_err(|_| EncodingError::new(ErrorKind::ValueOutOfRange, at))
    }
}

/// `C_j = val_j(t)·G_val + cast_id·G_id + r_j·H`.
#[must_use]
pub fn commit(
    bases: &Bases,
    option: OptionIndex,
    cast_id: &CastId,
    rand: &Scalar,
    chunk: ChunkIndex,
) -> Commitment {
    let value = packed_value(option, chunk);
    Commitment::from_point(&bases.pedersen(&value, &cast_id.to_scalar(), rand))
}

/// The opening of a record's commitment vector: the option, the cast
/// identifier and one randomness scalar per chunk. Zeroized on drop.
pub struct Opening {
    option: OptionIndex,
    cast_id: CastId,
    rand: [Scalar; MAX_CHUNKS],
}

impl Opening {
    /// Builds an opening. Entries of `rand` beyond the chunk count are
    /// ignored by [`verify_opening`].
    #[must_use]
    pub const fn new(option: OptionIndex, cast_id: CastId, rand: [Scalar; MAX_CHUNKS]) -> Self {
        Self {
            option,
            cast_id,
            rand,
        }
    }

    /// The option.
    #[must_use]
    pub const fn option(&self) -> OptionIndex {
        self.option
    }

    /// The cast identifier.
    #[must_use]
    pub const fn cast_id(&self) -> &CastId {
        &self.cast_id
    }

    /// The randomness scalars.
    #[must_use]
    pub const fn rand(&self) -> &[Scalar; MAX_CHUNKS] {
        &self.rand
    }
}

impl Drop for Opening {
    fn drop(&mut self) {
        self.cast_id.zeroize();
        self.rand.zeroize();
    }
}

impl ZeroizeOnDrop for Opening {}

impl core::fmt::Debug for Opening {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Opening(..)")
    }
}

/// Checks that `opening` opens every commitment of `commitments` (chunk `j`
/// at index `j`).
///
/// # Errors
/// [`Error::CapacityExceeded`] if there are no commitments or more than
/// `MAX_CHUNKS`; [`Error::OptionOutOfRange`] if the option is beyond the
/// last chunk; [`Error::OpeningInvalid`] if any commitment does not match.
pub fn verify_opening(
    bases: &Bases,
    commitments: &[Commitment],
    opening: &Opening,
) -> Result<Verified<()>, Error> {
    let chunk_count = commitments.len();
    if chunk_count == 0 || chunk_count > MAX_CHUNKS {
        return Err(Error::CapacityExceeded);
    }
    let last = chunk_count.saturating_mul(usize::from(DIGITS_PER_CHUNK));
    if usize::from(opening.option.get()) >= last {
        return Err(Error::OptionOutOfRange);
    }
    let id = opening.cast_id.to_scalar();
    let mut all_match = true;
    for (index, (commitment, rand)) in commitments.iter().zip(opening.rand.iter()).enumerate() {
        let chunk = u8::try_from(index)
            .ok()
            .and_then(ChunkIndex::new)
            .ok_or(Error::ChunkOutOfRange)?;
        let expected = bases.pedersen(&packed_value(opening.option, chunk), &id, rand);
        let matches = bool::from(expected.compress().ct_eq(&commitment.bytes));
        all_match &= matches;
    }
    if all_match {
        Ok(Verified::new(()))
    } else {
        Err(Error::OpeningInvalid)
    }
}

/// The group sum (product in multiplicative notation) of `commitments`.
/// The sum of no commitments is the identity.
///
/// # Errors
/// [`Error::InvalidPoint`] cannot occur for values built through the
/// constructors; it keeps the function total.
pub fn sum_commitments(commitments: &[Commitment]) -> Result<Commitment, Error> {
    let mut total = Point::identity();
    for commitment in commitments {
        total = total.add(&commitment.point()?);
    }
    Ok(Commitment::from_point(&total))
}

/// Checks `total == T·G_val + S·G_id + R·H`, the aggregate opening of a
/// chunk: `T` the packed digit sum, `S` the sum of cast identifiers, `R` the
/// sum of randomness (PROTOCOL.md §11.2).
///
/// # Errors
/// [`Error::AggregateInvalid`] if the equation does not hold.
pub fn verify_aggregate(
    bases: &Bases,
    total: &Commitment,
    packed_sum: &Scalar,
    id_sum: &Scalar,
    rand_sum: &Scalar,
) -> Result<Verified<()>, Error> {
    let expected = bases.pedersen(packed_sum, id_sum, rand_sum);
    if bool::from(expected.compress().ct_eq(&total.bytes)) {
        Ok(Verified::new(()))
    } else {
        Err(Error::AggregateInvalid)
    }
}

/// Reads `count ≤ 32` bits starting at bit `start` (little-endian) of a
/// 32-byte integer. `None` if the range is out of bounds.
#[must_use]
pub fn extract_bits(bytes: &[u8; 32], start: u32, count: u32) -> Option<u32> {
    if count > 32 {
        return None;
    }
    let end = start.checked_add(count)?;
    if end > 256 {
        return None;
    }
    let mut value: u32 = 0;
    for offset in 0..count {
        let bit = start.checked_add(offset)?;
        let byte = *bytes.get(usize::try_from(bit / 8).ok()?)?;
        let bit_value = byte.checked_shr(bit % 8).unwrap_or(0) & 1;
        value |= u32::from(bit_value).checked_shl(offset).unwrap_or(0);
    }
    Some(value)
}

/// `true` if any bit at or above `26 · 9 = 234` is set.
#[must_use]
pub fn has_bits_above_packed_range(bytes: &[u8; 32]) -> bool {
    // Bits 234..=239 live in byte 29 (bits 2..=7); bytes 30 and 31 are
    // entirely above the range.
    let [.., byte29, byte30, byte31] = *bytes;
    (byte29 & 0xFC) != 0 || byte30 != 0 || byte31 != 0
}

/// Splits a chunk's packed digit sum `T_j` into its nine 26-bit digits,
/// digit `d` being the count for option `9j + d`.
///
/// # Errors
/// [`Error::DigitOverflow`] if any bit above the packed range is set, which
/// cannot happen when every digit is below `2^26` (VC-024 is the verifier's
/// separate check that each digit is at most the issued count).
pub fn decode_digits(packed_sum: &Scalar) -> Result<[u32; 9], Error> {
    let bytes = packed_sum.to_bytes();
    if has_bits_above_packed_range(&bytes) {
        return Err(Error::DigitOverflow);
    }
    let mut digits = [0u32; 9];
    for (position, digit) in digits.iter_mut().enumerate() {
        let start = u32::try_from(position)
            .ok()
            .and_then(|p| p.checked_mul(DIGIT_BITS))
            .ok_or(Error::DigitOverflow)?;
        *digit = extract_bits(&bytes, start, DIGIT_BITS).ok_or(Error::DigitOverflow)?;
    }
    Ok(digits)
}
