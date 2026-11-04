//! The strict DER reader: the subset of X.690 DER that RFC 3161 tokens need.
//!
//! - Tags are one octet (tag numbers 0–30). Lengths are definite and in the
//!   shortest form, at most two length octets (a value of at most 65535
//!   octets, more than any bounded token holds).
//! - Every read is bounded by the enclosing value and returns `Result`; a
//!   constructed value is read by a child [`Reader`] one level deeper, and no
//!   reader goes deeper than [`MAX_DEPTH`].
//! - Primitive values follow the DER rules for their type: `BOOLEAN` is
//!   `0x00` or `0xFF`, `INTEGER` is minimal, `NULL` is empty, `OBJECT
//!   IDENTIFIER` arcs are minimal and complete, `BIT STRING` padding is zero.
//!   `SET` and `SET OF` elements are in ascending order of their encodings
//!   (for distinct tags this is also the canonical tag order of a `SET`).
//! - Callers finish every reader, so every `SEQUENCE` is consumed exactly.
//!
//! [`check_contents`] applies the same rules to a value the structure does
//! not interpret (a name, an unknown attribute), so nothing in an accepted
//! token escapes the subset. Nothing here recurses.

use crate::error::DerError;

/// The deepest nesting of constructed elements the reader enters.
///
/// A token's own structure is at most about twenty levels deep (a name
/// inside an ESS `issuerSerial` inside a signed attribute); the rest is
/// margin for unsigned attributes. The limit also bounds the explicit stack
/// of the reader's whole-tree check, which does not recurse.
pub const MAX_DEPTH: u8 = 32;

/// The longest `OBJECT IDENTIFIER` content accepted, in octets.
pub const MAX_OID_LEN: usize = 64;

pub(crate) const BOOLEAN: u8 = 0x01;
pub(crate) const INTEGER: u8 = 0x02;
pub(crate) const BIT_STRING: u8 = 0x03;
pub(crate) const OCTET_STRING: u8 = 0x04;
pub(crate) const NULL: u8 = 0x05;
pub(crate) const OID: u8 = 0x06;
pub(crate) const UTC_TIME: u8 = 0x17;
pub(crate) const GENERALIZED_TIME: u8 = 0x18;
pub(crate) const SEQUENCE: u8 = 0x30;
pub(crate) const SET: u8 = 0x31;
/// `[0]`, `[1]`, … constructed (explicit tags, implicit `SET OF`/`SEQUENCE`).
pub(crate) const CONTEXT_0: u8 = 0xA0;
pub(crate) const CONTEXT_1: u8 = 0xA1;
pub(crate) const CONTEXT_3: u8 = 0xA3;
pub(crate) const CONTEXT_4: u8 = 0xA4;
/// `[0]`, `[1]` primitive (implicit `INTEGER`, `OCTET STRING`).
pub(crate) const PRIMITIVE_0: u8 = 0x80;
pub(crate) const PRIMITIVE_1: u8 = 0x81;

const CONSTRUCTED_BIT: u8 = 0x20;
const CLASS_MASK: u8 = 0xC0;
const NUMBER_MASK: u8 = 0x1F;

/// One element: its tag, its value octets and its whole encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tlv<'a> {
    pub(crate) tag: u8,
    pub(crate) value: &'a [u8],
    pub(crate) raw: &'a [u8],
}

impl Tlv<'_> {
    const fn is_constructed(&self) -> bool {
        self.tag & CONSTRUCTED_BIT != 0
    }
}

/// Reads one element from the front of `input`, checking only its header.
///
/// Returns the element and the bytes after it.
pub(crate) fn parse_tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), DerError> {
    let (&tag, after_tag) = input.split_first().ok_or(DerError::Truncated)?;
    if tag & NUMBER_MASK == NUMBER_MASK {
        return Err(DerError::HighTagNumber);
    }
    let (&first, after_first) = after_tag.split_first().ok_or(DerError::Truncated)?;
    let (len, body) = match first {
        0x00..=0x7F => (usize::from(first), after_first),
        0x80 => return Err(DerError::IndefiniteLength),
        0x81 => {
            let (&octet, body) = after_first.split_first().ok_or(DerError::Truncated)?;
            if octet < 0x80 {
                return Err(DerError::NonMinimalLength);
            }
            (usize::from(octet), body)
        }
        0x82 => {
            let (octets, body) = after_first
                .split_first_chunk::<2>()
                .ok_or(DerError::Truncated)?;
            let value = u16::from_be_bytes(*octets);
            if value < 0x100 {
                return Err(DerError::NonMinimalLength);
            }
            (usize::from(value), body)
        }
        0x83..=0xFF => return Err(DerError::LengthTooLarge),
    };
    let (value, rest) = body.split_at_checked(len).ok_or(DerError::Truncated)?;
    // `rest` is a suffix of `input`, so the subtraction cannot underflow.
    let total = input
        .len()
        .checked_sub(rest.len())
        .ok_or(DerError::Truncated)?;
    let raw = input.get(..total).ok_or(DerError::Truncated)?;
    Ok((Tlv { tag, value, raw }, rest))
}

/// A cursor over the elements of one value.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Reader<'a> {
    rest: &'a [u8],
    depth: u8,
}

impl<'a> Reader<'a> {
    /// A reader over a complete encoding (depth 0).
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self {
            rest: input,
            depth: 0,
        }
    }

    pub(crate) const fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    pub(crate) fn peek_tag(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    /// Reads the next element, whatever its tag.
    pub(crate) fn read_any(&mut self) -> Result<Tlv<'a>, DerError> {
        let (tlv, rest) = parse_tlv(self.rest)?;
        self.rest = rest;
        Ok(tlv)
    }

    /// Reads the next element, which must have `tag`.
    pub(crate) fn read(&mut self, tag: u8) -> Result<Tlv<'a>, DerError> {
        match self.peek_tag() {
            None => Err(DerError::MissingField),
            Some(found) if found == tag => self.read_any(),
            Some(_) => Err(DerError::UnexpectedTag),
        }
    }

    /// Reads the next element if it has `tag`.
    pub(crate) fn optional(&mut self, tag: u8) -> Result<Option<Tlv<'a>>, DerError> {
        if self.peek_tag() == Some(tag) {
            self.read_any().map(Some)
        } else {
            Ok(None)
        }
    }

    /// A reader over the value of `tlv`, a constructed element read from this
    /// reader, one level deeper.
    pub(crate) fn enter(&self, tlv: &Tlv<'a>) -> Result<Reader<'a>, DerError> {
        let depth = self
            .depth
            .checked_add(1)
            .filter(|depth| *depth <= MAX_DEPTH)
            .ok_or(DerError::DepthExceeded)?;
        Ok(Reader {
            rest: tlv.value,
            depth,
        })
    }

    /// Reads the next element, which must have the constructed `tag`, and
    /// returns a reader over its value.
    pub(crate) fn nested(&mut self, tag: u8) -> Result<Reader<'a>, DerError> {
        let tlv = self.read(tag)?;
        self.enter(&tlv)
    }

    /// Reads a `SEQUENCE` and returns a reader over its value.
    pub(crate) fn sequence(&mut self) -> Result<Reader<'a>, DerError> {
        self.nested(SEQUENCE)
    }

    /// Reads a `SET` or `SET OF` (or an implicitly tagged one), checks the
    /// DER order of its elements, and returns a reader over its value.
    pub(crate) fn set(&mut self, tag: u8) -> Result<Reader<'a>, DerError> {
        let tlv = self.read(tag)?;
        self.enter_set(&tlv)
    }

    /// [`Reader::enter`] for a `SET` or `SET OF` value, after checking the
    /// DER order of its elements.
    pub(crate) fn enter_set(&self, tlv: &Tlv<'a>) -> Result<Reader<'a>, DerError> {
        check_set_order(tlv.value)?;
        self.enter(tlv)
    }

    /// Reads an `OBJECT IDENTIFIER` and returns its content octets.
    pub(crate) fn oid(&mut self) -> Result<&'a [u8], DerError> {
        let tlv = self.read(OID)?;
        check_oid(tlv.value)?;
        Ok(tlv.value)
    }

    /// Reads a non-negative `INTEGER` and returns its magnitude octets (see
    /// [`unsigned`]).
    pub(crate) fn unsigned(&mut self) -> Result<&'a [u8], DerError> {
        let tlv = self.read(INTEGER)?;
        unsigned(tlv.value)
    }

    /// Reads an `OCTET STRING` and returns its content.
    pub(crate) fn octets(&mut self) -> Result<&'a [u8], DerError> {
        self.read(OCTET_STRING).map(|tlv| tlv.value)
    }

    /// Reads the next element and checks it against the subset (see [`check_element`]).
    pub(crate) fn checked_any(&mut self) -> Result<Tlv<'a>, DerError> {
        let tlv = self.read_any()?;
        check_element(self, &tlv)?;
        Ok(tlv)
    }

    /// Reads the next element, which must have `tag`, and checks it against the subset.
    pub(crate) fn checked(&mut self, tag: u8) -> Result<Tlv<'a>, DerError> {
        let tlv = self.read(tag)?;
        check_element(self, &tlv)?;
        Ok(tlv)
    }

    /// Ends the reader: every byte of its value must have been read.
    pub(crate) const fn finish(&self) -> Result<(), DerError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(DerError::TrailingData)
        }
    }
}

/// Reads a complete encoding that is exactly one element with `tag` and
/// returns a reader over its value.
pub(crate) fn single(input: &[u8], tag: u8) -> Result<Reader<'_>, DerError> {
    let mut outer = Reader::new(input);
    let inner = outer.nested(tag)?;
    outer.finish()?;
    Ok(inner)
}

/// Checks that the elements of a `SET` value are in ascending DER order.
///
/// Two complete encodings are never a proper prefix of each other, so plain
/// lexicographic order is the X.690 §11.6 order. Equal neighbours are
/// allowed (a `SET OF` may repeat a value).
fn check_set_order(value: &[u8]) -> Result<(), DerError> {
    let mut rest = value;
    let mut previous: Option<&[u8]> = None;
    while !rest.is_empty() {
        let (tlv, after) = parse_tlv(rest)?;
        if previous.is_some_and(|previous| previous > tlv.raw) {
            return Err(DerError::SetNotSorted);
        }
        previous = Some(tlv.raw);
        rest = after;
    }
    Ok(())
}

/// The readers [`check_contents`] can hold at once: one per level from the
/// reader it starts with down to [`MAX_DEPTH`].
const STACK: usize = MAX_DEPTH as usize + 1;

/// Checks that every element left in `reader` is in the subset, and every
/// element nested in those, without recursion: an explicit stack of
/// readers, one per open constructed value, bounded by [`MAX_DEPTH`].
pub(crate) fn check_contents(reader: Reader<'_>) -> Result<(), DerError> {
    let mut stack = [Reader::new(&[]); STACK];
    let mut top = 0usize;
    *stack.get_mut(top).ok_or(DerError::DepthExceeded)? = reader;
    loop {
        let current = stack.get_mut(top).ok_or(DerError::DepthExceeded)?;
        if current.is_empty() {
            match top.checked_sub(1) {
                Some(below) => top = below,
                None => return Ok(()),
            }
            continue;
        }
        let tlv = current.read_any()?;
        if let Some(child) = check_one(current, &tlv)? {
            // `enter` bounds the depth, so the stack index stays below STACK.
            top = top.checked_add(1).ok_or(DerError::DepthExceeded)?;
            *stack.get_mut(top).ok_or(DerError::DepthExceeded)? = child;
        }
    }
}

/// Checks one element read from `parent` against the subset: the tag form,
/// the content rules of the universal primitive types this crate knows, the
/// order of a `SET`, and every nested element of a constructed value.
///
/// Context-specific and application primitive values, strings and times
/// are opaque octets here; the structure that uses them checks them.
pub(crate) fn check_element(parent: &Reader<'_>, tlv: &Tlv<'_>) -> Result<(), DerError> {
    match check_one(parent, tlv)? {
        Some(child) => check_contents(child),
        None => Ok(()),
    }
}

/// [`check_element`] for the element itself. Returns a reader over the
/// value of a constructed element, whose contents the caller checks.
fn check_one<'a>(parent: &Reader<'a>, tlv: &Tlv<'a>) -> Result<Option<Reader<'a>>, DerError> {
    let universal = tlv.tag & CLASS_MASK == 0;
    let number = tlv.tag & NUMBER_MASK;
    if tlv.is_constructed() {
        if universal && number != 0x10 && number != 0x11 {
            return Err(DerError::InvalidTagForm);
        }
        if tlv.tag == SET {
            check_set_order(tlv.value)?;
        }
        return parent.enter(tlv).map(Some);
    }
    if universal {
        match number {
            0x00 | 0x10 | 0x11 => return Err(DerError::InvalidTagForm),
            0x01 => {
                boolean(tlv.value)?;
            }
            0x02 => {
                integer(tlv.value)?;
            }
            0x03 => check_bit_string(tlv.value)?,
            0x05 => null(tlv.value)?,
            0x06 => check_oid(tlv.value)?,
            _ => {}
        }
    }
    Ok(None)
}

/// A `BOOLEAN` value: `0xFF` is true, `0x00` is false, anything else is refused.
pub(crate) fn boolean(value: &[u8]) -> Result<bool, DerError> {
    match value {
        [0xFF] => Ok(true),
        [0x00] => Ok(false),
        _ => Err(DerError::InvalidBoolean),
    }
}

/// A `NULL` value: no content octets.
pub(crate) const fn null(value: &[u8]) -> Result<(), DerError> {
    if value.is_empty() {
        Ok(())
    } else {
        Err(DerError::InvalidNull)
    }
}

/// An `INTEGER` value of either sign in minimal two's complement form.
///
/// Returns `true` if the value is negative.
pub(crate) fn integer(value: &[u8]) -> Result<bool, DerError> {
    match value {
        [] => Err(DerError::EmptyInteger),
        [0x00, next, ..] if *next < 0x80 => Err(DerError::NonMinimalInteger),
        [0xFF, next, ..] if *next >= 0x80 => Err(DerError::NonMinimalInteger),
        [first, ..] => Ok(*first >= 0x80),
    }
}

/// A non-negative `INTEGER` value. Returns its magnitude: the content octets
/// without the leading sign octet `0x00`, so the first octet (if any) is
/// non-zero and zero is the empty slice.
pub(crate) fn unsigned(value: &[u8]) -> Result<&[u8], DerError> {
    if integer(value)? {
        return Err(DerError::NegativeInteger);
    }
    match value.split_first() {
        Some((0x00, magnitude)) => Ok(magnitude),
        Some(_) | None => Ok(value),
    }
}

/// A non-negative `INTEGER` value that fits in a `u64`.
pub(crate) fn small_unsigned(value: &[u8]) -> Result<u64, DerError> {
    let magnitude = unsigned(value)?;
    if magnitude.len() > 8 {
        return Err(DerError::IntegerTooLarge);
    }
    let mut result = 0u64;
    for &octet in magnitude {
        // At most eight octets, so the shifted value never leaves the u64.
        result = result
            .checked_shl(8)
            .ok_or(DerError::IntegerTooLarge)?
            .checked_add(u64::from(octet))
            .ok_or(DerError::IntegerTooLarge)?;
    }
    Ok(result)
}

/// The content of an `OBJECT IDENTIFIER`: non-empty, at most
/// [`MAX_OID_LEN`] octets, every arc in minimal base-128 form (no leading
/// `0x80` octet) and the last arc complete.
pub(crate) fn check_oid(value: &[u8]) -> Result<(), DerError> {
    if value.is_empty() || value.len() > MAX_OID_LEN {
        return Err(DerError::InvalidOid);
    }
    let mut arc_start = true;
    for &octet in value {
        if arc_start && octet == 0x80 {
            return Err(DerError::InvalidOid);
        }
        arc_start = octet < 0x80;
    }
    if arc_start {
        Ok(())
    } else {
        Err(DerError::InvalidOid)
    }
}

/// A `BIT STRING` value: at most seven unused bits, none in an empty
/// string, and zero padding bits.
pub(crate) fn check_bit_string(value: &[u8]) -> Result<(), DerError> {
    let (&unused, octets) = value.split_first().ok_or(DerError::InvalidBitString)?;
    let padding_ok = match octets.last() {
        None => unused == 0,
        Some(&last) => {
            unused <= 7
                && 1u8
                    .checked_shl(u32::from(unused))
                    .and_then(|bit| bit.checked_sub(1))
                    .is_some_and(|mask| last & mask == 0)
        }
    };
    if padding_ok {
        Ok(())
    } else {
        Err(DerError::InvalidBitString)
    }
}

/// A `BIT STRING` value of whole octets (no unused bits). Returns the octets.
pub(crate) fn bit_string_octets(value: &[u8]) -> Result<&[u8], DerError> {
    match value.split_first() {
        Some((0x00, octets)) => Ok(octets),
        Some(_) | None => Err(DerError::InvalidBitString),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    fn tlv(input: &[u8]) -> Result<Tlv<'_>, DerError> {
        parse_tlv(input).map(|(tlv, _)| tlv)
    }

    #[test]
    fn short_and_long_lengths() {
        let short = [0x04, 0x7F];
        let mut long = [0u8; 3 + 0x80];
        long[..3].copy_from_slice(&[0x04, 0x81, 0x80]);
        let parsed = tlv(&long).unwrap();
        assert_eq!(parsed.value.len(), 0x80);
        assert_eq!(parsed.raw.len(), long.len());
        assert_eq!(tlv(&short), Err(DerError::Truncated));

        let mut two = vec![0x04, 0x82, 0x01, 0x00];
        two.resize(4 + 0x100, 0xAA);
        let parsed = tlv(&two).unwrap();
        assert_eq!(parsed.value.len(), 0x100);
        assert_eq!(parsed.raw, &two[..]);
        two.push(0x05);
        let (parsed, rest) = parse_tlv(&two).unwrap();
        assert_eq!(parsed.raw.len(), 4 + 0x100);
        assert_eq!(rest, &[0x05]);
    }

    #[test]
    fn length_rules() {
        assert_eq!(
            tlv(&[0x04, 0x80, 0x00, 0x00]),
            Err(DerError::IndefiniteLength)
        );
        assert_eq!(tlv(&[0x04, 0x81, 0x7F]), Err(DerError::NonMinimalLength));
        assert_eq!(
            tlv(&[0x04, 0x82, 0x00, 0xFF]),
            Err(DerError::NonMinimalLength)
        );
        assert_eq!(
            tlv(&[0x04, 0x83, 0x00, 0x01, 0x00]),
            Err(DerError::LengthTooLarge)
        );
        assert_eq!(tlv(&[0x04, 0xFF]), Err(DerError::LengthTooLarge));
        assert_eq!(tlv(&[0x04, 0x81]), Err(DerError::Truncated));
        assert_eq!(tlv(&[0x04, 0x82, 0x01]), Err(DerError::Truncated));
        assert_eq!(tlv(&[0x04]), Err(DerError::Truncated));
        assert_eq!(tlv(&[]), Err(DerError::Truncated));
        assert_eq!(tlv(&[0x1F, 0x00]), Err(DerError::HighTagNumber));
        assert_eq!(tlv(&[0x3F, 0x00]), Err(DerError::HighTagNumber));
        assert_eq!(tlv(&[0x1E, 0x00]).unwrap().tag, 0x1E);
        assert!(tlv(&[0x04, 0x00]).unwrap().value.is_empty());
    }

    #[test]
    fn reader_tags_and_finish() {
        let input = [0x02, 0x01, 0x05, 0x05, 0x00];
        let mut reader = Reader::new(&input);
        assert_eq!(reader.read(0x04), Err(DerError::UnexpectedTag));
        assert_eq!(reader.optional(0x04), Ok(None));
        assert_eq!(reader.finish(), Err(DerError::TrailingData));
        assert_eq!(reader.unsigned(), Ok(&[0x05][..]));
        assert_eq!(reader.optional(NULL).unwrap().unwrap().raw, &[0x05, 0x00]);
        assert!(reader.is_empty());
        assert_eq!(reader.finish(), Ok(()));
        assert_eq!(reader.read(NULL), Err(DerError::MissingField));
        assert_eq!(reader.peek_tag(), None);
    }

    #[test]
    fn depth_limit() {
        // MAX_DEPTH + 1 nested SEQUENCEs, innermost empty.
        let levels = usize::from(MAX_DEPTH) + 1;
        let mut nested = Vec::new();
        for _ in 0..levels {
            let mut outer = vec![0x30, u8::try_from(nested.len()).unwrap()];
            outer.extend_from_slice(&nested);
            nested = outer;
        }
        assert_eq!(
            check_contents(Reader::new(&nested)),
            Err(DerError::DepthExceeded)
        );
        // One level less is fine.
        assert_eq!(check_contents(Reader::new(&nested[2..])), Ok(()));
        let mut reader = Reader::new(&nested);
        for _ in 0..MAX_DEPTH {
            reader = reader.sequence().unwrap();
        }
        assert_eq!(reader.sequence().err(), Some(DerError::DepthExceeded));
    }

    #[test]
    fn primitive_rules() {
        assert_eq!(boolean(&[0xFF]), Ok(true));
        assert_eq!(boolean(&[0x00]), Ok(false));
        assert_eq!(boolean(&[0x01]), Err(DerError::InvalidBoolean));
        assert_eq!(boolean(&[]), Err(DerError::InvalidBoolean));
        assert_eq!(boolean(&[0xFF, 0x00]), Err(DerError::InvalidBoolean));
        assert_eq!(null(&[]), Ok(()));
        assert_eq!(null(&[0x00]), Err(DerError::InvalidNull));

        assert_eq!(integer(&[]), Err(DerError::EmptyInteger));
        assert_eq!(integer(&[0x00]), Ok(false));
        assert_eq!(integer(&[0x7F]), Ok(false));
        assert_eq!(integer(&[0x80]), Ok(true));
        assert_eq!(integer(&[0xFF]), Ok(true));
        assert_eq!(integer(&[0x00, 0x7F]), Err(DerError::NonMinimalInteger));
        assert_eq!(integer(&[0x00, 0x80]), Ok(false));
        assert_eq!(integer(&[0xFF, 0x80]), Err(DerError::NonMinimalInteger));
        assert_eq!(integer(&[0xFF, 0x7F]), Ok(true));
        assert_eq!(unsigned(&[0x00]), Ok(&[][..]));
        assert_eq!(unsigned(&[0x00, 0x80]), Ok(&[0x80][..]));
        assert_eq!(unsigned(&[0x01, 0x00]), Ok(&[0x01, 0x00][..]));
        assert_eq!(unsigned(&[0x80]), Err(DerError::NegativeInteger));
        assert_eq!(small_unsigned(&[0x01, 0x02]), Ok(0x0102));
        assert_eq!(small_unsigned(&[0x00]), Ok(0));
        assert_eq!(
            small_unsigned(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            Ok(u64::MAX)
        );
        assert_eq!(
            small_unsigned(&[0x01, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(DerError::IntegerTooLarge)
        );

        assert_eq!(check_oid(&[0x2A, 0x86, 0x48]), Ok(()));
        assert_eq!(check_oid(&[]), Err(DerError::InvalidOid));
        assert_eq!(check_oid(&[0x2A, 0x86]), Err(DerError::InvalidOid));
        assert_eq!(check_oid(&[0x2A, 0x80, 0x01]), Err(DerError::InvalidOid));
        assert_eq!(check_oid(&[0x80, 0x01]), Err(DerError::InvalidOid));
        assert_eq!(
            check_oid(&[0x2A, 0x01, 0x80, 0x01]),
            Err(DerError::InvalidOid)
        );
        assert_eq!(check_oid(&[0x2A, 0x81, 0x80, 0x01]), Ok(()));
        // 0x80 inside an arc continues it, so the arc is incomplete.
        assert_eq!(check_oid(&[0x2A, 0x81, 0x80]), Err(DerError::InvalidOid));
        assert_eq!(check_oid(&[0x01; MAX_OID_LEN]), Ok(()));
        assert_eq!(
            check_oid(&[0x01; MAX_OID_LEN + 1]),
            Err(DerError::InvalidOid)
        );

        assert_eq!(check_bit_string(&[0x00]), Ok(()));
        assert_eq!(check_bit_string(&[]), Err(DerError::InvalidBitString));
        assert_eq!(check_bit_string(&[0x01]), Err(DerError::InvalidBitString));
        assert_eq!(check_bit_string(&[0x07, 0x80]), Ok(()));
        assert_eq!(
            check_bit_string(&[0x07, 0x81]),
            Err(DerError::InvalidBitString)
        );
        assert_eq!(check_bit_string(&[0x06, 0xC0]), Ok(()));
        assert_eq!(
            check_bit_string(&[0x06, 0xC2]),
            Err(DerError::InvalidBitString)
        );
        assert_eq!(check_bit_string(&[0x01, 0x02]), Ok(()));
        assert_eq!(
            check_bit_string(&[0x01, 0x03]),
            Err(DerError::InvalidBitString)
        );
        assert_eq!(
            check_bit_string(&[0x08, 0x00]),
            Err(DerError::InvalidBitString)
        );
        assert_eq!(check_bit_string(&[0x00, 0xFF]), Ok(()));
        assert_eq!(bit_string_octets(&[0x00, 0xAB]), Ok(&[0xAB][..]));
        assert_eq!(
            bit_string_octets(&[0x01, 0xAA]),
            Err(DerError::InvalidBitString)
        );
        assert_eq!(bit_string_octets(&[]), Err(DerError::InvalidBitString));
    }

    #[test]
    fn generic_check() {
        let ok = |bytes: &[u8]| check_contents(Reader::new(bytes));
        assert_eq!(ok(&[0x30, 0x03, 0x01, 0x01, 0xFF]), Ok(()));
        assert_eq!(
            ok(&[0x30, 0x03, 0x01, 0x01, 0x01]),
            Err(DerError::InvalidBoolean)
        );
        assert_eq!(
            ok(&[0x30, 0x04, 0x02, 0x02, 0x00, 0x01]),
            Err(DerError::NonMinimalInteger)
        );
        assert_eq!(ok(&[0x05, 0x01, 0x00]), Err(DerError::InvalidNull));
        assert_eq!(ok(&[0x06, 0x01, 0x80]), Err(DerError::InvalidOid));
        assert_eq!(
            ok(&[0x03, 0x02, 0x01, 0x01]),
            Err(DerError::InvalidBitString)
        );
        // Constructed OCTET STRING (BER only), primitive SEQUENCE and SET, EOC.
        assert_eq!(ok(&[0x24, 0x00]), Err(DerError::InvalidTagForm));
        assert_eq!(ok(&[0x10, 0x00]), Err(DerError::InvalidTagForm));
        assert_eq!(ok(&[0x11, 0x00]), Err(DerError::InvalidTagForm));
        assert_eq!(ok(&[0x00, 0x00]), Err(DerError::InvalidTagForm));
        // Context, application and private tags are opaque when primitive.
        assert_eq!(ok(&[0x80, 0x01, 0x80, 0x41, 0x00, 0xC1, 0x00]), Ok(()));
        // ... and checked inside when constructed.
        assert_eq!(
            ok(&[0xA0, 0x03, 0x01, 0x01, 0x02]),
            Err(DerError::InvalidBoolean)
        );
        assert_eq!(
            ok(&[0x61, 0x03, 0x01, 0x01, 0x02]),
            Err(DerError::InvalidBoolean)
        );
        // Strings and times are opaque.
        assert_eq!(ok(&[0x0C, 0x01, 0xFF, 0x17, 0x01, 0x00]), Ok(()));
        // SET order.
        assert_eq!(
            ok(&[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]),
            Ok(())
        );
        assert_eq!(
            ok(&[0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]),
            Ok(())
        );
        assert_eq!(
            ok(&[0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01]),
            Err(DerError::SetNotSorted)
        );
        // SEQUENCE order is free.
        assert_eq!(
            ok(&[0x30, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01]),
            Ok(())
        );
        // Lengths inside are checked.
        assert_eq!(
            ok(&[0x30, 0x03, 0x04, 0x81, 0x01]),
            Err(DerError::NonMinimalLength)
        );
        assert_eq!(
            ok(&[0x30, 0x03, 0x04, 0x05, 0x01]),
            Err(DerError::Truncated)
        );
        assert_eq!(ok(&[0x30, 0x02, 0x04, 0x01]), Err(DerError::Truncated));
    }

    #[test]
    fn set_reader_checks_order() {
        let sorted = [0x31, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let unsorted = [0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01];
        assert!(Reader::new(&sorted).set(SET).is_ok());
        assert_eq!(
            Reader::new(&unsorted).set(SET).err(),
            Some(DerError::SetNotSorted)
        );
        assert_eq!(
            Reader::new(&[0x31, 0x02, 0x02, 0x81]).set(SET).err(),
            Some(DerError::Truncated)
        );
    }

    #[test]
    fn element_checks() {
        let check = |bytes: &[u8]| {
            let mut reader = Reader::new(bytes);
            let tlv = reader.read_any()?;
            check_element(&reader, &tlv)
        };
        assert_eq!(check(&[0x30, 0x03, 0x01, 0x01, 0xFF]), Ok(()));
        assert_eq!(
            check(&[0x30, 0x03, 0x01, 0x01, 0x01]),
            Err(DerError::InvalidBoolean)
        );
        assert_eq!(check(&[0x01, 0x01, 0x01]), Err(DerError::InvalidBoolean));
        assert_eq!(check(&[0x24, 0x00]), Err(DerError::InvalidTagForm));
        let mut reader = Reader::new(&[0x30, 0x03, 0x02, 0x02, 0x00]);
        assert_eq!(reader.checked(SEQUENCE).err(), Some(DerError::Truncated));
        let mut reader = Reader::new(&[0x30, 0x04, 0x02, 0x02, 0x00, 0x01]);
        assert_eq!(
            reader.checked(SEQUENCE).err(),
            Some(DerError::NonMinimalInteger)
        );
        let mut reader = Reader::new(&[0x30, 0x03, 0x02, 0x01, 0x05]);
        assert_eq!(reader.checked(SEQUENCE).map(|tlv| tlv.raw.len()), Ok(5));
        let mut reader = Reader::new(&[0x05, 0x01, 0x00]);
        assert_eq!(reader.checked_any().err(), Some(DerError::InvalidNull));
    }

    #[test]
    fn single_element() {
        assert!(single(&[0x30, 0x00], SEQUENCE).is_ok());
        assert_eq!(
            single(&[0x30, 0x00, 0x00], SEQUENCE).err(),
            Some(DerError::TrailingData)
        );
        assert_eq!(
            single(&[0x31, 0x00], SEQUENCE).err(),
            Some(DerError::UnexpectedTag)
        );
    }
}
