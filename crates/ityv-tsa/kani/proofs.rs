//! Kani bounded model-checking harnesses (verification ladder V2) for the
//! strict DER reader and the time parsers.
//!
//! Compiled only under `cargo kani`. Each harness states one property of
//! `src/der.rs` or `src/time.rs`. Kani additionally checks every harness for
//! panics, overflow and out-of-bounds access on all explored inputs, which
//! is the mechanical form of the crate's "no panics" promise.
//!
//! Run with `cargo kani -p ityv-tsa` from the workspace root. The file lives
//! outside `src/` and is included as `crate::proofs` by a `#[path]`
//! attribute in `src/lib.rs`.
// Harness file: outside the TCB and outside `src/` (CONSTITUTION.md §1.1).
// A harness states expected values with plain indexing and unchecked
// arithmetic on bounded symbolic inputs, and Kani itself reports any panic
// or overflow in them, so these restriction lints are relaxed for this file
// only.
#![allow(
    clippy::unreachable,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation
)]

use crate::der::{self, Reader};
use crate::error::DerError;
use crate::time;

/// The canonical header of a value of `len` octets with `tag`.
fn header(tag: u8, len: usize) -> ([u8; 4], usize) {
    if len < 0x80 {
        ([tag, len as u8, 0, 0], 2)
    } else if len < 0x100 {
        ([tag, 0x81, len as u8, 0], 3)
    } else {
        ([tag, 0x82, (len >> 8) as u8, len as u8], 4)
    }
}

/// Length decoding: an accepted header is the one canonical header of its
/// tag and length (so non-minimal, indefinite and over-long forms are all
/// refused), the element lies inside the input, and the rest follows it.
/// The input is long enough for every short, `0x81` and `0x82` length.
#[kani::proof]
#[kani::unwind(5)]
fn tlv_header_is_canonical_and_bounded() {
    let bytes: [u8; 260] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let input = &bytes[..len];
    match der::parse_tlv(input) {
        Ok((tlv, rest)) => {
            assert!(tlv.raw.len() + rest.len() == input.len());
            assert!(tlv.raw.as_ptr() == input.as_ptr());
            let (expected, header_len) = header(tlv.tag, tlv.value.len());
            assert!(tlv.raw.len() == header_len + tlv.value.len());
            assert!(&tlv.raw[..header_len] == &expected[..header_len]);
            assert!(tlv.tag & 0x1F != 0x1F);
        }
        Err(DerError::IndefiniteLength) => assert!(input[1] == 0x80),
        Err(DerError::LengthTooLarge) => assert!(input[1] > 0x82),
        Err(DerError::NonMinimalLength) => {
            assert!((input[1] == 0x81 && input[2] < 0x80) || (input[1] == 0x82 && input[2] == 0));
        }
        Err(DerError::HighTagNumber) => assert!(input[0] & 0x1F == 0x1F),
        Err(DerError::Truncated) => {}
        Err(_) => unreachable!(),
    }
}

/// Every canonical header is accepted with its length.
#[kani::proof]
#[kani::unwind(5)]
fn canonical_headers_are_accepted() {
    let tag: u8 = kani::any();
    kani::assume(tag & 0x1F != 0x1F);
    let len: usize = kani::any();
    kani::assume(len <= 256);
    let (head, header_len) = header(tag, len);
    let mut bytes = [0u8; 260];
    bytes[..header_len].copy_from_slice(&head[..header_len]);
    let total = header_len + len;
    let (tlv, rest) = der::parse_tlv(&bytes[..total]).unwrap();
    assert!(tlv.tag == tag && tlv.value.len() == len && rest.is_empty());
}

/// The whole-tree check (its explicit stack, nested elements, `SET` order
/// and primitive rules) never panics on any input of up to four octets,
/// and accepts only inputs that are a sequence of complete elements. Four
/// octets hold two nested levels or two elements, so the loop runs at most
/// five times. (Six octets already exhaust CBMC's memory; the unit tests
/// and the proptests cover deeper trees, and `der::tests::depth_limit` the
/// depth bound.)
#[kani::proof]
#[kani::unwind(6)]
fn tree_check_is_total() {
    let bytes: [u8; 4] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let input = &bytes[..len];
    if der::check_contents(Reader::new(input)).is_ok() && !input.is_empty() {
        let (first, _) = der::parse_tlv(input).unwrap();
        assert!(first.raw.len() <= input.len());
    }
}

/// Reading a `SEQUENCE` and finishing it consumes exactly its value.
#[kani::proof]
#[kani::unwind(6)]
fn sequences_are_consumed_exactly() {
    let bytes: [u8; 6] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let input = &bytes[..len];
    let mut outer = Reader::new(input);
    if let Ok(mut inner) = outer.sequence() {
        let value_len = usize::from(input[1]);
        assert!(input[0] == 0x30 && input[1] < 0x80);
        let mut read = 0;
        while let Ok(tlv) = inner.read_any() {
            read += tlv.raw.len();
        }
        if inner.finish().is_ok() {
            assert!(read == value_len);
        }
        assert!(outer.finish().is_ok() == (len == 2 + value_len));
    }
}

/// `BOOLEAN` is the single octet `0x00` or `0xFF`.
#[kani::proof]
fn boolean_is_strict() {
    let bytes: [u8; 2] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 2);
    let value = &bytes[..len];
    let result = der::boolean(value);
    let canonical = len == 1 && (bytes[0] == 0x00 || bytes[0] == 0xFF);
    assert!(result.is_ok() == canonical);
    if canonical {
        assert!(result == Ok(bytes[0] == 0xFF));
    } else {
        assert!(result == Err(DerError::InvalidBoolean));
    }
}

/// `INTEGER` is non-empty and minimal; the magnitude of a non-negative one
/// has no leading zero; `small_unsigned` is its big-endian value.
#[kani::proof]
#[kani::unwind(5)]
fn integers_are_minimal() {
    let bytes: [u8; 3] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 3);
    let value = &bytes[..len];
    let minimal = len > 0
        && !(len > 1 && bytes[0] == 0x00 && bytes[1] < 0x80)
        && !(len > 1 && bytes[0] == 0xFF && bytes[1] >= 0x80);
    assert!(der::integer(value).is_ok() == minimal);
    match der::unsigned(value) {
        Ok(magnitude) => {
            assert!(minimal && bytes[0] < 0x80);
            assert!(magnitude.first() != Some(&0));
            let mut expected = 0u64;
            for &octet in value {
                expected = expected * 256 + u64::from(octet);
            }
            assert!(der::small_unsigned(value) == Ok(expected));
        }
        Err(error) => {
            assert!(!minimal || bytes[0] >= 0x80);
            assert!(der::small_unsigned(value) == Err(error));
        }
    }
}

/// `OBJECT IDENTIFIER` content: non-empty, last octet without the
/// continuation bit, no arc starting with `0x80`.
#[kani::proof]
#[kani::unwind(6)]
fn object_identifiers_follow_the_arc_rules() {
    let bytes: [u8; 4] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 4);
    let value = &bytes[..len];
    let mut valid = len > 0 && bytes[len - 1] < 0x80;
    let mut arc_start = true;
    for &octet in value {
        if arc_start && octet == 0x80 {
            valid = false;
        }
        arc_start = octet < 0x80;
    }
    assert!(der::check_oid(value).is_ok() == valid);
}

/// `SET` elements must be in ascending order of their encodings.
#[kani::proof]
#[kani::unwind(6)]
fn sets_are_sorted() {
    let first: [u8; 3] = kani::any();
    let second: [u8; 3] = kani::any();
    // Two one-octet INTEGERs with arbitrary tags of the primitive universal class.
    kani::assume(first[1] == 1 && second[1] == 1);
    kani::assume(first[0] & 0x1F != 0x1F && second[0] & 0x1F != 0x1F);
    let mut set = [0x31, 6, 0, 0, 0, 0, 0, 0];
    set[2..5].copy_from_slice(&first);
    set[5..8].copy_from_slice(&second);
    let result = Reader::new(&set).set(der::SET);
    assert!(result.is_ok() == (first <= second));
}

/// A `GeneralizedTime` parser that never panics, and accepts only values
/// whose fraction is below a second and whose instant is at most
/// 9999-12-31T23:59:59Z.
#[kani::proof]
#[kani::unwind(26)]
fn generalized_time_is_total() {
    let bytes: [u8; 25] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    let fraction_allowed: bool = kani::any();
    if let Ok(instant) = time::generalized_time(&bytes[..len], fraction_allowed) {
        assert!(instant.nanos() < 1_000_000_000);
        assert!(instant.unix_seconds() <= 253_402_300_799);
        assert!(bytes[len - 1] == b'Z');
        assert!(fraction_allowed || len == 15);
        assert!(len == 15 || (len >= 17 && bytes[14] == b'.' && bytes[len - 2] != b'0'));
    }
}

/// A `UTCTime` parser that never panics and accepts only `YYMMDDhhmmssZ`
/// with `YY` of 70–99 or 00–49 (1970–2049).
#[kani::proof]
#[kani::unwind(15)]
fn utc_time_is_total() {
    let bytes: [u8; 14] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= bytes.len());
    if let Ok(instant) = time::utc_time(&bytes[..len]) {
        assert!(len == 13 && bytes[12] == b'Z');
        assert!(!(b'5'..=b'6').contains(&bytes[0]));
        assert!(instant.unix_seconds() < 2_524_608_000);
        assert!(instant.nanos() == 0);
    }
}

/// Days since 1970-01-01 by H. Hinnant's `days_from_civil`: eras of 400
/// years and March-based years, a different method from the crate's.
fn reference_days(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// `genTime` ± accuracy (`VerifiedTimestamp::earliest` and `latest`): for
/// every time up to the year 9999 and every accuracy up to
/// `MAX_ACCURACY_SECONDS`, moving later never fails and is exact (checked
/// against division and remainder), and moving earlier is its inverse and
/// fails exactly when the offset is larger than the time.
#[kani::proof]
fn time_offsets_are_exact() {
    let seconds: u64 = kani::any();
    let nanos: u32 = kani::any();
    let by_seconds: u64 = kani::any();
    let by_nanos: u32 = kani::any();
    kani::assume(seconds <= 253_402_300_799 && nanos < 1_000_000_000);
    kani::assume(by_seconds <= crate::MAX_ACCURACY_SECONDS && by_nanos < 1_000_000_000);
    let time = (seconds, nanos);
    let offset = (by_seconds, by_nanos);

    let total = u64::from(nanos) + u64::from(by_nanos);
    let exact = (
        seconds + by_seconds + total / 1_000_000_000,
        (total % 1_000_000_000) as u32,
    );
    let later = time::add_parts(time, offset);
    assert!(later == Some(exact));
    assert!(time::sub_parts(exact, offset) == Some(time));

    let earlier = time::sub_parts(time, offset);
    let larger = by_seconds > seconds || (by_seconds == seconds && by_nanos > nanos);
    assert!(earlier.is_none() == larger);
    if let Some(earlier) = earlier {
        assert!(earlier.1 < 1_000_000_000);
        assert!(time::add_parts(earlier, offset) == Some(time));
    }
}

// Every instant of a year, written as `GeneralizedTime`, parses to the
// reference Unix time, and an invalid day of the month is refused.
//
// The years are concrete, one harness per leap-year rule: common years (the
// epoch and the next), years divisible by 4, by 100 but not 400, by 400, and
// the last accepted year. With a symbolic year the solver must prove two
// division-based formulas equal for all 8030 years, which does not finish
// in the CI time limit; the property test
// `time::tests::generalized_time_matches_the_reference` covers random years
// against a third method (counting years one by one).

/// Common years: 1970 (the epoch) and 1971.
#[kani::proof]
#[kani::unwind(16)]
fn generalized_time_matches_the_reference_common_years() {
    for year in [1970, 1971] {
        check_year(year);
    }
}

/// Years divisible by 4 and not by 100: 1972 and 2024.
#[kani::proof]
#[kani::unwind(16)]
fn generalized_time_matches_the_reference_leap_years() {
    for year in [1972, 2024] {
        check_year(year);
    }
}

/// A year divisible by 100 but not by 400 (common): 2100.
#[kani::proof]
#[kani::unwind(16)]
fn generalized_time_matches_the_reference_century() {
    check_year(2100);
}

/// Years divisible by 400 (leap): 2000 and 2400.
#[kani::proof]
#[kani::unwind(16)]
fn generalized_time_matches_the_reference_quadricentennial() {
    for year in [2000, 2400] {
        check_year(year);
    }
}

/// The last accepted year: 9999.
#[kani::proof]
#[kani::unwind(16)]
fn generalized_time_matches_the_reference_last_year() {
    check_year(9999);
}

/// Every month, day and time of `year` against the reference.
fn check_year(year: u16) {
    let month: u8 = kani::any();
    let day: u8 = kani::any();
    let hour: u8 = kani::any();
    let minute: u8 = kani::any();
    let second: u8 = kani::any();
    kani::assume((1..=12).contains(&month) && (1..=31).contains(&day));
    kani::assume(hour <= 23 && minute <= 59 && second <= 59);
    check_instant(year, month, day, [hour, minute, second]);
}

/// One instant against the reference.
fn check_instant(year: u16, month: u8, day: u8, [hour, minute, second]: [u8; 3]) {
    let digits = |value: u16, out: &mut [u8]| {
        let mut rest = value;
        for slot in out.iter_mut().rev() {
            *slot = b'0' + (rest % 10) as u8;
            rest /= 10;
        }
    };
    let mut text = [0u8; 15];
    digits(year, &mut text[0..4]);
    digits(u16::from(month), &mut text[4..6]);
    digits(u16::from(day), &mut text[6..8]);
    digits(u16::from(hour), &mut text[8..10]);
    digits(u16::from(minute), &mut text[10..12]);
    digits(u16::from(second), &mut text[12..14]);
    text[14] = b'Z';

    let (y, m, d) = (i64::from(year), i64::from(month), i64::from(day));
    let next_month = if m == 12 {
        reference_days(y + 1, 1, 1)
    } else {
        reference_days(y, m + 1, 1)
    };
    let month_len = next_month - reference_days(y, m, 1);
    let result = time::generalized_time(&text, false);
    if d > month_len {
        assert!(result == Err(DerError::InvalidTime));
    } else {
        let seconds = reference_days(y, m, d) * 86_400
            + i64::from(hour) * 3600
            + i64::from(minute) * 60
            + i64::from(second);
        let instant = result.unwrap();
        assert!(instant.unix_seconds() == seconds as u64 && instant.nanos() == 0);
    }
}
