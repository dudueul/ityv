//! Strict `GeneralizedTime` and `UTCTime` (X.690 §11.7–11.8, RFC 5280 §4.1.2.5).
//!
//! `GeneralizedTime` is `YYYYMMDDhhmmss[.f…]Z`: UTC (`Z`), seconds always
//! present, and an optional fraction of one to nine digits that does not end
//! in `0` (DER removes trailing zeros; a fraction of zero is omitted).
//! `UTCTime` is `YYMMDDhhmmssZ`, with `YY` of 50–99 meaning 19YY (RFC 5280).
//! Every field is range-checked against the proleptic Gregorian calendar;
//! leap seconds (`60`) and years before 1970 are refused, since the result is
//! Unix time.

use crate::error::DerError;

/// A UTC instant: seconds since 1970-01-01T00:00:00Z (leap seconds not
/// counted, as in Unix time) and a fraction of a second in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GenTime {
    seconds: u64,
    nanos: u32,
}

impl GenTime {
    /// Whole seconds since the Unix epoch.
    #[must_use]
    pub const fn unix_seconds(&self) -> u64 {
        self.seconds
    }

    /// The fraction of a second, in nanoseconds (`0..1_000_000_000`); zero
    /// when the time has no fraction.
    #[must_use]
    pub const fn nanos(&self) -> u32 {
        self.nanos
    }
}

/// Days before the first of each month in a common year.
const DAYS_BEFORE_MONTH: [u64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];

/// Leap days in the years `1..=year` of the proleptic Gregorian calendar.
const fn leap_days_through(year: u64) -> u64 {
    // Division by non-zero constants cannot fail; the subtraction cannot
    // underflow because `year / 4 >= year / 100`.
    (year / 4)
        .saturating_sub(year / 100)
        .saturating_add(year / 400)
}

const fn is_leap(year: u64) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

/// Reads `count` ASCII digits from the front of `input`.
fn take_number(input: &mut &[u8], count: usize) -> Result<u64, DerError> {
    let (digits, rest) = input.split_at_checked(count).ok_or(DerError::InvalidTime)?;
    let mut value = 0u64;
    for &digit in digits {
        if !digit.is_ascii_digit() {
            return Err(DerError::InvalidTime);
        }
        // At most nine digits, so the value stays far below u64::MAX.
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit.wrapping_sub(b'0'))))
            .ok_or(DerError::InvalidTime)?;
    }
    *input = rest;
    Ok(value)
}

/// Seconds since the Unix epoch of a calendar date and time, after checking
/// every field.
fn unix_seconds(
    year: u64,
    month: u64,
    day: u64,
    hour: u64,
    minute: u64,
    second: u64,
) -> Result<u64, DerError> {
    if !(1970..=9999).contains(&year) || hour > 23 || minute > 59 || second > 59 {
        return Err(DerError::InvalidTime);
    }
    let month_index = usize::try_from(month)
        .ok()
        .and_then(|month| month.checked_sub(1))
        .ok_or(DerError::InvalidTime)?;
    let before_month = *DAYS_BEFORE_MONTH
        .get(month_index)
        .ok_or(DerError::InvalidTime)?;
    let leap = is_leap(year);
    let month_len = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day == 0 || day > month_len {
        return Err(DerError::InvalidTime);
    }
    let leap_adjust = u64::from(leap && month > 2);
    let previous = year.checked_sub(1).ok_or(DerError::InvalidTime)?;
    let days = year
        .checked_sub(1970)
        .and_then(|years| years.checked_mul(365))
        .and_then(|days| days.checked_add(leap_days_through(previous)))
        .and_then(|days| days.checked_sub(leap_days_through(1969)))
        .and_then(|days| days.checked_add(before_month))
        .and_then(|days| days.checked_add(leap_adjust))
        .and_then(|days| days.checked_add(day))
        .and_then(|days| days.checked_sub(1))
        .ok_or(DerError::InvalidTime)?;
    days.checked_mul(86_400)
        .and_then(|seconds| seconds.checked_add(hour.checked_mul(3600)?))
        .and_then(|seconds| seconds.checked_add(minute.checked_mul(60)?))
        .and_then(|seconds| seconds.checked_add(second))
        .ok_or(DerError::InvalidTime)
}

/// Reads `MMDDhhmmss` after the year and returns the instant.
fn date_time(year: u64, input: &mut &[u8]) -> Result<u64, DerError> {
    let month = take_number(input, 2)?;
    let day = take_number(input, 2)?;
    let hour = take_number(input, 2)?;
    let minute = take_number(input, 2)?;
    let second = take_number(input, 2)?;
    unix_seconds(year, month, day, hour, minute, second)
}

/// Parses a `GeneralizedTime` value. A fraction is accepted only if
/// `fraction_allowed` (a certificate's validity has none, RFC 5280).
pub(crate) fn generalized_time(value: &[u8], fraction_allowed: bool) -> Result<GenTime, DerError> {
    let mut rest = value;
    let year = take_number(&mut rest, 4)?;
    let seconds = date_time(year, &mut rest)?;
    let mut nanos = 0u32;
    if let Some((b'.', after_dot)) = rest.split_first() {
        if !fraction_allowed {
            return Err(DerError::InvalidTime);
        }
        let digits = after_dot
            .iter()
            .position(|octet| !octet.is_ascii_digit())
            .unwrap_or(after_dot.len());
        if digits == 0 || digits > 9 {
            return Err(DerError::InvalidTime);
        }
        let mut fraction = after_dot;
        let value = take_number(&mut fraction, digits)?;
        if value % 10 == 0 {
            // A trailing zero (and so also an all-zero fraction).
            return Err(DerError::InvalidTime);
        }
        let scale = u32::try_from(9usize.saturating_sub(digits))
            .ok()
            .and_then(|exponent| 10u64.checked_pow(exponent))
            .ok_or(DerError::InvalidTime)?;
        nanos = value
            .checked_mul(scale)
            .and_then(|nanos| u32::try_from(nanos).ok())
            .ok_or(DerError::InvalidTime)?;
        rest = fraction;
    }
    if rest == b"Z" {
        Ok(GenTime { seconds, nanos })
    } else {
        Err(DerError::InvalidTime)
    }
}

/// Parses a `UTCTime` value (`YYMMDDhhmmssZ`).
pub(crate) fn utc_time(value: &[u8]) -> Result<GenTime, DerError> {
    let mut rest = value;
    let short_year = take_number(&mut rest, 2)?;
    let century = if short_year >= 50 { 1900 } else { 2000 };
    let year = short_year
        .checked_add(century)
        .ok_or(DerError::InvalidTime)?;
    let seconds = date_time(year, &mut rest)?;
    if rest == b"Z" {
        Ok(GenTime { seconds, nanos: 0 })
    } else {
        Err(DerError::InvalidTime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn gt(text: &str) -> Result<(u64, u32), DerError> {
        generalized_time(text.as_bytes(), true).map(|t| (t.unix_seconds(), t.nanos()))
    }

    /// Unix seconds by counting every year and month since 1970, a
    /// different method from the crate's closed-form leap count. `None` if
    /// the day is not in the month.
    fn reference_seconds(date: [u64; 6]) -> Option<u64> {
        let [year, month, day, hour, minute, second] = date;
        let leap =
            |y: u64| (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400);
        let february = if leap(year) { 29 } else { 28 };
        let lengths = [31, february, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        let month_index = usize::try_from(month.checked_sub(1)?).ok()?;
        if day > lengths[month_index] {
            return None;
        }
        let mut days = 0u64;
        for past in 1970..year {
            days = days.checked_add(if leap(past) { 366 } else { 365 })?;
        }
        for length in &lengths[..month_index] {
            days = days.checked_add(*length)?;
        }
        days = days.checked_add(day)?.checked_sub(1)?;
        days.checked_mul(86_400)?
            .checked_add(hour.checked_mul(3600)?)?
            .checked_add(minute.checked_mul(60)?)?
            .checked_add(second)
    }

    proptest! {
        #[test]
        fn generalized_time_matches_the_reference(
            year in 1970u64..=9999,
            month in 1u64..=12,
            day in 1u64..=31,
            hour in 0u64..=23,
            minute in 0u64..=59,
            second in 0u64..=59,
            fraction in prop::option::of(1u32..1_000_000_000),
        ) {
            let mut text = std::format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}");
            let mut nanos = 0;
            if let Some(fraction) = fraction {
                let digits = std::format!("{fraction:09}");
                text.push('.');
                text.push_str(digits.trim_end_matches('0'));
                nanos = fraction;
            }
            text.push('Z');
            let parsed = gt(&text);
            match reference_seconds([year, month, day, hour, minute, second]) {
                None => prop_assert_eq!(parsed, Err(DerError::InvalidTime)),
                Some(seconds) => prop_assert_eq!(parsed, Ok((seconds, nanos))),
            }
        }

        #[test]
        fn time_parsers_are_total(bytes in prop::collection::vec(any::<u8>(), 0..32)) {
            let _ = generalized_time(&bytes, true);
            let _ = generalized_time(&bytes, false);
            let _ = utc_time(&bytes);
        }
    }

    #[test]
    fn known_instants() {
        assert_eq!(gt("19700101000000Z"), Ok((0, 0)));
        assert_eq!(gt("19700101000001Z"), Ok((1, 0)));
        assert_eq!(gt("19700102000000Z"), Ok((86_400, 0)));
        assert_eq!(gt("19710101000000Z"), Ok((31_536_000, 0)));
        assert_eq!(gt("19720301000000Z"), Ok((68_256_000, 0)));
        assert_eq!(gt("20000229235959Z"), Ok((951_868_799, 0)));
        assert_eq!(gt("20000301000000Z"), Ok((951_868_800, 0)));
        assert_eq!(gt("20380119031408Z"), Ok((2_147_483_648, 0)));
        assert_eq!(gt("20261104130407Z"), Ok((1_793_797_447, 0)));
        assert_eq!(gt("21000301000000Z"), Ok((4_107_542_400, 0)));
        assert_eq!(gt("99991231235959Z"), Ok((253_402_300_799, 0)));
        assert_eq!(gt("20261104130407.861Z"), Ok((1_793_797_447, 861_000_000)));
        assert_eq!(gt("20261104130407.5Z"), Ok((1_793_797_447, 500_000_000)));
        assert_eq!(gt("20261104130407.000000001Z"), Ok((1_793_797_447, 1)));
        assert_eq!(
            gt("20261104130407.123456789Z"),
            Ok((1_793_797_447, 123_456_789))
        );
    }

    #[test]
    fn refused_forms() {
        for bad in [
            "",
            "Z",
            "2026110413040Z",
            "20261104130407",
            "20261104130407z",
            "20261104130407+0000",
            "20261104130407ZZ",
            "202611041304Z",
            "20261104130407.Z",
            "20261104130407.10Z",
            "20261104130407.0Z",
            "20261104130407.1234567891Z",
            "20261104130407.1",
            "20261104130407,5Z",
            "2026 104130407Z",
            "20261304130407Z",
            "20260004130407Z",
            "20261100130407Z",
            "20261131130407Z",
            "20260230130407Z",
            "20250229130407Z",
            "21000229000000Z",
            "20261104240000Z",
            "20261104136000Z",
            "20261104130460Z",
            "19691231235959Z",
            "+2026110413040Z",
        ] {
            assert_eq!(gt(bad), Err(DerError::InvalidTime), "{bad}");
        }
        assert_eq!(gt("20240229000000Z").map(|t| t.0), Ok(1_709_164_800));
        assert_eq!(gt("20000229000000Z").map(|t| t.0), Ok(951_782_400));
        assert_eq!(gt("20261130000000Z").map(|t| t.0), Ok(1_795_996_800));
        assert_eq!(gt("20261231000000Z").map(|t| t.0), Ok(1_798_675_200));
        assert_eq!(gt("20260430000000Z").map(|t| t.0), Ok(1_777_507_200));
        assert_eq!(
            generalized_time(b"20261104130407.5Z", false),
            Err(DerError::InvalidTime)
        );
        assert_eq!(
            generalized_time(b"20261104130407Z", false).map(|t| t.unix_seconds()),
            Ok(1_793_797_447)
        );
    }

    #[test]
    fn utc_times() {
        let utc = |text: &str| utc_time(text.as_bytes()).map(|t| t.unix_seconds());
        assert_eq!(utc("261104130407Z"), Ok(1_793_797_447));
        assert_eq!(utc("700101000000Z"), Ok(0));
        assert_eq!(utc("491231235959Z"), Ok(2_524_607_999));
        assert_eq!(utc("500101000000Z"), Err(DerError::InvalidTime));
        assert_eq!(utc("691231235959Z"), Err(DerError::InvalidTime));
        assert_eq!(utc("2611041304Z"), Err(DerError::InvalidTime));
        assert_eq!(utc("261104130407"), Err(DerError::InvalidTime));
        assert_eq!(utc("261104130407.5Z"), Err(DerError::InvalidTime));
        assert_eq!(utc("261104130407+0900"), Err(DerError::InvalidTime));
        assert_eq!(utc_time(b"261104130407Z").map(|t| t.nanos()), Ok(0));
    }
}
