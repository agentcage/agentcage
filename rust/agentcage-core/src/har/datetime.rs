//! Just enough of Python's `datetime` for `--since`.
//!
//! `har.py` uses four things from it: `datetime.now(timezone.utc)`,
//! `datetime.fromisoformat`, `timedelta` subtraction, and the `<`
//! comparison between a capture entry's timestamp and the cutoff. The
//! last one carries a behaviour worth keeping: comparing an aware
//! datetime with a naive one raises `TypeError` in Python, and
//! `CaptureFilter.matches` catches that and *keeps* the entry. So
//! awareness is not a detail to normalize away — it decides whether the
//! filter applies at all. [`DateTime::lt`] returns `None` for that case
//! rather than guessing an offset.
//!
//! This is deliberately not a general date library and not a reason to
//! take a dependency on one. It handles the proleptic Gregorian calendar
//! over Python's year range, whole-second UTC offsets, and microsecond
//! resolution.

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

const MICROS_PER_SECOND: i64 = 1_000_000;
const SECONDS_PER_DAY: i64 = 86_400;

/// Python's `datetime.min`, as microseconds of civil time since the Unix
/// epoch: `0001-01-01T00:00:00`.
const MIN_CIVIL_MICROS: i64 = -62_135_596_800 * MICROS_PER_SECOND;
/// Python's `datetime.max`: `9999-12-31T23:59:59.999999`.
const MAX_CIVIL_MICROS: i64 = 253_402_300_799 * MICROS_PER_SECOND + 999_999;

/// A moment in time, aware or naive, with microsecond resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DateTime {
    /// Wall-clock microseconds since `1970-01-01T00:00:00` *in this
    /// value's own frame* — i.e. the calendar fields, not the instant.
    civil_micros: i64,
    /// The UTC offset in seconds, or `None` when this datetime is naive.
    offset_seconds: Option<i32>,
}

impl DateTime {
    /// `datetime.now(timezone.utc)`.
    ///
    /// The only clock read in `agentcage-core`. It is here because
    /// `parse_since("1h")` and `capture_to_har`'s fallback timestamp are
    /// both defined relative to "now" in the Python; every other entry
    /// point takes the value it needs.
    #[must_use]
    pub fn now_utc() -> Self {
        let micros = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|d| i64::try_from(d.as_micros()).ok())
            .unwrap_or(0);
        Self {
            civil_micros: micros,
            offset_seconds: Some(0),
        }
    }

    /// Build from calendar fields — `(year, month, day)`, then
    /// `(hour, minute, second, microsecond)` — rejecting out-of-range
    /// ones the way the `datetime` constructor does.
    #[must_use]
    pub fn from_parts(
        date: (i64, u32, u32),
        time: (u32, u32, u32, u32),
        offset_seconds: Option<i32>,
    ) -> Option<Self> {
        let (year, month, day) = date;
        let (hour, minute, second, microsecond) = time;
        if !(1..=9999).contains(&year)
            || !(1..=12).contains(&month)
            || day < 1
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
            || microsecond > 999_999
        {
            return None;
        }
        if offset_seconds.is_some_and(|o| o.abs() >= 24 * 3600) {
            return None;
        }
        let day_seconds = i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second);
        let civil_micros = (days_from_civil(year, month, day) * SECONDS_PER_DAY + day_seconds)
            * MICROS_PER_SECOND
            + i64::from(microsecond);
        Some(Self {
            civil_micros,
            offset_seconds,
        })
    }

    /// Whether this datetime carries a UTC offset.
    #[must_use]
    pub fn is_aware(&self) -> bool {
        self.offset_seconds.is_some()
    }

    /// `dt.replace(tzinfo=timezone.utc)` when `dt` is naive, otherwise
    /// `dt` — the last two lines of `parse_since`.
    #[must_use]
    pub fn assume_utc(self) -> Self {
        Self {
            offset_seconds: self.offset_seconds.or(Some(0)),
            ..self
        }
    }

    /// `self - timedelta(seconds=seconds)`.
    ///
    /// `None` where Python raises `OverflowError`, which is outside
    /// `datetime.min`/`datetime.max`. `parse_since` does not catch that,
    /// so Python propagates it out of the CLI; returning `None` here
    /// lands the caller on the same "no cutoff" path an unparseable
    /// `--since` takes.
    #[must_use]
    pub fn checked_sub_seconds(self, seconds: i64) -> Option<Self> {
        let civil_micros = seconds
            .checked_mul(MICROS_PER_SECOND)
            .and_then(|micros| self.civil_micros.checked_sub(micros))?;
        if !(MIN_CIVIL_MICROS..=MAX_CIVIL_MICROS).contains(&civil_micros) {
            return None;
        }
        Some(Self {
            civil_micros,
            ..self
        })
    }

    /// `self < other`, or `None` where Python raises `TypeError` for
    /// "can't compare offset-naive and offset-aware datetimes".
    #[must_use]
    pub fn lt(&self, other: &Self) -> Option<bool> {
        let (left, right) = self.comparable_with(other)?;
        Some(left < right)
    }

    /// `(self - other).total_seconds()`, rounded to whole seconds the
    /// way Python's `round` does, or `None` for a naive/aware mix.
    #[must_use]
    pub fn seconds_since(&self, other: &Self) -> Option<i64> {
        let (left, right) = self.comparable_with(other)?;
        Some(round_half_even(left - right, MICROS_PER_SECOND))
    }

    /// The pair of microsecond counts to compare, or `None` when one
    /// side is naive and the other is not — the `TypeError` case.
    ///
    /// Two aware datetimes compare as instants, so their offsets count;
    /// two naive ones compare as wall-clock fields, which is the same
    /// number with no offset to subtract.
    fn comparable_with(&self, other: &Self) -> Option<(i64, i64)> {
        match (self.offset_seconds, other.offset_seconds) {
            (Some(_), Some(_)) => Some((self.instant_micros(), other.instant_micros())),
            (None, None) => Some((self.civil_micros, other.civil_micros)),
            _ => None,
        }
    }

    /// The instant as microseconds since the epoch; the civil fields for
    /// a naive value, which only ever meet other naive values.
    fn instant_micros(&self) -> i64 {
        let offset = self.offset_seconds.unwrap_or(0);
        self.civil_micros - i64::from(offset) * MICROS_PER_SECOND
    }

    /// `dt.isoformat()`: `YYYY-MM-DDTHH:MM:SS`, `.ffffff` only when
    /// there are microseconds, then the offset as `+HH:MM` — with
    /// `:SS` appended when the offset is not a whole number of minutes.
    #[must_use]
    pub fn isoformat(&self) -> String {
        let (year, month, day, hour, minute, second, microsecond) = self.parts();
        let mut out = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}");
        if microsecond != 0 {
            let _ = write!(out, ".{microsecond:06}");
        }
        if let Some(offset) = self.offset_seconds {
            let sign = if offset < 0 { '-' } else { '+' };
            let total = offset.unsigned_abs();
            let (hours, minutes, seconds) = (total / 3600, (total / 60) % 60, total % 60);
            let _ = write!(out, "{sign}{hours:02}:{minutes:02}");
            if seconds != 0 {
                let _ = write!(out, ":{seconds:02}");
            }
        }
        out
    }

    fn parts(&self) -> (i64, u32, u32, u32, u32, u32, u32) {
        let micros_per_day = SECONDS_PER_DAY * MICROS_PER_SECOND;
        let days = self.civil_micros.div_euclid(micros_per_day);
        let mut rest = self.civil_micros.rem_euclid(micros_per_day);
        let microsecond = rest % MICROS_PER_SECOND;
        rest /= MICROS_PER_SECOND;
        let (year, month, day) = civil_from_days(days);
        (
            year,
            month,
            day,
            u32::try_from(rest / 3600).unwrap_or(0),
            u32::try_from((rest / 60) % 60).unwrap_or(0),
            u32::try_from(rest % 60).unwrap_or(0),
            u32::try_from(microsecond).unwrap_or(0),
        )
    }

    /// `datetime.fromisoformat`, over the subset a `--since` value or a
    /// capture timestamp can realistically be.
    ///
    /// Accepted: a complete date, extended (`2024-01-01`) or basic
    /// (`20240101`); optionally a separator — Python accepts *any* single
    /// character where ISO 8601 wants `T` — then a time as `HH`,
    /// `HH:MM`, `HH:MM:SS` or their basic forms, with an optional `.`
    /// or `,` fraction; then optionally `Z`, `z` or `±HH[:MM[:SS]]`.
    ///
    /// Not accepted, and rejected rather than guessed: ISO week dates
    /// (`2024-W01-1`), which Python 3.11+ does take. Nothing in agentcage
    /// writes one, and a wrong answer there is worse than none — `--since`
    /// falls back to "no cutoff", and a capture entry that fails to parse
    /// is kept.
    #[must_use]
    pub fn from_isoformat(text: &str) -> Option<Self> {
        let (year, month, day, consumed) = parse_date(text)?;
        let rest = &text[consumed..];
        if rest.is_empty() {
            return Self::from_parts((year, month, day), (0, 0, 0, 0), None);
        }
        // Python takes whatever character sits between date and time.
        let separator = rest.chars().next()?;
        let (hour, minute, second, microsecond, offset) =
            parse_time(&rest[separator.len_utf8()..])?;
        Self::from_parts(
            (year, month, day),
            (hour, minute, second, microsecond),
            offset,
        )
    }
}

/// `round(x / divisor)` with Python's banker's rounding.
fn round_half_even(value: i64, divisor: i64) -> i64 {
    let quotient = value.div_euclid(divisor);
    let remainder = value.rem_euclid(divisor);
    let doubled = remainder * 2;
    if doubled > divisor || (doubled == divisor && quotient % 2 != 0) {
        quotient + 1
    } else {
        quotient
    }
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days from `1970-01-01` to `year-month-day`, proleptic Gregorian.
/// Howard Hinnant's `days_from_civil`, which is exact for every year
/// Python's `datetime` can hold.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let month = i64::from(month);
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year =
        (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (
        if month <= 2 { year + 1 } else { year },
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

/// The date half, returning the fields and how many bytes it ate.
fn parse_date(text: &str) -> Option<(i64, u32, u32, usize)> {
    let bytes = text.as_bytes();
    if bytes.len() >= 10 && bytes[4] == b'-' && bytes[7] == b'-' {
        let year = parse_digits(&text[0..4])?;
        let month = parse_digits(&text[5..7])?;
        let day = parse_digits(&text[8..10])?;
        return Some((i64::from(year), month, day, 10));
    }
    if bytes.len() >= 8 && bytes[..8].iter().all(u8::is_ascii_digit) {
        let year = parse_digits(&text[0..4])?;
        let month = parse_digits(&text[4..6])?;
        let day = parse_digits(&text[6..8])?;
        return Some((i64::from(year), month, day, 8));
    }
    None
}

type TimeFields = (u32, u32, u32, u32, Option<i32>);

/// The time half plus its offset, from just after the separator.
fn parse_time(text: &str) -> Option<TimeFields> {
    let (time_text, offset) = split_offset(text)?;
    let (hour, minute, second, microsecond) = parse_clock(time_text)?;
    Some((hour, minute, second, microsecond, offset))
}

/// Split `HH:MM:SS.ffffff` from the `Z` or `±HH:MM` that may follow it.
fn split_offset(text: &str) -> Option<(&str, Option<i32>)> {
    // Uppercase only: CPython rejects a lowercase `z`.
    if let Some(clock) = text.strip_suffix('Z') {
        return Some((clock, Some(0)));
    }
    let Some(index) = text.find(['+', '-']) else {
        return Some((text, None));
    };
    let (clock, offset_text) = text.split_at(index);
    let sign = if offset_text.starts_with('-') { -1 } else { 1 };
    if offset_text.len() < 2 {
        return None;
    }
    // Python parses a sub-second offset too; agentcage never writes one,
    // and a whole-second offset is all `isoformat` can render back.
    let (hour, minute, second, _) = parse_clock(&offset_text[1..])?;
    let magnitude = i32::try_from(hour * 3600 + minute * 60 + second).ok()?;
    Some((clock, Some(sign * magnitude)))
}

/// `HH`, `HH:MM`, `HH:MM:SS[.ffffff]` and the basic-format equivalents.
fn parse_clock(text: &str) -> Option<(u32, u32, u32, u32)> {
    if text.is_empty() {
        return None;
    }
    let (clock, fraction) = match text.find(['.', ',']) {
        Some(index) => (&text[..index], Some(&text[index + 1..])),
        None => (text, None),
    };
    let (hour, minute, second) = if clock.contains(':') {
        // Every field is exactly two digits: `12:3` is a ValueError,
        // not five past noon.
        let mut fields = clock.split(':');
        let hour = parse_two_digits(fields.next()?)?;
        let minute = fields.next().map_or(Some(0), parse_two_digits)?;
        let second = fields.next().map_or(Some(0), parse_two_digits)?;
        if fields.next().is_some() {
            return None;
        }
        (hour, minute, second)
    } else {
        match clock.len() {
            2 => (parse_digits(clock)?, 0, 0),
            4 => (parse_digits(&clock[..2])?, parse_digits(&clock[2..])?, 0),
            6 => (
                parse_digits(&clock[..2])?,
                parse_digits(&clock[2..4])?,
                parse_digits(&clock[4..])?,
            ),
            _ => return None,
        }
    };
    Some((hour, minute, second, parse_fraction(fraction)?))
}

/// A decimal fraction of a second as microseconds. Python takes any
/// number of digits and truncates past the sixth.
fn parse_fraction(fraction: Option<&str>) -> Option<u32> {
    let Some(digits) = fraction else {
        return Some(0);
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut micros = String::with_capacity(6);
    micros.push_str(&digits[..digits.len().min(6)]);
    while micros.len() < 6 {
        micros.push('0');
    }
    micros.parse().ok()
}

/// Exactly two ASCII digits.
fn parse_two_digits(text: &str) -> Option<u32> {
    if text.len() != 2 {
        return None;
    }
    parse_digits(text)
}

/// A run of ASCII digits, and nothing else — `int()` on a Python `str`
/// would also take `+`, surrounding whitespace and non-ASCII digits, but
/// `fromisoformat` reaches these through a fixed-width slice.
fn parse_digits(text: &str) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::DateTime;

    fn iso(text: &str) -> Option<String> {
        DateTime::from_isoformat(text).map(|dt| dt.isoformat())
    }

    /// Each expectation is `datetime.fromisoformat(s).isoformat()` read
    /// off `CPython` 3.14, which is the newest interpreter the corpus is
    /// generated on.
    #[test]
    fn from_isoformat_agrees_with_python() {
        let accepted: &[(&str, &str)] = &[
            ("2024-01-01", "2024-01-01T00:00:00"),
            ("20240101", "2024-01-01T00:00:00"),
            ("2024-01-01T12:34:56", "2024-01-01T12:34:56"),
            // Any single character will do as the separator.
            ("2024-01-01 12:34:56", "2024-01-01T12:34:56"),
            ("2024-01-01x12:34:56", "2024-01-01T12:34:56"),
            ("2024-01-01T12", "2024-01-01T12:00:00"),
            ("2024-01-01T123456", "2024-01-01T12:34:56"),
            ("2024-01-01T12:34:56.123456", "2024-01-01T12:34:56.123456"),
            // Past six digits the fraction is truncated, not rounded.
            ("2024-01-01T12:34:56.1234567", "2024-01-01T12:34:56.123456"),
            ("2024-01-01T12:34:56.5", "2024-01-01T12:34:56.500000"),
            ("2024-01-01T12:34:56Z", "2024-01-01T12:34:56+00:00"),
            ("2024-01-01T12:34:56+05:30", "2024-01-01T12:34:56+05:30"),
            ("2024-01-01T12:34:56-0530", "2024-01-01T12:34:56-05:30"),
            // An offset can carry seconds, and `isoformat` shows them.
            (
                "2024-01-01T12:34:56+00:00:30",
                "2024-01-01T12:34:56+00:00:30",
            ),
            ("0001-01-01", "0001-01-01T00:00:00"),
            (
                "9999-12-31T23:59:59.999999+00:00",
                "9999-12-31T23:59:59.999999+00:00",
            ),
        ];
        for (text, expected) in accepted {
            assert_eq!(iso(text).as_deref(), Some(*expected), "parsing {text:?}");
        }

        let rejected = [
            "",
            "not-a-date",
            "2024-1-1",
            "2024-13-01",
            "2024-02-30",
            "2024-01-01T25:00:00",
            "2024-01-01T12:3",
            "2024-01-01T12:34:5",
            "2024-01-01T12:34:56.",
            "2024-01-01T",
            "2024-01-01T12:34:56+",
            // CPython wants an uppercase Z.
            "2024-01-01T12:34:56z",
            // A gap, not an accident: ISO week dates parse in Python and
            // are refused here rather than guessed at.
            "2024-W01-1",
        ];
        for text in rejected {
            assert_eq!(iso(text), None, "{text:?} should not parse");
        }
    }

    /// The leap-year rules, at the three boundaries that disagree.
    #[test]
    fn leap_years_are_gregorian() {
        assert!(iso("2024-02-29").is_some());
        assert!(iso("2000-02-29").is_some());
        assert!(iso("1900-02-29").is_none());
        assert!(iso("2023-02-29").is_none());
    }

    /// Python raises `TypeError` for a naive/aware comparison, and
    /// `CaptureFilter.matches` turns that into "keep the entry".
    #[test]
    fn naive_and_aware_do_not_compare() {
        let naive = DateTime::from_isoformat("2024-01-01T00:00:00").unwrap();
        let aware = DateTime::from_isoformat("2024-06-01T00:00:00+00:00").unwrap();
        assert!(!naive.is_aware());
        assert!(aware.is_aware());
        assert_eq!(naive.lt(&aware), None);
        assert_eq!(aware.lt(&naive), None);
        assert_eq!(naive.lt(&naive), Some(false));
        assert_eq!(naive.assume_utc().lt(&aware), Some(true));
    }

    /// An offset is part of the instant, not decoration.
    #[test]
    fn offsets_move_the_instant() {
        let utc = DateTime::from_isoformat("2024-01-01T12:00:00+00:00").unwrap();
        let ahead = DateTime::from_isoformat("2024-01-01T12:00:00+05:30").unwrap();
        assert_eq!(ahead.lt(&utc), Some(true));
        assert_eq!(utc.seconds_since(&ahead), Some(19_800));
    }

    #[test]
    fn subtraction_stops_at_pythons_range() {
        let start = DateTime::from_isoformat("2024-01-01T00:00:00+00:00").unwrap();
        assert_eq!(
            start.checked_sub_seconds(86_400).map(|d| d.isoformat()),
            Some("2023-12-31T00:00:00+00:00".to_string())
        );
        // Before year 1 is `OverflowError` in Python.
        assert_eq!(start.checked_sub_seconds(i64::MAX / 4), None);
        assert_eq!(start.checked_sub_seconds(i64::MAX), None);
    }
}
