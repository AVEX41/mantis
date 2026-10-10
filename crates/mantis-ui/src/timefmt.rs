//! Timestamp formatting without a date-time dependency.

/// `YYYY-MM-DD HH:MM:SS.mmm` (UTC) for unix microseconds.
pub fn format_utc(micros: i64) -> String {
    let secs = micros.div_euclid(1_000_000);
    let ms = micros.rem_euclid(1_000_000) / 1000;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{ms:03}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::format_utc;

    #[test]
    fn known_instants() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00.000");
        assert_eq!(format_utc(1_700_000_000_123_456), "2023-11-14 22:13:20.123");
        assert_eq!(format_utc(951_782_400_000_000), "2000-02-29 00:00:00.000"); // leap day
        assert_eq!(format_utc(-1), "1969-12-31 23:59:59.999");
        assert_eq!(format_utc(1_791_590_400_000_000), "2026-10-10 00:00:00.000");
    }
}
