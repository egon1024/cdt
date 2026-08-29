use time::{Date, Month, OffsetDateTime};

use crate::config::SessionRetention;

pub struct PurgeReport {
    pub removed: usize,
    pub skipped_unparseable: usize,
}

/// Parse session timestamps (RFC 3339). Returns None if unparseable.
pub fn parse_session_timestamp(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()
}

/// Whether a session should be removed under retention policy.
pub fn is_expired(
    updated_at: &str,
    retention: SessionRetention,
    now: OffsetDateTime,
) -> Option<bool> {
    let cutoff = retention.cutoff(now)?;
    let updated = parse_session_timestamp(updated_at)?;
    Some(updated < cutoff)
}

pub fn retention_label(retention: SessionRetention) -> String {
    match retention {
        SessionRetention::Never => "never".into(),
        SessionRetention::Days(days) => format!("{days}d"),
        SessionRetention::Months(months) => format!("{months}mo"),
    }
}

impl SessionRetention {
    pub fn cutoff(self, now: OffsetDateTime) -> Option<OffsetDateTime> {
        match self {
            Self::Never => None,
            Self::Days(days) => Some(now - time::Duration::days(days as i64)),
            Self::Months(months) => {
                let date = subtract_months(now.date(), months);
                Some(
                    date.with_time(now.time())
                        .assume_utc()
                        .replace_time(now.time()),
                )
            }
        }
    }
}

fn subtract_months(date: Date, months: u32) -> Date {
    let mut year = date.year();
    let mut month_number = date.month() as i32 - months as i32;
    while month_number < 1 {
        month_number += 12;
        year -= 1;
    }
    while month_number > 12 {
        month_number -= 12;
        year += 1;
    }
    let month = Month::try_from(month_number as u8).expect("valid month");
    let max_day = month.length(year);
    let day = date.day().min(max_day);
    Date::from_calendar_date(year, month, day).expect("valid calendar date")
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn days_retention_cutoff() {
        let now = datetime!(2026-08-25 12:00:00 UTC);
        let cutoff = SessionRetention::Days(180).cutoff(now).expect("cutoff");
        assert_eq!(cutoff, datetime!(2026-02-26 12:00:00 UTC));
    }

    #[test]
    fn months_retention_uses_calendar_months() {
        let now = datetime!(2026-08-25 12:00:00 UTC);
        let cutoff = SessionRetention::Months(6).cutoff(now).expect("cutoff");
        assert_eq!(cutoff.date(), datetime!(2026-02-25 00:00:00 UTC).date());
    }

    #[test]
    fn months_retention_clamps_end_of_month() {
        let now = datetime!(2026-03-31 10:00:00 UTC);
        let cutoff = SessionRetention::Months(1).cutoff(now).expect("cutoff");
        assert_eq!(cutoff.date(), datetime!(2026-02-28 00:00:00 UTC).date());
    }

    #[test]
    fn never_retention_never_expires() {
        let now = datetime!(2026-08-25 12:00:00 UTC);
        assert!(SessionRetention::Never.cutoff(now).is_none());
        assert_eq!(
            is_expired("2020-01-01T00:00:00Z", SessionRetention::Never, now),
            None
        );
    }

    #[test]
    fn recently_updated_session_survives_retention() {
        let now = datetime!(2026-08-25 12:00:00 UTC);
        assert_eq!(
            is_expired("2026-08-24T00:00:00Z", SessionRetention::Days(30), now),
            Some(false)
        );
    }

    #[test]
    fn untouched_old_session_is_purged() {
        let now = datetime!(2026-08-25 12:00:00 UTC);
        assert_eq!(
            is_expired("2020-01-01T00:00:00Z", SessionRetention::Days(30), now),
            Some(true)
        );
    }
}
