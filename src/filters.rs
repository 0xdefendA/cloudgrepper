//! Object-listing filters, ported from cloud.py's filter_object* functions.

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};

#[derive(Clone, Debug)]
pub struct ObjectMeta {
    pub key: String,
    pub size: i64,
    pub last_modified: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Default)]
pub struct Filters {
    pub key_contains: Option<String>,
    pub from_date: Option<DateTime<Utc>>,
    pub to_date: Option<DateTime<Utc>>,
    pub max_size: i64,
    // filter_object_google never checks size — GCS sets this false
    pub check_size: bool,
}

impl Filters {
    pub fn matches(&self, obj: &ObjectMeta) -> bool {
        if let Some(lm) = obj.last_modified {
            if let Some(from) = self.from_date {
                if lm < from {
                    return false;
                }
            }
            if let Some(to) = self.to_date {
                if lm > to {
                    return false;
                }
            }
        }
        if self.check_size && (obj.size == 0 || obj.size > self.max_size) {
            return false;
        }
        if let Some(kc) = &self.key_contains {
            if !obj.key.contains(kc.as_str()) {
                return false;
            }
        }
        true
    }
}

pub fn parse_date(s: &str) -> anyhow::Result<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Ok(dt.with_timezone(&Utc));
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Ok(ndt.and_utc());
    }
    if let Ok(ndt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Ok(ndt.and_utc());
    }
    if let Ok(nd) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Ok(nd.and_hms_opt(0, 0, 0).unwrap().and_utc());
    }
    anyhow::bail!("could not parse date: {s}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn meta(key: &str, size: i64, y: i32) -> ObjectMeta {
        ObjectMeta {
            key: key.into(),
            size,
            last_modified: Some(Utc.with_ymd_and_hms(y, 1, 1, 0, 0, 0).unwrap()),
        }
    }

    fn window() -> Filters {
        Filters {
            key_contains: Some("example".into()),
            from_date: Some(Utc.with_ymd_and_hms(2021, 1, 1, 0, 0, 0).unwrap()),
            to_date: Some(Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).unwrap()),
            max_size: 500,
            check_size: true,
        }
    }

    #[test]
    fn size_over_limit_rejected_then_accepted() {
        // Port of test_object_not_empty_and_size_greater_than_file_size
        let obj = meta("example_file.txt", 1000, 2022);
        assert!(!window().matches(&obj));
        let mut f = window();
        f.max_size = 500_000;
        assert!(f.matches(&obj));
    }

    #[test]
    fn empty_file_rejected() {
        // Port of test_filter_object_s3_empty_file
        let mut f = window();
        f.key_contains = Some("empty".into());
        f.max_size = 10_000;
        assert!(!f.matches(&meta("empty_file.log", 0, 2023)));
    }

    #[test]
    fn out_of_date_range_rejected() {
        let f = Filters {
            key_contains: Some("old".into()),
            from_date: Some(Utc.with_ymd_and_hms(2022, 1, 1, 0, 0, 0).unwrap()),
            to_date: Some(Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap()),
            max_size: 10_000,
            check_size: true,
        };
        assert!(!f.matches(&meta("old_file.log", 500, 2021)));
    }

    #[test]
    fn gcs_style_no_size_check() {
        // Port of test_returns_true_if_all_conditions_are_met: GCS blob with
        // no size still matches because filter_object_google never checks size
        let mut f = window();
        f.check_size = false;
        let obj = ObjectMeta {
            key: "example_file.txt".into(),
            size: 0,
            last_modified: None,
        };
        assert!(f.matches(&obj));
    }

    #[test]
    fn key_contains_rejects_nonmatching() {
        assert!(!window().matches(&meta("not_a_thing.txt", 100, 2022)));
    }

    #[test]
    fn parse_date_forms() {
        assert_eq!(
            parse_date("2023-01-01").unwrap(),
            Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).unwrap()
        );
        assert_eq!(
            parse_date("2023-01-01T10:30:00").unwrap(),
            Utc.with_ymd_and_hms(2023, 1, 1, 10, 30, 0).unwrap()
        );
        assert_eq!(
            parse_date("2023-01-01T10:30:00Z").unwrap(),
            Utc.with_ymd_and_hms(2023, 1, 1, 10, 30, 0).unwrap()
        );
        assert_eq!(
            parse_date("2023-01-01 10:30:00").unwrap(),
            Utc.with_ymd_and_hms(2023, 1, 1, 10, 30, 0).unwrap()
        );
        assert!(parse_date("not a date").is_err());
    }
}
