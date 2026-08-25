use serde::Deserialize;

use crate::paths::DelvePaths;

const DEFAULT_RETENTION: &str = "180d";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRetention {
    Never,
    Days(u64),
    Months(u32),
}

#[derive(Debug, Clone)]
pub struct DelveConfig {
    pub session_retention: SessionRetention,
}

impl Default for DelveConfig {
    fn default() -> Self {
        Self {
            session_retention: parse_retention(DEFAULT_RETENTION).expect("default retention"),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct DelveConfigFile {
    #[serde(default)]
    session: SessionSection,
}

#[derive(Debug, Deserialize, Default)]
struct SessionSection {
    retention: Option<String>,
}

impl DelveConfig {
    pub fn load(paths: &DelvePaths) -> (Self, Vec<String>) {
        let mut warnings = Vec::new();
        let path = paths.config_file();
        if !path.exists() {
            return (Self::default(), warnings);
        }

        let contents = match std::fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(error) => {
                warnings.push(format!(
                    "warning: could not read config {}: {}",
                    path.display(),
                    error
                ));
                return (Self::default(), warnings);
            }
        };

        let parsed: DelveConfigFile = match serde_yaml::from_str(&contents) {
            Ok(parsed) => parsed,
            Err(error) => {
                warnings.push(format!(
                    "warning: invalid config {}: {}; using defaults",
                    path.display(),
                    error
                ));
                return (Self::default(), warnings);
            }
        };

        let retention_raw = parsed
            .session
            .retention
            .unwrap_or_else(|| DEFAULT_RETENTION.to_string());
        let session_retention = match parse_retention(&retention_raw) {
            Ok(retention) => retention,
            Err(error) => {
                warnings.push(format!(
                    "warning: invalid session.retention \"{retention_raw}\": {error}; using {DEFAULT_RETENTION}"
                ));
                parse_retention(DEFAULT_RETENTION).expect("default retention")
            }
        };

        (Self { session_retention }, warnings)
    }
}

pub fn parse_retention(raw: &str) -> Result<SessionRetention, String> {
    let value = raw.trim().to_ascii_lowercase();
    if value.is_empty() {
        return Err("empty retention value".into());
    }
    if value == "0" || value == "never" {
        return Ok(SessionRetention::Never);
    }
    if let Some(days) = value.strip_suffix('d') {
        let days: u64 = days
            .parse()
            .map_err(|error| format!("invalid day count: {error}"))?;
        return Ok(SessionRetention::Days(days));
    }
    if let Some(months) = value.strip_suffix("mo") {
        let months: u32 = months
            .parse()
            .map_err(|error| format!("invalid month count: {error}"))?;
        return Ok(SessionRetention::Months(months));
    }
    Err(format!(
        "expected duration like 180d, 6mo, 0, or never; got \"{raw}\""
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_retention_forms() {
        assert_eq!(
            parse_retention("180d").expect("days"),
            SessionRetention::Days(180)
        );
        assert_eq!(
            parse_retention("6mo").expect("months"),
            SessionRetention::Months(6)
        );
        assert_eq!(
            parse_retention("never").expect("never"),
            SessionRetention::Never
        );
        assert_eq!(parse_retention("0").expect("zero"), SessionRetention::Never);
    }
}
