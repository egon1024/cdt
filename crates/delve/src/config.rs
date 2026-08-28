use serde::Deserialize;

use crate::paths::DelvePaths;

const DEFAULT_RETENTION: &str = "180d";
const DEFAULT_MAX_QUERIES: usize = 64;
const DEFAULT_MAX_PARALLEL_QUERIES: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRetention {
    Never,
    Days(u64),
    Months(u32),
}

#[derive(Debug, Clone)]
pub struct DelveConfig {
    pub session_retention: SessionRetention,
    pub trace_max_queries_per_action: usize,
    pub trace_max_parallel_queries: usize,
    /// Used by explore view-state persistence (Phase 5).
    #[allow(dead_code)]
    pub explore_persist_view_state: bool,
}

impl Default for DelveConfig {
    fn default() -> Self {
        Self {
            session_retention: parse_retention(DEFAULT_RETENTION).expect("default retention"),
            trace_max_queries_per_action: DEFAULT_MAX_QUERIES,
            trace_max_parallel_queries: DEFAULT_MAX_PARALLEL_QUERIES,
            explore_persist_view_state: true,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct DelveConfigFile {
    #[serde(default)]
    session: SessionSection,
    #[serde(default)]
    trace: TraceSection,
    #[serde(default)]
    explore: ExploreSection,
}

#[derive(Debug, Deserialize, Default)]
struct SessionSection {
    retention: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct TraceSection {
    max_queries_per_action: Option<usize>,
    max_parallel_queries: Option<usize>,
}

#[derive(Debug, Deserialize, Default)]
struct ExploreSection {
    persist_view_state: Option<bool>,
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

        let trace_max_queries_per_action = match parsed.trace.max_queries_per_action {
            None => DEFAULT_MAX_QUERIES,
            Some(0) => {
                warnings.push(format!(
                    "warning: invalid trace.max_queries_per_action 0; using {DEFAULT_MAX_QUERIES}"
                ));
                DEFAULT_MAX_QUERIES
            }
            Some(value) => value,
        };

        let trace_max_parallel_queries = match parsed.trace.max_parallel_queries {
            None => DEFAULT_MAX_PARALLEL_QUERIES,
            Some(0) => {
                warnings.push(format!(
                    "warning: invalid trace.max_parallel_queries 0; using {DEFAULT_MAX_PARALLEL_QUERIES}"
                ));
                DEFAULT_MAX_PARALLEL_QUERIES
            }
            Some(value) => value,
        };

        let explore_persist_view_state = parsed.explore.persist_view_state.unwrap_or(true);

        (
            Self {
                session_retention,
                trace_max_queries_per_action,
                trace_max_parallel_queries,
                explore_persist_view_state,
            },
            warnings,
        )
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

    #[test]
    fn default_max_queries_is_sixty_four() {
        assert_eq!(DelveConfig::default().trace_max_queries_per_action, 64);
    }

    #[test]
    fn default_max_parallel_queries_is_eight() {
        assert_eq!(DelveConfig::default().trace_max_parallel_queries, 8);
    }

    #[test]
    fn default_persist_view_state_is_true() {
        assert!(DelveConfig::default().explore_persist_view_state);
    }
}
