use serde::Deserialize;

use crate::paths::DelvePaths;

const DEFAULT_RETENTION: &str = "never";
const DEFAULT_MAX_QUERIES: usize = 64;
const DEFAULT_MAX_PARALLEL_QUERIES: usize = 8;
const DEFAULT_RTT_GREEN_MS: u32 = 50;
const DEFAULT_RTT_YELLOW_MS: u32 = 150;
const DEFAULT_RTT_ORANGE_MS: u32 = 500;
const DEFAULT_RTT_INSANE_MS: u32 = 2000;
const DEFAULT_RTT_BAR_WIDTH: u16 = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RttBarConfig {
    pub green_ms: u32,
    pub yellow_ms: u32,
    pub orange_ms: u32,
    pub insane_ms: u32,
    pub max_width: u16,
}

impl Default for RttBarConfig {
    fn default() -> Self {
        Self {
            green_ms: DEFAULT_RTT_GREEN_MS,
            yellow_ms: DEFAULT_RTT_YELLOW_MS,
            orange_ms: DEFAULT_RTT_ORANGE_MS,
            insane_ms: DEFAULT_RTT_INSANE_MS,
            max_width: DEFAULT_RTT_BAR_WIDTH,
        }
    }
}

impl RttBarConfig {
    pub fn normalized(self) -> Self {
        let green_ms = self.green_ms.max(1);
        let yellow_ms = self.yellow_ms.max(green_ms + 1);
        let orange_ms = self.orange_ms.max(yellow_ms + 1);
        let insane_ms = self.insane_ms.max(orange_ms + 1);
        let max_width = self.max_width.clamp(4, 40);
        Self {
            green_ms,
            yellow_ms,
            orange_ms,
            insane_ms,
            max_width,
        }
    }
}

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
    pub explore_rtt_bar: RttBarConfig,
}

impl Default for DelveConfig {
    fn default() -> Self {
        Self {
            session_retention: SessionRetention::Never,
            trace_max_queries_per_action: DEFAULT_MAX_QUERIES,
            trace_max_parallel_queries: DEFAULT_MAX_PARALLEL_QUERIES,
            explore_persist_view_state: true,
            explore_rtt_bar: RttBarConfig::default(),
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
    rtt_bar: Option<RttBarSection>,
}

#[derive(Debug, Deserialize, Default)]
struct RttBarSection {
    green_ms: Option<u32>,
    yellow_ms: Option<u32>,
    orange_ms: Option<u32>,
    insane_ms: Option<u32>,
    max_width: Option<u16>,
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
        let explore_rtt_bar = parse_rtt_bar_config(parsed.explore.rtt_bar, &mut warnings);

        (
            Self {
                session_retention,
                trace_max_queries_per_action,
                trace_max_parallel_queries,
                explore_persist_view_state,
                explore_rtt_bar,
            },
            warnings,
        )
    }
}

fn parse_rtt_bar_config(
    section: Option<RttBarSection>,
    warnings: &mut Vec<String>,
) -> RttBarConfig {
    let defaults = RttBarConfig::default();
    let section = section.unwrap_or_default();
    let mut config = RttBarConfig {
        green_ms: section.green_ms.unwrap_or(defaults.green_ms),
        yellow_ms: section.yellow_ms.unwrap_or(defaults.yellow_ms),
        orange_ms: section.orange_ms.unwrap_or(defaults.orange_ms),
        insane_ms: section.insane_ms.unwrap_or(defaults.insane_ms),
        max_width: section.max_width.unwrap_or(defaults.max_width),
    };
    if section.green_ms.is_some()
        || section.yellow_ms.is_some()
        || section.orange_ms.is_some()
        || section.insane_ms.is_some()
    {
        let normalized = config.normalized();
        if normalized != config {
            warnings.push(
                "warning: explore.rtt_bar thresholds adjusted to be strictly increasing".into(),
            );
        }
        config = normalized;
    } else if section.max_width.is_some() {
        config.max_width = config.max_width.clamp(4, 40);
    }
    config
}

pub fn parse_retention(raw: &str) -> Result<SessionRetention, String> {
    let value = raw.trim().to_ascii_lowercase();
    if value.is_empty() {
        return Err("empty retention value".into());
    }
    if value == "0" || value == "never" || value == "unlimited" {
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
        "expected duration like 180d, 6mo, unlimited, 0, or never; got \"{raw}\""
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
        assert_eq!(
            parse_retention("unlimited").expect("unlimited"),
            SessionRetention::Never
        );
    }

    #[test]
    fn default_session_retention_is_unlimited() {
        assert_eq!(
            DelveConfig::default().session_retention,
            SessionRetention::Never
        );
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

    #[test]
    fn default_rtt_bar_config_matches_expected_thresholds() {
        let config = DelveConfig::default().explore_rtt_bar;
        assert_eq!(config.green_ms, 50);
        assert_eq!(config.yellow_ms, 150);
        assert_eq!(config.orange_ms, 500);
        assert_eq!(config.insane_ms, 2000);
        assert_eq!(config.max_width, 20);
    }
}
