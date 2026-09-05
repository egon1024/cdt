use serde::Deserialize;

use crate::paths::DelvePaths;

const DEFAULT_RETENTION: &str = "never";
const DEFAULT_MAX_QUERIES: usize = 64;
const DEFAULT_MAX_PARALLEL_QUERIES: usize = 8;
const DEFAULT_RTT_GREEN_MS: u32 = 50;
const DEFAULT_RTT_YELLOW_MS: u32 = 125;
const DEFAULT_RTT_ORANGE_MS: u32 = 250;
const DEFAULT_RTT_INSANE_MS: u32 = 1000;
const DEFAULT_RTT_BAR_WIDTH: u16 = 20;

/// Fixed RTT scale for absolute-length bars (Browse detail, SVG export cards).
/// Matches the default `orange_ms` color threshold.
pub const RTT_BAR_ABSOLUTE_SCALE_MS: u32 = DEFAULT_RTT_ORANGE_MS;

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
        let parsed = read_delve_config_file(paths, &mut warnings);

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

    /// Emit all configurable keys in YAML form. Keys present in the config file are
    /// uncommented; unset keys are commented with their default values. Sections with
    /// no active keys are commented out entirely.
    pub fn dump_yaml(paths: &DelvePaths) -> (String, Vec<String>) {
        let mut warnings = Vec::new();
        let parsed = read_delve_config_file(paths, &mut warnings);
        let defaults = Self::default();
        let default_rtt = defaults.explore_rtt_bar;

        let mut out = String::new();
        let config_path = paths.config_file();
        out.push_str("# Config file: ");
        out.push_str(&config_path.display().to_string());
        out.push('\n');
        if config_path.exists() {
            out.push_str("# (file exists)\n");
        } else {
            out.push_str("# (file not found; showing defaults)\n");
        }
        out.push_str(
            "# Commented lines show default values (not set in your config file).\n\
             # Remove the leading # to override a default.\n\n",
        );

        write_session_dump_section(&mut out, &parsed);
        write_trace_dump_section(&mut out, &parsed, &defaults);
        write_explore_dump_section(&mut out, &parsed, &defaults, default_rtt);

        (out, warnings)
    }
}

fn read_delve_config_file(paths: &DelvePaths, warnings: &mut Vec<String>) -> DelveConfigFile {
    let path = paths.config_file();
    if !path.exists() {
        return DelveConfigFile::default();
    }

    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) => {
            warnings.push(format!(
                "warning: could not read config {}: {}",
                path.display(),
                error
            ));
            return DelveConfigFile::default();
        }
    };

    match serde_yaml::from_str(&contents) {
        Ok(parsed) => parsed,
        Err(error) => {
            warnings.push(format!(
                "warning: invalid config {}: {}; using defaults",
                path.display(),
                error
            ));
            DelveConfigFile::default()
        }
    }
}

fn write_session_dump_section(out: &mut String, parsed: &DelveConfigFile) {
    let mut body = String::new();
    write_yaml_key(
        &mut body,
        1,
        "retention",
        parsed.session.retention.clone(),
        DEFAULT_RETENTION.to_string(),
    );
    write_dump_section(out, "session", parsed.session.retention.is_some(), &body);
}

fn write_trace_dump_section(out: &mut String, parsed: &DelveConfigFile, defaults: &DelveConfig) {
    let mut body = String::new();
    write_yaml_key(
        &mut body,
        1,
        "max_queries_per_action",
        parsed.trace.max_queries_per_action,
        defaults.trace_max_queries_per_action,
    );
    write_yaml_key(
        &mut body,
        1,
        "max_parallel_queries",
        parsed.trace.max_parallel_queries,
        defaults.trace_max_parallel_queries,
    );
    let active = parsed.trace.max_queries_per_action.is_some()
        || parsed.trace.max_parallel_queries.is_some();
    write_dump_section(out, "trace", active, &body);
}

fn write_explore_dump_section(
    out: &mut String,
    parsed: &DelveConfigFile,
    defaults: &DelveConfig,
    default_rtt: RttBarConfig,
) {
    let mut body = String::new();
    write_yaml_key(
        &mut body,
        1,
        "persist_view_state",
        parsed.explore.persist_view_state,
        defaults.explore_persist_view_state,
    );
    let rtt_bar_active =
        write_rtt_bar_dump_section(&mut body, parsed.explore.rtt_bar.as_ref(), default_rtt);
    let active = parsed.explore.persist_view_state.is_some() || rtt_bar_active;
    write_dump_section(out, "explore", active, &body);
}

fn write_rtt_bar_dump_section(
    out: &mut String,
    section: Option<&RttBarSection>,
    default_rtt: RttBarConfig,
) -> bool {
    let mut body = String::new();
    let green_active = write_yaml_key(
        &mut body,
        2,
        "green_ms",
        section.and_then(|section| section.green_ms),
        default_rtt.green_ms,
    );
    let yellow_active = write_yaml_key(
        &mut body,
        2,
        "yellow_ms",
        section.and_then(|section| section.yellow_ms),
        default_rtt.yellow_ms,
    );
    let orange_active = write_yaml_key(
        &mut body,
        2,
        "orange_ms",
        section.and_then(|section| section.orange_ms),
        default_rtt.orange_ms,
    );
    let insane_active = write_yaml_key(
        &mut body,
        2,
        "insane_ms",
        section.and_then(|section| section.insane_ms),
        default_rtt.insane_ms,
    );
    let max_width_active = write_yaml_key(
        &mut body,
        2,
        "max_width",
        section.and_then(|section| section.max_width),
        default_rtt.max_width,
    );
    let active =
        green_active || yellow_active || orange_active || insane_active || max_width_active;
    write_dump_section(out, "  rtt_bar", active, &body);
    active
}

fn write_dump_section(out: &mut String, name: &str, active: bool, body: &str) {
    if active {
        out.push_str(name);
        out.push_str(":\n");
        out.push_str(body);
    } else {
        out.push('#');
        out.push_str(name);
        out.push_str(":\n");
        out.push_str(&comment_block(body));
    }
}

fn comment_block(lines: &str) -> String {
    let mut out = String::new();
    for line in lines.lines() {
        if line.is_empty() {
            out.push('\n');
            continue;
        }
        if line.starts_with('#') {
            out.push_str(line);
        } else {
            out.push('#');
            out.push_str(line);
        }
        out.push('\n');
    }
    out
}

fn write_yaml_key<T: std::fmt::Display>(
    out: &mut String,
    depth: usize,
    key: &str,
    value: Option<T>,
    default: T,
) -> bool {
    let indent = "  ".repeat(depth);
    if let Some(value) = value {
        out.push_str(&format!("{indent}{key}: {value}\n"));
        true
    } else {
        out.push_str(&format!("#{indent}{key}: {default}\n"));
        false
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
        assert_eq!(config.yellow_ms, 125);
        assert_eq!(config.orange_ms, 250);
        assert_eq!(config.insane_ms, 1000);
        assert_eq!(config.max_width, 20);
    }

    #[test]
    fn dump_yaml_without_config_comments_all_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = DelvePaths::from_root(dir.path());
        let (yaml, warnings) = DelveConfig::dump_yaml(&paths);
        assert!(warnings.is_empty());
        assert!(yaml.contains(&format!("# Config file: {}", paths.config_file().display())));
        assert!(yaml.contains("# (file not found; showing defaults)"));
        assert!(yaml.contains("# Commented lines show default values"));
        assert!(yaml.contains("#session:"));
        assert!(yaml.contains("#  retention: never"));
        assert!(yaml.contains("#trace:"));
        assert!(yaml.contains("#  max_queries_per_action: 64"));
        assert!(yaml.contains("#  max_parallel_queries: 8"));
        assert!(yaml.contains("#explore:"));
        assert!(yaml.contains("#  persist_view_state: true"));
        assert!(yaml.contains("#  rtt_bar:"));
        assert!(yaml.contains("#    green_ms: 50"));
        assert!(!yaml.contains("\n  retention: "));
        assert!(!yaml.contains("\n  rtt_bar:\n"));
    }

    #[test]
    fn dump_yaml_reflects_set_values() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = DelvePaths::from_root(dir.path());
        std::fs::create_dir_all(paths.config_file().parent().expect("parent")).expect("mkdir");
        std::fs::write(
            paths.config_file(),
            "session:\n  retention: 180d\ntrace:\n  max_parallel_queries: 4\nexplore:\n  rtt_bar:\n    green_ms: 75\n",
        )
        .expect("write config");

        let (yaml, warnings) = DelveConfig::dump_yaml(&paths);
        assert!(warnings.is_empty());
        assert!(yaml.contains(&format!("# Config file: {}", paths.config_file().display())));
        assert!(yaml.contains("# (file exists)"));
        assert!(yaml.contains("session:\n  retention: 180d"));
        assert!(yaml.contains("#  max_queries_per_action: 64"));
        assert!(yaml.contains("  max_parallel_queries: 4"));
        assert!(yaml.contains("#  persist_view_state: true"));
        assert!(yaml.contains("  rtt_bar:\n    green_ms: 75"));
        assert!(yaml.contains("#    yellow_ms: 125"));
    }
}
