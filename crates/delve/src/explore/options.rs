use std::time::Duration;

use dns_core::Transport;
use dns_resolve::TraceConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExploreOptions {
    pub plus_icmp: bool,
    pub query_overrides: ExploreQueryOverrides,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExploreQueryOverrides {
    pub timeout_secs: Option<u64>,
    pub retries: Option<u8>,
    pub use_tcp: Option<bool>,
}

impl ExploreQueryOverrides {
    pub fn is_empty(&self) -> bool {
        self.timeout_secs.is_none() && self.retries.is_none() && self.use_tcp.is_none()
    }
}

pub fn apply_explore_query_overrides(
    config: &mut TraceConfig,
    overrides: &ExploreQueryOverrides,
) {
    if let Some(timeout_secs) = overrides.timeout_secs {
        config.timeout = Duration::from_secs(timeout_secs.max(1));
    }
    if let Some(retries) = overrides.retries {
        config.retries = retries;
    }
    if let Some(use_tcp) = overrides.use_tcp {
        config.transport = if use_tcp {
            Transport::Tcp
        } else {
            Transport::Udp
        };
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExploreParseError {
    #[error("unexpected argument: {0}")]
    Unexpected(String),

    #[error("unknown option: {0}")]
    UnknownOption(String),

    #[error("missing value for {0}")]
    MissingValue(String),

    #[error("invalid value for {option}: {value}")]
    InvalidValue { option: String, value: String },
}

pub fn parse_explore_args(args: &[String]) -> Result<ExploreOptions, ExploreParseError> {
    let mut plus_icmp = false;
    let mut query_overrides = ExploreQueryOverrides::default();
    for arg in args {
        match arg.as_str() {
            "+icmp" => plus_icmp = true,
            other if other.starts_with('+') => {
                apply_explore_plus_option(other, &mut query_overrides)?;
            }
            other => return Err(ExploreParseError::Unexpected(other.to_string())),
        }
    }
    Ok(ExploreOptions {
        plus_icmp,
        query_overrides,
    })
}

fn apply_explore_plus_option(
    arg: &str,
    overrides: &mut ExploreQueryOverrides,
) -> Result<(), ExploreParseError> {
    let body = arg.trim_start_matches('+');
    let (keyword, value, negate) = split_query_option(body);

    match keyword {
        "time" | "timeout" => {
            let Some(raw) = value else {
                return Err(ExploreParseError::MissingValue(format!("+{keyword}")));
            };
            overrides.timeout_secs = Some(parse_timeout_seconds(keyword, raw)?);
        }
        "tries" => {
            let Some(raw) = value else {
                return Err(ExploreParseError::MissingValue("+tries".into()));
            };
            overrides.retries = Some(parse_tries(raw)?);
        }
        "tcp" => overrides.use_tcp = Some(!negate),
        "notcp" => overrides.use_tcp = Some(false),
        other => return Err(ExploreParseError::UnknownOption(format!("+{other}"))),
    }
    Ok(())
}

fn split_query_option(body: &str) -> (&str, Option<&str>, bool) {
    if let Some(rest) = body.strip_prefix("no") {
        if let Some((keyword, value)) = rest.split_once('=') {
            return (keyword, Some(value), true);
        }
        return (rest, None, true);
    }

    if let Some((keyword, value)) = body.split_once('=') {
        return (keyword, Some(value), false);
    }

    (body, None, false)
}

fn parse_timeout_seconds(option: &str, raw: &str) -> Result<u64, ExploreParseError> {
    let parsed: u64 = raw.parse().map_err(|_| ExploreParseError::InvalidValue {
        option: format!("+{option}"),
        value: raw.into(),
    })?;
    Ok(parsed.max(1))
}

fn parse_tries(raw: &str) -> Result<u8, ExploreParseError> {
    let parsed: u16 = raw.parse().map_err(|_| ExploreParseError::InvalidValue {
        option: "+tries".into(),
        value: raw.into(),
    })?;
    Ok((parsed.max(1)) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn parse_plus_icmp_flag() {
        let options = parse_explore_args(&args(&["+icmp"])).expect("parse");
        assert!(options.plus_icmp);
    }

    #[test]
    fn parse_empty_args() {
        let options = parse_explore_args(&[]).expect("parse");
        assert!(!options.plus_icmp);
        assert!(options.query_overrides.is_empty());
    }

    #[test]
    fn parse_timeout_and_tries_overrides() {
        let options =
            parse_explore_args(&args(&["+timeout=2", "+tries=1"])).expect("parse");
        assert_eq!(options.query_overrides.timeout_secs, Some(2));
        assert_eq!(options.query_overrides.retries, Some(1));
    }

    #[test]
    fn parse_time_alias_for_timeout() {
        let options = parse_explore_args(&args(&["+time=3"])).expect("parse");
        assert_eq!(options.query_overrides.timeout_secs, Some(3));
    }

    #[test]
    fn apply_overrides_updates_trace_config() {
        let mut config = TraceConfig::new(
            dns_core::DomainName::parse("example.com.").expect("qname"),
            dns_core::parse_record_type("A").expect("qtype"),
        );
        apply_explore_query_overrides(
            &mut config,
            &ExploreQueryOverrides {
                timeout_secs: Some(2),
                retries: Some(1),
                use_tcp: Some(true),
            },
        );
        assert_eq!(config.timeout, Duration::from_secs(2));
        assert_eq!(config.retries, 1);
        assert_eq!(config.transport, Transport::Tcp);
    }

    #[test]
    fn rejects_unknown_plus_option() {
        let error = parse_explore_args(&args(&["+fresh"])).expect_err("reject");
        assert!(matches!(error, ExploreParseError::UnknownOption(_)));
    }

    #[test]
    fn rejects_positional_after_id() {
        let error = parse_explore_args(&args(&["01SESSION"])).expect_err("reject");
        assert!(matches!(error, ExploreParseError::Unexpected(_)));
    }
}
