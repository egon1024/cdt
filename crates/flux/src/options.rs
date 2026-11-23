use std::time::Duration;

use thiserror::Error;

#[derive(Debug, Clone)]
pub struct FluxOptions {
    pub family: AddressFamily,
    pub window: WindowMode,
    pub late_grace: Duration,
    pub late_policy: LatePolicy,
    pub flow_buckets: u32,
    pub max_flow_threads: u32,
    pub qname_levels: u8,
    pub batch_views: Vec<ViewId>,
    pub batch_limit: usize,
    pub events: EventsMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    Auto,
    V4,
    V6,
    Both,
}

#[derive(Debug, Clone)]
pub enum WindowMode {
    Seconds(u64),
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LatePolicy {
    Correct,
    Drop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViewId {
    Sources,
    Destinations,
    Qtype,
    Rcode,
    Opcode,
    QnameLevel(u8),
    SrcXQname(u8),
}

#[derive(Debug, Clone)]
pub enum EventsMode {
    Off,
    Stdout,
    File(String),
}

#[derive(Debug, Error)]
pub enum OptionsError {
    #[error("unknown option: {0}")]
    Unknown(String),

    #[error("invalid value for {name}: {detail}")]
    InvalidValue { name: String, detail: String },

    #[error("required value missing for {0}")]
    MissingValue(String),
}

impl Default for FluxOptions {
    fn default() -> Self {
        Self {
            family: AddressFamily::Auto,
            window: WindowMode::Seconds(30),
            late_grace: Duration::from_millis(250),
            late_policy: LatePolicy::Correct,
            flow_buckets: 0,
            max_flow_threads: 1,
            qname_levels: 3,
            batch_views: vec![ViewId::Sources, ViewId::Qtype, ViewId::QnameLevel(2)],
            batch_limit: 50,
            events: EventsMode::Off,
        }
    }
}

impl FluxOptions {
    pub fn parse(tokens: &[String]) -> Result<Self, OptionsError> {
        let mut opts = Self::default();
        let mut from_file = false;
        for tok in tokens {
            if tok == "-4" {
                opts.family = AddressFamily::V4;
                continue;
            }
            if tok == "-6" {
                opts.family = AddressFamily::V6;
                continue;
            }
            if let Some(rest) = tok.strip_prefix('+') {
                parse_plus_option(rest, &mut opts, &mut from_file)?;
            } else if !tok.is_empty() {
                return Err(OptionsError::Unknown(tok.clone()));
            }
        }
        if from_file {
            opts.window = WindowMode::All;
        }
        Ok(opts)
    }

    pub fn events_to_stdout(&self) -> bool {
        matches!(self.events, EventsMode::Stdout)
    }

    pub fn options_overrode_window(&self) -> bool {
        !matches!(self.window, WindowMode::Seconds(30))
    }

    pub fn effective_flow_buckets(&self) -> (u32, Option<u32>) {
        let requested = if self.flow_buckets == 0 {
            let raw = 64u32.saturating_mul(self.max_flow_threads).max(64);
            next_pow2(raw).clamp(256, 65536)
        } else {
            self.flow_buckets
        };
        let actual = next_pow2(requested).clamp(256, 65536);
        let notice = if actual != requested {
            Some(requested)
        } else {
            None
        };
        (actual, notice)
    }
}

fn parse_plus_option(
    rest: &str,
    opts: &mut FluxOptions,
    from_file: &mut bool,
) -> Result<(), OptionsError> {
    let (key, value) = split_key_value(rest);
    match key {
        "family" => {
            let v = require_value(key, value)?;
            opts.family = match v {
                "auto" => AddressFamily::Auto,
                "v4" | "ipv4" => AddressFamily::V4,
                "v6" | "ipv6" => AddressFamily::V6,
                "both" => AddressFamily::Both,
                _ => {
                    return Err(OptionsError::InvalidValue {
                        name: key.into(),
                        detail: format!("expected auto, v4, v6, or both, got {v}"),
                    });
                }
            };
        }
        "window" => {
            let v = require_value(key, value)?;
            if v == "all" {
                opts.window = WindowMode::All;
            } else if let Some(secs) = v.strip_suffix('s') {
                let n: u64 = secs.parse().map_err(|_| OptionsError::InvalidValue {
                    name: key.into(),
                    detail: v.into(),
                })?;
                opts.window = WindowMode::Seconds(n);
            } else {
                let n: u64 = v.parse().map_err(|_| OptionsError::InvalidValue {
                    name: key.into(),
                    detail: v.into(),
                })?;
                opts.window = WindowMode::Seconds(n);
            }
        }
        "late-grace" => {
            let v = require_value(key, value)?;
            let ms: u64 = if let Some(s) = v.strip_suffix("ms") {
                s.parse().map_err(|_| OptionsError::InvalidValue {
                    name: key.into(),
                    detail: v.into(),
                })?
            } else if let Some(s) = v.strip_suffix('s') {
                s.parse::<u64>()
                    .map_err(|_| OptionsError::InvalidValue {
                        name: key.into(),
                        detail: v.into(),
                    })?
                    .saturating_mul(1000)
            } else {
                v.parse().map_err(|_| OptionsError::InvalidValue {
                    name: key.into(),
                    detail: v.into(),
                })?
            };
            opts.late_grace = Duration::from_millis(ms);
        }
        "late" => {
            let v = require_value(key, value)?;
            opts.late_policy = match v {
                "correct" => LatePolicy::Correct,
                "drop" => LatePolicy::Drop,
                _ => {
                    return Err(OptionsError::InvalidValue {
                        name: key.into(),
                        detail: "expected correct or drop".into(),
                    });
                }
            };
        }
        "flow-buckets" => {
            let v = require_value(key, value)?;
            opts.flow_buckets = v.parse().map_err(|_| OptionsError::InvalidValue {
                name: key.into(),
                detail: v.into(),
            })?;
        }
        "max-flow-threads" => {
            let v = require_value(key, value)?;
            opts.max_flow_threads = v.parse().map_err(|_| OptionsError::InvalidValue {
                name: key.into(),
                detail: v.into(),
            })?;
        }
        "levels" => {
            let v = require_value(key, value)?;
            opts.qname_levels = v.parse().map_err(|_| OptionsError::InvalidValue {
                name: key.into(),
                detail: v.into(),
            })?;
        }
        "views" => {
            let v = require_value(key, value)?;
            opts.batch_views = parse_view_list(v)?;
        }
        "limit" => {
            let v = require_value(key, value)?;
            opts.batch_limit = v.parse().map_err(|_| OptionsError::InvalidValue {
                name: key.into(),
                detail: v.into(),
            })?;
        }
        "events" => match value {
            None => opts.events = EventsMode::Stdout,
            Some("") | Some("-") => opts.events = EventsMode::Stdout,
            Some(path) => opts.events = EventsMode::File(path.to_string()),
        },
        _ if key.is_empty() && matches!(value, None | Some("") | Some("-")) => {
            opts.events = EventsMode::Stdout;
        }
        _ => return Err(OptionsError::Unknown(format!("+{rest}"))),
    }
    if key == "window" && matches!(value, Some("all")) {
        let _ = from_file;
    }
    Ok(())
}

fn parse_view_list(s: &str) -> Result<Vec<ViewId>, OptionsError> {
    let mut out = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let id = match part {
            "src" | "sources" => ViewId::Sources,
            "dst" | "destinations" => ViewId::Destinations,
            "qtype" => ViewId::Qtype,
            "rcode" => ViewId::Rcode,
            "opcode" => ViewId::Opcode,
            _ if part.chars().all(|c| c.is_ascii_digit()) => {
                let level: u8 = part.parse().map_err(|_| OptionsError::InvalidValue {
                    name: "views".into(),
                    detail: part.into(),
                })?;
                ViewId::QnameLevel(level)
            }
            _ => {
                return Err(OptionsError::InvalidValue {
                    name: "views".into(),
                    detail: part.into(),
                });
            }
        };
        out.push(id);
    }
    if out.is_empty() {
        return Err(OptionsError::InvalidValue {
            name: "views".into(),
            detail: "empty list".into(),
        });
    }
    Ok(out)
}

fn split_key_value(rest: &str) -> (&str, Option<&str>) {
    if let Some((k, v)) = rest.split_once('=') {
        (k, Some(v))
    } else {
        (rest, None)
    }
}

fn require_value<'a>(key: &str, value: Option<&'a str>) -> Result<&'a str, OptionsError> {
    match value {
        Some("") | None => Err(OptionsError::MissingValue(format!("+{key}"))),
        Some(v) => Ok(v),
    }
}

pub fn next_pow2(n: u32) -> u32 {
    if n <= 1 {
        return 1;
    }
    1u32 << (32 - (n - 1).leading_zeros())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_plus_window_rejects_missing_value() {
        let err = FluxOptions::parse(&["+window=".into()]).unwrap_err();
        assert!(matches!(err, OptionsError::MissingValue(_)));
    }

    #[test]
    fn flow_buckets_rounds_to_power_of_two() {
        let o = FluxOptions {
            flow_buckets: 1000,
            ..FluxOptions::default()
        };
        let (actual, notice) = o.effective_flow_buckets();
        assert_eq!(actual, 1024);
        assert_eq!(notice, Some(1000));
    }

    #[test]
    fn views_parsing() {
        let o = FluxOptions::parse(&["+views=src,qtype,2".into()]).unwrap();
        assert_eq!(o.batch_views.len(), 3);
    }
}
