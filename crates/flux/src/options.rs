use std::time::Duration;

use thiserror::Error;

use crate::capture::PortSet;
use crate::filter::QrSelection;
use crate::flow::{DefragMode, TcpMode};
use crate::scale::memory::{effective_mem_limit, parse_mem_limit};
use crate::scale::overload::OverloadPolicy;
use crate::scale::workers::QueuePolicy;

#[path = "options_filter.rs"]
mod options_filter;

#[derive(Debug, Clone)]
pub struct FluxOptions {
    pub family: AddressFamily,
    pub window: WindowMode,
    pub late_grace: Duration,
    pub late_policy: LatePolicy,
    pub flow_buckets: u32,
    pub flow_threads: u32,
    pub max_flow_threads: u32,
    pub dns_ports: PortSet,
    pub exclude_iface: Vec<String>,
    pub promisc: bool,
    pub workers: usize,
    pub queue_policy: QueuePolicy,
    pub mem_limit_bytes: Option<usize>,
    pub overload_policy: OverloadPolicy,
    pub qname_levels: u8,
    pub batch_views: Vec<ViewId>,
    pub batch_limit: usize,
    /// Live TUI refresh rate (updates per second); default 1 Hz.
    pub tui_hz: u32,
    pub events: EventsMode,
    pub filter_tokens: Vec<String>,
    pub preset: Option<String>,
    pub saved_filter: Option<String>,
    pub filter_files: Vec<String>,
    pub qr: Option<QrSelection>,
    pub initiator: Vec<String>,
    pub responder: Vec<String>,
    pub src: Vec<String>,
    pub dst: Vec<String>,
    pub start_bound: Option<f64>,
    pub end_bound: Option<f64>,
    pub key_cap: usize,
    pub tld_list_path: Option<String>,
    pub ede_show_no_ede: bool,
    pub ede_split_extra: bool,
    pub defrag: DefragMode,
    pub defrag_max_datagrams: usize,
    pub defrag_max_fragments: usize,
    pub defrag_timeout: Duration,
    pub tcp: TcpMode,
    pub tcp_max_connections: usize,
    pub tcp_max_buffer: usize,
    pub tcp_idle_timeout: Duration,
    pub tcp_max_faults: u32,
    pub pairing: bool,
    pub pair_timeout: Duration,
    pub pair_max: usize,
    pub dedup: bool,
    pub dedup_window: Duration,
    pub rate_mode: RateMode,
    pub view_sort: ViewSort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RateMode {
    #[default]
    Window,
    Tick,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ViewSort {
    #[default]
    Count,
    Rate,
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
    Ede,
    SrcXEde,
    Interface,
    Vlan,
    Transport,
    LatencyDst,
    LatencySrc,
    LatencyQtype,
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
            flow_threads: 1,
            max_flow_threads: default_max_flow_threads(),
            dns_ports: PortSet::dns_default(),
            exclude_iface: Vec::new(),
            promisc: false,
            workers: 1,
            queue_policy: QueuePolicy::default(),
            mem_limit_bytes: None,
            overload_policy: OverloadPolicy::default(),
            qname_levels: 3,
            batch_views: vec![ViewId::Sources, ViewId::Qtype, ViewId::QnameLevel(2)],
            batch_limit: 50,
            tui_hz: 1,
            events: EventsMode::Off,
            filter_tokens: Vec::new(),
            preset: None,
            saved_filter: None,
            filter_files: Vec::new(),
            qr: None,
            initiator: Vec::new(),
            responder: Vec::new(),
            src: Vec::new(),
            dst: Vec::new(),
            start_bound: None,
            end_bound: None,
            key_cap: 50,
            tld_list_path: None,
            ede_show_no_ede: false,
            ede_split_extra: false,
            defrag: DefragMode::On,
            defrag_max_datagrams: 512,
            defrag_max_fragments: 32,
            defrag_timeout: Duration::from_secs(30),
            tcp: TcpMode::Full,
            tcp_max_connections: 2048,
            tcp_max_buffer: 64 * 1024,
            tcp_idle_timeout: Duration::from_secs(120),
            tcp_max_faults: 3,
            pairing: true,
            pair_timeout: Duration::from_secs(5),
            pair_max: 10_000,
            dedup: false,
            dedup_window: Duration::from_millis(5),
            rate_mode: RateMode::Window,
            view_sort: ViewSort::Count,
        }
    }
}

impl FluxOptions {
    pub fn parse(tokens: &[String]) -> Result<Self, OptionsError> {
        let mut opts = Self::default();
        let mut from_file = false;
        let mut passthrough_filters: Vec<String> = Vec::new();
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
                if is_filter_token(rest) {
                    passthrough_filters.push(tok.clone());
                    continue;
                }
                parse_plus_option(rest, &mut opts, &mut from_file)?;
            } else if !tok.is_empty() {
                return Err(OptionsError::Unknown(tok.clone()));
            }
        }
        if from_file {
            opts.window = WindowMode::All;
        }
        opts.filter_tokens = passthrough_filters;
        Ok(opts)
    }

    pub fn within_time_bounds(&self, ts_secs: f64) -> bool {
        if let Some(start) = self.start_bound {
            if ts_secs < start {
                return false;
            }
        }
        if let Some(end) = self.end_bound {
            if ts_secs > end {
                return false;
            }
        }
        true
    }

    pub fn events_to_stdout(&self) -> bool {
        matches!(self.events, EventsMode::Stdout)
    }

    pub fn options_overrode_window(&self) -> bool {
        !matches!(self.window, WindowMode::Seconds(30))
    }

    pub fn effective_flow_threads(&self) -> u32 {
        self.flow_threads.max(1)
    }

    pub fn uses_split_pipeline(&self, listener_count: usize) -> bool {
        listener_count > 1 || self.effective_flow_threads() > 1 || self.workers > 1
    }

    pub fn memory_limit_bytes(&self) -> usize {
        effective_mem_limit(self.mem_limit_bytes)
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
        "flow-threads" => {
            let v = require_value(key, value)?;
            opts.flow_threads = v.parse().map_err(|_| OptionsError::InvalidValue {
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
        "port" => {
            let v = require_value(key, value)?;
            opts.dns_ports = PortSet::parse(v).map_err(|e| OptionsError::InvalidValue {
                name: key.into(),
                detail: e.to_string(),
            })?;
        }
        "exclude-iface" => {
            let v = require_value(key, value)?;
            opts.exclude_iface = split_csv(v);
        }
        "promisc" => {
            opts.promisc = true;
        }
        "workers" => {
            let v = require_value(key, value)?;
            opts.workers = v.parse().map_err(|_| OptionsError::InvalidValue {
                name: key.into(),
                detail: v.into(),
            })?;
        }
        "queue" => {
            let v = require_value(key, value)?;
            opts.queue_policy = QueuePolicy::parse(v).map_err(|e| OptionsError::InvalidValue {
                name: key.into(),
                detail: e,
            })?;
        }
        "mem" => {
            let v = require_value(key, value)?;
            opts.mem_limit_bytes =
                Some(parse_mem_limit(v).map_err(|e| OptionsError::InvalidValue {
                    name: key.into(),
                    detail: e,
                })?);
        }
        "overload" => {
            let v = require_value(key, value)?;
            opts.overload_policy =
                OverloadPolicy::parse(v).map_err(|e| OptionsError::InvalidValue {
                    name: key.into(),
                    detail: e,
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
        "tui-hz" => {
            let v = require_value(key, value)?;
            let hz: u32 = v.parse().map_err(|_| OptionsError::InvalidValue {
                name: key.into(),
                detail: v.into(),
            })?;
            if hz == 0 {
                return Err(OptionsError::InvalidValue {
                    name: key.into(),
                    detail: "must be at least 1".into(),
                });
            }
            opts.tui_hz = hz;
        }
        "events" => match value {
            None => opts.events = EventsMode::Stdout,
            Some("") | Some("-") => opts.events = EventsMode::Stdout,
            Some(path) => opts.events = EventsMode::File(path.to_string()),
        },
        "preset" => {
            let v = require_value(key, value)?;
            opts.preset = Some(v.into());
        }
        "filter" => {
            let v = require_value(key, value)?;
            opts.saved_filter = Some(v.into());
        }
        "filter-file" => {
            let v = require_value(key, value)?;
            opts.filter_files.push(v.into());
        }
        "qr" => {
            let v = require_value(key, value)?;
            opts.qr = Some(parse_qr(v)?);
        }
        "initiator" | "responder" | "src" | "dst" => {
            let v = require_value(key, value)?;
            let target = match key {
                "initiator" => &mut opts.initiator,
                "responder" => &mut opts.responder,
                "src" => &mut opts.src,
                "dst" => &mut opts.dst,
                _ => unreachable!(),
            };
            target.extend(split_csv(v));
        }
        "start" | "end" => {
            let v = require_value(key, value)?;
            let ts = parse_time_bound(v)?;
            if key == "start" {
                opts.start_bound = Some(ts);
            } else {
                opts.end_bound = Some(ts);
            }
        }
        "key-cap" => {
            let v = require_value(key, value)?;
            opts.key_cap = v.parse().map_err(|_| OptionsError::InvalidValue {
                name: key.into(),
                detail: v.into(),
            })?;
        }
        "tld-list" => {
            let v = require_value(key, value)?;
            opts.tld_list_path = Some(v.into());
        }
        "defrag" => {
            let v = require_value(key, value)?;
            opts.defrag = match v {
                "on" => DefragMode::On,
                "off" => DefragMode::Off,
                _ => {
                    return Err(OptionsError::InvalidValue {
                        name: key.into(),
                        detail: "expected on or off".into(),
                    });
                }
            };
        }
        "tcp" => {
            let v = require_value(key, value)?;
            opts.tcp = match v {
                "off" => TcpMode::Off,
                "simple" => TcpMode::Simple,
                "full" => TcpMode::Full,
                _ => {
                    return Err(OptionsError::InvalidValue {
                        name: key.into(),
                        detail: "expected off, simple, or full".into(),
                    });
                }
            };
        }
        "pairing" => {
            let v = require_value(key, value)?;
            opts.pairing = match v {
                "on" | "true" | "1" => true,
                "off" | "false" | "0" => false,
                _ => {
                    return Err(OptionsError::InvalidValue {
                        name: key.into(),
                        detail: "expected on or off".into(),
                    });
                }
            };
        }
        "pair-timeout" => {
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
                v.parse::<u64>()
                    .map_err(|_| OptionsError::InvalidValue {
                        name: key.into(),
                        detail: v.into(),
                    })?
                    .saturating_mul(1000)
            };
            opts.pair_timeout = Duration::from_millis(ms);
        }
        "pair-max" => {
            let v = require_value(key, value)?;
            opts.pair_max = v.parse().map_err(|_| OptionsError::InvalidValue {
                name: key.into(),
                detail: v.into(),
            })?;
        }
        "dedup" => {
            opts.dedup = match value {
                None | Some("") | Some("-") => true,
                Some("on" | "true" | "1") => true,
                Some("off" | "false" | "0") => false,
                Some(other) => {
                    return Err(OptionsError::InvalidValue {
                        name: key.into(),
                        detail: other.into(),
                    });
                }
            };
        }
        "dedup-window" => {
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
            opts.dedup_window = Duration::from_millis(ms);
        }
        "rate" => {
            let v = require_value(key, value)?;
            opts.rate_mode = match v {
                "window" => RateMode::Window,
                "tick" => RateMode::Tick,
                _ => {
                    return Err(OptionsError::InvalidValue {
                        name: key.into(),
                        detail: "expected window or tick".into(),
                    });
                }
            };
        }
        "sort" => {
            let v = require_value(key, value)?;
            opts.view_sort = match v {
                "count" => ViewSort::Count,
                "rate" => ViewSort::Rate,
                _ => {
                    return Err(OptionsError::InvalidValue {
                        name: key.into(),
                        detail: "expected count or rate".into(),
                    });
                }
            };
        }
        _ if filter_field_key(key) || key.starts_with("no") => {}
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

fn is_filter_token(rest: &str) -> bool {
    if is_flow_option_token(rest) {
        return false;
    }
    let key = filter_field_name_in_plus(rest);
    filter_field_key(key) || rest.starts_with("no")
}

fn is_flow_option_token(rest: &str) -> bool {
    let (key, value) = split_key_value(rest);
    match key {
        "defrag" => matches!(value, Some("on" | "off")),
        "tcp" => matches!(value, Some("off" | "simple" | "full")),
        "pairing" => matches!(value, Some("on" | "off" | "true" | "false" | "0" | "1")),
        "pair-timeout" | "pair-max" | "dedup-window" | "flow-threads" | "workers" | "port"
        | "queue" | "mem" | "overload" | "exclude-iface" | "tui-hz" => value.is_some(),
        "promisc" | "max-flow-threads" | "dedup" => true,
        _ => false,
    }
}

fn default_max_flow_threads() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
        .max(1)
}

/// Field name for a `+` filter flag, matching `filter::flags` parsing (`!=`, comparisons, `=`).
fn filter_field_name_in_plus(rest: &str) -> &str {
    let body = if let Some(b) = rest.strip_prefix("no") {
        b
    } else {
        rest
    };
    if let Some((k, _)) = body.split_once("!=") {
        return k;
    }
    if let Some((k, _)) = body.split_once('>') {
        return k;
    }
    if let Some((k, _)) = body.split_once('<') {
        return k;
    }
    if let Some((k, _)) = body.split_once('=') {
        return k;
    }
    body
}

fn filter_field_key(key: &str) -> bool {
    matches!(
        key,
        "qname"
            | "qtype"
            | "rcode"
            | "opcode"
            | "qr"
            | "aa"
            | "tc"
            | "rd"
            | "ra"
            | "ad"
            | "cd"
            | "malformed"
            | "edns"
            | "edns-version"
            | "do"
            | "opt"
            | "edns-opt"
            | "ede"
            | "size"
            | "wire-len"
            | "latency"
            | "family"
            | "transport"
            | "udp"
            | "tcp"
            | "iface"
            | "vlan"
    )
}

fn parse_qr(s: &str) -> Result<QrSelection, OptionsError> {
    match s.to_ascii_lowercase().as_str() {
        "query" | "q" => Ok(QrSelection::Query),
        "response" | "r" => Ok(QrSelection::Response),
        "both" => Ok(QrSelection::Both),
        _ => Err(OptionsError::InvalidValue {
            name: "+qr".into(),
            detail: s.into(),
        }),
    }
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

fn parse_time_bound(s: &str) -> Result<f64, OptionsError> {
    s.parse::<f64>().map_err(|_| OptionsError::InvalidValue {
        name: "+start/+end".into(),
        detail: s.into(),
    })
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
            "ede" => ViewId::Ede,
            "src-x-ede" | "src×ede" => ViewId::SrcXEde,
            "iface" | "interface" => ViewId::Interface,
            "vlan" => ViewId::Vlan,
            "transport" => ViewId::Transport,
            "latency-dst" | "latency-destinations" => ViewId::LatencyDst,
            "latency-src" | "latency-sources" => ViewId::LatencySrc,
            "latency-qtype" => ViewId::LatencyQtype,
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

    #[test]
    fn negated_qtype_filter_token() {
        let o = FluxOptions::parse(&["+qtype!=PTR".into(), "+views=qtype".into()]).unwrap();
        assert_eq!(o.filter_tokens, vec!["+qtype!=PTR".to_string()]);
    }

    #[test]
    fn filter_field_name_with_not_equal() {
        assert_eq!(filter_field_name_in_plus("qtype!=PTR"), "qtype");
    }

    #[test]
    fn filter_file_option_parses() {
        let o = FluxOptions::parse(&[
            "+filter-file=/tmp/flux-g2/leaks.yaml".into(),
            "+views=src".into(),
        ])
        .unwrap();
        assert_eq!(o.filter_files, vec!["/tmp/flux-g2/leaks.yaml".to_string()]);
        assert!(o.filter_tokens.is_empty());
    }
}
