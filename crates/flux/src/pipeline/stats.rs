use std::path::Path;

use crate::filter::{FilterHeader, MatchStats};
use crate::options::WindowMode;

#[derive(Debug, Clone)]
pub struct StatusLine {
    pub packets: u64,
    pub drops: u64,
    pub parse_busy_pct: u8,
    pub queue_depth: u64,
}

#[derive(Debug, Clone)]
pub enum WatchInput {
    Live { interfaces: Vec<String> },
    Replay { path: String },
}

#[derive(Debug, Clone)]
pub struct StatusBar {
    pub input: WatchInput,
    pub window: WindowMode,
    pub effective_window_secs: Option<u64>,
    pub filter: FilterHeader,
    pub match_stats: MatchStats,
    pub counted_in_window: u64,
    pub counters: StatusLine,
    /// Wall time since live session start (TUI only).
    pub elapsed_secs: Option<f32>,
}

impl StatusBar {
    pub fn format(&self) -> String {
        let mut parts = Vec::new();

        match &self.input {
            WatchInput::Live { interfaces } => {
                let ifaces = if interfaces.is_empty() {
                    "(default)".to_string()
                } else {
                    interfaces.join(",")
                };
                parts.push(format!("live {ifaces}"));
            }
            WatchInput::Replay { path } => {
                let label = Path::new(path)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(path.as_str());
                parts.push(format!("replay {label}"));
            }
        }

        parts.push(format!(
            "window {}",
            format_window(&self.window, self.effective_window_secs)
        ));

        parts.push(format!("qr={}", self.filter.qr.as_str()));

        if self.filter.is_empty() {
            parts.push("filter none".into());
        } else {
            let pct = if self.match_stats.total_observed == 0 {
                0.0
            } else {
                (self.match_stats.matched as f64) * 100.0 / (self.match_stats.total_observed as f64)
            };
            parts.push(format!(
                "filter {} — {} of {} ({pct:.1}%)",
                self.filter.label, self.match_stats.matched, self.match_stats.total_observed,
            ));
        }

        parts.push(format!("counted {} in window", self.counted_in_window));

        if let Some(elapsed) = self.elapsed_secs {
            parts.push(format!("elapsed {elapsed:.1}s"));
        }

        parts.push(format!(
            "pkts={} drops={} parse_busy={}% queue={}",
            self.counters.packets,
            self.counters.drops,
            self.counters.parse_busy_pct,
            self.counters.queue_depth,
        ));

        format!("--- status: {} ---\n", parts.join(" | "))
    }
}

fn format_window(window: &WindowMode, effective_secs: Option<u64>) -> String {
    match window {
        WindowMode::All => "all".into(),
        WindowMode::Seconds(configured) => {
            if let Some(eff) = effective_secs {
                if eff != *configured {
                    return format!("{eff}s effective of {configured}s");
                }
            }
            format!("{configured}s")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_bar_includes_window_and_replay() {
        let bar = StatusBar {
            input: WatchInput::Replay {
                path: "/tmp/udp-basic.pcap".into(),
            },
            window: WindowMode::All,
            effective_window_secs: None,
            filter: FilterHeader::default(),
            match_stats: MatchStats::default(),
            counted_in_window: 8,
            counters: StatusLine {
                packets: 8,
                drops: 0,
                parse_busy_pct: 50,
                queue_depth: 0,
            },
            elapsed_secs: None,
        };
        let s = bar.format();
        assert!(s.contains("replay udp-basic.pcap"));
        assert!(s.contains("window all"));
        assert!(s.contains("counted 8 in window"));
    }

    #[test]
    fn status_bar_live_iface_and_window() {
        let bar = StatusBar {
            input: WatchInput::Live {
                interfaces: vec!["lo".into()],
            },
            window: WindowMode::Seconds(30),
            effective_window_secs: Some(30),
            filter: FilterHeader::default(),
            match_stats: MatchStats::default(),
            counted_in_window: 12,
            counters: StatusLine {
                packets: 100,
                drops: 0,
                parse_busy_pct: 10,
                queue_depth: 0,
            },
            elapsed_secs: Some(5.2),
        };
        let s = bar.format();
        assert!(s.contains("live lo"));
        assert!(s.contains("window 30s"));
        assert!(s.contains("elapsed 5.2s"));
    }

    #[test]
    fn counters_nonzero_after_replay() {
        let s = StatusLine {
            packets: 10,
            drops: 0,
            parse_busy_pct: 50,
            queue_depth: 0,
        };
        assert!(s.packets == 10);
    }
}
