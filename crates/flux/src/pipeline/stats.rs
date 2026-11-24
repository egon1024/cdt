use std::path::Path;

use crate::filter::{FilterHeader, MatchStats};
use crate::flow::FlowCounters;
use crate::options::WindowMode;
use crate::scale::hints::Hint;
use crate::scale::overload::OverloadState;

#[derive(Debug, Clone)]
pub struct StatusLine {
    pub packets: u64,
    pub drops: u64,
    pub parse_busy_pct: u8,
    pub queue_depth: u64,
    /// Ethernet frames accepted on listeners (includes non-DNS).
    pub listener_frames: u64,
    /// Raw frames received in the last refresh interval (live TUI).
    pub recv_frames_last_tick: Option<u64>,
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
    pub flow: FlowCounters,
    pub pairing_enabled: bool,
    /// Wall time since live session start (TUI only).
    pub elapsed_secs: Option<f32>,
    pub overload: Option<OverloadState>,
    pub listener_stats: Vec<String>,
    pub hints: Vec<Hint>,
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

        if self.counters.listener_frames > 0 || self.counters.recv_frames_last_tick.is_some() {
            let mut io = format!("frames={}", self.counters.listener_frames);
            if let Some(n) = self.counters.recv_frames_last_tick {
                io.push_str(&format!(" recv_last={n}"));
            }
            io.push_str(&format!(
                " dns_msgs={} drops={}",
                self.counters.packets, self.counters.drops
            ));
            parts.push(io);
        } else {
            parts.push(format!(
                "pkts={} drops={}",
                self.counters.packets, self.counters.drops
            ));
        }
        parts.push(format!(
            "parse_busy={}% queue={}",
            self.counters.parse_busy_pct, self.counters.queue_depth
        ));

        let mut line = format!("--- status: {} ---", parts.join(" | "));
        line.push_str(&self.flow.format_suffix());
        line.push('\n');
        if let Some(ov) = &self.overload {
            if ov.active {
                let mut note = format!(
                    "--- overload: {:?} refused={} compacted={}",
                    ov.policy, ov.refused, ov.compacted_slices
                );
                if ov.compact_blocks_refilter {
                    note.push_str(" (compacted slices not re-filterable)");
                }
                note.push_str(" ---\n");
                line.push_str(&note);
            }
        }
        for hint in &self.hints {
            line.push_str(&format!("--- {hint:?} ---\n"));
        }
        for ls in &self.listener_stats {
            line.push_str(ls);
            line.push('\n');
        }
        if !self.pairing_enabled {
            line.push_str("--- note: pairing off; latency and unanswered unavailable ---\n");
        }
        line
    }

    /// Sectioned status for the live TUI stats panel (1 Hz updates while open).
    pub fn format_detail_lines(&self) -> Vec<String> {
        let mut out = vec!["== Session ==".to_string()];

        match &self.input {
            WatchInput::Live { interfaces } => {
                let ifaces = if interfaces.is_empty() {
                    "(default)".to_string()
                } else {
                    interfaces.join(", ")
                };
                out.push(format!("  input live on {ifaces}"));
            }
            WatchInput::Replay { path } => {
                let label = Path::new(path)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(path.as_str());
                out.push(format!("  input replay {label}"));
            }
        }

        out.push(format!(
            "  window {}",
            format_window(&self.window, self.effective_window_secs)
        ));
        if let Some(elapsed) = self.elapsed_secs {
            out.push(format!("  elapsed {elapsed:.1}s"));
        }
        out.push(format!("  qr filter {}", self.filter.qr.as_str()));
        if self.filter.is_empty() {
            out.push("  predicate none".into());
        } else {
            let pct = if self.match_stats.total_observed == 0 {
                0.0
            } else {
                (self.match_stats.matched as f64) * 100.0
                    / (self.match_stats.total_observed as f64)
            };
            out.push(format!(
                "  filter {} — {} of {} matched ({pct:.1}%)",
                self.filter.label, self.match_stats.matched, self.match_stats.total_observed,
            ));
        }
        out.push(format!("  counted in window {}", self.counted_in_window));

        out.push("".into());
        out.push("== Capture & parse ==".into());
        if self.counters.listener_frames > 0 || self.counters.recv_frames_last_tick.is_some() {
            out.push(format!("  listener frames {}", self.counters.listener_frames));
            if let Some(n) = self.counters.recv_frames_last_tick {
                out.push(format!("  recv last tick {n}"));
            }
            out.push(format!("  dns messages {}", self.counters.packets));
        } else {
            out.push(format!("  packets {}", self.counters.packets));
        }
        out.push(format!("  capture drops {}", self.counters.drops));
        out.push(format!(
            "  parse busy {}%  queue depth {}",
            self.counters.parse_busy_pct, self.counters.queue_depth
        ));

        if self.flow.any_nonzero() {
            out.push("".into());
            out.push("== Flow stage counters ==".into());
            for line in self.flow.format_lines() {
                out.push(format!("  {line}"));
            }
        }

        if let Some(ov) = &self.overload {
            if ov.active {
                out.push("".into());
                out.push("== Overload ==".into());
                out.push(format!("  policy {:?}", ov.policy));
                out.push(format!("  refused {}", ov.refused));
                out.push(format!("  compacted slices {}", ov.compacted_slices));
                if ov.compact_blocks_refilter {
                    out.push("  compacted slices not re-filterable".into());
                }
            }
        }

        if !self.pairing_enabled {
            out.push("".into());
            out.push("  note: pairing off — latency / unanswered views unavailable".into());
        }

        for hint in &self.hints {
            out.push("".into());
            out.push(format!("== Hint ==  {hint:?}"));
        }
        for ls in &self.listener_stats {
            out.push(ls.clone());
        }

        out
    }
}

/// Single-line key hints for the live TUI footer (static; avoids flicker on refresh).
pub const TUI_FOOTER_HINTS: &str =
    "v views · p panels · u stats · w scaling · l qname · g smart · h/? help · q quit";

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
                listener_frames: 0,
                recv_frames_last_tick: None,
            },
            flow: FlowCounters::default(),
            pairing_enabled: true,
            elapsed_secs: None,
            overload: None,
            listener_stats: Vec::new(),
            hints: Vec::new(),
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
                listener_frames: 0,
                recv_frames_last_tick: None,
            },
            flow: FlowCounters::default(),
            pairing_enabled: true,
            elapsed_secs: Some(5.2),
            overload: None,
            listener_stats: Vec::new(),
            hints: Vec::new(),
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
            listener_frames: 0,
            recv_frames_last_tick: None,
        };
        assert!(s.packets == 10);
    }
}
