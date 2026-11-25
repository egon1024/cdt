//! Session-scoped operator notices (startup config, topology, etc.) for live TUI and stderr.

use crate::capture::{LinuxSysTopology, ListenerSpec, discover_topology, topology_duplicate_hints};

/// Text shown at session start and in the **Notices** TUI modal (`!`, including Panels → **!**).
#[derive(Debug, Clone, Default)]
pub struct SessionNotices {
    lines: Vec<String>,
    /// Parallel to `lines`; TUI-only read tracking (stderr ignores this).
    read: Vec<bool>,
}

impl SessionNotices {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    pub fn unread_count(&self) -> usize {
        self.lines
            .iter()
            .enumerate()
            .filter(|(i, _)| !self.read.get(*i).copied().unwrap_or(false))
            .count()
    }

    pub fn read_count(&self) -> usize {
        self.lines.len().saturating_sub(self.unread_count())
    }

    /// Short suffix for the live TUI footer (after main key hints).
    pub fn tui_footer_suffix(&self) -> Option<String> {
        if self.is_empty() {
            return None;
        }
        let total = self.len();
        let unread = self.unread_count();
        let read = self.read_count();
        let body = if unread == 0 {
            format!("{total} total, all read")
        } else {
            format!("{total} total, {read} read, {unread} unread")
        };
        Some(format!("· ! notices: {body}"))
    }

    pub fn mark_all_read(&mut self) {
        self.read.resize(self.lines.len(), false);
        for flag in &mut self.read {
            *flag = true;
        }
    }

    pub fn push_line(&mut self, line: impl Into<String>) {
        let line = line.into();
        if !line.is_empty() {
            self.lines.push(line);
            self.read.push(false);
        }
    }

    /// Build warnings for a live capture session (e.g. topology duplicate capture).
    pub fn for_live_listeners(listeners: &[ListenerSpec]) -> Self {
        let names: Vec<_> = listeners.iter().map(|l| l.iface.clone()).collect();
        let mut notices = Self::new();
        let topo = discover_topology(&LinuxSysTopology, &names);
        for hint in topology_duplicate_hints(&names, &topo) {
            notices.push_line(strip_flux_prefix(&hint));
        }
        notices
    }

    /// Lines for `eprintln!("flux: …")` at startup (keeps batch/non-TUI behavior).
    pub fn emit_stderr(&self) {
        for line in &self.lines {
            eprintln!("flux: {line}");
        }
    }

    pub fn modal_lines(&self) -> Vec<String> {
        if self.lines.is_empty() {
            return vec!["No notices.".into()];
        }
        self.lines
            .iter()
            .zip(self.read.iter())
            .map(|(line, read)| {
                if *read {
                    line.clone()
                } else {
                    format!("• {line}")
                }
            })
            .collect()
    }
}

fn strip_flux_prefix(s: &str) -> String {
    s.strip_prefix("flux: ").unwrap_or(s).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modal_lines_preserve_content() {
        let mut n = SessionNotices::new();
        n.push_line("hint: br0 and its member(s) v0 are both selected");
        assert!(n.modal_lines().iter().any(|l| l.contains("v0")));
    }

    #[test]
    fn read_tracking_and_footer() {
        let mut n = SessionNotices::new();
        n.push_line("one");
        n.push_line("two");
        assert_eq!(n.unread_count(), 2);
        n.mark_all_read();
        assert_eq!(n.unread_count(), 0);
        assert!(n.tui_footer_suffix().unwrap().contains("all read"));
    }
}
