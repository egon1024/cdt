//! Session-scoped operator notices (startup config, topology, etc.) for live TUI and stderr.

use crate::capture::{
    LinuxSysTopology, ListenerSpec, discover_topology, opened_interfaces_message,
    topology_duplicate_hints,
};

/// Text shown at session start and in the **Notices** TUI modal (`!` or panel picker **n**).
#[derive(Debug, Clone, Default)]
pub struct SessionNotices {
    lines: Vec<String>,
}

impl SessionNotices {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    pub fn lines(&self) -> &[String] {
        &self.lines
    }

    pub fn push_line(&mut self, line: impl Into<String>) {
        let line = line.into();
        if !line.is_empty() {
            self.lines.push(line);
        }
    }

    /// Build notices for a live capture session (topology, opened interfaces).
    pub fn for_live_listeners(listeners: &[ListenerSpec]) -> Self {
        let names: Vec<_> = listeners.iter().map(|l| l.iface.clone()).collect();
        let mut notices = Self::new();
        notices.push_line(strip_flux_prefix(&opened_interfaces_message(listeners)));
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
            return vec!["No startup notices for this session.".into()];
        }
        let mut out = vec![
            "These messages were recorded when the session started.".into(),
            "They stay available under Panels → Notices (!).".into(),
            String::new(),
        ];
        out.extend(self.lines.iter().cloned());
        out
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
        n.push_line("opened interfaces: br0, v0");
        n.push_line("hint: br0 and its member(s) v0");
        assert!(n.modal_lines().iter().any(|l| l.contains("v0")));
    }
}
