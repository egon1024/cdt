use dns_resolve::{NodePath, TraceHop};

use crate::explore::{cache_source_symbol, ui_symbols};

/// Tracks hop numbering and repeated query fields across a trace or session replay.
#[derive(Debug, Default)]
pub struct HopDisplayState {
    hop_count: usize,
    last_qname: Option<String>,
    last_qtype: Option<String>,
    emitted_hop: bool,
}

impl HopDisplayState {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Format one hop for stderr, including a leading blank line after the first hop.
pub fn format_hop_human(state: &mut HopDisplayState, hop: &TraceHop, path: &NodePath) -> String {
    let mut output = String::new();
    if state.emitted_hop {
        output.push('\n');
    }
    state.emitted_hop = true;
    state.hop_count += 1;

    let indent = "  ".repeat(path.path.len());
    let path_label = format_path(path);
    let query = format_query(state, hop);

    let mut line = format!(
        "{indent}hop {} path {path_label}  [{}] {query}  {} via {} in {}ms ({}) {}",
        state.hop_count,
        hop.zone,
        hop.server,
        hop.transport,
        hop.rtt_ms,
        hop.rcode,
        cache_source_symbol(hop.from_cache, ui_symbols())
    );

    if let Some(nsid) = &hop.nsid {
        line.push_str(&format!(" NSID={nsid}"));
    }
    if let Some(code) = hop.ede_code {
        line.push_str(&format!(" EDE={code}"));
        if let Some(text) = &hop.ede_text {
            line.push_str(&format!(":{text}"));
        }
    }

    output.push_str(&line);
    output.push('\n');

    if !hop.referral_ns.is_empty() {
        output.push_str(&format!(
            "{indent}  referral NS: {}\n",
            hop.referral_ns.join(", ")
        ));
    }
    if !hop.glue.is_empty() {
        output.push_str(&format!("{indent}  glue: {}\n", hop.glue.join(", ")));
    }

    output
}

/// Human-readable hop line(s) matching live trace stderr output.
pub fn print_hop_human(state: &mut HopDisplayState, hop: &TraceHop, path: &NodePath) {
    eprint!("{}", format_hop_human(state, hop, path));
}

fn format_path(path: &NodePath) -> String {
    if path.path.is_empty() {
        return "[]".into();
    }
    let joined = path
        .path
        .iter()
        .map(|index| index.to_string())
        .collect::<Vec<_>>()
        .join(",");
    format!("[{joined}]")
}

fn format_query(state: &mut HopDisplayState, hop: &TraceHop) -> String {
    let same_qname = state.last_qname.as_deref() == Some(hop.qname.as_str());
    let same_qtype = state.last_qtype.as_deref() == Some(hop.qtype.as_str());

    let query = if same_qname && same_qtype {
        "·".into()
    } else {
        format!("{} {}", hop.qname, hop.qtype)
    };

    state.last_qname = Some(hop.qname.clone());
    state.last_qtype = Some(hop.qtype.clone());
    query
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::HopOutcome;

    fn sample_hop(qname: &str, qtype: &str, zone: &str) -> TraceHop {
        TraceHop {
            zone: zone.into(),
            server: "1.1.1.1".into(),
            server_name: None,
            qname: qname.into(),
            qtype: qtype.into(),
            transport: "udp".into(),
            rtt_ms: 12,
            rcode: "NOERROR".into(),
            nsid: None,
            ede_code: None,
            ede_text: None,
            referral_ns: vec!["ns.example.com.".into()],
            glue: vec![],
            response: Default::default(),
            from_cache: false,
            outcome: HopOutcome::Referral,
        }
    }

    #[test]
    fn first_hop_shows_query_and_path() {
        let mut state = HopDisplayState::new();
        let text = format_hop_human(
            &mut state,
            &sample_hop("example.com.", "A", "com."),
            &NodePath {
                tree: 0,
                path: vec![0],
            },
        );
        assert!(text.starts_with("  hop 1 path [0]"));
        assert!(text.contains("example.com. A"));
        assert!(!text.starts_with('\n'));
    }

    #[test]
    fn repeated_query_is_suppressed_with_dot() {
        let mut state = HopDisplayState::new();
        format_hop_human(
            &mut state,
            &sample_hop("example.com.", "A", "."),
            &NodePath::root(0),
        );
        let second = format_hop_human(
            &mut state,
            &sample_hop("example.com.", "A", "com."),
            &NodePath {
                tree: 0,
                path: vec![0],
            },
        );
        assert!(second.starts_with('\n'));
        assert!(second.contains("hop 2 path [0]"));
        assert!(second.contains("] ·  1.1.1.1"));
        assert!(!second.contains("example.com. A  1.1.1.1"));
    }

    #[test]
    fn changed_qname_is_shown_again() {
        let mut state = HopDisplayState::new();
        format_hop_human(
            &mut state,
            &sample_hop("example.com.", "A", "."),
            &NodePath::root(0),
        );
        let second = format_hop_human(
            &mut state,
            &sample_hop("cdn.example.com.", "A", "com."),
            &NodePath {
                tree: 0,
                path: vec![0],
            },
        );
        assert!(second.contains("cdn.example.com. A"));
    }
}
