use std::net::IpAddr;

use dns_resolve::{HopOutcome, TraceHop};

use super::terminal::{UiSymbols, cache_source_symbol};

pub fn hop_summary_line(hop: &TraceHop, symbols: UiSymbols) -> String {
    let marker = if matches!(hop.outcome, HopOutcome::Failed { .. }) {
        "✗ "
    } else {
        ""
    };
    format!(
        "{marker}[{}] {} {}  {}  {}",
        hop.zone,
        hop.qname,
        hop.qtype,
        hop.rcode,
        cache_source_symbol(hop.from_cache, symbols)
    )
}

pub fn hop_failure_line(hop: &TraceHop) -> Option<String> {
    match &hop.outcome {
        HopOutcome::Failed { kind, detail } => Some(format!("failure: {kind}: {detail}")),
        _ => None,
    }
}

pub fn format_server_endpoint(server: &str, server_name: Option<&str>) -> String {
    match effective_server_name(server, server_name) {
        Some(name) if name != server => format!("{name} ({server})"),
        _ => server.to_string(),
    }
}

pub fn format_server_line(server: &str, server_name: Option<&str>, transport: &str) -> String {
    format!(
        "server: {} ({transport})",
        format_server_endpoint(server, server_name)
    )
}

pub fn format_query_response_time_line(rtt_ms: u64) -> String {
    format!("query response time: {rtt_ms}ms")
}

pub fn effective_server_name(server: &str, server_name: Option<&str>) -> Option<String> {
    if let Some(name) = server_name.filter(|name| !name.is_empty()) {
        return Some(name.to_string());
    }
    server.parse::<IpAddr>().ok().and_then(|address| {
        dns_resolve::root_hints::root_server_name_for(address).map(str::to_string)
    })
}

pub fn render_indented_block(lines: &[String], indent: &str) -> String {
    let mut output = String::new();
    for line in lines {
        output.push_str(indent);
        output.push_str(line);
        output.push('\n');
    }
    output
}

pub fn hop_detail_lines(hop: &TraceHop, symbols: UiSymbols) -> Vec<String> {
    let mut lines = if hop.response.is_stored() {
        super::dig_view::hop_detail_plain(hop, symbols)
            .lines()
            .map(str::to_owned)
            .collect()
    } else {
        legacy_hop_detail_lines(hop, symbols)
    };
    if let Some(failure) = hop_failure_line(hop) {
        lines.push(failure);
    }
    lines
}

pub(crate) fn legacy_hop_detail_lines(hop: &TraceHop, symbols: UiSymbols) -> Vec<String> {
    let mut lines = vec![
        format!("zone: {}", hop.zone),
        format!("query: {} {}", hop.qname, hop.qtype),
        format_server_line(&hop.server, hop.server_name.as_deref(), &hop.transport),
        format_query_response_time_line(hop.rtt_ms),
        format!("rcode: {}", hop.rcode),
        format!("source: {}", cache_source_symbol(hop.from_cache, symbols)),
    ];
    if let Some(nsid) = &hop.nsid {
        lines.push(format!("nsid: {nsid}"));
    }
    if let Some(code) = hop.ede_code {
        let text = hop.ede_text.as_deref().unwrap_or("");
        lines.push(format!("ede: {code}:{text}"));
    }
    append_yaml_list_lines(&mut lines, "referral NS", &hop.referral_ns);
    append_yaml_list_lines(&mut lines, "glue", &hop.glue);
    lines
}

fn append_yaml_list_lines(lines: &mut Vec<String>, key: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    lines.push(format!("{key}:"));
    for value in values {
        lines.push(format!("  - {value}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::explore::terminal::UNICODE;
    use dns_resolve::HopOutcome;

    #[test]
    fn formats_multi_value_fields_as_yaml_lists() {
        let hop = TraceHop {
            zone: ".".into(),
            server: "1.1.1.1".into(),
            qname: "example.com.".into(),
            qtype: "A".into(),
            transport: "udp".into(),
            rtt_ms: 10,
            rcode: "NOERROR".into(),
            nsid: None,
            ede_code: None,
            ede_text: None,
            referral_ns: vec!["ns1.example.com.".into(), "ns2.example.com.".into()],
            glue: vec!["93.184.216.34".into()],
            server_name: None,
            response: Default::default(),
            from_cache: false,
            outcome: Default::default(),
        };
        let detail = hop_detail_lines(&hop, UNICODE).join("\n");
        assert!(detail.contains("referral NS:\n  - ns1.example.com.\n  - ns2.example.com."));
        assert!(detail.contains("glue:\n  - 93.184.216.34"));
    }

    #[test]
    fn server_line_includes_fqdn_when_known() {
        let line = format_server_line("198.41.0.4", Some("a.root-servers.net."), "udp");
        assert!(line.contains("a.root-servers.net. (198.41.0.4)"));
    }

    #[test]
    fn query_response_time_line_uses_expected_label() {
        assert_eq!(
            format_query_response_time_line(11),
            "query response time: 11ms"
        );
    }

    #[test]
    fn failed_hop_summary_and_detail_include_failure_reason() {
        let hop = TraceHop {
            zone: "com.".into(),
            server: "192.0.2.1".into(),
            server_name: None,
            qname: "example.com.".into(),
            qtype: "A".into(),
            transport: "udp".into(),
            rtt_ms: 0,
            rcode: "SERVFAIL".into(),
            nsid: None,
            ede_code: None,
            ede_text: None,
            referral_ns: vec![],
            glue: vec![],
            response: Default::default(),
            from_cache: false,
            outcome: HopOutcome::Failed {
                kind: "timeout".into(),
                detail: "no response".into(),
            },
        };
        let summary = hop_summary_line(&hop, UNICODE);
        assert!(summary.starts_with("✗ "));
        let detail = hop_detail_lines(&hop, UNICODE).join("\n");
        assert!(detail.contains("failure: timeout: no response"));
    }
}
