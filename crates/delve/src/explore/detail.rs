use std::net::IpAddr;

use dns_resolve::{FinalAnswer, TraceHop};

/// Filled diamond: response served from cache.
pub const CACHE_SYMBOL: &str = "◆";
/// Outline diamond: live DNS lookup.
pub const LIVE_SYMBOL: &str = "◇";

pub fn cache_source_symbol(from_cache: bool) -> &'static str {
    if from_cache {
        CACHE_SYMBOL
    } else {
        LIVE_SYMBOL
    }
}

pub fn cache_source_legend() -> [(&'static str, &'static str); 2] {
    [
        (CACHE_SYMBOL, "response from cache"),
        (LIVE_SYMBOL, "live DNS lookup"),
    ]
}

pub fn final_summary_line(qname: &str, qtype: &str, answer: Option<&FinalAnswer>) -> String {
    match answer {
        Some(answer) => format!(
            "{qname} {qtype}  {}ms  {}  {}",
            answer.rtt_ms,
            answer.rcode,
            cache_source_symbol(answer.from_cache)
        ),
        None => format!("{qname} {qtype}"),
    }
}

pub fn hop_summary_line(hop: &TraceHop) -> String {
    format!(
        "[{}] {} {}  {}ms  {}  {}",
        hop.zone,
        hop.qname,
        hop.qtype,
        hop.rtt_ms,
        hop.rcode,
        cache_source_symbol(hop.from_cache)
    )
}

pub fn format_server_endpoint(server: &str, server_name: Option<&str>) -> String {
    match effective_server_name(server, server_name) {
        Some(name) if name != server => format!("{name} ({server})"),
        _ => server.to_string(),
    }
}

pub fn format_server_line(
    server: &str,
    server_name: Option<&str>,
    transport: &str,
    rtt_ms: u64,
) -> String {
    format!(
        "server: {} ({transport}) in {rtt_ms}ms",
        format_server_endpoint(server, server_name)
    )
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

pub fn hop_detail_lines(hop: &TraceHop) -> Vec<String> {
    if hop.response.is_stored() {
        return super::dig_view::hop_detail_plain(hop)
            .lines()
            .map(str::to_owned)
            .collect();
    }
    legacy_hop_detail_lines(hop)
}

pub fn final_detail_lines(answer: &FinalAnswer) -> Vec<String> {
    if answer.response.is_stored() {
        return super::dig_view::final_detail_plain(answer)
            .lines()
            .map(str::to_owned)
            .collect();
    }
    legacy_final_detail_lines(answer)
}

pub(crate) fn legacy_hop_detail_lines(hop: &TraceHop) -> Vec<String> {
    let mut lines = vec![
        format!("zone: {}", hop.zone),
        format!("query: {} {}", hop.qname, hop.qtype),
        format_server_line(
            &hop.server,
            hop.server_name.as_deref(),
            &hop.transport,
            hop.rtt_ms,
        ),
        format!("rcode: {}", hop.rcode),
        format!("source: {}", cache_source_symbol(hop.from_cache)),
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

pub(crate) fn legacy_final_detail_lines(answer: &FinalAnswer) -> Vec<String> {
    let mut lines = vec![
        format_server_line(
            &answer.server,
            answer.server_name.as_deref(),
            if answer.transport.is_empty() {
                "udp"
            } else {
                answer.transport.as_str()
            },
            answer.rtt_ms,
        ),
        format!("rcode: {}", answer.rcode),
        format!("source: {}", cache_source_symbol(answer.from_cache)),
    ];
    if let Some(nsid) = &answer.nsid {
        lines.push(format!("nsid: {nsid}"));
    }
    append_yaml_list_lines(&mut lines, "records", &answer.records);
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

    #[test]
    fn cache_source_symbols_are_distinct() {
        assert_eq!(cache_source_symbol(true), CACHE_SYMBOL);
        assert_eq!(cache_source_symbol(false), LIVE_SYMBOL);
        assert_ne!(CACHE_SYMBOL, LIVE_SYMBOL);
    }

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
        };
        let detail = hop_detail_lines(&hop).join("\n");
        assert!(detail.contains("referral NS:\n  - ns1.example.com.\n  - ns2.example.com."));
        assert!(detail.contains("glue:\n  - 93.184.216.34"));
    }

    #[test]
    fn server_line_includes_fqdn_when_known() {
        let line = format_server_line("198.41.0.4", Some("a.root-servers.net."), "udp", 11);
        assert!(line.contains("a.root-servers.net. (198.41.0.4)"));
    }
}
