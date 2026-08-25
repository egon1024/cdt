use dns_resolve::{FinalAnswer, TraceHop};

pub fn format_hop_detail(hop: &TraceHop) -> String {
    let mut lines = vec![
        format!("zone: {}", hop.zone),
        format!("query: {} {}", hop.qname, hop.qtype),
        format!("server: {} ({})", hop.server, hop.transport),
        format!("rtt: {}ms", hop.rtt_ms),
        format!("rcode: {}", hop.rcode),
    ];
    if let Some(nsid) = &hop.nsid {
        lines.push(format!("nsid: {nsid}"));
    }
    if let Some(code) = hop.ede_code {
        let text = hop.ede_text.as_deref().unwrap_or("");
        lines.push(format!("ede: {code}:{text}"));
    }
    push_yaml_list(&mut lines, "referral NS", &hop.referral_ns);
    push_yaml_list(&mut lines, "glue", &hop.glue);
    lines.join("\n")
}

pub fn format_final_answer(answer: &FinalAnswer) -> String {
    let mut lines = vec![
        format!("server: {}", answer.server),
        format!("rtt: {}ms", answer.rtt_ms),
        format!("rcode: {}", answer.rcode),
    ];
    if let Some(nsid) = &answer.nsid {
        lines.push(format!("nsid: {nsid}"));
    }
    push_yaml_list(&mut lines, "records", &answer.records);
    lines.join("\n")
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

pub fn hop_summary_line(hop: &TraceHop) -> String {
    format!("[{}] {} {}", hop.zone, hop.qname, hop.qtype)
}

pub fn hop_detail_lines(hop: &TraceHop) -> Vec<String> {
    let mut lines = vec![
        format!("server: {} ({})", hop.server, hop.transport),
        format!("rtt: {}ms", hop.rtt_ms),
        format!("rcode: {}", hop.rcode),
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

pub fn final_detail_lines(answer: &FinalAnswer) -> Vec<String> {
    let mut lines = vec![
        format!("server: {}", answer.server),
        format!("rtt: {}ms", answer.rtt_ms),
        format!("rcode: {}", answer.rcode),
    ];
    if let Some(nsid) = &answer.nsid {
        lines.push(format!("nsid: {nsid}"));
    }
    append_yaml_list_lines(&mut lines, "records", &answer.records);
    lines
}

fn push_yaml_list(lines: &mut Vec<String>, key: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    append_yaml_list_lines(lines, key, values);
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
        };
        let detail = format_hop_detail(&hop);
        assert!(detail.contains("referral NS:\n  - ns1.example.com.\n  - ns2.example.com."));
        assert!(detail.contains("glue:\n  - 93.184.216.34"));
    }
}
