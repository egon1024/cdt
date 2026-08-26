use dns_core::response::DnsRecord;
use dns_resolve::{FinalAnswer, StoredDnsMessage, TraceHop};
use ratatui::text::{Line, Span};

use super::detail::{legacy_final_detail_lines, legacy_hop_detail_lines};
use super::theme::Theme;

struct DigView<'a> {
    qname: &'a str,
    qtype: &'a str,
    server: &'a str,
    transport: &'a str,
    rtt_ms: u64,
    rcode: &'a str,
    nsid: Option<&'a str>,
    ede_code: Option<u16>,
    ede_text: Option<&'a str>,
    zone: &'a str,
    message: &'a StoredDnsMessage,
}

impl<'a> DigView<'a> {
    fn from_hop(hop: &'a TraceHop) -> Self {
        Self {
            qname: &hop.qname,
            qtype: &hop.qtype,
            server: &hop.server,
            transport: &hop.transport,
            rtt_ms: hop.rtt_ms,
            rcode: &hop.rcode,
            nsid: hop.nsid.as_deref(),
            ede_code: hop.ede_code,
            ede_text: hop.ede_text.as_deref(),
            zone: &hop.zone,
            message: &hop.response,
        }
    }

    fn from_final(answer: &'a FinalAnswer) -> Self {
        let qname = if answer.qname.is_empty() {
            "."
        } else {
            answer.qname.as_str()
        };
        let qtype = if answer.qtype.is_empty() {
            "A"
        } else {
            answer.qtype.as_str()
        };
        Self {
            qname,
            qtype,
            server: &answer.server,
            transport: if answer.transport.is_empty() {
                "udp"
            } else {
                answer.transport.as_str()
            },
            rtt_ms: answer.rtt_ms,
            rcode: &answer.rcode,
            nsid: answer.nsid.as_deref(),
            ede_code: None,
            ede_text: None,
            zone: "final",
            message: &answer.response,
        }
    }

    fn to_plain(&self) -> String {
        let mut lines = Vec::new();
        self.push_meta_plain(&mut lines);
        lines.push(String::new());
        self.push_header_plain(&mut lines);
        self.push_section_plain(&mut lines, "ANSWER", &self.message.answers);
        self.push_section_plain(&mut lines, "AUTHORITY", &self.message.authorities);
        self.push_section_plain(&mut lines, "ADDITIONAL", &self.message.additionals);
        lines.join("\n")
    }

    fn to_styled(&self, theme: &Theme) -> Vec<Line<'static>> {
        let mut lines = Vec::new();
        lines.extend(self.meta_styled(theme));
        lines.push(Line::from(""));
        lines.extend(self.header_styled(theme));
        lines.extend(section_styled("ANSWER", &self.message.answers, theme));
        lines.extend(section_styled(
            "AUTHORITY",
            &self.message.authorities,
            theme,
        ));
        lines.extend(section_styled(
            "ADDITIONAL",
            &self.message.additionals,
            theme,
        ));
        lines
    }

    fn push_meta_plain(&self, lines: &mut Vec<String>) {
        lines.push(format!("zone: {}", self.zone));
        lines.push(format!(
            "server: {} ({}) in {}ms",
            self.server, self.transport, self.rtt_ms
        ));
        lines.push(format!("status: {}", self.rcode));
        if let Some(nsid) = self.nsid {
            lines.push(format!("nsid: {nsid}"));
        }
        if let Some(code) = self.ede_code {
            let text = self.ede_text.unwrap_or("");
            lines.push(format!("ede: {code}:{text}"));
        }
    }

    fn meta_styled(&self, theme: &Theme) -> Vec<Line<'static>> {
        let mut lines = vec![
            Line::from(vec![
                Span::styled("zone: ", theme.label()),
                Span::styled(self.zone.to_string(), theme.zone()),
            ]),
            Line::from(vec![
                Span::styled("server: ", theme.label()),
                Span::raw(format!("{} ({}) ", self.server, self.transport)),
                Span::styled(format!("{}ms", self.rtt_ms), theme.meta()),
            ]),
            Line::from(vec![
                Span::styled("status: ", theme.label()),
                Span::styled(self.rcode.to_string(), theme.rcode(self.rcode)),
            ]),
        ];
        if let Some(nsid) = self.nsid {
            lines.push(Line::from(vec![
                Span::styled("nsid: ", theme.label()),
                Span::raw(nsid.to_string()),
            ]));
        }
        if let Some(code) = self.ede_code {
            let text = self.ede_text.unwrap_or("");
            lines.push(Line::from(vec![
                Span::styled("ede: ", theme.label()),
                Span::raw(format!("{code}:{text}")),
            ]));
        }
        lines
    }

    fn push_header_plain(&self, lines: &mut Vec<String>) {
        lines.push(";; HEADER".into());
        lines.push(format!(
            ";;   id: {}  opcode: QUERY  status: {}",
            self.message.id, self.rcode
        ));
        lines.push(format!(";;   flags: {}", format_flags(self.message)));
        lines.push(format!(
            ";;   QUESTION: 1  ANSWER: {}  AUTHORITY: {}  ADDITIONAL: {}",
            self.message.answers.len(),
            self.message.authorities.len(),
            self.message.additionals.len()
        ));
        lines.push(String::new());
        lines.push(";; QUESTION SECTION:".into());
        lines.push(format!(";{:<24} IN  {}", self.qname, self.qtype));
    }

    fn header_styled(&self, theme: &Theme) -> Vec<Line<'static>> {
        vec![
            Line::from(Span::styled(";; HEADER", theme.section())),
            Line::from(vec![
                Span::styled(";;   id: ", theme.meta()),
                Span::raw(format!(
                    "{}  opcode: QUERY  status: {}",
                    self.message.id, self.rcode
                )),
            ]),
            Line::from(vec![
                Span::styled(";;   flags: ", theme.meta()),
                Span::raw(format_flags(self.message)),
            ]),
            Line::from(vec![
                Span::styled(";;   ", theme.meta()),
                Span::raw(format!(
                    "QUESTION: 1  ANSWER: {}  AUTHORITY: {}  ADDITIONAL: {}",
                    self.message.answers.len(),
                    self.message.authorities.len(),
                    self.message.additionals.len()
                )),
            ]),
            Line::from(""),
            Line::from(Span::styled(";; QUESTION SECTION:", theme.section())),
            Line::from(vec![
                Span::styled(";", theme.meta()),
                Span::raw(format!("{:<24} IN  ", self.qname)),
                Span::styled(self.qtype.to_string(), theme.record_type()),
            ]),
        ]
    }

    fn push_section_plain(&self, lines: &mut Vec<String>, title: &str, records: &[DnsRecord]) {
        if records.is_empty() {
            return;
        }
        lines.push(String::new());
        lines.push(format!(";; {title} SECTION:"));
        for record in records {
            lines.push(format_record(record));
        }
    }
}

pub fn hop_has_dig_view(hop: &TraceHop) -> bool {
    hop.response.is_stored()
}

pub fn final_has_dig_view(answer: &FinalAnswer) -> bool {
    answer.response.is_stored()
}

pub fn hop_detail_plain(hop: &TraceHop) -> String {
    if hop_has_dig_view(hop) {
        DigView::from_hop(hop).to_plain()
    } else {
        legacy_hop_detail_lines(hop).join("\n")
    }
}

pub fn final_detail_plain(answer: &FinalAnswer) -> String {
    if final_has_dig_view(answer) {
        DigView::from_final(answer).to_plain()
    } else {
        legacy_final_detail_lines(answer).join("\n")
    }
}

pub fn hop_detail_styled(hop: &TraceHop, theme: &Theme) -> Vec<Line<'static>> {
    if hop_has_dig_view(hop) {
        DigView::from_hop(hop).to_styled(theme)
    } else {
        legacy_hop_lines(hop, theme)
    }
}

pub fn final_detail_styled(answer: &FinalAnswer, theme: &Theme) -> Vec<Line<'static>> {
    if final_has_dig_view(answer) {
        DigView::from_final(answer).to_styled(theme)
    } else {
        legacy_final_lines(answer, theme)
    }
}

fn section_styled(title: &str, records: &[DnsRecord], theme: &Theme) -> Vec<Line<'static>> {
    if records.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!(";; {title} SECTION:"),
            theme.section(),
        )),
    ];
    for record in records {
        lines.push(record_styled(record, theme));
    }
    lines
}

fn format_flags(message: &StoredDnsMessage) -> String {
    let mut flags = vec!["qr"];
    if message.authoritative {
        flags.push("aa");
    }
    if message.truncated {
        flags.push("tc");
    }
    flags.join(" ")
}

fn format_record(record: &DnsRecord) -> String {
    format!(
        "{:<24} {:<5} {:<3} {:<5} {}",
        record.name, record.ttl, record.rclass, record.rtype, record.rdata
    )
}

fn record_styled(record: &DnsRecord, theme: &Theme) -> Line<'static> {
    Line::from(vec![
        Span::raw(format!("{:<24} {:<5} ", record.name, record.ttl)),
        Span::styled(format!("{:<3} ", record.rclass), theme.meta()),
        Span::styled(format!("{:<5} ", record.rtype), theme.record_type()),
        Span::raw(record.rdata.clone()),
    ])
}

fn legacy_hop_lines(hop: &TraceHop, theme: &Theme) -> Vec<Line<'static>> {
    legacy_hop_detail_lines(hop)
        .into_iter()
        .map(|line| styled_plain_line(&line, theme))
        .collect()
}

fn legacy_final_lines(answer: &FinalAnswer, theme: &Theme) -> Vec<Line<'static>> {
    legacy_final_detail_lines(answer)
        .into_iter()
        .map(|line| styled_plain_line(&line, theme))
        .collect()
}

fn styled_plain_line(line: &str, theme: &Theme) -> Line<'static> {
    if let Some((key, value)) = line.split_once(": ") {
        Line::from(vec![
            Span::styled(format!("{key}: "), theme.label()),
            Span::raw(value.to_string()),
        ])
    } else if line.ends_with(':') {
        Line::from(Span::styled(line.to_string(), theme.section()))
    } else if let Some(value) = line.strip_prefix("  - ") {
        Line::from(vec![Span::raw("  - "), Span::raw(value.to_string())])
    } else {
        Line::from(line.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_core::name::DomainName;
    use dns_core::response::DnsRecord;

    fn sample_message() -> StoredDnsMessage {
        StoredDnsMessage {
            id: 42,
            authoritative: false,
            truncated: false,
            answers: vec![],
            authorities: vec![DnsRecord {
                name: DomainName::parse("com.").expect("zone"),
                rtype: "NS".into(),
                rclass: "IN".into(),
                ttl: 86400,
                rdata: "a.gtld-servers.net.".into(),
            }],
            additionals: vec![],
        }
    }

    fn sample_hop() -> TraceHop {
        TraceHop {
            zone: ".".into(),
            server: "198.41.0.4".into(),
            qname: "example.com.".into(),
            qtype: "A".into(),
            transport: "udp".into(),
            rtt_ms: 11,
            rcode: "NOERROR".into(),
            nsid: None,
            ede_code: None,
            ede_text: None,
            referral_ns: vec!["a.gtld-servers.net.".into()],
            glue: vec![],
            response: sample_message(),
        }
    }

    #[test]
    fn dig_plain_includes_header_and_sections() {
        let text = hop_detail_plain(&sample_hop());
        assert!(text.contains(";; HEADER"));
        assert!(text.contains("flags: qr"));
        assert!(text.contains(";; QUESTION SECTION:"));
        assert!(text.contains(";example.com."));
        assert!(text.contains("IN  A"));
        assert!(text.contains(";; AUTHORITY SECTION:"));
        assert!(text.contains("a.gtld-servers.net."));
    }

    #[test]
    fn legacy_hop_falls_back_to_yaml_lists() {
        let mut hop = sample_hop();
        hop.response = StoredDnsMessage::default();
        let text = hop_detail_plain(&hop);
        assert!(text.contains("referral NS:\n  - a.gtld-servers.net."));
    }
}
