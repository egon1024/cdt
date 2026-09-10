use dns_resolve::TraceHop;
use ratatui::style::Style;
use ratatui::text::Span;
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use super::detail::effective_server_name;
use super::theme::Theme;

/// Generous cap for tree/compare rows; detail pane passes `None` for no truncation.
pub const DEFAULT_IDENTITY_MAX_WIDTH: usize = 52;
pub const MAX_IDENTITY_COLUMN_WIDTH: usize = 56;
pub const MIN_IDENTITY_COLUMN_WIDTH: usize = 16;

pub fn format_hop_identity(hop: &TraceHop, max_width: Option<usize>) -> String {
    let body = hop_identity_body(hop);
    let full = format!("[{}] {body}", hop.zone);
    match max_width {
        Some(max) => truncate_to_display_width(&full, max),
        None => full,
    }
}

pub fn hop_identity_display_width(hop: &TraceHop, max_width: Option<usize>) -> usize {
    display_width(format_hop_identity(hop, max_width).as_str())
}

pub fn hop_identity_spans(
    hop: &TraceHop,
    theme: &Theme,
    max_width: Option<usize>,
    body_style: Style,
) -> Vec<Span<'static>> {
    let zone = format!("[{}] ", hop.zone);
    let body = hop_identity_body(hop);
    let (zone, body) = match max_width {
        Some(max) => truncate_identity_parts(&zone, &body, max),
        None => (zone, body),
    };
    vec![
        Span::styled(zone, theme.zone()),
        Span::styled(body, body_style),
    ]
}

fn hop_identity_body(hop: &TraceHop) -> String {
    match effective_server_name(&hop.server, hop.server_name.as_deref()) {
        Some(name) => format!("{name} ({})", hop.server),
        None => format!("({})", hop.server),
    }
}

fn truncate_identity_parts(zone: &str, body: &str, max_width: usize) -> (String, String) {
    let full = format!("{zone}{body}");
    if display_width(full.as_str()) <= max_width {
        return (zone.to_string(), body.to_string());
    }
    // Prefer keeping the zone label intact; truncate the hostname/IP suffix.
    let zone_width = display_width(zone);
    if zone_width >= max_width {
        return (truncate_to_display_width(zone, max_width), String::new());
    }
    let body_budget = max_width.saturating_sub(zone_width);
    (
        zone.to_string(),
        truncate_to_display_width(body, body_budget),
    )
}

fn truncate_to_display_width(value: &str, max_width: usize) -> String {
    if display_width(value) <= max_width {
        return value.to_string();
    }
    let mut end = 0;
    let mut width = 0;
    for ch in value.chars() {
        let ch_width = UnicodeWidthChar::width(ch).unwrap_or(0);
        if width + ch_width > max_width.saturating_sub(1) {
            break;
        }
        width += ch_width;
        end += ch.len_utf8();
    }
    format!("{}…", &value[..end])
}

fn display_width(text: &str) -> usize {
    UnicodeWidthStr::width(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::{HopOutcome, TraceHop};

    fn hop(zone: &str, server: &str, server_name: Option<&str>) -> TraceHop {
        TraceHop {
            zone: zone.into(),
            server: server.into(),
            server_name: server_name.map(str::to_string),
            qname: "example.com.".into(),
            qtype: "A".into(),
            transport: "udp".into(),
            rtt_ms: 10,
            rcode: "NOERROR".into(),
            nsid: None,
            ede_code: None,
            ede_text: None,
            referral_ns: vec![],
            glue: vec![],
            response: Default::default(),
            from_cache: false,
            outcome: HopOutcome::Referral,
        }
    }

    #[test]
    fn identity_includes_zone_hostname_and_ip() {
        let text = format_hop_identity(&hop(".", "198.41.0.4", None), None);
        assert_eq!(text, "[.] a.root-servers.net. (198.41.0.4)");
    }

    #[test]
    fn identity_omits_hostname_when_unknown() {
        let text = format_hop_identity(&hop("com.", "192.41.162.30", None), None);
        assert_eq!(text, "[com.] (192.41.162.30)");
    }

    #[test]
    fn identity_uses_explicit_server_name() {
        let text = format_hop_identity(
            &hop("tuininga.org.", "193.47.99.5", Some("ns1.example.net.")),
            None,
        );
        assert_eq!(text, "[tuininga.org.] ns1.example.net. (193.47.99.5)");
    }

    #[test]
    fn identity_truncates_when_max_width_set() {
        let hop = hop("com.", "192.41.162.30", Some("a.gtld-servers.net."));
        let text = format_hop_identity(&hop, Some(24));
        assert!(display_width(text.as_str()) <= 24);
        assert!(text.starts_with("[com.]"));
        assert!(text.ends_with('…'));
    }
}
