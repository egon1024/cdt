use dns_resolve::StoredDnsMessage;
use ratatui::text::Span;

use super::theme::Theme;

/// DNS header flags in a stable display order (response-oriented).
pub const FLAG_ORDER: &[&str] = &["qr", "rd", "ra", "aa", "tc", "ad", "cd"];

pub fn flag_states(message: &StoredDnsMessage) -> Vec<(&'static str, bool)> {
    FLAG_ORDER
        .iter()
        .map(|name| {
            let active = match *name {
                "qr" => true,
                "rd" => message.recursion_desired,
                "ra" => message.recursion_available,
                "aa" => message.authoritative,
                "tc" => message.truncated,
                "ad" => message.authentic_data,
                "cd" => message.checking_disabled,
                _ => false,
            };
            (*name, active)
        })
        .collect()
}

pub fn format_flags_plain(message: &StoredDnsMessage) -> String {
    flag_states(message)
        .into_iter()
        .map(|(name, active)| flag_token_plain(name, active))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn format_flags_spans(message: &StoredDnsMessage, theme: &Theme) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    for (index, (name, active)) in flag_states(message).into_iter().enumerate() {
        if index > 0 {
            spans.push(Span::raw(" "));
        }
        spans.push(Span::styled(
            flag_token_plain(name, active),
            if active {
                theme.flag_active()
            } else {
                theme.flag_inactive()
            },
        ));
    }
    spans
}

fn flag_token_plain(name: &str, active: bool) -> String {
    if active {
        name.to_ascii_uppercase()
    } else {
        format!("({name})")
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
            recursion_desired: true,
            recursion_available: true,
            authentic_data: false,
            checking_disabled: false,
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

    #[test]
    fn plain_flags_list_all_in_order_with_inactive_markers() {
        let text = format_flags_plain(&sample_message());
        assert_eq!(text, "QR RD RA (aa) (tc) (ad) (cd)");
    }

    #[test]
    fn flag_order_is_stable() {
        assert_eq!(FLAG_ORDER, &["qr", "rd", "ra", "aa", "tc", "ad", "cd"]);
    }
}
