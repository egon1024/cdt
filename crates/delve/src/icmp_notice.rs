use dns_resolve::IcmpProbeCapability;

/// One-line stderr guidance when comparison ICMP cannot use datagram sockets.
pub fn format_comparison_icmp_notice(capability: IcmpProbeCapability) -> Option<String> {
    match capability {
        IcmpProbeCapability::Datagram => None,
        IcmpProbeCapability::PingCommand => Some(format!(
            "icmp: unprivileged ICMP sockets unavailable; using /bin/ping for network RTT.{}{}",
            linux_ping_group_hint(),
            disable_icmp_enrichment_hint()
        )),
        IcmpProbeCapability::None => Some(format!(
            "icmp: unavailable — unprivileged ICMP sockets are blocked and /bin/ping is not usable.{}{}",
            linux_ping_group_hint(),
            disable_icmp_enrichment_hint()
        )),
    }
}

fn disable_icmp_enrichment_hint() -> String {
    " To silence this notice, set enrichment.icmp.enabled: false in delve.yaml.".into()
}

fn linux_ping_group_hint() -> String {
    #[cfg(target_os = "linux")]
    {
        let gid = std::process::Command::new("id")
            .arg("-g")
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "1000".into());
        format!(" Optional native fix: sudo sysctl -w net.ipv4.ping_group_range=\"0 {gid}\".")
    }
    #[cfg(not(target_os = "linux"))]
    {
        String::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_capability_emits_no_notice() {
        assert!(format_comparison_icmp_notice(IcmpProbeCapability::Datagram).is_none());
    }

    #[test]
    fn fallback_notice_mentions_ping() {
        let notice =
            format_comparison_icmp_notice(IcmpProbeCapability::PingCommand).expect("notice");
        assert!(notice.contains("/bin/ping"));
        assert!(notice.contains("enrichment.icmp.enabled: false"));
        assert!(notice.contains("delve.yaml"));
        assert!(!notice.contains("delve.toml"));
    }

    #[test]
    fn unavailable_notice_mentions_icmp() {
        let notice = format_comparison_icmp_notice(IcmpProbeCapability::None).expect("notice");
        assert!(notice.contains("icmp: unavailable"));
        assert!(notice.contains("enrichment.icmp.enabled: false"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_notice_includes_sysctl_hint() {
        let notice =
            format_comparison_icmp_notice(IcmpProbeCapability::PingCommand).expect("notice");
        assert!(notice.contains("ping_group_range"));
    }
}
