use crate::config::DelveConfig;
use crate::session::{CaptureContext, PublicIpCapture, now_rfc3339};

pub fn capture_context_from_config(config: &DelveConfig) -> Option<CaptureContext> {
    if !config.capture_public_ip_enabled {
        return None;
    }
    let public_ip = resolve_public_ip(config)?;
    Some(CaptureContext {
        local_source_ips: Vec::new(),
        public_ip: Some(public_ip),
    })
}

fn resolve_public_ip(config: &DelveConfig) -> Option<PublicIpCapture> {
    match config.capture_public_ip_provider.as_str() {
        "static" => {
            let address = config.capture_public_ip_static_address?;
            Some(PublicIpCapture {
                provider: "static".into(),
                address,
                observed_at: now_rfc3339(),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn disabled_capture_returns_none() {
        let config = DelveConfig::default();
        assert!(capture_context_from_config(&config).is_none());
    }

    #[test]
    fn static_provider_stores_configured_address_without_network() {
        let config = DelveConfig {
            capture_public_ip_enabled: true,
            capture_public_ip_provider: "static".into(),
            capture_public_ip_static_address: Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            ..Default::default()
        };
        let context = capture_context_from_config(&config).expect("context");
        let public_ip = context.public_ip.expect("public ip");
        assert_eq!(public_ip.provider, "static");
        assert_eq!(
            public_ip.address,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))
        );
        assert!(!public_ip.observed_at.is_empty());
    }

    #[test]
    fn enabled_static_without_address_returns_none() {
        let config = DelveConfig {
            capture_public_ip_enabled: true,
            capture_public_ip_provider: "static".into(),
            ..Default::default()
        };
        assert!(capture_context_from_config(&config).is_none());
    }
}
