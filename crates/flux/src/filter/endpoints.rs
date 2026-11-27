use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

#[derive(Debug, Clone, Default)]
pub struct EndpointIndex {
    pub nets: Vec<IpNet>,
    pub addrs: Vec<IpAddr>,
}

impl EndpointIndex {
    pub fn from_tokens(tokens: &[String], resolver: &dyn EndpointResolver) -> Self {
        let mut nets = Vec::new();
        let mut addrs = Vec::new();
        for tok in tokens {
            if let Ok(net) = tok.parse::<IpNet>() {
                nets.push(net);
                continue;
            }
            if let Ok(ip) = tok.parse::<IpAddr>() {
                addrs.push(ip);
                continue;
            }
            for ip in resolver.resolve_host(tok) {
                addrs.push(ip);
            }
        }
        Self { nets, addrs }
    }

    pub fn merge(&mut self, other: &Self) {
        self.nets.extend(other.nets.iter().cloned());
        self.addrs.extend(other.addrs.iter().cloned());
    }

    pub fn ip_matches_any(&self, patterns: &[String], ip: &[u8]) -> bool {
        if patterns.is_empty() {
            return self.contains_ip(ip);
        }
        let idx = EndpointIndex::from_tokens(patterns, &NoopResolver);
        idx.contains_ip(ip)
    }

    pub fn contains_ip(&self, ip: &[u8]) -> bool {
        let Some(addr) = bytes_to_ip(ip) else {
            return false;
        };
        self.addrs.contains(&addr) || self.nets.iter().any(|n| n.contains(&addr))
    }
}

pub trait EndpointResolver: Send + Sync {
    fn resolve_host(&self, host: &str) -> Vec<IpAddr>;
}

#[derive(Debug, Default)]
pub struct NoopResolver;

impl EndpointResolver for NoopResolver {
    fn resolve_host(&self, _host: &str) -> Vec<IpAddr> {
        Vec::new()
    }
}

#[derive(Debug, Clone, Default)]
pub struct StubResolver {
    pub hosts: HashMap<String, Vec<IpAddr>>,
}

impl EndpointResolver for StubResolver {
    fn resolve_host(&self, host: &str) -> Vec<IpAddr> {
        self.hosts
            .get(&host.to_ascii_lowercase())
            .cloned()
            .unwrap_or_default()
    }
}

fn bytes_to_ip(bytes: &[u8]) -> Option<IpAddr> {
    match bytes.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        16 => {
            let chunks: Vec<_> = bytes
                .chunks(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            if chunks.len() == 8 {
                Some(IpAddr::V6(Ipv6Addr::new(
                    chunks[0], chunks[1], chunks[2], chunks[3], chunks[4], chunks[5], chunks[6],
                    chunks[7],
                )))
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn cidr_matches() {
        let idx = EndpointIndex::from_tokens(&["10.0.0.0/8".into()], &NoopResolver);
        let ip = [10, 1, 2, 3];
        assert!(idx.contains_ip(&ip));
        assert!(!idx.contains_ip(&[11, 0, 0, 1]));
    }

    #[test]
    fn stub_resolver_expands_names() {
        let mut resolver = StubResolver::default();
        resolver.hosts.insert(
            "ns1.example.net".into(),
            vec![IpAddr::from_str("203.0.113.1").unwrap()],
        );
        let idx = EndpointIndex::from_tokens(&["ns1.example.net".into()], &resolver);
        let ip: [u8; 4] = [203, 0, 113, 1];
        assert!(idx.contains_ip(&ip));
    }
}
