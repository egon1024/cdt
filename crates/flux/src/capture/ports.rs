use std::collections::HashSet;

use thiserror::Error;

#[derive(Debug, Clone, Default)]
pub struct PortSet {
    ports: HashSet<u16>,
}

impl PortSet {
    pub fn dns_default() -> Self {
        Self::parse("53").expect("53")
    }

    pub fn parse(list: &str) -> Result<Self, PortParseError> {
        let mut ports = HashSet::new();
        for part in list.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((a, b)) = part.split_once('-') {
                let lo: u16 = a
                    .trim()
                    .parse()
                    .map_err(|_| PortParseError::Invalid(part.into()))?;
                let hi: u16 = b
                    .trim()
                    .parse()
                    .map_err(|_| PortParseError::Invalid(part.into()))?;
                if lo > hi {
                    return Err(PortParseError::Range(lo, hi));
                }
                for p in lo..=hi {
                    ports.insert(p);
                }
            } else {
                let p: u16 = part
                    .parse()
                    .map_err(|_| PortParseError::Invalid(part.into()))?;
                ports.insert(p);
            }
        }
        if ports.is_empty() {
            return Err(PortParseError::Empty);
        }
        Ok(Self { ports })
    }

    pub fn contains(&self, port: u16) -> bool {
        self.ports.contains(&port)
    }

    pub fn is_dns_port(&self, src_port: u16, dst_port: u16) -> bool {
        self.contains(src_port) || self.contains(dst_port)
    }

    pub fn iter_sorted(&self) -> Vec<u16> {
        let mut v: Vec<_> = self.ports.iter().copied().collect();
        v.sort_unstable();
        v
    }
}

/// Decide whether the initiator endpoint is the L3 source, using listed DNS ports with QR fallback.
pub fn initiator_is_src(src_port: u16, dst_port: u16, qr: bool, ports: &PortSet) -> bool {
    let src_dns = ports.contains(src_port);
    let dst_dns = ports.contains(dst_port);
    match (src_dns, dst_dns) {
        (false, true) => true,
        (true, false) => false,
        (true, true) => !qr,
        (false, false) => !qr,
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PortParseError {
    #[error("empty port list")]
    Empty,
    #[error("invalid port or range: {0}")]
    Invalid(String),
    #[error("invalid port range {0}-{1}")]
    Range(u16, u16),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_53() {
        let p = PortSet::dns_default();
        assert!(p.contains(53));
        assert!(!p.contains(5353));
    }

    #[test]
    fn range_and_list() {
        let p = PortSet::parse("53,5353,8053-8055").unwrap();
        assert!(p.contains(53));
        assert!(p.contains(5353));
        assert!(p.contains(8054));
        assert!(!p.contains(8056));
    }

    #[test]
    fn server_to_server_uses_qr() {
        let p = PortSet::dns_default();
        assert!(initiator_is_src(53, 53, false, &p));
        assert!(!initiator_is_src(53, 53, true, &p));
    }

    #[test]
    fn client_to_server_uses_ports() {
        let p = PortSet::dns_default();
        assert!(initiator_is_src(49152, 53, false, &p));
        assert!(!initiator_is_src(53, 49152, true, &p));
    }
}
