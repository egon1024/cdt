use std::net::IpAddr;

use dns_core::response::Transport;
use serde::{Deserialize, Serialize};

/// Cache key separating answers that differ by transport or EDNS flags.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheKey {
    pub server: IpAddr,
    pub port: u16,
    pub qname: String,
    pub qtype: String,
    pub transport: Transport,
    pub dnssec: bool,
    pub request_nsid: bool,
}

impl CacheKey {
    pub fn storage_key(&self) -> String {
        serde_json::to_string(self).expect("cache key json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn dnssec_flag_changes_key() {
        let base = CacheKey {
            server: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            port: 53,
            qname: "example.com.".into(),
            qtype: "A".into(),
            transport: Transport::Udp,
            dnssec: false,
            request_nsid: true,
        };
        let with_dnssec = CacheKey {
            dnssec: true,
            ..base.clone()
        };
        assert_ne!(base.storage_key(), with_dnssec.storage_key());
    }
}
