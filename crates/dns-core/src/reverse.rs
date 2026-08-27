use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{DnsCoreError, Result};
use crate::name::DomainName;

/// Convert an IP address to the corresponding reverse-DNS (PTR) query name.
pub fn ip_to_ptr_name(addr: IpAddr) -> Result<DomainName> {
    match addr {
        IpAddr::V4(v4) => ipv4_to_ptr_name(v4),
        IpAddr::V6(v6) => ipv6_to_ptr_name(v6),
    }
}

fn ipv4_to_ptr_name(addr: Ipv4Addr) -> Result<DomainName> {
    let [a, b, c, d] = addr.octets();
    DomainName::parse(&format!("{d}.{c}.{b}.{a}.in-addr.arpa."))
}

fn ipv6_to_ptr_name(addr: Ipv6Addr) -> Result<DomainName> {
    let mut labels = Vec::with_capacity(32);
    for byte in addr.octets().into_iter().rev() {
        labels.push(format!("{:x}", byte & 0x0f));
        labels.push(format!("{:x}", byte >> 4));
    }
    DomainName::parse(&format!("{}.ip6.arpa.", labels.join(".")))
}

/// Parse a user-supplied reverse-lookup target as an IP address.
pub fn parse_reverse_target(input: &str) -> Result<IpAddr> {
    input
        .trim()
        .parse()
        .map_err(|error| DnsCoreError::Name(format!("invalid IP address for -x: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn ipv4_ptr_name() {
        let name = ip_to_ptr_name(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))).expect("name");
        assert_eq!(name.as_str(), "1.2.0.192.in-addr.arpa.");
    }

    #[test]
    fn ipv6_ptr_name() {
        let name = ip_to_ptr_name("2001:db8::1".parse().expect("ip")).expect("name");
        assert_eq!(
            name.as_str(),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
        );
    }
}
