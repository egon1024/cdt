use std::net::IpAddr;

/// IPv4 root server addresses (first IP per letter server, IANA order a–m).
pub fn root_servers_v4() -> Vec<IpAddr> {
    [
        "198.41.0.4",
        "199.9.14.201",
        "192.33.4.9",
        "199.7.91.13",
        "192.203.230.10",
        "192.5.5.241",
        "192.0.14.129",
        "192.0.47.126",
        "192.32.7.129",
        "192.52.178.30",
        "192.54.112.53",
        "192.55.83.30",
        "192.36.148.17",
    ]
    .iter()
    .filter_map(|addr| addr.parse().ok())
    .collect()
}

/// IPv6 root server addresses (IANA AAAA per letter server, same order as [`root_servers_v4`]).
pub fn root_servers_v6() -> Vec<IpAddr> {
    [
        "2001:503:ba3e::2:30",
        "2001:500:200::b",
        "2001:500:2::c",
        "2001:500:2d::d",
        "2001:500:a8::e",
        "2001:500:2f::f",
        "2001:500:12::d0d",
        "2001:500:1::53",
        "2001:7fe::53",
        "2001:503:c27::2:30",
        "2001:500:3::53",
        "2001:500:9f::42",
        "2001:dc3::35",
    ]
    .iter()
    .filter_map(|addr| addr.parse().ok())
    .collect()
}

/// All built-in root addresses: every IPv4 hint, then every IPv6 hint (v4 before v6 per letter batch).
pub fn root_servers() -> Vec<IpAddr> {
    let mut servers = root_servers_v4();
    servers.extend(root_servers_v6());
    servers
}

/// Root server letter names in the same order as [`root_servers_v4`] / [`root_servers_v6`].
pub fn root_server_names() -> [&'static str; 13] {
    [
        "a.root-servers.net.",
        "b.root-servers.net.",
        "c.root-servers.net.",
        "d.root-servers.net.",
        "e.root-servers.net.",
        "f.root-servers.net.",
        "g.root-servers.net.",
        "h.root-servers.net.",
        "i.root-servers.net.",
        "j.root-servers.net.",
        "k.root-servers.net.",
        "l.root-servers.net.",
        "m.root-servers.net.",
    ]
}

/// Built-in root hints as `(address, hostname)` pairs: all v4 letter servers, then all v6.
pub fn root_server_hints() -> Vec<(IpAddr, &'static str)> {
    let names = root_server_names();
    let mut hints = Vec::with_capacity(26);
    for (index, address) in root_servers_v4().into_iter().enumerate() {
        hints.push((address, names[index]));
    }
    for (index, address) in root_servers_v6().into_iter().enumerate() {
        hints.push((address, names[index]));
    }
    hints
}

/// Nameserver hostname for a built-in root server address, when known.
pub fn root_server_name_for(address: IpAddr) -> Option<&'static str> {
    root_server_hints()
        .into_iter()
        .find_map(|(candidate, name)| (candidate == address).then_some(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn root_server_name_for_known_v4_address() {
        let address = IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4));
        assert_eq!(root_server_name_for(address), Some("a.root-servers.net."));
    }

    #[test]
    fn root_server_name_for_known_v6_address() {
        let address: IpAddr = "2001:503:ba3e::2:30".parse().expect("v6");
        assert_eq!(root_server_name_for(address), Some("a.root-servers.net."));
    }

    #[test]
    fn root_hints_include_thirteen_v6_addresses() {
        assert_eq!(root_servers_v6().len(), 13);
        assert!(
            root_servers_v6()
                .iter()
                .all(|addr| matches!(addr, IpAddr::V6(_)))
        );
    }

    #[test]
    fn ordered_hints_list_v4_before_v6() {
        let hints = root_server_hints();
        assert_eq!(hints.len(), 26);
        assert!(matches!(hints[0].0, IpAddr::V4(_)));
        assert!(matches!(hints[13].0, IpAddr::V6(_)));
        assert_eq!(hints[0].1, hints[13].1);
    }

    #[test]
    fn probe_target_matches_first_v6_root() {
        let first_v6 = root_servers_v6()[0];
        assert_eq!(
            first_v6,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x503, 0xba3e, 0, 0, 0, 0x2, 0x30))
        );
    }
}
