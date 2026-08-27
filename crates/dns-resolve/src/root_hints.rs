/// Built-in root server addresses (first IP per letter server).
pub fn root_servers() -> Vec<std::net::IpAddr> {
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

/// Root server letter names in the same order as [`root_servers`].
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

/// Nameserver hostname for a built-in root server address, when known.
pub fn root_server_name_for(address: std::net::IpAddr) -> Option<&'static str> {
    root_servers()
        .into_iter()
        .zip(root_server_names())
        .find_map(|(candidate, name)| (candidate == address).then_some(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn root_server_name_for_known_address() {
        let address = IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4));
        assert_eq!(root_server_name_for(address), Some("a.root-servers.net."));
    }
}
