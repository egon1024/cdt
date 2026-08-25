use serde::{Deserialize, Serialize};

/// Extended DNS Error (OPT code 17, RFC 8914).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedDnsError {
    pub code: u16,
    pub meaning: String,
    pub extra_text: Option<String>,
}

/// Parsed EDNS option.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdnsOption {
    pub code: u16,
    pub name: String,
    pub raw: Vec<u8>,
    pub ede: Option<ExtendedDnsError>,
    pub nsid: Option<String>,
}

/// Parsed EDNS metadata from a DNS response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdnsMeta {
    pub version: u8,
    pub udp_payload_size: u16,
    pub dnssec_ok: bool,
    pub options: Vec<EdnsOption>,
}

impl EdnsMeta {
    pub fn nsid(&self) -> Option<&str> {
        self.options
            .iter()
            .find_map(|option| option.nsid.as_deref())
    }

    pub fn ede(&self) -> Option<&ExtendedDnsError> {
        self.options.iter().find_map(|option| option.ede.as_ref())
    }
}

const OPT_CODE_NSID: u16 = 3;
const OPT_CODE_EDE: u16 = 17;

/// IANA EDNS option code names (subset).
pub fn edns_option_name(code: u16) -> &'static str {
    match code {
        1 => "LLQ",
        2 => "UL",
        3 => "NSID",
        4 => "OWNER",
        5 => "DAU",
        6 => "DHU",
        7 => "N3U",
        8 => "CLIENT-SUBNET",
        10 => "EXPIRE",
        11 => "COOKIE",
        12 => "TCP-KEEPALIVE",
        13 => "PADDING",
        14 => "CHAIN",
        15 => "KEY-TAG",
        16 => "EXTENDED-DNS-ERROR",
        17 => "EDE",
        18 => "CLIENT-TAG",
        19 => "SERVER-TAG",
        _ => "UNKNOWN",
    }
}

/// EDE code meanings (RFC 8914, selected common codes).
pub fn ede_meaning(code: u16) -> &'static str {
    match code {
        0 => "Other",
        1 => "Unsupported DNSKEY Algorithm",
        2 => "Unsupported DS Digest Type",
        3 => "Stale Answer",
        4 => "Forged Answer",
        5 => "DNSSEC Indeterminate",
        6 => "DNSSEC Bogus",
        7 => "Signature Expired",
        8 => "Signature Not Yet Valid",
        9 => "DNSKEY Missing",
        10 => "RRSIGs Missing",
        11 => "No Zone Key Bit Set",
        12 => "NSEC Missing",
        13 => "Cached Error",
        14 => "Not Ready",
        15 => "Blocked",
        16 => "Censored",
        17 => "Filtered",
        18 => "Prohibited",
        19 => "Stale NXDOMAIN Answer",
        20 => "Not Authoritative",
        21 => "Not Supported",
        22 => "No Reachable Authority",
        23 => "Network Error",
        24 => "Invalid Data",
        _ => "Unknown EDE code",
    }
}

pub fn parse_ede_payload(raw: &[u8]) -> Option<ExtendedDnsError> {
    if raw.len() < 2 {
        return None;
    }

    let code = u16::from_be_bytes([raw[0], raw[1]]);
    let extra_text = if raw.len() > 2 {
        Some(String::from_utf8_lossy(&raw[2..]).into_owned())
    } else {
        None
    };

    Some(ExtendedDnsError {
        code,
        meaning: ede_meaning(code).to_owned(),
        extra_text,
    })
}

pub fn parse_nsid_payload(raw: &[u8]) -> String {
    if raw
        .iter()
        .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
    {
        String::from_utf8_lossy(raw).into_owned()
    } else {
        raw.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("")
    }
}

pub fn build_edns_option(code: u16, raw: Vec<u8>) -> EdnsOption {
    let mut option = EdnsOption {
        code,
        name: edns_option_name(code).to_owned(),
        raw: raw.clone(),
        ede: None,
        nsid: None,
    };

    match code {
        OPT_CODE_NSID => option.nsid = Some(parse_nsid_payload(&raw)),
        OPT_CODE_EDE => option.ede = parse_ede_payload(&raw),
        _ => {}
    }

    option
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ede_with_extra_text() {
        let mut raw = vec![0, 22];
        raw.extend_from_slice(b"No Reachable Authority");
        let ede = parse_ede_payload(&raw).expect("ede");
        assert_eq!(ede.code, 22);
        assert_eq!(ede.meaning, "No Reachable Authority");
        assert_eq!(ede.extra_text.as_deref(), Some("No Reachable Authority"));
    }

    #[test]
    fn parse_nsid_ascii() {
        assert_eq!(
            parse_nsid_payload(b"a.root-servers.net"),
            "a.root-servers.net"
        );
    }
}
