use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use hickory_proto::op::Message;
use hickory_proto::rr::Record;
use serde::{Deserialize, Serialize};

use crate::edns::EdnsMeta;
use crate::error::{DnsCoreError, Result};
use crate::name::DomainName;
use crate::query::extract_edns_meta;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transport {
    Udp,
    Tcp,
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Udp => write!(f, "udp"),
            Self::Tcp => write!(f, "tcp"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsResponse {
    pub id: u16,
    pub rcode: u16,
    pub rcode_text: String,
    pub authoritative: bool,
    pub truncated: bool,
    #[serde(default)]
    pub recursion_desired: bool,
    #[serde(default)]
    pub recursion_available: bool,
    #[serde(default)]
    pub authentic_data: bool,
    #[serde(default)]
    pub checking_disabled: bool,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
    pub edns: EdnsMeta,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: DomainName,
    pub rtype: String,
    pub rclass: String,
    pub ttl: u32,
    pub rdata: String,
}

impl DnsResponse {
    pub fn from_wire(bytes: &[u8]) -> Result<Self> {
        let message =
            Message::from_vec(bytes).map_err(|error| DnsCoreError::Parse(error.to_string()))?;
        Ok(Self::from_message(&message))
    }

    pub fn from_message(message: &Message) -> Self {
        let rcode = u16::from(message.metadata.response_code);
        Self {
            id: message.metadata.id,
            rcode,
            rcode_text: rcode_to_text(rcode),
            authoritative: message.metadata.authoritative,
            truncated: message.metadata.truncation,
            recursion_desired: message.metadata.recursion_desired,
            recursion_available: message.metadata.recursion_available,
            authentic_data: message.metadata.authentic_data,
            checking_disabled: message.metadata.checking_disabled,
            answers: message.answers.iter().map(convert_record).collect(),
            authorities: message.authorities.iter().map(convert_record).collect(),
            additionals: message.additionals.iter().map(convert_record).collect(),
            edns: extract_edns_meta(message),
        }
    }

    pub fn referral_zone(&self, _qname: &DomainName) -> Option<DomainName> {
        self.authorities
            .iter()
            .filter(|record| record.rtype == "NS")
            .filter_map(|record| DomainName::parse(record.name.as_str()).ok())
            .next()
    }

    pub fn ns_names(&self) -> Vec<DomainName> {
        self.authorities
            .iter()
            .filter(|record| record.rtype == "NS")
            .filter_map(|record| DomainName::parse(record.rdata.as_str()).ok())
            .collect()
    }

    pub fn glue_for(&self, ns_name: &DomainName) -> Vec<IpAddr> {
        self.additionals
            .iter()
            .filter(|record| record.rtype == "A" || record.rtype == "AAAA")
            .filter(|record| record.name.as_str().eq_ignore_ascii_case(ns_name.as_str()))
            .filter_map(|record| record.rdata.parse().ok())
            .collect()
    }

    /// CNAME target when `qname` is exactly the CNAME owner in the answer section.
    pub fn cname_target(&self, qname: &DomainName) -> Option<DomainName> {
        self.answers.iter().find_map(|record| {
            if record.rtype != "CNAME" {
                return None;
            }
            if !record.name.as_str().eq_ignore_ascii_case(qname.as_str()) {
                return None;
            }
            DomainName::parse(record.rdata.as_str()).ok()
        })
    }

    /// Rewrite `qname` using the longest applicable DNAME from answers or authority.
    pub fn dname_rewrite(&self, qname: &DomainName) -> Option<DomainName> {
        let q = qname.as_str().trim_end_matches('.');
        let mut best: Option<(usize, &DnsRecord)> = None;

        for record in self
            .answers
            .iter()
            .chain(self.authorities.iter())
            .filter(|record| record.rtype == "DNAME")
        {
            let owner = record.name.as_str().trim_end_matches('.');
            if q == owner || q.ends_with(&format!(".{owner}")) {
                let labels = owner.split('.').filter(|label| !label.is_empty()).count();
                if best
                    .as_ref()
                    .is_none_or(|(best_labels, _)| labels > *best_labels)
                {
                    best = Some((labels, record));
                }
            }
        }

        let (_, record) = best?;
        let owner = record.name.as_str().trim_end_matches('.');
        let left = q.strip_suffix(owner)?.strip_suffix('.').unwrap_or("");
        let target = record.rdata.trim_end_matches('.');
        let rewritten = if left.is_empty() {
            format!("{target}.")
        } else {
            format!("{left}.{target}.")
        };
        DomainName::parse(&rewritten).ok()
    }

    /// Next qname after following a CNAME or applying a DNAME rewrite, if any.
    pub fn alias_target(&self, qname: &DomainName) -> Option<DomainName> {
        if let Some(target) = self.cname_target(qname) {
            if !target.as_str().eq_ignore_ascii_case(qname.as_str()) {
                return Some(target);
            }
        }
        self.dname_rewrite(qname)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryResult {
    pub server: IpAddr,
    pub transport: Transport,
    pub qname: DomainName,
    pub qtype: String,
    pub rtt: Duration,
    pub response: DnsResponse,
    /// True when this response was served from the response cache.
    #[serde(default)]
    pub from_cache: bool,
}

fn convert_record(record: &Record) -> DnsRecord {
    DnsRecord {
        name: DomainName::parse(&record.name.to_ascii())
            .unwrap_or_else(|_| DomainName::parse(".").expect("root")),
        rtype: record.record_type().to_string(),
        rclass: record.dns_class.to_string(),
        ttl: record.ttl,
        rdata: record.data.to_string(),
    }
}

fn rcode_to_text(rcode: u16) -> String {
    match rcode {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        _ => format!("RCODE{rcode}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn referral_zone_from_ns() {
        let response = DnsResponse {
            id: 1,
            rcode: 0,
            rcode_text: "NOERROR".into(),
            authoritative: false,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
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
            edns: EdnsMeta::default(),
        };

        let qname = DomainName::parse("example.com.").expect("qname");
        assert_eq!(
            response.referral_zone(&qname).map(|zone| zone.to_string()),
            Some("com.".into())
        );
    }

    #[test]
    fn cname_target_from_answer() {
        let qname = DomainName::parse("www.example.com.").expect("qname");
        let response = DnsResponse {
            id: 1,
            rcode: 0,
            rcode_text: "NOERROR".into(),
            authoritative: true,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
            authentic_data: false,
            checking_disabled: false,
            answers: vec![DnsRecord {
                name: qname.clone(),
                rtype: "CNAME".into(),
                rclass: "IN".into(),
                ttl: 300,
                rdata: "cdn.example.com.".into(),
            }],
            authorities: vec![],
            additionals: vec![],
            edns: EdnsMeta::default(),
        };

        assert_eq!(
            response.cname_target(&qname).map(|name| name.to_string()),
            Some("cdn.example.com.".into())
        );
    }

    #[test]
    fn dname_rewrite_expands_suffix() {
        let qname = DomainName::parse("www.example.com.").expect("qname");
        let response = DnsResponse {
            id: 1,
            rcode: 0,
            rcode_text: "NOERROR".into(),
            authoritative: true,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
            authentic_data: false,
            checking_disabled: false,
            answers: vec![DnsRecord {
                name: DomainName::parse("example.com.").expect("owner"),
                rtype: "DNAME".into(),
                rclass: "IN".into(),
                ttl: 300,
                rdata: "newexample.net.".into(),
            }],
            authorities: vec![],
            additionals: vec![],
            edns: EdnsMeta::default(),
        };

        assert_eq!(
            response.dname_rewrite(&qname).map(|name| name.to_string()),
            Some("www.newexample.net.".into())
        );
    }
}
