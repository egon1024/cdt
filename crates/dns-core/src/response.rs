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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryResult {
    pub server: IpAddr,
    pub transport: Transport,
    pub qname: DomainName,
    pub qtype: String,
    pub rtt: Duration,
    pub response: DnsResponse,
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
}
