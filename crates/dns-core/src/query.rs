use hickory_proto::op::Edns;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::RecordType;
use hickory_proto::rr::rdata::opt::{EdnsOption, NSIDPayload};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

use crate::edns::{EdnsMeta, build_edns_option};
use crate::error::{DnsCoreError, Result};
use crate::name::DomainName;
use crate::response::{DnsResponse, Transport};

/// Options for constructing a DNS query.
#[derive(Debug, Clone)]
pub struct QueryOptions {
    pub qname: DomainName,
    pub qtype: RecordType,
    pub transport: Transport,
    pub timeout: std::time::Duration,
    pub retries: u8,
    pub dnssec: bool,
    pub request_nsid: bool,
    pub udp_payload_size: u16,
}

impl QueryOptions {
    pub fn new(qname: DomainName, qtype: RecordType) -> Self {
        Self {
            qname,
            qtype,
            transport: Transport::Udp,
            timeout: std::time::Duration::from_secs(5),
            retries: 2,
            dnssec: false,
            request_nsid: true,
            udp_payload_size: 1232,
        }
    }
}

/// Build a DNS query message wire bytes.
pub fn build_query(options: &QueryOptions) -> Result<Vec<u8>> {
    let qname = options.qname.to_wire_name()?;
    let mut message = Message::new(rand_query_id(), MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = false;
    message.add_query(Query::query(qname, options.qtype));

    let mut edns = Edns::new();
    edns.set_max_payload(options.udp_payload_size);
    if options.dnssec {
        edns.set_dnssec_ok(true);
    }

    if options.request_nsid {
        let nsid = NSIDPayload::try_from(&[][..])
            .map_err(|error| DnsCoreError::Parse(error.to_string()))?;
        edns.options_mut().insert(EdnsOption::NSID(nsid));
    }

    message.set_edns(edns);

    let mut bytes = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut bytes);
    message
        .emit(&mut encoder)
        .map_err(|error| DnsCoreError::Parse(error.to_string()))?;
    Ok(bytes)
}

/// Parse a user-supplied query type name.
pub fn parse_record_type(input: &str) -> Result<RecordType> {
    let upper = input.trim().to_ascii_uppercase();
    if let Some(raw) = upper.strip_prefix("TYPE") {
        let code: u16 = raw
            .parse()
            .map_err(|_| DnsCoreError::RecordType(input.into()))?;
        return Ok(RecordType::from(code));
    }

    match upper.as_str() {
        "RP" => Ok(RecordType::from(17)),
        "DNAME" => Ok(RecordType::from(39)),
        other => other
            .parse::<RecordType>()
            .map_err(|_| DnsCoreError::RecordType(input.into())),
    }
}

/// Stable presentation name for a record type (including hickory `Unknown` codes).
pub fn record_type_name(rtype: RecordType) -> String {
    match rtype {
        RecordType::Unknown(17) => "RP".into(),
        RecordType::Unknown(39) => "DNAME".into(),
        other => other.to_string(),
    }
}

/// Parse a DNS response from wire bytes.
pub fn parse_response(bytes: &[u8]) -> Result<DnsResponse> {
    DnsResponse::from_wire(bytes)
}

fn rand_query_id() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos())
        .unwrap_or(0);
    (nanos as u16) ^ (nanos as u16 >> 8)
}

/// Extract EDNS metadata from a parsed hickory message.
pub fn extract_edns_meta(message: &Message) -> EdnsMeta {
    let Some(edns) = message.edns.as_ref() else {
        return EdnsMeta::default();
    };

    let mut meta = EdnsMeta {
        version: edns.version(),
        udp_payload_size: edns.max_payload(),
        dnssec_ok: edns.flags().dnssec_ok,
        options: Vec::new(),
    };

    for (code, option) in edns.options().as_ref() {
        let code = u16::from(*code);
        let raw = option_to_raw(option);
        meta.options.push(build_edns_option(code, raw));
    }

    meta
}

fn option_to_raw(option: &EdnsOption) -> Vec<u8> {
    match option {
        EdnsOption::NSID(payload) => payload.as_ref().to_vec(),
        EdnsOption::Subnet(subnet) => {
            let mut raw = Vec::new();
            let _ = subnet.emit(&mut BinEncoder::new(&mut raw));
            raw
        }
        EdnsOption::Unknown(_, raw) => raw.clone(),
        #[allow(unreachable_patterns)]
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::RecordType;

    #[test]
    fn build_query_includes_edns() {
        let qname = DomainName::parse("example.com.").expect("qname");
        let options = QueryOptions::new(qname, RecordType::A);
        let wire = build_query(&options).expect("wire");
        let message = Message::from_vec(&wire).expect("message");
        assert!(message.edns.is_some());
    }

    #[test]
    fn parse_extended_record_types() {
        for (name, code) in [
            ("SRV", 33_u16),
            ("SSHFP", 44),
            ("HTTPS", 65),
            ("SVCB", 64),
            ("CAA", 257),
            ("PTR", 12),
            ("RP", 17),
            ("DNAME", 39),
        ] {
            let parsed = parse_record_type(name).expect(name);
            assert_eq!(u16::from(parsed), code, "{name}");
        }
        assert_eq!(u16::from(parse_record_type("TYPE39").expect("type")), 39);
    }

    #[test]
    fn record_type_name_maps_unknown_codes() {
        assert_eq!(record_type_name(RecordType::from(39)), "DNAME");
        assert_eq!(record_type_name(RecordType::from(17)), "RP");
    }
}
