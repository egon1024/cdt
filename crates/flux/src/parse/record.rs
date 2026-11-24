use dns_core::query::extract_edns_meta;
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;

use crate::capture::{DecodedDns, PortSet, initiator_is_src};
use crate::options::AddressFamily;

use super::ede::encode_edes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QnameHash(pub u64);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DnsFlags {
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub ad: bool,
    pub cd: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EdnsSummary {
    pub present: bool,
    pub version: u8,
    pub udp_payload_size: u16,
    pub dnssec_ok: bool,
    pub option_codes: [u16; 8],
    pub option_code_count: u8,
}

impl EdnsSummary {
    pub fn has_option(&self, code: u16) -> bool {
        let n = self.option_code_count as usize;
        self.option_codes[..n].contains(&code)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportProto {
    Udp,
    Tcp,
}

#[derive(Debug, Clone)]
pub struct ParsedObservation {
    pub record: ObservationRecord,
    pub ede_blob: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ObservationRecord {
    pub slice_sec: u64,
    pub iface: String,
    pub vlan: Option<u16>,
    pub family: AddressFamily,
    pub transport: TransportProto,
    pub src_ip: [u8; 16],
    pub src_len: u8,
    pub dst_ip: [u8; 16],
    pub dst_len: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub wire_len: u16,
    pub malformed: bool,
    pub id: u16,
    pub qr: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub flags: DnsFlags,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
    pub qname: String,
    pub qname_hash: QnameHash,
    pub qtype: u16,
    pub qclass: u16,
    pub edns: EdnsSummary,
    pub ede_off: u32,
    pub ede_len: u16,
    pub latency_ms: u32,
    pub fragment_count: u8,
    pub segment_count: u8,
    pub ip_fragmented: bool,
    pub unanswered: bool,
    pub tc_retry: bool,
    pub paired: bool,
    /// L3 source is the DNS initiator (port/QR semantics).
    pub initiator_is_src: bool,
}

impl ObservationRecord {
    pub fn ede_blob<'a>(&self, arena: &'a [u8]) -> &'a [u8] {
        if self.ede_len == 0 {
            return &[];
        }
        let off = self.ede_off as usize;
        let end = off.saturating_add(self.ede_len as usize);
        arena.get(off..end).unwrap_or(&[])
    }

    pub fn ede_codes(&self, arena: &[u8]) -> Vec<u16> {
        super::ede::distinct_ede_codes(self.ede_blob(arena))
    }

    pub fn has_ede(&self, arena: &[u8]) -> bool {
        !self.ede_blob(arena).is_empty()
    }

    pub fn initiator_is_src(&self) -> bool {
        self.initiator_is_src
    }

    pub fn responder_ip(&self) -> &[u8] {
        if self.initiator_is_src {
            &self.dst_ip[..self.dst_len as usize]
        } else {
            &self.src_ip[..self.src_len as usize]
        }
    }

    pub fn initiator_ip(&self) -> &[u8] {
        if self.initiator_is_src {
            &self.src_ip[..self.src_len as usize]
        } else {
            &self.dst_ip[..self.dst_len as usize]
        }
    }
}

pub fn parse_dns_payload(dns: &DecodedDns, slice_sec: u64, iface: &str) -> ParsedObservation {
    parse_dns_payload_with_transport(
        dns,
        slice_sec,
        iface,
        TransportProto::Udp,
        &PortSet::dns_default(),
    )
}

pub fn parse_dns_payload_with_transport(
    dns: &DecodedDns,
    slice_sec: u64,
    iface: &str,
    transport: TransportProto,
    ports: &PortSet,
) -> ParsedObservation {
    let wire_len = dns.payload.len().min(u16::MAX as usize) as u16;
    match Message::from_vec(&dns.payload) {
        Ok(msg) => {
            let qr = msg.metadata.message_type == hickory_proto::op::MessageType::Response;
            let opcode = u8::from(msg.metadata.op_code);
            let rcode = u16::from(msg.metadata.response_code) as u8;
            let id = msg.metadata.id;
            let flags = DnsFlags {
                aa: msg.metadata.authoritative,
                tc: msg.metadata.truncation,
                rd: msg.metadata.recursion_desired,
                ra: msg.metadata.recursion_available,
                ad: msg.metadata.authentic_data,
                cd: msg.metadata.checking_disabled,
            };
            let qdcount = msg.queries.len().min(u16::MAX as usize) as u16;
            let ancount = msg.answers.len().min(u16::MAX as usize) as u16;
            let nscount = msg.authorities.len().min(u16::MAX as usize) as u16;
            let arcount = msg.additionals.len().min(u16::MAX as usize) as u16;
            let (qname, qtype, qclass) = if let Some(q) = msg.queries.first() {
                (
                    q.name().to_string(),
                    record_type_code(q.query_type()),
                    u16::from(q.query_class()),
                )
            } else {
                (String::new(), 0, 0)
            };
            let qh = QnameHash(hash_qname(&qname));
            let init_src = initiator_is_src(dns.src_port, dns.dst_port, qr, ports);
            let meta = extract_edns_meta(&msg);
            let mut edns = EdnsSummary {
                present: msg.edns.is_some(),
                version: meta.version,
                udp_payload_size: meta.udp_payload_size,
                dnssec_ok: meta.dnssec_ok,
                option_code_count: meta.options.len().min(8) as u8,
                ..EdnsSummary::default()
            };
            for (i, opt) in meta.options.iter().take(8).enumerate() {
                edns.option_codes[i] = opt.code;
            }
            let mut ede_pairs: Vec<(u16, &str)> = Vec::new();
            for opt in &meta.options {
                if let Some(ede) = &opt.ede {
                    let text = ede.extra_text.as_deref().unwrap_or("");
                    ede_pairs.push((ede.code, text));
                }
            }
            let ede_blob = encode_edes(&ede_pairs);
            ParsedObservation {
                record: ObservationRecord {
                    slice_sec,
                    iface: iface.to_string(),
                    vlan: dns.vlan,
                    family: dns.family,
                    transport,
                    src_ip: dns.src_ip,
                    src_len: dns.src_ip_len,
                    dst_ip: dns.dst_ip,
                    dst_len: dns.dst_ip_len,
                    src_port: dns.src_port,
                    dst_port: dns.dst_port,
                    wire_len,
                    malformed: false,
                    id,
                    qr,
                    opcode,
                    rcode,
                    flags,
                    qdcount,
                    ancount,
                    nscount,
                    arcount,
                    qname,
                    qname_hash: qh,
                    qtype,
                    qclass,
                    edns,
                    ede_off: 0,
                    ede_len: ede_blob.len().min(u16::MAX as usize) as u16,
                    latency_ms: 0,
                    fragment_count: 1,
                    segment_count: 1,
                    ip_fragmented: false,
                    unanswered: false,
                    tc_retry: false,
                    paired: false,
                    initiator_is_src: init_src,
                },
                ede_blob,
            }
        }
        Err(_) => {
            let init_src = initiator_is_src(dns.src_port, dns.dst_port, false, ports);
            ParsedObservation {
                record: ObservationRecord {
                    slice_sec,
                    iface: iface.to_string(),
                    vlan: dns.vlan,
                    family: dns.family,
                    transport,
                    src_ip: dns.src_ip,
                    src_len: dns.src_ip_len,
                    dst_ip: dns.dst_ip,
                    dst_len: dns.dst_ip_len,
                    src_port: dns.src_port,
                    dst_port: dns.dst_port,
                    wire_len,
                    malformed: true,
                    id: 0,
                    qr: false,
                    opcode: 0,
                    rcode: 0,
                    flags: DnsFlags::default(),
                    qdcount: 0,
                    ancount: 0,
                    nscount: 0,
                    arcount: 0,
                    qname: String::new(),
                    qname_hash: QnameHash(0),
                    qtype: 0,
                    qclass: 0,
                    edns: EdnsSummary::default(),
                    ede_off: 0,
                    ede_len: 0,
                    latency_ms: 0,
                    fragment_count: 1,
                    segment_count: 1,
                    ip_fragmented: false,
                    unanswered: false,
                    tc_retry: false,
                    paired: false,
                    initiator_is_src: init_src,
                },
                ede_blob: Vec::new(),
            }
        }
    }
}

fn record_type_code(t: RecordType) -> u16 {
    t.into()
}

fn hash_qname(name: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = ahash::AHasher::default();
    name.to_ascii_lowercase().hash(&mut h);
    h.finish()
}

pub fn qname_level_label(name: &str, level: u8) -> String {
    if level == 0 || name.is_empty() {
        return name.to_string();
    }
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    if labels.is_empty() {
        return name.to_string();
    }
    let take = level.min(labels.len() as u8) as usize;
    labels[labels.len() - take..].join(".")
}

pub fn qname_tld(name: &str) -> Option<String> {
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').collect();
    labels.last().map(|s| s.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::options::AddressFamily;

    fn dns_with_payload(payload: Vec<u8>) -> DecodedDns {
        DecodedDns {
            family: AddressFamily::V4,
            src_ip: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            src_ip_len: 4,
            dst_ip: [10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            dst_ip_len: 4,
            src_port: 1000,
            dst_port: 53,
            vlan: Some(42),
            payload,
        }
    }

    #[test]
    fn malformed_payload_marked() {
        let dns = dns_with_payload(vec![0xff, 0xfe]);
        let parsed = parse_dns_payload(&dns, 100, "t");
        assert!(parsed.record.malformed);
        assert_eq!(parsed.record.vlan, Some(42));
    }

    #[test]
    fn qname_levels() {
        assert_eq!(qname_level_label("a.b.example.com.", 2), "example.com");
    }

    #[test]
    fn header_flags_and_counts_from_fixture_query() {
        use dns_core::name::DomainName;
        use dns_core::query::{QueryOptions, build_query};
        let opts = QueryOptions::new(DomainName::parse("test.example.").unwrap(), RecordType::A);
        let wire = build_query(&opts).expect("wire");
        let parsed = parse_dns_payload(&dns_with_payload(wire), 1, "eth0");
        let r = &parsed.record;
        assert!(!r.qr);
        assert!(r.edns.present);
        assert!(!r.flags.rd);
        assert_eq!(r.qdcount, 1);
        assert!(r.edns.udp_payload_size > 0);
    }

    #[test]
    fn ede_blob_round_trip_in_record() {
        let blob = encode_edes(&[(22, "No Reachable Authority"), (23, "net")]);
        let entries = crate::parse::ede_entries(&blob);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, 22);
    }
}
