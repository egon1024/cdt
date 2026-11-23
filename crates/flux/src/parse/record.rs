use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;

use crate::capture::DecodedDns;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QnameHash(pub u64);

#[derive(Debug, Clone)]
pub struct ObservationRecord {
    pub slice_sec: u64,
    pub iface: String,
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
    pub qname: String,
    pub qname_hash: QnameHash,
    pub qtype: u16,
    pub qclass: u16,
}

pub fn parse_dns_payload(dns: &DecodedDns, slice_sec: u64, iface: &str) -> ObservationRecord {
    let wire_len = dns.payload.len().min(u16::MAX as usize) as u16;
    match Message::from_vec(&dns.payload) {
        Ok(msg) => {
            let qr = msg.metadata.message_type == hickory_proto::op::MessageType::Response;
            let opcode = u8::from(msg.metadata.op_code);
            let rcode = u16::from(msg.metadata.response_code) as u8;
            let id = msg.metadata.id;
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
            ObservationRecord {
                slice_sec,
                iface: iface.to_string(),
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
                qname,
                qname_hash: qh,
                qtype,
                qclass,
            }
        }
        Err(_) => ObservationRecord {
            slice_sec,
            iface: iface.to_string(),
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
            qname: String::new(),
            qname_hash: QnameHash(0),
            qtype: 0,
            qclass: 0,
        },
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::options::AddressFamily;

    #[test]
    fn malformed_payload_marked() {
        let dns = crate::capture::DecodedDns {
            family: AddressFamily::V4,
            src_ip: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            src_ip_len: 4,
            dst_ip: [10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            dst_ip_len: 4,
            src_port: 1000,
            dst_port: 53,
            vlan: None,
            payload: vec![0xff, 0xfe],
        };
        let rec = parse_dns_payload(&dns, 100, "t");
        assert!(rec.malformed);
    }

    #[test]
    fn qname_levels() {
        assert_eq!(qname_level_label("a.b.example.com.", 2), "example.com");
    }
}
