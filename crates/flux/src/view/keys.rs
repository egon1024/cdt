use crate::options::ViewId;
use crate::parse::ObservationRecord;

pub trait ViewKey: Send + Sync {
    fn key_for(&self, record: &ObservationRecord, arena: &[u8]) -> Option<String>;
}

pub struct SourcesKey;

impl ViewKey for SourcesKey {
    fn key_for(&self, record: &ObservationRecord, _arena: &[u8]) -> Option<String> {
        Some(format_ip(&record.src_ip[..record.src_len as usize]))
    }
}

pub struct DestinationsKey;

impl ViewKey for DestinationsKey {
    fn key_for(&self, record: &ObservationRecord, _arena: &[u8]) -> Option<String> {
        Some(format_ip(&record.dst_ip[..record.dst_len as usize]))
    }
}

pub struct QtypeKey;

impl ViewKey for QtypeKey {
    fn key_for(&self, record: &ObservationRecord, _arena: &[u8]) -> Option<String> {
        Some(record_type_name(record.qtype))
    }
}

pub fn view_key_for(id: ViewId) -> Box<dyn ViewKey> {
    match id {
        ViewId::Sources => Box::new(SourcesKey),
        ViewId::Destinations => Box::new(DestinationsKey),
        ViewId::Qtype => Box::new(QtypeKey),
        _ => Box::new(SourcesKey),
    }
}

fn format_ip(ip: &[u8]) -> String {
    match ip.len() {
        4 => std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).to_string(),
        16 => {
            let chunks: Vec<_> = ip
                .chunks(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            if chunks.len() == 8 {
                std::net::Ipv6Addr::from(<[u16; 8]>::try_from(chunks.as_slice()).unwrap())
                    .to_string()
            } else {
                hex_encode(ip)
            }
        }
        _ => hex_encode(ip),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn record_type_name(code: u16) -> String {
    match code {
        1 => "A".into(),
        28 => "AAAA".into(),
        _ => format!("TYPE{code}"),
    }
}
