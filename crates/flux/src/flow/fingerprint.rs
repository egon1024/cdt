use std::hash::{Hash, Hasher};

use ahash::AHasher;

use crate::capture::{DnsL3Payload, RawPacket};

/// Forwarding-invariant fingerprint: L3 endpoints, protocol, ports, IPv4 ID, payload.
pub fn packet_fingerprint(_pkt: &RawPacket, l3: &DnsL3Payload) -> u64 {
    let mut hasher = AHasher::default();
    l3.src_ip[..l3.src_ip_len as usize].hash(&mut hasher);
    l3.dst_ip[..l3.dst_ip_len as usize].hash(&mut hasher);
    l3.src_port.hash(&mut hasher);
    l3.dst_port.hash(&mut hasher);
    l3.protocol.hash(&mut hasher);
    l3.payload.hash(&mut hasher);
    if let Some(key) = &l3.fragment_key {
        key.ip_id.hash(&mut hasher);
    }
    hasher.finish()
}
