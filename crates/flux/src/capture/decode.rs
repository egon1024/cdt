use etherparse::{NetSlice, SlicedPacket, TransportSlice};

use crate::options::AddressFamily;

use super::RawPacket;

#[derive(Debug, Clone)]
pub struct DecodedDns {
    pub family: AddressFamily,
    pub src_ip: [u8; 16],
    pub src_ip_len: u8,
    pub dst_ip: [u8; 16],
    pub dst_ip_len: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub vlan: Option<u16>,
    pub payload: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("not dns udp")]
    NotDns,

    #[error("parse error: {0}")]
    Parse(String),

    #[error("family filtered")]
    FamilyFiltered,
}

pub fn decode_frame(packet: &RawPacket, family: AddressFamily) -> Result<DecodedDns, FrameError> {
    if let Ok(sliced) = SlicedPacket::from_ethernet(packet.data.as_slice()) {
        return decode_sliced(&sliced, family);
    }
    if let Ok(sliced) = SlicedPacket::from_ip(packet.data.as_slice()) {
        return decode_sliced(&sliced, family);
    }
    Err(FrameError::Parse(
        "unable to parse link or network header".into(),
    ))
}

fn decode_sliced(
    sliced: &SlicedPacket<'_>,
    family: AddressFamily,
) -> Result<DecodedDns, FrameError> {
    let vlan = sliced.vlan.as_ref().map(|v| match v {
        etherparse::VlanSlice::SingleVlan(s) => u16::from(s.vlan_identifier()),
        etherparse::VlanSlice::DoubleVlan(d) => u16::from(d.outer().vlan_identifier()),
    });

    let udp = match sliced.transport.as_ref() {
        Some(TransportSlice::Udp(u)) => u,
        _ => return Err(FrameError::NotDns),
    };

    let (src_ip, dst_ip, src_len, dst_len, ip_af) = match sliced.net.as_ref() {
        Some(NetSlice::Ipv4(h)) => {
            let hdr = h.header();
            let mut src = [0u8; 16];
            let mut dst = [0u8; 16];
            src[..4].copy_from_slice(&hdr.source_addr().octets());
            dst[..4].copy_from_slice(&hdr.destination_addr().octets());
            (src, dst, 4u8, 4u8, AddressFamily::V4)
        }
        Some(NetSlice::Ipv6(h)) => {
            let hdr = h.header();
            (
                hdr.source_addr().octets(),
                hdr.destination_addr().octets(),
                16u8,
                16u8,
                AddressFamily::V6,
            )
        }
        _ => return Err(FrameError::NotDns),
    };

    if !family_matches(family, ip_af) {
        return Err(FrameError::FamilyFiltered);
    }

    let (src_port, dst_port) = (udp.source_port(), udp.destination_port());
    if src_port != 53 && dst_port != 53 {
        return Err(FrameError::NotDns);
    }

    Ok(DecodedDns {
        family: ip_af,
        src_ip,
        src_ip_len: src_len,
        dst_ip,
        dst_ip_len: dst_len,
        src_port,
        dst_port,
        vlan,
        payload: udp.payload().to_vec(),
    })
}

fn family_matches(filter: AddressFamily, actual: AddressFamily) -> bool {
    match filter {
        AddressFamily::Auto | AddressFamily::Both => true,
        AddressFamily::V4 => actual == AddressFamily::V4,
        AddressFamily::V6 => actual == AddressFamily::V6,
    }
}

#[cfg(test)]
mod tests {
    use etherparse::PacketBuilder;

    use super::*;

    fn udp_ipv4_packet() -> RawPacket {
        let dns = vec![
            0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 3, b'a', b'b',
            b'c', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ];
        let mut frame = Vec::new();
        PacketBuilder::ethernet2([0; 6], [0; 6])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .udp(49_152, 53)
            .write(&mut frame, &dns)
            .unwrap();
        RawPacket {
            data: frame,
            timestamp_secs: 1_700_000_000,
            timestamp_subsec_ns: 0,
            iface: "test".into(),
        }
    }

    #[test]
    fn decodes_ipv4_udp_dns() {
        let pkt = udp_ipv4_packet();
        let d = decode_frame(&pkt, AddressFamily::Auto).unwrap();
        assert_eq!(d.dst_port, 53);
        assert!(!d.payload.is_empty());
    }

    #[test]
    fn family_filter_v6_on_v4() {
        let pkt = udp_ipv4_packet();
        assert!(matches!(
            decode_frame(&pkt, AddressFamily::V6),
            Err(FrameError::FamilyFiltered)
        ));
    }
}
