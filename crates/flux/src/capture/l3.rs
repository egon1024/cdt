use etherparse::{NetSlice, SlicedPacket, TransportSlice};

use crate::flow::FragmentKey;
use crate::options::AddressFamily;

use super::RawPacket;

#[derive(Debug, Clone)]
pub struct DnsL3Payload {
    pub family: AddressFamily,
    pub src_ip: [u8; 16],
    pub src_ip_len: u8,
    pub dst_ip: [u8; 16],
    pub dst_ip_len: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub vlan: Option<u16>,
    pub protocol: u8,
    pub transport: L3Transport,
    pub payload: Vec<u8>,
    pub fragment_key: Option<FragmentKey>,
    pub fragment_offset: u16,
    pub more_fragments: bool,
    pub is_fragment: bool,
    pub fragment_count: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L3Transport {
    Udp,
    Tcp,
    Fragment,
}

#[derive(Debug, thiserror::Error)]
pub enum L3Error {
    #[error("not dns")]
    NotDns,
    #[error("family filtered")]
    FamilyFiltered,
    #[error("parse")]
    Parse,
}

pub fn parse_l3(pkt: &RawPacket, family: AddressFamily) -> Result<DnsL3Payload, L3Error> {
    let sliced = SlicedPacket::from_ethernet(pkt.data.as_slice())
        .or_else(|_| SlicedPacket::from_ip(pkt.data.as_slice()))
        .map_err(|_| L3Error::Parse)?;
    parse_sliced(&sliced, family)
}

fn parse_sliced(sliced: &SlicedPacket<'_>, family: AddressFamily) -> Result<DnsL3Payload, L3Error> {
    let vlan = sliced.vlan.as_ref().map(|v| match v {
        etherparse::VlanSlice::SingleVlan(s) => u16::from(s.vlan_identifier()),
        etherparse::VlanSlice::DoubleVlan(d) => u16::from(d.outer().vlan_identifier()),
    });
    match sliced.net.as_ref() {
        Some(NetSlice::Ipv4(h)) => parse_ipv4(h, sliced.transport.as_ref(), vlan, family),
        Some(NetSlice::Ipv6(h)) => parse_ipv6(h, sliced.transport.as_ref(), vlan, family),
        _ => Err(L3Error::NotDns),
    }
}

fn parse_ipv4(
    h: &etherparse::Ipv4Slice<'_>,
    transport: Option<&TransportSlice<'_>>,
    vlan: Option<u16>,
    family: AddressFamily,
) -> Result<DnsL3Payload, L3Error> {
    let hdr = h.header();
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src[..4].copy_from_slice(&hdr.source_addr().octets());
    dst[..4].copy_from_slice(&hdr.destination_addr().octets());
    if family == AddressFamily::V6 {
        return Err(L3Error::FamilyFiltered);
    }
    let offset = hdr.fragments_offset().value() * 8;
    let mf = hdr.more_fragments();
    let is_fragment = mf || offset > 0;
    let id = u32::from(hdr.identification());
    if is_fragment {
        let key = FragmentKey {
            src,
            src_len: 4,
            dst,
            dst_len: 4,
            protocol: hdr.protocol().0,
            ip_id: id,
        };
        let payload = h.payload().payload.to_vec();
        return Ok(DnsL3Payload {
            family: AddressFamily::V4,
            src_ip: src,
            src_ip_len: 4,
            dst_ip: dst,
            dst_ip_len: 4,
            src_port: 0,
            dst_port: 0,
            vlan,
            protocol: hdr.protocol().0,
            transport: L3Transport::Fragment,
            payload,
            fragment_key: Some(key),
            fragment_offset: offset,
            more_fragments: mf,
            is_fragment: true,
            fragment_count: 1,
        });
    }
    match transport {
        Some(TransportSlice::Udp(u)) => dns_udp(
            AddressFamily::V4,
            src,
            4,
            dst,
            4,
            u.source_port(),
            u.destination_port(),
            vlan,
            u.payload().to_vec(),
            false,
            1,
        ),
        Some(TransportSlice::Tcp(t)) => dns_tcp(
            AddressFamily::V4,
            src,
            4,
            dst,
            4,
            t.source_port(),
            t.destination_port(),
            vlan,
            t.payload().to_vec(),
        ),
        _ => Err(L3Error::NotDns),
    }
}

fn parse_ipv6(
    h: &etherparse::Ipv6Slice<'_>,
    transport: Option<&TransportSlice<'_>>,
    vlan: Option<u16>,
    family: AddressFamily,
) -> Result<DnsL3Payload, L3Error> {
    let hdr = h.header();
    let src = hdr.source_addr().octets();
    let dst = hdr.destination_addr().octets();
    if family == AddressFamily::V4 {
        return Err(L3Error::FamilyFiltered);
    }
    match transport {
        Some(TransportSlice::Udp(u)) => dns_udp(
            AddressFamily::V6,
            src,
            16,
            dst,
            16,
            u.source_port(),
            u.destination_port(),
            vlan,
            u.payload().to_vec(),
            false,
            1,
        ),
        Some(TransportSlice::Tcp(t)) => dns_tcp(
            AddressFamily::V6,
            src,
            16,
            dst,
            16,
            t.source_port(),
            t.destination_port(),
            vlan,
            t.payload().to_vec(),
        ),
        _ => Err(L3Error::NotDns),
    }
}

#[allow(clippy::too_many_arguments)]
fn dns_udp(
    af: AddressFamily,
    src_ip: [u8; 16],
    src_len: u8,
    dst_ip: [u8; 16],
    dst_len: u8,
    src_port: u16,
    dst_port: u16,
    vlan: Option<u16>,
    payload: Vec<u8>,
    is_fragment: bool,
    fragment_count: u8,
) -> Result<DnsL3Payload, L3Error> {
    if src_port != 53 && dst_port != 53 {
        return Err(L3Error::NotDns);
    }
    Ok(DnsL3Payload {
        family: af,
        src_ip,
        src_ip_len: src_len,
        dst_ip,
        dst_ip_len: dst_len,
        src_port,
        dst_port,
        vlan,
        protocol: 17,
        transport: L3Transport::Udp,
        payload,
        fragment_key: None,
        fragment_offset: 0,
        more_fragments: false,
        is_fragment,
        fragment_count,
    })
}

#[allow(clippy::too_many_arguments)]
fn dns_tcp(
    af: AddressFamily,
    src_ip: [u8; 16],
    src_len: u8,
    dst_ip: [u8; 16],
    dst_len: u8,
    src_port: u16,
    dst_port: u16,
    vlan: Option<u16>,
    payload: Vec<u8>,
) -> Result<DnsL3Payload, L3Error> {
    if src_port != 53 && dst_port != 53 {
        return Err(L3Error::NotDns);
    }
    Ok(DnsL3Payload {
        family: af,
        src_ip,
        src_ip_len: src_len,
        dst_ip,
        dst_ip_len: dst_len,
        src_port,
        dst_port,
        vlan,
        protocol: 6,
        transport: L3Transport::Tcp,
        payload,
        fragment_key: None,
        fragment_offset: 0,
        more_fragments: false,
        is_fragment: false,
        fragment_count: 1,
    })
}
