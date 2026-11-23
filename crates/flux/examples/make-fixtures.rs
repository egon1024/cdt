//! Generate deterministic DNS pcaps for flux tests and labs.
use std::env;
use std::path::PathBuf;

use dns_core::name::DomainName;
use dns_core::query::{QueryOptions, build_query};
use etherparse::PacketBuilder;
use flux::capture::write_pcap_file;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::RecordType;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir: PathBuf = env::args()
        .nth(1)
        .expect("usage: make-fixtures <dir>")
        .into();
    std::fs::create_dir_all(&dir)?;

    let clients: &[[u8; 4]] = &[[192, 0, 2, 10], [192, 0, 2, 11], [192, 0, 2, 12]];
    let server = [192, 0, 2, 53];
    let qnames = [
        "client-a.example.com.",
        "client-b.example.org.",
        "svc.test.",
    ];

    let mut frames = Vec::new();
    for (i, client) in clients.iter().enumerate() {
        let qname = qnames[i % qnames.len()];
        let opts = QueryOptions::new(DomainName::parse(qname)?, RecordType::A);
        let wire = fix_query_id(build_query(&opts)?, 0x1000 + i as u16);
        frames.push(ether_udp_dns_frame(
            client,
            &server,
            40_000 + i as u16,
            wire.clone(),
        ));

        let mut resp = Message::from_vec(&wire)?;
        resp.metadata.message_type = MessageType::Response;
        resp.metadata.response_code = ResponseCode::NoError;
        let resp_bytes = resp.to_vec()?;
        frames.push(ether_udp_dns_frame(&server, client, 53, resp_bytes));
    }

    frames.push(ether_udp_dns_frame(
        &clients[0],
        &server,
        41_000,
        vec![0xde, 0xad],
    ));

    let v6_client = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0a,
    ];
    let v6_server = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x35,
    ];
    let opts = QueryOptions::new(DomainName::parse("v6.example.net.")?, RecordType::AAAA);
    let wire = fix_query_id(build_query(&opts)?, 0x2000);
    frames.push(ether_udp_dns_v6_frame(&v6_client, &v6_server, 42_000, wire));

    write_pcap_file(&dir.join("udp-basic.pcap"), &frames)?;
    Ok(())
}

fn fix_query_id(wire: Vec<u8>, id: u16) -> Vec<u8> {
    let mut msg = Message::from_vec(&wire).expect("query");
    msg.metadata.id = id;
    msg.to_vec().expect("encode")
}

fn ether_udp_dns_frame(src: &[u8; 4], dst: &[u8; 4], sport: u16, dns: Vec<u8>) -> Vec<u8> {
    let payload = dns;
    let mut buf = Vec::with_capacity(14 + 20 + 8 + payload.len());
    PacketBuilder::ethernet2([0; 6], [0; 6])
        .ipv4(*src, *dst, 64)
        .udp(sport, 53)
        .write(&mut buf, &payload)
        .expect("frame");
    buf
}

fn ether_udp_dns_v6_frame(src: &[u8; 16], dst: &[u8; 16], sport: u16, dns: Vec<u8>) -> Vec<u8> {
    let payload = dns;
    let mut buf = Vec::with_capacity(14 + 40 + 8 + payload.len());
    PacketBuilder::ethernet2([0; 6], [0; 6])
        .ipv6(*src, *dst, 64)
        .udp(sport, 53)
        .write(&mut buf, &payload)
        .expect("frame");
    buf
}
