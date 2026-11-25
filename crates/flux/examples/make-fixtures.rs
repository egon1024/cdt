//! Generate deterministic DNS pcaps for flux tests and labs.
use std::env;
use std::path::PathBuf;

use dns_core::name::DomainName;
use dns_core::query::{QueryOptions, build_query};
use etherparse::PacketBuilder;
use etherparse::VlanId;
use flux::capture::{write_pcap_file, write_pcapng_dup};
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::RecordType;
use hickory_proto::rr::rdata::opt::EdnsOption;

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

    let mut mdns_frames = Vec::new();
    let mdns_opts = QueryOptions::new(DomainName::parse("mdns.local.")?, RecordType::PTR);
    let mdns_wire = fix_query_id(build_query(&mdns_opts)?, 0x1500);
    mdns_frames.push(ether_udp_dns_frame_port(
        &clients[0],
        &server,
        5353,
        5353,
        mdns_wire,
    ));
    write_pcap_file(&dir.join("port5353.pcap"), &mdns_frames)?;

    let mut ede_frames = Vec::new();
    let opts = QueryOptions::new(DomainName::parse("ede.test.")?, RecordType::A);
    let qwire = fix_query_id(build_query(&opts)?, 0x3000);
    ede_frames.push(ether_udp_dns_frame(
        &clients[0],
        &server,
        43_000,
        qwire.clone(),
    ));
    let mut resp = Message::from_vec(&qwire)?;
    resp.metadata.message_type = MessageType::Response;
    resp.metadata.response_code = ResponseCode::NoError;
    attach_edes(
        &mut resp,
        &[
            (22, "No Reachable Authority"),
            (23, "Network Error"),
            (22, "duplicate ignored"),
        ],
    );
    ede_frames.push(ether_udp_dns_frame(
        &server,
        &clients[0],
        53,
        resp.to_vec()?,
    ));

    write_pcap_file(&dir.join("edns-ede.pcap"), &ede_frames)?;

    let mut large_frames = Vec::new();
    for i in 0..12_000 {
        let qname = format!("host{i}.bulk.example.");
        let opts = QueryOptions::new(DomainName::parse(&qname)?, RecordType::A);
        let wire = fix_query_id(build_query(&opts)?, 0x4000 + (i % 60000) as u16);
        large_frames.push(ether_udp_dns_frame(
            &clients[i % clients.len()],
            &server,
            50_000 + (i % 1000) as u16,
            wire,
        ));
    }
    write_pcap_file(&dir.join("large.pcap"), &large_frames)?;

    // Phase 3 flow-tracking fixtures
    let frag_opts = QueryOptions::new(DomainName::parse("big.frag.example.")?, RecordType::A);
    let frag_q = fix_query_id(build_query(&frag_opts)?, 0x5100);
    let mut frag_resp = Message::from_vec(&frag_q)?;
    frag_resp.metadata.message_type = MessageType::Response;
    use hickory_proto::rr::rdata::A;
    use hickory_proto::rr::{Name, RData, Record};
    use std::net::Ipv4Addr;
    for i in 1..=40u8 {
        frag_resp.answers.push(Record::from_rdata(
            Name::from_ascii("big.frag.example.").expect("name"),
            30,
            RData::A(A(Ipv4Addr::new(192, 0, 2, i))),
        ));
    }
    let frag_wire = frag_resp.to_vec()?;
    let frag_frames =
        ipv4_udp_fragmented_frames(&server, &clients[0], 53, 0xbeef, &frag_wire, &[24, 24]);
    write_pcap_file(&dir.join("fragmented.pcap"), &frag_frames)?;

    let tcp_opts = QueryOptions::new(DomainName::parse("tcp.split.example.")?, RecordType::A);
    let tcp_wire = fix_query_id(build_query(&tcp_opts)?, 0x5200);
    let mut tcp_resp = Message::from_vec(&tcp_wire)?;
    tcp_resp.metadata.message_type = MessageType::Response;
    let framed = dns_over_tcp_bytes(&tcp_resp.to_vec()?);
    let (part_a, part_b) = framed.split_at(12);
    write_pcap_file(
        &dir.join("tcp-split.pcap"),
        &[
            ether_tcp_segment(&clients[1], &server, 45_100, part_a),
            ether_tcp_segment(&clients[1], &server, 45_100, part_b),
        ],
    )?;

    let mid_opts = QueryOptions::new(DomainName::parse("tcp.mid.example.")?, RecordType::A);
    let mid_wire = fix_query_id(build_query(&mid_opts)?, 0x5300);
    let mut mid_resp = Message::from_vec(&mid_wire)?;
    mid_resp.metadata.message_type = MessageType::Response;
    let mid_framed = dns_over_tcp_bytes(&mid_resp.to_vec()?);
    write_pcap_file(
        &dir.join("tcp-midstream.pcap"),
        &[
            ether_tcp_segment(
                &clients[2],
                &server,
                45_200,
                &[0xaa, 0xbb, 0xcc, 0xdd, 0xee],
            ),
            ether_tcp_segment(&clients[2], &server, 45_200, &mid_framed),
        ],
    )?;

    let un_opts = QueryOptions::new(DomainName::parse("lonely.query.example.")?, RecordType::A);
    let mut unanswered_frames = Vec::new();
    for i in 0..20u16 {
        let wire = fix_query_id(build_query(&un_opts)?, 0x5400 + i);
        unanswered_frames.push(ether_udp_dns_frame(&clients[0], &server, 46_000 + i, wire));
    }
    write_pcap_file(&dir.join("unanswered.pcap"), &unanswered_frames)?;

    let tc_opts = QueryOptions::new(DomainName::parse("tc.retry.example.")?, RecordType::A);
    let tc_q = fix_query_id(build_query(&tc_opts)?, 0x5500);
    let mut tc_udp_resp = Message::from_vec(&tc_q)?;
    tc_udp_resp.metadata.message_type = MessageType::Response;
    tc_udp_resp.metadata.truncation = true;
    write_pcap_file(
        &dir.join("tc-retry.pcap"),
        &[
            ether_udp_dns_frame(&clients[0], &server, 47_000, tc_q.clone()),
            ether_udp_dns_frame(&server, &clients[0], 53, tc_udp_resp.to_vec()?),
            ether_tcp_segment(&clients[0], &server, 47_001, &dns_over_tcp_bytes(&tc_q)),
        ],
    )?;

    let dup_opts = QueryOptions::new(DomainName::parse("dup.example.com.")?, RecordType::A);
    let dup_wire = fix_query_id(build_query(&dup_opts)?, 0x6000);
    let frame_br = ether_udp_dns_frame_ttl(&clients[0], &server, 48_000, dup_wire.clone(), 64);
    let frame_v0 = ether_udp_dns_frame_ttl(&clients[0], &server, 48_000, dup_wire, 32);
    write_pcapng_dup(
        &dir.join("dup-two-iface.pcapng"),
        &["br0", "v0"],
        &[&[frame_br], &[frame_v0]],
    )?;

    let vlan_opts = QueryOptions::new(DomainName::parse("vlan100.example.com.")?, RecordType::A);
    let vlan_wire = fix_query_id(build_query(&vlan_opts)?, 0x6100);
    let vlan200_opts = QueryOptions::new(DomainName::parse("vlan200.example.com.")?, RecordType::A);
    let vlan200_wire = fix_query_id(build_query(&vlan200_opts)?, 0x6200);
    write_pcap_file(
        &dir.join("vlan.pcap"),
        &[
            ether_udp_dns_vlan_frame(&clients[0], &server, 49_000, vlan_wire, 100),
            ether_udp_dns_vlan_frame(&clients[0], &server, 49_001, vlan200_wire, 200),
        ],
    )?;

    Ok(())
}

fn attach_edes(resp: &mut Message, pairs: &[(u16, &str)]) {
    let mut edns = resp.edns.take().unwrap_or_default();
    edns.set_max_payload(1232);
    for (code, text) in pairs {
        let mut raw = vec![(code >> 8) as u8, (code & 0xff) as u8];
        raw.extend_from_slice(text.as_bytes());
        edns.options_mut().insert(EdnsOption::Unknown(17, raw));
    }
    resp.set_edns(edns);
}

fn fix_query_id(wire: Vec<u8>, id: u16) -> Vec<u8> {
    let mut msg = Message::from_vec(&wire).expect("query");
    msg.metadata.id = id;
    msg.to_vec().expect("encode")
}

fn ether_udp_dns_frame_port(
    src: &[u8; 4],
    dst: &[u8; 4],
    sport: u16,
    dport: u16,
    dns: Vec<u8>,
) -> Vec<u8> {
    let payload = dns;
    let mut buf = Vec::with_capacity(14 + 20 + 8 + payload.len());
    PacketBuilder::ethernet2([0; 6], [0; 6])
        .ipv4(*src, *dst, 64)
        .udp(sport, dport)
        .write(&mut buf, &payload)
        .expect("frame");
    buf
}

fn ether_udp_dns_frame(src: &[u8; 4], dst: &[u8; 4], sport: u16, dns: Vec<u8>) -> Vec<u8> {
    ether_udp_dns_frame_ttl(src, dst, sport, dns, 64)
}

fn ether_udp_dns_frame_ttl(
    src: &[u8; 4],
    dst: &[u8; 4],
    sport: u16,
    dns: Vec<u8>,
    ttl: u8,
) -> Vec<u8> {
    let payload = dns;
    let mut buf = Vec::with_capacity(14 + 20 + 8 + payload.len());
    PacketBuilder::ethernet2([0; 6], [0; 6])
        .ipv4(*src, *dst, ttl)
        .udp(sport, 53)
        .write(&mut buf, &payload)
        .expect("frame");
    buf
}

fn ether_udp_dns_vlan_frame(
    src: &[u8; 4],
    dst: &[u8; 4],
    sport: u16,
    dns: Vec<u8>,
    vlan_id: u16,
) -> Vec<u8> {
    let payload = dns;
    let mut buf = Vec::with_capacity(14 + 4 + 20 + 8 + payload.len());
    PacketBuilder::ethernet2([0; 6], [0; 6])
        .single_vlan(VlanId::try_new(vlan_id).expect("vlan"))
        .ipv4(*src, *dst, 64)
        .udp(sport, 53)
        .write(&mut buf, &payload)
        .expect("vlan frame");
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

fn dns_over_tcp_bytes(dns: &[u8]) -> Vec<u8> {
    let len = dns.len() as u16;
    let mut out = len.to_be_bytes().to_vec();
    out.extend_from_slice(dns);
    out
}

fn ether_tcp_segment(src: &[u8; 4], dst: &[u8; 4], sport: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(14 + 20 + 20 + payload.len());
    PacketBuilder::ethernet2([0; 6], [0; 6])
        .ipv4(*src, *dst, 64)
        .tcp(sport, 53, 1, 1)
        .write(&mut buf, payload)
        .expect("tcp frame");
    buf
}

fn ipv4_udp_fragmented_frames(
    src: &[u8; 4],
    dst: &[u8; 4],
    sport: u16,
    ip_id: u16,
    dns: &[u8],
    chunk_sizes: &[usize],
) -> Vec<Vec<u8>> {
    let mut udp = Vec::with_capacity(8 + dns.len());
    udp.extend_from_slice(&sport.to_be_bytes());
    udp.extend_from_slice(&53u16.to_be_bytes());
    udp.extend_from_slice(&(dns.len() as u16).to_be_bytes());
    udp.extend_from_slice(dns);
    let mut offset = 0usize;
    let mut frames = Vec::new();
    for (i, &size) in chunk_sizes.iter().enumerate() {
        let end = if i + 1 == chunk_sizes.len() {
            udp.len()
        } else {
            (offset + size).min(udp.len())
        };
        let chunk = &udp[offset..end];
        let mf = end < udp.len();
        frames.push(ethernet_ipv4_fragment(
            src,
            dst,
            ip_id,
            offset as u16,
            mf,
            chunk,
        ));
        offset = end;
    }
    frames
}

fn ethernet_ipv4_fragment(
    src: &[u8; 4],
    dst: &[u8; 4],
    ip_id: u16,
    offset_bytes: u16,
    more_fragments: bool,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + 20 + payload.len());
    frame.extend_from_slice(&[0u8; 6]);
    frame.extend_from_slice(&[0u8; 6]);
    frame.extend_from_slice(&[0x08, 0x00]);
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    let total_len = (20 + payload.len()) as u16;
    ip[2..4].copy_from_slice(&total_len.to_be_bytes());
    ip[4..6].copy_from_slice(&ip_id.to_be_bytes());
    let frag_off = offset_bytes / 8;
    let flags = if more_fragments { 0x2000u16 } else { 0u16 };
    ip[6..8].copy_from_slice(&(flags | frag_off).to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(src);
    ip[16..20].copy_from_slice(dst);
    let csum = ipv4_header_checksum(&ip);
    ip[10..12].copy_from_slice(&csum.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(payload);
    frame
}

fn ipv4_header_checksum(hdr: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in hdr.chunks(2) {
        if chunk.len() == 2 {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        } else {
            sum += u32::from(chunk[0]) << 8;
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}
