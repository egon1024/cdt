use crate::capture::{DecodedDns, RawPacket};
use crate::capture::{DnsL3Payload, L3Error, L3Transport, parse_l3};
use crate::options::AddressFamily;
use crate::parse::{TransportProto, parse_dns_payload_with_transport};

use super::config::{FlowConfig, TcpMode};
use super::counters::FlowCounters;
use super::defrag::DefragState;
use super::keys::FlowKey;
use super::pairing::PairingState;
use super::tcp::TcpState;

#[derive(Debug, Clone)]
pub struct DnsMessageReady {
    pub decoded: DecodedDns,
    pub transport: TransportProto,
    pub fragment_count: u8,
    pub segment_count: u8,
    pub ip_fragmented: bool,
    pub timestamp_secs: u64,
    pub timestamp_subsec_ns: u32,
    pub iface: String,
}

pub struct FlowStage {
    config: FlowConfig,
    pub counters: FlowCounters,
    defrag: DefragState,
    tcp: TcpState,
    pub pairing: PairingState,
    pending_tcp_segments: std::collections::HashMap<FlowKey, u8>,
}

impl FlowStage {
    pub fn new(config: FlowConfig) -> Self {
        Self {
            defrag: DefragState::new(
                config.defrag,
                config.defrag_max_datagrams,
                config.defrag_max_fragments,
                config.defrag_timeout,
            ),
            tcp: TcpState::new(
                config.tcp,
                config.tcp_max_connections,
                config.tcp_max_buffer,
                config.tcp_idle_timeout,
                config.tcp_max_faults,
            ),
            pairing: PairingState::new(&config),
            config,
            counters: FlowCounters::default(),
            pending_tcp_segments: std::collections::HashMap::new(),
        }
    }

    pub fn process_packet(
        &mut self,
        pkt: &RawPacket,
        family: AddressFamily,
    ) -> Vec<DnsMessageReady> {
        let l3 = match parse_l3(pkt, family) {
            Ok(v) => v,
            Err(L3Error::NotDns) | Err(L3Error::Parse) => return Vec::new(),
            Err(L3Error::FamilyFiltered) => return Vec::new(),
        };
        match l3.transport {
            L3Transport::Fragment => self.process_fragment(l3, pkt),
            L3Transport::Udp => self.ready_udp(l3, pkt, 1),
            L3Transport::Tcp => self.process_tcp(l3, pkt),
        }
    }

    fn process_fragment(&mut self, l3: DnsL3Payload, pkt: &RawPacket) -> Vec<DnsMessageReady> {
        let Some(key) = l3.fragment_key else {
            return Vec::new();
        };
        let Some(dgram) = self.defrag.ingest_ipv4_fragment(
            key,
            l3.fragment_offset,
            l3.more_fragments,
            l3.payload,
            pkt.timestamp_secs,
            &mut self.counters,
        ) else {
            return Vec::new();
        };
        if dgram.payload.len() < 8 {
            return Vec::new();
        }
        let src_port = u16::from_be_bytes([dgram.payload[0], dgram.payload[1]]);
        let dst_port = u16::from_be_bytes([dgram.payload[2], dgram.payload[3]]);
        if src_port != 53 && dst_port != 53 {
            return Vec::new();
        }
        let udp_payload = dgram.payload[8..].to_vec();
        let udp_l3 = DnsL3Payload {
            family: AddressFamily::V4,
            src_ip: dgram.src_ip,
            src_ip_len: dgram.src_ip_len,
            dst_ip: dgram.dst_ip,
            dst_ip_len: dgram.dst_ip_len,
            src_port,
            dst_port,
            vlan: l3.vlan,
            protocol: 17,
            transport: L3Transport::Udp,
            payload: udp_payload,
            fragment_key: None,
            fragment_offset: 0,
            more_fragments: false,
            is_fragment: true,
            fragment_count: dgram.fragment_count,
        };
        self.ready_udp(udp_l3, pkt, dgram.fragment_count)
    }

    fn ready_udp(
        &mut self,
        l3: DnsL3Payload,
        pkt: &RawPacket,
        fragment_count: u8,
    ) -> Vec<DnsMessageReady> {
        vec![to_ready(&l3, pkt, TransportProto::Udp, fragment_count, 1)]
    }

    fn process_tcp(&mut self, l3: DnsL3Payload, pkt: &RawPacket) -> Vec<DnsMessageReady> {
        if self.config.tcp == TcpMode::Off {
            return Vec::new();
        }
        let key = FlowKey::from_endpoints(
            6,
            &l3.src_ip[..l3.src_ip_len as usize],
            l3.src_port,
            &l3.dst_ip[..l3.dst_ip_len as usize],
            l3.dst_port,
        );
        let had_data = !l3.payload.is_empty();
        let msgs =
            self.tcp
                .ingest_segment(key, &l3.payload, pkt.timestamp_secs, &mut self.counters);
        let mut out = Vec::new();
        for msg in msgs {
            let mut l3_msg = l3.clone();
            l3_msg.payload = msg.payload;
            let mut segment_count = msg.segment_count;
            if had_data {
                let entry = self.pending_tcp_segments.entry(key).or_insert(0);
                *entry = entry.saturating_add(1);
                if *entry > 1 {
                    segment_count = *entry;
                }
            }
            out.push(to_ready(
                &l3_msg,
                pkt,
                TransportProto::Tcp,
                1,
                segment_count,
            ));
            self.pending_tcp_segments.remove(&key);
        }
        out
    }

    pub fn drain_pairing_timeouts(&mut self, now_sec: u64) -> Vec<crate::parse::ParsedObservation> {
        let obs = self.pairing.poll_timeouts(now_sec);
        self.counters.pairing_evicted = self.pairing.counters().pairing_evicted;
        obs
    }

    pub fn sync_pairing_counters(&mut self) {
        self.counters.pairing_evicted = self.pairing.counters().pairing_evicted;
    }
}

fn to_ready(
    l3: &DnsL3Payload,
    pkt: &RawPacket,
    transport: TransportProto,
    fragment_count: u8,
    segment_count: u8,
) -> DnsMessageReady {
    DnsMessageReady {
        decoded: DecodedDns {
            family: l3.family,
            src_ip: l3.src_ip,
            src_ip_len: l3.src_ip_len,
            dst_ip: l3.dst_ip,
            dst_ip_len: l3.dst_ip_len,
            src_port: l3.src_port,
            dst_port: l3.dst_port,
            vlan: l3.vlan,
            payload: l3.payload.clone(),
        },
        transport,
        fragment_count,
        segment_count,
        ip_fragmented: l3.is_fragment || fragment_count > 1,
        timestamp_secs: pkt.timestamp_secs,
        timestamp_subsec_ns: pkt.timestamp_subsec_ns,
        iface: pkt.iface.clone(),
    }
}

pub fn parse_flow_message(ready: &DnsMessageReady) -> crate::parse::ParsedObservation {
    let mut parsed = parse_dns_payload_with_transport(
        &ready.decoded,
        ready.timestamp_secs,
        &ready.iface,
        ready.transport,
    );
    parsed.record.transport = ready.transport;
    parsed.record.fragment_count = ready.fragment_count;
    parsed.record.segment_count = ready.segment_count;
    parsed.record.ip_fragmented = ready.ip_fragmented;
    parsed
}
