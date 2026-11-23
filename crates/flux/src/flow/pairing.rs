use std::collections::HashMap;
use std::time::Duration;

use crate::parse::{ObservationRecord, ParsedObservation, QnameHash};

use super::config::FlowConfig;
use super::counters::FlowCounters;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct PairKey {
    client: [u8; 16],
    client_len: u8,
    server: [u8; 16],
    server_len: u8,
    id: u16,
    question: QnameHash,
}

#[derive(Debug, Clone)]
struct OutstandingQuery {
    record: ObservationRecord,
    query_time_ns: u128,
    inserted_sec: u64,
}

pub struct PairingState {
    enabled: bool,
    timeout: Duration,
    max_outstanding: usize,
    outstanding: HashMap<PairKey, OutstandingQuery>,
    trunc_hints: HashMap<(QnameHash, [u8; 16]), u64>,
    counters: FlowCounters,
}

impl PairingState {
    pub fn new(config: &FlowConfig) -> Self {
        Self {
            enabled: config.pairing,
            timeout: config.pair_timeout,
            max_outstanding: config.pair_max,
            outstanding: HashMap::new(),
            trunc_hints: HashMap::new(),
            counters: FlowCounters::default(),
        }
    }

    pub fn counters(&self) -> &FlowCounters {
        &self.counters
    }

    pub fn counters_mut(&mut self) -> &mut FlowCounters {
        &mut self.counters
    }

    pub fn on_message(&mut self, rec: &mut ObservationRecord, timestamp_ns: u128, now_sec: u64) {
        if !self.enabled {
            rec.paired = false;
            rec.latency_ms = 0;
            return;
        }
        if rec.tc_retry {
            return;
        }
        if !rec.qr {
            if rec.transport == crate::parse::TransportProto::Tcp
                && self.tc_retry_pending(rec, now_sec)
            {
                rec.tc_retry = true;
            }
            self.register_query(rec, timestamp_ns, now_sec);
        } else {
            self.pair_response(rec, timestamp_ns, now_sec);
        }
    }

    fn register_query(&mut self, rec: &ObservationRecord, ts_ns: u128, now_sec: u64) {
        let key = pair_key_from_query(rec);
        if self.outstanding.len() >= self.max_outstanding {
            self.evict_oldest();
        }
        self.outstanding.insert(
            key,
            OutstandingQuery {
                record: rec.clone(),
                query_time_ns: ts_ns,
                inserted_sec: now_sec,
            },
        );
    }

    fn pair_response(&mut self, rec: &mut ObservationRecord, ts_ns: u128, now_sec: u64) {
        let key = pair_key_from_response(rec);
        if let Some(q) = self.outstanding.remove(&key) {
            let delta_ms = ts_ns.saturating_sub(q.query_time_ns) / 1_000_000;
            rec.latency_ms = delta_ms.min(u32::MAX as u128) as u32;
            rec.paired = true;
        } else {
            rec.paired = false;
        }
        if rec.flags.tc && rec.transport == crate::parse::TransportProto::Udp {
            let client = initiator_bytes(rec);
            self.trunc_hints.insert(
                (rec.qname_hash, client),
                now_sec.saturating_add(self.timeout.as_secs()),
            );
        }
    }

    fn tc_retry_pending(&self, rec: &ObservationRecord, now_sec: u64) -> bool {
        let client = initiator_bytes(rec);
        self.trunc_hints
            .get(&(rec.qname_hash, client))
            .is_some_and(|expires| *expires >= now_sec)
    }

    fn evict_oldest(&mut self) {
        if let Some(oldest) = self
            .outstanding
            .iter()
            .min_by_key(|(_, q)| q.inserted_sec)
            .map(|(k, _)| *k)
        {
            self.outstanding.remove(&oldest);
            self.counters.pairing_evicted += 1;
        }
    }

    pub fn poll_timeouts(&mut self, now_sec: u64) -> Vec<ParsedObservation> {
        if !self.enabled {
            return Vec::new();
        }
        let timeout = self.timeout.as_secs();
        let expired: Vec<PairKey> = self
            .outstanding
            .iter()
            .filter(|(_, q)| now_sec.saturating_sub(q.inserted_sec) >= timeout)
            .map(|(k, _)| *k)
            .collect();
        let mut synthetics = Vec::new();
        for k in expired {
            let Some(q) = self.outstanding.remove(&k) else {
                continue;
            };
            let mut rec = q.record.clone();
            rec.slice_sec = now_sec;
            rec.unanswered = true;
            rec.qr = false;
            rec.paired = false;
            rec.latency_ms = 0;
            synthetics.push(ParsedObservation {
                record: rec,
                ede_blob: Vec::new(),
            });
        }
        self.trunc_hints.retain(|_, expires| *expires >= now_sec);
        synthetics
    }
}

fn pair_key_from_query(rec: &ObservationRecord) -> PairKey {
    PairKey {
        client: rec.src_ip,
        client_len: rec.src_len,
        server: rec.dst_ip,
        server_len: rec.dst_len,
        id: rec.id,
        question: rec.qname_hash,
    }
}

fn pair_key_from_response(rec: &ObservationRecord) -> PairKey {
    PairKey {
        client: rec.dst_ip,
        client_len: rec.dst_len,
        server: rec.src_ip,
        server_len: rec.src_len,
        id: rec.id,
        question: rec.qname_hash,
    }
}

fn initiator_bytes(rec: &ObservationRecord) -> [u8; 16] {
    if rec.qr { rec.dst_ip } else { rec.src_ip }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::options::AddressFamily;
    use crate::parse::{DnsFlags, EdnsSummary, TransportProto};

    fn query(id: u16, sec: u64) -> ObservationRecord {
        ObservationRecord {
            slice_sec: sec,
            iface: "t".into(),
            vlan: None,
            family: AddressFamily::V4,
            transport: TransportProto::Udp,
            src_ip: [192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            src_len: 4,
            dst_ip: [192, 0, 2, 53, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            dst_len: 4,
            src_port: 40_000,
            dst_port: 53,
            wire_len: 64,
            malformed: false,
            id,
            qr: false,
            opcode: 0,
            rcode: 0,
            flags: DnsFlags::default(),
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
            qname: "test.example.".into(),
            qname_hash: QnameHash(123),
            qtype: 1,
            qclass: 1,
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
        }
    }

    #[test]
    fn latency_on_paired_response() {
        let cfg = FlowConfig {
            pairing: true,
            pair_timeout: Duration::from_secs(5),
            pair_max: 100,
            ..FlowConfig::default()
        };
        let mut p = PairingState::new(&cfg);
        let mut q = query(0x10, 10);
        p.on_message(&mut q, 1_000_000_000, 10);
        let mut r = query(0x10, 10);
        r.qr = true;
        r.src_ip = q.dst_ip;
        r.dst_ip = q.src_ip;
        p.on_message(&mut r, 1_050_000_000, 10);
        assert!(r.paired);
        assert_eq!(r.latency_ms, 50);
    }

    #[test]
    fn synthetic_unanswered_in_timeout_slice() {
        let cfg = FlowConfig {
            pairing: true,
            pair_timeout: Duration::from_secs(2),
            pair_max: 100,
            ..FlowConfig::default()
        };
        let mut p = PairingState::new(&cfg);
        let mut q = query(0x20, 5);
        p.on_message(&mut q, 0, 5);
        let synth = p.poll_timeouts(7);
        assert_eq!(synth.len(), 1);
        assert!(synth[0].record.unanswered);
        assert_eq!(synth[0].record.slice_sec, 7);
    }
}
