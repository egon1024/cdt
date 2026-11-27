use std::collections::HashMap;
use std::time::Duration;

use super::config::TcpMode;
use super::counters::FlowCounters;
use super::keys::FlowKey;

#[derive(Debug, Clone)]
pub struct TcpDnsMessage {
    pub payload: Vec<u8>,
    pub segment_count: u8,
}

#[derive(Debug)]
struct TcpConn {
    buffer: Vec<u8>,
    last_activity_sec: u64,
    fault_count: u32,
    midstream: bool,
}

pub struct TcpState {
    mode: TcpMode,
    max_connections: usize,
    max_buffer: usize,
    idle_timeout: Duration,
    max_faults: u32,
    conns: HashMap<FlowKey, TcpConn>,
}

impl TcpState {
    pub fn new(
        mode: TcpMode,
        max_connections: usize,
        max_buffer: usize,
        idle_timeout: Duration,
        max_faults: u32,
    ) -> Self {
        Self {
            mode,
            max_connections,
            max_buffer,
            idle_timeout,
            max_faults,
            conns: HashMap::new(),
        }
    }

    pub fn ingest_segment(
        &mut self,
        key: FlowKey,
        segment: &[u8],
        now_sec: u64,
        counters: &mut FlowCounters,
    ) -> Vec<TcpDnsMessage> {
        if self.mode == TcpMode::Off {
            return Vec::new();
        }
        self.evict_idle(now_sec, counters);
        if !self.conns.contains_key(&key) {
            if self.conns.len() >= self.max_connections {
                counters.tcp_conn_limit += 1;
                return Vec::new();
            }
            self.conns.insert(
                key,
                TcpConn {
                    buffer: Vec::new(),
                    last_activity_sec: now_sec,
                    fault_count: 0,
                    midstream: true,
                },
            );
        }
        let conn = self.conns.get_mut(&key).unwrap();
        conn.last_activity_sec = now_sec;
        if self.mode == TcpMode::Simple {
            return self.parse_simple(segment, counters);
        }
        if conn.buffer.len() + segment.len() > self.max_buffer {
            counters.tcp_buffer_limit += 1;
            conn.buffer.clear();
            conn.fault_count = 0;
            conn.midstream = true;
            return Vec::new();
        }
        conn.buffer.extend_from_slice(segment);
        Self::drain_messages(conn, self.max_faults, counters)
    }

    fn parse_simple(&self, segment: &[u8], counters: &mut FlowCounters) -> Vec<TcpDnsMessage> {
        let mut out = Vec::new();
        let mut rest = segment;
        while rest.len() >= 2 {
            let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            if len == 0 || len > 65535 {
                counters.tcp_resync_failed += 1;
                break;
            }
            if rest.len() < 2 + len {
                counters.tcp_unparsed += 1;
                break;
            }
            out.push(TcpDnsMessage {
                payload: rest[2..2 + len].to_vec(),
                segment_count: 1,
            });
            rest = &rest[2 + len..];
        }
        if !rest.is_empty() {
            counters.tcp_unparsed += 1;
        }
        out
    }

    fn drain_messages(
        conn: &mut TcpConn,
        max_faults: u32,
        counters: &mut FlowCounters,
    ) -> Vec<TcpDnsMessage> {
        let mut out = Vec::new();
        loop {
            if conn.midstream {
                if !resync(&mut conn.buffer) {
                    return out;
                }
                conn.midstream = false;
            }
            if conn.buffer.len() < 2 {
                break;
            }
            let len = u16::from_be_bytes([conn.buffer[0], conn.buffer[1]]) as usize;
            if len == 0 || len > 65535 || !dns_length_sane(len) {
                conn.fault_count += 1;
                if conn.fault_count >= max_faults {
                    conn.buffer.clear();
                    conn.fault_count = 0;
                    conn.midstream = true;
                    counters.tcp_resync_failed += 1;
                } else {
                    conn.buffer.remove(0);
                }
                continue;
            }
            if conn.buffer.len() < 2 + len {
                break;
            }
            let payload = conn.buffer[2..2 + len].to_vec();
            conn.buffer.drain(..2 + len);
            conn.fault_count = 0;
            out.push(TcpDnsMessage {
                payload,
                segment_count: 1,
            });
        }
        out
    }

    fn evict_idle(&mut self, now_sec: u64, counters: &mut FlowCounters) {
        let idle = self.idle_timeout.as_secs();
        let stale: Vec<FlowKey> = self
            .conns
            .iter()
            .filter(|(_, c)| now_sec.saturating_sub(c.last_activity_sec) > idle)
            .map(|(k, _)| *k)
            .collect();
        for k in stale {
            self.conns.remove(&k);
            counters.tcp_idle_evicted += 1;
        }
    }
}

fn resync(buf: &mut Vec<u8>) -> bool {
    while buf.len() >= 2 {
        let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if len > 0 && dns_length_sane(len) {
            if buf.len() >= 2 + len {
                return true;
            }
            return false;
        }
        buf.remove(0);
    }
    false
}

fn dns_length_sane(len: usize) -> bool {
    (12..=65535).contains(&len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::keys::FlowKey;

    fn conn_key() -> FlowKey {
        FlowKey::from_endpoints(6, &[10, 0, 0, 1], 50_000, &[10, 0, 0, 2], 53)
    }

    #[test]
    fn full_mode_split_across_segments() {
        let payload = vec![0u8; 40];
        let mut wire = (payload.len() as u16).to_be_bytes().to_vec();
        wire.extend(&payload);
        let (mid, rest) = wire.split_at(10);
        let mut t = TcpState::new(TcpMode::Full, 8, 4096, Duration::from_secs(60), 3);
        let mut c = FlowCounters::default();
        let k = conn_key();
        let mut msgs = t.ingest_segment(k, mid, 1, &mut c);
        msgs.extend(t.ingest_segment(k, rest, 1, &mut c));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].payload, payload);
    }

    #[test]
    fn simple_mode_rejects_split() {
        let payload = vec![0u8; 20];
        let mut wire = (payload.len() as u16).to_be_bytes().to_vec();
        wire.extend(&payload);
        let (a, b) = wire.split_at(8);
        let mut t = TcpState::new(TcpMode::Simple, 8, 4096, Duration::from_secs(60), 3);
        let mut c = FlowCounters::default();
        let k = conn_key();
        assert!(t.ingest_segment(k, a, 1, &mut c).is_empty());
        assert!(t.ingest_segment(k, b, 1, &mut c).is_empty());
        assert!(c.tcp_unparsed > 0);
    }
}
