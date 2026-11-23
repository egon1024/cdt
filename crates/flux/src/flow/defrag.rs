use std::collections::HashMap;
use std::time::Duration;

use super::config::DefragMode;
use super::counters::FlowCounters;
use super::keys::FragmentKey;

#[derive(Debug, Clone)]
pub struct ReassembledDatagram {
    pub payload: Vec<u8>,
    pub src_ip: [u8; 16],
    pub src_ip_len: u8,
    pub dst_ip: [u8; 16],
    pub dst_ip_len: u8,
    pub fragment_count: u8,
}

#[derive(Debug)]
struct PartialDatagram {
    fragments: Vec<(u16, bool, Vec<u8>)>,
    first_seen_sec: u64,
}

pub struct DefragState {
    mode: DefragMode,
    max_datagrams: usize,
    max_fragments: usize,
    timeout: Duration,
    partials: HashMap<FragmentKey, PartialDatagram>,
}

impl DefragState {
    pub fn new(
        mode: DefragMode,
        max_datagrams: usize,
        max_fragments: usize,
        timeout: Duration,
    ) -> Self {
        Self {
            mode,
            max_datagrams,
            max_fragments,
            timeout,
            partials: HashMap::new(),
        }
    }

    pub fn ingest_ipv4_fragment(
        &mut self,
        key: FragmentKey,
        offset_bytes: u16,
        more_fragments: bool,
        payload: Vec<u8>,
        now_sec: u64,
        counters: &mut FlowCounters,
    ) -> Option<ReassembledDatagram> {
        if self.mode == DefragMode::Off {
            counters.fragmented_unparsed += 1;
            return None;
        }
        self.evict_stale(now_sec, counters);
        if !self.partials.contains_key(&key) && self.partials.len() >= self.max_datagrams {
            self.evict_oldest(counters);
        }
        let entry = self.partials.entry(key).or_insert_with(|| PartialDatagram {
            fragments: Vec::new(),
            first_seen_sec: now_sec,
        });
        if entry.fragments.len() >= self.max_fragments {
            counters.defrag_abandoned += 1;
            self.partials.remove(&key);
            return None;
        }
        entry
            .fragments
            .push((offset_bytes, more_fragments, payload));
        try_reassemble(key, &entry.fragments).map(|(payload, count)| ReassembledDatagram {
            payload,
            src_ip: key.src,
            src_ip_len: key.src_len,
            dst_ip: key.dst,
            dst_ip_len: key.dst_len,
            fragment_count: count,
        })
    }

    fn evict_stale(&mut self, now_sec: u64, counters: &mut FlowCounters) {
        let timeout_secs = self.timeout.as_secs();
        let stale: Vec<FragmentKey> = self
            .partials
            .iter()
            .filter(|(_, p)| now_sec.saturating_sub(p.first_seen_sec) > timeout_secs)
            .map(|(k, _)| *k)
            .collect();
        for k in stale {
            self.partials.remove(&k);
            counters.defrag_abandoned += 1;
        }
    }

    fn evict_oldest(&mut self, counters: &mut FlowCounters) {
        if let Some(oldest_key) = self
            .partials
            .iter()
            .min_by_key(|(_, p)| p.first_seen_sec)
            .map(|(k, _)| *k)
        {
            self.partials.remove(&oldest_key);
            counters.defrag_abandoned += 1;
        }
    }
}

fn try_reassemble(_key: FragmentKey, frags: &[(u16, bool, Vec<u8>)]) -> Option<(Vec<u8>, u8)> {
    let mut sorted = frags.to_vec();
    sorted.sort_by_key(|(off, _, _)| *off);
    let mut expected = 0u16;
    let mut out = Vec::new();
    for (off, _mf, data) in &sorted {
        if *off != expected {
            return None;
        }
        expected = expected.saturating_add(data.len() as u16);
        out.extend_from_slice(data);
    }
    let last_mf = sorted.last().map(|(_, mf, _)| *mf).unwrap_or(true);
    if last_mf {
        return None;
    }
    let count = sorted.len().min(u8::MAX as usize) as u8;
    Some((out, count))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> FragmentKey {
        FragmentKey {
            src: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            src_len: 4,
            dst: [10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            dst_len: 4,
            protocol: 17,
            ip_id: 0x1234,
        }
    }

    #[test]
    fn three_fragments_reassemble() {
        let mut d = DefragState::new(DefragMode::On, 16, 8, Duration::from_secs(30));
        let mut c = FlowCounters::default();
        let k = key();
        assert!(
            d.ingest_ipv4_fragment(k, 0, true, b"hel".to_vec(), 1, &mut c)
                .is_none()
        );
        assert!(
            d.ingest_ipv4_fragment(k, 3, true, b"lo-".to_vec(), 1, &mut c)
                .is_none()
        );
        let done = d
            .ingest_ipv4_fragment(k, 6, false, b"world".to_vec(), 1, &mut c)
            .unwrap();
        assert_eq!(done.payload, b"hello-world");
        assert_eq!(done.fragment_count, 3);
    }

    #[test]
    fn defrag_off_counts_only() {
        let mut d = DefragState::new(DefragMode::Off, 16, 8, Duration::from_secs(30));
        let mut c = FlowCounters::default();
        d.ingest_ipv4_fragment(key(), 0, true, vec![1], 1, &mut c);
        assert_eq!(c.fragmented_unparsed, 1);
    }
}
