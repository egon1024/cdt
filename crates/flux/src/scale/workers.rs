use crate::parse::{ObservationRecord, ParseWorker};
use crate::scale::memory::MemoryCounters;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum QueuePolicy {
    #[default]
    Block,
    Drop,
}

impl QueuePolicy {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "block" => Ok(Self::Block),
            "drop" => Ok(Self::Drop),
            _ => Err(format!("unknown queue policy: {s}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerResizeEvent {
    Add,
    Remove,
}

pub struct ParseWorkerPool {
    pub workers: Vec<ParseWorker>,
    pub queue_policy: QueuePolicy,
    pub queue_drops: u64,
    pub max_queue: usize,
}

impl ParseWorkerPool {
    pub fn new(count: usize, queue_policy: QueuePolicy) -> Self {
        let count = count.max(1);
        Self {
            workers: (0..count).map(|_| ParseWorker::default()).collect(),
            queue_policy,
            queue_drops: 0,
            max_queue: 4096,
        }
    }

    pub fn len(&self) -> usize {
        self.workers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.workers.is_empty()
    }

    pub fn resize(&mut self, new_len: usize) -> WorkerResizeEvent {
        let new_len = new_len.max(1);
        if new_len > self.workers.len() {
            while self.workers.len() < new_len {
                self.workers.push(ParseWorker::default());
            }
            WorkerResizeEvent::Add
        } else if new_len < self.workers.len() {
            self.workers.truncate(new_len);
            WorkerResizeEvent::Remove
        } else {
            WorkerResizeEvent::Add
        }
    }

    pub fn push_record(&mut self, rec: ObservationRecord, hash: u64) -> bool {
        let idx = (hash as usize) % self.workers.len();
        let worker = &mut self.workers[idx];
        if self.queue_policy == QueuePolicy::Drop
            && worker.stats.queue_depth as usize >= self.max_queue
        {
            self.queue_drops += 1;
            return false;
        }
        worker.stats.queue_depth = worker.stats.queue_depth.saturating_add(1);
        worker.push_record(rec);
        worker.stats.queue_depth = worker.stats.queue_depth.saturating_sub(1);
        true
    }

    pub fn drain_all(&self) -> impl Iterator<Item = &ObservationRecord> {
        self.workers.iter().flat_map(|w| w.records.iter())
    }

    pub fn account_memory(&self, mem: &mut MemoryCounters) {
        for w in &self.workers {
            mem.arena_bytes = mem.arena_bytes.saturating_add(w.arena.capacity());
            mem.record_bytes = mem
                .record_bytes
                .saturating_add(w.records.capacity() * std::mem::size_of::<ObservationRecord>());
        }
    }

    pub fn total_malformed(&self) -> u64 {
        self.workers.iter().map(|w| w.stats.malformed).sum()
    }

    pub fn avg_busy_percent(&self) -> u8 {
        if self.workers.is_empty() {
            return 0;
        }
        let sum: u64 = self
            .workers
            .iter()
            .map(|w| {
                let total = w.stats.busy_ns.saturating_add(w.stats.idle_ns).max(1);
                (w.stats.busy_ns.saturating_mul(100)) / total
            })
            .sum();
        (sum / self.workers.len() as u64).min(100) as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::options::AddressFamily;
    use crate::parse::{DnsFlags, EdnsSummary, QnameHash, TransportProto};

    fn stub_record() -> ObservationRecord {
        ObservationRecord {
            slice_sec: 1,
            iface: "t".into(),
            vlan: None,
            family: AddressFamily::V4,
            transport: TransportProto::Udp,
            src_ip: [0; 16],
            src_len: 4,
            dst_ip: [0; 16],
            dst_len: 4,
            src_port: 1,
            dst_port: 53,
            wire_len: 10,
            malformed: false,
            id: 1,
            qr: false,
            opcode: 0,
            rcode: 0,
            flags: DnsFlags::default(),
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
            qname: "x.".into(),
            qname_hash: QnameHash(1),
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
            initiator_is_src: true,
        }
    }

    #[test]
    fn resize_adds_workers() {
        let mut pool = ParseWorkerPool::new(1, QueuePolicy::Block);
        pool.resize(3);
        assert_eq!(pool.len(), 3);
    }

    #[test]
    fn drop_policy_counts() {
        let mut pool = ParseWorkerPool::new(1, QueuePolicy::Drop);
        pool.max_queue = 0;
        assert!(!pool.push_record(stub_record(), 0));
        assert_eq!(pool.queue_drops, 1);
    }
}
