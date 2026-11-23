use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::options::{LatePolicy, WindowMode};
use crate::parse::ObservationRecord;
use crate::view::{ViewCounts, build_counts};

use super::slice::{SliceId, TimeSlice};

#[derive(Debug, Default, Clone)]
pub struct PipelineCounters {
    pub packets: u64,
    pub capture_drops: u64,
    pub late_records: u64,
    pub listener_packets: u64,
}

#[derive(Debug, Clone)]
pub struct WindowTotals {
    pub counts: ViewCounts,
    pub total_messages: u64,
    pub effective_window_secs: Option<u64>,
}

pub struct Aggregator {
    pub slices: HashMap<SliceId, TimeSlice>,
    pub window: WindowMode,
    pub late_grace: Duration,
    pub late_policy: LatePolicy,
    pub now_sec: u64,
    pub window_totals: ViewCounts,
    pub total_in_window: u64,
    pub counters: PipelineCounters,
    pub last_pass: Instant,
}

impl Aggregator {
    pub fn new(window: WindowMode, late_grace: Duration, late_policy: LatePolicy) -> Self {
        Self {
            slices: HashMap::new(),
            window,
            late_grace,
            late_policy,
            now_sec: 0,
            window_totals: ViewCounts::default(),
            total_in_window: 0,
            counters: PipelineCounters::default(),
            last_pass: Instant::now(),
        }
    }

    pub fn ingest(&mut self, rec: ObservationRecord) {
        self.counters.packets += 1;
        let sec = rec.slice_sec;
        self.now_sec = self.now_sec.max(sec);
        let id = SliceId(sec);
        let slice = self
            .slices
            .entry(id)
            .or_insert_with(|| TimeSlice::open(sec));
        if slice.sealed {
            self.counters.late_records += 1;
            match self.late_policy {
                LatePolicy::Drop => return,
                LatePolicy::Correct => {
                    slice.records.push(rec);
                    return;
                }
            }
        }
        slice.records.push(rec);
    }

    pub fn tick(&mut self, current_sec: u64) {
        self.now_sec = self.now_sec.max(current_sec);
        self.seal_elapsed_slices();
        self.expire_old_slices();
    }

    fn seal_elapsed_slices(&mut self) {
        let grace = self.late_grace;
        let now = self.now_sec;
        for slice in self.slices.values_mut() {
            if !slice.sealed && slice.second < now {
                slice.sealed = true;
                slice.grace_until = Some(Instant::now() + grace);
                let partial = build_counts(&slice.records);
                self.window_totals.merge_add(&partial);
                self.total_in_window += slice.records.len() as u64;
            }
        }
    }

    fn expire_old_slices(&mut self) {
        let window_secs = match self.window {
            WindowMode::All => return,
            WindowMode::Seconds(s) => s,
        };
        let min_sec = self.now_sec.saturating_sub(window_secs);
        let expired: Vec<SliceId> = self
            .slices
            .iter()
            .filter(|(_, s)| s.sealed && s.second < min_sec)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            if let Some(slice) = self.slices.remove(&id) {
                let partial = build_counts(&slice.records);
                self.window_totals.merge_sub(&partial);
                self.total_in_window = self
                    .total_in_window
                    .saturating_sub(slice.records.len() as u64);
            }
        }
    }

    pub fn catch_up_stall(&mut self, jump_to_sec: u64) {
        self.now_sec = jump_to_sec;
        self.seal_elapsed_slices();
        self.expire_old_slices();
    }

    pub fn snapshot(&self) -> WindowTotals {
        WindowTotals {
            counts: self.window_totals.clone(),
            total_messages: self.total_in_window,
            effective_window_secs: match self.window {
                WindowMode::All => None,
                WindowMode::Seconds(s) => Some(s),
            },
        }
    }

    pub fn all_records(&self) -> Vec<ObservationRecord> {
        let mut v: Vec<ObservationRecord> = self
            .slices
            .values()
            .flat_map(|s| s.records.iter().cloned())
            .collect();
        if v.is_empty() {
            return v;
        }
        v.sort_by_key(|r| (r.slice_sec, r.id));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ObservationRecord;

    fn sample_rec(sec: u64) -> ObservationRecord {
        ObservationRecord {
            slice_sec: sec,
            iface: "t".into(),
            src_ip: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            src_len: 4,
            dst_ip: [10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            dst_len: 4,
            src_port: 1000,
            dst_port: 53,
            wire_len: 40,
            malformed: false,
            id: 1,
            qr: false,
            opcode: 0,
            rcode: 0,
            qname: "a.example.com.".into(),
            qname_hash: crate::parse::QnameHash(1),
            qtype: 1,
            qclass: 1,
        }
    }

    #[test]
    fn expiry_subtracts_window_totals() {
        let mut agg = Aggregator::new(
            WindowMode::Seconds(5),
            Duration::from_millis(0),
            LatePolicy::Correct,
        );
        for sec in 0..10 {
            agg.ingest(sample_rec(sec));
        }
        agg.tick(10);
        assert!(agg.total_in_window <= 5);
    }

    #[test]
    fn late_drop_ignored() {
        let mut agg = Aggregator::new(WindowMode::All, Duration::from_millis(0), LatePolicy::Drop);
        agg.ingest(sample_rec(1));
        agg.tick(3);
        let mut late = sample_rec(1);
        late.id = 2;
        agg.ingest(late);
        assert_eq!(agg.counters.late_records, 1);
    }
}
