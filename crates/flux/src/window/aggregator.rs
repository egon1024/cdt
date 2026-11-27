use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::filter::{CompiledFilter, EvalContext, MatchStats};
use crate::options::{LatePolicy, WindowMode};
use crate::parse::{ObservationRecord, ParsedObservation};
use crate::view::{ViewCounts, build_counts_from_slices_with_qname};

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
    pub match_stats: MatchStats,
    pub effective_window_secs: Option<u64>,
    /// Inclusive span of slice seconds represented in `counts` (`max - min + 1`).
    pub counted_span_secs: Option<u64>,
}

pub struct Aggregator {
    pub slices: HashMap<SliceId, TimeSlice>,
    pub window: WindowMode,
    pub late_grace: Duration,
    pub late_policy: LatePolicy,
    pub now_sec: u64,
    pub window_totals: ViewCounts,
    pub total_in_window: u64,
    pub match_stats: MatchStats,
    pub counters: PipelineCounters,
    pub last_pass: Instant,
    pub filter: CompiledFilter,
    pub eval_ctx: EvalContext,
    pub filter_generation: u64,
    pub smart_qname_labels: bool,
}

impl Aggregator {
    pub fn new(
        window: WindowMode,
        late_grace: Duration,
        late_policy: LatePolicy,
        filter: CompiledFilter,
        eval_ctx: EvalContext,
    ) -> Self {
        Self {
            slices: HashMap::new(),
            window,
            late_grace,
            late_policy,
            now_sec: 0,
            window_totals: ViewCounts::default(),
            total_in_window: 0,
            match_stats: MatchStats::default(),
            counters: PipelineCounters::default(),
            last_pass: Instant::now(),
            filter,
            eval_ctx,
            filter_generation: 1,
            smart_qname_labels: false,
        }
    }

    pub fn set_smart_qname_labels(&mut self, on: bool) {
        if self.smart_qname_labels != on {
            self.smart_qname_labels = on;
            self.recompute_window();
        }
    }

    pub fn set_filter(&mut self, filter: CompiledFilter, eval_ctx: EvalContext) {
        self.filter = filter;
        self.eval_ctx = eval_ctx;
        self.filter_generation += 1;
        self.recompute_window();
    }

    pub fn recompute_window(&mut self) {
        let (counts, stats) = build_counts_from_slices_with_qname(
            self.slices.values(),
            &self.filter,
            &self.eval_ctx,
            self.smart_qname_labels,
        );
        self.window_totals = counts;
        self.match_stats = stats;
        self.total_in_window = stats.matched;
    }

    pub fn ingest(&mut self, parsed: ParsedObservation) {
        self.counters.packets += 1;
        let mut rec = parsed.record;
        let sec = rec.slice_sec;
        self.now_sec = self.now_sec.max(sec);
        let id = SliceId(sec);
        let slice = self
            .slices
            .entry(id)
            .or_insert_with(|| TimeSlice::open(sec));
        if !parsed.ede_blob.is_empty() {
            let (off, len) = slice.append_ede_blob(&parsed.ede_blob);
            rec.ede_off = off;
            rec.ede_len = len;
        }
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
                let partial = build_counts_from_slice_filtered(
                    slice,
                    &self.filter,
                    &self.eval_ctx,
                    self.smart_qname_labels,
                );
                self.window_totals.merge_add(&partial.0);
                self.match_stats.matched += partial.1.matched;
                self.match_stats.total_observed += partial.1.total_observed;
                self.total_in_window += partial.1.matched;
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
                let partial = build_counts_from_slice_filtered(
                    &slice,
                    &self.filter,
                    &self.eval_ctx,
                    self.smart_qname_labels,
                );
                self.window_totals.merge_sub(&partial.0);
                self.match_stats.matched =
                    self.match_stats.matched.saturating_sub(partial.1.matched);
                self.match_stats.total_observed = self
                    .match_stats
                    .total_observed
                    .saturating_sub(partial.1.total_observed);
                self.total_in_window = self.total_in_window.saturating_sub(partial.1.matched);
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
            match_stats: self.match_stats,
            effective_window_secs: match self.window {
                WindowMode::All => None,
                WindowMode::Seconds(s) => Some(s),
            },
            counted_span_secs: Self::slice_span(&self.slices),
        }
    }

    pub fn counted_slice_span(&self) -> Option<u64> {
        Self::slice_span(&self.slices)
    }

    fn slice_span(slices: &HashMap<SliceId, TimeSlice>) -> Option<u64> {
        let mut min = None::<u64>;
        let mut max = None::<u64>;
        for id in slices.keys() {
            let sec = id.0;
            min = Some(min.map_or(sec, |m| m.min(sec)));
            max = Some(max.map_or(sec, |m| m.max(sec)));
        }
        match (min, max) {
            (Some(lo), Some(hi)) => Some(hi.saturating_sub(lo).saturating_add(1)),
            _ => None,
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

fn build_counts_from_slice_filtered(
    slice: &TimeSlice,
    filter: &CompiledFilter,
    ctx: &EvalContext,
    smart_qname: bool,
) -> (ViewCounts, MatchStats) {
    crate::view::build_counts_filtered_with_qname(
        &slice.records,
        &slice.arena,
        filter,
        ctx,
        smart_qname,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::QrSelection;
    use crate::filter::{Predicate, build_compiled};
    use crate::options::AddressFamily;
    use crate::parse::{DnsFlags, EdnsSummary, QnameHash, TransportProto};

    fn sample_rec(sec: u64) -> ParsedObservation {
        ParsedObservation {
            record: ObservationRecord {
                slice_sec: sec,
                iface: "eth0".into(),
                vlan: None,
                family: AddressFamily::V4,
                transport: TransportProto::Udp,
                src_ip: [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                src_len: 4,
                dst_ip: [5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                dst_len: 4,
                src_port: 1234,
                dst_port: 53,
                wire_len: 64,
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
                qname: "example.com.".into(),
                qname_hash: QnameHash(9),
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
            },
            ede_blob: Vec::new(),
        }
    }

    #[test]
    fn window_expiry_subtracts() {
        let filter = build_compiled(Predicate::True, "", QrSelection::Both);
        let mut agg = Aggregator::new(
            WindowMode::Seconds(1),
            Duration::from_millis(1),
            LatePolicy::Correct,
            filter,
            EvalContext::default(),
        );
        agg.ingest(sample_rec(10));
        agg.tick(11);
        assert_eq!(agg.total_in_window, 1);
        agg.catch_up_stall(20);
        assert_eq!(agg.total_in_window, 0);
    }

    #[test]
    fn filter_swap_recomputes() {
        let filter = build_compiled(Predicate::True, "", QrSelection::Both);
        let mut agg = Aggregator::new(
            WindowMode::All,
            Duration::from_millis(1),
            LatePolicy::Correct,
            filter,
            EvalContext::default(),
        );
        let mut bad = sample_rec(1);
        bad.record.malformed = true;
        agg.ingest(sample_rec(1));
        agg.ingest(bad);
        agg.tick(2);
        assert_eq!(agg.total_in_window, 2);
        let only_ok = build_compiled(
            Predicate::Field(crate::filter::FieldCond {
                field: crate::filter::FieldId::Malformed,
                negate: true,
                op: crate::filter::CompareOp::Eq,
                values: Vec::new(),
                regex: None,
            }),
            "no-malformed",
            QrSelection::Both,
        );
        agg.set_filter(only_ok, EvalContext::default());
        assert_eq!(agg.total_in_window, 1);
    }
}
