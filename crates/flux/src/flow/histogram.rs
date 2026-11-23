/// Log-linear latency histogram with exact add/subtract for window totals.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LatencyHistogram {
    buckets: [u64; LATENCY_BUCKETS],
    max_ms: u32,
    total_count: u64,
}

pub const LATENCY_BUCKETS: usize = 24;

/// Upper bounds in milliseconds for each bucket (exclusive except last).
const BUCKET_EDGES_MS: [u32; LATENCY_BUCKETS] = [
    1,
    2,
    3,
    5,
    8,
    13,
    21,
    34,
    55,
    89,
    144,
    233,
    377,
    610,
    987,
    1597,
    2584,
    4181,
    6765,
    10_000,
    20_000,
    50_000,
    100_000,
    u32::MAX,
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LatencyKeyStats {
    pub response_count: u64,
    pub unanswered: u64,
    pub hist: LatencyHistogram,
}

impl LatencyHistogram {
    pub fn record(&mut self, latency_ms: u32) {
        let idx = bucket_for_ms(latency_ms);
        self.buckets[idx] += 1;
        self.total_count += 1;
        if latency_ms > self.max_ms {
            self.max_ms = latency_ms;
        }
    }

    pub fn merge_add(&mut self, other: &LatencyHistogram) {
        for (a, b) in self.buckets.iter_mut().zip(other.buckets.iter()) {
            *a = a.saturating_add(*b);
        }
        self.total_count = self.total_count.saturating_add(other.total_count);
        self.max_ms = self.max_ms.max(other.max_ms);
    }

    pub fn merge_sub(&mut self, other: &LatencyHistogram) {
        for (a, b) in self.buckets.iter_mut().zip(other.buckets.iter()) {
            *a = a.saturating_sub(*b);
        }
        self.total_count = self.total_count.saturating_sub(other.total_count);
        if other.max_ms >= self.max_ms {
            self.recompute_max();
        }
    }

    fn recompute_max(&mut self) {
        self.max_ms = 0;
        for (idx, &count) in self.buckets.iter().enumerate().rev() {
            if count > 0 {
                self.max_ms = if idx == 0 {
                    0
                } else {
                    BUCKET_EDGES_MS[idx - 1]
                };
                break;
            }
        }
    }

    pub fn max_ms(&self) -> u32 {
        self.max_ms
    }

    pub fn count(&self) -> u64 {
        self.total_count
    }

    pub fn percentile(&self, p: f64) -> u32 {
        if self.total_count == 0 {
            return 0;
        }
        let target = ((self.total_count as f64) * p / 100.0).ceil() as u64;
        let mut seen = 0u64;
        for (idx, &count) in self.buckets.iter().enumerate() {
            seen += count;
            if seen >= target {
                return if idx == 0 {
                    0
                } else {
                    BUCKET_EDGES_MS[idx - 1]
                };
            }
        }
        self.max_ms
    }
}

impl LatencyKeyStats {
    pub fn merge_add(&mut self, other: &LatencyKeyStats) {
        self.response_count = self.response_count.saturating_add(other.response_count);
        self.unanswered = self.unanswered.saturating_add(other.unanswered);
        self.hist.merge_add(&other.hist);
    }

    pub fn merge_sub(&mut self, other: &LatencyKeyStats) {
        self.response_count = self.response_count.saturating_sub(other.response_count);
        self.unanswered = self.unanswered.saturating_sub(other.unanswered);
        self.hist.merge_sub(&other.hist);
    }
}

fn bucket_for_ms(ms: u32) -> usize {
    for (idx, edge) in BUCKET_EDGES_MS.iter().enumerate() {
        if ms < *edge {
            return idx;
        }
    }
    LATENCY_BUCKETS - 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_add_subtract_symmetric() {
        let mut a = LatencyHistogram::default();
        a.record(10);
        a.record(100);
        a.record(500);
        let b = a.clone();
        let mut c = LatencyHistogram::default();
        c.merge_add(&a);
        c.merge_sub(&b);
        assert_eq!(c.total_count, 0);
        assert_eq!(c.max_ms, 0);
    }

    #[test]
    fn percentile_bounds() {
        let mut h = LatencyHistogram::default();
        for _ in 0..90 {
            h.record(5);
        }
        for _ in 0..10 {
            h.record(200);
        }
        let p50 = h.percentile(50.0);
        let p95 = h.percentile(95.0);
        assert!(p50 <= 21);
        assert!(p95 >= 89);
    }
}
