#[derive(Debug, Default, Clone, Copy)]
pub struct FlowCounters {
    pub fragmented_unparsed: u64,
    pub defrag_abandoned: u64,
    pub tcp_unparsed: u64,
    pub tcp_conn_limit: u64,
    pub tcp_buffer_limit: u64,
    pub tcp_idle_evicted: u64,
    pub tcp_resync_failed: u64,
    pub pairing_evicted: u64,
    pub dedup_removals: u64,
}

impl FlowCounters {
    pub fn merge(&mut self, other: &FlowCounters) {
        self.fragmented_unparsed = self
            .fragmented_unparsed
            .saturating_add(other.fragmented_unparsed);
        self.defrag_abandoned = self.defrag_abandoned.saturating_add(other.defrag_abandoned);
        self.tcp_unparsed = self.tcp_unparsed.saturating_add(other.tcp_unparsed);
        self.tcp_conn_limit = self.tcp_conn_limit.saturating_add(other.tcp_conn_limit);
        self.tcp_buffer_limit = self.tcp_buffer_limit.saturating_add(other.tcp_buffer_limit);
        self.tcp_idle_evicted = self.tcp_idle_evicted.saturating_add(other.tcp_idle_evicted);
        self.tcp_resync_failed = self
            .tcp_resync_failed
            .saturating_add(other.tcp_resync_failed);
        self.pairing_evicted = self.pairing_evicted.saturating_add(other.pairing_evicted);
        self.dedup_removals = self.dedup_removals.saturating_add(other.dedup_removals);
    }

    pub fn any_nonzero(&self) -> bool {
        self.fragmented_unparsed > 0
            || self.defrag_abandoned > 0
            || self.tcp_unparsed > 0
            || self.tcp_conn_limit > 0
            || self.tcp_buffer_limit > 0
            || self.tcp_idle_evicted > 0
            || self.tcp_resync_failed > 0
            || self.pairing_evicted > 0
            || self.dedup_removals > 0
    }

    pub fn format_lines(&self) -> Vec<String> {
        let mut parts = Vec::new();
        if self.fragmented_unparsed > 0 {
            parts.push(format!("frag_unparsed={}", self.fragmented_unparsed));
        }
        if self.defrag_abandoned > 0 {
            parts.push(format!("defrag_abandoned={}", self.defrag_abandoned));
        }
        if self.tcp_unparsed > 0 {
            parts.push(format!("tcp_unparsed={}", self.tcp_unparsed));
        }
        if self.tcp_conn_limit > 0 {
            parts.push(format!("tcp_conn_limit={}", self.tcp_conn_limit));
        }
        if self.tcp_buffer_limit > 0 {
            parts.push(format!("tcp_buffer_limit={}", self.tcp_buffer_limit));
        }
        if self.tcp_idle_evicted > 0 {
            parts.push(format!("tcp_idle_evicted={}", self.tcp_idle_evicted));
        }
        if self.tcp_resync_failed > 0 {
            parts.push(format!("tcp_resync_failed={}", self.tcp_resync_failed));
        }
        if self.pairing_evicted > 0 {
            parts.push(format!(
                "pairing_evicted={} pair_evicted={}",
                self.pairing_evicted, self.pairing_evicted
            ));
        }
        if self.dedup_removals > 0 {
            parts.push(format!("dedup={}", self.dedup_removals));
        }
        parts
    }

    pub fn format_suffix(&self) -> String {
        let parts = self.format_lines();
        if parts.is_empty() {
            return String::new();
        }
        format!(" | {}", parts.join(" "))
    }
}
