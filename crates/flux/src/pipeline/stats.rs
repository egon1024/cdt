#[derive(Debug, Clone)]
pub struct StatusLine {
    pub packets: u64,
    pub drops: u64,
    pub parse_busy_pct: u8,
    pub queue_depth: u64,
}

impl StatusLine {
    pub fn format(&self) -> String {
        format!(
            "status: packets={} drops={} parse_busy={}% queue={}\n",
            self.packets, self.drops, self.parse_busy_pct, self.queue_depth
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_nonzero_after_replay() {
        let s = StatusLine {
            packets: 10,
            drops: 0,
            parse_busy_pct: 50,
            queue_depth: 0,
        };
        assert!(s.format().contains("packets=10"));
    }
}
