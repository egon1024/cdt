use crate::parse::ObservationRecord;

#[derive(Debug, Default, Clone)]
pub struct ParseStats {
    pub records_parsed: u64,
    pub malformed: u64,
    pub busy_ns: u64,
    pub idle_ns: u64,
    pub queue_depth: u64,
}

#[derive(Debug, Default)]
pub struct ParseWorker {
    pub arena: Vec<u8>,
    pub records: Vec<ObservationRecord>,
    pub stats: ParseStats,
}

impl ParseWorker {
    pub fn push_record(&mut self, rec: ObservationRecord) {
        if rec.malformed {
            self.stats.malformed += 1;
        }
        self.stats.records_parsed += 1;
        self.records.push(rec);
    }

    pub fn recycle_arena(&mut self) {
        self.arena.clear();
        self.arena.shrink_to_fit();
        self.arena.reserve(4096);
    }
}
