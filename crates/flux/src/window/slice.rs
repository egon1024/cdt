use crate::parse::ObservationRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SliceId(pub u64);

#[derive(Debug, Clone)]
pub struct TimeSlice {
    pub id: SliceId,
    pub second: u64,
    pub sealed: bool,
    pub records: Vec<ObservationRecord>,
    pub arena: Vec<u8>,
    pub grace_until: Option<std::time::Instant>,
}

impl TimeSlice {
    pub fn open(second: u64) -> Self {
        Self {
            id: SliceId(second),
            second,
            sealed: false,
            records: Vec::new(),
            arena: Vec::new(),
            grace_until: None,
        }
    }

    pub fn append_ede_blob(&mut self, blob: &[u8]) -> (u32, u16) {
        if blob.is_empty() {
            return (0, 0);
        }
        let off = self.arena.len() as u32;
        let len = blob.len().min(u16::MAX as usize) as u16;
        self.arena.extend_from_slice(&blob[..len as usize]);
        (off, len)
    }
}
