use crate::parse::ObservationRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SliceId(pub u64);

#[derive(Debug, Clone)]
pub struct TimeSlice {
    pub id: SliceId,
    pub second: u64,
    pub sealed: bool,
    pub records: Vec<ObservationRecord>,
    pub grace_until: Option<std::time::Instant>,
}

impl TimeSlice {
    pub fn open(second: u64) -> Self {
        Self {
            id: SliceId(second),
            second,
            sealed: false,
            records: Vec::new(),
            grace_until: None,
        }
    }
}
