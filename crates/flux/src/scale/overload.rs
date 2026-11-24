use std::time::Duration;

use crate::options::WindowMode;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum OverloadPolicy {
    #[default]
    Shrink,
    Drop,
    Sample,
    Compact,
}

impl OverloadPolicy {
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "shrink" => Ok(Self::Shrink),
            "drop" => Ok(Self::Drop),
            "sample" => Ok(Self::Sample),
            "compact" => Ok(Self::Compact),
            _ => Err(format!("unknown overload policy: {s}")),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct OverloadState {
    pub active: bool,
    pub policy: OverloadPolicy,
    pub sample_every: u32,
    pub refused: u64,
    pub compacted_slices: u64,
    pub effective_window_secs: Option<u64>,
    pub estimate_marker: bool,
    pub compact_blocks_refilter: bool,
}

impl OverloadState {
    pub fn new(policy: OverloadPolicy) -> Self {
        Self {
            policy,
            ..Self::default()
        }
    }

    pub fn mark_active(&mut self) {
        self.active = true;
    }

    pub fn shrink_window(&mut self, configured: u64, used_secs: u64) -> Option<u64> {
        self.mark_active();
        let eff = used_secs.min(configured).max(1);
        self.effective_window_secs = Some(eff);
        Some(eff)
    }

    pub fn should_admit_sample(&mut self, flow_hash: u64) -> bool {
        let every = self.sample_every.max(1);
        self.mark_active();
        self.estimate_marker = true;
        flow_hash % u64::from(every) == 0
    }

    pub fn refuse_record(&mut self) {
        self.mark_active();
        self.refused += 1;
    }
}

pub fn shrink_tick_interval(base: Duration) -> Duration {
    base
}

pub fn scale_estimate_count(count: u64, sample_every: u32) -> u64 {
    count.saturating_mul(u64::from(sample_every.max(1)))
}

pub fn apply_shrink_to_window(window: &WindowMode, effective: Option<u64>) -> Option<u64> {
    match window {
        WindowMode::All => None,
        WindowMode::Seconds(cfg) => Some(effective.unwrap_or(*cfg)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_band() {
        let mut st = OverloadState::new(OverloadPolicy::Sample);
        st.sample_every = 4;
        assert!(st.should_admit_sample(8));
        assert!(!st.should_admit_sample(9));
    }

    #[test]
    fn scale_estimates() {
        assert_eq!(scale_estimate_count(10, 4), 40);
    }
}
