use std::collections::VecDeque;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct DedupState {
    pub enabled: bool,
    window: Duration,
    recent: VecDeque<(u128, u64)>,
    pub removals: u64,
}

impl DedupState {
    pub fn new(enabled: bool, window: Duration) -> Self {
        Self {
            enabled,
            window,
            recent: VecDeque::new(),
            removals: 0,
        }
    }

    /// Returns true when the packet should be counted (first seen in the window).
    pub fn admit(&mut self, fp: u64, ts_ns: u128) -> bool {
        if !self.enabled {
            return true;
        }
        let window_ns = self.window.as_nanos();
        self.evict_before(ts_ns.saturating_sub(window_ns));
        let dup = self
            .recent
            .iter()
            .any(|(t, f)| *f == fp && ts_ns.saturating_sub(*t) <= window_ns);
        if dup {
            self.removals = self.removals.saturating_add(1);
            return false;
        }
        self.recent.push_back((ts_ns, fp));
        true
    }

    fn evict_before(&mut self, cutoff: u128) {
        while self.recent.front().is_some_and(|(t, _)| *t < cutoff) {
            self.recent.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn dedup_within_window() {
        let mut d = DedupState::new(true, Duration::from_millis(5));
        assert!(d.admit(42, 1_000_000));
        assert!(!d.admit(42, 1_002_000));
        assert_eq!(d.removals, 1);
        assert!(d.admit(42, 10_000_000));
    }

    #[test]
    fn dedup_off_passes_all() {
        let mut d = DedupState::new(false, Duration::from_millis(5));
        assert!(d.admit(1, 0));
        assert!(d.admit(1, 0));
        assert_eq!(d.removals, 0);
    }
}
