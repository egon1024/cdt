/// Per-action query cap (see `trace.max_queries_per_action` in delve config).
#[derive(Debug, Clone)]
pub struct QueryBudget {
    remaining: usize,
    cap: usize,
    pub truncated: bool,
}

impl QueryBudget {
    pub fn new(cap: usize) -> Self {
        Self {
            remaining: cap,
            cap,
            truncated: false,
        }
    }

    pub fn cap(&self) -> usize {
        self.cap
    }

    pub fn remaining(&self) -> usize {
        self.remaining
    }

    /// Reserve one query slot. Returns `false` when the cap is exhausted.
    pub fn try_consume(&mut self) -> bool {
        if self.remaining == 0 {
            self.truncated = true;
            return false;
        }
        self.remaining -= 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stops_at_cap_and_marks_truncated() {
        let mut budget = QueryBudget::new(2);
        assert!(budget.try_consume());
        assert!(budget.try_consume());
        assert!(!budget.try_consume());
        assert!(budget.truncated);
        assert_eq!(budget.remaining(), 0);
    }
}
