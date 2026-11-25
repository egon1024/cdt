use std::collections::HashMap;

use crate::options::{RateMode, ViewSort, WindowMode};

/// Inputs for computing per-row rates in count-based views.
#[derive(Debug, Clone)]
pub struct RateContext<'a> {
    pub rate_mode: RateMode,
    pub view_sort: ViewSort,
    pub window: &'a WindowMode,
    /// Shrink / status effective window (seconds); overrides configured window for divisor when set.
    pub effective_window_secs: Option<u64>,
    /// Span of counted slice seconds (`max - min + 1`) for `+window=all`.
    pub counted_span_secs: Option<u64>,
    /// Previous refresh counts per row key (live tick mode).
    pub tick_prev: Option<&'a HashMap<String, u64>>,
    pub tick_interval_secs: f64,
    /// Wall time for a one-shot batch replay (tick mode on batch).
    pub replay_wall_secs: Option<f64>,
}

pub fn window_divisor_secs(ctx: &RateContext<'_>) -> f64 {
    match ctx.window {
        WindowMode::All => ctx.counted_span_secs.unwrap_or(1).max(1) as f64,
        WindowMode::Seconds(configured) => {
            ctx.effective_window_secs.unwrap_or(*configured).max(1) as f64
        }
    }
}

pub fn rate_for_row(count: u64, key: &str, ctx: &RateContext<'_>) -> f64 {
    match ctx.rate_mode {
        RateMode::Window => count as f64 / window_divisor_secs(ctx),
        RateMode::Tick => {
            if let Some(prev) = ctx.tick_prev {
                let delta = count.saturating_sub(*prev.get(key).unwrap_or(&0));
                return delta as f64 / ctx.tick_interval_secs.max(0.001);
            }
            if let Some(wall) = ctx.replay_wall_secs {
                return count as f64 / wall.max(0.001);
            }
            count as f64 / window_divisor_secs(ctx)
        }
    }
}

pub fn format_rate_value(rate: f64) -> String {
    if rate >= 100.0 {
        format!("{rate:.0}")
    } else if rate >= 10.0 {
        format!("{rate:.1}")
    } else {
        format!("{rate:.2}")
    }
}

pub fn rate_mode_label(mode: RateMode) -> &'static str {
    match mode {
        RateMode::Window => "window",
        RateMode::Tick => "tick",
    }
}

pub fn apply_view_sort(rows: &mut [(String, u64, f64)], sort: ViewSort) {
    match sort {
        ViewSort::Count => {
            rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        }
        ViewSort::Rate => {
            rows.sort_by(|a, b| {
                b.2.partial_cmp(&a.2)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.0.cmp(&b.0))
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_rate_uses_effective_window() {
        let window = WindowMode::Seconds(15);
        let ctx = RateContext {
            rate_mode: RateMode::Window,
            view_sort: ViewSort::Count,
            window: &window,
            effective_window_secs: Some(7),
            counted_span_secs: None,
            tick_prev: None,
            tick_interval_secs: 1.0,
            replay_wall_secs: None,
        };
        assert!((rate_for_row(70, "k", &ctx) - 10.0).abs() < 0.01);
    }

    #[test]
    fn window_all_uses_slice_span() {
        let window = WindowMode::All;
        let ctx = RateContext {
            rate_mode: RateMode::Window,
            view_sort: ViewSort::Count,
            window: &window,
            effective_window_secs: None,
            counted_span_secs: Some(10),
            tick_prev: None,
            tick_interval_secs: 1.0,
            replay_wall_secs: None,
        };
        assert!((rate_for_row(100, "k", &ctx) - 10.0).abs() < 0.01);
    }

    #[test]
    fn tick_live_uses_delta() {
        let window = WindowMode::Seconds(30);
        let mut prev = HashMap::new();
        prev.insert("a".into(), 40);
        let ctx = RateContext {
            rate_mode: RateMode::Tick,
            view_sort: ViewSort::Count,
            window: &window,
            effective_window_secs: Some(30),
            counted_span_secs: None,
            tick_prev: Some(&prev),
            tick_interval_secs: 2.0,
            replay_wall_secs: None,
        };
        assert!((rate_for_row(50, "a", &ctx) - 5.0).abs() < 0.01);
    }

    #[test]
    fn sort_by_rate_orders_rows() {
        let mut rows = vec![
            ("high-count".into(), 100u64, 1.0f64),
            ("high-rate".into(), 10, 50.0),
        ];
        apply_view_sort(&mut rows, ViewSort::Rate);
        assert_eq!(rows[0].0, "high-rate");
    }
}
