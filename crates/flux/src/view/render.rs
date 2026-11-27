use std::collections::HashMap;

use crate::flow::LatencyKeyStats;
use crate::options::{RateMode, ViewId, ViewSort, WindowMode};
use crate::view::rate::{
    RateContext, apply_view_sort, format_rate_value, rate_for_row, rate_mode_label,
};
use crate::view::snapshot::{ViewCounts, apply_key_cap, rows_for_view};

#[derive(Debug, Clone)]
pub struct TableDisplay {
    pub rate_mode: RateMode,
    pub view_sort: ViewSort,
    pub window: WindowMode,
    pub effective_window_secs: Option<u64>,
    pub counted_span_secs: Option<u64>,
    pub tick_prev: Option<HashMap<String, u64>>,
    pub tick_interval_secs: f64,
    pub replay_wall_secs: Option<f64>,
}

impl Default for TableDisplay {
    fn default() -> Self {
        Self {
            rate_mode: RateMode::Window,
            view_sort: ViewSort::Count,
            window: WindowMode::Seconds(30),
            effective_window_secs: None,
            counted_span_secs: None,
            tick_prev: None,
            tick_interval_secs: 1.0,
            replay_wall_secs: None,
        }
    }
}

pub fn render_table_header(title: &str, total: u64, display: &TableDisplay) -> String {
    let rate = rate_mode_label(display.rate_mode);
    let sort = match display.view_sort {
        ViewSort::Count => "count",
        ViewSort::Rate => "rate",
    };
    format!("=== {title} ({total} messages) · +rate={rate} sort={sort} ===\n")
}

/// `terminal_width`: when set (TUI), name column grows with the pane; when `None`, uses a fixed layout.
#[allow(clippy::too_many_arguments)]
pub fn format_batch_tables(
    counts: &ViewCounts,
    views: &[ViewId],
    limit: usize,
    total: u64,
    key_cap: usize,
    show_no_ede: bool,
    terminal_width: Option<u16>,
    display: &TableDisplay,
) -> String {
    let mut out = String::new();
    let tick_ref = display.tick_prev.as_ref();
    let ctx = RateContext {
        rate_mode: display.rate_mode,
        view_sort: display.view_sort,
        window: &display.window,
        effective_window_secs: display.effective_window_secs,
        counted_span_secs: display.counted_span_secs,
        tick_prev: tick_ref,
        tick_interval_secs: display.tick_interval_secs,
        replay_wall_secs: display.replay_wall_secs,
    };
    for view in views {
        let title = view_title(*view);
        out.push_str(&render_table_header(&title, total, display));
        if is_latency_view(*view) {
            out.push_str(&format_latency_table(counts, *view, limit, terminal_width));
        } else {
            let mut rows = rows_for_view(counts, *view, show_no_ede);
            let mut rated: Vec<(String, u64, f64)> = rows
                .drain(..)
                .map(|(key, count)| {
                    let rate = rate_for_row(count, &key, &ctx);
                    (key, count, rate)
                })
                .collect();
            apply_view_sort(&mut rated, display.view_sort);
            let mut cap_rows: Vec<(String, u64)> =
                rated.iter().map(|(k, c, _)| (k.clone(), *c)).collect();
            apply_key_cap(&mut cap_rows, key_cap);
            let keep: std::collections::HashSet<String> =
                cap_rows.iter().map(|(k, _)| k.clone()).collect();
            rated.retain(|(k, _, _)| keep.contains(k));
            let (name_w, count_w, rate_w, pct_w) =
                count_table_layout(&rated, limit, terminal_width);
            out.push_str(&format_count_table_header(name_w, count_w, rate_w, pct_w));
            let denom = total.max(1);
            for (key, count, rate) in rated.iter().take(limit) {
                let pct = (count.saturating_mul(10000) / denom) as f64 / 100.0;
                let key_disp = truncate_key_left(key, name_w);
                let pct_s = format!("{pct:.2}%");
                let rate_s = format_rate_value(*rate);
                out.push_str(&format!(
                    "  {:<name_w$} {:>count_w$} {:>rate_w$} {:>pct_w$}\n",
                    key_disp, count, rate_s, pct_s
                ));
            }
        }
        out.push('\n');
    }
    out
}

const TABLE_INDENT: usize = 2;
const COL_GAP: usize = 1;
const MIN_NAME_COL: usize = 4;
const PCT_COL_WIDTH: usize = 7; // "100.00%" and header "Percent"
const RATE_COL_WIDTH: usize = 8; // header "Rate"
const FIXED_NAME_WIDTH: usize = 36;

/// Name column hugs content; Count, Rate, and Percent sit to its right. Terminal width caps name only.
fn count_table_layout(
    rows: &[(String, u64, f64)],
    limit: usize,
    terminal_width: Option<u16>,
) -> (usize, usize, usize, usize) {
    let sample = rows.iter().take(limit);
    let count_w = sample
        .clone()
        .map(|(_, c, _)| c.to_string().len())
        .max()
        .unwrap_or(1)
        .max("Count".len());
    let rate_w = sample
        .clone()
        .map(|(_, _, r)| format_rate_value(*r).len())
        .max()
        .unwrap_or(1)
        .max(RATE_COL_WIDTH)
        .max("Rate".len());
    let pct_w = PCT_COL_WIDTH;

    let natural_name_w = sample
        .map(|(k, _, _)| k.chars().count())
        .max()
        .unwrap_or(MIN_NAME_COL)
        .max("Name".len());

    let name_w = match terminal_width {
        None => FIXED_NAME_WIDTH,
        Some(tw) => {
            let tw = usize::from(tw);
            let max_name = tw.saturating_sub(
                TABLE_INDENT + COL_GAP + count_w + COL_GAP + rate_w + COL_GAP + pct_w,
            );
            if max_name == 0 {
                return (1, count_w, rate_w, pct_w);
            }
            let mut name_w = natural_name_w.min(max_name);
            if name_w < MIN_NAME_COL && max_name >= MIN_NAME_COL {
                name_w = MIN_NAME_COL;
            }
            name_w = name_w.max(1);
            while name_w > 1 && row_char_width(name_w, count_w, rate_w, pct_w) > tw {
                name_w -= 1;
            }
            name_w
        }
    };

    (name_w, count_w, rate_w, pct_w)
}

fn row_char_width(name_w: usize, count_w: usize, rate_w: usize, pct_w: usize) -> usize {
    TABLE_INDENT + name_w + COL_GAP + count_w + COL_GAP + rate_w + COL_GAP + pct_w
}

fn format_count_table_header(name_w: usize, count_w: usize, rate_w: usize, pct_w: usize) -> String {
    format!(
        "  {:<name_w$} {:>count_w$} {:>rate_w$} {:>pct_w$}\n",
        "Name", "Count", "Rate", "Percent"
    )
}

/// Drop leading labels; prefix `…` when truncated.
pub fn truncate_key_left(name: &str, max_chars: usize) -> String {
    let n = name.chars().count();
    if n <= max_chars {
        return name.to_string();
    }
    if max_chars == 0 {
        return String::new();
    }
    if max_chars == 1 {
        return "…".to_string();
    }
    let tail_len = max_chars - 1;
    let tail: String = name.chars().skip(n.saturating_sub(tail_len)).collect();
    format!("…{tail}")
}

fn view_title(view: ViewId) -> String {
    match view {
        ViewId::Sources => "Sources".into(),
        ViewId::Destinations => "Destinations".into(),
        ViewId::Qtype => "Qtype".into(),
        ViewId::Rcode => "Rcode".into(),
        ViewId::Opcode => "Opcode".into(),
        ViewId::QnameLevel(n) => format!("QName level {n}"),
        ViewId::SrcXQname(n) => format!("Source × qname level {n}"),
        ViewId::Ede => "EDE codes".into(),
        ViewId::SrcXEde => "Source × EDE".into(),
        ViewId::Interface => "Interfaces".into(),
        ViewId::Vlan => "VLAN".into(),
        ViewId::Transport => "Transport".into(),
        ViewId::LatencyDst => "Latency by destination".into(),
        ViewId::LatencySrc => "Latency by source".into(),
        ViewId::LatencyQtype => "Latency by qtype".into(),
    }
}

fn is_latency_view(view: ViewId) -> bool {
    matches!(
        view,
        ViewId::LatencyDst | ViewId::LatencySrc | ViewId::LatencyQtype
    )
}

fn format_latency_table(
    counts: &ViewCounts,
    view: ViewId,
    limit: usize,
    terminal_width: Option<u16>,
) -> String {
    let key_w = terminal_width
        .map(|w| usize::from(w.max(80)).saturating_sub(2 + 6 + 8 + 8 + 8 + 8 + 7 + 6))
        .unwrap_or(24)
        .max(12);
    let map = match view {
        ViewId::LatencyDst => &counts.latency_dst,
        ViewId::LatencySrc => &counts.latency_src,
        ViewId::LatencyQtype => &counts.latency_qtype,
        _ => return String::new(),
    };
    let mut rows: Vec<(&String, &LatencyKeyStats)> = map.iter().collect();
    rows.sort_by(|a, b| {
        b.1.hist
            .percentile(95.0)
            .cmp(&a.1.hist.percentile(95.0))
            .then_with(|| a.0.cmp(b.0))
    });
    let mut out = format!(
        "  {:<key_w$} {:>6} {:>8} {:>8} {:>8} {:>8} {:>6}\n",
        "key", "count", "p50", "p95", "p99", "max", "unans"
    );
    for (key, stats) in rows.iter().take(limit) {
        let h = &stats.hist;
        let key_disp = truncate_key_left(key, key_w);
        out.push_str(&format!(
            "  {:<key_w$} {:>6} {:>7}ms {:>7}ms {:>7}ms {:>7}ms {:>6}\n",
            key_disp,
            stats.response_count.saturating_add(stats.unanswered),
            h.percentile(50.0),
            h.percentile(95.0),
            h.percentile(99.0),
            h.max_ms(),
            stats.unanswered,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::options::{RateMode, ViewSort, WindowMode};
    use crate::view::snapshot::ViewCounts;

    fn default_display() -> TableDisplay {
        TableDisplay {
            window: WindowMode::Seconds(30),
            effective_window_secs: Some(30),
            ..TableDisplay::default()
        }
    }

    #[test]
    fn batch_output_stable() {
        let c = ViewCounts::default();
        let d = default_display();
        let a = format_batch_tables(&c, &[ViewId::Sources], 10, 0, 50, false, None, &d);
        let b = format_batch_tables(&c, &[ViewId::Sources], 10, 0, 50, false, None, &d);
        assert_eq!(a, b);
    }

    #[test]
    fn rate_column_window_average() {
        let mut c = ViewCounts::default();
        c.sources.insert("10.0.0.1".into(), 300);
        let d = TableDisplay {
            rate_mode: RateMode::Window,
            window: WindowMode::Seconds(30),
            effective_window_secs: Some(30),
            ..TableDisplay::default()
        };
        let out = format_batch_tables(&c, &[ViewId::Sources], 10, 300, 50, false, None, &d);
        assert!(out.contains("Rate"));
        assert!(out.contains("10.0"));
        assert!(out.contains("+rate=window"));
    }

    #[test]
    fn count_columns_hug_short_names() {
        let mut c = ViewCounts::default();
        c.sources.insert("a.com".into(), 5);
        let d = default_display();
        let out = format_batch_tables(&c, &[ViewId::Sources], 10, 5, 50, false, Some(120), &d);
        let row = out.lines().find(|l| l.contains("a.com")).expect("row");
        assert!(
            row.chars().count() < 40,
            "count/rate/percent should sit near name: {row:?}"
        );
    }

    #[test]
    fn narrow_terminal_keeps_count_rate_and_percent_visible() {
        let mut c = ViewCounts::default();
        c.sources
            .insert("averylonglabel.another.example.com".into(), 42);
        let tw = 44u16;
        let d = default_display();
        let out = format_batch_tables(&c, &[ViewId::Sources], 10, 42, 80, false, Some(tw), &d);
        let row = out
            .lines()
            .find(|l| l.starts_with("  ") && (l.contains('…') || l.contains(".com")))
            .expect("data row");
        assert!(row.contains("42"));
        assert!(row.contains('%'));
        let width = row.chars().count();
        assert!(
            width <= tw as usize,
            "row {:?} is {width} cols, pane is {tw}",
            row
        );
    }

    #[test]
    fn truncate_long_qname_from_left() {
        let name = "averylonglabel.another.example.com";
        assert_eq!(truncate_key_left(name, 20), "…another.example.com");
        assert_eq!(truncate_key_left("short", 10), "short");
    }

    #[test]
    fn sort_by_rate_reorders_output() {
        let mut c = ViewCounts::default();
        c.sources.insert("slow".into(), 10);
        c.sources.insert("burst".into(), 100);
        let d = TableDisplay {
            view_sort: ViewSort::Rate,
            window: WindowMode::Seconds(10),
            effective_window_secs: Some(10),
            ..TableDisplay::default()
        };
        let out = format_batch_tables(&c, &[ViewId::Sources], 10, 110, 50, false, None, &d);
        let data: Vec<_> = out
            .lines()
            .filter(|l| l.starts_with("  ") && !l.contains("Name"))
            .collect();
        assert_eq!(data.len(), 2);
        assert!(
            data[0].contains("burst"),
            "rate sort should list higher QPS first: {:?}",
            data
        );
    }

    #[test]
    fn tick_mode_differs_from_window_on_batch() {
        let mut c = ViewCounts::default();
        c.sources.insert("x".into(), 60);
        let window_d = TableDisplay {
            rate_mode: RateMode::Window,
            window: WindowMode::Seconds(30),
            effective_window_secs: Some(30),
            ..TableDisplay::default()
        };
        let tick_d = TableDisplay {
            rate_mode: RateMode::Tick,
            window: WindowMode::Seconds(30),
            effective_window_secs: Some(30),
            replay_wall_secs: Some(6.0),
            ..TableDisplay::default()
        };
        let w = format_batch_tables(&c, &[ViewId::Sources], 5, 60, 50, false, None, &window_d);
        let t = format_batch_tables(&c, &[ViewId::Sources], 5, 60, 50, false, None, &tick_d);
        assert_ne!(w, t);
    }
}
