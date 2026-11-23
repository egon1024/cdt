use crate::flow::LatencyKeyStats;
use crate::options::ViewId;
use crate::view::snapshot::{ViewCounts, counts_for_view};

pub fn render_table_header(title: &str, total: u64) -> String {
    format!("=== {title} ({total} messages) ===\n")
}

pub fn format_batch_tables(
    counts: &ViewCounts,
    views: &[ViewId],
    limit: usize,
    total: u64,
    key_cap: usize,
    show_no_ede: bool,
) -> String {
    let mut out = String::new();
    for view in views {
        let title = view_title(*view);
        out.push_str(&render_table_header(&title, total));
        if is_latency_view(*view) {
            out.push_str(&format_latency_table(counts, *view, limit));
        } else {
            let rows = counts_for_view(counts, *view, key_cap, show_no_ede);
            let denom = total.max(1);
            for (key, count) in rows.iter().take(limit) {
                let pct = (count.saturating_mul(10000) / denom) as f64 / 100.0;
                out.push_str(&format!("  {key:<40} {count:>8}  {pct:>6.2}%\n"));
            }
        }
        out.push('\n');
    }
    out
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

fn format_latency_table(counts: &ViewCounts, view: ViewId, limit: usize) -> String {
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
        "  {:<24} {:>6} {:>9} {:>9} {:>9} {:>9} {:>6}\n",
        "key", "count", "p50", "p95", "p99", "max", "unans"
    );
    for (key, stats) in rows.iter().take(limit) {
        let h = &stats.hist;
        out.push_str(&format!(
            "  {:<24} {:>6} {:>9} {:>9} {:>9} {:>9} {:>6}\n",
            key,
            stats.response_count.saturating_add(stats.unanswered),
            latency_ms_cell(h.percentile(50.0)),
            latency_ms_cell(h.percentile(95.0)),
            latency_ms_cell(h.percentile(99.0)),
            latency_ms_cell(h.max_ms()),
            stats.unanswered,
        ));
    }
    out
}

/// Right-aligned latency value plus `ms`, always nine monospace columns (matches header widths).
fn latency_ms_cell(ms: u32) -> String {
    format!("{:>7}ms", ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::view::snapshot::ViewCounts;

    #[test]
    fn batch_output_stable() {
        let c = ViewCounts::default();
        let a = format_batch_tables(&c, &[ViewId::Sources], 10, 0, 50, false);
        let b = format_batch_tables(&c, &[ViewId::Sources], 10, 0, 50, false);
        assert_eq!(a, b);
    }

    #[test]
    fn latency_ms_cell_fixed_width() {
        assert_eq!(super::latency_ms_cell(987).len(), 9);
        assert_eq!(super::latency_ms_cell(1000).len(), 9);
    }

    #[test]
    fn latency_table_header_aligns_with_data() {
        use crate::flow::{LatencyHistogram, LatencyKeyStats};
        let mut c = ViewCounts::default();
        c.latency_dst.insert(
            "192.0.2.53".into(),
            LatencyKeyStats {
                hist: LatencyHistogram::default(),
                response_count: 3,
                unanswered: 0,
            },
        );
        // Seed histogram so percentiles are non-zero
        let stats = c.latency_dst.get_mut("192.0.2.53").unwrap();
        for _ in 0..3 {
            stats.hist.record(987);
        }
        let table = super::format_latency_table(&c, ViewId::LatencyDst, 10);
        let mut lines = table.lines();
        let header = lines.next().expect("header");
        let data = lines.next().expect("data");
        // Column after key (24) + count (6) and single spaces between fields.
        let p50_col = 2 + 24 + 1 + 6 + 1;
        let h_col = &header[p50_col..p50_col + 9];
        let d_col = &data[p50_col..p50_col + 9];
        assert_eq!(h_col.trim(), "p50", "header slice: {h_col:?}");
        assert!(
            d_col.contains("987ms"),
            "data slice: {d_col:?} in\n{data}"
        );
    }
}
