use crate::flow::LatencyKeyStats;
use crate::options::ViewId;
use crate::view::snapshot::{ViewCounts, counts_for_view};

pub fn render_table_header(title: &str, total: u64) -> String {
    format!("=== {title} ({total} messages) ===\n")
}

/// `terminal_width`: when set (TUI), name column grows with the pane; when `None`, uses a fixed layout.
pub fn format_batch_tables(
    counts: &ViewCounts,
    views: &[ViewId],
    limit: usize,
    total: u64,
    key_cap: usize,
    show_no_ede: bool,
    terminal_width: Option<u16>,
) -> String {
    let mut out = String::new();
    for view in views {
        let title = view_title(*view);
        out.push_str(&render_table_header(&title, total));
        if is_latency_view(*view) {
            out.push_str(&format_latency_table(counts, *view, limit, terminal_width));
        } else {
            let rows = counts_for_view(counts, *view, key_cap, show_no_ede);
            let (name_w, count_w, pct_w) =
                count_table_layout(&rows, limit, terminal_width);
            out.push_str(&format_count_table_header(name_w, count_w, pct_w));
            let denom = total.max(1);
            for (key, count) in rows.iter().take(limit) {
                let pct = (count.saturating_mul(10000) / denom) as f64 / 100.0;
                let key_disp = truncate_key_left(key, name_w);
                let pct_s = format!("{pct:.2}%");
                out.push_str(&format!(
                    "  {:<name_w$} {:>count_w$} {:>pct_w$}\n",
                    key_disp, count, pct_s
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
const FIXED_NAME_WIDTH: usize = 40;

/// Name column hugs content; Count/Percent sit to its right. Terminal width caps name only.
fn count_table_layout(
    rows: &[(String, u64)],
    limit: usize,
    terminal_width: Option<u16>,
) -> (usize, usize, usize) {
    let sample = rows.iter().take(limit);
    let count_w = sample
        .clone()
        .map(|(_, c)| c.to_string().len())
        .max()
        .unwrap_or(1)
        .max("Count".len());
    let pct_w = PCT_COL_WIDTH;

    let natural_name_w = sample
        .map(|(k, _)| k.chars().count())
        .max()
        .unwrap_or(MIN_NAME_COL)
        .max("Name".len());

    let name_w = match terminal_width {
        None => FIXED_NAME_WIDTH,
        Some(tw) => {
            let tw = usize::from(tw);
            let max_name = tw.saturating_sub(TABLE_INDENT + COL_GAP + count_w + COL_GAP + pct_w);
            if max_name == 0 {
                return (1, count_w, pct_w);
            }
            let mut name_w = natural_name_w.min(max_name);
            if name_w < MIN_NAME_COL && max_name >= MIN_NAME_COL {
                name_w = MIN_NAME_COL;
            }
            name_w = name_w.max(1);
            while name_w > 1 && row_char_width(name_w, count_w, pct_w) > tw {
                name_w -= 1;
            }
            name_w
        }
    };

    (name_w, count_w, pct_w)
}

fn row_char_width(name_w: usize, count_w: usize, pct_w: usize) -> usize {
    TABLE_INDENT + name_w + COL_GAP + count_w + COL_GAP + pct_w
}

fn format_count_table_header(name_w: usize, count_w: usize, pct_w: usize) -> String {
    format!(
        "  {:<name_w$} {:>count_w$} {:>pct_w$}\n",
        "Name", "Count", "Percent"
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
    use crate::view::snapshot::ViewCounts;

    #[test]
    fn batch_output_stable() {
        let c = ViewCounts::default();
        let a = format_batch_tables(&c, &[ViewId::Sources], 10, 0, 50, false, None);
        let b = format_batch_tables(&c, &[ViewId::Sources], 10, 0, 50, false, None);
        assert_eq!(a, b);
    }

    #[test]
    fn count_columns_hug_short_names() {
        let mut c = ViewCounts::default();
        c.sources.insert("a.com".into(), 5);
        let out = format_batch_tables(&c, &[ViewId::Sources], 10, 5, 50, false, Some(120));
        let row = out.lines().find(|l| l.contains("a.com")).expect("row");
        assert!(
            row.chars().count() < 30,
            "count/percent should sit near name, not at far margin: {row:?}"
        );
    }

    #[test]
    fn narrow_terminal_keeps_count_and_percent_visible() {
        let mut c = ViewCounts::default();
        c.sources.insert("averylonglabel.another.example.com".into(), 42);
        let tw = 36u16;
        let out = format_batch_tables(&c, &[ViewId::Sources], 10, 42, 80, false, Some(tw));
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
        assert_eq!(
            truncate_key_left(name, 20),
            "…another.example.com"
        );
        assert_eq!(truncate_key_left("short", 10), "short");
    }
}
