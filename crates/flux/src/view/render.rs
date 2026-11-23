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
) -> String {
    let mut out = String::new();
    for view in views {
        let title = view_title(*view);
        out.push_str(&render_table_header(&title, total));
        let rows = counts_for_view(counts, *view);
        let denom = total.max(1);
        for (key, count) in rows.iter().take(limit) {
            let pct = (count.saturating_mul(10000) / denom) as f64 / 100.0;
            out.push_str(&format!("  {key:<40} {count:>8}  {pct:>6.2}%\n"));
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::view::snapshot::ViewCounts;

    #[test]
    fn batch_output_stable() {
        let c = ViewCounts::default();
        let a = format_batch_tables(&c, &[ViewId::Sources], 10, 0);
        let b = format_batch_tables(&c, &[ViewId::Sources], 10, 0);
        assert_eq!(a, b);
    }
}
