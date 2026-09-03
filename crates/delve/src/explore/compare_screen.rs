//! Compare-screen helpers: fork scoping, row selection, sticky-header scrolling.

use dns_resolve::NodePath;
use ratatui::text::{Line, Span};

use crate::config::RttBarConfig;

use super::path_summary::{ForkComparison, HopTiming, PathSummary, comparison_for_explore};
use super::rtt_bar::rtt_bar_spans;
use super::theme::Theme;
use super::tree::ExploreTree;

const HOP_ZONE_WIDTH: usize = 22;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompareViewport {
    pub header_lines: usize,
    pub inner_height: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompareScreenModel {
    pub comparison: ForkComparison,
    pub row: usize,
}

impl CompareScreenModel {
    pub fn from_tree(tree: &ExploreTree, selection: &NodePath) -> Option<Self> {
        let comparison = comparison_for_explore(tree, selection)?;
        let row = comparison
            .paths
            .iter()
            .position(|path| {
                selection.path.starts_with(&path.path.path)
                    || path.path.path.starts_with(&selection.path)
            })
            .unwrap_or(0);
        Some(Self { comparison, row })
    }

    pub fn selected_path(&self) -> Option<&NodePath> {
        self.comparison.paths.get(self.row).map(|path| &path.path)
    }

    pub fn move_row(&mut self, delta: isize) {
        if self.comparison.paths.is_empty() {
            return;
        }
        let next = self.row as isize + delta;
        let max = self.comparison.paths.len().saturating_sub(1) as isize;
        self.row = next.clamp(0, max) as usize;
    }

    pub fn rows(&self) -> &[PathSummary] {
        &self.comparison.paths
    }
}

/// Keep `row` visible in the scrollable body beneath a sticky header.
pub fn scroll_for_row(row: usize, viewport: CompareViewport, current_scroll: u16) -> u16 {
    let body_height = viewport
        .inner_height
        .saturating_sub(viewport.header_lines as u16);
    if body_height == 0 {
        return current_scroll;
    }
    let row = row as u16;
    if row < current_scroll {
        return row;
    }
    let last_visible = current_scroll.saturating_add(body_height.saturating_sub(1));
    if row > last_visible {
        row.saturating_sub(body_height.saturating_sub(1))
    } else {
        current_scroll
    }
}

pub fn sticky_header_lines(comparison: &ForkComparison, theme: &Theme) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(vec![
        Span::styled("Compare  ", theme.label()),
        Span::raw(format!(
            "{}  {}",
            comparison.fork_zone, comparison.fork_qname
        )),
    ])];
    if comparison.all_agree {
        lines.push(Line::from(Span::styled(
            "All paths agree (same response code and answer records)",
            theme.accent_bold(),
        )));
    }
    lines.push(Line::from(vec![
        Span::styled(format!("{:<22}", "server"), theme.label()),
        Span::styled(format!(" {:>4}", "hops"), theme.label()),
        Span::styled(format!(" {:>8}", "dns"), theme.label()),
        Span::styled(format!(" {:>6}", "Δ"), theme.label()),
        Span::styled(format!(" {:>6}", "icmp"), theme.label()),
        Span::styled("  outcome", theme.label()),
        Span::styled("  referral", theme.label()),
    ]));
    lines
}

pub fn summary_row_line(summary: &PathSummary, selected: bool, theme: &Theme) -> Line<'static> {
    let style = if selected {
        theme.tree_selected()
    } else if summary.failed {
        theme.failure()
    } else {
        theme.meta()
    };
    let marker = if selected { ">" } else { " " };
    let delta = match summary.dns_rtt_delta_ms {
        Some(0) => "0".to_string(),
        Some(ms) => format!("+{ms}"),
        None => "—".to_string(),
    };
    let icmp = summary
        .icmp_rtt_ms
        .map(|ms| format!("{ms}ms"))
        .unwrap_or_else(|| "n/a".to_string());
    let cache_mark = if summary.cache_served_hops.is_empty() {
        String::new()
    } else {
        " cache".to_string()
    };
    Line::from(Span::styled(
        format!(
            "{marker}{:<21} {:>4} {:>8} {:>6} {:>6}  {:<16} {}{}",
            truncate(&summary.label, 21),
            summary.hop_count,
            format!("{}ms", summary.dns_rtt_total_ms),
            delta,
            icmp,
            truncate(&summary.outcome, 16),
            format_referral(
                &summary.referral_diff.only_here,
                &summary.referral_diff.missing
            ),
            cache_mark
        ),
        style,
    ))
}

/// Bar scale for per-hop lines: the slowest hop anywhere in the comparison, so
/// hop bars stay comparable when the operator moves between rows.
pub fn hop_scale_ms(comparison: &ForkComparison) -> u32 {
    comparison
        .paths
        .iter()
        .flat_map(|path| path.dns_rtt_per_hop.iter())
        .map(|hop| hop.rtt_ms.min(u64::from(u32::MAX)) as u32)
        .max()
        .unwrap_or(0)
        .max(1)
}

pub fn hop_detail_lines(
    summary: &PathSummary,
    scale_max_rtt_ms: u32,
    rtt_config: RttBarConfig,
    theme: &Theme,
) -> Vec<Line<'static>> {
    summary
        .dns_rtt_per_hop
        .iter()
        .map(|hop| hop_detail_line(hop, scale_max_rtt_ms, rtt_config, theme))
        .collect()
}

fn hop_detail_line(
    hop: &HopTiming,
    scale_max_rtt_ms: u32,
    rtt_config: RttBarConfig,
    theme: &Theme,
) -> Line<'static> {
    let zone = truncate(&hop.zone, HOP_ZONE_WIDTH);
    let padding = HOP_ZONE_WIDTH.saturating_sub(zone.chars().count());
    let mut spans = vec![Span::styled(
        format!("    {zone}{}  ", " ".repeat(padding)),
        theme.zone(),
    )];
    spans.extend(rtt_bar_spans(
        hop.rtt_ms.min(u64::from(u32::MAX)) as u32,
        scale_max_rtt_ms,
        rtt_config,
        theme,
    ));
    let mark = if hop.from_cache { " (cache)" } else { "" };
    spans.push(Span::styled(
        format!("  {}ms{mark}", hop.rtt_ms),
        theme.meta(),
    ));
    Line::from(spans)
}

fn format_referral(only_here: &[String], missing: &[String]) -> String {
    let mut parts = Vec::new();
    for name in only_here {
        parts.push(format!("+{name}"));
    }
    for name in missing {
        parts.push(format!("-{name}"));
    }
    parts.join(" ")
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut out = String::new();
    for ch in value.chars().take(max.saturating_sub(1)) {
        out.push(ch);
    }
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::{HopOutcome, NodeOrigin, TraceHop, TraceNode, TraceTree, TraceTreeRequest};

    use crate::explore::tree::build_explore_tree;

    fn hop(zone: &str, server: &str, rtt_ms: u64, outcome: HopOutcome) -> TraceHop {
        TraceHop {
            zone: zone.into(),
            server: server.into(),
            server_name: None,
            qname: "example.com.".into(),
            qtype: "A".into(),
            transport: "udp".into(),
            rtt_ms,
            rcode: "NOERROR".into(),
            nsid: None,
            ede_code: None,
            ede_text: None,
            referral_ns: vec![],
            glue: vec![],
            response: Default::default(),
            from_cache: false,
            outcome,
        }
    }

    fn leaf(server: &str, rtt_ms: u64) -> TraceNode {
        TraceNode {
            hop: hop("example.com.", server, rtt_ms, HopOutcome::Answered),
            origin: NodeOrigin::Trace,
            children: vec![],
        }
    }

    fn fork_tree(child_count: usize) -> ExploreTree {
        let children = (0..child_count)
            .map(|index| leaf(&format!("192.0.2.{}", index + 1), 10 + index as u64))
            .collect();
        let tree = TraceTree {
            request: TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
            root: TraceNode {
                hop: hop("org.", "199.19.56.1", 12, HopOutcome::Referral),
                origin: NodeOrigin::Trace,
                children,
            },
            budget_truncated: false,
        };
        build_explore_tree(&tree)
    }

    #[test]
    fn compare_is_scoped_to_fork_children() {
        let tree = fork_tree(3);
        let model = CompareScreenModel::from_tree(&tree, &NodePath::root(0)).expect("model");
        assert_eq!(model.rows().len(), 3);
        assert!(
            model
                .rows()
                .iter()
                .all(|row| row.path.path.len() == 1 && row.path.tree == 0)
        );
        assert_eq!(model.comparison.fork_zone, "org.");
    }

    #[test]
    fn selected_row_maps_back_to_node_path() {
        let tree = fork_tree(3);
        let mut model = CompareScreenModel::from_tree(
            &tree,
            &NodePath {
                tree: 0,
                path: vec![2],
            },
        )
        .expect("model");
        assert_eq!(model.row, 2);
        assert_eq!(
            model.selected_path().cloned(),
            Some(NodePath {
                tree: 0,
                path: vec![2]
            })
        );
        model.move_row(-1);
        assert_eq!(
            model.selected_path().cloned(),
            Some(NodePath {
                tree: 0,
                path: vec![1]
            })
        );
    }

    #[test]
    fn scrolling_keeps_header_and_selected_row_visible() {
        let viewport = CompareViewport {
            header_lines: 3,
            inner_height: 8,
        };
        // body height = 5
        assert_eq!(scroll_for_row(0, viewport, 0), 0);
        assert_eq!(scroll_for_row(4, viewport, 0), 0);
        assert_eq!(scroll_for_row(5, viewport, 0), 1);
        assert_eq!(scroll_for_row(12, viewport, 0), 8);
        assert_eq!(scroll_for_row(2, viewport, 4), 2);
    }

    #[test]
    fn unavailable_without_sibling_paths() {
        let tree = fork_tree(1);
        assert!(CompareScreenModel::from_tree(&tree, &NodePath::root(0)).is_none());
    }

    #[test]
    fn rows_include_new_branch_child() {
        let tree = fork_tree(2);
        let before = CompareScreenModel::from_tree(&tree, &NodePath::root(0)).expect("before");
        assert_eq!(before.rows().len(), 2);
        let tree = fork_tree(4);
        let after = CompareScreenModel::from_tree(&tree, &NodePath::root(0)).expect("after");
        assert_eq!(after.rows().len(), 4);
    }

    #[test]
    fn cache_served_mark_appears_in_row() {
        let mut tree = fork_tree(2);
        tree.tree.root.children[0].hop.from_cache = true;
        let model = CompareScreenModel::from_tree(&tree, &NodePath::root(0)).expect("model");
        let line = summary_row_line(&model.rows()[0], false, &Theme::from_env());
        let text: String = line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        assert!(text.contains("cache"));
        let other: String = summary_row_line(&model.rows()[1], false, &Theme::from_env())
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        assert!(!other.contains("cache"));
    }

    #[test]
    fn hop_lines_bar_the_slowest_hop_and_mark_cache() {
        let mut tree = fork_tree(2);
        tree.tree.root.children[0].hop.from_cache = true;
        tree.tree.root.children[1].hop.rtt_ms = 400;
        let model = CompareScreenModel::from_tree(&tree, &NodePath::root(0)).expect("model");
        let scale = hop_scale_ms(&model.comparison);
        assert_eq!(scale, 400);

        let theme = Theme::from_env();
        let config = RttBarConfig::default();
        let cached = hop_detail_lines(&model.rows()[0], scale, config, &theme);
        let slow = hop_detail_lines(&model.rows()[1], scale, config, &theme);
        assert_eq!(cached.len(), 1);
        assert_eq!(slow.len(), 1);

        let cached_text: String = cached[0]
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        let slow_text: String = slow[0]
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        assert!(cached_text.contains("(cache)"));
        assert!(!slow_text.contains("(cache)"));
        assert!(slow_text.contains("400ms"));

        let filled = |line: &Line<'_>| line.spans.iter().filter(|span| span.content == "█").count();
        assert_eq!(filled(&slow[0]), config.normalized().max_width as usize);
        assert!(filled(&cached[0]) < filled(&slow[0]));
    }
}
