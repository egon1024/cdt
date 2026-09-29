use std::collections::BTreeMap;
use std::net::IpAddr;

use dns_resolve::NodePath;
use dns_resolve::probe::IcmpProber;
#[cfg(test)]
use ratatui::style::Style;
use ratatui::text::{Line, Span};
#[cfg(test)]
use unicode_width::UnicodeWidthStr;

#[cfg(test)]
use dns_resolve::HopOutcome;

use crate::config::RttBarConfig;
use crate::session::TargetEnrichments;

#[cfg(test)]
use super::hop_identity::{
    MAX_IDENTITY_COLUMN_WIDTH, MIN_IDENTITY_COLUMN_WIDTH, hop_identity_display_width,
    hop_identity_spans,
};
#[cfg(test)]
use super::path_summary::icmp_rtt_from_targets;
use super::path_summary::{
    ForkComparison, PathSummary, comparison_for_explore, enrich_icmp_with_live_probe,
    format_referral_delta_column, referral_header_line,
};
use super::rtt_bar::rtt_bar_spans;
use super::theme::Theme;
use super::tree::ExploreTree;
#[cfg(test)]
use super::tree::VisibleNode;

/// Per-hop Compare rows (legacy tree table); kept for regression tests only.
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub struct CompareColumns {
    /// Indent + tree marker + identity, left-aligned; padded on the right.
    pub tree_column_width: usize,
    pub rcode_width: usize,
    pub rtt_width: usize,
    pub rtt_bar_width: usize,
    pub icmp_width: usize,
}

#[cfg(test)]
impl CompareColumns {
    pub const MIN_RCODE_WIDTH: usize = 7;
    pub const INDENT_WIDTH: usize = 2;

    pub fn for_visible(
        tree: &ExploreTree,
        visible: &[VisibleNode],
        rtt_config: RttBarConfig,
        theme: &Theme,
    ) -> Self {
        let rtt_bar_width = rtt_config.normalized().max_width as usize;

        let mut tree_column_width = display_width("identity");
        let mut rcode_width = Self::MIN_RCODE_WIDTH;

        for node in visible {
            let Some(hop) = tree.hop_at(&node.path) else {
                continue;
            };
            let marker = compare_tree_marker(node, tree, theme);
            let identity_width = hop_identity_display_width(hop, Some(MAX_IDENTITY_COLUMN_WIDTH))
                .min(MAX_IDENTITY_COLUMN_WIDTH);
            let row_tree_width =
                node.depth * Self::INDENT_WIDTH + display_width(marker.as_str()) + identity_width;
            tree_column_width = tree_column_width.max(row_tree_width);
            if matches!(hop.outcome, HopOutcome::Failed { .. }) {
                rcode_width = rcode_width.max(display_width("FAILED"));
            } else {
                rcode_width = rcode_width.max(display_width(hop.rcode.as_str()));
            }
        }

        Self {
            tree_column_width: tree_column_width.max(MIN_IDENTITY_COLUMN_WIDTH),
            rcode_width,
            rtt_width: 7,
            rtt_bar_width,
            icmp_width: 6,
        }
    }

    pub fn header(self, theme: &Theme) -> Line<'static> {
        Line::from(vec![
            Span::styled(
                pad_right_display("identity", self.tree_column_width),
                theme.label(),
            ),
            Span::raw("  "),
            Span::styled(pad_left_display("rcode", self.rcode_width), theme.label()),
            Span::raw("  "),
            Span::styled(pad_left_display("rtt", self.rtt_width), theme.label()),
            Span::raw("  "),
            Span::styled(
                pad_left_display("rtt latency", self.rtt_bar_width),
                theme.label(),
            ),
            Span::raw("  "),
            Span::styled(pad_left_display("icmp", self.icmp_width), theme.label()),
        ])
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub fn compare_row(
    node: &VisibleNode,
    tree: &ExploreTree,
    selected: bool,
    path_highlighted: bool,
    columns: CompareColumns,
    targets: &BTreeMap<IpAddr, TargetEnrichments>,
    rtt_config: RttBarConfig,
    scale_max_rtt_ms: u32,
    theme: &Theme,
) -> Option<Line<'static>> {
    let hop = tree.hop_at(&node.path)?;

    let failed = matches!(hop.outcome, HopOutcome::Failed { .. });
    let row_style = if selected {
        theme.tree_selected()
    } else if path_highlighted {
        theme.accent_bold()
    } else if failed {
        theme.failure()
    } else {
        theme.meta()
    };

    let rcode = if failed {
        pad_left_display("FAILED", columns.rcode_width)
    } else {
        pad_left_display(&hop.rcode, columns.rcode_width)
    };
    let rtt = pad_left_display(format!("{}ms", hop.rtt_ms), columns.rtt_width);
    let icmp = pad_left_display(
        icmp_rtt_from_targets(targets, &hop.server)
            .map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "n/a".to_string()),
        columns.icmp_width,
    );

    let mut spans = compare_tree_spans(node, hop, tree, columns, theme, row_style);
    spans.extend([
        Span::raw("  "),
        Span::styled(
            rcode,
            if failed {
                theme.failure()
            } else {
                theme.rcode(&hop.rcode)
            },
        ),
        Span::raw("  "),
        Span::styled(rtt, row_style),
        Span::raw("  "),
    ]);
    let bar_start = spans.len();
    spans.extend(rtt_bar_spans(
        hop.rtt_ms.min(u32::MAX as u64) as u32,
        scale_max_rtt_ms,
        rtt_config,
        theme,
    ));
    let bar_end = spans.len();
    spans.push(Span::raw("  "));
    spans.push(Span::styled(icmp, row_style));

    if selected {
        apply_compare_selection(&mut spans, row_style, bar_start..bar_end);
    }

    Some(Line::from(spans))
}

#[cfg(test)]
fn apply_compare_selection(
    spans: &mut [Span<'static>],
    style: Style,
    skip: std::ops::Range<usize>,
) {
    for (index, span) in spans.iter_mut().enumerate() {
        if skip.contains(&index) {
            continue;
        }
        span.style = style;
    }
}

#[cfg(test)]
fn compare_tree_spans(
    node: &VisibleNode,
    hop: &dns_resolve::TraceHop,
    tree: &ExploreTree,
    columns: CompareColumns,
    theme: &Theme,
    row_style: Style,
) -> Vec<Span<'static>> {
    let indent = "  ".repeat(node.depth);
    let marker = compare_tree_marker(node, tree, theme);
    let mut spans = vec![Span::styled(format!("{indent}{marker}"), row_style)];
    spans.extend(hop_identity_spans(
        hop,
        theme,
        Some(MAX_IDENTITY_COLUMN_WIDTH),
        row_style,
    ));
    let rendered_width: usize = spans
        .iter()
        .map(|span| display_width(span.content.as_ref()))
        .sum();
    if rendered_width < columns.tree_column_width {
        spans.push(Span::raw(
            " ".repeat(columns.tree_column_width - rendered_width),
        ));
    }
    spans
}

/// Expand/collapse marker for all expandable nodes; forks also get a branch dot.
#[cfg(test)]
pub fn compare_tree_marker(node: &VisibleNode, tree: &ExploreTree, theme: &Theme) -> String {
    if !node.expandable {
        return "  ".to_string();
    }
    let expand = if node.expanded {
        theme.symbols.tree_expand
    } else {
        theme.symbols.tree_collapse
    };
    if children_count(node, tree) >= 2 {
        format!("{expand}•")
    } else {
        expand.to_string()
    }
}

#[cfg(test)]
fn children_count(node: &VisibleNode, tree: &ExploreTree) -> usize {
    tree.node_at(&node.path)
        .map(|trace_node| trace_node.children.len())
        .unwrap_or(0)
}

#[cfg(test)]
fn display_width(text: &str) -> usize {
    UnicodeWidthStr::width(text)
}

#[cfg(test)]
fn pad_left_display(value: impl std::fmt::Display, width: usize) -> String {
    let text = value.to_string();
    let text_width = display_width(text.as_str());
    if text_width >= width {
        return text;
    }
    format!("{}{}", " ".repeat(width - text_width), text)
}

#[cfg(test)]
fn pad_right_display(value: impl std::fmt::Display, width: usize) -> String {
    let text = value.to_string();
    let text_width = display_width(text.as_str());
    if text_width >= width {
        return text;
    }
    format!("{}{}", text, " ".repeat(width - text_width))
}

/// Fork-scoped compare table backed by `path_summary` projections.
#[derive(Debug, Clone, PartialEq)]
pub struct ForkCompareModel {
    pub comparison: ForkComparison,
    pub row: usize,
}

impl ForkCompareModel {
    pub fn from_tree(
        tree: &ExploreTree,
        selection: &NodePath,
        targets: &BTreeMap<IpAddr, TargetEnrichments>,
        prober: &dyn IcmpProber,
        live_probe: bool,
    ) -> Option<Self> {
        let comparison = comparison_for_explore(tree, selection)?;
        let comparison =
            enrich_icmp_with_live_probe(comparison, tree.trace(), targets, prober, live_probe);
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

    pub fn path_count(&self) -> usize {
        self.comparison.paths.len()
    }

    #[cfg(test)]
    pub fn selected_path(&self) -> Option<&NodePath> {
        self.comparison.paths.get(self.row).map(|path| &path.path)
    }

    #[cfg(test)]
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

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkCompareViewport {
    pub header_lines: usize,
    pub inner_height: u16,
}

#[derive(Debug, Clone)]
pub struct ForkCompareRender {
    pub header_lines: usize,
    pub lines: Vec<Line<'static>>,
}

pub fn render_fork_compare(
    model: &ForkCompareModel,
    rtt_config: RttBarConfig,
    theme: &Theme,
) -> ForkCompareRender {
    let header = fork_compare_header_lines(&model.comparison, rtt_config, theme);
    let header_lines = header.len();
    let scale = fork_compare_scale_ms(&model.comparison);
    let referral_agree = model.comparison.referral.agree;
    let mut lines = header;
    for (index, path) in model.rows().iter().enumerate() {
        lines.push(fork_compare_row_line(
            path,
            index == model.row,
            referral_agree,
            scale,
            rtt_config,
            theme,
        ));
    }
    ForkCompareRender {
        header_lines,
        lines,
    }
}

/// Keep `row` visible in the scrollable body beneath a sticky header.
#[cfg(test)]
pub fn scroll_fork_compare_row(
    row: usize,
    viewport: ForkCompareViewport,
    current_scroll: u16,
) -> u16 {
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

pub fn fork_compare_scale_ms(comparison: &ForkComparison) -> u32 {
    comparison
        .paths
        .iter()
        .map(|path| path.dns_rtt_total_ms.min(u64::from(u32::MAX)) as u32)
        .max()
        .unwrap_or(0)
        .max(1)
}

pub fn fork_compare_row_line(
    summary: &PathSummary,
    selected: bool,
    referral_agree: bool,
    scale_max_rtt_ms: u32,
    rtt_config: RttBarConfig,
    theme: &Theme,
) -> Line<'static> {
    let field_style = if selected {
        theme.accent_bold()
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
    let mut spans = vec![Span::styled(
        format!(
            "{marker}{:<21} {:>4} {:>8}",
            truncate_fork_label(&summary.label, 21),
            summary.hop_count,
            format!("{}ms", summary.dns_rtt_total_ms),
        ),
        field_style,
    )];
    spans.push(Span::raw("  "));
    spans.extend(rtt_bar_spans(
        summary.dns_rtt_total_ms.min(u64::from(u32::MAX)) as u32,
        scale_max_rtt_ms,
        rtt_config,
        theme,
    ));
    spans.push(Span::styled(
        format!(
            " {:>6} {:>6}  {:<16} {}{}",
            delta,
            icmp,
            truncate_fork_label(&summary.outcome, 16),
            format_referral_delta_column(&summary.referral_diff, referral_agree),
            cache_mark
        ),
        field_style,
    ));
    Line::from(spans)
}

pub fn fork_compare_header_lines(
    comparison: &ForkComparison,
    rtt_config: RttBarConfig,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let mut lines = vec![Line::from(vec![
        Span::styled("Compare  ", theme.label()),
        Span::raw(format!(
            "{}  {}",
            comparison.fork_zone, comparison.fork_qname
        )),
    ])];
    if comparison.answers.agree {
        lines.push(Line::from(Span::styled(
            "Answers agree (same response code and answer records)",
            theme.accent_bold(),
        )));
    }
    if let Some(line) = referral_header_line(&comparison.referral) {
        lines.push(Line::from(Span::styled(line, theme.meta())));
    }
    lines.push(Line::from(vec![
        Span::styled(format!("{:<22}", "server"), theme.label()),
        Span::styled(format!(" {:>4}", "hops"), theme.label()),
        Span::styled(format!(" {:>8}", "dns"), theme.label()),
        Span::raw("  "),
        Span::styled(
            pad_fork_bar_header("rtt latency", rtt_config.normalized().max_width as usize),
            theme.label(),
        ),
        Span::styled(format!(" {:>6}", "Δ"), theme.label()),
        Span::styled(format!(" {:>6}", "icmp"), theme.label()),
        Span::styled("  outcome", theme.label()),
        Span::styled("  referral Δ", theme.label()),
    ]));
    lines
}

fn pad_fork_bar_header(label: &str, width: usize) -> String {
    let label_width = label.chars().count();
    if label_width >= width {
        return label.to_string();
    }
    format!("{label}{}", " ".repeat(width - label_width))
}

fn truncate_fork_label(value: &str, max: usize) -> String {
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
pub(crate) struct SilentIcmpProber;

#[cfg(test)]
impl IcmpProber for SilentIcmpProber {
    fn probe(&self, _addr: IpAddr, _timeout: std::time::Duration) -> dns_resolve::IcmpProbeResult {
        dns_resolve::IcmpProbeResult::Unavailable
    }
}

#[cfg(test)]
impl Default for SilentIcmpProber {
    fn default() -> Self {
        Self
    }
}

#[cfg(test)]
fn display_index(text: &str, needle: &str) -> usize {
    let byte = text
        .find(needle)
        .unwrap_or_else(|| panic!("missing {needle}"));
    display_width(&text[..byte])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RttBarConfig;
    use crate::explore::rtt_bar::max_rtt_ms_for_visible;
    use dns_resolve::{
        HopOutcome, IcmpMethod, IcmpSnapshot, TraceHop, TraceTreeRequest, build_linear_tree,
    };
    use std::collections::BTreeMap;
    use std::net::IpAddr;

    fn hop(zone: &str, server: &str, rtt_ms: u64) -> TraceHop {
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
            outcome: HopOutcome::Referral,
        }
    }

    #[test]
    fn columns_align_identity_and_rcode_fields() {
        let trace = build_linear_tree(
            vec![
                hop(".", "198.41.0.4", 12),
                hop("com.", "192.41.162.30", 200),
            ],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-08-25T00:00:00Z".into(),
            },
        );
        let tree = super::super::tree::build_explore_tree(&trace);
        let visible = tree.visible_nodes(&tree.default_expanded_paths());
        let rtt_config = RttBarConfig::default();
        let theme = Theme::from_env();
        let columns = CompareColumns::for_visible(&tree, &visible, rtt_config, &theme);
        let scale_max_rtt_ms = max_rtt_ms_for_visible(&tree, &visible);
        let targets = BTreeMap::new();
        let row = compare_row(
            &visible[1],
            &tree,
            false,
            false,
            columns,
            &targets,
            RttBarConfig::default(),
            scale_max_rtt_ms,
            &theme,
        )
        .expect("row");
        let text = row
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert!(text.contains("[com.]"));
        assert!(text.contains("192.41.162.30"));
        assert!(text.contains("NOERROR"));
        assert!(text.contains("200ms"));
    }

    #[test]
    fn identity_indents_with_tree_depth() {
        let trace = build_linear_tree(
            vec![
                hop(".", "198.41.0.4", 96),
                hop("org.", "199.249.112.1", 100),
                hop("tuininga.org.", "213.133.100.98", 108),
            ],
            TraceTreeRequest {
                qname: "tuininga.org.".into(),
                qtype: "A".into(),
                started_at: "2026-08-25T00:00:00Z".into(),
            },
        );
        let tree = super::super::tree::build_explore_tree(&trace);
        let expanded = tree.default_expanded_paths();
        let visible = tree.visible_nodes(&expanded);
        let rtt_config = RttBarConfig::default();
        let theme = Theme::from_env();
        let columns = CompareColumns::for_visible(&tree, &visible, rtt_config, &theme);
        let scale_max_rtt_ms = max_rtt_ms_for_visible(&tree, &visible);
        let targets = BTreeMap::new();
        let shallow = compare_row(
            &visible[0],
            &tree,
            false,
            false,
            columns,
            &targets,
            RttBarConfig::default(),
            scale_max_rtt_ms,
            &theme,
        )
        .expect("row");
        let deep = compare_row(
            &visible[visible.len() - 1],
            &tree,
            false,
            false,
            columns,
            &targets,
            RttBarConfig::default(),
            scale_max_rtt_ms,
            &theme,
        )
        .expect("row");

        let shallow_text: String = shallow
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();
        let deep_text: String = deep
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();

        assert!(
            display_index(&deep_text, "[") > display_index(&shallow_text, "["),
            "deeper hops should indent identity further right"
        );

        let rcode_offset = columns.tree_column_width + 2;
        assert_eq!(display_index(&shallow_text, "NOERROR"), rcode_offset);
        assert_eq!(display_index(&deep_text, "NOERROR"), rcode_offset);
    }

    #[test]
    fn fork_nodes_show_expand_marker_and_branch_dot() {
        let fork_tree = super::super::tree::build_explore_tree(&dns_resolve::TraceTree {
            request: TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-08-25T00:00:00Z".into(),
            },
            root: dns_resolve::TraceNode {
                hop: hop(".", "1.1.1.1", 10),
                origin: dns_resolve::NodeOrigin::Trace,
                children: vec![
                    dns_resolve::TraceNode {
                        hop: hop("com.", "192.0.2.10", 10),
                        origin: dns_resolve::NodeOrigin::Trace,
                        children: vec![],
                    },
                    dns_resolve::TraceNode {
                        hop: hop("com.", "192.0.2.11", 20),
                        origin: dns_resolve::NodeOrigin::Trace,
                        children: vec![],
                    },
                ],
            },
            budget_truncated: false,
        });
        let visible = fork_tree.visible_nodes(&fork_tree.default_expanded_paths());
        let root = visible.first().expect("root");
        let theme = Theme::from_env();
        let marker = compare_tree_marker(root, &fork_tree, &theme);
        assert!(
            marker.contains('•'),
            "fork rows should include a branch marker"
        );
        assert!(
            marker.contains(theme.symbols.tree_expand.trim())
                || marker.contains(theme.symbols.tree_collapse.trim()),
            "fork rows should show expand/collapse state"
        );
    }

    #[test]
    fn rtt_latency_bar_sits_between_rtt_and_icmp_columns() {
        let trace = build_linear_tree(
            vec![hop(".", "1.1.1.1", 12)],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-08-25T00:00:00Z".into(),
            },
        );
        let tree = super::super::tree::build_explore_tree(&trace);
        let visible = tree.visible_nodes(&[]);
        let rtt_config = RttBarConfig::default();
        let theme = Theme::from_env();
        let columns = CompareColumns::for_visible(&tree, &visible, rtt_config, &theme);
        let mut targets = BTreeMap::new();
        targets.insert(
            "1.1.1.1".parse::<IpAddr>().expect("ip"),
            crate::session::TargetEnrichments {
                icmp: Some(IcmpSnapshot {
                    method: IcmpMethod::Datagram,
                    samples: 1,
                    min_ms: 4,
                    avg_ms: 5,
                    max_ms: 6,
                    probed_at: "2026-09-06T00:00:00Z".into(),
                }),
                ..Default::default()
            },
        );
        let row = compare_row(
            &visible[0],
            &tree,
            false,
            false,
            columns,
            &targets,
            rtt_config,
            max_rtt_ms_for_visible(&tree, &visible),
            &theme,
        )
        .expect("row");
        let joined: String = row.spans.iter().map(|span| span.content.as_ref()).collect();
        let rtt_pos = joined.find("12ms").expect("dns rtt");
        let bar_pos = joined.find('█').expect("rtt latency bar");
        let icmp_pos = joined.find("5ms").expect("icmp rtt");
        assert!(rtt_pos < bar_pos);
        assert!(bar_pos < icmp_pos);
    }

    #[test]
    fn icmp_column_reads_session_targets() {
        let trace = build_linear_tree(
            vec![hop(".", "1.1.1.1", 12)],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-08-25T00:00:00Z".into(),
            },
        );
        let tree = super::super::tree::build_explore_tree(&trace);
        let visible = tree.visible_nodes(&[]);
        let rtt_config = RttBarConfig::default();
        let theme = Theme::from_env();
        let columns = CompareColumns::for_visible(&tree, &visible, rtt_config, &theme);
        let mut targets = BTreeMap::new();
        targets.insert(
            "1.1.1.1".parse::<IpAddr>().expect("ip"),
            crate::session::TargetEnrichments {
                icmp: Some(IcmpSnapshot {
                    method: IcmpMethod::Datagram,
                    samples: 1,
                    min_ms: 4,
                    avg_ms: 5,
                    max_ms: 6,
                    probed_at: "2026-09-06T00:00:00Z".into(),
                }),
                ..Default::default()
            },
        );
        let row = compare_row(
            &visible[0],
            &tree,
            false,
            false,
            columns,
            &targets,
            RttBarConfig::default(),
            max_rtt_ms_for_visible(&tree, &visible),
            &theme,
        )
        .expect("row");
        let text = row
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert!(text.contains("5ms"));
    }

    #[test]
    fn selected_row_styles_all_fields_except_rtt_bar() {
        let trace = build_linear_tree(
            vec![hop(".", "198.41.0.4", 96)],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-08-25T00:00:00Z".into(),
            },
        );
        let tree = super::super::tree::build_explore_tree(&trace);
        let visible = tree.visible_nodes(&[]);
        let theme = Theme::from_env();
        let columns = CompareColumns::for_visible(&tree, &visible, RttBarConfig::default(), &theme);
        let selected_style = theme.tree_selected();
        let row = compare_row(
            &visible[0],
            &tree,
            true,
            false,
            columns,
            &BTreeMap::new(),
            RttBarConfig::default(),
            max_rtt_ms_for_visible(&tree, &visible),
            &theme,
        )
        .expect("row");

        for (index, span) in row.spans.iter().enumerate() {
            let content = span.content.as_ref();
            if content.chars().all(|ch| ch == '█' || ch == '░') {
                assert_ne!(span.style, selected_style);
                continue;
            }
            assert_eq!(span.style, selected_style, "span {index}: {content:?}");
        }
    }

    #[test]
    fn shows_effective_server_name_for_root_hints() {
        let trace = build_linear_tree(
            vec![hop(".", "198.41.0.4", 96)],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-08-25T00:00:00Z".into(),
            },
        );
        let tree = super::super::tree::build_explore_tree(&trace);
        let visible = tree.visible_nodes(&[]);
        let rtt_config = RttBarConfig::default();
        let theme = Theme::from_env();
        let columns = CompareColumns::for_visible(&tree, &visible, rtt_config, &theme);
        let scale_max_rtt_ms = max_rtt_ms_for_visible(&tree, &visible);
        let row = compare_row(
            &visible[0],
            &tree,
            false,
            false,
            columns,
            &BTreeMap::new(),
            rtt_config,
            scale_max_rtt_ms,
            &theme,
        )
        .expect("row");
        let text = row
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert!(text.contains("a.root-servers.net"));
        assert!(text.contains("198.41.0.4"));
    }

    fn fork_compare_tree(child_count: usize) -> ExploreTree {
        use dns_resolve::{NodeOrigin, TraceNode, TraceTree};

        let children = (0..child_count)
            .map(|index| dns_resolve::TraceNode {
                hop: TraceHop {
                    zone: "example.com.".into(),
                    server: format!("192.0.2.{}", index + 1),
                    server_name: None,
                    qname: "example.com.".into(),
                    qtype: "A".into(),
                    transport: "udp".into(),
                    rtt_ms: 10 + index as u64,
                    rcode: "NOERROR".into(),
                    nsid: None,
                    ede_code: None,
                    ede_text: None,
                    referral_ns: vec![],
                    glue: vec![],
                    response: Default::default(),
                    from_cache: false,
                    outcome: HopOutcome::Answered,
                },
                origin: NodeOrigin::Trace,
                children: vec![],
            })
            .collect();
        let tree = TraceTree {
            request: TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
            root: TraceNode {
                hop: TraceHop {
                    zone: "org.".into(),
                    server: "199.19.56.1".into(),
                    server_name: None,
                    qname: "example.com.".into(),
                    qtype: "A".into(),
                    transport: "udp".into(),
                    rtt_ms: 12,
                    rcode: "NOERROR".into(),
                    nsid: None,
                    ede_code: None,
                    ede_text: None,
                    referral_ns: vec![],
                    glue: vec![],
                    response: Default::default(),
                    from_cache: false,
                    outcome: HopOutcome::Referral,
                },
                origin: NodeOrigin::Trace,
                children,
            },
            budget_truncated: false,
        };
        super::super::tree::build_explore_tree(&tree)
    }

    #[test]
    fn fork_compare_is_scoped_to_fork_children() {
        let tree = fork_compare_tree(3);
        let model = ForkCompareModel::from_tree(
            &tree,
            &NodePath::root(0),
            &BTreeMap::new(),
            &SilentIcmpProber,
            false,
        )
        .expect("model");
        assert_eq!(model.rows().len(), 3);
        assert_eq!(model.comparison.fork_zone, "org.");
    }

    #[test]
    fn fork_compare_row_maps_to_node_path() {
        let tree = fork_compare_tree(3);
        let mut model = ForkCompareModel::from_tree(
            &tree,
            &NodePath {
                tree: 0,
                path: vec![2],
            },
            &BTreeMap::new(),
            &SilentIcmpProber,
            false,
        )
        .expect("model");
        assert_eq!(model.row, 2);
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
    fn fork_compare_scroll_keeps_selected_row_visible() {
        let viewport = ForkCompareViewport {
            header_lines: 3,
            inner_height: 8,
        };
        assert_eq!(scroll_fork_compare_row(0, viewport, 0), 0);
        assert_eq!(scroll_fork_compare_row(5, viewport, 0), 1);
    }

    #[test]
    fn fork_compare_unavailable_without_sibling_paths() {
        let tree = fork_compare_tree(1);
        assert!(
            ForkCompareModel::from_tree(
                &tree,
                &NodePath::root(0),
                &BTreeMap::new(),
                &SilentIcmpProber,
                false,
            )
            .is_none()
        );
    }
}
