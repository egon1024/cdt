use ratatui::text::{Line, Span};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use dns_resolve::HopOutcome;

use crate::config::RttBarConfig;

use super::rtt_bar::rtt_bar_spans;
use super::theme::Theme;
use super::tree::{ExploreTree, VisibleNode};

#[derive(Debug, Clone, Copy)]
pub struct CompareColumns {
    pub zone_width: usize,
    pub server_width: usize,
    pub rcode_width: usize,
    pub rtt_width: usize,
}

impl CompareColumns {
    pub const MAX_ZONE_WIDTH: usize = 20;
    pub const MAX_SERVER_WIDTH: usize = 28;
    pub const MIN_RCODE_WIDTH: usize = 7;

    pub fn for_visible(tree: &ExploreTree, visible: &[VisibleNode]) -> Self {
        let mut zone_width = 4;
        let mut server_width = 6;
        let mut rcode_width = Self::MIN_RCODE_WIDTH;

        for node in visible {
            let hop = tree.hop_at(&node.path).expect("visible hop");
            zone_width = zone_width.max(hop.zone.chars().count());
            server_width = server_width.max(hop.server.chars().count());
            if matches!(hop.outcome, HopOutcome::Failed { .. }) {
                rcode_width = rcode_width.max(6);
            } else {
                rcode_width = rcode_width.max(hop.rcode.chars().count());
            }
        }

        Self {
            zone_width: zone_width.min(Self::MAX_ZONE_WIDTH),
            server_width: server_width.min(Self::MAX_SERVER_WIDTH),
            rcode_width,
            rtt_width: 7,
        }
    }

    pub fn header(self, theme: &Theme) -> Line<'static> {
        Line::from(vec![
            Span::raw("  "),
            Span::styled(pad_left("zone", self.zone_width), theme.label()),
            Span::raw("  "),
            Span::styled(pad_left("server", self.server_width), theme.label()),
            Span::raw("  "),
            Span::styled(pad_left("rcode", self.rcode_width), theme.label()),
            Span::raw("  "),
            Span::styled(pad_left("rtt", self.rtt_width), theme.label()),
            Span::raw("  "),
            Span::styled("latency", theme.label()),
        ])
    }
}

pub fn compare_row(
    node: &VisibleNode,
    tree: &ExploreTree,
    selected: bool,
    columns: CompareColumns,
    rtt_config: RttBarConfig,
    theme: &Theme,
) -> Line<'static> {
    let hop = tree.hop_at(&node.path).expect("visible hop");
    let indent = "  ".repeat(node.depth);
    let marker = if selected {
        ">"
    } else if node.expandable && children_count(node, tree) >= 2 {
        "•"
    } else if node.expandable {
        if node.expanded {
            theme.symbols.tree_expand
        } else {
            theme.symbols.tree_collapse
        }
    } else {
        " "
    };

    let failed = matches!(hop.outcome, HopOutcome::Failed { .. });
    let row_style = if selected {
        theme.tree_selected()
    } else if failed {
        theme.failure()
    } else {
        theme.meta()
    };

    let zone = truncate_field(&hop.zone, columns.zone_width);
    let server = truncate_field(&hop.server, columns.server_width);
    let rcode = if failed {
        pad_left("FAILED", columns.rcode_width)
    } else {
        pad_left(&hop.rcode, columns.rcode_width)
    };
    let rtt = pad_left(format!("{}ms", hop.rtt_ms), columns.rtt_width);

    let mut spans = vec![
        Span::styled(format!("{indent}{marker} "), row_style),
        Span::styled(pad_left(zone, columns.zone_width), theme.zone()),
        Span::raw("  "),
        Span::styled(pad_left(server, columns.server_width), row_style),
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
    ];
    spans.extend(rtt_bar_spans(
        hop.rtt_ms.min(u32::MAX as u64) as u32,
        rtt_config,
        theme,
    ));

    Line::from(spans)
}

fn children_count(node: &VisibleNode, tree: &ExploreTree) -> usize {
    tree.node_at(&node.path)
        .map(|trace_node| trace_node.children.len())
        .unwrap_or(0)
}

fn pad_left(value: impl std::fmt::Display, width: usize) -> String {
    let text = value.to_string();
    let display_width = UnicodeWidthStr::width(text.as_str());
    if display_width >= width {
        return text;
    }
    format!("{:>width$}", text, width = width)
}

fn truncate_field(value: &str, max_width: usize) -> String {
    if UnicodeWidthStr::width(value) <= max_width {
        return value.to_string();
    }
    let mut end = 0;
    let mut width = 0;
    for ch in value.chars() {
        let ch_width = UnicodeWidthChar::width(ch).unwrap_or(0);
        if width + ch_width > max_width.saturating_sub(1) {
            break;
        }
        width += ch_width;
        end += ch.len_utf8();
    }
    format!("{}…", &value[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RttBarConfig;
    use dns_resolve::{HopOutcome, TraceHop, TraceTreeRequest, build_linear_tree};

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
    fn columns_align_server_and_rcode_fields() {
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
        let columns = CompareColumns::for_visible(&tree, &visible);
        let theme = Theme::from_env();
        let row = compare_row(
            &visible[1],
            &tree,
            false,
            columns,
            RttBarConfig::default(),
            &theme,
        );
        let text = row
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert!(text.contains("192.41.162.30"));
        assert!(text.contains("NOERROR"));
        assert!(text.contains("200ms"));
    }

    #[test]
    fn header_and_rows_share_column_widths() {
        let trace = build_linear_tree(
            vec![hop("com.", "short", 5)],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-08-25T00:00:00Z".into(),
            },
        );
        let tree = super::super::tree::build_explore_tree(&trace);
        let visible = tree.visible_nodes(&[]);
        let columns = CompareColumns::for_visible(&tree, &visible);
        let header = columns.header(&Theme::from_env());
        let row = compare_row(
            &visible[0],
            &tree,
            false,
            columns,
            RttBarConfig::default(),
            &Theme::from_env(),
        );
        assert!(!header.spans.is_empty());
        assert!(!row.spans.is_empty());
    }
}
