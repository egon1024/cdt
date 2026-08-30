use ratatui::text::{Line, Span};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use dns_resolve::HopOutcome;

use crate::config::RttBarConfig;

use super::detail::effective_server_name;
use super::rtt_bar::rtt_bar_spans;
use super::theme::Theme;
use super::tree::{ExploreTree, VisibleNode};

#[derive(Debug, Clone, Copy)]
pub struct CompareColumns {
    pub prefix_width: usize,
    pub zone_width: usize,
    pub server_width: usize,
    pub server_name_width: usize,
    pub rcode_width: usize,
    pub rtt_width: usize,
}

impl CompareColumns {
    pub const MAX_ZONE_WIDTH: usize = 20;
    pub const MAX_SERVER_WIDTH: usize = 28;
    pub const MAX_SERVER_NAME_WIDTH: usize = 28;
    pub const MIN_SERVER_NAME_WIDTH: usize = 4;
    pub const MIN_RCODE_WIDTH: usize = 7;
    pub const INDENT_WIDTH: usize = 2;

    pub fn for_visible(tree: &ExploreTree, visible: &[VisibleNode]) -> Self {
        let max_depth = visible.iter().map(|node| node.depth).max().unwrap_or(0);
        let prefix_width = max_depth * Self::INDENT_WIDTH + 2;

        let mut zone_width = 4;
        let mut server_width = 6;
        let mut server_name_width = Self::MIN_SERVER_NAME_WIDTH;
        let mut rcode_width = Self::MIN_RCODE_WIDTH;

        for node in visible {
            let hop = tree.hop_at(&node.path).expect("visible hop");
            zone_width = zone_width.max(display_width(hop.zone.as_str()));
            server_width = server_width.max(display_width(hop.server.as_str()));
            server_name_width =
                server_name_width.max(display_width(hop_server_name(hop).as_str()));
            if matches!(hop.outcome, HopOutcome::Failed { .. }) {
                rcode_width = rcode_width.max(display_width("FAILED"));
            } else {
                rcode_width = rcode_width.max(display_width(hop.rcode.as_str()));
            }
        }

        Self {
            prefix_width,
            zone_width: zone_width.min(Self::MAX_ZONE_WIDTH),
            server_width: server_width.min(Self::MAX_SERVER_WIDTH),
            server_name_width: server_name_width.min(Self::MAX_SERVER_NAME_WIDTH),
            rcode_width,
            rtt_width: 7,
        }
    }

    pub fn header(self, theme: &Theme) -> Line<'static> {
        Line::from(vec![
            Span::raw(format_prefix(0, "", self.prefix_width)),
            Span::styled(pad_left_display("zone", self.zone_width), theme.label()),
            Span::raw("  "),
            Span::styled(pad_left_display("server", self.server_width), theme.label()),
            Span::raw("  "),
            Span::styled(pad_left_display("name", self.server_name_width), theme.label()),
            Span::raw("  "),
            Span::styled(pad_left_display("rcode", self.rcode_width), theme.label()),
            Span::raw("  "),
            Span::styled(pad_left_display("rtt", self.rtt_width), theme.label()),
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
    let server_name = truncate_field(&hop_server_name(hop), columns.server_name_width);
    let rcode = if failed {
        pad_left_display("FAILED", columns.rcode_width)
    } else {
        pad_left_display(&hop.rcode, columns.rcode_width)
    };
    let rtt = pad_left_display(format!("{}ms", hop.rtt_ms), columns.rtt_width);

    let mut spans = vec![
        Span::styled(
            format_prefix(node.depth, marker, columns.prefix_width),
            row_style,
        ),
        Span::styled(pad_left_display(zone, columns.zone_width), theme.zone()),
        Span::raw("  "),
        Span::styled(pad_left_display(server, columns.server_width), row_style),
        Span::raw("  "),
        Span::styled(
            pad_left_display(server_name, columns.server_name_width),
            theme.label(),
        ),
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

fn hop_server_name(hop: &dns_resolve::TraceHop) -> String {
    effective_server_name(&hop.server, hop.server_name.as_deref()).unwrap_or_default()
}

fn children_count(node: &VisibleNode, tree: &ExploreTree) -> usize {
    tree.node_at(&node.path)
        .map(|trace_node| trace_node.children.len())
        .unwrap_or(0)
}

fn format_prefix(depth: usize, marker: &str, prefix_width: usize) -> String {
    let indent = "  ".repeat(depth);
    let content = format!("{indent}{marker}");
    let content_width = display_width(content.as_str());
    if content_width >= prefix_width {
        return content;
    }
    format!("{}{}", content, " ".repeat(prefix_width - content_width))
}

fn display_width(text: &str) -> usize {
    UnicodeWidthStr::width(text)
}

fn pad_left_display(value: impl std::fmt::Display, width: usize) -> String {
    let text = value.to_string();
    let text_width = display_width(text.as_str());
    if text_width >= width {
        return text;
    }
    format!("{}{}", " ".repeat(width - text_width), text)
}

fn truncate_field(value: &str, max_width: usize) -> String {
    if display_width(value) <= max_width {
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
fn column_starts(line: &Line) -> Vec<usize> {
    let mut starts = Vec::new();
    let mut offset = 0;
    for span in &line.spans {
        starts.push(offset);
        offset += display_width(span.content.as_ref());
    }
    starts.push(offset);
    starts
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
    fn header_and_rows_align_columns_at_different_depths() {
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
        let columns = CompareColumns::for_visible(&tree, &visible);
        let theme = Theme::from_env();
        let header = columns.header(&theme);
        let shallow = compare_row(
            &visible[0],
            &tree,
            false,
            columns,
            RttBarConfig::default(),
            &theme,
        );
        let deep = compare_row(
            &visible[visible.len() - 1],
            &tree,
            true,
            columns,
            RttBarConfig::default(),
            &theme,
        );

        let header_starts = column_starts(&header);
        let shallow_starts = column_starts(&shallow);
        let deep_starts = column_starts(&deep);

        assert_eq!(header_starts[1], shallow_starts[1]);
        assert_eq!(header_starts[1], deep_starts[1]);
        assert_eq!(header_starts[3], shallow_starts[3]);
        assert_eq!(header_starts[3], deep_starts[3]);
        assert_eq!(header_starts[5], shallow_starts[5]);
        assert_eq!(header_starts[5], deep_starts[5]);
        assert_eq!(header_starts[7], shallow_starts[7]);
        assert_eq!(header_starts[7], deep_starts[7]);
        assert_eq!(header_starts[9], shallow_starts[9]);
        assert_eq!(header_starts[9], deep_starts[9]);
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
        let columns = CompareColumns::for_visible(&tree, &visible);
        let row = compare_row(
            &visible[0],
            &tree,
            false,
            columns,
            RttBarConfig::default(),
            &Theme::from_env(),
        );
        let text = row
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert!(text.contains("a.root-servers.net"));
    }
}
