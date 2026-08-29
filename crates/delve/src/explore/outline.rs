use std::collections::HashMap;

use super::detail::{hop_detail_lines, hop_summary_line, render_indented_block};
use super::terminal::UiSymbols;
use super::tree::ExploreTree;
use dns_resolve::{TraceNode, TraceTree};

pub fn render_trace_outline(tree: &TraceTree, symbols: UiSymbols) -> String {
    let mut indices = HashMap::new();
    for (index, path) in tree.display_order().into_iter().enumerate() {
        indices.insert(path.path, index);
    }
    let mut output = format!("{} {}\n", tree.qname(), tree.qtype());
    render_trace_node(&tree.root, &[], true, &indices, "", symbols, &mut output);
    output
}

fn render_trace_node(
    node: &TraceNode,
    path: &[usize],
    last: bool,
    indices: &HashMap<Vec<usize>, usize>,
    prefix: &str,
    symbols: UiSymbols,
    output: &mut String,
) {
    let branch = if last {
        symbols.branch_end
    } else {
        symbols.branch_tee
    };
    let child_prefix = format!(
        "{}{}",
        prefix,
        if last { "   " } else { symbols.branch_pipe }
    );
    let detail_indent = format!("{child_prefix}   ");
    let display_index = indices.get(path).copied().unwrap_or(0);

    output.push_str(&format!(
        "{prefix}{branch}[{display_index}] {}\n",
        hop_summary_line(&node.hop, symbols)
    ));
    output.push_str(&render_indented_block(
        &hop_detail_lines(&node.hop, symbols),
        &detail_indent,
    ));

    let child_count = node.children.len();
    for (index, child) in node.children.iter().enumerate() {
        let mut child_path = path.to_vec();
        child_path.push(index);
        render_trace_node(
            child,
            &child_path,
            index + 1 == child_count,
            indices,
            &child_prefix,
            symbols,
            output,
        );
    }
}

pub fn render_outline(tree: &ExploreTree, symbols: UiSymbols) -> String {
    render_trace_outline(tree.trace(), symbols)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::explore::terminal::UNICODE;
    use crate::explore::tree::build_explore_tree;
    use dns_resolve::{HopOutcome, TraceHop, TraceTreeRequest, build_linear_tree};

    fn sample_trace() -> dns_resolve::TraceTree {
        build_linear_tree(
            vec![TraceHop {
                zone: ".".into(),
                server: "198.41.0.4".into(),
                server_name: None,
                qname: "example.com.".into(),
                qtype: "A".into(),
                transport: "udp".into(),
                rtt_ms: 11,
                rcode: "NOERROR".into(),
                nsid: None,
                ede_code: None,
                ede_text: None,
                referral_ns: vec!["a.gtld-servers.net.".into(), "b.gtld-servers.net.".into()],
                glue: vec![],
                response: Default::default(),
                from_cache: false,
                outcome: HopOutcome::Answered,
            }],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-08-25T00:00:00Z".into(),
            },
        )
    }

    #[test]
    fn outline_uses_yaml_style_lists() {
        let tree = build_explore_tree(&sample_trace());
        let outline = render_outline(&tree, UNICODE);
        assert!(outline.starts_with("example.com. A\n"));
        assert!(outline.contains("referral NS:\n"));
        assert!(outline.contains("  - a.gtld-servers.net."));
    }

    #[test]
    fn outline_prints_display_indices() {
        let tree = build_explore_tree(&sample_trace());
        let outline = render_outline(&tree, UNICODE);
        assert!(outline.contains("[0]"));
    }
}
