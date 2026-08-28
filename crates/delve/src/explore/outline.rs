use super::detail::{hop_detail_lines, hop_summary_line, render_indented_block};
use super::terminal::UiSymbols;
use super::tree::{ExploreNode, ExploreTree};

pub fn render_outline(tree: &ExploreTree, symbols: UiSymbols) -> String {
    let mut output = String::new();
    output.push_str(&format!("{} {}\n", tree.qname, tree.qtype));

    let child_count = tree.children.len();
    for (index, child) in tree.children.iter().enumerate() {
        let last = index + 1 == child_count;
        render_node(tree, child, "", last, symbols, &mut output);
    }

    output
}

fn render_node(
    tree: &ExploreTree,
    node: &ExploreNode,
    prefix: &str,
    last: bool,
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

    match node {
        ExploreNode::Delegation {
            hop_index,
            children,
        } => {
            let hop = tree.hop(*hop_index);
            output.push_str(&format!(
                "{prefix}{branch}{}\n",
                hop_summary_line(hop, symbols)
            ));
            output.push_str(&render_indented_block(
                &hop_detail_lines(hop, symbols),
                &detail_indent,
            ));
            render_children(tree, children, &child_prefix, symbols, output);
        }
        ExploreNode::Resolve { target, children } => {
            output.push_str(&format!("{prefix}{branch}(resolve {target})\n"));
            render_children(tree, children, &child_prefix, symbols, output);
        }
        ExploreNode::Hop { hop_index } => {
            let hop = tree.hop(*hop_index);
            output.push_str(&format!(
                "{prefix}{branch}{}\n",
                hop_summary_line(hop, symbols)
            ));
            output.push_str(&render_indented_block(
                &hop_detail_lines(hop, symbols),
                &detail_indent,
            ));
        }
    }
}

fn render_children(
    tree: &ExploreTree,
    children: &[ExploreNode],
    prefix: &str,
    symbols: UiSymbols,
    output: &mut String,
) {
    let child_count = children.len();
    for (index, child) in children.iter().enumerate() {
        let last = index + 1 == child_count;
        render_node(tree, child, prefix, last, symbols, output);
    }
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
}
