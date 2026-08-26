use super::detail::{
    final_detail_lines, hop_detail_lines, hop_summary_line, render_indented_block,
};
use super::tree::{ExploreNode, ExploreTree};

pub fn render_outline(tree: &ExploreTree) -> String {
    let mut output = String::new();
    output.push_str(&format!("{} {}\n", tree.qname, tree.qtype));

    let child_count = tree.children.len();
    for (index, child) in tree.children.iter().enumerate() {
        let last = index + 1 == child_count;
        render_node(tree, child, "", last, &mut output);
    }

    output
}

fn render_node(
    tree: &ExploreTree,
    node: &ExploreNode,
    prefix: &str,
    last: bool,
    output: &mut String,
) {
    let branch = if last { "└─ " } else { "├─ " };
    let child_prefix = format!("{}{}", prefix, if last { "   " } else { "│  " });
    let detail_indent = format!("{child_prefix}   ");

    match node {
        ExploreNode::Delegation {
            hop_index,
            children,
        } => {
            let hop = tree.hop(*hop_index);
            output.push_str(&format!("{prefix}{branch}{}\n", hop_summary_line(hop)));
            output.push_str(&render_indented_block(
                &hop_detail_lines(hop),
                &detail_indent,
            ));
            render_children(tree, children, &child_prefix, output);
        }
        ExploreNode::Resolve { target, children } => {
            output.push_str(&format!("{prefix}{branch}(resolve {target})\n"));
            render_children(tree, children, &child_prefix, output);
        }
        ExploreNode::Hop { hop_index } => {
            let hop = tree.hop(*hop_index);
            output.push_str(&format!("{prefix}{branch}{}\n", hop_summary_line(hop)));
            output.push_str(&render_indented_block(
                &hop_detail_lines(hop),
                &detail_indent,
            ));
        }
        ExploreNode::Final => {
            output.push_str(&format!("{prefix}{branch}final\n"));
            if let Some(answer) = tree.trace().final_response.as_ref() {
                output.push_str(&render_indented_block(
                    &final_detail_lines(answer),
                    &detail_indent,
                ));
            } else {
                output.push_str(&format!("{detail_indent}—\n"));
            }
        }
    }
}

fn render_children(
    tree: &ExploreTree,
    children: &[ExploreNode],
    prefix: &str,
    output: &mut String,
) {
    let child_count = children.len();
    for (index, child) in children.iter().enumerate() {
        let last = index + 1 == child_count;
        render_node(tree, child, prefix, last, output);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::explore::tree::build_explore_tree;
    use dns_resolve::{FinalAnswer, TraceHop, TraceResult};

    fn sample_trace() -> TraceResult {
        TraceResult {
            qname: "example.com.".into(),
            qtype: "A".into(),
            started_at: "2026-08-25T00:00:00Z".into(),
            hops: vec![TraceHop {
                zone: ".".into(),
                server: "198.41.0.4".into(),
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
            }],
            final_response: Some(FinalAnswer {
                server: "93.184.216.34".into(),
                rtt_ms: 5,
                rcode: "NOERROR".into(),
                records: vec!["example.com. 300 93.184.216.34".into()],
                nsid: None,
                qname: String::new(),
                qtype: String::new(),
                transport: String::new(),
                response: Default::default(),
            }),
        }
    }

    #[test]
    fn outline_uses_yaml_style_lists() {
        let tree = build_explore_tree(&sample_trace());
        let outline = render_outline(&tree);
        assert!(outline.starts_with("example.com. A\n"));
        assert!(outline.contains("referral NS:\n"));
        assert!(outline.contains("  - a.gtld-servers.net."));
        assert!(outline.contains("records:\n"));
        assert!(outline.contains("  - example.com. 300 93.184.216.34"));
    }
}
