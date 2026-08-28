use super::tree::{ExploreNode, ExploreTree};

pub fn render_tree_json(tree: &ExploreTree, session_id: &str) -> String {
    let payload = serde_json::json!({
        "event": "explore_tree",
        "session": session_id,
        "qname": tree.qname,
        "qtype": tree.qtype,
        "tree": tree
            .children
            .iter()
            .map(|node| json_value(tree, node))
            .collect::<Vec<_>>(),
    });
    serde_json::to_string(&payload).expect("json")
}

fn json_value(tree: &ExploreTree, node: &ExploreNode) -> serde_json::Value {
    match node {
        ExploreNode::Delegation {
            hop_index,
            children,
        } => serde_json::json!({
            "kind": "delegation",
            "hop": tree.hop(*hop_index),
            "children": children.iter().map(|child| json_value(tree, child)).collect::<Vec<_>>(),
        }),
        ExploreNode::Resolve { target, children } => serde_json::json!({
            "kind": "resolve",
            "target": target,
            "children": children.iter().map(|child| json_value(tree, child)).collect::<Vec<_>>(),
        }),
        ExploreNode::Hop { hop_index } => serde_json::json!({
            "kind": "hop",
            "hop": tree.hop(*hop_index),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::explore::tree::build_explore_tree;
    use dns_resolve::{HopOutcome, TraceHop, TraceTreeRequest, build_linear_tree};

    #[test]
    fn json_includes_session_and_tree() {
        let trace = build_linear_tree(
            vec![TraceHop {
                zone: ".".into(),
                server: "1.1.1.1".into(),
                server_name: None,
                qname: "example.com.".into(),
                qtype: "A".into(),
                transport: "udp".into(),
                rtt_ms: 10,
                rcode: "NOERROR".into(),
                nsid: None,
                ede_code: None,
                ede_text: None,
                referral_ns: vec![],
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
        );
        let tree = build_explore_tree(&trace);
        let json = render_tree_json(&tree, "01JTEST");
        assert!(json.contains("\"event\":\"explore_tree\""));
        assert!(json.contains("\"session\":\"01JTEST\""));
        assert!(json.contains("\"kind\":\"delegation\""));
    }
}
