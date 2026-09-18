use dns_resolve::TraceNode;

use super::tree::ExploreTree;

pub fn render_tree_json(tree: &ExploreTree, session_id: &str) -> String {
    let payload = serde_json::json!({
        "event": "explore_tree",
        "session": session_id,
        "qname": tree.qname,
        "qtype": tree.qtype,
        "tree": json_node(&tree.tree.root),
    });
    serde_json::to_string(&payload).expect("json")
}

fn json_node(node: &TraceNode) -> serde_json::Value {
    serde_json::json!({
        "hop": node.hop,
        "origin": node.origin,
        "children": node.children.iter().map(json_node).collect::<Vec<_>>(),
    })
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
        assert!(json.contains("\"hop\""));
        assert!(json.contains("\"children\""));
    }
}
