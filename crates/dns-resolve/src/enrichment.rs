//! Helpers for collecting server targets from stored trace trees.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use crate::{TraceNode, TraceTree};

/// Collect unique server IPs from a trace tree with associated hostnames from hops.
pub fn collect_unique_server_targets(tree: &TraceTree) -> BTreeMap<IpAddr, BTreeSet<String>> {
    let mut targets = BTreeMap::new();
    collect_from_node(&tree.root, &mut targets);
    targets
}

fn collect_from_node(node: &TraceNode, targets: &mut BTreeMap<IpAddr, BTreeSet<String>>) {
    if let Ok(ip) = node.hop.server.parse::<IpAddr>() {
        let entry = targets.entry(ip).or_default();
        if let Some(name) = node.hop.server_name.as_deref() {
            if !name.is_empty() {
                entry.insert(name.to_string());
            }
        }
    }
    for child in &node.children {
        collect_from_node(child, targets);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        HopOutcome, NodeOrigin, TraceHop, TraceTreeRequest, build_linear_tree, tree::TraceNode,
    };

    fn hop(server: &str, server_name: Option<&str>) -> TraceHop {
        TraceHop {
            zone: ".".into(),
            server: server.into(),
            server_name: server_name.map(str::to_string),
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
        }
    }

    #[test]
    fn collects_unique_ips_from_linear_tree() {
        let tree = build_linear_tree(
            vec![hop("1.1.1.1", Some("one.example.com."))],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-09-06T00:00:00Z".into(),
            },
        );
        let targets = collect_unique_server_targets(&tree);
        assert_eq!(targets.len(), 1);
        let names = targets.get(&"1.1.1.1".parse().unwrap()).expect("ip");
        assert!(names.contains("one.example.com."));
    }

    #[test]
    fn deduplicates_repeated_ips_on_branched_tree() {
        let tree = TraceTree {
            request: TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-09-06T00:00:00Z".into(),
            },
            root: TraceNode {
                hop: hop("1.1.1.1", Some("ns1.example.com.")),
                origin: NodeOrigin::Trace,
                children: vec![
                    TraceNode {
                        hop: hop("8.8.8.8", Some("ns.google.")),
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    },
                    TraceNode {
                        hop: hop("1.1.1.1", Some("NS1.EXAMPLE.COM.")),
                        origin: NodeOrigin::Branch {
                            at: crate::NodePath::root(0),
                            intent: crate::tree::BranchIntent::AlternateServer,
                            at_time: "2026-09-06T00:00:00Z".into(),
                        },
                        children: vec![],
                    },
                ],
            },
            budget_truncated: false,
        };
        let targets = collect_unique_server_targets(&tree);
        assert_eq!(targets.len(), 2);
        let root_names = targets.get(&"1.1.1.1".parse().unwrap()).expect("1.1.1.1");
        assert_eq!(root_names.len(), 2);
        assert!(root_names.contains("ns1.example.com."));
        assert!(root_names.contains("NS1.EXAMPLE.COM."));
    }
}
