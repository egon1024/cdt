use dns_resolve::{TraceHop, TraceNode, TraceTree};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExploreNode {
    Delegation {
        hop_index: usize,
        children: Vec<ExploreNode>,
    },
    Resolve {
        target: String,
        children: Vec<ExploreNode>,
    },
    #[allow(dead_code)]
    Hop { hop_index: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExploreTree {
    pub qname: String,
    pub qtype: String,
    pub children: Vec<ExploreNode>,
    trace: TraceTree,
    hops: Vec<TraceHop>,
}

impl ExploreTree {
    pub fn hop(&self, index: usize) -> &TraceHop {
        &self.hops[index]
    }

    pub fn trace(&self) -> &TraceTree {
        &self.trace
    }
}

pub fn build_explore_tree(trace: &TraceTree) -> ExploreTree {
    build_explore_tree_with_qname(trace, None)
}

pub fn build_explore_tree_with_qname(
    trace: &TraceTree,
    display_qname: Option<&str>,
) -> ExploreTree {
    let mut hops = Vec::new();
    let children = vec![build_from_trace_node(&trace.root, &mut hops)];

    ExploreTree {
        qname: display_qname.unwrap_or_else(|| trace.qname()).to_string(),
        qtype: trace.qtype().to_string(),
        children,
        trace: trace.clone(),
        hops,
    }
}

fn build_from_trace_node(node: &TraceNode, hops: &mut Vec<TraceHop>) -> ExploreNode {
    let hop_index = hops.len();
    hops.push(node.hop.clone());

    let children: Vec<ExploreNode> = node
        .children
        .iter()
        .map(|child| {
            if is_root_zone(&child.hop.zone) {
                ExploreNode::Resolve {
                    target: child.hop.qname.clone(),
                    children: vec![build_from_trace_node(child, hops)],
                }
            } else {
                build_from_trace_node(child, hops)
            }
        })
        .collect();

    ExploreNode::Delegation {
        hop_index,
        children,
    }
}

fn is_root_zone(zone: &str) -> bool {
    zone.trim_end_matches('.').is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::{HopOutcome, TraceHop, TraceNode, TraceTreeRequest, build_linear_tree};

    fn hop(zone: &str, qname: &str, server: &str) -> TraceHop {
        TraceHop {
            zone: zone.into(),
            server: server.into(),
            server_name: None,
            qname: qname.into(),
            qtype: "A".into(),
            transport: "udp".into(),
            rtt_ms: 11,
            rcode: "NOERROR".into(),
            nsid: None,
            ede_code: None,
            ede_text: None,
            referral_ns: vec!["ns.example.com.".into()],
            glue: vec![],
            response: Default::default(),
            from_cache: false,
            outcome: HopOutcome::Referral,
        }
    }

    fn trace_with_hops(qname: &str, hops: Vec<TraceHop>) -> TraceTree {
        let mut hops = hops;
        if let Some(last) = hops.last_mut() {
            last.outcome = HopOutcome::Answered;
        }
        build_linear_tree(
            hops,
            TraceTreeRequest {
                qname: qname.into(),
                qtype: "A".into(),
                started_at: "2026-08-25T00:00:00Z".into(),
            },
        )
    }

    fn trace_with_root(root: TraceNode, qname: &str) -> TraceTree {
        TraceTree {
            request: TraceTreeRequest {
                qname: qname.into(),
                qtype: "A".into(),
                started_at: "2026-08-25T00:00:00Z".into(),
            },
            root,
            budget_truncated: false,
        }
    }

    #[test]
    fn builds_main_path_without_resolution() {
        let tree = build_explore_tree(&trace_with_hops(
            "example.com.",
            vec![
                hop(".", "example.com.", "198.41.0.4"),
                hop("com.", "example.com.", "192.41.162.30"),
            ],
        ));

        let ExploreNode::Delegation {
            hop_index: root_index,
            children,
        } = &tree.children[0]
        else {
            panic!("expected root delegation");
        };
        assert_eq!(*root_index, 0);
        assert_eq!(children.len(), 1);
        assert!(matches!(
            &children[0],
            ExploreNode::Delegation {
                hop_index: 1,
                children
            } if children.is_empty()
        ));
    }

    #[test]
    fn renders_terminal_siblings_from_trace_tree() {
        let mut terminal = hop("example.com.", "example.com.", "93.184.216.34");
        terminal.outcome = HopOutcome::Answered;
        let sibling = hop("example.com.", "example.com.", "93.184.216.35");
        let tree = build_explore_tree(&trace_with_root(
            TraceNode {
                hop: hop(".", "example.com.", "198.41.0.4"),
                origin: dns_resolve::NodeOrigin::Trace,
                children: vec![TraceNode {
                    hop: hop("com.", "example.com.", "192.41.162.30"),
                    origin: dns_resolve::NodeOrigin::Trace,
                    children: vec![
                        TraceNode {
                            hop: terminal,
                            origin: dns_resolve::NodeOrigin::Trace,
                            children: Vec::new(),
                        },
                        TraceNode {
                            hop: sibling,
                            origin: dns_resolve::NodeOrigin::Trace,
                            children: Vec::new(),
                        },
                    ],
                }],
            },
            "example.com.",
        ));

        let ExploreNode::Delegation { children, .. } = &tree.children[0] else {
            panic!("expected root delegation");
        };
        let ExploreNode::Delegation {
            children: terminal_children,
            ..
        } = &children[0]
        else {
            panic!("expected com delegation");
        };
        assert_eq!(terminal_children.len(), 2);
    }

    #[test]
    fn wraps_alias_leg_in_resolve_branch() {
        let alias_leg = TraceNode {
            hop: hop(".", "cdn.example.com.", "198.41.0.4"),
            origin: dns_resolve::NodeOrigin::Trace,
            children: vec![TraceNode {
                hop: {
                    let mut answered = hop("example.com.", "cdn.example.com.", "93.184.216.34");
                    answered.outcome = HopOutcome::Answered;
                    answered
                },
                origin: dns_resolve::NodeOrigin::Trace,
                children: Vec::new(),
            }],
        };
        let mut cname = hop("example.com.", "www.example.com.", "93.184.216.34");
        cname.outcome = HopOutcome::Answered;
        let tree = build_explore_tree(&trace_with_root(
            TraceNode {
                hop: hop(".", "www.example.com.", "198.41.0.4"),
                origin: dns_resolve::NodeOrigin::Trace,
                children: vec![TraceNode {
                    hop: cname,
                    origin: dns_resolve::NodeOrigin::Trace,
                    children: vec![alias_leg],
                }],
            },
            "www.example.com.",
        ));

        let ExploreNode::Delegation { children, .. } = &tree.children[0] else {
            panic!("expected root delegation");
        };
        let ExploreNode::Delegation {
            children: cname_children,
            ..
        } = &children[0]
        else {
            panic!("expected cname delegation hop");
        };
        let ExploreNode::Resolve { target, .. } = &cname_children[0] else {
            panic!("expected alias resolve branch");
        };
        assert_eq!(target, "cdn.example.com.");
    }

    #[test]
    fn uses_display_qname_override() {
        let tree = build_explore_tree_with_qname(
            &trace_with_hops(
                "cdn.example.com.",
                vec![hop(".", "cdn.example.com.", "198.41.0.4")],
            ),
            Some("www.example.com."),
        );
        assert_eq!(tree.qname, "www.example.com.");
    }
}
