use dns_resolve::{FinalAnswer, TraceHop, TraceResult};

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
    Hop {
        hop_index: usize,
    },
    Final,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExploreTree {
    pub qname: String,
    pub qtype: String,
    pub children: Vec<ExploreNode>,
    trace: TraceResult,
}

impl ExploreTree {
    pub fn hop(&self, index: usize) -> &TraceHop {
        &self.trace.hops[index]
    }

    pub fn trace(&self) -> &TraceResult {
        &self.trace
    }
}

pub fn build_explore_tree(trace: &TraceResult) -> ExploreTree {
    let alias_legs = alias_delegation_legs(&trace.hops);
    let mut children = if alias_legs.len() >= 2 {
        build_alias_chain_children(&trace.hops, &alias_legs)
    } else {
        build_main_path_children(
            &trace.hops,
            &normalize_qname(&trace.qname),
            0..trace.hops.len(),
        )
    };

    if trace.final_response.is_some() && should_show_final_node(trace) {
        attach_final_node(&mut children);
    }

    ExploreTree {
        qname: trace.qname.clone(),
        qtype: trace.qtype.clone(),
        children,
        trace: trace.clone(),
    }
}

fn attach_final_node(children: &mut Vec<ExploreNode>) {
    if let Some(ExploreNode::Resolve {
        children: inner, ..
    }) = children.last_mut()
    {
        inner.push(ExploreNode::Final);
    } else {
        children.push(ExploreNode::Final);
    }
}

/// The trace stores the authoritative exchange as both the last hop and
/// `final_response`. Skip a separate Final node when they describe the same query.
fn should_show_final_node(trace: &TraceResult) -> bool {
    let Some(answer) = trace.final_response.as_ref() else {
        return false;
    };
    let Some(last_hop) = trace.hops.last() else {
        return true;
    };
    !final_answer_matches_hop(last_hop, answer, &trace.qname)
}

fn final_answer_matches_hop(hop: &TraceHop, answer: &FinalAnswer, trace_qname: &str) -> bool {
    let answer_qname = if answer.qname.is_empty() {
        trace_qname
    } else {
        answer.qname.as_str()
    };
    hop.server == answer.server
        && hop.rtt_ms == answer.rtt_ms
        && hop.rcode == answer.rcode
        && normalize_qname(&hop.qname) == normalize_qname(answer_qname)
}

fn build_alias_chain_children(hops: &[TraceHop], legs: &[(usize, usize)]) -> Vec<ExploreNode> {
    legs.iter()
        .map(|(start, end)| {
            let target = hops[*start].qname.clone();
            let main_qname = normalize_qname(&target);
            let children = build_main_path_children(hops, &main_qname, *start..*end);
            ExploreNode::Resolve { target, children }
        })
        .collect()
}

fn build_main_path_children(
    hops: &[TraceHop],
    main_qname: &str,
    range: std::ops::Range<usize>,
) -> Vec<ExploreNode> {
    let mut children = Vec::new();
    let mut index = range.start;

    while index < range.end {
        let hop_qname = normalize_qname(&hops[index].qname);
        if hop_qname == main_qname {
            let hop_index = index;
            index += 1;
            let resolution_children =
                collect_resolution_groups(hops, main_qname, &mut index, range.end);
            children.push(ExploreNode::Delegation {
                hop_index,
                children: resolution_children,
            });
        } else {
            children.push(collect_resolution_group(
                hops, main_qname, &mut index, range.end,
            ));
        }
    }

    children
}

fn alias_delegation_legs(hops: &[TraceHop]) -> Vec<(usize, usize)> {
    let mut legs = Vec::new();
    let mut index = 0;

    while index < hops.len() {
        if !is_root_zone(&hops[index].zone) {
            index += 1;
            continue;
        }

        let qname_norm = normalize_qname(&hops[index].qname);
        let start = index;
        index += 1;
        while index < hops.len() && normalize_qname(&hops[index].qname) == qname_norm {
            index += 1;
        }

        if is_alias_delegation_leg(hops, start, index) {
            legs.push((start, index));
        }
    }

    legs
}

fn is_alias_delegation_leg(hops: &[TraceHop], start: usize, end: usize) -> bool {
    if end <= start + 1 {
        return false;
    }

    is_root_zone(&hops[start].zone) && hops[start..end].iter().any(|hop| !is_root_zone(&hop.zone))
}

fn collect_resolution_groups(
    hops: &[TraceHop],
    main_qname: &str,
    index: &mut usize,
    end: usize,
) -> Vec<ExploreNode> {
    let mut groups = Vec::new();
    while *index < end && normalize_qname(&hops[*index].qname) != main_qname {
        groups.push(collect_resolution_group(hops, main_qname, index, end));
    }
    groups
}

fn collect_resolution_group(
    hops: &[TraceHop],
    main_qname: &str,
    index: &mut usize,
    end: usize,
) -> ExploreNode {
    let target = hops[*index].qname.clone();
    let target_norm = normalize_qname(&target);
    let mut children = Vec::new();

    while *index < end {
        let hop_qname = normalize_qname(&hops[*index].qname);
        if hop_qname == main_qname {
            break;
        }
        if hop_qname != target_norm {
            break;
        }
        children.push(ExploreNode::Hop { hop_index: *index });
        *index += 1;
    }

    ExploreNode::Resolve { target, children }
}

fn is_root_zone(zone: &str) -> bool {
    normalize_zone(zone) == "."
}

fn normalize_zone(zone: &str) -> String {
    let trimmed = zone.trim_end_matches('.');
    if trimmed.is_empty() {
        ".".into()
    } else {
        format!("{}.", trimmed.to_ascii_lowercase())
    }
}

fn normalize_qname(qname: &str) -> String {
    let trimmed = qname.trim_end_matches('.');
    if trimmed.is_empty() {
        ".".into()
    } else {
        format!("{}.", trimmed.to_ascii_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::{FinalAnswer, TraceHop};

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
        }
    }

    fn trace_with_hops(qname: &str, hops: Vec<TraceHop>) -> TraceResult {
        TraceResult {
            qname: qname.into(),
            qtype: "A".into(),
            started_at: "2026-08-25T00:00:00Z".into(),
            hops,
            final_response: Some(FinalAnswer {
                server: "93.184.216.34".into(),
                server_name: None,
                rtt_ms: 5,
                rcode: "NOERROR".into(),
                records: vec!["example.com. 300 93.184.216.34".into()],
                nsid: None,
                qname: String::new(),
                qtype: String::new(),
                transport: String::new(),
                response: Default::default(),
                from_cache: false,
            }),
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

        assert_eq!(tree.children.len(), 3);
        assert!(matches!(
            &tree.children[0],
            ExploreNode::Delegation {
                hop_index: 0,
                children
            } if children.is_empty()
        ));
        assert!(matches!(
            &tree.children[1],
            ExploreNode::Delegation {
                hop_index: 1,
                children
            } if children.is_empty()
        ));
        assert!(matches!(tree.children[2], ExploreNode::Final));
    }

    #[test]
    fn groups_nameserver_resolution_under_delegation_hop() {
        let tree = build_explore_tree(&trace_with_hops(
            "example.com.",
            vec![
                hop(".", "example.com.", "198.41.0.4"),
                hop(".", "ns.example.com.", "198.41.0.4"),
                hop("com.", "ns.example.com.", "192.41.162.30"),
                hop("example.com.", "example.com.", "93.184.216.34"),
            ],
        ));

        let ExploreNode::Delegation {
            hop_index: 0,
            children,
        } = &tree.children[0]
        else {
            panic!("expected delegation hop");
        };
        assert_eq!(children.len(), 1);
        let ExploreNode::Resolve { target, children } = &children[0] else {
            panic!("expected resolve node");
        };
        assert_eq!(target, "ns.example.com.");
        assert_eq!(children.len(), 2);
        assert!(matches!(children[0], ExploreNode::Hop { hop_index: 1 }));
        assert!(matches!(children[1], ExploreNode::Hop { hop_index: 2 }));
    }

    #[test]
    fn omits_final_node_when_last_hop_matches_final_answer() {
        let mut authoritative = hop("example.com.", "example.com.", "93.184.216.34");
        authoritative.rtt_ms = 5;
        let trace = TraceResult {
            qname: "example.com.".into(),
            qtype: "A".into(),
            started_at: "2026-08-25T00:00:00Z".into(),
            hops: vec![
                hop(".", "example.com.", "198.41.0.4"),
                hop("com.", "example.com.", "192.41.162.30"),
                authoritative,
            ],
            final_response: Some(FinalAnswer {
                server: "93.184.216.34".into(),
                server_name: None,
                rtt_ms: 5,
                rcode: "NOERROR".into(),
                records: vec!["example.com. 300 93.184.216.34".into()],
                nsid: None,
                qname: "example.com.".into(),
                qtype: "A".into(),
                transport: "udp".into(),
                response: Default::default(),
                from_cache: false,
            }),
        };

        let tree = build_explore_tree(&trace);
        assert!(!contains_final_node(&tree.children));
        assert!(matches!(
            tree.children.last(),
            Some(ExploreNode::Delegation { hop_index: 2, .. })
        ));
    }

    fn contains_final_node(nodes: &[ExploreNode]) -> bool {
        nodes.iter().any(|node| match node {
            ExploreNode::Final => true,
            ExploreNode::Delegation { children, .. } | ExploreNode::Resolve { children, .. } => {
                contains_final_node(children)
            }
            ExploreNode::Hop { .. } => false,
        })
    }

    #[test]
    fn wraps_each_alias_leg_in_resolve_branch() {
        let tree = build_explore_tree(&trace_with_hops(
            "target.example.com.",
            vec![
                hop(".", "www.example.com.", "198.41.0.4"),
                hop("com.", "www.example.com.", "192.41.162.30"),
                hop(".", "cdn.example.com.", "198.41.0.4"),
                hop("com.", "cdn.example.com.", "192.41.162.30"),
                hop(".", "target.example.com.", "198.41.0.4"),
                hop("com.", "target.example.com.", "192.41.162.30"),
            ],
        ));

        assert_eq!(tree.children.len(), 3);
        assert!(matches!(
            &tree.children[0],
            ExploreNode::Resolve { target, .. } if target == "www.example.com."
        ));
        assert!(matches!(
            &tree.children[1],
            ExploreNode::Resolve { target, .. } if target == "cdn.example.com."
        ));
        let ExploreNode::Resolve { children, .. } = &tree.children[2] else {
            panic!("expected final resolve branch");
        };
        assert!(matches!(children.last(), Some(ExploreNode::Final)));
    }
}
