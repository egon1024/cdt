use dns_resolve::{TraceHop, TraceResult};

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
    let main_qname = normalize_qname(&trace.qname);
    let mut children = Vec::new();
    let mut index = 0;

    while index < trace.hops.len() {
        let hop_qname = normalize_qname(&trace.hops[index].qname);
        if hop_qname == main_qname {
            let hop_index = index;
            index += 1;
            let resolution_children =
                collect_resolution_groups(&trace.hops, &main_qname, &mut index);
            children.push(ExploreNode::Delegation {
                hop_index,
                children: resolution_children,
            });
        } else {
            children.push(collect_resolution_group(
                &trace.hops,
                &main_qname,
                &mut index,
            ));
        }
    }

    if trace.final_response.is_some() {
        children.push(ExploreNode::Final);
    }

    ExploreTree {
        qname: trace.qname.clone(),
        qtype: trace.qtype.clone(),
        children,
        trace: trace.clone(),
    }
}

fn collect_resolution_groups(
    hops: &[TraceHop],
    main_qname: &str,
    index: &mut usize,
) -> Vec<ExploreNode> {
    let mut groups = Vec::new();
    while *index < hops.len() && normalize_qname(&hops[*index].qname) != main_qname {
        groups.push(collect_resolution_group(hops, main_qname, index));
    }
    groups
}

fn collect_resolution_group(hops: &[TraceHop], main_qname: &str, index: &mut usize) -> ExploreNode {
    let target = hops[*index].qname.clone();
    let target_norm = normalize_qname(&target);
    let mut children = Vec::new();

    while *index < hops.len() {
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
        }
    }

    fn trace_with_hops(hops: Vec<TraceHop>) -> TraceResult {
        TraceResult {
            qname: "example.com.".into(),
            qtype: "A".into(),
            started_at: "2026-08-25T00:00:00Z".into(),
            hops,
            final_response: Some(FinalAnswer {
                server: "93.184.216.34".into(),
                rtt_ms: 5,
                rcode: "NOERROR".into(),
                records: vec!["example.com. 300 93.184.216.34".into()],
                nsid: None,
            }),
        }
    }

    #[test]
    fn builds_main_path_without_resolution() {
        let tree = build_explore_tree(&trace_with_hops(vec![
            hop(".", "example.com.", "198.41.0.4"),
            hop("com.", "example.com.", "192.41.162.30"),
        ]));

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
        let tree = build_explore_tree(&trace_with_hops(vec![
            hop(".", "example.com.", "198.41.0.4"),
            hop(".", "ns.example.com.", "198.41.0.4"),
            hop("com.", "ns.example.com.", "192.41.162.30"),
            hop("example.com.", "example.com.", "93.184.216.34"),
        ]));

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
}
