use serde::{Deserialize, Serialize};

use crate::TraceHop;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum HopOutcome {
    #[default]
    Referral,
    Answered,
    Failed {
        kind: String,
        detail: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NodeOrigin {
    Trace,
    Branch {
        at: NodePath,
        intent: BranchIntent,
        at_time: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BranchIntent {
    AlternateServer,
    ExpandCut,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct NodePath {
    pub tree: usize,
    pub path: Vec<usize>,
}

impl NodePath {
    pub fn root(tree: usize) -> Self {
        Self {
            tree,
            path: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceNode {
    pub hop: TraceHop,
    pub origin: NodeOrigin,
    pub children: Vec<TraceNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceTreeRequest {
    pub qname: String,
    pub qtype: String,
    pub started_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceTree {
    pub request: TraceTreeRequest,
    pub root: TraceNode,
}

impl TraceTree {
    pub fn qname(&self) -> &str {
        &self.request.qname
    }

    pub fn qtype(&self) -> &str {
        &self.request.qtype
    }

    pub fn started_at(&self) -> &str {
        &self.request.started_at
    }

    pub fn node_count(&self) -> usize {
        fn count(node: &TraceNode) -> usize {
            1 + node.children.iter().map(count).sum::<usize>()
        }
        count(&self.root)
    }

    pub fn resolve(&self, path: &NodePath) -> Option<&TraceNode> {
        if path.tree != 0 {
            return None;
        }
        let mut node = &self.root;
        for index in &path.path {
            node = node.children.get(*index)?;
        }
        Some(node)
    }

    pub fn primary_path(&self) -> Vec<&TraceNode> {
        let mut nodes = vec![&self.root];
        let mut current = &self.root;
        while let Some(child) = current.children.first() {
            nodes.push(child);
            current = child;
        }
        nodes
    }

    pub fn primary_hops(&self) -> Vec<&TraceHop> {
        self.primary_path()
            .into_iter()
            .map(|node| &node.hop)
            .collect()
    }

    pub fn leaf(&self) -> &TraceNode {
        self.primary_path()
            .last()
            .expect("trace tree always has a root")
    }

    pub fn answering_hop(&self) -> Option<&TraceHop> {
        let hop = &self.leaf().hop;
        if hop.outcome == HopOutcome::Answered {
            Some(hop)
        } else {
            None
        }
    }

    pub fn display_order(&self) -> Vec<NodePath> {
        let mut paths = Vec::new();
        collect_preorder(&self.root, 0, &[], &mut paths);
        paths
    }

    pub fn path_for_display_index(&self, index: usize) -> Option<NodePath> {
        self.display_order().into_iter().nth(index)
    }

    pub fn display_index_for_path(&self, path: &NodePath) -> Option<usize> {
        self.display_order()
            .into_iter()
            .position(|candidate| candidate == *path)
    }
}

pub fn build_linear_tree(hops: Vec<TraceHop>, request: TraceTreeRequest) -> TraceTree {
    assert!(!hops.is_empty(), "linear trace must have at least one hop");
    let mut current = None;
    for hop in hops.into_iter().rev() {
        current = Some(TraceNode {
            hop,
            origin: NodeOrigin::Trace,
            children: current.into_iter().collect(),
        });
    }
    TraceTree {
        request,
        root: current.expect("at least one hop"),
    }
}

fn collect_preorder(node: &TraceNode, tree: usize, path: &[usize], out: &mut Vec<NodePath>) {
    out.push(NodePath {
        tree,
        path: path.to_vec(),
    });
    for (index, child) in node.children.iter().enumerate() {
        let mut child_path = path.to_vec();
        child_path.push(index);
        collect_preorder(child, tree, &child_path, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StoredDnsMessage;

    fn sample_hop(label: &str) -> TraceHop {
        TraceHop {
            zone: ".".into(),
            server: "1.1.1.1".into(),
            server_name: None,
            qname: label.into(),
            qtype: "A".into(),
            transport: "udp".into(),
            rtt_ms: 1,
            rcode: "NOERROR".into(),
            nsid: None,
            ede_code: None,
            ede_text: None,
            referral_ns: vec![],
            glue: vec![],
            response: StoredDnsMessage::default(),
            from_cache: false,
            outcome: HopOutcome::Answered,
        }
    }

    #[test]
    fn hop_outcome_round_trips_each_variant() {
        for outcome in [
            HopOutcome::Answered,
            HopOutcome::Referral,
            HopOutcome::Failed {
                kind: "timeout".into(),
                detail: "deadline exceeded".into(),
            },
        ] {
            let json = serde_json::to_string(&outcome).expect("serialize");
            let decoded: HopOutcome = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(decoded, outcome);
        }
    }

    #[test]
    fn hop_outcome_rejects_unknown_variant() {
        let error = serde_json::from_str::<HopOutcome>(r#"{"outcome":"unknown"}"#)
            .expect_err("unknown variant");
        assert!(error.to_string().contains("unknown"));
    }

    #[test]
    fn trace_node_preserves_child_ordering() {
        let tree = TraceNode {
            hop: sample_hop("root"),
            origin: NodeOrigin::Trace,
            children: vec![
                TraceNode {
                    hop: sample_hop("left"),
                    origin: NodeOrigin::Trace,
                    children: vec![TraceNode {
                        hop: sample_hop("left-leaf"),
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    }],
                },
                TraceNode {
                    hop: sample_hop("right"),
                    origin: NodeOrigin::Trace,
                    children: vec![],
                },
            ],
        };

        assert_eq!(tree.children[0].hop.qname, "left");
        assert_eq!(tree.children[1].hop.qname, "right");
        assert_eq!(tree.children[0].children[0].hop.qname, "left-leaf");
    }

    #[test]
    fn trace_tree_round_trips_through_json() {
        let tree = TraceTree {
            request: TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
            root: TraceNode {
                hop: sample_hop("root"),
                origin: NodeOrigin::Trace,
                children: vec![TraceNode {
                    hop: sample_hop("child"),
                    origin: NodeOrigin::Trace,
                    children: vec![],
                }],
            },
        };

        let json = serde_json::to_vec(&tree).expect("serialize");
        let decoded: TraceTree = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(decoded, tree);
        assert_eq!(json, serde_json::to_vec(&decoded).expect("re-serialize"));
    }

    #[test]
    fn node_path_resolves_root_valid_child_and_past_end() {
        let tree = TraceTree {
            request: TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
            root: TraceNode {
                hop: sample_hop("root"),
                origin: NodeOrigin::Trace,
                children: vec![TraceNode {
                    hop: sample_hop("child"),
                    origin: NodeOrigin::Trace,
                    children: vec![],
                }],
            },
        };

        assert!(tree.resolve(&NodePath::root(0)).is_some());
        assert!(
            tree.resolve(&NodePath {
                tree: 0,
                path: vec![0],
            })
            .is_some()
        );
        assert!(
            tree.resolve(&NodePath {
                tree: 0,
                path: vec![99],
            })
            .is_none()
        );
    }

    #[test]
    fn display_index_mapping_is_bijection_for_branching_tree() {
        let tree = TraceTree {
            request: TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
            root: TraceNode {
                hop: sample_hop("root"),
                origin: NodeOrigin::Trace,
                children: vec![
                    TraceNode {
                        hop: sample_hop("left"),
                        origin: NodeOrigin::Trace,
                        children: vec![TraceNode {
                            hop: sample_hop("left-leaf"),
                            origin: NodeOrigin::Trace,
                            children: vec![],
                        }],
                    },
                    TraceNode {
                        hop: sample_hop("right"),
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    },
                ],
            },
        };

        let order = tree.display_order();
        assert_eq!(order.len(), 4);
        for (index, path) in order.iter().enumerate() {
            assert_eq!(tree.display_index_for_path(path), Some(index));
            assert_eq!(tree.path_for_display_index(index).as_ref(), Some(path));
        }
    }
}
