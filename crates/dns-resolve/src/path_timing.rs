use crate::tree::{HopOutcome, NodePath, TraceNode, TraceTree};

/// Child-index chain from the tree root through an answered leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnsweredPath {
    pub path: Vec<usize>,
}

/// A path with its cumulative DNS RTT total.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathIdentity {
    pub path: Vec<usize>,
    pub total_rtt_ms: u64,
}

/// Fastest, slowest, and average full-path RTT totals over answered leaves.
#[derive(Debug, Clone, PartialEq)]
pub struct PathTimingSummary {
    pub count: usize,
    pub fastest: PathIdentity,
    pub slowest: PathIdentity,
    pub average_rtt_ms: f64,
}

/// Per-sibling hop RTT at a fork cut.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkSiblingRtt {
    pub child_index: usize,
    pub rtt_ms: u64,
}

impl TraceTree {
    /// Enumerate root-to-leaf chains whose terminal hop has outcome `Answered`.
    pub fn answered_leaf_paths(&self) -> Vec<AnsweredPath> {
        let mut paths = Vec::new();
        collect_answered_leaf_paths(&self.root, &[], &mut paths);
        paths
    }

    /// Sum `rtt_ms` along a path from the root through the given child indices.
    pub fn path_rtt_total(&self, path: &[usize]) -> Option<u64> {
        let mut total = 0u64;
        let mut node = &self.root;
        total = total.saturating_add(node.hop.rtt_ms);
        for index in path {
            node = node.children.get(*index)?;
            total = total.saturating_add(node.hop.rtt_ms);
        }
        Some(total)
    }

    /// Whole-tree fastest, slowest, and average path totals over answered leaves.
    pub fn path_timing_summary(&self) -> Option<PathTimingSummary> {
        let paths = self.answered_leaf_paths();
        build_summary(self, &paths)
    }

    /// Fork-scoped path totals for answered leaves descending through `fork`.
    pub fn fork_path_timing_summary(&self, fork: &NodePath) -> Option<PathTimingSummary> {
        if fork.tree != 0 {
            return None;
        }
        let node = self.resolve(fork)?;
        if node.children.len() < 2 {
            return None;
        }
        let scoped: Vec<AnsweredPath> = self
            .answered_leaf_paths()
            .into_iter()
            .filter(|answered| path_passes_through_fork(&answered.path, &fork.path))
            .collect();
        build_summary(self, &scoped)
    }

    /// Hop RTT at the fork for each immediate child sibling.
    pub fn fork_sibling_hop_rtts(&self, fork: &NodePath) -> Option<Vec<ForkSiblingRtt>> {
        if fork.tree != 0 {
            return None;
        }
        let node = self.resolve(fork)?;
        if node.children.len() < 2 {
            return None;
        }
        Some(
            node.children
                .iter()
                .enumerate()
                .map(|(child_index, child)| ForkSiblingRtt {
                    child_index,
                    rtt_ms: child.hop.rtt_ms,
                })
                .collect(),
        )
    }
}

fn collect_answered_leaf_paths(node: &TraceNode, path: &[usize], out: &mut Vec<AnsweredPath>) {
    if node.children.is_empty() {
        if matches!(node.hop.outcome, HopOutcome::Answered) {
            out.push(AnsweredPath {
                path: path.to_vec(),
            });
        }
        return;
    }
    for (index, child) in node.children.iter().enumerate() {
        let mut child_path = path.to_vec();
        child_path.push(index);
        collect_answered_leaf_paths(child, &child_path, out);
    }
}

fn path_passes_through_fork(path: &[usize], fork_path: &[usize]) -> bool {
    path.len() >= fork_path.len() && path.starts_with(fork_path)
}

fn build_summary(tree: &TraceTree, paths: &[AnsweredPath]) -> Option<PathTimingSummary> {
    if paths.is_empty() {
        return None;
    }
    let mut identities: Vec<PathIdentity> = paths
        .iter()
        .map(|answered| PathIdentity {
            path: answered.path.clone(),
            total_rtt_ms: tree.path_rtt_total(&answered.path).unwrap_or(0),
        })
        .collect();
    let count = identities.len();
    let total_sum: u64 = identities.iter().map(|id| id.total_rtt_ms).sum();
    identities.sort_by_key(|id| id.total_rtt_ms);
    let fastest = identities.first().cloned()?;
    let slowest = identities.last().cloned()?;
    Some(PathTimingSummary {
        count,
        fastest,
        slowest,
        average_rtt_ms: total_sum as f64 / count as f64,
    })
}

#[cfg(test)]
mod path_timing_tests {
    use super::*;
    use crate::tree::{NodeOrigin, TraceTreeRequest};
    use crate::{StoredDnsMessage, TraceHop};

    fn hop(zone: &str, rtt_ms: u64, outcome: HopOutcome) -> TraceHop {
        TraceHop {
            zone: zone.into(),
            server: "1.1.1.1".into(),
            server_name: None,
            qname: "example.com.".into(),
            qtype: "A".into(),
            transport: "udp".into(),
            rtt_ms,
            rcode: "NOERROR".into(),
            nsid: None,
            ede_code: None,
            ede_text: None,
            referral_ns: vec![],
            glue: vec![],
            response: StoredDnsMessage::default(),
            from_cache: false,
            outcome,
        }
    }

    fn request() -> TraceTreeRequest {
        TraceTreeRequest {
            qname: "example.com.".into(),
            qtype: "A".into(),
            started_at: "2026-01-01T00:00:00Z".into(),
        }
    }

    fn linear_tree(rtts: &[u64]) -> TraceTree {
        let mut current = None;
        for (index, &rtt) in rtts.iter().enumerate().rev() {
            let outcome = if index == rtts.len() - 1 {
                HopOutcome::Answered
            } else {
                HopOutcome::Referral
            };
            current = Some(TraceNode {
                hop: hop(&format!("zone-{index}"), rtt, outcome),
                origin: NodeOrigin::Trace,
                children: current.into_iter().collect(),
            });
        }
        TraceTree {
            request: request(),
            root: current.expect("non-empty"),
            budget_truncated: false,
        }
    }

    #[test]
    fn answered_leaf_paths_linear_trace_has_one_path() {
        let tree = linear_tree(&[10, 20, 30]);
        let paths = tree.answered_leaf_paths();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].path, vec![0, 0]);
    }

    #[test]
    fn answered_leaf_paths_branching_yields_distinct_chains() {
        let tree = TraceTree {
            request: request(),
            root: TraceNode {
                hop: hop(".", 5, HopOutcome::Referral),
                origin: NodeOrigin::Trace,
                children: vec![
                    TraceNode {
                        hop: hop("left", 10, HopOutcome::Answered),
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    },
                    TraceNode {
                        hop: hop("right", 20, HopOutcome::Answered),
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    },
                ],
            },
            budget_truncated: false,
        };
        let paths = tree.answered_leaf_paths();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0].path, vec![0]);
        assert_eq!(paths[1].path, vec![1]);
    }

    #[test]
    fn answered_leaf_paths_exclude_failed_and_referral_terminals() {
        let tree = TraceTree {
            request: request(),
            root: TraceNode {
                hop: hop(".", 1, HopOutcome::Referral),
                origin: NodeOrigin::Trace,
                children: vec![
                    TraceNode {
                        hop: hop(
                            "failed",
                            0,
                            HopOutcome::Failed {
                                kind: "timeout".into(),
                                detail: "deadline".into(),
                            },
                        ),
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    },
                    TraceNode {
                        hop: hop("referral", 2, HopOutcome::Referral),
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    },
                    TraceNode {
                        hop: hop("answered", 3, HopOutcome::Answered),
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    },
                ],
            },
            budget_truncated: false,
        };
        let paths = tree.answered_leaf_paths();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].path, vec![2]);
    }

    #[test]
    fn path_rtt_total_sums_hops_along_chain() {
        let tree = linear_tree(&[12, 8, 45]);
        assert_eq!(tree.path_rtt_total(&[]), Some(12));
        assert_eq!(tree.path_rtt_total(&[0]), Some(20));
        assert_eq!(tree.path_rtt_total(&[0, 0]), Some(65));
    }

    #[test]
    fn path_timing_summary_reports_fastest_slowest_and_average() {
        let tree = TraceTree {
            request: request(),
            root: TraceNode {
                hop: hop(".", 10, HopOutcome::Referral),
                origin: NodeOrigin::Trace,
                children: vec![
                    TraceNode {
                        hop: hop("fast", 50, HopOutcome::Answered),
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    },
                    TraceNode {
                        hop: hop("slow", 200, HopOutcome::Answered),
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    },
                    TraceNode {
                        hop: hop("mid", 100, HopOutcome::Answered),
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    },
                    TraceNode {
                        hop: hop(
                            "failed",
                            0,
                            HopOutcome::Failed {
                                kind: "servfail".into(),
                                detail: "boom".into(),
                            },
                        ),
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    },
                ],
            },
            budget_truncated: false,
        };
        let summary = tree.path_timing_summary().expect("summary");
        assert_eq!(summary.count, 3);
        assert_eq!(summary.fastest.total_rtt_ms, 60);
        assert_eq!(summary.slowest.total_rtt_ms, 210);
        assert!((summary.average_rtt_ms - 126.66666666666667).abs() < 0.001);
    }

    #[test]
    fn path_timing_summary_unavailable_without_answered_paths() {
        let tree = TraceTree {
            request: request(),
            root: TraceNode {
                hop: hop(".", 1, HopOutcome::Referral),
                origin: NodeOrigin::Trace,
                children: vec![TraceNode {
                    hop: hop(
                        "failed",
                        0,
                        HopOutcome::Failed {
                            kind: "timeout".into(),
                            detail: "deadline".into(),
                        },
                    ),
                    origin: NodeOrigin::Trace,
                    children: vec![],
                }],
            },
            budget_truncated: false,
        };
        assert!(tree.path_timing_summary().is_none());
    }

    #[test]
    fn fork_path_timing_summary_at_root_matches_whole_tree() {
        let tree = TraceTree {
            request: request(),
            root: TraceNode {
                hop: hop(".", 10, HopOutcome::Referral),
                origin: NodeOrigin::Trace,
                children: vec![
                    TraceNode {
                        hop: hop("fast", 50, HopOutcome::Answered),
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    },
                    TraceNode {
                        hop: hop("slow", 200, HopOutcome::Answered),
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    },
                ],
            },
            budget_truncated: false,
        };
        let whole = tree.path_timing_summary().expect("whole");
        let fork = tree
            .fork_path_timing_summary(&NodePath::root(0))
            .expect("fork at root");
        assert_eq!(whole.count, fork.count);
        assert_eq!(whole.fastest, fork.fastest);
        assert_eq!(whole.slowest, fork.slowest);
    }

    #[test]
    fn fork_path_timing_summary_scopes_to_descendants() {
        let tree = TraceTree {
            request: request(),
            root: TraceNode {
                hop: hop(".", 10, HopOutcome::Referral),
                origin: NodeOrigin::Trace,
                children: vec![
                    TraceNode {
                        hop: hop("left-cut", 5, HopOutcome::Referral),
                        origin: NodeOrigin::Trace,
                        children: vec![
                            TraceNode {
                                hop: hop("left-a", 20, HopOutcome::Answered),
                                origin: NodeOrigin::Trace,
                                children: vec![],
                            },
                            TraceNode {
                                hop: hop("left-b", 40, HopOutcome::Answered),
                                origin: NodeOrigin::Trace,
                                children: vec![],
                            },
                        ],
                    },
                    TraceNode {
                        hop: hop("right-cut", 100, HopOutcome::Answered),
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    },
                ],
            },
            budget_truncated: false,
        };
        let fork = NodePath {
            tree: 0,
            path: vec![0],
        };
        let summary = tree.fork_path_timing_summary(&fork).expect("fork summary");
        assert_eq!(summary.count, 2);
        assert_eq!(summary.fastest.total_rtt_ms, 35);
        assert_eq!(summary.slowest.total_rtt_ms, 55);
    }

    #[test]
    fn fork_path_timing_summary_unavailable_without_fork() {
        let tree = linear_tree(&[10, 20]);
        let selection = NodePath {
            tree: 0,
            path: vec![0],
        };
        assert!(tree.fork_path_timing_summary(&selection).is_none());
    }

    #[test]
    fn fork_sibling_hop_rtts_lists_each_child_at_cut() {
        let tree = TraceTree {
            request: request(),
            root: TraceNode {
                hop: hop(".", 1, HopOutcome::Referral),
                origin: NodeOrigin::Trace,
                children: vec![
                    TraceNode {
                        hop: hop("a", 45, HopOutcome::Answered),
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    },
                    TraceNode {
                        hop: hop("b", 52, HopOutcome::Answered),
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    },
                    TraceNode {
                        hop: hop("c", 112, HopOutcome::Answered),
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    },
                ],
            },
            budget_truncated: false,
        };
        let siblings = tree
            .fork_sibling_hop_rtts(&NodePath::root(0))
            .expect("siblings");
        assert_eq!(siblings.len(), 3);
        assert_eq!(
            siblings,
            vec![
                ForkSiblingRtt {
                    child_index: 0,
                    rtt_ms: 45
                },
                ForkSiblingRtt {
                    child_index: 1,
                    rtt_ms: 52
                },
                ForkSiblingRtt {
                    child_index: 2,
                    rtt_ms: 112
                },
            ]
        );
    }
}
