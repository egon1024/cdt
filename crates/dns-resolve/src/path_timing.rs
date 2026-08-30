//! Path timing aggregates over stored trace trees.

use crate::{HopOutcome, NodePath, TraceNode, TraceTree};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathTimingEntry {
    pub path: Vec<usize>,
    pub total_rtt_ms: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PathTimingSummary {
    pub fastest: PathTimingEntry,
    pub slowest: PathTimingEntry,
    pub average_ms: f64,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkSiblingHopRtt {
    pub child_index: usize,
    pub rtt_ms: u64,
}

/// Enumerate child-index chains for every answered leaf in the tree.
pub fn answered_leaf_paths(tree: &TraceTree) -> Vec<Vec<usize>> {
    let mut paths = Vec::new();
    collect_answered_leaf_paths(&tree.root, &[], &mut paths);
    paths
}

/// Sum `rtt_ms` from the root through the given child-index path.
pub fn path_rtt_total(tree: &TraceTree, path: &[usize]) -> u64 {
    let mut total = tree.root.hop.rtt_ms;
    let mut node = &tree.root;
    for index in path {
        node = node
            .children
            .get(*index)
            .unwrap_or_else(|| panic!("invalid path segment {index}"));
        total += node.hop.rtt_ms;
    }
    total
}

/// Whole-tree fastest, slowest, and average over answered leaf paths.
pub fn path_timing_summary(tree: &TraceTree) -> Option<PathTimingSummary> {
    summary_from_paths(tree, &answered_leaf_paths(tree))
}

/// Fork-scoped path timing for answered leaves descending through `fork`.
pub fn fork_path_timing_summary(tree: &TraceTree, fork: &NodePath) -> Option<PathTimingSummary> {
    let fork_node = tree.resolve(fork)?;
    if fork_node.children.len() < 2 {
        return None;
    }
    let scoped: Vec<Vec<usize>> = answered_leaf_paths(tree)
        .into_iter()
        .filter(|path| path.starts_with(&fork.path))
        .collect();
    summary_from_paths(tree, &scoped)
}

/// Per-sibling hop RTT at a fork node.
pub fn fork_sibling_hop_rtts(tree: &TraceTree, fork: &NodePath) -> Option<Vec<ForkSiblingHopRtt>> {
    let fork_node = tree.resolve(fork)?;
    if fork_node.children.len() < 2 {
        return None;
    }
    Some(
        fork_node
            .children
            .iter()
            .enumerate()
            .map(|(child_index, child)| ForkSiblingHopRtt {
                child_index,
                rtt_ms: child.hop.rtt_ms,
            })
            .collect(),
    )
}

fn summary_from_paths(tree: &TraceTree, paths: &[Vec<usize>]) -> Option<PathTimingSummary> {
    if paths.is_empty() {
        return None;
    }
    let mut entries: Vec<PathTimingEntry> = paths
        .iter()
        .map(|path| PathTimingEntry {
            path: path.clone(),
            total_rtt_ms: path_rtt_total(tree, path),
        })
        .collect();
    entries.sort_by_key(|entry| entry.total_rtt_ms);
    let fastest = entries.first().expect("non-empty").clone();
    let slowest = entries.last().expect("non-empty").clone();
    let total: u64 = entries.iter().map(|entry| entry.total_rtt_ms).sum();
    let count = entries.len();
    Some(PathTimingSummary {
        fastest,
        slowest,
        average_ms: total as f64 / count as f64,
        count,
    })
}

fn collect_answered_leaf_paths(node: &TraceNode, prefix: &[usize], out: &mut Vec<Vec<usize>>) {
    if node.children.is_empty() {
        if node.hop.outcome == HopOutcome::Answered {
            out.push(prefix.to_vec());
        }
        return;
    }
    for (index, child) in node.children.iter().enumerate() {
        let mut child_prefix = prefix.to_vec();
        child_prefix.push(index);
        collect_answered_leaf_paths(child, &child_prefix, out);
    }
}

#[cfg(test)]
pub(crate) mod path_timing_tests {
    use super::*;
    use crate::{TraceHop, TraceTreeRequest, build_linear_tree};

    fn hop_with_outcome(zone: &str, rtt_ms: u64, outcome: HopOutcome) -> TraceHop {
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
            response: Default::default(),
            from_cache: false,
            outcome,
        }
    }

    fn answered_hop(zone: &str, rtt_ms: u64) -> TraceHop {
        hop_with_outcome(zone, rtt_ms, HopOutcome::Answered)
    }

    fn referral_hop(zone: &str, rtt_ms: u64) -> TraceHop {
        hop_with_outcome(zone, rtt_ms, HopOutcome::Referral)
    }

    fn failed_hop(zone: &str, rtt_ms: u64) -> TraceHop {
        hop_with_outcome(
            zone,
            rtt_ms,
            HopOutcome::Failed {
                kind: "timeout".into(),
                detail: "no response".into(),
            },
        )
    }

    fn branching_fixture_tree() -> TraceTree {
        TraceTree {
            request: TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
            root: TraceNode {
                hop: referral_hop(".", 10),
                origin: crate::NodeOrigin::Trace,
                children: vec![
                    TraceNode {
                        hop: referral_hop("a.", 45),
                        origin: crate::NodeOrigin::Trace,
                        children: vec![
                            TraceNode {
                                hop: answered_hop("leaf-a1.", 5),
                                origin: crate::NodeOrigin::Trace,
                                children: vec![],
                            },
                            TraceNode {
                                hop: answered_hop("leaf-a2.", 15),
                                origin: crate::NodeOrigin::Trace,
                                children: vec![],
                            },
                        ],
                    },
                    TraceNode {
                        hop: referral_hop("b.", 52),
                        origin: crate::NodeOrigin::Trace,
                        children: vec![TraceNode {
                            hop: answered_hop("leaf-b.", 48),
                            origin: crate::NodeOrigin::Trace,
                            children: vec![],
                        }],
                    },
                    TraceNode {
                        hop: referral_hop("c.", 112),
                        origin: crate::NodeOrigin::Trace,
                        children: vec![TraceNode {
                            hop: answered_hop("leaf-c.", 88),
                            origin: crate::NodeOrigin::Trace,
                            children: vec![],
                        }],
                    },
                ],
            },
            budget_truncated: false,
        }
    }

    #[test]
    fn answered_leaf_paths_linear_and_branching() {
        let linear = build_linear_tree(
            vec![
                referral_hop(".", 12),
                referral_hop("com.", 8),
                answered_hop("example.com.", 45),
            ],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
        );
        assert_eq!(answered_leaf_paths(&linear), vec![vec![0, 0]]);

        let branching = branching_fixture_tree();
        assert_eq!(
            answered_leaf_paths(&branching),
            vec![vec![0, 0], vec![0, 1], vec![1, 0], vec![2, 0]]
        );
    }

    #[test]
    fn path_rtt_total_sums_hops_along_chain() {
        let linear = build_linear_tree(
            vec![
                referral_hop(".", 12),
                referral_hop("com.", 8),
                answered_hop("example.com.", 45),
            ],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
        );
        assert_eq!(path_rtt_total(&linear, &[0, 0]), 65);
    }

    #[test]
    fn path_timing_summary_excludes_failed_terminal_paths() {
        let mut tree = branching_fixture_tree();
        tree.root.children.push(TraceNode {
            hop: failed_hop("d.", 0),
            origin: crate::NodeOrigin::Trace,
            children: vec![],
        });
        let summary = path_timing_summary(&tree).expect("summary");
        assert_eq!(summary.count, 4);
    }

    #[test]
    fn path_timing_summary_reports_fastest_slowest_and_average() {
        let tree = branching_fixture_tree();
        let summary = path_timing_summary(&tree).expect("summary");
        assert_eq!(summary.fastest.total_rtt_ms, 60);
        assert_eq!(summary.fastest.path, vec![0, 0]);
        assert_eq!(summary.slowest.total_rtt_ms, 210);
        assert_eq!(summary.slowest.path, vec![2, 0]);
        assert_eq!(summary.count, 4);
        assert!((summary.average_ms - 112.5).abs() < f64::EPSILON);
    }

    #[test]
    fn path_timing_summary_unavailable_without_answered_paths() {
        let tree = build_linear_tree(
            vec![failed_hop("com.", 0)],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
        );
        assert!(path_timing_summary(&tree).is_none());
    }

    #[test]
    fn fork_path_timing_summary_at_root_matches_whole_tree() {
        let tree = branching_fixture_tree();
        let whole = path_timing_summary(&tree).expect("whole tree");
        let fork = fork_path_timing_summary(&tree, &NodePath::root(0)).expect("fork");
        assert_eq!(whole, fork);
    }

    #[test]
    fn fork_path_timing_summary_scopes_to_descendants() {
        let tree = branching_fixture_tree();
        let scoped = fork_path_timing_summary(
            &tree,
            &NodePath {
                tree: 0,
                path: vec![0],
            },
        )
        .expect("scoped");
        assert_eq!(scoped.count, 2);
        assert_eq!(scoped.fastest.total_rtt_ms, 60);
        assert_eq!(scoped.slowest.total_rtt_ms, 70);
    }

    #[test]
    fn fork_path_timing_summary_unavailable_without_fork() {
        let tree = build_linear_tree(
            vec![referral_hop(".", 10), answered_hop("example.com.", 5)],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
        );
        assert!(
            fork_path_timing_summary(
                &tree,
                &NodePath {
                    tree: 0,
                    path: vec![0],
                }
            )
            .is_none()
        );
    }

    #[test]
    fn fork_sibling_hop_rtts_lists_each_child_at_cut() {
        let tree = branching_fixture_tree();
        let siblings = fork_sibling_hop_rtts(&tree, &NodePath::root(0)).expect("siblings");
        assert_eq!(siblings.len(), 3);
        assert_eq!(siblings[0].child_index, 0);
        assert_eq!(siblings[0].rtt_ms, 45);
        assert_eq!(siblings[1].child_index, 1);
        assert_eq!(siblings[1].rtt_ms, 52);
        assert_eq!(siblings[2].child_index, 2);
        assert_eq!(siblings[2].rtt_ms, 112);
    }
}
