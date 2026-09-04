use dns_resolve::{NodePath, TraceHop, TraceNode, TraceTree};

#[derive(Debug, Clone)]
pub struct ExploreTree {
    pub qname: String,
    pub qtype: String,
    pub tree_index: usize,
    pub tree: TraceTree,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VisibleNode {
    pub path: NodePath,
    pub depth: usize,
    pub expandable: bool,
    pub expanded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareFork {
    pub at: NodePath,
    pub row: usize,
}

impl ExploreTree {
    pub fn trace(&self) -> &TraceTree {
        &self.tree
    }

    pub fn node_at(&self, path: &NodePath) -> Option<&TraceNode> {
        self.tree.resolve(path)
    }

    pub fn hop_at(&self, path: &NodePath) -> Option<&TraceHop> {
        self.tree.resolve(path).map(|node| &node.hop)
    }

    pub fn has_children(&self, path: &NodePath) -> bool {
        self.tree
            .resolve(path)
            .is_some_and(|node| !node.children.is_empty())
    }

    pub fn default_expanded_paths(&self) -> Vec<NodePath> {
        let mut paths = Vec::new();
        collect_expandable_paths(&self.tree.root, self.tree_index, &[], &mut paths);
        paths
    }

    pub fn visible_nodes(&self, expanded_paths: &[NodePath]) -> Vec<VisibleNode> {
        let mut visible = Vec::new();
        append_visible(
            &self.tree.root,
            self.tree_index,
            &[],
            0,
            expanded_paths,
            &mut visible,
        );
        visible
    }

    pub fn compare_fork(&self, selection: &NodePath) -> Option<CompareFork> {
        let node = self.tree.resolve(selection)?;
        if node.children.len() >= 2 {
            return Some(CompareFork {
                at: selection.clone(),
                row: 0,
            });
        }
        if selection.path.is_empty() {
            return None;
        }
        let parent_path = parent_path(&selection.path);
        let parent = self.tree.resolve(&NodePath {
            tree: selection.tree,
            path: parent_path.clone(),
        })?;
        if parent.children.len() < 2 {
            return None;
        }
        let row = selection.path.last().copied().unwrap_or(0);
        Some(CompareFork {
            at: NodePath {
                tree: selection.tree,
                path: parent_path,
            },
            row,
        })
    }

    pub fn compare_available(&self, selection: &NodePath) -> bool {
        self.compare_fork(selection).is_some()
    }

    /// Shallowest fork anywhere in the tree, used to tell the operator where
    /// comparison is reachable when the current selection has no sibling paths.
    pub fn nearest_fork(&self) -> Option<NodePath> {
        let mut queue = std::collections::VecDeque::from([NodePath::root(self.tree_index)]);
        while let Some(path) = queue.pop_front() {
            let Some(node) = self.tree.resolve(&path) else {
                continue;
            };
            if node.children.len() >= 2 {
                return Some(path);
            }
            for index in 0..node.children.len() {
                let mut child = path.path.clone();
                child.push(index);
                queue.push_back(NodePath {
                    tree: path.tree,
                    path: child,
                });
            }
        }
        None
    }

    /// Why Compare cannot be shown for `selection`, naming the fork to select
    /// with the same display index `session outline` prints and `--at-hop` takes.
    pub fn compare_unavailable_reason(&self, selection: &NodePath) -> String {
        match self.nearest_fork() {
            Some(fork) if &fork == selection => {
                "no sibling paths at this node yet; branch it to compare alternatives".into()
            }
            Some(fork) => {
                let path = fork.to_string();
                match self.tree.display_index_for_path(&fork) {
                    Some(index) => format!(
                        "no sibling paths at this node; select hop {index} (at-path {path}) to compare"
                    ),
                    None => {
                        format!("no sibling paths at this node; select at-path {path} to compare")
                    }
                }
            }
            None => "this trace has a single path, so there is nothing to compare".into(),
        }
    }

    pub fn selection_for_visible_index(
        &self,
        index: usize,
        expanded: &[NodePath],
    ) -> Option<NodePath> {
        self.visible_nodes(expanded)
            .get(index)
            .map(|node| node.path.clone())
    }

    pub fn visible_index_for_selection(
        &self,
        selection: &NodePath,
        expanded: &[NodePath],
    ) -> Option<usize> {
        self.visible_nodes(expanded)
            .iter()
            .position(|node| node.path == *selection)
    }

    pub fn nearest_visible_ancestor(
        &self,
        selection: &NodePath,
        expanded: &[NodePath],
    ) -> NodePath {
        let visible = self.visible_nodes(expanded);
        if visible.iter().any(|node| node.path == *selection) {
            return selection.clone();
        }
        let mut path = selection.path.clone();
        while !path.is_empty() {
            path.pop();
            let candidate = NodePath {
                tree: selection.tree,
                path: path.clone(),
            };
            if visible.iter().any(|node| node.path == candidate) {
                return candidate;
            }
        }
        visible
            .first()
            .map(|node| node.path.clone())
            .unwrap_or_else(|| NodePath::root(selection.tree))
    }
}

pub fn build_explore_tree(trace: &TraceTree) -> ExploreTree {
    build_explore_tree_with_qname(trace, 0, None)
}

pub fn build_explore_tree_with_qname(
    trace: &TraceTree,
    tree_index: usize,
    display_qname: Option<&str>,
) -> ExploreTree {
    ExploreTree {
        qname: display_qname.unwrap_or_else(|| trace.qname()).to_string(),
        qtype: trace.qtype().to_string(),
        tree_index,
        tree: trace.clone(),
    }
}

fn parent_path(path: &[usize]) -> Vec<usize> {
    let mut parent = path.to_vec();
    parent.pop();
    parent
}

fn collect_expandable_paths(
    node: &TraceNode,
    tree_index: usize,
    path: &[usize],
    paths: &mut Vec<NodePath>,
) {
    if node.children.is_empty() {
        return;
    }
    paths.push(NodePath {
        tree: tree_index,
        path: path.to_vec(),
    });
    for (index, child) in node.children.iter().enumerate() {
        let mut child_path = path.to_vec();
        child_path.push(index);
        collect_expandable_paths(child, tree_index, &child_path, paths);
    }
}

fn append_visible(
    node: &TraceNode,
    tree_index: usize,
    path: &[usize],
    depth: usize,
    expanded_paths: &[NodePath],
    visible: &mut Vec<VisibleNode>,
) {
    let current = NodePath {
        tree: tree_index,
        path: path.to_vec(),
    };
    let expandable = !node.children.is_empty();
    let expanded = expandable && expanded_paths.iter().any(|existing| existing == &current);
    visible.push(VisibleNode {
        path: current,
        depth,
        expandable,
        expanded,
    });
    if !expanded {
        return;
    }
    for (index, child) in node.children.iter().enumerate() {
        let mut child_path = path.to_vec();
        child_path.push(index);
        append_visible(
            child,
            tree_index,
            &child_path,
            depth + 1,
            expanded_paths,
            visible,
        );
    }
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
    fn visible_nodes_follow_expansion() {
        let tree = build_explore_tree(&trace_with_hops(
            "example.com.",
            vec![
                hop(".", "example.com.", "198.41.0.4"),
                hop("com.", "example.com.", "192.41.162.30"),
            ],
        ));
        let expanded = vec![NodePath::root(0)];
        let visible = tree.visible_nodes(&expanded);
        assert_eq!(visible.len(), 2);
        assert_eq!(visible[0].path, NodePath::root(0));
        assert_eq!(visible[1].path.path, vec![0]);
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

        let fork = tree.compare_fork(&NodePath {
            tree: 0,
            path: vec![0, 0],
        });
        assert!(fork.is_some());
        assert_eq!(fork.unwrap().at.path, vec![0]);
        let expanded_fork = vec![
            NodePath::root(0),
            NodePath {
                tree: 0,
                path: vec![0],
            },
        ];
        let visible = tree.visible_nodes(&expanded_fork);
        assert_eq!(
            visible
                .iter()
                .filter(|node| node.path.path == vec![0, 0] || node.path.path == vec![0, 1])
                .count(),
            2
        );
    }

    /// Every real trace forks below the root, and explore opens with the root
    /// selected, so the unavailable message has to say where the fork is instead
    /// of only that the current node has none.
    #[test]
    fn compare_unavailable_reason_points_at_the_nearest_fork() {
        let tree = build_explore_tree(&trace_with_root(
            TraceNode {
                hop: hop(".", "tuininga.org.", "198.41.0.4"),
                origin: dns_resolve::NodeOrigin::Trace,
                children: vec![TraceNode {
                    hop: hop("org.", "tuininga.org.", "199.249.112.1"),
                    origin: dns_resolve::NodeOrigin::Trace,
                    children: vec![
                        TraceNode {
                            hop: hop("tuininga.org.", "tuininga.org.", "193.47.99.5"),
                            origin: dns_resolve::NodeOrigin::Trace,
                            children: Vec::new(),
                        },
                        TraceNode {
                            hop: hop("tuininga.org.", "tuininga.org.", "88.198.229.192"),
                            origin: dns_resolve::NodeOrigin::Trace,
                            children: Vec::new(),
                        },
                    ],
                }],
            },
            "tuininga.org.",
        ));

        let root = NodePath::root(0);
        assert!(!tree.compare_available(&root));
        assert_eq!(
            tree.nearest_fork(),
            Some(NodePath {
                tree: 0,
                path: vec![0]
            })
        );
        let reason = tree.compare_unavailable_reason(&root);
        assert!(reason.contains("select hop 1"), "{reason}");
        assert!(reason.contains("at-path 0.0"), "{reason}");
    }

    #[test]
    fn compare_unavailable_reason_states_a_single_path_trace() {
        let tree = build_explore_tree(&trace_with_hops(
            "example.com.",
            vec![
                hop(".", "example.com.", "198.41.0.4"),
                hop("com.", "example.com.", "192.41.162.30"),
            ],
        ));
        assert_eq!(tree.nearest_fork(), None);
        let reason = tree.compare_unavailable_reason(&NodePath::root(0));
        assert!(reason.contains("single path"), "{reason}");
        assert!(!reason.contains("at-path"), "{reason}");
    }

    #[test]
    fn uses_display_qname_override() {
        let tree = build_explore_tree_with_qname(
            &trace_with_hops(
                "cdn.example.com.",
                vec![hop(".", "cdn.example.com.", "198.41.0.4")],
            ),
            0,
            Some("www.example.com."),
        );
        assert_eq!(tree.qname, "www.example.com.");
    }

    #[test]
    fn default_expanded_paths_show_delegation_structure() {
        let tree = build_explore_tree(&trace_with_hops(
            "example.com.",
            vec![
                hop(".", "example.com.", "198.41.0.4"),
                hop("com.", "example.com.", "192.41.162.30"),
            ],
        ));
        let paths = tree.default_expanded_paths();
        assert!(paths.contains(&NodePath::root(0)));
        let visible = tree.visible_nodes(&paths);
        assert_eq!(visible.len(), 2);
    }
}
