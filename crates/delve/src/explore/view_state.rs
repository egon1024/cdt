use std::time::{Duration, Instant};

use dns_resolve::NodePath;

use crate::session::{ExploreViewState, SessionDocument};

use super::tree::ExploreTree;

const PERSIST_DEBOUNCE: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveScreen {
    Browse,
    Compare,
}

impl ActiveScreen {
    pub fn from_str(value: &str) -> Self {
        match value {
            "compare" => Self::Compare,
            _ => Self::Browse,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Browse => "browse",
            Self::Compare => "compare",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowsePane {
    Tree,
    Detail,
}

impl BrowsePane {
    pub fn from_str(value: &str) -> Self {
        match value {
            "detail" => Self::Detail,
            _ => Self::Tree,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tree => "tree",
            Self::Detail => "detail",
        }
    }

    pub fn cycle_forward(self) -> Self {
        match self {
            Self::Tree => Self::Detail,
            Self::Detail => Self::Tree,
        }
    }

    #[allow(dead_code)]
    pub fn cycle_backward(self) -> Self {
        match self {
            Self::Tree => Self::Detail,
            Self::Detail => Self::Tree,
        }
    }
}

pub struct ViewStateController {
    pub active_screen: ActiveScreen,
    pub expanded_paths: Vec<NodePath>,
    pub selection: NodePath,
    pub browse_pane: BrowsePane,
    pub compare_fork: Option<NodePath>,
    pub compare_row: usize,
    dirty: bool,
    last_change: Option<Instant>,
}

impl ViewStateController {
    pub fn from_document(tree: &ExploreTree, document: &SessionDocument) -> Self {
        if let Some(state) = &document.view_state {
            restore_from_state(tree, state)
        } else {
            Self::default_for_tree(tree)
        }
    }

    pub fn default_for_tree(tree: &ExploreTree) -> Self {
        let selection = NodePath::root(tree.tree_index);
        Self {
            active_screen: ActiveScreen::Browse,
            expanded_paths: tree.default_expanded_paths(),
            selection,
            browse_pane: BrowsePane::Tree,
            compare_fork: None,
            compare_row: 0,
            dirty: false,
            last_change: None,
        }
    }

    pub fn mark_dirty(&mut self) {
        self.dirty = true;
        self.last_change = Some(Instant::now());
    }

    pub fn should_persist_now(&self, force: bool) -> bool {
        if !self.dirty {
            return false;
        }
        if force {
            return true;
        }
        self.last_change
            .is_some_and(|instant| instant.elapsed() >= PERSIST_DEBOUNCE)
    }

    pub fn persisted(&mut self) {
        self.dirty = false;
        self.last_change = None;
    }

    pub fn to_view_state(&self) -> ExploreViewState {
        ExploreViewState {
            active_screen: self.active_screen.as_str().into(),
            expanded_paths: self
                .expanded_paths
                .iter()
                .map(|path| path.path.clone())
                .collect(),
            selection: self.selection.path.clone(),
            pane: self.browse_pane.as_str().into(),
            compare_focus_row: self.compare_row,
        }
    }

    pub fn selected_visible_index(&self, tree: &ExploreTree) -> usize {
        tree.visible_index_for_selection(&self.selection, &self.expanded_paths)
            .unwrap_or(0)
    }

    pub fn set_selection_visible_index(&mut self, tree: &ExploreTree, index: usize) {
        if let Some(path) = tree.selection_for_visible_index(index, &self.expanded_paths) {
            self.selection = path;
            self.mark_dirty();
        }
    }

    pub fn toggle_expansion(&mut self, path: &NodePath) {
        if let Some(index) = self
            .expanded_paths
            .iter()
            .position(|existing| existing == path)
        {
            self.expanded_paths.remove(index);
        } else {
            self.expanded_paths.push(path.clone());
        }
        self.mark_dirty();
    }

    pub fn expand_all(&mut self, tree: &ExploreTree) {
        self.expanded_paths = tree.default_expanded_paths();
        for path in tree.trace().display_order() {
            if tree.has_children(&path)
                && !self.expanded_paths.iter().any(|existing| existing == &path)
            {
                self.expanded_paths.push(path);
            }
        }
        self.mark_dirty();
    }

    pub fn collapse_all(&mut self, tree: &ExploreTree) {
        self.expanded_paths.clear();
        self.selection = tree.nearest_visible_ancestor(&self.selection, &self.expanded_paths);
        self.mark_dirty();
    }
}

pub fn restore_from_state(tree: &ExploreTree, state: &ExploreViewState) -> ViewStateController {
    let tree_index = tree.tree_index;
    let expanded_paths: Vec<NodePath> = state
        .expanded_paths
        .iter()
        .map(|path| NodePath {
            tree: tree_index,
            path: path.clone(),
        })
        .filter(|path| tree.node_at(path).is_some())
        .collect();

    let selection = NodePath {
        tree: tree_index,
        path: state.selection.clone(),
    };
    let selection = if tree.node_at(&selection).is_some() {
        selection
    } else {
        NodePath::root(tree_index)
    };

    let expanded_paths = if expanded_paths.is_empty() {
        tree.default_expanded_paths()
    } else {
        expanded_paths
    };

    ViewStateController {
        active_screen: ActiveScreen::from_str(&state.active_screen),
        expanded_paths,
        selection,
        browse_pane: BrowsePane::from_str(&state.pane),
        compare_fork: None,
        compare_row: state.compare_focus_row,
        dirty: false,
        last_change: None,
    }
}

pub fn apply_view_state(document: &mut SessionDocument, controller: &ViewStateController) {
    document.view_state = Some(controller.to_view_state());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionDocument;
    use crate::trace_request::TraceRequest;
    use dns_resolve::{HopOutcome, TraceHop, TraceTreeRequest, build_linear_tree};

    fn sample_tree() -> ExploreTree {
        let trace = build_linear_tree(
            vec![
                TraceHop {
                    zone: ".".into(),
                    server: "198.41.0.4".into(),
                    server_name: None,
                    qname: "example.com.".into(),
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
                },
                TraceHop {
                    zone: "com.".into(),
                    server: "192.41.162.30".into(),
                    server_name: None,
                    qname: "example.com.".into(),
                    qtype: "A".into(),
                    transport: "udp".into(),
                    rtt_ms: 8,
                    rcode: "NOERROR".into(),
                    nsid: None,
                    ede_code: None,
                    ede_text: None,
                    referral_ns: vec![],
                    glue: vec![],
                    response: Default::default(),
                    from_cache: false,
                    outcome: HopOutcome::Answered,
                },
            ],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-08-25T00:00:00Z".into(),
            },
        );
        crate::explore::tree::build_explore_tree(&trace)
    }

    #[test]
    fn restores_expansion_and_selection() {
        let tree = sample_tree();
        let mut controller = ViewStateController::default_for_tree(&tree);
        controller.expanded_paths = vec![NodePath::root(0)];
        controller.selection = NodePath {
            tree: 0,
            path: vec![0],
        };
        controller.active_screen = ActiveScreen::Compare;
        controller.compare_row = 1;

        let document = SessionDocument {
            version: 2,
            id: "01TEST".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
            pinned: false,
            trees: vec![crate::session::SessionTree {
                request: TraceRequest::from_options(&crate::dig_options::TraceOptions {
                    qname: "example.com".into(),
                    ..Default::default()
                }),
                tree: tree.trace().clone(),
            }],
            view_state: Some(controller.to_view_state()),
        };

        let restored = ViewStateController::from_document(&tree, &document);
        assert_eq!(restored.active_screen, ActiveScreen::Compare);
        assert_eq!(restored.selection.path, vec![0]);
        assert!(restored.expanded_paths.contains(&NodePath::root(0)));
    }

    #[test]
    fn drops_stale_paths_on_restore() {
        let tree = sample_tree();
        let state = ExploreViewState {
            active_screen: "browse".into(),
            expanded_paths: vec![vec![99]],
            selection: vec![99],
            pane: "tree".into(),
            compare_focus_row: 0,
        };
        let restored = restore_from_state(&tree, &state);
        assert_eq!(restored.selection, NodePath::root(0));
        assert!(
            !restored
                .expanded_paths
                .iter()
                .any(|path| path.path == vec![99])
        );
    }

    #[test]
    fn collapse_all_moves_selection_to_visible_ancestor() {
        let tree = sample_tree();
        let mut controller = ViewStateController::default_for_tree(&tree);
        controller.selection = NodePath {
            tree: 0,
            path: vec![0],
        };
        controller.expand_all(&tree);
        controller.collapse_all(&tree);
        assert_eq!(controller.selection, NodePath::root(0));
        assert!(controller.expanded_paths.is_empty());
    }

    #[test]
    fn debounce_blocks_immediate_persist() {
        let tree = sample_tree();
        let mut controller = ViewStateController::default_for_tree(&tree);
        controller.mark_dirty();
        assert!(!controller.should_persist_now(false));
        assert!(controller.should_persist_now(true));
    }
}
