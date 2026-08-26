use std::io;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use dns_resolve::TraceHop;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

use super::detail::{format_final_answer, format_hop_detail, hop_summary_line};
use super::tree::{ExploreNode, ExploreTree};

#[derive(Debug, Clone)]
struct VisibleNode {
    label: String,
    node: NodeRef,
    depth: usize,
    expandable: bool,
    expanded: bool,
}

#[derive(Debug, Clone)]
enum NodeRef {
    Delegation { hop_index: usize, path: Vec<usize> },
    Resolve { target: String, path: Vec<usize> },
    Hop { hop_index: usize },
    Final,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pane {
    Tree,
    Detail,
}

impl Pane {
    const ORDER: [Self; 2] = [Self::Tree, Self::Detail];

    fn cycle_forward(self) -> Self {
        let index = Self::index_of(self);
        Self::ORDER[(index + 1) % Self::ORDER.len()]
    }

    fn cycle_backward(self) -> Self {
        let index = Self::index_of(self);
        let len = Self::ORDER.len();
        Self::ORDER[(index + len - 1) % len]
    }

    fn index_of(pane: Self) -> usize {
        Self::ORDER
            .iter()
            .position(|candidate| *candidate == pane)
            .unwrap_or(0)
    }
}

pub fn run_tui(tree: &ExploreTree) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut expanded_paths: Vec<Vec<usize>> = default_expanded_paths(tree);
    let mut selected = 0;
    let mut focused = Pane::Tree;
    let mut detail_scroll = 0u16;
    let mut result = Ok(());

    loop {
        let visible = build_visible_nodes(tree, &expanded_paths);
        if selected >= visible.len() {
            selected = visible.len().saturating_sub(1);
        }

        terminal.draw(|frame| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                .split(frame.area());

            let tree_items: Vec<ListItem> = visible
                .iter()
                .enumerate()
                .map(|(index, node)| {
                    let indent = "  ".repeat(node.depth);
                    let marker = if node.expandable {
                        if node.expanded { "▼ " } else { "▶ " }
                    } else {
                        "  "
                    };
                    let mut style = Style::default();
                    if focused == Pane::Tree && index == selected {
                        style = style.add_modifier(Modifier::REVERSED);
                    }
                    ListItem::new(Line::from(format!("{indent}{marker}{}", node.label)))
                        .style(style)
                })
                .collect();

            let tree_title = if focused == Pane::Tree {
                format!("{} {}  [tree]", tree.qname, tree.qtype)
            } else {
                format!("{} {}  [tree — Tab / Shift-Tab]", tree.qname, tree.qtype)
            };
            let tree_widget = List::new(tree_items)
                .block(Block::default().title(tree_title).borders(Borders::ALL));
            frame.render_widget(tree_widget, chunks[0]);

            let detail = detail_text(tree, visible.get(selected));
            let detail_title = if focused == Pane::Detail {
                "Details  [focused — j/k scroll]".to_string()
            } else {
                "Details  [Tab / Shift-Tab]".to_string()
            };
            let detail_widget = Paragraph::new(detail)
                .block(Block::default().title(detail_title).borders(Borders::ALL))
                .wrap(Wrap { trim: false })
                .scroll((detail_scroll, 0));
            frame.render_widget(detail_widget, chunks[1]);
        })?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Tab => focused = focused.cycle_forward(),
                    KeyCode::BackTab => focused = focused.cycle_backward(),
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Char('?') => {}
                    _ if focused == Pane::Tree => match key.code {
                        KeyCode::Down | KeyCode::Char('j') if selected + 1 < visible.len() => {
                            selected += 1;
                            detail_scroll = 0;
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            selected = selected.saturating_sub(1);
                            detail_scroll = 0;
                        }
                        KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                            if let Some(node) = visible.get(selected)
                                && node.expandable
                            {
                                toggle_path(&mut expanded_paths, &node.node);
                            }
                        }
                        KeyCode::Left | KeyCode::Char('h') => {
                            if let Some(node) = visible.get(selected)
                                && node.expandable
                                && node.expanded
                            {
                                toggle_path(&mut expanded_paths, &node.node);
                            }
                        }
                        _ => {}
                    },
                    _ if focused == Pane::Detail => match key.code {
                        KeyCode::Down | KeyCode::Char('j') => {
                            detail_scroll = detail_scroll.saturating_add(1);
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            detail_scroll = detail_scroll.saturating_sub(1);
                        }
                        KeyCode::PageDown | KeyCode::Char(' ') => {
                            detail_scroll = detail_scroll.saturating_add(10);
                        }
                        KeyCode::PageUp => {
                            detail_scroll = detail_scroll.saturating_sub(10);
                        }
                        KeyCode::Home => {
                            detail_scroll = 0;
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    if let Err(error) = execute!(terminal.backend_mut(), LeaveAlternateScreen) {
        result = Err(error);
    }
    terminal.show_cursor()?;
    result
}

fn default_expanded_paths(tree: &ExploreTree) -> Vec<Vec<usize>> {
    let mut paths = Vec::new();
    for (index, child) in tree.children.iter().enumerate() {
        collect_expandable_paths(child, vec![index], &mut paths);
    }
    paths
}

fn collect_expandable_paths(node: &ExploreNode, path: Vec<usize>, paths: &mut Vec<Vec<usize>>) {
    if has_children(node) {
        paths.push(path.clone());
        match node {
            ExploreNode::Delegation { children, .. } | ExploreNode::Resolve { children, .. } => {
                for (index, child) in children.iter().enumerate() {
                    let mut child_path = path.clone();
                    child_path.push(index);
                    collect_expandable_paths(child, child_path, paths);
                }
            }
            ExploreNode::Hop { .. } | ExploreNode::Final => {}
        }
    }
}

fn has_children(node: &ExploreNode) -> bool {
    match node {
        ExploreNode::Delegation { children, .. } => !children.is_empty(),
        ExploreNode::Resolve { children, .. } => !children.is_empty(),
        ExploreNode::Hop { .. } | ExploreNode::Final => false,
    }
}

fn toggle_path(expanded_paths: &mut Vec<Vec<usize>>, node_ref: &NodeRef) {
    let Some(path) = node_path(node_ref) else {
        return;
    };
    if let Some(index) = expanded_paths.iter().position(|existing| existing == &path) {
        expanded_paths.remove(index);
    } else {
        expanded_paths.push(path);
    }
}

fn node_path(node_ref: &NodeRef) -> Option<Vec<usize>> {
    match node_ref {
        NodeRef::Delegation { path, .. } | NodeRef::Resolve { path, .. } => Some(path.clone()),
        NodeRef::Hop { .. } | NodeRef::Final => None,
    }
}

fn build_visible_nodes(tree: &ExploreTree, expanded_paths: &[Vec<usize>]) -> Vec<VisibleNode> {
    let mut visible = Vec::new();
    for (index, child) in tree.children.iter().enumerate() {
        append_visible_node(tree, child, vec![index], 0, expanded_paths, &mut visible);
    }
    visible
}

fn append_visible_node(
    tree: &ExploreTree,
    node: &ExploreNode,
    path: Vec<usize>,
    depth: usize,
    expanded_paths: &[Vec<usize>],
    visible: &mut Vec<VisibleNode>,
) {
    let expandable = has_children(node);
    let expanded = expandable && expanded_paths.iter().any(|existing| existing == &path);

    let (label, node_ref) = match node {
        ExploreNode::Delegation { hop_index, .. } => {
            let hop = tree.hop(*hop_index);
            (
                delegation_label(hop),
                NodeRef::Delegation {
                    hop_index: *hop_index,
                    path: path.clone(),
                },
            )
        }
        ExploreNode::Resolve { target, .. } => (
            format!("resolve {target}"),
            NodeRef::Resolve {
                target: target.clone(),
                path: path.clone(),
            },
        ),
        ExploreNode::Hop { hop_index } => {
            let hop = tree.hop(*hop_index);
            (
                hop_label(hop),
                NodeRef::Hop {
                    hop_index: *hop_index,
                },
            )
        }
        ExploreNode::Final => {
            let label = tree
                .trace()
                .final_response
                .as_ref()
                .and_then(|answer| answer.records.first())
                .map(|record| format!("final: {record}"))
                .unwrap_or_else(|| "final".into());
            (label, NodeRef::Final)
        }
    };

    visible.push(VisibleNode {
        label,
        node: node_ref,
        depth,
        expandable,
        expanded,
    });

    if !expanded {
        return;
    }

    let children = match node {
        ExploreNode::Delegation { children, .. } | ExploreNode::Resolve { children, .. } => {
            children
        }
        ExploreNode::Hop { .. } | ExploreNode::Final => return,
    };

    for (index, child) in children.iter().enumerate() {
        let mut child_path = path.clone();
        child_path.push(index);
        append_visible_node(tree, child, child_path, depth + 1, expanded_paths, visible);
    }
}

fn delegation_label(hop: &TraceHop) -> String {
    format!("{}  {}ms  {}", hop_summary_line(hop), hop.rtt_ms, hop.rcode)
}

fn hop_label(hop: &TraceHop) -> String {
    delegation_label(hop)
}

fn detail_text(tree: &ExploreTree, selected: Option<&VisibleNode>) -> String {
    let Some(selected) = selected else {
        return "Select a node to inspect hop details.".into();
    };

    match &selected.node {
        NodeRef::Delegation { hop_index, .. } | NodeRef::Hop { hop_index } => {
            format_hop_detail(tree.hop(*hop_index))
        }
        NodeRef::Resolve { target, .. } => format!("Nameserver resolution for {target}"),
        NodeRef::Final => tree
            .trace()
            .final_response
            .as_ref()
            .map(format_final_answer)
            .unwrap_or_else(|| "No final answer recorded.".into()),
    }
}

#[cfg(test)]
mod pane_tests {
    use super::Pane;

    #[test]
    fn tab_cycles_forward_through_panes() {
        assert_eq!(Pane::Tree.cycle_forward(), Pane::Detail);
        assert_eq!(Pane::Detail.cycle_forward(), Pane::Tree);
    }

    #[test]
    fn shift_tab_cycles_backward_through_panes() {
        assert_eq!(Pane::Tree.cycle_backward(), Pane::Detail);
        assert_eq!(Pane::Detail.cycle_backward(), Pane::Tree);
    }
}
