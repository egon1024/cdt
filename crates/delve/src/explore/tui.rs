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

pub fn run_tui(tree: &ExploreTree) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut expanded_paths: Vec<Vec<usize>> = default_expanded_paths(tree);
    let mut selected = 0;
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
                    let style = if index == selected {
                        Style::default().add_modifier(Modifier::REVERSED)
                    } else {
                        Style::default()
                    };
                    ListItem::new(Line::from(format!("{indent}{marker}{}", node.label)))
                        .style(style)
                })
                .collect();

            let tree_widget = List::new(tree_items).block(
                Block::default()
                    .title(format!("{} {}", tree.qname, tree.qtype))
                    .borders(Borders::ALL),
            );
            frame.render_widget(tree_widget, chunks[0]);

            let detail = detail_text(tree, visible.get(selected));
            let detail_widget = Paragraph::new(detail)
                .block(Block::default().title("Details").borders(Borders::ALL))
                .wrap(Wrap { trim: false });
            frame.render_widget(detail_widget, chunks[1]);
        })?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Down | KeyCode::Char('j') if selected + 1 < visible.len() => {
                        selected += 1;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        selected = selected.saturating_sub(1);
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
                    KeyCode::Char('?') => {}
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
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
                .map(|answer| format!("final: {}", answer.records.join(", ")))
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
    let referral = hop.referral_ns.first().map(String::as_str).unwrap_or("—");
    format!(
        "[{}] {} → {}  {}  {}ms  {}",
        hop.zone, hop.qname, referral, hop.server, hop.rtt_ms, hop.rcode
    )
}

fn hop_label(hop: &TraceHop) -> String {
    format!(
        "[{}] {}  {}  {}ms  {}",
        hop.zone, hop.qname, hop.server, hop.rtt_ms, hop.rcode
    )
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

fn format_hop_detail(hop: &TraceHop) -> String {
    let mut lines = vec![
        format!("zone: {}", hop.zone),
        format!("query: {} {}", hop.qname, hop.qtype),
        format!("server: {} ({})", hop.server, hop.transport),
        format!("rtt: {}ms", hop.rtt_ms),
        format!("rcode: {}", hop.rcode),
    ];
    if let Some(nsid) = &hop.nsid {
        lines.push(format!("nsid: {nsid}"));
    }
    if let Some(code) = hop.ede_code {
        let text = hop.ede_text.as_deref().unwrap_or("");
        lines.push(format!("ede: {code}:{text}"));
    }
    if !hop.referral_ns.is_empty() {
        lines.push(format!("referral NS: {}", hop.referral_ns.join(", ")));
    }
    if !hop.glue.is_empty() {
        lines.push(format!("glue: {}", hop.glue.join(", ")));
    }
    lines.join("\n")
}

fn format_final_answer(answer: &dns_resolve::FinalAnswer) -> String {
    let mut lines = vec![
        format!("server: {}", answer.server),
        format!("rtt: {}ms", answer.rtt_ms),
        format!("rcode: {}", answer.rcode),
    ];
    if let Some(nsid) = &answer.nsid {
        lines.push(format!("nsid: {nsid}"));
    }
    if !answer.records.is_empty() {
        lines.push("records:".into());
        for record in &answer.records {
            lines.push(format!("  {record}"));
        }
    }
    lines.join("\n")
}
