use std::io;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use dns_resolve::TraceHop;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::block::BorderType;
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};

use super::dig_view::{final_detail_styled, hop_detail_styled};
use super::theme::Theme;
use super::tree::{ExploreNode, ExploreTree};

#[derive(Debug, Clone)]
struct VisibleNode {
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
    let mut show_help = false;
    let mut theme = Theme::from_env();
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
                    let mut line = tree_line(tree, node, &indent, marker, &theme);
                    if focused == Pane::Tree && index == selected {
                        line = line.style(theme.tree_selected());
                    }
                    ListItem::new(line)
                })
                .collect();

            let color_hint = if theme.color_enabled { "on" } else { "off" };
            let tree_title = if focused == Pane::Tree {
                format!("{} {}  [tree]  color:{color_hint}", tree.qname, tree.qtype)
            } else {
                format!(
                    "{} {}  [Tab / Shift-Tab]  color:{color_hint}",
                    tree.qname, tree.qtype
                )
            };
            let tree_widget = List::new(tree_items).block(
                Block::default()
                    .title(tree_title)
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(if focused == Pane::Tree {
                        theme.border_focused()
                    } else {
                        theme.border_unfocused()
                    }),
            );
            frame.render_widget(tree_widget, chunks[0]);

            let detail_lines = detail_content(tree, visible.get(selected), &theme);
            let detail_title = if focused == Pane::Detail {
                "Details  [focused — j/k scroll]".to_string()
            } else {
                "Details  [Tab / Shift-Tab]".to_string()
            };
            let detail_widget = Paragraph::new(detail_lines)
                .block(
                    Block::default()
                        .title(detail_title)
                        .borders(Borders::ALL)
                        .border_type(BorderType::Rounded)
                        .border_style(if focused == Pane::Detail {
                            theme.border_focused()
                        } else {
                            theme.border_unfocused()
                        }),
                )
                .wrap(Wrap { trim: false })
                .scroll((detail_scroll, 0));
            frame.render_widget(detail_widget, chunks[1]);

            if show_help {
                render_help_overlay(frame, &theme);
            }
        })?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if show_help {
                    match key.code {
                        KeyCode::Char('h') | KeyCode::Esc => show_help = false,
                        KeyCode::Char('q') => break,
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            break;
                        }
                        KeyCode::Char('c') => theme.toggle_color(),
                        _ => {}
                    }
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('h') => show_help = true,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Char('c') => theme.toggle_color(),
                    KeyCode::Tab => focused = focused.cycle_forward(),
                    KeyCode::BackTab => focused = focused.cycle_backward(),
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
                        KeyCode::Left => {
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

fn tree_line(
    tree: &ExploreTree,
    node: &VisibleNode,
    indent: &str,
    marker: &str,
    theme: &Theme,
) -> Line<'static> {
    match &node.node {
        NodeRef::Delegation { hop_index, .. } | NodeRef::Hop { hop_index } => {
            let hop = tree.hop(*hop_index);
            hop_tree_line(indent, marker, hop, theme)
        }
        NodeRef::Resolve { target, .. } => Line::from(vec![
            Span::raw(format!("{indent}{marker}")),
            Span::styled("resolve ", theme.accent()),
            Span::raw(target.clone()),
        ]),
        NodeRef::Final => {
            let answer = tree.trace().final_response.as_ref();
            Line::from(vec![
                Span::raw(format!("{indent}{marker}")),
                Span::styled(
                    format!("{} {}  ", tree.qname, tree.qtype),
                    theme.accent_bold(),
                ),
                Span::styled(
                    format!("{}ms  ", answer.map(|a| a.rtt_ms).unwrap_or(0)),
                    theme.meta(),
                ),
                Span::styled(
                    answer
                        .map(|a| a.rcode.clone())
                        .unwrap_or_else(|| "—".into()),
                    theme.rcode(answer.map(|a| a.rcode.as_str()).unwrap_or("")),
                ),
            ])
        }
    }
}

fn hop_tree_line(indent: &str, marker: &str, hop: &TraceHop, theme: &Theme) -> Line<'static> {
    Line::from(vec![
        Span::raw(format!("{indent}{marker}")),
        Span::styled(format!("[{}] ", hop.zone), theme.zone()),
        Span::raw(format!("{} {}  ", hop.qname, hop.qtype)),
        Span::styled(format!("{}ms  ", hop.rtt_ms), theme.meta()),
        Span::styled(hop.rcode.clone(), theme.rcode(&hop.rcode)),
    ])
}

fn detail_content(
    tree: &ExploreTree,
    selected: Option<&VisibleNode>,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let Some(selected) = selected else {
        return vec![Line::from(Span::styled(
            "Select a node to inspect hop details.",
            theme.meta(),
        ))];
    };

    match &selected.node {
        NodeRef::Delegation { hop_index, .. } | NodeRef::Hop { hop_index } => {
            hop_detail_styled(tree.hop(*hop_index), theme)
        }
        NodeRef::Resolve { target, .. } => vec![
            Line::from(Span::styled("Nameserver resolution", theme.section())),
            Line::from(vec![
                Span::styled("target: ", theme.label()),
                Span::raw(target.clone()),
            ]),
        ],
        NodeRef::Final => tree
            .trace()
            .final_response
            .as_ref()
            .map(|answer| final_detail_styled(answer, theme))
            .unwrap_or_else(|| {
                vec![Line::from(Span::styled(
                    "No final answer recorded.",
                    theme.meta(),
                ))]
            }),
    }
}

fn render_help_overlay(frame: &mut ratatui::Frame<'_>, theme: &Theme) {
    let area = centered_rect(62, 72, frame.area());
    frame.render_widget(Clear, area);

    let help_text = Paragraph::new(help_lines(theme))
        .block(
            Block::default()
                .title("Keyboard shortcuts")
                .title_alignment(Alignment::Center)
                .title_style(theme.accent_bold())
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(theme.border_focused()),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(help_text, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn help_lines(theme: &Theme) -> Vec<Line<'static>> {
    vec![
        help_section("General", theme),
        help_binding("h", "Show this help", theme),
        help_binding("Esc, h", "Close help", theme),
        help_binding("q, Esc", "Quit", theme),
        help_binding("Ctrl+C", "Quit", theme),
        help_binding("c", "Toggle colors (respects NO_COLOR)", theme),
        help_binding("Tab", "Next pane", theme),
        help_binding("Shift-Tab", "Previous pane", theme),
        Line::from(""),
        help_section("Tree pane", theme),
        help_binding("j, ↓", "Move selection down", theme),
        help_binding("k, ↑", "Move selection up", theme),
        help_binding("Enter, l, →", "Expand node", theme),
        help_binding("←", "Collapse node", theme),
        Line::from(""),
        help_section("Details pane", theme),
        help_binding("j, ↓", "Scroll down", theme),
        help_binding("k, ↑", "Scroll up", theme),
        help_binding("Space, PgDn", "Page down", theme),
        help_binding("PgUp", "Page up", theme),
        help_binding("Home", "Scroll to top", theme),
    ]
}

fn help_section(title: &str, theme: &Theme) -> Line<'static> {
    Line::from(Span::styled(title.to_string(), theme.help_heading()))
}

fn help_binding(keys: &str, description: &str, theme: &Theme) -> Line<'static> {
    Line::from(vec![
        Span::raw("  "),
        Span::styled(format!("{keys:<14}"), theme.help_key()),
        Span::raw(format!(" {description}")),
    ])
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
        append_visible_node(child, vec![index], 0, expanded_paths, &mut visible);
    }
    visible
}

fn append_visible_node(
    node: &ExploreNode,
    path: Vec<usize>,
    depth: usize,
    expanded_paths: &[Vec<usize>],
    visible: &mut Vec<VisibleNode>,
) {
    let expandable = has_children(node);
    let expanded = expandable && expanded_paths.iter().any(|existing| existing == &path);

    let node_ref = match node {
        ExploreNode::Delegation { hop_index, .. } => NodeRef::Delegation {
            hop_index: *hop_index,
            path: path.clone(),
        },
        ExploreNode::Resolve { target, .. } => NodeRef::Resolve {
            target: target.clone(),
            path: path.clone(),
        },
        ExploreNode::Hop { hop_index } => NodeRef::Hop {
            hop_index: *hop_index,
        },
        ExploreNode::Final => NodeRef::Final,
    };

    visible.push(VisibleNode {
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
        append_visible_node(child, child_path, depth + 1, expanded_paths, visible);
    }
}

#[cfg(test)]
mod pane_tests {
    use super::{Pane, help_lines};
    use crate::explore::theme::Theme;

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

    #[test]
    fn help_overlay_lists_expected_bindings() {
        let theme = Theme::from_env();
        let text: String = help_lines(&theme)
            .into_iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");

        assert!(text.contains("h              Show this help"));
        assert!(text.contains("Shift-Tab      Previous pane"));
        assert!(text.contains("←              Collapse node"));
        assert!(text.contains("Toggle colors"));
    }
}
