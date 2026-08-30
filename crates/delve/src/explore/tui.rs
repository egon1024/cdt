use std::io;
use std::sync::mpsc;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use dns_resolve::{HopOutcome, NodePath, TraceHop, TraceProgress};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Position, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::block::BorderType;
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::branch::{
    BranchError, BranchIntentArg, BranchReport, ServerTargetInput, branch_session,
};
use crate::paths::DelvePaths;
use crate::runtime::Runtime;
use crate::session::SessionDocument;

use super::detail::hop_failure_line;
use super::dig_view::hop_detail_styled;
use super::pane_split::{AxisScrollHints, VerticalPaneSplit};
use super::terminal::{cache_source_legend, cache_source_symbol};
use super::theme::Theme;
use super::tree::{ExploreTree, VisibleNode};
use super::view_state::{ActiveScreen, BrowsePane, ViewStateController, apply_view_state};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BrowseScrollLimits {
    detail_max_scroll: u16,
    tree_max_scroll_x: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BranchOverlay {
    None,
    Menu,
    AlternateInput,
}

#[derive(Debug)]
enum BranchWorkerMessage {
    Progress(String),
    Done(Result<BranchReport, BranchError>),
}

pub struct ExploreContext<'a> {
    pub runtime: &'a Runtime,
    pub document: &'a mut SessionDocument,
    pub persist_view_state: bool,
}

pub fn run_tui(ctx: ExploreContext<'_>) -> io::Result<()> {
    let runtime = ctx.runtime;
    let document = ctx.document;
    let persist_view_state = ctx.persist_view_state;
    let mut tree = explore_tree_from_document(document);
    let session_id = document.id.clone();
    let paths = runtime.paths.clone();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut view = ViewStateController::from_document(&tree, document);
    let mut theme = Theme::from_env();
    let mut detail_scroll = 0u16;
    let mut tree_scroll_x = 0u16;
    let mut show_help = false;
    let mut unavailable_message: Option<String> = None;
    let mut branch_overlay = BranchOverlay::None;
    let mut alternate_server_input = String::new();
    let mut branch_rx: Option<mpsc::Receiver<BranchWorkerMessage>> = None;
    let mut branch_progress: Option<String> = None;
    let mut persist_warning_shown = false;
    let mut result = Ok(());

    loop {
        let mut branch_finished = false;
        if let Some(rx) = &branch_rx {
            while let Ok(message) = rx.try_recv() {
                match message {
                    BranchWorkerMessage::Progress(text) => branch_progress = Some(text),
                    BranchWorkerMessage::Done(report) => {
                        branch_finished = true;
                        branch_progress = None;
                        branch_overlay = BranchOverlay::None;
                        match report {
                            Ok(report) => {
                                if report.nodes_added > 0 {
                                    if let Ok(updated) = runtime.get_session(&session_id) {
                                        *document = updated;
                                        tree = explore_tree_from_document(document);
                                        if !view
                                            .expanded_paths
                                            .iter()
                                            .any(|path| path == &view.selection)
                                        {
                                            view.expanded_paths.push(view.selection.clone());
                                        }
                                    }
                                    view.mark_dirty();
                                    persist_view_state_now(
                                        runtime,
                                        document,
                                        persist_view_state,
                                        &mut view,
                                        &mut persist_warning_shown,
                                        true,
                                    );
                                }
                                unavailable_message = Some(format_branch_report(&report));
                            }
                            Err(error) => {
                                unavailable_message = Some(error.to_string());
                            }
                        }
                    }
                }
            }
        }
        if branch_finished {
            branch_rx = None;
        }

        if view.should_persist_now(false) {
            persist_view_state_now(
                runtime,
                document,
                persist_view_state,
                &mut view,
                &mut persist_warning_shown,
                false,
            );
        }

        let visible = tree.visible_nodes(&view.expanded_paths);
        let selected_index = view.selected_visible_index(&tree);
        if selected_index >= visible.len() {
            view.set_selection_visible_index(&tree, visible.len().saturating_sub(1));
        }

        let scroll_limits = browse_scroll_limits(
            Rect::from((Position::ORIGIN, terminal.size()?)),
            view.browse_split,
            &tree,
            &visible,
            selected_index,
            &theme,
        );
        detail_scroll = detail_scroll.min(scroll_limits.detail_max_scroll);
        tree_scroll_x = tree_scroll_x.min(scroll_limits.tree_max_scroll_x);

        terminal.draw(|frame| {
            let header = screen_indicator(&view, &tree, &theme);
            let body = frame.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(1), Constraint::Min(0)])
                .split(body);

            frame.render_widget(Paragraph::new(header).style(theme.meta()), chunks[0]);

            match view.active_screen {
                ActiveScreen::Browse => render_browse(
                    frame,
                    chunks[1],
                    &tree,
                    &visible,
                    selected_index,
                    &view,
                    detail_scroll,
                    tree_scroll_x,
                    &theme,
                    &session_id,
                ),
                ActiveScreen::Compare => render_compare(
                    frame,
                    chunks[1],
                    &tree,
                    &view,
                    &theme,
                    unavailable_message.as_deref(),
                ),
            }

            if show_help {
                render_help_overlay(frame, &view, &theme);
            }
            if branch_overlay != BranchOverlay::None || branch_progress.is_some() {
                render_branch_overlay(
                    frame,
                    &theme,
                    branch_overlay,
                    &alternate_server_input,
                    branch_progress.as_deref(),
                );
            }
            if let Some(message) = &unavailable_message
                && view.active_screen != ActiveScreen::Compare
                && branch_overlay == BranchOverlay::None
                && branch_progress.is_none()
            {
                render_message_overlay(frame, &theme, message);
            }
        })?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                if branch_rx.is_some() {
                    if matches!(key.code, KeyCode::Esc) {
                        unavailable_message =
                            Some("branch in progress; wait for completion".into());
                    }
                    continue;
                }

                if show_help {
                    match key.code {
                        KeyCode::Char('?') | KeyCode::Esc => show_help = false,
                        KeyCode::Char('q') => break,
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            break;
                        }
                        KeyCode::Char('c') => theme.toggle_color(),
                        _ => {}
                    }
                    continue;
                }

                if branch_overlay == BranchOverlay::AlternateInput {
                    match key.code {
                        KeyCode::Esc => branch_overlay = BranchOverlay::Menu,
                        KeyCode::Enter => {
                            let target = alternate_server_input.trim();
                            if target.is_empty() {
                                unavailable_message = Some("server address required".into());
                            } else {
                                start_branch(
                                    &paths,
                                    session_id.clone(),
                                    view.selection.clone(),
                                    BranchIntentArg::AlternateServer {
                                        target: parse_server_target_input(target),
                                    },
                                    &mut branch_rx,
                                );
                                branch_overlay = BranchOverlay::None;
                                alternate_server_input.clear();
                                persist_view_state_now(
                                    runtime,
                                    document,
                                    persist_view_state,
                                    &mut view,
                                    &mut persist_warning_shown,
                                    true,
                                );
                            }
                        }
                        KeyCode::Backspace => {
                            alternate_server_input.pop();
                        }
                        KeyCode::Char(ch) => alternate_server_input.push(ch),
                        _ => {}
                    }
                    continue;
                }

                if branch_overlay == BranchOverlay::Menu {
                    match key.code {
                        KeyCode::Esc | KeyCode::Char('b') => branch_overlay = BranchOverlay::None,
                        KeyCode::Char('e') => {
                            start_branch(
                                &paths,
                                session_id.clone(),
                                view.selection.clone(),
                                BranchIntentArg::ExpandCut,
                                &mut branch_rx,
                            );
                            branch_overlay = BranchOverlay::None;
                            persist_view_state_now(
                                runtime,
                                document,
                                persist_view_state,
                                &mut view,
                                &mut persist_warning_shown,
                                true,
                            );
                        }
                        KeyCode::Char('a') => {
                            branch_overlay = BranchOverlay::AlternateInput;
                            alternate_server_input.clear();
                        }
                        _ => {}
                    }
                    continue;
                }

                if unavailable_message.is_some() {
                    match key.code {
                        KeyCode::Enter | KeyCode::Char(' ') => {
                            unavailable_message = None;
                        }
                        KeyCode::Char('q') => break,
                        KeyCode::Esc => unavailable_message = None,
                        _ => {}
                    }
                    if unavailable_message.is_none() {
                        continue;
                    }
                }

                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('?') => show_help = true,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Char('c') => {
                        theme.toggle_color();
                        view.mark_dirty();
                    }
                    KeyCode::Tab => {
                        cycle_screen_forward(&mut view, &tree, &mut unavailable_message)
                    }
                    KeyCode::BackTab => {
                        cycle_screen_backward(&mut view, &tree, &mut unavailable_message)
                    }
                    KeyCode::Char('1') => select_screen(
                        &mut view,
                        ActiveScreen::Browse,
                        &tree,
                        &mut unavailable_message,
                    ),
                    KeyCode::Char('2') => select_screen(
                        &mut view,
                        ActiveScreen::Compare,
                        &tree,
                        &mut unavailable_message,
                    ),
                    KeyCode::Char('m') => {
                        jump_to_compare(&mut view, &tree, &mut unavailable_message)
                    }
                    KeyCode::Char('E') => {
                        view.expand_all(&tree);
                        detail_scroll = 0;
                    }
                    KeyCode::Char('C') => {
                        view.collapse_all(&tree);
                        detail_scroll = 0;
                    }
                    KeyCode::Char('+') | KeyCode::Char('=') => {
                        if view.active_screen == ActiveScreen::Browse {
                            view.browse_split.grow_first();
                            view.mark_dirty();
                        }
                    }
                    KeyCode::Char('-') | KeyCode::Char('_') => {
                        if view.active_screen == ActiveScreen::Browse {
                            view.browse_split.shrink_first();
                            view.mark_dirty();
                        }
                    }
                    KeyCode::Char('b') if view.active_screen == ActiveScreen::Browse => {
                        branch_overlay = BranchOverlay::Menu;
                    }
                    _ => {
                        if view.active_screen == ActiveScreen::Browse {
                            handle_browse_keys(
                                key,
                                &mut view,
                                &tree,
                                &visible,
                                selected_index,
                                &mut detail_scroll,
                                &mut tree_scroll_x,
                                scroll_limits,
                            );
                        } else {
                            handle_compare_keys(key, &mut view, &tree);
                        }
                    }
                }
            }
        }
    }

    persist_view_state_now(
        runtime,
        document,
        persist_view_state,
        &mut view,
        &mut persist_warning_shown,
        true,
    );

    disable_raw_mode()?;
    if let Err(error) = execute!(terminal.backend_mut(), LeaveAlternateScreen) {
        result = Err(error);
    }
    terminal.show_cursor()?;
    result
}

fn explore_tree_from_document(document: &SessionDocument) -> ExploreTree {
    let trace = document
        .primary_tree()
        .expect("v2 session must contain a trace tree");
    if let Some(request) = document.primary_request() {
        super::tree::build_explore_tree_with_qname(trace, 0, Some(&request.qname))
    } else {
        super::tree::build_explore_tree(trace)
    }
}

fn persist_view_state_now(
    runtime: &Runtime,
    document: &mut SessionDocument,
    persist_view_state: bool,
    view: &mut ViewStateController,
    persist_warning_shown: &mut bool,
    force: bool,
) {
    if !persist_view_state {
        return;
    }
    if !view.should_persist_now(force) {
        return;
    }
    apply_view_state(document, view);
    if let Err(error) = runtime.update_session(document) {
        if !*persist_warning_shown {
            *persist_warning_shown = true;
            eprintln!("warning: failed to persist explore view state: {error}");
        }
    } else {
        view.persisted();
    }
}

fn parse_server_target_input(value: &str) -> ServerTargetInput {
    if let Some(rest) = value.strip_prefix('@') {
        if let Ok(address) = rest.parse() {
            return ServerTargetInput::Address(address);
        }
    }
    if let Ok(address) = value.parse() {
        return ServerTargetInput::Address(address);
    }
    ServerTargetInput::Name(value.to_string())
}

fn start_branch(
    paths: &DelvePaths,
    session_id: String,
    at: NodePath,
    intent: BranchIntentArg,
    branch_rx: &mut Option<mpsc::Receiver<BranchWorkerMessage>>,
) {
    let (tx, rx) = mpsc::channel();
    *branch_rx = Some(rx);
    let paths = paths.clone();
    std::thread::spawn(move || {
        let runtime = Runtime::open(paths);
        let mut progress = ChannelProgress::new(tx.clone());
        let result = branch_session(&runtime, &session_id, at, intent, false, &mut progress);
        let _ = tx.send(BranchWorkerMessage::Done(result));
    });
}

struct ChannelProgress {
    tx: mpsc::Sender<BranchWorkerMessage>,
}

impl ChannelProgress {
    fn new(tx: mpsc::Sender<BranchWorkerMessage>) -> Self {
        Self { tx }
    }
}

impl TraceProgress for ChannelProgress {
    fn hop(&mut self, _hop: &TraceHop, _path: &NodePath) {}

    fn message(&mut self, message: &str) {
        let _ = self
            .tx
            .send(BranchWorkerMessage::Progress(message.to_string()));
    }

    fn budget_truncated(&mut self, cap: usize) {
        let _ = self.tx.send(BranchWorkerMessage::Progress(format!(
            "budget truncated at {cap}"
        )));
    }
}

fn format_branch_report(report: &BranchReport) -> String {
    if report.dry_run {
        return "dry run complete".into();
    }
    if report.nodes_added == 0 {
        return "nothing to branch".into();
    }
    format!("added {} node(s)", report.nodes_added)
}

fn screen_indicator(
    view: &ViewStateController,
    tree: &ExploreTree,
    theme: &Theme,
) -> Line<'static> {
    let compare_available = tree.compare_available(&view.selection);
    let browse = Span::styled(
        if view.active_screen == ActiveScreen::Browse {
            "[Browse*]"
        } else {
            "[Browse]"
        },
        if view.active_screen == ActiveScreen::Browse {
            theme.accent_bold()
        } else {
            theme.meta()
        },
    );
    let compare_label = if compare_available {
        if view.active_screen == ActiveScreen::Compare {
            "[Compare*]"
        } else {
            "[Compare]"
        }
    } else {
        "[Compare (unavailable)]"
    };
    let compare = Span::styled(
        compare_label,
        if view.active_screen == ActiveScreen::Compare {
            theme.accent_bold()
        } else {
            theme.meta()
        },
    );
    Line::from(vec![browse, Span::raw("  "), compare])
}

fn cycle_screen_forward(
    view: &mut ViewStateController,
    tree: &ExploreTree,
    message: &mut Option<String>,
) {
    if view.active_screen == ActiveScreen::Browse {
        if tree.compare_available(&view.selection) {
            view.active_screen = ActiveScreen::Compare;
            view.compare_fork = tree.compare_fork(&view.selection).map(|fork| fork.at);
            view.mark_dirty();
        } else {
            *message = Some("Compare requires a node with multiple alternate paths".into());
        }
    } else {
        view.active_screen = ActiveScreen::Browse;
        view.mark_dirty();
    }
}

fn cycle_screen_backward(
    view: &mut ViewStateController,
    tree: &ExploreTree,
    message: &mut Option<String>,
) {
    if view.active_screen == ActiveScreen::Compare {
        view.active_screen = ActiveScreen::Browse;
        view.mark_dirty();
    } else if tree.compare_available(&view.selection) {
        view.active_screen = ActiveScreen::Compare;
        view.compare_fork = tree.compare_fork(&view.selection).map(|fork| fork.at);
        view.mark_dirty();
    } else {
        *message = Some("Compare requires a node with multiple alternate paths".into());
    }
}

fn select_screen(
    view: &mut ViewStateController,
    screen: ActiveScreen,
    tree: &ExploreTree,
    message: &mut Option<String>,
) {
    if screen == ActiveScreen::Compare && !tree.compare_available(&view.selection) {
        *message = Some("Compare requires a node with multiple alternate paths".into());
        return;
    }
    view.active_screen = screen;
    if screen == ActiveScreen::Compare {
        view.compare_fork = tree.compare_fork(&view.selection).map(|fork| fork.at);
    }
    view.mark_dirty();
}

fn jump_to_compare(
    view: &mut ViewStateController,
    tree: &ExploreTree,
    message: &mut Option<String>,
) {
    select_screen(view, ActiveScreen::Compare, tree, message);
}

fn browse_body_area(terminal_area: Rect) -> Rect {
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)])
        .split(terminal_area)[1]
}

fn browse_pane_areas(body_area: Rect, split: VerticalPaneSplit) -> (Rect, Rect) {
    split.split(body_area)
}

fn browse_scroll_limits(
    terminal_area: Rect,
    browse_split: VerticalPaneSplit,
    tree: &ExploreTree,
    visible: &[VisibleNode],
    selected_index: usize,
    theme: &Theme,
) -> BrowseScrollLimits {
    let (tree_area, detail_area) = browse_pane_areas(browse_body_area(terminal_area), browse_split);

    let color_hint = if theme.color_enabled { "on" } else { "off" };
    let tree_title = format!("{} {}  [tree]  color:{color_hint}", tree.qname, tree.qtype);
    let tree_block = Block::default()
        .title(tree_title)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded);
    let tree_inner = tree_block.inner(tree_area);
    let mut max_line_width = 0usize;
    for node in visible {
        let indent = "  ".repeat(node.depth);
        let marker = if node.expandable {
            if node.expanded {
                theme.symbols.tree_expand
            } else {
                theme.symbols.tree_collapse
            }
        } else {
            "  "
        };
        let hop = tree.hop_at(&node.path).expect("visible node hop");
        let line = hop_tree_line(&indent, marker, hop, theme);
        max_line_width = max_line_width.max(line_display_width(&line));
    }
    let tree_max_scroll_x = max_horizontal_scroll(max_line_width, tree_inner.width);

    let detail_title = "Details";
    let detail_block = Block::default()
        .title(detail_title)
        .title_bottom(footer_line(theme).centered())
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded);
    let detail_inner = detail_block.inner(detail_area);
    let detail_lines = detail_content(tree, visible.get(selected_index), theme);
    let detail_max_scroll = max_vertical_scroll(
        wrapped_line_count(&detail_lines, detail_inner.width),
        detail_inner.height,
    );

    BrowseScrollLimits {
        detail_max_scroll,
        tree_max_scroll_x,
    }
}

fn wrapped_line_count(lines: &[Line<'_>], width: u16) -> usize {
    let width = width as usize;
    if width == 0 {
        return lines.len();
    }
    lines
        .iter()
        .map(|line| {
            let line_width = line_display_width(line);
            if line_width == 0 {
                1
            } else {
                line_width.div_ceil(width)
            }
        })
        .sum()
}

fn max_vertical_scroll(wrapped_lines: usize, inner_height: u16) -> u16 {
    wrapped_lines
        .saturating_sub(inner_height as usize)
        .min(u16::MAX as usize) as u16
}

fn max_horizontal_scroll(line_width: usize, inner_width: u16) -> u16 {
    line_width
        .saturating_sub(inner_width as usize)
        .min(u16::MAX as usize) as u16
}

#[allow(clippy::too_many_arguments)]
fn handle_browse_keys(
    key: event::KeyEvent,
    view: &mut ViewStateController,
    tree: &ExploreTree,
    visible: &[VisibleNode],
    selected_index: usize,
    detail_scroll: &mut u16,
    tree_scroll_x: &mut u16,
    scroll_limits: BrowseScrollLimits,
) {
    if key.code == KeyCode::Char('w') {
        view.browse_pane = view.browse_pane.cycle_forward();
        view.mark_dirty();
        return;
    }

    if view.browse_pane == BrowsePane::Detail {
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => {
                *detail_scroll = (*detail_scroll + 1).min(scroll_limits.detail_max_scroll);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                *detail_scroll = detail_scroll.saturating_sub(1);
            }
            KeyCode::PageDown | KeyCode::Char(' ') => {
                *detail_scroll = (*detail_scroll + 10).min(scroll_limits.detail_max_scroll);
            }
            KeyCode::PageUp => {
                *detail_scroll = detail_scroll.saturating_sub(10);
            }
            KeyCode::Home => {
                *detail_scroll = 0;
            }
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Down | KeyCode::Char('j') if selected_index + 1 < visible.len() => {
            view.set_selection_visible_index(tree, selected_index + 1);
            *detail_scroll = 0;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            view.set_selection_visible_index(tree, selected_index.saturating_sub(1));
            *detail_scroll = 0;
        }
        KeyCode::Left | KeyCode::Char('h') => {
            *tree_scroll_x = tree_scroll_x.saturating_sub(1);
        }
        KeyCode::Right | KeyCode::Char('l') => {
            *tree_scroll_x = (*tree_scroll_x + 1).min(scroll_limits.tree_max_scroll_x);
        }
        KeyCode::Enter | KeyCode::Char(' ') => {
            if let Some(node) = visible.get(selected_index)
                && node.expandable
            {
                view.toggle_expansion(&node.path);
            }
        }
        _ => {}
    }
}

fn handle_compare_keys(key: event::KeyEvent, view: &mut ViewStateController, tree: &ExploreTree) {
    let fork = tree.compare_fork(&view.selection);
    let Some(fork) = fork else {
        return;
    };
    let row_count = tree
        .node_at(&fork.at)
        .map(|node| node.children.len())
        .unwrap_or(0);
    match key.code {
        KeyCode::Down | KeyCode::Char('j') if view.compare_row + 1 < row_count => {
            view.compare_row += 1;
            view.mark_dirty();
        }
        KeyCode::Up | KeyCode::Char('k') => {
            view.compare_row = view.compare_row.saturating_sub(1);
            view.mark_dirty();
        }
        KeyCode::Enter => {
            let mut path = fork.at.path.clone();
            path.push(view.compare_row);
            let selection = NodePath {
                tree: fork.at.tree,
                path,
            };
            if tree.node_at(&selection).is_some() {
                view.selection = selection;
                view.active_screen = ActiveScreen::Browse;
                view.mark_dirty();
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn render_browse(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    tree: &ExploreTree,
    visible: &[VisibleNode],
    selected_index: usize,
    view: &ViewStateController,
    detail_scroll: u16,
    tree_scroll_x: u16,
    theme: &Theme,
    session_id: &str,
) {
    let (tree_area, detail_area) = view.browse_split.split(area);

    let color_hint = if theme.color_enabled { "on" } else { "off" };
    let session_hint = format!("session:{session_id}  ");
    let mut max_line_width = 0usize;
    let mut raw_tree_lines = Vec::with_capacity(visible.len());

    for (index, node) in visible.iter().enumerate() {
        let indent = "  ".repeat(node.depth);
        let marker = if node.expandable {
            if node.expanded {
                theme.symbols.tree_expand
            } else {
                theme.symbols.tree_collapse
            }
        } else {
            "  "
        };
        let hop = tree.hop_at(&node.path).expect("visible node hop");
        let line = hop_tree_line(&indent, marker, hop, theme);
        max_line_width = max_line_width.max(line_display_width(&line));
        let selected = view.browse_pane == BrowsePane::Tree && index == selected_index;
        raw_tree_lines.push((line, selected));
    }

    let tree_title_base = format!(
        "{session_hint}{} {}  [tree]  color:{color_hint}",
        tree.qname, tree.qtype
    );
    let tree_block = Block::default()
        .title(tree_title_base.as_str())
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(if view.browse_pane == BrowsePane::Tree {
            theme.border_focused()
        } else {
            theme.border_unfocused()
        });
    let tree_inner = tree_block.inner(tree_area);
    let tree_max_scroll_x = max_horizontal_scroll(max_line_width, tree_inner.width);
    let clamped_tree_scroll_x = tree_scroll_x.min(tree_max_scroll_x);
    let tree_scroll_hints =
        AxisScrollHints::horizontal(clamped_tree_scroll_x, tree_max_scroll_x).format_horizontal();
    let tree_title = format!("{tree_title_base}{tree_scroll_hints}");
    let tree_rows = raw_tree_lines
        .into_iter()
        .map(|(line, selected)| {
            let line = if selected {
                apply_tree_selection(line, theme)
            } else {
                line
            };
            ListItem::new(scroll_line(line, clamped_tree_scroll_x))
        })
        .collect::<Vec<_>>();

    let tree_widget = List::new(tree_rows).block(
        Block::default()
            .title(tree_title)
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(if view.browse_pane == BrowsePane::Tree {
                theme.border_focused()
            } else {
                theme.border_unfocused()
            }),
    );
    frame.render_widget(tree_widget, tree_area);

    let detail_lines = detail_content(tree, visible.get(selected_index), theme);
    let detail_focus_hint = if view.browse_pane == BrowsePane::Detail {
        " — j/k scroll when focused"
    } else {
        ""
    };
    let detail_block = Block::default()
        .title("Details")
        .title_bottom(footer_line(theme).centered())
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(if view.browse_pane == BrowsePane::Detail {
            theme.border_focused()
        } else {
            theme.border_unfocused()
        });
    let detail_inner = detail_block.inner(detail_area);
    let detail_max_scroll = max_vertical_scroll(
        wrapped_line_count(&detail_lines, detail_inner.width),
        detail_inner.height,
    );
    let clamped_detail_scroll = detail_scroll.min(detail_max_scroll);
    let detail_scroll_hints =
        AxisScrollHints::vertical(clamped_detail_scroll, detail_max_scroll).format_vertical();
    let detail_title =
        format!("Details{detail_focus_hint}  [w toggles focus]{detail_scroll_hints}");
    let detail_widget = Paragraph::new(detail_lines)
        .block(
            Block::default()
                .title(detail_title)
                .title_bottom(footer_line(theme).centered())
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(if view.browse_pane == BrowsePane::Detail {
                    theme.border_focused()
                } else {
                    theme.border_unfocused()
                }),
        )
        .wrap(Wrap { trim: false })
        .scroll((clamped_detail_scroll, 0));
    frame.render_widget(detail_widget, detail_area);
}

fn render_compare(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    tree: &ExploreTree,
    view: &ViewStateController,
    theme: &Theme,
    unavailable_message: Option<&str>,
) {
    let fork = tree.compare_fork(&view.selection);
    let lines = if let Some(fork) = fork {
        let node = tree.node_at(&fork.at).expect("fork node");
        let mut rows = vec![
            Line::from(Span::styled("Compare paths at fork", theme.section())),
            Line::from(""),
        ];
        for (index, child) in node.children.iter().enumerate() {
            let hop = &child.hop;
            let marker = if index == view.compare_row { ">" } else { " " };
            let failed = matches!(hop.outcome, HopOutcome::Failed { .. });
            let label = if failed {
                format!("{marker} {}  FAILED", hop.server)
            } else {
                format!("{marker} {}  {}  {}ms", hop.server, hop.rcode, hop.rtt_ms)
            };
            rows.push(Line::from(Span::styled(
                label,
                if failed {
                    theme.failure()
                } else if index == view.compare_row {
                    theme.accent_bold()
                } else {
                    theme.meta()
                },
            )));
        }
        rows.push(Line::from(""));
        rows.push(Line::from(Span::styled(
            "Enter returns to Browse at selected row",
            theme.meta(),
        )));
        rows
    } else {
        vec![Line::from(Span::styled(
            unavailable_message.unwrap_or("Select a node with multiple paths to compare"),
            theme.meta(),
        ))]
    };

    let widget = Paragraph::new(lines)
        .block(
            Block::default()
                .title("Compare")
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(theme.border_focused()),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(widget, area);
}

fn render_branch_overlay(
    frame: &mut ratatui::Frame<'_>,
    theme: &Theme,
    overlay: BranchOverlay,
    alternate_input: &str,
    progress: Option<&str>,
) {
    let area = centered_rect(60, 40, frame.area());
    frame.render_widget(Clear, area);
    let mut lines = vec![
        Line::from(Span::styled("Branch", theme.section())),
        Line::from(""),
    ];
    if let Some(progress) = progress {
        lines.push(Line::from(progress.to_string()));
    } else if overlay == BranchOverlay::AlternateInput {
        lines.push(Line::from("Alternate server address:"));
        lines.push(Line::from(format!("> {alternate_input}")));
        lines.push(Line::from("Enter to confirm, Esc to go back"));
    } else {
        lines.extend([
            Line::from("e  expand unqueried nameservers"),
            Line::from("a  alternate server"),
            Line::from("Esc cancel"),
        ]);
    }
    let widget = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Double)
            .border_style(theme.border_focused()),
    );
    frame.render_widget(widget, area);
}

fn render_message_overlay(frame: &mut ratatui::Frame<'_>, theme: &Theme, message: &str) {
    let area = centered_rect(60, 30, frame.area());
    frame.render_widget(Clear, area);
    let widget = Paragraph::new(message).block(
        Block::default()
            .title("Notice")
            .borders(Borders::ALL)
            .border_style(theme.border_focused()),
    );
    frame.render_widget(widget, area);
}

fn hop_tree_line(indent: &str, marker: &str, hop: &TraceHop, theme: &Theme) -> Line<'static> {
    let failed = matches!(hop.outcome, HopOutcome::Failed { .. });
    let prefix = if failed {
        Span::styled("✗ ", theme.failure())
    } else {
        Span::raw("")
    };
    Line::from(vec![
        Span::raw(format!("{indent}{marker}")),
        prefix,
        Span::styled(format!("[{}] ", hop.zone), theme.zone()),
        Span::raw(format!("{} {}  ", hop.qname, hop.qtype)),
        Span::styled(hop.rcode.clone(), theme.rcode(&hop.rcode)),
        Span::styled(
            format!("  {}  ", cache_source_symbol(hop.from_cache, theme.symbols)),
            theme.cache_source(hop.from_cache),
        ),
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
    let hop = tree.hop_at(&selected.path).expect("hop");
    let mut lines = hop_detail_styled(hop, theme);
    if let Some(failure) = hop_failure_line(hop) {
        lines.push(Line::from(Span::styled(failure, theme.failure())));
    }
    lines
}

fn apply_tree_selection(mut line: Line<'static>, theme: &Theme) -> Line<'static> {
    let style = theme.tree_selected();
    line.style = style;
    for span in &mut line.spans {
        span.style = style;
    }
    line
}

fn scroll_line(mut line: Line<'static>, offset: u16) -> Line<'static> {
    if offset == 0 {
        return line;
    }
    let mut skip = offset as usize;
    let mut spans = Vec::new();
    for span in line.spans {
        if skip == 0 {
            spans.push(span);
            continue;
        }
        let (rest, consumed) = skip_prefix_by_width(span.content.as_ref(), skip);
        skip = skip.saturating_sub(consumed);
        if !rest.is_empty() {
            spans.push(Span {
                style: span.style,
                content: rest.into(),
            });
        }
    }
    line.spans = spans;
    line
}

fn skip_prefix_by_width(text: &str, skip: usize) -> (String, usize) {
    if skip == 0 {
        return (text.to_string(), 0);
    }
    let mut consumed = 0;
    let mut start_byte = 0;
    for ch in text.chars() {
        let width = UnicodeWidthChar::width(ch).unwrap_or(0);
        if consumed + width > skip {
            break;
        }
        consumed += width;
        start_byte += ch.len_utf8();
    }
    (text[start_byte..].to_string(), consumed)
}

fn line_display_width(line: &Line<'_>) -> usize {
    line.spans
        .iter()
        .map(|span| UnicodeWidthStr::width(span.content.as_ref()))
        .sum()
}

fn footer_line(theme: &Theme) -> Line<'static> {
    Line::from(vec![
        Span::raw("Press "),
        Span::styled("?", theme.help_key()),
        Span::raw(" for help"),
    ])
}

fn render_help_overlay(frame: &mut ratatui::Frame<'_>, view: &ViewStateController, theme: &Theme) {
    let area = centered_rect(62, 72, frame.area());
    frame.render_widget(Clear, area);
    let help_text = Paragraph::new(help_lines(view, theme))
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

fn help_lines(view: &ViewStateController, theme: &Theme) -> Vec<Line<'static>> {
    let mut lines = vec![
        help_section("Global", theme),
        help_binding("?", "Show this help", theme),
        help_binding("q, Esc", "Quit", theme),
        help_binding("Ctrl+C", "Quit", theme),
        help_binding("c", "Toggle colors", theme),
        help_binding("Tab / Shift-Tab", "Cycle screens", theme),
        help_binding("1 / 2", "Select Browse / Compare", theme),
        help_binding("m", "Jump to Compare", theme),
        Line::from(""),
    ];
    if view.active_screen == ActiveScreen::Browse {
        lines.extend([
            help_section("Browse", theme),
            help_binding("w", "Toggle tree/detail focus", theme),
            help_binding("j/k, ↑/↓", "Move selection", theme),
            help_binding("Space, Enter", "Toggle expand", theme),
            help_binding("E / C", "Expand all / collapse all", theme),
            help_binding("b", "Branch from selection", theme),
            help_binding("←/→, h/l", "Scroll tree horizontally", theme),
            help_binding("+ / -", "Resize tree/detail split", theme),
            Line::from(""),
            help_section("Hop symbols", theme),
            help_symbol_legend(
                cache_source_legend(theme.symbols)[0].0,
                cache_source_legend(theme.symbols)[0].1,
                true,
                theme,
            ),
            help_symbol_legend(
                cache_source_legend(theme.symbols)[1].0,
                cache_source_legend(theme.symbols)[1].1,
                false,
                theme,
            ),
        ]);
    } else {
        lines.extend([
            help_section("Compare", theme),
            help_binding("j/k, ↑/↓", "Move row", theme),
            help_binding("Enter", "Return to Browse at row", theme),
        ]);
    }
    lines
}

fn help_section(title: &str, theme: &Theme) -> Line<'static> {
    Line::from(Span::styled(title.to_string(), theme.help_heading()))
}

fn help_binding(keys: &str, description: &str, theme: &Theme) -> Line<'static> {
    Line::from(vec![
        Span::raw("  "),
        Span::styled(format!("{keys:<18}"), theme.help_key()),
        Span::raw(description.to_string()),
    ])
}

fn help_symbol_legend(
    symbol: &str,
    description: &str,
    from_cache: bool,
    theme: &Theme,
) -> Line<'static> {
    Line::from(vec![
        Span::raw("  "),
        Span::styled(format!("{symbol:<3}"), theme.cache_source(from_cache)),
        Span::raw(description.to_string()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browse_pane_cycles_with_w() {
        let pane = BrowsePane::Tree;
        assert_eq!(pane.cycle_forward(), BrowsePane::Detail);
        assert_eq!(BrowsePane::Detail.cycle_forward(), BrowsePane::Tree);
    }

    #[test]
    fn detail_scroll_max_is_zero_when_content_fits() {
        let lines = vec![Line::from("short line")];
        assert_eq!(max_vertical_scroll(wrapped_line_count(&lines, 80), 20), 0);
    }

    #[test]
    fn detail_scroll_stops_at_bottom_when_pressing_down() {
        let tree = super::super::tree::build_explore_tree(&dns_resolve::build_linear_tree(
            vec![sample_hop()],
            dns_resolve::TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-08-25T00:00:00Z".into(),
            },
        ));
        let mut view = ViewStateController::default_for_tree(&tree);
        let visible = tree.visible_nodes(&view.expanded_paths);
        let mut detail_scroll = 0;
        let mut tree_scroll_x = 0;
        let limits = BrowseScrollLimits {
            detail_max_scroll: 3,
            tree_max_scroll_x: 0,
        };

        view.browse_pane = BrowsePane::Detail;
        for _ in 0..20 {
            handle_browse_keys(
                event::KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
                &mut view,
                &tree,
                &visible,
                0,
                &mut detail_scroll,
                &mut tree_scroll_x,
                limits,
            );
        }
        assert_eq!(detail_scroll, 3);
    }

    #[test]
    fn browse_w_toggles_focus_from_detail_pane() {
        let tree = super::super::tree::build_explore_tree(&dns_resolve::build_linear_tree(
            vec![sample_hop()],
            dns_resolve::TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-08-25T00:00:00Z".into(),
            },
        ));
        let mut view = ViewStateController::default_for_tree(&tree);
        let visible = tree.visible_nodes(&view.expanded_paths);
        let mut detail_scroll = 0;
        let mut tree_scroll_x = 0;

        view.browse_pane = BrowsePane::Detail;
        handle_browse_keys(
            event::KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE),
            &mut view,
            &tree,
            &visible,
            0,
            &mut detail_scroll,
            &mut tree_scroll_x,
            BrowseScrollLimits {
                detail_max_scroll: 0,
                tree_max_scroll_x: 0,
            },
        );
        assert_eq!(view.browse_pane, BrowsePane::Tree);
    }

    #[test]
    fn help_lists_screen_bindings() {
        let view = ViewStateController::default_for_tree(&super::super::tree::build_explore_tree(
            &dns_resolve::build_linear_tree(
                vec![sample_hop()],
                dns_resolve::TraceTreeRequest {
                    qname: "example.com.".into(),
                    qtype: "A".into(),
                    started_at: "2026-08-25T00:00:00Z".into(),
                },
            ),
        ));
        let theme = Theme::from_env();
        let text = help_lines(&view, &theme)
            .into_iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("Cycle screens"));
        assert!(text.contains("Expand all / collapse all"));
        assert!(text.contains("Branch from selection"));
    }

    fn sample_hop() -> dns_resolve::TraceHop {
        dns_resolve::TraceHop {
            zone: ".".into(),
            server: "1.1.1.1".into(),
            server_name: None,
            qname: "example.com.".into(),
            qtype: "A".into(),
            transport: "udp".into(),
            rtt_ms: 10,
            rcode: "NOERROR".into(),
            nsid: None,
            ede_code: None,
            ede_text: None,
            referral_ns: vec![],
            glue: vec![],
            response: Default::default(),
            from_cache: false,
            outcome: dns_resolve::HopOutcome::Answered,
        }
    }
}
