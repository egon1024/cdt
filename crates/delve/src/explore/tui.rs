use std::io;
use std::sync::mpsc;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use dns_resolve::{HopOutcome, NodePath, RefreshProgress, TraceHop, TraceProgress};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Position, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::block::BorderType;
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::branch::{
    BranchError, BranchIntentArg, BranchReport, ServerTargetInput, branch_session,
    format_branch_report,
};
use crate::config::RttBarConfig;
use crate::paths::DelvePaths;
use crate::runtime::Runtime;
use crate::session::SessionDocument;

use super::compare::{CompareColumns, compare_row};
use super::detail::hop_failure_line;
use super::dig_view::hop_detail_styled;
use super::pane_split::{AxisScrollHints, VerticalPaneSplit};
use super::path_timing::{
    build_compare_timing, fork_full_path_lines, fork_sibling_lines, path_on_highlight,
    whole_tree_summary_lines,
};
use super::refresh::refresh_document_tree;
use super::rtt_bar::max_rtt_ms_for_visible;
use super::terminal::{ColorCapability, cache_source_legend, cache_source_symbol};
use super::theme::Theme;
use super::tree::{ExploreTree, VisibleNode};
use super::view_state::{ActiveScreen, BrowsePane, ViewStateController, apply_view_state};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BrowseScrollLimits {
    detail_max_scroll: u16,
    tree_max_scroll_x: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CompareScrollLimits {
    max_scroll: u16,
    inner_height: u16,
    first_row_line: usize,
    total_lines: usize,
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

#[derive(Debug)]
enum RefreshWorkerMessage {
    Progress {
        current: usize,
        total: usize,
    },
    Done(
        Result<
            (Box<SessionDocument>, dns_resolve::RefreshTreeReport),
            super::refresh::RefreshError,
        >,
    ),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefreshOverlay {
    None,
    ConfirmExitSave,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScreenNotice {
    screen: ActiveScreen,
    message: String,
}

fn set_screen_notice(
    notice: &mut Option<ScreenNotice>,
    screen: ActiveScreen,
    message: impl Into<String>,
) {
    *notice = Some(ScreenNotice {
        screen,
        message: message.into(),
    });
}

fn screen_notice_message(notice: &Option<ScreenNotice>, screen: ActiveScreen) -> Option<&str> {
    notice
        .as_ref()
        .filter(|entry| entry.screen == screen)
        .map(|entry| entry.message.as_str())
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
    let mut compare_scroll = 0u16;
    let rtt_bar_config = runtime.config.explore_rtt_bar;
    let mut show_help = false;
    let mut screen_notice: Option<ScreenNotice> = None;
    let mut branch_overlay = BranchOverlay::None;
    let mut alternate_server_input = String::new();
    let mut branch_rx: Option<mpsc::Receiver<BranchWorkerMessage>> = None;
    let mut branch_progress: Option<String> = None;
    let mut refresh_rx: Option<mpsc::Receiver<RefreshWorkerMessage>> = None;
    let mut refresh_progress: Option<(usize, usize)> = None;
    let mut refresh_origin_screen: Option<ActiveScreen> = None;
    let mut refresh_overlay = RefreshOverlay::None;
    let mut unsaved_rtt_refresh = false;
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
                                        &session_id,
                                        unsaved_rtt_refresh,
                                    );
                                }
                                set_screen_notice(
                                    &mut screen_notice,
                                    ActiveScreen::Browse,
                                    format_branch_report(&report),
                                );
                            }
                            Err(error) => {
                                set_screen_notice(
                                    &mut screen_notice,
                                    ActiveScreen::Browse,
                                    error.to_string(),
                                );
                            }
                        }
                    }
                }
            }
        }
        if branch_finished {
            branch_rx = None;
        }

        let mut refresh_finished = false;
        if let Some(rx) = &refresh_rx {
            while let Ok(message) = rx.try_recv() {
                match message {
                    RefreshWorkerMessage::Progress { current, total } => {
                        refresh_progress = Some((current, total));
                    }
                    RefreshWorkerMessage::Done(report) => {
                        refresh_finished = true;
                        refresh_progress = None;
                        match report {
                            Ok((updated, report)) => {
                                *document = *updated;
                                tree = explore_tree_from_document(document);
                                if report.hops_updated > 0 {
                                    unsaved_rtt_refresh = true;
                                }
                                if report.hops_failed > 0 {
                                    set_screen_notice(
                                        &mut screen_notice,
                                        refresh_origin_screen
                                            .take()
                                            .unwrap_or(ActiveScreen::Browse),
                                        format_refresh_failure(&report),
                                    );
                                } else {
                                    refresh_origin_screen = None;
                                }
                            }
                            Err(error) => {
                                set_screen_notice(
                                    &mut screen_notice,
                                    refresh_origin_screen.take().unwrap_or(ActiveScreen::Browse),
                                    error.to_string(),
                                );
                            }
                        }
                    }
                }
            }
        }
        if refresh_finished {
            refresh_rx = None;
            refresh_origin_screen = None;
        }

        if view.should_persist_now(false) {
            persist_view_state_now(
                runtime,
                document,
                persist_view_state,
                &mut view,
                &mut persist_warning_shown,
                false,
                &session_id,
                unsaved_rtt_refresh,
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

        if view.active_screen == ActiveScreen::Compare {
            let compare_visible = tree.visible_nodes(&view.expanded_paths);
            if view.compare_row >= compare_visible.len() {
                view.compare_row = compare_visible.len().saturating_sub(1);
            }
            let compare_limits = compare_scroll_limits(
                Rect::from((Position::ORIGIN, terminal.size()?)),
                &view,
                &tree,
                compare_visible.len(),
            );
            compare_scroll = compare_scroll.min(compare_limits.max_scroll);
        }

        terminal.draw(|frame| {
            let header = screen_indicator(&view, &theme);
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
                    &visible,
                    &view,
                    compare_scroll,
                    rtt_bar_config,
                    &theme,
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
            if let Some((current, total)) = refresh_progress {
                render_refresh_progress_overlay(frame, &theme, current, total);
            }
            if refresh_overlay == RefreshOverlay::ConfirmExitSave {
                render_refresh_confirm_overlay(frame, &theme);
            }
            if let Some(message) = screen_notice_message(&screen_notice, ActiveScreen::Browse)
                && branch_overlay == BranchOverlay::None
                && branch_progress.is_none()
                && refresh_overlay == RefreshOverlay::None
                && refresh_progress.is_none()
            {
                render_message_overlay(frame, &theme, message);
            }
            if let Some(message) = screen_notice_message(&screen_notice, ActiveScreen::Compare)
                && refresh_overlay == RefreshOverlay::None
                && refresh_progress.is_none()
                && branch_overlay == BranchOverlay::None
                && branch_progress.is_none()
            {
                render_compare_notice(frame, &theme, message);
            }
        })?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }

                if branch_rx.is_some() || refresh_rx.is_some() {
                    if matches!(key.code, KeyCode::Esc) {
                        set_screen_notice(
                            &mut screen_notice,
                            view.active_screen,
                            if refresh_rx.is_some() {
                                "RTT refresh in progress; wait for completion".to_string()
                            } else {
                                "branch in progress; wait for completion".to_string()
                            },
                        );
                    }
                    continue;
                }

                if refresh_overlay == RefreshOverlay::ConfirmExitSave {
                    match key.code {
                        KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                            if let Err(error) =
                                super::refresh::persist_refreshed_tree(runtime, document)
                            {
                                set_screen_notice(
                                    &mut screen_notice,
                                    view.active_screen,
                                    format!("failed to save refreshed RTTs: {error}"),
                                );
                            } else {
                                unsaved_rtt_refresh = false;
                                break;
                            }
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                            unsaved_rtt_refresh = false;
                            break;
                        }
                        _ => {}
                    }
                    continue;
                }

                if show_help {
                    match key.code {
                        KeyCode::Char('?') | KeyCode::Esc => show_help = false,
                        KeyCode::Char('q')
                            if request_quit(unsaved_rtt_refresh, &mut refresh_overlay) =>
                        {
                            break;
                        }
                        KeyCode::Char('c')
                            if key.modifiers.contains(KeyModifiers::CONTROL)
                                && request_quit(unsaved_rtt_refresh, &mut refresh_overlay) =>
                        {
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
                                set_screen_notice(
                                    &mut screen_notice,
                                    ActiveScreen::Browse,
                                    "server address required",
                                );
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
                                    &session_id,
                                    unsaved_rtt_refresh,
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
                                &session_id,
                                unsaved_rtt_refresh,
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

                if screen_notice
                    .as_ref()
                    .is_some_and(|notice| notice.screen == view.active_screen)
                {
                    match key.code {
                        KeyCode::Enter | KeyCode::Char(' ') => {
                            screen_notice = None;
                        }
                        KeyCode::Char('q')
                            if request_quit(unsaved_rtt_refresh, &mut refresh_overlay) =>
                        {
                            break;
                        }
                        KeyCode::Esc => screen_notice = None,
                        _ => {}
                    }
                    if screen_notice.is_none() {
                        continue;
                    }
                }

                match key.code {
                    KeyCode::Char('q')
                        if request_quit(unsaved_rtt_refresh, &mut refresh_overlay) =>
                    {
                        break;
                    }
                    KeyCode::Char('?') => show_help = true,
                    KeyCode::Char('c')
                        if key.modifiers.contains(KeyModifiers::CONTROL)
                            && request_quit(unsaved_rtt_refresh, &mut refresh_overlay) =>
                    {
                        break;
                    }
                    KeyCode::Char('c') => {
                        theme.toggle_color();
                        view.mark_dirty();
                    }
                    KeyCode::Tab => {
                        if cycle_screen_forward(&mut view, &tree) {
                            sync_compare_scroll(
                                &mut compare_scroll,
                                view.selected_visible_index(&tree),
                                visible.len(),
                                compare_scroll_limits(
                                    Rect::from((Position::ORIGIN, terminal.size()?)),
                                    &view,
                                    &tree,
                                    visible.len(),
                                ),
                            );
                        }
                    }
                    KeyCode::BackTab => {
                        if cycle_screen_backward(&mut view, &tree) {
                            sync_compare_scroll(
                                &mut compare_scroll,
                                view.selected_visible_index(&tree),
                                visible.len(),
                                compare_scroll_limits(
                                    Rect::from((Position::ORIGIN, terminal.size()?)),
                                    &view,
                                    &tree,
                                    visible.len(),
                                ),
                            );
                        }
                    }
                    KeyCode::Char('1') => select_screen(&mut view, ActiveScreen::Browse, &tree),
                    KeyCode::Char('2') => {
                        select_screen(&mut view, ActiveScreen::Compare, &tree);
                        sync_compare_scroll(
                            &mut compare_scroll,
                            view.selected_visible_index(&tree),
                            visible.len(),
                            compare_scroll_limits(
                                Rect::from((Position::ORIGIN, terminal.size()?)),
                                &view,
                                &tree,
                                visible.len(),
                            ),
                        );
                    }
                    KeyCode::Char('m') => {
                        jump_to_compare(&mut view, &tree);
                        sync_compare_scroll(
                            &mut compare_scroll,
                            view.selected_visible_index(&tree),
                            visible.len(),
                            compare_scroll_limits(
                                Rect::from((Position::ORIGIN, terminal.size()?)),
                                &view,
                                &tree,
                                visible.len(),
                            ),
                        );
                    }
                    KeyCode::Char('E') => {
                        view.expand_all(&tree);
                        detail_scroll = 0;
                        compare_scroll = 0;
                    }
                    KeyCode::Char('C') => {
                        view.collapse_all(&tree);
                        detail_scroll = 0;
                        compare_scroll = 0;
                    }
                    KeyCode::Char('r') | KeyCode::Char('R') if refresh_rx.is_none() => {
                        start_refresh(
                            &paths,
                            document,
                            &mut refresh_rx,
                            &mut refresh_origin_screen,
                            view.active_screen,
                        );
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
                            let compare_limits = compare_scroll_limits(
                                Rect::from((Position::ORIGIN, terminal.size()?)),
                                &view,
                                &tree,
                                visible.len(),
                            );
                            handle_compare_keys(
                                key,
                                &mut view,
                                &tree,
                                &visible,
                                &mut compare_scroll,
                                compare_limits,
                                &mut screen_notice,
                            );
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
        &session_id,
        unsaved_rtt_refresh,
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

#[allow(clippy::too_many_arguments)]
fn persist_view_state_now(
    runtime: &Runtime,
    document: &mut SessionDocument,
    persist_view_state: bool,
    view: &mut ViewStateController,
    persist_warning_shown: &mut bool,
    force: bool,
    session_id: &str,
    unsaved_rtt_refresh: bool,
) {
    if !persist_view_state {
        return;
    }
    if !view.should_persist_now(force) {
        return;
    }
    let mut to_save = document.clone();
    if unsaved_rtt_refresh {
        if let Ok(saved) = runtime.get_session(session_id) {
            to_save.trees = saved.trees;
        }
    }
    apply_view_state(&mut to_save, view);
    if let Err(error) = runtime.update_session(&to_save) {
        if !*persist_warning_shown {
            *persist_warning_shown = true;
            eprintln!("warning: failed to persist explore view state: {error}");
        }
    } else {
        view.persisted();
    }
}

fn request_quit(unsaved_rtt_refresh: bool, refresh_overlay: &mut RefreshOverlay) -> bool {
    if unsaved_rtt_refresh {
        *refresh_overlay = RefreshOverlay::ConfirmExitSave;
        false
    } else {
        true
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

fn start_refresh(
    paths: &DelvePaths,
    document: &SessionDocument,
    refresh_rx: &mut Option<mpsc::Receiver<RefreshWorkerMessage>>,
    refresh_origin_screen: &mut Option<ActiveScreen>,
    origin_screen: ActiveScreen,
) {
    let (tx, rx) = mpsc::channel();
    *refresh_rx = Some(rx);
    *refresh_origin_screen = Some(origin_screen);
    let working = document.clone();
    let paths = paths.clone();
    std::thread::spawn(move || {
        let runtime = Runtime::open(paths);
        let mut progress = RefreshChannelProgress::new(tx.clone());
        let mut working = working;
        let result = refresh_document_tree(&mut working, &runtime, &mut progress)
            .map(|report| (Box::new(working), report));
        let _ = tx.send(RefreshWorkerMessage::Done(result));
    });
}

struct RefreshChannelProgress {
    tx: mpsc::Sender<RefreshWorkerMessage>,
}

impl RefreshChannelProgress {
    fn new(tx: mpsc::Sender<RefreshWorkerMessage>) -> Self {
        Self { tx }
    }
}

impl RefreshProgress for RefreshChannelProgress {
    fn hop_started(&mut self, current: usize, total: usize) {
        let _ = self
            .tx
            .send(RefreshWorkerMessage::Progress { current, total });
    }
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

fn screen_indicator(view: &ViewStateController, theme: &Theme) -> Line<'static> {
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
    let compare = Span::styled(
        if view.active_screen == ActiveScreen::Compare {
            "[Compare*]"
        } else {
            "[Compare]"
        },
        if view.active_screen == ActiveScreen::Compare {
            theme.accent_bold()
        } else {
            theme.meta()
        },
    );
    Line::from(vec![browse, Span::raw("  "), compare])
}

fn activate_compare(view: &mut ViewStateController, tree: &ExploreTree) {
    view.active_screen = ActiveScreen::Compare;
    view.compare_row = view.selected_visible_index(tree);
    view.compare_fork = tree.compare_fork(&view.selection).map(|fork| fork.at);
    view.mark_dirty();
}

fn cycle_screen_forward(view: &mut ViewStateController, tree: &ExploreTree) -> bool {
    if view.active_screen == ActiveScreen::Browse {
        activate_compare(view, tree);
        true
    } else {
        view.active_screen = ActiveScreen::Browse;
        view.mark_dirty();
        false
    }
}

fn cycle_screen_backward(view: &mut ViewStateController, tree: &ExploreTree) -> bool {
    if view.active_screen == ActiveScreen::Compare {
        view.active_screen = ActiveScreen::Browse;
        view.mark_dirty();
        false
    } else {
        activate_compare(view, tree);
        true
    }
}

fn select_screen(view: &mut ViewStateController, screen: ActiveScreen, tree: &ExploreTree) {
    if screen == ActiveScreen::Compare {
        activate_compare(view, tree);
        return;
    }
    view.active_screen = screen;
    view.mark_dirty();
}

fn jump_to_compare(view: &mut ViewStateController, tree: &ExploreTree) {
    activate_compare(view, tree);
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

    let color_hint = theme.color_status_hint();
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

fn handle_compare_keys(
    key: event::KeyEvent,
    view: &mut ViewStateController,
    tree: &ExploreTree,
    visible: &[VisibleNode],
    compare_scroll: &mut u16,
    scroll_limits: CompareScrollLimits,
    screen_notice: &mut Option<ScreenNotice>,
) {
    let selected_index = view.selected_visible_index(tree);
    match key.code {
        KeyCode::Down | KeyCode::Char('j') if selected_index + 1 < visible.len() => {
            let new_index = selected_index + 1;
            view.set_selection_visible_index(tree, new_index);
            view.compare_fork = tree.compare_fork(&view.selection).map(|fork| fork.at);
            sync_compare_scroll(compare_scroll, new_index, visible.len(), scroll_limits);
        }
        KeyCode::Up | KeyCode::Char('k') => {
            let new_index = selected_index.saturating_sub(1);
            view.set_selection_visible_index(tree, new_index);
            view.compare_fork = tree.compare_fork(&view.selection).map(|fork| fork.at);
            sync_compare_scroll(compare_scroll, new_index, visible.len(), scroll_limits);
        }
        KeyCode::Char(' ') => {
            if let Some(node) = visible.get(selected_index)
                && node.expandable
            {
                view.toggle_expansion(&node.path);
            }
        }
        KeyCode::Enter => {
            view.active_screen = ActiveScreen::Browse;
            view.mark_dirty();
        }
        KeyCode::Char('E') => view.expand_all(tree),
        KeyCode::Char('C') => view.collapse_all(tree),
        KeyCode::Char('F') => {
            if view.compare_fork.is_some() {
                view.show_fork_full_path_panel = !view.show_fork_full_path_panel;
                view.mark_dirty();
                *screen_notice = None;
            } else {
                set_screen_notice(
                    screen_notice,
                    ActiveScreen::Compare,
                    "no fork context for full-path panel",
                );
            }
        }
        KeyCode::Char('B') => {
            if view.compare_fork.is_some() {
                view.show_fork_sibling_panel = !view.show_fork_sibling_panel;
                view.mark_dirty();
                *screen_notice = None;
            } else {
                set_screen_notice(
                    screen_notice,
                    ActiveScreen::Compare,
                    "no fork context for sibling breakdown",
                );
            }
        }
        KeyCode::Char('f') => {
            let timing = build_compare_timing(tree, view.compare_fork.as_ref());
            if let Some(summary) = timing.whole_tree {
                if view.highlighted_path.as_ref() == Some(&summary.fastest.path) {
                    view.highlighted_path = None;
                } else {
                    view.highlighted_path = Some(summary.fastest.path);
                }
                view.mark_dirty();
            }
        }
        KeyCode::Char('s') => {
            let timing = build_compare_timing(tree, view.compare_fork.as_ref());
            if let Some(summary) = timing.whole_tree {
                if view.highlighted_path.as_ref() == Some(&summary.slowest.path) {
                    view.highlighted_path = None;
                } else {
                    view.highlighted_path = Some(summary.slowest.path);
                }
                view.mark_dirty();
            }
        }
        KeyCode::Esc => {
            view.highlighted_path = None;
            view.mark_dirty();
            *screen_notice = None;
        }
        _ => {}
    }
}

fn sync_compare_scroll(
    scroll: &mut u16,
    selected_index: usize,
    _visible_rows: usize,
    limits: CompareScrollLimits,
) {
    let line_index = limits.first_row_line + selected_index;
    ensure_line_visible(line_index, scroll, limits.inner_height, limits.total_lines);
    *scroll = (*scroll).min(limits.max_scroll);
}

fn compare_scroll_limits(
    terminal_area: Rect,
    view: &ViewStateController,
    tree: &ExploreTree,
    visible_rows: usize,
) -> CompareScrollLimits {
    let body = browse_body_area(terminal_area);
    let block = Block::default()
        .title("Compare")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded);
    let inner = block.inner(body);
    let layout = compare_layout(view, tree, visible_rows);
    CompareScrollLimits {
        max_scroll: max_vertical_scroll(layout.total_lines, inner.height),
        inner_height: inner.height,
        first_row_line: layout.first_row_line,
        total_lines: layout.total_lines,
    }
}

#[derive(Debug, Clone, Copy)]
struct CompareLayout {
    total_lines: usize,
    first_row_line: usize,
}

fn compare_layout(
    view: &ViewStateController,
    tree: &ExploreTree,
    visible_rows: usize,
) -> CompareLayout {
    let timing = build_compare_timing(tree, view.compare_fork.as_ref());
    let mut before = whole_tree_summary_lines(&timing, &Theme::from_env()).len();
    if view.show_fork_full_path_panel {
        before += fork_full_path_lines(&timing, &Theme::from_env()).len() + 1;
    }
    let first_row_line = before + 2;
    let mut total = first_row_line + visible_rows;
    if view.show_fork_sibling_panel {
        total += 1 + fork_sibling_lines(&timing, &Theme::from_env()).len();
    }
    CompareLayout {
        total_lines: total,
        first_row_line,
    }
}

fn ensure_line_visible(
    line_index: usize,
    scroll: &mut u16,
    viewport_height: u16,
    total_lines: usize,
) {
    let viewport = viewport_height as usize;
    if viewport == 0 {
        return;
    }
    let scroll_usize = *scroll as usize;
    if line_index < scroll_usize {
        *scroll = line_index as u16;
    } else if line_index >= scroll_usize + viewport {
        let max_scroll = total_lines.saturating_sub(viewport);
        *scroll = (line_index + 1).saturating_sub(viewport).min(max_scroll) as u16;
    }
}

#[allow(clippy::too_many_arguments)]
fn render_compare(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    tree: &ExploreTree,
    visible: &[VisibleNode],
    view: &ViewStateController,
    compare_scroll: u16,
    rtt_config: RttBarConfig,
    theme: &Theme,
) {
    let columns = CompareColumns::for_visible(tree, visible);
    let selected_index = view.selected_visible_index(tree);
    let scale_max_rtt_ms = max_rtt_ms_for_visible(tree, visible);
    let timing = build_compare_timing(tree, view.compare_fork.as_ref());
    let mut lines = whole_tree_summary_lines(&timing, theme);
    if view.show_fork_full_path_panel {
        lines.push(Line::from(""));
        lines.extend(fork_full_path_lines(&timing, theme));
    }
    lines.push(columns.header(theme));
    lines.push(Line::from(""));
    let highlight = view.highlighted_path.as_deref();
    for (index, node) in visible.iter().enumerate() {
        let path_highlighted =
            highlight.is_some_and(|path| path_on_highlight(&node.path.path, path));
        lines.push(compare_row(
            node,
            tree,
            index == selected_index,
            path_highlighted,
            columns,
            rtt_config,
            scale_max_rtt_ms,
            theme,
        ));
    }
    if view.show_fork_sibling_panel {
        lines.push(Line::from(""));
        lines.extend(fork_sibling_lines(&timing, theme));
    }

    let block = Block::default()
        .title("Compare")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme.border_focused());
    let inner = block.inner(area);
    let max_scroll = max_vertical_scroll(lines.len(), inner.height);
    let clamped_scroll = compare_scroll.min(max_scroll);
    let scroll_hints = AxisScrollHints::vertical(clamped_scroll, max_scroll).format_vertical();
    let title = format!(
        "Compare — answered paths only; • marks forks; latency bar scales to visible max{scroll_hints}"
    );

    let widget = Paragraph::new(lines)
        .block(
            Block::default()
                .title(title)
                .title_bottom(footer_line(theme).centered())
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(theme.border_focused()),
        )
        .wrap(Wrap { trim: false })
        .scroll((clamped_scroll, 0));
    frame.render_widget(widget, area);
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

    let color_hint = theme.color_status_hint();
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
    let detail_title = format!("Details{detail_scroll_hints}");
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

fn render_compare_notice(frame: &mut ratatui::Frame<'_>, theme: &Theme, message: &str) {
    let area = Rect {
        x: frame.area().x + 2,
        y: frame.area().y + frame.area().height.saturating_sub(3),
        width: frame.area().width.saturating_sub(4),
        height: 2,
    };
    frame.render_widget(Clear, area);
    let widget = Paragraph::new(message).style(theme.meta());
    frame.render_widget(widget, area);
}

fn render_refresh_progress_overlay(
    frame: &mut ratatui::Frame<'_>,
    theme: &Theme,
    current: usize,
    total: usize,
) {
    let area = centered_rect(50, 20, frame.area());
    frame.render_widget(Clear, area);
    let widget = Paragraph::new(format!("Refreshing hop RTTs… {current}/{total}")).block(
        Block::default()
            .title("RTT refresh")
            .borders(Borders::ALL)
            .border_style(theme.border_focused()),
    );
    frame.render_widget(widget, area);
}

fn render_refresh_confirm_overlay(frame: &mut ratatui::Frame<'_>, theme: &Theme) {
    let area = centered_rect(55, 25, frame.area());
    frame.render_widget(Clear, area);
    let widget = Paragraph::new(vec![
        Line::from("Save refreshed RTTs before quitting?"),
        Line::from(""),
        Line::from("y/Enter  save and quit"),
        Line::from("n/Esc     quit without saving"),
    ])
    .block(
        Block::default()
            .title("Unsaved RTT refresh")
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

fn format_refresh_failure(report: &dns_resolve::RefreshTreeReport) -> String {
    if report.hops_updated == 0 {
        format!(
            "refresh failed for all {} hops; RTTs unchanged",
            report.hops_total
        )
    } else {
        format!(
            "refreshed {}/{} hops ({} failed)",
            report.hops_updated, report.hops_total, report.hops_failed
        )
    }
}

fn help_lines(view: &ViewStateController, theme: &Theme) -> Vec<Line<'static>> {
    let mut lines = vec![
        help_section("Global", theme),
        help_binding("?", "Show this help", theme),
        help_binding("q", "Quit (prompts to save refreshed RTTs)", theme),
        help_binding("Ctrl+C", "Quit", theme),
        help_binding("c", "Toggle colors", theme),
        help_binding("Tab / Shift-Tab", "Cycle screens", theme),
        help_binding("1 / 2", "Select Browse / Compare", theme),
        help_binding("m", "Jump to Compare", theme),
        help_binding("r", "Refresh hop RTTs in memory", theme),
        help_binding("E / C", "Expand all / collapse all", theme),
        Line::from(""),
    ];
    if view.active_screen == ActiveScreen::Browse {
        lines.extend([
            help_section("Browse", theme),
            help_binding("w", "Toggle tree/detail focus", theme),
            help_binding("j/k, ↑/↓", "Move selection", theme),
            help_binding("Space, Enter", "Toggle expand", theme),
            help_binding("E / C", "Expand all / collapse all", theme),
            help_binding("b", "Branch from selected node", theme),
            help_binding("h/l, ←/→", "Scroll tree horizontally", theme),
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
            help_binding("j/k, ↑/↓", "Move selection (scrolls view)", theme),
            help_binding("Space", "Toggle expand", theme),
            help_binding("E / C", "Expand all / collapse all", theme),
            help_binding("Enter", "Return to Browse", theme),
            help_binding("F", "Toggle fork full-path stats panel", theme),
            help_binding("B", "Toggle fork sibling hop RTT panel", theme),
            help_binding("f / s", "Highlight fastest / slowest answered path", theme),
            help_binding("Esc", "Clear path highlight", theme),
            Line::from(""),
            help_section("Compare stats", theme),
            help_binding(
                "",
                "Totals sum hop RTT along answered leaf paths only",
                theme,
            ),
            Line::from(""),
            help_section("RTT bar colors", theme),
            help_binding(
                "",
                if matches!(
                    theme.color_capability,
                    ColorCapability::Indexed | ColorCapability::Truecolor
                ) {
                    "Gradient toward next step: green→yellow, then yellow→orange, then orange→red"
                } else {
                    "Stepped bands: green / yellow / orange / red"
                },
                theme,
            ),
            help_binding("green", "≤ green_ms (config)", theme),
            help_binding("yellow", "≤ yellow_ms", theme),
            help_binding("orange", "≤ orange_ms", theme),
            help_binding("red", "> orange_ms", theme),
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
        assert!(text.contains("Refresh hop RTTs"));
        assert!(text.contains("Branch from selected node"));
    }

    #[test]
    fn screen_notice_only_matches_own_screen() {
        let mut notice = None;
        set_screen_notice(&mut notice, ActiveScreen::Compare, "refreshed 3 hops");
        assert_eq!(
            screen_notice_message(&notice, ActiveScreen::Compare),
            Some("refreshed 3 hops")
        );
        assert_eq!(screen_notice_message(&notice, ActiveScreen::Browse), None);
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
