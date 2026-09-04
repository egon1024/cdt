use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use dns_resolve::{
    DatagramIcmpProber, HopOutcome, IcmpProber, NodePath, RefreshProgress, TraceHop, TraceProgress,
};
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

use super::compare_screen::{
    CompareScreenModel, CompareViewport, hop_detail_lines, hop_scale_ms, scroll_for_row,
    sticky_header_lines, summary_row_line,
};
use super::detail::hop_failure_line;
use super::dig_view::hop_detail_styled;
use super::pane_split::{AxisScrollHints, VerticalPaneSplit};
use super::path_summary::enrich_icmp_cached;
use super::path_timing::{
    build_compare_timing, fork_full_path_lines, fork_sibling_lines, path_on_highlight,
    whole_tree_summary_lines,
};
use super::refresh::refresh_document_tree;
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
    let mut tree = explore_tree_from_document(document)?;
    let session_id = document.id.clone();
    let paths = runtime.paths.clone();

    let terminal_guard = TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
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
    let mut icmp_cache: HashMap<String, Option<u64>> = HashMap::new();
    let icmp_prober = DatagramIcmpProber::default();

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
                                        tree = explore_tree_from_document(document)?;
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
                                tree = explore_tree_from_document(document)?;
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
            rtt_bar_config,
            &theme,
        );
        detail_scroll = detail_scroll.min(scroll_limits.detail_max_scroll);
        tree_scroll_x = tree_scroll_x.min(scroll_limits.tree_max_scroll_x);

        if view.active_screen == ActiveScreen::Compare {
            if let Some(model) = CompareScreenModel::from_tree(&tree, &view.selection) {
                if view.compare_row >= model.rows().len() {
                    view.compare_row = model.rows().len().saturating_sub(1);
                }
                let compare_limits = compare_scroll_limits(
                    Rect::from((Position::ORIGIN, terminal.size()?)),
                    &view,
                    &tree,
                    model.rows().len(),
                );
                compare_scroll = compare_scroll.min(compare_limits.max_scroll);
            }
        }

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
                    rtt_bar_config,
                    &theme,
                    &session_id,
                ),
                ActiveScreen::Compare => render_compare(
                    frame,
                    chunks[1],
                    &tree,
                    &view,
                    compare_scroll,
                    rtt_bar_config,
                    &theme,
                    &mut icmp_cache,
                    &icmp_prober,
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
            if let Some(message) = screen_notice_message(&screen_notice, view.active_screen)
                && branch_overlay == BranchOverlay::None
                && branch_progress.is_none()
                && refresh_overlay == RefreshOverlay::None
                && refresh_progress.is_none()
            {
                match view.active_screen {
                    ActiveScreen::Browse => render_message_overlay(frame, &theme, message),
                    ActiveScreen::Compare => render_compare_notice(frame, &theme, message),
                }
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
                    KeyCode::Tab => match cycle_screen_forward(&mut view, &tree) {
                        ScreenCycle::EnteredCompare => {
                            screen_notice = None;
                            sync_compare_scroll_for_view(
                                &mut compare_scroll,
                                &view,
                                &tree,
                                terminal.size()?,
                            );
                        }
                        ScreenCycle::SkippedUnavailable => {
                            set_screen_notice(
                                &mut screen_notice,
                                view.active_screen,
                                tree.compare_unavailable_reason(&view.selection),
                            );
                        }
                        ScreenCycle::LeftCompare => screen_notice = None,
                    },
                    KeyCode::BackTab => match cycle_screen_backward(&mut view, &tree) {
                        ScreenCycle::EnteredCompare => {
                            screen_notice = None;
                            sync_compare_scroll_for_view(
                                &mut compare_scroll,
                                &view,
                                &tree,
                                terminal.size()?,
                            );
                        }
                        ScreenCycle::SkippedUnavailable => {
                            set_screen_notice(
                                &mut screen_notice,
                                view.active_screen,
                                tree.compare_unavailable_reason(&view.selection),
                            );
                        }
                        ScreenCycle::LeftCompare => screen_notice = None,
                    },
                    KeyCode::Char('1') => {
                        if select_screen(&mut view, ActiveScreen::Browse, &tree) {
                            screen_notice = None;
                        }
                    }
                    KeyCode::Char('2') => {
                        if !select_screen(&mut view, ActiveScreen::Compare, &tree) {
                            set_screen_notice(
                                &mut screen_notice,
                                view.active_screen,
                                tree.compare_unavailable_reason(&view.selection),
                            );
                        } else {
                            screen_notice = None;
                            sync_compare_scroll_for_view(
                                &mut compare_scroll,
                                &view,
                                &tree,
                                terminal.size()?,
                            );
                        }
                    }
                    KeyCode::Char('m') => {
                        if !jump_to_compare(&mut view, &tree) {
                            set_screen_notice(
                                &mut screen_notice,
                                view.active_screen,
                                tree.compare_unavailable_reason(&view.selection),
                            );
                        } else {
                            screen_notice = None;
                            sync_compare_scroll_for_view(
                                &mut compare_scroll,
                                &view,
                                &tree,
                                terminal.size()?,
                            );
                        }
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
                            let row_count = CompareScreenModel::from_tree(&tree, &view.selection)
                                .map(|model| model.rows().len())
                                .unwrap_or(0);
                            let compare_limits = compare_scroll_limits(
                                Rect::from((Position::ORIGIN, terminal.size()?)),
                                &view,
                                &tree,
                                row_count,
                            );
                            handle_compare_keys(
                                key,
                                &mut view,
                                &tree,
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

    terminal.show_cursor()?;
    terminal_guard.leave();
    Ok(())
}

static TERMINAL_SESSION_ACTIVE: AtomicBool = AtomicBool::new(false);

struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        TERMINAL_SESSION_ACTIVE.store(true, Ordering::SeqCst);
        Ok(Self)
    }

    fn leave(self) {
        restore_terminal_session();
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal_session();
    }
}

fn restore_terminal_session() {
    if !TERMINAL_SESSION_ACTIVE.swap(false, Ordering::SeqCst) {
        return;
    }
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen);
}

fn explore_tree_from_document(document: &SessionDocument) -> io::Result<ExploreTree> {
    let trace = document
        .primary_tree()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "session has no trace tree"))?;
    Ok(if let Some(request) = document.primary_request() {
        super::tree::build_explore_tree_with_qname(trace, 0, Some(&request.qname))
    } else {
        super::tree::build_explore_tree(trace)
    })
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScreenCycle {
    EnteredCompare,
    LeftCompare,
    SkippedUnavailable,
}

fn screen_indicator(
    view: &ViewStateController,
    tree: &ExploreTree,
    theme: &Theme,
) -> Line<'static> {
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
    let compare_openable = tree.compare_openable();
    let compare_label = if view.active_screen == ActiveScreen::Compare {
        "[Compare*]"
    } else if compare_openable {
        "[Compare]"
    } else {
        "[Compare n/a]"
    };
    let compare = Span::styled(
        compare_label,
        if view.active_screen == ActiveScreen::Compare {
            theme.accent_bold()
        } else if compare_openable {
            theme.meta()
        } else {
            theme.failure()
        },
    );
    Line::from(vec![browse, Span::raw("  "), compare])
}

fn activate_compare(view: &mut ViewStateController, tree: &ExploreTree) -> bool {
    if let Some(fork) = tree.compare_fork(&view.selection) {
        return enter_compare(view, fork);
    }
    let Some(fork_path) = tree.nearest_fork() else {
        return false;
    };
    reveal_path(view, tree, &fork_path);
    tree.compare_fork(&view.selection)
        .map(|fork| enter_compare(view, fork))
        .unwrap_or(false)
}

fn enter_compare(view: &mut ViewStateController, fork: super::tree::CompareFork) -> bool {
    view.active_screen = ActiveScreen::Compare;
    view.compare_fork = Some(fork.at.clone());
    view.compare_row = fork.row;
    view.mark_dirty();
    true
}

fn cycle_screen_forward(view: &mut ViewStateController, tree: &ExploreTree) -> ScreenCycle {
    if view.active_screen == ActiveScreen::Browse {
        if activate_compare(view, tree) {
            ScreenCycle::EnteredCompare
        } else {
            ScreenCycle::SkippedUnavailable
        }
    } else {
        view.active_screen = ActiveScreen::Browse;
        view.mark_dirty();
        ScreenCycle::LeftCompare
    }
}

fn cycle_screen_backward(view: &mut ViewStateController, tree: &ExploreTree) -> ScreenCycle {
    if view.active_screen == ActiveScreen::Compare {
        view.active_screen = ActiveScreen::Browse;
        view.mark_dirty();
        ScreenCycle::LeftCompare
    } else if activate_compare(view, tree) {
        ScreenCycle::EnteredCompare
    } else {
        ScreenCycle::SkippedUnavailable
    }
}

fn select_screen(view: &mut ViewStateController, screen: ActiveScreen, tree: &ExploreTree) -> bool {
    if screen == ActiveScreen::Compare {
        return activate_compare(view, tree);
    }
    view.active_screen = screen;
    view.mark_dirty();
    true
}

fn jump_to_compare(view: &mut ViewStateController, tree: &ExploreTree) -> bool {
    activate_compare(view, tree)
}

fn reveal_path(view: &mut ViewStateController, tree: &ExploreTree, path: &NodePath) {
    view.selection = path.clone();
    let mut ancestor = Vec::new();
    let root = NodePath::root(path.tree);
    if tree.has_children(&root) && !view.expanded_paths.iter().any(|existing| existing == &root) {
        view.expanded_paths.push(root);
    }
    for index in &path.path {
        let current = NodePath {
            tree: path.tree,
            path: ancestor.clone(),
        };
        if tree.has_children(&current)
            && !view
                .expanded_paths
                .iter()
                .any(|existing| existing == &current)
        {
            view.expanded_paths.push(current);
        }
        ancestor.push(*index);
    }
    view.mark_dirty();
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
    rtt_config: RttBarConfig,
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
        let Some(hop) = tree.hop_at(&node.path) else {
            continue;
        };
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
    let detail_lines = detail_content(tree, visible.get(selected_index), rtt_config, theme);
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
    compare_scroll: &mut u16,
    scroll_limits: CompareScrollLimits,
    screen_notice: &mut Option<ScreenNotice>,
) {
    let Some(mut model) = CompareScreenModel::from_tree(tree, &view.selection) else {
        if matches!(key.code, KeyCode::Enter | KeyCode::Esc) {
            view.active_screen = ActiveScreen::Browse;
            view.mark_dirty();
        }
        return;
    };
    model.row = view.compare_row.min(model.rows().len().saturating_sub(1));
    match key.code {
        KeyCode::Down | KeyCode::Char('j') => {
            model.move_row(1);
            apply_compare_row(view, &model);
            sync_compare_row_scroll(compare_scroll, model.row, scroll_limits);
        }
        KeyCode::Up | KeyCode::Char('k') => {
            model.move_row(-1);
            apply_compare_row(view, &model);
            sync_compare_row_scroll(compare_scroll, model.row, scroll_limits);
        }
        KeyCode::Enter => {
            if let Some(path) = model.selected_path().cloned() {
                reveal_path(view, tree, &path);
            }
            view.active_screen = ActiveScreen::Browse;
            view.mark_dirty();
        }
        KeyCode::Char('E') => view.expand_all(tree),
        KeyCode::Char('C') => view.collapse_all(tree),
        KeyCode::Char('F') => {
            view.show_fork_full_path_panel = !view.show_fork_full_path_panel;
            view.mark_dirty();
            *screen_notice = None;
        }
        KeyCode::Char('B') => {
            view.show_fork_sibling_panel = !view.show_fork_sibling_panel;
            view.mark_dirty();
            *screen_notice = None;
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

fn apply_compare_row(view: &mut ViewStateController, model: &CompareScreenModel) {
    view.compare_row = model.row;
    view.compare_fork = Some(model.comparison.fork.clone());
    if let Some(path) = model.selected_path() {
        view.selection = path.clone();
    }
    view.mark_dirty();
}

fn sync_compare_scroll_for_view(
    scroll: &mut u16,
    view: &ViewStateController,
    tree: &ExploreTree,
    size: ratatui::layout::Size,
) {
    let row_count = CompareScreenModel::from_tree(tree, &view.selection)
        .map(|model| model.rows().len())
        .unwrap_or(0);
    let limits = compare_scroll_limits(Rect::from((Position::ORIGIN, size)), view, tree, row_count);
    sync_compare_row_scroll(scroll, view.compare_row, limits);
}

fn sync_compare_row_scroll(scroll: &mut u16, row: usize, limits: CompareScrollLimits) {
    let viewport = CompareViewport {
        header_lines: limits.first_row_line,
        inner_height: limits.inner_height,
    };
    *scroll = scroll_for_row(row, viewport, *scroll).min(limits.max_scroll);
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
        max_scroll: max_vertical_scroll(
            layout.total_lines.saturating_sub(layout.first_row_line),
            inner.height.saturating_sub(layout.first_row_line as u16),
        ),
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
    let theme = Theme::from_env();
    let timing = build_compare_timing(tree, view.compare_fork.as_ref());
    let header_lines = CompareScreenModel::from_tree(tree, &view.selection)
        .map(|model| {
            whole_tree_summary_lines(&timing, &theme).len()
                + sticky_header_lines(&model.comparison, &theme).len()
        })
        .unwrap_or(2);
    let mut extra = 0;
    if view.show_fork_full_path_panel {
        extra += fork_full_path_lines(&timing, &theme).len() + 1;
    }
    if view.show_fork_sibling_panel {
        extra += 1 + fork_sibling_lines(&timing, &theme).len();
    }
    CompareLayout {
        total_lines: header_lines + visible_rows + extra,
        first_row_line: header_lines,
    }
}

#[allow(clippy::too_many_arguments)]
fn render_compare(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    tree: &ExploreTree,
    view: &ViewStateController,
    compare_scroll: u16,
    rtt_config: RttBarConfig,
    theme: &Theme,
    icmp_cache: &mut HashMap<String, Option<u64>>,
    prober: &dyn IcmpProber,
) {
    let Some(mut model) = CompareScreenModel::from_tree(tree, &view.selection) else {
        let widget = Paragraph::new(tree.compare_unavailable_reason(&view.selection))
            .block(
                Block::default()
                    .title("Compare")
                    .title_bottom(footer_line(theme).centered())
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(theme.border_focused()),
            )
            .wrap(Wrap { trim: false });
        frame.render_widget(widget, area);
        return;
    };
    enrich_icmp_cached(&mut model.comparison, tree.trace(), icmp_cache, prober);
    model.row = view.compare_row.min(model.rows().len().saturating_sub(1));

    let mut header = whole_tree_summary_lines(
        &build_compare_timing(tree, view.compare_fork.as_ref()),
        theme,
    );
    header.extend(sticky_header_lines(&model.comparison, theme));
    let hop_scale = hop_scale_ms(&model.comparison);
    let mut body_lines = Vec::new();
    let highlight = view.highlighted_path.as_deref();
    for (index, summary) in model.rows().iter().enumerate() {
        let path_highlighted = highlight.is_some_and(|path| {
            path_on_highlight(&summary.path.path, path) || path.starts_with(&summary.path.path)
        });
        body_lines.push(summary_row_line(
            summary,
            index == model.row || path_highlighted,
            theme,
        ));
        if index == model.row {
            body_lines.extend(hop_detail_lines(summary, hop_scale, rtt_config, theme));
        }
    }
    let timing = build_compare_timing(tree, view.compare_fork.as_ref());
    if view.show_fork_full_path_panel {
        body_lines.push(Line::from(""));
        body_lines.extend(fork_full_path_lines(&timing, theme));
    }
    if view.show_fork_sibling_panel {
        body_lines.push(Line::from(""));
        body_lines.extend(fork_sibling_lines(&timing, theme));
    }

    let title = format!(
        "Compare — {} sibling path{}",
        model.rows().len(),
        if model.rows().len() == 1 { "" } else { "s" }
    );
    let block = Block::default()
        .title(title)
        .title_bottom(footer_line(theme).centered())
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(theme.border_focused());
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let header_height = (header.len() as u16).min(inner.height);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(header_height), Constraint::Min(0)])
        .split(inner);
    frame.render_widget(Paragraph::new(header).wrap(Wrap { trim: false }), chunks[0]);
    let body_height = chunks[1].height;
    let max_scroll = max_vertical_scroll(body_lines.len(), body_height);
    let clamped = compare_scroll.min(max_scroll);
    frame.render_widget(
        Paragraph::new(body_lines)
            .wrap(Wrap { trim: false })
            .scroll((clamped, 0)),
        chunks[1],
    );
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
    rtt_config: RttBarConfig,
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
        let Some(hop) = tree.hop_at(&node.path) else {
            continue;
        };
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

    let detail_lines = detail_content(tree, visible.get(selected_index), rtt_config, theme);
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
    let widget = Paragraph::new(message)
        .block(
            Block::default()
                .title("Notice")
                .borders(Borders::ALL)
                .border_style(theme.border_focused()),
        )
        .wrap(Wrap { trim: false });
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
    let widget = Paragraph::new(message)
        .style(theme.meta())
        .wrap(Wrap { trim: false });
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
    rtt_config: RttBarConfig,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let Some(selected) = selected else {
        return vec![Line::from(Span::styled(
            "Select a node to inspect hop details.",
            theme.meta(),
        ))];
    };
    let Some(hop) = tree.hop_at(&selected.path) else {
        return vec![Line::from(Span::styled(
            "Selected node is unavailable in this session.",
            theme.meta(),
        ))];
    };
    let mut lines = hop_detail_styled(hop, theme, rtt_config);
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
            help_binding("j/k, ↑/↓", "Move among sibling paths", theme),
            help_binding("Enter", "Return to Browse at selected path", theme),
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

/// Exercises the same tree/view/limit work `run_tui` performs before its first draw.
#[cfg(test)]
pub(crate) fn simulate_explore_first_frame(
    tree: &ExploreTree,
    view: &ViewStateController,
    terminal_area: Rect,
) {
    let theme = Theme::from_env();
    let visible = tree.visible_nodes(&view.expanded_paths);
    let mut selected_index = view.selected_visible_index(tree);
    if selected_index >= visible.len() {
        selected_index = visible.len().saturating_sub(1);
    }

    let rtt_config = RttBarConfig::default();
    let _scroll_limits = browse_scroll_limits(
        terminal_area,
        view.browse_split,
        tree,
        &visible,
        selected_index,
        rtt_config,
        &theme,
    );
    let _detail_scroll = 0u16;
    let _tree_scroll_x = 0u16;

    if view.active_screen == ActiveScreen::Compare {
        let mut icmp_cache = HashMap::new();
        struct UnavailableProber;
        impl IcmpProber for UnavailableProber {
            fn probe(
                &self,
                _addr: std::net::IpAddr,
                _timeout: std::time::Duration,
            ) -> dns_resolve::IcmpProbeResult {
                dns_resolve::IcmpProbeResult::Unavailable
            }
        }
        if let Some(model) = CompareScreenModel::from_tree(tree, &view.selection) {
            let mut comparison = model.comparison;
            enrich_icmp_cached(
                &mut comparison,
                tree.trace(),
                &mut icmp_cache,
                &UnavailableProber,
            );
            let _ = sticky_header_lines(&comparison, &theme);
            let hop_scale = hop_scale_ms(&comparison);
            for (index, summary) in comparison.paths.iter().enumerate() {
                let _ = summary_row_line(summary, index == model.row, &theme);
                let _ = hop_detail_lines(summary, hop_scale, rtt_config, &theme);
            }
            let _compare_limits =
                compare_scroll_limits(terminal_area, view, tree, comparison.paths.len());
        }
    }

    for node in &visible {
        if let Some(hop) = tree.hop_at(&node.path) {
            let _ = hop_tree_line("", "  ", hop, &theme);
        }
        let _ = detail_content(tree, visible.get(selected_index), rtt_config, &theme);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{ExploreViewState, SessionDocument};
    use crate::trace_request::TraceRequest;
    use dns_resolve::{HopOutcome, NodeOrigin, TraceHop, TraceNode, TraceTree, TraceTreeRequest};
    use std::panic::{AssertUnwindSafe, catch_unwind};

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

        // The frame looks the notice up by active screen, so a Browse notice
        // cannot paint over Compare once the operator gets there.
        let mut browse_notice = None;
        set_screen_notice(
            &mut browse_notice,
            ActiveScreen::Browse,
            "no sibling paths at this node; select hop 1 (at-path 0.0) to compare",
        );
        assert_eq!(
            screen_notice_message(&browse_notice, ActiveScreen::Compare),
            None
        );
    }

    /// Pressing `2` from the root jumps to the nearest fork instead of staying
    /// on Browse with Compare unavailable.
    #[test]
    fn compare_from_root_jumps_to_nearest_fork() {
        let tree = super::super::tree::build_explore_tree(&TraceTree {
            request: TraceTreeRequest {
                qname: "tuininga.org.".into(),
                qtype: "A".into(),
                started_at: "2026-08-25T00:00:00Z".into(),
            },
            root: TraceNode {
                hop: sample_hop(),
                origin: NodeOrigin::Trace,
                children: vec![TraceNode {
                    hop: sample_hop(),
                    origin: NodeOrigin::Trace,
                    children: vec![
                        tuininga_answered_leaf("192.0.2.10", "ns1", 10),
                        tuininga_answered_leaf("192.0.2.11", "ns2", 20),
                    ],
                }],
            },
            budget_truncated: false,
        });
        let mut view = ViewStateController::default_for_tree(&tree);
        view.selection = NodePath::root(0);

        assert!(select_screen(&mut view, ActiveScreen::Compare, &tree));
        assert_eq!(view.active_screen, ActiveScreen::Compare);
        assert_eq!(
            view.compare_fork,
            Some(NodePath {
                tree: 0,
                path: vec![0]
            })
        );
    }

    fn fork_explore_tree() -> ExploreTree {
        super::super::tree::build_explore_tree(&TraceTree {
            request: TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-08-25T00:00:00Z".into(),
            },
            root: TraceNode {
                hop: sample_hop(),
                origin: NodeOrigin::Trace,
                children: vec![
                    tuininga_answered_leaf("192.0.2.10", "ns1", 10),
                    tuininga_answered_leaf("192.0.2.11", "ns2", 20),
                ],
            },
            budget_truncated: false,
        })
    }

    #[test]
    fn tab_skips_compare_without_sibling_paths() {
        let tree = super::super::tree::build_explore_tree(&dns_resolve::build_linear_tree(
            vec![sample_hop()],
            dns_resolve::TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-08-25T00:00:00Z".into(),
            },
        ));
        let mut view = ViewStateController::default_for_tree(&tree);
        assert_eq!(
            cycle_screen_forward(&mut view, &tree),
            ScreenCycle::SkippedUnavailable
        );
        assert_eq!(view.active_screen, ActiveScreen::Browse);
        assert!(!select_screen(&mut view, ActiveScreen::Compare, &tree));
        assert_eq!(view.active_screen, ActiveScreen::Browse);
    }

    #[test]
    fn compare_rows_appear_after_branch_and_enter_returns_to_path() {
        let tree = fork_explore_tree();
        let mut view = ViewStateController::default_for_tree(&tree);
        assert!(activate_compare(&mut view, &tree));
        assert_eq!(view.active_screen, ActiveScreen::Compare);
        let mut scroll = 0u16;
        handle_compare_keys(
            event::KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
            &mut view,
            &tree,
            &mut scroll,
            CompareScrollLimits {
                max_scroll: 0,
                inner_height: 20,
                first_row_line: 3,
                total_lines: 5,
            },
            &mut None,
        );
        handle_compare_keys(
            event::KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &mut view,
            &tree,
            &mut scroll,
            CompareScrollLimits {
                max_scroll: 0,
                inner_height: 20,
                first_row_line: 3,
                total_lines: 5,
            },
            &mut None,
        );
        assert_eq!(view.active_screen, ActiveScreen::Browse);
        assert_eq!(view.selection.path, vec![1]);
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

    fn tuininga_answered_leaf(server: &str, name: &str, rtt_ms: u64) -> TraceNode {
        TraceNode {
            hop: TraceHop {
                zone: "tuininga.org.".into(),
                server: server.into(),
                server_name: Some(format!("{name}.")),
                qname: "tuininga.org.".into(),
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
                outcome: HopOutcome::Answered,
            },
            origin: NodeOrigin::Branch {
                at: dns_resolve::NodePath::root(0),
                intent: dns_resolve::BranchIntent::ExpandCut,
                at_time: "2026-08-25T00:00:00Z".into(),
            },
            children: vec![],
        }
    }

    /// Pre-fix root expand-cut bug: terminal `tuininga.org.` hops attached as root siblings.
    fn corrupted_tuininga_trace_tree() -> TraceTree {
        let org_path = TraceNode {
            hop: TraceHop {
                zone: "org.".into(),
                server: "199.249.112.1".into(),
                server_name: Some("a0.org.afilias-nst.info.".into()),
                qname: "tuininga.org.".into(),
                qtype: "A".into(),
                transport: "udp".into(),
                rtt_ms: 2,
                rcode: "NOERROR".into(),
                nsid: None,
                ede_code: None,
                ede_text: None,
                referral_ns: vec![
                    "helium.ns.hetzner.de.".into(),
                    "hydrogen.ns.hetzner.com.".into(),
                    "oxygen.ns.hetzner.com.".into(),
                ],
                glue: vec![],
                response: Default::default(),
                from_cache: false,
                outcome: HopOutcome::Referral,
            },
            origin: NodeOrigin::Trace,
            children: vec![
                tuininga_answered_leaf("193.47.99.5", "helium.ns.hetzner.de", 107),
                tuininga_answered_leaf("213.133.100.98", "hydrogen.ns.hetzner.com", 109),
                tuininga_answered_leaf("88.198.229.192", "oxygen.ns.hetzner.com", 110),
            ],
        };
        TraceTree {
            request: TraceTreeRequest {
                qname: "tuininga.org.".into(),
                qtype: "A".into(),
                started_at: "2026-08-25T00:00:00Z".into(),
            },
            root: TraceNode {
                hop: TraceHop {
                    zone: ".".into(),
                    server: "198.41.0.4".into(),
                    server_name: None,
                    qname: "tuininga.org.".into(),
                    qtype: "A".into(),
                    transport: "udp".into(),
                    rtt_ms: 1,
                    rcode: "NOERROR".into(),
                    nsid: None,
                    ede_code: None,
                    ede_text: None,
                    referral_ns: vec![
                        "a0.org.afilias-nst.info.".into(),
                        "b0.org.afilias-nst.org.".into(),
                        "c0.org.afilias-nst.info.".into(),
                    ],
                    glue: vec![
                        "199.249.112.1".into(),
                        "199.249.120.1".into(),
                        "199.249.125.1".into(),
                    ],
                    response: Default::default(),
                    from_cache: false,
                    outcome: HopOutcome::Referral,
                },
                origin: NodeOrigin::Trace,
                children: vec![
                    org_path,
                    tuininga_answered_leaf("193.47.99.5", "helium.ns.hetzner.de", 111),
                    tuininga_answered_leaf("213.133.100.98", "hydrogen.ns.hetzner.com", 112),
                ],
            },
            budget_truncated: false,
        }
    }

    fn corrupted_tuininga_document(view_state: ExploreViewState) -> SessionDocument {
        let trace = corrupted_tuininga_trace_tree();
        SessionDocument {
            version: 2,
            id: "01CORRUPTTUININGA00000000".into(),
            created_at: "2026-08-25T00:00:00Z".into(),
            updated_at: "2026-08-25T00:00:00Z".into(),
            pinned: false,
            trees: vec![crate::session::SessionTree {
                request: TraceRequest::from_options(&crate::dig_options::TraceOptions {
                    qname: "tuininga.org".into(),
                    ..Default::default()
                }),
                tree: trace,
            }],
            view_state: Some(view_state),
        }
    }

    fn corrupted_view_state_fixtures() -> Vec<(&'static str, ExploreViewState)> {
        vec![
            (
                "stale_deep_paths",
                ExploreViewState {
                    active_screen: "browse".into(),
                    expanded_paths: vec![vec![], vec![0], vec![0, 0], vec![99], vec![0, 99]],
                    selection: vec![0, 0, 2],
                    pane: "tree".into(),
                    compare_focus_row: 4,
                    browse_split_percent: 65,
                },
            ),
            (
                "compare_with_stale_row",
                ExploreViewState {
                    active_screen: "compare".into(),
                    expanded_paths: vec![vec![], vec![0], vec![1], vec![2]],
                    selection: vec![2],
                    pane: "tree".into(),
                    compare_focus_row: 99,
                    browse_split_percent: 55,
                },
            ),
            (
                "compare_root_fork",
                ExploreViewState {
                    active_screen: "compare".into(),
                    expanded_paths: vec![vec![]],
                    selection: vec![1],
                    pane: "detail".into(),
                    compare_focus_row: 1,
                    browse_split_percent: 40,
                },
            ),
        ]
    }

    #[test]
    fn corrupted_tuininga_startup_does_not_panic_before_first_draw() {
        let terminal_area = Rect::new(0, 0, 80, 24);
        for (label, view_state) in corrupted_view_state_fixtures() {
            let document = corrupted_tuininga_document(view_state);
            let explore_tree = super::super::tree::build_explore_tree(
                document.primary_tree().expect("trace tree"),
            );
            let view = ViewStateController::from_document(&explore_tree, &document);
            let result = catch_unwind(AssertUnwindSafe(|| {
                simulate_explore_first_frame(&explore_tree, &view, terminal_area);
            }));
            assert!(
                result.is_ok(),
                "explore startup panicked for corrupted tuininga fixture {label}"
            );
        }
    }

    #[test]
    fn corrupted_tuininga_startup_survives_zero_terminal_area() {
        let document = corrupted_tuininga_document(corrupted_view_state_fixtures()[0].1.clone());
        let explore_tree =
            super::super::tree::build_explore_tree(document.primary_tree().expect("trace tree"));
        let view = ViewStateController::from_document(&explore_tree, &document);
        let result = catch_unwind(AssertUnwindSafe(|| {
            simulate_explore_first_frame(&explore_tree, &view, Rect::new(0, 0, 0, 0));
        }));
        assert!(
            result.is_ok(),
            "zero-size terminal area must not panic during startup prep"
        );
    }

    #[test]
    fn corrupted_tuininga_root_has_extra_zone_siblings() {
        let trace = corrupted_tuininga_trace_tree();
        let root = trace
            .resolve(&dns_resolve::NodePath::root(0))
            .expect("root");
        assert_eq!(root.children.len(), 3);
        assert_eq!(root.children[0].hop.zone, "org.");
        assert!(
            root.children[1..]
                .iter()
                .all(|child| child.hop.zone == "tuininga.org."),
            "buggy sessions attach terminal hops as root siblings"
        );
    }
}
