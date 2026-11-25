#![cfg(all(target_os = "linux", feature = "tui"))]

use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use crate::options::ViewId;
use crate::window::Aggregator;

use super::config_panel::format_config_lines;
use super::live_ingest::LivePipeline;
use super::stats::StatusBar;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modal {
    None,
    Help {
        scroll: u16,
    },
    ViewPicker {
        scroll: u16,
    },
    PanelPicker {
        scroll: u16,
    },
    Pipeline {
        scroll: u16,
    },
    Workers {
        scroll: u16,
    },
    Stats {
        scroll: u16,
    },
    Config {
        scroll: u16,
    },
    /// Warnings (e.g. topology); auto-opens when non-empty.
    Notices {
        scroll: u16,
    },
    QnameLevelInput {
        buf: String,
    },
}

impl Modal {
    pub fn is_open(&self) -> bool {
        !matches!(self, Modal::None)
    }

    pub fn open(&mut self, next: Modal) {
        *self = next;
    }

    pub fn dismiss(&mut self) {
        *self = Modal::None;
    }

    fn scroll_up(&mut self) {
        match self {
            Modal::Help { scroll }
            | Modal::ViewPicker { scroll }
            | Modal::PanelPicker { scroll }
            | Modal::Pipeline { scroll }
            | Modal::Workers { scroll }
            | Modal::Stats { scroll }
            | Modal::Config { scroll }
            | Modal::Notices { scroll } => {
                *scroll = scroll.saturating_sub(1);
            }
            _ => {}
        }
    }

    fn scroll_down(&mut self, max: u16) {
        match self {
            Modal::Help { scroll }
            | Modal::ViewPicker { scroll }
            | Modal::PanelPicker { scroll }
            | Modal::Pipeline { scroll }
            | Modal::Workers { scroll }
            | Modal::Stats { scroll }
            | Modal::Config { scroll }
            | Modal::Notices { scroll } => {
                *scroll = (*scroll + 1).min(max);
            }
            _ => {}
        }
    }
}

pub struct KeyResult {
    pub quit: bool,
    pub force_redraw: bool,
}

pub fn handle_key(
    modal: &mut Modal,
    view: &mut ViewId,
    agg: &mut Aggregator,
    pipeline: &mut LivePipeline,
    options: &mut crate::options::FluxOptions,
    code: KeyCode,
    modifiers: KeyModifiers,
) -> KeyResult {
    if modifiers.contains(KeyModifiers::CONTROL) && code == KeyCode::Char('c') {
        return KeyResult {
            quit: true,
            force_redraw: true,
        };
    }

    if code == KeyCode::Char('q') {
        if modal.is_open() {
            mark_notices_read_if_open(modal, pipeline);
            modal.dismiss();
            return KeyResult {
                quit: false,
                force_redraw: true,
            };
        }
        return KeyResult {
            quit: true,
            force_redraw: true,
        };
    }

    if code == KeyCode::Esc {
        if modal.is_open() {
            mark_notices_read_if_open(modal, pipeline);
            modal.dismiss();
            return KeyResult {
                quit: false,
                force_redraw: true,
            };
        }
        return KeyResult {
            quit: false,
            force_redraw: false,
        };
    }

    if code == KeyCode::Backspace
        && modal.is_open()
        && !matches!(modal, Modal::QnameLevelInput { .. })
    {
        mark_notices_read_if_open(modal, pipeline);
        modal.dismiss();
        return KeyResult {
            quit: false,
            force_redraw: true,
        };
    }

    if let Some(result) = try_modal_launcher(modal, pipeline, code) {
        return result;
    }

    match modal.clone() {
        Modal::QnameLevelInput { buf } => handle_qname_input(modal, view, code, buf),
        Modal::ViewPicker { .. } => handle_view_picker(modal, view, code),
        Modal::PanelPicker { .. } => handle_panel_picker(modal, pipeline, code),
        Modal::Workers { .. } => handle_workers_modal(modal, pipeline, options, code),
        Modal::Help { .. }
        | Modal::Pipeline { .. }
        | Modal::Stats { .. }
        | Modal::Config { .. }
        | Modal::Notices { .. } => handle_scroll_modal(modal, code),
        Modal::None => handle_main_keys(view, agg, pipeline, options, code),
    }
}

/// Keys that belong to the open picker/entry modal, not global launchers.
fn launcher_suppressed(modal: &Modal, code: KeyCode) -> bool {
    match modal {
        Modal::PanelPicker { .. } => matches!(
            code,
            KeyCode::Char('l')
                | KeyCode::Char('w')
                | KeyCode::Char('h')
                | KeyCode::Char('?')
                | KeyCode::Char('u')
                | KeyCode::Char('c')
                | KeyCode::Char('!')
        ),
        Modal::ViewPicker { .. } => view_action(code).is_some(),
        Modal::QnameLevelInput { .. } => match code {
            KeyCode::Backspace | KeyCode::Enter => true,
            KeyCode::Char(c) => c.is_ascii_digit(),
            _ => false,
        },
        Modal::Workers { .. } => {
            matches!(
                code,
                KeyCode::Char('+') | KeyCode::Char('=') | KeyCode::Char('-')
            )
        }
        Modal::Help { .. }
        | Modal::Pipeline { .. }
        | Modal::Stats { .. }
        | Modal::Config { .. }
        | Modal::Notices { .. }
        | Modal::None => false,
    }
}

/// Open/replace a top-level modal from any UI state (listeners, help, another picker, etc.).
fn mark_notices_read_if_open(modal: &Modal, pipeline: &mut LivePipeline) {
    if matches!(modal, Modal::Notices { .. }) {
        pipeline.session_notices.mark_all_read();
    }
}

fn try_modal_launcher(
    modal: &mut Modal,
    pipeline: &LivePipeline,
    code: KeyCode,
) -> Option<KeyResult> {
    if launcher_suppressed(modal, code) {
        return None;
    }
    let next = match code {
        KeyCode::Char('p') => Some(Modal::PanelPicker { scroll: 0 }),
        KeyCode::Char('v') => Some(Modal::ViewPicker { scroll: 0 }),
        KeyCode::Char('w') => Some(Modal::Workers { scroll: 0 }),
        KeyCode::Char('l') => Some(Modal::QnameLevelInput { buf: String::new() }),
        KeyCode::Char('?') | KeyCode::Char('h') => Some(Modal::Help { scroll: 0 }),
        KeyCode::Char('u') => Some(Modal::Stats { scroll: 0 }),
        KeyCode::Char('c') => Some(Modal::Config { scroll: 0 }),
        KeyCode::Char('!') if !pipeline.session_notices.is_empty() => {
            Some(Modal::Notices { scroll: 0 })
        }
        _ => None,
    };
    next.map(|m| {
        modal.open(m);
        KeyResult {
            quit: false,
            force_redraw: true,
        }
    })
}

fn handle_qname_input(
    modal: &mut Modal,
    view: &mut ViewId,
    code: KeyCode,
    buf: String,
) -> KeyResult {
    let mut buf = buf;
    match code {
        KeyCode::Backspace => {
            buf.pop();
            *modal = Modal::QnameLevelInput { buf };
        }
        KeyCode::Enter => {
            if let Ok(n) = buf.parse::<u8>() {
                if (1..=9).contains(&n) {
                    *view = ViewId::QnameLevel(n);
                }
            }
            modal.dismiss();
        }
        KeyCode::Char(c) if c.is_ascii_digit() && buf.is_empty() => {
            buf.push(c);
            *modal = Modal::QnameLevelInput { buf };
        }
        _ => {}
    }
    KeyResult {
        quit: false,
        force_redraw: true,
    }
}

fn view_action(code: KeyCode) -> Option<ViewId> {
    match code {
        KeyCode::Char('s') => Some(ViewId::Sources),
        KeyCode::Char('d') => Some(ViewId::Destinations),
        KeyCode::Char('t') => Some(ViewId::Qtype),
        KeyCode::Char('r') => Some(ViewId::Rcode),
        KeyCode::Char('o') => Some(ViewId::Opcode),
        KeyCode::Char(c) if c.is_ascii_digit() => {
            let n = c.to_digit(10)? as u8;
            if (1..=9).contains(&n) {
                Some(ViewId::QnameLevel(n))
            } else {
                None
            }
        }
        _ => None,
    }
}

enum PanelAction {
    Pipeline,
    Workers,
    Help,
    Stats,
    Config,
    Notices,
}

fn panel_action(code: KeyCode) -> Option<PanelAction> {
    match code {
        KeyCode::Char('l') => Some(PanelAction::Pipeline),
        KeyCode::Char('w') => Some(PanelAction::Workers),
        KeyCode::Char('?') | KeyCode::Char('h') => Some(PanelAction::Help),
        KeyCode::Char('u') => Some(PanelAction::Stats),
        KeyCode::Char('c') => Some(PanelAction::Config),
        KeyCode::Char('!') => Some(PanelAction::Notices),
        _ => None,
    }
}

fn handle_scroll_keys(modal: &mut Modal, code: KeyCode, scroll_max: u16) -> bool {
    if matches!(code, KeyCode::Up | KeyCode::Char('k')) {
        modal.scroll_up();
        return true;
    }
    if matches!(code, KeyCode::Down | KeyCode::Char('j')) {
        modal.scroll_down(scroll_max);
        return true;
    }
    false
}

fn handle_view_picker(modal: &mut Modal, view: &mut ViewId, code: KeyCode) -> KeyResult {
    if handle_scroll_keys(modal, code, 80) {
        return KeyResult {
            quit: false,
            force_redraw: true,
        };
    }
    if let Some(v) = view_action(code) {
        *view = v;
        modal.dismiss();
        return KeyResult {
            quit: false,
            force_redraw: true,
        };
    }
    KeyResult {
        quit: false,
        force_redraw: false,
    }
}

fn handle_panel_picker(modal: &mut Modal, _pipeline: &LivePipeline, code: KeyCode) -> KeyResult {
    if matches!(code, KeyCode::Up | KeyCode::Char('k')) {
        modal.scroll_up();
        return KeyResult {
            quit: false,
            force_redraw: true,
        };
    }
    if matches!(code, KeyCode::Down | KeyCode::Char('j')) {
        modal.scroll_down(80);
        return KeyResult {
            quit: false,
            force_redraw: true,
        };
    }
    if let Some(action) = panel_action(code) {
        match action {
            PanelAction::Pipeline => modal.open(Modal::Pipeline { scroll: 0 }),
            PanelAction::Workers => modal.open(Modal::Workers { scroll: 0 }),
            PanelAction::Help => modal.open(Modal::Help { scroll: 0 }),
            PanelAction::Stats => modal.open(Modal::Stats { scroll: 0 }),
            PanelAction::Config => modal.open(Modal::Config { scroll: 0 }),
            PanelAction::Notices => modal.open(Modal::Notices { scroll: 0 }),
        }
        return KeyResult {
            quit: false,
            force_redraw: true,
        };
    }
    KeyResult {
        quit: false,
        force_redraw: false,
    }
}

fn handle_workers_modal(
    modal: &mut Modal,
    pipeline: &mut LivePipeline,
    options: &mut crate::options::FluxOptions,
    code: KeyCode,
) -> KeyResult {
    if matches!(code, KeyCode::Up | KeyCode::Char('k')) {
        modal.scroll_up();
        return KeyResult {
            quit: false,
            force_redraw: true,
        };
    }
    if matches!(code, KeyCode::Down | KeyCode::Char('j')) {
        modal.scroll_down(120);
        return KeyResult {
            quit: false,
            force_redraw: true,
        };
    }
    match code {
        KeyCode::Char('+') | KeyCode::Char('=') => {
            let n = pipeline.worker_count().saturating_add(1);
            pipeline.resize_workers(n);
            options.workers = n;
        }
        KeyCode::Char('-') => {
            let n = pipeline.worker_count().saturating_sub(1).max(1);
            pipeline.resize_workers(n);
            options.workers = n;
        }
        _ => {}
    }
    KeyResult {
        quit: false,
        force_redraw: true,
    }
}

fn handle_scroll_modal(modal: &mut Modal, code: KeyCode) -> KeyResult {
    if matches!(code, KeyCode::Up | KeyCode::Char('k')) {
        modal.scroll_up();
    } else if matches!(code, KeyCode::Down | KeyCode::Char('j')) {
        modal.scroll_down(120);
    } else if matches!(code, KeyCode::PageUp) {
        for _ in 0..5 {
            modal.scroll_up();
        }
    } else if matches!(code, KeyCode::PageDown) {
        modal.scroll_down(120);
    }
    KeyResult {
        quit: false,
        force_redraw: true,
    }
}

fn handle_main_keys(
    view: &mut ViewId,
    agg: &mut Aggregator,
    pipeline: &mut LivePipeline,
    options: &mut crate::options::FluxOptions,
    code: KeyCode,
) -> KeyResult {
    match code {
        KeyCode::Char('g') => {
            let on = !agg.smart_qname_labels;
            agg.set_smart_qname_labels(on);
        }
        KeyCode::Char('+') | KeyCode::Char('=') => {
            let n = pipeline.worker_count().saturating_add(1);
            pipeline.resize_workers(n);
            options.workers = n;
        }
        KeyCode::Char('-') => {
            let n = pipeline.worker_count().saturating_sub(1).max(1);
            pipeline.resize_workers(n);
            options.workers = n;
        }
        KeyCode::Char('f') => {
            let mut picker = crate::filter::PickerState::Closed;
            let _ = crate::filter::picker_key(&mut picker, 'f');
        }
        other => {
            if let Some(v) = view_action(other) {
                *view = v;
            }
        }
    }
    KeyResult {
        quit: false,
        force_redraw: true,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn render_modal(
    f: &mut Frame<'_>,
    modal: &Modal,
    iface: &str,
    capture_threads: u32,
    fanout_group: Option<u32>,
    pipeline: &LivePipeline,
    options: &crate::options::FluxOptions,
    hint_lines: &[String],
    smart_qname: bool,
    status: &StatusBar,
) {
    if matches!(modal, Modal::None) {
        return;
    }
    let (title, lines, scroll) = match modal {
        Modal::None => return,
        Modal::Help { scroll } => ("Help", help_lines(smart_qname), *scroll),
        Modal::ViewPicker { scroll } => ("Views", view_picker_lines(), *scroll),
        Modal::PanelPicker { scroll } => (
            "Panels",
            panel_picker_lines(!pipeline.session_notices.is_empty()),
            *scroll,
        ),
        Modal::Pipeline { scroll } => (
            "Pipeline",
            pipeline_lines(iface, capture_threads, fanout_group, pipeline, hint_lines),
            *scroll,
        ),
        Modal::Workers { scroll } => (
            "Scaling",
            scaling_lines(iface, capture_threads, fanout_group, pipeline, hint_lines),
            *scroll,
        ),
        Modal::Stats { scroll } => ("Stats", status.format_detail_lines(), *scroll),
        Modal::Config { scroll } => (
            "Config",
            format_config_lines(
                options,
                &pipeline.listeners,
                iface,
                fanout_group,
                status.effective_window_secs,
                pipeline,
            ),
            *scroll,
        ),
        Modal::Notices { scroll } => ("Notices", pipeline.session_notices.modal_lines(), *scroll),
        Modal::QnameLevelInput { buf } => {
            let popup = centered_rect(50, 20, f.area());
            f.render_widget(Clear, popup);
            let text = format!("QName view label level (1–9)\n\nLevel: {buf}_");
            f.render_widget(
                Paragraph::new(text)
                    .block(
                        Block::default()
                            .title("QName level")
                            .title_bottom(Line::from("Enter confirm · Esc dismiss"))
                            .borders(Borders::ALL),
                    )
                    .alignment(Alignment::Left),
                popup,
            );
            return;
        }
    };

    let popup = centered_rect(78, 60, f.area());
    f.render_widget(Clear, popup);
    let content_h = modal_content_height(popup);
    let footer = modal_footer(lines.len(), content_h);
    let body = scrollable_text(&lines, scroll, content_h);
    f.render_widget(
        Paragraph::new(body)
            .block(
                Block::default()
                    .title(title)
                    .title_bottom(Line::from(footer))
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false }),
        popup,
    );
}

/// Inner paragraph height for a titled modal block (top title + bottom footer).
fn modal_content_height(area: Rect) -> u16 {
    Block::default()
        .title(" ")
        .title_bottom(Line::from(" "))
        .borders(Borders::ALL)
        .inner(area)
        .height
}

fn inside_tmux() -> bool {
    std::env::var_os("TMUX").is_some()
}

fn modal_footer(line_count: usize, content_height: u16) -> String {
    let mut footer = if inside_tmux() {
        "Backspace dismiss · Esc may lag (tmux escape-time; see ?)".to_string()
    } else {
        "Esc or Backspace dismiss".to_string()
    };
    if line_count > content_height as usize {
        footer.push_str(" · ↑/↓ j/k scroll");
    }
    footer
}

fn scrollable_text(lines: &[String], scroll: u16, visible_rows: u16) -> String {
    let skip = scroll as usize;
    let take = visible_rows as usize;
    lines
        .iter()
        .skip(skip)
        .take(take)
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
}

fn help_lines(smart_qname: bool) -> Vec<String> {
    let smart = if smart_qname { "on" } else { "off" };
    let mut lines = vec![
        "Views (main table)".into(),
        "  v             view picker (lists all view keys)".into(),
        "  s d t r o     sources, destinations, qtype, rcode, opcode".into(),
        "  1–9           qname grouping at label level N".into(),
        "  l             set qname level (1–9) via prompt".into(),
        "".into(),
        "Panels (modals)".into(),
        "  p             panel picker".into(),
        "  p → l/w/u/c/!/h pipeline, scaling, stats, config, notices, help".into(),
        "  u             stats (live counters)".into(),
        "  c             session config (interfaces, options)".into(),
        "  !             warnings (topology, etc.)".into(),
        "  w             scaling — parse threads +/- (shortcut)".into(),
        "".into(),
        "Startup".into(),
        "  Topology warnings auto-open Notices; Esc marks read; footer counts".into(),
        "".into(),
        "Scaling".into(),
        "  + / -         parse threads (also in w modal)".into(),
        "".into(),
        "Labels".into(),
        format!("  g             toggle smart qname aggregation ({smart})"),
        "                (PSL-aware: e.g. example.co.uk at level 2)".into(),
        "".into(),
        "Other".into(),
        "  ? or h        this help".into(),
        "  Esc, Backspace  close modal (does not quit)".into(),
        "  q             close modal, or quit when none open".into(),
        "  Ctrl+C        quit".into(),
    ];
    if inside_tmux() {
        lines.push("".into());
        lines.push("tmux (Esc latency)".into());
        lines.push("  Backspace     dismiss without delay".into());
        lines.push("  escape-time   add to ~/.tmux.conf:".into());
        lines.push("                set -g escape-time 0".into());
        lines.push("                then: tmux source-file ~/.tmux.conf".into());
        lines.push("  Terminator    outside tmux does not pass kitty Esc fix;".into());
        lines.push("                tmux holds Esc for sequence detection".into());
        lines.push("  1–9           use top-row keys; numpad may lag like Esc".into());
    } else {
        lines.push("".into());
        lines.push("  Backspace     instant dismiss if Esc feels slow".into());
    }
    lines
}

fn view_picker_lines() -> Vec<String> {
    vec![
        "Choose a view (key switches main table and closes picker):".into(),
        "".into(),
        "  s   Sources".into(),
        "  d   Destinations".into(),
        "  t   Qtypes".into(),
        "  r   Rcodes".into(),
        "  o   Opcodes".into(),
        "  1-9 QName label level 1 … 9".into(),
    ]
}

fn panel_picker_lines(has_notices: bool) -> Vec<String> {
    let mut lines = vec![
        "Choose a panel (key opens it):".into(),
        "".into(),
        "  l   Pipeline".into(),
        "  w   Scaling".into(),
        "  u   Stats".into(),
        "  c   Config".into(),
    ];
    if has_notices {
        lines.push("  !   Notices (warnings)".into());
    }
    lines.push("  h   Help".into());
    lines
}

fn pipeline_diagram(capture: u32, flow: u32, parse: usize) -> String {
    format!("  capture({capture})  ->  flow({flow})  ->  parse({parse})")
}

fn kv_line(key: &str, value: impl std::fmt::Display) -> String {
    format!("  {key}: {value}")
}

fn pipeline_lines(
    iface: &str,
    capture_threads: u32,
    fanout_group: Option<u32>,
    pipeline: &LivePipeline,
    hint_lines: &[String],
) -> Vec<String> {
    let fanout = fanout_group
        .map(|g| format!("kernel PACKET_FANOUT group {g}"))
        .unwrap_or_else(|| "single capture path (no fanout)".into());
    let flow = pipeline.flow_threads();
    let parse = pipeline.worker_count();
    let mut out = vec![
        pipeline_diagram(capture_threads, flow, parse),
        String::new(),
    ];
    out.push("== Capture ==".into());
    out.push(kv_line("interface", iface));
    out.push(kv_line("capture threads", capture_threads));
    out.push(kv_line("fanout", fanout));
    out.push(String::new());
    out.push("== Flow ==".into());
    out.push(kv_line("flow threads", flow));
    out.push("  (virtual hash buckets)".into());
    out.push(String::new());
    out.push("== Parse ==".into());
    out.push(kv_line("parse threads", parse));
    out.push(kv_line(
        "busy",
        format!("{}%", pipeline.parse_busy_percent()),
    ));
    out.push(kv_line("queue depth", pipeline.queue_depth()));
    out.push(String::new());
    out.push("== Tuning hints ==".into());
    if hint_lines.is_empty() {
        out.push("  (none)".into());
    } else {
        for h in hint_lines {
            out.push(format!("  {h}"));
        }
    }
    out
}

fn scaling_lines(
    iface: &str,
    capture_threads: u32,
    fanout_group: Option<u32>,
    pipeline: &LivePipeline,
    hint_lines: &[String],
) -> Vec<String> {
    let fanout = fanout_group
        .map(|g| format!("fanout group {g}"))
        .unwrap_or_else(|| "no fanout".into());
    let flow = pipeline.flow_threads();
    let parse = pipeline.worker_count();
    let mut out = vec![
        pipeline_diagram(capture_threads, flow, parse),
        String::new(),
    ];
    out.push("Adjust parse threads with + / - (live only).".into());
    out.push("Capture and flow thread counts: set at startup (CLI).".into());
    out.push(String::new());
    out.push("== Threads ==".into());
    out.push(kv_line("interface", iface));
    out.push(kv_line("capture threads", capture_threads));
    out.push(kv_line("fanout", fanout));
    out.push(kv_line("flow threads", flow));
    out.push(kv_line("parse threads", parse));
    out.push(kv_line(
        "busy",
        format!("{}%", pipeline.parse_busy_percent()),
    ));
    out.push(kv_line("queue depth", pipeline.queue_depth()));
    out.push(String::new());
    out.push("== Tuning hints ==".into());
    if hint_lines.is_empty() {
        out.push("  (none)".into());
    } else {
        for h in hint_lines {
            out.push(format!("  {h}"));
        }
    }
    out
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
