#![cfg(all(target_os = "linux", feature = "tui"))]

use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use crate::options::ViewId;
use crate::window::Aggregator;

use super::live_ingest::LivePipeline;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modal {
    None,
    Help { scroll: u16 },
    PanelPicker { scroll: u16 },
    Listeners { scroll: u16 },
    Workers { scroll: u16 },
    QnameLevelInput { buf: String },
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
            Modal::Help { scroll } | Modal::PanelPicker { scroll } | Modal::Listeners { scroll } | Modal::Workers { scroll } => {
                *scroll = scroll.saturating_sub(1);
            }
            _ => {}
        }
    }

    fn scroll_down(&mut self, max: u16) {
        match self {
            Modal::Help { scroll }
            | Modal::PanelPicker { scroll }
            | Modal::Listeners { scroll }
            | Modal::Workers { scroll } => {
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
        return KeyResult {
            quit: true,
            force_redraw: true,
        };
    }

    if code == KeyCode::Esc {
        if modal.is_open() {
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

    match modal.clone() {
        Modal::QnameLevelInput { buf } => handle_qname_input(modal, view, code, buf),
        Modal::PanelPicker { .. } => handle_panel_picker(modal, view, code),
        Modal::Workers { .. } => handle_workers_modal(modal, pipeline, options, code),
        Modal::Help { .. } | Modal::Listeners { .. } => handle_scroll_modal(modal, code),
        Modal::None => handle_main_keys(modal, view, agg, pipeline, options, code),
    }
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
        KeyCode::Char(c) if c.is_ascii_digit() && buf.len() < 1 => {
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

fn panel_action(code: KeyCode) -> Option<PanelAction> {
    match code {
        KeyCode::Char('s') => Some(PanelAction::View(ViewId::Sources)),
        KeyCode::Char('d') => Some(PanelAction::View(ViewId::Destinations)),
        KeyCode::Char('t') => Some(PanelAction::View(ViewId::Qtype)),
        KeyCode::Char('r') => Some(PanelAction::View(ViewId::Rcode)),
        KeyCode::Char('o') => Some(PanelAction::View(ViewId::Opcode)),
        KeyCode::Char('l') => Some(PanelAction::Listeners),
        KeyCode::Char(c) if c.is_ascii_digit() => {
            let n = c.to_digit(10)? as u8;
            if (1..=9).contains(&n) {
                Some(PanelAction::View(ViewId::QnameLevel(n)))
            } else {
                None
            }
        }
        _ => None,
    }
}

enum PanelAction {
    View(ViewId),
    Listeners,
}

fn handle_panel_picker(modal: &mut Modal, view: &mut ViewId, code: KeyCode) -> KeyResult {
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
            PanelAction::View(v) => {
                *view = v;
                modal.dismiss();
            }
            PanelAction::Listeners => {
                modal.open(Modal::Listeners { scroll: 0 });
            }
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
    modal: &mut Modal,
    view: &mut ViewId,
    agg: &mut Aggregator,
    pipeline: &mut LivePipeline,
    options: &mut crate::options::FluxOptions,
    code: KeyCode,
) -> KeyResult {
    match code {
        KeyCode::Char('p') => {
            modal.open(Modal::PanelPicker { scroll: 0 });
        }
        KeyCode::Char('w') => {
            modal.open(Modal::Workers { scroll: 0 });
        }
        KeyCode::Char('l') => {
            modal.open(Modal::QnameLevelInput { buf: String::new() });
        }
        KeyCode::Char('g') => {
            let on = !agg.smart_qname_labels;
            agg.set_smart_qname_labels(on);
        }
        KeyCode::Char('?') | KeyCode::Char('h') => {
            modal.open(Modal::Help { scroll: 0 });
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
            if let Some(action) = panel_action(other) {
                match action {
                    PanelAction::View(v) => *view = v,
                    PanelAction::Listeners => modal.open(Modal::Listeners { scroll: 0 }),
                }
            }
        }
    }
    KeyResult {
        quit: false,
        force_redraw: true,
    }
}

pub fn render_modal(
    f: &mut Frame<'_>,
    modal: &Modal,
    iface: &str,
    capture_threads: u32,
    fanout_group: Option<u32>,
    pipeline: &LivePipeline,
    hint_lines: &[String],
    smart_qname: bool,
) {
    if matches!(modal, Modal::None) {
        return;
    }
    let (title, lines, scroll) = match modal {
        Modal::None => return,
        Modal::Help { scroll } => ("Help", help_lines(smart_qname), *scroll),
        Modal::PanelPicker { scroll } => ("Panels", panel_picker_lines(), *scroll),
        Modal::Listeners { scroll } => (
            "Listeners & pipeline",
            listeners_lines(iface, capture_threads, fanout_group, pipeline, hint_lines),
            *scroll,
        ),
        Modal::Workers { scroll } => (
            "Workers & tuning",
            workers_lines(iface, capture_threads, fanout_group, pipeline, hint_lines),
            *scroll,
        ),
        Modal::QnameLevelInput { buf } => {
            let popup = centered_rect(50, 20, f.area());
            f.render_widget(Clear, popup);
            let text = format!(
                "QName view label level (1–9)\n\nLevel: {buf}_\n\nEnter confirm · Esc cancel"
            );
            f.render_widget(
                Paragraph::new(text)
                    .block(
                        Block::default()
                            .title("QName level")
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
    let inner_h = popup.height.saturating_sub(2);
    let body = scrollable_text(&lines, scroll, inner_h);
    let foot = "Esc dismiss · ↑/↓ or j/k scroll";
    f.render_widget(
        Paragraph::new(format!("{body}\n{foot}"))
            .block(Block::default().title(title).borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        popup,
    );
}

fn scrollable_text(lines: &[String], scroll: u16, visible_rows: u16) -> String {
    let skip = scroll as usize;
    let take = visible_rows.saturating_sub(1) as usize;
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
    vec![
        "Navigation".into(),
        "  s d t r o     source, destination, qtype, rcode, opcode views".into(),
        "  1–9           qname grouping at label level N".into(),
        "  l             set qname level (1–9) via prompt".into(),
        "  p             panel picker modal (then pick a view key)".into(),
        "  p → l         listeners & pipeline modal".into(),
        "".into(),
        "Scaling".into(),
        "  w             workers / thread tuning modal".into(),
        "  + / -         parse workers (also in w modal)".into(),
        "".into(),
        "Labels".into(),
        format!("  g             toggle smart qname aggregation ({smart})"),
        "                (PSL-aware: e.g. example.co.uk at level 2)".into(),
        "".into(),
        "Other".into(),
        "  ? or h        this help".into(),
        "  Esc           close modal (does not quit)".into(),
        "  q, Ctrl+C     quit".into(),
    ]
}

fn panel_picker_lines() -> Vec<String> {
    vec![
        "Choose a panel (key closes picker):".into(),
        "".into(),
        "  s   Sources".into(),
        "  d   Destinations".into(),
        "  t   Qtypes".into(),
        "  r   Rcodes".into(),
        "  o   Opcodes".into(),
        "  1-9 QName level 1 … 9".into(),
        "  l   Listeners & pipeline".into(),
    ]
}

fn listeners_lines(
    iface: &str,
    capture_threads: u32,
    fanout_group: Option<u32>,
    pipeline: &LivePipeline,
    hint_lines: &[String],
) -> Vec<String> {
    let fanout = fanout_group
        .map(|g| format!("kernel PACKET_FANOUT group {g}"))
        .unwrap_or_else(|| "single capture path (no fanout)".into());
    let mut out = vec![
        "== Capture ==".into(),
        format!("  interface {iface}"),
        format!("  listener threads {capture_threads} ({fanout})"),
        "".into(),
        "== Flow stage ==".into(),
        format!(
            "  flow threads {} (virtual hash buckets)",
            pipeline.flow_threads()
        ),
        "".into(),
        "== Parse stage ==".into(),
        format!(
            "  workers {}  busy {}%  queue depth {}",
            pipeline.worker_count(),
            pipeline.parse_busy_percent(),
            pipeline.queue_depth()
        ),
        "".into(),
        "== Tuning hints ==".into(),
    ];
    if hint_lines.is_empty() {
        out.push("  (none)".into());
    } else {
        for h in hint_lines {
            out.push(format!("  {h}"));
        }
    }
    out
}

fn workers_lines(
    iface: &str,
    capture_threads: u32,
    fanout_group: Option<u32>,
    pipeline: &LivePipeline,
    hint_lines: &[String],
) -> Vec<String> {
    let fanout = fanout_group
        .map(|g| format!("fanout group {g}"))
        .unwrap_or_else(|| "no fanout".into());
    let mut out = vec![
        "Adjust parse workers with + / - (live)".into(),
        "Capture / flow counts are set at startup (CLI).".into(),
        "".into(),
        format!("capture on {iface}: threads={capture_threads} ({fanout})"),
        format!("flow threads: {}", pipeline.flow_threads()),
        format!(
            "parse workers: {} (busy {}%, queue {})",
            pipeline.worker_count(),
            pipeline.parse_busy_percent(),
            pipeline.queue_depth()
        ),
        "".into(),
        "== Tuning hints ==".into(),
    ];
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