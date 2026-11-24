#![cfg(all(target_os = "linux", feature = "tui"))]

use std::io::{self, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossterm::ExecutableCommand;
use crossterm::event::{self, Event};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};
use thiserror::Error;

use crate::capture::LiveCapture;
use crate::filter::NoopResolver;
use crate::options::{FluxOptions, ViewId};
use crate::scale::hints::{HintEngine, ListenerMeasurements};
use crate::view::format_batch_tables;
use crate::window::Aggregator;

use super::live_ingest::LivePipeline;
use super::stats::{StatusBar, StatusLine, TUI_FOOTER_HINTS, WatchInput};
use crate::scale::priority::{ThreadRole, apply_thread_priority};

use super::tui_modal::{Modal, handle_key, render_modal};

/// Per-loop packet budget; drained in smaller chunks so keys are handled between batches.
const CAPTURE_DRAIN_BUDGET: u64 = 8_192;
const CAPTURE_DRAIN_CHUNK: u64 = 16;
/// Block waiting for input; kept short so Esc feels immediate (especially with a modal open).
const EVENT_WAIT_BUSY_MS: u64 = 4;
const EVENT_WAIT_IDLE_MS: u64 = 12;

#[derive(Default)]
struct DrawCache {
    main_text: String,
    title: String,
}

impl DrawCache {
    fn is_valid(&self) -> bool {
        !self.main_text.is_empty()
    }
}

#[derive(Debug, Error)]
pub enum TuiError {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Live(#[from] crate::capture::LiveCaptureError),

    #[error(transparent)]
    Options(#[from] crate::options::OptionsError),
}

pub fn run_live(
    cap: LiveCapture,
    mut options: FluxOptions,
    capture_threads: u32,
) -> Result<(), TuiError> {
    apply_thread_priority(ThreadRole::Tui);
    cap.set_nonblocking()?;
    let iface = cap.iface().to_string();
    let fanout_group = cap.fanout_group;
    let filter = options.compile_filter(&NoopResolver)?;
    let eval_ctx = options.build_eval_context(&NoopResolver);
    let mut agg = Aggregator::new(
        options.window.clone(),
        options.late_grace,
        options.late_policy,
        filter,
        eval_ctx,
    );
    let mut pipeline = LivePipeline::new(&options);
    let hint_engine = HintEngine::new();
    let refresh = Duration::from_secs_f64(1.0 / options.tui_hz.max(1) as f64);

    let mut stdout = io::stdout();
    enable_raw_mode()?;
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;
    let mut view = ViewId::Sources;
    let mut modal = Modal::None;
    let start = Instant::now();
    let mut last_draw = Instant::now();
    let mut frames_since_draw: u64 = 0;
    let mut force_redraw = true;
    let mut draw_cache = DrawCache::default();
    let mut overlay_dismiss_redraw = false;

    'live: loop {
        if drain_events(
            &mut modal,
            &mut view,
            &mut agg,
            &mut pipeline,
            &mut options,
            &mut force_redraw,
            &mut overlay_dismiss_redraw,
        )? {
            break 'live;
        }
        if maybe_redraw(
            force_redraw,
            overlay_dismiss_redraw,
            &mut term,
            &iface,
            capture_threads,
            fanout_group,
            &agg,
            &pipeline,
            &options,
            &hint_engine,
            &view,
            &modal,
            start,
            refresh,
            &mut frames_since_draw,
            &mut last_draw,
            &mut draw_cache,
        )? {
            force_redraw = false;
            overlay_dismiss_redraw = false;
        }

        let mut drained_this_turn = 0u64;
        while drained_this_turn < CAPTURE_DRAIN_BUDGET {
            let chunk = drain_capture(
                &cap,
                &mut agg,
                &mut pipeline,
                &options,
                CAPTURE_DRAIN_CHUNK,
            );
            if chunk == 0 {
                break;
            }
            drained_this_turn += chunk;
            frames_since_draw += chunk;

            if drain_events(
                &mut modal,
                &mut view,
                &mut agg,
                &mut pipeline,
                &mut options,
                &mut force_redraw,
                &mut overlay_dismiss_redraw,
            )? {
                break 'live;
            }
            if maybe_redraw(
                force_redraw,
                overlay_dismiss_redraw,
                &mut term,
                &iface,
                capture_threads,
                fanout_group,
                &agg,
                &pipeline,
                &options,
                &hint_engine,
                &view,
                &modal,
                start,
                refresh,
                &mut frames_since_draw,
                &mut last_draw,
                &mut draw_cache,
            )? {
                force_redraw = false;
                overlay_dismiss_redraw = false;
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        agg.tick(now);
        pipeline.drain_flow_timeouts(&mut agg, now);

        if drain_events(
            &mut modal,
            &mut view,
            &mut agg,
            &mut pipeline,
            &mut options,
            &mut force_redraw,
            &mut overlay_dismiss_redraw,
        )? {
            break 'live;
        }
        if maybe_redraw(
            force_redraw,
            overlay_dismiss_redraw,
            &mut term,
            &iface,
            capture_threads,
            fanout_group,
            &agg,
            &pipeline,
            &options,
            &hint_engine,
            &view,
            &modal,
            start,
            refresh,
            &mut frames_since_draw,
            &mut last_draw,
            &mut draw_cache,
        )? {
            force_redraw = false;
            overlay_dismiss_redraw = false;
        }

        if last_draw.elapsed() >= refresh {
            draw_live_frame(
                &mut term,
                &iface,
                capture_threads,
                fanout_group,
                &agg,
                &pipeline,
                &options,
                &hint_engine,
                &view,
                &modal,
                start,
                refresh,
                &mut frames_since_draw,
                &mut draw_cache,
            )?;
            last_draw = Instant::now();
        }

        let wait_ms = if modal.is_open() || drained_this_turn == 0 {
            EVENT_WAIT_BUSY_MS
        } else {
            EVENT_WAIT_IDLE_MS
        };
        if wait_for_event(Duration::from_millis(wait_ms))?
            && drain_events(
                &mut modal,
                &mut view,
                &mut agg,
                &mut pipeline,
                &mut options,
                &mut force_redraw,
                &mut overlay_dismiss_redraw,
            )?
        {
            break 'live;
        }
        if maybe_redraw(
            force_redraw,
            overlay_dismiss_redraw,
            &mut term,
            &iface,
            capture_threads,
            fanout_group,
            &agg,
            &pipeline,
            &options,
            &hint_engine,
            &view,
            &modal,
            start,
            refresh,
            &mut frames_since_draw,
            &mut last_draw,
            &mut draw_cache,
        )? {
            force_redraw = false;
        }
    }
    disable_raw_mode()?;
    term.backend_mut().execute(LeaveAlternateScreen)?;
    Ok(())
}

fn wait_for_event(block: Duration) -> Result<bool, TuiError> {
    Ok(event::poll(block)?)
}

/// Non-blocking: drain every pending event from the terminal.
fn drain_events(
    modal: &mut Modal,
    view: &mut ViewId,
    agg: &mut Aggregator,
    pipeline: &mut LivePipeline,
    options: &mut FluxOptions,
    force_redraw: &mut bool,
    overlay_dismiss: &mut bool,
) -> Result<bool, TuiError> {
    while event::poll(Duration::ZERO)? {
        if handle_one_event(
            modal,
            view,
            agg,
            pipeline,
            options,
            force_redraw,
            overlay_dismiss,
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn handle_one_event(
    modal: &mut Modal,
    view: &mut ViewId,
    agg: &mut Aggregator,
    pipeline: &mut LivePipeline,
    options: &mut FluxOptions,
    force_redraw: &mut bool,
    overlay_dismiss: &mut bool,
) -> Result<bool, TuiError> {
    match event::read()? {
        Event::Resize(_, _) => {
            *force_redraw = true;
            Ok(false)
        }
        Event::Key(key) => {
            let had_overlay = modal.is_open();
            let outcome = handle_key(
                modal,
                view,
                agg,
                pipeline,
                options,
                key.code,
                key.modifiers,
            );
            if outcome.quit {
                return Ok(true);
            }
            if had_overlay && !modal.is_open() && outcome.force_redraw {
                *overlay_dismiss = true;
            }
            *force_redraw |= outcome.force_redraw;
            Ok(false)
        }
        _ => Ok(false),
    }
}

fn flush_frame(term: &mut Terminal<CrosstermBackend<std::io::Stdout>>) -> Result<(), TuiError> {
    Write::flush(term.backend_mut())?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn maybe_redraw(
    force_redraw: bool,
    overlay_dismiss: bool,
    term: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    iface: &str,
    capture_threads: u32,
    fanout_group: Option<u32>,
    agg: &Aggregator,
    pipeline: &LivePipeline,
    options: &FluxOptions,
    hint_engine: &HintEngine,
    view: &ViewId,
    modal: &Modal,
    start: Instant,
    refresh: Duration,
    frames_since_draw: &mut u64,
    last_draw: &mut Instant,
    cache: &mut DrawCache,
) -> Result<bool, TuiError> {
    if !force_redraw {
        return Ok(false);
    }
    if overlay_dismiss && !modal.is_open() && cache.is_valid() {
        draw_cached_main_frame(term, cache)?;
    } else {
        draw_live_frame(
            term,
            iface,
            capture_threads,
            fanout_group,
            agg,
            pipeline,
            options,
            hint_engine,
            view,
            modal,
            start,
            refresh,
            frames_since_draw,
            cache,
        )?;
    }
    *last_draw = Instant::now();
    Ok(true)
}

fn draw_cached_main_frame(
    term: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    cache: &DrawCache,
) -> Result<(), TuiError> {
    let main_text = cache.main_text.clone();
    let title = cache.title.clone();
    term.draw(|f| {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(4), Constraint::Length(1)])
            .split(f.area());
        f.render_widget(
            Paragraph::new(main_text).block(Block::default().title(title).borders(Borders::ALL)),
            chunks[0],
        );
        f.render_widget(
            Paragraph::new(TUI_FOOTER_HINTS).block(Block::default().borders(Borders::TOP)),
            chunks[1],
        );
    })?;
    flush_frame(term)
}

#[allow(clippy::too_many_arguments)]
fn draw_live_frame(
    term: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    iface: &str,
    capture_threads: u32,
    fanout_group: Option<u32>,
    agg: &Aggregator,
    pipeline: &LivePipeline,
    options: &FluxOptions,
    hint_engine: &HintEngine,
    view: &ViewId,
    modal: &Modal,
    start: Instant,
    refresh: Duration,
    frames_since_draw: &mut u64,
    cache: &mut DrawCache,
) -> Result<(), TuiError> {
    let snap = agg.snapshot();
    let recv_last = *frames_since_draw;
    *frames_since_draw = 0;
    let hints = hint_engine.evaluate(
        &[ListenerMeasurements {
            iface: iface.to_string(),
            rate_pps: recv_last as f64 / refresh.as_secs_f64().max(0.001),
            drops: agg.counters.capture_drops,
            capture_threads,
            capture_busy_pct: 0,
            capture_queue: 0,
        }],
        &pipeline.parse_measurements(),
        0,
        None,
    );
    let hint_lines = HintEngine::format_hints(&hints);

    let total = snap.total_messages;
    let smart = agg.smart_qname_labels;
    let smart_tag = if smart { " smart-qname" } else { "" };
    let title = format!("flux watch {iface}{smart_tag}");

    let status = StatusBar {
            input: WatchInput::Live {
                interfaces: vec![iface.to_string()],
            },
            window: options.window.clone(),
            effective_window_secs: snap.effective_window_secs,
            filter: agg.filter.header.clone(),
            match_stats: snap.match_stats,
            counted_in_window: snap.total_messages,
            counters: StatusLine {
                packets: agg.counters.packets,
                drops: agg.counters.capture_drops,
                parse_busy_pct: pipeline.parse_busy_percent(),
                queue_depth: pipeline.queue_depth(),
                listener_frames: agg.counters.listener_packets,
                recv_frames_last_tick: Some(recv_last),
            },
            flow: pipeline.flow_counters(),
            pairing_enabled: options.pairing,
            elapsed_secs: Some(start.elapsed().as_secs_f32()),
            overload: None,
            listener_stats: Vec::new(),
            hints: Vec::new(),
    };

    let table_width = term.size()?.width.saturating_sub(4).max(32);
    let main_text = format_batch_tables(
        &snap.counts,
        &[*view],
        options.batch_limit,
        total,
        options.key_cap,
        options.ede_show_no_ede,
        Some(table_width),
    );
    cache.title.clone_from(&title);
    cache.main_text.clone_from(&main_text);

    let main_text_draw = main_text.clone();
    let title_draw = title.clone();
    term.draw(|f| {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(4), Constraint::Length(1)])
            .split(f.area());

        f.render_widget(
            Paragraph::new(main_text_draw)
                .block(Block::default().title(title_draw).borders(Borders::ALL)),
            chunks[0],
        );
        f.render_widget(
            Paragraph::new(TUI_FOOTER_HINTS).block(Block::default().borders(Borders::TOP)),
            chunks[1],
        );

        render_modal(
            f,
            modal,
            iface,
            capture_threads,
            fanout_group,
            pipeline,
            &hint_lines,
            smart,
            &status,
        );
    })?;
    flush_frame(term)
}

fn drain_capture(
    cap: &LiveCapture,
    agg: &mut Aggregator,
    pipeline: &mut LivePipeline,
    options: &FluxOptions,
    max_packets: u64,
) -> u64 {
    let mut n = 0u64;
    while n < max_packets {
        match cap.try_recv_packet() {
            Ok(Some(pkt)) => {
                pipeline.process_packet(agg, &pkt, options);
                n += 1;
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    n
}