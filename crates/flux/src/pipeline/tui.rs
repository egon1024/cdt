#![cfg(all(target_os = "linux", feature = "tui"))]

use std::io;
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

    loop {
        frames_since_draw += drain_capture(&cap, &mut agg, &mut pipeline, &options);

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                let outcome = handle_key(
                    &mut modal,
                    &mut view,
                    &mut agg,
                    &mut pipeline,
                    &mut options,
                    key.code,
                    key.modifiers,
                );
                if outcome.quit {
                    break;
                }
                force_redraw |= outcome.force_redraw;
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        agg.tick(now);
        pipeline.drain_flow_timeouts(&mut agg, now);

        if force_redraw || last_draw.elapsed() >= refresh {
            let snap = agg.snapshot();
            let recv_last = frames_since_draw;
            frames_since_draw = 0;
            let hints = hint_engine.evaluate(
                &[ListenerMeasurements {
                    iface: iface.clone(),
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
            term.draw(|f| {
                let smart_tag = if smart { " smart-qname" } else { "" };
                let title = format!("flux watch {iface}{smart_tag}");

                let status = StatusBar {
                    input: WatchInput::Live {
                        interfaces: vec![iface.clone()],
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

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(4), Constraint::Length(1)])
                    .split(f.area());

                let table_width = chunks[0].width.saturating_sub(2).max(32);
                let main_text = format_batch_tables(
                    &snap.counts,
                    &[view],
                    options.batch_limit,
                    total,
                    options.key_cap,
                    options.ede_show_no_ede,
                    Some(table_width),
                );
                f.render_widget(
                    Paragraph::new(main_text).block(Block::default().title(title).borders(Borders::ALL)),
                    chunks[0],
                );
                f.render_widget(
                    Paragraph::new(TUI_FOOTER_HINTS).block(Block::default().borders(Borders::TOP)),
                    chunks[1],
                );

                render_modal(
                    f,
                    &modal,
                    &iface,
                    capture_threads,
                    fanout_group,
                    &pipeline,
                    &hint_lines,
                    smart,
                    &status,
                );
            })?;

            last_draw = Instant::now();
            force_redraw = false;
        }
    }
    disable_raw_mode()?;
    term.backend_mut().execute(LeaveAlternateScreen)?;
    Ok(())
}

fn drain_capture(
    cap: &LiveCapture,
    agg: &mut Aggregator,
    pipeline: &mut LivePipeline,
    options: &FluxOptions,
) -> u64 {
    let mut n = 0u64;
    loop {
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