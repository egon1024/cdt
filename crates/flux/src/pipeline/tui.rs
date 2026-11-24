#![cfg(all(target_os = "linux", feature = "tui"))]

use std::io;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use thiserror::Error;

use crate::capture::LiveCapture;
use crate::filter::NoopResolver;
use crate::options::{FluxOptions, ViewId};
use crate::parse::ParseWorker;
use crate::view::format_batch_tables;
use crate::window::Aggregator;

use super::ingest::{drain_flow_timeouts, ingest_packet, new_flow_stage, worker_busy_percent};
use super::stats::{StatusBar, StatusLine, WatchInput};
use crate::scale::hints::{HintEngine, ListenerMeasurements, ParseThreadMeasurements};
use crate::scale::priority::{ThreadRole, apply_thread_priority};

#[derive(Debug, Error)]
pub enum TuiError {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Live(#[from] crate::capture::LiveCaptureError),

    #[error(transparent)]
    Options(#[from] crate::options::OptionsError),
}

pub fn run_live(cap: LiveCapture, mut options: FluxOptions) -> Result<(), TuiError> {
    apply_thread_priority(ThreadRole::Tui);
    cap.set_nonblocking()?;
    let iface = cap.iface().to_string();
    let filter = options.compile_filter(&NoopResolver)?;
    let eval_ctx = options.build_eval_context(&NoopResolver);
    let mut agg = Aggregator::new(
        options.window.clone(),
        options.late_grace,
        options.late_policy,
        filter,
        eval_ctx,
    );
    let mut worker = ParseWorker::default();
    let mut flow = new_flow_stage(&options);

    let mut stdout = io::stdout();
    enable_raw_mode()?;
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;
    let mut view = ViewId::Sources;
    let mut show_help = false;
    let mut show_listeners = false;
    let mut worker_count = options.workers.max(1);
    let hint_engine = HintEngine::new();
    let start = Instant::now();

    loop {
        let drained = drain_capture(&cap, &mut agg, &mut worker, &mut flow, &options);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        agg.tick(now);
        drain_flow_timeouts(&mut agg, &mut worker, &mut flow, now);

        let snap = agg.snapshot();
        // Header and row shares use windowed, filter-matched totals — not lifetime packet count.
        let total = snap.total_messages;
        term.draw(|f| {
            let title = if drained > 0 {
                format!("flux watch {iface} (+{drained} pkts)")
            } else {
                format!("flux watch {iface}")
            };
            let hints = hint_engine.evaluate(
                &[ListenerMeasurements {
                    iface: iface.clone(),
                    rate_pps: drained as f64 / 0.08_f64.max(f32::EPSILON as f64),
                    drops: agg.counters.capture_drops,
                    capture_threads: cap.fanout_slot.map(|_| 2).unwrap_or(1),
                    capture_busy_pct: 0,
                    capture_queue: 0,
                }],
                &[ParseThreadMeasurements {
                    busy_pct: worker_busy_percent(&worker),
                    queue_depth: worker.stats.queue_depth,
                }],
                0,
                None,
            );
            let listener_lines: Vec<String> = if show_listeners {
                vec![
                    format!(
                        "listener {iface}: threads={} fanout={:?} workers={worker_count}",
                        cap.fanout_slot.unwrap_or(0) + 1,
                        cap.fanout_group
                    ),
                    format!(
                        "parse worker busy={}% queue={}",
                        worker_busy_percent(&worker),
                        worker.stats.queue_depth
                    ),
                ]
            } else {
                Vec::new()
            };
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
                    parse_busy_pct: worker_busy_percent(&worker),
                    queue_depth: worker.stats.queue_depth,
                },
                flow: flow.counters,
                pairing_enabled: options.pairing,
                elapsed_secs: Some(start.elapsed().as_secs_f32()),
                overload: None,
                listener_stats: listener_lines,
                hints,
            };

            let footer_text = status.format().trim_end().to_string();
            // Pin status to the last rows; tables + hints stay in the main pane.
            let footer_lines: u16 = if footer_text.len() > 100 { 3 } else { 2 };
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(4), Constraint::Length(footer_lines)])
                .split(f.area());

            let main_block = Block::default().title(title).borders(Borders::ALL);
            let mut main_text = format_batch_tables(
                &snap.counts,
                &[view],
                options.batch_limit,
                total,
                options.key_cap,
                options.ede_show_no_ede,
            );
            if show_listeners {
                main_text.push_str("\n-- listeners panel --\n");
                for line in &status.listener_stats {
                    main_text.push_str(line);
                    main_text.push('\n');
                }
                for h in &status.hints {
                    main_text.push_str(&format!("{h:?}\n"));
                }
            }
            if show_help {
                main_text.push_str(
                    "\nkeys: s src d dst t qtype r rcode o opcode 1-3 qname l listeners + - workers ? help q quit\n",
                );
            } else {
                main_text.push_str("\n? for help, l listeners, q quit\n");
            }
            f.render_widget(Paragraph::new(main_text).block(main_block), chunks[0]);

            f.render_widget(
                Paragraph::new(footer_text)
                    .block(Block::default().borders(Borders::TOP))
                    .wrap(Wrap { trim: true }),
                chunks[1],
            );
        })?;

        if event::poll(Duration::from_millis(80))? {
            if let Event::Key(key) = event::read()? {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    break;
                }
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('s') => view = ViewId::Sources,
                    KeyCode::Char('d') => view = ViewId::Destinations,
                    KeyCode::Char('t') => view = ViewId::Qtype,
                    KeyCode::Char('r') => view = ViewId::Rcode,
                    KeyCode::Char('o') => view = ViewId::Opcode,
                    KeyCode::Char('1') => view = ViewId::QnameLevel(1),
                    KeyCode::Char('2') => view = ViewId::QnameLevel(2),
                    KeyCode::Char('3') => view = ViewId::QnameLevel(3),
                    KeyCode::Char('?') => show_help = !show_help,
                    KeyCode::Char('l') => show_listeners = !show_listeners,
                    KeyCode::Char('+') => {
                        worker_count = worker_count.saturating_add(1);
                        options.workers = worker_count;
                    }
                    KeyCode::Char('-') => {
                        worker_count = worker_count.saturating_sub(1).max(1);
                        options.workers = worker_count;
                    }
                    KeyCode::Char('f') => {
                        let mut picker = crate::filter::PickerState::Closed;
                        let _ = crate::filter::picker_key(&mut picker, 'f');
                    }
                    _ => {}
                }
            }
        }
    }
    disable_raw_mode()?;
    term.backend_mut().execute(LeaveAlternateScreen)?;
    Ok(())
}

fn drain_capture(
    cap: &LiveCapture,
    agg: &mut Aggregator,
    worker: &mut ParseWorker,
    flow: &mut crate::flow::FlowStage,
    options: &FluxOptions,
) -> u64 {
    let mut n = 0u64;
    loop {
        match cap.try_recv_packet() {
            Ok(Some(pkt)) => {
                ingest_packet(agg, worker, flow, &pkt, options);
                n += 1;
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    n
}
