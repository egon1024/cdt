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

use super::ingest::{ingest_packet, worker_busy_percent};
use super::stats::{StatusBar, StatusLine, WatchInput};

#[derive(Debug, Error)]
pub enum TuiError {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Live(#[from] crate::capture::LiveCaptureError),

    #[error(transparent)]
    Options(#[from] crate::options::OptionsError),
}

pub fn run_live(cap: LiveCapture, options: FluxOptions) -> Result<(), TuiError> {
    cap.set_nonblocking()?;
    let iface = cap.iface().to_string();
    let (buckets, _) = options.effective_flow_buckets();
    let seed: u64 = 0;

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

    let mut stdout = io::stdout();
    enable_raw_mode()?;
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;
    let mut view = ViewId::Sources;
    let mut show_help = false;
    let start = Instant::now();

    loop {
        let drained = drain_capture(&cap, &mut agg, &mut worker, &options, buckets, seed);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        agg.tick(now);

        let snap = agg.snapshot();
        // Header and row shares use windowed, filter-matched totals — not lifetime packet count.
        let total = snap.total_messages;
        term.draw(|f| {
            let title = if drained > 0 {
                format!("flux watch {iface} (+{drained} pkts)")
            } else {
                format!("flux watch {iface}")
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
                elapsed_secs: Some(start.elapsed().as_secs_f32()),
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
            if show_help {
                main_text.push_str(
                    "\nkeys: s src d dst t qtype r rcode o opcode 1-3 qname ? help q quit\n",
                );
            } else {
                main_text.push_str("\n? for help, q to quit\n");
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
    options: &FluxOptions,
    buckets: u32,
    seed: u64,
) -> u64 {
    let mut n = 0u64;
    loop {
        match cap.try_recv_packet() {
            Ok(Some(pkt)) => {
                ingest_packet(agg, worker, &pkt, options, buckets, seed);
                n += 1;
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    n
}
