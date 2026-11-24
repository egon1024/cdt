#![cfg(all(target_os = "linux", feature = "tui"))]

use std::io;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use thiserror::Error;

use crate::capture::LiveCapture;
use crate::filter::NoopResolver;
use crate::options::{FluxOptions, ViewId};
use crate::scale::hints::{HintEngine, ListenerMeasurements};
use crate::view::format_batch_tables;
use crate::window::Aggregator;

use super::live_ingest::LivePipeline;
use super::stats::{StatusBar, StatusLine, WatchInput};
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
    let mut show_help = false;
    let mut show_listeners = false;
    let start = Instant::now();
    let mut last_draw = Instant::now();
    let mut frames_since_draw: u64 = 0;
    let mut force_redraw = true;

    loop {
        frames_since_draw += drain_capture(&cap, &mut agg, &mut pipeline, &options);

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    break;
                }
                force_redraw = true;
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
                    _ => {}
                }
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
            let listener_panel = listener_panel_lines(
                &iface,
                capture_threads,
                fanout_group,
                pipeline.flow_threads(),
                pipeline.worker_count(),
                pipeline.parse_busy_percent(),
                pipeline.queue_depth(),
            );

            let total = snap.total_messages;
            term.draw(|f| {
                let title = format!("flux watch {iface}");

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

                let footer_text = status.format().trim_end().to_string();
                let footer_lines: u16 = if footer_text.len() > 100 { 3 } else { 2 };
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Min(4), Constraint::Length(footer_lines)])
                    .split(f.area());

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
                        "\nkeys: s src d dst t qtype r rcode o opcode 1-3 qname l listeners + - workers ? help q quit\n",
                    );
                } else {
                    main_text.push_str("\n? for help, l listeners, q quit\n");
                }
                f.render_widget(
                    Paragraph::new(main_text).block(Block::default().title(title).borders(Borders::ALL)),
                    chunks[0],
                );
                f.render_widget(
                    Paragraph::new(footer_text)
                        .block(Block::default().borders(Borders::TOP))
                        .wrap(Wrap { trim: true }),
                    chunks[1],
                );

                if show_listeners {
                    let popup = centered_rect(72, 48, f.area());
                    f.render_widget(Clear, popup);
                    let mut body = listener_panel.join("\n");
                    body.push_str("\n\n-- tuning hints --\n");
                    if hint_lines.is_empty() {
                        body.push_str("  (none)\n");
                    } else {
                        for h in &hint_lines {
                            body.push_str("  ");
                            body.push_str(h);
                            body.push('\n');
                        }
                    }
                    body.push_str("\n(press l to close)");
                    f.render_widget(
                        Paragraph::new(body)
                            .block(
                                Block::default()
                                    .title("Listeners & pipeline")
                                    .borders(Borders::ALL),
                            )
                            .alignment(Alignment::Left),
                        popup,
                    );
                }
            })?;

            last_draw = Instant::now();
            force_redraw = false;
        }
    }
    disable_raw_mode()?;
    term.backend_mut().execute(LeaveAlternateScreen)?;
    Ok(())
}

fn listener_panel_lines(
    iface: &str,
    capture_threads: u32,
    fanout_group: Option<u32>,
    flow_threads: u32,
    parse_workers: usize,
    parse_busy: u8,
    queue_depth: u64,
) -> Vec<String> {
    let fanout = fanout_group
        .map(|g| format!("kernel fanout group {g}"))
        .unwrap_or_else(|| "no fanout (1 capture thread)".into());
    vec![
        format!("capture {iface}: threads={capture_threads} ({fanout})"),
        format!("flow stage: {flow_threads} thread(s) over virtual buckets"),
        format!(
            "parse: {parse_workers} worker(s) busy={parse_busy}% queue={queue_depth}"
        ),
    ]
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