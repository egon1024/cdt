mod ingest;
mod live_ingest;
mod notices;
mod replay;
mod scaled_replay;
mod stats;
#[cfg(feature = "tui")]
mod tui;
#[cfg(all(target_os = "linux", feature = "tui"))]
mod tui_modal;

pub use notices::SessionNotices;
pub use replay::replay_file;
pub use stats::{StatusBar, StatusLine, WatchInput};

use crate::options::{FluxOptions, WindowMode};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error(transparent)]
    Capture(#[from] crate::capture::CaptureError),

    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Live(#[from] crate::capture::LiveCaptureError),

    #[error("{0}")]
    Config(String),

    #[error(transparent)]
    Options(#[from] crate::options::OptionsError),
}

pub fn run_watch(
    interfaces: Vec<String>,
    read_file: Option<&str>,
    mut options: FluxOptions,
    use_tui: bool,
) -> Result<(), PipelineError> {
    if let Some(path) = read_file {
        if !options.options_overrode_window() {
            options.window = WindowMode::All;
        }
        let notice = options.effective_flow_buckets().1;
        if let Some(req) = notice {
            eprintln!(
                "flux: rounded +flow-buckets={req} to {}",
                options.effective_flow_buckets().0
            );
        }
        let out = replay_file(path, &options)?;
        // Pcap replay always prints batch tables; a TTY must not suppress output (G2 lab).
        let _ = use_tui;
        print!("{out}");
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let table = crate::capture::host_interface_table();
        let listeners =
            crate::capture::resolve_listeners(&interfaces, &options.exclude_iface, &table)
                .map_err(|e| PipelineError::Config(e.to_string()))?;
        if listeners.is_empty() {
            return Err(PipelineError::Config(
                "flux watch: no eligible capture interfaces".into(),
            ));
        }
        let session_notices = SessionNotices::for_live_listeners(&listeners);
        session_notices.emit_stderr();
        if listeners.iter().any(|s| s.capture_threads > 1) {
            if let Some(detail) = crate::capture::live::fanout_probe_error() {
                return Err(PipelineError::Config(format!(
                    "flux watch: per-interface capture threads > 1 require Linux PACKET_FANOUT \
                     ({detail}); try `-i <iface>:threads=1` and use `+flow-threads` / `+workers`"
                )));
            }
        }
        let iface = &listeners[0].iface;
        let cap_opts = crate::capture::live::LiveCaptureOpts {
            promisc: options.promisc,
            fanout_group: 1,
            fanout_slot: 0,
            fanout_threads: listeners[0].capture_threads,
        };
        if use_tui {
            let cap = crate::capture::live::LiveCapture::open_with(iface, cap_opts)
                .map_err(PipelineError::Live)?;
            return run_live_tui(cap, options, listeners[0].capture_threads, session_notices);
        }
        let _ = cap_opts;
        Err(PipelineError::Config(
            "live capture requires a TTY; use -r for batch replay".into(),
        ))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = interfaces;
        let _ = options;
        let _ = use_tui;
        Err(PipelineError::Config(
            "flux watch: live capture requires Linux (omit -i to list all up interfaces, \
             +exclude-iface, multi-listener capture); use -r for replay on this host"
                .into(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn run_live_tui(
    cap: crate::capture::LiveCapture,
    options: FluxOptions,
    capture_threads: u32,
    session_notices: SessionNotices,
) -> Result<(), PipelineError> {
    #[cfg(feature = "tui")]
    {
        tui::run_live(cap, options, capture_threads, session_notices).map_err(|e| match e {
            tui::TuiError::Live(l) => PipelineError::Live(l),
            tui::TuiError::Io(io) => PipelineError::Config(io.to_string()),
            tui::TuiError::Options(o) => PipelineError::Options(o),
        })
    }
    #[cfg(not(feature = "tui"))]
    {
        let _ = (cap, options);
        Err(PipelineError::Config("TUI disabled".into()))
    }
}
