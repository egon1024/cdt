mod ingest;
mod replay;
mod stats;
#[cfg(feature = "tui")]
mod tui;

pub use replay::replay_file;
pub use stats::StatusLine;

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
        if !use_tui || options.events_to_stdout() {
            print!("{out}");
        }
        return Ok(());
    }

    if interfaces.is_empty() {
        return Err(PipelineError::Config(
            "flux watch: specify -i <iface> for live capture or -r <file> for replay".into(),
        ));
    }

    #[cfg(target_os = "linux")]
    {
        let iface = &interfaces[0];
        if use_tui {
            let cap = crate::capture::open_live(iface)?;
            return run_live_tui(cap, options);
        }
        Err(PipelineError::Config(
            "live capture requires a TTY; use -r for batch replay".into(),
        ))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (interfaces, options, use_tui);
        Err(PipelineError::Config(
            "live capture is only supported on Linux".into(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn run_live_tui(
    cap: crate::capture::LiveCapture,
    options: FluxOptions,
) -> Result<(), PipelineError> {
    #[cfg(feature = "tui")]
    {
        tui::run_live(cap, options).map_err(|e| match e {
            tui::TuiError::Live(l) => PipelineError::Live(l),
            tui::TuiError::Io(io) => PipelineError::Config(io.to_string()),
        })
    }
    #[cfg(not(feature = "tui"))]
    {
        let _ = (cap, options);
        Err(PipelineError::Config("TUI disabled".into()))
    }
}
