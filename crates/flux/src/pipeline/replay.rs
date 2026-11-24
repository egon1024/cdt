use crate::options::FluxOptions;

use super::PipelineError;
use super::scaled_replay::replay_file_scaled;
use super::stats::StatusBar;

pub struct ReplayOutcome {
    pub body: String,
    pub status: StatusBar,
}

pub fn replay_file(path: &str, options: &FluxOptions) -> Result<String, PipelineError> {
    let out = replay_file_scaled(path, options)?;
    Ok(format!("{}{}", out.body, out.status.format()))
}
