use std::io::IsTerminal;

use thiserror::Error;

use crate::args::{Cli, Command, ValidateArgs, WatchArgs};
use crate::options::{FluxOptions, OptionsError};
use crate::pipeline::{PipelineError, run_watch};
use crate::validate;

#[derive(Debug, Error)]
pub enum CliError {
    #[error(transparent)]
    Options(#[from] OptionsError),

    #[error(transparent)]
    Pipeline(#[from] PipelineError),

    #[error(transparent)]
    Validate(#[from] validate::ValidateError),

    #[error("{0}")]
    Usage(String),
}

pub fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Watch(args) => run_watch_command(args),
        Command::Validate(args) => run_validate_command(args),
    }
}

fn run_watch_command(args: WatchArgs) -> Result<(), CliError> {
    if !args.interfaces.is_empty() && args.read_file.is_some() {
        return Err(CliError::Usage(
            "cannot use -i (live capture) and -r (file replay) together".into(),
        ));
    }
    let options = FluxOptions::parse(&args.options)?;
    let use_tui = std::io::stdout().is_terminal() && !options.events_to_stdout();
    run_watch(args.interfaces, args.read_file.as_deref(), options, use_tui)?;
    Ok(())
}

fn run_validate_command(args: ValidateArgs) -> Result<(), CliError> {
    if args.files.is_empty() {
        return Err(CliError::Usage(
            "flux validate requires at least one file".into(),
        ));
    }
    validate::validate_files(&args.files)?;
    Ok(())
}
