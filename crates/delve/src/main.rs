mod cli;
mod config;
mod dig_options;
mod explore;
mod hop_display;
mod last_session;
mod paths;
mod progress;
mod replay;
mod retention;
mod runtime;
mod session;
mod trace_request;

use std::process::ExitCode;

use clap::Parser;
use cli::Cli;

fn main() -> ExitCode {
    match Cli::parse().run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("delve: {error}");
            ExitCode::FAILURE
        }
    }
}
