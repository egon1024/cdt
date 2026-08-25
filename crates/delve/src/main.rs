mod cli;
mod config;
mod dig_options;
mod hop_display;
mod paths;
mod progress;
mod retention;
mod runtime;
mod session;

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
