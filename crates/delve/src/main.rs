use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    match delve::args::Cli::parse().run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("delve: {error}");
            ExitCode::FAILURE
        }
    }
}
