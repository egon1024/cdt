use std::process::ExitCode;

use cdt::args::{Cli, Command};
use cdt::manifest::load_embedded;
use clap::Parser;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let manifest = load_embedded();

    match cli.command {
        None | Some(Command::Version { json: false }) => {
            println!("{} {}", manifest.bundle.name, manifest.bundle.version);
            for component in &manifest.components {
                println!(
                    "  {} {} — {}",
                    component.binary, component.version, component.description
                );
            }
        }
        Some(Command::Version { json: true }) => {
            println!("{}", serde_json::to_string_pretty(&manifest).expect("json"));
        }
        Some(Command::List { json: false }) => {
            for component in &manifest.components {
                println!(
                    "{} {} — {}",
                    component.binary, component.version, component.description
                );
            }
        }
        Some(Command::List { json: true }) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&manifest.components).expect("json")
            );
        }
    }

    ExitCode::SUCCESS
}
