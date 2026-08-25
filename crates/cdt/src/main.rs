mod manifest;

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use manifest::load_embedded;

#[derive(Debug, Parser)]
#[command(name = "cdt", version, about = "Cole's DNS Tools bundle")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Show bundle and component versions.
    Version {
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// List bundled utilities.
    List {
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
}

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
