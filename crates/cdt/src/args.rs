use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "cdt",
    version,
    about = "Cole's DNS Tools bundle",
    after_long_help = "Full documentation: /usr/share/doc/cdt/docs/cdt.md (or docs/cdt.md in source tarballs)."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
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
