use clap::{Parser, Subcommand};

#[cfg(target_os = "linux")]
const FLUX_LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (cdt-flux-v1 phases 1–5; linux live capture)"
);

#[cfg(not(target_os = "linux"))]
const FLUX_LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (cdt-flux-v1 phases 1–5; replay-only on this OS)"
);

#[derive(Debug, Parser)]
#[command(
    name = "flux",
    version,
    long_version = FLUX_LONG_VERSION,
    about = "Live DNS traffic observer"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Observe live traffic or replay a capture file
    Watch(WatchArgs),
    /// Validate saved filter and data-source files
    Validate(ValidateArgs),
}

#[derive(Debug, Parser)]
pub struct WatchArgs {
    /// Network interface(s) for live capture (`eth0,lo`, or `eth0:threads=4`). Omit `-i` to
    /// capture every interface that is up (including loopback), minus any `+exclude-iface` match.
    #[arg(short = 'i')]
    pub interfaces: Vec<String>,

    /// Read packets from a pcap or pcapng file (`-` for stdin)
    #[arg(short = 'r')]
    pub read_file: Option<String>,

    /// Trailing dig-style options (`+window=30s`, `+views=src,qtype`, …)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub options: Vec<String>,
}

#[derive(Debug, Parser)]
pub struct ValidateArgs {
    /// Filter or data-source files to validate
    pub files: Vec<String>,
}

impl Cli {
    pub fn parse_and_run() -> Result<(), crate::cli::CliError> {
        Self::parse().run()
    }

    pub fn run(self) -> Result<(), crate::cli::CliError> {
        crate::cli::run(self)
    }
}
