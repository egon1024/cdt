use clap::{Parser, Subcommand};

use crate::trace_options_help::TRACE_OPTIONS_HELP;

#[derive(Debug, Parser)]
#[command(
    name = "delve",
    version,
    about = "DNS delegation-path tracer",
    after_long_help = "Full guide: /usr/share/doc/cdt/docs/delve.md (or docs/delve.md in source tarballs).\n\
See also: cdt(1)."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Trace the DNS delegation path for a query name (dig-style options; see `delve trace --help`).
    Trace(TraceArgs),
    /// Inspect or manage stored trace sessions.
    Session(SessionCommand),
    /// Inspect or manage the response cache.
    Cache(CacheCommand),
}

#[derive(Debug, Parser)]
#[command(
    about = "Trace the DNS delegation path for a query name",
    long_about = "Trace the DNS delegation path for a query name.\n\
Options use dig-style +flags and -type shorthands, not GNU --long-options.",
    after_long_help = TRACE_OPTIONS_HELP
)]
pub struct TraceArgs {
    /// Query name, optional @server, and dig-style options (see below).
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        num_args = 0..,
        value_name = "QNAME [@SERVER] [OPTIONS...]"
    )]
    pub args: Vec<String>,
}

#[derive(Debug, Parser)]
pub struct SessionCommand {
    #[command(subcommand)]
    pub command: SessionSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum SessionSubcommand {
    /// List stored sessions.
    List,
    /// Print the current default session id.
    Current,
    /// Show a stored session by id or prefix.
    Show(SessionShowArgs),
    /// Remove a stored session.
    Rm(SessionRmArgs),
    /// Pin a session so retention purge skips it.
    Pin(SessionIdArgs),
    /// Unpin a session so retention purge may remove it.
    Unpin(SessionIdArgs),
    /// Purge sessions older than configured retention.
    Purge(SessionPurgeArgs),
    /// Print a stored session as an indented tree on stdout.
    Outline(SessionOutlineArgs),
    /// Print a stored session as structured JSON (explore tree) on stdout.
    Events(SessionEventsArgs),
    /// Explore a stored session in the interactive tree TUI.
    Explore(SessionExploreArgs),
    /// Branch a stored trace at a node.
    Branch(SessionBranchArgs),
}

#[derive(Debug, Parser)]
pub struct SessionBranchArgs {
    /// Session id or prefix. When omitted, uses the default session.
    pub id: Option<String>,
    /// Node display index from `session outline`.
    #[arg(long, conflicts_with = "at_path")]
    pub at_hop: Option<usize>,
    /// Stable node path (for example `0.1.2`).
    #[arg(long, conflicts_with = "at_hop")]
    pub at_path: Option<String>,
    /// Query a named nameserver or `@address` at the zone cut.
    #[arg(long)]
    pub server: Option<String>,
    /// Query every unqueried nameserver at the zone cut.
    #[arg(long)]
    pub expand: bool,
    /// Describe the branch plan without issuing queries.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Parser)]
pub struct SessionOutlineArgs {
    /// Session id or prefix. When omitted, uses the default session.
    pub id: Option<String>,
}

#[derive(Debug, Parser)]
pub struct SessionEventsArgs {
    /// Session id or prefix. When omitted, uses the default session.
    pub id: Option<String>,
}

#[derive(Debug, Parser)]
pub struct SessionExploreArgs {
    /// Session id or prefix. When omitted, uses the default session.
    pub id: Option<String>,
}

#[derive(Debug, Parser)]
pub struct SessionShowArgs {
    /// Session id or prefix. When omitted, uses the default session.
    pub id: Option<String>,
    /// Emit the stored trace as JSON (`event: complete`).
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct SessionRmArgs {
    pub id: String,
}

#[derive(Debug, Parser)]
pub struct SessionIdArgs {
    pub id: String,
}

#[derive(Debug, Parser)]
pub struct SessionPurgeArgs {
    /// Session id or prefix. Removes that unpinned session regardless of retention age.
    pub id: Option<String>,
    /// Remove all unpinned sessions regardless of retention age.
    #[arg(long, conflicts_with = "id")]
    pub all: bool,
    /// Report what would be removed without deleting.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Parser)]
pub struct CacheCommand {
    #[command(subcommand)]
    pub command: CacheSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum CacheSubcommand {
    /// Show cache statistics.
    Stats,
    /// Purge cache entries.
    Purge(CachePurgeArgs),
}

#[derive(Debug, Parser)]
pub struct CachePurgeArgs {
    /// Remove only expired entries (default when neither flag is set).
    #[arg(long)]
    pub expired: bool,
    /// Remove all entries.
    #[arg(long)]
    pub all: bool,
}
