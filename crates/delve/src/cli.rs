use std::net::IpAddr;

use clap::{Parser, Subcommand};
use dns_core::{DomainName, Transport, parse_record_type};
use dns_resolve::{TraceConfig, run_trace};
use thiserror::Error;

use crate::dig_options::{ParseError, TraceOptions, parse_trace_args};
use crate::hop_display::print_hop_human;
use crate::progress::StderrProgress;
use crate::runtime::Runtime;
use crate::session::SessionDocument;

#[derive(Debug, Parser)]
#[command(name = "delve", version, about = "DNS delegation-path tracer")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Trace delegation path for a query name.
    Trace(TraceArgs),
    /// Inspect or manage stored trace sessions.
    Session(SessionCommand),
    /// Inspect or manage the response cache.
    Cache(CacheCommand),
}

#[derive(Debug, Parser)]
pub struct TraceArgs {
    /// Query name, optional @server, and dig-style query options (+tcp, +timeout=, -t TYPE, ...).
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        num_args = 0..,
        value_name = "ARG"
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
}

#[derive(Debug, Parser)]
pub struct SessionShowArgs {
    pub id: String,
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        num_args = 0..,
        value_name = "ARG"
    )]
    pub args: Vec<String>,
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

#[derive(Debug, Error)]
pub enum CliError {
    #[error(transparent)]
    Resolve(#[from] dns_resolve::ResolveError),

    #[error(transparent)]
    Core(#[from] dns_core::DnsCoreError),

    #[error(transparent)]
    Parse(#[from] ParseError),

    #[error(transparent)]
    Session(#[from] crate::session::SessionError),

    #[error("invalid query type: {0}")]
    QueryType(String),

    #[error("invalid server address: {0}")]
    Server(String),

    #[error(transparent)]
    Cache(#[from] dns_cache::CacheError),

    #[error("response cache is not available")]
    CacheUnavailable,
}

impl Cli {
    pub fn run(self) -> Result<(), CliError> {
        match self.command {
            Command::Trace(args) => run_trace_command(args),
            Command::Session(command) => run_session_command(command),
            Command::Cache(command) => run_cache_command(command),
        }
    }
}

fn run_trace_command(args: TraceArgs) -> Result<(), CliError> {
    let options = parse_trace_args(&args.args)?;
    let runtime = Runtime::open_platform();
    runtime.emit_warnings();
    run_parsed_trace(options, &runtime)
}

fn run_parsed_trace(options: TraceOptions, runtime: &Runtime) -> Result<(), CliError> {
    let qname = DomainName::parse(&options.qname)?;
    let qtype = parse_record_type(&options.qtype)
        .map_err(|_| CliError::QueryType(options.qtype.clone()))?;
    let mut config = TraceConfig::new(qname, qtype);
    config.transport = if options.use_tcp {
        Transport::Tcp
    } else {
        Transport::Udp
    };
    config.timeout = options.timeout;
    config.retries = options.retries;
    config.dnssec = options.dnssec;
    config.request_nsid = options.request_nsid;
    config.ipv4_only = options.ipv4_only;
    config.ipv6_only = options.ipv6_only;
    config.use_cache = options.use_cache;
    for raw in &options.cache_skip_qnames {
        config.cache_skip_qnames.insert(DomainName::parse(raw)?);
    }
    config.cache = runtime.cache.clone();

    if let Some(server) = options.server.as_deref() {
        let addr: IpAddr = server
            .parse()
            .map_err(|error: std::net::AddrParseError| CliError::Server(error.to_string()))?;
        config.start_servers = Some(vec![addr]);
    }

    let mut progress = StderrProgress::new(options.events);
    let result = run_trace(&config, &mut progress)?;

    if options.save_session {
        let session_id = runtime.save_session(&result)?;
        eprintln!("session: {session_id}");
    }

    if options.events {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "event": "complete",
                "result": result,
            }))
            .expect("json")
        );
    } else {
        eprintln!();
        if let Some(answer) = &result.final_response {
            eprintln!(
                "final answer from {} in {}ms ({})",
                answer.server, answer.rtt_ms, answer.rcode
            );
            for record in &answer.records {
                eprintln!("  {record}");
            }
            if let Some(nsid) = &answer.nsid {
                eprintln!("  NSID: {nsid}");
            }
        }
    }

    Ok(())
}

fn run_session_command(command: SessionCommand) -> Result<(), CliError> {
    let runtime = Runtime::open_platform();
    runtime.emit_warnings();
    match command.command {
        SessionSubcommand::List => {
            let summaries = runtime.list_sessions()?;
            for summary in summaries {
                let marker = if summary.pinned { "* " } else { "  " };
                println!(
                    "{marker}{}  {} {}  {} hops  {}",
                    summary.id, summary.qname, summary.qtype, summary.hop_count, summary.created_at
                );
            }
            Ok(())
        }
        SessionSubcommand::Show(args) => {
            let events = parse_events_only(&args.args)?;
            let document = runtime.get_session(&args.id)?;
            print_session(&document, events);
            Ok(())
        }
        SessionSubcommand::Rm(args) => {
            runtime.remove_session(&args.id)?;
            Ok(())
        }
        SessionSubcommand::Pin(args) => {
            runtime.pin_session(&args.id)?;
            Ok(())
        }
        SessionSubcommand::Unpin(args) => {
            runtime.unpin_session(&args.id)?;
            Ok(())
        }
        SessionSubcommand::Purge(args) => {
            let report = runtime.purge_sessions(args.dry_run)?;
            if args.dry_run {
                println!("would remove {} sessions", report.removed);
            } else {
                println!("removed {} sessions", report.removed);
            }
            Ok(())
        }
    }
}

fn run_cache_command(command: CacheCommand) -> Result<(), CliError> {
    let runtime = Runtime::open_platform();
    runtime.emit_warnings();
    let cache = runtime.cache.as_ref().ok_or(CliError::CacheUnavailable)?;
    match command.command {
        CacheSubcommand::Stats => {
            let stats = cache.stats();
            println!("path: {}", runtime.paths.cache_db.display());
            println!("entries: {}", stats.entries);
            println!("bytes: {}", stats.bytes);
            println!("hits: {}", stats.hits);
            println!("misses: {}", stats.misses);
            Ok(())
        }
        CacheSubcommand::Purge(args) => {
            let removed = if args.all {
                cache.purge_all()?
            } else {
                cache.purge_expired()?
            };
            println!("removed {removed} entries");
            Ok(())
        }
    }
}

fn parse_events_only(args: &[String]) -> Result<bool, ParseError> {
    let mut events = false;
    for arg in args {
        match arg.as_str() {
            "+events" => events = true,
            "+noevents" => events = false,
            other if other.starts_with('+') => {
                return Err(ParseError::UnknownOption(other.to_string()));
            }
            other => return Err(ParseError::Unexpected(other.to_string())),
        }
    }
    Ok(events)
}

fn print_session(document: &SessionDocument, events: bool) {
    if events {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "event": "complete",
                "session": document.id,
                "result": document.result,
            }))
            .expect("json")
        );
        return;
    }

    println!("session: {}", document.id);
    if document.pinned {
        println!("pinned: yes");
    }
    println!("started: {}", document.created_at);
    println!("query: {} {}", document.result.qname, document.result.qtype);
    for hop in &document.result.hops {
        print_hop_human(hop);
    }
    if let Some(answer) = &document.result.final_response {
        eprintln!(
            "final answer from {} in {}ms ({})",
            answer.server, answer.rtt_ms, answer.rcode
        );
        for record in &answer.records {
            eprintln!("  {record}");
        }
    }
}
