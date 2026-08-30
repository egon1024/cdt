use std::io::{self, Write};
use std::net::IpAddr;

use dns_core::{DomainName, Transport, ip_to_ptr_name, parse_record_type, parse_reverse_target};
use dns_resolve::{ExpansionPolicy, TraceConfig, run_trace};
use thiserror::Error;

use crate::args::{
    CacheCommand, CacheSubcommand, Cli, Command, SessionBranchArgs, SessionCommand,
    SessionSubcommand, TraceArgs,
};
use crate::branch::{
    BranchError, BranchIntentArg, format_branch_report, parse_server_target, resolve_branch_target,
};
use crate::dig_options::{ParseError, TraceOptions, parse_trace_args};
use crate::expand_confirm::{ExpandConfirmOutcome, confirm_expand_all, expand_all_is_tty};
use crate::explore::{ExploreError, run_events, run_explore, run_outline};
use crate::hop_display::{HopDisplayState, print_hop_human};
use crate::progress::StderrProgress;
use crate::replay::{print_final_answer, print_reused_session_notice, replay_session};
use crate::retention::format_timestamp_for_list;
use crate::runtime::{Runtime, SessionReuseLookup};
use crate::session::SessionDocument;
use crate::trace_request::TraceRequest;

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

    #[error("full expansion requires confirmation; use +expand=all+force in non-interactive mode")]
    ExpandAllNeedsForce,

    #[error(transparent)]
    Explore(#[from] ExploreError),

    #[error(transparent)]
    Branch(#[from] BranchError),
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
    let request = TraceRequest::from_options(&options);

    if options.expansion == ExpansionPolicy::All && !options.expand_all_force {
        let server_count = options.server.as_ref().map(|_| 1usize).unwrap_or(13);
        let budget = runtime.config.trace_max_queries_per_action;
        let mut read_tty = read_tty_line;
        match confirm_expand_all(server_count, budget, &mut read_tty, expand_all_is_tty()) {
            ExpandConfirmOutcome::Confirmed => {
                eprintln!("starting full expansion trace...");
                let _ = io::stderr().flush();
            }
            ExpandConfirmOutcome::Declined => return Ok(()),
            ExpandConfirmOutcome::NoTerminal => return Err(CliError::ExpandAllNeedsForce),
        }
    }

    if options.save_session && !options.fresh {
        match runtime.find_matching_session(&request)? {
            SessionReuseLookup::Reuse(document) => {
                replay_session(&document, options.events);
                print_reused_session_notice(&document);
                return Ok(());
            }
            SessionReuseLookup::ExtendedMatch { id } => {
                eprintln!("matching extended session {id} exists; running fresh trace");
            }
            SessionReuseLookup::NoMatch => {}
        }
    }

    let qname = if options.reverse_lookup {
        let ip = parse_reverse_target(&options.qname)?;
        ip_to_ptr_name(ip)?
    } else {
        DomainName::parse(&options.qname)?
    };
    let qtype = parse_record_type(&options.qtype)
        .map_err(|_| CliError::QueryType(options.qtype.clone()))?;
    let mut config = TraceConfig::new(qname, qtype);
    config.follow_aliases = options.follow_aliases;
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
    config.expansion_policy = options.expansion;
    config.max_queries_per_action = runtime.config.trace_max_queries_per_action;
    config.max_parallel_queries = runtime.config.trace_max_parallel_queries;
    config.set_debug(options.debug);
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

    let mut progress = StderrProgress::new(options.events, options.debug);
    let result = run_trace(&config, &mut progress)?;

    if options.save_session {
        let session_id = runtime.save_session(&result, &request)?;
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
        print_final_answer(&result);
    }

    Ok(())
}

fn read_tty_line(_prompt: &str) -> std::io::Result<String> {
    use std::fs::OpenOptions;
    use std::io::{BufRead, BufReader};

    let tty = OpenOptions::new().read(true).open("/dev/tty")?;
    let mut reader = BufReader::new(tty);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    Ok(line)
}

fn run_session_command(command: SessionCommand) -> Result<(), CliError> {
    let runtime = Runtime::open_platform();
    runtime.emit_warnings();
    match command.command {
        SessionSubcommand::List => {
            let default_id = runtime.default_session_id().ok();
            for item in runtime.list_sessions()? {
                match item {
                    crate::session::SessionListItem::Session(summary) => {
                        let pin = if summary.pinned { '*' } else { ' ' };
                        let current = if default_id.as_deref() == Some(summary.id.as_str()) {
                            '@'
                        } else {
                            ' '
                        };
                        println!(
                            "{pin}{current} {}  {} {}  {} nodes  created {} updated {}",
                            summary.id,
                            summary.qname,
                            summary.qtype,
                            summary.node_count,
                            format_timestamp_for_list(&summary.created_at),
                            format_timestamp_for_list(&summary.updated_at)
                        );
                    }
                    crate::session::SessionListItem::Unreadable { id, message } => {
                        println!("?  {id}  unreadable: {message}");
                    }
                }
            }
            Ok(())
        }
        SessionSubcommand::Current => {
            let id = runtime.default_session_id()?;
            println!("{id}");
            Ok(())
        }
        SessionSubcommand::Show(args) => {
            if let Some(id) = &args.id {
                if id.starts_with('+') {
                    return Err(CliError::Parse(ParseError::Unexpected(format!(
                        "{id} is not valid for session show; use --json for JSON output"
                    ))));
                }
            }
            let (session_id, _) = resolve_session_target(args.id, Vec::new(), &runtime)?;
            let document = runtime.get_session(&session_id)?;
            print_session(&document, args.json);
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
            let report = runtime.purge_sessions(args.id.as_deref(), args.all, args.dry_run)?;
            let noun = if args.id.is_some() {
                "session"
            } else if args.all {
                "unpinned sessions"
            } else {
                "sessions"
            };
            if args.dry_run {
                println!("would remove {} {}", report.removed, noun);
            } else {
                println!("removed {} {}", report.removed, noun);
            }
            Ok(())
        }
        SessionSubcommand::Outline(args) => {
            let (session_id, _) = resolve_session_target(args.id, Vec::new(), &runtime)?;
            let document = runtime.get_session(&session_id)?;
            run_outline(&document)?;
            Ok(())
        }
        SessionSubcommand::Events(args) => {
            let (session_id, _) = resolve_session_target(args.id, Vec::new(), &runtime)?;
            let document = runtime.get_session(&session_id)?;
            run_events(&document)?;
            Ok(())
        }
        SessionSubcommand::Explore(args) => {
            let (session_id, _) = resolve_session_target(args.id, Vec::new(), &runtime)?;
            let document = runtime.get_session(&session_id)?;
            let mut document = document;
            run_explore(&runtime, &mut document)?;
            Ok(())
        }
        SessionSubcommand::Branch(args) => run_session_branch(args, &runtime),
    }
}

fn run_session_branch(args: SessionBranchArgs, runtime: &Runtime) -> Result<(), CliError> {
    if args.at_hop.is_none() && args.at_path.is_none() {
        return Err(CliError::Branch(BranchError::UnresolvedPath {
            path: "missing --at-hop or --at-path".into(),
        }));
    }
    if !args.expand && args.server.is_none() && !args.dry_run {
        return Err(CliError::Branch(BranchError::MissingTarget));
    }
    let (session_id, _) = resolve_session_target(args.id, Vec::new(), runtime)?;
    let document = runtime.get_session(&session_id)?;
    let at = resolve_branch_target(&document, args.at_hop, args.at_path.as_deref())?;
    let intent = if args.expand || args.server.is_none() {
        BranchIntentArg::ExpandCut
    } else {
        BranchIntentArg::AlternateServer {
            target: parse_server_target(args.server.as_deref().expect("server checked"))?,
        }
    };
    let mut progress = crate::progress::StderrProgress::new(false, false);
    let report = crate::branch::branch_session(
        runtime,
        &session_id,
        at,
        intent,
        args.dry_run,
        &mut progress,
    )?;
    println!("{}", format_branch_report(&report));
    Ok(())
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

fn resolve_session_target(
    id: Option<String>,
    mut args: Vec<String>,
    runtime: &Runtime,
) -> Result<(String, Vec<String>), CliError> {
    if let Some(id) = id {
        if id.starts_with('+') {
            args.insert(0, id);
        } else {
            return Ok((id, args));
        }
    }
    let default = runtime.default_session_id()?;
    Ok((default, args))
}

fn print_session(document: &SessionDocument, json: bool) {
    let tree = document
        .primary_tree()
        .expect("v2 session must contain a trace tree");
    if json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "event": "complete",
                "session": document.id,
                "version": document.version,
                "created_at": document.created_at,
                "updated_at": document.updated_at,
                "pinned": document.pinned,
                "trees": document.trees,
                "view_state": document.view_state,
            }))
            .expect("json")
        );
        return;
    }

    println!("session: {}", document.id);
    if document.pinned {
        println!("pinned: yes");
    }
    println!("created: {}", document.created_at);
    println!("updated: {}", document.updated_at);
    println!("query: {} {}", tree.qname(), tree.qtype());
    let mut hop_display = HopDisplayState::new();
    for path in tree.display_order() {
        if let Some(node) = tree.resolve(&path) {
            print_hop_human(&mut hop_display, &node.hop, &path);
        }
    }
    if let Some(hop) = tree.answering_hop() {
        eprintln!(
            "final answer from {} in {}ms ({})",
            hop.server, hop.rtt_ms, hop.rcode
        );
        for record in &hop.response.answers {
            eprintln!("  {} {} {}", record.name, record.ttl, record.rdata);
        }
    }
}
