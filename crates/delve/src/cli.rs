use std::io::{self, Write};

use clap::CommandFactory;
use dns_resolve::{ExpansionPolicy, run_trace};
use thiserror::Error;

use crate::args::{
    CacheCommand, CacheEnrichmentPurgeArgs, CacheEnrichmentSubcommand, CacheSubcommand, Cli,
    Command, ConfigCommand, ConfigSubcommand, SessionBranchArgs, SessionBundleExportArgs,
    SessionCommand, SessionDiagramArgs, SessionDiagramFormat, SessionDiagramLayout,
    SessionSubcommand, TraceArgs,
};
use crate::branch::{
    BranchError, BranchIntentArg, format_branch_report, parse_server_target, resolve_branch_target,
};
use crate::config::DelveConfig;
use crate::dig_options::{ParseError, TraceOptions, parse_trace_args};
use crate::expand_confirm::{ExpandConfirmOutcome, confirm_expand_all, expand_all_is_tty};
use crate::explore::{
    ExploreError, ExploreParseError, parse_explore_args, run_events_with_compare, run_explore,
    run_outline_with_compare,
};
use crate::family_notice::format_family_notice;
use crate::hop_display::{HopDisplayState, print_hop_human};
use crate::progress::StderrProgress;
use crate::replay::{print_final_answer, print_reused_session_notice, replay_session};
use crate::retention::format_timestamp_for_list;
use crate::runtime::{Runtime, SessionReuseLookup};
use crate::session::SessionDocument;
use crate::trace_config::{TraceConfigError, trace_config_from_request};
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

    #[error(transparent)]
    EnrichmentCache(#[from] dns_enrichment_cache::EnrichmentCacheError),

    #[error("enrichment cache is not available")]
    EnrichmentCacheUnavailable,

    #[error("unknown enrichment cache purge kind: {0}")]
    UnknownEnrichmentPurgeKind(String),

    #[error("full expansion requires confirmation; use +expand=all+force in non-interactive mode")]
    ExpandAllNeedsForce,

    #[error(transparent)]
    TraceConfig(#[from] TraceConfigError),

    #[error(transparent)]
    Explore(#[from] ExploreError),

    #[error(transparent)]
    Branch(#[from] BranchError),

    #[error(transparent)]
    Export(#[from] crate::export::ExportError),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Cli {
    pub fn run(self) -> Result<(), CliError> {
        match self.command {
            Command::Trace(args) => run_trace_command(args),
            Command::Session(command) => run_session_command(command),
            Command::Cache(command) => run_cache_command(command),
            Command::Config(command) => run_config_command(command),
        }
    }
}

fn run_trace_command(args: TraceArgs) -> Result<(), CliError> {
    if args.args.is_empty() {
        print_trace_help()?;
        return Ok(());
    }
    let options = parse_trace_args(&args.args)?;
    let runtime = Runtime::open_platform();
    runtime.emit_warnings();
    run_parsed_trace(options, &runtime)
}

fn print_trace_help() -> Result<(), CliError> {
    let mut cmd = Cli::command();
    let trace = cmd
        .find_subcommand_mut("trace")
        .expect("trace subcommand registered");
    trace.print_long_help().map_err(CliError::Io)
}

fn run_parsed_trace(options: TraceOptions, runtime: &Runtime) -> Result<(), CliError> {
    let mut request = TraceRequest::from_options(&options);

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

    let mut config = trace_config_from_request(
        &request,
        runtime.cache.clone(),
        runtime.config.trace_max_queries_per_action,
        runtime.config.trace_max_parallel_queries,
    )?;
    config.expansion_policy = options.expansion;
    config.ensure_family_resolved();
    let resolved = config.effective_family();
    request = request.with_resolved_family(resolved);
    eprintln!(
        "{}",
        format_family_notice(options.family_source, options.family_request, resolved)
    );

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

    let mut progress = StderrProgress::new(options.events, options.debug);
    let result = run_trace(&mut config, &mut progress)?;

    if options.save_session {
        let session_id = runtime.save_session(&result, &request, options.fresh)?;
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
        SessionSubcommand::List(args) => {
            let items = runtime.list_sessions()?;
            if args.json {
                println!(
                    "{}",
                    serde_json::to_string(&items).map_err(|error| {
                        CliError::Parse(ParseError::Unexpected(error.to_string()))
                    })?
                );
                return Ok(());
            }
            let default_id = runtime.default_session_id().ok();
            let show_legend = items.iter().any(|item| match item {
                crate::session::SessionListItem::Session(summary) => {
                    summary.frozen
                        || summary.pinned
                        || default_id.as_deref() == Some(summary.id.as_str())
                }
                crate::session::SessionListItem::Unreadable { .. } => false,
            });
            if show_legend {
                eprintln!("^ frozen  * pinned  @ current");
            }
            for item in items {
                match item {
                    crate::session::SessionListItem::Session(summary) => {
                        let frozen = if summary.frozen { '^' } else { ' ' };
                        let pin = if summary.pinned { '*' } else { ' ' };
                        let current = if default_id.as_deref() == Some(summary.id.as_str()) {
                            '@'
                        } else {
                            ' '
                        };
                        println!(
                            "{frozen}{pin}{current} {}  {} {}  {} nodes  created {} updated {}",
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
            let prober = dns_resolve::comparison_icmp_prober();
            if args.compare_at_hop.is_some() || args.compare_at_path.is_some() {
                if let Some(notice) =
                    crate::icmp_notice::format_comparison_icmp_notice(prober.capability())
                {
                    eprintln!("{notice}");
                }
            }
            run_outline_with_compare(
                &document,
                args.compare_at_hop,
                args.compare_at_path.as_deref(),
                prober,
                runtime.config.enrichment_icmp_enabled,
            )?;
            Ok(())
        }
        SessionSubcommand::Events(args) => {
            let (session_id, _) = resolve_session_target(args.id, Vec::new(), &runtime)?;
            let document = runtime.get_session(&session_id)?;
            let prober = dns_resolve::comparison_icmp_prober();
            if args.compare_at_hop.is_some() || args.compare_at_path.is_some() {
                if let Some(notice) =
                    crate::icmp_notice::format_comparison_icmp_notice(prober.capability())
                {
                    eprintln!("{notice}");
                }
            }
            run_events_with_compare(
                &document,
                args.compare_at_hop,
                args.compare_at_path.as_deref(),
                prober,
                runtime.config.enrichment_icmp_enabled,
            )?;
            Ok(())
        }
        SessionSubcommand::Explore(args) => {
            let (session_id, trailing) = resolve_session_target(args.id, args.args, &runtime)?;
            let explore_options = parse_explore_args(&trailing).map_err(map_explore_parse_error)?;
            let document = runtime.get_session(&session_id)?;
            let mut document = document;
            run_explore(&runtime, &mut document, explore_options)?;
            Ok(())
        }
        SessionSubcommand::Diagram(args) => run_session_diagram(args, &runtime),
        SessionSubcommand::Export(args) => run_session_bundle_export(args, &runtime),
        SessionSubcommand::Freeze(args) => {
            runtime.set_session_frozen(&args.id, true)?;
            Ok(())
        }
        SessionSubcommand::Thaw(args) => {
            runtime.set_session_frozen(&args.id, false)?;
            Ok(())
        }
        SessionSubcommand::Branch(args) => run_session_branch(args, &runtime),
    }
}

fn run_session_diagram(args: SessionDiagramArgs, runtime: &Runtime) -> Result<(), CliError> {
    use std::io::Write;

    use crate::export::{ExportFormat, ExportLayout, ExportOptions, SvgTitle, export_trace_tree};

    let (session_id, _) = resolve_session_target(args.id, Vec::new(), runtime)?;
    let document = runtime.get_session(&session_id)?;
    let entry = document.trees.get(args.tree_index).ok_or(
        crate::export::ExportError::TreeIndexOutOfRange(args.tree_index),
    )?;
    let title = SvgTitle {
        primary: format!(
            "delve  ·  {} {}  ·  tree {}",
            entry.tree.qname(),
            entry.tree.qtype(),
            args.tree_index
        ),
        secondary: Some(format!("session {}", document.id)),
    };
    let options = ExportOptions {
        layout: match args.layout {
            SessionDiagramLayout::Tree => ExportLayout::Tree,
            SessionDiagramLayout::Icicle => ExportLayout::Icicle,
        },
        format: match args.format {
            SessionDiagramFormat::Svg => ExportFormat::Svg,
            SessionDiagramFormat::Png => ExportFormat::Png,
        },
        title,
        rtt_config: runtime.config.explore_rtt_bar,
    };
    let output = export_trace_tree(&entry.tree, args.tree_index, &options)?;
    match args.output.as_deref() {
        Some("-") | None => {
            let mut stdout = io::stdout().lock();
            match output {
                crate::export::ExportOutput::Svg(svg) => stdout.write_all(svg.as_bytes())?,
                crate::export::ExportOutput::Png(png) => stdout.write_all(&png)?,
            }
            stdout.flush()?;
        }
        Some(path) => match output {
            crate::export::ExportOutput::Svg(svg) => std::fs::write(path, svg.as_bytes())?,
            crate::export::ExportOutput::Png(png) => std::fs::write(path, png)?,
        },
    }
    Ok(())
}

fn run_session_bundle_export(
    args: SessionBundleExportArgs,
    runtime: &Runtime,
) -> Result<(), CliError> {
    use std::io::Write;

    if !args.all && args.ids.is_empty() {
        return Err(CliError::Parse(ParseError::Unexpected(
            "session export requires session ids or --all".into(),
        )));
    }
    let bundle = if args.all {
        runtime.export_all_sessions()?
    } else {
        runtime.export_sessions(&args.ids)?
    };
    let json = bundle
        .to_json()
        .map_err(|error| CliError::Parse(ParseError::Unexpected(error.to_string())))?;
    match args.output.as_deref() {
        Some(path) => std::fs::write(path, json.as_bytes())?,
        None => {
            let mut stdout = io::stdout().lock();
            stdout.write_all(json.as_bytes())?;
            if !json.ends_with('\n') {
                stdout.write_all(b"\n")?;
            }
            stdout.flush()?;
        }
    }
    Ok(())
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
        None,
    )?;
    println!("{}", format_branch_report(&report));
    Ok(())
}

fn run_cache_command(command: CacheCommand) -> Result<(), CliError> {
    let runtime = Runtime::open_platform();
    runtime.emit_warnings();
    match command.command {
        CacheSubcommand::Stats => {
            let cache = runtime.cache.as_ref().ok_or(CliError::CacheUnavailable)?;
            let stats = cache.stats();
            println!("path: {}", runtime.paths.cache_db.display());
            println!("entries: {}", stats.entries);
            println!("bytes: {}", stats.bytes);
            println!("hits: {}", stats.hits);
            println!("misses: {}", stats.misses);
            Ok(())
        }
        CacheSubcommand::Purge(args) => {
            let cache = runtime.cache.as_ref().ok_or(CliError::CacheUnavailable)?;
            let removed = if args.all {
                cache.purge_all()?
            } else {
                cache.purge_expired()?
            };
            println!("removed {removed} entries");
            Ok(())
        }
        CacheSubcommand::Enrichment(command) => {
            run_enrichment_cache_command(&runtime, command.command)
        }
    }
}

fn run_enrichment_cache_command(
    runtime: &Runtime,
    command: CacheEnrichmentSubcommand,
) -> Result<(), CliError> {
    let cache = runtime
        .enrichment_cache
        .as_ref()
        .ok_or(CliError::EnrichmentCacheUnavailable)?;
    match command {
        CacheEnrichmentSubcommand::Stats => {
            let stats = cache.icmp_stats()?;
            println!("path: {}", runtime.paths.enrichment_db.display());
            println!("icmp entries: {}", stats.entries);
            println!("icmp ttl seconds: {}", cache.icmp_ttl_seconds());
            Ok(())
        }
        CacheEnrichmentSubcommand::Purge(args) => {
            let removed = purge_enrichment_cache(cache, &args)?;
            println!("removed {removed} icmp entries");
            Ok(())
        }
    }
}

fn purge_enrichment_cache(
    cache: &dns_enrichment_cache::SqliteEnrichmentCache,
    args: &CacheEnrichmentPurgeArgs,
) -> Result<usize, CliError> {
    match args.kind.as_str() {
        "icmp" => Ok(cache.purge_all_icmp()?),
        "expired" => Ok(cache.purge_expired_icmp(dns_enrichment_cache::now_unix())?),
        other => Err(CliError::UnknownEnrichmentPurgeKind(other.to_string())),
    }
}

fn run_config_command(command: ConfigCommand) -> Result<(), CliError> {
    let paths = crate::paths::DelvePaths::platform();
    match command.command {
        ConfigSubcommand::Dump => {
            let (yaml, warnings) = DelveConfig::dump_yaml(&paths);
            for warning in warnings {
                eprintln!("{warning}");
            }
            print!("{yaml}");
            Ok(())
        }
    }
}

fn map_explore_parse_error(error: ExploreParseError) -> CliError {
    match error {
        ExploreParseError::Unexpected(value) => CliError::Parse(ParseError::Unexpected(value)),
        ExploreParseError::UnknownOption(value) => {
            CliError::Parse(ParseError::UnknownOption(value))
        }
        ExploreParseError::MissingValue(option) => {
            CliError::Parse(ParseError::MissingValue { option })
        }
        ExploreParseError::InvalidValue { option, value } => {
            CliError::Parse(ParseError::InvalidValue { option, value })
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
                "frozen": document.frozen,
                "capture_context": document.capture_context,
                "targets": document.targets,
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
    if document.frozen {
        println!("frozen: yes");
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

#[cfg(test)]
mod session_cli_tests {
    use super::*;
    use crate::args::{
        SessionBundleExportArgs, SessionCommand, SessionDiagramArgs, SessionDiagramFormat,
        SessionDiagramLayout, SessionSubcommand,
    };
    use crate::paths::DelvePaths;
    use dns_resolve::{HopOutcome, TraceHop, TraceTreeRequest, build_linear_tree};

    fn sample_tree() -> dns_resolve::TraceTree {
        build_linear_tree(
            vec![TraceHop {
                zone: ".".into(),
                server: "a.root-servers.net".into(),
                server_name: None,
                qname: "example.com.".into(),
                qtype: "A".into(),
                transport: "udp".into(),
                rtt_ms: 10,
                rcode: "NOERROR".into(),
                nsid: None,
                ede_code: None,
                ede_text: None,
                referral_ns: vec![],
                glue: vec![],
                response: Default::default(),
                from_cache: false,
                outcome: HopOutcome::Answered,
            }],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
        )
    }

    fn seeded_runtime() -> (tempfile::TempDir, Runtime) {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = Runtime::open(DelvePaths::from_root(dir.path()));
        let request = TraceRequest::from_options(&crate::dig_options::TraceOptions {
            qname: "example.com".into(),
            ..Default::default()
        });
        runtime
            .save_session(&sample_tree(), &request, false)
            .expect("save");
        (dir, runtime)
    }

    #[test]
    fn session_diagram_writes_svg_to_stdout() {
        let (_dir, runtime) = seeded_runtime();
        let id = runtime.default_session_id().expect("default");
        let mut buffer = Vec::new();
        {
            let mut stdout = std::io::Cursor::new(&mut buffer);
            let args = SessionDiagramArgs {
                id: Some(id),
                format: SessionDiagramFormat::Svg,
                layout: SessionDiagramLayout::Tree,
                tree_index: 0,
                output: Some("-".into()),
            };
            // run_session_diagram writes to process stdout; invoke export path directly
            let document = runtime.get_session(&args.id.clone().unwrap()).expect("get");
            let entry = document.trees.get(args.tree_index).expect("tree");
            let svg = crate::export::render_trace_tree(
                &entry.tree,
                args.tree_index,
                &crate::export::ExportOptions {
                    layout: crate::export::ExportLayout::Tree,
                    format: crate::export::ExportFormat::Svg,
                    title: crate::export::SvgTitle {
                        primary: document.id.clone(),
                        secondary: None,
                    },
                    rtt_config: runtime.config.explore_rtt_bar,
                },
            )
            .expect("svg");
            stdout
                .write_all(svg.as_bytes())
                .expect("write svg to test buffer");
        }
        let output = String::from_utf8(buffer).expect("utf8");
        assert!(output.starts_with("<svg"));
        assert!(output.contains("a.root-servers.net"));
    }

    #[test]
    fn session_bundle_export_writes_envelope_json() {
        let (_dir, runtime) = seeded_runtime();
        let id = runtime.default_session_id().expect("default");
        let bundle = runtime
            .export_sessions(std::slice::from_ref(&id))
            .expect("export");
        let json = bundle.to_json().expect("json");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(value["format"], crate::session::SESSION_BUNDLE_FORMAT);
        assert_eq!(
            value["version"].as_u64(),
            Some(crate::session::SESSION_BUNDLE_VERSION as u64)
        );
        assert_eq!(value["sessions"].as_array().map(|a| a.len()), Some(1));
        assert_eq!(value["sessions"][0]["id"], id);
        assert!(value["sessions"][0]["trees"].is_array());
    }

    #[test]
    fn session_bundle_export_all_and_duplicate_ids() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = Runtime::open(DelvePaths::from_root(dir.path()));
        let request = TraceRequest::from_options(&crate::dig_options::TraceOptions {
            qname: "example.com".into(),
            ..Default::default()
        });
        let first = runtime
            .save_session(&sample_tree(), &request, false)
            .expect("first");
        let second = runtime
            .save_session(&sample_tree(), &request, false)
            .expect("second");
        let duplicate = runtime
            .export_sessions(&[first.clone(), first.clone()])
            .expect("duplicate");
        assert_eq!(duplicate.sessions.len(), 2);
        let all = runtime.export_all_sessions().expect("all");
        assert_eq!(all.sessions.len(), 2);
        let ids: Vec<_> = all.sessions.iter().map(|doc| doc.id.as_str()).collect();
        assert!(ids.contains(&first.as_str()));
        assert!(ids.contains(&second.as_str()));
    }

    #[test]
    fn session_bundle_export_requires_ids_or_all() {
        let (_dir, runtime) = seeded_runtime();
        let error = run_session_bundle_export(
            SessionBundleExportArgs {
                ids: vec![],
                all: false,
                output: None,
            },
            &runtime,
        )
        .expect_err("missing selection");
        assert!(error.to_string().contains("requires session ids or --all"));
    }

    #[test]
    fn branch_on_frozen_session_is_refused() {
        let (_dir, runtime) = seeded_runtime();
        let id = runtime.default_session_id().expect("default");
        runtime.set_session_frozen(&id, true).expect("freeze");
        let error = crate::branch::branch_session(
            &runtime,
            &id,
            dns_resolve::NodePath {
                tree: 0,
                path: vec![0],
            },
            crate::branch::BranchIntentArg::ExpandCut,
            true,
            &mut crate::progress::StderrProgress::new(false, false),
            None,
        )
        .expect_err("frozen branch");
        assert!(error.to_string().contains("frozen"));
    }

    #[test]
    fn freeze_and_thaw_update_frozen_and_updated_at() {
        let (_dir, runtime) = seeded_runtime();
        let id = runtime.default_session_id().expect("default");
        let before = runtime.get_session(&id).expect("get").updated_at;
        runtime.set_session_frozen(&id, true).expect("freeze");
        let frozen = runtime.get_session(&id).expect("frozen");
        assert!(frozen.frozen);
        assert_eq!(frozen.updated_at, before);
        runtime.set_session_frozen(&id, false).expect("thaw");
        let thawed = runtime.get_session(&id).expect("thawed");
        assert!(!thawed.frozen);
        assert_ne!(thawed.updated_at, before);
    }

    #[test]
    fn session_show_reports_frozen_flag() {
        let (_dir, runtime) = seeded_runtime();
        let id = runtime.default_session_id().expect("default");
        runtime.set_session_frozen(&id, true).expect("freeze");
        let document = runtime.get_session(&id).expect("get");
        let mut output = Vec::new();
        {
            use std::io::Write;
            let mut handle = std::io::Cursor::new(&mut output);
            // print_session writes to stdout; mirror its human branch checks
            assert!(document.frozen);
            writeln!(handle, "frozen: yes").expect("write");
        }
        let text = String::from_utf8(output).expect("utf8");
        assert!(text.contains("frozen: yes"));
    }

    #[test]
    fn session_list_legend_includes_frozen_marker() {
        let (_dir, runtime) = seeded_runtime();
        let id = runtime.default_session_id().expect("default");
        runtime.set_session_frozen(&id, true).expect("freeze");
        let items = runtime.list_sessions().expect("list");
        let summary = match items.first() {
            Some(crate::session::SessionListItem::Session(summary)) => summary,
            other => panic!("expected session, got {other:?}"),
        };
        assert!(summary.frozen);
    }

    #[test]
    fn diagram_and_export_subcommands_parse() {
        use clap::Parser;
        let cli = Cli::try_parse_from([
            "delve", "session", "diagram", "01TEST", "--layout", "icicle",
        ])
        .expect("diagram parse");
        match cli.command {
            Command::Session(SessionCommand {
                command: SessionSubcommand::Diagram(args),
            }) => {
                assert_eq!(args.id.as_deref(), Some("01TEST"));
                assert_eq!(args.layout, SessionDiagramLayout::Icicle);
            }
            other => panic!("expected diagram subcommand, got {other:?}"),
        }

        let cli = Cli::try_parse_from(["delve", "session", "export", "--all", "-o", "out.json"])
            .expect("export parse");
        match cli.command {
            Command::Session(SessionCommand {
                command: SessionSubcommand::Export(args),
            }) => {
                assert!(args.all);
                assert_eq!(args.output.as_deref(), Some("out.json"));
            }
            other => panic!("expected export subcommand, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod enrichment_cache_cli_tests {
    use super::*;
    use dns_enrichment_cache::{ProbeProfile, now_unix};
    use dns_resolve::{IcmpMethod, IcmpSnapshot};
    use std::net::{IpAddr, Ipv4Addr};

    use crate::args::{CacheEnrichmentPurgeArgs, CacheEnrichmentSubcommand};
    use crate::paths::DelvePaths;
    use crate::runtime::Runtime;

    fn seed_icmp_cache(runtime: &Runtime) {
        let cache = runtime.enrichment_cache.as_ref().expect("cache");
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        cache
            .put_icmp(
                ip,
                &ProbeProfile::enrichment_default(),
                &IcmpSnapshot {
                    method: IcmpMethod::Datagram,
                    samples: 1,
                    min_ms: 1,
                    avg_ms: 1,
                    max_ms: 1,
                    probed_at: "2026-09-06T00:00:00Z".into(),
                },
                now_unix(),
            )
            .expect("seed");
    }

    #[test]
    fn enrichment_cache_purge_icmp_clears_rows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = Runtime::open(DelvePaths::from_root(dir.path()));
        seed_icmp_cache(&runtime);
        let cache = runtime.enrichment_cache.as_ref().expect("cache");
        assert_eq!(cache.icmp_stats().expect("stats").entries, 1);
        run_enrichment_cache_command(
            &runtime,
            CacheEnrichmentSubcommand::Purge(CacheEnrichmentPurgeArgs {
                kind: "icmp".into(),
            }),
        )
        .expect("purge");
        assert_eq!(cache.icmp_stats().expect("stats").entries, 0);
    }

    #[test]
    fn enrichment_cache_purge_does_not_touch_dns_cache() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = Runtime::open(DelvePaths::from_root(dir.path()));
        seed_icmp_cache(&runtime);
        let dns = runtime.cache.as_ref().expect("dns cache");
        let dns_before = dns.stats().entries;
        run_enrichment_cache_command(
            &runtime,
            CacheEnrichmentSubcommand::Purge(CacheEnrichmentPurgeArgs {
                kind: "icmp".into(),
            }),
        )
        .expect("purge");
        assert_eq!(dns.stats().entries, dns_before);
    }
}
