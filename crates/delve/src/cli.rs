use std::net::IpAddr;

use clap::{Parser, Subcommand};
use dns_core::{DomainName, Transport, parse_record_type};
use dns_resolve::{TraceConfig, run_trace};
use thiserror::Error;

use crate::dig_options::{ParseError, TraceOptions, parse_trace_args};
use crate::progress::StderrProgress;

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

#[derive(Debug, Error)]
pub enum CliError {
    #[error(transparent)]
    Resolve(#[from] dns_resolve::ResolveError),

    #[error(transparent)]
    Core(#[from] dns_core::DnsCoreError),

    #[error(transparent)]
    Parse(#[from] ParseError),

    #[error("invalid query type: {0}")]
    QueryType(String),

    #[error("invalid server address: {0}")]
    Server(String),
}

impl Cli {
    pub fn run(self) -> Result<(), CliError> {
        match self.command {
            Command::Trace(args) => run_trace_command(args),
        }
    }
}

fn run_trace_command(args: TraceArgs) -> Result<(), CliError> {
    let options = parse_trace_args(&args.args)?;
    run_parsed_trace(options)
}

fn run_parsed_trace(options: TraceOptions) -> Result<(), CliError> {
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

    if let Some(server) = options.server.as_deref() {
        let addr: IpAddr = server
            .parse()
            .map_err(|error: std::net::AddrParseError| CliError::Server(error.to_string()))?;
        config.start_servers = Some(vec![addr]);
    }

    let mut progress = StderrProgress::new(options.events);
    let result = run_trace(&config, &mut progress)?;

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
