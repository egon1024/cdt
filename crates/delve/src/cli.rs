use std::net::IpAddr;
use std::time::Duration;

use clap::{Parser, Subcommand};
use dns_core::{DomainName, Transport, parse_record_type};
use dns_resolve::{TraceConfig, run_trace};
use thiserror::Error;

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
    /// Query name to trace.
    pub qname: String,

    /// Nameserver to query instead of starting from root hints.
    #[arg(value_name = "@server")]
    pub server: Option<String>,

    /// Query type (default: A).
    #[arg(long, default_value = "A")]
    pub qtype: String,

    /// Use IPv4 only.
    #[arg(short = '4', long = "ipv4")]
    pub ipv4_only: bool,

    /// Use IPv6 only.
    #[arg(short = '6', long = "ipv6")]
    pub ipv6_only: bool,

    /// Use TCP transport.
    #[arg(long = "tcp")]
    pub use_tcp: bool,

    /// Per-query timeout in seconds (dig +time=).
    #[arg(long = "time", default_value_t = 5)]
    pub timeout_secs: u64,

    /// Retry count (dig +tries=).
    #[arg(long = "tries", default_value_t = 2)]
    pub retries: u8,

    /// Set DO bit and collect DNSSEC records.
    #[arg(long = "dnssec")]
    pub dnssec: bool,

    /// Disable NSID requests (enabled by default).
    #[arg(long = "nonsid")]
    pub no_nsid: bool,

    /// Emit NDJSON events on stdout.
    #[arg(long = "events")]
    pub events: bool,
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error(transparent)]
    Resolve(#[from] dns_resolve::ResolveError),

    #[error(transparent)]
    Core(#[from] dns_core::DnsCoreError),

    #[error("invalid query type: {0}")]
    QueryType(String),

    #[error("invalid server address: {0}")]
    Server(String),

    #[error("cannot use -4 and -6 together")]
    AddressFamily,
}

impl Cli {
    pub fn run(self) -> Result<(), CliError> {
        match self.command {
            Command::Trace(args) => run_trace_command(args),
        }
    }
}

fn run_trace_command(args: TraceArgs) -> Result<(), CliError> {
    if args.ipv4_only && args.ipv6_only {
        return Err(CliError::AddressFamily);
    }

    let qname = DomainName::parse(&args.qname)?;
    let qtype =
        parse_record_type(&args.qtype).map_err(|_| CliError::QueryType(args.qtype.clone()))?;
    let mut config = TraceConfig::new(qname, qtype);
    config.transport = if args.use_tcp {
        Transport::Tcp
    } else {
        Transport::Udp
    };
    config.timeout = Duration::from_secs(args.timeout_secs);
    config.retries = args.retries;
    config.dnssec = args.dnssec;
    config.request_nsid = !args.no_nsid;
    config.ipv4_only = args.ipv4_only;
    config.ipv6_only = args.ipv6_only;

    if let Some(server) = args.server.as_deref() {
        let addr: IpAddr = server
            .parse()
            .map_err(|error: std::net::AddrParseError| CliError::Server(error.to_string()))?;
        config.start_servers = Some(vec![addr]);
    }

    let mut progress = StderrProgress::new(args.events);
    let result = run_trace(&config, &mut progress)?;

    if args.events {
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
