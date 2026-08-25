use dns_core::name::DomainName;
use dns_core::query::QueryOptions;
use dns_core::response::{DnsResponse, QueryResult, Transport};
use dns_core::transport::exchange;
use hickory_proto::rr::RecordType;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

pub mod root_hints;
pub mod trace;

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error(transparent)]
    Core(#[from] dns_core::DnsCoreError),

    #[error("no reachable nameserver for zone {zone}")]
    NoReachableNameserver { zone: String },

    #[error("could not resolve nameserver {name}: {reason}")]
    NameserverResolution { name: String, reason: String },

    #[error("delegation loop detected at zone {zone}")]
    DelegationLoop { zone: String },

    #[error("trace exceeded maximum delegation depth ({max})")]
    MaxDepth { max: usize },
}

pub type Result<T> = std::result::Result<T, ResolveError>;

#[derive(Debug, Clone)]
pub struct TraceConfig {
    pub qname: DomainName,
    pub qtype: RecordType,
    pub port: u16,
    pub transport: Transport,
    pub timeout: std::time::Duration,
    pub retries: u8,
    pub dnssec: bool,
    pub request_nsid: bool,
    pub ipv4_only: bool,
    pub ipv6_only: bool,
    pub max_depth: usize,
    pub start_servers: Option<Vec<std::net::IpAddr>>,
}

impl TraceConfig {
    pub fn new(qname: DomainName, qtype: RecordType) -> Self {
        Self {
            qname,
            qtype,
            port: 53,
            transport: Transport::Udp,
            timeout: std::time::Duration::from_secs(5),
            retries: 2,
            dnssec: false,
            request_nsid: true,
            ipv4_only: false,
            ipv6_only: false,
            max_depth: 32,
            start_servers: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceHop {
    pub zone: String,
    pub server: String,
    pub qname: String,
    pub qtype: String,
    pub transport: String,
    pub rtt_ms: u64,
    pub rcode: String,
    pub nsid: Option<String>,
    pub ede_code: Option<u16>,
    pub ede_text: Option<String>,
    pub referral_ns: Vec<String>,
    pub glue: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceResult {
    pub qname: String,
    pub qtype: String,
    pub started_at: String,
    pub hops: Vec<TraceHop>,
    pub final_response: Option<FinalAnswer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalAnswer {
    pub server: String,
    pub rtt_ms: u64,
    pub rcode: String,
    pub records: Vec<String>,
    pub nsid: Option<String>,
}

pub trait TraceProgress: Send {
    fn hop(&mut self, hop: &TraceHop);
    fn message(&mut self, message: &str);
}

pub fn run_trace(config: &TraceConfig, progress: &mut dyn TraceProgress) -> Result<TraceResult> {
    trace::run(config, progress)
}

pub(crate) fn query_server(
    server: std::net::IpAddr,
    config: &TraceConfig,
    qname: &DomainName,
    qtype: RecordType,
) -> Result<QueryResult> {
    let mut options = QueryOptions::new(qname.clone(), qtype);
    options.transport = config.transport;
    options.timeout = config.timeout;
    options.retries = config.retries;
    options.dnssec = config.dnssec;
    options.request_nsid = config.request_nsid;
    exchange(server, config.port, &options).map_err(ResolveError::from)
}

pub(crate) fn hop_from_query(
    zone: &DomainName,
    query: &QueryResult,
    referral_ns: Vec<String>,
    glue: Vec<String>,
) -> TraceHop {
    TraceHop {
        zone: zone.to_string(),
        server: query.server.to_string(),
        qname: query.qname.to_string(),
        qtype: query.qtype.clone(),
        transport: query.transport.to_string(),
        rtt_ms: query.rtt.as_millis() as u64,
        rcode: query.response.rcode_text.clone(),
        nsid: query.response.edns.nsid().map(str::to_owned),
        ede_code: query.response.edns.ede().map(|ede| ede.code),
        ede_text: query
            .response
            .edns
            .ede()
            .and_then(|ede| ede.extra_text.clone()),
        referral_ns,
        glue,
    }
}

pub(crate) fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}

pub(crate) fn filter_addresses(
    addresses: &[std::net::IpAddr],
    ipv4_only: bool,
    ipv6_only: bool,
) -> Vec<std::net::IpAddr> {
    addresses
        .iter()
        .copied()
        .filter(|addr| match addr {
            std::net::IpAddr::V4(_) => !ipv6_only,
            std::net::IpAddr::V6(_) => !ipv4_only,
        })
        .collect()
}

pub(crate) fn first_referral_ns(response: &DnsResponse) -> Option<DomainName> {
    response.ns_names().into_iter().next()
}
