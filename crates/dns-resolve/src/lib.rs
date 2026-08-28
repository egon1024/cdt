use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use dns_cache::{CacheKey, CachedEntry, ResponseCache, now_unix, shared_cache, ttl_from_result};
use dns_core::name::DomainName;
use dns_core::query::QueryOptions;
use dns_core::response::{DnsRecord, DnsResponse, QueryResult, Transport};
use dns_core::transport::exchange;
use hickory_proto::rr::RecordType;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

pub mod budget;
pub mod root_hints;
pub mod trace;
pub mod tree;

pub use budget::QueryBudget;

pub use tree::{
    BranchIntent, HopOutcome, NodeOrigin, NodePath, TraceNode, TraceTree, TraceTreeRequest,
    build_linear_tree,
};

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

    #[error("alias loop detected at name {name}")]
    AliasLoop { name: String },

    #[error("trace exceeded maximum alias depth ({max})")]
    MaxAliasDepth { max: usize },
}

pub type Result<T> = std::result::Result<T, ResolveError>;

/// Controls how many nameservers are queried at each zone cut during a trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpansionPolicy {
    /// Single-path: one server per cut (`+expand=none`).
    None,
    /// Expand only the terminal answer cut (`+expand=last`, default).
    #[default]
    Last,
    /// Query every nameserver at every cut (`+expand=all`).
    All,
}

/// Exchange hook for tests and cache integration.
pub trait DnsExchange: Send + Sync {
    fn exchange(
        &self,
        server: IpAddr,
        port: u16,
        options: &QueryOptions,
    ) -> dns_core::Result<QueryResult>;
}

#[derive(Debug)]
struct DefaultExchange;

impl DnsExchange for DefaultExchange {
    fn exchange(
        &self,
        server: IpAddr,
        port: u16,
        options: &QueryOptions,
    ) -> dns_core::Result<QueryResult> {
        exchange(server, port, options)
    }
}

#[derive(Clone)]
pub struct TraceConfig {
    pub qname: DomainName,
    pub qtype: RecordType,
    pub port: u16,
    pub transport: Transport,
    pub timeout: Duration,
    pub retries: u8,
    pub dnssec: bool,
    pub request_nsid: bool,
    pub ipv4_only: bool,
    pub ipv6_only: bool,
    pub max_depth: usize,
    pub max_alias_depth: usize,
    pub follow_aliases: bool,
    pub start_servers: Option<Vec<IpAddr>>,
    pub use_cache: bool,
    pub cache_skip_qnames: HashSet<DomainName>,
    pub cache: Option<Arc<dyn ResponseCache>>,
    pub exchange: Arc<dyn DnsExchange>,
    pub exchange_counter: Arc<AtomicUsize>,
    /// Nameserver hostnames currently being resolved (detects cyclic NS lookups).
    pub ns_resolution_active: HashSet<String>,
    pub expansion_policy: ExpansionPolicy,
    pub max_queries_per_action: usize,
}

impl TraceConfig {
    pub fn new(qname: DomainName, qtype: RecordType) -> Self {
        Self {
            qname,
            qtype,
            port: 53,
            transport: Transport::Udp,
            timeout: Duration::from_secs(5),
            retries: 2,
            dnssec: false,
            request_nsid: true,
            ipv4_only: false,
            ipv6_only: false,
            max_depth: 32,
            max_alias_depth: 16,
            follow_aliases: false,
            start_servers: None,
            use_cache: true,
            cache_skip_qnames: HashSet::new(),
            cache: None,
            exchange: Arc::new(DefaultExchange),
            exchange_counter: Arc::new(AtomicUsize::new(0)),
            ns_resolution_active: HashSet::new(),
            expansion_policy: ExpansionPolicy::Last,
            max_queries_per_action: 64,
        }
    }

    pub fn with_memory_cache(&mut self) -> Arc<dyn ResponseCache> {
        let cache = shared_cache(dns_cache::MemoryCache::new());
        self.cache = Some(cache.clone());
        cache
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StoredDnsMessage {
    pub id: u16,
    pub authoritative: bool,
    pub truncated: bool,
    #[serde(default)]
    pub recursion_desired: bool,
    #[serde(default)]
    pub recursion_available: bool,
    #[serde(default)]
    pub authentic_data: bool,
    #[serde(default)]
    pub checking_disabled: bool,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

impl StoredDnsMessage {
    pub fn from_response(response: &DnsResponse) -> Self {
        Self {
            id: response.id,
            authoritative: response.authoritative,
            truncated: response.truncated,
            recursion_desired: response.recursion_desired,
            recursion_available: response.recursion_available,
            authentic_data: response.authentic_data,
            checking_disabled: response.checking_disabled,
            answers: response.answers.clone(),
            authorities: response.authorities.clone(),
            additionals: response.additionals.clone(),
        }
    }

    pub fn is_stored(&self) -> bool {
        self.id != 0
            || self.authoritative
            || self.truncated
            || self.recursion_desired
            || self.recursion_available
            || self.authentic_data
            || self.checking_disabled
            || !self.answers.is_empty()
            || !self.authorities.is_empty()
            || !self.additionals.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServerTarget {
    pub address: IpAddr,
    pub name: Option<String>,
}

impl ServerTarget {
    pub fn from_address(address: IpAddr) -> Self {
        Self {
            address,
            name: None,
        }
    }

    pub fn with_name(address: IpAddr, name: impl Into<String>) -> Self {
        Self {
            address,
            name: Some(name.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceHop {
    pub zone: String,
    pub server: String,
    #[serde(default)]
    pub server_name: Option<String>,
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
    #[serde(default)]
    pub response: StoredDnsMessage,
    /// True when this hop was served from the response cache.
    #[serde(default)]
    pub from_cache: bool,
    #[serde(default)]
    pub outcome: HopOutcome,
}

pub trait TraceProgress: Send {
    fn hop(&mut self, hop: &TraceHop, path: &NodePath);
    fn message(&mut self, message: &str);
    fn budget_truncated(&mut self, _cap: usize) {}
}

pub fn run_trace(config: &TraceConfig, progress: &mut dyn TraceProgress) -> Result<TraceTree> {
    trace::run(config, progress)
}

pub(crate) fn query_server(
    server: IpAddr,
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

    let key = CacheKey {
        server,
        port: config.port,
        qname: qname.to_string(),
        qtype: qtype.to_string(),
        transport: config.transport,
        dnssec: config.dnssec,
        request_nsid: config.request_nsid,
    };

    if cache_enabled_for(config, qname) {
        if let Some(cache) = &config.cache {
            if let Some(entry) = cache.get(&key) {
                let mut result = entry.result;
                result.from_cache = true;
                return Ok(result);
            }
        }
    }

    config.exchange_counter.fetch_add(1, Ordering::SeqCst);
    let mut result = config
        .exchange
        .exchange(server, config.port, &options)
        .map_err(ResolveError::from)?;
    result.from_cache = false;

    if cache_enabled_for(config, qname) {
        if let Some(cache) = &config.cache {
            let ttl = ttl_from_result(&result);
            let entry = CachedEntry::from_query_result(
                result.clone(),
                now_unix(),
                ttl.as_secs().min(u64::from(u32::MAX)) as u32,
            );
            let _ = cache.put(&key, entry);
        }
    }

    Ok(result)
}

pub(crate) fn cache_enabled_for(config: &TraceConfig, qname: &DomainName) -> bool {
    if !config.use_cache {
        return false;
    }
    for skip in &config.cache_skip_qnames {
        if qname.as_str().eq_ignore_ascii_case(skip.as_str()) {
            return false;
        }
    }
    true
}

pub(crate) fn hop_from_query(
    zone: &DomainName,
    query: &QueryResult,
    server_name: Option<String>,
    referral_ns: Vec<String>,
    glue: Vec<String>,
    outcome: HopOutcome,
) -> TraceHop {
    TraceHop {
        zone: zone.to_string(),
        server: query.server.to_string(),
        server_name,
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
        response: StoredDnsMessage::from_response(&query.response),
        from_cache: query.from_cache,
        outcome,
    }
}

pub(crate) fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".into())
}

pub(crate) fn filter_addresses(
    addresses: &[IpAddr],
    ipv4_only: bool,
    ipv6_only: bool,
) -> Vec<IpAddr> {
    addresses
        .iter()
        .copied()
        .filter(|addr| match addr {
            IpAddr::V4(_) => !ipv6_only,
            IpAddr::V6(_) => !ipv4_only,
        })
        .collect()
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use dns_core::EdnsMeta;
    use dns_core::name::DomainName;
    use dns_core::response::{DnsResponse, QueryResult};
    use hickory_proto::rr::RecordType;

    struct CountingExchange {
        calls: Arc<AtomicUsize>,
    }

    impl DnsExchange for CountingExchange {
        fn exchange(
            &self,
            server: IpAddr,
            _port: u16,
            options: &QueryOptions,
        ) -> dns_core::Result<QueryResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(QueryResult {
                server,
                transport: options.transport,
                qname: options.qname.clone(),
                qtype: options.qtype.to_string(),
                rtt: Duration::from_millis(5),
                response: DnsResponse {
                    id: 1,
                    rcode: 0,
                    rcode_text: "NOERROR".into(),
                    authoritative: true,
                    truncated: false,
                    recursion_desired: false,
                    recursion_available: false,
                    authentic_data: false,
                    checking_disabled: false,
                    answers: vec![],
                    authorities: vec![],
                    additionals: vec![],
                    edns: EdnsMeta::default(),
                },
                from_cache: false,
            })
        }
    }

    #[test]
    fn cache_hit_marks_result_from_cache() {
        let qname = DomainName::parse("example.com.").expect("qname");
        let mut config = TraceConfig::new(qname, RecordType::A);
        let _cache = config.with_memory_cache();
        let calls = Arc::new(AtomicUsize::new(0));
        config.exchange = Arc::new(CountingExchange {
            calls: calls.clone(),
        });

        let server = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let first =
            query_server(server, &config, &config.qname.clone(), RecordType::A).expect("first");
        let second =
            query_server(server, &config, &config.qname.clone(), RecordType::A).expect("second");

        assert!(!first.from_cache);
        assert!(second.from_cache);
    }

    #[test]
    fn cache_hit_skips_exchange() {
        let qname = DomainName::parse("example.com.").expect("qname");
        let mut config = TraceConfig::new(qname, RecordType::A);
        let cache = config.with_memory_cache();
        let calls = Arc::new(AtomicUsize::new(0));
        config.exchange = Arc::new(CountingExchange {
            calls: calls.clone(),
        });

        let server = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        query_server(server, &config, &config.qname.clone(), RecordType::A).expect("first");
        query_server(server, &config, &config.qname.clone(), RecordType::A).expect("second");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn nocache_always_exchanges() {
        let qname = DomainName::parse("example.com.").expect("qname");
        let mut config = TraceConfig::new(qname, RecordType::A);
        config.with_memory_cache();
        config.use_cache = false;
        let calls = Arc::new(AtomicUsize::new(0));
        config.exchange = Arc::new(CountingExchange {
            calls: calls.clone(),
        });

        let server = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        query_server(server, &config, &config.qname.clone(), RecordType::A).expect("first");
        query_server(server, &config, &config.qname.clone(), RecordType::A).expect("second");

        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn nocache_qname_skips_only_matching_queries() {
        let qname = DomainName::parse("example.com.").expect("qname");
        let ns_name = DomainName::parse("ns.example.com.").expect("ns");
        let mut config = TraceConfig::new(qname, RecordType::A);
        let cache = config.with_memory_cache();
        config
            .cache_skip_qnames
            .insert(DomainName::parse("ns.example.com.").expect("skip"));
        let calls = Arc::new(AtomicUsize::new(0));
        config.exchange = Arc::new(CountingExchange {
            calls: calls.clone(),
        });

        let server = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        query_server(server, &config, &config.qname, RecordType::A).expect("first main");
        query_server(server, &config, &config.qname, RecordType::A).expect("second main");
        query_server(server, &config, &ns_name, RecordType::A).expect("first ns");
        query_server(server, &config, &ns_name, RecordType::A).expect("second ns");

        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn truncated_response_is_not_retried() {
        let qname = DomainName::parse("example.com.").expect("qname");
        let mut config = TraceConfig::new(qname, RecordType::A);
        config.retries = 3;
        let calls = Arc::new(AtomicUsize::new(0));
        config.exchange = Arc::new(TruncatedExchange {
            calls: calls.clone(),
        });

        let server = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let result = query_server(server, &config, &config.qname.clone(), RecordType::A)
            .expect("truncated response");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(result.response.truncated);
    }

    struct TruncatedExchange {
        calls: Arc<AtomicUsize>,
    }

    impl DnsExchange for TruncatedExchange {
        fn exchange(
            &self,
            server: IpAddr,
            _port: u16,
            options: &QueryOptions,
        ) -> dns_core::Result<QueryResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(QueryResult {
                server,
                transport: options.transport,
                qname: options.qname.clone(),
                qtype: options.qtype.to_string(),
                rtt: Duration::from_millis(1),
                response: DnsResponse {
                    id: 1,
                    rcode: 0,
                    rcode_text: "NOERROR".into(),
                    authoritative: true,
                    truncated: true,
                    recursion_desired: false,
                    recursion_available: false,
                    authentic_data: false,
                    checking_disabled: false,
                    answers: vec![],
                    authorities: vec![],
                    additionals: vec![],
                    edns: EdnsMeta::default(),
                },
                from_cache: false,
            })
        }
    }
}
