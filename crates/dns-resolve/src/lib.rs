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
    pub start_servers: Option<Vec<IpAddr>>,
    pub use_cache: bool,
    pub cache_skip_qnames: HashSet<DomainName>,
    pub cache: Option<Arc<dyn ResponseCache>>,
    pub exchange: Arc<dyn DnsExchange>,
    pub exchange_counter: Arc<AtomicUsize>,
    /// Nameserver hostnames currently being resolved (detects cyclic NS lookups).
    pub ns_resolution_active: HashSet<String>,
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
            start_servers: None,
            use_cache: true,
            cache_skip_qnames: HashSet::new(),
            cache: None,
            exchange: Arc::new(DefaultExchange),
            exchange_counter: Arc::new(AtomicUsize::new(0)),
            ns_resolution_active: HashSet::new(),
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
            answers: response.answers.clone(),
            authorities: response.authorities.clone(),
            additionals: response.additionals.clone(),
        }
    }

    pub fn is_stored(&self) -> bool {
        self.id != 0
            || self.authoritative
            || self.truncated
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TraceResult {
    pub qname: String,
    pub qtype: String,
    pub started_at: String,
    pub hops: Vec<TraceHop>,
    pub final_response: Option<FinalAnswer>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalAnswer {
    pub server: String,
    #[serde(default)]
    pub server_name: Option<String>,
    pub rtt_ms: u64,
    pub rcode: String,
    pub records: Vec<String>,
    pub nsid: Option<String>,
    #[serde(default)]
    pub qname: String,
    #[serde(default)]
    pub qtype: String,
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub response: StoredDnsMessage,
}

pub trait TraceProgress: Send {
    fn hop(&mut self, hop: &TraceHop);
    fn message(&mut self, message: &str);
}

pub fn run_trace(config: &TraceConfig, progress: &mut dyn TraceProgress) -> Result<TraceResult> {
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
                return Ok(entry.result);
            }
        }
    }

    config.exchange_counter.fetch_add(1, Ordering::SeqCst);
    let result = config
        .exchange
        .exchange(server, config.port, &options)
        .map_err(ResolveError::from)?;

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
                    answers: vec![],
                    authorities: vec![],
                    additionals: vec![],
                    edns: EdnsMeta::default(),
                },
            })
        }
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
}
