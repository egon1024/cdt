use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use dns_cache::ResponseCache;
use dns_core::{DomainName, Transport, ip_to_ptr_name, parse_record_type, parse_reverse_target};
use dns_resolve::{ExpansionPolicy, TraceConfig};

use crate::trace_request::TraceRequest;

#[derive(Debug, thiserror::Error)]
pub enum TraceConfigError {
    #[error(transparent)]
    Core(#[from] dns_core::DnsCoreError),

    #[error("invalid query type: {0}")]
    QueryType(String),

    #[error("invalid server address: {0}")]
    Server(String),
}

pub fn trace_config_from_request(
    request: &TraceRequest,
    cache: Option<Arc<dyn ResponseCache>>,
    max_queries: usize,
    max_parallel: usize,
) -> Result<TraceConfig, TraceConfigError> {
    let qname = if request.reverse_lookup {
        let ip = parse_reverse_target(&request.qname)?;
        ip_to_ptr_name(ip)?
    } else {
        DomainName::parse(&request.qname)?
    };
    let qtype = parse_record_type(&request.qtype)
        .map_err(|_| TraceConfigError::QueryType(request.qtype.clone()))?;
    let mut config = TraceConfig::new(qname, qtype);
    config.follow_aliases = request.follow_aliases;
    config.transport = if request.use_tcp {
        Transport::Tcp
    } else {
        Transport::Udp
    };
    config.timeout = Duration::from_secs(request.timeout_secs.max(1));
    config.retries = request.retries;
    config.dnssec = request.dnssec;
    config.request_nsid = request.request_nsid;
    config.ipv4_only = request.ipv4_only;
    config.ipv6_only = request.ipv6_only;
    config.use_cache = request.use_cache;
    config.expansion_policy = ExpansionPolicy::None;
    config.max_queries_per_action = max_queries;
    config.max_parallel_queries = max_parallel;
    config.set_debug(request.debug);
    for raw in &request.cache_skip_qnames {
        config
            .cache_skip_qnames
            .insert(DomainName::parse(raw).map_err(TraceConfigError::Core)?);
    }
    config.cache = cache;
    if let Some(server) = request.server.as_deref() {
        let addr: IpAddr = server.parse().map_err(|error: std::net::AddrParseError| {
            TraceConfigError::Server(error.to_string())
        })?;
        config.start_servers = Some(vec![addr]);
    }
    Ok(config)
}
