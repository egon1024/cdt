use serde::{Deserialize, Serialize};

use crate::dig_options::TraceOptions;

/// Trace parameters used to match stored sessions for reuse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceRequest {
    pub qname: String,
    pub qtype: String,
    pub server: Option<String>,
    pub ipv4_only: bool,
    pub ipv6_only: bool,
    pub use_tcp: bool,
    pub timeout_secs: u64,
    pub retries: u8,
    pub dnssec: bool,
    pub request_nsid: bool,
    pub use_cache: bool,
    pub cache_skip_qnames: Vec<String>,
}

impl TraceRequest {
    pub fn from_options(options: &TraceOptions) -> Self {
        let mut cache_skip_qnames = options.cache_skip_qnames.clone();
        cache_skip_qnames.sort();
        Self {
            qname: options.qname.clone(),
            qtype: options.qtype.clone(),
            server: options.server.clone(),
            ipv4_only: options.ipv4_only,
            ipv6_only: options.ipv6_only,
            use_tcp: options.use_tcp,
            timeout_secs: options.timeout.as_secs().max(1),
            retries: options.retries,
            dnssec: options.dnssec,
            request_nsid: options.request_nsid,
            use_cache: options.use_cache,
            cache_skip_qnames,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn cache_skip_qnames_are_sorted_for_stable_matching() {
        let options = TraceOptions {
            qname: "example.com".into(),
            cache_skip_qnames: vec!["z.example.".into(), "a.example.".into()],
            ..TraceOptions::default()
        };
        let request = TraceRequest::from_options(&options);
        assert_eq!(
            request.cache_skip_qnames,
            vec!["a.example.".to_string(), "z.example.".to_string()]
        );
    }

    #[test]
    fn timeout_is_normalized_to_seconds() {
        let options = TraceOptions {
            qname: "example.com".into(),
            timeout: Duration::from_secs(3),
            ..TraceOptions::default()
        };
        let request = TraceRequest::from_options(&options);
        assert_eq!(request.timeout_secs, 3);
    }
}
