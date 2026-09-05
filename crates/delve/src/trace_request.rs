use dns_resolve::{AddressFamilyRequest, ExpansionPolicy, ResolvedAddressFamily};
use serde::{Deserialize, Deserializer, Serialize};

use crate::dig_options::TraceOptions;

/// Trace parameters used to match stored sessions for reuse.
#[derive(Debug, Clone, Serialize)]
pub struct TraceRequest {
    pub qname: String,
    pub qtype: String,
    #[serde(default)]
    pub reverse_lookup: bool,
    #[serde(default)]
    pub follow_aliases: bool,
    pub server: Option<String>,
    #[serde(default)]
    pub family_request: AddressFamilyRequest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_address_family: Option<ResolvedAddressFamily>,
    pub use_tcp: bool,
    pub timeout_secs: u64,
    pub retries: u8,
    pub dnssec: bool,
    pub request_nsid: bool,
    pub use_cache: bool,
    pub cache_skip_qnames: Vec<String>,
    #[serde(default)]
    pub debug: bool,
    #[serde(default)]
    pub expansion: ExpansionPolicy,
    /// Legacy phase-1 field; deserialized for old sessions only.
    #[serde(default, skip_serializing)]
    ipv4_only: bool,
    /// Legacy phase-1 field; deserialized for old sessions only.
    #[serde(default, skip_serializing)]
    ipv6_only: bool,
}

impl PartialEq for TraceRequest {
    fn eq(&self, other: &Self) -> bool {
        self.qname == other.qname
            && self.qtype == other.qtype
            && self.reverse_lookup == other.reverse_lookup
            && self.follow_aliases == other.follow_aliases
            && self.server == other.server
            && self.family_request == other.family_request
            && self.resolved_address_family == other.resolved_address_family
            && self.use_tcp == other.use_tcp
            && self.timeout_secs == other.timeout_secs
            && self.retries == other.retries
            && self.dnssec == other.dnssec
            && self.request_nsid == other.request_nsid
            && self.use_cache == other.use_cache
            && self.cache_skip_qnames == other.cache_skip_qnames
            && self.debug == other.debug
            && self.expansion == other.expansion
    }
}

impl Eq for TraceRequest {}

impl TraceRequest {
    pub fn from_options(options: &TraceOptions) -> Self {
        let mut cache_skip_qnames = options.cache_skip_qnames.clone();
        cache_skip_qnames.sort();
        Self {
            qname: options.qname.clone(),
            qtype: options.qtype.clone(),
            reverse_lookup: options.reverse_lookup,
            follow_aliases: options.follow_aliases,
            server: options.server.clone(),
            family_request: options.family_request,
            resolved_address_family: None,
            use_tcp: options.use_tcp,
            timeout_secs: options.timeout.as_secs().max(1),
            retries: options.retries,
            dnssec: options.dnssec,
            request_nsid: options.request_nsid,
            use_cache: options.use_cache,
            cache_skip_qnames,
            debug: options.debug,
            expansion: options.expansion,
            ipv4_only: false,
            ipv6_only: false,
        }
    }

    pub fn with_resolved_family(mut self, resolved: ResolvedAddressFamily) -> Self {
        self.resolved_address_family = Some(resolved);
        self
    }

    /// Effective family for session reuse; legacy sessions without the field use dual-stack.
    pub fn effective_resolved_family(&self) -> ResolvedAddressFamily {
        self.resolved_address_family
            .or_else(|| legacy_resolved_family(self.ipv4_only, self.ipv6_only))
            .unwrap_or(ResolvedAddressFamily::Both)
    }

    /// Whether this request can reuse a stored session tree entry.
    pub fn matches_for_reuse(&self, stored: &Self) -> bool {
        self.qname == stored.qname
            && self.qtype == stored.qtype
            && self.reverse_lookup == stored.reverse_lookup
            && self.follow_aliases == stored.follow_aliases
            && self.server == stored.server
            && self.use_tcp == stored.use_tcp
            && self.timeout_secs == stored.timeout_secs
            && self.retries == stored.retries
            && self.dnssec == stored.dnssec
            && self.request_nsid == stored.request_nsid
            && self.use_cache == stored.use_cache
            && self.cache_skip_qnames == stored.cache_skip_qnames
            && self.debug == stored.debug
            && self.expansion == stored.expansion
            && self.effective_resolved_family() == stored.effective_resolved_family()
    }
}

fn legacy_resolved_family(ipv4_only: bool, ipv6_only: bool) -> Option<ResolvedAddressFamily> {
    if ipv6_only {
        Some(ResolvedAddressFamily::V6)
    } else if ipv4_only {
        Some(ResolvedAddressFamily::V4)
    } else {
        None
    }
}

impl<'de> Deserialize<'de> for TraceRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            qname: String,
            qtype: String,
            #[serde(default)]
            reverse_lookup: bool,
            #[serde(default)]
            follow_aliases: bool,
            server: Option<String>,
            #[serde(default)]
            family_request: Option<AddressFamilyRequest>,
            #[serde(default)]
            resolved_address_family: Option<ResolvedAddressFamily>,
            use_tcp: bool,
            timeout_secs: u64,
            retries: u8,
            dnssec: bool,
            request_nsid: bool,
            use_cache: bool,
            cache_skip_qnames: Vec<String>,
            #[serde(default)]
            debug: bool,
            #[serde(default)]
            expansion: ExpansionPolicy,
            #[serde(default)]
            ipv4_only: bool,
            #[serde(default)]
            ipv6_only: bool,
        }

        let wire = Wire::deserialize(deserializer)?;
        let family_request = wire.family_request.unwrap_or({
            if wire.ipv6_only {
                AddressFamilyRequest::V6
            } else if wire.ipv4_only {
                AddressFamilyRequest::V4
            } else {
                AddressFamilyRequest::Auto
            }
        });

        Ok(Self {
            qname: wire.qname,
            qtype: wire.qtype,
            reverse_lookup: wire.reverse_lookup,
            follow_aliases: wire.follow_aliases,
            server: wire.server,
            family_request,
            resolved_address_family: wire.resolved_address_family,
            use_tcp: wire.use_tcp,
            timeout_secs: wire.timeout_secs,
            retries: wire.retries,
            dnssec: wire.dnssec,
            request_nsid: wire.request_nsid,
            use_cache: wire.use_cache,
            cache_skip_qnames: wire.cache_skip_qnames,
            debug: wire.debug,
            expansion: wire.expansion,
            ipv4_only: wire.ipv4_only,
            ipv6_only: wire.ipv6_only,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::dig_options::FamilySource;

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

    #[test]
    fn expansion_policy_participates_in_matching() {
        let default_request = TraceRequest::from_options(&TraceOptions {
            qname: "example.com".into(),
            ..TraceOptions::default()
        });
        let mut none_request = default_request.clone();
        none_request.expansion = ExpansionPolicy::None;
        assert!(!default_request.matches_for_reuse(&none_request));
        assert_eq!(default_request.expansion, ExpansionPolicy::Last);
    }

    #[test]
    fn resolved_family_round_trips_in_json() {
        let request = TraceRequest::from_options(&TraceOptions {
            qname: "example.com".into(),
            ..TraceOptions::default()
        })
        .with_resolved_family(ResolvedAddressFamily::V4);
        let json = serde_json::to_string(&request).expect("serialize");
        let restored: TraceRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            restored.resolved_address_family,
            Some(ResolvedAddressFamily::V4)
        );
    }

    #[test]
    fn legacy_session_without_resolved_family_treated_as_both() {
        let json = r#"{
            "qname": "example.com",
            "qtype": "A",
            "server": null,
            "ipv4_only": false,
            "ipv6_only": false,
            "use_tcp": false,
            "timeout_secs": 5,
            "retries": 2,
            "dnssec": false,
            "request_nsid": true,
            "use_cache": true,
            "cache_skip_qnames": []
        }"#;
        let request: TraceRequest = serde_json::from_str(json).expect("deserialize");
        assert_eq!(
            request.effective_resolved_family(),
            ResolvedAddressFamily::Both
        );
    }

    #[test]
    fn reuse_matches_on_resolved_family_not_request_spelling() {
        let mut auto = TraceRequest::from_options(&TraceOptions {
            qname: "example.com".into(),
            ..TraceOptions::default()
        })
        .with_resolved_family(ResolvedAddressFamily::V4);
        let explicit = TraceRequest::from_options(&TraceOptions {
            qname: "example.com".into(),
            family_request: AddressFamilyRequest::V4,
            family_source: FamilySource::Minus4,
            ..TraceOptions::default()
        })
        .with_resolved_family(ResolvedAddressFamily::V4);
        assert!(auto.matches_for_reuse(&explicit));
        auto.resolved_address_family = Some(ResolvedAddressFamily::Both);
        assert!(!auto.matches_for_reuse(&explicit));
    }
}
