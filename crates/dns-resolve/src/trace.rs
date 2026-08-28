use std::collections::HashSet;
use std::net::IpAddr;

use dns_core::name::DomainName;
use dns_core::query::record_type_name;
use dns_core::response::DnsResponse;
use hickory_proto::rr::RecordType;

use crate::root_hints::{root_server_names, root_servers};
use crate::{
    HopOutcome, ServerTarget, TraceTree, TraceTreeRequest, build_linear_tree, now_rfc3339,
};
use crate::{
    ResolveError, Result, TraceConfig, TraceProgress, filter_addresses, hop_from_query,
    query_server,
};

pub fn run(config: &TraceConfig, progress: &mut dyn TraceProgress) -> Result<TraceTree> {
    let mut qname = config.qname.clone();
    let mut alias_visited = HashSet::new();
    let mut hops = Vec::new();

    if start_servers(config).is_empty() {
        return Err(ResolveError::NoReachableNameserver { zone: ".".into() });
    }

    'restart: loop {
        let mut servers = start_servers(config);
        let mut current_zone = DomainName::parse(".").expect("root zone");
        let mut visited_zones = HashSet::new();

        for depth in 0..config.max_depth {
            let (query_result, server_name) =
                query_first_available(&servers, config, &qname, config.qtype)?;
            let referral_ns = query_result.response.ns_names();
            let glue = collect_glue(&query_result.response, &referral_ns);

            let hop = hop_from_query(
                &current_zone,
                &query_result,
                server_name.clone(),
                referral_ns.iter().map(ToString::to_string).collect(),
                glue.iter().map(ToString::to_string).collect(),
                HopOutcome::Referral,
            );
            progress.hop(&hop);
            hops.push(hop);

            if config.follow_aliases {
                if let Some(alias) = query_result.response.alias_target(&qname, config.qtype) {
                    if alias_visited.len() >= config.max_alias_depth {
                        return Err(ResolveError::MaxAliasDepth {
                            max: config.max_alias_depth,
                        });
                    }
                    let alias_key = alias.to_string();
                    if !alias_visited.insert(alias_key.clone()) {
                        return Err(ResolveError::AliasLoop { name: alias_key });
                    }
                    progress.message(&format!("following alias to {alias}"));
                    qname = alias;
                    continue 'restart;
                }
            }

            if is_authoritative_answer(&query_result.response, &qname, config.qtype) {
                if let Some(last) = hops.last_mut() {
                    last.outcome = HopOutcome::Answered;
                }
                return Ok(build_linear_tree(
                    hops,
                    TraceTreeRequest {
                        qname: qname.to_string(),
                        qtype: record_type_name(config.qtype),
                        started_at: now_rfc3339(),
                    },
                ));
            }

            let Some(next_zone) = query_result.response.referral_zone(&qname) else {
                if let Some(last) = hops.last_mut() {
                    last.outcome = HopOutcome::Answered;
                }
                return Ok(build_linear_tree(
                    hops,
                    TraceTreeRequest {
                        qname: qname.to_string(),
                        qtype: record_type_name(config.qtype),
                        started_at: now_rfc3339(),
                    },
                ));
            };

            if !visited_zones.insert(next_zone.to_string()) {
                return Err(ResolveError::DelegationLoop {
                    zone: next_zone.to_string(),
                });
            }

            let ns_names = query_result.response.ns_names();
            if ns_names.is_empty() {
                return Err(ResolveError::NoReachableNameserver {
                    zone: next_zone.to_string(),
                });
            }

            progress.message(&format!(
                "following delegation to zone {} via {:?}",
                next_zone,
                ns_names
                    .iter()
                    .map(|name| name.to_string())
                    .collect::<Vec<_>>()
            ));

            servers = resolve_nameservers_from_referral(
                &query_result.response,
                &servers,
                config,
                &current_zone,
                progress,
            )?;

            if servers.is_empty() {
                return Err(ResolveError::NoReachableNameserver {
                    zone: next_zone.to_string(),
                });
            }

            current_zone = next_zone;

            if depth + 1 == config.max_depth - 1 {
                progress.message("approaching maximum delegation depth");
            }
        }

        return Err(ResolveError::MaxDepth {
            max: config.max_depth,
        });
    }
}

fn start_servers(config: &TraceConfig) -> Vec<ServerTarget> {
    let mut servers = config
        .start_servers
        .clone()
        .map(|addresses| {
            addresses
                .into_iter()
                .map(ServerTarget::from_address)
                .collect()
        })
        .unwrap_or_else(default_root_targets);
    servers = filter_targets(&servers, config.ipv4_only, config.ipv6_only);
    servers
}

fn default_root_targets() -> Vec<ServerTarget> {
    root_servers()
        .into_iter()
        .zip(root_server_names())
        .map(|(address, name)| ServerTarget::with_name(address, name))
        .collect()
}

fn filter_targets(targets: &[ServerTarget], ipv4_only: bool, ipv6_only: bool) -> Vec<ServerTarget> {
    filter_addresses(
        &targets
            .iter()
            .map(|target| target.address)
            .collect::<Vec<_>>(),
        ipv4_only,
        ipv6_only,
    )
    .into_iter()
    .filter_map(|address| {
        targets
            .iter()
            .find(|target| target.address == address)
            .cloned()
    })
    .collect()
}

fn query_first_available(
    servers: &[ServerTarget],
    config: &TraceConfig,
    qname: &DomainName,
    qtype: RecordType,
) -> Result<(dns_core::QueryResult, Option<String>)> {
    let mut last_error = None;
    for server in servers {
        match query_server(server.address, config, qname, qtype) {
            Ok(result) => return Ok((result, server.name.clone())),
            Err(error) => last_error = Some(error),
        }
    }
    Err(
        last_error.unwrap_or_else(|| ResolveError::NoReachableNameserver {
            zone: qname.to_string(),
        }),
    )
}

fn resolve_nameservers_from_referral(
    referral: &DnsResponse,
    current_servers: &[ServerTarget],
    config: &TraceConfig,
    parent_zone: &DomainName,
    progress: &mut dyn TraceProgress,
) -> Result<Vec<ServerTarget>> {
    let ns_names = referral.ns_names();
    let mut ordered: Vec<&DomainName> = ns_names.iter().collect();
    ordered.sort_by_key(|ns| !referral.glue_for(ns).is_empty());

    let mut last_error = None;
    for ns_name in ordered {
        match resolve_nameserver(
            ns_name,
            referral,
            current_servers,
            config,
            parent_zone,
            progress,
        ) {
            Ok(targets) if !targets.is_empty() => return Ok(targets),
            Ok(_) => {}
            Err(error) => last_error = Some(error),
        }
    }

    if let Some(error) = last_error {
        return Err(error);
    }

    Err(ResolveError::NoReachableNameserver {
        zone: parent_zone.to_string(),
    })
}

fn resolve_nameserver(
    ns_name: &DomainName,
    referral: &DnsResponse,
    current_servers: &[ServerTarget],
    config: &TraceConfig,
    parent_zone: &DomainName,
    progress: &mut dyn TraceProgress,
) -> Result<Vec<ServerTarget>> {
    if config.ns_resolution_active.contains(ns_name.as_str()) {
        return Err(ResolveError::NameserverResolution {
            name: ns_name.to_string(),
            reason: "nameserver resolution loop detected".into(),
        });
    }

    let mut addresses = filter_addresses(
        &referral.glue_for(ns_name),
        config.ipv4_only,
        config.ipv6_only,
    );

    if !addresses.is_empty() {
        progress.message(&format!("using glue for {}: {:?}", ns_name, addresses));
        return Ok(addresses
            .into_iter()
            .map(|address| ServerTarget::with_name(address, ns_name.to_string()))
            .collect());
    }

    progress.message(&format!("resolving addresses for {}", ns_name));

    for qtype in [RecordType::A, RecordType::AAAA] {
        if let Ok((result, _)) = query_first_available(
            &filter_targets(current_servers, config.ipv4_only, config.ipv6_only),
            config,
            ns_name,
            qtype,
        ) {
            addresses.extend(
                result
                    .response
                    .answers
                    .iter()
                    .filter(|record| record.rtype == "A" || record.rtype == "AAAA")
                    .filter_map(|record| record.rdata.parse::<IpAddr>().ok()),
            );
        }
    }

    addresses = filter_addresses(&addresses, config.ipv4_only, config.ipv6_only);
    if !addresses.is_empty() {
        return Ok(addresses
            .into_iter()
            .map(|address| ServerTarget::with_name(address, ns_name.to_string()))
            .collect());
    }

    if ns_name.is_subdomain_of(parent_zone) {
        return Err(ResolveError::NameserverResolution {
            name: ns_name.to_string(),
            reason: "missing glue for in-bailiwick nameserver".into(),
        });
    }

    let mut sub_config = config.clone();
    sub_config.qname = ns_name.clone();
    sub_config.qtype = RecordType::A;
    sub_config.ns_resolution_active.insert(ns_name.to_string());

    let sub_trace = run(&sub_config, progress)?;
    if let Some(hop) = sub_trace.answering_hop() {
        let parsed = hop
            .response
            .answers
            .iter()
            .filter(|record| record.rtype == "A" || record.rtype == "AAAA")
            .filter_map(|record| record.rdata.parse().ok())
            .collect::<Vec<_>>();
        addresses = filter_addresses(&parsed, config.ipv4_only, config.ipv6_only);
        if !addresses.is_empty() {
            return Ok(addresses
                .into_iter()
                .map(|address| ServerTarget::with_name(address, ns_name.to_string()))
                .collect());
        }
    }

    Err(ResolveError::NameserverResolution {
        name: ns_name.to_string(),
        reason: "no A/AAAA records found".into(),
    })
}

fn collect_glue(response: &DnsResponse, ns_names: &[DomainName]) -> Vec<IpAddr> {
    ns_names
        .iter()
        .flat_map(|ns| response.glue_for(ns))
        .collect()
}

fn is_authoritative_answer(response: &DnsResponse, qname: &DomainName, qtype: RecordType) -> bool {
    if response.authoritative {
        return true;
    }

    let qtype = record_type_name(qtype);
    response.answers.iter().any(|record| {
        record.name.as_str().eq_ignore_ascii_case(qname.as_str()) && record.rtype == qtype
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    use dns_core::EdnsMeta;
    use dns_core::name::DomainName;
    use dns_core::response::{DnsRecord, DnsResponse};
    use hickory_proto::rr::RecordType;

    struct SilentProgress;

    impl crate::TraceProgress for SilentProgress {
        fn hop(&mut self, _hop: &crate::TraceHop) {}
        fn message(&mut self, _message: &str) {}
    }

    #[test]
    fn nameserver_resolution_loop_is_detected() {
        let referral = DnsResponse {
            id: 1,
            rcode: 0,
            rcode_text: "NOERROR".into(),
            authoritative: false,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
            authentic_data: false,
            checking_disabled: false,
            answers: vec![],
            authorities: vec![DnsRecord {
                name: DomainName::parse("example.com.").expect("zone"),
                rtype: "NS".into(),
                rclass: "IN".into(),
                ttl: 3600,
                rdata: "ns.loop.example.".into(),
            }],
            additionals: vec![],
            edns: EdnsMeta::default(),
        };
        let parent_zone = DomainName::parse("com.").expect("zone");
        let ns_name = DomainName::parse("ns.loop.example.").expect("ns");
        let mut config = TraceConfig::new(
            DomainName::parse("example.com.").expect("qname"),
            RecordType::A,
        );
        config.ns_resolution_active.insert(ns_name.to_string());

        let error = resolve_nameserver(
            &ns_name,
            &referral,
            &[ServerTarget::from_address(IpAddr::V4(Ipv4Addr::new(
                1, 1, 1, 1,
            )))],
            &config,
            &parent_zone,
            &mut SilentProgress,
        )
        .expect_err("loop");

        assert!(matches!(
            error,
            ResolveError::NameserverResolution { reason, .. }
                if reason.contains("nameserver resolution loop")
        ));
    }

    #[test]
    fn prefers_nameserver_with_glue() {
        let glued = DomainName::parse("ns1.example.com.").expect("glued");
        let referral = DnsResponse {
            id: 1,
            rcode: 0,
            rcode_text: "NOERROR".into(),
            authoritative: false,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
            authentic_data: false,
            checking_disabled: false,
            answers: vec![],
            authorities: vec![
                DnsRecord {
                    name: DomainName::parse("example.com.").expect("zone"),
                    rtype: "NS".into(),
                    rclass: "IN".into(),
                    ttl: 3600,
                    rdata: "ns2.example.com.".into(),
                },
                DnsRecord {
                    name: DomainName::parse("example.com.").expect("zone"),
                    rtype: "NS".into(),
                    rclass: "IN".into(),
                    ttl: 3600,
                    rdata: "ns1.example.com.".into(),
                },
            ],
            additionals: vec![DnsRecord {
                name: glued.clone(),
                rtype: "A".into(),
                rclass: "IN".into(),
                ttl: 3600,
                rdata: "93.184.216.34".into(),
            }],
            edns: EdnsMeta::default(),
        };
        let parent_zone = DomainName::parse("com.").expect("zone");
        let config = TraceConfig::new(
            DomainName::parse("example.com.").expect("qname"),
            RecordType::A,
        );

        let addresses = resolve_nameservers_from_referral(
            &referral,
            &[ServerTarget::from_address(IpAddr::V4(Ipv4Addr::new(
                1, 1, 1, 1,
            )))],
            &config,
            &parent_zone,
            &mut SilentProgress,
        )
        .expect("addresses");

        assert_eq!(
            addresses,
            vec![ServerTarget::with_name(
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                "ns1.example.com."
            )]
        );
    }

    #[test]
    fn authoritative_when_flag_set() {
        let response = DnsResponse {
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
            edns: dns_core::EdnsMeta::default(),
        };
        let qname = DomainName::parse("example.com.").expect("qname");
        assert!(is_authoritative_answer(&response, &qname, RecordType::A));
    }

    struct CnameOnlyExchange {
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl crate::DnsExchange for CnameOnlyExchange {
        fn exchange(
            &self,
            server: IpAddr,
            _port: u16,
            options: &dns_core::QueryOptions,
        ) -> dns_core::Result<dns_core::QueryResult> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(dns_core::QueryResult {
                server,
                transport: options.transport,
                qname: options.qname.clone(),
                qtype: options.qtype.to_string(),
                rtt: std::time::Duration::from_millis(1),
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
                    answers: vec![DnsRecord {
                        name: options.qname.clone(),
                        rtype: "CNAME".into(),
                        rclass: "IN".into(),
                        ttl: 300,
                        rdata: "cdn.example.com.".into(),
                    }],
                    authorities: vec![],
                    additionals: vec![],
                    edns: EdnsMeta::default(),
                },
                from_cache: false,
            })
        }
    }

    #[test]
    fn cname_query_with_follow_stops_at_cname_owner() {
        let qname = DomainName::parse("www.example.com.").expect("qname");
        let mut config = TraceConfig::new(qname, RecordType::CNAME);
        config.follow_aliases = true;
        config.start_servers = Some(vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        config.exchange = std::sync::Arc::new(CnameOnlyExchange {
            calls: calls.clone(),
        });

        let tree = run(&config, &mut SilentProgress).expect("trace");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(tree.node_count(), 1);
        assert_eq!(tree.leaf().hop.qtype, "CNAME");
    }

    #[test]
    fn a_query_with_follow_continues_past_cname() {
        let qname = DomainName::parse("www.example.com.").expect("qname");
        let mut config = TraceConfig::new(qname, RecordType::A);
        config.follow_aliases = true;
        config.start_servers = Some(vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        config.exchange = std::sync::Arc::new(CnameOnlyExchange {
            calls: calls.clone(),
        });

        let tree = run(&config, &mut SilentProgress).expect("trace");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(tree.request.qname, "cdn.example.com.");
    }
}
