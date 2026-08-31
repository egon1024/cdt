use std::collections::HashSet;
use std::net::IpAddr;

use dns_core::name::DomainName;
use dns_core::query::record_type_name;
use dns_core::response::DnsResponse;
use hickory_proto::rr::RecordType;

use crate::root_hints::{root_server_names, root_servers};
use crate::{
    ExpansionPolicy, HopOutcome, QueryBudget, QueryDebugContext, ResolveError, Result,
    ServerTarget, TraceConfig, TraceHop, TraceNode, TraceProgress, TraceTree, TraceTreeRequest,
    filter_addresses, now_rfc3339, query_server, record_query_debug,
};

#[allow(dead_code)]
pub(crate) struct QueryAttempt {
    pub server: ServerTarget,
    pub result: Result<dns_core::QueryResult>,
}

pub fn run(config: &TraceConfig, progress: &mut dyn TraceProgress) -> Result<TraceTree> {
    let original_qname = config.qname.clone();
    let started_at = now_rfc3339();
    let mut budget = QueryBudget::new(config.max_queries_per_action);
    let mut alias_visited = HashSet::new();

    if start_servers(config).is_empty() {
        return Err(ResolveError::NoReachableNameserver { zone: ".".into() });
    }

    let defer_terminal_expansion =
        config.follow_aliases && config.expansion_policy == ExpansionPolicy::Last;

    let mut root = trace_leg(
        config,
        &mut budget,
        progress,
        config.qname.clone(),
        defer_terminal_expansion,
    )?;

    if config.follow_aliases {
        loop {
            let Some(alias) = alias_target_from_tree(&root, config.qtype) else {
                if defer_terminal_expansion {
                    expand_last_on_combined_tree(config, &mut budget, progress, &mut root)?;
                }
                break;
            };

            if alias_visited.len() >= config.max_alias_depth {
                return Err(ResolveError::MaxAliasDepth {
                    max: config.max_alias_depth,
                });
            }
            if !alias_visited.insert(alias.clone()) {
                return Err(ResolveError::AliasLoop { name: alias });
            }

            progress.message(&format!("following alias to {alias}"));
            let alias_qname = DomainName::parse(&alias).map_err(ResolveError::Core)?;
            let alias_leg = trace_leg(
                config,
                &mut budget,
                progress,
                alias_qname,
                defer_terminal_expansion,
            )?;
            attach_alias_leg(&mut root, alias_leg);
        }
    }

    Ok(TraceTree {
        request: TraceTreeRequest {
            qname: original_qname.to_string(),
            qtype: record_type_name(config.qtype),
            started_at,
        },
        root,
        budget_truncated: budget.truncated,
    })
}

fn trace_leg(
    config: &TraceConfig,
    budget: &mut QueryBudget,
    progress: &mut dyn TraceProgress,
    qname: DomainName,
    defer_terminal_expansion: bool,
) -> Result<TraceNode> {
    crate::job_queue::run_policy(config, budget, progress, qname, defer_terminal_expansion)
}

fn attach_alias_leg(root: &mut TraceNode, leg: TraceNode) {
    primary_leaf_mut(root).children.push(leg);
}

fn primary_leaf_mut(node: &mut TraceNode) -> &mut TraceNode {
    let mut current = node;
    loop {
        if current.children.is_empty() {
            return current;
        }
        current = &mut current.children[0];
    }
}

fn is_root_zone(zone: &str) -> bool {
    zone.trim_end_matches('.').is_empty()
}

fn find_final_leg_indices(root: &TraceNode) -> Vec<usize> {
    let mut path = Vec::new();
    let mut current = root;
    while let Some(first) = current.children.first() {
        if is_root_zone(&first.hop.zone) {
            path.push(0);
            return path;
        }
        path.push(0);
        current = first;
    }
    Vec::new()
}

fn resolve_mut<'a>(root: &'a mut TraceNode, path: &[usize]) -> &'a mut TraceNode {
    let mut node = root;
    for &index in path {
        node = &mut node.children[index];
    }
    node
}

fn clone_primary_chain(node: &TraceNode) -> Vec<TraceNode> {
    let mut chain = vec![TraceNode {
        hop: node.hop.clone(),
        origin: node.origin.clone(),
        children: Vec::new(),
    }];
    let mut current = node;
    while let Some(first) = current.children.first() {
        if is_root_zone(&first.hop.zone) {
            break;
        }
        chain.push(TraceNode {
            hop: first.hop.clone(),
            origin: first.origin.clone(),
            children: Vec::new(),
        });
        current = first;
    }
    chain
}

fn expand_last_on_combined_tree(
    config: &TraceConfig,
    budget: &mut QueryBudget,
    progress: &mut dyn TraceProgress,
    root: &mut TraceNode,
) -> Result<()> {
    let leg_indices = find_final_leg_indices(root);
    let leg_root = resolve_mut(root, &leg_indices);
    let chain = clone_primary_chain(leg_root);
    if chain.len() < 2 {
        return Ok(());
    }

    let leaf = chain.last().expect("chain length checked").hop.clone();
    if leaf.outcome != HopOutcome::Answered {
        return Ok(());
    }

    let parent = chain[chain.len() - 2].hop.clone();
    let parent_zone = DomainName::parse(&parent.zone).map_err(ResolveError::Core)?;
    let current_zone = DomainName::parse(&leaf.zone).map_err(ResolveError::Core)?;
    let qname = DomainName::parse(&leaf.qname).map_err(ResolveError::Core)?;
    let parent_response =
        dns_response_from_stored(&parent).ok_or_else(|| ResolveError::NoReachableNameserver {
            zone: parent.zone.clone(),
        })?;

    let chain_len = chain.len();
    let mut chain: Vec<TraceNode> = chain
        .into_iter()
        .take(chain_len.saturating_sub(1))
        .collect();

    let parent_path = if chain.len() <= 1 {
        Vec::new()
    } else {
        vec![0; chain.len() - 1]
    };

    let server = server_target_from_hop(&leaf)?;
    let query_result = query_result_from_hop(&leaf, server.address)?;

    let mut siblings = crate::job_queue::run_terminal_sibling_expansion(
        config,
        budget,
        progress,
        crate::job_queue::TerminalSiblingExpansion {
            parent_path,
            parent_delegation: parent_response,
            parent_zone,
            cut_servers: Vec::new(),
            zone: current_zone,
            qname,
            qtype: config.qtype,
            primary_server: server,
            primary_hop: leaf,
            primary_query_result: query_result,
            force_single_path_subtrees: true,
        },
    )?;

    if siblings.is_empty() {
        return Ok(());
    }

    if chain.is_empty() {
        let mut root = siblings.remove(0);
        root.children.extend(siblings);
        *leg_root = root;
    } else {
        let parent_idx = chain.len() - 1;
        chain[parent_idx].children = siblings;
        *leg_root = link_chain(chain);
    }
    Ok(())
}

pub fn server_target_from_hop(hop: &TraceHop) -> Result<ServerTarget> {
    let address: IpAddr = hop
        .server
        .parse()
        .map_err(|_| ResolveError::NameserverResolution {
            name: hop.server.clone(),
            reason: "invalid server address in hop".into(),
        })?;
    Ok(ServerTarget::with_name(
        address,
        hop.server_name.clone().unwrap_or_default(),
    ))
}

fn query_result_from_hop(hop: &TraceHop, server: IpAddr) -> Result<dns_core::QueryResult> {
    let response =
        dns_response_from_stored(hop).ok_or_else(|| ResolveError::NameserverResolution {
            name: hop.qname.clone(),
            reason: "missing stored response on hop".into(),
        })?;
    let transport = match hop.transport.to_ascii_lowercase().as_str() {
        "tcp" => dns_core::Transport::Tcp,
        _ => dns_core::Transport::Udp,
    };
    Ok(dns_core::QueryResult {
        server,
        transport,
        qname: DomainName::parse(&hop.qname).map_err(ResolveError::Core)?,
        qtype: hop.qtype.clone(),
        rtt: std::time::Duration::from_millis(hop.rtt_ms),
        response,
        from_cache: hop.from_cache,
    })
}

fn alias_target_from_tree(root: &TraceNode, qtype: RecordType) -> Option<String> {
    let leaf = primary_leaf(root);
    let qname = DomainName::parse(&leaf.hop.qname).ok()?;
    let response = dns_response_from_stored(&leaf.hop)?;
    response
        .alias_target(&qname, qtype)
        .map(|name| name.to_string())
}

pub fn dns_response_from_stored(hop: &TraceHop) -> Option<DnsResponse> {
    if !hop.response.is_stored() {
        return None;
    }
    Some(DnsResponse {
        id: hop.response.id,
        rcode: 0,
        rcode_text: hop.rcode.clone(),
        authoritative: hop.response.authoritative,
        truncated: hop.response.truncated,
        recursion_desired: hop.response.recursion_desired,
        recursion_available: hop.response.recursion_available,
        authentic_data: hop.response.authentic_data,
        checking_disabled: hop.response.checking_disabled,
        answers: hop.response.answers.clone(),
        authorities: hop.response.authorities.clone(),
        additionals: hop.response.additionals.clone(),
        edns: dns_core::EdnsMeta::default(),
    })
}

fn primary_leaf(node: &TraceNode) -> &TraceNode {
    let mut current = node;
    while let Some(child) = current.children.first() {
        current = child;
    }
    current
}

fn answering_hop_from_node(node: &TraceNode) -> Option<&TraceHop> {
    let leaf = primary_leaf(node);
    if matches!(leaf.hop.outcome, HopOutcome::Answered) {
        Some(&leaf.hop)
    } else {
        None
    }
}

pub(crate) fn referral_key(
    response: &DnsResponse,
    qname: &DomainName,
    next_zone: &DomainName,
) -> String {
    let mut names = response.ns_names();
    names.sort_by_key(|name| name.to_string());
    format!(
        "{}|{}|{}",
        next_zone,
        qname,
        names
            .iter()
            .map(|name| name.to_string())
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn link_chain(mut nodes: Vec<TraceNode>) -> TraceNode {
    assert!(!nodes.is_empty(), "trace chain must not be empty");
    while nodes.len() > 1 {
        let child = nodes.pop().expect("child");
        nodes.last_mut().expect("parent").children.push(child);
    }
    nodes.pop().expect("root")
}

pub(crate) fn query_one(
    servers: &[ServerTarget],
    config: &TraceConfig,
    budget: &mut QueryBudget,
    qname: &DomainName,
    qtype: RecordType,
) -> Result<(dns_core::QueryResult, Option<String>)> {
    let mut last_error = None;
    for server in servers {
        if !config.budget_exempt && !budget.try_consume() {
            progress_budget_if_needed(config, budget);
            return Err(
                last_error.unwrap_or_else(|| ResolveError::NoReachableNameserver {
                    zone: qname.to_string(),
                }),
            );
        }
        record_query_debug(
            config,
            server.address,
            qname,
            qtype,
            QueryDebugContext::ns_resolve(),
        );
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

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn query_all(
    servers: &[ServerTarget],
    config: &TraceConfig,
    budget: &mut QueryBudget,
    qname: &DomainName,
    qtype: RecordType,
) -> Vec<QueryAttempt> {
    let mut attempts = Vec::new();
    for server in servers {
        if !config.budget_exempt && !budget.try_consume() {
            break;
        }
        record_query_debug(
            config,
            server.address,
            qname,
            qtype,
            QueryDebugContext::ns_resolve(),
        );
        let result = query_server(server.address, config, qname, qtype);
        attempts.push(QueryAttempt {
            server: server.clone(),
            result,
        });
    }
    attempts
}

fn progress_budget_if_needed(_config: &TraceConfig, _budget: &mut QueryBudget) {}

pub fn failed_hop(
    config: &TraceConfig,
    zone: &DomainName,
    qname: &DomainName,
    qtype: RecordType,
    server: &ServerTarget,
    error: &ResolveError,
) -> TraceHop {
    TraceHop {
        zone: zone.to_string(),
        server: server.address.to_string(),
        server_name: server.name.clone(),
        qname: qname.to_string(),
        qtype: record_type_name(qtype),
        transport: config.transport.to_string(),
        rtt_ms: 0,
        rcode: "SERVFAIL".into(),
        nsid: None,
        ede_code: None,
        ede_text: None,
        referral_ns: vec![],
        glue: vec![],
        response: Default::default(),
        from_cache: false,
        outcome: HopOutcome::Failed {
            kind: error_kind(error),
            detail: error.to_string(),
        },
    }
}

fn error_kind(error: &ResolveError) -> String {
    match error {
        ResolveError::NoReachableNameserver { .. } => "no_reachable_nameserver".into(),
        ResolveError::NameserverResolution { .. } => "nameserver_resolution".into(),
        ResolveError::DelegationLoop { .. } => "delegation_loop".into(),
        ResolveError::MaxDepth { .. } => "max_depth".into(),
        ResolveError::AliasLoop { .. } => "alias_loop".into(),
        ResolveError::MaxAliasDepth { .. } => "max_alias_depth".into(),
        ResolveError::Core(_) => "core".into(),
    }
}

pub(crate) fn start_servers(config: &TraceConfig) -> Vec<ServerTarget> {
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

pub fn expansion_targets_for_cut(
    parent_delegation: Option<&DnsResponse>,
    parent_zone: &DomainName,
    fallback_servers: &[ServerTarget],
    config: &TraceConfig,
    budget: &mut QueryBudget,
    progress: &mut dyn TraceProgress,
) -> Result<Vec<ServerTarget>> {
    let Some(parent_delegation) = parent_delegation else {
        return Ok(fallback_servers.to_vec());
    };

    resolve_all_nameserver_targets_from_referral(
        parent_delegation,
        fallback_servers,
        config,
        budget,
        parent_zone,
        progress,
    )
}

fn resolve_all_nameserver_targets_from_referral(
    referral: &DnsResponse,
    current_servers: &[ServerTarget],
    config: &TraceConfig,
    budget: &mut QueryBudget,
    parent_zone: &DomainName,
    progress: &mut dyn TraceProgress,
) -> Result<Vec<ServerTarget>> {
    let ns_names = referral.ns_names();
    if ns_names.is_empty() {
        return Err(ResolveError::NoReachableNameserver {
            zone: parent_zone.to_string(),
        });
    }

    let mut targets = Vec::new();
    let mut last_error = None;

    for ns_name in ns_names {
        match resolve_nameserver(
            &ns_name,
            referral,
            current_servers,
            config,
            budget,
            parent_zone,
            progress,
        ) {
            Ok(addresses) if !addresses.is_empty() => targets.push(addresses[0].clone()),
            Ok(_) => {}
            Err(error) => last_error = Some(error),
        }
    }

    if !targets.is_empty() {
        return Ok(targets);
    }

    if let Some(error) = last_error {
        return Err(error);
    }

    Err(ResolveError::NoReachableNameserver {
        zone: parent_zone.to_string(),
    })
}

/// Resolve a single referral nameserver to a query target.
pub fn resolve_nameserver_target_for_referral(
    ns_name: &DomainName,
    referral: &DnsResponse,
    current_servers: &[ServerTarget],
    config: &TraceConfig,
    budget: &mut QueryBudget,
    parent_zone: &DomainName,
    progress: &mut dyn TraceProgress,
) -> Result<Option<ServerTarget>> {
    match resolve_nameserver(
        ns_name,
        referral,
        current_servers,
        config,
        budget,
        parent_zone,
        progress,
    ) {
        Ok(addresses) if !addresses.is_empty() => Ok(Some(addresses[0].clone())),
        Ok(_) => Ok(None),
        Err(error) => Err(error),
    }
}

pub(crate) fn announce_multi_server_query(
    progress: &mut dyn TraceProgress,
    zone: &DomainName,
    server_count: usize,
) {
    if server_count > 1 {
        progress.message(&format!(
            "querying {server_count} nameserver(s) at zone {zone}"
        ));
    }
}

pub fn server_matches_primary(
    server: &ServerTarget,
    primary_server: &ServerTarget,
    primary_result_server: IpAddr,
) -> bool {
    if server.address == primary_server.address || server.address == primary_result_server {
        return true;
    }
    match (&server.name, &primary_server.name) {
        (Some(server_name), Some(primary_name)) => server_name.eq_ignore_ascii_case(primary_name),
        _ => false,
    }
}

pub(crate) fn resolve_nameservers_from_referral(
    referral: &DnsResponse,
    current_servers: &[ServerTarget],
    config: &TraceConfig,
    budget: &mut QueryBudget,
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
            budget,
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
    budget: &mut QueryBudget,
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
        let targets: Vec<ServerTarget> = addresses
            .into_iter()
            .map(|address| ServerTarget::with_name(address, ns_name.to_string()))
            .collect();
        remember_ns_targets(config, ns_name, &targets);
        return Ok(targets);
    }

    if let Some(targets) = cached_ns_targets(config, ns_name) {
        return Ok(targets);
    }

    progress.message(&format!("resolving addresses for {}", ns_name));

    let mut exempt = config.clone();
    exempt.budget_exempt = true;

    for qtype in [RecordType::A, RecordType::AAAA] {
        if let Ok((result, _)) = query_one(
            &filter_targets(current_servers, config.ipv4_only, config.ipv6_only),
            &exempt,
            budget,
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
        let targets: Vec<ServerTarget> = addresses
            .into_iter()
            .map(|address| ServerTarget::with_name(address, ns_name.to_string()))
            .collect();
        remember_ns_targets(config, ns_name, &targets);
        return Ok(targets);
    }

    if ns_name.is_subdomain_of(parent_zone) {
        return Err(ResolveError::NameserverResolution {
            name: ns_name.to_string(),
            reason: "missing glue for in-bailiwick nameserver".into(),
        });
    }

    let subtree = crate::job_queue::run_ns_resolution_batch(&exempt, budget, ns_name.clone())?;
    if let Some(hop) = answering_hop_from_node(&subtree) {
        let parsed = hop
            .response
            .answers
            .iter()
            .filter(|record| record.rtype == "A" || record.rtype == "AAAA")
            .filter_map(|record| record.rdata.parse().ok())
            .collect::<Vec<_>>();
        addresses = filter_addresses(&parsed, config.ipv4_only, config.ipv6_only);
        if !addresses.is_empty() {
            let targets: Vec<ServerTarget> = addresses
                .into_iter()
                .map(|address| ServerTarget::with_name(address, ns_name.to_string()))
                .collect();
            remember_ns_targets(config, ns_name, &targets);
            return Ok(targets);
        }
    }

    Err(ResolveError::NameserverResolution {
        name: ns_name.to_string(),
        reason: "no A/AAAA records found".into(),
    })
}

fn cached_ns_targets(config: &TraceConfig, ns_name: &DomainName) -> Option<Vec<ServerTarget>> {
    config
        .ns_target_cache
        .lock()
        .ok()?
        .get(ns_name.as_str())
        .cloned()
}

fn remember_ns_targets(config: &TraceConfig, ns_name: &DomainName, targets: &[ServerTarget]) {
    if targets.is_empty() {
        return;
    }
    if let Ok(mut cache) = config.ns_target_cache.lock() {
        cache.insert(ns_name.to_string(), targets.to_vec());
    }
}

/// Seed the per-trace nameserver target cache from hops already present in a session tree.
///
/// Branch continuation reuses these addresses when a delegation has no glue, avoiding
/// redundant (and sometimes failing) in-bailiwick nameserver sub-traces.
pub fn seed_ns_targets_from_tree(config: &TraceConfig, root: &TraceNode) {
    seed_ns_targets_from_node(config, root);
}

fn seed_ns_targets_from_node(config: &TraceConfig, node: &TraceNode) {
    if let Some(name) = node
        .hop
        .server_name
        .as_deref()
        .filter(|name| !name.is_empty())
    {
        if let (Ok(ns_name), Ok(target)) =
            (DomainName::parse(name), server_target_from_hop(&node.hop))
        {
            remember_ns_targets(config, &ns_name, std::slice::from_ref(&target));
        }
    }
    for child in &node.children {
        seed_ns_targets_from_node(config, child);
    }
}

pub(crate) fn collect_glue(response: &DnsResponse, ns_names: &[DomainName]) -> Vec<IpAddr> {
    ns_names
        .iter()
        .flat_map(|ns| response.glue_for(ns))
        .collect()
}

pub(crate) fn is_authoritative_answer(
    response: &DnsResponse,
    qname: &DomainName,
    qtype: RecordType,
) -> bool {
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
    use crate::NodePath;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use dns_core::EdnsMeta;
    use dns_core::name::DomainName;
    use dns_core::response::{DnsRecord, DnsResponse};
    use hickory_proto::rr::RecordType;

    struct SilentProgress;

    impl crate::TraceProgress for SilentProgress {
        fn hop(&mut self, _hop: &crate::TraceHop, _path: &NodePath) {}
        fn message(&mut self, _message: &str) {}
    }

    fn test_config(qname: &str, exchange: Arc<dyn crate::DnsExchange>) -> TraceConfig {
        let mut config = TraceConfig::new(DomainName::parse(qname).expect("qname"), RecordType::A);
        config.start_servers = Some(vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
        config.exchange = exchange;
        config
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
        let mut budget = QueryBudget::new(64);

        let error = resolve_nameserver(
            &ns_name,
            &referral,
            &[ServerTarget::from_address(IpAddr::V4(Ipv4Addr::new(
                1, 1, 1, 1,
            )))],
            &config,
            &mut budget,
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
        let mut budget = QueryBudget::new(64);

        let addresses = resolve_nameservers_from_referral(
            &referral,
            &[ServerTarget::from_address(IpAddr::V4(Ipv4Addr::new(
                1, 1, 1, 1,
            )))],
            &config,
            &mut budget,
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
        calls: Arc<AtomicUsize>,
    }

    impl crate::DnsExchange for CnameOnlyExchange {
        fn exchange(
            &self,
            server: IpAddr,
            _port: u16,
            options: &dns_core::QueryOptions,
        ) -> dns_core::Result<dns_core::QueryResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(dns_core::QueryResult {
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
        config.expansion_policy = ExpansionPolicy::None;
        config.start_servers = Some(vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
        let calls = Arc::new(AtomicUsize::new(0));
        config.exchange = Arc::new(CnameOnlyExchange {
            calls: calls.clone(),
        });

        let tree = run(&config, &mut SilentProgress).expect("trace");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(tree.node_count(), 1);
        assert_eq!(tree.leaf().hop.qtype, "CNAME");
    }

    #[test]
    fn a_query_with_follow_continues_past_cname() {
        let qname = DomainName::parse("www.example.com.").expect("qname");
        let mut config = TraceConfig::new(qname, RecordType::A);
        config.follow_aliases = true;
        config.expansion_policy = ExpansionPolicy::None;
        config.start_servers = Some(vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
        let calls = Arc::new(AtomicUsize::new(0));
        config.exchange = Arc::new(CnameOnlyExchange {
            calls: calls.clone(),
        });

        let tree = run(&config, &mut SilentProgress).expect("trace");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(tree.request.qname, "www.example.com.");
        assert!(tree.node_count() >= 2);
    }

    fn find_hop_nodes<'a>(root: &'a TraceNode, qname: &str) -> Vec<&'a TraceNode> {
        let mut matches = Vec::new();
        collect_hop_nodes(root, qname, &mut matches);
        matches
    }

    fn collect_hop_nodes<'a>(node: &'a TraceNode, qname: &str, matches: &mut Vec<&'a TraceNode>) {
        let target = qname.trim_end_matches('.').to_ascii_lowercase();
        let hop_qname = node.hop.qname.trim_end_matches('.').to_ascii_lowercase();
        if hop_qname == target {
            matches.push(node);
        }
        for child in &node.children {
            collect_hop_nodes(child, qname, matches);
        }
    }

    fn count_root_zone_starts(root: &TraceNode, qname: &str) -> usize {
        let target = qname.trim_end_matches('.').to_ascii_lowercase();
        fn walk(node: &TraceNode, qname: &str) -> usize {
            let mut count = 0;
            if node.hop.zone.trim_end_matches('.').is_empty()
                && node
                    .hop
                    .qname
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(qname)
            {
                count += 1;
            }
            for child in &node.children {
                count += walk(child, qname);
            }
            count
        }
        walk(root, &target)
    }

    #[test]
    fn last_policy_with_follow_preserves_original_qname() {
        let qname = DomainName::parse("www.example.com.").expect("qname");
        let mut config = TraceConfig::new(qname, RecordType::A);
        config.follow_aliases = true;
        config.expansion_policy = ExpansionPolicy::Last;
        config.start_servers = Some(vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
        config.exchange = Arc::new(MultiNsDelegatingExchange);

        let tree = run(&config, &mut SilentProgress).expect("trace");
        assert_eq!(tree.request.qname, "www.example.com.");
    }

    fn find_first_leg_terminal(root: &TraceNode) -> Option<&TraceNode> {
        let mut current = root;
        loop {
            let first = current.children.first()?;
            if is_root_zone(&first.hop.zone) {
                return Some(current);
            }
            current = first;
        }
    }

    fn answered_hops_at_zone<'a>(
        root: &'a TraceNode,
        qname: &str,
        zone: &str,
    ) -> Vec<&'a TraceNode> {
        let target_qname = qname.trim_end_matches('.').to_ascii_lowercase();
        let target_zone = zone.trim_end_matches('.').to_ascii_lowercase();
        find_hop_nodes(root, qname)
            .into_iter()
            .filter(|node| {
                node.hop.outcome == HopOutcome::Answered
                    && node.hop.zone.trim_end_matches('.').to_ascii_lowercase() == target_zone
                    && node.hop.qname.trim_end_matches('.').to_ascii_lowercase() == target_qname
            })
            .collect()
    }

    #[test]
    fn last_policy_with_follow_defers_expansion_on_cname_leg() {
        let qname = DomainName::parse("www.example.com.").expect("qname");
        let mut config = TraceConfig::new(qname, RecordType::A);
        config.follow_aliases = true;
        config.expansion_policy = ExpansionPolicy::Last;
        config.start_servers = Some(vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
        config.exchange = Arc::new(MultiNsDelegatingExchange);

        let tree = run(&config, &mut SilentProgress).expect("trace");

        let terminal = find_first_leg_terminal(&tree.root).expect("first-leg terminal hop");
        assert_eq!(
            terminal.hop.zone.trim_end_matches('.'),
            "example.com",
            "alias terminal hop should be at the authoritative example.com zone cut"
        );
        assert_eq!(
            terminal.children.len(),
            1,
            "alias leg should attach as a single subtree (no sibling fan-out on CNAME leg)"
        );
        assert!(
            is_root_zone(&terminal.children[0].hop.zone),
            "alias leg should restart at the root zone"
        );
        assert_eq!(
            answered_hops_at_zone(&tree.root, "www.example.com.", "example.com").len(),
            1,
            "only one terminal answered hop for www at the example.com zone cut"
        );
    }

    #[test]
    fn last_policy_with_follow_stores_cname_on_terminal_hop() {
        let qname = DomainName::parse("www.example.com.").expect("qname");
        let mut config = TraceConfig::new(qname, RecordType::A);
        config.follow_aliases = true;
        config.expansion_policy = ExpansionPolicy::Last;
        config.start_servers = Some(vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
        config.exchange = Arc::new(MultiNsDelegatingExchange);

        let tree = run(&config, &mut SilentProgress).expect("trace");
        let terminal = find_first_leg_terminal(&tree.root).expect("first-leg terminal hop");
        assert!(
            terminal
                .hop
                .response
                .answers
                .iter()
                .any(|record| record.rtype == "CNAME" && record.rdata == "example.com."),
            "terminal hop on the alias leg should retain the CNAME answer"
        );
    }

    #[test]
    fn last_policy_with_follow_expands_only_final_leg() {
        let qname = DomainName::parse("www.example.com.").expect("qname");
        let mut config = TraceConfig::new(qname, RecordType::A);
        config.follow_aliases = true;
        config.expansion_policy = ExpansionPolicy::Last;
        config.start_servers = Some(vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
        config.exchange = Arc::new(MultiNsDelegatingExchange);

        let tree = run(&config, &mut SilentProgress).expect("trace");

        let path = tree.primary_path();
        let parent = path.iter().rev().nth(1).expect("terminal delegation hop");
        assert_eq!(
            parent.children.len(),
            3,
            "terminal cut on the final alias leg should expand all parent-referral NS"
        );
    }

    #[test]
    fn last_policy_with_follow_traces_final_leg_once() {
        let qname = DomainName::parse("www.example.com.").expect("qname");
        let mut config = TraceConfig::new(qname, RecordType::A);
        config.follow_aliases = true;
        config.expansion_policy = ExpansionPolicy::Last;
        config.start_servers = Some(vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
        config.exchange = Arc::new(MultiNsDelegatingExchange);

        let tree = run(&config, &mut SilentProgress).expect("trace");

        assert_eq!(
            count_root_zone_starts(&tree.root, "example.com."),
            1,
            "following a CNAME must not restart the alias target delegation twice"
        );
    }

    struct RecordingProgress {
        hops: Arc<AtomicUsize>,
    }

    impl crate::TraceProgress for RecordingProgress {
        fn hop(&mut self, _hop: &crate::TraceHop, _path: &NodePath) {
            self.hops.fetch_add(1, Ordering::SeqCst);
        }

        fn message(&mut self, _message: &str) {}
    }

    #[test]
    fn nameserver_subtrace_does_not_emit_live_hops() {
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
                rdata: "ns.outside.example.".into(),
            }],
            additionals: vec![],
            edns: EdnsMeta::default(),
        };
        let parent_zone = DomainName::parse("com.").expect("zone");
        let ns_name = DomainName::parse("ns.outside.example.").expect("ns");
        let mut config = TraceConfig::new(
            DomainName::parse("example.com.").expect("qname"),
            RecordType::A,
        );
        config.exchange = Arc::new(AuthoritativeExchange);
        let mut budget = QueryBudget::new(64);
        let hops = Arc::new(AtomicUsize::new(0));
        let mut progress = RecordingProgress { hops: hops.clone() };

        let addresses = resolve_nameserver(
            &ns_name,
            &referral,
            &[ServerTarget::from_address(IpAddr::V4(Ipv4Addr::new(
                1, 1, 1, 1,
            )))],
            &config,
            &mut budget,
            &parent_zone,
            &mut progress,
        )
        .expect("addresses");

        assert!(!addresses.is_empty());
        assert_eq!(
            hops.load(Ordering::SeqCst),
            0,
            "nested NS-resolution traces must not emit hops on the caller progress sink"
        );
    }

    #[test]
    fn glueless_ns_resolution_does_not_consume_action_budget() {
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
                rdata: "ns.outside.example.".into(),
            }],
            additionals: vec![],
            edns: EdnsMeta::default(),
        };
        let parent_zone = DomainName::parse("com.").expect("zone");
        let ns_name = DomainName::parse("ns.outside.example.").expect("ns");
        let mut config = TraceConfig::new(
            DomainName::parse("example.com.").expect("qname"),
            RecordType::A,
        );
        config.exchange = Arc::new(AuthoritativeExchange);
        let mut budget = QueryBudget::new(5);
        let mut progress = SilentProgress;

        let addresses = resolve_nameserver(
            &ns_name,
            &referral,
            &[ServerTarget::from_address(IpAddr::V4(Ipv4Addr::new(
                1, 1, 1, 1,
            )))],
            &config,
            &mut budget,
            &parent_zone,
            &mut progress,
        )
        .expect("addresses");

        assert!(!addresses.is_empty());
        assert_eq!(
            budget.remaining(),
            5,
            "glueless NS resolution must not consume trace.max_queries_per_action"
        );
        assert!(!budget.truncated);
    }

    #[test]
    fn ns_resolution_subtrace_writes_response_cache_entries() {
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
                rdata: "ns.outside.example.".into(),
            }],
            additionals: vec![],
            edns: EdnsMeta::default(),
        };
        let parent_zone = DomainName::parse("com.").expect("zone");
        let ns_name = DomainName::parse("ns.outside.example.").expect("ns");
        let mut config = TraceConfig::new(
            DomainName::parse("example.com.").expect("qname"),
            RecordType::A,
        );
        config.exchange = Arc::new(AuthoritativeExchange);
        let cache = config.with_memory_cache();
        let mut budget = QueryBudget::new(64);
        let mut progress = SilentProgress;

        assert_eq!(cache.stats().entries, 0);

        let addresses = resolve_nameserver(
            &ns_name,
            &referral,
            &[ServerTarget::from_address(IpAddr::V4(Ipv4Addr::new(
                1, 1, 1, 1,
            )))],
            &config,
            &mut budget,
            &parent_zone,
            &mut progress,
        )
        .expect("addresses");
        assert!(!addresses.is_empty());
        assert!(
            cache.stats().entries > 0,
            "glueless NS resolution queries should populate the response cache"
        );
    }

    #[test]
    fn glue_preferred_over_ns_target_cache() {
        let glueless_referral = DnsResponse {
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
                rdata: "ns.outside.example.".into(),
            }],
            additionals: vec![],
            edns: EdnsMeta::default(),
        };
        let glued_referral = DnsResponse {
            additionals: vec![DnsRecord {
                name: DomainName::parse("ns.outside.example.").expect("ns"),
                rtype: "A".into(),
                rclass: "IN".into(),
                ttl: 3600,
                rdata: "93.184.216.34".into(),
            }],
            ..glueless_referral.clone()
        };
        let parent_zone = DomainName::parse("com.").expect("zone");
        let ns_name = DomainName::parse("ns.outside.example.").expect("ns");

        struct DistinctAddressExchange;

        impl crate::DnsExchange for DistinctAddressExchange {
            fn exchange(
                &self,
                server: IpAddr,
                _port: u16,
                options: &dns_core::QueryOptions,
            ) -> dns_core::Result<dns_core::response::QueryResult> {
                Ok(dns_core::response::QueryResult {
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
                        truncated: false,
                        recursion_desired: false,
                        recursion_available: false,
                        authentic_data: false,
                        checking_disabled: false,
                        answers: vec![DnsRecord {
                            name: options.qname.clone(),
                            rtype: "A".into(),
                            rclass: "IN".into(),
                            ttl: 300,
                            rdata: "1.2.3.4".into(),
                        }],
                        authorities: vec![],
                        additionals: vec![],
                        edns: EdnsMeta::default(),
                    },
                    from_cache: false,
                })
            }
        }

        let mut config = TraceConfig::new(
            DomainName::parse("example.com.").expect("qname"),
            RecordType::A,
        );
        config.exchange = Arc::new(DistinctAddressExchange);
        let mut budget = QueryBudget::new(64);
        let mut progress = SilentProgress;
        let servers = [ServerTarget::from_address(IpAddr::V4(Ipv4Addr::new(
            1, 1, 1, 1,
        )))];

        let cached = resolve_nameserver(
            &ns_name,
            &glueless_referral,
            &servers,
            &config,
            &mut budget,
            &parent_zone,
            &mut progress,
        )
        .expect("cached resolution");
        assert_eq!(
            cached[0].address,
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            "fixture setup should cache the queried address"
        );

        let glued = resolve_nameserver(
            &ns_name,
            &glued_referral,
            &servers,
            &config,
            &mut budget,
            &parent_zone,
            &mut progress,
        )
        .expect("glued resolution");

        assert_eq!(
            glued,
            vec![ServerTarget::with_name(
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
                "ns.outside.example."
            )]
        );
    }

    #[test]
    fn ns_target_cache_reuses_nameserver_within_trace() {
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
                rdata: "ns.outside.example.".into(),
            }],
            additionals: vec![],
            edns: EdnsMeta::default(),
        };
        let parent_zone = DomainName::parse("com.").expect("zone");
        let ns_name = DomainName::parse("ns.outside.example.").expect("ns");
        let calls = Arc::new(AtomicUsize::new(0));

        struct CountingAuthoritativeExchange {
            calls: Arc<AtomicUsize>,
        }

        impl crate::DnsExchange for CountingAuthoritativeExchange {
            fn exchange(
                &self,
                server: IpAddr,
                _port: u16,
                options: &dns_core::QueryOptions,
            ) -> dns_core::Result<dns_core::response::QueryResult> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                AuthoritativeExchange.exchange(server, _port, options)
            }
        }

        let mut config = TraceConfig::new(
            DomainName::parse("example.com.").expect("qname"),
            RecordType::A,
        );
        config.exchange = Arc::new(CountingAuthoritativeExchange {
            calls: calls.clone(),
        });
        let mut budget = QueryBudget::new(64);
        let mut progress = SilentProgress;
        let servers = [ServerTarget::from_address(IpAddr::V4(Ipv4Addr::new(
            1, 1, 1, 1,
        )))];

        let first = resolve_nameserver(
            &ns_name,
            &referral,
            &servers,
            &config,
            &mut budget,
            &parent_zone,
            &mut progress,
        )
        .expect("first resolution");
        let calls_after_first = calls.load(Ordering::SeqCst);

        let second = resolve_nameserver(
            &ns_name,
            &referral,
            &servers,
            &config,
            &mut budget,
            &parent_zone,
            &mut progress,
        )
        .expect("second resolution");

        assert_eq!(first, second);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            calls_after_first,
            "second resolve_nameserver should reuse ns_target_cache"
        );
    }

    #[test]
    fn query_all_records_each_server() {
        let servers = vec![
            ServerTarget::from_address(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            ServerTarget::from_address(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))),
        ];
        let calls = Arc::new(AtomicUsize::new(0));

        struct CountingExchange {
            calls: Arc<AtomicUsize>,
        }

        impl crate::DnsExchange for CountingExchange {
            fn exchange(
                &self,
                server: IpAddr,
                _port: u16,
                options: &dns_core::QueryOptions,
            ) -> dns_core::Result<dns_core::QueryResult> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(dns_core::QueryResult {
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

        let config = test_config(
            "example.com.",
            Arc::new(CountingExchange {
                calls: calls.clone(),
            }),
        );
        let mut budget = QueryBudget::new(64);
        let qname = DomainName::parse("example.com.").expect("qname");
        let attempts = query_all(&servers, &config, &mut budget, &qname, RecordType::A);
        assert_eq!(attempts.len(), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn budget_stops_query_all_early() {
        let servers = (0..5)
            .map(|octet| ServerTarget::from_address(IpAddr::V4(Ipv4Addr::new(octet, 0, 0, 1))))
            .collect::<Vec<_>>();
        let calls = Arc::new(AtomicUsize::new(0));

        struct CountingExchange {
            calls: Arc<AtomicUsize>,
        }

        impl crate::DnsExchange for CountingExchange {
            fn exchange(
                &self,
                server: IpAddr,
                _port: u16,
                options: &dns_core::QueryOptions,
            ) -> dns_core::Result<dns_core::QueryResult> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(dns_core::QueryResult {
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

        let config = test_config("example.com.", Arc::new(CountingExchange { calls }));
        let mut budget = QueryBudget::new(2);
        let qname = DomainName::parse("example.com.").expect("qname");
        let attempts = query_all(&servers, &config, &mut budget, &qname, RecordType::A);
        assert_eq!(attempts.len(), 2);
        assert!(budget.truncated);
    }

    #[test]
    fn none_policy_trace_is_linear() {
        let mut config = test_config("example.com.", Arc::new(AuthoritativeExchange));
        config.expansion_policy = ExpansionPolicy::None;
        let tree = run(&config, &mut SilentProgress).expect("trace");
        assert!(tree.root.children.len() <= 1);
        assert!(!tree.budget_truncated);
    }

    #[test]
    fn last_policy_expands_terminal_cut_to_siblings() {
        let mut config = test_config("example.com.", Arc::new(MultiNsDelegatingExchange));
        config.expansion_policy = ExpansionPolicy::Last;
        config.start_servers = Some(vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
        let tree = run(&config, &mut SilentProgress).expect("trace");
        let path = tree.primary_path();
        let parent = path.iter().rev().nth(1).expect("delegation hop");
        assert!(
            parent.children.len() >= 2,
            "terminal cut should expand to multiple siblings"
        );
    }

    #[test]
    fn last_policy_expands_all_parent_referral_nameservers() {
        let mut config = test_config("example.com.", Arc::new(MultiNsDelegatingExchange));
        config.expansion_policy = ExpansionPolicy::Last;
        config.start_servers = Some(vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
        let tree = run(&config, &mut SilentProgress).expect("trace");
        let path = tree.primary_path();
        let parent = path.iter().rev().nth(1).expect("delegation hop");
        assert_eq!(
            parent.children.len(),
            3,
            "terminal cut should query every NS from the parent delegation"
        );
    }

    #[test]
    fn resolve_all_nameserver_targets_returns_one_per_ns() {
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
                    rdata: "ns1.example.com.".into(),
                },
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
                    rdata: "ns3.example.com.".into(),
                },
            ],
            additionals: vec![
                DnsRecord {
                    name: DomainName::parse("ns1.example.com.").expect("ns"),
                    rtype: "A".into(),
                    rclass: "IN".into(),
                    ttl: 300,
                    rdata: "1.0.0.1".into(),
                },
                DnsRecord {
                    name: DomainName::parse("ns2.example.com.").expect("ns"),
                    rtype: "A".into(),
                    rclass: "IN".into(),
                    ttl: 300,
                    rdata: "2.0.0.2".into(),
                },
                DnsRecord {
                    name: DomainName::parse("ns3.example.com.").expect("ns"),
                    rtype: "A".into(),
                    rclass: "IN".into(),
                    ttl: 300,
                    rdata: "3.0.0.3".into(),
                },
            ],
            edns: EdnsMeta::default(),
        };
        let parent_zone = DomainName::parse("com.").expect("zone");
        let config = TraceConfig::new(
            DomainName::parse("example.com.").expect("qname"),
            RecordType::A,
        );
        let mut budget = QueryBudget::new(64);

        let targets = resolve_all_nameserver_targets_from_referral(
            &referral,
            &[ServerTarget::from_address(IpAddr::V4(Ipv4Addr::new(
                1, 1, 1, 1,
            )))],
            &config,
            &mut budget,
            &parent_zone,
            &mut SilentProgress,
        )
        .expect("targets");

        assert_eq!(targets.len(), 3);
        assert!(
            targets
                .iter()
                .any(|target| target.address == IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)))
        );
        assert!(
            targets
                .iter()
                .any(|target| target.address == IpAddr::V4(Ipv4Addr::new(2, 0, 0, 2)))
        );
        assert!(
            targets
                .iter()
                .any(|target| target.address == IpAddr::V4(Ipv4Addr::new(3, 0, 0, 3)))
        );
    }

    #[test]
    fn all_policy_queries_each_start_server() {
        let calls = Arc::new(AtomicUsize::new(0));

        struct CountingAuth(Arc<AtomicUsize>);

        impl crate::DnsExchange for CountingAuth {
            fn exchange(
                &self,
                server: IpAddr,
                _port: u16,
                options: &dns_core::QueryOptions,
            ) -> dns_core::Result<dns_core::QueryResult> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(dns_core::QueryResult {
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
                        truncated: false,
                        recursion_desired: false,
                        recursion_available: false,
                        authentic_data: false,
                        checking_disabled: false,
                        answers: vec![DnsRecord {
                            name: options.qname.clone(),
                            rtype: "A".into(),
                            rclass: "IN".into(),
                            ttl: 300,
                            rdata: "93.184.216.34".into(),
                        }],
                        authorities: vec![],
                        additionals: vec![],
                        edns: EdnsMeta::default(),
                    },
                    from_cache: false,
                })
            }
        }

        let mut config = test_config("example.com.", Arc::new(CountingAuth(calls.clone())));
        config.expansion_policy = ExpansionPolicy::All;
        config.start_servers = Some(vec![
            IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(2, 0, 0, 1)),
        ]);
        let _tree = run(&config, &mut SilentProgress).expect("trace");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    struct AuthoritativeExchange;

    impl crate::DnsExchange for AuthoritativeExchange {
        fn exchange(
            &self,
            server: IpAddr,
            _port: u16,
            options: &dns_core::QueryOptions,
        ) -> dns_core::Result<dns_core::QueryResult> {
            Ok(dns_core::QueryResult {
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
                    truncated: false,
                    recursion_desired: false,
                    recursion_available: false,
                    authentic_data: false,
                    checking_disabled: false,
                    answers: vec![DnsRecord {
                        name: options.qname.clone(),
                        rtype: "A".into(),
                        rclass: "IN".into(),
                        ttl: 300,
                        rdata: "93.184.216.34".into(),
                    }],
                    authorities: vec![],
                    additionals: vec![],
                    edns: EdnsMeta::default(),
                },
                from_cache: false,
            })
        }
    }

    struct MultiNsDelegatingExchange;

    impl crate::DnsExchange for MultiNsDelegatingExchange {
        fn exchange(
            &self,
            server: IpAddr,
            _port: u16,
            options: &dns_core::QueryOptions,
        ) -> dns_core::Result<dns_core::QueryResult> {
            let qname = options.qname.to_string();
            let is_example_zone_ns = matches!(
                server,
                IpAddr::V4(v4)
                    if matches!(v4.octets(), [1, 0, 0, 1] | [2, 0, 0, 2] | [3, 0, 0, 3])
            );
            let is_example_qname = qname == "example.com." || qname == "www.example.com.";
            let (authoritative, answers, authorities, additionals) =
                if qname == "www.example.com." && is_example_zone_ns {
                    (
                        true,
                        vec![DnsRecord {
                            name: options.qname.clone(),
                            rtype: "CNAME".into(),
                            rclass: "IN".into(),
                            ttl: 300,
                            rdata: "example.com.".into(),
                        }],
                        vec![],
                        vec![],
                    )
                } else if qname == "example.com." && is_example_zone_ns {
                    (
                        true,
                        vec![DnsRecord {
                            name: options.qname.clone(),
                            rtype: "A".into(),
                            rclass: "IN".into(),
                            ttl: 300,
                            rdata: "93.184.216.34".into(),
                        }],
                        vec![],
                        vec![],
                    )
                } else if is_example_qname && server == IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)) {
                    (
                        false,
                        vec![],
                        vec![DnsRecord {
                            name: DomainName::parse("com.").expect("zone"),
                            rtype: "NS".into(),
                            rclass: "IN".into(),
                            ttl: 3600,
                            rdata: "ns.com.".into(),
                        }],
                        vec![DnsRecord {
                            name: DomainName::parse("ns.com.").expect("ns"),
                            rtype: "A".into(),
                            rclass: "IN".into(),
                            ttl: 300,
                            rdata: "192.41.162.30".into(),
                        }],
                    )
                } else if is_example_qname {
                    (
                        false,
                        vec![],
                        vec![
                            DnsRecord {
                                name: DomainName::parse("example.com.").expect("zone"),
                                rtype: "NS".into(),
                                rclass: "IN".into(),
                                ttl: 3600,
                                rdata: "ns1.example.com.".into(),
                            },
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
                                rdata: "ns3.example.com.".into(),
                            },
                        ],
                        vec![
                            DnsRecord {
                                name: DomainName::parse("ns1.example.com.").expect("ns"),
                                rtype: "A".into(),
                                rclass: "IN".into(),
                                ttl: 300,
                                rdata: "1.0.0.1".into(),
                            },
                            DnsRecord {
                                name: DomainName::parse("ns2.example.com.").expect("ns"),
                                rtype: "A".into(),
                                rclass: "IN".into(),
                                ttl: 300,
                                rdata: "2.0.0.2".into(),
                            },
                            DnsRecord {
                                name: DomainName::parse("ns3.example.com.").expect("ns"),
                                rtype: "A".into(),
                                rclass: "IN".into(),
                                ttl: 300,
                                rdata: "3.0.0.3".into(),
                            },
                        ],
                    )
                } else {
                    (
                        false,
                        vec![],
                        vec![DnsRecord {
                            name: DomainName::parse("com.").expect("zone"),
                            rtype: "NS".into(),
                            rclass: "IN".into(),
                            ttl: 3600,
                            rdata: "ns.com.".into(),
                        }],
                        vec![],
                    )
                };

            Ok(dns_core::QueryResult {
                server,
                transport: options.transport,
                qname: options.qname.clone(),
                qtype: options.qtype.to_string(),
                rtt: Duration::from_millis(1),
                response: DnsResponse {
                    id: 1,
                    rcode: 0,
                    rcode_text: "NOERROR".into(),
                    authoritative,
                    truncated: false,
                    recursion_desired: false,
                    recursion_available: false,
                    authentic_data: false,
                    checking_disabled: false,
                    answers,
                    authorities,
                    additionals,
                    edns: EdnsMeta::default(),
                },
                from_cache: false,
            })
        }
    }
}
