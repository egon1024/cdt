use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use dns_core::name::DomainName;
use dns_core::query::record_type_name;
use dns_core::response::DnsResponse;
use hickory_proto::rr::RecordType;

use crate::root_hints::{root_server_names, root_servers};
use crate::{
    ExpansionPolicy, HopOutcome, NodeOrigin, NodePath, QueryBudget, ResolveError, Result,
    ServerTarget, TraceConfig, TraceHop, TraceNode, TraceProgress, TraceTree, TraceTreeRequest,
    filter_addresses, hop_from_query, now_rfc3339, query_server,
};

pub(crate) struct QueryAttempt {
    pub server: ServerTarget,
    pub result: Result<dns_core::QueryResult>,
}

struct PrimaryAttempt {
    server: ServerTarget,
    query_result: dns_core::QueryResult,
    hop: TraceHop,
}

pub fn run(config: &TraceConfig, progress: &mut dyn TraceProgress) -> Result<TraceTree> {
    let mut qname = config.qname.clone();
    let mut alias_visited = HashSet::new();
    let started_at = now_rfc3339();

    if start_servers(config).is_empty() {
        return Err(ResolveError::NoReachableNameserver { zone: ".".into() });
    }

    'restart: loop {
        let mut budget = QueryBudget::new(config.max_queries_per_action);
        let root_zone = DomainName::parse(".").expect("root zone");

        let root = match config.expansion_policy {
            ExpansionPolicy::None => trace_linear(
                config,
                &mut budget,
                progress,
                &NodePath::root(0),
                start_servers(config),
                qname.clone(),
                root_zone,
                &mut HashSet::new(),
            )?,
            ExpansionPolicy::Last => {
                trace_last_policy(config, &mut budget, progress, qname.clone(), root_zone)?
            }
            ExpansionPolicy::All => trace_all_policy(
                config,
                &mut budget,
                progress,
                &NodePath::root(0),
                start_servers(config),
                qname.clone(),
                root_zone,
                &mut HashSet::new(),
                false,
            )?,
        };

        if config.follow_aliases {
            if let Some(alias) = alias_target_from_tree(&root, config.qtype) {
                if alias_visited.len() >= config.max_alias_depth {
                    return Err(ResolveError::MaxAliasDepth {
                        max: config.max_alias_depth,
                    });
                }
                if !alias_visited.insert(alias.clone()) {
                    return Err(ResolveError::AliasLoop { name: alias });
                }
                progress.message(&format!("following alias to {alias}"));
                qname = DomainName::parse(&alias).map_err(ResolveError::Core)?;
                continue 'restart;
            }
        }

        return Ok(TraceTree {
            request: TraceTreeRequest {
                qname: qname.to_string(),
                qtype: record_type_name(config.qtype),
                started_at: started_at.clone(),
            },
            root,
            budget_truncated: budget.truncated,
        });
    }
}

fn alias_target_from_tree(root: &TraceNode, qtype: RecordType) -> Option<String> {
    let leaf = primary_leaf(root);
    let qname = DomainName::parse(&leaf.hop.qname).ok()?;
    let response = dns_response_from_stored(&leaf.hop)?;
    response
        .alias_target(&qname, qtype)
        .map(|name| name.to_string())
}

fn dns_response_from_stored(hop: &TraceHop) -> Option<DnsResponse> {
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

fn trace_last_policy(
    config: &TraceConfig,
    budget: &mut QueryBudget,
    progress: &mut dyn TraceProgress,
    qname: DomainName,
    root_zone: DomainName,
) -> Result<TraceNode> {
    let mut visited_zones = HashSet::new();
    let mut chain: Vec<TraceNode> = Vec::new();
    let mut path_prefix: Vec<usize> = Vec::new();
    let mut servers = start_servers(config);
    let mut current_zone = root_zone.clone();
    let current_qname = qname;
    let mut parent_delegation: Option<DnsResponse> = None;
    let mut parent_delegation_zone = root_zone;

    for depth in 0..config.max_depth {
        let (query_result, server_name) =
            query_one(&servers, config, budget, &current_qname, config.qtype)?;
        let referral_ns = query_result.response.ns_names();
        let glue = collect_glue(&query_result.response, &referral_ns);

        if config.follow_aliases
            && query_result
                .response
                .alias_target(&current_qname, config.qtype)
                .is_some()
        {
            // Outer restart loop handles alias following after the tree is built.
        }

        if is_authoritative_answer(&query_result.response, &current_qname, config.qtype) {
            let primary_server = servers
                .iter()
                .find(|server| server.address == query_result.server)
                .cloned()
                .unwrap_or_else(|| {
                    ServerTarget::with_name(
                        query_result.server,
                        server_name.clone().unwrap_or_default(),
                    )
                });
            let hop = hop_from_query(
                &current_zone,
                &query_result,
                server_name.clone(),
                referral_ns.iter().map(ToString::to_string).collect(),
                glue.iter().map(ToString::to_string).collect(),
                HopOutcome::Answered,
            );
            let expansion_servers = expansion_targets_for_cut(
                parent_delegation.as_ref(),
                &parent_delegation_zone,
                &servers,
                config,
                budget,
                progress,
            )?;
            expand_cut(
                config,
                budget,
                progress,
                &mut chain,
                &path_prefix,
                &expansion_servers,
                &current_zone,
                &current_qname,
                true,
                Some(PrimaryAttempt {
                    server: primary_server,
                    query_result,
                    hop,
                }),
            )?;
            return Ok(link_chain(chain));
        }

        let Some(next_zone) = query_result.response.referral_zone(&current_qname) else {
            let primary_server = servers
                .iter()
                .find(|server| server.address == query_result.server)
                .cloned()
                .unwrap_or_else(|| {
                    ServerTarget::with_name(
                        query_result.server,
                        server_name.clone().unwrap_or_default(),
                    )
                });
            let hop = hop_from_query(
                &current_zone,
                &query_result,
                server_name,
                referral_ns.iter().map(ToString::to_string).collect(),
                glue.iter().map(ToString::to_string).collect(),
                HopOutcome::Answered,
            );
            let expansion_servers = expansion_targets_for_cut(
                parent_delegation.as_ref(),
                &parent_delegation_zone,
                &servers,
                config,
                budget,
                progress,
            )?;
            expand_cut(
                config,
                budget,
                progress,
                &mut chain,
                &path_prefix,
                &expansion_servers,
                &current_zone,
                &current_qname,
                true,
                Some(PrimaryAttempt {
                    server: primary_server,
                    query_result,
                    hop,
                }),
            )?;
            return Ok(link_chain(chain));
        };

        let hop = hop_from_query(
            &current_zone,
            &query_result,
            server_name.clone(),
            referral_ns.iter().map(ToString::to_string).collect(),
            glue.iter().map(ToString::to_string).collect(),
            HopOutcome::Referral,
        );
        let path = node_path(0, &path_prefix);
        progress.hop(&hop, &path);
        chain.push(TraceNode {
            hop,
            origin: NodeOrigin::Trace,
            children: Vec::new(),
        });

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

        parent_delegation = Some(query_result.response.clone());
        parent_delegation_zone = current_zone.clone();

        servers = resolve_nameservers_from_referral(
            &query_result.response,
            &servers,
            config,
            budget,
            &current_zone,
            progress,
        )?;

        if servers.is_empty() {
            return Err(ResolveError::NoReachableNameserver {
                zone: next_zone.to_string(),
            });
        }

        current_zone = next_zone;
        path_prefix.push(0);

        if depth + 1 == config.max_depth - 1 {
            progress.message("approaching maximum delegation depth");
        }
    }

    Err(ResolveError::MaxDepth {
        max: config.max_depth,
    })
}

#[allow(clippy::too_many_arguments)]
fn trace_linear(
    config: &TraceConfig,
    budget: &mut QueryBudget,
    progress: &mut dyn TraceProgress,
    path: &NodePath,
    servers: Vec<ServerTarget>,
    qname: DomainName,
    current_zone: DomainName,
    visited_zones: &mut HashSet<String>,
) -> Result<TraceNode> {
    if path.path.len() >= config.max_depth {
        return Err(ResolveError::MaxDepth {
            max: config.max_depth,
        });
    }

    let path_prefix = path.path.clone();
    let current_qname = qname;

    let (query_result, server_name) =
        query_one(&servers, config, budget, &current_qname, config.qtype)?;
    let referral_ns = query_result.response.ns_names();
    let glue = collect_glue(&query_result.response, &referral_ns);
    let hop = hop_from_query(
        &current_zone,
        &query_result,
        server_name,
        referral_ns.iter().map(ToString::to_string).collect(),
        glue.iter().map(ToString::to_string).collect(),
        HopOutcome::Referral,
    );
    let node_path = node_path(path.tree, &path_prefix);
    progress.hop(&hop, &node_path);

    let mut node = TraceNode {
        hop,
        origin: NodeOrigin::Trace,
        children: Vec::new(),
    };

    if is_authoritative_answer(&query_result.response, &current_qname, config.qtype) {
        node.hop.outcome = HopOutcome::Answered;
        return Ok(node);
    }

    let Some(next_zone) = query_result.response.referral_zone(&current_qname) else {
        node.hop.outcome = HopOutcome::Answered;
        return Ok(node);
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

    let next_servers = resolve_nameservers_from_referral(
        &query_result.response,
        &servers,
        config,
        budget,
        &current_zone,
        progress,
    )?;

    if next_servers.is_empty() {
        return Err(ResolveError::NoReachableNameserver {
            zone: next_zone.to_string(),
        });
    }

    let child = trace_linear(
        config,
        budget,
        progress,
        &node_path,
        next_servers,
        current_qname,
        next_zone,
        visited_zones,
    )?;
    node.children.push(child);
    Ok(node)
}

#[allow(clippy::too_many_arguments)]
fn trace_all_policy(
    config: &TraceConfig,
    budget: &mut QueryBudget,
    progress: &mut dyn TraceProgress,
    path: &NodePath,
    servers: Vec<ServerTarget>,
    qname: DomainName,
    current_zone: DomainName,
    visited_zones: &mut HashSet<String>,
    force_single: bool,
) -> Result<TraceNode> {
    if force_single {
        return trace_linear(
            config,
            budget,
            progress,
            path,
            servers,
            qname,
            current_zone,
            visited_zones,
        );
    }

    let attempts = query_all(&servers, config, budget, &qname, config.qtype);
    if attempts.is_empty() && budget.truncated {
        progress.budget_truncated(budget.cap());
        return Err(ResolveError::NoReachableNameserver {
            zone: current_zone.to_string(),
        });
    }

    let mut siblings = Vec::new();
    for (index, attempt) in attempts.into_iter().enumerate() {
        let mut child_path = path.path.clone();
        child_path.push(index);
        let child_path = node_path(path.tree, &child_path);

        match attempt.result {
            Ok(query_result) => {
                let referral_ns = query_result.response.ns_names();
                let glue = collect_glue(&query_result.response, &referral_ns);
                let hop = hop_from_query(
                    &current_zone,
                    &query_result,
                    attempt.server.name.clone(),
                    referral_ns.iter().map(ToString::to_string).collect(),
                    glue.iter().map(ToString::to_string).collect(),
                    HopOutcome::Referral,
                );
                progress.hop(&hop, &child_path);
                let mut node = TraceNode {
                    hop,
                    origin: NodeOrigin::Trace,
                    children: Vec::new(),
                };

                if is_authoritative_answer(&query_result.response, &qname, config.qtype) {
                    node.hop.outcome = HopOutcome::Answered;
                    siblings.push(node);
                    continue;
                }

                let Some(next_zone) = query_result.response.referral_zone(&qname) else {
                    node.hop.outcome = HopOutcome::Answered;
                    siblings.push(node);
                    continue;
                };

                if !visited_zones.insert(next_zone.to_string()) {
                    node.hop.outcome = HopOutcome::Failed {
                        kind: "delegation_loop".into(),
                        detail: next_zone.to_string(),
                    };
                    siblings.push(node);
                    continue;
                }

                let next_servers = resolve_nameservers_from_referral(
                    &query_result.response,
                    &servers,
                    config,
                    budget,
                    &current_zone,
                    progress,
                );

                match next_servers {
                    Ok(next_servers) if !next_servers.is_empty() => {
                        let subtree = trace_all_policy(
                            config,
                            budget,
                            progress,
                            &child_path,
                            next_servers,
                            qname.clone(),
                            next_zone,
                            visited_zones,
                            false,
                        )?;
                        node.children.push(subtree);
                    }
                    Ok(_) => {
                        node.hop.outcome = HopOutcome::Failed {
                            kind: "no_reachable_nameserver".into(),
                            detail: next_zone.to_string(),
                        };
                    }
                    Err(error) => {
                        node.hop.outcome = HopOutcome::Failed {
                            kind: "nameserver_resolution".into(),
                            detail: error.to_string(),
                        };
                    }
                }
                siblings.push(node);
            }
            Err(error) => {
                let hop = failed_hop(
                    config,
                    &current_zone,
                    &qname,
                    config.qtype,
                    &attempt.server,
                    &error,
                );
                progress.hop(&hop, &child_path);
                siblings.push(TraceNode {
                    hop,
                    origin: NodeOrigin::Trace,
                    children: Vec::new(),
                });
            }
        }
    }

    if budget.truncated {
        progress.budget_truncated(budget.cap());
    }

    if siblings.is_empty() {
        return Err(ResolveError::NoReachableNameserver {
            zone: current_zone.to_string(),
        });
    }

    let mut root = siblings.remove(0);
    root.children.extend(siblings);
    Ok(root)
}

#[allow(clippy::too_many_arguments)]
fn expand_cut(
    config: &TraceConfig,
    budget: &mut QueryBudget,
    progress: &mut dyn TraceProgress,
    chain: &mut Vec<TraceNode>,
    path_prefix: &[usize],
    expansion_servers: &[ServerTarget],
    current_zone: &DomainName,
    qname: &DomainName,
    force_single_subtrees: bool,
    primary: Option<PrimaryAttempt>,
) -> Result<()> {
    let attempts = query_expansion_servers(
        expansion_servers,
        config,
        budget,
        qname,
        config.qtype,
        primary.as_ref(),
    );
    let mut siblings = Vec::new();
    let mut seen_referrals: HashMap<String, ()> = HashMap::new();

    for (index, attempt) in attempts.into_iter().enumerate() {
        let mut sibling_path = path_prefix.to_vec();
        if chain.len() <= 1 {
            sibling_path.push(index);
        } else {
            sibling_path.pop();
            sibling_path.push(index);
        }
        let sibling_path = node_path(0, &sibling_path);

        match attempt.result {
            Ok(query_result) => {
                if let Some(primary_attempt) = primary.as_ref() {
                    if server_matches_primary(&attempt.server, primary_attempt) {
                        progress.hop(&primary_attempt.hop, &sibling_path);
                        siblings.push(TraceNode {
                            hop: primary_attempt.hop.clone(),
                            origin: NodeOrigin::Trace,
                            children: Vec::new(),
                        });
                        continue;
                    }
                }

                let referral_ns = query_result.response.ns_names();
                let glue = collect_glue(&query_result.response, &referral_ns);
                let hop = hop_from_query(
                    current_zone,
                    &query_result,
                    attempt.server.name.clone(),
                    referral_ns.iter().map(ToString::to_string).collect(),
                    glue.iter().map(ToString::to_string).collect(),
                    if is_authoritative_answer(&query_result.response, qname, config.qtype) {
                        HopOutcome::Answered
                    } else {
                        HopOutcome::Referral
                    },
                );
                progress.hop(&hop, &sibling_path);
                let mut node = TraceNode {
                    hop,
                    origin: NodeOrigin::Trace,
                    children: Vec::new(),
                };

                if is_authoritative_answer(&query_result.response, qname, config.qtype) {
                    siblings.push(node);
                    continue;
                }

                if let Some(next_zone) = query_result.response.referral_zone(qname) {
                    let key = referral_key(&query_result.response, qname, &next_zone);
                    if seen_referrals.contains_key(&key) {
                        siblings.push(node);
                        continue;
                    }
                    seen_referrals.insert(key, ());

                    if let Ok(next_servers) = resolve_nameservers_from_referral(
                        &query_result.response,
                        expansion_servers,
                        config,
                        budget,
                        current_zone,
                        progress,
                    ) {
                        if !next_servers.is_empty() {
                            let mut visited = HashSet::new();
                            visited.insert(next_zone.to_string());
                            let subtree = if force_single_subtrees {
                                trace_linear(
                                    config,
                                    budget,
                                    progress,
                                    &sibling_path,
                                    next_servers,
                                    qname.clone(),
                                    next_zone,
                                    &mut visited,
                                )?
                            } else {
                                trace_all_policy(
                                    config,
                                    budget,
                                    progress,
                                    &sibling_path,
                                    next_servers,
                                    qname.clone(),
                                    next_zone,
                                    &mut visited,
                                    false,
                                )?
                            };
                            node.children.push(subtree);
                        }
                    }
                }
                siblings.push(node);
            }
            Err(error) => {
                let hop = failed_hop(
                    config,
                    current_zone,
                    qname,
                    config.qtype,
                    &attempt.server,
                    &error,
                );
                progress.hop(&hop, &sibling_path);
                siblings.push(TraceNode {
                    hop,
                    origin: NodeOrigin::Trace,
                    children: Vec::new(),
                });
            }
        }
    }

    if budget.truncated {
        progress.budget_truncated(budget.cap());
    }

    if siblings.is_empty() {
        return Ok(());
    }

    if chain.is_empty() {
        let mut root = siblings.remove(0);
        root.children.extend(siblings);
        chain.push(root);
    } else {
        let parent_idx = chain.len() - 1;
        chain[parent_idx].children = siblings;
    }

    Ok(())
}

fn referral_key(response: &DnsResponse, qname: &DomainName, next_zone: &DomainName) -> String {
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

fn node_path(tree: usize, path: &[usize]) -> NodePath {
    NodePath {
        tree,
        path: path.to_vec(),
    }
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
        if !budget.try_consume() {
            progress_budget_if_needed(config, budget);
            return Err(
                last_error.unwrap_or_else(|| ResolveError::NoReachableNameserver {
                    zone: qname.to_string(),
                }),
            );
        }
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

pub(crate) fn query_all(
    servers: &[ServerTarget],
    config: &TraceConfig,
    budget: &mut QueryBudget,
    qname: &DomainName,
    qtype: RecordType,
) -> Vec<QueryAttempt> {
    let mut attempts = Vec::new();
    for server in servers {
        if !budget.try_consume() {
            break;
        }
        let result = query_server(server.address, config, qname, qtype);
        attempts.push(QueryAttempt {
            server: server.clone(),
            result,
        });
    }
    attempts
}

fn progress_budget_if_needed(_config: &TraceConfig, _budget: &mut QueryBudget) {}

fn failed_hop(
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

fn expansion_targets_for_cut(
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

fn query_expansion_servers(
    servers: &[ServerTarget],
    config: &TraceConfig,
    budget: &mut QueryBudget,
    qname: &DomainName,
    qtype: RecordType,
    primary: Option<&PrimaryAttempt>,
) -> Vec<QueryAttempt> {
    let mut attempts = Vec::new();
    for server in servers {
        if let Some(primary_attempt) = primary {
            if server_matches_primary(server, primary_attempt) {
                attempts.push(QueryAttempt {
                    server: server.clone(),
                    result: Ok(primary_attempt.query_result.clone()),
                });
                continue;
            }
        }
        if !budget.try_consume() {
            break;
        }
        let result = query_server(server.address, config, qname, qtype);
        attempts.push(QueryAttempt {
            server: server.clone(),
            result,
        });
    }
    attempts
}

fn server_matches_primary(server: &ServerTarget, primary: &PrimaryAttempt) -> bool {
    if server.address == primary.server.address || server.address == primary.query_result.server {
        return true;
    }
    match (&server.name, &primary.server.name) {
        (Some(server_name), Some(primary_name)) => server_name.eq_ignore_ascii_case(primary_name),
        _ => false,
    }
}

fn resolve_nameservers_from_referral(
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
        return Ok(addresses
            .into_iter()
            .map(|address| ServerTarget::with_name(address, ns_name.to_string()))
            .collect());
    }

    progress.message(&format!("resolving addresses for {}", ns_name));

    for qtype in [RecordType::A, RecordType::AAAA] {
        if let Ok((result, _)) = query_one(
            &filter_targets(current_servers, config.ipv4_only, config.ipv6_only),
            config,
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
    sub_config.expansion_policy = ExpansionPolicy::None;
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
        assert_eq!(tree.request.qname, "cdn.example.com.");
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
            let (authoritative, answers, authorities, additionals) = if qname == "example.com."
                && is_example_zone_ns
            {
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
            } else if qname == "example.com." && server == IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)) {
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
            } else if qname == "example.com." {
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
