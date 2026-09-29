use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use dns_core::name::DomainName;
use dns_resolve::trace::{
    dns_response_from_stored, expansion_targets_for_cut, resolve_nameserver_target_for_referral,
    server_matches_primary, server_target_from_hop,
};
use dns_resolve::{
    NodeOrigin, NodePath, QueryBudget, ServerTarget, TraceConfig, TraceNode, TraceProgress,
};

use super::{BranchError, ServerTargetInput};

pub fn parse_server_target(value: &str) -> Result<ServerTargetInput, BranchError> {
    let value = value.trim();
    if let Some(address) = value.strip_prefix('@') {
        let addr = IpAddr::from_str(address).map_err(|_| BranchError::InvalidServer {
            value: value.into(),
        })?;
        return Ok(ServerTargetInput::Address(addr));
    }
    if value.parse::<IpAddr>().is_ok() {
        return Ok(ServerTargetInput::Address(
            IpAddr::from_str(value).expect("checked above"),
        ));
    }
    Ok(ServerTargetInput::Name(value.to_string()))
}

fn subtree_covers_ns_name(
    cut_hop: &dns_resolve::TraceHop,
    ns_name: &DomainName,
    queried_children: &[&TraceNode],
) -> bool {
    queried_children
        .iter()
        .any(|child| node_tree_covers_ns(cut_hop, ns_name, child))
}

fn node_tree_covers_ns(
    cut_hop: &dns_resolve::TraceHop,
    ns_name: &DomainName,
    node: &TraceNode,
) -> bool {
    if hop_matches_ns_at_cut(cut_hop, ns_name, &node.hop) {
        return true;
    }
    node.children
        .iter()
        .any(|child| node_tree_covers_ns(cut_hop, ns_name, child))
}

fn hop_matches_ns_at_cut(
    cut_hop: &dns_resolve::TraceHop,
    ns_name: &DomainName,
    hop: &dns_resolve::TraceHop,
) -> bool {
    if hop
        .server_name
        .as_deref()
        .is_some_and(|name| normalize_ns_name(name) == normalize_ns_name(ns_name.as_str()))
    {
        return true;
    }
    if let Some(glue_ip) = glue_ip_for_ns(cut_hop, ns_name) {
        if let Ok(target) = server_target_from_hop(hop) {
            return target.address == glue_ip;
        }
    }
    false
}

fn glue_ip_for_ns(cut_hop: &dns_resolve::TraceHop, ns_name: &DomainName) -> Option<IpAddr> {
    let normalized = normalize_ns_name(ns_name.as_str());
    if !cut_hop.referral_ns.is_empty() {
        if let Some(index) = cut_hop
            .referral_ns
            .iter()
            .position(|ns| normalize_ns_name(ns) == normalized)
        {
            if let Some(glue) = cut_hop.glue.get(index) {
                return glue.parse().ok();
            }
        }
    }
    let referral = referral_for_hop(cut_hop)?;
    let ns_names = referral_ns_names(cut_hop, Some(&referral));
    let index = ns_names
        .iter()
        .position(|name| normalize_ns_name(name.as_str()) == normalized)?;
    cut_hop.glue.get(index)?.parse().ok()
}

pub(crate) fn nameserver_satisfied_at_cut(
    cut_hop: &dns_resolve::TraceHop,
    cut_is_session_root: bool,
    ns_name: &DomainName,
    queried_children: &[&TraceNode],
) -> bool {
    if cut_is_session_root && cut_hop.zone == "." {
        queried_children.iter().any(|child| {
            delegation_hop_for_cut_child(cut_hop, child)
                .is_some_and(|hop| hop_matches_ns_at_cut(cut_hop, ns_name, &hop))
        })
    } else {
        subtree_covers_ns_name(cut_hop, ns_name, queried_children)
    }
}

fn delegation_hop_for_cut_child(
    cut_hop: &dns_resolve::TraceHop,
    child: &TraceNode,
) -> Option<dns_resolve::TraceHop> {
    let mut node = child;
    loop {
        if node.hop.zone != cut_hop.zone {
            return Some(node.hop.clone());
        }
        match node.children.as_slice() {
            [] => return None,
            [only] => node = only,
            _ => return None,
        }
    }
}

pub(crate) fn apply_branch_origin(node: &mut TraceNode, origin: NodeOrigin) {
    if !matches!(node.origin, NodeOrigin::Branch { .. }) {
        node.origin = origin;
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn expand_cut_targets(
    delegation_hop: &dns_resolve::TraceHop,
    cut_is_session_root: bool,
    queried_children: &[&TraceNode],
    config: &mut TraceConfig,
    budget: &mut QueryBudget,
    progress: &mut dyn TraceProgress,
    warnings: &mut Vec<String>,
    dry_run: bool,
) -> Result<Vec<ServerTarget>, BranchError> {
    let zone = DomainName::parse(&delegation_hop.zone)?;
    let referral = referral_for_hop(delegation_hop);
    let fallback = queried_children
        .iter()
        .filter_map(|child| server_target_from_hop(&child.hop).ok())
        .collect::<Vec<_>>();

    let ns_names = referral_ns_names(delegation_hop, referral.as_ref());
    if ns_names.is_empty() {
        if fallback.is_empty() {
            warnings.push("no nameservers listed at this zone cut".into());
            return Ok(Vec::new());
        }
        warnings.push(
            "referral nameservers unavailable; reusing servers from existing paths only".into(),
        );
        return Ok(filter_unqueried_targets(
            cut_is_session_root,
            delegation_hop,
            &fallback,
            queried_children,
        ));
    }

    let mut targets = Vec::new();
    let mut unresolved_ns = Vec::new();
    let mut last_error = None;

    for ns_name in ns_names {
        if nameserver_satisfied_at_cut(
            delegation_hop,
            cut_is_session_root,
            &ns_name,
            queried_children,
        ) {
            continue;
        }
        if let Some(target) = child_target_for_ns(&ns_name, queried_children) {
            targets.push(target);
            continue;
        }
        unresolved_ns.push(ns_name.clone());
        let Some(referral) = referral.as_ref() else {
            continue;
        };
        match resolve_nameserver_target_for_referral(
            &ns_name, referral, &fallback, config, budget, &zone, progress, dry_run,
        ) {
            Ok(Some(target)) => targets.push(target),
            Ok(None) => {}
            Err(error) => last_error = Some(error),
        }
    }

    let targets = dedupe_server_targets(filter_unqueried_targets(
        cut_is_session_root,
        delegation_hop,
        &targets,
        queried_children,
    ));
    if targets.is_empty() {
        if unresolved_ns.is_empty() {
            warnings.push("all nameservers at this zone cut already queried".into());
            return Ok(Vec::new());
        }
        if let Some(error) = last_error {
            return Err(error.into());
        }
        let names = unresolved_ns
            .iter()
            .map(|name| name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        if dry_run {
            return Ok(unresolved_ns
                .into_iter()
                .map(|ns_name| unresolved_ns_target(&ns_name))
                .collect());
        }
        warnings.push(format!(
            "could not resolve nameserver addresses at this cut: {names}"
        ));
        return Ok(Vec::new());
    }
    Ok(targets)
}

fn unresolved_ns_target(ns_name: &DomainName) -> ServerTarget {
    ServerTarget {
        address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        name: Some(ns_name.to_string()),
    }
}

fn referral_ns_names(
    delegation_hop: &dns_resolve::TraceHop,
    referral: Option<&dns_core::response::DnsResponse>,
) -> Vec<DomainName> {
    if let Some(referral) = referral {
        return referral.ns_names();
    }
    delegation_hop
        .referral_ns
        .iter()
        .filter_map(|ns| DomainName::parse(ns).ok())
        .collect()
}

fn child_target_for_ns(
    ns_name: &DomainName,
    queried_children: &[&TraceNode],
) -> Option<ServerTarget> {
    queried_children
        .iter()
        .find_map(|child| ns_target_in_subtree(ns_name, child))
}

fn ns_target_in_subtree(ns_name: &DomainName, node: &TraceNode) -> Option<ServerTarget> {
    let normalized = normalize_ns_name(ns_name.as_str());
    if node
        .hop
        .server_name
        .as_deref()
        .is_some_and(|name| normalize_ns_name(name) == normalized)
    {
        return server_target_from_hop(&node.hop).ok();
    }
    node.children
        .iter()
        .find_map(|child| ns_target_in_subtree(ns_name, child))
}

pub(crate) fn resolve_alternate_target(
    target: &ServerTargetInput,
    delegation_hop: &dns_resolve::TraceHop,
    queried_children: &[&TraceNode],
    config: &mut TraceConfig,
    budget: &mut QueryBudget,
    progress: &mut dyn TraceProgress,
    warnings: &mut Vec<String>,
) -> Result<Vec<ServerTarget>, BranchError> {
    let resolved = match target {
        ServerTargetInput::Address(address) => vec![ServerTarget::from_address(*address)],
        ServerTargetInput::Name(name) => {
            let zone = DomainName::parse(&delegation_hop.zone)?;
            let referral = referral_for_hop(delegation_hop);
            let all_targets =
                expansion_targets_for_cut(referral.as_ref(), &zone, &[], config, budget, progress)?;
            let normalized = normalize_ns_name(name);
            all_targets
                .into_iter()
                .filter(|server| {
                    server
                        .name
                        .as_deref()
                        .is_some_and(|server_name| normalize_ns_name(server_name) == normalized)
                })
                .collect()
        }
    };

    if resolved.is_empty() {
        return Ok(Vec::new());
    }

    let server = &resolved[0];
    if queried_children
        .iter()
        .any(|child| subtree_queried_primary(server, child))
    {
        warnings.push(format!(
            "server {} was already queried at this zone cut",
            server_label(server)
        ));
        return Ok(Vec::new());
    }

    Ok(vec![server.clone()])
}

fn filter_unqueried_targets(
    cut_is_session_root: bool,
    cut_hop: &dns_resolve::TraceHop,
    targets: &[ServerTarget],
    queried_children: &[&TraceNode],
) -> Vec<ServerTarget> {
    targets
        .iter()
        .filter(|target| {
            if cut_is_session_root && cut_hop.zone == "." {
                !queried_children.iter().any(|child| {
                    delegation_hop_for_cut_child(cut_hop, child).is_some_and(|hop| {
                        server_target_from_hop(&hop).ok().is_some_and(|existing| {
                            server_matches_primary(target, &existing, existing.address)
                        })
                    })
                })
            } else {
                !queried_children
                    .iter()
                    .any(|child| subtree_queried_primary(target, child))
            }
        })
        .cloned()
        .collect()
}

fn subtree_queried_primary(target: &ServerTarget, node: &TraceNode) -> bool {
    if let Ok(existing) = server_target_from_hop(&node.hop) {
        if server_matches_primary(target, &existing, existing.address) {
            return true;
        }
    }
    node.children
        .iter()
        .any(|child| subtree_queried_primary(target, child))
}

fn dedupe_server_targets(targets: Vec<ServerTarget>) -> Vec<ServerTarget> {
    let mut deduped = Vec::with_capacity(targets.len());
    for target in targets {
        if deduped
            .iter()
            .any(|existing| server_matches_primary(&target, existing, existing.address))
        {
            continue;
        }
        deduped.push(target);
    }
    deduped
}

pub(crate) fn parent_path(path: &[usize]) -> Vec<usize> {
    let mut parent = path.to_vec();
    if !parent.is_empty() {
        parent.pop();
    }
    parent
}

pub(crate) fn format_path(path: &NodePath) -> String {
    path.to_string()
}

pub(crate) fn server_label(server: &ServerTarget) -> String {
    match &server.name {
        Some(name) if !name.is_empty() => {
            if server.address.is_unspecified() {
                format!("{name} (needs live resolution, no glue in referral)")
            } else {
                format!("{name} ({})", server.address)
            }
        }
        _ => server.address.to_string(),
    }
}

fn normalize_ns_name(name: &str) -> String {
    let trimmed = name.trim_end_matches('.');
    trimmed.to_ascii_lowercase()
}

fn referral_for_hop(hop: &dns_resolve::TraceHop) -> Option<dns_core::response::DnsResponse> {
    if let Some(response) = dns_response_from_stored(hop) {
        return Some(response);
    }
    if hop.referral_ns.is_empty() {
        return None;
    }
    let zone = DomainName::parse(&hop.zone).ok()?;
    let authorities = hop
        .referral_ns
        .iter()
        .filter_map(|ns| {
            DomainName::parse(ns)
                .ok()
                .map(|name| dns_core::response::DnsRecord {
                    name: zone.clone(),
                    rtype: "NS".into(),
                    rclass: "IN".into(),
                    ttl: 3600,
                    rdata: name.to_string(),
                })
        })
        .collect::<Vec<_>>();
    let mut additionals = Vec::new();
    for (index, ns) in hop.referral_ns.iter().enumerate() {
        let Some(glue_addr) = hop.glue.get(index) else {
            continue;
        };
        let Ok(ns_name) = DomainName::parse(ns) else {
            continue;
        };
        additionals.push(dns_core::response::DnsRecord {
            name: ns_name,
            rtype: "A".into(),
            rclass: "IN".into(),
            ttl: 300,
            rdata: glue_addr.clone(),
        });
    }
    Some(dns_core::response::DnsResponse {
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
        authorities,
        additionals,
        edns: dns_core::EdnsMeta::default(),
    })
}
