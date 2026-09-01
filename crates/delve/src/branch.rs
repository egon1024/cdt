use std::net::IpAddr;
use std::str::FromStr;

use dns_core::name::DomainName;
use dns_core::parse_record_type;
use dns_resolve::trace::{
    dns_response_from_stored, expansion_targets_for_cut, resolve_nameserver_target_for_referral,
    seed_ns_targets_from_tree, server_matches_primary, server_target_from_hop,
};
use dns_resolve::{
    BranchIntent, BranchJobRequest, NodeOrigin, NodePath, QueryBudget, ResolveError, ServerTarget,
    TraceConfig, TraceNode, TraceProgress, run_branch_job, run_expand_cut_branch,
};
use thiserror::Error;

use crate::runtime::Runtime;
use crate::session::{SessionDocument, SessionTree};
use crate::trace_config::trace_config_from_request;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchIntentArg {
    AlternateServer { target: ServerTargetInput },
    ExpandCut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerTargetInput {
    Name(String),
    Address(IpAddr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchPlan {
    pub zone: String,
    pub server: String,
    pub qname: String,
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchReport {
    pub nodes_added: usize,
    pub updated_at: Option<String>,
    pub warnings: Vec<String>,
    pub budget_truncated: bool,
    pub dry_run: bool,
    pub plan: Option<BranchPlan>,
}

#[derive(Debug, Error)]
pub enum BranchError {
    #[error(transparent)]
    Resolve(#[from] ResolveError),

    #[error(transparent)]
    Core(#[from] dns_core::DnsCoreError),

    #[error(transparent)]
    Session(#[from] crate::session::SessionError),

    #[error(transparent)]
    TraceConfig(#[from] crate::trace_config::TraceConfigError),

    #[error("session has no trace tree")]
    NoTree,

    #[error("node path {path} does not resolve in session")]
    UnresolvedPath { path: String },

    #[error("display index {index} is out of range")]
    OutOfRangeHop { index: usize },

    #[error("branch requires --server or --expand")]
    MissingTarget,

    #[error("invalid node path: {value}")]
    InvalidPath { value: String },

    #[error("invalid server argument: {value}")]
    InvalidServer { value: String },
}

pub fn parse_node_path(value: &str) -> Result<NodePath, BranchError> {
    if value.is_empty() {
        return Err(BranchError::InvalidPath {
            value: value.into(),
        });
    }
    let mut segments = value.split('.');
    let tree = segments
        .next()
        .ok_or_else(|| BranchError::InvalidPath {
            value: value.into(),
        })?
        .parse::<usize>()
        .map_err(|_| BranchError::InvalidPath {
            value: value.into(),
        })?;
    let path = segments
        .map(|segment| {
            segment
                .parse::<usize>()
                .map_err(|_| BranchError::InvalidPath {
                    value: value.into(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(NodePath { tree, path })
}

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

pub fn resolve_branch_target(
    document: &SessionDocument,
    at_hop: Option<usize>,
    at_path: Option<&str>,
) -> Result<NodePath, BranchError> {
    let tree = document.primary_tree().ok_or(BranchError::NoTree)?;
    if let Some(path_value) = at_path {
        let path = parse_node_path(path_value)?;
        if tree.resolve(&path).is_none() {
            return Err(BranchError::UnresolvedPath {
                path: path_value.into(),
            });
        }
        return Ok(path);
    }
    if let Some(index) = at_hop {
        return tree
            .path_for_display_index(index)
            .ok_or(BranchError::OutOfRangeHop { index });
    }
    Err(BranchError::MissingTarget)
}

pub fn branch_session(
    runtime: &Runtime,
    session_id: &str,
    at: NodePath,
    intent: BranchIntentArg,
    dry_run: bool,
    progress: &mut dyn TraceProgress,
) -> Result<BranchReport, BranchError> {
    let mut document = runtime.get_session(session_id)?;
    let report = execute_branch(&mut document, at, intent, dry_run, runtime, progress, None)?;
    if !dry_run && report.nodes_added > 0 {
        runtime.update_session(&document)?;
    }
    Ok(report)
}

pub fn execute_branch(
    document: &mut SessionDocument,
    at: NodePath,
    intent: BranchIntentArg,
    dry_run: bool,
    runtime: &Runtime,
    progress: &mut dyn TraceProgress,
    exchange_override: Option<std::sync::Arc<dyn dns_resolve::DnsExchange>>,
) -> Result<BranchReport, BranchError> {
    let session_tree =
        document
            .trees
            .get_mut(at.tree)
            .ok_or_else(|| BranchError::UnresolvedPath {
                path: format_path(&at),
            })?;
    let node = session_tree
        .tree
        .resolve(&at)
        .ok_or_else(|| BranchError::UnresolvedPath {
            path: format_path(&at),
        })?;
    let hop = node.hop.clone();

    let (cut_path, selected_path) = cut_context(&at, session_tree)?;
    let cut_node =
        session_tree
            .tree
            .resolve(&cut_path)
            .ok_or_else(|| BranchError::UnresolvedPath {
                path: format_path(&cut_path),
            })?;
    let delegation_hop = cut_node.hop.clone();

    let mut warnings = Vec::new();
    let mut planning_budget = QueryBudget::new(runtime.config.trace_max_queries_per_action);
    let request = session_tree.request.clone();
    let mut config = trace_config_from_request(
        &request,
        runtime.cache.clone(),
        runtime.config.trace_max_queries_per_action,
        runtime.config.trace_max_parallel_queries,
    )?;
    if let Some(exchange) = exchange_override {
        config.exchange = exchange;
    }
    seed_ns_targets_from_tree(&config, &session_tree.tree.root);

    let queried_children: Vec<_> = cut_node.children.iter().collect();
    let targets = match &intent {
        BranchIntentArg::ExpandCut => expand_cut_targets(
            &delegation_hop,
            &queried_children,
            &mut config,
            &mut planning_budget,
            progress,
            &mut warnings,
        )?,
        BranchIntentArg::AlternateServer { target } => {
            let target = resolve_alternate_target(
                target,
                &delegation_hop,
                &queried_children,
                &mut config,
                &mut planning_budget,
                progress,
                &mut warnings,
            )?;
            if target.is_empty() {
                return Ok(empty_report(dry_run, &delegation_hop, Vec::new(), warnings));
            }
            target
        }
    };

    let plan = BranchPlan {
        zone: delegation_hop.zone.clone(),
        server: delegation_hop.server.clone(),
        qname: delegation_hop.qname.clone(),
        targets: targets.iter().map(server_label).collect(),
    };

    if dry_run {
        return Ok(BranchReport {
            nodes_added: 0,
            updated_at: None,
            warnings,
            budget_truncated: false,
            dry_run: true,
            plan: Some(plan),
        });
    }

    if targets.is_empty() {
        return Ok(empty_report(dry_run, &delegation_hop, targets, warnings));
    }

    let qname = DomainName::parse(&hop.qname)?;
    let qtype = parse_record_type(&hop.qtype)?;
    let zone = DomainName::parse(&delegation_hop.zone)?;

    let is_expand_cut = matches!(intent, BranchIntentArg::ExpandCut);

    let mut branch_budget = QueryBudget::new(runtime.config.trace_max_queries_per_action);
    let mut new_nodes = if is_expand_cut {
        let attach_prefix = cut_path.path.clone();
        run_expand_cut_branch(
            &config,
            &mut branch_budget,
            progress,
            at.clone(),
            targets,
            qname,
            qtype,
            zone,
            attach_prefix,
        )?
    } else {
        let server = targets
            .into_iter()
            .next()
            .expect("non-empty targets checked above");
        let parent_path = parent_path(&selected_path.path);
        let attach_index = session_tree
            .tree
            .resolve(&NodePath {
                tree: selected_path.tree,
                path: parent_path.clone(),
            })
            .map(|parent| parent.children.len())
            .unwrap_or(0);
        let mut attach_path = parent_path;
        attach_path.push(attach_index);
        let node = run_branch_job(
            &config,
            &mut branch_budget,
            progress,
            BranchJobRequest {
                at: at.clone(),
                intent: BranchIntent::AlternateServer,
                attach_path,
                server,
                qname,
                qtype,
                zone,
            },
        )?;
        vec![node]
    };

    if is_expand_cut {
        let primary_delegation = session_tree.tree.root.children.first();
        new_nodes = normalize_expand_cut_attachments(
            &delegation_hop,
            cut_path.path.is_empty(),
            primary_delegation,
            new_nodes,
        );
    }

    let nodes_added = new_nodes.len();
    if nodes_added == 0 {
        return Ok(empty_report(dry_run, &delegation_hop, Vec::new(), warnings));
    }

    if is_expand_cut {
        let cut = session_tree
            .tree
            .resolve_mut(&cut_path)
            .expect("cut exists");
        cut.children.extend(new_nodes);
    } else {
        let parent_path = parent_path(&selected_path.path);
        let parent = session_tree
            .tree
            .resolve_mut(&NodePath {
                tree: selected_path.tree,
                path: parent_path,
            })
            .expect("parent exists");
        parent.children.extend(new_nodes);
    }

    document.touch_updated_at();
    Ok(BranchReport {
        nodes_added,
        updated_at: Some(document.updated_at.clone()),
        warnings,
        budget_truncated: planning_budget.truncated || branch_budget.truncated,
        dry_run: false,
        plan: Some(plan),
    })
}

fn empty_report(
    dry_run: bool,
    hop: &dns_resolve::TraceHop,
    targets: Vec<ServerTarget>,
    warnings: Vec<String>,
) -> BranchReport {
    BranchReport {
        nodes_added: 0,
        updated_at: None,
        warnings,
        budget_truncated: false,
        dry_run,
        plan: Some(BranchPlan {
            zone: hop.zone.clone(),
            server: hop.server.clone(),
            qname: hop.qname.clone(),
            targets: targets.iter().map(server_label).collect(),
        }),
    }
}

fn cut_context(
    at: &NodePath,
    session_tree: &SessionTree,
) -> Result<(NodePath, NodePath), BranchError> {
    let node = session_tree
        .tree
        .resolve(at)
        .ok_or_else(|| BranchError::UnresolvedPath {
            path: format_path(at),
        })?;
    if !node.hop.referral_ns.is_empty() || node.children.len() > 1 {
        return Ok((at.clone(), at.clone()));
    }
    if at.path.is_empty() {
        return Ok((at.clone(), at.clone()));
    }
    let mut cut_path = at.clone();
    cut_path.path.pop();
    if session_tree.tree.resolve(&cut_path).is_none() {
        return Err(BranchError::UnresolvedPath {
            path: format_path(at),
        });
    }
    Ok((cut_path, at.clone()))
}

/// When expanding at the session root, branch subtrees include a redundant hop at the
/// cut zone because the session root already represents that query. Hoist to the
/// next delegation level so siblings match the primary trace shape (`[org.]` not `[.]`).
fn normalize_expand_cut_attachments(
    cut_hop: &dns_resolve::TraceHop,
    cut_is_session_root: bool,
    primary_delegation: Option<&TraceNode>,
    nodes: Vec<TraceNode>,
) -> Vec<TraceNode> {
    if !cut_is_session_root {
        return nodes;
    }
    let attachment_zone = primary_delegation.map(|node| node.hop.zone.as_str());
    nodes
        .into_iter()
        .flat_map(|node| {
            normalize_expand_cut_attachment(cut_hop, attachment_zone, primary_delegation, node)
        })
        .collect()
}

fn normalize_expand_cut_attachment(
    cut_hop: &dns_resolve::TraceHop,
    attachment_zone: Option<&str>,
    _primary_delegation: Option<&TraceNode>,
    mut node: TraceNode,
) -> Vec<TraceNode> {
    let branch_origin =
        matches!(&node.origin, NodeOrigin::Branch { .. }).then(|| node.origin.clone());

    while node.hop.zone == cut_hop.zone {
        match node.children.len() {
            0 => break,
            1 => node = node.children.remove(0),
            _ => return promote_branch_origin(branch_origin, node.children),
        }
    }
    if node.hop.zone == cut_hop.zone {
        if node.children.is_empty() {
            return Vec::new();
        }
        return promote_branch_origin(branch_origin, node.children);
    }

    if let Some(expected_zone) = attachment_zone {
        if node.hop.zone != expected_zone {
            return Vec::new();
        }
    }

    if let Some(origin) = branch_origin {
        apply_branch_origin(&mut node, origin);
    }
    vec![node]
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
    let referral = referral_for_hop(cut_hop)?;
    let ns_names = referral_ns_names(cut_hop, Some(&referral));
    let normalized = normalize_ns_name(ns_name.as_str());
    let index = ns_names
        .iter()
        .position(|name| normalize_ns_name(name.as_str()) == normalized)?;
    cut_hop.glue.get(index)?.parse().ok()
}

/// True when the session root already has one delegation path per nameserver listed at the cut.
fn root_referral_satisfied(
    cut_hop: &dns_resolve::TraceHop,
    queried_children: &[&TraceNode],
) -> bool {
    if cut_hop.zone != "." {
        return false;
    }
    let ns_count = referral_ns_names(cut_hop, referral_for_hop(cut_hop).as_ref()).len();
    if ns_count == 0 {
        return false;
    }
    let delegation_paths = queried_children
        .iter()
        .filter(|child| child.hop.zone != cut_hop.zone)
        .count();
    delegation_paths >= ns_count
}

fn promote_branch_origin(
    origin: Option<NodeOrigin>,
    mut children: Vec<TraceNode>,
) -> Vec<TraceNode> {
    if let Some(origin) = origin {
        for child in &mut children {
            apply_branch_origin(child, origin.clone());
        }
    }
    children
}

fn apply_branch_origin(node: &mut TraceNode, origin: NodeOrigin) {
    if !matches!(node.origin, NodeOrigin::Branch { .. }) {
        node.origin = origin;
    }
}

fn expand_cut_targets(
    delegation_hop: &dns_resolve::TraceHop,
    queried_children: &[&TraceNode],
    config: &mut TraceConfig,
    budget: &mut QueryBudget,
    progress: &mut dyn TraceProgress,
    warnings: &mut Vec<String>,
) -> Result<Vec<ServerTarget>, BranchError> {
    let zone = DomainName::parse(&delegation_hop.zone)?;
    if root_referral_satisfied(delegation_hop, queried_children) {
        warnings.push("all nameservers at this zone cut already queried".into());
        return Ok(Vec::new());
    }
    let referral = referral_for_hop(delegation_hop);
    let fallback = queried_children
        .iter()
        .filter_map(|child| server_target_from_hop(&child.hop).ok())
        .collect::<Vec<_>>();

    let ns_names = referral_ns_names(delegation_hop, referral.as_ref());
    if ns_names.is_empty() {
        return Ok(filter_unqueried_targets(&fallback, queried_children));
    }

    let mut targets = Vec::new();
    let mut unresolved_ns = Vec::new();
    let mut last_error = None;

    for ns_name in ns_names {
        if subtree_covers_ns_name(delegation_hop, &ns_name, queried_children) {
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
            &ns_name, referral, &fallback, config, budget, &zone, progress,
        ) {
            Ok(Some(target)) => targets.push(target),
            Ok(None) => {}
            Err(error) => last_error = Some(error),
        }
    }

    let targets = dedupe_server_targets(filter_unqueried_targets(&targets, queried_children));
    if targets.is_empty() {
        if unresolved_ns.is_empty() || last_error.is_none() {
            warnings.push("all nameservers at this zone cut already queried".into());
            return Ok(Vec::new());
        }
        if let Some(error) = last_error {
            return Err(error.into());
        }
    }
    Ok(targets)
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

fn resolve_alternate_target(
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
    targets: &[ServerTarget],
    queried_children: &[&TraceNode],
) -> Vec<ServerTarget> {
    targets
        .iter()
        .filter(|target| {
            !queried_children
                .iter()
                .any(|child| subtree_queried_primary(target, child))
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

fn parent_path(path: &[usize]) -> Vec<usize> {
    let mut parent = path.to_vec();
    if !parent.is_empty() {
        parent.pop();
    }
    parent
}

fn format_path(path: &NodePath) -> String {
    if path.path.is_empty() {
        return path.tree.to_string();
    }
    format!(
        "{}.{}",
        path.tree,
        path.path
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(".")
    )
}

fn server_label(server: &ServerTarget) -> String {
    match &server.name {
        Some(name) if !name.is_empty() => format!("{name} ({})", server.address),
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

pub fn format_branch_report(report: &BranchReport) -> String {
    let mut lines = Vec::new();
    if let Some(plan) = &report.plan {
        lines.push(format!(
            "node: zone {} server {} query {}",
            plan.zone, plan.server, plan.qname
        ));
        if plan.targets.is_empty() {
            lines.push("nothing to query at this cut".into());
        } else {
            lines.push("would query:".into());
            for target in &plan.targets {
                lines.push(format!("  - {target}"));
            }
        }
    }
    if report.dry_run {
        lines.push("dry run: no queries issued".into());
        return lines.join("\n");
    }
    if report.nodes_added == 0 {
        lines.push("no nodes added".into());
    } else {
        lines.push(format!("added {} node(s)", report.nodes_added));
        if let Some(updated_at) = &report.updated_at {
            lines.push(format!("updated_at: {updated_at}"));
        }
    }
    for warning in &report.warnings {
        lines.push(format!("warning: {warning}"));
    }
    if report.budget_truncated {
        lines.push("warning: per-action query cap reached".into());
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use dns_core::EdnsMeta;
    use dns_core::response::{DnsRecord, DnsResponse};
    use dns_resolve::{HopOutcome, NodeOrigin, TraceHop, TraceTree, TraceTreeRequest};

    use crate::dig_options::TraceOptions;
    use crate::runtime::Runtime;
    use crate::session::SessionDocument;
    use crate::trace_request::TraceRequest;

    struct SilentProgress;

    impl TraceProgress for SilentProgress {
        fn hop(&mut self, _hop: &TraceHop, _path: &NodePath) {}
        fn message(&mut self, _message: &str) {}
    }

    struct AuthoritativeExchange;

    impl dns_resolve::DnsExchange for AuthoritativeExchange {
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

    struct DelegatingExchange {
        fail: Vec<IpAddr>,
    }

    impl dns_resolve::DnsExchange for DelegatingExchange {
        fn exchange(
            &self,
            server: IpAddr,
            _port: u16,
            options: &dns_core::QueryOptions,
        ) -> dns_core::Result<dns_core::response::QueryResult> {
            if self.fail.contains(&server) {
                return Err(dns_core::DnsCoreError::Parse(
                    "injected transport failure".into(),
                ));
            }
            Ok(dns_core::response::QueryResult {
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

    fn delegation_hop() -> TraceHop {
        TraceHop {
            zone: "com.".into(),
            server: "192.0.0.1".into(),
            server_name: Some("ns1.com.".into()),
            qname: "example.com.".into(),
            qtype: "A".into(),
            transport: "tcp".into(),
            rtt_ms: 5,
            rcode: "NOERROR".into(),
            nsid: None,
            ede_code: None,
            ede_text: None,
            referral_ns: vec![
                "ns1.com.".into(),
                "ns2.com.".into(),
                "ns3.com.".into(),
                "ns4.com.".into(),
            ],
            glue: vec![
                "192.0.0.1".into(),
                "192.0.0.2".into(),
                "192.0.0.3".into(),
                "192.0.0.4".into(),
            ],
            response: Default::default(),
            from_cache: false,
            outcome: HopOutcome::Referral,
        }
    }

    fn branched_tree() -> TraceTree {
        let root = TraceNode {
            hop: TraceHop {
                zone: ".".into(),
                server: "198.41.0.4".into(),
                server_name: None,
                qname: "example.com.".into(),
                qtype: "A".into(),
                transport: "tcp".into(),
                rtt_ms: 1,
                rcode: "NOERROR".into(),
                nsid: None,
                ede_code: None,
                ede_text: None,
                referral_ns: vec!["a.gtld-servers.net.".into()],
                glue: vec![],
                response: Default::default(),
                from_cache: false,
                outcome: HopOutcome::Referral,
            },
            origin: NodeOrigin::Trace,
            children: vec![TraceNode {
                hop: delegation_hop(),
                origin: NodeOrigin::Trace,
                children: vec![TraceNode {
                    hop: TraceHop {
                        zone: "com.".into(),
                        server: "192.0.0.1".into(),
                        server_name: Some("ns1.com.".into()),
                        qname: "example.com.".into(),
                        qtype: "A".into(),
                        transport: "tcp".into(),
                        rtt_ms: 2,
                        rcode: "NOERROR".into(),
                        nsid: None,
                        ede_code: None,
                        ede_text: None,
                        referral_ns: vec![],
                        glue: vec![],
                        response: Default::default(),
                        from_cache: false,
                        outcome: HopOutcome::Referral,
                    },
                    origin: NodeOrigin::Trace,
                    children: vec![],
                }],
            }],
        };
        TraceTree {
            request: TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-08-25T00:00:00Z".into(),
            },
            root,
            budget_truncated: false,
        }
    }

    fn sample_document(tree: TraceTree, request: TraceRequest) -> SessionDocument {
        SessionDocument::new("01BRANCH".into(), request, tree)
    }

    fn runtime() -> Runtime {
        Runtime::open(crate::paths::DelvePaths::from_root(
            tempfile::tempdir().expect("tempdir").path(),
        ))
    }

    #[test]
    fn parse_node_path_accepts_tree_and_segments() {
        let path = parse_node_path("0.1.2").expect("path");
        assert_eq!(path.tree, 0);
        assert_eq!(path.path, vec![1, 2]);
    }

    #[test]
    fn resolve_target_by_display_index_and_path_agree() {
        let tree = branched_tree();
        let document = sample_document(
            tree,
            TraceRequest::from_options(&TraceOptions {
                qname: "example.com".into(),
                use_tcp: true,
                dnssec: true,
                ..Default::default()
            }),
        );
        let by_hop = resolve_branch_target(&document, Some(2), None).expect("hop");
        let by_path = resolve_branch_target(&document, None, Some("0.0.0")).expect("path");
        assert_eq!(by_hop, by_path);
    }

    #[test]
    fn expand_cut_dry_run_lists_unqueried_servers() {
        let tree = branched_tree();
        let mut request = TraceRequest::from_options(&TraceOptions {
            qname: "example.com".into(),
            ..Default::default()
        });
        request.use_tcp = true;
        let mut document = sample_document(tree, request);
        let updated_before = document.updated_at.clone();
        let runtime = runtime();
        let cut = NodePath {
            tree: 0,
            path: vec![0],
        };
        let report = execute_branch(
            &mut document,
            cut,
            BranchIntentArg::ExpandCut,
            true,
            &runtime,
            &mut SilentProgress,
            None,
        )
        .expect("dry run");
        assert!(report.dry_run);
        assert_eq!(report.nodes_added, 0);
        let plan = report.plan.expect("plan");
        assert_eq!(plan.targets.len(), 3);
        assert_eq!(document.updated_at, updated_before);
    }

    #[test]
    fn expand_cut_adds_nodes_for_unqueried_servers() {
        let tree = branched_tree();
        let mut document = sample_document(
            tree,
            TraceRequest::from_options(&TraceOptions {
                qname: "example.com".into(),
                ..Default::default()
            }),
        );
        let runtime = runtime();
        let cut = NodePath {
            tree: 0,
            path: vec![0],
        };
        let report = execute_branch(
            &mut document,
            cut,
            BranchIntentArg::ExpandCut,
            false,
            &runtime,
            &mut SilentProgress,
            Some(Arc::new(AuthoritativeExchange)),
        )
        .expect("branch");
        assert_eq!(report.nodes_added, 3);
        let cut_node = document
            .primary_tree()
            .expect("tree")
            .resolve(&NodePath {
                tree: 0,
                path: vec![0],
            })
            .expect("cut");
        assert_eq!(cut_node.children.len(), 4);
        assert!(cut_node.children.iter().skip(1).all(|node| matches!(
            node.origin,
            NodeOrigin::Branch {
                intent: BranchIntent::ExpandCut,
                ..
            }
        )));
    }

    #[test]
    fn fully_queried_cut_is_noop() {
        let mut tree = branched_tree();
        let cut = tree
            .resolve_mut(&NodePath {
                tree: 0,
                path: vec![0],
            })
            .expect("cut");
        for index in 2..=4 {
            cut.children.push(TraceNode {
                hop: TraceHop {
                    zone: "com.".into(),
                    server: format!("192.0.0.{index}"),
                    server_name: Some(format!("ns{index}.com.")),
                    qname: "example.com.".into(),
                    qtype: "A".into(),
                    transport: "udp".into(),
                    rtt_ms: 1,
                    rcode: "NOERROR".into(),
                    nsid: None,
                    ede_code: None,
                    ede_text: None,
                    referral_ns: vec![],
                    glue: vec![],
                    response: Default::default(),
                    from_cache: false,
                    outcome: HopOutcome::Referral,
                },
                origin: NodeOrigin::Trace,
                children: vec![],
            });
        }
        let updated_before: String = "2026-08-25T00:00:00Z".into();
        let mut document = SessionDocument {
            updated_at: updated_before.clone(),
            ..sample_document(
                tree,
                TraceRequest::from_options(&TraceOptions {
                    qname: "example.com".into(),
                    ..Default::default()
                }),
            )
        };
        let runtime = runtime();
        let report = execute_branch(
            &mut document,
            NodePath {
                tree: 0,
                path: vec![0],
            },
            BranchIntentArg::ExpandCut,
            false,
            &runtime,
            &mut SilentProgress,
            Some(Arc::new(AuthoritativeExchange)),
        )
        .expect("branch");
        assert_eq!(report.nodes_added, 0);
        assert_eq!(document.updated_at, updated_before);
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("all nameservers at this zone cut already queried"))
        );
    }

    fn tuininga_tree() -> TraceTree {
        let root = TraceNode {
            hop: TraceHop {
                zone: ".".into(),
                server: "198.41.0.4".into(),
                server_name: None,
                qname: "tuininga.org.".into(),
                qtype: "A".into(),
                transport: "udp".into(),
                rtt_ms: 1,
                rcode: "NOERROR".into(),
                nsid: None,
                ede_code: None,
                ede_text: None,
                referral_ns: vec![
                    "a0.org.afilias-nst.info.".into(),
                    "b0.org.afilias-nst.org.".into(),
                    "c0.org.afilias-nst.info.".into(),
                ],
                glue: vec![
                    "199.249.112.1".into(),
                    "199.249.120.1".into(),
                    "199.249.125.1".into(),
                ],
                response: Default::default(),
                from_cache: false,
                outcome: HopOutcome::Referral,
            },
            origin: NodeOrigin::Trace,
            children: vec![TraceNode {
                hop: TraceHop {
                    zone: "org.".into(),
                    server: "199.249.112.1".into(),
                    server_name: Some("a0.org.afilias-nst.info.".into()),
                    qname: "tuininga.org.".into(),
                    qtype: "A".into(),
                    transport: "udp".into(),
                    rtt_ms: 2,
                    rcode: "NOERROR".into(),
                    nsid: None,
                    ede_code: None,
                    ede_text: None,
                    referral_ns: vec![
                        "helium.ns.hetzner.de.".into(),
                        "hydrogen.ns.hetzner.com.".into(),
                        "oxygen.ns.hetzner.com.".into(),
                    ],
                    glue: vec![],
                    response: Default::default(),
                    from_cache: false,
                    outcome: HopOutcome::Referral,
                },
                origin: NodeOrigin::Trace,
                children: vec![
                    TraceNode {
                        hop: TraceHop {
                            zone: "tuininga.org.".into(),
                            server: "193.47.99.5".into(),
                            server_name: Some("helium.ns.hetzner.de.".into()),
                            qname: "tuininga.org.".into(),
                            qtype: "A".into(),
                            transport: "udp".into(),
                            rtt_ms: 3,
                            rcode: "NOERROR".into(),
                            nsid: None,
                            ede_code: None,
                            ede_text: None,
                            referral_ns: vec![],
                            glue: vec![],
                            response: Default::default(),
                            from_cache: false,
                            outcome: HopOutcome::Answered,
                        },
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    },
                    TraceNode {
                        hop: TraceHop {
                            zone: "tuininga.org.".into(),
                            server: "213.133.100.98".into(),
                            server_name: Some("hydrogen.ns.hetzner.com.".into()),
                            qname: "tuininga.org.".into(),
                            qtype: "A".into(),
                            transport: "udp".into(),
                            rtt_ms: 4,
                            rcode: "NOERROR".into(),
                            nsid: None,
                            ede_code: None,
                            ede_text: None,
                            referral_ns: vec![],
                            glue: vec![],
                            response: Default::default(),
                            from_cache: false,
                            outcome: HopOutcome::Answered,
                        },
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    },
                    TraceNode {
                        hop: TraceHop {
                            zone: "tuininga.org.".into(),
                            server: "88.198.229.192".into(),
                            server_name: Some("oxygen.ns.hetzner.com.".into()),
                            qname: "tuininga.org.".into(),
                            qtype: "A".into(),
                            transport: "udp".into(),
                            rtt_ms: 5,
                            rcode: "NOERROR".into(),
                            nsid: None,
                            ede_code: None,
                            ede_text: None,
                            referral_ns: vec![],
                            glue: vec![],
                            response: Default::default(),
                            from_cache: false,
                            outcome: HopOutcome::Answered,
                        },
                        origin: NodeOrigin::Trace,
                        children: vec![],
                    },
                ],
            }],
        };
        TraceTree {
            request: TraceTreeRequest {
                qname: "tuininga.org.".into(),
                qtype: "A".into(),
                started_at: "2026-08-25T00:00:00Z".into(),
            },
            root,
            budget_truncated: false,
        }
    }

    #[test]
    fn expand_cut_from_root_dry_run_lists_unqueried_org_servers() {
        let mut document = sample_document(
            tuininga_tree(),
            TraceRequest::from_options(&TraceOptions {
                qname: "tuininga.org.".into(),
                ..Default::default()
            }),
        );
        let runtime = runtime();
        let report = execute_branch(
            &mut document,
            NodePath::root(0),
            BranchIntentArg::ExpandCut,
            true,
            &runtime,
            &mut SilentProgress,
            None,
        )
        .expect("branch");
        let plan = report.plan.expect("plan");
        assert_eq!(plan.zone, ".");
        assert_eq!(plan.targets.len(), 2);
        assert!(
            plan.targets
                .iter()
                .any(|target| target.contains("b0.org.afilias-nst.org"))
        );
        assert!(
            plan.targets
                .iter()
                .any(|target| target.contains("c0.org.afilias-nst.info"))
        );
    }

    #[test]
    fn expand_cut_from_root_reuses_session_nameserver_targets() {
        struct TuiningaBranchExchange;

        impl TuiningaBranchExchange {
            fn is_org_server(server: IpAddr) -> bool {
                matches!(
                    server,
                    IpAddr::V4(v4) if matches!(
                        v4.octets(),
                        [199, 249, 112, 1] | [199, 249, 120, 1] | [199, 249, 125, 1]
                    )
                )
            }

            fn is_root_expand_target(server: IpAddr) -> bool {
                matches!(
                    server,
                    IpAddr::V4(v4) if matches!(v4.octets(), [199, 249, 120, 1] | [199, 249, 125, 1])
                )
            }

            fn is_hetzner_server(server: IpAddr) -> bool {
                matches!(
                    server,
                    IpAddr::V4(v4) if matches!(
                        v4.octets(),
                        [193, 47, 99, 5] | [213, 133, 100, 98] | [88, 198, 229, 192]
                    )
                )
            }
        }

        impl dns_resolve::DnsExchange for TuiningaBranchExchange {
            fn exchange(
                &self,
                server: IpAddr,
                _port: u16,
                options: &dns_core::query::QueryOptions,
            ) -> dns_core::Result<dns_core::response::QueryResult> {
                let qname = options.qname.as_str();
                if qname.contains("hetzner") {
                    panic!(
                        "branch should reuse session nameserver targets instead of sub-tracing {qname}"
                    );
                }
                if !qname
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case("tuininga.org")
                {
                    return Err(dns_core::DnsCoreError::Parse(format!(
                        "unexpected query {qname} to {server}"
                    )));
                }
                if Self::is_hetzner_server(server) {
                    return Ok(dns_core::response::QueryResult {
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
                    });
                }
                if Self::is_root_expand_target(server) {
                    return Ok(dns_core::response::QueryResult {
                        server,
                        transport: options.transport,
                        qname: options.qname.clone(),
                        qtype: options.qtype.to_string(),
                        rtt: std::time::Duration::from_millis(1),
                        response: DnsResponse {
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
                                name: DomainName::parse("org.").expect("zone"),
                                rtype: "NS".into(),
                                rclass: "IN".into(),
                                ttl: 3600,
                                rdata: "a0.org.afilias-nst.info.".into(),
                            }],
                            additionals: vec![],
                            edns: EdnsMeta::default(),
                        },
                        from_cache: false,
                    });
                }
                if Self::is_org_server(server) {
                    return Ok(dns_core::response::QueryResult {
                        server,
                        transport: options.transport,
                        qname: options.qname.clone(),
                        qtype: options.qtype.to_string(),
                        rtt: std::time::Duration::from_millis(1),
                        response: DnsResponse {
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
                                name: DomainName::parse("tuininga.org.").expect("zone"),
                                rtype: "NS".into(),
                                rclass: "IN".into(),
                                ttl: 3600,
                                rdata: "helium.ns.hetzner.de.".into(),
                            }],
                            additionals: vec![],
                            edns: EdnsMeta::default(),
                        },
                        from_cache: false,
                    });
                }
                Ok(dns_core::response::QueryResult {
                    server,
                    transport: options.transport,
                    qname: options.qname.clone(),
                    qtype: options.qtype.to_string(),
                    rtt: std::time::Duration::from_millis(1),
                    response: DnsResponse {
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
                            name: DomainName::parse("org.").expect("zone"),
                            rtype: "NS".into(),
                            rclass: "IN".into(),
                            ttl: 3600,
                            rdata: "a0.org.afilias-nst.info.".into(),
                        }],
                        additionals: vec![],
                        edns: EdnsMeta::default(),
                    },
                    from_cache: false,
                })
            }
        }

        let mut document = sample_document(
            tuininga_tree(),
            TraceRequest::from_options(&TraceOptions {
                qname: "tuininga.org.".into(),
                ..Default::default()
            }),
        );
        let runtime = runtime();
        let report = execute_branch(
            &mut document,
            NodePath::root(0),
            BranchIntentArg::ExpandCut,
            false,
            &runtime,
            &mut SilentProgress,
            Some(Arc::new(TuiningaBranchExchange)),
        )
        .expect("branch");
        assert_eq!(report.nodes_added, 2);
        let root = document
            .primary_tree()
            .expect("tree")
            .resolve(&NodePath::root(0))
            .expect("root");
        assert_eq!(root.children.len(), 3);
        assert!(
            root.children.iter().all(|child| child.hop.zone == "org."),
            "root expand should attach org-level siblings, not redundant root-zone hops"
        );
        assert_eq!(
            root.children
                .iter()
                .filter(|child| matches!(
                    child.origin,
                    NodeOrigin::Branch {
                        intent: BranchIntent::ExpandCut,
                        ..
                    }
                ))
                .count(),
            2
        );
    }

    #[test]
    fn normalize_expand_cut_attachment_peels_redundant_root_hop() {
        let cut = dns_resolve::TraceHop {
            zone: ".".into(),
            server: "198.41.0.4".into(),
            server_name: None,
            qname: "tuininga.org.".into(),
            qtype: "A".into(),
            transport: "udp".into(),
            rtt_ms: 1,
            rcode: "NOERROR".into(),
            nsid: None,
            ede_code: None,
            ede_text: None,
            referral_ns: vec![],
            glue: vec![],
            response: Default::default(),
            from_cache: false,
            outcome: HopOutcome::Referral,
        };
        let org = TraceNode {
            hop: TraceHop {
                zone: "org.".into(),
                server: "199.249.120.1".into(),
                server_name: Some("b2.org.afilias-nst.org.".into()),
                qname: "tuininga.org.".into(),
                qtype: "A".into(),
                transport: "udp".into(),
                rtt_ms: 2,
                rcode: "NOERROR".into(),
                nsid: None,
                ede_code: None,
                ede_text: None,
                referral_ns: vec![],
                glue: vec![],
                response: Default::default(),
                from_cache: false,
                outcome: HopOutcome::Referral,
            },
            origin: NodeOrigin::Branch {
                at: NodePath::root(0),
                intent: BranchIntent::ExpandCut,
                at_time: "now".into(),
            },
            children: vec![],
        };
        let branch = TraceNode {
            hop: TraceHop {
                zone: ".".into(),
                server: "199.249.120.1".into(),
                server_name: Some("b2.org.afilias-nst.org.".into()),
                qname: "tuininga.org.".into(),
                qtype: "A".into(),
                transport: "udp".into(),
                rtt_ms: 2,
                rcode: "NOERROR".into(),
                nsid: None,
                ede_code: None,
                ede_text: None,
                referral_ns: vec![],
                glue: vec![],
                response: Default::default(),
                from_cache: false,
                outcome: HopOutcome::Referral,
            },
            origin: NodeOrigin::Branch {
                at: NodePath::root(0),
                intent: BranchIntent::ExpandCut,
                at_time: "now".into(),
            },
            children: vec![org.clone()],
        };
        let normalized = normalize_expand_cut_attachments(&cut, true, Some(&org), vec![branch]);
        assert_eq!(normalized.len(), 1);
        assert_eq!(normalized[0].hop.zone, "org.");
        assert_eq!(normalized[0].hop.server, "199.249.120.1");
        assert!(matches!(
            normalized[0].origin,
            NodeOrigin::Branch {
                intent: BranchIntent::ExpandCut,
                ..
            }
        ));

        let unchanged = normalize_expand_cut_attachments(&cut, false, None, vec![org]);
        assert_eq!(unchanged.len(), 1);
        assert_eq!(unchanged[0].hop.zone, "org.");
    }

    #[test]
    fn expand_cut_reuses_queried_nameserver_without_dns() {
        struct PanicExchange;

        impl dns_resolve::DnsExchange for PanicExchange {
            fn exchange(
                &self,
                _server: IpAddr,
                _port: u16,
                _options: &dns_core::query::QueryOptions,
            ) -> dns_core::Result<dns_core::response::QueryResult> {
                panic!("expand cut should not query when child hops already cover referral NS");
            }
        }

        let mut document = sample_document(
            tuininga_tree(),
            TraceRequest::from_options(&TraceOptions {
                qname: "tuininga.org.".into(),
                ..Default::default()
            }),
        );
        let runtime = runtime();
        let report = execute_branch(
            &mut document,
            NodePath {
                tree: 0,
                path: vec![0],
            },
            BranchIntentArg::ExpandCut,
            false,
            &runtime,
            &mut SilentProgress,
            Some(std::sync::Arc::new(PanicExchange)),
        )
        .expect("branch");
        assert_eq!(report.nodes_added, 0);
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("all nameservers at this zone cut already queried"))
        );
    }

    #[test]
    fn alternate_server_uses_tcp_dnssec_from_request() {
        let request = TraceRequest::from_options(&TraceOptions {
            qname: "example.com".into(),
            use_tcp: true,
            dnssec: true,
            ..Default::default()
        });
        let runtime = runtime();
        let mut config = trace_config_from_request(
            &request,
            runtime.cache.clone(),
            runtime.config.trace_max_queries_per_action,
            runtime.config.trace_max_parallel_queries,
        )
        .expect("config");
        config.exchange = Arc::new(AuthoritativeExchange);
        let mut budget = QueryBudget::new(64);
        let mut warnings = Vec::new();
        let tree = branched_tree();
        let document = sample_document(tree, request);
        let targets = resolve_alternate_target(
            &ServerTargetInput::Name("ns2.com.".into()),
            &delegation_hop(),
            &[document
                .primary_tree()
                .expect("tree")
                .resolve(&NodePath {
                    tree: 0,
                    path: vec![0, 0],
                })
                .expect("child")],
            &mut config,
            &mut budget,
            &mut SilentProgress,
            &mut warnings,
        )
        .expect("targets");
        assert_eq!(targets.len(), 1);
        assert_eq!(config.transport, dns_core::Transport::Tcp);
        assert!(config.dnssec);
    }

    #[test]
    fn already_queried_server_warns_and_skips() {
        let tree = branched_tree();
        let mut document = sample_document(
            tree,
            TraceRequest::from_options(&TraceOptions {
                qname: "example.com".into(),
                ..Default::default()
            }),
        );
        let runtime = runtime();
        let report = execute_branch(
            &mut document,
            NodePath {
                tree: 0,
                path: vec![0, 0],
            },
            BranchIntentArg::AlternateServer {
                target: ServerTargetInput::Name("ns1.com.".into()),
            },
            false,
            &runtime,
            &mut SilentProgress,
            Some(Arc::new(AuthoritativeExchange)),
        )
        .expect("branch");
        assert_eq!(report.nodes_added, 0);
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains("already queried"))
        );
    }

    #[test]
    fn expand_cut_records_failed_nodes() {
        let tree = branched_tree();
        let mut document = sample_document(
            tree,
            TraceRequest::from_options(&TraceOptions {
                qname: "example.com".into(),
                ..Default::default()
            }),
        );
        let runtime = runtime();
        let report = execute_branch(
            &mut document,
            NodePath {
                tree: 0,
                path: vec![0],
            },
            BranchIntentArg::ExpandCut,
            false,
            &runtime,
            &mut SilentProgress,
            Some(Arc::new(DelegatingExchange {
                fail: vec![
                    IpAddr::V4(Ipv4Addr::new(192, 0, 0, 2)),
                    IpAddr::V4(Ipv4Addr::new(192, 0, 0, 3)),
                ],
            })),
        )
        .expect("branch");
        assert_eq!(report.nodes_added, 3);
        let cut = document
            .primary_tree()
            .expect("tree")
            .resolve(&NodePath {
                tree: 0,
                path: vec![0],
            })
            .expect("cut");
        assert!(
            cut.children
                .iter()
                .any(|node| { matches!(node.hop.outcome, HopOutcome::Failed { .. }) })
        );
    }

    #[test]
    fn format_branch_report_states_when_nothing_added() {
        let report = BranchReport {
            nodes_added: 0,
            updated_at: None,
            warnings: vec!["server ns1.example. was already queried at this zone cut".into()],
            budget_truncated: false,
            dry_run: false,
            plan: Some(BranchPlan {
                zone: "com.".into(),
                server: "192.0.0.1".into(),
                qname: "example.com.".into(),
                targets: vec![],
            }),
        };
        let text = format_branch_report(&report);
        assert!(text.contains("no nodes added"));
        assert!(text.contains("already queried"));
    }

    #[test]
    fn branch_session_persists_updates() {
        let tree = branched_tree();
        let request = TraceRequest::from_options(&TraceOptions {
            qname: "example.com".into(),
            ..Default::default()
        });
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = Runtime::open(crate::paths::DelvePaths::from_root(dir.path()));
        let id = runtime.save_session(&tree, &request).expect("save");
        let mut document = runtime.get_session(&id).expect("get");
        let report = execute_branch(
            &mut document,
            NodePath {
                tree: 0,
                path: vec![0],
            },
            BranchIntentArg::ExpandCut,
            false,
            &runtime,
            &mut SilentProgress,
            Some(Arc::new(AuthoritativeExchange)),
        )
        .expect("branch");
        assert!(report.nodes_added > 0);
        runtime.update_session(&document).expect("update");
        let document = runtime.get_session(&id).expect("reload");
        let cut = document
            .primary_tree()
            .expect("tree")
            .resolve(&NodePath {
                tree: 0,
                path: vec![0],
            })
            .expect("cut");
        assert!(cut.children.len() > 1);
    }

    #[test]
    fn failed_update_leaves_session_without_partial_branch() {
        let tree = branched_tree();
        let request = TraceRequest::from_options(&TraceOptions {
            qname: "example.com".into(),
            ..Default::default()
        });
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = crate::paths::DelvePaths::from_root(dir.path());
        let runtime = Runtime::open(paths.clone());
        let id = runtime.save_session(&tree, &request).expect("save");
        let before = runtime.get_session(&id).expect("before");
        let before_children = before
            .primary_tree()
            .expect("tree")
            .resolve(&NodePath {
                tree: 0,
                path: vec![0],
            })
            .expect("cut")
            .children
            .len();

        let mut document = before.clone();
        let _report = execute_branch(
            &mut document,
            NodePath {
                tree: 0,
                path: vec![0],
            },
            BranchIntentArg::ExpandCut,
            false,
            &runtime,
            &mut SilentProgress,
            Some(Arc::new(AuthoritativeExchange)),
        )
        .expect("branch");
        document.id = "missing-session-id".into();
        assert!(runtime.update_session(&document).is_err());

        let after = runtime.get_session(&id).expect("after");
        let after_children = after
            .primary_tree()
            .expect("tree")
            .resolve(&NodePath {
                tree: 0,
                path: vec![0],
            })
            .expect("cut")
            .children
            .len();
        assert_eq!(after_children, before_children);
    }

    #[test]
    fn normalize_skips_shallow_tuininga_branch_below_root() {
        let cut = dns_resolve::TraceHop {
            zone: ".".into(),
            server: "198.41.0.4".into(),
            server_name: None,
            qname: "tuininga.org.".into(),
            qtype: "A".into(),
            transport: "udp".into(),
            rtt_ms: 1,
            rcode: "NOERROR".into(),
            nsid: None,
            ede_code: None,
            ede_text: None,
            referral_ns: vec![],
            glue: vec![],
            response: Default::default(),
            from_cache: false,
            outcome: HopOutcome::Referral,
        };
        let org_template = tuininga_tree().root.children[0].clone();
        let tuininga_leaf = TraceNode {
            hop: TraceHop {
                zone: "tuininga.org.".into(),
                server: "193.47.99.5".into(),
                server_name: Some("helium.ns.hetzner.de.".into()),
                qname: "tuininga.org.".into(),
                qtype: "A".into(),
                transport: "udp".into(),
                rtt_ms: 110,
                rcode: "NOERROR".into(),
                nsid: None,
                ede_code: None,
                ede_text: None,
                referral_ns: vec![],
                glue: vec![],
                response: Default::default(),
                from_cache: false,
                outcome: HopOutcome::Answered,
            },
            origin: NodeOrigin::Branch {
                at: NodePath::root(0),
                intent: BranchIntent::ExpandCut,
                at_time: "now".into(),
            },
            children: vec![],
        };

        let normalized =
            normalize_expand_cut_attachments(&cut, true, Some(&org_template), vec![tuininga_leaf]);

        assert!(normalized.is_empty());
    }

    #[test]
    fn expand_cut_from_root_second_expand_is_noop() {
        let mut document = sample_document(
            tuininga_tree(),
            TraceRequest::from_options(&TraceOptions {
                qname: "tuininga.org.".into(),
                ..Default::default()
            }),
        );
        let runtime = runtime();
        let first = execute_branch(
            &mut document,
            NodePath::root(0),
            BranchIntentArg::ExpandCut,
            false,
            &runtime,
            &mut SilentProgress,
            Some(Arc::new(TuiningaBranchExchangeImpl)),
        )
        .expect("first branch");
        assert_eq!(first.nodes_added, 2);
        let root_len = document
            .primary_tree()
            .expect("tree")
            .resolve(&NodePath::root(0))
            .expect("root")
            .children
            .len();
        assert_eq!(root_len, 3);
        assert!(
            document
                .primary_tree()
                .expect("tree")
                .resolve(&NodePath::root(0))
                .expect("root")
                .children
                .iter()
                .all(|child| child.hop.zone == "org.")
        );
        let root = document
            .primary_tree()
            .expect("tree")
            .resolve(&NodePath::root(0))
            .expect("root");
        let cut_hop = root.hop.clone();
        let queried: Vec<&TraceNode> = root.children.iter().collect();
        for ns in [
            "a0.org.afilias-nst.info.",
            "b0.org.afilias-nst.org.",
            "c0.org.afilias-nst.info.",
        ] {
            assert!(
                subtree_covers_ns_name(&cut_hop, &DomainName::parse(ns).expect("ns"), &queried,)
                    || root_referral_satisfied(&cut_hop, &queried),
                "expected {ns} to be covered after first root expand",
            );
        }
        assert!(root_referral_satisfied(&cut_hop, &queried));

        let second = execute_branch(
            &mut document,
            NodePath::root(0),
            BranchIntentArg::ExpandCut,
            false,
            &runtime,
            &mut SilentProgress,
            Some(Arc::new(TuiningaBranchExchangeImpl)),
        )
        .expect("second branch");
        assert_eq!(second.nodes_added, 0);
        assert!(
            second
                .warnings
                .iter()
                .any(|warning| warning.contains("all nameservers at this zone cut already queried"))
        );
        assert_eq!(
            document
                .primary_tree()
                .expect("tree")
                .resolve(&NodePath::root(0))
                .expect("root")
                .children
                .len(),
            3
        );
    }

    #[test]
    fn expand_cut_from_root_dry_run_ignores_ns_in_primary_subtree() {
        let mut tree = tuininga_tree();
        tree.root.hop.referral_ns = vec![
            "a0.org.afilias-nst.info.".into(),
            "b0.org.afilias-nst.org.".into(),
            "c0.org.afilias-nst.info.".into(),
            "d0.org.afilias-nst.org.".into(),
            "e0.org.afilias-nst.info.".into(),
        ];
        let mut document = sample_document(
            tree,
            TraceRequest::from_options(&TraceOptions {
                qname: "tuininga.org.".into(),
                ..Default::default()
            }),
        );
        let runtime = runtime();
        let report = execute_branch(
            &mut document,
            NodePath::root(0),
            BranchIntentArg::ExpandCut,
            true,
            &runtime,
            &mut SilentProgress,
            None,
        )
        .expect("branch");
        let plan = report.plan.expect("plan");
        assert_eq!(plan.zone, ".");
        assert_eq!(plan.targets.len(), 2);
        assert!(
            plan.targets
                .iter()
                .any(|target| target.contains("b0.org.afilias-nst.org"))
        );
        assert!(
            plan.targets
                .iter()
                .any(|target| target.contains("c0.org.afilias-nst.info"))
        );
    }

    struct TuiningaBranchExchangeImpl;

    impl TuiningaBranchExchangeImpl {
        fn is_org_server(server: IpAddr) -> bool {
            matches!(
                server,
                IpAddr::V4(v4) if matches!(
                    v4.octets(),
                    [199, 249, 112, 1] | [199, 249, 120, 1] | [199, 249, 125, 1]
                )
            )
        }

        fn is_root_expand_target(server: IpAddr) -> bool {
            matches!(
                server,
                IpAddr::V4(v4) if matches!(v4.octets(), [199, 249, 120, 1] | [199, 249, 125, 1])
            )
        }

        fn is_hetzner_server(server: IpAddr) -> bool {
            matches!(
                server,
                IpAddr::V4(v4) if matches!(
                    v4.octets(),
                    [193, 47, 99, 5] | [213, 133, 100, 98] | [88, 198, 229, 192]
                )
            )
        }
    }

    impl dns_resolve::DnsExchange for TuiningaBranchExchangeImpl {
        fn exchange(
            &self,
            server: IpAddr,
            _port: u16,
            options: &dns_core::query::QueryOptions,
        ) -> dns_core::Result<dns_core::response::QueryResult> {
            let qname = options.qname.as_str();
            if qname.contains("hetzner") {
                return Err(dns_core::DnsCoreError::Parse(format!(
                    "branch should reuse session nameserver targets instead of sub-tracing {qname}"
                )));
            }
            if !qname
                .trim_end_matches('.')
                .eq_ignore_ascii_case("tuininga.org")
            {
                return Err(dns_core::DnsCoreError::Parse(format!(
                    "unexpected query {qname} to {server}"
                )));
            }
            if Self::is_hetzner_server(server) {
                return Ok(dns_core::response::QueryResult {
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
                });
            }
            if Self::is_root_expand_target(server) {
                return Ok(dns_core::response::QueryResult {
                    server,
                    transport: options.transport,
                    qname: options.qname.clone(),
                    qtype: options.qtype.to_string(),
                    rtt: std::time::Duration::from_millis(1),
                    response: DnsResponse {
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
                            name: DomainName::parse("org.").expect("zone"),
                            rtype: "NS".into(),
                            rclass: "IN".into(),
                            ttl: 3600,
                            rdata: "a0.org.afilias-nst.info.".into(),
                        }],
                        additionals: vec![],
                        edns: EdnsMeta::default(),
                    },
                    from_cache: false,
                });
            }
            if Self::is_org_server(server) {
                return Ok(dns_core::response::QueryResult {
                    server,
                    transport: options.transport,
                    qname: options.qname.clone(),
                    qtype: options.qtype.to_string(),
                    rtt: std::time::Duration::from_millis(1),
                    response: DnsResponse {
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
                            name: DomainName::parse("tuininga.org.").expect("zone"),
                            rtype: "NS".into(),
                            rclass: "IN".into(),
                            ttl: 3600,
                            rdata: "helium.ns.hetzner.de.".into(),
                        }],
                        additionals: vec![],
                        edns: EdnsMeta::default(),
                    },
                    from_cache: false,
                });
            }
            Ok(dns_core::response::QueryResult {
                server,
                transport: options.transport,
                qname: options.qname.clone(),
                qtype: options.qtype.to_string(),
                rtt: std::time::Duration::from_millis(1),
                response: DnsResponse {
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
                        name: DomainName::parse("org.").expect("zone"),
                        rtype: "NS".into(),
                        rclass: "IN".into(),
                        ttl: 3600,
                        rdata: "a0.org.afilias-nst.info.".into(),
                    }],
                    additionals: vec![],
                    edns: EdnsMeta::default(),
                },
                from_cache: false,
            })
        }
    }
}
