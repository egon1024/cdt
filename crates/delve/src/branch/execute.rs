use dns_core::name::DomainName;
use dns_core::parse_record_type;
use dns_resolve::trace::seed_ns_targets_from_tree;
use dns_resolve::{
    BranchIntent, BranchJobRequest, HopOutcome, NodeOrigin, NodePath, QueryBudget, ServerTarget,
    TraceNode, TraceProgress, run_branch_job, run_expand_cut_branch,
};

use super::target::{
    apply_branch_origin, expand_cut_targets, format_path, parent_path, resolve_alternate_target,
    server_label,
};
use super::{BranchError, BranchIntentArg, BranchPlan, BranchReport};
use crate::explore::{ExploreQueryOverrides, apply_explore_query_overrides};
use crate::runtime::Runtime;
use crate::session::{SessionDocument, SessionTree};
use crate::trace_config::trace_config_from_request;

/// Crate-internal test seam for deterministic DNS; production passes `None`.
pub(crate) type ExchangeOverride = Option<std::sync::Arc<dyn dns_resolve::DnsExchange>>;

#[allow(clippy::too_many_arguments)]
pub fn execute_branch(
    document: &mut SessionDocument,
    at: NodePath,
    intent: BranchIntentArg,
    dry_run: bool,
    runtime: &Runtime,
    progress: &mut dyn TraceProgress,
    exchange_override: ExchangeOverride,
    query_overrides: Option<&ExploreQueryOverrides>,
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
    let cut_hop_index = session_tree.tree.display_index_for_path(&cut_path);
    let cut_label = format_path(&cut_path);

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
    if let Some(overrides) = query_overrides {
        apply_explore_query_overrides(&mut config, overrides);
    }
    seed_ns_targets_from_tree(&config, &session_tree.tree.root);

    let queried_children: Vec<_> = cut_node.children.iter().collect();
    let targets = match &intent {
        BranchIntentArg::ExpandCut => expand_cut_targets(
            &delegation_hop,
            cut_path.path.is_empty(),
            &queried_children,
            &mut config,
            &mut planning_budget,
            progress,
            &mut warnings,
            dry_run,
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
                return Ok(empty_report(
                    dry_run,
                    &delegation_hop,
                    cut_hop_index,
                    &cut_label,
                    Vec::new(),
                    warnings,
                ));
            }
            target
        }
    };

    let plan = BranchPlan {
        hop: cut_hop_index,
        path: cut_label.clone(),
        zone: delegation_hop.zone.clone(),
        server: delegation_hop.server.clone(),
        qname: delegation_hop.qname.clone(),
        targets: targets.iter().map(server_label).collect(),
    };
    let targets_for_report = targets.clone();

    if dry_run {
        return Ok(BranchReport {
            nodes_added: 0,
            updated_at: None,
            warnings,
            budget_truncated: planning_budget.truncated,
            dry_run: true,
            plan: Some(plan),
        });
    }

    if targets.is_empty() {
        return Ok(empty_report(
            dry_run,
            &delegation_hop,
            cut_hop_index,
            &cut_label,
            targets,
            warnings,
        ));
    }

    let qname = DomainName::parse(&hop.qname)?;
    let qtype = parse_record_type(&hop.qtype)?;
    let zone = DomainName::parse(&delegation_hop.zone)?;

    let is_expand_cut = matches!(intent, BranchIntentArg::ExpandCut);

    let mut branch_budget = QueryBudget::new(runtime.config.trace_max_queries_per_action);
    let branch_targets = targets.clone();
    let mut new_nodes = if is_expand_cut {
        let attach_prefix = cut_path.path.clone();
        run_expand_cut_branch(
            &config,
            &mut branch_budget,
            progress,
            at.clone(),
            branch_targets,
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
        if let Some(reference_zone) = reference_answer_zone(primary_delegation) {
            align_answer_hop_zones(&mut new_nodes, &reference_zone, &delegation_hop.zone);
        }
    }

    let nodes_added = new_nodes.len();
    if nodes_added == 0 {
        if !targets_for_report.is_empty() {
            warnings
                .push("branch queries completed but no nodes could be attached at this cut".into());
        }
        return Ok(empty_report(
            dry_run,
            &delegation_hop,
            cut_hop_index,
            &cut_label,
            targets_for_report,
            warnings,
        ));
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
    cut_hop_index: Option<usize>,
    cut_label: &str,
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
            hop: cut_hop_index,
            path: cut_label.to_string(),
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

fn reference_answer_zone(primary_delegation: Option<&TraceNode>) -> Option<String> {
    primary_delegation
        .and_then(|node| {
            node.children
                .iter()
                .find(|child| matches!(child.hop.outcome, HopOutcome::Answered))
        })
        .map(|child| child.hop.zone.clone())
}

pub(crate) fn align_answer_hop_zones(
    nodes: &mut [TraceNode],
    reference_zone: &str,
    cut_zone: &str,
) {
    if reference_zone == cut_zone {
        return;
    }
    for node in nodes.iter_mut() {
        align_answer_hop_zone_recursive(node, reference_zone, cut_zone);
    }
}

fn align_answer_hop_zone_recursive(node: &mut TraceNode, reference_zone: &str, cut_zone: &str) {
    if matches!(node.hop.outcome, HopOutcome::Answered) && node.hop.zone == cut_zone {
        node.hop.zone = reference_zone.to_string();
    }
    for child in &mut node.children {
        align_answer_hop_zone_recursive(child, reference_zone, cut_zone);
    }
}

/// When expanding at the session root, branch subtrees include a redundant hop at the
/// cut zone because the session root already represents that query. Hoist to the
/// next delegation level so siblings match the primary trace shape (`[org.]` not `[.]`).
pub(crate) fn normalize_expand_cut_attachments(
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
            normalize_expand_cut_attachment(
                cut_hop,
                cut_is_session_root,
                attachment_zone,
                primary_delegation,
                node,
            )
        })
        .collect()
}

fn normalize_expand_cut_attachment(
    cut_hop: &dns_resolve::TraceHop,
    cut_is_session_root: bool,
    attachment_zone: Option<&str>,
    _primary_delegation: Option<&TraceNode>,
    node: TraceNode,
) -> Vec<TraceNode> {
    let branch_origin =
        matches!(&node.origin, NodeOrigin::Branch { .. }).then(|| node.origin.clone());

    let Some(expected_zone) = attachment_zone else {
        if let Some(origin) = branch_origin {
            let mut node = node;
            apply_branch_origin(&mut node, origin);
            return vec![node];
        }
        return vec![node];
    };

    let Some(mut node) = extract_delegation_hop(&node, &cut_hop.zone, expected_zone) else {
        return Vec::new();
    };

    if cut_is_session_root {
        node.children.clear();
    }

    if let Some(origin) = branch_origin {
        apply_branch_origin(&mut node, origin);
    }
    vec![node]
}

/// Walk a single-path branch subtree to the delegation hop at `attachment_zone`.
fn extract_delegation_hop(
    node: &TraceNode,
    cut_zone: &str,
    attachment_zone: &str,
) -> Option<TraceNode> {
    let mut node = node.clone();
    loop {
        if node.hop.zone == attachment_zone {
            return Some(node);
        }
        if node.hop.zone == cut_zone && node.children.len() == 1 {
            let child = node.children[0].clone();
            if child.hop.zone != cut_zone
                && child.hop.zone != attachment_zone
                && child.hop.zone.ends_with('.')
            {
                // Org NS queried at the root cut often delegates straight to the qname zone.
                let mut synthetic = child;
                synthetic.hop.zone = attachment_zone.to_string();
                synthetic.children.clear();
                return Some(synthetic);
            }
        }
        match node.children.as_slice() {
            [only] => node = only.clone(),
            _ => return None,
        }
        if node.hop.zone != cut_zone && node.hop.zone != attachment_zone && node.children.is_empty()
        {
            return None;
        }
    }
}
