//! Fork-scoped path comparison projection shared by Compare, outline, and events.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::IpAddr;
use std::str::FromStr;

use dns_resolve::probe::{IcmpProber, probe_icmp_rtt};
use dns_resolve::{HopOutcome, NodePath, TraceHop, TraceNode, TraceTree};
use serde::Serialize;

use crate::session::TargetEnrichments;

use super::tree::ExploreTree;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct HopTiming {
    pub zone: String,
    pub rtt_ms: u64,
    pub from_cache: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReferralDiff {
    pub only_here: Vec<String>,
    pub missing: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnswerSummary {
    pub agree: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReferralSummary {
    pub agree: bool,
    pub comparable_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub shared: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub union: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PathSummary {
    pub path: NodePath,
    pub label: String,
    pub hop_count: usize,
    pub dns_rtt_per_hop: Vec<HopTiming>,
    pub dns_rtt_total_ms: u64,
    pub dns_rtt_delta_ms: Option<u64>,
    pub icmp_rtt_ms: Option<u64>,
    pub outcome: String,
    pub failed: bool,
    pub referral_ns: Vec<String>,
    pub referral_diff: ReferralDiff,
    pub cache_served_hops: Vec<usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ForkComparison {
    pub fork: NodePath,
    pub fork_zone: String,
    pub fork_qname: String,
    pub answers: AnswerSummary,
    pub referral: ReferralSummary,
    pub paths: Vec<PathSummary>,
}

pub fn fork_for_selection(tree: &TraceTree, selection: &NodePath) -> Option<NodePath> {
    let node = tree.resolve(selection)?;
    if node.children.len() >= 2 {
        return Some(selection.clone());
    }
    let mut path = selection.path.clone();
    while !path.is_empty() {
        path.pop();
        let parent = NodePath {
            tree: selection.tree,
            path: path.clone(),
        };
        let Some(parent_node) = tree.resolve(&parent) else {
            break;
        };
        if parent_node.children.len() >= 2 {
            return Some(parent);
        }
    }
    None
}

/// Shallowest fork anywhere in the tree.
pub fn nearest_fork(tree: &TraceTree, tree_index: usize) -> Option<NodePath> {
    let mut queue = VecDeque::from([NodePath::root(tree_index)]);
    while let Some(path) = queue.pop_front() {
        let Some(node) = tree.resolve(&path) else {
            continue;
        };
        if node.children.len() >= 2 {
            return Some(path);
        }
        for index in 0..node.children.len() {
            let mut child = path.path.clone();
            child.push(index);
            queue.push_back(NodePath {
                tree: path.tree,
                path: child,
            });
        }
    }
    None
}

/// Fork used for Compare at `selection`, including when the fork is below root.
pub fn fork_for_compare(tree: &TraceTree, selection: &NodePath) -> Option<NodePath> {
    if let Some(fork) = fork_for_selection(tree, selection) {
        return Some(fork);
    }
    let nearest = nearest_fork(tree, selection.tree)?;
    if selection.path.is_empty() || nearest.path.starts_with(&selection.path) {
        Some(nearest)
    } else {
        None
    }
}

pub fn summarize_fork(tree: &TraceTree, fork: &NodePath) -> Option<ForkComparison> {
    let fork_node = tree.resolve(fork)?;
    if fork_node.children.len() < 2 {
        return None;
    }

    let mut paths: Vec<PathSummary> = fork_node
        .children
        .iter()
        .enumerate()
        .map(|(index, child)| {
            let mut path = fork.path.clone();
            path.push(index);
            summarize_child(fork.tree, path, child)
        })
        .collect();

    let fastest = paths
        .iter()
        .filter(|path| !path.failed)
        .map(|path| path.dns_rtt_total_ms)
        .min();
    for path in &mut paths {
        path.dns_rtt_delta_ms = if path.failed {
            None
        } else {
            fastest.map(|baseline| path.dns_rtt_total_ms.saturating_sub(baseline))
        };
    }

    apply_referral_diffs(&mut paths);
    let referral = compute_referral_summary(&paths);

    Some(ForkComparison {
        fork: fork.clone(),
        fork_zone: fork_node.hop.zone.clone(),
        fork_qname: fork_node.hop.qname.clone(),
        answers: AnswerSummary {
            agree: paths_agree(&fork_node.children),
        },
        referral,
        paths,
    })
}

pub fn comparison_at(tree: &TraceTree, selection: &NodePath) -> Option<ForkComparison> {
    let fork = fork_for_compare(tree, selection)?;
    summarize_fork(tree, &fork)
}

pub fn comparison_for_explore(tree: &ExploreTree, selection: &NodePath) -> Option<ForkComparison> {
    comparison_at(tree.trace(), selection)
}

/// Read ICMP snapshot from session targets when enrichment exists for `server`.
pub fn icmp_snapshot_from_targets<'a>(
    targets: &'a BTreeMap<IpAddr, TargetEnrichments>,
    server: &str,
) -> Option<&'a dns_resolve::IcmpSnapshot> {
    let addr = IpAddr::from_str(server).ok()?;
    targets.get(&addr).and_then(|entry| entry.icmp.as_ref())
}

/// Read ICMP display RTT from session targets when a snapshot exists for `server`.
pub fn icmp_rtt_from_targets(
    targets: &BTreeMap<IpAddr, TargetEnrichments>,
    server: &str,
) -> Option<u64> {
    icmp_snapshot_from_targets(targets, server).map(|snapshot| snapshot.avg_ms)
}

pub fn enrich_icmp(
    mut comparison: ForkComparison,
    tree: &TraceTree,
    targets: &BTreeMap<IpAddr, TargetEnrichments>,
    prober: &dyn IcmpProber,
) -> ForkComparison {
    let mut cache = std::collections::HashMap::new();
    enrich_icmp_cached(&mut comparison, tree, targets, &mut cache, prober);
    comparison
}

pub fn enrich_icmp_cached(
    comparison: &mut ForkComparison,
    tree: &TraceTree,
    targets: &BTreeMap<IpAddr, TargetEnrichments>,
    cache: &mut std::collections::HashMap<String, Option<u64>>,
    prober: &dyn IcmpProber,
) {
    for path in &mut comparison.paths {
        let Some(node) = tree.resolve(&path.path) else {
            continue;
        };
        let server = node.hop.server.clone();
        if let Some(rtt) = icmp_rtt_from_targets(targets, &server) {
            path.icmp_rtt_ms = Some(rtt);
            continue;
        }
        let rtt = *cache.entry(server.clone()).or_insert_with(|| {
            IpAddr::from_str(&server)
                .ok()
                .and_then(|addr| probe_icmp_rtt(prober, addr))
        });
        path.icmp_rtt_ms = rtt;
    }
}

pub fn render_comparison_text(comparison: &ForkComparison) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "Compare fork {} ({})  at-path {}",
        comparison.fork_zone,
        comparison.fork_qname,
        format_node_path(&comparison.fork)
    ));
    if comparison.answers.agree {
        lines.push("Answers agree (same response code and answer records)".to_string());
    }
    if let Some(line) = referral_header_line(&comparison.referral) {
        lines.push(line);
    }
    lines.push(format!(
        "{:<22} {:>4} {:>8} {:>6} {:>6}  {:<16} {}",
        "server", "hops", "dns", "Δ", "icmp", "outcome", "referral Δ"
    ));
    for path in &comparison.paths {
        let delta = match path.dns_rtt_delta_ms {
            Some(0) => "0".to_string(),
            Some(ms) => format!("+{ms}"),
            None => "—".to_string(),
        };
        let icmp = path
            .icmp_rtt_ms
            .map(|ms| format!("{ms}ms"))
            .unwrap_or_else(|| "n/a".to_string());
        lines.push(format!(
            "{:<22} {:>4} {:>8} {:>6} {:>6}  {:<16} {}",
            truncate(&path.label, 22),
            path.hop_count,
            format!("{}ms", path.dns_rtt_total_ms),
            delta,
            icmp,
            truncate(&path.outcome, 16),
            format_referral_delta_column(&path.referral_diff, comparison.referral.agree)
        ));
        if !path.dns_rtt_per_hop.is_empty() {
            let hops = path
                .dns_rtt_per_hop
                .iter()
                .map(format_hop_timing)
                .collect::<Vec<_>>()
                .join(" → ");
            lines.push(format!("  hops: {hops}"));
        }
    }
    lines.join("\n") + "\n"
}

pub fn render_comparison_json(session_id: &str, comparison: &ForkComparison) -> String {
    #[derive(Serialize)]
    struct PathComparisonEvent<'a> {
        event: &'static str,
        session: &'a str,
        #[serde(flatten)]
        comparison: &'a ForkComparison,
    }
    serde_json::to_string(&PathComparisonEvent {
        event: "path_comparison",
        session: session_id,
        comparison,
    })
    .expect("json")
}

/// Header line listing shared or divergent referral NS at the fork.
pub fn referral_header_line(referral: &ReferralSummary) -> Option<String> {
    if referral.comparable_count == 0 {
        return None;
    }
    if referral.agree {
        return Some(format!(
            "referral NS (all paths): {}",
            referral.shared.join(", ")
        ));
    }
    if referral.union.is_empty() {
        return None;
    }
    Some(format!(
        "referral NS (differ): {}",
        referral.union.join(", ")
    ))
}

/// Per-row referral column: em dash when paths agree or this row has no diff.
pub fn format_referral_delta_column(diff: &ReferralDiff, referral_agree: bool) -> String {
    if referral_agree {
        return "—".to_string();
    }
    let formatted = format_referral_diff(diff);
    if formatted.is_empty() {
        "—".to_string()
    } else {
        formatted
    }
}

fn summarize_child(tree_index: usize, path: Vec<usize>, child: &TraceNode) -> PathSummary {
    let chain = primary_chain(child);
    let hop_count = chain.len();
    let dns_rtt_per_hop: Vec<HopTiming> = chain
        .iter()
        .map(|node| HopTiming {
            zone: node.hop.zone.clone(),
            rtt_ms: node.hop.rtt_ms,
            from_cache: node.hop.from_cache,
        })
        .collect();
    let dns_rtt_total_ms = dns_rtt_per_hop.iter().map(|hop| hop.rtt_ms).sum();
    let cache_served_hops = dns_rtt_per_hop
        .iter()
        .enumerate()
        .filter(|(_, hop)| hop.from_cache)
        .map(|(index, _)| index)
        .collect();
    let leaf = chain.last().expect("child chain is non-empty");
    PathSummary {
        path: NodePath {
            tree: tree_index,
            path,
        },
        label: path_label(&child.hop),
        hop_count,
        dns_rtt_per_hop,
        dns_rtt_total_ms,
        dns_rtt_delta_ms: None,
        icmp_rtt_ms: None,
        outcome: outcome_text(&leaf.hop),
        failed: matches!(leaf.hop.outcome, HopOutcome::Failed { .. }),
        referral_ns: child.hop.referral_ns.clone(),
        referral_diff: ReferralDiff {
            only_here: Vec::new(),
            missing: Vec::new(),
        },
        cache_served_hops,
    }
}

fn primary_chain(node: &TraceNode) -> Vec<&TraceNode> {
    let mut chain = vec![node];
    let mut current = node;
    while let Some(child) = current.children.first() {
        chain.push(child);
        current = child;
    }
    chain
}

fn path_label(hop: &TraceHop) -> String {
    super::detail::format_server_endpoint(&hop.server, hop.server_name.as_deref())
}

fn outcome_text(hop: &TraceHop) -> String {
    match &hop.outcome {
        HopOutcome::Failed { kind, detail } => {
            if detail.is_empty() {
                kind.clone()
            } else {
                format!("{kind}: {detail}")
            }
        }
        _ => hop.rcode.clone(),
    }
}

fn referral_sets(paths: &[PathSummary]) -> Vec<BTreeSet<String>> {
    paths
        .iter()
        .map(|path| path.referral_ns.iter().cloned().collect())
        .collect()
}

fn comparable_referral_sets(sets: &[BTreeSet<String>]) -> Vec<&BTreeSet<String>> {
    // A path that returned no referral set (failed, or answered at the fork) has
    // nothing to differ from, and must not drag the baseline for the paths that did.
    sets.iter().filter(|set| !set.is_empty()).collect()
}

fn compute_referral_summary(paths: &[PathSummary]) -> ReferralSummary {
    let sets = referral_sets(paths);
    let comparable = comparable_referral_sets(&sets);
    let comparable_count = comparable.len();
    if comparable_count == 0 {
        return ReferralSummary {
            agree: false,
            comparable_count: 0,
            shared: Vec::new(),
            union: Vec::new(),
        };
    }
    if comparable_count == 1 {
        return ReferralSummary {
            agree: true,
            comparable_count,
            shared: sorted_names(comparable[0]),
            union: Vec::new(),
        };
    }
    let union: BTreeSet<String> = comparable
        .iter()
        .flat_map(|set| set.iter().cloned())
        .collect();
    let agree = comparable.windows(2).all(|pair| pair[0] == pair[1]);
    if agree {
        ReferralSummary {
            agree: true,
            comparable_count,
            shared: sorted_names(comparable[0]),
            union: Vec::new(),
        }
    } else {
        ReferralSummary {
            agree: false,
            comparable_count,
            shared: Vec::new(),
            union: sorted_names(&union),
        }
    }
}

fn sorted_names(set: &BTreeSet<String>) -> Vec<String> {
    set.iter().cloned().collect()
}

fn apply_referral_diffs(paths: &mut [PathSummary]) {
    let sets = referral_sets(paths);
    let comparable = comparable_referral_sets(&sets);
    let (union, intersection) = if comparable.len() < 2 {
        (BTreeSet::new(), BTreeSet::new())
    } else {
        let union: BTreeSet<String> = comparable
            .iter()
            .flat_map(|set| set.iter().cloned())
            .collect();
        let intersection: BTreeSet<String> = comparable.iter().fold(union.clone(), |acc, set| {
            acc.intersection(set).cloned().collect()
        });
        (union, intersection)
    };
    for (index, path) in paths.iter_mut().enumerate() {
        let set = &sets[index];
        path.referral_diff = if set.is_empty() {
            ReferralDiff {
                only_here: Vec::new(),
                missing: Vec::new(),
            }
        } else {
            ReferralDiff {
                only_here: set.difference(&intersection).cloned().collect(),
                missing: union.difference(set).cloned().collect(),
            }
        };
    }
}

fn paths_agree(children: &[TraceNode]) -> bool {
    if children.is_empty() {
        return true;
    }
    let signatures: Vec<_> = children
        .iter()
        .map(|child| {
            let leaf = primary_chain(child)
                .last()
                .map(|node| &node.hop)
                .expect("chain");
            match &leaf.outcome {
                HopOutcome::Failed { kind, detail } => (kind.clone(), detail.clone(), Vec::new()),
                _ => (leaf.rcode.clone(), String::new(), answer_signature(leaf)),
            }
        })
        .collect();
    signatures.windows(2).all(|pair| pair[0] == pair[1])
        && signatures
            .first()
            .is_none_or(|signature| signature.1.is_empty())
}

fn answer_signature(hop: &TraceHop) -> Vec<(String, String, String)> {
    let mut answers: Vec<_> = hop
        .response
        .answers
        .iter()
        .map(|record| {
            (
                record.name.to_string(),
                record.rtype.clone(),
                record.rdata.clone(),
            )
        })
        .collect();
    answers.sort();
    answers
}

fn format_node_path(path: &NodePath) -> String {
    path.to_string()
}

fn format_referral_diff(diff: &ReferralDiff) -> String {
    let mut parts = Vec::new();
    for name in &diff.only_here {
        parts.push(format!("+{name}"));
    }
    for name in &diff.missing {
        parts.push(format!("-{name}"));
    }
    if parts.is_empty() {
        String::new()
    } else {
        parts.join(" ")
    }
}

fn format_hop_timing(hop: &HopTiming) -> String {
    if hop.from_cache {
        format!("{} {}ms (cache)", hop.zone, hop.rtt_ms)
    } else {
        format!("{} {}ms", hop.zone, hop.rtt_ms)
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    let mut out = String::new();
    for ch in value.chars().take(max.saturating_sub(1)) {
        out.push(ch);
    }
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use dns_core::name::DomainName;
    use dns_core::response::DnsRecord;
    use dns_resolve::probe::{IcmpProbeResult, IcmpProber};
    use dns_resolve::{IcmpMethod, IcmpSnapshot, NodeOrigin, StoredDnsMessage, TraceTreeRequest};

    use crate::session::TargetEnrichments;

    struct ScriptedProber {
        result: IcmpProbeResult,
        calls: AtomicUsize,
    }

    impl IcmpProber for ScriptedProber {
        fn probe(&self, _addr: IpAddr, _timeout: Duration) -> IcmpProbeResult {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.result.clone()
        }
    }

    fn hop(
        zone: &str,
        server: &str,
        rtt_ms: u64,
        outcome: HopOutcome,
        referral_ns: &[&str],
        from_cache: bool,
        answers: Vec<DnsRecord>,
    ) -> TraceHop {
        TraceHop {
            zone: zone.into(),
            server: server.into(),
            server_name: None,
            qname: "example.com.".into(),
            qtype: "A".into(),
            transport: "udp".into(),
            rtt_ms,
            rcode: match &outcome {
                HopOutcome::Failed { .. } => "SERVFAIL".into(),
                _ => "NOERROR".into(),
            },
            nsid: None,
            ede_code: None,
            ede_text: None,
            referral_ns: referral_ns.iter().map(|name| (*name).to_string()).collect(),
            glue: vec![],
            response: StoredDnsMessage {
                answers,
                ..Default::default()
            },
            from_cache,
            outcome,
        }
    }

    fn a_record(ip: &str) -> DnsRecord {
        DnsRecord {
            name: DomainName::parse("example.com.").expect("name"),
            rtype: "A".into(),
            rclass: "IN".into(),
            ttl: 300,
            rdata: ip.into(),
        }
    }

    fn node(hop: TraceHop, children: Vec<TraceNode>) -> TraceNode {
        TraceNode {
            hop,
            origin: NodeOrigin::Trace,
            children,
        }
    }

    fn leaf(
        zone: &str,
        server: &str,
        rtt_ms: u64,
        outcome: HopOutcome,
        from_cache: bool,
        answers: Vec<DnsRecord>,
    ) -> TraceNode {
        node(
            hop(zone, server, rtt_ms, outcome, &[], from_cache, answers),
            vec![],
        )
    }

    /// Root fork with three sibling paths of different lengths and timings.
    fn differing_length_tree() -> TraceTree {
        TraceTree {
            request: TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
            root: node(
                hop(
                    ".",
                    "198.41.0.4",
                    10,
                    HopOutcome::Referral,
                    &[],
                    false,
                    vec![],
                ),
                vec![
                    node(
                        hop(
                            "com.",
                            "192.5.6.30",
                            20,
                            HopOutcome::Referral,
                            &["a.gtld-servers.net.", "b.gtld-servers.net."],
                            false,
                            vec![],
                        ),
                        vec![leaf(
                            "example.com.",
                            "93.184.216.34",
                            5,
                            HopOutcome::Answered,
                            false,
                            vec![a_record("93.184.216.34")],
                        )],
                    ),
                    node(
                        hop(
                            "com.",
                            "192.12.94.30",
                            40,
                            HopOutcome::Referral,
                            &["a.gtld-servers.net.", "c.gtld-servers.net."],
                            false,
                            vec![],
                        ),
                        vec![node(
                            hop(
                                "example.net.",
                                "192.0.2.1",
                                15,
                                HopOutcome::Referral,
                                &[],
                                false,
                                vec![],
                            ),
                            vec![leaf(
                                "example.com.",
                                "93.184.216.34",
                                8,
                                HopOutcome::Answered,
                                false,
                                vec![a_record("93.184.216.34")],
                            )],
                        )],
                    ),
                    leaf(
                        "com.",
                        "192.0.2.53",
                        0,
                        HopOutcome::Failed {
                            kind: "timeout".into(),
                            detail: "no response".into(),
                        },
                        false,
                        vec![],
                    ),
                ],
            ),
            budget_truncated: false,
        }
    }

    fn agreeing_tree() -> TraceTree {
        let answer = vec![a_record("93.184.216.34")];
        TraceTree {
            request: TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
            root: node(
                hop(
                    "org.",
                    "199.19.56.1",
                    12,
                    HopOutcome::Referral,
                    &[],
                    false,
                    vec![],
                ),
                vec![
                    leaf(
                        "example.com.",
                        "192.0.2.10",
                        30,
                        HopOutcome::Answered,
                        true,
                        answer.clone(),
                    ),
                    leaf(
                        "example.com.",
                        "192.0.2.11",
                        32,
                        HopOutcome::Answered,
                        false,
                        answer,
                    ),
                ],
            ),
            budget_truncated: false,
        }
    }

    #[test]
    fn differing_path_lengths_are_visible() {
        let tree = differing_length_tree();
        let comparison = summarize_fork(&tree, &NodePath::root(0)).expect("fork");
        assert_eq!(comparison.paths.len(), 3);
        assert_eq!(comparison.paths[0].hop_count, 2);
        assert_eq!(comparison.paths[1].hop_count, 3);
        assert_eq!(comparison.paths[2].hop_count, 1);
        assert_ne!(comparison.paths[0].hop_count, comparison.paths[1].hop_count);
    }

    #[test]
    fn timing_delta_uses_fastest_successful_sibling() {
        let tree = differing_length_tree();
        let comparison = summarize_fork(&tree, &NodePath::root(0)).expect("fork");
        // 20+5=25 vs 40+15+8=63 vs failed 0
        assert_eq!(comparison.paths[0].dns_rtt_total_ms, 25);
        assert_eq!(comparison.paths[1].dns_rtt_total_ms, 63);
        assert_eq!(comparison.paths[0].dns_rtt_delta_ms, Some(0));
        assert_eq!(comparison.paths[1].dns_rtt_delta_ms, Some(38));
        assert_eq!(comparison.paths[2].dns_rtt_delta_ms, None);
        assert!(comparison.paths[2].outcome.contains("timeout"));
    }

    #[test]
    fn failed_sibling_is_excluded_from_baseline() {
        let tree = differing_length_tree();
        let comparison = summarize_fork(&tree, &NodePath::root(0)).expect("fork");
        let successful_min = comparison
            .paths
            .iter()
            .filter(|path| path.dns_rtt_delta_ms == Some(0))
            .map(|path| path.dns_rtt_total_ms)
            .next()
            .expect("baseline");
        assert_eq!(successful_min, 25);
        assert_ne!(successful_min, 0);
    }

    #[test]
    fn referral_differences_are_surfaced() {
        let tree = differing_length_tree();
        let comparison = summarize_fork(&tree, &NodePath::root(0)).expect("fork");
        assert!(!comparison.referral.agree);
        assert!(
            comparison
                .referral
                .union
                .iter()
                .any(|name| name == "b.gtld-servers.net.")
        );
        assert!(
            comparison
                .referral
                .union
                .iter()
                .any(|name| name == "c.gtld-servers.net.")
        );
        assert!(
            comparison.paths[0]
                .referral_diff
                .only_here
                .iter()
                .any(|name| name == "b.gtld-servers.net.")
        );
        assert!(
            comparison.paths[1]
                .referral_diff
                .only_here
                .iter()
                .any(|name| name == "c.gtld-servers.net.")
        );
        assert!(
            comparison.paths[0]
                .referral_diff
                .missing
                .iter()
                .any(|name| name == "c.gtld-servers.net.")
        );
        let text = render_comparison_text(&comparison);
        assert!(text.contains("referral NS (differ):"));
        assert!(text.contains("+b.gtld-servers.net."));
    }

    #[test]
    fn matching_referral_sets_report_no_difference() {
        let mut tree = differing_length_tree();
        // Make the two answered siblings agree on the referral set; the failed
        // sibling still has none of its own.
        tree.root.children[1].hop.referral_ns = tree.root.children[0].hop.referral_ns.clone();
        let comparison = summarize_fork(&tree, &NodePath::root(0)).expect("fork");
        assert!(comparison.referral.agree);
        assert_eq!(
            comparison.referral.shared,
            vec![
                "a.gtld-servers.net.".to_string(),
                "b.gtld-servers.net.".to_string(),
            ]
        );
        for path in &comparison.paths {
            assert!(path.referral_diff.only_here.is_empty());
            assert!(path.referral_diff.missing.is_empty());
        }
        let text = render_comparison_text(&comparison);
        assert!(text.contains("referral NS (all paths):"));
        assert!(text.contains("a.gtld-servers.net., b.gtld-servers.net."));
        assert!(text.contains("referral Δ"));
        assert!(text.contains("—"));
        assert!(!text.contains("+a.gtld-servers.net."));
        assert!(!text.contains("-a.gtld-servers.net."));
    }

    #[test]
    fn answers_agree_case_is_flagged() {
        let tree = agreeing_tree();
        let comparison = summarize_fork(&tree, &NodePath::root(0)).expect("fork");
        assert!(comparison.answers.agree);
        assert_eq!(comparison.paths[0].outcome, "NOERROR");
        assert_eq!(comparison.paths[1].outcome, "NOERROR");
        let text = render_comparison_text(&comparison);
        assert!(text.contains("Answers agree"));
        assert!(!text.contains("All paths agree"));
    }

    #[test]
    fn cache_served_hops_are_recorded() {
        let tree = agreeing_tree();
        let comparison = summarize_fork(&tree, &NodePath::root(0)).expect("fork");
        assert_eq!(comparison.paths[0].cache_served_hops, vec![0]);
        assert!(comparison.paths[1].cache_served_hops.is_empty());
        let text = render_comparison_text(&comparison);
        assert!(text.contains("(cache)"));
    }

    #[test]
    fn summarize_does_not_probe() {
        let tree = agreeing_tree();
        let prober = ScriptedProber {
            result: IcmpProbeResult::Unavailable,
            calls: AtomicUsize::new(0),
        };
        let _ = summarize_fork(&tree, &NodePath::root(0));
        assert_eq!(prober.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn enrich_icmp_records_success_and_unavailable() {
        let tree = agreeing_tree();
        let comparison = summarize_fork(&tree, &NodePath::root(0)).expect("fork");
        let success = ScriptedProber {
            result: IcmpProbeResult::Rtt(Duration::from_millis(7)),
            calls: AtomicUsize::new(0),
        };
        let enriched = enrich_icmp(comparison.clone(), &tree, &BTreeMap::new(), &success);
        assert_eq!(success.calls.load(Ordering::SeqCst), 2);
        assert_eq!(enriched.paths[0].icmp_rtt_ms, Some(7));

        let unavailable = ScriptedProber {
            result: IcmpProbeResult::Unavailable,
            calls: AtomicUsize::new(0),
        };
        let blank = enrich_icmp(comparison, &tree, &BTreeMap::new(), &unavailable);
        assert!(blank.paths.iter().all(|path| path.icmp_rtt_ms.is_none()));
        let text = render_comparison_text(&blank);
        assert!(text.contains("n/a"));
    }

    #[test]
    fn comparison_at_root_uses_nearest_fork_below() {
        let tree = TraceTree {
            request: TraceTreeRequest {
                qname: "tuininga.org.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
            root: node(
                hop(
                    ".",
                    "198.41.0.4",
                    10,
                    HopOutcome::Referral,
                    &[],
                    false,
                    vec![],
                ),
                vec![node(
                    hop(
                        "org.",
                        "199.249.112.1",
                        8,
                        HopOutcome::Referral,
                        &[],
                        false,
                        vec![],
                    ),
                    vec![
                        leaf(
                            "tuininga.org.",
                            "193.47.99.5",
                            12,
                            HopOutcome::Answered,
                            false,
                            vec![],
                        ),
                        leaf(
                            "tuininga.org.",
                            "88.198.229.192",
                            14,
                            HopOutcome::Answered,
                            false,
                            vec![],
                        ),
                    ],
                )],
            ),
            budget_truncated: false,
        };
        let comparison = comparison_at(&tree, &NodePath::root(0)).expect("fork below root");
        assert_eq!(comparison.fork.path, vec![0]);
        assert_eq!(comparison.paths.len(), 2);
    }

    #[test]
    fn comparison_at_walks_up_to_parent_fork() {
        let tree = agreeing_tree();
        let comparison = comparison_at(
            &tree,
            &NodePath {
                tree: 0,
                path: vec![1],
            },
        )
        .expect("parent fork");
        assert!(comparison.fork.path.is_empty());
        assert_eq!(comparison.paths.len(), 2);
    }

    #[test]
    fn linear_tree_has_nothing_to_compare() {
        let tree = TraceTree {
            request: TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
            root: node(
                hop(
                    ".",
                    "198.41.0.4",
                    10,
                    HopOutcome::Referral,
                    &[],
                    false,
                    vec![],
                ),
                vec![leaf(
                    "com.",
                    "192.5.6.30",
                    8,
                    HopOutcome::Answered,
                    false,
                    vec![],
                )],
            ),
            budget_truncated: false,
        };
        assert!(comparison_at(&tree, &NodePath::root(0)).is_none());
    }

    #[test]
    fn newly_branched_child_appears_as_row() {
        let mut tree = agreeing_tree();
        let before = summarize_fork(&tree, &NodePath::root(0)).expect("before");
        assert_eq!(before.paths.len(), 2);
        tree.root.children.push(leaf(
            "example.com.",
            "192.0.2.12",
            40,
            HopOutcome::Answered,
            false,
            vec![a_record("93.184.216.34")],
        ));
        let after = summarize_fork(&tree, &NodePath::root(0)).expect("after");
        assert_eq!(after.paths.len(), 3);
        assert_eq!(after.paths[2].label, "192.0.2.12");
    }

    #[test]
    fn json_identifies_session_and_fork() {
        let tree = agreeing_tree();
        let comparison = summarize_fork(&tree, &NodePath::root(0)).expect("fork");
        let json = render_comparison_json("01JSESSION", &comparison);
        assert!(json.contains("\"event\":\"path_comparison\""));
        assert!(json.contains("\"session\":\"01JSESSION\""));
        assert!(json.contains("\"fork_zone\":\"org.\""));
        assert!(json.contains("\"answers\":{\"agree\":true}"));
        assert!(json.contains("\"referral\""));
        assert!(json.contains("\"hop_count\""));
        assert!(json.contains("\"dns_rtt_total_ms\""));
        assert!(!json.contains("\"all_agree\""));
    }

    #[test]
    fn enrich_icmp_reads_session_targets_without_probing() {
        let tree = agreeing_tree();
        let comparison = summarize_fork(&tree, &NodePath::root(0)).expect("fork");
        let ip10: IpAddr = "192.0.2.10".parse().expect("ip");
        let ip11: IpAddr = "192.0.2.11".parse().expect("ip");
        let mut targets = BTreeMap::new();
        targets.insert(
            ip10,
            TargetEnrichments {
                icmp: Some(IcmpSnapshot {
                    method: IcmpMethod::Datagram,
                    samples: 1,
                    min_ms: 5,
                    avg_ms: 6,
                    max_ms: 7,
                    probed_at: "2026-01-01T00:00:00Z".into(),
                }),
                ..Default::default()
            },
        );
        targets.insert(
            ip11,
            TargetEnrichments {
                icmp: Some(IcmpSnapshot {
                    method: IcmpMethod::Datagram,
                    samples: 1,
                    min_ms: 9,
                    avg_ms: 10,
                    max_ms: 11,
                    probed_at: "2026-01-01T00:00:00Z".into(),
                }),
                ..Default::default()
            },
        );
        let prober = ScriptedProber {
            result: IcmpProbeResult::Rtt(Duration::from_millis(99)),
            calls: AtomicUsize::new(0),
        };
        let enriched = enrich_icmp(comparison, &tree, &targets, &prober);
        assert_eq!(prober.calls.load(Ordering::SeqCst), 0);
        assert_eq!(enriched.paths[0].icmp_rtt_ms, Some(6));
        assert_eq!(enriched.paths[1].icmp_rtt_ms, Some(10));
    }

    #[test]
    fn enrich_icmp_falls_back_to_probe_when_target_missing() {
        let tree = agreeing_tree();
        let comparison = summarize_fork(&tree, &NodePath::root(0)).expect("fork");
        let prober = ScriptedProber {
            result: IcmpProbeResult::Rtt(Duration::from_millis(4)),
            calls: AtomicUsize::new(0),
        };
        let enriched = enrich_icmp(comparison, &tree, &BTreeMap::new(), &prober);
        assert_eq!(prober.calls.load(Ordering::SeqCst), 2);
        assert!(
            enriched
                .paths
                .iter()
                .all(|path| path.icmp_rtt_ms == Some(4))
        );
    }

    #[test]
    fn icmp_probe_uses_child_server_address() {
        let tree = agreeing_tree();
        let comparison = summarize_fork(&tree, &NodePath::root(0)).expect("fork");
        let seen = std::sync::Mutex::new(Vec::new());
        struct RecordingProber {
            seen: std::sync::Mutex<Vec<IpAddr>>,
        }
        impl IcmpProber for RecordingProber {
            fn probe(&self, addr: IpAddr, _timeout: Duration) -> IcmpProbeResult {
                self.seen.lock().expect("lock").push(addr);
                IcmpProbeResult::Unavailable
            }
        }
        let prober = RecordingProber { seen };
        let _ = enrich_icmp(comparison, &tree, &BTreeMap::new(), &prober);
        let addrs = prober.seen.lock().expect("lock");
        assert_eq!(
            *addrs,
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)),
            ]
        );
    }
}
