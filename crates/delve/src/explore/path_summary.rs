//! Fork-scoped path comparison projection shared by Compare, outline, and events.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::str::FromStr;

use dns_resolve::probe::{IcmpProber, probe_icmp_rtt};
use dns_resolve::{HopOutcome, NodePath, TraceHop, TraceNode, TraceTree};
use serde::Serialize;

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
    pub all_agree: bool,
    pub paths: Vec<PathSummary>,
}

pub fn fork_for_selection(tree: &TraceTree, selection: &NodePath) -> Option<NodePath> {
    let node = tree.resolve(selection)?;
    if node.children.len() >= 2 {
        return Some(selection.clone());
    }
    if selection.path.is_empty() {
        return None;
    }
    let mut parent_path = selection.path.clone();
    parent_path.pop();
    let parent = NodePath {
        tree: selection.tree,
        path: parent_path,
    };
    let parent_node = tree.resolve(&parent)?;
    if parent_node.children.len() >= 2 {
        Some(parent)
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

    Some(ForkComparison {
        fork: fork.clone(),
        fork_zone: fork_node.hop.zone.clone(),
        fork_qname: fork_node.hop.qname.clone(),
        all_agree: paths_agree(&fork_node.children),
        paths,
    })
}

pub fn comparison_at(tree: &TraceTree, selection: &NodePath) -> Option<ForkComparison> {
    let fork = fork_for_selection(tree, selection)?;
    summarize_fork(tree, &fork)
}

pub fn comparison_for_explore(tree: &ExploreTree, selection: &NodePath) -> Option<ForkComparison> {
    comparison_at(tree.trace(), selection)
}

pub fn enrich_icmp(
    mut comparison: ForkComparison,
    tree: &TraceTree,
    prober: &dyn IcmpProber,
) -> ForkComparison {
    let mut cache = std::collections::HashMap::new();
    enrich_icmp_cached(&mut comparison, tree, &mut cache, prober);
    comparison
}

pub fn enrich_icmp_cached(
    comparison: &mut ForkComparison,
    tree: &TraceTree,
    cache: &mut std::collections::HashMap<String, Option<u64>>,
    prober: &dyn IcmpProber,
) {
    for path in &mut comparison.paths {
        let Some(node) = tree.resolve(&path.path) else {
            continue;
        };
        let server = node.hop.server.clone();
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
        "Compare fork {} ({})  path {}",
        comparison.fork_zone,
        comparison.fork_qname,
        format_node_path(&comparison.fork)
    ));
    if comparison.all_agree {
        lines.push("All paths agree (same response code and answer records)".to_string());
    }
    lines.push(format!(
        "{:<22} {:>4} {:>8} {:>6} {:>6}  {:<16} {}",
        "server", "hops", "dns", "Δ", "icmp", "outcome", "referral"
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
            format_referral_diff(&path.referral_diff)
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
    let payload = serde_json::json!({
        "event": "path_comparison",
        "session": session_id,
        "fork": comparison.fork,
        "fork_zone": comparison.fork_zone,
        "fork_qname": comparison.fork_qname,
        "all_agree": comparison.all_agree,
        "paths": comparison.paths,
    });
    serde_json::to_string(&payload).expect("json")
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
    match hop.server_name.as_deref() {
        Some(name) if !name.is_empty() => format!("{name} ({})", hop.server),
        _ => hop.server.clone(),
    }
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

fn apply_referral_diffs(paths: &mut [PathSummary]) {
    let sets: Vec<BTreeSet<String>> = paths
        .iter()
        .map(|path| path.referral_ns.iter().cloned().collect())
        .collect();
    let union: BTreeSet<String> = sets.iter().flat_map(|set| set.iter().cloned()).collect();
    let intersection: BTreeSet<String> = sets.iter().fold(union.clone(), |acc, set| {
        acc.intersection(set).cloned().collect()
    });
    for (index, path) in paths.iter_mut().enumerate() {
        let set = &sets[index];
        path.referral_diff = ReferralDiff {
            only_here: set.difference(&intersection).cloned().collect(),
            missing: union.difference(set).cloned().collect(),
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
    if path.path.is_empty() {
        return "[0]".to_string();
    }
    format!(
        "[0.{}]",
        path.path
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(".")
    )
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
    use dns_resolve::{NodeOrigin, StoredDnsMessage, TraceTreeRequest};

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
    }

    #[test]
    fn all_agree_case_is_flagged() {
        let tree = agreeing_tree();
        let comparison = summarize_fork(&tree, &NodePath::root(0)).expect("fork");
        assert!(comparison.all_agree);
        assert_eq!(comparison.paths[0].outcome, "NOERROR");
        assert_eq!(comparison.paths[1].outcome, "NOERROR");
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
        let enriched = enrich_icmp(comparison.clone(), &tree, &success);
        assert_eq!(success.calls.load(Ordering::SeqCst), 2);
        assert_eq!(enriched.paths[0].icmp_rtt_ms, Some(7));

        let unavailable = ScriptedProber {
            result: IcmpProbeResult::Unavailable,
            calls: AtomicUsize::new(0),
        };
        let blank = enrich_icmp(comparison, &tree, &unavailable);
        assert!(blank.paths.iter().all(|path| path.icmp_rtt_ms.is_none()));
        let text = render_comparison_text(&blank);
        assert!(text.contains("n/a"));
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
        assert!(json.contains("\"hop_count\""));
        assert!(json.contains("\"dns_rtt_total_ms\""));
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
        let _ = enrich_icmp(comparison, &tree, &prober);
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
