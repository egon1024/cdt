use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};

use dns_enrichment_cache::{ProbeProfile, SqliteEnrichmentCache, now_unix};
use dns_resolve::{
    ComparisonIcmpProber, IcmpSnapshot, TraceTree, collect_unique_server_targets,
    comparison_icmp_prober,
};

use crate::icmp_notice::format_comparison_icmp_notice;
use crate::runtime::Runtime;
use crate::session::{SessionDocument, merge_target_hostname, now_rfc3339};

static ICMP_NOTICE_EMITTED: AtomicBool = AtomicBool::new(false);

pub trait TraceEnrichmentProber: Send + Sync {
    fn probe_snapshot(
        &self,
        ip: IpAddr,
        timeout_ms: u64,
        ping_samples: u8,
        probed_at: &str,
    ) -> Option<IcmpSnapshot>;
}

impl TraceEnrichmentProber for ComparisonIcmpProber {
    fn probe_snapshot(
        &self,
        ip: IpAddr,
        timeout_ms: u64,
        ping_samples: u8,
        probed_at: &str,
    ) -> Option<IcmpSnapshot> {
        self.probe_enrichment_snapshot(ip, timeout_ms, ping_samples, probed_at.to_string())
    }
}

pub fn populate_after_trace(
    document: &mut SessionDocument,
    tree: &TraceTree,
    runtime: &Runtime,
    fresh: bool,
) {
    if !runtime.config.enrichment_icmp_enabled || !runtime.config.enrichment_icmp_on_trace {
        merge_tree_names(document, tree);
        return;
    }
    populate_icmp_for_tree(
        document,
        tree,
        runtime,
        fresh,
        comparison_icmp_prober(),
        |_| true,
    );
}

pub fn populate_after_branch(
    document: &mut SessionDocument,
    tree_index: usize,
    runtime: &Runtime,
    fresh: bool,
) {
    let Some(tree) = document
        .trees
        .get(tree_index)
        .map(|entry| entry.tree.clone())
    else {
        return;
    };
    if !runtime.config.enrichment_icmp_enabled {
        merge_tree_names(document, &tree);
        return;
    }
    let existing_ips: HashSet<IpAddr> = document.targets.keys().copied().collect();
    populate_icmp_for_tree(
        document,
        &tree,
        runtime,
        fresh,
        comparison_icmp_prober(),
        |ip| fresh || !existing_ips.contains(&ip),
    );
}

fn merge_tree_names(document: &mut SessionDocument, tree: &TraceTree) {
    for (ip, names) in collect_unique_server_targets(tree) {
        let entry = document.targets.entry(ip).or_default();
        for name in names {
            merge_target_hostname(&mut entry.names, &name);
        }
    }
}

fn populate_icmp_for_tree(
    document: &mut SessionDocument,
    tree: &TraceTree,
    runtime: &Runtime,
    fresh: bool,
    prober: &dyn TraceEnrichmentProber,
    should_probe: impl Fn(IpAddr) -> bool,
) {
    maybe_emit_icmp_notice();
    let profile = probe_profile(runtime);
    let collected = collect_unique_server_targets(tree);
    for (ip, names) in collected {
        let entry = document.targets.entry(ip).or_default();
        for name in names {
            merge_target_hostname(&mut entry.names, &name);
        }
        if !should_probe(ip) {
            continue;
        }
        let snapshot = resolve_icmp_snapshot(
            ip,
            runtime.enrichment_cache.as_deref(),
            &profile,
            fresh,
            prober,
            runtime.config.enrichment_icmp_timeout_ms,
            runtime.config.enrichment_icmp_ping_samples,
        );
        if let Some(snapshot) = snapshot {
            entry.icmp = Some(snapshot);
        }
    }
}

fn resolve_icmp_snapshot(
    ip: IpAddr,
    cache: Option<&SqliteEnrichmentCache>,
    profile: &ProbeProfile,
    fresh: bool,
    prober: &dyn TraceEnrichmentProber,
    timeout_ms: u64,
    ping_samples: u8,
) -> Option<IcmpSnapshot> {
    let now = now_unix();
    if !fresh {
        if let Some(cache) = cache {
            if let Some(snapshot) = cache.get_icmp(ip, profile, now) {
                return Some(snapshot);
            }
        }
    }
    let probed_at = now_rfc3339();
    let snapshot = prober.probe_snapshot(ip, timeout_ms, ping_samples, &probed_at)?;
    if let Some(cache) = cache {
        let _ = cache.put_icmp(ip, profile, &snapshot, now);
    }
    Some(snapshot)
}

fn probe_profile(runtime: &Runtime) -> ProbeProfile {
    ProbeProfile {
        timeout_ms: runtime.config.enrichment_icmp_timeout_ms,
        ping_samples: runtime.config.enrichment_icmp_ping_samples,
    }
}

fn maybe_emit_icmp_notice() {
    if ICMP_NOTICE_EMITTED.swap(true, Ordering::SeqCst) {
        return;
    }
    if let Some(notice) = format_comparison_icmp_notice(comparison_icmp_prober().capability()) {
        eprintln!("{notice}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::{
        HopOutcome, IcmpMethod, NodeOrigin, TraceHop, TraceNode, TraceTreeRequest,
        build_linear_tree, tree::BranchIntent,
    };
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use crate::session::TargetEnrichments;
    use crate::dig_options::TraceOptions;
    use crate::paths::DelvePaths;
    use crate::runtime::Runtime;
    use crate::trace_request::TraceRequest;

    struct MockProber {
        snapshots: BTreeMap<IpAddr, IcmpSnapshot>,
        calls: Mutex<Vec<IpAddr>>,
    }

    impl MockProber {
        fn new() -> Self {
            Self {
                snapshots: BTreeMap::new(),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn with_snapshot(mut self, ip: IpAddr, snapshot: IcmpSnapshot) -> Self {
            self.snapshots.insert(ip, snapshot);
            self
        }
    }

    impl TraceEnrichmentProber for MockProber {
        fn probe_snapshot(
            &self,
            ip: IpAddr,
            _timeout_ms: u64,
            _ping_samples: u8,
            _probed_at: &str,
        ) -> Option<IcmpSnapshot> {
            self.calls.lock().expect("lock").push(ip);
            self.snapshots.get(&ip).cloned()
        }
    }

    fn hop(server: &str, server_name: Option<&str>) -> TraceHop {
        TraceHop {
            zone: ".".into(),
            server: server.into(),
            server_name: server_name.map(str::to_string),
            qname: "example.com.".into(),
            qtype: "A".into(),
            transport: "udp".into(),
            rtt_ms: 10,
            rcode: "NOERROR".into(),
            nsid: None,
            ede_code: None,
            ede_text: None,
            referral_ns: vec![],
            glue: vec![],
            response: Default::default(),
            from_cache: false,
            outcome: HopOutcome::Answered,
        }
    }

    fn branched_tree() -> TraceTree {
        TraceTree {
            request: TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-09-06T00:00:00Z".into(),
            },
            root: TraceNode {
                hop: hop("1.1.1.1", Some("ns1.example.com.")),
                origin: NodeOrigin::Trace,
                children: vec![TraceNode {
                    hop: hop("8.8.8.8", Some("ns.google.")),
                    origin: NodeOrigin::Branch {
                        at: dns_resolve::NodePath::root(0),
                        intent: BranchIntent::AlternateServer,
                        at_time: "2026-09-06T00:00:00Z".into(),
                    },
                    children: vec![],
                }],
            },
            budget_truncated: false,
        }
    }

    fn sample_request() -> TraceRequest {
        TraceRequest::from_options(&TraceOptions {
            qname: "example.com".into(),
            ..Default::default()
        })
    }

    fn runtime_with_cache(dir: &tempfile::TempDir) -> Runtime {
        let paths = DelvePaths::from_root(dir.path());
        let mut runtime = Runtime::open(paths);
        runtime.config.enrichment_icmp_enabled = true;
        runtime.config.enrichment_icmp_on_trace = true;
        runtime
    }

    fn snapshot_for(_ip: IpAddr) -> IcmpSnapshot {
        IcmpSnapshot {
            method: IcmpMethod::Datagram,
            samples: 1,
            min_ms: 12,
            avg_ms: 12,
            max_ms: 12,
            probed_at: "2026-09-06T00:00:00Z".into(),
        }
    }

    #[test]
    fn merge_tree_names_normalizes_hostnames() {
        let tree = build_linear_tree(
            vec![hop("1.1.1.1", Some("ONE.example.com."))],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-09-06T00:00:00Z".into(),
            },
        );
        let mut document = SessionDocument::new("01TEST".into(), sample_request(), tree.clone());
        merge_tree_names(&mut document, &tree);
        let entry = document
            .targets
            .get(&"1.1.1.1".parse().unwrap())
            .expect("target");
        assert!(entry.names.contains("one.example.com"));
    }

    #[test]
    fn populate_after_trace_writes_cache_and_targets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_with_cache(&dir);
        let ip: IpAddr = "1.1.1.1".parse().expect("ip");
        let snapshot = snapshot_for(ip);
        let prober = MockProber::new().with_snapshot(ip, snapshot.clone());
        let tree = build_linear_tree(
            vec![hop("1.1.1.1", None)],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-09-06T00:00:00Z".into(),
            },
        );
        let mut document = SessionDocument::new("01TEST".into(), sample_request(), tree.clone());
        populate_icmp_for_tree(&mut document, &tree, &runtime, false, &prober, |_| true);
        assert_eq!(
            document
                .targets
                .get(&ip)
                .and_then(|entry| entry.icmp.as_ref()),
            Some(&snapshot)
        );
        let cache = runtime.enrichment_cache.as_ref().expect("cache");
        let profile = probe_profile(&runtime);
        assert_eq!(
            cache.get_icmp(ip, &profile, now_unix()).as_ref(),
            Some(&snapshot)
        );
    }

    #[test]
    fn fresh_bypasses_cache_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_with_cache(&dir);
        let ip: IpAddr = "1.1.1.1".parse().expect("ip");
        let cache = runtime.enrichment_cache.as_ref().expect("cache");
        let profile = probe_profile(&runtime);
        let stale = IcmpSnapshot {
            avg_ms: 1,
            ..snapshot_for(ip)
        };
        cache
            .put_icmp(ip, &profile, &stale, now_unix())
            .expect("seed cache");
        let fresh_snapshot = IcmpSnapshot {
            avg_ms: 99,
            ..snapshot_for(ip)
        };
        let prober = MockProber::new().with_snapshot(ip, fresh_snapshot.clone());
        let tree = build_linear_tree(
            vec![hop("1.1.1.1", None)],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-09-06T00:00:00Z".into(),
            },
        );
        let mut document = SessionDocument::new("01TEST".into(), sample_request(), tree.clone());
        populate_icmp_for_tree(&mut document, &tree, &runtime, true, &prober, |_| true);
        assert_eq!(
            document
                .targets
                .get(&ip)
                .and_then(|entry| entry.icmp.as_ref()),
            Some(&fresh_snapshot)
        );
        assert_eq!(prober.calls.lock().expect("lock").len(), 1);
    }

    #[test]
    fn branch_only_probes_new_ips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_with_cache(&dir);
        let existing: IpAddr = "1.1.1.1".parse().expect("ip");
        let new_ip: IpAddr = "8.8.8.8".parse().expect("ip");
        let tree = branched_tree();
        let mut document = SessionDocument::new("01TEST".into(), sample_request(), tree.clone());
        document.targets.insert(
            existing,
            TargetEnrichments {
                icmp: Some(snapshot_for(existing)),
                ..Default::default()
            },
        );
        let prober = MockProber::new().with_snapshot(new_ip, snapshot_for(new_ip));
        let existing_ips: HashSet<IpAddr> = document.targets.keys().copied().collect();
        populate_icmp_for_tree(&mut document, &tree, &runtime, false, &prober, |ip| {
            !existing_ips.contains(&ip)
        });
        assert_eq!(
            document
                .targets
                .get(&existing)
                .and_then(|entry| entry.icmp.as_ref()),
            Some(&snapshot_for(existing))
        );
        assert_eq!(*prober.calls.lock().expect("lock"), vec![new_ip]);
    }
}
