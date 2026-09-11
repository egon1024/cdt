use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

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
    maybe_emit_icmp_notice();
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
) -> Option<String> {
    let tree = document
        .trees
        .get(tree_index)
        .map(|entry| entry.tree.clone())?;
    if !runtime.config.enrichment_icmp_enabled {
        merge_tree_names(document, &tree);
        return None;
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
    icmp_capability_notice_once()
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
    let profile = probe_profile(runtime);
    let collected = collect_unique_server_targets(tree);
    let mut probe_ips = Vec::new();
    for (ip, names) in collected {
        let entry = document.targets.entry(ip).or_default();
        for name in names {
            merge_target_hostname(&mut entry.names, &name);
        }
        if !should_probe(ip) {
            continue;
        }
        if let Some(snapshot) =
            cached_icmp_snapshot(ip, runtime.enrichment_cache.as_deref(), &profile, fresh)
        {
            entry.icmp = Some(snapshot);
            continue;
        }
        probe_ips.push(ip);
    }
    let probed = probe_icmp_snapshots_parallel(
        &probe_ips,
        runtime.config.enrichment_icmp_max_parallel_probes,
        runtime.enrichment_cache.as_deref(),
        &profile,
        prober,
        runtime.config.enrichment_icmp_timeout_ms,
        runtime.config.enrichment_icmp_ping_samples,
        |_, _| {},
    );
    for (ip, snapshot) in probed {
        if let Some(snapshot) = snapshot {
            document.targets.entry(ip).or_default().icmp = Some(snapshot);
        }
    }
}

fn cached_icmp_snapshot(
    ip: IpAddr,
    cache: Option<&SqliteEnrichmentCache>,
    profile: &ProbeProfile,
    fresh: bool,
) -> Option<IcmpSnapshot> {
    if fresh {
        return None;
    }
    let now = now_unix();
    cache.and_then(|cache| cache.get_icmp(ip, profile, now))
}

fn resolve_icmp_snapshot(
    ip: IpAddr,
    cache: Option<&SqliteEnrichmentCache>,
    profile: &ProbeProfile,
    prober: &dyn TraceEnrichmentProber,
    timeout_ms: u64,
    ping_samples: u8,
) -> Option<IcmpSnapshot> {
    let probed_at = now_rfc3339();
    let snapshot = prober.probe_snapshot(ip, timeout_ms, ping_samples, &probed_at)?;
    if let Some(cache) = cache {
        let _ = cache.put_icmp(ip, profile, &snapshot, now_unix());
    }
    Some(snapshot)
}

/// Probe many IPs with a bounded worker pool (batch `thread::scope` workers).
#[allow(clippy::too_many_arguments)]
fn probe_icmp_snapshots_parallel(
    ips: &[IpAddr],
    max_parallel: usize,
    cache: Option<&SqliteEnrichmentCache>,
    profile: &ProbeProfile,
    prober: &dyn TraceEnrichmentProber,
    timeout_ms: u64,
    ping_samples: u8,
    mut on_progress: impl FnMut(usize, usize),
) -> Vec<(IpAddr, Option<IcmpSnapshot>)> {
    let total = ips.len();
    if total == 0 {
        return Vec::new();
    }
    let max_parallel = max_parallel.max(1);
    if max_parallel == 1 {
        return ips
            .iter()
            .enumerate()
            .map(|(index, ip)| {
                on_progress(index + 1, total);
                (
                    *ip,
                    resolve_icmp_snapshot(*ip, cache, profile, prober, timeout_ms, ping_samples),
                )
            })
            .collect();
    }

    let mut results = Vec::with_capacity(total);
    let mut next_index = 0usize;
    while next_index < total {
        let batch_end = (next_index + max_parallel).min(total);
        let batch = &ips[next_index..batch_end];
        let batch_results = thread::scope(|scope| {
            batch
                .iter()
                .map(|ip| {
                    let ip = *ip;
                    scope.spawn(move || {
                        (
                            ip,
                            resolve_icmp_snapshot(
                                ip,
                                cache,
                                profile,
                                prober,
                                timeout_ms,
                                ping_samples,
                            ),
                        )
                    })
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| handle.join().expect("icmp probe worker"))
                .collect::<Vec<_>>()
        });
        for (offset, outcome) in batch_results.into_iter().enumerate() {
            on_progress(next_index + offset + 1, total);
            results.push(outcome);
        }
        next_index = batch_end;
    }
    results
}

pub fn probe_profile(runtime: &Runtime) -> ProbeProfile {
    ProbeProfile {
        timeout_ms: runtime.config.enrichment_icmp_timeout_ms,
        ping_samples: runtime.config.enrichment_icmp_ping_samples,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpRefreshReport {
    pub targets_total: usize,
    pub targets_updated: usize,
    pub targets_failed: usize,
    pub capability_notice: Option<String>,
}

pub fn refresh_icmp_targets_with_prober(
    document: &mut SessionDocument,
    runtime: &Runtime,
    prober: &dyn TraceEnrichmentProber,
    mut on_progress: impl FnMut(usize, usize),
) -> IcmpRefreshReport {
    let Some(tree) = document.primary_tree().cloned() else {
        return IcmpRefreshReport {
            targets_total: 0,
            targets_updated: 0,
            targets_failed: 0,
            capability_notice: None,
        };
    };
    if !runtime.config.enrichment_icmp_enabled {
        merge_tree_names(document, &tree);
        return IcmpRefreshReport {
            targets_total: 0,
            targets_updated: 0,
            targets_failed: 0,
            capability_notice: None,
        };
    }
    let capability_notice = icmp_capability_notice_once();
    merge_tree_names(document, &tree);
    let ips: Vec<IpAddr> = collect_unique_server_targets(&tree).into_keys().collect();
    let total = ips.len();
    let profile = probe_profile(runtime);
    let mut updated = 0usize;
    let mut failed = 0usize;
    let priors: BTreeMap<IpAddr, Option<IcmpSnapshot>> = ips
        .iter()
        .map(|ip| {
            (
                *ip,
                document
                    .targets
                    .get(ip)
                    .and_then(|entry| entry.icmp.clone()),
            )
        })
        .collect();
    let probed = probe_icmp_snapshots_parallel(
        &ips,
        runtime.config.enrichment_icmp_max_parallel_probes,
        runtime.enrichment_cache.as_deref(),
        &profile,
        prober,
        runtime.config.enrichment_icmp_timeout_ms,
        runtime.config.enrichment_icmp_ping_samples,
        &mut on_progress,
    );
    for (ip, snapshot) in probed {
        let prior = priors.get(&ip).and_then(|value| value.clone());
        let entry = document.targets.entry(ip).or_default();
        if let Some(snapshot) = snapshot {
            entry.icmp = Some(snapshot);
            updated += 1;
        } else if prior.is_some() {
            entry.icmp = prior;
            failed += 1;
        } else {
            failed += 1;
        }
    }
    IcmpRefreshReport {
        targets_total: total,
        targets_updated: updated,
        targets_failed: failed,
        capability_notice,
    }
}

/// One-line guidance when comparison ICMP cannot use datagram sockets.
/// Emitted at most once per process; safe to call from background workers.
pub fn icmp_capability_notice_once() -> Option<String> {
    if ICMP_NOTICE_EMITTED.swap(true, Ordering::SeqCst) {
        return None;
    }
    format_comparison_icmp_notice(comparison_icmp_prober().capability())
}

fn maybe_emit_icmp_notice() {
    if let Some(notice) = icmp_capability_notice_once() {
        eprintln!("{notice}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::{
        HopOutcome, IcmpMethod, NodeOrigin, TraceHop, TraceNode, TraceTree, TraceTreeRequest,
        build_linear_tree, tree::BranchIntent,
    };
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    use crate::dig_options::TraceOptions;
    use crate::paths::DelvePaths;
    use crate::runtime::Runtime;
    use crate::session::TargetEnrichments;
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

    fn runtime_with_parallelism(dir: &tempfile::TempDir, max_parallel: usize) -> Runtime {
        let mut runtime = runtime_with_cache(dir);
        runtime.config.enrichment_icmp_max_parallel_probes = max_parallel;
        runtime
    }

    struct ConcurrentProbeTracker {
        delay: Duration,
        in_flight: AtomicUsize,
        peak_in_flight: AtomicUsize,
        snapshots: BTreeMap<IpAddr, IcmpSnapshot>,
    }

    impl ConcurrentProbeTracker {
        fn new(delay: Duration, snapshots: BTreeMap<IpAddr, IcmpSnapshot>) -> Self {
            Self {
                delay,
                in_flight: AtomicUsize::new(0),
                peak_in_flight: AtomicUsize::new(0),
                snapshots,
            }
        }

        fn record_in_flight(&self, current: usize) {
            let mut peak = self.peak_in_flight.load(Ordering::SeqCst);
            while current > peak {
                match self.peak_in_flight.compare_exchange(
                    peak,
                    current,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => break,
                    Err(observed) => peak = observed,
                }
            }
        }
    }

    impl TraceEnrichmentProber for ConcurrentProbeTracker {
        fn probe_snapshot(
            &self,
            ip: IpAddr,
            _timeout_ms: u64,
            _ping_samples: u8,
            _probed_at: &str,
        ) -> Option<IcmpSnapshot> {
            let current = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.record_in_flight(current);
            std::thread::sleep(self.delay);
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            self.snapshots.get(&ip).cloned()
        }
    }

    fn multi_server_tree(servers: &[&str]) -> TraceTree {
        assert!(servers.len() >= 2);
        TraceTree {
            request: TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-09-06T00:00:00Z".into(),
            },
            root: TraceNode {
                hop: hop(servers[0], None),
                origin: NodeOrigin::Trace,
                children: servers[1..]
                    .iter()
                    .map(|server| TraceNode {
                        hop: hop(server, None),
                        origin: NodeOrigin::Branch {
                            at: dns_resolve::NodePath::root(0),
                            intent: BranchIntent::AlternateServer,
                            at_time: "2026-09-06T00:00:00Z".into(),
                        },
                        children: vec![],
                    })
                    .collect(),
            },
            budget_truncated: false,
        }
    }

    fn snapshots_for(servers: &[&str]) -> BTreeMap<IpAddr, IcmpSnapshot> {
        servers
            .iter()
            .map(|server| {
                let ip: IpAddr = server.parse().expect("ip");
                (ip, snapshot_for(ip))
            })
            .collect()
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
    fn icmp_capability_notice_emits_at_most_once() {
        ICMP_NOTICE_EMITTED.store(false, Ordering::SeqCst);
        let first = icmp_capability_notice_once();
        let second = icmp_capability_notice_once();
        assert!(second.is_none());
        if let Some(notice) = first {
            assert!(notice.contains("icmp"));
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
    fn populate_after_trace_skips_icmp_when_disabled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = Runtime::open(DelvePaths::from_root(dir.path()));
        assert!(!runtime.config.enrichment_icmp_enabled);
        let ip: IpAddr = "1.1.1.1".parse().expect("ip");
        let tree = build_linear_tree(
            vec![hop("1.1.1.1", None)],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-09-06T00:00:00Z".into(),
            },
        );
        let mut document = SessionDocument::new("01TEST".into(), sample_request(), tree.clone());
        populate_after_trace(&mut document, &tree, &runtime, false);
        assert!(document.targets.contains_key(&ip));
        assert!(
            document
                .targets
                .get(&ip)
                .and_then(|entry| entry.icmp.as_ref())
                .is_none()
        );
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

    #[test]
    fn parallel_icmp_probes_respect_max_in_flight() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_with_parallelism(&dir, 2);
        let servers = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1"];
        let tree = multi_server_tree(&servers);
        let prober =
            ConcurrentProbeTracker::new(Duration::from_millis(40), snapshots_for(&servers));
        let mut document = SessionDocument::new("01TEST".into(), sample_request(), tree.clone());
        populate_icmp_for_tree(&mut document, &tree, &runtime, true, &prober, |_| true);
        for server in servers {
            let ip: IpAddr = server.parse().expect("ip");
            assert!(
                document
                    .targets
                    .get(&ip)
                    .and_then(|entry| entry.icmp.as_ref())
                    .is_some(),
                "missing snapshot for {server}"
            );
        }
        assert!(
            prober.peak_in_flight.load(Ordering::SeqCst) <= 2,
            "peak in-flight {} exceeded cap 2",
            prober.peak_in_flight.load(Ordering::SeqCst)
        );
    }

    #[test]
    fn parallel_icmp_refresh_updates_all_targets_and_reports_progress() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_with_parallelism(&dir, 3);
        let servers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"];
        let tree = multi_server_tree(&servers);
        let prober = ConcurrentProbeTracker::new(Duration::from_millis(5), snapshots_for(&servers));
        let mut document = SessionDocument::new("01TEST".into(), sample_request(), tree);
        let progress = Arc::new(Mutex::new(Vec::new()));
        let progress_handle = Arc::clone(&progress);
        let report =
            refresh_icmp_targets_with_prober(&mut document, &runtime, &prober, |current, total| {
                progress_handle.lock().expect("lock").push((current, total))
            });
        assert_eq!(report.targets_total, 3);
        assert_eq!(report.targets_updated, 3);
        assert_eq!(report.targets_failed, 0);
        for server in servers {
            let ip: IpAddr = server.parse().expect("ip");
            assert_eq!(
                document
                    .targets
                    .get(&ip)
                    .and_then(|entry| entry.icmp.as_ref())
                    .map(|snapshot| snapshot.avg_ms),
                Some(12)
            );
        }
        let seen = progress.lock().expect("lock");
        assert_eq!(seen.len(), 3);
        assert_eq!(seen.last().copied(), Some((3, 3)));
    }

    #[test]
    fn parallel_populate_uses_cache_without_live_probe() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_with_parallelism(&dir, 4);
        let servers = ["1.1.1.1", "8.8.8.8"];
        let tree = multi_server_tree(&servers);
        let ip_a: IpAddr = "1.1.1.1".parse().expect("ip");
        let ip_b: IpAddr = "8.8.8.8".parse().expect("ip");
        let cache = runtime.enrichment_cache.as_ref().expect("cache");
        let profile = probe_profile(&runtime);
        let cached = snapshot_for(ip_a);
        cache
            .put_icmp(ip_a, &profile, &cached, now_unix())
            .expect("seed cache");
        let prober = MockProber::new().with_snapshot(ip_b, snapshot_for(ip_b));
        let mut document = SessionDocument::new("01TEST".into(), sample_request(), tree.clone());
        populate_icmp_for_tree(&mut document, &tree, &runtime, false, &prober, |_| true);
        assert_eq!(
            document
                .targets
                .get(&ip_a)
                .and_then(|entry| entry.icmp.as_ref()),
            Some(&cached)
        );
        assert_eq!(
            document
                .targets
                .get(&ip_b)
                .and_then(|entry| entry.icmp.as_ref()),
            Some(&snapshot_for(ip_b))
        );
        assert_eq!(*prober.calls.lock().expect("lock"), vec![ip_b]);
    }

    #[test]
    fn max_parallel_one_probes_sequentially_without_overlap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = runtime_with_parallelism(&dir, 1);
        let servers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"];
        let tree = multi_server_tree(&servers);
        let prober = ConcurrentProbeTracker::new(Duration::from_millis(5), snapshots_for(&servers));
        let mut document = SessionDocument::new("01TEST".into(), sample_request(), tree.clone());
        populate_icmp_for_tree(&mut document, &tree, &runtime, true, &prober, |_| true);
        assert_eq!(prober.peak_in_flight.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn probe_icmp_snapshots_parallel_returns_empty_for_no_targets() {
        let prober = MockProber::new();
        let profile = ProbeProfile {
            timeout_ms: 200,
            ping_samples: 3,
        };
        let results =
            probe_icmp_snapshots_parallel(&[], 4, None, &profile, &prober, 200, 3, |_, _| {});
        assert!(results.is_empty());
        assert!(prober.calls.lock().expect("lock").is_empty());
    }
}
