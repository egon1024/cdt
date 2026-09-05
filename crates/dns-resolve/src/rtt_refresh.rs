//! Hop-by-hop RTT refresh for stored trace trees.

use std::net::IpAddr;
use std::thread;

use dns_core::name::DomainName;
use dns_core::parse_record_type;
use dns_core::response::Transport;
use hickory_proto::rr::RecordType;

use crate::trace::server_target_from_hop;
use crate::{TraceConfig, TraceNode, TraceTree};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshHopResult {
    pub path: Vec<usize>,
    pub success: bool,
    pub previous_rtt_ms: u64,
    pub new_rtt_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshTreeReport {
    pub hops_total: usize,
    pub hops_updated: usize,
    pub hops_failed: usize,
    pub results: Vec<RefreshHopResult>,
}

pub trait RefreshProgress: Send {
    fn hop_started(&mut self, current: usize, total: usize);
}

#[derive(Clone)]
struct HopSnapshot {
    path: Vec<usize>,
    server: IpAddr,
    qname: DomainName,
    qtype: RecordType,
    transport: Transport,
    previous_rtt_ms: u64,
}

struct HopQueryOutcome {
    path: Vec<usize>,
    previous_rtt_ms: u64,
    result: Result<u64, String>,
}

/// Re-query every hop in `tree` with cache bypass and update `rtt_ms` on success.
pub fn refresh_tree_rtts(
    tree: &mut TraceTree,
    config: &TraceConfig,
    progress: &mut dyn RefreshProgress,
) -> RefreshTreeReport {
    let mut snapshots = Vec::new();
    let mut parse_failures = Vec::new();
    collect_hop_snapshots(&tree.root, &[], &mut snapshots, &mut parse_failures);
    let total = snapshots.len() + parse_failures.len();
    let max_parallel = config.max_parallel_queries.max(1);
    let mut outcomes = parse_failures;
    let queried = if max_parallel == 1 {
        snapshots
            .into_iter()
            .enumerate()
            .map(|(index, snapshot)| {
                progress.hop_started(outcomes.len() + index + 1, total);
                query_hop_nocache(config, snapshot)
            })
            .collect()
    } else {
        refresh_parallel(
            config,
            snapshots,
            max_parallel,
            progress,
            outcomes.len(),
            total,
        )
    };
    outcomes.extend(queried);

    let mut hops_updated = 0usize;
    let mut hops_failed = 0usize;
    let mut results = Vec::with_capacity(outcomes.len());
    for outcome in outcomes {
        let (success, new_rtt_ms, error) = match outcome.result {
            Ok(value) => (true, Some(value), None),
            Err(error) => (false, None, Some(error)),
        };
        if success {
            hops_updated += 1;
            if let Some(node) = resolve_mut_by_path(tree, &outcome.path) {
                node.hop.rtt_ms = new_rtt_ms.unwrap_or(node.hop.rtt_ms);
                node.hop.from_cache = false;
            }
        } else {
            hops_failed += 1;
        }
        results.push(RefreshHopResult {
            path: outcome.path,
            success,
            previous_rtt_ms: outcome.previous_rtt_ms,
            new_rtt_ms,
            error,
        });
    }

    RefreshTreeReport {
        hops_total: total,
        hops_updated,
        hops_failed,
        results,
    }
}

fn refresh_parallel(
    config: &TraceConfig,
    snapshots: Vec<HopSnapshot>,
    max_parallel: usize,
    progress: &mut dyn RefreshProgress,
    completed: usize,
    total: usize,
) -> Vec<HopQueryOutcome> {
    let mut outcomes = Vec::with_capacity(snapshots.len());
    let mut next_index = 0usize;
    while next_index < snapshots.len() {
        let batch_end = (next_index + max_parallel).min(snapshots.len());
        let batch = snapshots[next_index..batch_end].to_vec();
        let batch_outcomes = thread::scope(|scope| {
            batch
                .into_iter()
                .map(|snapshot| {
                    let config = config.clone();
                    scope.spawn(move || query_hop_nocache(&config, snapshot))
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|handle| handle.join().expect("worker"))
                .collect::<Vec<_>>()
        });
        for outcome in batch_outcomes {
            outcomes.push(outcome);
            progress.hop_started(completed + outcomes.len(), total);
        }
        next_index = batch_end;
    }
    outcomes
}

fn query_hop_nocache(config: &TraceConfig, snapshot: HopSnapshot) -> HopQueryOutcome {
    let mut query_config = config.clone();
    query_config.use_cache = false;
    query_config.transport = snapshot.transport;
    let result = crate::query_server(
        snapshot.server,
        &query_config,
        &snapshot.qname,
        snapshot.qtype,
    )
    .map(|response| response.rtt.as_millis() as u64)
    .map_err(|error| error.to_string());
    HopQueryOutcome {
        path: snapshot.path,
        previous_rtt_ms: snapshot.previous_rtt_ms,
        result,
    }
}

fn collect_hop_snapshots(
    node: &TraceNode,
    prefix: &[usize],
    out: &mut Vec<HopSnapshot>,
    failures: &mut Vec<HopQueryOutcome>,
) {
    match hop_snapshot(node, prefix) {
        Ok(snapshot) => out.push(snapshot),
        Err(error) => failures.push(HopQueryOutcome {
            path: prefix.to_vec(),
            previous_rtt_ms: node.hop.rtt_ms,
            result: Err(error),
        }),
    }
    for (index, child) in node.children.iter().enumerate() {
        let mut child_prefix = prefix.to_vec();
        child_prefix.push(index);
        collect_hop_snapshots(child, &child_prefix, out, failures);
    }
}

fn hop_snapshot(node: &TraceNode, path: &[usize]) -> Result<HopSnapshot, String> {
    let hop = &node.hop;
    let server = server_target_from_hop(hop)
        .map_err(|error| error.to_string())?
        .address;
    let qname = DomainName::parse(&hop.qname).map_err(|error| error.to_string())?;
    let qtype = parse_record_type(&hop.qtype).map_err(|error| error.to_string())?;
    let transport = transport_from_hop(hop);
    Ok(HopSnapshot {
        path: path.to_vec(),
        server,
        qname,
        qtype,
        transport,
        previous_rtt_ms: hop.rtt_ms,
    })
}

fn transport_from_hop(hop: &crate::TraceHop) -> Transport {
    match hop.transport.to_ascii_lowercase().as_str() {
        "tcp" => Transport::Tcp,
        _ => Transport::Udp,
    }
}

fn resolve_mut_by_path<'a>(tree: &'a mut TraceTree, path: &[usize]) -> Option<&'a mut TraceNode> {
    if path.is_empty() {
        return Some(&mut tree.root);
    }
    let mut node = &mut tree.root;
    for index in path {
        node = node.children.get_mut(*index)?;
    }
    Some(node)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DnsExchange, HopOutcome, QueryOptions, TraceTreeRequest, build_linear_tree};
    use dns_core::response::{DnsResponse, QueryResult};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    struct ScriptedExchange {
        rtts: HashMap<IpAddr, u64>,
        calls: Arc<AtomicUsize>,
        fail: Option<IpAddr>,
    }

    impl DnsExchange for ScriptedExchange {
        fn exchange(
            &self,
            server: IpAddr,
            _port: u16,
            _options: &QueryOptions,
        ) -> dns_core::Result<QueryResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail == Some(server) {
                return Err(dns_core::DnsCoreError::Parse("simulated failure".into()));
            }
            let rtt_ms = self.rtts.get(&server).copied().unwrap_or(99);
            Ok(QueryResult {
                server,
                transport: Transport::Udp,
                qname: DomainName::parse("example.com.").expect("qname"),
                qtype: "A".into(),
                rtt: Duration::from_millis(rtt_ms),
                response: DnsResponse {
                    id: 0,
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
                },
                from_cache: false,
            })
        }
    }

    struct NoProgress;

    impl RefreshProgress for NoProgress {
        fn hop_started(&mut self, _current: usize, _total: usize) {}
    }

    fn sample_tree() -> TraceTree {
        build_linear_tree(
            vec![hop(".", "198.41.0.4", 10), hop("com.", "192.0.2.1", 20)],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
        )
    }

    fn hop(zone: &str, server: &str, rtt_ms: u64) -> crate::TraceHop {
        crate::TraceHop {
            zone: zone.into(),
            server: server.into(),
            server_name: None,
            qname: "example.com.".into(),
            qtype: "A".into(),
            transport: "udp".into(),
            rtt_ms,
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

    fn config_with_exchange(exchange: Arc<dyn DnsExchange>) -> TraceConfig {
        let mut config = TraceConfig::new(
            DomainName::parse("example.com.").expect("qname"),
            RecordType::A,
        );
        config.exchange = exchange;
        config.use_cache = true;
        config
    }

    #[test]
    fn refresh_tree_rtts_updates_hops_with_mock_exchange() {
        let mut tree = sample_tree();
        let calls = Arc::new(AtomicUsize::new(0));
        let exchange = Arc::new(ScriptedExchange {
            rtts: HashMap::from([
                (IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)), 111),
                (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 222),
            ]),
            calls: Arc::clone(&calls),
            fail: None,
        });
        let config = config_with_exchange(exchange);
        let report = refresh_tree_rtts(&mut tree, &config, &mut NoProgress);
        assert_eq!(report.hops_total, 2);
        assert_eq!(report.hops_updated, 2);
        assert_eq!(tree.root.hop.rtt_ms, 111);
        assert_eq!(tree.root.children[0].hop.rtt_ms, 222);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn refresh_tree_rtts_retains_prior_rtt_on_failure() {
        let mut tree = sample_tree();
        let fail = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let exchange = Arc::new(ScriptedExchange {
            rtts: HashMap::from([(IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)), 111)]),
            calls: Arc::new(AtomicUsize::new(0)),
            fail: Some(fail),
        });
        let config = config_with_exchange(exchange);
        let report = refresh_tree_rtts(&mut tree, &config, &mut NoProgress);
        assert_eq!(report.hops_updated, 1);
        assert_eq!(report.hops_failed, 1);
        assert_eq!(tree.root.hop.rtt_ms, 111);
        assert_eq!(tree.root.children[0].hop.rtt_ms, 20);
    }

    #[test]
    fn refresh_tree_rtts_respects_parallel_cap() {
        let mut tree = sample_tree();
        let calls = Arc::new(AtomicUsize::new(0));
        let exchange = Arc::new(ScriptedExchange {
            rtts: HashMap::from([
                (IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)), 1),
                (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 2),
            ]),
            calls: Arc::clone(&calls),
            fail: None,
        });
        let mut config = config_with_exchange(exchange);
        config.max_parallel_queries = 1;
        let report = refresh_tree_rtts(&mut tree, &config, &mut NoProgress);
        assert_eq!(report.hops_total, 2);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
