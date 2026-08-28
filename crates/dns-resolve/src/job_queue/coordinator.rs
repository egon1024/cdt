use std::collections::{BTreeMap, HashMap, HashSet};

use dns_core::name::DomainName;
use dns_core::response::DnsResponse;
use hickory_proto::rr::RecordType;

use crate::trace::{
    announce_multi_server_query, collect_glue, expansion_targets_for_cut, failed_hop,
    is_authoritative_answer, resolve_nameservers_from_referral, server_matches_primary,
    start_servers,
};
use crate::{
    ExpansionPolicy, HopOutcome, QueryBudget, ResolveError, Result, ServerTarget, TraceConfig,
    TraceNode, TraceProgress, hop_from_query,
};

use super::emitter::EmitScheduler;
use super::pool::{JobOutcome, WorkerPool};
use super::queue::WorkQueue;
use super::result_store::ResultStore;
use super::types::{JobId, JobKind, TraceJob};
use super::worker::execute_job;

/// Run a trace through the serial job queue for any expansion policy.
pub fn run_policy(
    config: &TraceConfig,
    budget: &mut QueryBudget,
    progress: &mut dyn TraceProgress,
    qname: DomainName,
    defer_terminal_expansion: bool,
) -> Result<TraceNode> {
    let mut coordinator = Coordinator::new(config, budget, progress, defer_terminal_expansion);
    coordinator.run(qname)
}

/// Run a single-path (`+expand=none`) trace through the serial job queue.
#[cfg(test)]
pub fn run_none_policy(
    config: &TraceConfig,
    budget: &mut QueryBudget,
    progress: &mut dyn TraceProgress,
    qname: DomainName,
) -> Result<TraceNode> {
    run_policy(config, budget, progress, qname, false)
}

struct DelegationInfo {
    response: DnsResponse,
    zone: DomainName,
    servers_at_cut: Vec<ServerTarget>,
}

pub struct Coordinator<'a> {
    config: &'a TraceConfig,
    budget: &'a mut QueryBudget,
    progress: &'a mut dyn TraceProgress,
    defer_terminal_expansion: bool,
    queue: WorkQueue,
    results: ResultStore,
    emitter: EmitScheduler,
    visited_zones: HashSet<String>,
    referral_by_path: HashMap<Vec<usize>, DelegationInfo>,
    top_level_siblings: BTreeMap<usize, TraceNode>,
    next_job_id: u64,
}

impl<'a> Coordinator<'a> {
    fn new(
        config: &'a TraceConfig,
        budget: &'a mut QueryBudget,
        progress: &'a mut dyn TraceProgress,
        defer_terminal_expansion: bool,
    ) -> Self {
        Self {
            config,
            budget,
            progress,
            defer_terminal_expansion,
            queue: WorkQueue::new(),
            results: ResultStore::new(),
            emitter: EmitScheduler::new(),
            visited_zones: HashSet::new(),
            referral_by_path: HashMap::new(),
            top_level_siblings: BTreeMap::new(),
            next_job_id: 1,
        }
    }

    fn alloc_job_id(&mut self) -> JobId {
        let id = JobId(self.next_job_id);
        self.next_job_id += 1;
        id
    }

    fn try_enqueue_job(
        &mut self,
        server: ServerTarget,
        fallback_servers: Vec<ServerTarget>,
        qname: DomainName,
        qtype: RecordType,
        zone: DomainName,
        path: Vec<usize>,
    ) -> bool {
        if !self.budget.try_consume() {
            return false;
        }
        self.emitter.register_path(path.clone());
        let job_id = self.alloc_job_id();
        self.queue.enqueue(TraceJob {
            id: job_id,
            kind: JobKind::Trace,
            server,
            qname,
            qtype,
            zone,
            path,
            fallback_servers,
        });
        true
    }

    fn enqueue_single_server(
        &mut self,
        servers: Vec<ServerTarget>,
        qname: DomainName,
        zone: DomainName,
        path: Vec<usize>,
    ) -> Result<()> {
        let mut servers = servers;
        if servers.is_empty() {
            return Err(ResolveError::NoReachableNameserver {
                zone: zone.to_string(),
            });
        }
        let primary = servers.remove(0);
        if !self.try_enqueue_job(primary, servers, qname, self.config.qtype, zone, path) {
            self.progress.budget_truncated(self.budget.cap());
        }
        Ok(())
    }

    fn enqueue_cut(
        &mut self,
        servers: Vec<ServerTarget>,
        qname: DomainName,
        zone: DomainName,
        path: Vec<usize>,
    ) -> Result<()> {
        if servers.is_empty() {
            return Err(ResolveError::NoReachableNameserver {
                zone: zone.to_string(),
            });
        }

        match self.config.expansion_policy {
            ExpansionPolicy::None | ExpansionPolicy::Last => {
                self.enqueue_single_server(servers, qname, zone, path)
            }
            ExpansionPolicy::All => {
                if servers.len() > 1 {
                    announce_multi_server_query(self.progress, &zone, servers.len());
                }
                for (index, server) in servers.into_iter().enumerate() {
                    let mut job_path = path.clone();
                    job_path.push(index);
                    if !self.try_enqueue_job(
                        server,
                        vec![],
                        qname.clone(),
                        self.config.qtype,
                        zone.clone(),
                        job_path,
                    ) {
                        self.progress.budget_truncated(self.budget.cap());
                        break;
                    }
                }
                Ok(())
            }
        }
    }

    fn run(&mut self, qname: DomainName) -> Result<TraceNode> {
        let root_zone = DomainName::parse(".").expect("root zone");
        let initial_path = match self.config.expansion_policy {
            ExpansionPolicy::All => vec![],
            _ => vec![],
        };
        self.enqueue_cut(start_servers(self.config), qname, root_zone, initial_path)?;

        let max_parallel = self.config.max_parallel_queries.max(1);
        if max_parallel == 1 {
            self.run_serial()?;
        } else {
            self.run_parallel(max_parallel)?;
        }

        self.finalize_tree()
    }

    fn run_serial(&mut self) -> Result<()> {
        while let Some(job) = self.queue.dequeue() {
            self.dispatch_job(job)?;
        }
        Ok(())
    }

    fn run_parallel(&mut self, max_parallel: usize) -> Result<()> {
        let pool = WorkerPool::new(self.config.clone(), max_parallel);
        let mut in_flight = 0usize;

        loop {
            while in_flight < max_parallel {
                if let Some(job) = self.queue.dequeue() {
                    self.submit_job(&pool, job)?;
                    in_flight += 1;
                } else {
                    break;
                }
            }

            if in_flight == 0 {
                break;
            }

            let JobOutcome { job, result } = pool.recv();
            in_flight -= 1;
            self.complete_job(job, result)?;
        }

        pool.shutdown();
        Ok(())
    }

    fn submit_job(&mut self, pool: &WorkerPool, job: TraceJob) -> Result<()> {
        if job.path.len() >= self.config.max_depth {
            return Err(ResolveError::MaxDepth {
                max: self.config.max_depth,
            });
        }
        pool.submit(job);
        Ok(())
    }

    fn dispatch_job(&mut self, job: TraceJob) -> Result<()> {
        if job.path.len() >= self.config.max_depth {
            return Err(ResolveError::MaxDepth {
                max: self.config.max_depth,
            });
        }

        match execute_job(&job, self.config) {
            Ok(query_result) => self.handle_success(job, query_result),
            Err(error) => self.handle_failure(job, error),
        }
    }

    fn complete_job(
        &mut self,
        job: TraceJob,
        result: Result<dns_core::response::QueryResult>,
    ) -> Result<()> {
        match result {
            Ok(query_result) => self.handle_success(job, query_result),
            Err(error) => self.handle_failure(job, error),
        }
    }

    fn finalize_tree(&mut self) -> Result<TraceNode> {
        if self.config.expansion_policy == ExpansionPolicy::All {
            if let Some(mut root) = self.top_level_siblings.remove(&0) {
                let siblings = std::mem::take(&mut self.top_level_siblings);
                for (_, sibling) in siblings {
                    root.children.push(sibling);
                }
                if let Some(stored) = self.results.take_tree() {
                    return Ok(merge_all_roots(stored, root));
                }
                return Ok(root);
            }
        }

        self.results
            .take_tree()
            .ok_or_else(|| ResolveError::NoReachableNameserver { zone: ".".into() })
    }

    fn handle_failure(&mut self, job: TraceJob, error: ResolveError) -> Result<()> {
        if self.config.expansion_policy == ExpansionPolicy::All {
            let hop = failed_hop(
                self.config,
                &job.zone,
                &job.qname,
                job.qtype,
                &job.server,
                &error,
            );
            self.store_completed_node(&job.path, hop);
            return Ok(());
        }

        if let Some(next_server) = job.fallback_servers.first().cloned() {
            let mut fallback = job.fallback_servers;
            fallback.remove(0);
            if self.try_enqueue_job(
                next_server,
                fallback,
                job.qname,
                job.qtype,
                job.zone,
                job.path,
            ) {
                return Ok(());
            }
            self.progress.budget_truncated(self.budget.cap());
            return Ok(());
        }
        Err(error)
    }

    fn handle_success(
        &mut self,
        job: TraceJob,
        query_result: dns_core::response::QueryResult,
    ) -> Result<()> {
        let referral_ns = query_result.response.ns_names();
        let glue = collect_glue(&query_result.response, &referral_ns);
        let mut hop = hop_from_query(
            &job.zone,
            &query_result,
            job.server.name.clone(),
            referral_ns.iter().map(ToString::to_string).collect(),
            glue.iter().map(ToString::to_string).collect(),
            HopOutcome::Referral,
        );

        if is_authoritative_answer(&query_result.response, &job.qname, job.qtype) {
            hop.outcome = HopOutcome::Answered;
            return self.handle_terminal_answer(job, hop, query_result);
        }

        let Some(next_zone) = query_result.response.referral_zone(&job.qname) else {
            hop.outcome = HopOutcome::Answered;
            return self.handle_terminal_answer(job, hop, query_result);
        };

        if self.config.expansion_policy == ExpansionPolicy::All {
            if !self.visited_zones.insert(next_zone.to_string()) {
                hop.outcome = HopOutcome::Failed {
                    kind: "delegation_loop".into(),
                    detail: next_zone.to_string(),
                };
                self.store_completed_node(&job.path, hop);
                return Ok(());
            }
        } else if !self.visited_zones.insert(next_zone.to_string()) {
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

        self.progress.message(&format!(
            "following delegation to zone {} via {:?}",
            next_zone,
            ns_names
                .iter()
                .map(|name| name.to_string())
                .collect::<Vec<_>>()
        ));

        self.referral_by_path.insert(
            job.path.clone(),
            DelegationInfo {
                response: query_result.response.clone(),
                zone: job.zone.clone(),
                servers_at_cut: vec![job.server.clone()],
            },
        );

        let next_servers = match resolve_nameservers_from_referral(
            &query_result.response,
            std::slice::from_ref(&job.server),
            self.config,
            self.budget,
            &job.zone,
            self.progress,
        ) {
            Ok(servers) if !servers.is_empty() => servers,
            Ok(_) => {
                if self.config.expansion_policy == ExpansionPolicy::All {
                    hop.outcome = HopOutcome::Failed {
                        kind: "no_reachable_nameserver".into(),
                        detail: next_zone.to_string(),
                    };
                    self.store_completed_node(&job.path, hop);
                    return Ok(());
                }
                return Err(ResolveError::NoReachableNameserver {
                    zone: next_zone.to_string(),
                });
            }
            Err(error) => {
                if self.config.expansion_policy == ExpansionPolicy::All {
                    hop.outcome = HopOutcome::Failed {
                        kind: "nameserver_resolution".into(),
                        detail: error.to_string(),
                    };
                    self.store_completed_node(&job.path, hop);
                    return Ok(());
                }
                return Err(error);
            }
        };

        hop.outcome = HopOutcome::Referral;
        self.store_completed_node(&job.path, hop);

        let child_path = child_path_for_policy(self.config.expansion_policy, &job.path);
        self.enqueue_cut(next_servers, job.qname, next_zone, child_path)?;
        Ok(())
    }

    fn handle_terminal_answer(
        &mut self,
        job: TraceJob,
        hop: crate::TraceHop,
        query_result: dns_core::response::QueryResult,
    ) -> Result<()> {
        if self.config.expansion_policy == ExpansionPolicy::Last && !self.defer_terminal_expansion {
            return self.expand_terminal_last(job, hop, query_result);
        }

        self.store_completed_node(&job.path, hop);
        Ok(())
    }

    fn expand_terminal_last(
        &mut self,
        job: TraceJob,
        hop: crate::TraceHop,
        query_result: dns_core::response::QueryResult,
    ) -> Result<()> {
        let parent_path = parent_path(&job.path);
        let (parent_delegation, parent_zone, cut_servers) =
            if let Some(info) = self.referral_by_path.get(&parent_path) {
                (
                    Some(&info.response),
                    &info.zone,
                    info.servers_at_cut.as_slice(),
                )
            } else {
                (None, &job.zone, std::slice::from_ref(&job.server))
            };

        let expansion_servers = expansion_targets_for_cut(
            parent_delegation,
            parent_zone,
            cut_servers,
            self.config,
            self.budget,
            self.progress,
        )?;

        if expansion_servers.len() > 1 {
            announce_multi_server_query(self.progress, &job.zone, expansion_servers.len());
        }

        let primary_server = job.server.clone();
        let primary_result_server = query_result.server;

        for (index, server) in expansion_servers.iter().enumerate() {
            let mut sibling_path = parent_path.clone();
            sibling_path.push(index);
            // The linear-walk job already registered its path at enqueue time.
            if sibling_path != job.path {
                self.emitter.register_path(sibling_path.clone());
            }

            if server_matches_primary(server, &primary_server, primary_result_server) {
                self.store_completed_node(&sibling_path, hop.clone());
                continue;
            }

            if !self.try_enqueue_job(
                server.clone(),
                vec![],
                job.qname.clone(),
                job.qtype,
                job.zone.clone(),
                sibling_path,
            ) {
                self.progress.budget_truncated(self.budget.cap());
                break;
            }
        }

        Ok(())
    }

    fn store_completed_node(&mut self, path: &[usize], hop: crate::TraceHop) {
        if self.config.expansion_policy == ExpansionPolicy::All && path.len() == 1 {
            let index = path[0];
            let node = TraceNode {
                hop: hop.clone(),
                origin: crate::NodeOrigin::Trace,
                children: Vec::new(),
            };
            self.top_level_siblings.insert(index, node);
            self.emitter.mark_ready(path, hop);
            self.emitter.drain(self.progress);
            return;
        }

        self.results.insert_hop(path, hop.clone());
        self.emitter.mark_ready(path, hop);
        self.emitter.drain(self.progress);
    }
}

fn parent_path(path: &[usize]) -> Vec<usize> {
    let mut parent = path.to_vec();
    if parent.is_empty() {
        return parent;
    }
    parent.pop();
    parent
}

fn child_path_for_policy(policy: ExpansionPolicy, parent_path: &[usize]) -> Vec<usize> {
    match policy {
        ExpansionPolicy::None | ExpansionPolicy::Last => {
            let mut child = parent_path.to_vec();
            child.push(0);
            child
        }
        ExpansionPolicy::All => parent_path.to_vec(),
    }
}

fn merge_all_roots(stored: TraceNode, all_root: TraceNode) -> TraceNode {
    if stored.hop.zone != "." || stored.hop.server == "0.0.0.0" {
        return stored;
    }
    if stored.children.is_empty() {
        return all_root;
    }
    let TraceNode {
        hop,
        origin,
        mut children,
    } = all_root;
    let mut merged = stored;
    if hop.server != "0.0.0.0" {
        children.insert(
            0,
            TraceNode {
                hop,
                origin,
                children: Vec::new(),
            },
        );
    }
    merged.children.extend(children);
    merged
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use dns_core::EdnsMeta;
    use dns_core::name::DomainName;
    use dns_core::response::{DnsRecord, DnsResponse};
    use hickory_proto::rr::RecordType;

    use crate::TraceHop;

    struct SilentProgress;

    impl TraceProgress for SilentProgress {
        fn hop(&mut self, _hop: &TraceHop, _path: &crate::NodePath) {}
        fn message(&mut self, _message: &str) {}
    }

    struct RecordingProgress {
        messages: Vec<String>,
    }

    impl TraceProgress for RecordingProgress {
        fn hop(&mut self, _hop: &TraceHop, _path: &crate::NodePath) {}
        fn message(&mut self, message: &str) {
            self.messages.push(message.to_string());
        }
    }

    struct HopRecordingProgress {
        paths: Vec<Vec<usize>>,
    }

    impl TraceProgress for HopRecordingProgress {
        fn hop(&mut self, _hop: &TraceHop, path: &crate::NodePath) {
            self.paths.push(path.path.clone());
        }
        fn message(&mut self, _message: &str) {}
    }

    fn test_config(qname: &str, exchange: Arc<dyn crate::DnsExchange>) -> TraceConfig {
        let mut config = TraceConfig::new(DomainName::parse(qname).expect("qname"), RecordType::A);
        config.start_servers = Some(vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
        config.exchange = exchange;
        config
    }

    struct AuthoritativeExchange;

    impl crate::DnsExchange for AuthoritativeExchange {
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

    #[test]
    fn enqueues_and_completes_one_job() {
        let mut config = test_config("example.com.", Arc::new(AuthoritativeExchange));
        config.expansion_policy = ExpansionPolicy::None;
        let mut budget = QueryBudget::new(64);
        let qname = DomainName::parse("example.com.").expect("qname");
        let root =
            run_none_policy(&config, &mut budget, &mut SilentProgress, qname).expect("trace");
        assert_eq!(root.hop.outcome, HopOutcome::Answered);
        assert!(root.children.is_empty());
    }

    struct MultiCutExchange;

    impl crate::DnsExchange for MultiCutExchange {
        fn exchange(
            &self,
            server: IpAddr,
            _port: u16,
            options: &dns_core::QueryOptions,
        ) -> dns_core::Result<dns_core::response::QueryResult> {
            let qname = options.qname.to_string();
            let is_example_qname = qname == "example.com.";
            let is_example_zone_ns = matches!(
                server,
                IpAddr::V4(v4) if matches!(v4.octets(), [2, 0, 0, 2])
            );
            let (authoritative, answers, authorities, additionals) =
                if is_example_qname && is_example_zone_ns {
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
                            rdata: "1.1.1.1".into(),
                        }],
                    )
                } else if is_example_qname {
                    (
                        false,
                        vec![],
                        vec![DnsRecord {
                            name: DomainName::parse("example.com.").expect("zone"),
                            rtype: "NS".into(),
                            rclass: "IN".into(),
                            ttl: 3600,
                            rdata: "ns.example.com.".into(),
                        }],
                        vec![DnsRecord {
                            name: DomainName::parse("ns.example.com.").expect("ns"),
                            rtype: "A".into(),
                            rclass: "IN".into(),
                            ttl: 300,
                            rdata: "2.0.0.2".into(),
                        }],
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

    #[test]
    fn three_cut_fixture_matches_linear_tree() {
        let mut config = test_config("example.com.", Arc::new(MultiCutExchange));
        config.start_servers = Some(vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
        let mut budget = QueryBudget::new(64);
        let qname = DomainName::parse("example.com.").expect("qname");
        let root =
            run_none_policy(&config, &mut budget, &mut SilentProgress, qname).expect("trace");
        assert!(root.children.len() <= 1);
    }

    #[test]
    fn budget_stops_enqueueing_follow_up_jobs() {
        let mut config = test_config("example.com.", Arc::new(MultiCutExchange));
        config.start_servers = Some(vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
        let mut budget = QueryBudget::new(1);
        let qname = DomainName::parse("example.com.").expect("qname");
        let root =
            run_none_policy(&config, &mut budget, &mut SilentProgress, qname).expect("trace");
        assert!(budget.truncated);
        assert_eq!(root.hop.zone, ".");
        assert!(root.children.is_empty());
    }

    #[test]
    fn terminal_last_expansion_announces_zone_cut() {
        let mut config = test_config("example.com.", Arc::new(MultiNsDelegatingExchange));
        config.expansion_policy = ExpansionPolicy::Last;
        config.start_servers = Some(vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
        let mut budget = QueryBudget::new(64);
        let mut progress = RecordingProgress { messages: vec![] };
        let qname = DomainName::parse("example.com.").expect("qname");
        let _tree = run_policy(&config, &mut budget, &mut progress, qname, false).expect("trace");
        assert!(
            progress.messages.iter().any(|message| {
                message.contains("querying 3 nameserver(s) at zone example.com.")
            }),
            "expected zone-cut announcement: {:?}",
            progress.messages
        );
    }

    struct MultiNsDelegatingExchange;

    impl crate::DnsExchange for MultiNsDelegatingExchange {
        fn exchange(
            &self,
            server: IpAddr,
            _port: u16,
            options: &dns_core::QueryOptions,
        ) -> dns_core::Result<dns_core::response::QueryResult> {
            let qname = options.qname.to_string();
            let is_example_zone_ns = matches!(
                server,
                IpAddr::V4(v4)
                    if matches!(v4.octets(), [1, 0, 0, 1] | [2, 0, 0, 2] | [3, 0, 0, 3])
            );
            let is_example_qname = qname == "example.com.";
            let (authoritative, answers, authorities, additionals) =
                if is_example_qname && is_example_zone_ns {
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
                            rdata: "1.1.1.1".into(),
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

    #[test]
    fn terminal_last_emits_all_sibling_hops_in_order() {
        let mut config = test_config("example.com.", Arc::new(MultiNsDelegatingExchange));
        config.expansion_policy = ExpansionPolicy::Last;
        config.start_servers = Some(vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
        let mut budget = QueryBudget::new(64);
        let mut progress = HopRecordingProgress { paths: vec![] };
        let qname = DomainName::parse("example.com.").expect("qname");
        let _tree = run_policy(&config, &mut budget, &mut progress, qname, false).expect("trace");
        assert!(
            progress.paths.contains(&vec![0, 1]) && progress.paths.contains(&vec![0, 2]),
            "expected terminal sibling hops to be emitted, got {:?}",
            progress.paths
        );
    }

    #[test]
    fn workers_do_not_reference_trace_progress() {
        let source = include_str!("worker.rs");
        assert!(
            !source.contains("TraceProgress"),
            "workers must not call TraceProgress directly"
        );
    }

    #[test]
    fn all_policy_follows_first_shared_referral_zone() {
        let mut config = test_config("example.com.", Arc::new(MultiCutExchange));
        config.expansion_policy = ExpansionPolicy::All;
        config.max_parallel_queries = 4;
        config.start_servers = Some(vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
        let mut budget = QueryBudget::new(64);
        let qname = DomainName::parse("example.com.").expect("qname");
        let tree =
            run_policy(&config, &mut budget, &mut SilentProgress, qname, false).expect("trace");
        assert!(
            !tree.children.is_empty(),
            "expected trace to continue past root referral"
        );
    }

    #[test]
    fn single_worker_matches_serial_output_on_fixture() {
        let mut serial_config = test_config("example.com.", Arc::new(MultiCutExchange));
        serial_config.expansion_policy = ExpansionPolicy::None;
        serial_config.max_parallel_queries = 1;
        serial_config.start_servers = Some(vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);

        let mut parallel_config = serial_config.clone();
        parallel_config.max_parallel_queries = 8;

        let mut budget = QueryBudget::new(64);
        let qname = DomainName::parse("example.com.").expect("qname");
        let serial_tree = run_policy(
            &serial_config,
            &mut budget,
            &mut SilentProgress,
            qname.clone(),
            false,
        )
        .expect("serial trace");

        let mut budget = QueryBudget::new(64);
        let parallel_tree = run_policy(
            &parallel_config,
            &mut budget,
            &mut SilentProgress,
            qname,
            false,
        )
        .expect("parallel trace");

        assert_eq!(serial_tree.hop.zone, parallel_tree.hop.zone);
        assert_eq!(serial_tree.children.len(), parallel_tree.children.len());
    }

    #[test]
    fn terminal_last_reuses_primary_hop_for_first_sibling() {
        let mut config = test_config("example.com.", Arc::new(MultiCutExchange));
        config.expansion_policy = ExpansionPolicy::Last;
        config.start_servers = Some(vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))]);
        let mut budget = QueryBudget::new(64);
        let qname = DomainName::parse("example.com.").expect("qname");
        let tree =
            run_policy(&config, &mut budget, &mut SilentProgress, qname, false).expect("trace");
        let wrapped = crate::TraceTree {
            request: crate::TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "now".into(),
            },
            root: tree,
            budget_truncated: false,
        };
        let path = wrapped.primary_path();
        let parent = path.iter().rev().nth(1).expect("delegation hop");
        let servers: HashSet<_> = parent
            .children
            .iter()
            .map(|node| node.hop.server.clone())
            .collect();
        assert_eq!(parent.children.len(), servers.len());
    }
}
