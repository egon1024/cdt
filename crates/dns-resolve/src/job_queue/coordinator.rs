use std::collections::HashSet;

use dns_core::name::DomainName;
use hickory_proto::rr::RecordType;

use crate::trace::{
    collect_glue, is_authoritative_answer, resolve_nameservers_from_referral, start_servers,
};
use crate::{
    HopOutcome, QueryBudget, ResolveError, Result, ServerTarget, TraceConfig, TraceNode,
    TraceProgress, hop_from_query,
};

use super::emitter::EmitScheduler;
use super::queue::WorkQueue;
use super::result_store::ResultStore;
use super::types::{JobId, JobKind, JobResult, TraceJob};
use super::worker::execute_job;

/// Run a single-path (`+expand=none`) trace through the serial job queue.
pub fn run_none_policy(
    config: &TraceConfig,
    budget: &mut QueryBudget,
    progress: &mut dyn TraceProgress,
    qname: DomainName,
) -> Result<TraceNode> {
    let mut coordinator = Coordinator::new(config, budget, progress);
    coordinator.run(qname)
}

pub struct Coordinator<'a> {
    config: &'a TraceConfig,
    budget: &'a mut QueryBudget,
    progress: &'a mut dyn TraceProgress,
    queue: WorkQueue,
    results: ResultStore,
    emitter: EmitScheduler,
    visited_zones: HashSet<String>,
    next_job_id: u64,
}

impl<'a> Coordinator<'a> {
    fn new(
        config: &'a TraceConfig,
        budget: &'a mut QueryBudget,
        progress: &'a mut dyn TraceProgress,
    ) -> Self {
        Self {
            config,
            budget,
            progress,
            queue: WorkQueue::new(),
            results: ResultStore::new(),
            emitter: EmitScheduler::new(),
            visited_zones: HashSet::new(),
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

    fn enqueue_cut(
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

    fn run(&mut self, qname: DomainName) -> Result<TraceNode> {
        let root_zone = DomainName::parse(".").expect("root zone");
        self.enqueue_cut(start_servers(self.config), qname, root_zone, vec![])?;

        while let Some(job) = self.queue.dequeue() {
            self.process_job(job)?;
        }

        self.results
            .take_tree()
            .ok_or_else(|| ResolveError::NoReachableNameserver { zone: ".".into() })
    }

    fn process_job(&mut self, job: TraceJob) -> Result<()> {
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

    fn handle_failure(&mut self, job: TraceJob, error: ResolveError) -> Result<()> {
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
            self.store_completed_job(JobResult {
                job_id: job.id,
                path: job.path.clone(),
                hop,
                query_result,
            });
            return Ok(());
        }

        let Some(next_zone) = query_result.response.referral_zone(&job.qname) else {
            hop.outcome = HopOutcome::Answered;
            self.store_completed_job(JobResult {
                job_id: job.id,
                path: job.path.clone(),
                hop,
                query_result,
            });
            return Ok(());
        };

        if !self.visited_zones.insert(next_zone.to_string()) {
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

        let next_servers = resolve_nameservers_from_referral(
            &query_result.response,
            std::slice::from_ref(&job.server),
            self.config,
            self.budget,
            &job.zone,
            self.progress,
        )?;

        if next_servers.is_empty() {
            return Err(ResolveError::NoReachableNameserver {
                zone: next_zone.to_string(),
            });
        }

        self.store_completed_job(JobResult {
            job_id: job.id,
            path: job.path.clone(),
            hop,
            query_result,
        });

        let mut child_path = job.path;
        child_path.push(0);
        self.enqueue_cut(next_servers, job.qname, next_zone, child_path)?;
        Ok(())
    }

    fn store_completed_job(&mut self, completed: JobResult) {
        self.results
            .insert_hop(&completed.path, completed.hop.clone());
        self.emitter.mark_ready(&completed.path, completed.hop);
        self.emitter.drain(self.progress);
    }
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
        let config = test_config("example.com.", Arc::new(AuthoritativeExchange));
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
                IpAddr::V4(v4)
                    if matches!(v4.octets(), [2, 0, 0, 2])
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
        let leaf = root
            .children
            .first()
            .map(|child| {
                let mut current = child;
                while let Some(next) = current.children.first() {
                    current = next;
                }
                current
            })
            .unwrap_or(&root);
        assert_eq!(leaf.hop.outcome, HopOutcome::Answered);
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
}
