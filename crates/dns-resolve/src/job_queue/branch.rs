use dns_core::name::DomainName;
use hickory_proto::rr::RecordType;

use crate::tree::{BranchIntent, NodePath, TraceNode};
use crate::{QueryBudget, Result, ServerTarget, TraceConfig, TraceProgress};

use super::coordinator::run_branch_jobs;

/// One branch query submitted through the job queue.
#[derive(Debug, Clone)]
pub struct BranchJobRequest {
    pub at: NodePath,
    pub intent: BranchIntent,
    pub attach_path: Vec<usize>,
    pub server: ServerTarget,
    pub qname: DomainName,
    pub qtype: RecordType,
    pub zone: DomainName,
}

/// Run a single alternate-server branch query and return the subtree rooted at
/// the new sibling node (including any delegation followed below the cut).
pub fn run_branch_job(
    config: &TraceConfig,
    budget: &mut QueryBudget,
    progress: &mut dyn TraceProgress,
    request: BranchJobRequest,
) -> Result<TraceNode> {
    let zone = request.zone.clone();
    let mut nodes = run_branch_jobs(config, budget, progress, vec![request])?;
    nodes
        .pop()
        .ok_or_else(|| crate::ResolveError::NoReachableNameserver {
            zone: zone.to_string(),
        })
}

/// Run expand-cut branch queries for each nameserver at a zone cut.
#[allow(clippy::too_many_arguments)]
pub fn run_expand_cut_branch(
    config: &TraceConfig,
    budget: &mut QueryBudget,
    progress: &mut dyn TraceProgress,
    at: NodePath,
    servers: Vec<ServerTarget>,
    qname: DomainName,
    qtype: RecordType,
    zone: DomainName,
    attach_path_prefix: Vec<usize>,
) -> Result<Vec<TraceNode>> {
    let requests = servers
        .into_iter()
        .enumerate()
        .map(|(index, server)| {
            let mut attach_path = attach_path_prefix.clone();
            attach_path.push(index);
            BranchJobRequest {
                at: at.clone(),
                intent: BranchIntent::ExpandCut,
                attach_path,
                server,
                qname: qname.clone(),
                qtype,
                zone: zone.clone(),
            }
        })
        .collect();
    run_branch_jobs(config, budget, progress, requests)
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

    use crate::{
        BranchIntent, HopOutcome, NodeOrigin, NodePath, QueryBudget, TraceConfig, TraceHop,
        TraceProgress,
    };

    struct SilentProgress;

    impl TraceProgress for SilentProgress {
        fn hop(&mut self, _hop: &TraceHop, _path: &NodePath) {}
        fn message(&mut self, _message: &str) {}
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

    struct DelegatingBranchExchange;

    impl crate::DnsExchange for DelegatingBranchExchange {
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

    fn primary_leaf(node: &TraceNode) -> &TraceNode {
        let mut current = node;
        while let Some(child) = current.children.first() {
            current = child;
        }
        current
    }

    #[test]
    fn branch_job_follows_delegation_to_answer() {
        let qname = DomainName::parse("example.com.").expect("qname");
        let mut config = TraceConfig::new(qname.clone(), RecordType::A);
        config.exchange = Arc::new(DelegatingBranchExchange);
        let at = NodePath {
            tree: 0,
            path: vec![1],
        };

        let mut budget = QueryBudget::new(64);
        let node = run_branch_job(
            &config,
            &mut budget,
            &mut SilentProgress,
            BranchJobRequest {
                at,
                intent: BranchIntent::AlternateServer,
                attach_path: vec![1],
                server: ServerTarget::from_address(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
                qname,
                qtype: RecordType::A,
                zone: DomainName::parse(".").expect("zone"),
            },
        )
        .expect("branch");

        assert_eq!(node.hop.outcome, HopOutcome::Referral);
        assert!(
            !node.children.is_empty(),
            "branch should continue through delegation"
        );
        assert!(matches!(node.children[0].origin, NodeOrigin::Trace));
        let leaf = primary_leaf(&node);
        assert_eq!(leaf.hop.outcome, HopOutcome::Answered);
        assert_eq!(leaf.hop.zone, "example.com.");
        match node.origin {
            NodeOrigin::Branch { intent, .. } => {
                assert_eq!(intent, BranchIntent::AlternateServer);
            }
            other => panic!("expected branch origin on first hop, got {other:?}"),
        }
    }

    #[test]
    fn branch_job_sets_node_origin_branch() {
        let qname = DomainName::parse("example.com.").expect("qname");
        let mut config = TraceConfig::new(qname.clone(), RecordType::A);
        config.start_servers = Some(vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
        config.exchange = Arc::new(AuthoritativeExchange);
        let at = NodePath {
            tree: 0,
            path: vec![0, 1],
        };

        let mut budget = QueryBudget::new(64);
        let node = run_branch_job(
            &config,
            &mut budget,
            &mut SilentProgress,
            BranchJobRequest {
                at: at.clone(),
                intent: BranchIntent::AlternateServer,
                attach_path: vec![0],
                server: ServerTarget::with_name(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), "ns"),
                qname,
                qtype: RecordType::A,
                zone: DomainName::parse("example.com.").expect("zone"),
            },
        )
        .expect("branch");

        assert_eq!(node.hop.outcome, HopOutcome::Answered);
        match node.origin {
            NodeOrigin::Branch {
                at: branch_at,
                intent,
                ..
            } => {
                assert_eq!(branch_at, at);
                assert_eq!(intent, BranchIntent::AlternateServer);
            }
            other => panic!("expected branch origin, got {other:?}"),
        }
    }

    #[test]
    fn expand_cut_branch_queries_each_server() {
        let qname = DomainName::parse("example.com.").expect("qname");
        let mut config = TraceConfig::new(qname.clone(), RecordType::A);
        config.exchange = Arc::new(AuthoritativeExchange);
        let at = NodePath {
            tree: 0,
            path: vec![2],
        };
        let servers = vec![
            ServerTarget::with_name(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), "ns1."),
            ServerTarget::with_name(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2)), "ns2."),
        ];

        let mut budget = QueryBudget::new(64);
        let nodes = run_expand_cut_branch(
            &config,
            &mut budget,
            &mut SilentProgress,
            at.clone(),
            servers,
            qname,
            RecordType::A,
            DomainName::parse("example.com.").expect("zone"),
            vec![0],
        )
        .expect("expand cut");

        assert_eq!(nodes.len(), 2);
        for node in nodes {
            match node.origin {
                NodeOrigin::Branch { intent, .. } => {
                    assert_eq!(intent, BranchIntent::ExpandCut);
                }
                other => panic!("expected branch origin, got {other:?}"),
            }
        }
    }
}
