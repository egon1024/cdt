use super::*;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use dns_core::EdnsMeta;
use dns_core::name::DomainName;
use dns_core::response::{DnsRecord, DnsResponse};
use dns_resolve::{
    BranchIntent, HopOutcome, NodeOrigin, NodePath, QueryBudget, TraceHop, TraceNode,
    TraceProgress, TraceTree, TraceTreeRequest,
};

use crate::branch::execute::{align_answer_hop_zones, normalize_expand_cut_attachments};
use crate::branch::target::{
    expand_cut_targets, nameserver_satisfied_at_cut, resolve_alternate_target,
};
use crate::dig_options::TraceOptions;
use crate::runtime::Runtime;
use crate::session::SessionDocument;
use crate::trace_config::trace_config_from_request;
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
        None,
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
        None,
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

fn tuininga_a2_session_tree() -> TraceTree {
    let mut tree = tuininga_tree();
    tree.root.hop.referral_ns = vec![
        "a2.org.afilias-nst.info.".into(),
        "b2.org.afilias-nst.org.".into(),
        "d0.org.afilias-nst.org.".into(),
        "a0.org.afilias-nst.info.".into(),
        "b0.org.afilias-nst.org.".into(),
        "c0.org.afilias-nst.info.".into(),
    ];
    tree.root.hop.glue = vec![
        "199.249.112.1".into(),
        "199.249.120.1".into(),
        "199.19.57.1".into(),
        "199.19.56.1".into(),
        "199.19.54.1".into(),
        "199.19.53.1".into(),
    ];
    tree.root.children[0].hop.server_name = Some("a2.org.afilias-nst.info.".into());
    tree
}

#[test]
fn expand_cut_from_a2_primary_session_dry_run_lists_remaining_root_ns() {
    let mut document = sample_document(
        tuininga_a2_session_tree(),
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
        None,
    )
    .expect("branch");
    let plan = report.plan.expect("plan");
    assert_eq!(plan.zone, ".");
    assert_eq!(plan.targets.len(), 5);
    assert!(
        !plan
            .targets
            .iter()
            .any(|target| target.contains("a2.org.afilias-nst.info"))
    );
    assert!(
        plan.targets
            .iter()
            .any(|target| target.contains("b0.org.afilias-nst.org"))
    );
}

#[test]
fn expand_cut_from_a2_primary_session_adds_org_siblings_without_loop() {
    let mut document = sample_document(
        tuininga_a2_session_tree(),
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
        Some(Arc::new(TuiningaBranchExchangeImpl {
            root_cut_queried: Mutex::new(HashSet::new()),
        })),
        None,
    )
    .expect("branch should not hit delegation loop at tuininga.org");
    assert_eq!(report.nodes_added, 5);
    let root = document
        .primary_tree()
        .expect("tree")
        .resolve(&NodePath::root(0))
        .expect("root");
    assert_eq!(root.children.len(), 6);
    assert!(root.children.iter().all(|child| child.hop.zone == "org."));
}

#[test]
fn expand_cut_from_a2_primary_when_org_ns_skips_tld_hop() {
    struct SkippedTldBranchExchange {
        root_cut_queried: Mutex<HashSet<IpAddr>>,
    }

    impl dns_resolve::DnsExchange for SkippedTldBranchExchange {
        fn exchange(
            &self,
            server: IpAddr,
            _port: u16,
            options: &dns_core::query::QueryOptions,
        ) -> dns_core::Result<dns_core::response::QueryResult> {
            assert_eq!(options.qname.as_str(), "tuininga.org.");
            if tuininga_root_cut_queried(&self.root_cut_queried, server) {
                return Ok(tuininga_qname_delegation(server, options));
            }
            Ok(tuininga_org_delegation(server, options))
        }
    }

    let mut document = sample_document(
        tuininga_a2_session_tree(),
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
        Some(Arc::new(SkippedTldBranchExchange {
            root_cut_queried: Mutex::new(HashSet::new()),
        })),
        None,
    )
    .expect("branch");
    assert_eq!(report.nodes_added, 5, "{:?}", report.warnings);
    let root = document
        .primary_tree()
        .expect("tree")
        .resolve(&NodePath::root(0))
        .expect("root");
    assert_eq!(root.children.len(), 6);
    assert!(root.children.iter().all(|child| child.hop.zone == "org."));
}

fn tuininga_qname_delegation(
    server: IpAddr,
    options: &dns_core::query::QueryOptions,
) -> dns_core::response::QueryResult {
    dns_core::response::QueryResult {
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
    }
}

#[test]
#[ignore = "requires live DNS"]
fn live_root_expand_attaches_org_siblings() {
    use dns_resolve::{QueryBudget, run_expand_cut_branch};

    let tree = tuininga_a2_session_tree();
    let request = TraceRequest::from_options(&TraceOptions {
        qname: "tuininga.org.".into(),
        ..Default::default()
    });
    let mut document = sample_document(tree, request.clone());
    let runtime = runtime();
    let session_tree = document.primary_tree().expect("tree");
    let mut config = trace_config_from_request(
        &request,
        runtime.cache.clone(),
        runtime.config.trace_max_queries_per_action,
        runtime.config.trace_max_parallel_queries,
    )
    .expect("config");
    dns_resolve::trace::seed_ns_targets_from_tree(&config, &session_tree.root);
    let qname = dns_core::name::DomainName::parse("tuininga.org.").expect("qname");
    let qtype = dns_core::parse_record_type("A").expect("qtype");
    let zone = dns_core::name::DomainName::parse(".").expect("zone");
    let cut_hop = session_tree.root.hop.clone();
    let targets = expand_cut_targets(
        &cut_hop,
        true,
        &session_tree.root.children.iter().collect::<Vec<_>>(),
        &mut config,
        &mut QueryBudget::new(64),
        &mut SilentProgress,
        &mut Vec::new(),
        false,
    )
    .expect("targets");
    eprintln!("targets={}", targets.len());
    let mut budget = QueryBudget::new(64);
    let raw = run_expand_cut_branch(
        &config,
        &mut budget,
        &mut SilentProgress,
        NodePath::root(0),
        targets,
        qname,
        qtype,
        zone,
        vec![],
    )
    .expect("branch jobs");
    for (index, node) in raw.iter().enumerate() {
        eprintln!(
            "raw[{index}] zone={} server={} outcome={:?} children={}",
            node.hop.zone,
            node.hop.server,
            node.hop.outcome,
            node.children.len()
        );
        for (cidx, child) in node.children.iter().enumerate() {
            eprintln!(
                "  child[{cidx}] zone={} server={} children={}",
                child.hop.zone,
                child.hop.server,
                child.children.len()
            );
        }
    }
    let normalized =
        normalize_expand_cut_attachments(&cut_hop, true, session_tree.root.children.first(), raw);
    eprintln!("normalized={}", normalized.len());

    let report = execute_branch(
        &mut document,
        NodePath::root(0),
        BranchIntentArg::ExpandCut,
        false,
        &runtime,
        &mut SilentProgress,
        None,
        None,
    )
    .expect("live branch");
    eprintln!(
        "nodes_added={} warnings={:?}",
        report.nodes_added, report.warnings
    );
    assert!(
        report.nodes_added >= 1,
        "expected live root expand to attach org siblings"
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
fn format_branch_report_lists_targets_when_attach_fails() {
    let report = BranchReport {
        nodes_added: 0,
        updated_at: None,
        warnings: vec![
            "branch queries completed but no nodes could be attached at this cut".into(),
        ],
        budget_truncated: false,
        dry_run: false,
        plan: Some(BranchPlan {
            hop: Some(0),
            path: "0".into(),
            zone: ".".into(),
            server: "198.41.0.4".into(),
            qname: "tuininga.org.".into(),
            targets: vec!["b0.org.afilias-nst.org. (199.249.120.1)".into()],
        }),
    };
    let text = format_branch_report(&report);
    assert!(!text.contains("nothing to query"));
    assert!(text.contains("queried:"));
    assert!(text.contains("b0.org.afilias-nst.org"));
    assert!(text.contains("no nodes added"));
}

/// A dry run used to return before the warning loop, so an empty plan gave
/// the operator "nothing to query at this cut" with no reason and no hint
/// that the per-action cap had been reached.
#[test]
fn dry_run_report_keeps_warnings_and_budget_notice() {
    let report = BranchReport {
        nodes_added: 0,
        updated_at: None,
        warnings: vec!["all nameservers at this zone cut already queried".into()],
        budget_truncated: true,
        dry_run: true,
        plan: Some(BranchPlan {
            hop: Some(1),
            path: "0.0".into(),
            zone: "org.".into(),
            server: "199.249.112.1".into(),
            qname: "tuininga.org.".into(),
            targets: Vec::new(),
        }),
    };
    let text = format_branch_report(&report);
    assert!(text.contains("nothing to query at this cut"));
    assert!(text.contains("dry run: no queries issued"));
    assert!(text.contains("warning: all nameservers at this zone cut already queried"));
    assert!(text.contains("warning: per-action query cap reached"));
}

/// The node line has to name the hop and path it resolved, so `--at-hop=N`
/// can be checked against what `session outline` prints.
#[test]
fn report_node_line_names_resolved_hop_and_path() {
    let report = BranchReport {
        nodes_added: 0,
        updated_at: None,
        warnings: Vec::new(),
        budget_truncated: false,
        dry_run: true,
        plan: Some(BranchPlan {
            hop: Some(1),
            path: "0.0".into(),
            zone: "org.".into(),
            server: "199.249.112.1".into(),
            qname: "tuininga.org.".into(),
            targets: Vec::new(),
        }),
    };
    let text = format_branch_report(&report);
    assert!(
        text.starts_with(
            "node: hop 1 (at-path 0.0) zone org. server 199.249.112.1 query tuininga.org."
        ),
        "{text}"
    );
}

/// `+expand=last` leaves the terminal cut fully queried, so a dry run there
/// has nothing to do. It must say why, and name the hop it resolved, rather
/// than reporting a bare "nothing to query at this cut".
#[test]
fn dry_run_at_fully_queried_cut_explains_why_nothing_is_queried() {
    let mut document = sample_document(
        tuininga_tree(),
        TraceRequest::from_options(&TraceOptions {
            qname: "tuininga.org.".into(),
            ..Default::default()
        }),
    );
    let runtime = runtime();
    let at = resolve_branch_target(&document, Some(1), None).expect("hop 1");
    let report = execute_branch(
        &mut document,
        at,
        BranchIntentArg::ExpandCut,
        true,
        &runtime,
        &mut SilentProgress,
        None,
        None,
    )
    .expect("branch");
    let text = format_branch_report(&report);
    assert!(
        text.contains("node: hop 1 (at-path 0.0) zone org. server 199.249.112.1"),
        "{text}"
    );
    assert!(text.contains("nothing to query at this cut"), "{text}");
    assert!(
        text.contains("warning: all nameservers at this zone cut already queried"),
        "{text}"
    );
    assert!(text.contains("dry run: no queries issued"), "{text}");
}

fn linear_www_tuininga_tree() -> TraceTree {
    TraceTree {
        request: TraceTreeRequest {
            qname: "www.tuininga.org.".into(),
            qtype: "A".into(),
            started_at: "2026-09-19T00:00:00Z".into(),
        },
        root: TraceNode {
            hop: TraceHop {
                zone: ".".into(),
                server: "198.41.0.4".into(),
                server_name: Some("a.root-servers.net.".into()),
                qname: "www.tuininga.org.".into(),
                qtype: "A".into(),
                transport: "udp".into(),
                rtt_ms: 96,
                rcode: "NOERROR".into(),
                nsid: None,
                ede_code: None,
                ede_text: None,
                referral_ns: vec![
                    "a2.org.afilias-nst.info.".into(),
                    "b2.org.afilias-nst.org.".into(),
                    "d0.org.afilias-nst.org.".into(),
                ],
                glue: vec![
                    "199.249.112.1".into(),
                    "199.249.120.1".into(),
                    "199.19.57.1".into(),
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
                    server_name: Some("a2.org.afilias-nst.info.".into()),
                    qname: "www.tuininga.org.".into(),
                    qtype: "A".into(),
                    transport: "udp".into(),
                    rtt_ms: 103,
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
                children: vec![TraceNode {
                    hop: TraceHop {
                        zone: "www.tuininga.org.".into(),
                        server: "193.47.99.5".into(),
                        server_name: Some("helium.ns.hetzner.de.".into()),
                        qname: "www.tuininga.org.".into(),
                        qtype: "A".into(),
                        transport: "udp".into(),
                        rtt_ms: 105,
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
                }],
            }],
        },
        budget_truncated: false,
    }
}

/// Linear `+expand=last` traces leave sibling nameservers at the org cut
/// unqueried; branching at hop 1 should list them.
#[test]
fn expand_cut_at_org_hop_lists_unqueried_tuininga_nameservers() {
    let mut document = sample_document(
        linear_www_tuininga_tree(),
        TraceRequest::from_options(&TraceOptions {
            qname: "www.tuininga.org".into(),
            ..Default::default()
        }),
    );
    let runtime = runtime();
    let at = resolve_branch_target(&document, Some(1), None).expect("hop 1");
    let report = execute_branch(
        &mut document,
        at,
        BranchIntentArg::ExpandCut,
        true,
        &runtime,
        &mut SilentProgress,
        None,
        None,
    )
    .expect("branch");
    let report_text = format_branch_report(&report);
    let plan = report.plan.as_ref().expect("plan");
    assert_eq!(plan.zone, "org.");
    assert_eq!(plan.targets.len(), 2);
    assert!(
        plan.targets
            .iter()
            .any(|target| target.contains("hydrogen.ns.hetzner.com")),
        "targets={:?}",
        plan.targets
    );
    assert!(
        plan.targets
            .iter()
            .any(|target| target.contains("oxygen.ns.hetzner.com")),
        "targets={:?}",
        plan.targets
    );
    assert!(
        plan.targets
            .iter()
            .all(|target| target.contains("needs live resolution")),
        "glueless dry-run targets should note live resolution is required: {:?}",
        plan.targets
    );
    assert!(
        !report
            .warnings
            .iter()
            .any(|warning| warning.contains("all nameservers at this zone cut already queried")),
        "glueless unqueried NS must not be reported as already queried: {:?}",
        report.warnings
    );
    assert!(
        report_text.contains("would query:"),
        "report should list pending nameservers, got:\n{report_text}"
    );
    assert!(
        !report_text.contains("nothing to query at this cut"),
        "report should not claim nothing to query when NS remain:\n{report_text}"
    );
}

#[test]
fn expand_cut_from_fresh_tuininga_trace_dry_run_lists_remaining_root_ns() {
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

fn tuininga_root_cut_queried(seen: &Mutex<HashSet<IpAddr>>, server: IpAddr) -> bool {
    seen.lock().expect("root cut mutex").insert(server)
}

fn tuininga_org_referral(
    server: IpAddr,
    options: &dns_core::query::QueryOptions,
) -> dns_core::response::QueryResult {
    dns_core::response::QueryResult {
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
    }
}

fn tuininga_org_delegation(
    server: IpAddr,
    options: &dns_core::query::QueryOptions,
) -> dns_core::response::QueryResult {
    dns_core::response::QueryResult {
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
    }
}

#[test]
fn expand_cut_from_root_reuses_session_nameserver_targets() {
    struct TuiningaBranchExchange {
        root_cut_queried: Mutex<HashSet<IpAddr>>,
    }

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
            if Self::is_root_expand_target(server)
                && tuininga_root_cut_queried(&self.root_cut_queried, server)
            {
                return Ok(tuininga_org_referral(server, options));
            }
            if Self::is_org_server(server) {
                return Ok(tuininga_org_delegation(server, options));
            }
            Ok(tuininga_org_referral(server, options))
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
        Some(Arc::new(TuiningaBranchExchange {
            root_cut_queried: Mutex::new(HashSet::new()),
        })),
        None,
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
fn align_answer_hop_zones_matches_primary_terminal_cut() {
    let mut nodes = vec![TraceNode {
        hop: TraceHop {
            zone: "org.".into(),
            server: "193.47.99.5".into(),
            server_name: Some("helium.ns.hetzner.de.".into()),
            qname: "tuininga.org.".into(),
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
        },
        origin: NodeOrigin::Branch {
            at: NodePath::root(0),
            intent: BranchIntent::ExpandCut,
            at_time: "now".into(),
        },
        children: vec![],
    }];
    align_answer_hop_zones(&mut nodes, "tuininga.org.", "org.");
    assert_eq!(nodes[0].hop.zone, "tuininga.org.");
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
        None,
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
        None,
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
        None,
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
            hop: Some(1),
            path: "0.0".into(),
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
    let id = runtime.save_session(&tree, &request, false).expect("save");
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
        None,
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
    let id = runtime.save_session(&tree, &request, false).expect("save");
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
        None,
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
fn normalize_extracts_org_when_branch_skips_tld_hop() {
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
        children: vec![TraceNode {
            hop: TraceHop {
                zone: "tuininga.org.".into(),
                server: "199.249.120.1".into(),
                server_name: Some("b2.org.afilias-nst.org.".into()),
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
                outcome: HopOutcome::Referral,
            },
            origin: NodeOrigin::Branch {
                at: NodePath::root(0),
                intent: BranchIntent::ExpandCut,
                at_time: "now".into(),
            },
            children: vec![],
        }],
    };

    let normalized =
        normalize_expand_cut_attachments(&cut, true, Some(&org_template), vec![branch]);

    assert_eq!(normalized.len(), 1);
    assert_eq!(normalized[0].hop.zone, "org.");
    assert_eq!(normalized[0].hop.server, "199.249.120.1");
}

#[test]
fn normalize_extracts_org_from_deep_branch_subtree() {
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
    let branch = TraceNode {
        hop: TraceHop {
            zone: ".".into(),
            server: "199.19.54.1".into(),
            server_name: Some("b0.org.afilias-nst.org.".into()),
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
        children: vec![TraceNode {
            hop: TraceHop {
                zone: "org.".into(),
                server: "199.19.54.1".into(),
                server_name: Some("b0.org.afilias-nst.org.".into()),
                qname: "tuininga.org.".into(),
                qtype: "A".into(),
                transport: "udp".into(),
                rtt_ms: 3,
                rcode: "NOERROR".into(),
                nsid: None,
                ede_code: None,
                ede_text: None,
                referral_ns: vec!["helium.ns.hetzner.de.".into()],
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
            children: vec![TraceNode {
                hop: TraceHop {
                    zone: "tuininga.org.".into(),
                    server: "193.47.99.5".into(),
                    server_name: Some("helium.ns.hetzner.de.".into()),
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
                origin: NodeOrigin::Branch {
                    at: NodePath::root(0),
                    intent: BranchIntent::ExpandCut,
                    at_time: "now".into(),
                },
                children: vec![],
            }],
        }],
    };

    let normalized =
        normalize_expand_cut_attachments(&cut, true, Some(&org_template), vec![branch]);

    assert_eq!(normalized.len(), 1);
    assert_eq!(normalized[0].hop.zone, "org.");
    assert_eq!(normalized[0].hop.server, "199.19.54.1");
    assert!(normalized[0].children.is_empty());
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
        Some(Arc::new(TuiningaBranchExchangeImpl {
            root_cut_queried: Mutex::new(HashSet::new()),
        })),
        None,
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
    assert!(nameserver_satisfied_at_cut(
        &cut_hop,
        true,
        &DomainName::parse("a0.org.afilias-nst.info.").expect("ns"),
        &queried,
    ));
    assert!(nameserver_satisfied_at_cut(
        &cut_hop,
        true,
        &DomainName::parse("b0.org.afilias-nst.org.").expect("ns"),
        &queried,
    ));
    assert!(nameserver_satisfied_at_cut(
        &cut_hop,
        true,
        &DomainName::parse("c0.org.afilias-nst.info.").expect("ns"),
        &queried,
    ));

    let second = execute_branch(
        &mut document,
        NodePath::root(0),
        BranchIntentArg::ExpandCut,
        false,
        &runtime,
        &mut SilentProgress,
        Some(Arc::new(TuiningaBranchExchangeImpl {
            root_cut_queried: Mutex::new(HashSet::new()),
        })),
        None,
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

struct TuiningaBranchExchangeImpl {
    root_cut_queried: Mutex<HashSet<IpAddr>>,
}

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
        if Self::is_root_expand_target(server)
            && tuininga_root_cut_queried(&self.root_cut_queried, server)
        {
            return Ok(tuininga_org_referral(server, options));
        }
        if Self::is_org_server(server) {
            return Ok(tuininga_org_delegation(server, options));
        }
        Ok(tuininga_org_referral(server, options))
    }
}
