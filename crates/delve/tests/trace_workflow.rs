//! Synthetic end-to-end workflow: expand=last trace snapshot → branch → compare → reopen.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use delve::branch::{BranchIntentArg, execute_branch};
use delve::dig_options::TraceOptions;
use delve::explore::{build_explore_tree, render_events_comparison, render_outline_comparison};
use delve::paths::DelvePaths;
use delve::runtime::Runtime;
use delve::session::ExploreViewState;
use delve::trace_request::TraceRequest;
use dns_core::EdnsMeta;
use dns_core::response::{DnsRecord, DnsResponse};
use dns_resolve::{
    DatagramIcmpProber, ExpansionPolicy, HopOutcome, NodeOrigin, NodePath, TraceHop, TraceNode,
    TraceProgress, TraceTree, TraceTreeRequest,
};

struct SilentProgress;

impl TraceProgress for SilentProgress {
    fn hop(&mut self, _hop: &TraceHop, _path: &NodePath) {}
    fn message(&mut self, _message: &str) {}
}

fn tuininga_expand_last_tree() -> TraceTree {
    TraceTree {
        request: TraceTreeRequest {
            qname: "tuininga.org.".into(),
            qtype: "A".into(),
            started_at: "2026-09-01T12:00:00Z".into(),
        },
        root: TraceNode {
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
                    terminal_answer("193.47.99.5", "helium.ns.hetzner.de.", 3),
                    terminal_answer("213.133.100.98", "hydrogen.ns.hetzner.com.", 4),
                    terminal_answer("88.198.229.192", "oxygen.ns.hetzner.com.", 5),
                ],
            }],
        },
        budget_truncated: false,
    }
}

fn terminal_answer(server: &str, server_name: &str, rtt_ms: u64) -> TraceNode {
    TraceNode {
        hop: TraceHop {
            zone: "tuininga.org.".into(),
            server: server.into(),
            server_name: Some(server_name.into()),
            qname: "tuininga.org.".into(),
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
        },
        origin: NodeOrigin::Trace,
        children: vec![],
    }
}

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
}

impl dns_resolve::DnsExchange for TuiningaBranchExchange {
    fn exchange(
        &self,
        server: IpAddr,
        _port: u16,
        options: &dns_core::query::QueryOptions,
    ) -> dns_core::Result<dns_core::response::QueryResult> {
        let qname = options.qname.as_str();
        if !qname
            .trim_end_matches('.')
            .eq_ignore_ascii_case("tuininga.org")
        {
            return Err(dns_core::DnsCoreError::Parse(format!(
                "unexpected query {qname} to {server}"
            )));
        }
        if Self::is_root_expand_target(server) {
            let mut queried = self.root_cut_queried.lock().expect("lock");
            if queried.insert(server) {
                return Ok(org_referral(server, options));
            }
        }
        if Self::is_org_server(server) {
            return Ok(org_delegation(server, options));
        }
        Ok(org_referral(server, options))
    }
}

fn org_referral(
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
                name: dns_core::name::DomainName::parse("org.").expect("org"),
                rtype: "NS".into(),
                rclass: "IN".into(),
                ttl: 86400,
                rdata: "ns.org.".into(),
            }],
            additionals: vec![],
            edns: EdnsMeta::default(),
        },
        from_cache: false,
    }
}

fn org_delegation(
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
    }
}

fn trace_request() -> TraceRequest {
    let mut request = TraceRequest::from_options(&TraceOptions {
        qname: "tuininga.org.".into(),
        ..Default::default()
    });
    request.expansion = ExpansionPolicy::Last;
    request
}

#[test]
fn trace_branch_compare_and_reopen_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let runtime = Runtime::open(DelvePaths::from_root(dir.path()));
    let tree = tuininga_expand_last_tree();
    let request = trace_request();
    let created_at = tree.started_at().to_string();

    let id = runtime
        .save_session(&tree, &request, false)
        .expect("save session");
    let mut document = runtime.get_session(&id).expect("load session");
    assert_eq!(document.version, 2);
    assert_eq!(document.created_at, created_at);
    assert!(!document.has_branches());
    assert_eq!(
        document.primary_tree().expect("tree").root.children.len(),
        1
    );

    let prober = DatagramIcmpProber::default();
    let outline_before = render_outline_comparison(&document, Some(0), None, &prober)
        .expect("fork below root is reachable from hop 0");
    assert!(outline_before.contains("helium.ns.hetzner.de"));

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
    )
    .expect("branch");
    assert_eq!(report.nodes_added, 2);
    assert!(document.updated_at >= document.created_at);
    assert!(document.has_branches());

    let root = document
        .primary_tree()
        .expect("tree")
        .resolve(&NodePath::root(0))
        .expect("root");
    assert_eq!(root.children.len(), 3);

    let outline = render_outline_comparison(&document, Some(0), None, &prober)
        .expect("outline comparison after branch");
    let events = render_events_comparison(&document, Some(0), None, &prober)
        .expect("events comparison after branch");
    assert!(outline.contains("helium.ns.hetzner.de"));
    assert!(events.contains("\"path_comparison\""));
    assert!(events.contains("\"dns_rtt_total_ms\""));

    document.view_state = Some(ExploreViewState {
        active_screen: "compare".into(),
        expanded_paths: vec![vec![0]],
        selection: vec![0, 0],
        pane: "tree".into(),
        compare_focus_row: 1,
        browse_split_percent: 60,
    });
    runtime
        .update_session(&document)
        .expect("persist view state");

    let reopened = runtime.get_session(&id).expect("reopen session");
    assert_eq!(reopened.view_state, document.view_state);
    assert_eq!(
        reopened.primary_tree().expect("tree").root.children.len(),
        3
    );

    let explore = build_explore_tree(reopened.primary_tree().expect("tree"));
    let restored = reopened.view_state.as_ref().expect("view state");
    assert_eq!(restored.active_screen, "compare");
    assert_eq!(restored.selection, vec![0, 0]);
    assert_eq!(restored.compare_focus_row, 1);
    assert!(
        explore
            .node_at(&NodePath {
                tree: 0,
                path: restored.selection.clone(),
            })
            .is_some(),
        "stored selection resolves in explore tree after reopen"
    );
}
