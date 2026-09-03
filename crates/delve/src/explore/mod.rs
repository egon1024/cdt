mod compare_screen;
mod detail;
mod dig_view;
mod flags;
mod json;
mod outline;
mod pane_split;
mod path_summary;
mod path_timing;
mod refresh;
mod rtt_bar;
mod rtt_color;
pub use rtt_color::rtt_gradient_rgb;
mod terminal;
mod theme;
mod tree;
mod tui;
mod view_state;

pub use json::render_tree_json;
pub use outline::render_outline;
pub(crate) use terminal::{cache_source_symbol, ui_symbols};
pub use tree::{build_explore_tree, build_explore_tree_with_qname};
pub use tui::{ExploreContext, run_tui};

use crate::branch::resolve_branch_target;
use crate::runtime::Runtime;
use crate::session::SessionDocument;
use dns_resolve::{DatagramIcmpProber, IcmpProber};
use path_summary::{comparison_at, enrich_icmp, render_comparison_json, render_comparison_text};
use std::io::{self, IsTerminal, Write};

fn explore_tree_for_document(
    document: &SessionDocument,
) -> Result<tree::ExploreTree, ExploreError> {
    let trace = document.primary_tree().ok_or(ExploreError::NoTraceTree)?;
    Ok(if let Some(request) = document.primary_request() {
        build_explore_tree_with_qname(trace, 0, Some(&request.qname))
    } else {
        build_explore_tree(trace)
    })
}

pub fn run_outline(document: &SessionDocument) -> Result<(), ExploreError> {
    run_outline_with_compare(document, None, None, &DatagramIcmpProber::default())
}

pub fn run_outline_with_compare(
    document: &SessionDocument,
    compare_at_hop: Option<usize>,
    compare_at_path: Option<&str>,
    prober: &dyn IcmpProber,
) -> Result<(), ExploreError> {
    if compare_at_hop.is_some() || compare_at_path.is_some() {
        let output = render_outline_comparison(document, compare_at_hop, compare_at_path, prober)?;
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(output.as_bytes())
            .map_err(ExploreError::Io)?;
        stdout.flush().map_err(ExploreError::Io)?;
        return Ok(());
    }
    let tree = explore_tree_for_document(document)?;
    let mut output = format!("session: {}\n", document.id);
    output.push_str(&render_outline(&tree, ui_symbols()));
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(output.as_bytes())
        .map_err(ExploreError::Io)?;
    stdout.flush().map_err(ExploreError::Io)?;
    Ok(())
}

pub fn run_events(document: &SessionDocument) -> Result<(), ExploreError> {
    run_events_with_compare(document, None, None, &DatagramIcmpProber::default())
}

pub fn run_events_with_compare(
    document: &SessionDocument,
    compare_at_hop: Option<usize>,
    compare_at_path: Option<&str>,
    prober: &dyn IcmpProber,
) -> Result<(), ExploreError> {
    if compare_at_hop.is_some() || compare_at_path.is_some() {
        let output = render_events_comparison(document, compare_at_hop, compare_at_path, prober)?;
        println!("{output}");
        return Ok(());
    }
    let tree = explore_tree_for_document(document)?;
    println!("{}", render_tree_json(&tree, &document.id));
    Ok(())
}

pub fn render_outline_comparison(
    document: &SessionDocument,
    compare_at_hop: Option<usize>,
    compare_at_path: Option<&str>,
    prober: &dyn IcmpProber,
) -> Result<String, ExploreError> {
    let comparison = load_comparison(document, compare_at_hop, compare_at_path, prober)?;
    Ok(render_comparison_text(&comparison))
}

pub fn render_events_comparison(
    document: &SessionDocument,
    compare_at_hop: Option<usize>,
    compare_at_path: Option<&str>,
    prober: &dyn IcmpProber,
) -> Result<String, ExploreError> {
    let comparison = load_comparison(document, compare_at_hop, compare_at_path, prober)?;
    Ok(render_comparison_json(&document.id, &comparison))
}

fn load_comparison(
    document: &SessionDocument,
    compare_at_hop: Option<usize>,
    compare_at_path: Option<&str>,
    prober: &dyn IcmpProber,
) -> Result<path_summary::ForkComparison, ExploreError> {
    let target = resolve_branch_target(document, compare_at_hop, compare_at_path)
        .map_err(|error| ExploreError::UnresolvedCompareTarget(error.to_string()))?;
    let named = compare_at_path
        .map(str::to_string)
        .or_else(|| compare_at_hop.map(|hop| hop.to_string()))
        .unwrap_or_else(|| {
            target
                .path
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(".")
        });
    let tree = document.primary_tree().ok_or(ExploreError::NoTraceTree)?;
    let Some(comparison) = comparison_at(tree, &target) else {
        return Err(ExploreError::NothingToCompare { target: named });
    };
    Ok(enrich_icmp(comparison, tree, prober))
}

pub fn run_explore(runtime: &Runtime, document: &mut SessionDocument) -> Result<(), ExploreError> {
    if !io::stdout().is_terminal() || !io::stdin().is_terminal() {
        return Err(ExploreError::NotTerminal);
    }
    explore_tree_for_document(document)?;

    run_tui(ExploreContext {
        runtime,
        document,
        persist_view_state: runtime.config.explore_persist_view_state,
    })
    .map_err(ExploreError::Io)
}

#[derive(Debug, thiserror::Error)]
pub enum ExploreError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(
        "explore requires an interactive terminal (stdin and stdout); use `delve session outline` for a printable tree"
    )]
    NotTerminal,

    #[error("session has no trace tree")]
    NoTraceTree,

    #[error("nothing to compare at {target}: no sibling paths")]
    NothingToCompare { target: String },

    #[error("{0}")]
    UnresolvedCompareTarget(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionDocument;
    use crate::trace_request::TraceRequest;
    use dns_resolve::{HopOutcome, TraceHop, TraceTreeRequest, build_linear_tree};

    #[test]
    fn run_outline_writes_tree() {
        let document = SessionDocument::new(
            "01JTESTSESSION000000000000".into(),
            TraceRequest::from_options(&crate::dig_options::TraceOptions {
                qname: "example.com".into(),
                ..Default::default()
            }),
            build_linear_tree(
                vec![
                    TraceHop {
                        zone: ".".into(),
                        server: "198.41.0.4".into(),
                        server_name: None,
                        qname: "example.com.".into(),
                        qtype: "A".into(),
                        transport: "udp".into(),
                        rtt_ms: 11,
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
                    TraceHop {
                        zone: "com.".into(),
                        server: "192.41.162.30".into(),
                        server_name: None,
                        qname: "example.com.".into(),
                        qtype: "A".into(),
                        transport: "udp".into(),
                        rtt_ms: 8,
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
                ],
                TraceTreeRequest {
                    qname: "example.com.".into(),
                    qtype: "A".into(),
                    started_at: "2026-08-25T12:00:00Z".into(),
                },
            ),
        );

        let tree = explore_tree_for_document(&document).expect("tree");
        let outline = render_outline(&tree, ui_symbols());
        assert!(outline.contains("example.com. A"));
        assert!(outline.contains("rtt: 11 ms"));

        let json = render_tree_json(&tree, &document.id);
        assert!(json.contains("\"event\":\"explore_tree\""));

        run_outline(&document).expect("outline");
        run_events(&document).expect("events");
    }

    #[test]
    fn failed_node_outline_includes_failure_detail() {
        let document = SessionDocument::new(
            "01FAIL".into(),
            TraceRequest::from_options(&crate::dig_options::TraceOptions {
                qname: "example.com".into(),
                ..Default::default()
            }),
            build_linear_tree(
                vec![TraceHop {
                    zone: "com.".into(),
                    server: "192.0.2.1".into(),
                    server_name: None,
                    qname: "example.com.".into(),
                    qtype: "A".into(),
                    transport: "udp".into(),
                    rtt_ms: 0,
                    rcode: "SERVFAIL".into(),
                    nsid: None,
                    ede_code: None,
                    ede_text: None,
                    referral_ns: vec![],
                    glue: vec![],
                    response: Default::default(),
                    from_cache: false,
                    outcome: HopOutcome::Failed {
                        kind: "timeout".into(),
                        detail: "no response".into(),
                    },
                }],
                TraceTreeRequest {
                    qname: "example.com.".into(),
                    qtype: "A".into(),
                    started_at: "2026-08-25T12:00:00Z".into(),
                },
            ),
        );
        let tree = explore_tree_for_document(&document).expect("tree");
        let outline = render_outline(&tree, ui_symbols());
        assert!(outline.contains("failure: timeout: no response"));
    }

    #[test]
    fn explore_tree_for_document_errors_without_tree() {
        let document = SessionDocument {
            version: 2,
            id: "01EMPTY".into(),
            created_at: "2026-08-25T12:00:00Z".into(),
            updated_at: "2026-08-25T12:00:00Z".into(),
            pinned: false,
            trees: vec![],
            view_state: None,
        };
        assert!(matches!(
            explore_tree_for_document(&document),
            Err(ExploreError::NoTraceTree)
        ));
    }

    fn fork_document() -> SessionDocument {
        use dns_core::name::DomainName;
        use dns_core::response::DnsRecord;
        use dns_resolve::{NodeOrigin, StoredDnsMessage, TraceNode, TraceTree};

        fn hop(
            zone: &str,
            server: &str,
            rtt_ms: u64,
            outcome: HopOutcome,
            referral_ns: &[&str],
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
                rcode: "NOERROR".into(),
                nsid: None,
                ede_code: None,
                ede_text: None,
                referral_ns: referral_ns.iter().map(|name| (*name).to_string()).collect(),
                glue: vec![],
                response: StoredDnsMessage {
                    answers,
                    ..Default::default()
                },
                from_cache: false,
                outcome,
            }
        }
        fn a_record() -> DnsRecord {
            DnsRecord {
                name: DomainName::parse("example.com.").expect("name"),
                rtype: "A".into(),
                rclass: "IN".into(),
                ttl: 300,
                rdata: "93.184.216.34".into(),
            }
        }
        fn node(hop: TraceHop, children: Vec<TraceNode>) -> TraceNode {
            TraceNode {
                hop,
                origin: NodeOrigin::Trace,
                children,
            }
        }
        SessionDocument::new(
            "01COMPARE".into(),
            TraceRequest::from_options(&crate::dig_options::TraceOptions {
                qname: "example.com".into(),
                ..Default::default()
            }),
            TraceTree {
                request: TraceTreeRequest {
                    qname: "example.com.".into(),
                    qtype: "A".into(),
                    started_at: "2026-08-25T12:00:00Z".into(),
                },
                root: node(
                    hop(".", "198.41.0.4", 10, HopOutcome::Referral, &[], vec![]),
                    vec![
                        node(
                            hop(
                                "com.",
                                "192.5.6.30",
                                20,
                                HopOutcome::Referral,
                                &["a.gtld-servers.net.", "b.gtld-servers.net."],
                                vec![],
                            ),
                            vec![node(
                                hop(
                                    "example.com.",
                                    "93.184.216.34",
                                    5,
                                    HopOutcome::Answered,
                                    &[],
                                    vec![a_record()],
                                ),
                                vec![],
                            )],
                        ),
                        node(
                            hop(
                                "com.",
                                "192.12.94.30",
                                40,
                                HopOutcome::Referral,
                                &["a.gtld-servers.net.", "c.gtld-servers.net."],
                                vec![],
                            ),
                            vec![node(
                                hop(
                                    "example.com.",
                                    "93.184.216.34",
                                    15,
                                    HopOutcome::Answered,
                                    &[],
                                    vec![a_record()],
                                ),
                                vec![],
                            )],
                        ),
                    ],
                ),
                budget_truncated: false,
            },
        )
    }

    struct SilentProber;

    impl dns_resolve::IcmpProber for SilentProber {
        fn probe(
            &self,
            _addr: std::net::IpAddr,
            _timeout: std::time::Duration,
        ) -> dns_resolve::IcmpProbeResult {
            dns_resolve::IcmpProbeResult::Unavailable
        }
    }

    #[test]
    fn outline_comparison_prints_rows_without_dns_exchange() {
        let document = fork_document();
        let text =
            render_outline_comparison(&document, Some(0), None, &SilentProber).expect("compare");
        assert!(text.contains("server"));
        assert!(text.contains("192.5.6.30"));
        assert!(text.contains("192.12.94.30"));
        assert!(text.contains("hops"));
        assert!(text.contains("25ms"));
        assert!(text.contains("55ms"));
        assert!(text.contains("n/a"));
        assert!(text.contains("+b.gtld-servers.net."));
        assert!(text.contains("+c.gtld-servers.net."));
    }

    #[test]
    fn events_comparison_json_matches_projection() {
        let document = fork_document();
        let json = render_events_comparison(&document, Some(0), None, &SilentProber).expect("json");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(value["event"], "path_comparison");
        assert_eq!(value["session"], "01COMPARE");
        let paths = value["paths"].as_array().expect("paths");
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0]["hop_count"], 2);
        assert_eq!(paths[0]["dns_rtt_total_ms"], 25);
        assert_eq!(paths[1]["dns_rtt_total_ms"], 55);
        assert_eq!(paths[0]["outcome"], "NOERROR");
    }

    #[test]
    fn comparison_reports_nothing_to_compare_on_text_and_json() {
        let document = SessionDocument::new(
            "01LINEAR".into(),
            TraceRequest::from_options(&crate::dig_options::TraceOptions {
                qname: "example.com".into(),
                ..Default::default()
            }),
            build_linear_tree(
                vec![TraceHop {
                    zone: ".".into(),
                    server: "198.41.0.4".into(),
                    server_name: None,
                    qname: "example.com.".into(),
                    qtype: "A".into(),
                    transport: "udp".into(),
                    rtt_ms: 11,
                    rcode: "NOERROR".into(),
                    nsid: None,
                    ede_code: None,
                    ede_text: None,
                    referral_ns: vec![],
                    glue: vec![],
                    response: Default::default(),
                    from_cache: false,
                    outcome: HopOutcome::Answered,
                }],
                TraceTreeRequest {
                    qname: "example.com.".into(),
                    qtype: "A".into(),
                    started_at: "2026-08-25T12:00:00Z".into(),
                },
            ),
        );
        let text = render_outline_comparison(&document, Some(0), None, &SilentProber);
        let json = render_events_comparison(&document, Some(0), None, &SilentProber);
        assert!(matches!(text, Err(ExploreError::NothingToCompare { .. })));
        assert!(matches!(json, Err(ExploreError::NothingToCompare { .. })));
        assert!(!format!("{}", text.unwrap_err()).contains("server"));
    }

    #[test]
    fn compare_screen_text_and_json_agree() {
        use super::compare_screen::{CompareScreenModel, summary_row_line};
        use super::path_summary::summarize_fork;
        use super::theme::Theme;
        use dns_resolve::NodePath;

        let document = fork_document();
        let tree = explore_tree_for_document(&document).expect("tree");
        let projection = summarize_fork(tree.trace(), &NodePath::root(0)).expect("projection");
        let text =
            render_outline_comparison(&document, Some(0), None, &SilentProber).expect("text");
        let json = render_events_comparison(&document, Some(0), None, &SilentProber).expect("json");
        let value: serde_json::Value = serde_json::from_str(&json).expect("parse");
        let model = CompareScreenModel::from_tree(&tree, &NodePath::root(0)).expect("screen");
        let theme = Theme::from_env();

        assert_eq!(projection.paths.len(), 2);
        assert_eq!(model.rows().len(), 2);
        assert_eq!(value["paths"].as_array().expect("paths").len(), 2);
        for (index, path) in projection.paths.iter().enumerate() {
            assert_eq!(path.hop_count, model.rows()[index].hop_count);
            assert_eq!(
                path.dns_rtt_total_ms,
                value["paths"][index]["dns_rtt_total_ms"]
                    .as_u64()
                    .expect("rtt")
            );
            assert_eq!(path.outcome, model.rows()[index].outcome);
            assert!(text.contains(&path.label));
            assert!(text.contains(&format!("{}ms", path.dns_rtt_total_ms)));
            let row = summary_row_line(path, false, &theme);
            let row_text: String = row.spans.iter().map(|span| span.content.as_ref()).collect();
            assert!(row_text.contains(&path.hop_count.to_string()));
            assert!(row_text.contains(&path.outcome));
            let referral = &path.referral_diff.only_here;
            if let Some(name) = referral.first() {
                assert!(text.contains(&format!("+{name}")));
                assert!(row_text.contains(&format!("+{name}")));
            }
        }
    }
}
