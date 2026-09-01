mod compare;
mod detail;
mod dig_view;
mod flags;
mod json;
mod outline;
mod pane_split;
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

use crate::runtime::Runtime;
use crate::session::SessionDocument;
use std::io::{self, IsTerminal, Write};

fn explore_tree_for_document(document: &SessionDocument) -> tree::ExploreTree {
    let trace = document
        .primary_tree()
        .expect("v2 session must contain a trace tree");
    if let Some(request) = document.primary_request() {
        build_explore_tree_with_qname(trace, 0, Some(&request.qname))
    } else {
        build_explore_tree(trace)
    }
}

pub fn run_outline(document: &SessionDocument) -> Result<(), ExploreError> {
    let tree = explore_tree_for_document(document);
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
    let tree = explore_tree_for_document(document);
    println!("{}", render_tree_json(&tree, &document.id));
    Ok(())
}

pub fn run_explore(runtime: &Runtime, document: &mut SessionDocument) -> Result<(), ExploreError> {
    if !io::stdout().is_terminal() {
        return Err(ExploreError::NotTerminal);
    }

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

    #[error("stdout is not a terminal; use `delve session outline` for a printable tree")]
    NotTerminal,
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

        let tree = explore_tree_for_document(&document);
        let outline = render_outline(&tree, ui_symbols());
        assert!(outline.contains("example.com. A"));
        assert!(outline.contains("query response time: 11ms"));

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
        let tree = explore_tree_for_document(&document);
        let outline = render_outline(&tree, ui_symbols());
        assert!(outline.contains("failure: timeout: no response"));
    }
}
