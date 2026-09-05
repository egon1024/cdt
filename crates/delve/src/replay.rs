use dns_resolve::{TraceProgress, TraceTree};

use crate::progress::StderrProgress;
use crate::session::SessionDocument;

pub fn replay_session(document: &SessionDocument, events: bool) {
    let tree = document
        .primary_tree()
        .expect("v2 session must contain a trace tree");
    let mut progress = StderrProgress::new(events, false);
    for path in tree.display_order() {
        if let Some(node) = tree.resolve(&path) {
            progress.hop(&node.hop, &path);
        }
    }

    if events {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "event": "complete",
                "reused": true,
                "session": document.id,
                "traced_at": document.created_at,
                "result": tree,
            }))
            .expect("json")
        );
        return;
    }

    eprintln!();
    print_final_answer(tree);
}

pub fn print_final_answer(result: &TraceTree) {
    if let Some(hop) = result.answering_hop() {
        eprintln!(
            "final answer from {} in {}ms ({})",
            hop.server, hop.rtt_ms, hop.rcode
        );
        for record in &hop.response.answers {
            eprintln!("  {} {} {}", record.name, record.ttl, record.rdata);
        }
        if let Some(nsid) = &hop.nsid {
            eprintln!("  NSID: {nsid}");
        }
    }
}

pub fn print_reused_session_notice(document: &SessionDocument) {
    eprintln!(
        "session: {} (reused snapshot from {})",
        document.id, document.created_at
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionDocument;
    use crate::trace_request::TraceRequest;
    use dns_resolve::{HopOutcome, TraceHop, TraceTreeRequest, build_linear_tree};

    fn sample_document() -> SessionDocument {
        SessionDocument::new(
            "01TEST".into(),
            TraceRequest::from_options(&crate::dig_options::TraceOptions {
                qname: "example.com".into(),
                ..Default::default()
            }),
            build_linear_tree(
                vec![TraceHop {
                    zone: ".".into(),
                    server: "1.1.1.1".into(),
                    server_name: None,
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
                    outcome: HopOutcome::Answered,
                }],
                TraceTreeRequest {
                    qname: "example.com.".into(),
                    qtype: "A".into(),
                    started_at: "2026-08-25T00:00:00Z".into(),
                },
            ),
        )
    }

    #[test]
    fn replay_emits_tree_paths() {
        let document = sample_document();
        let tree = document.primary_tree().expect("tree");
        assert_eq!(tree.display_order().len(), 1);
        replay_session(&document, false);
    }
}
