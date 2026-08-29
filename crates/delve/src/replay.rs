use dns_resolve::{TraceProgress, TraceTree};

use crate::progress::StderrProgress;
use crate::session::SessionDocument;

pub fn replay_session(document: &SessionDocument, events: bool) {
    let mut progress = StderrProgress::new(events, false);
    for path in document.result.display_order() {
        if let Some(node) = document.result.resolve(&path) {
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
                "result": document.result,
            }))
            .expect("json")
        );
        return;
    }

    eprintln!();
    print_final_answer(&document.result);
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
