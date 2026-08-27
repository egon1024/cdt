use dns_resolve::{TraceProgress, TraceResult};

use crate::progress::StderrProgress;
use crate::session::SessionDocument;

pub fn replay_session(document: &SessionDocument, events: bool) {
    let mut progress = StderrProgress::new(events);
    for hop in &document.result.hops {
        progress.hop(hop);
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

pub fn print_final_answer(result: &TraceResult) {
    if let Some(answer) = &result.final_response {
        eprintln!(
            "final answer from {} in {}ms ({})",
            answer.server, answer.rtt_ms, answer.rcode
        );
        for record in &answer.records {
            eprintln!("  {record}");
        }
        if let Some(nsid) = &answer.nsid {
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
