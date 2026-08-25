use dns_resolve::{TraceHop, TraceProgress};

use crate::hop_display::print_hop_human;

pub struct StderrProgress {
    events: bool,
}

impl StderrProgress {
    pub fn new(events: bool) -> Self {
        Self { events }
    }
}

impl TraceProgress for StderrProgress {
    fn hop(&mut self, hop: &TraceHop) {
        if self.events {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "event": "hop",
                    "hop": hop,
                }))
                .expect("json")
            );
            return;
        }

        print_hop_human(hop);
    }

    fn message(&mut self, message: &str) {
        if self.events {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "event": "message",
                    "message": message,
                }))
                .expect("json")
            );
        } else {
            eprintln!("  -> {message}");
        }
    }
}
