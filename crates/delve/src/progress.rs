use dns_resolve::{TraceHop, TraceProgress};

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

        let mut line = format!(
            "[{}] {} {} {} via {} in {}ms ({})",
            hop.zone, hop.qname, hop.qtype, hop.server, hop.transport, hop.rtt_ms, hop.rcode
        );

        if let Some(nsid) = &hop.nsid {
            line.push_str(&format!(" NSID={nsid}"));
        }
        if let Some(code) = hop.ede_code {
            line.push_str(&format!(" EDE={code}"));
            if let Some(text) = &hop.ede_text {
                line.push_str(&format!(":{text}"));
            }
        }

        eprintln!("{line}");

        if !hop.referral_ns.is_empty() {
            eprintln!("  referral NS: {}", hop.referral_ns.join(", "));
        }
        if !hop.glue.is_empty() {
            eprintln!("  glue: {}", hop.glue.join(", "));
        }
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
