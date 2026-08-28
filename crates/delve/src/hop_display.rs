use dns_resolve::TraceHop;

use crate::explore::{cache_source_symbol, ui_symbols};

/// Human-readable hop line(s) matching live trace stderr output.
pub fn print_hop_human(hop: &TraceHop, depth: usize) {
    let indent = "  ".repeat(depth);
    let mut line = format!(
        "{indent}[{}] {} {} {} via {} in {}ms ({}) {}",
        hop.zone,
        hop.qname,
        hop.qtype,
        hop.server,
        hop.transport,
        hop.rtt_ms,
        hop.rcode,
        cache_source_symbol(hop.from_cache, ui_symbols())
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
        eprintln!("{indent}  referral NS: {}", hop.referral_ns.join(", "));
    }
    if !hop.glue.is_empty() {
        eprintln!("{indent}  glue: {}", hop.glue.join(", "));
    }
}
