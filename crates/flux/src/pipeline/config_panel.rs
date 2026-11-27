//! Live TUI panel: effective `flux watch` configuration (not session counters).

use super::live_ingest::LivePipeline;
use crate::capture::ListenerSpec;
use crate::options::{AddressFamily, EventsMode, FluxOptions, WindowMode};

pub fn format_config_lines(
    options: &FluxOptions,
    listeners: &[ListenerSpec],
    attached_iface: &str,
    fanout_group: Option<u32>,
    effective_window_secs: Option<u64>,
    pipeline: &LivePipeline,
) -> Vec<String> {
    let mut out = vec!["== Capture ==".into()];
    if listeners.is_empty() {
        out.push("  no listener specs".into());
    } else {
        for spec in listeners {
            let threads = if spec.capture_threads > 1 {
                format!(" ({} capture threads)", spec.capture_threads)
            } else {
                String::new()
            };
            let attach = if spec.iface == attached_iface {
                "  ← attached"
            } else {
                ""
            };
            out.push(format!("  {}{}{attach}", spec.iface, threads));
        }
    }
    out.push(format!("  promisc {}", on_off(options.promisc)));
    if let Some(g) = fanout_group {
        out.push(format!("  PACKET_FANOUT group {g}"));
    }
    out.push(format!("  address family {}", family_label(options.family)));
    if !options.exclude_iface.is_empty() {
        out.push(format!(
            "  exclude-iface {}",
            options.exclude_iface.join(", ")
        ));
    }

    out.push(String::new());
    out.push("== Window & time ==".into());
    out.push(format!(
        "  window {}",
        window_label(&options.window, effective_window_secs)
    ));
    out.push(format!(
        "  late grace {} ms · policy {:?}",
        options.late_grace.as_millis(),
        options.late_policy
    ));
    if options.start_bound.is_some() || options.end_bound.is_some() {
        out.push(format!(
            "  bounds start={:?} end={:?}",
            options.start_bound, options.end_bound
        ));
    }

    out.push(String::new());
    out.push("== Scaling ==".into());
    let (buckets, bucket_note) = options.effective_flow_buckets();
    out.push(format!(
        "  flow threads {} (max {})",
        options.effective_flow_threads(),
        options.max_flow_threads
    ));
    out.push(format!(
        "  flow buckets {buckets}{}",
        bucket_note
            .map(|r| format!(" (requested {r}, rounded)"))
            .unwrap_or_default()
    ));
    out.push(format!(
        "  parse workers {} · queue {:?}",
        pipeline.worker_count(),
        options.queue_policy
    ));
    out.push(format!(
        "  mem limit {} bytes",
        options.memory_limit_bytes()
    ));
    out.push(format!("  overload policy {:?}", options.overload_policy));

    out.push(String::new());
    out.push("== DNS path ==".into());
    out.push(format!("  dns ports {:?}", options.dns_ports));
    out.push(format!(
        "  defrag {:?} (max dg {} frags {} timeout {}s)",
        options.defrag,
        options.defrag_max_datagrams,
        options.defrag_max_fragments,
        options.defrag_timeout.as_secs()
    ));
    out.push(format!(
        "  tcp {:?} (conns {} buf {} idle {}s)",
        options.tcp,
        options.tcp_max_connections,
        options.tcp_max_buffer,
        options.tcp_idle_timeout.as_secs()
    ));
    out.push(format!(
        "  pairing {} timeout {}s max {}",
        on_off(options.pairing),
        options.pair_timeout.as_secs(),
        options.pair_max
    ));
    out.push(format!(
        "  dedup {} window {} ms",
        on_off(options.dedup),
        options.dedup_window.as_millis()
    ));

    out.push(String::new());
    out.push("== Filters (CLI) ==".into());
    if let Some(qr) = &options.qr {
        out.push(format!("  qr {}", qr.as_str()));
    }
    push_token_list(&mut out, "initiator", &options.initiator);
    push_token_list(&mut out, "responder", &options.responder);
    push_token_list(&mut out, "src", &options.src);
    push_token_list(&mut out, "dst", &options.dst);
    if !options.filter_tokens.is_empty() {
        out.push(format!("  filters {}", options.filter_tokens.join(" ")));
    } else if options.preset.is_none() && options.saved_filter.is_none() {
        out.push("  filters none".into());
    }
    if let Some(p) = &options.preset {
        out.push(format!("  preset {p}"));
    }
    if let Some(p) = &options.saved_filter {
        out.push(format!("  saved-filter {p}"));
    }
    for path in &options.filter_files {
        out.push(format!("  filter-file {path}"));
    }

    out.push(String::new());
    out.push("== Display ==".into());
    out.push(format!("  tui refresh {} Hz", options.tui_hz));
    out.push(format!("  batch table limit {}", options.batch_limit));
    out.push(format!("  key cap {}", options.key_cap));
    out.push(format!("  default qname levels {}", options.qname_levels));
    out.push(format!("  events {:?}", events_label(&options.events)));

    out
}

fn on_off(v: bool) -> &'static str {
    if v { "on" } else { "off" }
}

fn family_label(f: AddressFamily) -> &'static str {
    match f {
        AddressFamily::Auto => "auto",
        AddressFamily::V4 => "ipv4",
        AddressFamily::V6 => "ipv6",
        AddressFamily::Both => "both",
    }
}

fn window_label(window: &WindowMode, effective_secs: Option<u64>) -> String {
    match window {
        WindowMode::All => "all".into(),
        WindowMode::Seconds(configured) => {
            if let Some(eff) = effective_secs {
                if eff != *configured {
                    return format!("{eff}s effective of {configured}s");
                }
            }
            format!("{configured}s")
        }
    }
}

fn events_label(mode: &EventsMode) -> String {
    match mode {
        EventsMode::Off => "off".into(),
        EventsMode::Stdout => "stdout".into(),
        EventsMode::File(p) => format!("file {p}"),
    }
}

fn push_token_list(out: &mut Vec<String>, name: &str, items: &[String]) {
    if !items.is_empty() {
        out.push(format!("  {name} {}", items.join(" ")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_attached_listener() {
        let options = FluxOptions::default();
        let listeners = vec![ListenerSpec {
            iface: "br0".into(),
            capture_threads: 2,
        }];
        let pipeline = LivePipeline::new(&options, Default::default(), &listeners);
        let lines = format_config_lines(&options, &listeners, "br0", Some(1), None, &pipeline);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("br0") && l.contains("attached"))
        );
        assert!(lines.iter().any(|l| l.contains("flow threads")));
    }
}
