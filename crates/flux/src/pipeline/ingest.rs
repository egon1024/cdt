use crate::capture::RawPacket;
use crate::flow::{FlowConfig, FlowStage, parse_flow_message};
use crate::options::FluxOptions;
use crate::parse::ParseWorker;
use crate::window::Aggregator;

pub fn ingest_packet(
    agg: &mut Aggregator,
    worker: &mut ParseWorker,
    flow: &mut FlowStage,
    pkt: &RawPacket,
    options: &FluxOptions,
) {
    agg.counters.listener_packets += 1;
    let messages = flow.process_packet(pkt, options.family);
    for ready in messages {
        if !options.within_time_bounds(ready.timestamp_secs as f64) {
            continue;
        }
        let mut parsed = parse_flow_message(&ready, &options.dns_ports);
        let ts_ns = u128::from(ready.timestamp_secs) * 1_000_000_000
            + u128::from(ready.timestamp_subsec_ns);
        flow.pairing
            .on_message(&mut parsed.record, ts_ns, ready.timestamp_secs);
        flow.sync_pairing_counters();
        worker.push_record(parsed.record.clone());
        agg.ingest(parsed);
    }
    worker.stats.busy_ns = worker.stats.busy_ns.saturating_add(1);
    worker.stats.idle_ns = 1;
}

pub fn drain_flow_timeouts(
    agg: &mut Aggregator,
    worker: &mut ParseWorker,
    flow: &mut FlowStage,
    now_sec: u64,
) {
    let synthetics = flow.drain_pairing_timeouts(now_sec);
    for parsed in synthetics {
        worker.push_record(parsed.record.clone());
        agg.ingest(parsed);
    }
}

pub fn new_flow_stage(options: &FluxOptions) -> FlowStage {
    FlowStage::new(FlowConfig::from_options(options))
}

pub fn worker_busy_percent(worker: &ParseWorker) -> u8 {
    let total = worker
        .stats
        .busy_ns
        .saturating_add(worker.stats.idle_ns)
        .max(1);
    ((worker.stats.busy_ns.saturating_mul(100)) / total).min(100) as u8
}
