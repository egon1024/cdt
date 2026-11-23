use crate::capture::{FrameError, RawPacket, decode_frame};
use crate::flow::{FlowKey, hash_to_bucket};
use crate::options::FluxOptions;
use crate::parse::{ParseWorker, parse_dns_payload};
use crate::window::Aggregator;

pub fn ingest_packet(
    agg: &mut Aggregator,
    worker: &mut ParseWorker,
    pkt: &RawPacket,
    options: &FluxOptions,
    buckets: u32,
    seed: u64,
) {
    agg.counters.listener_packets += 1;
    let decoded = match decode_frame(pkt, options.family) {
        Ok(d) => d,
        Err(FrameError::NotDns) | Err(FrameError::FamilyFiltered) => return,
        Err(FrameError::Parse(_)) => return,
    };
    let src = &decoded.src_ip[..decoded.src_ip_len as usize];
    let dst = &decoded.dst_ip[..decoded.dst_ip_len as usize];
    let _key = FlowKey::from_endpoints(17, src, decoded.src_port, dst, decoded.dst_port);
    let _bucket = hash_to_bucket(seed, &_key, buckets);
    if !options.within_time_bounds(pkt.timestamp_secs as f64) {
        return;
    }
    let parsed = parse_dns_payload(&decoded, pkt.slice_second(), &pkt.iface);
    worker.push_record(parsed.record.clone());
    agg.ingest(parsed);
    worker.stats.busy_ns = worker.stats.busy_ns.saturating_add(1);
    worker.stats.idle_ns = 1;
}

pub fn worker_busy_percent(worker: &ParseWorker) -> u8 {
    let total = worker
        .stats
        .busy_ns
        .saturating_add(worker.stats.idle_ns)
        .max(1);
    ((worker.stats.busy_ns.saturating_mul(100)) / total).min(100) as u8
}
