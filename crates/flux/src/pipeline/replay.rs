use crate::capture::{FrameError, decode_frame, iter_packets, open_packet_source};
use crate::flow::{FlowBuckets, FlowKey, hash_to_bucket};
use crate::options::FluxOptions;
use crate::parse::{ParseWorker, parse_dns_payload};
use crate::view::format_batch_tables;
use crate::window::Aggregator;

use super::PipelineError;
use super::stats::StatusLine;

pub fn replay_file(path: &str, options: &FluxOptions) -> Result<String, PipelineError> {
    let mut source = open_packet_source(Some(path))?;
    let mut worker = ParseWorker::default();
    let mut agg = Aggregator::new(
        options.window.clone(),
        options.late_grace,
        options.late_policy,
    );
    let (buckets, _) = options.effective_flow_buckets();
    let _fb = FlowBuckets::new(buckets);
    let seed: u64 = 0;
    let mut packets = 0u64;

    for pkt in iter_packets(&mut source, "replay") {
        let pkt = pkt?;
        packets += 1;
        agg.counters.listener_packets += 1;
        let decoded = match decode_frame(&pkt, options.family) {
            Ok(d) => d,
            Err(FrameError::NotDns) | Err(FrameError::FamilyFiltered) => continue,
            Err(FrameError::Parse(_)) => continue,
        };
        let src = &decoded.src_ip[..decoded.src_ip_len as usize];
        let dst = &decoded.dst_ip[..decoded.dst_ip_len as usize];
        let _key = FlowKey::from_endpoints(17, src, decoded.src_port, dst, decoded.dst_port);
        let _bucket = hash_to_bucket(seed, &_key, buckets);
        let rec = parse_dns_payload(&decoded, pkt.slice_second(), &pkt.iface);
        worker.push_record(rec.clone());
        agg.ingest(rec);
        worker.stats.busy_ns = packets;
        worker.stats.idle_ns = 1;
    }

    let max_sec = worker
        .records
        .iter()
        .map(|r| r.slice_sec)
        .max()
        .unwrap_or(0);
    agg.tick(max_sec + 1);
    agg.catch_up_stall(max_sec + 2);

    let snap = agg.snapshot();
    let body = format_batch_tables(
        &snap.counts,
        &options.batch_views,
        options.batch_limit,
        snap.total_messages.max(packets),
    );
    let status = StatusLine {
        packets: agg.counters.packets,
        drops: agg.counters.capture_drops,
        parse_busy_pct: worker.busy_percent(),
        queue_depth: worker.stats.queue_depth,
    };
    Ok(format!("{body}{}", status.format()))
}

trait BusyPercent {
    fn busy_percent(&self) -> u8;
}

impl BusyPercent for ParseWorker {
    fn busy_percent(&self) -> u8 {
        let total = self.stats.busy_ns.saturating_add(self.stats.idle_ns).max(1);
        ((self.stats.busy_ns.saturating_mul(100)) / total).min(100) as u8
    }
}
