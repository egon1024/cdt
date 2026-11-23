use crate::capture::{iter_packets, open_packet_source};
use crate::filter::{NoopResolver, filter_header_line};
use crate::flow::FlowBuckets;
use crate::options::FluxOptions;
use crate::parse::ParseWorker;
use crate::view::format_batch_tables;
use crate::window::Aggregator;

use super::PipelineError;
use super::ingest::{ingest_packet, worker_busy_percent};
use super::stats::StatusLine;

pub fn replay_file(path: &str, options: &FluxOptions) -> Result<String, PipelineError> {
    let filter = options.compile_filter(&NoopResolver)?;
    let eval_ctx = options.build_eval_context(&NoopResolver);
    let mut source = open_packet_source(Some(path))?;
    let mut worker = ParseWorker::default();
    let mut agg = Aggregator::new(
        options.window.clone(),
        options.late_grace,
        options.late_policy,
        filter.clone(),
        eval_ctx,
    );
    let (buckets, _) = options.effective_flow_buckets();
    let _fb = FlowBuckets::new(buckets);
    let seed: u64 = 0;

    for pkt in iter_packets(&mut source, "replay") {
        let pkt = pkt?;
        ingest_packet(&mut agg, &mut worker, &pkt, options, buckets, seed);
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
    let header = filter_header_line(&filter.header, &snap.match_stats);
    let body = format_batch_tables(
        &snap.counts,
        &options.batch_views,
        options.batch_limit,
        snap.total_messages,
        options.key_cap,
        options.ede_show_no_ede,
    );
    let status = StatusLine {
        packets: agg.counters.packets,
        drops: agg.counters.capture_drops,
        parse_busy_pct: worker_busy_percent(&worker),
        queue_depth: worker.stats.queue_depth,
    };
    Ok(format!("{header}{body}{}", status.format()))
}
