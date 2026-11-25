use crate::capture::{iter_packets_multi, open_packet_source, parse_l3};
use crate::filter::NoopResolver;
use crate::flow::FlowStage;
use crate::flow::packet_fingerprint;
use crate::flow::{FlowKey, hash_to_bucket};
use crate::options::FluxOptions;
use crate::parse::ParseWorker;
use crate::scale::OverlapTracker;
use crate::scale::flow_pool::FlowThreadPool;
use crate::scale::memory::{MemoryBudget, MemoryCounters};
use crate::scale::overload::{OverloadPolicy, OverloadState, scale_estimate_count};
use crate::scale::workers::ParseWorkerPool;
use crate::view::{TableDisplay, format_batch_tables};
use crate::window::Aggregator;

use super::PipelineError;
use super::ingest::{drain_flow_timeouts, new_flow_stage, worker_busy_percent};
use super::replay::ReplayOutcome;
use super::stats::{StatusBar, StatusLine, WatchInput};

pub fn replay_file_scaled(
    path: &str,
    options: &FluxOptions,
) -> Result<ReplayOutcome, PipelineError> {
    let replay_started = std::time::Instant::now();
    let filter = options.compile_filter(&NoopResolver)?;
    let eval_ctx = options.build_eval_context(&NoopResolver);
    let mut source = open_packet_source(Some(path))?;
    let mut agg = Aggregator::new(
        options.window.clone(),
        options.late_grace,
        options.late_policy,
        filter.clone(),
        eval_ctx,
    );

    let hash_seed: u64 = rand::random();
    let mut overload = OverloadState::new(options.overload_policy);
    overload.sample_every = 4;
    let mem_budget = MemoryBudget::from_limit(options.memory_limit_bytes());
    let mut mem = MemoryCounters::default();

    let worker_pool = ParseWorkerPool::new(options.workers.max(1), options.queue_policy);
    let mut workers = worker_pool;
    let mut single_worker = ParseWorker::default();
    let mut single_flow = new_flow_stage(options);
    let mut flow_pool = FlowThreadPool::new(options, hash_seed);
    let use_pool = options.uses_split_pipeline(1);

    let mut resize_at: Option<usize> = None;
    if options.workers >= 2 {
        resize_at = Some(6_000);
    }

    let mut overlap = OverlapTracker::default();
    let mut packet_index = 0usize;
    for pkt in iter_packets_multi(&mut source, "replay") {
        let pkt = pkt?;
        if let Ok(l3) = parse_l3(&pkt, options.family, &options.dns_ports) {
            let fp = packet_fingerprint(&pkt, &l3);
            overlap.observe(fp, &pkt.iface);
        }
        packet_index += 1;
        if let Some(idx) = resize_at
            && idx == packet_index
        {
            workers.resize(workers.len().saturating_add(1));
        }

        if use_pool {
            let routed = flow_pool.process_packet(&pkt, options.family, &options.dns_ports);
            for (_thread, ready) in routed {
                if !options.within_time_bounds(ready.timestamp_secs as f64) {
                    continue;
                }
                if should_skip_overload(
                    &mut overload,
                    &mem_budget,
                    &mut mem,
                    hash_seed,
                    &ready,
                    options,
                ) {
                    continue;
                }
                let parsed = flow_pool.stages[0].pair_message(&ready, &options.dns_ports);
                let flow_hash = hash_to_bucket(
                    hash_seed,
                    &FlowKey::from_endpoints(
                        17,
                        &ready.decoded.src_ip[..ready.decoded.src_ip_len as usize],
                        ready.decoded.src_port,
                        &ready.decoded.dst_ip[..ready.decoded.dst_ip_len as usize],
                        ready.decoded.dst_port,
                    ),
                    flow_pool.bucket_map.buckets,
                );
                if !workers.push_record(parsed.record.clone(), u64::from(flow_hash)) {
                    agg.counters.capture_drops += 1;
                }
                agg.ingest(parsed);
            }
        } else {
            ingest_single(
                &mut agg,
                &mut single_worker,
                &mut single_flow,
                &pkt,
                options,
                &mut overload,
                &mem_budget,
                &mut mem,
                hash_seed,
            );
        }

        account_memory(&mut mem, &workers, &agg);
        apply_shrink_overload(&mut agg, &mut overload, options, &mem, &mem_budget);
    }

    let max_sec = agg.slices.keys().map(|s| s.0).max().unwrap_or(0);
    let pair_deadline = max_sec.saturating_add(options.pair_timeout.as_secs().saturating_add(1));
    agg.tick(max_sec + 1);

    if use_pool {
        let synthetics = flow_pool.stages[0].drain_pairing_timeouts(pair_deadline);
        for parsed in synthetics {
            workers.push_record(parsed.record.clone(), 0);
            agg.ingest(parsed);
        }
    } else {
        drain_flow_timeouts(
            &mut agg,
            &mut single_worker,
            &mut single_flow,
            pair_deadline,
        );
    }
    agg.catch_up_stall(pair_deadline + 1);

    let snap = agg.snapshot();
    let estimated_total = if overload.estimate_marker {
        scale_estimate_count(snap.total_messages, overload.sample_every)
    } else {
        snap.total_messages
    };
    let display = TableDisplay {
        rate_mode: options.rate_mode,
        view_sort: options.view_sort,
        window: options.window.clone(),
        effective_window_secs: overload
            .effective_window_secs
            .or(snap.effective_window_secs),
        counted_span_secs: snap.counted_span_secs,
        tick_prev: None,
        tick_interval_secs: 1.0,
        replay_wall_secs: Some(replay_started.elapsed().as_secs_f64().max(0.001)),
    };
    let mut body = format_batch_tables(
        &snap.counts,
        &options.batch_views,
        options.batch_limit,
        estimated_total,
        options.key_cap,
        options.ede_show_no_ede,
        None,
        &display,
    );
    if overload.estimate_marker {
        body = format!("~ estimates at 1/{}\n{body}", overload.sample_every);
    }

    let parse_busy = if use_pool {
        workers.avg_busy_percent()
    } else {
        worker_busy_percent(&single_worker)
    };
    let queue_depth = if use_pool {
        workers.queue_drops
    } else {
        single_worker.stats.queue_depth
    };

    let status = StatusBar {
        input: WatchInput::Replay { path: path.into() },
        window: options.window.clone(),
        effective_window_secs: overload
            .effective_window_secs
            .or(snap.effective_window_secs),
        filter: filter.header.clone(),
        match_stats: snap.match_stats,
        counted_in_window: estimated_total,
        counters: StatusLine {
            packets: agg.counters.packets,
            drops: agg
                .counters
                .capture_drops
                .saturating_add(workers.queue_drops),
            parse_busy_pct: parse_busy,
            queue_depth,
            listener_frames: agg.counters.listener_packets,
            recv_frames_last_tick: None,
        },
        flow: if use_pool {
            flow_pool.merged_counters()
        } else {
            single_flow.counters
        },
        pairing_enabled: options.pairing,
        elapsed_secs: None,
        overload: Some(overload),
        listener_stats: overlap.format_listener_lines(),
        hints: Vec::new(),
    };
    if let Some(hint) = overlap.high_overlap_hint(50.0) {
        eprintln!("{hint}");
    }
    Ok(ReplayOutcome { body, status })
}

#[allow(clippy::too_many_arguments)]
fn ingest_single(
    agg: &mut Aggregator,
    worker: &mut ParseWorker,
    flow: &mut FlowStage,
    pkt: &crate::capture::RawPacket,
    options: &FluxOptions,
    overload: &mut OverloadState,
    mem_budget: &MemoryBudget,
    mem: &mut MemoryCounters,
    hash_seed: u64,
) {
    use super::ingest::ingest_packet;
    if overload.policy == OverloadPolicy::Drop && mem_budget.is_over(mem.total()) {
        overload.refuse_record();
        return;
    }
    if overload.policy == OverloadPolicy::Sample {
        let key = FlowKey::from_endpoints(17, &[0], 0, &[0], 0);
        let _ = key;
        if !overload.should_admit_sample(hash_seed.wrapping_add(pkt.timestamp_secs)) {
            return;
        }
    }
    ingest_packet(agg, worker, flow, pkt, options);
}

#[allow(clippy::too_many_arguments)]
fn should_skip_overload(
    overload: &mut OverloadState,
    mem_budget: &MemoryBudget,
    mem: &mut MemoryCounters,
    hash_seed: u64,
    ready: &crate::flow::DnsMessageReady,
    _options: &FluxOptions,
) -> bool {
    if overload.policy == OverloadPolicy::Drop && mem_budget.is_over(mem.total()) {
        overload.refuse_record();
        return true;
    }
    if overload.policy == OverloadPolicy::Sample {
        let key = FlowKey::from_endpoints(
            17,
            &ready.decoded.src_ip[..ready.decoded.src_ip_len as usize],
            ready.decoded.src_port,
            &ready.decoded.dst_ip[..ready.decoded.dst_ip_len as usize],
            ready.decoded.dst_port,
        );
        let bucket = hash_to_bucket(hash_seed, &key, 65536);
        if !overload.should_admit_sample(u64::from(bucket)) {
            return true;
        }
    }
    false
}

fn account_memory(mem: &mut MemoryCounters, workers: &ParseWorkerPool, agg: &Aggregator) {
    workers.account_memory(mem);
    mem.record_bytes = agg
        .all_records()
        .len()
        .saturating_mul(std::mem::size_of::<crate::parse::ObservationRecord>());
}

fn apply_shrink_overload(
    agg: &mut Aggregator,
    overload: &mut OverloadState,
    options: &FluxOptions,
    mem: &MemoryCounters,
    budget: &MemoryBudget,
) {
    if !budget.is_over(mem.total()) {
        return;
    }
    if overload.policy == OverloadPolicy::Compact {
        overload.mark_active();
        overload.compact_blocks_refilter = true;
        overload.compacted_slices = overload.compacted_slices.saturating_add(1);
        let ids: Vec<_> = agg.slices.keys().copied().collect();
        if let Some(oldest) = ids.into_iter().min_by_key(|id| id.0) {
            if let Some(slice) = agg.slices.get_mut(&oldest) {
                slice.records.clear();
                slice.arena.clear();
            }
        }
        return;
    }
    if overload.policy != OverloadPolicy::Shrink {
        return;
    }
    let configured = match options.window {
        crate::options::WindowMode::Seconds(s) => s,
        crate::options::WindowMode::All => return,
    };
    let eff = (configured / 2).max(1);
    overload.shrink_window(configured, eff);
    agg.catch_up_stall(agg.now_sec);
}
