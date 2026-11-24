//! Shared live-replay packet path for scaled capture (flow threads + parse workers).

use crate::capture::RawPacket;
use crate::flow::{FlowKey, FlowStage, hash_to_bucket, parse_flow_message};
use crate::options::FluxOptions;
use crate::parse::ParseWorker;
use crate::scale::flow_pool::FlowThreadPool;
use crate::scale::workers::ParseWorkerPool;
use crate::window::Aggregator;

use super::ingest::{ingest_packet, new_flow_stage};

pub struct LivePipeline {
    pub use_pool: bool,
    pub flow: FlowStage,
    pub flow_pool: FlowThreadPool,
    pub workers: ParseWorkerPool,
    pub worker: ParseWorker,
    pub hash_seed: u64,
}

impl LivePipeline {
    pub fn new(options: &FluxOptions) -> Self {
        let hash_seed = rand::random();
        let use_pool = options.uses_split_pipeline(1);
        Self {
            use_pool,
            flow: new_flow_stage(options),
            flow_pool: FlowThreadPool::new(options, hash_seed),
            workers: ParseWorkerPool::new(options.workers.max(1), options.queue_policy),
            worker: ParseWorker::default(),
            hash_seed,
        }
    }

    pub fn flow_threads(&self) -> u32 {
        if self.use_pool {
            self.flow_pool.flow_threads
        } else {
            1
        }
    }

    pub fn worker_count(&self) -> usize {
        if self.use_pool { self.workers.len() } else { 1 }
    }

    pub fn resize_workers(&mut self, new_len: usize) {
        if self.use_pool {
            self.workers.resize(new_len);
        }
    }

    pub fn process_packet(&mut self, agg: &mut Aggregator, pkt: &RawPacket, options: &FluxOptions) {
        if self.use_pool {
            self.process_packet_pooled(agg, pkt, options);
        } else {
            ingest_packet(agg, &mut self.worker, &mut self.flow, pkt, options);
        }
    }

    fn process_packet_pooled(
        &mut self,
        agg: &mut Aggregator,
        pkt: &RawPacket,
        options: &FluxOptions,
    ) {
        agg.counters.listener_packets += 1;
        let routed = self
            .flow_pool
            .process_packet(pkt, options.family, &options.dns_ports);
        for (thread, ready) in routed {
            if !options.within_time_bounds(ready.timestamp_secs as f64) {
                continue;
            }
            let stage = &mut self.flow_pool.stages[thread as usize];
            let mut parsed = parse_flow_message(&ready, &options.dns_ports);
            let ts_ns = u128::from(ready.timestamp_secs) * 1_000_000_000
                + u128::from(ready.timestamp_subsec_ns);
            stage
                .pairing
                .on_message(&mut parsed.record, ts_ns, ready.timestamp_secs);
            stage.sync_pairing_counters();
            let flow_hash = hash_to_bucket(
                self.hash_seed,
                &FlowKey::from_endpoints(
                    if ready.transport == crate::parse::TransportProto::Udp {
                        17
                    } else {
                        6
                    },
                    &ready.decoded.src_ip[..ready.decoded.src_ip_len as usize],
                    ready.decoded.src_port,
                    &ready.decoded.dst_ip[..ready.decoded.dst_ip_len as usize],
                    ready.decoded.dst_port,
                ),
                self.flow_pool.bucket_map.buckets,
            );
            if !self
                .workers
                .push_record(parsed.record.clone(), u64::from(flow_hash))
            {
                agg.counters.capture_drops += 1;
            }
            agg.ingest(parsed);
        }
    }

    pub fn drain_flow_timeouts(&mut self, agg: &mut Aggregator, now_sec: u64) {
        if self.use_pool {
            for parsed in self.flow_pool.drain_pairing_timeouts(now_sec) {
                if !self.workers.push_record(parsed.record.clone(), 0) {
                    agg.counters.capture_drops += 1;
                }
                agg.ingest(parsed);
            }
        } else {
            super::ingest::drain_flow_timeouts(agg, &mut self.worker, &mut self.flow, now_sec);
        }
    }

    pub fn flow_counters(&self) -> crate::flow::FlowCounters {
        if self.use_pool {
            self.flow_pool.merged_counters()
        } else {
            self.flow.counters
        }
    }

    pub fn parse_busy_percent(&self) -> u8 {
        if self.use_pool {
            self.workers.avg_busy_percent()
        } else {
            super::ingest::worker_busy_percent(&self.worker)
        }
    }

    pub fn queue_depth(&self) -> u64 {
        if self.use_pool {
            self.workers
                .workers
                .iter()
                .map(|w| w.stats.queue_depth)
                .sum()
        } else {
            self.worker.stats.queue_depth
        }
    }

    pub fn parse_measurements(&self) -> Vec<crate::scale::hints::ParseThreadMeasurements> {
        if self.use_pool {
            self.workers
                .workers
                .iter()
                .map(|w| crate::scale::hints::ParseThreadMeasurements {
                    busy_pct: super::ingest::worker_busy_percent(w),
                    queue_depth: w.stats.queue_depth,
                })
                .collect()
        } else {
            vec![crate::scale::hints::ParseThreadMeasurements {
                busy_pct: self.parse_busy_percent(),
                queue_depth: self.queue_depth(),
            }]
        }
    }
}
