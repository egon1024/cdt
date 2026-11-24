use crate::capture::{DnsL3Payload, RawPacket};
use crate::flow::{
    BucketMap, FlowBuckets, FlowConfig, FlowKey, FlowStage, FragmentKey, hash_to_bucket,
};
use crate::options::{AddressFamily, FluxOptions};
use crate::parse::ParsedObservation;

pub struct FlowThreadPool {
    pub stages: Vec<FlowStage>,
    pub bucket_map: BucketMap,
    pub hash_seed: u64,
    pub flow_threads: u32,
}

impl FlowThreadPool {
    pub fn new(options: &FluxOptions, hash_seed: u64) -> Self {
        let buckets = FlowBuckets::new(options.effective_flow_buckets().0);
        let flow_threads = options.effective_flow_threads();
        let bucket_map = BucketMap::for_runtime(&buckets, flow_threads);
        let config = FlowConfig::from_options(options);
        let stages: Vec<_> = (0..flow_threads)
            .map(|_| FlowStage::new(config.clone()))
            .collect();
        Self {
            stages,
            bucket_map,
            hash_seed,
            flow_threads,
        }
    }

    pub fn thread_for_packet(&self, pkt: &RawPacket, family: AddressFamily) -> u32 {
        use crate::capture::parse_l3;
        match parse_l3(pkt, family, &options_ports_default()) {
            Ok(l3) => self.thread_for_l3(&l3),
            Err(_) => 0,
        }
    }

    pub fn thread_for_l3(&self, l3: &DnsL3Payload) -> u32 {
        if let Some(fk) = l3.fragment_key {
            let bucket = hash_fragment_to_bucket(self.hash_seed, &fk, self.bucket_map.buckets);
            return self.bucket_map.bucket_for_thread(bucket);
        }
        let key = FlowKey::from_endpoints(
            l3.protocol,
            &l3.src_ip[..l3.src_ip_len as usize],
            l3.src_port,
            &l3.dst_ip[..l3.dst_ip_len as usize],
            l3.dst_port,
        );
        let bucket = hash_to_bucket(self.hash_seed, &key, self.bucket_map.buckets);
        self.bucket_map.bucket_for_thread(bucket)
    }

    pub fn process_packet(
        &mut self,
        pkt: &RawPacket,
        family: AddressFamily,
        ports: &crate::capture::PortSet,
    ) -> Vec<(u32, crate::flow::DnsMessageReady)> {
        use crate::capture::parse_l3;
        let l3 = match parse_l3(pkt, family, ports) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        let thread = self.thread_for_l3(&l3);
        let mut msgs = self.stages[thread as usize].process_packet(pkt, family);
        if msgs.is_empty() && l3.is_fragment {
            return Vec::new();
        }
        let mut retained = Vec::new();
        for msg in msgs.drain(..) {
            let flow_key = FlowKey::from_endpoints(
                if msg.transport == crate::parse::TransportProto::Udp {
                    17
                } else {
                    6
                },
                &msg.decoded.src_ip[..msg.decoded.src_ip_len as usize],
                msg.decoded.src_port,
                &msg.decoded.dst_ip[..msg.decoded.dst_ip_len as usize],
                msg.decoded.dst_port,
            );
            let bucket = hash_to_bucket(self.hash_seed, &flow_key, self.bucket_map.buckets);
            let dest = self.bucket_map.bucket_for_thread(bucket);
            let owner = if self.flow_threads > 1 { dest } else { thread };
            retained.push((owner, msg));
        }
        retained
    }

    pub fn drain_pairing_timeouts(&mut self, now_sec: u64) -> Vec<ParsedObservation> {
        let mut out = Vec::new();
        for stage in &mut self.stages {
            out.extend(stage.drain_pairing_timeouts(now_sec));
        }
        out
    }

    pub fn merged_counters(&self) -> crate::flow::FlowCounters {
        let mut c = crate::flow::FlowCounters::default();
        for s in &self.stages {
            c.merge(&s.counters);
        }
        c
    }
}

fn hash_fragment_to_bucket(seed: u64, key: &FragmentKey, buckets: u32) -> u32 {
    let mut h = seed ^ key.protocol as u64;
    h ^= u64::from(key.ip_id);
    (h as u32) & (buckets - 1)
}

fn options_ports_default() -> crate::capture::PortSet {
    crate::capture::PortSet::dns_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_map_uses_flow_threads() {
        let opts = FluxOptions {
            flow_threads: 4,
            max_flow_threads: 8,
            ..FluxOptions::default()
        };
        let pool = FlowThreadPool::new(&opts, 99);
        assert_eq!(pool.flow_threads, 4);
        assert_eq!(pool.stages.len(), 4);
    }
}
