#[derive(Debug, Clone)]
pub struct FlowBuckets {
    pub count: u32,
    pub requested: Option<u32>,
}

impl FlowBuckets {
    pub fn new(requested: u32) -> Self {
        let count = crate::options::next_pow2(requested.max(1)).clamp(256, 65536);
        let notice = if count != requested && requested != 0 {
            Some(requested)
        } else {
            None
        };
        Self {
            count,
            requested: notice,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BucketMap {
    pub buckets: u32,
    pub flow_threads: u32,
}

impl BucketMap {
    pub fn new(buckets: &FlowBuckets, max_flow_threads: u32) -> Self {
        let flow_threads = max_flow_threads.max(1);
        Self {
            buckets: buckets.count,
            flow_threads,
        }
    }

    pub fn bucket_for_thread(&self, bucket: u32) -> u32 {
        bucket % self.flow_threads
    }
}
