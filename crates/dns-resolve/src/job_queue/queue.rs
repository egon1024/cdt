use std::collections::VecDeque;

use super::types::TraceJob;

#[derive(Debug, Default)]
pub struct WorkQueue {
    pending: VecDeque<TraceJob>,
}

impl WorkQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enqueue(&mut self, job: TraceJob) {
        self.pending.push_back(job);
    }

    pub fn dequeue(&mut self) -> Option<TraceJob> {
        self.pending.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ServerTarget;
    use crate::job_queue::types::{JobId, JobKind};
    use dns_core::name::DomainName;
    use hickory_proto::rr::RecordType;
    use std::net::{IpAddr, Ipv4Addr};

    fn sample_job(id: u64) -> TraceJob {
        TraceJob {
            id: JobId(id),
            kind: JobKind::Trace,
            server: ServerTarget::from_address(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            qname: DomainName::parse("example.com.").expect("qname"),
            qtype: RecordType::A,
            zone: DomainName::parse(".").expect("zone"),
            path: vec![],
            fallback_servers: vec![],
        }
    }

    #[test]
    fn enqueues_and_dequeues_in_order() {
        let mut queue = WorkQueue::new();
        queue.enqueue(sample_job(1));
        queue.enqueue(sample_job(2));

        let first = queue.dequeue().expect("first");
        assert_eq!(first.id, JobId(1));
        let second = queue.dequeue().expect("second");
        assert_eq!(second.id, JobId(2));
        assert!(queue.dequeue().is_none());
    }
}
