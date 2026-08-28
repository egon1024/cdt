use std::fmt;

use dns_core::name::DomainName;
use hickory_proto::rr::RecordType;

use crate::{ServerTarget, TraceHop};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JobId(pub u64);

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "job-{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JobKind {
    /// Primary trace hop at a zone cut.
    Trace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TraceJob {
    pub id: JobId,
    pub kind: JobKind,
    pub server: ServerTarget,
    pub qname: DomainName,
    pub qtype: RecordType,
    pub zone: DomainName,
    /// Tree path where this hop belongs (e.g. `[]`, `[0]`, `[0, 0]`).
    pub path: Vec<usize>,
    /// Remaining server candidates for this cut when the current server fails.
    pub fallback_servers: Vec<ServerTarget>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct JobResult {
    pub job_id: JobId,
    pub path: Vec<usize>,
    pub hop: TraceHop,
    pub query_result: dns_core::response::QueryResult,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn trace_job_carries_path_and_server_identity() {
        let job = TraceJob {
            id: JobId(1),
            kind: JobKind::Trace,
            server: ServerTarget::with_name(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), "ns1.example."),
            qname: DomainName::parse("example.com.").expect("qname"),
            qtype: RecordType::A,
            zone: DomainName::parse("com.").expect("zone"),
            path: vec![0, 1],
            fallback_servers: vec![],
        };

        let key = format!("{}|{}|{:?}", job.server.address, job.qname, job.path);
        assert!(key.contains("1.0.0.1"));
        assert!(key.contains("example.com."));
        assert!(key.contains("[0, 1]"));
        assert_eq!(job.path, vec![0, 1]);
        assert_eq!(job.server.address, IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)));
    }
}
