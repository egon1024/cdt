use crate::{Result, TraceConfig, query_server};

use super::types::TraceJob;

pub fn execute_job(
    job: &TraceJob,
    config: &TraceConfig,
) -> Result<dns_core::response::QueryResult> {
    query_server(job.server.address, config, &job.qname, job.qtype)
}
