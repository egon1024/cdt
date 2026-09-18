use crate::{QueryDebugContext, Result, TraceConfig, query_server, record_query_debug};

use super::types::TraceJob;

pub fn execute_job(
    job: &TraceJob,
    config: &TraceConfig,
) -> Result<dns_core::response::QueryResult> {
    record_query_debug(
        config,
        job.server.address,
        &job.qname,
        job.qtype,
        QueryDebugContext::trace_job(job.id.0, job.path.clone()),
    );
    query_server(job.server.address, config, &job.qname, job.qtype)
}
