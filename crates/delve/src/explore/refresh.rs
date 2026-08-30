use dns_resolve::{RefreshProgress, RefreshTreeReport, refresh_tree_rtts};

use crate::runtime::Runtime;
use crate::session::{SessionDocument, SessionError};
use crate::trace_config::{TraceConfigError, trace_config_from_request};

#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    #[error(transparent)]
    TraceConfig(#[from] TraceConfigError),

    #[error(transparent)]
    Session(#[from] SessionError),

    #[error("session has no trace tree")]
    NoTree,
}

pub fn refresh_document_tree(
    document: &mut SessionDocument,
    runtime: &Runtime,
    progress: &mut dyn RefreshProgress,
) -> Result<RefreshTreeReport, RefreshError> {
    let session_tree = document.trees.get_mut(0).ok_or(RefreshError::NoTree)?;
    let request = session_tree.request.clone();
    let mut config = trace_config_from_request(
        &request,
        runtime.cache.clone(),
        runtime.config.trace_max_queries_per_action,
        runtime.config.trace_max_parallel_queries,
    )?;
    config.use_cache = false;
    let report = refresh_tree_rtts(&mut session_tree.tree, &config, progress);
    Ok(report)
}

pub fn persist_refreshed_tree(
    runtime: &Runtime,
    document: &SessionDocument,
) -> Result<(), SessionError> {
    runtime.update_session(document)
}
