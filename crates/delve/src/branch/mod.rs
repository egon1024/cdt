use std::net::IpAddr;

use dns_resolve::{NodePath, TraceProgress};
use thiserror::Error;

use crate::explore::ExploreQueryOverrides;
use crate::runtime::Runtime;
use crate::session::SessionDocument;

mod execute;
mod report;
mod target;

#[cfg(test)]
mod tests;

pub use execute::execute_branch;
pub use report::format_branch_report;
pub use target::parse_server_target;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchIntentArg {
    AlternateServer { target: ServerTargetInput },
    ExpandCut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerTargetInput {
    Name(String),
    Address(IpAddr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchPlan {
    /// Display index of the planned cut, as `session outline` prints it and
    /// `--at-hop` accepts it.
    pub hop: Option<usize>,
    /// Planned cut in `--at-path` syntax.
    pub path: String,
    pub zone: String,
    pub server: String,
    pub qname: String,
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchReport {
    pub nodes_added: usize,
    pub updated_at: Option<String>,
    pub warnings: Vec<String>,
    pub budget_truncated: bool,
    pub dry_run: bool,
    pub plan: Option<BranchPlan>,
}

#[derive(Debug, Error)]
pub enum BranchError {
    #[error(transparent)]
    Resolve(#[from] dns_resolve::ResolveError),

    #[error(transparent)]
    Core(#[from] dns_core::DnsCoreError),

    #[error(transparent)]
    Session(#[from] crate::session::SessionError),

    #[error(transparent)]
    TraceConfig(#[from] crate::trace_config::TraceConfigError),

    #[error("session has no trace tree")]
    NoTree,

    #[error("node path {path} does not resolve in session")]
    UnresolvedPath { path: String },

    #[error("display index {index} is out of range")]
    OutOfRangeHop { index: usize },

    #[error("branch requires --server or --expand")]
    MissingTarget,

    #[error("invalid node path: {value}")]
    InvalidPath { value: String },

    #[error("invalid server argument: {value}")]
    InvalidServer { value: String },
}

pub fn parse_node_path(value: &str) -> Result<NodePath, BranchError> {
    if value.is_empty() {
        return Err(BranchError::InvalidPath {
            value: value.into(),
        });
    }
    let mut segments = value.split('.');
    let tree = segments
        .next()
        .ok_or_else(|| BranchError::InvalidPath {
            value: value.into(),
        })?
        .parse::<usize>()
        .map_err(|_| BranchError::InvalidPath {
            value: value.into(),
        })?;
    let path = segments
        .map(|segment| {
            segment
                .parse::<usize>()
                .map_err(|_| BranchError::InvalidPath {
                    value: value.into(),
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(NodePath { tree, path })
}

pub fn resolve_branch_target(
    document: &SessionDocument,
    at_hop: Option<usize>,
    at_path: Option<&str>,
) -> Result<NodePath, BranchError> {
    let tree = document.primary_tree().ok_or(BranchError::NoTree)?;
    if let Some(path_value) = at_path {
        let path = parse_node_path(path_value)?;
        if tree.resolve(&path).is_none() {
            return Err(BranchError::UnresolvedPath {
                path: path_value.into(),
            });
        }
        return Ok(path);
    }
    if let Some(index) = at_hop {
        return tree
            .path_for_display_index(index)
            .ok_or(BranchError::OutOfRangeHop { index });
    }
    Err(BranchError::MissingTarget)
}

pub fn branch_session(
    runtime: &Runtime,
    session_id: &str,
    at: NodePath,
    intent: BranchIntentArg,
    dry_run: bool,
    progress: &mut dyn TraceProgress,
    query_overrides: Option<&ExploreQueryOverrides>,
) -> Result<BranchReport, BranchError> {
    let mut document = runtime.get_session(session_id)?;
    if document.frozen {
        return Err(crate::session::SessionError::Frozen {
            id: document.id.clone(),
        }
        .into());
    }
    let tree_index = at.tree;
    let mut report = execute_branch(
        &mut document,
        at,
        intent,
        dry_run,
        runtime,
        progress,
        None,
        query_overrides,
    )?;
    if !dry_run && report.nodes_added > 0 {
        if let Some(notice) =
            crate::enrichment::populate_after_branch(&mut document, tree_index, runtime, false)
        {
            report.warnings.push(notice);
        }
        runtime.update_session(&document)?;
    }
    Ok(report)
}
