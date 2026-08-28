use dns_resolve::TraceTree;
use serde::{Deserialize, Serialize};

use crate::trace_request::TraceRequest;

pub const SESSION_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionDocument {
    pub version: u32,
    pub id: String,
    pub created_at: String,
    #[serde(default)]
    pub pinned: bool,
    #[serde(default)]
    pub request: Option<TraceRequest>,
    pub result: TraceTree,
}

impl SessionDocument {
    pub fn new(id: String, request: TraceRequest, result: TraceTree) -> Self {
        Self {
            version: SESSION_FORMAT_VERSION,
            id,
            created_at: result.started_at().to_string(),
            pinned: false,
            request: Some(request),
            result,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    pub id: String,
    pub qname: String,
    pub qtype: String,
    pub created_at: String,
    pub hop_count: usize,
    pub pinned: bool,
}

impl SessionSummary {
    pub fn from_document(document: &SessionDocument) -> Self {
        Self {
            id: document.id.clone(),
            qname: document.result.qname().to_string(),
            qtype: document.result.qtype().to_string(),
            created_at: document.created_at.clone(),
            hop_count: document.result.node_count(),
            pinned: document.pinned,
        }
    }
}
