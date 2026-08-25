use dns_resolve::TraceResult;
use serde::{Deserialize, Serialize};

pub const SESSION_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionDocument {
    pub version: u32,
    pub id: String,
    pub created_at: String,
    pub result: TraceResult,
}

impl SessionDocument {
    pub fn new(id: String, result: TraceResult) -> Self {
        Self {
            version: SESSION_FORMAT_VERSION,
            id,
            created_at: result.started_at.clone(),
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
}

impl SessionSummary {
    pub fn from_document(document: &SessionDocument) -> Self {
        Self {
            id: document.id.clone(),
            qname: document.result.qname.clone(),
            qtype: document.result.qtype.clone(),
            created_at: document.created_at.clone(),
            hop_count: document.result.hops.len(),
        }
    }
}
