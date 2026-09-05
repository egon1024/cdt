use dns_resolve::{NodeOrigin, TraceNode, TraceTree};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::trace_request::TraceRequest;

pub const SESSION_FORMAT_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExploreViewState {
    #[serde(default)]
    pub active_screen: String,
    #[serde(default)]
    pub expanded_paths: Vec<Vec<usize>>,
    #[serde(default)]
    pub selection: Vec<usize>,
    #[serde(default)]
    pub pane: String,
    #[serde(default)]
    pub compare_focus_row: usize,
    #[serde(default = "default_browse_split_percent")]
    pub browse_split_percent: u16,
}

fn default_browse_split_percent() -> u16 {
    55
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionTree {
    pub request: TraceRequest,
    pub tree: TraceTree,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionDocument {
    pub version: u32,
    pub id: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default)]
    pub pinned: bool,
    pub trees: Vec<SessionTree>,
    #[serde(default)]
    pub view_state: Option<ExploreViewState>,
}

impl SessionDocument {
    pub fn new(id: String, request: TraceRequest, result: TraceTree) -> Self {
        let timestamp = result.started_at().to_string();
        Self {
            version: SESSION_FORMAT_VERSION,
            id,
            created_at: timestamp.clone(),
            updated_at: timestamp,
            pinned: false,
            trees: vec![SessionTree {
                request,
                tree: result,
            }],
            view_state: None,
        }
    }

    pub fn primary_tree(&self) -> Option<&TraceTree> {
        self.trees.first().map(|entry| &entry.tree)
    }

    pub fn primary_request(&self) -> Option<&TraceRequest> {
        self.trees.first().map(|entry| &entry.request)
    }

    pub fn node_count(&self) -> usize {
        self.trees.iter().map(|entry| entry.tree.node_count()).sum()
    }

    pub fn has_branches(&self) -> bool {
        self.trees
            .iter()
            .any(|entry| tree_has_branch_origin(&entry.tree.root))
    }

    pub fn matches_trace_request(&self, request: &TraceRequest) -> bool {
        self.trees.len() == 1 && self.trees[0].request.matches_for_reuse(request)
    }

    pub fn touch_updated_at(&mut self) {
        self.updated_at = now_rfc3339();
    }
}

fn tree_has_branch_origin(node: &TraceNode) -> bool {
    matches!(node.origin, NodeOrigin::Branch { .. })
        || node.children.iter().any(tree_has_branch_origin)
}

pub fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    pub id: String,
    pub qname: String,
    pub qtype: String,
    pub created_at: String,
    pub updated_at: String,
    pub node_count: usize,
    pub pinned: bool,
}

impl SessionSummary {
    pub fn from_document(document: &SessionDocument) -> Self {
        let primary = document
            .primary_tree()
            .expect("v2 session must contain at least one tree");
        Self {
            id: document.id.clone(),
            qname: primary.qname().to_string(),
            qtype: primary.qtype().to_string(),
            created_at: document.created_at.clone(),
            updated_at: document.updated_at.clone(),
            node_count: document.node_count(),
            pinned: document.pinned,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionListItem {
    Session(SessionSummary),
    Unreadable { id: String, message: String },
}

pub(crate) fn parse_session_document(
    id: &str,
    body: &str,
) -> super::store::Result<SessionDocument> {
    use super::store::SessionError;

    let value: serde_json::Value = serde_json::from_str(body)
        .map_err(|error| SessionError::Serialization(error.to_string()))?;
    let version = value
        .get("version")
        .and_then(|entry| entry.as_u64())
        .unwrap_or(1) as u32;
    if version != SESSION_FORMAT_VERSION {
        let session_id = value
            .get("id")
            .and_then(|entry| entry.as_str())
            .unwrap_or(id);
        return Err(SessionError::UnsupportedFormat {
            id: session_id.to_string(),
            version,
        });
    }
    serde_json::from_value(value).map_err(|error| SessionError::Serialization(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::{HopOutcome, TraceHop, TraceTreeRequest, build_linear_tree};

    fn sample_tree(started_at: &str) -> TraceTree {
        build_linear_tree(
            vec![TraceHop {
                zone: ".".into(),
                server: "1.1.1.1".into(),
                server_name: None,
                qname: "example.com.".into(),
                qtype: "A".into(),
                transport: "udp".into(),
                rtt_ms: 10,
                rcode: "NOERROR".into(),
                nsid: None,
                ede_code: None,
                ede_text: None,
                referral_ns: vec![],
                glue: vec![],
                response: Default::default(),
                from_cache: false,
                outcome: HopOutcome::Answered,
            }],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: started_at.into(),
            },
        )
    }

    fn sample_request() -> TraceRequest {
        TraceRequest::from_options(&crate::dig_options::TraceOptions {
            qname: "example.com".into(),
            ..Default::default()
        })
    }

    #[test]
    fn v2_document_round_trips_through_json() {
        let document = SessionDocument::new(
            "01TEST".into(),
            sample_request(),
            sample_tree("2026-08-25T00:00:00Z"),
        );
        let json = serde_json::to_string(&document).expect("serialize");
        let decoded: SessionDocument = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(document, decoded);
        assert_eq!(document.version, 2);
        assert_eq!(document.trees.len(), 1);
    }

    #[test]
    fn version_one_document_is_rejected() {
        let v1 = serde_json::json!({
            "version": 1,
            "id": "01OLD",
            "created_at": "2026-01-01T00:00:00Z",
            "pinned": false,
            "request": null,
            "result": {
                "request": {
                    "qname": "example.com.",
                    "qtype": "A",
                    "started_at": "2026-01-01T00:00:00Z"
                },
                "root": {
                    "hop": {
                        "zone": ".",
                        "server": "1.1.1.1",
                        "qname": "example.com.",
                        "qtype": "A",
                        "transport": "udp",
                        "rtt_ms": 1,
                        "rcode": "NOERROR",
                        "referral_ns": [],
                        "glue": [],
                        "response": {},
                        "from_cache": false,
                        "outcome": "answered"
                    },
                    "origin": { "kind": "trace" },
                    "children": []
                }
            }
        });
        let body = serde_json::to_string(&v1).expect("json");
        let error = parse_session_document("01OLD", &body).expect_err("v1 must be rejected");
        assert!(error.to_string().contains("01OLD"));
        assert!(error.to_string().contains("unsupported"));
    }
}
