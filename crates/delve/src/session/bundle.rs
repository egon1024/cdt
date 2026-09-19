use serde::{Deserialize, Serialize};

use super::document::{SessionDocument, now_rfc3339};
use super::store::{Result, SessionError};

pub const SESSION_BUNDLE_FORMAT: &str = "delve-sessions";
pub const SESSION_BUNDLE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionBundle {
    pub format: String,
    pub version: u32,
    pub exported_at: String,
    pub sessions: Vec<SessionDocument>,
}

impl SessionBundle {
    pub fn new(sessions: Vec<SessionDocument>) -> Self {
        Self {
            format: SESSION_BUNDLE_FORMAT.to_string(),
            version: SESSION_BUNDLE_VERSION,
            exported_at: now_rfc3339(),
            sessions,
        }
    }

    pub fn validate_envelope(value: &serde_json::Value) -> Result<()> {
        let format = value
            .get("format")
            .and_then(|entry| entry.as_str())
            .ok_or_else(|| SessionError::Store("session bundle missing format field".into()))?;
        if format != SESSION_BUNDLE_FORMAT {
            return Err(SessionError::Store(format!(
                "unsupported session bundle format {format:?}; expected {SESSION_BUNDLE_FORMAT:?}"
            )));
        }
        let version = value
            .get("version")
            .and_then(|entry| entry.as_u64())
            .ok_or_else(|| SessionError::Store("session bundle missing version field".into()))?;
        if version as u32 != SESSION_BUNDLE_VERSION {
            return Err(SessionError::Store(format!(
                "unsupported session bundle version {version}; expected {SESSION_BUNDLE_VERSION}"
            )));
        }
        if !value
            .get("sessions")
            .map(|entry| entry.is_array())
            .unwrap_or(false)
        {
            return Err(SessionError::Store(
                "session bundle missing sessions array".into(),
            ));
        }
        Ok(())
    }

    pub fn from_json(body: &str) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_str(body)
            .map_err(|error| SessionError::Serialization(error.to_string()))?;
        Self::validate_envelope(&value)?;
        serde_json::from_value(value)
            .map_err(|error| SessionError::Serialization(error.to_string()))
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|error| SessionError::Serialization(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace_request::TraceRequest;
    use dns_resolve::{HopOutcome, TraceHop, TraceTreeRequest, build_linear_tree};

    fn sample_document(id: &str) -> SessionDocument {
        SessionDocument::new(
            id.into(),
            TraceRequest::from_options(&crate::dig_options::TraceOptions {
                qname: "example.com".into(),
                ..Default::default()
            }),
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
                    started_at: "2026-08-25T00:00:00Z".into(),
                },
            ),
        )
    }

    #[test]
    fn bundle_round_trips_through_json() {
        let bundle = SessionBundle::new(vec![sample_document("01TEST")]);
        let json = bundle.to_json().expect("serialize");
        let decoded = SessionBundle::from_json(&json).expect("deserialize");
        assert_eq!(bundle.sessions, decoded.sessions);
        assert_eq!(decoded.format, SESSION_BUNDLE_FORMAT);
        assert_eq!(decoded.version, SESSION_BUNDLE_VERSION);
    }

    #[test]
    fn bundle_rejects_wrong_format() {
        let value = serde_json::json!({
            "format": "other",
            "version": 1,
            "exported_at": "2026-01-01T00:00:00Z",
            "sessions": []
        });
        let error = SessionBundle::validate_envelope(&value).expect_err("format");
        assert!(error.to_string().contains("format"));
    }

    #[test]
    fn bundle_rejects_wrong_version() {
        let value = serde_json::json!({
            "format": SESSION_BUNDLE_FORMAT,
            "version": 99,
            "exported_at": "2026-01-01T00:00:00Z",
            "sessions": []
        });
        let error = SessionBundle::validate_envelope(&value).expect_err("version");
        assert!(error.to_string().contains("version"));
    }
}
