use std::path::{Path, PathBuf};

use dns_resolve::TraceResult;
use time::OffsetDateTime;

use crate::config::SessionRetention;
use crate::retention::{PurgeReport, is_expired};
use crate::trace_request::TraceRequest;

use super::document::{SessionDocument, SessionSummary};
use super::id::new_session_id;
use super::store::{Result, SessionError, SessionStore};

pub struct NdjsonSessionStore {
    dir: PathBuf,
    disabled_reason: Option<String>,
}

impl NdjsonSessionStore {
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).map_err(|error| SessionError::Store(error.to_string()))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            disabled_reason: None,
        })
    }

    pub fn disabled(reason: String) -> Self {
        Self {
            dir: PathBuf::new(),
            disabled_reason: Some(reason),
        }
    }

    fn session_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }
}

impl SessionStore for NdjsonSessionStore {
    fn save(&mut self, result: &TraceResult, request: &TraceRequest) -> Result<String> {
        if let Some(reason) = &self.disabled_reason {
            return Err(SessionError::Store(reason.clone()));
        }
        let id = new_session_id();
        let document = SessionDocument::new(id.clone(), request.clone(), result.clone());
        let body = serde_json::to_string_pretty(&document)
            .map_err(|error| SessionError::Serialization(error.to_string()))?;
        let path = self.session_path(&id);
        std::fs::write(path, body).map_err(|error| SessionError::Store(error.to_string()))?;
        Ok(id)
    }

    fn get(&self, id: &str) -> Result<SessionDocument> {
        if let Some(reason) = &self.disabled_reason {
            return Err(SessionError::Store(reason.clone()));
        }
        let path = self.session_path(id);
        let body = std::fs::read_to_string(path)
            .map_err(|_| SessionError::NotFound { id: id.to_string() })?;
        serde_json::from_str(&body).map_err(|error| SessionError::Serialization(error.to_string()))
    }

    fn list(&self) -> Result<Vec<SessionSummary>> {
        if let Some(reason) = &self.disabled_reason {
            return Err(SessionError::Store(reason.clone()));
        }
        let mut summaries = Vec::new();
        for entry in
            std::fs::read_dir(&self.dir).map_err(|error| SessionError::Store(error.to_string()))?
        {
            let entry = entry.map_err(|error| SessionError::Store(error.to_string()))?;
            if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let document = self.get(
                entry
                    .path()
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or_default(),
            )?;
            summaries.push(SessionSummary::from_document(&document));
        }
        summaries.sort_by(|left, right| right.created_at.cmp(&left.created_at));
        Ok(summaries)
    }

    fn remove(&mut self, id: &str) -> Result<()> {
        if let Some(reason) = &self.disabled_reason {
            return Err(SessionError::Store(reason.clone()));
        }
        let path = self.session_path(id);
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err(SessionError::NotFound { id: id.to_string() })
            }
            Err(error) => Err(SessionError::Store(error.to_string())),
        }
    }

    fn all_ids(&self) -> Result<Vec<String>> {
        if let Some(reason) = &self.disabled_reason {
            return Err(SessionError::Store(reason.clone()));
        }
        let mut ids = Vec::new();
        for entry in
            std::fs::read_dir(&self.dir).map_err(|error| SessionError::Store(error.to_string()))?
        {
            let entry = entry.map_err(|error| SessionError::Store(error.to_string()))?;
            if entry.path().extension().and_then(|ext| ext.to_str()) == Some("json") {
                if let Some(stem) = entry.path().file_stem().and_then(|stem| stem.to_str()) {
                    ids.push(stem.to_string());
                }
            }
        }
        ids.sort();
        Ok(ids)
    }

    fn set_pinned(&mut self, id: &str, pinned: bool) -> Result<()> {
        if let Some(reason) = &self.disabled_reason {
            return Err(SessionError::Store(reason.clone()));
        }
        let mut document = self.get(id)?;
        document.pinned = pinned;
        let body = serde_json::to_string_pretty(&document)
            .map_err(|error| SessionError::Serialization(error.to_string()))?;
        std::fs::write(self.session_path(id), body)
            .map_err(|error| SessionError::Store(error.to_string()))?;
        Ok(())
    }

    fn purge_by_retention(
        &mut self,
        retention: SessionRetention,
        dry_run: bool,
    ) -> Result<PurgeReport> {
        if let Some(reason) = &self.disabled_reason {
            return Err(SessionError::Store(reason.clone()));
        }
        if retention == SessionRetention::Never {
            return Ok(PurgeReport {
                removed: 0,
                skipped_unparseable: 0,
            });
        }

        let now = OffsetDateTime::now_utc();
        let ids = self.all_ids()?;
        let mut removed = 0;
        let mut skipped_unparseable = 0;

        for id in ids {
            let document = self.get(&id)?;
            if document.pinned {
                continue;
            }
            match is_expired(&document.created_at, retention, now) {
                Some(true) => {
                    if !dry_run {
                        self.remove(&id)?;
                    }
                    removed += 1;
                }
                Some(false) => {}
                None => skipped_unparseable += 1,
            }
        }

        Ok(PurgeReport {
            removed,
            skipped_unparseable,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::TraceResult;

    fn sample_result() -> TraceResult {
        TraceResult {
            qname: "example.com.".into(),
            qtype: "A".into(),
            started_at: "2026-08-25T00:00:00Z".into(),
            hops: vec![],
            final_response: None,
        }
    }

    fn sample_request() -> TraceRequest {
        TraceRequest::from_options(&crate::dig_options::TraceOptions {
            qname: "example.com".into(),
            ..Default::default()
        })
    }

    #[test]
    fn round_trip_ndjson_session() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = NdjsonSessionStore::open(dir.path()).expect("open");
        let id = store
            .save(&sample_result(), &sample_request())
            .expect("save");
        let loaded = store.get(&id).expect("get");
        assert_eq!(loaded.result.qname, "example.com.");
    }
}
