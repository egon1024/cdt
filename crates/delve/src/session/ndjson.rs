use std::path::{Path, PathBuf};

use dns_resolve::TraceResult;

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
    fn save(&mut self, result: &TraceResult) -> Result<String> {
        if let Some(reason) = &self.disabled_reason {
            return Err(SessionError::Store(reason.clone()));
        }
        let id = new_session_id();
        let document = SessionDocument::new(id.clone(), result.clone());
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

    #[test]
    fn round_trip_ndjson_session() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = NdjsonSessionStore::open(dir.path()).expect("open");
        let id = store.save(&sample_result()).expect("save");
        let loaded = store.get(&id).expect("get");
        assert_eq!(loaded.result.qname, "example.com.");
    }
}
