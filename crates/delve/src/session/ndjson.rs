use std::path::{Path, PathBuf};

use dns_resolve::TraceTree;
use time::OffsetDateTime;

use crate::config::SessionRetention;
use crate::retention::{PurgeReport, is_expired};
use crate::trace_request::TraceRequest;

use super::document::{SessionDocument, SessionListItem, SessionSummary, parse_session_document};
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

    fn write_atomic(path: &Path, body: &str) -> Result<()> {
        let temp = path.with_extension("json.tmp");
        std::fs::write(&temp, body).map_err(|error| SessionError::Store(error.to_string()))?;
        std::fs::rename(&temp, path).map_err(|error| {
            let _ = std::fs::remove_file(&temp);
            SessionError::Store(error.to_string())
        })
    }
}

impl SessionStore for NdjsonSessionStore {
    fn save(&mut self, result: &TraceTree, request: &TraceRequest) -> Result<String> {
        if let Some(reason) = &self.disabled_reason {
            return Err(SessionError::Store(reason.clone()));
        }
        let id = new_session_id();
        let document = SessionDocument::new(id.clone(), request.clone(), result.clone());
        let body = serde_json::to_string_pretty(&document)
            .map_err(|error| SessionError::Serialization(error.to_string()))?;
        let path = self.session_path(&id);
        Self::write_atomic(&path, &body)?;
        Ok(id)
    }

    fn update(&mut self, document: &SessionDocument) -> Result<()> {
        if let Some(reason) = &self.disabled_reason {
            return Err(SessionError::Store(reason.clone()));
        }
        let body = serde_json::to_string_pretty(document)
            .map_err(|error| SessionError::Serialization(error.to_string()))?;
        let path = self.session_path(&document.id);
        if !path.exists() {
            return Err(SessionError::NotFound {
                id: document.id.clone(),
            });
        }
        Self::write_atomic(&path, &body)
    }

    fn get(&self, id: &str) -> Result<SessionDocument> {
        if let Some(reason) = &self.disabled_reason {
            return Err(SessionError::Store(reason.clone()));
        }
        let path = self.session_path(id);
        let body = std::fs::read_to_string(path)
            .map_err(|_| SessionError::NotFound { id: id.to_string() })?;
        parse_session_document(id, &body)
    }

    fn list(&self) -> Result<Vec<SessionListItem>> {
        if let Some(reason) = &self.disabled_reason {
            return Err(SessionError::Store(reason.clone()));
        }
        let mut items = Vec::new();
        for entry in
            std::fs::read_dir(&self.dir).map_err(|error| SessionError::Store(error.to_string()))?
        {
            let entry = entry.map_err(|error| SessionError::Store(error.to_string()))?;
            if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let id = entry
                .path()
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or_default()
                .to_string();
            let body = match std::fs::read_to_string(entry.path()) {
                Ok(body) => body,
                Err(error) => {
                    items.push(SessionListItem::Unreadable {
                        id: id.clone(),
                        message: error.to_string(),
                    });
                    continue;
                }
            };
            match parse_session_document(&id, &body) {
                Ok(document) => items.push(SessionListItem::Session(
                    SessionSummary::from_document(&document),
                )),
                Err(error) => items.push(SessionListItem::Unreadable {
                    id,
                    message: error.to_string(),
                }),
            }
        }
        items.sort_by(|left, right| {
            let left_updated = match left {
                SessionListItem::Session(summary) => &summary.updated_at,
                SessionListItem::Unreadable { .. } => "",
            };
            let right_updated = match right {
                SessionListItem::Session(summary) => &summary.updated_at,
                SessionListItem::Unreadable { .. } => "",
            };
            right_updated.cmp(left_updated)
        });
        Ok(items)
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
        document.touch_updated_at();
        self.update(&document)
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
            let document = match self.get(&id) {
                Ok(document) => document,
                Err(_) => {
                    skipped_unparseable += 1;
                    continue;
                }
            };
            if document.pinned {
                continue;
            }
            match is_expired(&document.updated_at, retention, now) {
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

    fn purge_all(&mut self, dry_run: bool) -> Result<PurgeReport> {
        if let Some(reason) = &self.disabled_reason {
            return Err(SessionError::Store(reason.clone()));
        }

        let ids = self.all_ids()?;
        let mut removed = 0;

        for id in ids {
            let document = self.get(&id)?;
            if document.pinned {
                continue;
            }
            if !dry_run {
                self.remove(&id)?;
            }
            removed += 1;
        }

        Ok(PurgeReport {
            removed,
            skipped_unparseable: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::{HopOutcome, TraceHop, TraceTreeRequest, build_linear_tree};

    fn sample_result() -> TraceTree {
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
        )
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
        assert_eq!(loaded.primary_tree().expect("tree").qname(), "example.com.");
    }

    #[test]
    fn atomic_write_leaves_original_when_rename_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("session.json");
        std::fs::write(&target, "original").expect("write original");
        std::fs::create_dir_all(target.with_extension("json.tmp")).expect("block temp");
        let error = NdjsonSessionStore::write_atomic(&target, "updated").expect_err("rename");
        assert!(!error.to_string().is_empty());
        let contents = std::fs::read_to_string(&target).expect("read");
        assert_eq!(contents, "original");
    }
}
