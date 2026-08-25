use std::path::Path;
use std::sync::Mutex;

use crate::trace_request::TraceRequest;
use dns_resolve::TraceResult;
use rusqlite::{Connection, params};
use time::OffsetDateTime;

use crate::config::SessionRetention;
use crate::retention::{PurgeReport, is_expired};

use super::document::{SessionDocument, SessionSummary};
use super::id::new_session_id;
use super::store::{Result, SessionError, SessionStore};

pub struct SqliteSessionStore {
    conn: Mutex<Connection>,
}

impl SqliteSessionStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| SessionError::Store(error.to_string()))?;
        }
        let conn =
            Connection::open(path).map_err(|error| SessionError::Store(error.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                qname TEXT NOT NULL,
                qtype TEXT NOT NULL,
                hop_count INTEGER NOT NULL,
                pinned INTEGER NOT NULL DEFAULT 0,
                body TEXT NOT NULL
            );",
        )
        .map_err(|error| SessionError::Store(error.to_string()))?;
        let _ = conn.execute(
            "ALTER TABLE sessions ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0",
            [],
        );
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

impl SessionStore for SqliteSessionStore {
    fn save(&mut self, result: &TraceResult, request: &TraceRequest) -> Result<String> {
        let id = new_session_id();
        let document = SessionDocument::new(id.clone(), request.clone(), result.clone());
        let body = serde_json::to_string(&document)
            .map_err(|error| SessionError::Serialization(error.to_string()))?;
        let summary = SessionSummary::from_document(&document);
        let guard = self.conn.lock().expect("sqlite lock");
        guard
            .execute(
                "INSERT INTO sessions (id, created_at, qname, qtype, hop_count, pinned, body)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    summary.id,
                    summary.created_at,
                    summary.qname,
                    summary.qtype,
                    summary.hop_count as i64,
                    if summary.pinned { 1 } else { 0 },
                    body,
                ],
            )
            .map_err(|error| SessionError::Store(error.to_string()))?;
        Ok(id)
    }

    fn get(&self, id: &str) -> Result<SessionDocument> {
        let guard = self.conn.lock().expect("sqlite lock");
        let body: String = guard
            .query_row(
                "SELECT body FROM sessions WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .map_err(|_| SessionError::NotFound { id: id.to_string() })?;
        serde_json::from_str(&body).map_err(|error| SessionError::Serialization(error.to_string()))
    }

    fn list(&self) -> Result<Vec<SessionSummary>> {
        let guard = self.conn.lock().expect("sqlite lock");
        let mut stmt = guard
            .prepare(
                "SELECT id, created_at, qname, qtype, hop_count, pinned
                 FROM sessions ORDER BY created_at DESC",
            )
            .map_err(|error| SessionError::Store(error.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(SessionSummary {
                    id: row.get(0)?,
                    created_at: row.get(1)?,
                    qname: row.get(2)?,
                    qtype: row.get(3)?,
                    hop_count: row.get::<_, i64>(4)? as usize,
                    pinned: row.get::<_, i64>(5)? != 0,
                })
            })
            .map_err(|error| SessionError::Store(error.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| SessionError::Store(error.to_string()))
    }

    fn remove(&mut self, id: &str) -> Result<()> {
        let guard = self.conn.lock().expect("sqlite lock");
        let deleted = guard
            .execute("DELETE FROM sessions WHERE id = ?1", params![id])
            .map_err(|error| SessionError::Store(error.to_string()))?;
        if deleted == 0 {
            return Err(SessionError::NotFound { id: id.to_string() });
        }
        Ok(())
    }

    fn all_ids(&self) -> Result<Vec<String>> {
        let guard = self.conn.lock().expect("sqlite lock");
        let mut stmt = guard
            .prepare("SELECT id FROM sessions ORDER BY id")
            .map_err(|error| SessionError::Store(error.to_string()))?;
        let rows = stmt
            .query_map([], |row| row.get(0))
            .map_err(|error| SessionError::Store(error.to_string()))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| SessionError::Store(error.to_string()))
    }

    fn set_pinned(&mut self, id: &str, pinned: bool) -> Result<()> {
        let mut document = self.get(id)?;
        document.pinned = pinned;
        let body = serde_json::to_string(&document)
            .map_err(|error| SessionError::Serialization(error.to_string()))?;
        let guard = self.conn.lock().expect("sqlite lock");
        let updated = guard
            .execute(
                "UPDATE sessions SET body = ?1, pinned = ?2 WHERE id = ?3",
                params![body, if pinned { 1 } else { 0 }, id],
            )
            .map_err(|error| SessionError::Store(error.to_string()))?;
        if updated == 0 {
            return Err(SessionError::NotFound { id: id.to_string() });
        }
        Ok(())
    }

    fn purge_by_retention(
        &mut self,
        retention: SessionRetention,
        dry_run: bool,
    ) -> Result<PurgeReport> {
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
    use dns_resolve::{TraceHop, TraceResult};

    fn sample_result(started_at: &str) -> TraceResult {
        TraceResult {
            qname: "example.com.".into(),
            qtype: "A".into(),
            started_at: started_at.into(),
            hops: vec![TraceHop {
                zone: ".".into(),
                server: "1.1.1.1".into(),
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
            }],
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
    fn round_trip_session() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sessions.sqlite");
        let mut store = SqliteSessionStore::open(&path).expect("open");
        let id = store
            .save(&sample_result("2026-08-25T00:00:00Z"), &sample_request())
            .expect("save");
        let loaded = store.get(&id).expect("get");
        assert_eq!(loaded.result.qname, "example.com.");
        assert!(!loaded.pinned);
    }

    #[test]
    fn purge_skips_pinned_and_old_sessions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sessions.sqlite");
        let mut store = SqliteSessionStore::open(&path).expect("open");
        let old_id = store
            .save(&sample_result("2020-01-01T00:00:00Z"), &sample_request())
            .expect("old");
        let pinned_id = store
            .save(&sample_result("2020-01-02T00:00:00Z"), &sample_request())
            .expect("pinned");
        store.set_pinned(&pinned_id, true).expect("pin");
        let report = store
            .purge_by_retention(SessionRetention::Days(30), false)
            .expect("purge");
        assert_eq!(report.removed, 1);
        assert!(store.get(&old_id).is_err());
        assert!(store.get(&pinned_id).is_ok());
    }
}
