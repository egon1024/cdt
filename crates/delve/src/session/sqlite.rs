use std::path::Path;
use std::sync::Mutex;

use crate::trace_request::TraceRequest;
use dns_resolve::TraceTree;
use rusqlite::{Connection, params};
use time::OffsetDateTime;

use crate::config::SessionRetention;
use crate::retention::{PurgeReport, is_expired};

use super::document::{SessionDocument, SessionListItem, SessionSummary, parse_session_document};
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
        if !Self::has_v2_columns(&conn, path)? {
            return Err(SessionError::UnsupportedLegacyStore {
                path: path.display().to_string(),
            });
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                qname TEXT NOT NULL,
                qtype TEXT NOT NULL,
                node_count INTEGER NOT NULL,
                pinned INTEGER NOT NULL DEFAULT 0,
                body TEXT NOT NULL
            );",
        )
        .map_err(|error| SessionError::Store(error.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn has_v2_columns(conn: &Connection, path: &Path) -> Result<bool> {
        let table_exists: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'sessions'",
                [],
                |row| row.get::<_, i64>(0).map(|count| count > 0),
            )
            .unwrap_or(false);
        if !table_exists {
            return Ok(true);
        }
        if conn
            .prepare("SELECT updated_at, node_count FROM sessions LIMIT 0")
            .is_err()
        {
            return Err(SessionError::UnsupportedLegacyStore {
                path: path.display().to_string(),
            });
        }
        Ok(true)
    }

    fn write_document(conn: &Connection, document: &SessionDocument) -> Result<()> {
        let body = serde_json::to_string(document)
            .map_err(|error| SessionError::Serialization(error.to_string()))?;
        let summary = SessionSummary::from_document(document);
        let updated = conn
            .execute(
                "UPDATE sessions
                 SET created_at = ?1, updated_at = ?2, qname = ?3, qtype = ?4,
                     node_count = ?5, pinned = ?6, body = ?7
                 WHERE id = ?8",
                params![
                    summary.created_at,
                    summary.updated_at,
                    summary.qname,
                    summary.qtype,
                    summary.node_count as i64,
                    if summary.pinned { 1 } else { 0 },
                    body,
                    summary.id,
                ],
            )
            .map_err(|error| SessionError::Store(error.to_string()))?;
        if updated == 0 {
            return Err(SessionError::NotFound {
                id: document.id.clone(),
            });
        }
        Ok(())
    }
}

impl SessionStore for SqliteSessionStore {
    fn save(&mut self, result: &TraceTree, request: &TraceRequest) -> Result<String> {
        let id = new_session_id();
        let document = SessionDocument::new(id.clone(), request.clone(), result.clone());
        let body = serde_json::to_string(&document)
            .map_err(|error| SessionError::Serialization(error.to_string()))?;
        let summary = SessionSummary::from_document(&document);
        let guard = self.conn.lock().expect("sqlite lock");
        guard
            .execute(
                "INSERT INTO sessions (id, created_at, updated_at, qname, qtype, node_count, pinned, body)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    summary.id,
                    summary.created_at,
                    summary.updated_at,
                    summary.qname,
                    summary.qtype,
                    summary.node_count as i64,
                    if summary.pinned { 1 } else { 0 },
                    body,
                ],
            )
            .map_err(|error| SessionError::Store(error.to_string()))?;
        Ok(id)
    }

    fn update(&mut self, document: &SessionDocument) -> Result<()> {
        let guard = self.conn.lock().expect("sqlite lock");
        guard
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|error| SessionError::Store(error.to_string()))?;
        let result = Self::write_document(&guard, document);
        match result {
            Ok(()) => guard
                .execute_batch("COMMIT")
                .map_err(|error| SessionError::Store(error.to_string()))?,
            Err(error) => {
                let _ = guard.execute_batch("ROLLBACK");
                return Err(error);
            }
        }
        Ok(())
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
        parse_session_document(id, &body)
    }

    fn list(&self) -> Result<Vec<SessionListItem>> {
        let guard = self.conn.lock().expect("sqlite lock");
        let mut stmt = guard
            .prepare(
                "SELECT id, created_at, updated_at, qname, qtype, node_count, pinned, body
                 FROM sessions ORDER BY updated_at DESC",
            )
            .map_err(|error| SessionError::Store(error.to_string()))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, String>(7)?,
                ))
            })
            .map_err(|error| SessionError::Store(error.to_string()))?;
        let mut items = Vec::new();
        for row in rows {
            let (id, created_at, updated_at, qname, qtype, node_count, pinned, body) =
                row.map_err(|error| SessionError::Store(error.to_string()))?;
            match parse_session_document(&id, &body) {
                Ok(document) => items.push(SessionListItem::Session(SessionSummary {
                    id: document.id,
                    qname,
                    qtype,
                    created_at,
                    updated_at,
                    node_count: node_count as usize,
                    pinned: pinned != 0,
                })),
                Err(error) => items.push(SessionListItem::Unreadable {
                    id,
                    message: error.to_string(),
                }),
            }
        }
        Ok(items)
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
        document.touch_updated_at();
        self.update(&document)
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

    fn purge_session(
        &mut self,
        id: &str,
        retention: SessionRetention,
        dry_run: bool,
    ) -> Result<PurgeReport> {
        if retention == SessionRetention::Never {
            return Ok(PurgeReport {
                removed: 0,
                skipped_unparseable: 0,
            });
        }

        let document = self.get(id)?;
        if document.pinned {
            return Ok(PurgeReport {
                removed: 0,
                skipped_unparseable: 0,
            });
        }

        let now = OffsetDateTime::now_utc();
        match is_expired(&document.updated_at, retention, now) {
            Some(true) => {
                if !dry_run {
                    self.remove(id)?;
                }
                Ok(PurgeReport {
                    removed: 1,
                    skipped_unparseable: 0,
                })
            }
            Some(false) => Ok(PurgeReport {
                removed: 0,
                skipped_unparseable: 0,
            }),
            None => Ok(PurgeReport {
                removed: 0,
                skipped_unparseable: 1,
            }),
        }
    }

    fn purge_all(&mut self, dry_run: bool) -> Result<PurgeReport> {
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

    fn sample_result(started_at: &str) -> TraceTree {
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
    fn round_trip_session() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sessions.sqlite");
        let mut store = SqliteSessionStore::open(&path).expect("open");
        let id = store
            .save(&sample_result("2026-08-25T00:00:00Z"), &sample_request())
            .expect("save");
        let loaded = store.get(&id).expect("get");
        assert_eq!(loaded.primary_tree().expect("tree").qname(), "example.com.");
        assert!(!loaded.pinned);
        assert_eq!(loaded.version, 2);
    }

    #[test]
    fn update_is_durable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sessions.sqlite");
        let mut store = SqliteSessionStore::open(&path).expect("open");
        let id = store
            .save(&sample_result("2026-08-25T00:00:00Z"), &sample_request())
            .expect("save");
        let mut document = store.get(&id).expect("get");
        document.pinned = true;
        document.updated_at = "2026-08-26T00:00:00Z".into();
        store.update(&document).expect("update");
        let loaded = store.get(&id).expect("reload");
        assert!(loaded.pinned);
        assert_eq!(loaded.updated_at, "2026-08-26T00:00:00Z");
    }

    #[test]
    fn failed_update_leaves_prior_document_intact() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sessions.sqlite");
        let mut store = SqliteSessionStore::open(&path).expect("open");
        let id = store
            .save(&sample_result("2026-08-25T00:00:00Z"), &sample_request())
            .expect("save");
        let original = store.get(&id).expect("get");
        let mut missing = original.clone();
        missing.id = "missing".into();
        let error = store.update(&missing).expect_err("missing id");
        assert!(error.to_string().contains("not found"));
        let reloaded = store.get(&id).expect("reload");
        assert_eq!(reloaded, original);
    }

    #[test]
    fn list_orders_by_updated_at_desc() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sessions.sqlite");
        let mut store = SqliteSessionStore::open(&path).expect("open");
        let older = store
            .save(&sample_result("2026-08-25T00:00:00Z"), &sample_request())
            .expect("older");
        let newer = store
            .save(&sample_result("2026-08-26T00:00:00Z"), &sample_request())
            .expect("newer");
        let items = store.list().expect("list");
        let ids = items
            .into_iter()
            .filter_map(|item| match item {
                SessionListItem::Session(summary) => Some(summary.id),
                SessionListItem::Unreadable { .. } => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(ids, vec![newer, older]);
    }

    #[test]
    fn list_reports_unreadable_session() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sessions.sqlite");
        let store = SqliteSessionStore::open(&path).expect("open");
        let guard = store.conn.lock().expect("lock");
        guard
            .execute(
                "INSERT INTO sessions (id, created_at, updated_at, qname, qtype, node_count, pinned, body)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    "01BAD",
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                    "example.com.",
                    "A",
                    1,
                    0,
                    r#"{"version":1,"id":"01BAD"}"#,
                ],
            )
            .expect("insert v1");
        drop(guard);
        let items = store.list().expect("list");
        assert!(matches!(
            items.first(),
            Some(SessionListItem::Unreadable { id, .. }) if id == "01BAD"
        ));
    }

    #[test]
    fn legacy_store_without_v2_columns_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sessions.sqlite");
        let conn = Connection::open(&path).expect("open");
        conn.execute_batch(
            "CREATE TABLE sessions (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                qname TEXT NOT NULL,
                qtype TEXT NOT NULL,
                hop_count INTEGER NOT NULL,
                pinned INTEGER NOT NULL DEFAULT 0,
                body TEXT NOT NULL
            );",
        )
        .expect("legacy schema");
        drop(conn);
        let error = match SqliteSessionStore::open(&path) {
            Err(error) => error,
            Ok(_) => panic!("legacy store should be rejected"),
        };
        assert!(matches!(error, SessionError::UnsupportedLegacyStore { .. }));
    }

    #[test]
    fn pin_bumps_updated_at() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sessions.sqlite");
        let mut store = SqliteSessionStore::open(&path).expect("open");
        let id = store
            .save(&sample_result("2026-08-25T00:00:00Z"), &sample_request())
            .expect("save");
        let before = store.get(&id).expect("get").updated_at;
        store.set_pinned(&id, true).expect("pin");
        let after = store.get(&id).expect("get").updated_at;
        assert_ne!(before, after);
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

    #[test]
    fn purge_session_applies_retention_to_one_session() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sessions.sqlite");
        let mut store = SqliteSessionStore::open(&path).expect("open");
        let old_id = store
            .save(&sample_result("2020-01-01T00:00:00Z"), &sample_request())
            .expect("old");
        let recent_id = store
            .save(&sample_result("2026-08-25T00:00:00Z"), &sample_request())
            .expect("recent");

        let report = store
            .purge_session(&old_id, SessionRetention::Days(30), false)
            .expect("purge old");
        assert_eq!(report.removed, 1);
        assert!(store.get(&old_id).is_err());
        assert!(store.get(&recent_id).is_ok());

        let report = store
            .purge_session(&recent_id, SessionRetention::Days(30), false)
            .expect("purge recent");
        assert_eq!(report.removed, 0);
        assert!(store.get(&recent_id).is_ok());
    }

    #[test]
    fn purge_session_skips_pinned_session() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sessions.sqlite");
        let mut store = SqliteSessionStore::open(&path).expect("open");
        let id = store
            .save(&sample_result("2020-01-01T00:00:00Z"), &sample_request())
            .expect("save");
        store.set_pinned(&id, true).expect("pin");
        let report = store
            .purge_session(&id, SessionRetention::Days(30), false)
            .expect("purge");
        assert_eq!(report.removed, 0);
        assert!(store.get(&id).is_ok());
    }

    #[test]
    fn purge_all_removes_unpinned_regardless_of_age() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sessions.sqlite");
        let mut store = SqliteSessionStore::open(&path).expect("open");
        let recent_id = store
            .save(&sample_result("2026-08-25T00:00:00Z"), &sample_request())
            .expect("recent");
        let pinned_id = store
            .save(&sample_result("2026-08-25T01:00:00Z"), &sample_request())
            .expect("pinned");
        store.set_pinned(&pinned_id, true).expect("pin");
        let report = store.purge_all(false).expect("purge all");
        assert_eq!(report.removed, 1);
        assert!(store.get(&recent_id).is_err());
        assert!(store.get(&pinned_id).is_ok());
    }

    #[test]
    fn purge_all_dry_run_leaves_sessions_intact() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sessions.sqlite");
        let mut store = SqliteSessionStore::open(&path).expect("open");
        let id = store
            .save(&sample_result("2026-08-25T00:00:00Z"), &sample_request())
            .expect("save");
        let report = store.purge_all(true).expect("dry run");
        assert_eq!(report.removed, 1);
        assert!(store.get(&id).is_ok());
    }

    #[test]
    fn remove_unsupported_session_succeeds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sessions.sqlite");
        let store = SqliteSessionStore::open(&path).expect("open");
        let guard = store.conn.lock().expect("lock");
        guard
            .execute(
                "INSERT INTO sessions (id, created_at, updated_at, qname, qtype, node_count, pinned, body)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    "01BAD",
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z",
                    "example.com.",
                    "A",
                    1,
                    0,
                    r#"{"version":1,"id":"01BAD"}"#,
                ],
            )
            .expect("insert v1");
        drop(guard);
        let mut store = store;
        store.remove("01BAD").expect("remove unsupported");
        assert!(store.get("01BAD").is_err());
    }
}
