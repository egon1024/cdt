use std::path::Path;
use std::sync::Mutex;

use dns_resolve::TraceResult;
use rusqlite::{Connection, params};

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
                body TEXT NOT NULL
            );",
        )
        .map_err(|error| SessionError::Store(error.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

impl SessionStore for SqliteSessionStore {
    fn save(&mut self, result: &TraceResult) -> Result<String> {
        let id = new_session_id();
        let document = SessionDocument::new(id.clone(), result.clone());
        let body = serde_json::to_string(&document)
            .map_err(|error| SessionError::Serialization(error.to_string()))?;
        let summary = SessionSummary::from_document(&document);
        let guard = self.conn.lock().expect("sqlite lock");
        guard
            .execute(
                "INSERT INTO sessions (id, created_at, qname, qtype, hop_count, body)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    summary.id,
                    summary.created_at,
                    summary.qname,
                    summary.qtype,
                    summary.hop_count as i64,
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
                "SELECT id, created_at, qname, qtype, hop_count FROM sessions ORDER BY created_at DESC",
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::{TraceHop, TraceResult};

    fn sample_result() -> TraceResult {
        TraceResult {
            qname: "example.com.".into(),
            qtype: "A".into(),
            started_at: "2026-08-25T00:00:00Z".into(),
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

    #[test]
    fn round_trip_session() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sessions.sqlite");
        let mut store = SqliteSessionStore::open(&path).expect("open");
        let id = store.save(&sample_result()).expect("save");
        let loaded = store.get(&id).expect("get");
        assert_eq!(loaded.result, sample_result());
    }
}
