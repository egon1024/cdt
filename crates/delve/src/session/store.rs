use dns_resolve::TraceResult;
use thiserror::Error;

use super::document::{SessionDocument, SessionSummary};
use super::id::{is_ambiguous_prefix, resolve_prefix};
use super::ndjson::NdjsonSessionStore;
use super::sqlite::SqliteSessionStore;
use crate::paths::DelvePaths;

pub type Result<T> = std::result::Result<T, SessionError>;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("session not found: {id}")]
    NotFound { id: String },

    #[error("ambiguous session id prefix: {prefix}")]
    AmbiguousPrefix { prefix: String },

    #[error("session store error: {0}")]
    Store(String),

    #[error("session serialization error: {0}")]
    Serialization(String),
}

pub trait SessionStore: Send {
    fn save(&mut self, result: &TraceResult) -> Result<String>;
    fn get(&self, id: &str) -> Result<SessionDocument>;
    fn list(&self) -> Result<Vec<SessionSummary>>;
    fn remove(&mut self, id: &str) -> Result<()>;
    fn all_ids(&self) -> Result<Vec<String>>;
}

pub struct OpenSessionStore {
    inner: Box<dyn SessionStore>,
}

impl SessionStore for OpenSessionStore {
    fn save(&mut self, result: &TraceResult) -> Result<String> {
        self.inner.save(result)
    }

    fn get(&self, id: &str) -> Result<SessionDocument> {
        let resolved = self.resolve_lookup_id(id)?;
        self.inner.get(&resolved)
    }

    fn list(&self) -> Result<Vec<SessionSummary>> {
        self.inner.list()
    }

    fn remove(&mut self, id: &str) -> Result<()> {
        let resolved = self.resolve_lookup_id(id)?;
        self.inner.remove(&resolved)
    }

    fn all_ids(&self) -> Result<Vec<String>> {
        self.inner.all_ids()
    }
}

impl OpenSessionStore {
    fn resolve_lookup_id(&self, prefix: &str) -> Result<String> {
        let ids = self.inner.all_ids()?;
        if ids.iter().any(|id| id == prefix) {
            return Ok(prefix.to_string());
        }
        if is_ambiguous_prefix(prefix, &ids) {
            return Err(SessionError::AmbiguousPrefix {
                prefix: prefix.to_string(),
            });
        }
        resolve_prefix(prefix, &ids).ok_or_else(|| SessionError::NotFound {
            id: prefix.to_string(),
        })
    }
}

pub fn open_session_store(paths: &DelvePaths) -> (OpenSessionStore, Option<String>) {
    let _ = paths.ensure_data_dirs();
    if let Ok(store) = SqliteSessionStore::open(&paths.sessions_db) {
        return (
            OpenSessionStore {
                inner: Box::new(store),
            },
            None,
        );
    }

    let warning = format!(
        "warning: sqlite session store unavailable at {}; using NDJSON files in {}",
        paths.sessions_db.display(),
        paths.sessions_dir.display()
    );
    let store = NdjsonSessionStore::open(&paths.sessions_dir)
        .unwrap_or_else(|error| NdjsonSessionStore::disabled(error.to_string()));
    (
        OpenSessionStore {
            inner: Box::new(store),
        },
        Some(warning),
    )
}
