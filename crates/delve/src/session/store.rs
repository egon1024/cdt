use dns_resolve::TraceTree;
use thiserror::Error;

use crate::config::SessionRetention;
use crate::retention::PurgeReport;
use crate::trace_request::TraceRequest;

use super::bundle::SessionBundle;
use super::document::{SessionDocument, SessionListItem, session_content_eq};
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

    #[error("no sessions stored; run a trace or specify a session id")]
    NoSessions,

    #[error("session {id} uses unsupported format version {version}")]
    UnsupportedFormat { id: String, version: u32 },

    #[error("unsupported legacy session store at {path}; remove or migrate the file")]
    UnsupportedLegacyStore { path: String },

    #[error("session {id} is frozen; thaw before modifying trace content")]
    Frozen { id: String },
}

pub(crate) fn assert_content_mutation_allowed(
    existing: &SessionDocument,
    incoming: &SessionDocument,
) -> Result<()> {
    if existing.frozen && !session_content_eq(existing, incoming) {
        return Err(SessionError::Frozen {
            id: existing.id.clone(),
        });
    }
    Ok(())
}

pub trait SessionStore: Send {
    fn save(&mut self, result: &TraceTree, request: &TraceRequest) -> Result<String>;
    fn save_document(&mut self, document: SessionDocument) -> Result<String>;
    fn update(&mut self, document: &SessionDocument) -> Result<()>;
    fn get(&self, id: &str) -> Result<SessionDocument>;
    fn list(&self) -> Result<Vec<SessionListItem>>;
    fn remove(&mut self, id: &str) -> Result<()>;
    fn all_ids(&self) -> Result<Vec<String>>;
    fn set_pinned(&mut self, id: &str, pinned: bool) -> Result<()>;
    fn set_frozen(&mut self, id: &str, frozen: bool) -> Result<()>;
    fn purge_by_retention(
        &mut self,
        retention: SessionRetention,
        dry_run: bool,
    ) -> Result<PurgeReport>;
    fn purge_session(&mut self, id: &str, dry_run: bool) -> Result<PurgeReport>;
    fn purge_all(&mut self, dry_run: bool) -> Result<PurgeReport>;
}

pub struct OpenSessionStore {
    inner: Box<dyn SessionStore>,
}

impl SessionStore for OpenSessionStore {
    fn save(&mut self, result: &TraceTree, request: &TraceRequest) -> Result<String> {
        self.inner.save(result, request)
    }

    fn save_document(&mut self, document: SessionDocument) -> Result<String> {
        self.inner.save_document(document)
    }

    fn update(&mut self, document: &SessionDocument) -> Result<()> {
        self.inner.update(document)
    }

    fn get(&self, id: &str) -> Result<SessionDocument> {
        let resolved = self.resolve_lookup_id(id)?;
        self.inner.get(&resolved)
    }

    fn list(&self) -> Result<Vec<SessionListItem>> {
        self.inner.list()
    }

    fn remove(&mut self, id: &str) -> Result<()> {
        let resolved = self.resolve_lookup_id(id)?;
        self.inner.remove(&resolved)
    }

    fn all_ids(&self) -> Result<Vec<String>> {
        self.inner.all_ids()
    }

    fn set_pinned(&mut self, id: &str, pinned: bool) -> Result<()> {
        let resolved = self.resolve_lookup_id(id)?;
        self.inner.set_pinned(&resolved, pinned)
    }

    fn set_frozen(&mut self, id: &str, frozen: bool) -> Result<()> {
        let resolved = self.resolve_lookup_id(id)?;
        self.inner.set_frozen(&resolved, frozen)
    }

    fn purge_by_retention(
        &mut self,
        retention: SessionRetention,
        dry_run: bool,
    ) -> Result<PurgeReport> {
        self.inner.purge_by_retention(retention, dry_run)
    }

    fn purge_session(&mut self, id: &str, dry_run: bool) -> Result<PurgeReport> {
        let resolved = self.resolve_lookup_id(id)?;
        self.inner.purge_session(&resolved, dry_run)
    }

    fn purge_all(&mut self, dry_run: bool) -> Result<PurgeReport> {
        self.inner.purge_all(dry_run)
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

    pub fn export_sessions(&self, ids: &[String]) -> Result<SessionBundle> {
        let mut sessions = Vec::with_capacity(ids.len());
        for id in ids {
            sessions.push(self.get(id)?);
        }
        Ok(SessionBundle::new(sessions))
    }

    pub fn export_all_sessions(&self) -> Result<SessionBundle> {
        let ids = self.all_ids()?;
        let mut sessions = Vec::with_capacity(ids.len());
        for id in ids {
            sessions.push(self.inner.get(&id)?);
        }
        Ok(SessionBundle::new(sessions))
    }
}

pub struct OpenSessionReport {
    pub store: OpenSessionStore,
    pub fallback_warning: Option<String>,
    pub purge_report: PurgeReport,
}

pub fn open_session_store(paths: &DelvePaths, retention: SessionRetention) -> OpenSessionReport {
    let _ = paths.ensure_data_dirs();
    let (inner, fallback_warning) = if let Ok(store) = SqliteSessionStore::open(&paths.sessions_db)
    {
        (Box::new(store) as Box<dyn SessionStore>, None)
    } else {
        let warning = format!(
            "warning: sqlite session store unavailable at {}; using NDJSON files in {}",
            paths.sessions_db.display(),
            paths.sessions_dir.display()
        );
        let store = NdjsonSessionStore::open(&paths.sessions_dir)
            .unwrap_or_else(|error| NdjsonSessionStore::disabled(error.to_string()));
        (Box::new(store) as Box<dyn SessionStore>, Some(warning))
    };

    let mut store = OpenSessionStore { inner };
    let purge_report = store
        .purge_by_retention(retention, false)
        .unwrap_or(PurgeReport {
            removed: 0,
            skipped_unparseable: 0,
        });

    OpenSessionReport {
        store,
        fallback_warning,
        purge_report,
    }
}
