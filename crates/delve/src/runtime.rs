use std::sync::{Arc, Mutex};

use dns_cache::{ResponseCache, SqliteCache};
use dns_resolve::TraceTree;

use crate::config::DelveConfig;
use crate::last_session::{clear_last_session, read_last_session, write_last_session};
use crate::paths::DelvePaths;
use crate::retention::retention_label;
use crate::session::SessionStore;
use crate::session::{
    OpenSessionStore, SessionDocument, SessionError, SessionSummary, open_session_store,
};
use crate::trace_request::TraceRequest;

pub struct Runtime {
    pub paths: DelvePaths,
    pub config: DelveConfig,
    pub cache: Option<Arc<dyn ResponseCache>>,
    sessions: Mutex<OpenSessionStore>,
    pub warnings: Vec<String>,
}

impl Runtime {
    pub fn open_platform() -> Self {
        Self::open(DelvePaths::platform())
    }

    pub fn open(paths: DelvePaths) -> Self {
        let (config, config_warnings) = DelveConfig::load(&paths);
        let mut warnings = config_warnings;
        let session_report = open_session_store(&paths, config.session_retention);
        if let Some(warning) = session_report.fallback_warning {
            warnings.push(warning);
        }
        if session_report.purge_report.removed > 0 {
            warnings.push(format!(
                "purged {} sessions older than {}",
                session_report.purge_report.removed,
                retention_label(config.session_retention),
            ));
        }
        if session_report.purge_report.skipped_unparseable > 0 {
            warnings.push(format!(
                "warning: skipped {} sessions with unparseable timestamps during retention purge",
                session_report.purge_report.skipped_unparseable
            ));
        }

        let cache = match paths.ensure_cache_dir() {
            Ok(()) => match SqliteCache::open(&paths.cache_db) {
                Ok(cache) => Some(Arc::new(cache) as Arc<dyn ResponseCache>),
                Err(error) => {
                    warnings.push(format!(
                        "warning: response cache unavailable at {}: {}",
                        paths.cache_db.display(),
                        error
                    ));
                    None
                }
            },
            Err(error) => {
                warnings.push(format!(
                    "warning: response cache unavailable at {}: {}",
                    paths.cache_db.display(),
                    error
                ));
                None
            }
        };

        Self {
            paths,
            config,
            cache,
            sessions: Mutex::new(session_report.store),
            warnings,
        }
    }

    pub fn emit_warnings(&self) {
        for warning in &self.warnings {
            eprintln!("{warning}");
        }
    }

    pub fn save_session(
        &self,
        result: &TraceTree,
        request: &TraceRequest,
    ) -> Result<String, SessionError> {
        self.sessions
            .lock()
            .expect("session lock")
            .save(result, request)
    }

    pub fn find_matching_session(
        &self,
        request: &TraceRequest,
    ) -> Result<Option<SessionDocument>, SessionError> {
        for summary in self.list_sessions()? {
            let document = self.get_session(&summary.id)?;
            if document.request.as_ref() == Some(request) {
                return Ok(Some(document));
            }
        }
        Ok(None)
    }

    pub fn remember_session(&self, id: &str) -> Result<(), SessionError> {
        write_last_session(&self.paths, id)
    }

    pub fn last_session_id(&self) -> Result<String, SessionError> {
        read_last_session(&self.paths)
    }

    pub fn forget_last_session(&self) -> Result<(), SessionError> {
        clear_last_session(&self.paths)
    }

    pub fn touch_session(&self, id: &str) -> Result<SessionDocument, SessionError> {
        let document = self.get_session(id)?;
        self.remember_session(&document.id)?;
        Ok(document)
    }

    pub fn get_session(&self, id: &str) -> Result<SessionDocument, SessionError> {
        self.sessions.lock().expect("session lock").get(id)
    }

    pub fn list_sessions(&self) -> Result<Vec<SessionSummary>, SessionError> {
        self.sessions.lock().expect("session lock").list()
    }

    pub fn remove_session(&self, id: &str) -> Result<(), SessionError> {
        let resolved = self.get_session(id)?;
        self.sessions
            .lock()
            .expect("session lock")
            .remove(&resolved.id)?;
        if self.last_session_id().ok().as_deref() == Some(resolved.id.as_str()) {
            let _ = self.forget_last_session();
        }
        Ok(())
    }

    pub fn pin_session(&self, id: &str) -> Result<(), SessionError> {
        self.sessions
            .lock()
            .expect("session lock")
            .set_pinned(id, true)
    }

    pub fn unpin_session(&self, id: &str) -> Result<(), SessionError> {
        self.sessions
            .lock()
            .expect("session lock")
            .set_pinned(id, false)
    }

    pub fn purge_sessions(
        &self,
        dry_run: bool,
    ) -> Result<crate::retention::PurgeReport, SessionError> {
        self.sessions
            .lock()
            .expect("session lock")
            .purge_by_retention(self.config.session_retention, dry_run)
    }
}

#[cfg(test)]
mod degradation_tests {
    use super::*;
    use crate::session::SessionStore;
    use crate::trace_request::TraceRequest;
    use dns_resolve::{HopOutcome, TraceHop, TraceTree, TraceTreeRequest, build_linear_tree};

    fn empty_tree(started_at: &str) -> TraceTree {
        build_linear_tree(
            vec![TraceHop {
                zone: ".".into(),
                server: "1.1.1.1".into(),
                server_name: None,
                qname: "example.com.".into(),
                qtype: "A".into(),
                transport: "udp".into(),
                rtt_ms: 1,
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
    fn falls_back_to_ndjson_when_sessions_db_unwritable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = DelvePaths::from_root(dir.path());
        std::fs::create_dir_all(&paths.data_dir).expect("data dir");
        let sessions_db = paths.data_dir.join("sessions.sqlite");
        std::fs::write(&sessions_db, "not sqlite").expect("write");
        let report =
            crate::session::open_session_store(&paths, crate::config::SessionRetention::Never);
        assert!(report.fallback_warning.is_some());
        let mut store = report.store;
        let id = store
            .save(&empty_tree("2026-08-25T00:00:00Z"), &sample_request())
            .expect("save via ndjson");
        assert!(store.get(&id).is_ok());
    }

    #[test]
    fn warns_when_cache_db_corrupt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = DelvePaths::from_root(dir.path());
        std::fs::create_dir_all(&paths.cache_dir).expect("cache dir");
        std::fs::write(&paths.cache_db, "corrupt").expect("write corrupt");
        let runtime = Runtime::open(paths);
        assert!(runtime.cache.is_none());
        assert!(
            runtime
                .warnings
                .iter()
                .any(|w| w.contains("response cache"))
        );
    }

    #[test]
    fn find_matching_session_returns_most_recent_match() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = DelvePaths::from_root(dir.path());
        let runtime = Runtime::open(paths);
        let request = sample_request();
        let first = runtime
            .save_session(&empty_tree("2026-08-25T00:00:00Z"), &request)
            .expect("first");
        let second = runtime
            .save_session(&empty_tree("2026-08-25T01:00:00Z"), &request)
            .expect("second");
        let matched = runtime
            .find_matching_session(&request)
            .expect("find")
            .expect("some");
        assert_eq!(matched.id, second);
        assert_ne!(matched.id, first);
    }

    #[test]
    fn remember_session_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = DelvePaths::from_root(dir.path());
        let runtime = Runtime::open(paths);
        runtime.remember_session("01JTEST").expect("remember");
        assert_eq!(runtime.last_session_id().expect("last"), "01JTEST");
    }
}
