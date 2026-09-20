use super::document::{SESSION_FORMAT_VERSION, SessionDocument, now_rfc3339};
use super::id::new_session_id;
use super::store::{OpenSessionStore, Result, SessionError, SessionStore};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportPolicy {
    Skip,
    Replace,
    Reassign,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportSessionOptions {
    pub policy: ImportPolicy,
    pub force: bool,
    pub pin: bool,
    pub touch: bool,
    pub frozen: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportSessionStatus {
    Imported { id: String },
    Replaced { id: String },
    Reassigned { original_id: String, id: String },
    Skipped { id: String, reason: String },
    Failed { id: String, error: String },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct NoReplayNotice {
    pub id: String,
    pub reasons: Vec<String>,
}

impl SessionDocument {
    pub fn replay_notice_reasons(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if self.trees.len() > 1 {
            reasons.push("multi_tree".into());
        }
        if self.has_branches() {
            reasons.push("branched".into());
        }
        reasons
    }
}

fn apply_import_mutations(document: &mut SessionDocument, options: &ImportSessionOptions) {
    if options.pin {
        document.pinned = true;
    }
    if options.touch {
        document.updated_at = now_rfc3339();
    }
    if options.frozen {
        document.frozen = true;
    }
}

impl OpenSessionStore {
    pub fn import_session(
        &mut self,
        mut document: SessionDocument,
        options: ImportSessionOptions,
    ) -> Result<ImportSessionStatus> {
        let id = document.id.clone();
        if document.version != SESSION_FORMAT_VERSION {
            return Ok(ImportSessionStatus::Failed {
                id,
                error: format!(
                    "unsupported session format version {}; expected {SESSION_FORMAT_VERSION}",
                    document.version
                ),
            });
        }

        apply_import_mutations(&mut document, &options);

        match options.policy {
            ImportPolicy::Reassign => {
                let original_id = document.id.clone();
                document.id = new_session_id();
                let stored_id = self.save_document(document)?;
                Ok(ImportSessionStatus::Reassigned {
                    original_id,
                    id: stored_id,
                })
            }
            ImportPolicy::Skip => match self.get(&id) {
                Ok(_) => Ok(ImportSessionStatus::Skipped {
                    id,
                    reason: "session id already exists".into(),
                }),
                Err(SessionError::NotFound { .. }) => {
                    let stored_id = self.save_document(document)?;
                    Ok(ImportSessionStatus::Imported { id: stored_id })
                }
                Err(error) => Err(error),
            },
            ImportPolicy::Replace => match self.get(&id) {
                Ok(existing) => {
                    if existing.frozen && !options.force {
                        return Ok(ImportSessionStatus::Failed {
                            id: id.clone(),
                            error: format!(
                                "session {id} is frozen locally; export a backup or use --force with --replace"
                            ),
                        });
                    }
                    self.upsert_document(document)?;
                    Ok(ImportSessionStatus::Replaced { id })
                }
                Err(SessionError::NotFound { .. }) => {
                    let stored_id = self.save_document(document)?;
                    Ok(ImportSessionStatus::Imported { id: stored_id })
                }
                Err(error) => Err(error),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace_request::TraceRequest;
    use dns_resolve::{HopOutcome, TraceHop, TraceTreeRequest, build_linear_tree};

    use super::super::ndjson::NdjsonSessionStore;
    use super::super::sqlite::SqliteSessionStore;
    use super::super::store::SessionStore;

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

    fn with_store<F>(backend: &str, test: F)
    where
        F: FnOnce(&mut OpenSessionStore),
    {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = match backend {
            "sqlite" => {
                let path = dir.path().join("sessions.sqlite");
                OpenSessionStore::from_inner(Box::new(
                    SqliteSessionStore::open(&path).expect("open sqlite"),
                ))
            }
            "ndjson" => OpenSessionStore::from_inner(Box::new(
                NdjsonSessionStore::open(&dir.path().join("sessions")).expect("open ndjson"),
            )),
            other => panic!("unknown backend {other}"),
        };
        test(&mut store);
    }

    #[test]
    fn import_skip_policy_on_both_backends() {
        for backend in ["sqlite", "ndjson"] {
            with_store(backend, |store| {
                let document = sample_document("01IMPORTSKIP");
                store.save_document(document.clone()).expect("seed");
                let status = store
                    .import_session(
                        document,
                        ImportSessionOptions {
                            policy: ImportPolicy::Skip,
                            force: false,
                            pin: false,
                            touch: false,
                            frozen: false,
                        },
                    )
                    .expect("import");
                assert!(matches!(
                    status,
                    ImportSessionStatus::Skipped { ref id, .. } if id == "01IMPORTSKIP"
                ));
            });
        }
    }

    #[test]
    fn import_replace_and_reassign_on_both_backends() {
        for backend in ["sqlite", "ndjson"] {
            with_store(backend, |store| {
                let mut document = sample_document("01IMPORTBASE");
                store.save_document(document.clone()).expect("seed");
                document.trees[0].tree.root.hop.rtt_ms = 42;
                let status = store
                    .import_session(
                        document,
                        ImportSessionOptions {
                            policy: ImportPolicy::Replace,
                            force: false,
                            pin: false,
                            touch: false,
                            frozen: false,
                        },
                    )
                    .expect("replace");
                assert!(matches!(
                    status,
                    ImportSessionStatus::Replaced { ref id } if id == "01IMPORTBASE"
                ));
                assert_eq!(
                    store.get("01IMPORTBASE").expect("get").trees[0]
                        .tree
                        .root
                        .hop
                        .rtt_ms,
                    42
                );

                let reassigned = store
                    .import_session(
                        sample_document("01IMPORTBASE"),
                        ImportSessionOptions {
                            policy: ImportPolicy::Reassign,
                            force: false,
                            pin: false,
                            touch: false,
                            frozen: false,
                        },
                    )
                    .expect("reassign");
                let new_id = match reassigned {
                    ImportSessionStatus::Reassigned { id, .. } => id,
                    other => panic!("expected reassigned, got {other:?}"),
                };
                assert_ne!(new_id, "01IMPORTBASE");
                assert!(store.get(&new_id).is_ok());
            });
        }
    }

    #[test]
    fn import_rejects_non_v2_document() {
        with_store("sqlite", |store| {
            let mut document = sample_document("01IMPORTV1");
            document.version = 1;
            let status = store
                .import_session(
                    document,
                    ImportSessionOptions {
                        policy: ImportPolicy::Skip,
                        force: false,
                        pin: false,
                        touch: false,
                        frozen: false,
                    },
                )
                .expect("import");
            assert!(matches!(status, ImportSessionStatus::Failed { .. }));
            assert!(store.get("01IMPORTV1").is_err());
        });
    }

    #[test]
    fn import_applies_pin_touch_and_frozen_mutations() {
        with_store("sqlite", |store| {
            let document = sample_document("01IMPORTMUT");
            let status = store
                .import_session(
                    document,
                    ImportSessionOptions {
                        policy: ImportPolicy::Skip,
                        force: false,
                        pin: true,
                        touch: true,
                        frozen: true,
                    },
                )
                .expect("import");
            assert!(matches!(
                status,
                ImportSessionStatus::Imported { ref id } if id == "01IMPORTMUT"
            ));
            let stored = store.get("01IMPORTMUT").expect("get");
            assert!(stored.pinned);
            assert!(stored.frozen);
            assert_ne!(stored.updated_at, "2026-08-25T00:00:00Z");
        });
    }

    #[test]
    fn import_replace_refuses_local_frozen_without_force() {
        with_store("sqlite", |store| {
            let document = sample_document("01IMPORTFRZ");
            store.save_document(document.clone()).expect("seed");
            store.set_frozen("01IMPORTFRZ", true).expect("freeze");
            let status = store
                .import_session(
                    document,
                    ImportSessionOptions {
                        policy: ImportPolicy::Replace,
                        force: false,
                        pin: false,
                        touch: false,
                        frozen: false,
                    },
                )
                .expect("import");
            assert!(matches!(status, ImportSessionStatus::Failed { .. }));
            assert_eq!(
                store.get("01IMPORTFRZ").expect("get").trees[0]
                    .tree
                    .root
                    .hop
                    .rtt_ms,
                10
            );

            let mut replacement = sample_document("01IMPORTFRZ");
            replacement.trees[0].tree.root.hop.rtt_ms = 99;
            let forced = store
                .import_session(
                    replacement,
                    ImportSessionOptions {
                        policy: ImportPolicy::Replace,
                        force: true,
                        pin: false,
                        touch: false,
                        frozen: false,
                    },
                )
                .expect("force replace");
            assert!(matches!(forced, ImportSessionStatus::Replaced { .. }));
            assert_eq!(
                store.get("01IMPORTFRZ").expect("get").trees[0]
                    .tree
                    .root
                    .hop
                    .rtt_ms,
                99
            );
        });
    }

    #[test]
    fn import_bundle_continues_after_non_v2_session() {
        with_store("sqlite", |store| {
            let mut bad = sample_document("01BAD");
            bad.version = 1;
            let good = sample_document("01GOOD");
            let outcomes = [
                store.import_session(
                    bad,
                    ImportSessionOptions {
                        policy: ImportPolicy::Skip,
                        force: false,
                        pin: false,
                        touch: false,
                        frozen: false,
                    },
                ),
                store.import_session(
                    good,
                    ImportSessionOptions {
                        policy: ImportPolicy::Skip,
                        force: false,
                        pin: false,
                        touch: false,
                        frozen: false,
                    },
                ),
            ];
            assert!(matches!(
                outcomes[0].as_ref().expect("bad"),
                ImportSessionStatus::Failed { .. }
            ));
            assert!(matches!(
                outcomes[1].as_ref().expect("good"),
                ImportSessionStatus::Imported { .. }
            ));
            assert!(store.get("01GOOD").is_ok());
        });
    }
}
