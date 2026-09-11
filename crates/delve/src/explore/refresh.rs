use dns_resolve::{RefreshProgress, RefreshTreeReport, refresh_tree_rtts};

use crate::enrichment::{IcmpRefreshReport, refresh_icmp_targets_with_prober};
use crate::runtime::Runtime;
use crate::session::{SessionDocument, SessionError};
use crate::trace_config::{TraceConfigError, trace_config_from_request};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshScope {
    All,
    #[expect(dead_code)]
    DnsRttOnly,
    #[expect(dead_code)]
    IcmpOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnifiedRefreshReport {
    pub dns: Option<RefreshTreeReport>,
    pub icmp: Option<IcmpRefreshReport>,
}

impl UnifiedRefreshReport {
    pub fn has_unsaved_changes(&self) -> bool {
        self.dns
            .as_ref()
            .is_some_and(|report| report.hops_updated > 0)
            || self
                .icmp
                .as_ref()
                .is_some_and(|report| report.targets_updated > 0)
    }
}

pub trait UnifiedRefreshProgress: Send {
    fn dns_hop_started(&mut self, current: usize, total: usize);
    fn icmp_target_started(&mut self, current: usize, total: usize);
}

struct DnsProgressAdapter<'a>(&'a mut dyn UnifiedRefreshProgress);

impl RefreshProgress for DnsProgressAdapter<'_> {
    fn hop_started(&mut self, current: usize, total: usize) {
        self.0.dns_hop_started(current, total);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RefreshError {
    #[error(transparent)]
    TraceConfig(#[from] TraceConfigError),

    #[error(transparent)]
    Session(#[from] SessionError),

    #[error("session has no trace tree")]
    NoTree,
}

#[expect(dead_code)]
pub fn refresh_document_tree(
    document: &mut SessionDocument,
    runtime: &Runtime,
    progress: &mut dyn RefreshProgress,
) -> Result<RefreshTreeReport, RefreshError> {
    let session_tree = document.trees.get_mut(0).ok_or(RefreshError::NoTree)?;
    let request = session_tree.request.clone();
    let mut config = trace_config_from_request(
        &request,
        runtime.cache.clone(),
        runtime.config.trace_max_queries_per_action,
        runtime.config.trace_max_parallel_queries,
    )?;
    config.use_cache = false;
    Ok(refresh_tree_rtts(&mut session_tree.tree, &config, progress))
}

pub fn refresh_document(
    document: &mut SessionDocument,
    runtime: &Runtime,
    scope: RefreshScope,
    explore_plus_icmp: bool,
    progress: &mut dyn UnifiedRefreshProgress,
) -> Result<UnifiedRefreshReport, RefreshError> {
    let effective_icmp = runtime.config.effective_icmp_enabled(explore_plus_icmp);
    let dns = match scope {
        RefreshScope::All | RefreshScope::DnsRttOnly => {
            Some(refresh_document_dns(document, runtime, progress)?)
        }
        RefreshScope::IcmpOnly => None,
    };
    let icmp = match scope {
        RefreshScope::All | RefreshScope::IcmpOnly => Some(refresh_targets_icmp(
            document,
            runtime,
            effective_icmp,
            progress,
        )),
        RefreshScope::DnsRttOnly => None,
    };
    Ok(UnifiedRefreshReport { dns, icmp })
}

fn refresh_document_dns(
    document: &mut SessionDocument,
    runtime: &Runtime,
    progress: &mut dyn UnifiedRefreshProgress,
) -> Result<RefreshTreeReport, RefreshError> {
    let session_tree = document.trees.get_mut(0).ok_or(RefreshError::NoTree)?;
    let request = session_tree.request.clone();
    let mut config = trace_config_from_request(
        &request,
        runtime.cache.clone(),
        runtime.config.trace_max_queries_per_action,
        runtime.config.trace_max_parallel_queries,
    )?;
    config.use_cache = false;
    let mut adapter = DnsProgressAdapter(progress);
    Ok(refresh_tree_rtts(
        &mut session_tree.tree,
        &config,
        &mut adapter,
    ))
}

pub fn refresh_targets_icmp(
    document: &mut SessionDocument,
    runtime: &Runtime,
    effective_icmp: bool,
    progress: &mut dyn UnifiedRefreshProgress,
) -> IcmpRefreshReport {
    refresh_icmp_targets_with_prober(
        document,
        runtime,
        effective_icmp,
        dns_resolve::comparison_icmp_prober(),
        |current, total| progress.icmp_target_started(current, total),
    )
}

pub fn persist_refreshed_tree(
    runtime: &Runtime,
    document: &SessionDocument,
) -> Result<(), SessionError> {
    runtime.update_session(document)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::{HopOutcome, TraceHop, TraceTreeRequest, build_linear_tree};

    use crate::dig_options::TraceOptions;
    use crate::paths::DelvePaths;
    use crate::runtime::Runtime;
    use crate::trace_request::TraceRequest;

    struct RecordingProgress {
        dns: Vec<(usize, usize)>,
        icmp: Vec<(usize, usize)>,
    }

    impl RecordingProgress {
        fn new() -> Self {
            Self {
                dns: Vec::new(),
                icmp: Vec::new(),
            }
        }
    }

    impl UnifiedRefreshProgress for RecordingProgress {
        fn dns_hop_started(&mut self, current: usize, total: usize) {
            self.dns.push((current, total));
        }

        fn icmp_target_started(&mut self, current: usize, total: usize) {
            self.icmp.push((current, total));
        }
    }

    fn sample_document() -> SessionDocument {
        SessionDocument::new(
            "01REFRESH".into(),
            TraceRequest::from_options(&TraceOptions {
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
                    started_at: "2026-09-06T00:00:00Z".into(),
                },
            ),
        )
    }

    #[test]
    fn refresh_scope_all_skips_icmp_without_effective_icmp() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = Runtime::open(DelvePaths::from_root(dir.path()));
        let mut document = sample_document();
        let mut progress = RecordingProgress::new();
        let report = refresh_document(
            &mut document,
            &runtime,
            RefreshScope::All,
            false,
            &mut progress,
        )
        .expect("refresh");
        assert!(report.dns.is_some());
        assert_eq!(report.icmp.as_ref().map(|icmp| icmp.targets_total), Some(0));
        assert!(progress.icmp.is_empty());
    }

    #[test]
    fn refresh_scope_all_runs_icmp_with_explore_plus_icmp() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = Runtime::open(DelvePaths::from_root(dir.path()));
        let mut document = sample_document();
        let mut progress = RecordingProgress::new();
        let report = refresh_document(
            &mut document,
            &runtime,
            RefreshScope::All,
            true,
            &mut progress,
        )
        .expect("refresh");
        assert!(report.dns.is_some());
        assert!(report.icmp.is_some());
        assert!(!progress.icmp.is_empty());
    }

    #[test]
    fn refresh_scope_all_runs_dns_then_icmp() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut runtime = Runtime::open(DelvePaths::from_root(dir.path()));
        runtime.config.enrichment_icmp_enabled = true;
        let mut document = sample_document();
        let mut progress = RecordingProgress::new();
        let report = refresh_document(
            &mut document,
            &runtime,
            RefreshScope::All,
            false,
            &mut progress,
        )
        .expect("refresh");
        assert!(report.dns.is_some());
        assert!(report.icmp.is_some());
        assert!(!progress.dns.is_empty());
        assert!(!progress.icmp.is_empty());
    }

    #[test]
    fn unified_refresh_bypasses_icmp_cache_read() {
        use dns_enrichment_cache::now_unix;
        use dns_resolve::{IcmpMethod, IcmpSnapshot};
        use std::net::IpAddr;
        use std::sync::Mutex;

        use crate::enrichment::{TraceEnrichmentProber, probe_profile};
        use crate::session::TargetEnrichments;

        struct MockProber {
            calls: Mutex<Vec<IpAddr>>,
        }

        impl TraceEnrichmentProber for MockProber {
            fn probe_snapshot(
                &self,
                ip: IpAddr,
                _timeout_ms: u64,
                _ping_samples: u8,
                _probed_at: &str,
            ) -> Option<IcmpSnapshot> {
                self.calls.lock().expect("lock").push(ip);
                Some(IcmpSnapshot {
                    method: IcmpMethod::Datagram,
                    samples: 1,
                    min_ms: 42,
                    avg_ms: 42,
                    max_ms: 42,
                    probed_at: "2026-09-06T00:00:00Z".into(),
                })
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let mut runtime = Runtime::open(DelvePaths::from_root(dir.path()));
        runtime.config.enrichment_icmp_enabled = true;
        let ip: IpAddr = "1.1.1.1".parse().expect("ip");
        let cache = runtime.enrichment_cache.as_ref().expect("cache");
        let profile = probe_profile(&runtime);
        cache
            .put_icmp(
                ip,
                &profile,
                &IcmpSnapshot {
                    method: IcmpMethod::Datagram,
                    samples: 1,
                    min_ms: 1,
                    avg_ms: 1,
                    max_ms: 1,
                    probed_at: "2026-09-06T00:00:00Z".into(),
                },
                now_unix(),
            )
            .expect("seed cache");

        let mut document = sample_document();
        document.targets.insert(
            ip,
            TargetEnrichments {
                icmp: Some(IcmpSnapshot {
                    method: IcmpMethod::Datagram,
                    samples: 1,
                    min_ms: 1,
                    avg_ms: 1,
                    max_ms: 1,
                    probed_at: "2026-09-06T00:00:00Z".into(),
                }),
                ..Default::default()
            },
        );

        let prober = MockProber {
            calls: Mutex::new(Vec::new()),
        };
        let report =
            refresh_icmp_targets_with_prober(&mut document, &runtime, true, &prober, |_, _| {});
        assert_eq!(report.targets_updated, 1);
        assert_eq!(
            document
                .targets
                .get(&ip)
                .and_then(|entry| entry.icmp.as_ref())
                .map(|snapshot| snapshot.avg_ms),
            Some(42)
        );
        assert_eq!(*prober.calls.lock().expect("lock"), vec![ip]);
    }

    #[test]
    fn explore_plus_icmp_refresh_persists_targets() {
        use dns_resolve::{IcmpMethod, IcmpSnapshot};
        use std::net::IpAddr;

        use crate::enrichment::TraceEnrichmentProber;

        struct MockProber;

        impl TraceEnrichmentProber for MockProber {
            fn probe_snapshot(
                &self,
                _ip: IpAddr,
                _timeout_ms: u64,
                _ping_samples: u8,
                _probed_at: &str,
            ) -> Option<IcmpSnapshot> {
                Some(IcmpSnapshot {
                    method: IcmpMethod::Datagram,
                    samples: 1,
                    min_ms: 55,
                    avg_ms: 55,
                    max_ms: 55,
                    probed_at: "2026-09-06T00:00:00Z".into(),
                })
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = Runtime::open(DelvePaths::from_root(dir.path()));
        let seed = sample_document();
        let id = runtime
            .save_session(
                seed.primary_tree().expect("tree"),
                seed.primary_request().expect("request"),
                false,
            )
            .expect("seed");
        let mut document = runtime.get_session(&id).expect("load");
        let report =
            refresh_icmp_targets_with_prober(&mut document, &runtime, true, &MockProber, |_, _| {});
        assert_eq!(report.targets_updated, 1);
        persist_refreshed_tree(&runtime, &document).expect("persist");
        let loaded = runtime.get_session(&id).expect("reload");
        let ip: IpAddr = "1.1.1.1".parse().expect("ip");
        assert_eq!(
            loaded
                .targets
                .get(&ip)
                .and_then(|entry| entry.icmp.as_ref())
                .map(|snapshot| snapshot.avg_ms),
            Some(55)
        );
    }

    #[test]
    fn persist_refreshed_tree_writes_targets() {
        use dns_resolve::{IcmpMethod, IcmpSnapshot};
        use std::net::IpAddr;

        use crate::session::TargetEnrichments;

        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = Runtime::open(DelvePaths::from_root(dir.path()));
        let document = sample_document();
        let id = runtime
            .save_session(
                document.primary_tree().expect("tree"),
                document.primary_request().expect("request"),
                false,
            )
            .expect("seed");
        let mut document = runtime.get_session(&id).expect("load");
        let ip: IpAddr = "1.1.1.1".parse().expect("ip");
        document.targets.insert(
            ip,
            TargetEnrichments {
                icmp: Some(IcmpSnapshot {
                    method: IcmpMethod::Datagram,
                    samples: 1,
                    min_ms: 99,
                    avg_ms: 99,
                    max_ms: 99,
                    probed_at: "2026-09-06T00:00:00Z".into(),
                }),
                ..Default::default()
            },
        );
        persist_refreshed_tree(&runtime, &document).expect("persist");
        let loaded = runtime.get_session(&id).expect("load");
        assert_eq!(
            loaded
                .targets
                .get(&ip)
                .and_then(|entry| entry.icmp.as_ref())
                .map(|snapshot| snapshot.avg_ms),
            Some(99)
        );
    }
}
