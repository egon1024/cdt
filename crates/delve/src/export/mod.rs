mod card;
mod layout_tree;
mod svg;

use dns_resolve::TraceTree;

use crate::config::RttBarConfig;

pub use card::{HopCard, build_cards, path_attribute};
pub use layout_tree::{TreeEdge, TreeLayout, layout_tree};
pub use svg::{SvgTitle, render_tree_svg};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExportLayout {
    #[default]
    Tree,
    Icicle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExportFormat {
    #[default]
    Svg,
    Png,
}

pub struct ExportOptions {
    pub layout: ExportLayout,
    pub format: ExportFormat,
    pub title: SvgTitle,
    pub rtt_config: RttBarConfig,
}

pub fn render_trace_tree(
    tree: &TraceTree,
    tree_index: usize,
    options: &ExportOptions,
) -> Result<String, ExportError> {
    match options.format {
        ExportFormat::Svg => match options.layout {
            ExportLayout::Tree => {
                let cards = build_cards(tree, tree_index);
                let layout = layout_tree(&cards, tree);
                Ok(render_tree_svg(
                    &cards,
                    &layout,
                    &options.title,
                    options.rtt_config,
                ))
            }
            ExportLayout::Icicle => Err(ExportError::UnsupportedLayout("icicle")),
        },
        ExportFormat::Png => Err(ExportError::UnsupportedFormat("png")),
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExportError {
    #[error("layout {0} is not implemented yet")]
    UnsupportedLayout(&'static str),

    #[error("format {0} is not available in this build")]
    UnsupportedFormat(&'static str),

    #[error("tree index {0} is out of range")]
    TreeIndexOutOfRange(usize),
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::{HopOutcome, TraceHop, TraceTreeRequest, build_linear_tree};

    #[test]
    fn render_trace_tree_produces_svg() {
        let tree = build_linear_tree(
            vec![TraceHop {
                zone: ".".into(),
                server: "198.41.0.4".into(),
                server_name: None,
                qname: "example.com.".into(),
                qtype: "A".into(),
                transport: "udp".into(),
                rtt_ms: 11,
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
                started_at: "2026-01-01T00:00:00Z".into(),
            },
        );
        let svg = render_trace_tree(
            &tree,
            0,
            &ExportOptions {
                layout: ExportLayout::Tree,
                format: ExportFormat::Svg,
                title: SvgTitle {
                    primary: "test".into(),
                    secondary: None,
                },
                rtt_config: RttBarConfig::default(),
            },
        )
        .expect("svg");
        assert!(svg.starts_with("<svg"));
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::default_session::DELVE_SESSION_ENV;
    use crate::paths::DelvePaths;
    use crate::runtime::Runtime;
    use crate::trace_request::TraceRequest;
    use dns_resolve::{HopOutcome, TraceHop, TraceTreeRequest, build_linear_tree};

    fn save_sample_session(runtime: &Runtime) -> String {
        let request = TraceRequest::from_options(&crate::dig_options::TraceOptions {
            qname: "example.com".into(),
            ..Default::default()
        });
        let tree = build_linear_tree(
            vec![TraceHop {
                zone: ".".into(),
                server: "198.41.0.4".into(),
                server_name: Some("a.root-servers.net".into()),
                qname: "example.com.".into(),
                qtype: "A".into(),
                transport: "udp".into(),
                rtt_ms: 11,
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
                started_at: "2026-01-01T00:00:00Z".into(),
            },
        );
        runtime.save_session(&tree, &request).expect("save")
    }

    #[test]
    fn session_export_writes_svg_file_from_fixture() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = Runtime::open(DelvePaths::from_root(dir.path()));
        let id = save_sample_session(&runtime);
        let document = runtime.get_session(&id).expect("session");
        let tree = document.primary_tree().expect("tree");
        let svg = render_trace_tree(
            tree,
            0,
            &ExportOptions {
                layout: ExportLayout::Tree,
                format: ExportFormat::Svg,
                title: SvgTitle {
                    primary: format!("session {}", document.id),
                    secondary: None,
                },
                rtt_config: RttBarConfig::default(),
            },
        )
        .expect("svg");
        let output = dir.path().join("trace.svg");
        std::fs::write(&output, svg.as_bytes()).expect("write");
        let written = std::fs::read_to_string(&output).expect("read");
        assert!(written.starts_with("<svg"));
        assert!(written.contains("a.root-servers.net"));
        assert!(written.contains(r#"data-path="0""#));
    }

    #[test]
    fn export_uses_delve_session_default_resolution() {
        let dir = tempfile::tempdir().expect("tempdir");
        let runtime = Runtime::open(DelvePaths::from_root(dir.path()));
        let older = save_sample_session(&runtime);
        let newer = save_sample_session(&runtime);
        assert_ne!(older, newer);

        unsafe {
            std::env::set_var(DELVE_SESSION_ENV, &older);
        }
        let session_id = runtime.default_session_id().expect("default");
        assert_eq!(session_id, older);
        let document = runtime.get_session(&session_id).expect("session");
        let tree = document.primary_tree().expect("tree");
        let svg = render_trace_tree(
            tree,
            0,
            &ExportOptions {
                layout: ExportLayout::Tree,
                format: ExportFormat::Svg,
                title: SvgTitle {
                    primary: document.id.clone(),
                    secondary: None,
                },
                rtt_config: RttBarConfig::default(),
            },
        )
        .expect("svg");
        assert!(svg.contains("a.root-servers.net"));
        unsafe {
            std::env::remove_var(DELVE_SESSION_ENV);
        }
    }
}
