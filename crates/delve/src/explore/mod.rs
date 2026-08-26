mod detail;
mod dig_view;
mod flags;
mod json;
mod outline;
mod terminal;
mod theme;
mod tree;
mod tui;

pub use json::render_tree_json;
pub use outline::render_outline;
pub(crate) use terminal::{cache_source_symbol, ui_symbols};
pub use tree::build_explore_tree;
pub use tui::run_tui;

use crate::dig_options::ParseError;
use crate::session::SessionDocument;
use std::io::{self, IsTerminal, Write};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OutlineOptions {
    pub events: bool,
}

pub fn parse_outline_args(args: &[String]) -> Result<OutlineOptions, ParseError> {
    let mut options = OutlineOptions::default();
    for arg in args {
        match arg.as_str() {
            "+events" => options.events = true,
            "+noevents" => options.events = false,
            other if other.starts_with('+') => {
                return Err(ParseError::UnknownOption(other.to_string()));
            }
            other => return Err(ParseError::Unexpected(other.to_string())),
        }
    }
    Ok(options)
}

pub fn run_outline(
    document: &SessionDocument,
    options: OutlineOptions,
) -> Result<(), ExploreError> {
    let tree = build_explore_tree(&document.result);

    if options.events {
        println!("{}", render_tree_json(&tree, &document.id));
        return Ok(());
    }

    let outline = render_outline(&tree, ui_symbols());
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(outline.as_bytes())
        .map_err(ExploreError::Io)?;
    stdout.flush().map_err(ExploreError::Io)?;
    Ok(())
}

pub fn run_explore(document: &SessionDocument) -> Result<(), ExploreError> {
    if !io::stdout().is_terminal() {
        return Err(ExploreError::NotTerminal);
    }

    let tree = build_explore_tree(&document.result);
    run_tui(&tree).map_err(ExploreError::Io)
}

#[derive(Debug, thiserror::Error)]
pub enum ExploreError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("stdout is not a terminal; use `delve session outline` for a printable tree")]
    NotTerminal,
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::{FinalAnswer, TraceHop, TraceResult};

    #[test]
    fn parses_outline_flags() {
        let options = parse_outline_args(&["+events".into()]).expect("parse");
        assert!(options.events);

        let options = parse_outline_args(&["+noevents".into()]).expect("parse");
        assert!(!options.events);
    }

    #[test]
    fn rejects_unknown_outline_flags() {
        let error = parse_outline_args(&["+outline".into()]).expect_err("parse");
        assert!(matches!(error, ParseError::UnknownOption(option) if option == "+outline"));
    }

    #[test]
    fn run_outline_writes_tree() {
        let document = SessionDocument {
            version: 1,
            id: "01JTESTSESSION000000000000".into(),
            created_at: "2026-08-25T12:00:00Z".into(),
            pinned: false,
            request: None,
            result: TraceResult {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-08-25T12:00:00Z".into(),
                hops: vec![
                    TraceHop {
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
                        referral_ns: vec!["a.gtld-servers.net.".into()],
                        glue: vec![],
                        response: Default::default(),
                        from_cache: false,
                    },
                    TraceHop {
                        zone: "com.".into(),
                        server: "192.41.162.30".into(),
                        server_name: None,
                        qname: "example.com.".into(),
                        qtype: "A".into(),
                        transport: "udp".into(),
                        rtt_ms: 8,
                        rcode: "NOERROR".into(),
                        nsid: None,
                        ede_code: None,
                        ede_text: None,
                        referral_ns: vec![],
                        glue: vec![],
                        response: Default::default(),
                        from_cache: false,
                    },
                ],
                final_response: Some(FinalAnswer {
                    server: "93.184.216.34".into(),
                    server_name: None,
                    rtt_ms: 8,
                    rcode: "NOERROR".into(),
                    records: vec!["example.com. 300 93.184.216.34".into()],
                    nsid: None,
                    qname: String::new(),
                    qtype: String::new(),
                    transport: String::new(),
                    response: Default::default(),
                    from_cache: false,
                }),
            },
        };

        let tree = build_explore_tree(&document.result);
        let outline = render_outline(&tree, ui_symbols());
        assert!(outline.contains("example.com. A"));
        assert!(outline.contains("records:\n"));
        assert!(outline.contains("  - example.com. 300 93.184.216.34"));

        let json = render_tree_json(&tree, &document.id);
        assert!(json.contains("\"event\":\"explore_tree\""));

        run_outline(&document, OutlineOptions::default()).expect("outline");
    }
}
