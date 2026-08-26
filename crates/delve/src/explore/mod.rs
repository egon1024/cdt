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
pub struct ExploreOptions {
    pub outline: bool,
    pub events: bool,
}

pub fn parse_explore_args(args: &[String]) -> Result<ExploreOptions, ParseError> {
    let mut options = ExploreOptions::default();
    for arg in args {
        match arg.as_str() {
            "+outline" => options.outline = true,
            "+nooutline" => options.outline = false,
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

pub fn run_explore(
    document: &SessionDocument,
    options: ExploreOptions,
) -> Result<(), ExploreError> {
    let tree = build_explore_tree(&document.result);

    if options.events {
        println!("{}", render_tree_json(&tree, &document.id));
        return Ok(());
    }

    let use_outline = options.outline || !io::stdout().is_terminal();
    if use_outline {
        let outline = render_outline(&tree, ui_symbols());
        let mut stdout = io::stdout().lock();
        stdout
            .write_all(outline.as_bytes())
            .map_err(ExploreError::Tui)?;
        stdout.flush().map_err(ExploreError::Tui)?;
        if !options.outline && !io::stdout().is_terminal() {
            eprintln!(
                "delve: stdout is not a terminal; wrote outline to stdout (redirect stdout to capture, e.g. > outline.txt)"
            );
        }
        return Ok(());
    }

    run_tui(&tree).map_err(ExploreError::Tui)
}

#[derive(Debug, thiserror::Error)]
pub enum ExploreError {
    #[error(transparent)]
    Tui(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::{FinalAnswer, TraceHop, TraceResult};

    #[test]
    fn parses_explore_flags() {
        let options = parse_explore_args(&["+outline".into(), "+events".into()]).expect("parse");
        assert!(options.outline);
        assert!(options.events);
    }

    #[test]
    fn run_explore_outline_writes_tree() {
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

        run_explore(
            &document,
            ExploreOptions {
                outline: true,
                events: false,
            },
        )
        .expect("outline explore");
    }
}
