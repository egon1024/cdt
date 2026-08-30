use dns_resolve::{
    ForkSiblingHopRtt, PathTimingSummary, fork_path_timing_summary, fork_sibling_hop_rtts,
    path_timing_summary,
};
use ratatui::text::{Line, Span};

use super::theme::Theme;
use super::tree::ExploreTree;
use dns_resolve::NodePath;

#[derive(Debug, Clone, PartialEq)]
pub struct CompareTimingContext {
    pub whole_tree: Option<PathTimingSummary>,
    pub fork_full_path: Option<PathTimingSummary>,
    pub fork_siblings: Option<Vec<ForkSiblingHopRtt>>,
    pub budget_truncated: bool,
    pub fork_zone: Option<String>,
}

pub fn build_compare_timing(
    tree: &ExploreTree,
    fork_at: Option<&NodePath>,
) -> CompareTimingContext {
    let trace = tree.trace();
    let fork_full_path = fork_at.and_then(|fork| fork_path_timing_summary(trace, fork));
    let fork_siblings = fork_at.and_then(|fork| fork_sibling_hop_rtts(trace, fork));
    let fork_zone = fork_at.and_then(|fork| tree.hop_at(fork).map(|hop| hop.zone.clone()));
    CompareTimingContext {
        whole_tree: path_timing_summary(trace),
        fork_full_path,
        fork_siblings,
        budget_truncated: trace.budget_truncated,
        fork_zone,
    }
}

pub fn format_path_chain(path: &[usize]) -> String {
    if path.is_empty() {
        return "[0]".to_string();
    }
    let mut chain = String::from("[0");
    for index in path {
        chain.push('→');
        chain.push_str(&index.to_string());
    }
    chain.push(']');
    chain
}

pub fn path_on_highlight(hop_path: &[usize], highlight: &[usize]) -> bool {
    if hop_path.len() > highlight.len() {
        return false;
    }
    hop_path == &highlight[..hop_path.len()]
}

pub fn whole_tree_summary_lines(
    context: &CompareTimingContext,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    match &context.whole_tree {
        Some(summary) => {
            lines.push(Line::from(vec![
                Span::styled("Paths ", theme.label()),
                Span::raw(format!(
                    "fastest {} {}ms  slowest {} {}ms  avg {:.0}ms (n={})",
                    format_path_chain(&summary.fastest.path),
                    summary.fastest.total_rtt_ms,
                    format_path_chain(&summary.slowest.path),
                    summary.slowest.total_rtt_ms,
                    summary.average_ms,
                    summary.count,
                )),
            ]));
            if context.budget_truncated {
                lines.push(Line::from(Span::styled(
                    "Path stats may be incomplete (budget truncated)".to_string(),
                    theme.failure(),
                )));
            }
        }
        None => {
            lines.push(Line::from(Span::styled(
                "No answered paths — timing unavailable".to_string(),
                theme.meta(),
            )));
        }
    }
    lines
}

pub fn fork_full_path_lines(context: &CompareTimingContext, theme: &Theme) -> Vec<Line<'static>> {
    let zone = context.fork_zone.as_deref().unwrap_or("fork");
    match &context.fork_full_path {
        Some(summary) => vec![Line::from(vec![
            Span::styled(format!("Fork {zone} paths "), theme.label()),
            Span::raw(format!(
                "fastest {} {}ms  slowest {} {}ms  avg {:.0}ms (n={})",
                format_path_chain(&summary.fastest.path),
                summary.fastest.total_rtt_ms,
                format_path_chain(&summary.slowest.path),
                summary.slowest.total_rtt_ms,
                summary.average_ms,
                summary.count,
            )),
        ])],
        None => vec![Line::from(Span::styled(
            "No fork-scoped answered paths".to_string(),
            theme.meta(),
        ))],
    }
}

pub fn fork_sibling_lines(context: &CompareTimingContext, theme: &Theme) -> Vec<Line<'static>> {
    let zone = context.fork_zone.as_deref().unwrap_or("fork");
    let Some(siblings) = &context.fork_siblings else {
        return vec![Line::from(Span::styled(
            "No fork sibling breakdown available".to_string(),
            theme.meta(),
        ))];
    };
    let mut lines = vec![Line::from(Span::styled(
        format!("Fork {zone} sibling hop RTTs"),
        theme.label(),
    ))];
    for sibling in siblings {
        lines.push(Line::from(format!(
            "  [{}] {}ms",
            sibling.child_index, sibling.rtt_ms
        )));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::{HopOutcome, TraceHop, TraceTreeRequest, build_linear_tree};

    fn hop(zone: &str, rtt_ms: u64, outcome: HopOutcome) -> TraceHop {
        TraceHop {
            zone: zone.into(),
            server: "1.1.1.1".into(),
            server_name: None,
            qname: "example.com.".into(),
            qtype: "A".into(),
            transport: "udp".into(),
            rtt_ms,
            rcode: "NOERROR".into(),
            nsid: None,
            ede_code: None,
            ede_text: None,
            referral_ns: vec![],
            glue: vec![],
            response: Default::default(),
            from_cache: false,
            outcome,
        }
    }

    #[test]
    fn build_compare_timing_reads_whole_tree_summary() {
        let trace = build_linear_tree(
            vec![
                hop(".", 12, HopOutcome::Referral),
                hop("com.", 8, HopOutcome::Answered),
            ],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
        );
        let tree = super::super::tree::build_explore_tree(&trace);
        let context = build_compare_timing(&tree, None);
        let summary = context.whole_tree.expect("summary");
        assert_eq!(summary.fastest.total_rtt_ms, 20);
    }

    #[test]
    fn budget_truncated_notice_when_flag_set() {
        let mut trace = build_linear_tree(
            vec![
                hop(".", 12, HopOutcome::Referral),
                hop("com.", 8, HopOutcome::Answered),
            ],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
        );
        trace.budget_truncated = true;
        let tree = super::super::tree::build_explore_tree(&trace);
        let context = build_compare_timing(&tree, None);
        let lines = whole_tree_summary_lines(&context, &Theme::from_env());
        let text = lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("budget truncated"));
    }

    #[test]
    fn format_path_chain_uses_display_indices() {
        assert_eq!(format_path_chain(&[]), "[0]");
        assert_eq!(format_path_chain(&[1, 2]), "[0→1→2]");
    }
}
