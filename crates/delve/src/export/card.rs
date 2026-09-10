use dns_resolve::{BranchIntent, HopOutcome, NodeOrigin, NodePath, TraceHop, TraceTree};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HopCard {
    pub path: NodePath,
    pub path_attr: String,
    pub display_index: usize,
    pub depth: usize,
    pub hop: TraceHop,
    pub is_branch: bool,
    pub branch_label: Option<String>,
}

pub fn path_attribute(tree: usize, path: &[usize]) -> String {
    if path.is_empty() {
        return tree.to_string();
    }
    let mut out = tree.to_string();
    for index in path {
        out.push('.');
        out.push_str(&index.to_string());
    }
    out
}

pub fn build_cards(tree: &TraceTree, tree_index: usize) -> Vec<HopCard> {
    let mut cards = Vec::new();
    let display_order = tree.display_order();
    for (display_index, path) in display_order.into_iter().enumerate() {
        let node = tree.resolve(&path).expect("display path resolves");
        let (is_branch, branch_label) = branch_meta(&node.origin);
        cards.push(HopCard {
            path: path.clone(),
            path_attr: path_attribute(tree_index, &path.path),
            display_index,
            depth: path.path.len(),
            hop: node.hop.clone(),
            is_branch,
            branch_label,
        });
    }
    cards
}

fn branch_meta(origin: &NodeOrigin) -> (bool, Option<String>) {
    match origin {
        NodeOrigin::Trace => (false, None),
        NodeOrigin::Branch { intent, .. } => {
            let label = match intent {
                BranchIntent::AlternateServer => "alternate_server",
                BranchIntent::ExpandCut => "expand_cut",
            };
            (true, Some(label.to_string()))
        }
    }
}

pub fn outcome_label(outcome: &HopOutcome) -> &'static str {
    match outcome {
        HopOutcome::Referral => "REFERRAL",
        HopOutcome::Answered => "ANSWERED",
        HopOutcome::Failed { .. } => "FAILED",
    }
}

pub fn failure_detail(hop: &TraceHop) -> Option<String> {
    match &hop.outcome {
        HopOutcome::Failed { kind, detail } => Some(format!("{kind}: {detail}")),
        _ => None,
    }
}

pub fn answer_rdata(hop: &TraceHop) -> Option<String> {
    if !matches!(hop.outcome, HopOutcome::Answered) {
        return None;
    }
    hop.response
        .answers
        .first()
        .map(|record| format!("{} {}", record.name, record.rdata))
}

pub fn card_rows(hop: &TraceHop) -> Vec<CardRow> {
    let mut rows = Vec::new();
    rows.push(CardRow::labeled(
        "server",
        hop.server_name.clone().unwrap_or_else(|| "-".into()),
        RowKind::Strong,
    ));
    rows.push(CardRow::unlabeled(hop.server.clone(), RowKind::Dim));
    rows.push(CardRow::labeled(
        "query",
        format!("{}  {}", hop.qname, hop.qtype),
        RowKind::Plain,
    ));
    let mut proto = hop.transport.clone();
    if hop.from_cache {
        proto.push_str("   [cache]");
    }
    rows.push(CardRow::labeled("proto", proto, RowKind::Plain));
    if let Some(detail) = failure_detail(hop) {
        rows.push(CardRow::labeled("error", detail, RowKind::Bad));
    } else {
        rows.push(CardRow::labeled("rcode", hop.rcode.clone(), RowKind::Plain));
    }
    if let Some(nsid) = &hop.nsid {
        rows.push(CardRow::labeled("nsid", nsid.clone(), RowKind::Dim));
    }
    if let Some(answer) = answer_rdata(hop) {
        rows.push(CardRow::labeled("answer", answer, RowKind::Good));
    }
    if !hop.referral_ns.is_empty() {
        rows.push(CardRow::labeled(
            "referral",
            format!("{} NS", hop.referral_ns.len()),
            RowKind::Dim,
        ));
    }
    rows.push(CardRow::rtt());
    rows
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardRow {
    pub label: String,
    pub value: Option<String>,
    pub kind: RowKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowKind {
    Plain,
    Strong,
    Dim,
    Good,
    Bad,
    Rtt,
}

impl CardRow {
    fn labeled(label: &str, value: String, kind: RowKind) -> Self {
        Self {
            label: label.into(),
            value: Some(value),
            kind,
        }
    }

    fn unlabeled(value: String, kind: RowKind) -> Self {
        Self {
            label: String::new(),
            value: Some(value),
            kind,
        }
    }

    fn rtt() -> Self {
        Self {
            label: "rtt".into(),
            value: None,
            kind: RowKind::Rtt,
        }
    }
}

pub fn measure_card(hop: &TraceHop, branch_label: Option<&str>) -> (f64, f64) {
    const PAD: f64 = 10.0;
    const HEADER_H: f64 = 26.0;
    const LH: f64 = 18.0;
    const FS: f64 = 13.0;
    const CW: f64 = 0.60205 * FS;
    const LABEL_W: usize = 9;

    let rows = card_rows(hop);
    let mut width_chars = 0usize;
    for row in &rows {
        let text_len = if row.kind == RowKind::Rtt {
            LABEL_W + 22
        } else {
            LABEL_W + row.value.as_ref().map(String::len).unwrap_or(0)
        };
        width_chars = width_chars.max(text_len);
    }
    let header = format!("[{}]  {}", hop.zone, outcome_label(&hop.outcome));
    let header_chars = header.len() + 6;
    width_chars = width_chars.max(header_chars);
    if let Some(label) = branch_label {
        width_chars = width_chars.max(LABEL_W + label.len() + 8);
    }
    let width = width_chars as f64 * CW + 2.0 * PAD;
    let height = HEADER_H + rows.len() as f64 * LH + PAD;
    (width, height)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::{TraceNode, TraceTreeRequest};

    fn sample_hop(zone: &str, server: &str) -> TraceHop {
        TraceHop {
            zone: zone.into(),
            server: server.into(),
            server_name: Some(format!("{server}.example.net")),
            qname: "example.com.".into(),
            qtype: "A".into(),
            transport: "udp".into(),
            rtt_ms: 11,
            rcode: "NOERROR".into(),
            nsid: None,
            ede_code: None,
            ede_text: None,
            referral_ns: vec!["ns.example.com.".into()],
            glue: vec![],
            response: Default::default(),
            from_cache: false,
            outcome: HopOutcome::Referral,
        }
    }

    #[test]
    fn build_cards_maps_paths_and_branch_origin() {
        let tree = TraceTree {
            request: TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
            root: TraceNode {
                hop: sample_hop(".", "198.41.0.4"),
                origin: NodeOrigin::Trace,
                children: vec![TraceNode {
                    hop: {
                        let mut hop = sample_hop("com.", "192.41.162.30");
                        hop.outcome = HopOutcome::Answered;
                        hop
                    },
                    origin: NodeOrigin::Branch {
                        at: NodePath::root(0),
                        intent: BranchIntent::ExpandCut,
                        at_time: "2026-01-01T00:00:00Z".into(),
                    },
                    children: vec![],
                }],
            },
            budget_truncated: false,
        };
        let cards = build_cards(&tree, 0);
        assert_eq!(cards.len(), 2);
        assert_eq!(cards[0].path_attr, "0");
        assert_eq!(cards[1].path_attr, "0.0");
        assert!(cards[1].is_branch);
        assert_eq!(cards[1].branch_label.as_deref(), Some("expand_cut"));
    }

    #[test]
    fn path_attribute_formats_nested_paths() {
        assert_eq!(path_attribute(0, &[]), "0");
        assert_eq!(path_attribute(0, &[1, 2]), "0.1.2");
    }
}
