use std::collections::HashMap;

use dns_resolve::{HopOutcome, TraceTree};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use super::card::{HopCard, answer_rdata, failure_detail, outcome_label};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IcicleColumnKey {
    Idx,
    Zone,
    Server,
    Ip,
    Proto,
    Rcode,
    Rtt,
    Badge,
    Detail,
}

impl IcicleColumnKey {
    pub const ALL: [Self; 9] = [
        Self::Idx,
        Self::Zone,
        Self::Server,
        Self::Ip,
        Self::Proto,
        Self::Rcode,
        Self::Rtt,
        Self::Badge,
        Self::Detail,
    ];

    pub fn header_label(self) -> &'static str {
        match self {
            Self::Idx => "hop",
            Self::Zone => "zone",
            Self::Server => "server",
            Self::Ip => "address",
            Self::Proto => "proto",
            Self::Rcode => "rcode",
            Self::Rtt => "rtt",
            Self::Badge => "outcome",
            Self::Detail => "detail",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct IcicleColumn {
    pub key: IcicleColumnKey,
    pub x: f64,
    pub width: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IcicleRowLayout {
    pub card_index: usize,
    pub y: f64,
    pub depth: usize,
    pub parent_index: Option<usize>,
    pub child_index: usize,
    pub sibling_count: usize,
    pub is_primary_path: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IcicleLayout {
    pub columns: Vec<IcicleColumn>,
    pub rows: Vec<IcicleRowLayout>,
    pub content_left: f64,
    pub content_width: f64,
    pub column_header_y: f64,
    pub width: f64,
    pub height: f64,
}

const FS: f64 = 13.0;
const FSH: f64 = 13.5;
const COL_PAD: f64 = 14.0;
const RTT_BAR_W: f64 = 100.0;
const RTT_MS_SLOT: f64 = 56.0;

const COL_MIN: [(IcicleColumnKey, f64); 9] = [
    (IcicleColumnKey::Idx, 44.0),
    (IcicleColumnKey::Zone, 110.0),
    (IcicleColumnKey::Server, 180.0),
    (IcicleColumnKey::Ip, 120.0),
    (IcicleColumnKey::Proto, 72.0),
    (IcicleColumnKey::Rcode, 72.0),
    (IcicleColumnKey::Rtt, RTT_BAR_W + RTT_MS_SLOT + COL_PAD),
    (IcicleColumnKey::Badge, 88.0),
    (IcicleColumnKey::Detail, 200.0),
];

pub const LEFT: f64 = 18.0;
pub const ROW_H: f64 = 54.0;
pub const ROW_GAP: f64 = 6.0;
pub const INDENT: f64 = 28.0;
pub const RAIL_W: f64 = 14.0;
pub const COLUMN_HEADER_TOP: f64 = 62.0;
pub const ROW_TOP: f64 = 78.0;

pub fn proto_text(hop: &dns_resolve::TraceHop) -> String {
    let mut parts = vec![hop.transport.clone()];
    if hop.from_cache {
        parts.push("cache".into());
    }
    parts.join(" ")
}

pub fn detail_text(card: &HopCard) -> (String, &'static str, &'static str) {
    if let Some(detail) = failure_detail(&card.hop) {
        return (detail, "#b91c1c", "bold");
    }
    if let Some(answer) = answer_rdata(&card.hop) {
        return (answer, "#15803d", "bold");
    }
    if !card.hop.referral_ns.is_empty() {
        return (
            format!("{} NS", card.hop.referral_ns.len()),
            "#64748b",
            "normal",
        );
    }
    if let Some(nsid) = &card.hop.nsid {
        return (format!("nsid {nsid}"), "#64748b", "normal");
    }
    if let Some(label) = &card.branch_label {
        return (format!("branch: {label}"), "#7c3aed", "bold");
    }
    (String::new(), "#64748b", "normal")
}

pub fn cell_text(key: IcicleColumnKey, card: &HopCard) -> String {
    match key {
        IcicleColumnKey::Idx => format!("[{}]", card.display_index),
        IcicleColumnKey::Zone => card.hop.zone.clone(),
        IcicleColumnKey::Server => card.hop.server_name.clone().unwrap_or_else(|| "-".into()),
        IcicleColumnKey::Ip => card.hop.server.clone(),
        IcicleColumnKey::Proto => proto_text(&card.hop),
        IcicleColumnKey::Rcode => {
            if matches!(card.hop.outcome, HopOutcome::Failed { .. }) {
                "—".into()
            } else {
                card.hop.rcode.clone()
            }
        }
        IcicleColumnKey::Badge => outcome_label(&card.hop.outcome).into(),
        IcicleColumnKey::Detail => detail_text(card).0,
        IcicleColumnKey::Rtt => String::new(),
    }
}

fn text_width(value: &str, font_size: f64) -> f64 {
    value.width() as f64 * 0.60205 * font_size
}

pub fn ellipsize(value: &str, max_width: f64, font_size: f64) -> String {
    if text_width(value, font_size) <= max_width {
        return value.to_string();
    }
    let max_cols = (max_width / (0.60205 * font_size)).floor() as usize;
    let mut out = String::new();
    let mut used = 0usize;
    for ch in value.chars() {
        let w = ch.width().unwrap_or(0);
        if used + w + 1 > max_cols.saturating_sub(1) {
            out.push('…');
            break;
        }
        out.push(ch);
        used += w;
    }
    out
}

pub fn measure_columns(cards: &[HopCard]) -> Vec<IcicleColumn> {
    let mut widths: HashMap<IcicleColumnKey, f64> =
        COL_MIN.iter().copied().collect::<HashMap<_, _>>();

    for card in cards {
        for key in IcicleColumnKey::ALL {
            if key == IcicleColumnKey::Rtt {
                widths.insert(
                    key,
                    widths
                        .get(&key)
                        .copied()
                        .unwrap_or(RTT_BAR_W + RTT_MS_SLOT + COL_PAD)
                        .max(RTT_BAR_W + RTT_MS_SLOT + COL_PAD),
                );
                continue;
            }
            let size = if key == IcicleColumnKey::Zone {
                FSH
            } else {
                FS
            };
            let w = text_width(&cell_text(key, card), size) + COL_PAD;
            widths
                .entry(key)
                .and_modify(|existing| *existing = existing.max(w))
                .or_insert(w);
        }
    }

    let mut x = 0.0;
    let mut columns = Vec::new();
    for key in IcicleColumnKey::ALL {
        let width = widths[&key];
        columns.push(IcicleColumn { key, x, width });
        x += width;
    }
    columns
}

pub fn content_x(depth: usize) -> f64 {
    LEFT + depth as f64 * INDENT + RAIL_W + 6.0
}

pub fn is_primary_path(path: &[usize]) -> bool {
    path.iter().all(|index| *index == 0)
}

pub fn layout_icicle(cards: &[HopCard], tree: &TraceTree) -> IcicleLayout {
    let columns = measure_columns(cards);
    let content_width = columns.last().map(|c| c.x + c.width).unwrap_or(0.0) + 24.0;

    let path_to_index: HashMap<Vec<usize>, usize> = cards
        .iter()
        .enumerate()
        .map(|(index, card)| (card.path.path.clone(), index))
        .collect();

    let mut rows = Vec::with_capacity(cards.len());
    for (card_index, card) in cards.iter().enumerate() {
        let parent_index = if card.path.path.is_empty() {
            None
        } else {
            let mut parent_path = card.path.path.clone();
            parent_path.pop();
            path_to_index.get(&parent_path).copied()
        };
        let child_index = card.path.path.last().copied().unwrap_or(0);
        let sibling_count = if card.path.path.is_empty() {
            1
        } else {
            let mut parent_path = card.path.path.clone();
            parent_path.pop();
            tree.resolve(&dns_resolve::NodePath {
                tree: card.path.tree,
                path: parent_path,
            })
            .map(|node| node.children.len())
            .unwrap_or(1)
        };

        rows.push(IcicleRowLayout {
            card_index,
            y: ROW_TOP + card_index as f64 * (ROW_H + ROW_GAP),
            depth: card.depth,
            parent_index,
            child_index,
            sibling_count,
            is_primary_path: is_primary_path(&card.path.path),
        });
    }

    let content_left = cards
        .first()
        .map(|card| content_x(card.depth))
        .unwrap_or(LEFT);
    let height = ROW_TOP + cards.len() as f64 * (ROW_H + ROW_GAP) + 24.0;
    let width = LEFT + content_width + 24.0;

    IcicleLayout {
        columns,
        rows,
        content_left,
        content_width,
        column_header_y: COLUMN_HEADER_TOP,
        width,
        height,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::{NodeOrigin, TraceHop, TraceNode, TraceTreeRequest};

    fn hop(zone: &str, server: &str, name: &str) -> TraceHop {
        TraceHop {
            zone: zone.into(),
            server: server.into(),
            server_name: Some(name.into()),
            qname: "example.com.".into(),
            qtype: "A".into(),
            transport: "udp".into(),
            rtt_ms: 20,
            rcode: "NOERROR".into(),
            nsid: None,
            ede_code: None,
            ede_text: None,
            referral_ns: vec![],
            glue: vec![],
            response: Default::default(),
            from_cache: false,
            outcome: HopOutcome::Referral,
        }
    }

    fn branching_tree() -> TraceTree {
        TraceTree {
            request: TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
            root: TraceNode {
                hop: hop(".", "198.41.0.4", "a.root-servers.net"),
                origin: NodeOrigin::Trace,
                children: vec![TraceNode {
                    hop: hop("com.", "192.41.162.30", "a.gtld-servers.net"),
                    origin: NodeOrigin::Trace,
                    children: vec![
                        TraceNode {
                            hop: hop("example.com.", "199.43.135.53", "a.iana-servers.net"),
                            origin: NodeOrigin::Trace,
                            children: vec![],
                        },
                        TraceNode {
                            hop: hop(
                                "example.com.",
                                "199.43.133.53",
                                "very-long-authoritative-server-name.example.net",
                            ),
                            origin: NodeOrigin::Trace,
                            children: vec![],
                        },
                    ],
                }],
            },
            budget_truncated: false,
        }
    }

    #[test]
    fn measure_columns_widens_server_for_long_names() {
        let tree = branching_tree();
        let cards = super::super::card::build_cards(&tree, 0);
        let columns = measure_columns(&cards);
        let server = columns
            .iter()
            .find(|col| col.key == IcicleColumnKey::Server)
            .expect("server column");
        assert!(server.width >= 180.0);
        assert!(
            server.width
                > COL_MIN
                    .iter()
                    .find(|(key, _)| *key == IcicleColumnKey::Server)
                    .map(|(_, w)| *w)
                    .unwrap()
        );
    }

    #[test]
    fn ellipsize_truncates_without_exceeding_width() {
        let truncated = ellipsize("very-long-authoritative-server-name.example.net", 120.0, FS);
        assert!(truncated.ends_with('…'));
        assert!(text_width(&truncated, FS) <= 120.0 + 1.0);
    }

    #[test]
    fn layout_icicle_marks_primary_path() {
        let tree = branching_tree();
        let cards = super::super::card::build_cards(&tree, 0);
        let layout = layout_icicle(&cards, &tree);
        assert!(layout.rows[0].is_primary_path);
        assert!(layout.rows[1].is_primary_path);
        assert!(layout.rows[2].is_primary_path);
        assert!(!layout.rows[3].is_primary_path);
    }
}
