use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::config::RttBarConfig;
use crate::explore::rtt_gradient_rgb;

use super::card::{HopCard, RowKind, card_rows, outcome_label};
use super::layout_tree::{TreeEdge, TreeLayout};

const FONT: &str = "DejaVu Sans Mono, monospace";
const FS: f64 = 13.0;
const FSH: f64 = 13.5;
const CW: f64 = 0.60205 * FS;
const LH: f64 = 18.0;
const PAD: f64 = 10.0;
const HEADER_H: f64 = 26.0;
const COL_GAP: f64 = 64.0;
const LABEL_W: usize = 9;
const TITLE_FS: f64 = 15.0;
const SUBTITLE_FS: f64 = 12.0;
pub(crate) const TOP_PAD: f64 = 52.0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvgTitle {
    pub primary: String,
    pub secondary: Option<String>,
}

struct OutcomeStyle {
    stroke: &'static str,
    tint: &'static str,
}

fn outcome_style(outcome: &dns_resolve::HopOutcome) -> OutcomeStyle {
    match outcome {
        dns_resolve::HopOutcome::Referral => OutcomeStyle {
            stroke: "#64748b",
            tint: "#f1f5f9",
        },
        dns_resolve::HopOutcome::Answered => OutcomeStyle {
            stroke: "#15803d",
            tint: "#f0fdf4",
        },
        dns_resolve::HopOutcome::Failed { .. } => OutcomeStyle {
            stroke: "#b91c1c",
            tint: "#fef2f2",
        },
    }
}

fn hex_rgb((r, g, b): (u8, u8, u8)) -> String {
    format!("#{r:02x}{g:02x}{b:02x}")
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn text(x: f64, y: f64, value: &str, fill: &str, size: f64, weight: &str, anchor: &str) -> String {
    format!(
        r#"<text x="{x:.1}" y="{y:.1}" font-family="{FONT}" font-size="{size}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}" xml:space="preserve">{}</text>"#,
        escape_xml(value)
    )
}

fn char_width(font_size: f64) -> f64 {
    0.60205 * font_size
}

fn truncate_to_width(value: &str, max_width: f64, font_size: f64) -> String {
    let max_cols = (max_width / char_width(font_size)).floor() as usize;
    if value.width() <= max_cols {
        return value.to_string();
    }
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

pub(crate) fn render_header(width: f64, title: &SvgTitle) -> String {
    let text_w = (width - 2.0 * PAD).max(0.0);
    let primary = truncate_to_width(&title.primary, text_w, TITLE_FS);
    let mut parts = vec![
        format!(
            r##"<g id="header"><rect x="0" y="0" width="{width:.1}" height="{TOP_PAD:.1}" fill="#f8fafc"/>"##
        ),
        format!(
            r##"<line x1="0" y1="{TOP_PAD:.1}" x2="{width:.1}" y2="{TOP_PAD:.1}" stroke="#e2e8f0" stroke-width="1"/>"##
        ),
        text(PAD, 22.0, &primary, "#0f172a", TITLE_FS, "bold", "start"),
    ];
    if let Some(secondary) = &title.secondary {
        let secondary = truncate_to_width(secondary, text_w, SUBTITLE_FS);
        parts.push(text(
            PAD,
            40.0,
            &secondary,
            "#64748b",
            SUBTITLE_FS,
            "normal",
            "start",
        ));
    }
    parts.push("</g>".into());
    parts.join("")
}

pub fn render_tree_svg(
    cards: &[HopCard],
    layout: &TreeLayout,
    title: &SvgTitle,
    rtt_config: RttBarConfig,
) -> String {
    let width = layout.width;
    let height = layout.height + TOP_PAD;
    let tree_height = layout.height;
    let mut parts = vec![
        format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0}" height="{height:.0}" viewBox="0 0 {width:.0} {height:.0}">"#
        ),
        format!(
            r##"<defs><clipPath id="tree-content"><rect x="0" y="0" width="{width:.1}" height="{tree_height:.1}"/></clipPath></defs>"##
        ),
        render_header(width, title),
        format!(r#"<g transform="translate(0,{TOP_PAD:.0})" clip-path="url(#tree-content)">"#),
    ];

    for edge in &layout.edges {
        parts.push(render_edge(edge, layout));
    }
    for (card, positioned) in cards.iter().zip(&layout.cards) {
        parts.push(render_card(card, positioned, rtt_config));
    }

    parts.push("</g></svg>".into());
    parts.join("")
}

fn render_card(
    card: &HopCard,
    positioned: &super::layout_tree::PositionedCard,
    rtt_config: RttBarConfig,
) -> String {
    let style = outcome_style(&card.hop.outcome);
    let mut stroke = style.stroke;
    let mut tint = style.tint;
    let dashed = card.is_branch;
    if dashed {
        stroke = "#7c3aed";
        tint = "#faf5ff";
    }
    let dash_attr = if dashed {
        r#" stroke-dasharray="6 4""#
    } else {
        ""
    };

    let x = positioned.x;
    let y = positioned.y;
    let w = positioned.width;
    let h = positioned.height;
    let badge = outcome_label(&card.hop.outcome);
    let tooltip = format!(
        "[{}] {} via {} — {} in {}ms",
        card.display_index,
        card.hop.zone,
        card.hop.server_name.as_deref().unwrap_or(&card.hop.server),
        card.hop.rcode,
        card.hop.rtt_ms
    );

    let mut out = format!(
        r#"<g data-path="{}"><title>{}</title>"#,
        escape_xml(&card.path_attr),
        escape_xml(&tooltip)
    );
    out.push_str(&format!(
        r##"<rect x="{x:.1}" y="{y:.1}" width="{w:.1}" height="{h:.1}" rx="7" fill="#ffffff" stroke="{stroke}" stroke-width="1.6"{dash_attr}/>"##
    ));
    out.push_str(&format!(
        r##"<path d="M{x:.1} {y2:.1} a7 7 0 0 1 7 -7 h{wmid:.1} a7 7 0 0 1 7 7 v{vh:.1} h{neg_w:.1} z" fill="{tint}"/>"##,
        y2 = y + 7.0,
        wmid = w - 14.0,
        vh = HEADER_H - 7.0,
        neg_w = -w,
    ));
    out.push_str(&format!(
        r##"<rect x="{x:.1}" y="{yhdr:.1}" width="{w:.1}" height="1" fill="{stroke}" fill-opacity="0.35"/>"##,
        yhdr = y + HEADER_H,
    ));
    out.push_str(&format!(
        r##"<path d="M{x:.1} {y2:.1} a7 7 0 0 1 7 -7 h1 v{h:.1} h-1 a7 7 0 0 1 -7 -7 z" fill="{stroke}"/>"##,
        y2 = y + 7.0,
        h = h,
    ));

    out.push_str(&text(
        x + PAD + 4.0,
        y + 18.0,
        &format!("[{}]  {}", card.display_index, card.hop.zone),
        "#0f172a",
        FSH,
        "bold",
        "start",
    ));
    out.push_str(&text(
        x + w - PAD,
        y + 18.0,
        badge,
        stroke,
        11.0,
        "bold",
        "end",
    ));

    let mut row_y = y + HEADER_H + 15.0;
    for row in card_rows(&card.hop) {
        if !row.label.is_empty() {
            out.push_str(&text(
                x + PAD + 4.0,
                row_y,
                &row.label,
                "#94a3b8",
                FS - 1.0,
                "normal",
                "start",
            ));
        }
        let value_x = x + PAD + 4.0 + LABEL_W as f64 * CW;
        match row.kind {
            RowKind::Rtt => {
                let bar_w = 96.0;
                let scale_ms = 500.0;
                let frac = (card.hop.rtt_ms as f64 / scale_ms).clamp(0.0, 1.0);
                let filled = if card.hop.rtt_ms == 0 {
                    0.0
                } else {
                    (bar_w * frac).max(3.0)
                };
                let color = hex_rgb(rtt_gradient_rgb(
                    card.hop.rtt_ms.min(u32::MAX as u64) as u32,
                    rtt_config,
                ));
                out.push_str(&format!(
                    r##"<rect x="{value_x:.1}" y="{by:.1}" width="{bar_w}" height="10" rx="2" fill="#e2e8f0"/>"##,
                    by = row_y - 9.0
                ));
                out.push_str(&format!(
                    r##"<rect x="{value_x:.1}" y="{by:.1}" width="{filled:.1}" height="10" rx="2" fill="{color}"/>"##,
                    by = row_y - 9.0
                ));
                out.push_str(&text(
                    value_x + bar_w + 8.0,
                    row_y,
                    &format!("{} ms", card.hop.rtt_ms),
                    "#0f172a",
                    FS,
                    "bold",
                    "start",
                ));
            }
            _ => {
                let (fill, weight) = match row.kind {
                    RowKind::Strong => ("#0f172a", "bold"),
                    RowKind::Dim => ("#64748b", "normal"),
                    RowKind::Good => ("#15803d", "bold"),
                    RowKind::Bad => ("#b91c1c", "bold"),
                    RowKind::Plain | RowKind::Rtt => ("#334155", "normal"),
                };
                if let Some(value) = &row.value {
                    out.push_str(&text(value_x, row_y, value, fill, FS, weight, "start"));
                }
            }
        }
        row_y += LH;
    }

    if let Some(label) = &card.branch_label {
        out.push_str(&text(
            x + PAD + 4.0,
            row_y,
            &format!("origin: branch: {label}"),
            "#7c3aed",
            FS - 1.0,
            "bold",
            "start",
        ));
    }

    out.push_str("</g>");
    out
}

fn render_edge(edge: &TreeEdge, layout: &TreeLayout) -> String {
    let parent = &layout.cards[edge.parent_index];
    let child = &layout.cards[edge.child_index];
    let x1 = parent.x + parent.width;
    let y1 = parent.y + HEADER_H / 2.0 + 4.0;
    let x2 = child.x;
    let y2 = child.y + HEADER_H / 2.0 + 4.0;
    let mx = x1 + COL_GAP / 2.0;
    let col = if edge.dashed { "#7c3aed" } else { "#94a3b8" };
    let dash = if edge.dashed {
        r#" stroke-dasharray="5 4""#
    } else {
        ""
    };
    let bend = if y2 > y1 { 8.0 } else { -8.0 };
    format!(
        r##"<path d="M{x1:.1} {y1:.1} H{mx1:.1} Q{mx:.1} {y1:.1} {mx:.1} {qy:.1} V{vy:.1} Q{mx:.1} {y2:.1} {mx2:.1} {y2:.1} H{x2:.1}" fill="none" stroke="{col}" stroke-width="1.6"{dash} stroke-linecap="round"/><circle cx="{cx:.1}" cy="{y2:.1}" r="2.6" fill="{col}"/>"##,
        mx1 = mx - 8.0,
        qy = y1 + bend,
        vy = y2 - bend,
        mx2 = mx + 8.0,
        x2 = x2 - 5.0,
        cx = x2 - 3.0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::{
        HopOutcome, NodeOrigin, TraceHop, TraceNode, TraceTree, TraceTreeRequest, build_linear_tree,
    };

    use crate::export::card::build_cards;
    use crate::export::layout_tree::layout_tree;

    fn sample_hop() -> TraceHop {
        TraceHop {
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
            referral_ns: vec!["a.gtld-servers.net.".into()],
            glue: vec![],
            response: Default::default(),
            from_cache: false,
            outcome: HopOutcome::Referral,
        }
    }

    #[test]
    fn single_hop_svg_contains_card_and_metadata() {
        let tree = build_linear_tree(
            vec![sample_hop()],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
        );
        let cards = build_cards(&tree, 0);
        let layout = layout_tree(&cards, &tree);
        let svg = render_tree_svg(
            &cards,
            &layout,
            &SvgTitle {
                primary: "delve · example.com. A".into(),
                secondary: None,
            },
            RttBarConfig::default(),
        );
        assert!(svg.contains("<svg"));
        assert!(svg.contains(r#"clipPath id="tree-content""#));
        assert!(svg.contains(r#"clip-path="url(#tree-content)""#));
        assert!(!svg.contains("fill=\"#ffffff\"/>"));
        assert!(svg.contains("a.root-servers.net"));
        assert!(svg.contains("REFERRAL"));
        assert!(svg.contains("11 ms"));
    }

    #[test]
    fn nested_path_includes_data_path_and_title() {
        let tree = TraceTree {
            request: TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
            root: TraceNode {
                hop: sample_hop(),
                origin: NodeOrigin::Trace,
                children: vec![TraceNode {
                    hop: {
                        let mut hop = sample_hop();
                        hop.zone = "com.".into();
                        hop
                    },
                    origin: NodeOrigin::Trace,
                    children: vec![],
                }],
            },
            budget_truncated: false,
        };
        let cards = build_cards(&tree, 0);
        let layout = layout_tree(&cards, &tree);
        let svg = render_tree_svg(
            &cards,
            &layout,
            &SvgTitle {
                primary: "title".into(),
                secondary: None,
            },
            RttBarConfig::default(),
        );
        assert!(svg.contains(r#"data-path="0.0""#));
        assert!(svg.contains("<title>"));
    }

    #[test]
    fn two_level_tree_renders_edge_path() {
        let tree = TraceTree {
            request: TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
            root: TraceNode {
                hop: sample_hop(),
                origin: NodeOrigin::Trace,
                children: vec![TraceNode {
                    hop: {
                        let mut hop = sample_hop();
                        hop.zone = "com.".into();
                        hop.outcome = HopOutcome::Answered;
                        hop
                    },
                    origin: NodeOrigin::Trace,
                    children: vec![],
                }],
            },
            budget_truncated: false,
        };
        let cards = build_cards(&tree, 0);
        let layout = layout_tree(&cards, &tree);
        let svg = render_tree_svg(
            &cards,
            &layout,
            &SvgTitle {
                primary: "title".into(),
                secondary: None,
            },
            RttBarConfig::default(),
        );
        assert!(svg.contains(r#"<path d="M"#));
        assert!(svg.contains(r#"<circle cx="#));
    }

    #[test]
    fn header_spans_full_width_and_truncates_long_session_id() {
        let session = "session 01M1FGVANFKBGJBSZ8CTDGPD78";
        let title = SvgTitle {
            primary: "delve  ·  tuininga.org. A  ·  tree 0".into(),
            secondary: Some(session.into()),
        };
        let width = 900.0;
        let header = render_header(width, &title);
        assert!(header.contains(r#"id="header""#));
        assert!(header.contains(&format!(r#"width="{width:.1}""#)));
        assert!(header.contains("fill=\"#f8fafc\""));
        assert!(header.contains("tuininga.org."));
        assert!(header.contains(session));

        let narrow = truncate_to_width(session, 200.0, SUBTITLE_FS);
        assert!(narrow.ends_with('…'));
        assert!(narrow.len() < session.len());
    }
}
