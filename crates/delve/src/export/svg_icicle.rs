use crate::config::RttBarConfig;
use crate::explore::rtt_gradient_rgb;

use super::card::{HopCard, outcome_label};
use super::layout_icicle::{
    INDENT, IcicleColumnKey, IcicleLayout, LEFT, RAIL_W, ROW_H, cell_text, detail_text, ellipsize,
    proto_text,
};
use super::svg::{SvgTitle, TOP_PAD, render_header};

const FONT: &str = "DejaVu Sans Mono, monospace";
const FS: f64 = 13.0;
const FSH: f64 = 13.5;
const RTT_BAR_W: f64 = 100.0;
const RTT_MS_SLOT: f64 = 56.0;
const COL_PAD: f64 = 14.0;

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

#[allow(clippy::too_many_arguments)]
fn text_clipped(
    x: f64,
    y: f64,
    value: &str,
    fill: &str,
    size: f64,
    weight: &str,
    anchor: &str,
    clip_id: &str,
) -> String {
    format!(
        r#"<text x="{x:.1}" y="{y:.1}" font-family="{FONT}" font-size="{size}" font-weight="{weight}" fill="{fill}" text-anchor="{anchor}" clip-path="url(#{clip_id})" xml:space="preserve">{}</text>"#,
        escape_xml(value)
    )
}

fn hex_rgb((r, g, b): (u8, u8, u8)) -> String {
    format!("#{r:02x}{g:02x}{b:02x}")
}

fn clip_rect(id: &str, x: f64, y: f64, w: f64, h: f64) -> String {
    format!(
        r#"<clipPath id="{id}"><rect x="{x:.1}" y="{y:.1}" width="{w:.1}" height="{h:.1}"/></clipPath>"#
    )
}

fn row_style(card: &HopCard) -> (&'static str, &'static str, bool) {
    if card.is_branch {
        return ("#faf5ff", "#7c3aed", true);
    }
    match card.hop.outcome {
        dns_resolve::HopOutcome::Referral => ("#f1f5f9", "#64748b", false),
        dns_resolve::HopOutcome::Answered => ("#f0fdf4", "#15803d", false),
        dns_resolve::HopOutcome::Failed { .. } => ("#fef2f2", "#b91c1c", false),
    }
}

fn render_column_headers(layout: &IcicleLayout, x0: f64) -> String {
    let mut out = String::new();
    for column in &layout.columns {
        out.push_str(&text(
            x0 + column.x,
            layout.column_header_y,
            column.key.header_label(),
            "#94a3b8",
            10.0,
            "bold",
            "start",
        ));
    }
    out
}

fn render_rails(layout: &IcicleLayout, cards: &[HopCard]) -> String {
    let mut out = String::new();
    for row in &layout.rows {
        let Some(parent_index) = row.parent_index else {
            continue;
        };
        let parent = &layout.rows[parent_index];
        let card = &cards[row.card_index];
        let y_parent = parent.y + ROW_H / 2.0;
        let y_self = row.y + ROW_H / 2.0;
        let x_rail = LEFT + row.depth as f64 * INDENT + RAIL_W / 2.0;
        let x_parent_rail = LEFT + parent.depth as f64 * INDENT + RAIL_W / 2.0;
        let col = if card.is_branch { "#7c3aed" } else { "#cbd5e1" };
        let dash = if card.is_branch {
            r#" stroke-dasharray="4 3""#
        } else {
            ""
        };
        out.push_str(&format!(
            r##"<path d="M{x_parent_rail:.1} {y_parent:.1} V{y_self:.1}" fill="none" stroke="{col}" stroke-width="1.5"{dash}/>"##
        ));
        out.push_str(&format!(
            r##"<path d="M{x_parent_rail:.1} {y_self:.1} H{x_rail:.1}" fill="none" stroke="{col}" stroke-width="1.5"{dash}/>"##
        ));
    }
    out
}

fn render_primary_markers(layout: &IcicleLayout) -> String {
    let mut out = String::new();
    for row in &layout.rows {
        if !row.is_primary_path {
            continue;
        }
        let y = row.y + ROW_H / 2.0;
        let x = super::layout_icicle::content_x(row.depth) - 8.0;
        out.push_str(&format!(
            r##"<circle cx="{x:.1}" cy="{y:.1}" r="3.2" fill="#0ea5e9" fill-opacity="0.85"/>"##
        ));
    }
    out
}

fn render_row(
    card: &HopCard,
    row: &super::layout_icicle::IcicleRowLayout,
    layout: &IcicleLayout,
    rtt_config: RttBarConfig,
    defs: &mut Vec<String>,
) -> String {
    let y = row.y;
    let x0 = super::layout_icicle::content_x(row.depth);
    let row_width = layout.content_width - row.depth as f64 * INDENT;
    let (bg, stroke, dashed) = row_style(card);
    let dash_attr = if dashed {
        r#" stroke-dasharray="6 4""#
    } else {
        ""
    };
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
        r##"<rect x="{x:.1}" y="{y:.1}" width="{row_width:.1}" height="{ROW_H:.1}" rx="6" fill="{bg}" stroke="{stroke}" stroke-width="1.4"{dash_attr}/>"##,
        x = x0 - 8.0,
    ));
    out.push_str(&format!(
        r##"<rect x="{x:.1}" y="{y:.1}" width="4" height="{ROW_H:.1}" rx="2" fill="{stroke}"/>"##,
        x = x0 - 8.0,
    ));

    let cy = y + ROW_H / 2.0 + 5.0;
    let clip_h = ROW_H - 4.0;

    for column in &layout.columns {
        let key = column.key;
        if key == IcicleColumnKey::Rtt {
            let bar_x = x0 + column.x;
            let bar_y = y + ROW_H / 2.0 - 5.0;
            let frac = (card.hop.rtt_ms as f64 / 500.0).clamp(0.0, 1.0);
            let filled = if card.hop.rtt_ms == 0 {
                0.0
            } else {
                (RTT_BAR_W * frac).max(3.0)
            };
            let color = hex_rgb(rtt_gradient_rgb(
                card.hop.rtt_ms.min(u32::MAX as u64) as u32,
                rtt_config,
            ));
            out.push_str(&format!(
                r##"<rect x="{bar_x:.1}" y="{bar_y:.1}" width="{RTT_BAR_W}" height="10" rx="2" fill="#e2e8f0"/>"##
            ));
            out.push_str(&format!(
                r##"<rect x="{bar_x:.1}" y="{bar_y:.1}" width="{filled:.1}" height="10" rx="2" fill="{color}"/>"##
            ));
            let ms_x = bar_x + RTT_BAR_W + 8.0;
            let ms = format!("{} ms", card.hop.rtt_ms);
            out.push_str(&text(
                ms_x + RTT_MS_SLOT - 4.0,
                cy,
                &ms,
                "#0f172a",
                FS - 1.0,
                "bold",
                "end",
            ));
            continue;
        }

        let slot = column.width - COL_PAD;
        let cx = x0 + column.x;
        let clip_id = format!(
            "clip-{}-{}",
            card.display_index,
            match key {
                IcicleColumnKey::Idx => "idx",
                IcicleColumnKey::Zone => "zone",
                IcicleColumnKey::Server => "server",
                IcicleColumnKey::Ip => "ip",
                IcicleColumnKey::Proto => "proto",
                IcicleColumnKey::Rcode => "rcode",
                IcicleColumnKey::Rtt => "rtt",
                IcicleColumnKey::Badge => "badge",
                IcicleColumnKey::Detail => "detail",
            }
        );
        defs.push(clip_rect(&clip_id, cx, y + 2.0, slot, clip_h));

        let (value, fill, weight, size) = match key {
            IcicleColumnKey::Idx => (
                cell_text(key, card),
                "#64748b".to_string(),
                "normal",
                FS - 1.0,
            ),
            IcicleColumnKey::Zone => (cell_text(key, card), "#0f172a".to_string(), "bold", FSH),
            IcicleColumnKey::Server => (cell_text(key, card), "#0f172a".to_string(), "bold", FS),
            IcicleColumnKey::Ip => (cell_text(key, card), "#64748b".to_string(), "normal", FS),
            IcicleColumnKey::Proto => (
                proto_text(&card.hop),
                "#64748b".to_string(),
                "normal",
                FS - 1.0,
            ),
            IcicleColumnKey::Rcode => (cell_text(key, card), "#64748b".to_string(), "normal", FS),
            IcicleColumnKey::Badge => (badge.to_string(), stroke.to_string(), "bold", FS - 1.0),
            IcicleColumnKey::Detail => {
                let (detail, detail_fill, detail_weight) = detail_text(card);
                if detail.is_empty() {
                    continue;
                }
                (detail, detail_fill.to_string(), detail_weight, FS - 1.0)
            }
            IcicleColumnKey::Rtt => unreachable!(),
        };

        let shown = ellipsize(&value, slot, size);
        out.push_str(&text_clipped(
            cx, cy, &shown, &fill, size, weight, "start", &clip_id,
        ));
    }

    out.push_str("</g>");
    out
}

pub fn render_icicle_svg(
    cards: &[HopCard],
    layout: &IcicleLayout,
    title: &SvgTitle,
    rtt_config: RttBarConfig,
) -> String {
    let width = layout.width;
    let height = layout.height + TOP_PAD;
    let body_height = layout.height;
    let header_x0 =
        super::layout_icicle::content_x(cards.first().map(|card| card.depth).unwrap_or(0));
    let mut defs = Vec::new();
    let mut parts = vec![
        format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0}" height="{height:.0}" viewBox="0 0 {width:.0} {height:.0}">"#
        ),
        format!(
            r##"<defs><clipPath id="icicle-content"><rect x="0" y="0" width="{width:.1}" height="{body_height:.1}"/></clipPath></defs>"##
        ),
        render_header(width, title),
        format!(r#"<g transform="translate(0,{TOP_PAD:.0})" clip-path="url(#icicle-content)">"#),
        render_column_headers(layout, header_x0),
        render_rails(layout, cards),
        render_primary_markers(layout),
    ];

    for row in &layout.rows {
        parts.push(render_row(
            &cards[row.card_index],
            row,
            layout,
            rtt_config,
            &mut defs,
        ));
    }

    let defs_markup = if defs.is_empty() {
        String::new()
    } else {
        format!("<defs>{}</defs>", defs.join(""))
    };
    if !defs_markup.is_empty() {
        parts.insert(1, defs_markup);
    }

    parts.push("</g></svg>".into());
    parts.join("")
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::{HopOutcome, NodeOrigin, TraceHop, TraceNode, TraceTree, TraceTreeRequest};

    use crate::export::card::build_cards;
    use crate::export::layout_icicle::layout_icicle;

    fn branching_tree() -> TraceTree {
        TraceTree {
            request: TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
            root: TraceNode {
                hop: TraceHop {
                    zone: ".".into(),
                    server: "198.41.0.4".into(),
                    server_name: Some("a.root-servers.net".into()),
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
                },
                origin: NodeOrigin::Trace,
                children: vec![TraceNode {
                    hop: TraceHop {
                        zone: "com.".into(),
                        server: "192.41.162.30".into(),
                        server_name: Some("a.gtld-servers.net".into()),
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
                    },
                    origin: NodeOrigin::Trace,
                    children: vec![
                        TraceNode {
                            hop: TraceHop {
                                zone: "example.com.".into(),
                                server: "199.43.135.53".into(),
                                server_name: Some("a.iana-servers.net".into()),
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
                            },
                            origin: NodeOrigin::Trace,
                            children: vec![],
                        },
                        TraceNode {
                            hop: TraceHop {
                                zone: "example.com.".into(),
                                server: "199.43.133.53".into(),
                                server_name: Some(
                                    "very-long-authoritative-server-name.example.net".into(),
                                ),
                                qname: "example.com.".into(),
                                qtype: "A".into(),
                                transport: "tcp".into(),
                                rtt_ms: 2000,
                                rcode: "NOERROR".into(),
                                nsid: None,
                                ede_code: None,
                                ede_text: None,
                                referral_ns: vec![],
                                glue: vec![],
                                response: Default::default(),
                                from_cache: true,
                                outcome: HopOutcome::Answered,
                            },
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
    fn icicle_svg_contains_columns_clip_paths_and_primary_marker() {
        let tree = branching_tree();
        let cards = build_cards(&tree, 0);
        let layout = layout_icicle(&cards, &tree);
        let svg = render_icicle_svg(
            &cards,
            &layout,
            &SvgTitle {
                primary: "delve · example.com. A".into(),
                secondary: None,
            },
            RttBarConfig::default(),
        );
        assert!(svg.contains("hop"));
        assert!(svg.contains("outcome"));
        assert!(svg.contains("clip-"));
        assert!(svg.contains("fill=\"#0ea5e9\""));
        assert!(svg.contains("2000 ms"));
        assert!(svg.contains("ANSWERED"));
    }

    #[test]
    fn icicle_svg_uses_data_path_attributes() {
        let tree = branching_tree();
        let cards = build_cards(&tree, 0);
        let layout = layout_icicle(&cards, &tree);
        let svg = render_icicle_svg(
            &cards,
            &layout,
            &SvgTitle {
                primary: "title".into(),
                secondary: None,
            },
            RttBarConfig::default(),
        );
        assert!(svg.contains(r#"data-path="0.0.1""#));
    }
}
