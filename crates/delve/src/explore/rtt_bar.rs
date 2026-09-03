use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

use crate::config::RttBarConfig;

use super::rtt_color::rtt_gradient_rgb;
use super::terminal::{self, ColorCapability};
use super::theme::Theme;
use crate::config::RTT_BAR_ABSOLUTE_SCALE_MS;

/// Absolute scale used for Browse detail RTT bars (matches export card scale).
pub const DETAIL_RTT_SCALE_MS: u32 = RTT_BAR_ABSOLUTE_SCALE_MS;

/// Glyph used for the unfilled portion of an RTT bar so the full track is visible.
pub const RTT_BAR_EMPTY: &str = "░";

/// Fixed-width latency bar. `scale_max_rtt_ms` is the value that fills the bar
/// completely (Compare: max visible RTT; Browse detail: [`DETAIL_RTT_SCALE_MS`]).
pub fn rtt_bar_spans(
    rtt_ms: u32,
    scale_max_rtt_ms: u32,
    config: RttBarConfig,
    theme: &Theme,
) -> Vec<Span<'static>> {
    let config = config.normalized();
    let width = config.max_width as usize;
    let scale_ms = scale_max_rtt_ms.max(1) as f64;
    let ms_per_char = scale_ms / width as f64;

    let filled = if rtt_ms == 0 {
        0
    } else {
        ((rtt_ms as f64 / scale_ms) * width as f64)
            .round()
            .clamp(1.0, width as f64) as usize
    };

    let mut spans = Vec::with_capacity(width);
    for index in 0..width {
        if index < filled {
            let ms_at = ((index + 1) as f64 * ms_per_char).round() as u32;
            spans.push(Span::styled("█", style_for_rtt(ms_at, config, theme)));
        } else {
            spans.push(Span::styled(RTT_BAR_EMPTY, theme.meta()));
        }
    }
    spans
}

/// Plain-text RTT line for outline / dig plain output (no bar glyphs).
pub fn format_rtt_plain_line(rtt_ms: u64) -> String {
    format!("rtt: {rtt_ms} ms")
}

/// Browse detail meta line: `rtt` label, absolute-scale bar, colored `{n} ms`.
pub fn rtt_detail_line(rtt_ms: u64, config: RttBarConfig, theme: &Theme) -> Line<'static> {
    let rtt_u32 = rtt_ms.min(u64::from(u32::MAX)) as u32;
    let mut spans = vec![Span::styled("rtt  ", theme.label())];
    spans.extend(rtt_bar_spans(rtt_u32, DETAIL_RTT_SCALE_MS, config, theme));
    spans.push(Span::raw("  "));
    spans.push(Span::styled(
        format!("{rtt_ms} ms"),
        style_for_rtt(rtt_u32, config.normalized(), theme),
    ));
    Line::from(spans)
}

#[allow(dead_code)]
pub fn max_rtt_ms_for_visible(
    tree: &super::tree::ExploreTree,
    visible: &[super::tree::VisibleNode],
) -> u32 {
    visible
        .iter()
        .filter_map(|node| tree.hop_at(&node.path))
        .map(|hop| hop.rtt_ms.min(u32::MAX as u64) as u32)
        .max()
        .unwrap_or(0)
        .max(1)
}

pub fn style_for_rtt(rtt_ms: u32, config: RttBarConfig, theme: &Theme) -> Style {
    if !theme.color_enabled {
        return Style::default();
    }
    match theme.color_capability {
        ColorCapability::Basic => style_for_rtt_stepped(rtt_ms, config, theme),
        ColorCapability::Indexed => {
            let (red, green, blue) = rtt_gradient_rgb(rtt_ms, config);
            Style::default().fg(Color::Indexed(terminal::rgb_to_ansi256(red, green, blue)))
        }
        ColorCapability::Truecolor => {
            let (red, green, blue) = rtt_gradient_rgb(rtt_ms, config);
            Style::default().fg(Color::Rgb(red, green, blue))
        }
    }
}

fn style_for_rtt_stepped(rtt_ms: u32, config: RttBarConfig, theme: &Theme) -> Style {
    if rtt_ms <= config.green_ms {
        theme.rtt_green()
    } else if rtt_ms <= config.yellow_ms {
        theme.rtt_yellow()
    } else if rtt_ms <= config.orange_ms {
        theme.rtt_orange()
    } else {
        theme.rtt_red()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RttBarConfig;
    use dns_resolve::{HopOutcome, TraceHop, TraceTreeRequest, build_linear_tree};

    fn hop(rtt_ms: u64) -> TraceHop {
        TraceHop {
            zone: ".".into(),
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
            outcome: HopOutcome::Answered,
        }
    }

    fn config() -> RttBarConfig {
        RttBarConfig {
            green_ms: 50,
            yellow_ms: 100,
            orange_ms: 200,
            insane_ms: 500,
            max_width: 20,
        }
    }

    fn theme_with_capability(capability: ColorCapability) -> Theme {
        let mut theme = Theme::from_env();
        theme.color_enabled = true;
        theme.color_capability = capability;
        theme
    }

    #[test]
    fn bar_always_uses_configured_width() {
        let theme = Theme::from_env();
        let cfg = config();
        let spans = rtt_bar_spans(10, 100, cfg, &theme);
        assert_eq!(spans.len(), 20);
        assert_eq!(spans.iter().filter(|s| s.content == "█").count(), 2);
        assert_eq!(
            spans.iter().filter(|s| s.content == RTT_BAR_EMPTY).count(),
            18
        );
    }

    #[test]
    fn longest_rtt_fills_full_bar() {
        let theme = Theme::from_env();
        let cfg = config();
        let spans = rtt_bar_spans(200, 200, cfg, &theme);
        assert_eq!(spans.iter().filter(|s| s.content == "█").count(), 20);
    }

    #[test]
    fn bar_length_scales_relative_to_visible_max() {
        let theme = Theme::from_env();
        let cfg = config();
        let short = rtt_bar_spans(50, 200, cfg, &theme);
        let long = rtt_bar_spans(200, 200, cfg, &theme);
        let short_filled = short.iter().filter(|s| s.content == "█").count();
        let long_filled = long.iter().filter(|s| s.content == "█").count();
        assert_eq!(long_filled, 20);
        assert!(short_filled < long_filled);
        assert_eq!(short_filled, 5);
    }

    #[test]
    fn zero_rtt_uses_empty_bar_slot() {
        let theme = Theme::from_env();
        let cfg = config();
        let spans = rtt_bar_spans(0, 100, cfg, &theme);
        assert_eq!(spans.len(), 20);
        assert!(spans.iter().all(|span| span.content == RTT_BAR_EMPTY));
    }

    #[test]
    fn detail_line_uses_absolute_scale_and_colored_ms() {
        let theme = theme_with_capability(ColorCapability::Truecolor);
        let cfg = config();
        let line = rtt_detail_line(200, cfg, &theme);
        let contents: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert!(contents.starts_with("rtt  "));
        assert!(contents.contains("200 ms"));
        assert!(contents.contains('█'));
        assert!(contents.contains(RTT_BAR_EMPTY));
        let ms_span = line
            .spans
            .iter()
            .find(|s| s.content == "200 ms")
            .expect("ms span");
        assert_eq!(ms_span.style.fg, Some(Color::Rgb(255, 132, 32)));
    }

    #[test]
    fn format_rtt_plain_line_matches_export_style_label() {
        assert_eq!(format_rtt_plain_line(11), "rtt: 11 ms");
    }

    #[test]
    fn filled_characters_receive_threshold_colors() {
        let theme = theme_with_capability(ColorCapability::Basic);
        let cfg = config();
        let spans = rtt_bar_spans(200, 200, cfg, &theme);
        assert!(spans[0].style != Style::default());
        assert!(spans[19].style != Style::default());
    }

    #[test]
    fn truecolor_gradient_varies_across_bar() {
        let theme = theme_with_capability(ColorCapability::Truecolor);
        let cfg = config();
        let spans = rtt_bar_spans(500, 500, cfg, &theme);
        let first = spans[0].style.fg;
        let last = spans[19].style.fg;
        assert_ne!(first, last);
        assert_eq!(last, Some(Color::Rgb(214, 48, 48)));
        let Color::Rgb(red, green, blue) = first.unwrap() else {
            panic!("expected rgb color");
        };
        assert!(green > blue);
        assert!(red >= 72);
    }

    #[test]
    fn gradient_reaches_yellow_at_green_ms() {
        let cfg = config();
        assert_eq!(rtt_gradient_rgb(0, cfg), (72, 198, 108));
        assert_eq!(rtt_gradient_rgb(cfg.green_ms, cfg), (72, 198, 108));
    }

    #[test]
    fn gradient_reaches_yellow_at_yellow_ms() {
        let cfg = config();
        let mid = rtt_gradient_rgb(75, cfg);
        assert!(mid.0 > 72);
        assert!(mid.1 < 214);
        assert_eq!(rtt_gradient_rgb(cfg.yellow_ms, cfg), (255, 214, 48));
    }

    #[test]
    fn gradient_reaches_orange_at_orange_ms() {
        let cfg = config();
        let mid = rtt_gradient_rgb(150, cfg);
        assert_eq!(mid.0, 255);
        assert!(mid.1 < 214);
        assert!(mid.1 > 48);
        assert_eq!(rtt_gradient_rgb(cfg.orange_ms, cfg), (255, 132, 32));
    }

    #[test]
    fn gradient_reaches_red_at_insane_ms() {
        let cfg = config();
        assert_eq!(rtt_gradient_rgb(cfg.insane_ms, cfg), (214, 48, 48));
    }

    #[test]
    fn gradient_interpolates_toward_next_step_before_milestone() {
        let cfg = config();
        let early = rtt_gradient_rgb(25, cfg);
        assert_eq!(early, (72, 198, 108));
        let late = rtt_gradient_rgb(75, cfg);
        assert!(late.1 > 198);
        assert!(late.0 > 72);
    }

    #[test]
    fn max_rtt_for_visible_reads_hop_rtts() {
        let trace = build_linear_tree(
            vec![hop(40), hop(120)],
            TraceTreeRequest {
                qname: "example.com.".into(),
                qtype: "A".into(),
                started_at: "2026-01-01T00:00:00Z".into(),
            },
        );
        let tree = super::super::tree::build_explore_tree(&trace);
        let visible = tree.visible_nodes(&tree.default_expanded_paths());
        assert_eq!(max_rtt_ms_for_visible(&tree, &visible), 120);
    }
}
