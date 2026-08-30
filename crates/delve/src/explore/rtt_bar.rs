use ratatui::style::Style;
use ratatui::text::Span;

use crate::config::RttBarConfig;

use super::theme::Theme;

pub fn rtt_bar_spans(rtt_ms: u32, config: RttBarConfig, theme: &Theme) -> Vec<Span<'static>> {
    if rtt_ms == 0 {
        return Vec::new();
    }
    let config = config.normalized();
    let scale_ms = config.insane_ms.max(1) as f64;
    let char_count = ((rtt_ms as f64 / scale_ms) * config.max_width as f64).ceil() as u16;
    let char_count = char_count.clamp(1, config.max_width);
    let ms_per_char = scale_ms / config.max_width as f64;

    (0..char_count)
        .map(|index| {
            let ms_at = ((index + 1) as f64 * ms_per_char).round() as u32;
            Span::styled("█", style_for_rtt(ms_at, config, theme))
        })
        .collect()
}

pub fn style_for_rtt(rtt_ms: u32, config: RttBarConfig, theme: &Theme) -> Style {
    let config = config.normalized();
    if !theme.color_enabled {
        return Style::default();
    }
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

    #[test]
    fn bar_length_scales_with_rtt() {
        let config = RttBarConfig {
            green_ms: 50,
            yellow_ms: 100,
            orange_ms: 200,
            insane_ms: 100,
            max_width: 10,
        };
        let theme = Theme::from_env();
        let short = rtt_bar_spans(10, config, &theme);
        let long = rtt_bar_spans(90, config, &theme);
        assert!(short.len() < long.len());
    }

    #[test]
    fn zero_rtt_produces_empty_bar() {
        let config = RttBarConfig::default();
        let theme = Theme::from_env();
        assert!(rtt_bar_spans(0, config, &theme).is_empty());
    }
}
