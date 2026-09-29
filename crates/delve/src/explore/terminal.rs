use std::sync::OnceLock;

pub use crate::display::{
    UiSymbols, cache_source_label, cache_source_legend, cache_source_symbol, format_cache_source,
    ui_symbols,
};

/// How many distinct colors the terminal can render for RTT bar gradients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorCapability {
    /// 8/16 ANSI colors — stepped threshold bands.
    Basic,
    /// 256-color palette — smooth gradient via indexed colors.
    Indexed,
    /// 24-bit RGB — smooth gradient via truecolor.
    Truecolor,
}

static COLOR_DETECTED: OnceLock<ColorCapability> = OnceLock::new();

pub fn detect_color_capability() -> ColorCapability {
    *COLOR_DETECTED.get_or_init(detect_color_capability_uncached)
}

fn detect_color_capability_uncached() -> ColorCapability {
    if force_basic_colors() {
        return ColorCapability::Basic;
    }
    if force_truecolor() {
        return ColorCapability::Truecolor;
    }
    if terminal_reports_truecolor() {
        return ColorCapability::Truecolor;
    }
    if terminal_reports_256color() {
        return ColorCapability::Indexed;
    }
    if modern_terminal_hint() {
        return ColorCapability::Truecolor;
    }
    ColorCapability::Basic
}

fn force_basic_colors() -> bool {
    is_set("DELVE_BASIC_COLORS") || is_set("DELVE_NO_TRUECOLOR")
}

fn force_truecolor() -> bool {
    is_set("DELVE_TRUECOLOR")
}

fn terminal_reports_truecolor() -> bool {
    matches!(
        std::env::var("COLORTERM").as_deref(),
        Ok("truecolor") | Ok("24bit")
    ) || term_contains_any(&["truecolor", "direct"])
}

fn terminal_reports_256color() -> bool {
    term_contains_any(&["256color"])
}

fn term_contains_any(needles: &[&str]) -> bool {
    let Ok(term) = std::env::var("TERM") else {
        return false;
    };
    let lower = term.to_ascii_lowercase();
    needles.iter().any(|needle| lower.contains(needle))
}

fn is_set(name: &str) -> bool {
    match std::env::var(name) {
        Ok(value) => !value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("false"),
        Err(_) => false,
    }
}

fn modern_terminal_hint() -> bool {
    std::env::var("WT_SESSION").is_ok()
        || std::env::var("KITTY_WINDOW_ID").is_ok()
        || std::env::var("ALACRITTY_WINDOW_ID").is_ok()
        || std::env::var("KONSOLE_VERSION").is_ok()
        || matches!(
            std::env::var("TERM_PROGRAM").as_deref(),
            Ok("iTerm.app")
                | Ok("Apple_Terminal")
                | Ok("WezTerm")
                | Ok("vscode")
                | Ok("Tabby")
                | Ok("ghostty")
        )
}

/// Map an sRGB triplet to the nearest ANSI 256-color index.
pub fn rgb_to_ansi256(red: u8, green: u8, blue: u8) -> u8 {
    if red == green && green == blue {
        if red < 8 {
            return 16;
        }
        if red > 248 {
            return 231;
        }
        return (((f32::from(red) - 8.0) / 247.0) * 24.0).round() as u8 + 232;
    }

    let red_index = (f32::from(red) / 255.0 * 5.0).round() as u8;
    let green_index = (f32::from(green) / 255.0 * 5.0).round() as u8;
    let blue_index = (f32::from(blue) / 255.0 * 5.0).round() as u8;
    16 + 36 * red_index + 6 * green_index + blue_index
}

#[cfg(test)]
mod tests {
    #[test]
    fn rgb_to_ansi256_maps_grayscale_and_cube() {
        assert_eq!(super::rgb_to_ansi256(0, 0, 0), 16);
        assert_eq!(super::rgb_to_ansi256(255, 255, 255), 231);
        assert_eq!(super::rgb_to_ansi256(255, 0, 0), 196);
    }
}
