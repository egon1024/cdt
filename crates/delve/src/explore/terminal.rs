use std::sync::OnceLock;

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

/// How richly we can render non-ASCII UI chrome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextCapability {
    /// 7-bit-safe fallbacks only.
    Ascii,
    /// Box drawing and geometric symbols (◆, ├, ▼, …).
    Unicode,
    /// Likely emoji-capable terminal; emoji only where layout is not affected.
    Emoji,
}

/// Glyphs used in explore output. Keep width at one column for tree alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UiSymbols {
    pub cache: &'static str,
    pub live: &'static str,
    pub tree_expand: &'static str,
    pub tree_collapse: &'static str,
    pub branch_tee: &'static str,
    pub branch_end: &'static str,
    pub branch_pipe: &'static str,
    pub missing: &'static str,
    /// Optional emoji legend labels (help overlay only); `None` when not using emoji.
    pub cache_legend: Option<&'static str>,
    pub live_legend: Option<&'static str>,
}

const ASCII: UiSymbols = UiSymbols {
    cache: "*",
    live: "o",
    tree_expand: "+",
    tree_collapse: "-",
    branch_tee: "|-- ",
    branch_end: "`-- ",
    branch_pipe: "|  ",
    missing: "-",
    cache_legend: None,
    live_legend: None,
};

pub(crate) const UNICODE: UiSymbols = UiSymbols {
    cache: "◆",
    live: "◇",
    tree_expand: "▼ ",
    tree_collapse: "▶ ",
    branch_tee: "├─ ",
    branch_end: "└─ ",
    branch_pipe: "│  ",
    missing: "—",
    cache_legend: None,
    live_legend: None,
};

const EMOJI: UiSymbols = UiSymbols {
    cache: "◆",
    live: "◇",
    tree_expand: "▼ ",
    tree_collapse: "▶ ",
    branch_tee: "├─ ",
    branch_end: "└─ ",
    branch_pipe: "│  ",
    missing: "—",
    cache_legend: Some("📦"),
    live_legend: Some("⚡"),
};

static DETECTED: OnceLock<TextCapability> = OnceLock::new();
static COLOR_DETECTED: OnceLock<ColorCapability> = OnceLock::new();

pub fn detect_color_capability() -> ColorCapability {
    *COLOR_DETECTED.get_or_init(detect_color_capability_uncached)
}

pub fn detect_text_capability() -> TextCapability {
    *DETECTED.get_or_init(detect_text_capability_uncached)
}

pub fn ui_symbols() -> UiSymbols {
    match detect_text_capability() {
        TextCapability::Ascii => ASCII,
        TextCapability::Unicode => UNICODE,
        TextCapability::Emoji => EMOJI,
    }
}

pub fn cache_source_symbol(from_cache: bool, symbols: UiSymbols) -> &'static str {
    if from_cache {
        symbols.cache
    } else {
        symbols.live
    }
}

pub fn cache_source_legend(symbols: UiSymbols) -> [(&'static str, &'static str); 2] {
    [
        (
            symbols.cache_legend.unwrap_or(symbols.cache),
            "response from cache",
        ),
        (
            symbols.live_legend.unwrap_or(symbols.live),
            "live DNS lookup",
        ),
    ]
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

fn detect_text_capability_uncached() -> TextCapability {
    if force_ascii() {
        return TextCapability::Ascii;
    }
    if force_unicode() {
        return if terminal_supports_emoji() {
            TextCapability::Emoji
        } else {
            TextCapability::Unicode
        };
    }
    if !locale_supports_utf8() {
        return TextCapability::Ascii;
    }
    if terminal_supports_emoji() {
        TextCapability::Emoji
    } else {
        TextCapability::Unicode
    }
}

fn force_ascii() -> bool {
    is_set("DELVE_ASCII") || is_set("DELVE_NO_UNICODE")
}

fn force_unicode() -> bool {
    is_set("DELVE_UNICODE")
}

fn is_set(name: &str) -> bool {
    match std::env::var(name) {
        Ok(value) => !value.is_empty() && value != "0" && !value.eq_ignore_ascii_case("false"),
        Err(_) => false,
    }
}

fn locale_supports_utf8() -> bool {
    for var in ["LC_ALL", "LC_CTYPE", "LANG"] {
        let Ok(value) = std::env::var(var) else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        if value.eq_ignore_ascii_case("C") || value.starts_with("C.") || value == "POSIX" {
            return false;
        }
        let lower = value.to_ascii_lowercase();
        if lower.contains("utf-8") || lower.contains("utf8") {
            return true;
        }
    }

    // Modern GUI terminals often omit UTF-8 locale vars but still render Unicode.
    modern_terminal_hint()
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

fn terminal_supports_emoji() -> bool {
    if is_set("DELVE_NO_EMOJI") {
        return false;
    }
    if !locale_supports_utf8() && !modern_terminal_hint() {
        return false;
    }

    std::env::var("WT_SESSION").is_ok()
        || std::env::var("KITTY_WINDOW_ID").is_ok()
        || matches!(
            std::env::var("TERM_PROGRAM").as_deref(),
            Ok("iTerm.app") | Ok("Apple_Terminal") | Ok("WezTerm") | Ok("vscode") | Ok("Tabby")
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
    use super::*;

    #[test]
    fn ascii_symbols_are_single_column_safe() {
        for ch in [ASCII.cache, ASCII.live] {
            assert!(ch.is_ascii());
            assert_eq!(ch.chars().count(), 1);
        }
    }

    #[test]
    fn unicode_symbols_use_geometric_and_box_drawing() {
        assert_eq!(UNICODE.cache, "◆");
        assert_eq!(UNICODE.branch_tee, "├─ ");
    }

    #[test]
    fn emoji_tier_keeps_tree_symbols_unicode() {
        assert_eq!(EMOJI.tree_expand, UNICODE.tree_expand);
        assert_eq!(EMOJI.cache, UNICODE.cache);
        assert!(EMOJI.cache_legend.is_some());
    }

    #[test]
    fn cache_source_symbol_selects_glyph() {
        let symbols = UNICODE;
        assert_eq!(cache_source_symbol(true, symbols), "◆");
        assert_eq!(cache_source_symbol(false, symbols), "◇");
    }

    #[test]
    fn rgb_to_ansi256_maps_grayscale_and_cube() {
        assert_eq!(super::rgb_to_ansi256(0, 0, 0), 16);
        assert_eq!(super::rgb_to_ansi256(255, 255, 255), 231);
        assert_eq!(super::rgb_to_ansi256(255, 0, 0), 196);
    }
}
