use ratatui::layout::{Constraint, Direction, Layout, Rect};

/// Adjustable vertical split between a top and bottom pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerticalPaneSplit {
    pub first_percent: u16,
}

impl VerticalPaneSplit {
    pub const DEFAULT_PERCENT: u16 = 55;
    pub const MIN_PERCENT: u16 = 25;
    pub const MAX_PERCENT: u16 = 75;
    pub const STEP: u16 = 5;

    pub fn new(percent: u16) -> Self {
        Self {
            first_percent: percent.clamp(Self::MIN_PERCENT, Self::MAX_PERCENT),
        }
    }

    pub fn from_stored(percent: u16) -> Self {
        if (Self::MIN_PERCENT..=Self::MAX_PERCENT).contains(&percent) {
            Self::new(percent)
        } else {
            Self::default()
        }
    }

    pub fn split(self, area: Rect) -> (Rect, Rect) {
        let second = 100 - self.first_percent;
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(self.first_percent),
                Constraint::Percentage(second),
            ])
            .split(area);
        (chunks[0], chunks[1])
    }

    pub fn grow_first(&mut self) {
        self.first_percent = (self.first_percent + Self::STEP).min(Self::MAX_PERCENT);
    }

    pub fn shrink_first(&mut self) {
        self.first_percent = self
            .first_percent
            .saturating_sub(Self::STEP)
            .max(Self::MIN_PERCENT);
    }
}

impl Default for VerticalPaneSplit {
    fn default() -> Self {
        Self::new(Self::DEFAULT_PERCENT)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AxisScrollHints {
    pub backward: bool,
    pub forward: bool,
}

impl AxisScrollHints {
    pub fn vertical(position: u16, max_scroll: u16) -> Self {
        Self {
            backward: position > 0,
            forward: position < max_scroll,
        }
    }

    pub fn horizontal(position: u16, max_scroll: u16) -> Self {
        Self::vertical(position, max_scroll)
    }

    pub fn format_vertical(self) -> String {
        format_directional_hints(self, '▲', '▼')
    }

    pub fn format_horizontal(self) -> String {
        format_directional_hints(self, '◀', '▶')
    }
}

fn format_directional_hints(hints: AxisScrollHints, backward: char, forward: char) -> String {
    if !hints.backward && !hints.forward {
        return String::new();
    }
    let mut rendered = String::from("  ");
    if hints.backward {
        rendered.push(backward);
    }
    if hints.forward {
        if hints.backward {
            rendered.push(' ');
        }
        rendered.push(forward);
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_percent_clamps_on_construct() {
        assert_eq!(
            VerticalPaneSplit::new(10).first_percent,
            VerticalPaneSplit::MIN_PERCENT
        );
        assert_eq!(
            VerticalPaneSplit::new(90).first_percent,
            VerticalPaneSplit::MAX_PERCENT
        );
    }

    #[test]
    fn grow_and_shrink_first_respect_bounds() {
        let mut split = VerticalPaneSplit::new(VerticalPaneSplit::MAX_PERCENT);
        split.grow_first();
        assert_eq!(split.first_percent, VerticalPaneSplit::MAX_PERCENT);

        split = VerticalPaneSplit::new(VerticalPaneSplit::MIN_PERCENT);
        split.shrink_first();
        assert_eq!(split.first_percent, VerticalPaneSplit::MIN_PERCENT);
    }

    #[test]
    fn vertical_scroll_hints_only_show_available_directions() {
        assert_eq!(AxisScrollHints::vertical(0, 0).format_vertical(), "");
        assert_eq!(AxisScrollHints::vertical(0, 5).format_vertical(), "  ▼");
        assert_eq!(AxisScrollHints::vertical(3, 5).format_vertical(), "  ▲ ▼");
        assert_eq!(AxisScrollHints::vertical(5, 5).format_vertical(), "  ▲");
    }

    #[test]
    fn horizontal_scroll_hints_only_show_available_directions() {
        assert_eq!(
            AxisScrollHints::horizontal(2, 4).format_horizontal(),
            "  ◀ ▶"
        );
        assert_eq!(AxisScrollHints::horizontal(0, 2).format_horizontal(), "  ▶");
    }
}
