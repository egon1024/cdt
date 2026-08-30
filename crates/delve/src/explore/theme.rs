use ratatui::style::{Color, Modifier, Style};

use super::terminal::{self, ColorCapability};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    pub color_enabled: bool,
    pub color_capability: ColorCapability,
    pub symbols: super::terminal::UiSymbols,
}

impl Theme {
    pub fn from_env() -> Self {
        Self {
            color_enabled: std::env::var("NO_COLOR").is_err(),
            color_capability: terminal::detect_color_capability(),
            symbols: super::terminal::ui_symbols(),
        }
    }

    pub fn toggle_color(&mut self) {
        self.color_enabled = !self.color_enabled;
    }

    pub fn color_status_hint(&self) -> &'static str {
        if !self.color_enabled {
            "off"
        } else {
            match self.color_capability {
                ColorCapability::Basic => "on",
                ColorCapability::Indexed => "256",
                ColorCapability::Truecolor => "rgb",
            }
        }
    }

    pub fn accent(&self) -> Style {
        if self.color_enabled {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        }
    }

    pub fn accent_bold(&self) -> Style {
        self.accent().add_modifier(Modifier::BOLD)
    }

    pub fn section(&self) -> Style {
        if self.color_enabled {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().add_modifier(Modifier::BOLD)
        }
    }

    pub fn label(&self) -> Style {
        if self.color_enabled {
            Style::default().fg(Color::Blue)
        } else {
            Style::default()
        }
    }

    pub fn meta(&self) -> Style {
        if self.color_enabled {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default()
        }
    }

    pub fn record_type(&self) -> Style {
        if self.color_enabled {
            Style::default().fg(Color::Magenta)
        } else {
            Style::default()
        }
    }

    pub fn rcode(&self, rcode: &str) -> Style {
        if !self.color_enabled {
            return Style::default();
        }
        match rcode {
            "NOERROR" => Style::default().fg(Color::Green),
            "NXDOMAIN" | "SERVFAIL" | "REFUSED" | "FORMERR" | "NOTIMP" => {
                Style::default().fg(Color::Red)
            }
            _ => Style::default().fg(Color::Yellow),
        }
    }

    pub fn zone(&self) -> Style {
        if self.color_enabled {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::BOLD)
        }
    }

    pub fn tree_selected(&self) -> Style {
        if self.color_enabled {
            // Blue (not cyan) so accent/zone text stays readable if a span style leaks through.
            Style::default()
                .fg(Color::White)
                .bg(Color::Blue)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::REVERSED)
        }
    }

    pub fn cache_source(&self, from_cache: bool) -> Style {
        if !self.color_enabled {
            return if from_cache {
                Style::default().add_modifier(Modifier::DIM)
            } else {
                Style::default()
            };
        }
        if from_cache {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Green)
        }
    }

    pub fn border_focused(&self) -> Style {
        if self.color_enabled {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        }
    }

    pub fn border_unfocused(&self) -> Style {
        if self.color_enabled {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default()
        }
    }

    pub fn flag_active(&self) -> Style {
        if self.color_enabled {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::BOLD)
        }
    }

    pub fn flag_inactive(&self) -> Style {
        if self.color_enabled {
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::DIM)
        } else {
            Style::default().add_modifier(Modifier::DIM)
        }
    }

    pub fn help_heading(&self) -> Style {
        self.accent_bold()
    }

    pub fn help_key(&self) -> Style {
        self.label().add_modifier(Modifier::BOLD)
    }

    pub fn failure(&self) -> Style {
        if self.color_enabled {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::BOLD)
        }
    }

    pub fn rtt_green(&self) -> Style {
        if self.color_enabled {
            Style::default().fg(Color::Green)
        } else {
            Style::default()
        }
    }

    pub fn rtt_yellow(&self) -> Style {
        if self.color_enabled {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        }
    }

    pub fn rtt_orange(&self) -> Style {
        if self.color_enabled {
            Style::default().fg(Color::Rgb(255, 165, 0))
        } else {
            Style::default()
        }
    }

    pub fn rtt_red(&self) -> Style {
        if self.color_enabled {
            Style::default().fg(Color::Red)
        } else {
            Style::default()
        }
    }
}
