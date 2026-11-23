#![cfg(all(target_os = "linux", feature = "tui"))]

use std::io;
use std::time::{Duration, Instant};

use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};
use thiserror::Error;

use crate::options::{FluxOptions, ViewId};
use crate::view::format_batch_tables;

#[derive(Debug, Error)]
pub enum TuiError {
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub fn run_live(iface: &str, _options: FluxOptions) -> Result<(), TuiError> {
    let mut stdout = io::stdout();
    enable_raw_mode()?;
    stdout.execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;
    let mut view = ViewId::Sources;
    let start = Instant::now();
    loop {
        term.draw(|f| {
            let block = Block::default()
                .title(format!("flux watch {iface}"))
                .borders(Borders::ALL);
            let help = "s src d dst t qtype r rcode o opcode 1-3 qname ? help q quit";
            let counts = crate::view::ViewCounts::default();
            let body = format_batch_tables(&counts, &[view], 20, 0);
            let text = format!(
                "{body}\n{help}\nelapsed: {:.1}s",
                start.elapsed().as_secs_f32()
            );
            let para = Paragraph::new(text).block(block);
            f.render_widget(para, f.area());
        })?;
        if event::poll(Duration::from_millis(200))? {
            if let Event::Key(key) = event::read()? {
                if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
                    break;
                }
                match key.code {
                    KeyCode::Char('q') => break,
                    KeyCode::Char('s') => view = ViewId::Sources,
                    KeyCode::Char('d') => view = ViewId::Destinations,
                    KeyCode::Char('t') => view = ViewId::Qtype,
                    KeyCode::Char('r') => view = ViewId::Rcode,
                    KeyCode::Char('o') => view = ViewId::Opcode,
                    KeyCode::Char('1') => view = ViewId::QnameLevel(1),
                    KeyCode::Char('2') => view = ViewId::QnameLevel(2),
                    KeyCode::Char('3') => view = ViewId::QnameLevel(3),
                    KeyCode::Char('?') => {}
                    _ => {}
                }
            }
        }
    }
    disable_raw_mode()?;
    term.backend_mut().execute(LeaveAlternateScreen)?;
    Ok(())
}
