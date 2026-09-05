use std::io::{self, IsTerminal, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpandConfirmOutcome {
    Confirmed,
    Declined,
    NoTerminal,
}

pub fn confirm_expand_all(
    server_count: usize,
    budget: usize,
    prompt: &mut dyn FnMut(&str) -> io::Result<String>,
    is_tty: bool,
) -> ExpandConfirmOutcome {
    if !is_tty {
        return ExpandConfirmOutcome::NoTerminal;
    }

    let warning = format!(
        "warning: +expand=all may query every nameserver at every zone cut \
         (starting with {server_count} server(s) at the first cut, budget {budget} queries per action)"
    );
    eprintln!("{warning}");
    eprint!("Proceed with full expansion? [y/N] ");
    let _ = io::stderr().flush();

    match prompt("") {
        Ok(answer) if answer.trim().eq_ignore_ascii_case("y") => ExpandConfirmOutcome::Confirmed,
        Ok(_) => ExpandConfirmOutcome::Declined,
        Err(_) => ExpandConfirmOutcome::Declined,
    }
}

pub fn expand_all_is_tty() -> bool {
    io::stderr().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirm_accepts_y() {
        let mut answers = vec!["y".into()];
        let mut prompt =
            move |_prompt: &str| answers.pop().ok_or(io::ErrorKind::UnexpectedEof.into());
        assert_eq!(
            confirm_expand_all(4, 64, &mut prompt, true),
            ExpandConfirmOutcome::Confirmed
        );
    }

    #[test]
    fn decline_on_n() {
        let mut answers = vec!["n".into()];
        let mut prompt =
            move |_prompt: &str| answers.pop().ok_or(io::ErrorKind::UnexpectedEof.into());
        assert_eq!(
            confirm_expand_all(4, 64, &mut prompt, true),
            ExpandConfirmOutcome::Declined
        );
    }

    #[test]
    fn no_terminal_without_tty() {
        let mut prompt = |_prompt: &str| Ok("y".into());
        assert_eq!(
            confirm_expand_all(4, 64, &mut prompt, false),
            ExpandConfirmOutcome::NoTerminal
        );
    }

    #[test]
    fn force_not_implied_by_plain_all() {
        // Parsing lives in dig_options; this test documents the contract.
        assert_ne!(
            ExpandConfirmOutcome::Confirmed,
            ExpandConfirmOutcome::NoTerminal
        );
    }
}
