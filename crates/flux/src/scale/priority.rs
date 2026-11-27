#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadRole {
    Aggregator,
    Tui,
    Parse,
    Capture,
    Flow,
}

/// Apply Linux nice value for the role; failures only warn.
pub fn apply_thread_priority(role: ThreadRole) -> Option<i32> {
    let nice = match role {
        ThreadRole::Aggregator => -5,
        ThreadRole::Tui => 5,
        ThreadRole::Parse | ThreadRole::Capture | ThreadRole::Flow => 0,
    };
    #[cfg(target_os = "linux")]
    {
        let rc = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, nice) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!(
                "flux: could not set {:?} thread priority to nice {}: {}",
                role, nice, err
            );
            return None;
        }
        Some(nice)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = role;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_returns_nice_or_warns() {
        let nice = apply_thread_priority(ThreadRole::Aggregator);
        #[cfg(target_os = "linux")]
        assert!(nice == Some(-5) || nice.is_none());
        #[cfg(not(target_os = "linux"))]
        assert!(nice.is_none());
    }
}
