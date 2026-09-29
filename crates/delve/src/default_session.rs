pub const DELVE_SESSION_ENV: &str = "DELVE_SESSION";

/// Session id from `DELVE_SESSION` when set and non-empty after trimming.
pub fn read_env_session() -> Option<String> {
    match std::env::var(DELVE_SESSION_ENV) {
        Ok(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => None,
    }
}

pub fn stale_delve_session_warning(env_value: &str) -> String {
    format!(
        "warning: DELVE_SESSION={env_value} is not a stored session; using the most recently modified session"
    )
}

/// Serializes tests that mutate process-global `DELVE_SESSION`.
#[cfg(test)]
pub fn test_env_lock() -> TestEnvLock {
    TestEnvLock::acquire()
}

#[cfg(test)]
static DELVE_SESSION_ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub struct TestEnvLock {
    _guard: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl TestEnvLock {
    fn acquire() -> Self {
        Self {
            _guard: DELVE_SESSION_ENV_TEST_LOCK
                .lock()
                .expect("DELVE_SESSION env test lock"),
        }
    }
}

#[cfg(test)]
impl Drop for TestEnvLock {
    fn drop(&mut self) {
        // SAFETY: tests hold the env lock; no other test reads `DELVE_SESSION` concurrently.
        unsafe {
            std::env::remove_var(DELVE_SESSION_ENV);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_delve_session_warning_message() {
        assert_eq!(
            stale_delve_session_warning("01JSTALEDELVESESSION"),
            "warning: DELVE_SESSION=01JSTALEDELVESESSION is not a stored session; using the most recently modified session"
        );
    }

    #[test]
    fn env_session_trimmed_and_empty_ignored() {
        let _lock = test_env_lock();
        unsafe {
            std::env::set_var(DELVE_SESSION_ENV, "  01JTRIMMED  ");
        }
        assert_eq!(read_env_session().expect("trimmed"), "01JTRIMMED");

        unsafe {
            std::env::set_var(DELVE_SESSION_ENV, "   ");
        }
        assert!(read_env_session().is_none());
    }
}
