use std::fs;
use std::path::Path;

use crate::paths::DelvePaths;
use crate::session::SessionError;

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

/// Default session for commands that omit an id: `DELVE_SESSION`, then last-session file.
pub fn default_session_id(paths: &DelvePaths) -> Result<String, SessionError> {
    if let Some(id) = read_env_session() {
        return Ok(id);
    }
    read_last_session(paths)
}

pub fn read_last_session(paths: &DelvePaths) -> Result<String, SessionError> {
    let path = paths.last_session_file();
    let id = fs::read_to_string(&path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                SessionError::NoLastSession
            } else {
                SessionError::Store(format!(
                    "failed to read last session from {}: {error}",
                    path.display()
                ))
            }
        })?
        .trim()
        .to_string();
    if id.is_empty() {
        return Err(SessionError::NoLastSession);
    }
    Ok(id)
}

pub fn write_last_session(paths: &DelvePaths, id: &str) -> Result<(), SessionError> {
    let path = paths.last_session_file();
    write_atomic(&path, id)
}

pub fn clear_last_session(paths: &DelvePaths) -> Result<(), SessionError> {
    let path = paths.last_session_file();
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(SessionError::Store(format!(
            "failed to clear last session at {}: {error}",
            path.display()
        ))),
    }
}

fn write_atomic(path: &Path, id: &str) -> Result<(), SessionError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| SessionError::Store(error.to_string()))?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, format!("{id}\n")).map_err(|error| SessionError::Store(error.to_string()))?;
    fs::rename(&tmp, path).map_err(|error| SessionError::Store(error.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::DelvePaths;

    #[test]
    fn round_trip_last_session() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = DelvePaths::from_root(dir.path());
        write_last_session(&paths, "01JTESTSESSION").expect("write");
        assert_eq!(read_last_session(&paths).expect("read"), "01JTESTSESSION");
        clear_last_session(&paths).expect("clear");
        assert!(matches!(
            read_last_session(&paths),
            Err(SessionError::NoLastSession)
        ));
    }

    #[test]
    fn default_session_env_resolution() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = DelvePaths::from_root(dir.path());
        write_last_session(&paths, "01JFROMFILE").expect("write");

        unsafe {
            std::env::set_var(DELVE_SESSION_ENV, "01JFROMENV");
        }
        assert_eq!(
            default_session_id(&paths).expect("env override"),
            "01JFROMENV"
        );

        unsafe {
            std::env::set_var(DELVE_SESSION_ENV, "   ");
        }
        assert_eq!(
            default_session_id(&paths).expect("empty env"),
            "01JFROMFILE"
        );

        unsafe {
            std::env::set_var(DELVE_SESSION_ENV, "  01JTRIMMED  ");
        }
        assert_eq!(
            default_session_id(&paths).expect("trimmed env"),
            "01JTRIMMED"
        );

        unsafe {
            std::env::remove_var(DELVE_SESSION_ENV);
        }
    }
}
