use std::path::Path;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidateError {
    #[error("{file}:{line}: {message}")]
    FileLine {
        file: String,
        line: u32,
        message: String,
    },

    #[error("cannot read {0}: {1}")]
    Io(String, #[source] std::io::Error),
}

/// Phase 1 stub: no saved-filter compiler yet; reject obviously invalid YAML roots.
pub fn validate_files(paths: &[String]) -> Result<(), ValidateError> {
    for path in paths {
        validate_one(path)?;
    }
    Ok(())
}

fn validate_one(path: &str) -> Result<(), ValidateError> {
    let content =
        std::fs::read_to_string(path).map_err(|e| ValidateError::Io(path.to_string(), e))?;
    if content.trim().is_empty() {
        return Err(ValidateError::FileLine {
            file: path.to_string(),
            line: 1,
            message: "empty file".into(),
        });
    }
    // Accept any non-empty file in phase 1; full compiler arrives in phase 2.
    let _ = Path::new(path);
    Ok(())
}
