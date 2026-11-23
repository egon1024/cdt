use std::path::Path;

use thiserror::Error;

use crate::filter::{SavedFilterError, validate_filter_yaml};

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
    validate_filter_yaml(&content, path).map_err(map_saved_err)?;
    let _ = Path::new(path);
    Ok(())
}

fn map_saved_err(err: SavedFilterError) -> ValidateError {
    match err {
        SavedFilterError::FileLine {
            file,
            line,
            message,
        } => ValidateError::FileLine {
            file,
            line,
            message,
        },
        SavedFilterError::UnknownField(f) => ValidateError::FileLine {
            file: "filter".into(),
            line: 1,
            message: format!("unknown field {f}"),
        },
        SavedFilterError::Io(e) => ValidateError::Io("filter".into(), e),
        SavedFilterError::Yaml(e) => ValidateError::FileLine {
            file: "filter".into(),
            line: e.location().map(|l| l.line() as u32).unwrap_or(1),
            message: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn valid_yaml_accepted() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "qtype: A").unwrap();
        validate_files(&[f.path().to_string_lossy().into()]).unwrap();
    }

    #[test]
    fn unknown_field_rejects() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "answer: foo").unwrap();
        let err = validate_files(&[f.path().to_string_lossy().into()]).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }
}
