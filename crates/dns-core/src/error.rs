use thiserror::Error;

#[derive(Debug, Error)]
pub enum DnsCoreError {
    #[error("failed to parse DNS message: {0}")]
    Parse(String),

    #[error("invalid domain name: {0}")]
    Name(String),

    #[error("unsupported record type: {0}")]
    RecordType(String),
}

pub type Result<T> = std::result::Result<T, DnsCoreError>;
