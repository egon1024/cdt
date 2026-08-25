use thiserror::Error;

pub type Result<T> = std::result::Result<T, CacheError>;

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("cache database error: {0}")]
    Database(String),

    #[error("cache serialization error: {0}")]
    Serialization(String),
}
