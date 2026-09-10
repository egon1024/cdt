use thiserror::Error;

pub type Result<T> = std::result::Result<T, EnrichmentCacheError>;

#[derive(Debug, Error)]
pub enum EnrichmentCacheError {
    #[error("enrichment cache database error: {0}")]
    Database(String),

    #[error("enrichment cache serialization error: {0}")]
    Serialization(String),
}
