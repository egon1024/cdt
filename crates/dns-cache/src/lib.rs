mod error;
mod expiry;
mod key;
mod sqlite;

pub use error::{CacheError, Result};
pub use expiry::cache_ttl_seconds;
pub use key::CacheKey;
pub use sqlite::{CacheStats, SqliteCache};

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dns_core::response::QueryResult;

/// Cached query payload with receipt metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CachedEntry {
    pub result: QueryResult,
    pub received_at_unix: i64,
    pub ttl_seconds: u32,
}

impl CachedEntry {
    pub fn from_query_result(result: QueryResult, received_at_unix: i64, ttl_seconds: u32) -> Self {
        Self {
            result,
            received_at_unix,
            ttl_seconds,
        }
    }

    pub fn is_expired(&self, now_unix: i64) -> bool {
        now_unix >= self.received_at_unix + i64::from(self.ttl_seconds)
    }
}

/// Response cache contract used by the resolver.
pub trait ResponseCache: Send + Sync {
    fn get(&self, key: &CacheKey) -> Option<CachedEntry>;
    fn put(&self, key: &CacheKey, entry: CachedEntry) -> Result<()>;
    fn stats(&self) -> CacheStats;
    fn purge_expired(&self) -> Result<usize>;
    fn purge_all(&self) -> Result<usize>;
}

/// In-memory cache for unit tests.
#[derive(Debug, Default)]
pub struct MemoryCache {
    entries: std::sync::Mutex<std::collections::HashMap<String, CachedEntry>>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl MemoryCache {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ResponseCache for MemoryCache {
    fn get(&self, key: &CacheKey) -> Option<CachedEntry> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let key = key.storage_key();
        let guard = self.entries.lock().expect("cache lock");
        let entry = guard.get(&key)?;
        if entry.is_expired(now) {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        self.hits.fetch_add(1, Ordering::Relaxed);
        Some(entry.clone())
    }

    fn put(&self, key: &CacheKey, entry: CachedEntry) -> Result<()> {
        let key = key.storage_key();
        self.entries.lock().expect("cache lock").insert(key, entry);
        Ok(())
    }

    fn stats(&self) -> CacheStats {
        let guard = self.entries.lock().expect("cache lock");
        CacheStats {
            entries: guard.len(),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            bytes: 0,
        }
    }

    fn purge_expired(&self) -> Result<usize> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut guard = self.entries.lock().expect("cache lock");
        let before = guard.len();
        guard.retain(|_, entry| !entry.is_expired(now));
        Ok(before - guard.len())
    }

    fn purge_all(&self) -> Result<usize> {
        let mut guard = self.entries.lock().expect("cache lock");
        let count = guard.len();
        guard.clear();
        Ok(count)
    }
}

pub fn shared_cache(cache: MemoryCache) -> Arc<dyn ResponseCache> {
    Arc::new(cache)
}

pub fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

pub fn ttl_from_result(result: &QueryResult) -> Duration {
    let seconds = cache_ttl_seconds(&result.response);
    Duration::from_secs(seconds.max(1))
}
