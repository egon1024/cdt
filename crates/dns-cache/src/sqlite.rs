use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use rusqlite::{Connection, params};

use crate::error::{CacheError, Result};
use crate::{CacheKey, CachedEntry, ResponseCache};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheStats {
    pub entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub bytes: u64,
}

pub struct SqliteCache {
    conn: Mutex<Connection>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl SqliteCache {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| CacheError::Database(error.to_string()))?;
        }
        let conn =
            Connection::open(path).map_err(|error| CacheError::Database(error.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                received_at INTEGER NOT NULL,
                ttl_seconds INTEGER NOT NULL
            );",
        )
        .map_err(|error| CacheError::Database(error.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        })
    }

    pub fn open_readonly(path: &Path) -> Result<Self> {
        let conn = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|error| CacheError::Database(error.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        })
    }
}

impl ResponseCache for SqliteCache {
    fn get(&self, key: &CacheKey) -> Option<CachedEntry> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let guard = self.conn.lock().expect("sqlite lock");
        let key = key.storage_key();
        let mut stmt = guard
            .prepare("SELECT value, received_at, ttl_seconds FROM cache WHERE key = ?1 LIMIT 1")
            .map_err(|error| CacheError::Database(error.to_string()))
            .ok()?;
        let row = stmt.query_row(params![key], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, u32>(2)?,
            ))
        });
        match row {
            Ok((value, _received_at, _ttl_seconds)) => {
                let entry: CachedEntry = serde_json::from_str(&value)
                    .map_err(|error| CacheError::Serialization(error.to_string()))
                    .ok()?;
                if entry.is_expired(now) {
                    self.misses.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(entry)
            }
            Err(_) => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    fn put(&self, key: &CacheKey, entry: CachedEntry) -> Result<()> {
        let guard = self.conn.lock().expect("sqlite lock");
        let key = key.storage_key();
        let value = serde_json::to_string(&entry)
            .map_err(|error| CacheError::Serialization(error.to_string()))?;
        guard
            .execute(
                "INSERT OR REPLACE INTO cache (key, value, received_at, ttl_seconds)
                 VALUES (?1, ?2, ?3, ?4)",
                params![key, value, entry.received_at_unix, entry.ttl_seconds],
            )
            .map_err(|error| CacheError::Database(error.to_string()))?;
        Ok(())
    }

    fn stats(&self) -> CacheStats {
        let guard = self.conn.lock().expect("sqlite lock");
        let entries = guard
            .query_row("SELECT COUNT(*) FROM cache", [], |row| row.get::<_, i64>(0))
            .unwrap_or(0) as usize;
        let bytes = guard
            .query_row(
                "SELECT COALESCE(SUM(LENGTH(value)), 0) FROM cache",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0) as u64;
        CacheStats {
            entries,
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            bytes,
        }
    }

    fn purge_expired(&self) -> Result<usize> {
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let guard = self.conn.lock().expect("sqlite lock");
        let deleted = guard
            .execute(
                "DELETE FROM cache WHERE received_at + ttl_seconds <= ?1",
                params![now],
            )
            .map_err(|error| CacheError::Database(error.to_string()))?;
        Ok(deleted)
    }

    fn purge_all(&self) -> Result<usize> {
        let guard = self.conn.lock().expect("sqlite lock");
        let deleted = guard
            .execute("DELETE FROM cache", [])
            .map_err(|error| CacheError::Database(error.to_string()))?;
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use dns_core::EdnsMeta;
    use dns_core::name::DomainName;
    use dns_core::response::{DnsResponse, QueryResult, Transport};

    use crate::now_unix;

    fn sample_result() -> QueryResult {
        QueryResult {
            server: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            transport: Transport::Udp,
            qname: DomainName::parse("example.com.").expect("qname"),
            qtype: "A".into(),
            rtt: Duration::from_millis(12),
            response: DnsResponse {
                id: 1,
                rcode: 0,
                rcode_text: "NOERROR".into(),
                authoritative: true,
                truncated: false,
                answers: vec![],
                authorities: vec![],
                additionals: vec![],
                edns: EdnsMeta::default(),
            },
        }
    }

    #[test]
    fn round_trip_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cache.sqlite");
        let cache = SqliteCache::open(&path).expect("open");
        let key = CacheKey {
            server: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            port: 53,
            qname: "example.com.".into(),
            qtype: "A".into(),
            transport: Transport::Udp,
            dnssec: false,
            request_nsid: true,
        };
        let entry = CachedEntry::from_query_result(sample_result(), now_unix(), 300);
        cache.put(&key, entry.clone()).expect("put");
        let loaded = cache.get(&key).expect("get");
        assert_eq!(loaded.ttl_seconds, entry.ttl_seconds);
    }
}
