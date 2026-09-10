use std::net::IpAddr;
use std::path::Path;
use std::sync::Mutex;

use dns_resolve::IcmpSnapshot;
use rusqlite::{Connection, params};

use crate::error::{EnrichmentCacheError, Result};
use crate::profile::ProbeProfile;

pub const DEFAULT_ICMP_TTL_SECONDS: u32 = 15 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpCacheStats {
    pub entries: usize,
}

pub struct SqliteEnrichmentCache {
    conn: Mutex<Connection>,
    icmp_ttl_seconds: u32,
}

impl SqliteEnrichmentCache {
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_ttl(path, DEFAULT_ICMP_TTL_SECONDS)
    }

    pub fn open_with_ttl(path: &Path, icmp_ttl_seconds: u32) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| EnrichmentCacheError::Database(error.to_string()))?;
        }
        let conn = Connection::open(path)
            .map_err(|error| EnrichmentCacheError::Database(error.to_string()))?;
        init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
            icmp_ttl_seconds,
        })
    }

    pub fn icmp_ttl_seconds(&self) -> u32 {
        self.icmp_ttl_seconds
    }

    pub fn get_icmp(
        &self,
        ip: IpAddr,
        profile: &ProbeProfile,
        now_unix: i64,
    ) -> Option<IcmpSnapshot> {
        let guard = self.conn.lock().expect("sqlite lock");
        let profile_hash = profile.profile_hash();
        let mut stmt = guard
            .prepare(
                "SELECT snapshot_json, expires_at FROM icmp_cache
                 WHERE ip = ?1 AND profile_hash = ?2 LIMIT 1",
            )
            .ok()?;
        let row = stmt.query_row(params![ip.to_string(), profile_hash], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        });
        match row {
            Ok((snapshot_json, expires_at)) if expires_at > now_unix => {
                serde_json::from_str(&snapshot_json).ok()
            }
            Ok(_) => None,
            Err(_) => None,
        }
    }

    pub fn put_icmp(
        &self,
        ip: IpAddr,
        profile: &ProbeProfile,
        snapshot: &IcmpSnapshot,
        now_unix: i64,
    ) -> Result<()> {
        let guard = self.conn.lock().expect("sqlite lock");
        let profile_hash = profile.profile_hash();
        let snapshot_json = serde_json::to_string(snapshot)
            .map_err(|error| EnrichmentCacheError::Serialization(error.to_string()))?;
        let expires_at = now_unix + i64::from(self.icmp_ttl_seconds);
        guard
            .execute(
                "INSERT OR REPLACE INTO icmp_cache
                 (ip, profile_hash, snapshot_json, written_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    ip.to_string(),
                    profile_hash,
                    snapshot_json,
                    now_unix,
                    expires_at
                ],
            )
            .map_err(|error| EnrichmentCacheError::Database(error.to_string()))?;
        Ok(())
    }

    pub fn purge_expired_icmp(&self, now_unix: i64) -> Result<usize> {
        let guard = self.conn.lock().expect("sqlite lock");
        let deleted = guard
            .execute(
                "DELETE FROM icmp_cache WHERE expires_at <= ?1",
                params![now_unix],
            )
            .map_err(|error| EnrichmentCacheError::Database(error.to_string()))?;
        Ok(deleted)
    }

    pub fn purge_all_icmp(&self) -> Result<usize> {
        let guard = self.conn.lock().expect("sqlite lock");
        let deleted = guard
            .execute("DELETE FROM icmp_cache", [])
            .map_err(|error| EnrichmentCacheError::Database(error.to_string()))?;
        Ok(deleted)
    }

    pub fn icmp_stats(&self) -> Result<IcmpCacheStats> {
        let guard = self.conn.lock().expect("sqlite lock");
        let entries = guard
            .query_row("SELECT COUNT(*) FROM icmp_cache", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(|error| EnrichmentCacheError::Database(error.to_string()))?
            as usize;
        Ok(IcmpCacheStats { entries })
    }
}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS icmp_cache (
            ip TEXT NOT NULL,
            profile_hash TEXT NOT NULL,
            snapshot_json TEXT NOT NULL,
            written_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            PRIMARY KEY (ip, profile_hash)
        );
        CREATE TABLE IF NOT EXISTS asn_cache (
            ip TEXT NOT NULL,
            profile_hash TEXT NOT NULL,
            snapshot_json TEXT NOT NULL,
            written_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            PRIMARY KEY (ip, profile_hash)
        );
        CREATE TABLE IF NOT EXISTS geo_cache (
            ip TEXT NOT NULL,
            profile_hash TEXT NOT NULL,
            snapshot_json TEXT NOT NULL,
            written_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            PRIMARY KEY (ip, profile_hash)
        );",
    )
    .map_err(|error| EnrichmentCacheError::Database(error.to_string()))?;
    Ok(())
}

pub fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dns_resolve::{IcmpMethod, IcmpSnapshot};
    use std::net::{IpAddr, Ipv4Addr};

    fn sample_snapshot(probed_at: &str) -> IcmpSnapshot {
        IcmpSnapshot {
            method: IcmpMethod::Datagram,
            samples: 1,
            min_ms: 10,
            avg_ms: 10,
            max_ms: 10,
            probed_at: probed_at.into(),
        }
    }

    #[test]
    fn insert_and_get_icmp_within_ttl() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("enrichment.sqlite");
        let cache = SqliteEnrichmentCache::open(&path).expect("open");
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let profile = ProbeProfile::enrichment_default();
        let now = now_unix();
        let snapshot = sample_snapshot("2026-09-05T00:00:00Z");
        cache.put_icmp(ip, &profile, &snapshot, now).expect("put");
        let loaded = cache.get_icmp(ip, &profile, now).expect("get");
        assert_eq!(loaded, snapshot);
    }

    #[test]
    fn expired_entry_is_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("enrichment.sqlite");
        let cache = SqliteEnrichmentCache::open(&path).expect("open");
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let profile = ProbeProfile::enrichment_default();
        let written_at = now_unix() - i64::from(DEFAULT_ICMP_TTL_SECONDS) - 1;
        cache
            .put_icmp(ip, &profile, &sample_snapshot("old"), written_at)
            .expect("put");
        assert!(cache.get_icmp(ip, &profile, now_unix()).is_none());
    }

    #[test]
    fn different_profile_hashes_do_not_collide() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("enrichment.sqlite");
        let cache = SqliteEnrichmentCache::open(&path).expect("open");
        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let profile_a = ProbeProfile::enrichment_default();
        let mut profile_b = ProbeProfile::enrichment_default();
        profile_b.ping_samples = 5;
        let now = now_unix();
        let snapshot_a = sample_snapshot("a");
        let snapshot_b = IcmpSnapshot {
            samples: 5,
            avg_ms: 20,
            ..sample_snapshot("b")
        };
        cache
            .put_icmp(ip, &profile_a, &snapshot_a, now)
            .expect("put a");
        cache
            .put_icmp(ip, &profile_b, &snapshot_b, now)
            .expect("put b");
        assert_eq!(
            cache.get_icmp(ip, &profile_a, now).as_ref(),
            Some(&snapshot_a)
        );
        assert_eq!(
            cache.get_icmp(ip, &profile_b, now).as_ref(),
            Some(&snapshot_b)
        );
    }

    #[test]
    fn purge_expired_removes_stale_rows() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("enrichment.sqlite");
        let cache = SqliteEnrichmentCache::open(&path).expect("open");
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let profile = ProbeProfile::enrichment_default();
        let stale_at = now_unix() - i64::from(DEFAULT_ICMP_TTL_SECONDS) - 10;
        cache
            .put_icmp(ip, &profile, &sample_snapshot("stale"), stale_at)
            .expect("put");
        let purged = cache.purge_expired_icmp(now_unix()).expect("purge");
        assert_eq!(purged, 1);
        assert_eq!(cache.icmp_stats().expect("stats").entries, 0);
    }
}
