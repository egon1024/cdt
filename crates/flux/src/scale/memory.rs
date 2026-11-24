#[derive(Debug, Clone, Copy)]
pub struct MemoryBudget {
    pub limit_bytes: usize,
}

impl MemoryBudget {
    pub fn from_limit(limit: usize) -> Self {
        Self {
            limit_bytes: limit.max(1024),
        }
    }

    pub fn is_over(&self, used: usize) -> bool {
        used >= self.limit_bytes
    }
}

#[derive(Debug, Default, Clone)]
pub struct MemoryCounters {
    pub arena_bytes: usize,
    pub record_bytes: usize,
    pub refused_records: u64,
}

impl MemoryCounters {
    pub fn total(&self) -> usize {
        self.arena_bytes.saturating_add(self.record_bytes)
    }
}

pub fn parse_mem_limit(raw: &str) -> Result<usize, String> {
    let raw = raw.trim();
    if let Some(kib) = raw.strip_suffix("KiB").or_else(|| raw.strip_suffix("Ki")) {
        let n: usize = kib.parse().map_err(|_| raw.to_string())?;
        return Ok(n.saturating_mul(1024));
    }
    if let Some(mib) = raw.strip_suffix("MiB").or_else(|| raw.strip_suffix("Mi")) {
        let n: usize = mib.parse().map_err(|_| raw.to_string())?;
        return Ok(n.saturating_mul(1024 * 1024));
    }
    if let Some(gib) = raw.strip_suffix("GiB").or_else(|| raw.strip_suffix("Gi")) {
        let n: usize = gib.parse().map_err(|_| raw.to_string())?;
        return Ok(n.saturating_mul(1024 * 1024 * 1024));
    }
    raw.parse::<usize>()
        .map_err(|_| format!("invalid +mem value: {raw}"))
}

#[cfg(target_os = "linux")]
fn physical_ram_bytes() -> usize {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse::<usize>().ok())
        })
        .map(|kib| kib.saturating_mul(1024))
        .unwrap_or(2 * 1024 * 1024 * 1024)
}

#[cfg(not(target_os = "linux"))]
fn physical_ram_bytes() -> usize {
    2 * 1024 * 1024 * 1024
}

/// Default memory cap: min(25% physical RAM, 2 GiB).
pub fn default_mem_limit() -> usize {
    let quarter = physical_ram_bytes() / 4;
    quarter.min(2 * 1024 * 1024 * 1024)
}

pub fn effective_mem_limit(explicit: Option<usize>) -> usize {
    explicit.unwrap_or_else(default_mem_limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mi_b() {
        assert_eq!(parse_mem_limit("8MiB").unwrap(), 8 * 1024 * 1024);
    }

    #[test]
    fn default_under_two_gib() {
        let d = default_mem_limit();
        assert!(d >= 1024);
        assert!(d <= 2 * 1024 * 1024 * 1024);
    }
}
