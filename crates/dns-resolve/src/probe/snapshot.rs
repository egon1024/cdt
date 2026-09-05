//! Serializable ICMP measurement stored on sessions and in the enrichment cache.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IcmpMethod {
    Datagram,
    Ping,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcmpSnapshot {
    pub method: IcmpMethod,
    pub samples: u8,
    pub min_ms: u64,
    pub avg_ms: u64,
    pub max_ms: u64,
    pub probed_at: String,
}

impl IcmpSnapshot {
    pub fn from_single_rtt(method: IcmpMethod, rtt_ms: u64, probed_at: impl Into<String>) -> Self {
        Self {
            method,
            samples: 1,
            min_ms: rtt_ms,
            avg_ms: rtt_ms,
            max_ms: rtt_ms,
            probed_at: probed_at.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn icmp_snapshot_round_trips_through_json() {
        let snapshot = IcmpSnapshot {
            method: IcmpMethod::Ping,
            samples: 3,
            min_ms: 10,
            avg_ms: 12,
            max_ms: 15,
            probed_at: "2026-09-05T12:00:00Z".into(),
        };
        let json = serde_json::to_string(&snapshot).expect("serialize");
        let decoded: IcmpSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(snapshot, decoded);
    }
}
