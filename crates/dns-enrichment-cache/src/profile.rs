use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Probe parameters that distinguish ICMP cache entries for the same IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProbeProfile {
    pub timeout_ms: u64,
    pub ping_samples: u8,
}

impl ProbeProfile {
    pub const DEFAULT_TIMEOUT_MS: u64 = 200;
    pub const DEFAULT_PING_SAMPLES: u8 = 3;

    pub fn enrichment_default() -> Self {
        Self {
            timeout_ms: Self::DEFAULT_TIMEOUT_MS,
            ping_samples: Self::DEFAULT_PING_SAMPLES,
        }
    }

    pub fn profile_hash(&self) -> String {
        let mut hasher = DefaultHasher::new();
        Hash::hash(self, &mut hasher);
        format!("{:016x}", hasher.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn different_profiles_do_not_collide() {
        let a = ProbeProfile::enrichment_default();
        let mut b = ProbeProfile::enrichment_default();
        b.ping_samples = 5;
        assert_ne!(a.profile_hash(), b.profile_hash());
    }

    #[test]
    fn same_profile_is_stable() {
        let profile = ProbeProfile::enrichment_default();
        assert_eq!(profile.profile_hash(), profile.profile_hash());
    }
}
