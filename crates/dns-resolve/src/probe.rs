//! Optional network probes used by comparison, never by ordinary traces.

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

pub mod icmp;

pub use icmp::DatagramIcmpProber;

/// Counts datagram ICMP probe attempts. Ordinary traces must leave this at zero.
pub static ICMP_PROBE_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IcmpProbeResult {
    Rtt(Duration),
    Unavailable,
    Error(String),
}

pub trait IcmpProber: Send + Sync {
    fn probe(&self, addr: IpAddr, timeout: Duration) -> IcmpProbeResult;
}

/// Map any probe outcome to an optional RTT. Never fails the caller.
pub fn probe_icmp_rtt(prober: &dyn IcmpProber, addr: IpAddr) -> Option<u64> {
    match prober.probe(addr, Duration::from_millis(200)) {
        IcmpProbeResult::Rtt(duration) => Some(duration.as_millis() as u64),
        IcmpProbeResult::Unavailable | IcmpProbeResult::Error(_) => None,
    }
}

pub fn reset_icmp_probe_attempts() {
    ICMP_PROBE_ATTEMPTS.store(0, Ordering::SeqCst);
}

pub fn icmp_probe_attempts() -> usize {
    ICMP_PROBE_ATTEMPTS.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    struct ScriptedProber {
        result: IcmpProbeResult,
    }

    impl IcmpProber for ScriptedProber {
        fn probe(&self, _addr: IpAddr, _timeout: Duration) -> IcmpProbeResult {
            self.result.clone()
        }
    }

    #[test]
    fn success_returns_millis() {
        let prober = ScriptedProber {
            result: IcmpProbeResult::Rtt(Duration::from_millis(42)),
        };
        assert_eq!(
            probe_icmp_rtt(&prober, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            Some(42)
        );
    }

    #[test]
    fn unavailable_and_error_do_not_fail() {
        let unavailable = ScriptedProber {
            result: IcmpProbeResult::Unavailable,
        };
        let error = ScriptedProber {
            result: IcmpProbeResult::Error("send failed".into()),
        };
        let addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(probe_icmp_rtt(&unavailable, addr), None);
        assert_eq!(probe_icmp_rtt(&error, addr), None);
    }
}
