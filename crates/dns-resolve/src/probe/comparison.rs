//! ICMP prober selected for fork comparison export.

use std::sync::OnceLock;
use std::time::Duration;

use super::icmp::{DatagramIcmpProber, datagram_icmp_socket_available};
use super::ping_command::PingCommandProber;
use super::snapshot::{IcmpMethod, IcmpSnapshot};
use super::{IcmpProbeResult, IcmpProber, probe_icmp_rtt};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpProbeCapability {
    /// Native unprivileged datagram ICMP sockets work on this host.
    Datagram,
    /// Datagram sockets are blocked; `/bin/ping` is used instead.
    PingCommand,
    /// Neither datagram sockets nor a working `ping` binary is available.
    None,
}

#[derive(Debug)]
pub struct ComparisonIcmpProber {
    capability: IcmpProbeCapability,
    datagram: DatagramIcmpProber,
    ping: Option<PingCommandProber>,
}

impl ComparisonIcmpProber {
    pub fn new() -> Self {
        if datagram_icmp_socket_available() {
            return Self {
                capability: IcmpProbeCapability::Datagram,
                datagram: DatagramIcmpProber::default(),
                ping: None,
            };
        }
        if let Some(ping) = PingCommandProber::discover() {
            return Self {
                capability: IcmpProbeCapability::PingCommand,
                datagram: DatagramIcmpProber::default(),
                ping: Some(ping),
            };
        }
        Self {
            capability: IcmpProbeCapability::None,
            datagram: DatagramIcmpProber::default(),
            ping: None,
        }
    }

    pub fn capability(&self) -> IcmpProbeCapability {
        self.capability
    }

    pub fn probe_enrichment_snapshot(
        &self,
        addr: std::net::IpAddr,
        timeout_ms: u64,
        ping_samples: u8,
        probed_at: impl Into<String>,
    ) -> Option<IcmpSnapshot> {
        let timeout = Duration::from_millis(timeout_ms.max(1));
        let probed_at = probed_at.into();
        match self.capability {
            IcmpProbeCapability::Datagram => probe_icmp_rtt(self, addr)
                .map(|rtt| IcmpSnapshot::from_single_rtt(IcmpMethod::Datagram, rtt, probed_at)),
            IcmpProbeCapability::PingCommand => {
                let ping = self.ping.as_ref()?;
                let stats = ping.probe_samples(addr, timeout, ping_samples).ok()?;
                Some(IcmpSnapshot {
                    method: IcmpMethod::Ping,
                    samples: stats.samples.max(1),
                    min_ms: stats.min_ms.round() as u64,
                    avg_ms: stats.avg_ms.round() as u64,
                    max_ms: stats.max_ms.round() as u64,
                    probed_at,
                })
            }
            IcmpProbeCapability::None => None,
        }
    }
}

impl Default for ComparisonIcmpProber {
    fn default() -> Self {
        Self::new()
    }
}

/// Process-wide comparison prober (detects datagram vs `/bin/ping` once).
pub fn comparison_icmp_prober() -> &'static ComparisonIcmpProber {
    static PROBER: OnceLock<ComparisonIcmpProber> = OnceLock::new();
    PROBER.get_or_init(ComparisonIcmpProber::new)
}

impl IcmpProber for ComparisonIcmpProber {
    fn probe(&self, addr: std::net::IpAddr, timeout: Duration) -> IcmpProbeResult {
        match self.capability {
            IcmpProbeCapability::Datagram => self.datagram.probe(addr, timeout),
            IcmpProbeCapability::PingCommand => self
                .ping
                .as_ref()
                .expect("ping prober")
                .probe(addr, timeout),
            IcmpProbeCapability::None => IcmpProbeResult::Unavailable,
        }
    }
}
