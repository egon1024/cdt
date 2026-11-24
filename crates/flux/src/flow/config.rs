use std::time::Duration;

use crate::capture::PortSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefragMode {
    On,
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpMode {
    Off,
    Simple,
    Full,
}

#[derive(Debug, Clone)]
pub struct FlowConfig {
    pub defrag: DefragMode,
    pub defrag_max_datagrams: usize,
    pub defrag_max_fragments: usize,
    pub defrag_timeout: Duration,
    pub tcp: TcpMode,
    pub tcp_max_connections: usize,
    pub tcp_max_buffer: usize,
    pub tcp_idle_timeout: Duration,
    pub tcp_max_faults: u32,
    pub pairing: bool,
    pub pair_timeout: Duration,
    pub pair_max: usize,
    pub dns_ports: PortSet,
    pub dedup: bool,
    pub dedup_window: Duration,
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self {
            defrag: DefragMode::On,
            defrag_max_datagrams: 512,
            defrag_max_fragments: 32,
            defrag_timeout: Duration::from_secs(30),
            tcp: TcpMode::Full,
            tcp_max_connections: 2048,
            tcp_max_buffer: 64 * 1024,
            tcp_idle_timeout: Duration::from_secs(120),
            tcp_max_faults: 3,
            pairing: true,
            pair_timeout: Duration::from_secs(5),
            pair_max: 10_000,
            dns_ports: PortSet::dns_default(),
            dedup: false,
            dedup_window: Duration::from_millis(5),
        }
    }
}

impl FlowConfig {
    pub fn from_options(opts: &crate::options::FluxOptions) -> Self {
        Self {
            defrag: opts.defrag,
            defrag_max_datagrams: opts.defrag_max_datagrams,
            defrag_max_fragments: opts.defrag_max_fragments,
            defrag_timeout: opts.defrag_timeout,
            tcp: opts.tcp,
            tcp_max_connections: opts.tcp_max_connections,
            tcp_max_buffer: opts.tcp_max_buffer,
            tcp_idle_timeout: opts.tcp_idle_timeout,
            tcp_max_faults: opts.tcp_max_faults,
            pairing: opts.pairing,
            pair_timeout: opts.pair_timeout,
            pair_max: opts.pair_max,
            dns_ports: opts.dns_ports.clone(),
            dedup: opts.dedup,
            dedup_window: opts.dedup_window,
        }
    }
}
