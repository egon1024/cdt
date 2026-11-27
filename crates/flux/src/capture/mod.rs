mod decode;
mod file;
pub mod iface_spec;
pub mod l3;
pub mod listeners;
#[cfg(target_os = "linux")]
pub mod live;
mod ports;
pub mod topology;

pub use decode::{DecodedDns, FrameError, decode_frame};
pub use file::{
    CaptureError, PacketSource, iter_packets, iter_packets_multi, open_packet_source, sniff_format,
    write_pcap_file, write_pcapng_dup,
};
pub use iface_spec::{IfaceSpecError, ListenerSpec, parse_interface_args};
pub use l3::{DnsL3Payload, L3Error, L3Transport, parse_l3};
pub use listeners::{
    InterfaceTable, ListenerError, NetInterface, host_interface_table, opened_interfaces_message,
    resolve_listeners,
};
pub use ports::{PortParseError, PortSet, initiator_is_src};
pub use topology::{
    LinuxSysTopology, MockTopology, NetTopology, TopologySource, discover_topology,
    topology_duplicate_hints,
};

#[cfg(target_os = "linux")]
pub use live::{LiveCapture, LiveCaptureError, LiveCaptureOpts, fanout_available, open_live};

#[derive(Debug, Clone)]
pub struct RawPacket {
    pub data: Vec<u8>,
    pub timestamp_secs: u64,
    pub timestamp_subsec_ns: u32,
    pub iface: String,
}

impl RawPacket {
    pub fn timestamp_nanos(&self) -> u128 {
        u128::from(self.timestamp_secs) * 1_000_000_000 + u128::from(self.timestamp_subsec_ns)
    }

    pub fn slice_second(&self) -> u64 {
        self.timestamp_secs
    }
}
