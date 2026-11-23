mod decode;
mod file;
#[cfg(target_os = "linux")]
mod live;

pub use decode::{DecodedDns, FrameError, decode_frame};
pub use file::{
    CaptureError, PacketSource, iter_packets, open_packet_source, sniff_format, write_pcap_file,
};

#[cfg(target_os = "linux")]
pub use live::{LiveCapture, LiveCaptureError, open_live};

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
