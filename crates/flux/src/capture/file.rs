use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use pcap_file::pcap::{PcapPacket, PcapReader, PcapWriter};
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption;
use pcap_file::pcapng::{Block, PcapNgReader};
use thiserror::Error;

use super::RawPacket;

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("pcap read error: {0}")]
    Pcap(String),
}

pub enum PacketSource {
    Pcap(PcapReader<Box<dyn Read>>),
    PcapNg(PcapNgReader<Box<dyn Read>>),
}

pub fn open_packet_source(path: Option<&str>) -> Result<PacketSource, CaptureError> {
    match path {
        None => Err(CaptureError::Pcap("no input".into())),
        Some("-") => {
            let mut stdin = io::stdin().lock();
            let mut magic = [0u8; 4];
            stdin.read_exact(&mut magic)?;
            let mut buf = Vec::new();
            buf.extend_from_slice(&magic);
            io::copy(&mut stdin, &mut buf)?;
            open_from_bytes(buf, &magic == b"\x0a\x0d\x0d\x0a")
        }
        Some(p) => {
            let mut file = File::open(p)?;
            let mut magic = [0u8; 4];
            file.read_exact(&mut magic)?;
            file.seek(SeekFrom::Start(0))?;
            let mut buf = Vec::new();
            io::copy(&mut file, &mut buf)?;
            open_from_bytes(buf, &magic == b"\x0a\x0d\x0d\x0a")
        }
    }
}

fn open_from_bytes(buf: Vec<u8>, is_ng: bool) -> Result<PacketSource, CaptureError> {
    let reader: Box<dyn Read> = Box::new(io::Cursor::new(buf));
    if is_ng {
        let ng = PcapNgReader::new(reader).map_err(|e| CaptureError::Pcap(e.to_string()))?;
        return Ok(PacketSource::PcapNg(ng));
    }
    let pcap = PcapReader::new(reader).map_err(|e| CaptureError::Pcap(e.to_string()))?;
    Ok(PacketSource::Pcap(pcap))
}

pub fn write_pcapng_dup(
    path: &std::path::Path,
    interfaces: &[&str],
    frames_per_iface: &[&[Vec<u8>]],
) -> Result<(), CaptureError> {
    use std::borrow::Cow;
    use std::fs::File;
    use std::time::Duration;

    use pcap_file::DataLink;
    use pcap_file::pcapng::PcapNgWriter;
    use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
    use pcap_file::pcapng::blocks::interface_description::{
        InterfaceDescriptionBlock, InterfaceDescriptionOption,
    };

    let file = File::create(path)?;
    let mut writer = PcapNgWriter::new(file).map_err(|e| CaptureError::Pcap(e.to_string()))?;
    for name in interfaces {
        let idb = InterfaceDescriptionBlock {
            linktype: DataLink::ETHERNET,
            snaplen: 0xFFFF,
            options: vec![InterfaceDescriptionOption::IfName(Cow::Borrowed(name))],
        };
        writer
            .write_pcapng_block(idb)
            .map_err(|e| CaptureError::Pcap(e.to_string()))?;
    }
    let base = 1_700_000_000u64;
    let mut idx = 0u32;
    for (iface_id, frames) in frames_per_iface.iter().enumerate() {
        for frame in *frames {
            let pkt = EnhancedPacketBlock {
                interface_id: iface_id as u32,
                timestamp: Duration::new(base, idx.saturating_mul(1_000_000)),
                original_len: frame.len() as u32,
                data: Cow::Borrowed(frame),
                options: vec![],
            };
            writer
                .write_pcapng_block(pkt)
                .map_err(|e| CaptureError::Pcap(e.to_string()))?;
            idx += 1;
        }
    }
    Ok(())
}

pub fn write_pcap_file(path: &std::path::Path, frames: &[Vec<u8>]) -> Result<(), CaptureError> {
    use pcap_file::pcap::PcapPacket;
    let file = File::create(path)?;
    let mut writer = PcapWriter::new(file).map_err(|e| CaptureError::Pcap(e.to_string()))?;
    let base = 1_700_000_000u64;
    for (i, frame) in frames.iter().enumerate() {
        let pkt = PcapPacket::new_owned(
            std::time::Duration::new(base + i as u64, 0),
            frame.len() as u32,
            frame.clone(),
        );
        writer
            .write_packet(&pkt)
            .map_err(|e| CaptureError::Pcap(e.to_string()))?;
    }
    Ok(())
}

pub struct PacketIter<'a> {
    source: &'a mut PacketSource,
    iface: &'a str,
}

/// Iterator that resolves per-interface names from pcapng IDBs.
pub struct MultiPacketIter<'a> {
    source: &'a mut PacketSource,
    fallback_iface: &'a str,
    iface_names: Vec<String>,
}

pub fn iter_packets<'a>(source: &'a mut PacketSource, iface: &'a str) -> PacketIter<'a> {
    PacketIter { source, iface }
}

pub fn iter_packets_multi<'a>(
    source: &'a mut PacketSource,
    fallback_iface: &'a str,
) -> MultiPacketIter<'a> {
    MultiPacketIter {
        source,
        fallback_iface,
        iface_names: Vec::new(),
    }
}

impl Iterator for PacketIter<'_> {
    type Item = Result<RawPacket, CaptureError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.source {
            PacketSource::Pcap(r) => match r.next_packet() {
                Some(Ok(pkt)) => Some(Ok(to_raw(pkt, self.iface))),
                Some(Err(e)) => Some(Err(CaptureError::Pcap(e.to_string()))),
                None => None,
            },
            PacketSource::PcapNg(r) => read_ng_packet(r, self.iface, &mut Vec::new()),
        }
    }
}

impl Iterator for MultiPacketIter<'_> {
    type Item = Result<RawPacket, CaptureError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.source {
            PacketSource::Pcap(r) => match r.next_packet() {
                Some(Ok(pkt)) => Some(Ok(to_raw(pkt, self.fallback_iface))),
                Some(Err(e)) => Some(Err(CaptureError::Pcap(e.to_string()))),
                None => None,
            },
            PacketSource::PcapNg(r) => {
                read_ng_packet(r, self.fallback_iface, &mut self.iface_names)
            }
        }
    }
}

fn iface_name_from_idb(
    idb: &pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionBlock<'_>,
    next_id: usize,
) -> String {
    for opt in &idb.options {
        if let InterfaceDescriptionOption::IfName(name) = opt {
            return name.to_string();
        }
    }
    format!("if{next_id}")
}

fn read_ng_packet(
    r: &mut PcapNgReader<Box<dyn Read>>,
    fallback: &str,
    iface_names: &mut Vec<String>,
) -> Option<Result<RawPacket, CaptureError>> {
    loop {
        match r.next_block() {
            Some(Ok(Block::InterfaceDescription(idb))) => {
                let name = iface_name_from_idb(&idb, iface_names.len());
                iface_names.push(name);
                continue;
            }
            Some(Ok(Block::EnhancedPacket(epb))) => {
                let ts = epb.timestamp;
                let iface = iface_names
                    .get(epb.interface_id as usize)
                    .map(String::as_str)
                    .unwrap_or(fallback);
                return Some(Ok(RawPacket {
                    data: epb.data.to_vec(),
                    timestamp_secs: ts.as_secs(),
                    timestamp_subsec_ns: ts.subsec_nanos(),
                    iface: iface.to_string(),
                }));
            }
            Some(Ok(_)) => continue,
            Some(Err(e)) => return Some(Err(CaptureError::Pcap(e.to_string()))),
            None => return None,
        }
    }
}

pub fn sniff_format(path: &Path) -> Result<&'static str, CaptureError> {
    let mut f = File::open(path)?;
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)?;
    if &magic == b"\x0a\x0d\x0d\x0a" {
        Ok("pcapng")
    } else {
        Ok("pcap")
    }
}

fn to_raw(pkt: PcapPacket<'_>, iface: &str) -> RawPacket {
    let ts = pkt.timestamp;
    RawPacket {
        data: pkt.data.to_vec(),
        timestamp_secs: ts.as_secs(),
        timestamp_subsec_ns: ts.subsec_nanos(),
        iface: iface.to_string(),
    }
}
