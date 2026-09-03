//! Unprivileged datagram ICMP echo. Never requests a raw socket or extra privilege.

use std::io::{self, ErrorKind};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use super::{ICMP_PROBE_ATTEMPTS, IcmpProbeResult, IcmpProber};

const IPPROTO_ICMP: i32 = 1;
const IPPROTO_ICMPV6: i32 = 58;
const ICMPV4_ECHO_REQUEST: u8 = 8;
const ICMPV4_ECHO_REPLY: u8 = 0;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;

#[derive(Debug, Clone, Copy)]
pub struct DatagramIcmpProber {
    pub timeout: Duration,
}

impl Default for DatagramIcmpProber {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(200),
        }
    }
}

impl IcmpProber for DatagramIcmpProber {
    fn probe(&self, addr: IpAddr, timeout: Duration) -> IcmpProbeResult {
        ICMP_PROBE_ATTEMPTS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        match echo(addr, self.timeout.min(timeout)) {
            Ok(rtt) => IcmpProbeResult::Rtt(rtt),
            Err(error) if is_unavailable(&error) => IcmpProbeResult::Unavailable,
            Err(error) => IcmpProbeResult::Error(error.to_string()),
        }
    }
}

fn echo(addr: IpAddr, timeout: Duration) -> io::Result<Duration> {
    let (domain, protocol, request_type, reply_type) = match addr {
        IpAddr::V4(_) => (
            Domain::IPV4,
            Protocol::from(IPPROTO_ICMP),
            ICMPV4_ECHO_REQUEST,
            ICMPV4_ECHO_REPLY,
        ),
        IpAddr::V6(_) => (
            Domain::IPV6,
            Protocol::from(IPPROTO_ICMPV6),
            ICMPV6_ECHO_REQUEST,
            ICMPV6_ECHO_REPLY,
        ),
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(protocol))?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;

    let id = std::process::id() as u16;
    let seq = 1u16;
    let packet = echo_request(request_type, id, seq);
    let dest = SockAddr::from(SocketAddr::new(addr, 0));
    let started = Instant::now();
    socket.send_to(&packet, &dest)?;

    let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 64];
    loop {
        let (n, _) = socket.recv_from(&mut buf)?;
        if n < 8 {
            continue;
        }
        let icmp_type = unsafe { buf[0].assume_init() };
        if icmp_type == reply_type {
            return Ok(started.elapsed());
        }
        if started.elapsed() >= timeout {
            return Err(io::Error::new(ErrorKind::TimedOut, "icmp timeout"));
        }
    }
}

fn echo_request(icmp_type: u8, id: u16, seq: u16) -> [u8; 16] {
    let mut packet = [0u8; 16];
    packet[0] = icmp_type;
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    packet[6..8].copy_from_slice(&seq.to_be_bytes());
    let now = Instant::now();
    packet[8..16].copy_from_slice(&now.elapsed().as_nanos().to_be_bytes()[..8]);
    if icmp_type == ICMPV4_ECHO_REQUEST {
        let sum = internet_checksum(&packet);
        packet[2..4].copy_from_slice(&sum.to_be_bytes());
    }
    packet
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [rest] = chunks.remainder() {
        sum += u32::from(*rest) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

fn is_unavailable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::PermissionDenied
            | ErrorKind::AddrNotAvailable
            | ErrorKind::Unsupported
            | ErrorKind::TimedOut
            | ErrorKind::WouldBlock
    ) || error.raw_os_error() == Some(1)
        || error.raw_os_error() == Some(13)
        || error.raw_os_error() == Some(93)
        || error.raw_os_error() == Some(97)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::probe_icmp_rtt;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn datagram_prober_never_fails_caller() {
        let prober = DatagramIcmpProber {
            timeout: Duration::from_millis(20),
        };
        let _ = probe_icmp_rtt(&prober, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn socket_open_uses_datagram_not_raw() {
        let _ = Socket::new(
            Domain::IPV4,
            Type::DGRAM,
            Some(Protocol::from(IPPROTO_ICMP)),
        );
    }

    #[test]
    fn checksum_of_zero_header_is_stable() {
        let packet = [0u8; 8];
        assert_eq!(internet_checksum(&packet), 0xffff);
    }
}
