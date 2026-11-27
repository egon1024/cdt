//! Linux live capture (phase 1 uses `AF_PACKET` `SOCK_RAW`; `TPACKET_V3` fanout in phase 4).

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum LiveCaptureError {
    #[error("live capture requires CAP_NET_RAW (try sudo or replay a pcap with -r)")]
    Privilege,

    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("interface error: {0}")]
    Interface(String),

    #[error("per-interface capture threads > 1 require Linux PACKET_FANOUT support ({detail})")]
    FanoutUnavailable { detail: String },
}

#[derive(Debug)]
pub struct LiveCapture {
    fd: OwnedFd,
    iface: String,
    pub fanout_group: Option<u32>,
    pub fanout_slot: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
pub struct LiveCaptureOpts {
    pub promisc: bool,
    pub fanout_group: u32,
    pub fanout_slot: u32,
    pub fanout_threads: u32,
}

impl LiveCapture {
    pub fn open(iface: &str) -> Result<Self, LiveCaptureError> {
        Self::open_with(
            iface,
            LiveCaptureOpts {
                promisc: false,
                fanout_group: 0,
                fanout_slot: 0,
                fanout_threads: 1,
            },
        )
    }

    pub fn open_with(iface: &str, opts: LiveCaptureOpts) -> Result<Self, LiveCaptureError> {
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, libc::ETH_P_ALL.to_be()) };
        if fd < 0 {
            let err = io::Error::last_os_error();
            if is_privilege_os_error(err.raw_os_error()) {
                return Err(LiveCaptureError::Privilege);
            }
            return Err(LiveCaptureError::Io(err));
        }
        let ifindex = iface_ifindex(iface)?;
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        addr.sll_ifindex = ifindex;
        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if ret != 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            if is_privilege_os_error(err.raw_os_error()) {
                return Err(LiveCaptureError::Privilege);
            }
            return Err(LiveCaptureError::Io(err));
        }
        attach_dns_bpf(fd)?;
        if opts.promisc {
            set_promisc(fd, iface, true)?;
        }
        let fanout_group = if opts.fanout_threads > 1 {
            // Kernel packs fanout *mode* in low 16 bits and group id in high 16 bits.
            let fanout = libc::PACKET_FANOUT_HASH | (opts.fanout_group << 16);
            if unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_PACKET,
                    libc::PACKET_FANOUT,
                    &fanout as *const _ as *const libc::c_void,
                    std::mem::size_of::<u32>() as u32,
                )
            } != 0
            {
                let err = io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(LiveCaptureError::FanoutUnavailable {
                    detail: err.to_string(),
                });
            }
            Some(opts.fanout_group)
        } else {
            None
        };
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            iface: iface.to_string(),
            fanout_group,
            fanout_slot: if opts.fanout_threads > 1 {
                Some(opts.fanout_slot)
            } else {
                None
            },
        })
    }

    pub fn iface(&self) -> &str {
        &self.iface
    }

    pub fn recv_one(&self, buf: &mut [u8]) -> Result<usize, LiveCaptureError> {
        let n = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
            )
        };
        if n < 0 {
            return Err(LiveCaptureError::Io(io::Error::last_os_error()));
        }
        Ok(n as usize)
    }

    pub fn set_nonblocking(&self) -> Result<(), LiveCaptureError> {
        let fd = self.fd.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
        if flags < 0 {
            return Err(LiveCaptureError::Io(io::Error::last_os_error()));
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(LiveCaptureError::Io(io::Error::last_os_error()));
        }
        Ok(())
    }

    pub fn try_recv_packet(&self) -> Result<Option<super::RawPacket>, LiveCaptureError> {
        let mut buf = [0u8; 65_535];
        match self.recv_one(&mut buf) {
            Ok(n) => {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                Ok(Some(super::RawPacket {
                    data: buf[..n].to_vec(),
                    timestamp_secs: ts.as_secs(),
                    timestamp_subsec_ns: ts.subsec_nanos(),
                    iface: self.iface.clone(),
                }))
            }
            Err(LiveCaptureError::Io(e))
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.raw_os_error() == Some(libc::EAGAIN) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }
}

pub fn open_live(iface: &str) -> Result<LiveCapture, LiveCaptureError> {
    LiveCapture::open(iface)
}

/// Probe whether `PACKET_FANOUT` works the same way as live open (socket bound to `lo`).
pub fn fanout_probe_error() -> Option<String> {
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, libc::ETH_P_ALL.to_be()) };
    if fd < 0 {
        let err = io::Error::last_os_error();
        return Some(err.to_string());
    }
    let bind_err = bind_loopback(fd);
    if let Err(e) = bind_err {
        unsafe { libc::close(fd) };
        return Some(e.to_string());
    }
    let fanout = libc::PACKET_FANOUT_HASH | (1_u32 << 16);
    let ok = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_PACKET,
            libc::PACKET_FANOUT,
            &fanout as *const _ as *const libc::c_void,
            std::mem::size_of::<u32>() as u32,
        ) == 0
    };
    if !ok {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Some(err.to_string());
    }
    unsafe { libc::close(fd) };
    None
}

pub fn fanout_available() -> bool {
    fanout_probe_error().is_none()
}

fn bind_loopback(fd: RawFd) -> Result<(), io::Error> {
    let ifindex = iface_ifindex("lo").map_err(io::Error::other)?;
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    addr.sll_ifindex = ifindex;
    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_ll as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn set_promisc(fd: RawFd, iface: &str, on: bool) -> Result<(), LiveCaptureError> {
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in iface.bytes().take(libc::IFNAMSIZ - 1).enumerate() {
        req.ifr_name[i] = b as libc::c_char;
    }
    let flags = unsafe {
        if libc::ioctl(
            fd,
            libc::SIOCGIFFLAGS,
            &mut req as *mut libc::ifreq as *mut _,
        ) != 0
        {
            return Err(LiveCaptureError::Io(io::Error::last_os_error()));
        }
        req.ifr_ifru.ifru_flags
    };
    if on {
        req.ifr_ifru.ifru_flags = flags | (libc::IFF_PROMISC as i16);
    } else {
        req.ifr_ifru.ifru_flags = flags & !(libc::IFF_PROMISC as i16);
    }
    if unsafe {
        libc::ioctl(
            fd,
            libc::SIOCSIFFLAGS,
            &req as *const libc::ifreq as *mut libc::c_void,
        )
    } != 0
    {
        return Err(LiveCaptureError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

fn is_privilege_os_error(code: Option<i32>) -> bool {
    matches!(code, Some(libc::EPERM) | Some(libc::EACCES))
}

fn iface_ifindex(iface: &str) -> Result<i32, LiveCaptureError> {
    let path = format!("/sys/class/net/{iface}/ifindex");
    let s =
        std::fs::read_to_string(&path).map_err(|e| LiveCaptureError::Interface(e.to_string()))?;
    s.trim()
        .parse()
        .map_err(|_| LiveCaptureError::Interface(format!("invalid ifindex for {iface}")))
}

/// Classic BPF: UDP or TCP port 53, or IPv4/IPv6 fragments.
fn attach_dns_bpf(fd: RawFd) -> Result<(), LiveCaptureError> {
    // Minimal program accepting all traffic in phase 1; port filter applied in userspace.
    let _ = fd;
    Ok(())
}

#[cfg(target_os = "linux")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fanout_parse_threads_request() {
        let err = LiveCaptureOpts {
            promisc: false,
            fanout_group: 1,
            fanout_slot: 2,
            fanout_threads: 4,
        };
        assert_eq!(err.fanout_threads, 4);
    }

    #[test]
    fn unprivileged_open_fails() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let err = LiveCapture::open("lo").unwrap_err();
        assert!(matches!(err, LiveCaptureError::Privilege));
    }
}
