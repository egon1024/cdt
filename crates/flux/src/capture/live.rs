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
}

#[derive(Debug)]
pub struct LiveCapture {
    fd: OwnedFd,
    iface: String,
}

impl LiveCapture {
    pub fn open(iface: &str) -> Result<Self, LiveCaptureError> {
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, libc::ETH_P_ALL.to_be()) };
        if fd < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EPERM) {
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
            if err.raw_os_error() == Some(libc::EPERM) {
                return Err(LiveCaptureError::Privilege);
            }
            return Err(LiveCaptureError::Io(err));
        }
        attach_dns_bpf(fd)?;
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            iface: iface.to_string(),
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
}

pub fn open_live(iface: &str) -> Result<LiveCapture, LiveCaptureError> {
    LiveCapture::open(iface)
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
    fn unprivileged_open_fails() {
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let err = LiveCapture::open("lo").unwrap_err();
        assert!(matches!(err, LiveCaptureError::Privilege));
    }
}
