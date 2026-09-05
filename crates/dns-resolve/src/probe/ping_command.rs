//! Fallback ICMP RTT via the system `ping` binary when datagram sockets are blocked.

use std::io;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::time::Duration;

use super::{IcmpProbeResult, IcmpProber};

#[derive(Debug, Clone)]
pub struct PingCommandProber {
    program: String,
}

impl PingCommandProber {
    pub fn discover() -> Option<Self> {
        let program = "ping".to_string();
        let mut cmd = Command::new(&program);
        cmd.arg("-c").arg("1");
        #[cfg(target_os = "linux")]
        cmd.arg("-W").arg("1");
        #[cfg(target_os = "macos")]
        cmd.arg("-W").arg("1000");
        cmd.arg("127.0.0.1");
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
        match cmd.status() {
            Ok(status) if status.success() => Some(Self { program }),
            _ => None,
        }
    }
}

impl IcmpProber for PingCommandProber {
    fn probe(&self, addr: IpAddr, timeout: Duration) -> IcmpProbeResult {
        let mut cmd = Command::new(&self.program);
        cmd.arg("-c").arg("1");
        #[cfg(target_os = "linux")]
        {
            cmd.arg("-n");
            let secs = timeout.as_secs().max(1);
            cmd.arg("-W").arg(secs.to_string());
        }
        #[cfg(target_os = "macos")]
        {
            let ms = timeout.as_millis().max(1) as u64;
            cmd.arg("-W").arg(ms.to_string());
        }
        match addr {
            IpAddr::V4(_) => {
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                cmd.arg("-4");
            }
            IpAddr::V6(_) => {
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                cmd.arg("-6");
            }
        }
        cmd.arg(addr.to_string());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::null());

        let output = match cmd.output() {
            Ok(output) if output.status.success() => output,
            Ok(_) => return IcmpProbeResult::Unavailable,
            Err(error) if is_unavailable(&error) => return IcmpProbeResult::Unavailable,
            Err(error) => return IcmpProbeResult::Error(error.to_string()),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_ping_rtt_ms(&stdout)
            .map(IcmpProbeResult::Rtt)
            .unwrap_or(IcmpProbeResult::Unavailable)
    }
}

pub fn parse_ping_rtt_ms(output: &str) -> Option<Duration> {
    for line in output.lines() {
        let Some(rest) = line.split("time=").nth(1) else {
            continue;
        };
        let number: String = rest
            .chars()
            .take_while(|ch| ch.is_ascii_digit() || *ch == '.')
            .collect();
        if number.is_empty() {
            continue;
        }
        let ms = number.parse::<f64>().ok()?;
        return Some(Duration::from_secs_f64(ms / 1000.0));
    }
    None
}

fn is_unavailable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_ping_output() {
        let output = "64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=10.2 ms";
        assert_eq!(
            parse_ping_rtt_ms(output).map(|duration| duration.as_millis()),
            Some(10)
        );
    }

    #[test]
    fn parses_ping_without_unit_suffix() {
        let output = "round-trip min/avg/max/stddev = 1.234/2.345/3.456/0.111 ms\n\
                      64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=2.345 ms";
        assert_eq!(
            parse_ping_rtt_ms(output).map(|duration| duration.as_millis()),
            Some(2)
        );
    }
}
