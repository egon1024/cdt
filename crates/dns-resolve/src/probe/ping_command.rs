//! Fallback ICMP RTT via the system `ping` binary when datagram sockets are blocked.

use std::io;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::time::Duration;

use super::{IcmpProbeResult, IcmpProber};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PingSampleStats {
    pub samples: u8,
    pub min_ms: f64,
    pub avg_ms: f64,
    pub max_ms: f64,
}

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

    pub fn probe_samples(
        &self,
        addr: IpAddr,
        timeout: Duration,
        samples: u8,
    ) -> Result<PingSampleStats, IcmpProbeResult> {
        let samples = samples.max(1);
        let mut cmd = Command::new(&self.program);
        cmd.arg("-c").arg(samples.to_string());
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
            Ok(_) => return Err(IcmpProbeResult::Unavailable),
            Err(error) if is_unavailable(&error) => return Err(IcmpProbeResult::Unavailable),
            Err(error) => return Err(IcmpProbeResult::Error(error.to_string())),
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_ping_sample_stats(&stdout, samples).ok_or(IcmpProbeResult::Unavailable)
    }
}

impl IcmpProber for PingCommandProber {
    fn probe(&self, addr: IpAddr, timeout: Duration) -> IcmpProbeResult {
        match self.probe_samples(addr, timeout, 1) {
            Ok(stats) => IcmpProbeResult::Rtt(Duration::from_secs_f64(stats.avg_ms / 1000.0)),
            Err(result) => result,
        }
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

pub fn parse_ping_sample_stats(output: &str, samples: u8) -> Option<PingSampleStats> {
    if let Some(stats) = parse_ping_summary_line(output) {
        return Some(PingSampleStats { samples, ..stats });
    }
    parse_ping_rtt_ms(output).map(|duration| {
        let ms = duration.as_secs_f64() * 1000.0;
        PingSampleStats {
            samples: 1,
            min_ms: ms,
            avg_ms: ms,
            max_ms: ms,
        }
    })
}

fn parse_ping_summary_line(output: &str) -> Option<PingSampleStats> {
    for line in output.lines() {
        let Some(rest) = line.split('=').nth(1) else {
            continue;
        };
        let Some(values) = rest.split_whitespace().next() else {
            continue;
        };
        let mut parts = values.split('/');
        let min_ms = parts.next()?.parse::<f64>().ok()?;
        let avg_ms = parts.next()?.parse::<f64>().ok()?;
        let max_ms = parts.next()?.parse::<f64>().ok()?;
        return Some(PingSampleStats {
            samples: 0,
            min_ms,
            avg_ms,
            max_ms,
        });
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

    #[test]
    fn parses_multi_sample_summary_line() {
        let output = "PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n\
                      round-trip min/avg/max/stddev = 1.234/2.345/3.456/0.111 ms";
        let stats = parse_ping_sample_stats(output, 3).expect("stats");
        assert_eq!(stats.samples, 3);
        assert!((stats.min_ms - 1.234).abs() < f64::EPSILON);
        assert!((stats.avg_ms - 2.345).abs() < f64::EPSILON);
        assert!((stats.max_ms - 3.456).abs() < f64::EPSILON);
    }

    #[test]
    fn mocked_ping_output_for_single_sample() {
        let output = "64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=42.0 ms";
        let stats = parse_ping_sample_stats(output, 1).expect("stats");
        assert_eq!(stats.samples, 1);
        assert!((stats.avg_ms - 42.0).abs() < f64::EPSILON);
    }
}
