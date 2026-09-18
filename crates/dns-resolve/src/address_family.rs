//! IPv4/IPv6 address-family selection for trace candidate servers.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};

/// Operator-requested address family policy (CLI / session input).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressFamilyRequest {
    /// Probe IPv6 reachability once per process; fall back to v4-only when unroutable.
    #[default]
    Auto,
    V4,
    V6,
    Both,
}

/// Effective family policy used during a trace after resolving [`AddressFamilyRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolvedAddressFamily {
    V4,
    V6,
    Both,
}

impl ResolvedAddressFamily {
    pub fn label(self) -> &'static str {
        match self {
            Self::V4 => "v4-only",
            Self::V6 => "v6-only",
            Self::Both => "dual-stack",
        }
    }
}

/// Primary IPv6 probe target: `a.root-servers.net` AAAA (IANA).
pub const PROBE_V6_TARGET: Ipv6Addr = Ipv6Addr::new(0x2001, 0x503, 0xba3e, 0, 0, 0, 0x2, 0x30);

const PROBE_TIMEOUT: Duration = Duration::from_millis(200);

/// Counts IPv6 reachability probe attempts (for tests).
pub static IPV6_PROBE_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);

static AUTO_RESOLVED: Mutex<Option<ResolvedAddressFamily>> = Mutex::new(None);

#[cfg(test)]
static TEST_PROBE_RESULT: Mutex<Option<bool>> = Mutex::new(None);

/// Resolve the effective address family for a trace.
pub fn resolve_address_family(request: AddressFamilyRequest) -> ResolvedAddressFamily {
    match request {
        AddressFamilyRequest::V4 => ResolvedAddressFamily::V4,
        AddressFamilyRequest::V6 => ResolvedAddressFamily::V6,
        AddressFamilyRequest::Both => ResolvedAddressFamily::Both,
        AddressFamilyRequest::Auto => {
            let mut guard = AUTO_RESOLVED.lock().expect("address family cache");
            if let Some(cached) = *guard {
                return cached;
            }
            let resolved = if probe_ipv6_reachable() {
                ResolvedAddressFamily::Both
            } else {
                ResolvedAddressFamily::V4
            };
            *guard = Some(resolved);
            resolved
        }
    }
}

/// Returns record types to query when resolving a nameserver hostname.
pub fn ns_record_types(family: ResolvedAddressFamily) -> &'static [hickory_proto::rr::RecordType] {
    use hickory_proto::rr::RecordType;
    match family {
        ResolvedAddressFamily::V4 => &[RecordType::A],
        ResolvedAddressFamily::V6 => &[RecordType::AAAA],
        ResolvedAddressFamily::Both => &[RecordType::A, RecordType::AAAA],
    }
}

/// Probe whether IPv6 UDP traffic can leave the host toward the primary probe target.
pub fn probe_ipv6_reachable() -> bool {
    IPV6_PROBE_ATTEMPTS.fetch_add(1, Ordering::SeqCst);

    #[cfg(test)]
    if let Some(result) = *TEST_PROBE_RESULT.lock().expect("test probe lock") {
        return result;
    }

    probe_ipv6_reachable_impl()
}

fn probe_ipv6_reachable_impl() -> bool {
    let socket = match Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)) {
        Ok(socket) => socket,
        Err(_) => return false,
    };
    if socket.set_write_timeout(Some(PROBE_TIMEOUT)).is_err() {
        return false;
    }

    let dest = socket2::SockAddr::from(SocketAddr::new(IpAddr::V6(PROBE_V6_TARGET), 53));
    // Minimal DNS header — content does not matter; routing is decided by sendto().
    let packet = [0u8; 12];

    match socket.send_to(&packet, &dest) {
        Ok(_) => true,
        Err(error) if is_immediate_unreachable(&error) => false,
        Err(_) => true,
    }
}

fn is_immediate_unreachable(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable | ErrorKind::AddrNotAvailable
    ) || matches!(
        error.raw_os_error(),
        Some(101) | Some(113) | Some(99) // ENETUNREACH, EHOSTUNREACH, EADDRNOTAVAIL (linux)
    )
}

#[cfg(test)]
pub fn reset_address_family_cache_for_tests() {
    *AUTO_RESOLVED.lock().expect("address family cache") = None;
    *TEST_PROBE_RESULT.lock().expect("test probe lock") = None;
    IPV6_PROBE_ATTEMPTS.store(0, Ordering::SeqCst);
}

#[cfg(test)]
pub fn set_test_probe_result_for_tests(reachable: Option<bool>) {
    *TEST_PROBE_RESULT.lock().expect("test probe lock") = reachable;
}

#[cfg(test)]
static ADDRESS_FAMILY_TEST_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    fn with_isolated_cache<T>(f: impl FnOnce() -> T) -> T {
        let _guard = ADDRESS_FAMILY_TEST_LOCK.lock().expect("test lock");
        reset_address_family_cache_for_tests();
        f()
    }

    #[test]
    fn explicit_requests_skip_probe() {
        with_isolated_cache(|| {
            assert_eq!(
                resolve_address_family(AddressFamilyRequest::V4),
                ResolvedAddressFamily::V4
            );
            assert_eq!(
                resolve_address_family(AddressFamilyRequest::V6),
                ResolvedAddressFamily::V6
            );
            assert_eq!(
                resolve_address_family(AddressFamilyRequest::Both),
                ResolvedAddressFamily::Both
            );
            assert_eq!(IPV6_PROBE_ATTEMPTS.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn auto_caches_probe_result() {
        with_isolated_cache(|| {
            set_test_probe_result_for_tests(Some(false));

            assert_eq!(
                resolve_address_family(AddressFamilyRequest::Auto),
                ResolvedAddressFamily::V4
            );
            assert_eq!(
                resolve_address_family(AddressFamilyRequest::Auto),
                ResolvedAddressFamily::V4
            );
            assert_eq!(IPV6_PROBE_ATTEMPTS.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn auto_selects_dual_stack_when_probe_succeeds() {
        with_isolated_cache(|| {
            set_test_probe_result_for_tests(Some(true));

            assert_eq!(
                resolve_address_family(AddressFamilyRequest::Auto),
                ResolvedAddressFamily::Both
            );
        });
    }

    #[test]
    fn unreachable_errors_classified() {
        assert!(is_immediate_unreachable(&std::io::Error::from(
            ErrorKind::NetworkUnreachable
        )));
        assert!(is_immediate_unreachable(&std::io::Error::from(
            ErrorKind::HostUnreachable
        )));
        assert!(!is_immediate_unreachable(&std::io::Error::from(
            ErrorKind::TimedOut
        )));
    }
}
