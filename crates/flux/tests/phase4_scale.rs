use std::process::Command;
use std::sync::{Mutex, OnceLock};

use flux::capture::{InterfaceTable, NetInterface, PortSet, initiator_is_src, resolve_listeners};
use flux::scale::hints::HintEngine;
use flux::scale::hints::{ListenerMeasurements, ParseThreadMeasurements};
use tempfile::tempdir;

static CARGO_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

fn regenerate_fixtures(dir: &std::path::Path) {
    let lock = CARGO_MUTEX.get_or_init(|| Mutex::new(()));
    let _g = lock.lock().unwrap();
    let status = Command::new(env!("CARGO"))
        .args(["run", "-p", "flux", "--example", "make-fixtures", "--"])
        .arg(dir)
        .status()
        .expect("make-fixtures");
    assert!(status.success());
}

fn flux_run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_flux"))
        .args(args)
        .output()
        .expect("flux")
}

#[test]
fn port_5353_fixture_counted() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let pcap = dir.path().join("port5353.pcap");
    let out = flux_run(&[
        "watch",
        "-r",
        pcap.to_str().unwrap(),
        "+port=53,5353",
        "+views=src",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("counted"), "{text}");
}

#[test]
fn server_to_server_qr_roles() {
    let p = PortSet::dns_default();
    assert!(!initiator_is_src(53, 53, true, &p));
    assert!(initiator_is_src(53, 53, false, &p));
}

#[test]
fn flow_threads_four_matches_single_totals() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let pcap = dir.path().join("udp-basic.pcap");
    let base = flux_run(&["watch", "-r", pcap.to_str().unwrap(), "+views=src"]);
    assert!(base.status.success());
    let scaled = flux_run(&[
        "watch",
        "-r",
        pcap.to_str().unwrap(),
        "+flow-threads=4",
        "+views=src",
    ]);
    assert!(
        scaled.status.success(),
        "{}",
        String::from_utf8_lossy(&scaled.stderr)
    );
    let b = extract_counted(&String::from_utf8_lossy(&base.stdout));
    let s = extract_counted(&String::from_utf8_lossy(&scaled.stdout));
    assert_eq!(b, s, "base={b} scaled={s}");
}

#[test]
fn worker_resize_preserves_totals() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let pcap = dir.path().join("large.pcap");
    let once = flux_run(&[
        "watch",
        "-r",
        pcap.to_str().unwrap(),
        "+workers=1",
        "+views=src",
    ]);
    let resized = flux_run(&[
        "watch",
        "-r",
        pcap.to_str().unwrap(),
        "+workers=2",
        "+views=src",
    ]);
    assert!(once.status.success() && resized.status.success());
    assert_eq!(
        extract_counted(&String::from_utf8_lossy(&once.stdout)),
        extract_counted(&String::from_utf8_lossy(&resized.stdout))
    );
}

#[test]
fn overload_shrink_shows_effective_window() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let pcap = dir.path().join("large.pcap");
    let out = flux_run(&[
        "watch",
        "-r",
        pcap.to_str().unwrap(),
        "+window=15s",
        "+mem=64KiB",
        "+overload=shrink",
        "+views=src",
    ]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("effective") || text.contains("overload"),
        "{text}"
    );
}

#[test]
fn overload_policies_emit_markers() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let pcap = dir.path().join("large.pcap");
    for pol in ["drop", "sample", "compact"] {
        let out = flux_run(&[
            "watch",
            "-r",
            pcap.to_str().unwrap(),
            "+window=all",
            "+mem=32KiB",
            &format!("+overload={pol}"),
            "+views=src",
        ]);
        assert!(out.status.success(), "{pol}");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains("overload") || text.contains('~') || text.contains("refused"),
            "{pol}: {text}"
        );
    }
}

#[test]
fn iface_spec_parser_threads() {
    let spec = flux::capture::ListenerSpec::parse("eth0:threads=4").unwrap();
    assert_eq!(spec.capture_threads, 4);
}

#[test]
fn listener_table_default_excludes_glob() {
    let table = InterfaceTable::from_interfaces([
        NetInterface {
            name: "lo".into(),
            up: true,
        },
        NetInterface {
            name: "veth0".into(),
            up: true,
        },
    ]);
    let sel = resolve_listeners(&[], &["veth*".into()], &table).unwrap();
    assert_eq!(sel.len(), 1);
    assert_eq!(sel[0].iface, "lo");
}

#[test]
fn hint_engine_parse_saturation() {
    let engine = HintEngine::new();
    let hints = engine.evaluate(
        &[],
        &[ParseThreadMeasurements {
            busy_pct: 99,
            queue_depth: 500,
        }],
        20,
        None,
    );
    assert!(!hints.is_empty());
}

#[test]
fn hint_engine_capture_drops() {
    let engine = HintEngine::new();
    let hints = engine.evaluate(
        &[ListenerMeasurements {
            iface: "eth0".into(),
            rate_pps: 0.0,
            drops: 3,
            capture_threads: 2,
            capture_busy_pct: 0,
            capture_queue: 0,
        }],
        &[],
        0,
        None,
    );
    assert!(!hints.is_empty());
}

#[test]
#[cfg(target_os = "linux")]
fn live_watch_lists_default_interfaces_on_stderr() {
    let out = flux_run(&["watch", "+window=10s"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("flux: opened interfaces:"),
        "stderr={stderr}"
    );
    assert!(
        !stderr.contains("specify -i"),
        "pre-phase-4 flux binary? stderr={stderr}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn exclude_iface_option_parses() {
    let out = flux_run(&["watch", "-i", "lo", "+exclude-iface=veth*"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("unknown option"), "stderr={stderr}");
    assert!(stderr.contains("opened interfaces: lo"), "stderr={stderr}");
}

#[test]
#[cfg(target_os = "linux")]
fn unknown_interface_named_in_error() {
    let out = flux_run(&["watch", "-i", "does-not-exist"]);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unknown interface: does-not-exist"),
        "stderr={stderr}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn live_fanout_integration_gated() {
    if std::env::var("FLUX_LIVE_FANOUT_TEST").ok().as_deref() != Some("1") {
        return;
    }
    assert!(flux::capture::fanout_available());
    let cap = flux::capture::LiveCapture::open_with(
        "lo",
        flux::capture::LiveCaptureOpts {
            promisc: false,
            fanout_group: 9,
            fanout_slot: 0,
            fanout_threads: 2,
        },
    );
    assert!(cap.is_ok());
}

fn extract_counted(stdout: &str) -> u64 {
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("counted ") {
            if let Some(n) = rest.split_whitespace().next() {
                return n.parse().unwrap_or(0);
            }
        }
        if line.contains("counted ") {
            if let Some(idx) = line.find("counted ") {
                let rest = &line[idx + 8..];
                if let Some(n) = rest.split_whitespace().next() {
                    return n.parse().unwrap_or(0);
                }
            }
        }
    }
    stdout
        .lines()
        .find_map(|l| l.split("counted ").nth(1))
        .and_then(|r| r.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}
