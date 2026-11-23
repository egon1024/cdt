use std::process::Command;

use flux::options::FluxOptions;
use tempfile::tempdir;

fn regenerate_fixtures(dir: &std::path::Path) {
    let status = Command::new(env!("CARGO"))
        .args(["run", "-p", "flux", "--example", "make-fixtures", "--"])
        .arg(dir)
        .status()
        .expect("make-fixtures");
    assert!(status.success());
}

#[test]
fn fragmented_defrag_on_counts_response() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let bin = env!("CARGO_BIN_EXE_flux");
    let pcap = dir.path().join("fragmented.pcap");
    let out = Command::new(bin)
        .args([
            "watch",
            "-r",
            pcap.to_str().unwrap(),
            "+preset=fragmented",
            "+qr=both",
            "+views=src",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("192.0.2.53"));
}

#[test]
fn fragmented_defrag_off_unparsed_counter() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let bin = env!("CARGO_BIN_EXE_flux");
    let pcap = dir.path().join("fragmented.pcap");
    let out = Command::new(bin)
        .args([
            "watch",
            "-r",
            pcap.to_str().unwrap(),
            "+defrag=off",
            "+views=src",
        ])
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("frag_unparsed"));
}

#[test]
fn tcp_modes_split_fixture() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let bin = env!("CARGO_BIN_EXE_flux");
    let pcap = dir.path().join("tcp-split.pcap");
    let full = Command::new(bin)
        .args([
            "watch",
            "-r",
            pcap.to_str().unwrap(),
            "+tcp=full",
            "+qr=both",
            "+views=transport",
        ])
        .output()
        .unwrap();
    let full_s = String::from_utf8_lossy(&full.stdout);
    assert!(full_s.contains("qr=both"), "{full_s}");
    assert!(full_s.contains("Transport (1 messages)"), "{full_s}");
    assert!(full_s.contains("tcp"));
    let simple = Command::new(bin)
        .args([
            "watch",
            "-r",
            pcap.to_str().unwrap(),
            "+tcp=simple",
            "+qr=both",
            "+views=transport",
        ])
        .output()
        .unwrap();
    let simple_s = String::from_utf8_lossy(&simple.stdout);
    assert!(simple_s.contains("tcp_unparsed"), "{simple_s}");
    assert!(
        simple_s.contains("Transport (0 messages)"),
        "simple must not count split TCP: {simple_s}"
    );
    let off = Command::new(bin)
        .args([
            "watch",
            "-r",
            pcap.to_str().unwrap(),
            "+tcp=off",
            "+qr=both",
            "+views=transport",
        ])
        .output()
        .unwrap();
    let so = String::from_utf8_lossy(&off.stdout);
    assert!(!so.contains("tcp        1"));
}

#[test]
fn latency_view_on_basic_fixture() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let bin = env!("CARGO_BIN_EXE_flux");
    let pcap = dir.path().join("udp-basic.pcap");
    let out = Command::new(bin)
        .args([
            "watch",
            "-r",
            pcap.to_str().unwrap(),
            "+views=latency-dst",
            "+qr=both",
        ])
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("p50"));
    assert!(s.contains("p95"));
}

#[test]
fn unanswered_preset_lists_queries() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let bin = env!("CARGO_BIN_EXE_flux");
    let pcap = dir.path().join("unanswered.pcap");
    let out = Command::new(bin)
        .args([
            "watch",
            "-r",
            pcap.to_str().unwrap(),
            "+preset=unanswered",
            "+views=dst",
            "+pair-timeout=1s",
        ])
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("192.0.2.53"));
}

#[test]
fn pair_max_eviction_visible() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let bin = env!("CARGO_BIN_EXE_flux");
    let pcap = dir.path().join("unanswered.pcap");
    let out = Command::new(bin)
        .args([
            "watch",
            "-r",
            pcap.to_str().unwrap(),
            "+pair-max=5",
            "+views=dst",
        ])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("pair_evicted"));
}

#[test]
fn pairing_off_note() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let bin = env!("CARGO_BIN_EXE_flux");
    let pcap = dir.path().join("udp-basic.pcap");
    let out = Command::new(bin)
        .args([
            "watch",
            "-r",
            pcap.to_str().unwrap(),
            "+pairing=off",
            "+views=latency-dst",
        ])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("pairing off"));
}

#[test]
fn flow_options_parse() {
    let o = FluxOptions::parse(&[
        "+defrag=off".into(),
        "+tcp=simple".into(),
        "+pairing=off".into(),
        "+pair-timeout=2s".into(),
        "+pair-max=99".into(),
    ])
    .unwrap();
    assert!(!o.pairing);
    assert_eq!(o.pair_max, 99);
}
