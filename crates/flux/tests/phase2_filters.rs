use std::process::Command;
use std::time::Instant;

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
fn ede_fixture_multi_code_counts() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let bin = env!("CARGO_BIN_EXE_flux");
    let pcap = dir.path().join("edns-ede.pcap");
    let out = Command::new(bin)
        .args([
            "watch",
            "-r",
            pcap.to_str().unwrap(),
            "+views=ede",
            "+qr=response",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("22"));
    assert!(s.contains("23"));
}

#[test]
fn large_fixture_recompute_timing() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let bin = env!("CARGO_BIN_EXE_flux");
    let pcap = dir.path().join("large.pcap");
    let t0 = Instant::now();
    let out = Command::new(bin)
        .args([
            "watch",
            "-r",
            pcap.to_str().unwrap(),
            "+views=src",
            "+qtype=TYPE1",
        ])
        .output()
        .unwrap();
    let elapsed = t0.elapsed();
    assert!(out.status.success());
    eprintln!("large.pcap replay filter elapsed: {:?}", elapsed);
    assert!(elapsed.as_secs() < 120);
}

#[test]
fn g2_step1_qtype_or_and_negation() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let bin = env!("CARGO_BIN_EXE_flux");
    let pcap = dir.path().join("udp-basic.pcap");

    let out = Command::new(bin)
        .args([
            "watch",
            "-r",
            pcap.to_str().unwrap(),
            "+qtype=A,AAAA",
            "+views=qtype",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("A"));
    assert!(!s.is_empty());

    let out = Command::new(bin)
        .args([
            "watch",
            "-r",
            pcap.to_str().unwrap(),
            "+qtype!=PTR",
            "+views=qtype",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("A"));
}

#[test]
fn g2_step1_qname_suffix_view() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let bin = env!("CARGO_BIN_EXE_flux");
    let pcap = dir.path().join("udp-basic.pcap");
    let out = Command::new(bin)
        .args([
            "watch",
            "-r",
            pcap.to_str().unwrap(),
            "+qname=example.com",
            "+views=3",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("example.com"));
}

#[test]
fn preset_malformed_and_filter_header() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let bin = env!("CARGO_BIN_EXE_flux");
    let pcap = dir.path().join("udp-basic.pcap");
    let out = Command::new(bin)
        .args([
            "watch",
            "-r",
            pcap.to_str().unwrap(),
            "+preset=malformed",
            "+views=src",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("Filter:"));
}

#[test]
fn time_bounds_limit_packets() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let opts = FluxOptions::parse(&["+start=0".into(), "+end=0".into()]).unwrap();
    assert!(opts.within_time_bounds(0.0));
    assert!(!opts.within_time_bounds(1.0));
}
