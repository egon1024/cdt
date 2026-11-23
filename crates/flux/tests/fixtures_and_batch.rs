use std::process::Command;
use std::sync::{Mutex, OnceLock};

use flux::capture::{open_packet_source, sniff_format};
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

#[test]
fn fixtures_are_byte_identical_across_runs() {
    let d1 = tempdir().unwrap();
    let d2 = tempdir().unwrap();
    regenerate_fixtures(d1.path());
    regenerate_fixtures(d2.path());
    for name in [
        "udp-basic.pcap",
        "edns-ede.pcap",
        "large.pcap",
        "fragmented.pcap",
        "tcp-split.pcap",
        "tcp-midstream.pcap",
        "unanswered.pcap",
        "tc-retry.pcap",
    ] {
        let a = std::fs::read(d1.path().join(name)).unwrap();
        let b = std::fs::read(d2.path().join(name)).unwrap();
        assert_eq!(a, b, "{name}");
    }
}

#[test]
fn batch_replay_is_deterministic() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let pcap = dir.path().join("udp-basic.pcap");
    assert_eq!(sniff_format(&pcap).unwrap(), "pcap");

    let bin = env!("CARGO_BIN_EXE_flux");
    let args = ["watch", "-r", pcap.to_str().unwrap(), "+views=src,qtype,2"];
    let o1 = Command::new(bin).args(args).output().expect("flux");
    assert!(
        o1.status.success(),
        "{}",
        String::from_utf8_lossy(&o1.stderr)
    );
    let o2 = Command::new(bin).args(args).output().expect("flux");
    assert_eq!(o1.stdout, o2.stdout);
    assert!(!o1.stdout.is_empty());
}

#[test]
fn pcap_round_trip_open() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let mut src =
        open_packet_source(Some(dir.path().join("udp-basic.pcap").to_str().unwrap())).unwrap();
    let mut n = 0usize;
    for pkt in flux::capture::iter_packets(&mut src, "t") {
        pkt.unwrap();
        n += 1;
    }
    assert!(n > 0);
}
