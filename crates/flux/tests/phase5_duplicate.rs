use std::process::Command;
use std::sync::{Mutex, OnceLock};

use flux::capture::{MockTopology, discover_topology, topology_duplicate_hints};
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
fn topology_bridge_mock_hint() {
    let mut mock = MockTopology::default();
    mock.set_bridge("br0", "v0");
    let topo = discover_topology(&mock, &["br0".into(), "v0".into()]);
    let hints = topology_duplicate_hints(&["br0".into(), "v0".into()], &topo);
    assert!(!hints.is_empty());
}

#[test]
fn dedup_halves_duplicate_iface_counts() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let pcap = dir.path().join("dup-two-iface.pcapng");
    let base = flux_run(&[
        "watch",
        "-r",
        pcap.to_str().unwrap(),
        "+views=src",
        "+pairing=off",
        "+window=all",
    ]);
    assert!(
        base.status.success(),
        "{}",
        String::from_utf8_lossy(&base.stderr)
    );
    let dedup = flux_run(&[
        "watch",
        "-r",
        pcap.to_str().unwrap(),
        "+dedup",
        "+views=src",
        "+pairing=off",
        "+window=all",
    ]);
    assert!(
        dedup.status.success(),
        "{}",
        String::from_utf8_lossy(&dedup.stderr)
    );
    let base_out = String::from_utf8_lossy(&base.stdout);
    let base_err = String::from_utf8_lossy(&base.stderr);
    let dedup_out = String::from_utf8_lossy(&dedup.stdout);
    let dedup_err = String::from_utf8_lossy(&dedup.stderr);
    let base_n = extract_counted(&format!("{base_out}{base_err}"));
    let dedup_n = extract_counted(&format!("{dedup_out}{dedup_err}"));
    assert!(base_n >= 2, "base={base_n}");
    assert_eq!(dedup_n, 1, "dedup={dedup_n} base={base_n}");
    let status = String::from_utf8_lossy(&dedup.stderr);
    assert!(
        status.contains("dedup=") || String::from_utf8_lossy(&dedup.stdout).contains("dedup="),
        "{status}"
    );
}

#[test]
fn overlap_table_in_replay_status() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let pcap = dir.path().join("dup-two-iface.pcapng");
    let out = flux_run(&[
        "watch",
        "-r",
        pcap.to_str().unwrap(),
        "+window=all",
        "+views=iface",
    ]);
    assert!(out.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(combined.contains("overlap"), "{combined}");
}

#[test]
fn vlan_view_and_filter() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let pcap = dir.path().join("vlan.pcap");
    let all = flux_run(&[
        "watch",
        "-r",
        pcap.to_str().unwrap(),
        "+views=vlan",
        "+window=all",
    ]);
    assert!(all.status.success());
    let text = String::from_utf8_lossy(&all.stdout);
    assert!(text.contains("100") && text.contains("200"), "{text}");
    let filtered = flux_run(&[
        "watch",
        "-r",
        pcap.to_str().unwrap(),
        "+vlan=100",
        "+views=src",
        "+pairing=off",
        "+window=all",
    ]);
    assert!(filtered.status.success());
    let ftxt = String::from_utf8_lossy(&filtered.stdout);
    assert!(ftxt.contains("counted 1"), "{ftxt}");
    assert!(ftxt.contains("1 of 2 (50.0%)"), "{ftxt}");
    let wrong_vlan = flux_run(&[
        "watch",
        "-r",
        pcap.to_str().unwrap(),
        "+vlan=99",
        "+views=src",
        "+pairing=off",
        "+window=all",
    ]);
    assert!(wrong_vlan.status.success());
    let wrong = String::from_utf8_lossy(&wrong_vlan.stdout);
    assert!(
        wrong.contains("0 of 2 (0.0%)") || wrong.contains("counted 0"),
        "{wrong}"
    );
    let vlan200 = flux_run(&[
        "watch",
        "-r",
        pcap.to_str().unwrap(),
        "+vlan=200",
        "+views=src",
        "+pairing=off",
        "+window=all",
    ]);
    assert!(vlan200.status.success());
    let v200 = String::from_utf8_lossy(&vlan200.stdout);
    assert!(v200.contains("counted 1"), "{v200}");
}

#[test]
fn dup_fixture_iface_names_distinct() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let pcap = dir.path().join("dup-two-iface.pcapng");
    let out = flux_run(&[
        "watch",
        "-r",
        pcap.to_str().unwrap(),
        "+views=iface",
        "+pairing=off",
        "+window=all",
    ]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("br0") && text.contains("v0"), "{text}");
}

fn extract_counted(text: &str) -> u64 {
    for line in text.lines() {
        if let Some(idx) = line.find("counted ") {
            let rest = &line[idx + "counted ".len()..];
            if let Some(n) = rest.split_whitespace().next() {
                if let Ok(v) = n.parse::<u64>() {
                    return v;
                }
            }
        }
    }
    0
}
