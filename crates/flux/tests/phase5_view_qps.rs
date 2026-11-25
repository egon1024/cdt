use std::process::Command;

use tempfile::tempdir;

fn regenerate_fixtures(dir: &std::path::Path) {
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
fn batch_rate_window_and_tick_differ() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let pcap = dir.path().join("udp-basic.pcap");
    let p = pcap.to_str().unwrap();
    let window = flux_run(&[
        "watch",
        "-r",
        p,
        "+window=30s",
        "+views=src",
        "+rate=window",
    ]);
    let tick = flux_run(&["watch", "-r", p, "+window=30s", "+views=src", "+rate=tick"]);
    assert!(window.status.success() && tick.status.success());
    let w = String::from_utf8_lossy(&window.stdout);
    let t = String::from_utf8_lossy(&tick.stdout);
    assert!(w.contains("Rate"));
    assert!(w.contains("+rate=window"));
    assert!(t.contains("+rate=tick"));
    assert_ne!(w, t);
}

#[test]
fn options_rate_and_sort_parse() {
    let opts = flux::options::FluxOptions::parse(&[
        "+rate=tick".into(),
        "+sort=rate".into(),
        "+views=src".into(),
    ])
    .expect("parse");
    assert_eq!(opts.rate_mode, flux::options::RateMode::Tick);
    assert_eq!(opts.view_sort, flux::options::ViewSort::Rate);
}
