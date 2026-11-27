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
fn replay_window_15s_pairing_off_matches_steady_qps() {
    let dir = tempdir().unwrap();
    regenerate_fixtures(dir.path());
    let pcap = dir.path().join("large.pcap");
    let p = pcap.to_str().unwrap();
    let out = flux_run(&[
        "watch",
        "-r",
        p,
        "+pairing=off",
        "+window=15s",
        "+rate=window",
        "+views=src",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let counted = extract_counted(&text);
    assert_eq!(
        counted, 15,
        "expected last 15 seconds of 1 q/s pcap: {text}"
    );
    let row = text
        .lines()
        .find(|l| l.contains("192.0.2.10"))
        .expect("source row");
    assert!(
        row.contains("0.33"),
        "steady 1 q/s / 3 sources => ~0.33/s per source: {row}"
    );

    let all = flux_run(&[
        "watch",
        "-r",
        p,
        "+pairing=off",
        "+rate=window",
        "+views=src",
    ]);
    assert!(all.status.success());
    let all_text = String::from_utf8_lossy(&all.stdout);
    let row_all = all_text
        .lines()
        .find(|l| l.contains("192.0.2.10"))
        .expect("source row all");
    assert!(
        row_all.contains("0.33"),
        "window-all steady rate: {row_all}"
    );
}

fn extract_counted(text: &str) -> u64 {
    for line in text.lines() {
        if let Some(idx) = line.find("counted ") {
            let rest = &line[idx + "counted ".len()..];
            let n: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(v) = n.parse() {
                return v;
            }
        }
    }
    0
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
