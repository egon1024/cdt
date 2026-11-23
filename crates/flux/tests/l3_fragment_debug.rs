use flux::capture::{iter_packets, open_packet_source, parse_l3};
use flux::options::AddressFamily;
use tempfile::tempdir;

#[test]
fn fragmented_pcap_yields_l3_fragments() {
    let dir = tempdir().unwrap();
    let status = std::process::Command::new(env!("CARGO"))
        .args(["run", "-p", "flux", "--example", "make-fixtures", "--"])
        .arg(dir.path())
        .status()
        .unwrap();
    assert!(status.success());
    let path = dir.path().join("fragmented.pcap");
    let mut src = open_packet_source(Some(path.to_str().unwrap())).unwrap();
    let mut frags = 0;
    for pkt in iter_packets(&mut src, "t") {
        let pkt = pkt.unwrap();
        if parse_l3(&pkt, AddressFamily::Auto).is_ok() {
            frags += 1;
        }
    }
    assert!(frags > 0, "expected parseable fragment frames");
}
