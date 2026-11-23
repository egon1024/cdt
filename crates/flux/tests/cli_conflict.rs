use std::process::Command;

#[test]
fn interface_and_read_conflict() {
    let bin = env!("CARGO_BIN_EXE_flux");
    let out = Command::new(bin)
        .args(["watch", "-i", "lo", "-r", "/dev/null"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("cannot use"), "{err}");
}

#[test]
fn help_lists_subcommands() {
    let bin = env!("CARGO_BIN_EXE_flux");
    let out = Command::new(bin).arg("--help").output().unwrap();
    let help = String::from_utf8_lossy(&out.stdout);
    assert!(help.contains("watch"));
    assert!(help.contains("validate"));
}
