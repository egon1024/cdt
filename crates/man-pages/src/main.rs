use std::env;
use std::fs;
use std::path::PathBuf;

use clap::CommandFactory;

fn main() {
    let out_dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("packaging/man"));

    fs::create_dir_all(&out_dir).expect("create man output directory");

    let delve_cmd = delve::args::Cli::command();
    clap_mangen::generate_to(delve_cmd, &out_dir).expect("generate delve.1");

    let cdt_cmd = cdt::args::Cli::command();
    clap_mangen::generate_to(cdt_cmd, &out_dir).expect("generate cdt.1");
}
