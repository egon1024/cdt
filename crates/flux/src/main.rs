use flux::args::Cli;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    if let Err(err) = Cli::parse_and_run() {
        eprintln!("flux: {err}");
        std::process::exit(1);
    }
}
