# cdt

Cole's DNS Tools — a Rust workspace for DNS utilities.

## Structure

- `crates/dns-core` — shared DNS primitives used across tools
- `crates/*` — individual tool crates (added as tools are developed)

## Development

```bash
cargo build
cargo test
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

CI runs format, Clippy, and tests on pull requests (aligned with DNSConduit).

## Planned (not yet implemented)

- Documentation site generation and deployment (DNSConduit-style `docs-ci` / `docs-deploy`)
- Release packages and distribution assets (DNSConduit-style `packaging/` and release workflows)
