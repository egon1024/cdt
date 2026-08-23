# cdt

Cole's DNS Tools — a Rust workspace for DNS utilities.

## Structure

- `crates/dns-core` — shared DNS primitives used across tools
- `crates/*` — individual tool crates (added as tools are developed)

## Development

```bash
make test    # fmt-check, clippy, unit tests (same as CI)
make build
make help    # list all targets
```

CI runs `make test` on pull requests (aligned with DNSConduit).

## Planned (not yet implemented)

- Documentation site generation and deployment (DNSConduit-style `docs-ci` / `docs-deploy`)
- Release packages and distribution assets (DNSConduit-style `packaging/` and release workflows)
