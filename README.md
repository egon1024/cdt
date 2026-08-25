# cdt

Cole's DNS Tools — a Rust workspace for DNS utilities.

## Structure

- `crates/dns-core` — shared DNS primitives (wire format, EDNS/EDE/NSID)
- `crates/dns-resolve` — iterative delegation tracing
- `crates/delve` — `delve` CLI binary
- `crates/*` — additional tool crates as they are developed

## delve (phase 1)

Trace delegation for a query name:

```bash
cargo run -p delve -- trace example.com
cargo run -p delve -- trace example.com --events   # NDJSON on stdout
cargo run -p delve -- trace example.com --tcp -4 --time 3
```

Flags follow dig conventions where practical (`--tcp`, `--time`, `--tries`, `-4`/`-6`, `--dnssec`, `--nonsid`). NSID is requested by default.

## Development

```bash
make test    # fmt-check, clippy, unit tests (same as CI)
make build
make help    # list all targets
```

CI runs `make test` on pull requests (aligned with DNSConduit).

## Releases

Versioning follows DNSConduit-style semver rules:

- **Current version** is the highest semver among GitHub releases and git tags (or `0.0.0` before the first release).
- **Default bump** on merge to `main` is **minor** (first release → `0.1.0`).
- Override with a PR description line containing only `#major`, `#minor`, or `#patch` (case-insensitive). Only one directive is allowed.

Pull requests get an automated **version preview** comment. On merge to `main`, the **Release** workflow bumps `Cargo.toml` / `Cargo.lock` and creates a GitHub release.

Configure a `RELEASE_PUSH_TOKEN` repository secret (admin PAT) so the release workflow can merge the version-bump PR. Release artifacts and docs deploy are not wired yet.

## Planned (not yet implemented)

- Documentation site generation and deployment (DNSConduit-style `docs-ci` / `docs-deploy`)
- Release packages and distribution assets (DNSConduit-style `packaging/` and release workflows)
