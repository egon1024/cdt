# cdt

Cole's DNS Tools — a Rust workspace for DNS utilities.

## AI-assisted development

This project was built with extensive assistance from AI tools. Some operators
and contributors prefer software written without that involvement — a view I
can respect, even if I don't agree with it. I am not currently planning to
reevaluate how cdt is developed, and I will not engage in arguments about that
decision.

## Utilities

User-facing tools ship in the CDT bundle. Each utility has a guide in `docs/` —
a hub page at `docs/<tool>.md`, with deeper pages under `docs/<tool>/` when needed:

| Utility | Binary | Documentation |
|---------|--------|-----------------|
| Bundle meta | `cdt` | [docs/cdt.md](docs/cdt.md) |
| Delegation tracer | `delve` | [docs/delve.md](docs/delve.md) ([concepts](docs/delve/concepts.md), [reference](docs/delve/reference.md), …) · [release notes](docs/release-notes/delve.md) |

```bash
cargo run -p delve -- trace example.com
cargo run -p cdt -- version
```

## Workspace layout

- `cdt-manifest.toml` — bundle and utility version manifest
- `docs/` — per-utility documentation (Markdown hub + optional sub-guides)
- `crates/cdt` — `cdt` bundle meta utility
- `crates/delve` — `delve` CLI binary
- `crates/dns-core` — shared DNS primitives (wire format, EDNS/EDE/NSID)
- `crates/dns-resolve` — iterative delegation tracing
- `crates/dns-cache` — TTL-aware response cache (used by delve)
- `crates/*` — additional tool crates as they are developed

## Development

```bash
make test    # fmt-check, clippy, unit tests, script regressions (same as CI)
make build
make help    # list all targets
```

CI runs `make test` on pull requests on **amd64** and **arm64** GitHub-hosted
runners. Optional CI jobs build and smoke-test native arm64 `.deb` and `.rpm`
packages on `ubuntu-24.04-arm`.

### arm64 Linux (including 64-bit Raspberry Pi OS)

On hosts where `uname -m` is `aarch64` (64-bit Raspberry Pi OS, cloud ARM VMs,
Apple Silicon Linux VMs, and similar), use the same entry point as CI:

```bash
make test
```

Optional local packaging check (slow):

```bash
VERSION=0.0.0-local ARCH=arm64 make release-artifacts
ARCH=arm64 VERSION=0.0.0-local bash .github/scripts/verify-release-artifacts.sh
```

Shipped Linux packages target **arm64/aarch64** alongside amd64. **32-bit**
Raspberry Pi OS (`armv7l`, armhf) is not a supported install target for those
packages; use 64-bit Pi OS or download the amd64 or arm64 artifact that matches
your CPU.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the
full text.
