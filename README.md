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
| Delegation tracer | `delve` | [docs/delve.md](docs/delve.md) ([concepts](docs/delve/concepts.md), [reference](docs/delve/reference.md), …) |

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
make test    # fmt-check, clippy, unit tests (same as CI)
make build
make help    # list all targets
```

CI runs `make test` on pull requests.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the
full text.
