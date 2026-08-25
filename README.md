# cdt

Cole's DNS Tools — a Rust workspace for DNS utilities.

## Structure

- `cdt-manifest.toml` — bundle and utility version manifest (source of truth for releases)
- `crates/cdt` — `cdt` bundle meta utility (`cdt version`, `cdt list`)
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

CI runs `make test` on pull requests.

## Releases

CDT ships as a **bundle** (`cdt`) containing independently versioned utilities. The manifest in `cdt-manifest.toml` is the source of truth; release automation syncs versions into each crate.

```bash
make version                 # show manifest + cdt version output
cargo run -p cdt -- version  # bundle and utility versions
delve --version              # delve utility version only
```

### Versioning rules

| What | Version | Tag |
|------|---------|-----|
| Bundle | `cdt` in `cdt-manifest.toml` | `cdt-v0.1.0` |
| Utilities | per-component in manifest (e.g. `delve 0.1.0`) | listed in release notes |
| Internal libs | `workspace.package.version` (tracks bundle) | — |

**Bundle bump** on merge to `main` defaults to **minor** (first release → `0.1.0`).

**PR directives:**

- Bundle: `#cdt:minor` or shorthand `#minor` (only one bundle level per PR)
- Utility: `#delve:patch`, `#delve:minor`, etc.
- Utilities with changes under `crates/<utility>/` receive an automatic **patch** bump unless overridden

Pull requests get an automated **version preview** comment. On merge to `main`, the **Release** workflow bumps `cdt-manifest.toml`, crate `Cargo.toml` files, and creates a GitHub release tagged `cdt-vX.Y.Z`.

Configure a `RELEASE_PUSH_TOKEN` repository secret (admin PAT) so the release workflow can merge the version-bump PR. Release artifacts are not wired yet.

## Planned (not yet implemented)

- Release packages and distribution assets
