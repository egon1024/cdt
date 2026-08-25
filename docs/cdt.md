# cdt

The `cdt` binary is the **bundle meta utility** for Cole's DNS Tools. It reports
what is in the CDT release and which versions are installed. It does not perform
DNS operations itself.

## Commands

```bash
cdt version          # bundle version and all component versions
cdt version --json   # same, as JSON
cdt list               # bundled utilities (name, version, description)
cdt list --json
```

## Versioning

The bundle version and per-utility versions live in `cdt-manifest.toml` at the
repository root. Release automation keeps crate `Cargo.toml` versions in sync
with the manifest.

See the [repository README](../README.md#releases) for bump directives and
release workflow.

## Related utilities

- [delve](delve.md) — delegation-path tracer (`delve` binary)
