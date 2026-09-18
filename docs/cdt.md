# cdt

The `cdt` binary is the **bundle meta utility** for Cole's DNS Tools. It reports what is in the CDT release and which versions are installed. It does not perform DNS operations itself.

## Commands

```bash
cdt version          # bundle version and all component versions
cdt version --json   # same, as JSON
cdt list               # bundled utilities (name, version, description)
cdt list --json
```

## Version output

The bundle version and per-utility versions live in `cdt-manifest.toml` at the repository root.

```bash
make version
cargo run -p cdt -- version
```

## Related utilities

- [delve](delve.md) — delegation-path tracer (`delve` binary)
