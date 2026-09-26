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

## Installing from GitHub releases

Published bundles appear on [GitHub Releases](https://github.com/egon1024/cdt/releases)
under tags `cdt-vX.Y.Z`. Each release ships **amd64** and **arm64** Linux
artifacts with the same formats on both architectures.

Pick the asset that matches your host (`uname -m` is `x86_64` for amd64,
`aarch64` for arm64):

| Format | amd64 | arm64 |
|--------|-------|-------|
| Production tarball | `cdt-X.Y.Z-amd64.tar.gz` | `cdt-X.Y.Z-arm64.tar.gz` |
| Debug tarball | `cdt-X.Y.Z-amd64-debug.tar.gz` | `cdt-X.Y.Z-arm64-debug.tar.gz` |
| Debian package | `cdt_X.Y.Z_amd64.deb` | `cdt_X.Y.Z_arm64.deb` |
| Debian debug package | `cdt-dbg_X.Y.Z_amd64.deb` | `cdt-dbg_X.Y.Z_arm64.deb` |
| RPM package | `cdt-X.Y.Z-1.x86_64.rpm` | `cdt-X.Y.Z-1.aarch64.rpm` |
| RPM debug package | `cdt-dbg-X.Y.Z-1.x86_64.rpm` | `cdt-dbg-X.Y.Z-1.aarch64.rpm` |

Each release also includes `SHA256SUMS` (all assets) and `cdt-X.Y.Z.spdx.json`
(SBOM from the amd64 build job).

Example (Debian on arm64):

```bash
curl -LO "https://github.com/egon1024/cdt/releases/download/cdt-vX.Y.Z/cdt_X.Y.Z_arm64.deb"
sudo dpkg -i "cdt_X.Y.Z_arm64.deb" || sudo apt-get -f install -y
cdt version
```

Tarballs unpack `bin/cdt`, `bin/delve`, and bundled docs; add `bin` to your
`PATH` or copy the binaries into a directory already on `PATH`.

## Local development on arm64

Contributors on **64-bit ARM Linux** (`uname -m` → `aarch64`), including
64-bit Raspberry Pi OS, run the same quality gate as CI:

```bash
make test
```

GitHub pull requests run that target on native arm64 runners as well as amd64.
Shipped `.deb` and `.rpm` files are built for **arm64**, not 32-bit armhf
(`armv7l`); 32-bit Raspberry Pi OS cannot install the published arm64 packages.

See [README.md](../README.md#arm64-linux-including-64-bit-raspberry-pi-os) for
optional local packaging commands.

## Related utilities

- [delve](delve.md) — delegation-path tracer (`delve` binary)
- [delve release notes](release-notes/delve.md) — operator-facing changes
- [Release notes index](release-notes/README.md) — all utility changelogs
