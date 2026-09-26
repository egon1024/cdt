# CDT utility release notes

Per-utility, operator-facing changelogs. Each file lists versions newest-first
with **New**, **Changed**, **Removed**, and **Fixed** subsections as needed.

| Utility | Release notes |
|---------|---------------|
| `cdt` (bundle) | [cdt.md](cdt.md) |
| `delve` | [delve.md](delve.md) |

Utilities listed here match [cdt-manifest.toml](../../cdt-manifest.toml)
components. See [docs/cdt.md](../cdt.md) for the documentation hub.

## Maintainer workflow

When cutting a release, automation runs:

```bash
python3 .github/scripts/cdt-versions.py component-versions-json
python3 .github/scripts/cdt-versions.py release-notes \
  --version "$(python3 -c 'import tomllib, pathlib; print(tomllib.loads(pathlib.Path("cdt-manifest.toml").read_text())["bundle"]["version"])')" \
  --component-versions "$(python3 .github/scripts/cdt-versions.py component-versions-json)"
```

While features are in flight, add bullets under **`## Unreleased`** in each
affected utility file.

**Semver on merge:** the merged PR description can override automatic patch bumps.
Use a line such as **`#delve:major`** (or `#delve:minor` / `#delve:patch`) so release
automation bumps the utility accordingly — for example **`#delve:major`** on delve
**0.1.1** yields **1.0.0**. The CDT bundle version still follows `#cdt:…` or the
default bundle bump unless you set `#major` / `#minor` / `#patch` for the bundle.

During **release preparation** (`bump-cdt-versions.sh`),
automation promotes that section for every bumped utility:

1. Renames **`## Unreleased`** → **`## <new-component-version>`** (newest-first)
2. Inserts a fresh empty **`## Unreleased`** at the top for the next cycle
3. Commits the updated files with the manifest bump PR

You can run the same step locally:

```bash
python3 .github/scripts/cdt-versions.py promote-release-notes \
  --bundle-version 0.8.0 \
  --component-versions '{"delve":"0.1.2"}'
```

The GitHub release body (`release-notes` subcommand) pulls the **`## <version>`**
sections for bumped utilities and links to the full file in this directory.
