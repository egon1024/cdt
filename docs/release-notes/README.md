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

For each utility whose component version **bumps** in the release, ensure
`docs/release-notes/<utility>.md` has a matching `## <version>` section with
operator-facing **New / Changed / Removed / Fixed** bullets. The GitHub release
body pulls those sections and links to the full file in this directory.
