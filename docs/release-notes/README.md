# CDT utility release notes

Per-utility, operator-facing changelogs. Each file lists versions newest-first
with **New**, **Changed**, **Removed**, and **Fixed** subsections as needed.

### File format

- Top-level **`## <version>`** headings (newest first). Use **`## Unreleased`**
  for work not yet tagged.
- Under each version, optional **`### New`**, **`### Changed`**, **`### Removed`**,
  and **`### Fixed`** sections with bullet lists.
- Describe **operator-visible** behavior (commands, flags, outcomes), not
  internal refactors or crate layout.

### When to update

Add or extend bullets under **`## Unreleased`** in every affected utility file
in the same change that ships user-facing behavior. If a PR touches multiple
utilities, update each corresponding `docs/release-notes/<utility>.md`.

In-flight work stays under **`## Unreleased`**. Do not add a **`## x.y.z`** heading
for the next release by hand — release prep promotes **Unreleased** to the new
component version (see below).

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

During **release preparation**, `bump-cdt-versions.sh` (invoked from
`.github/workflows/release.yml`) bumps manifest and crate versions, then
promotes release notes for every bumped utility:

1. Renames **`## Unreleased`** → **`## <new-component-version>`** (newest-first)
2. Inserts a fresh empty **`## Unreleased`** at the top for the next cycle
3. Commits the updated files with the manifest bump PR

You can run the same step locally:

```bash
python3 .github/scripts/cdt-versions.py promote-release-notes \
  --bundle-version 0.8.0 \
  --component-versions '{"delve":"0.1.2"}'
```

When the release is published, `.github/scripts/publish-cdt-release.sh` runs
`release-notes` and passes the Markdown to `gh release create`. That subcommand
pulls the **`## <version>`** sections for bumped utilities and links to the
full file in this directory (for example `docs/release-notes/delve.md`).
