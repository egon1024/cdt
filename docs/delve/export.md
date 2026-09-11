# delve — session export

Export a stored trace tree as a static image for sharing, documentation, or
post-mortem review. Export reads the session from disk only — no live DNS
queries.

## Command

```bash
delve session export [id] [--format svg|png] [--layout tree|icicle]
                      [--output path|-] [--tree-index N]
```

| Flag | Default | Purpose |
|------|---------|---------|
| `[id]` | default session | Session id or unique prefix (same rules as `session show`) |
| `--format` | `svg` | Output format: `svg` or `png` |
| `--layout` | `tree` | Diagram layout: `tree` (node-link cards) or `icicle` (indented rows) |
| `--output`, `-o` | stdout | Output file path, or `-` for stdout |
| `--tree-index` | `0` | Which trace tree in a multi-tree session document |

## Examples

```bash
# SVG to stdout (default session, tree layout)
delve session export

# SVG file for a specific session
delve session export 01J... --output trace.svg

# Icicle layout — compact rows for wide multipath traces
delve session export --layout icicle --output trace-icicle.svg

# PNG rasterization (requires export-png feature — see below)
delve session export --format png --layout tree --output trace.png
```

Omit `[id]` to use the [default session](concepts.md#default-session).

## Layouts

### Tree (default)

Left-to-right tidy tree with hop cards connected by orthogonal edges. Best for
small to medium traces where the delegation fan-out is easy to follow visually.

Each card shows zone, server, query, transport, rcode, RTT bar, outcome badge,
and branch/cache indicators when present. SVG groups carry `data-path` attributes
and `<title>` tooltips for machine and human use.

### Icicle

One horizontal row per hop, indented by depth with tree connector rails. Best for
wide `+expand=all` traces where tree cards would sprawl horizontally. Columns are
measured from content width with ellipsis overflow; the primary path is marked in
the gutter.

RTT bar colors match the explore Compare view (`explore.rtt_bar` in
[configuration](configuration.md#explorertt_bar)).

## PNG export and packaging

SVG export is always available.

PNG export rasterizes the same SVG using `resvg` and is enabled by default in
source and official `.deb`, `.rpm`, and release tarball builds.

To build a leaner binary without PNG support:

```bash
cargo build -p delve --no-default-features
```

If `--format png` is requested in a build without `export-png`, delve exits with
an error explaining that PNG export is not enabled in that build.

## Multi-tree sessions

When a session document contains more than one trace tree (for example after
branching), export renders one tree per invocation. Use `--tree-index` to select
which tree; index `0` is the default.

## See also

- [Session explore](explore.md) — interactive TUI and JSON exports
- [Command reference](reference.md) — full CLI table
- [Concepts](concepts.md) — sessions, branching, expansion
