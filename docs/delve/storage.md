# delve — storage and output

Where delve persists data on disk and the shapes it writes.

## Data locations

| Data | Path |
|------|------|
| Config | `$XDG_CONFIG_HOME/cdt/delve.yaml` |
| Response cache | `$XDG_CACHE_HOME/cdt/delve/cache.sqlite` |
| Enrichment cache | `$XDG_DATA_HOME/cdt/delve/enrichment.sqlite` |
| Sessions (SQLite) | `$XDG_DATA_HOME/cdt/delve/sessions.sqlite` |
| Sessions (NDJSON fallback) | `$XDG_DATA_HOME/cdt/delve/sessions/*.json` |

On non-Linux platforms, the `directories` crate selects the equivalent config, cache, and data locations.

Installed packages ship the full documentation tree at `/usr/share/doc/cdt/docs/` (including this guide and sibling pages under `docs/delve/`).

## Sessions vs response cache

These are separate on purpose:

- **Sessions** store a full **snapshot** of trace trees (`TraceResult` and nested tree nodes). `delve session show` reads only that stored data — no network, no cache.
- **Response cache** speeds up **new live traces and branches** by reusing recent DNS responses within record TTL. `delve cache stats` reports entry count, size, and cumulative hit/miss counts (persisted in `cache.sqlite` across runs). Cache expiry does not affect stored sessions.
- **Enrichment cache** stores recent ICMP probe snapshots keyed by resolver IP (default TTL 15 minutes). Session `targets` on disk are independent; purging enrichment cache does not remove stored session ICMP. Administer with `delve cache enrichment …`.

See [concepts — response cache](concepts.md#response-cache) for operator-facing behavior.

## Output shapes

### Live trace (`+events`)

NDJSON lines on stdout include `hop`, `message`, and `complete` events. The `complete` event carries the full `TraceResult`.

Human progress and the `session: …` line go to stderr.

### Stored sessions

Sessions use a JSON document containing trace trees, view state, enrichment
**`targets`** (resolver IPs with optional ICMP snapshots), optional
**`capture_context`**, and metadata (`id`, `created_at`, `updated_at`, `pinned`,
`frozen`, and the `TraceRequest` used for reuse matching).

Flat export via `session show --json` emits the primary tree as a `TraceResult`-shaped `complete` event. Hierarchical export via `session events` emits an `explore_tree` event — see [explore](explore.md#show-json-vs-events).

### Portable session bundles

`delve session export` / `import` move full session documents in a JSON envelope
(`format: "delve-sessions"`). That is separate from diagram images
(`session diagram`) and from the flat `show --json` / `events` shapes above.
See [reference — session bundles](reference.md#session-bundles).

## Format versions

Most operators can ignore the numbers below. They matter when reading raw JSON
on disk, writing importers, or diagnosing an import that skipped a session.

| Layer | Field | Current | Role |
|-------|-------|---------|------|
| **Session document** | `version` inside each stored session | `2` | Shape of one session (trees, view state, freeze, …) |
| **Portable bundle** | envelope `format` + `version` | `delve-sessions` / `1` | Wrapper around one or more session documents |

These version spaces are independent. A bundle with envelope `version: 1` still
carries session documents whose own `version` is `2`.

**History (session documents):** early delve builds stored a flatter session
shape (`version: 1`). Current builds write and import only the current document
shape. Import reports and skips documents it cannot read; it does not convert
older shapes in place.

**Bundles:** unsupported envelope `format` or `version` fails before any store
write. That check is separate from per-session document acceptance.

## See also

- [delve](../delve.md) — hub and quick start
- [Concepts](concepts.md) — sessions vs cache, freeze
- [Configuration](configuration.md) — config file path
