# delve — storage and output

Where delve persists data on disk and the shapes it writes.

## Data locations

| Data | Path |
|------|------|
| Config | `$XDG_CONFIG_HOME/cdt/delve.yaml` |
| Response cache | `$XDG_CACHE_HOME/cdt/delve/cache.sqlite` |
| Sessions (SQLite) | `$XDG_DATA_HOME/cdt/delve/sessions.sqlite` |
| Sessions (NDJSON fallback) | `$XDG_DATA_HOME/cdt/delve/sessions/*.json` |

On non-Linux platforms, the `directories` crate selects the equivalent config,
cache, and data locations.

Installed packages ship the full documentation tree at
`/usr/share/doc/cdt/docs/` (including this guide and sibling pages under
`docs/delve/`).

## Sessions vs response cache

These are separate on purpose:

- **Sessions** store a full **snapshot** of trace trees (`TraceResult` and nested
  tree nodes). `delve session show` reads only that stored data — no network, no
  cache.
- **Response cache** speeds up **new live traces and branches** by reusing recent
  DNS responses within record TTL. `delve cache stats` reports entry count, size,
  and cumulative hit/miss counts (persisted in `cache.sqlite` across runs). Cache
  expiry does not affect stored sessions.

See [concepts — response cache](concepts.md#response-cache) for operator-facing
behavior.

## Output shapes

### Live trace (`+events`)

NDJSON lines on stdout include `hop`, `message`, and `complete` events. The
`complete` event carries the full `TraceResult`.

Human progress and the `session: …` line go to stderr.

### Stored sessions

Sessions use a versioned JSON document containing trace trees, view state, and
metadata (`id`, `created_at`, `updated_at`, `pinned`, and the `TraceRequest` used
for reuse matching).

Flat export via `session show --json` emits the primary tree as a `TraceResult`-shaped
`complete` event. Hierarchical export via `session events` emits an `explore_tree`
event — see [explore](explore.md#show-json-vs-events).

## See also

- [delve](../delve.md) — hub and quick start
- [Concepts](concepts.md) — sessions vs cache
- [Configuration](configuration.md) — config file path
