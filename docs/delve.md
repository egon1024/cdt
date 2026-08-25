# delve

`delve` traces the DNS delegation path for a query name — similar in spirit to
`dig +trace`, but built for operators who need structured per-hop metadata (NSID,
EDE, RTT), persisted sessions, and machine-readable output.

## Quick start

```bash
delve trace example.com
delve trace example.com +events          # NDJSON on stdout
delve trace example.com +tcp -4 +timeout=3 -t NS @1.1.1.1
```

After a trace with saving enabled (the default), stderr includes:

```text
session: 01JXXXXXXXXXXXXXXXXXXXXXXXXXX
```

## Command overview

| Command | Purpose |
|---------|---------|
| `delve trace …` | Run a delegation trace |
| `delve session list` | List stored sessions |
| `delve session show <id>` | Show a stored session (no network) |
| `delve session rm <id>` | Delete one session |
| `delve session pin <id>` | Exempt from retention purge |
| `delve session unpin <id>` | Allow retention purge again |
| `delve session purge` | Apply retention policy now |
| `delve session purge --dry-run` | Report what would be removed |
| `delve session explore <id>` | Interactive tree explorer (TUI) or static outline |
| `delve cache stats` | Response cache statistics |
| `delve cache purge` | Remove expired cache entries |
| `delve cache purge --all` | Clear the entire response cache |

Session ids accept a full ULID or a unique short prefix (like git).

## Trace query options

Options follow **dig** conventions (not GNU long flags):

| Option | Default | Notes |
|--------|---------|-------|
| `+tcp` / `+notcp` | UDP | Transport |
| `+timeout=N` / `+time=N` | 5s | Both spellings; `N < 1` clamps to 1 |
| `+tries=N` | 2 | Retries per server |
| `+dnssec` / `+nodnssec` | off | Sets the DO bit |
| `+nsid` / `+nonsid` | **on** | delve requests NSID by default |
| `+events` | off | NDJSON event stream on stdout |
| `+cache` / `+nocache` | on | Use the global response cache for all queries |
| `+nocache=QNAME` | — | Skip cache for that exact query name (repeatable); other queries still use cache |
| `+save` / `+nosave` | on | Persist trace as a session |
| `-t TYPE` or `-TYPE` | `A` | Query type |
| `-4` / `-6` | both | Address family; mutually exclusive |
| `@server` | root hints | Starting server (**IP literal** only today) |

Supported query types: `A`, `AAAA`, `NS`, `CNAME`, `SOA`, `MX`, `TXT`.

Human progress is written to **stderr**; with `+events`, structured events go to
**stdout** so you can redirect:

```bash
delve trace example.com +events > trace.ndjson
```

## Configuration

delve reads an optional YAML config file:

**Linux (XDG):** `$XDG_CONFIG_HOME/cdt/delve.yaml`

Typical path: `~/.config/cdt/delve.yaml`

If the file is missing, defaults apply. If the file exists but is invalid,
delve prints a warning and falls back to defaults.

### Example

```yaml
session:
  retention: 180d
```

### `session.retention`

Controls how long **unpinned** stored sessions are kept before automatic purge.

| Value | Meaning |
|-------|---------|
| `180d` | Calendar days (default when unset: **180d**) |
| `6mo` | Calendar months (same day-of-month, N months earlier; end-of-month clamped) |
| `0` or `never` | Sessions are never removed by retention |

Retention purge runs when the session store is opened (any command that touches
sessions: `trace` with `+save`, `session list`, etc.). Pinned sessions are
skipped. When sessions are removed, stderr shows a notice only if the count is
greater than zero, for example:

```text
purged 3 sessions older than 180d
```

Use `delve session pin <id>` to keep a session across retention. Pinned sessions
show a `*` prefix in `delve session list`.

Manual removal: `delve session rm <id>` or `delve session purge`.

## Session explore

`delve session explore <id>` walks a stored trace as a tree — delegation hops and
nameserver-resolution branches — without network I/O.

| Mode | When | Output |
|------|------|--------|
| **TUI** (default) | Interactive terminal | Full-screen tree + detail pane; `j`/`k` move, Enter expand/collapse, `q` quit |
| **Outline** | `+outline`, or stdout not a tty | One-shot indented tree on stdout |
| **Tree JSON** | `+events` | Structured tree document on stdout |

```bash
delve session explore 01J...           # TUI when attached to a terminal
delve session explore 01J... +outline  # print tree once and exit
delve session explore 01J... +events   # JSON tree on stdout
```

## Data locations

| Data | Path |
|------|------|
| Config | `$XDG_CONFIG_HOME/cdt/delve.yaml` |
| Response cache | `$XDG_CACHE_HOME/cdt/delve/cache.sqlite` |
| Sessions (SQLite) | `$XDG_DATA_HOME/cdt/delve/sessions.sqlite` |
| Sessions (NDJSON fallback) | `$XDG_DATA_HOME/cdt/delve/sessions/*.json` |

On non-Linux platforms, the `directories` crate selects the equivalent config,
cache, and data locations.

## Sessions vs response cache

These are separate on purpose:

- **Sessions** store a full **snapshot** of the trace (`TraceResult`). `delve
  session show` reads only that stored data — no network, no cache.
- **Response cache** speeds up **new live traces** by reusing recent DNS
  responses within record TTL. `delve cache stats` reports entry count, size,
  and cumulative hit/miss counts (persisted in `cache.sqlite` across runs).
  Cache expiry does not affect stored sessions.

Each `delve trace` with `+save` creates a **new** session. Re-running a trace may
use the cache for fewer queries, but it does not update an existing session.

## Output shapes

With `+events`, NDJSON lines include `hop`, `message`, and `complete` events.
The `complete` event carries the full `TraceResult`.

Stored sessions use a versioned JSON document (`version: 1`) containing the same
`TraceResult` shape plus metadata (`id`, `created_at`, `pinned`).

## See also

- [cdt](cdt.md) — bundle version and utility list
