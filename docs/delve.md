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
| `delve session list` | List stored sessions (`*` pinned, `@` current default) |
| `delve session current` | Print the current default session id |
| `delve session show [id]` | Show a stored session (no network); omit id for the default |
| `delve session show [id] --json` | Same session as flat JSON (`event: complete`) |
| `delve session rm <id>` | Delete one session |
| `delve session pin <id>` | Exempt from retention purge |
| `delve session unpin <id>` | Allow retention purge again |
| `delve session purge` | Apply retention policy now |
| `delve session purge --dry-run` | Report what would be removed |
| `delve session explore [id]` | Interactive tree explorer (TUI); omit id to reopen the last session |
| `delve session outline [id]` | Indented resolution tree on stdout; omit id for the last session |
| `delve session events [id]` | Structured JSON explore tree on stdout; omit id for the last session |
| `delve cache stats` | Response cache statistics |
| `delve cache purge` | Remove expired cache entries |
| `delve cache purge --all` | Clear the entire response cache |

Session ids accept a full ULID or a unique short prefix (like git).

The **default session** is the last one you traced, explored, or otherwise
touched. Commands that accept an optional `[id]` (`show`, `outline`, `events`,
`explore`) use it when you omit the id. `delve session current` prints that id;
`delve session list` marks it with `@` in the first column (`*` means pinned).

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
| `+fresh` | off | Always run a live trace; do not reuse a stored session |
| `+follow` / `+nofollow` | off | Follow CNAME and DNAME aliases, restarting delegation from the new name |
| `-t TYPE` or `-TYPE` | `A` | Query type |
| `-x` | off | Reverse lookup: positional argument is an IP address; queries `PTR` at the corresponding `in-addr.arpa` / `ip6.arpa` name |
| `-4` / `-6` | both | Address family; mutually exclusive |
| `@server` | root hints | Starting server (**IP literal** only today) |

Supported query types:

| Category | Types |
|----------|-------|
| Address / naming | `A`, `AAAA`, `CNAME`, `DNAME`, `NS`, `PTR`, `RP` |
| Mail / text / service | `MX`, `TXT`, `SRV`, `HTTPS`, `SVCB` |
| Security / DNSSEC / DANE | `CAA`, `CDNSKEY`, `CDS`, `CERT`, `CSYNC`, `DNSKEY`, `DS`, `OPENPGPKEY`, `RRSIG`, `NSEC`, `NSEC3`, `NSEC3PARAM`, `SMIMEA`, `SSHFP`, `TLSA` |
| Other | `HINFO`, `LOC`, `NAPTR`, `SOA` |

Any IANA type code also works via `TYPEnn` (for example `TYPE45` for IPSECKEY).

Truncated UDP responses (`TC=1`) are recorded as-is. Delve does **not** automatically retry over TCP when `TC` is set; use `+tcp` up front if you need TCP for the whole trace.

Human progress is written to **stderr**; with `+events`, structured events go to
**stdout** so you can redirect:

```bash
delve trace example.com +events > trace.ndjson
```

### Session reuse

When `+save` is enabled (the default), `delve trace` checks for an existing stored
session whose trace parameters match the current request (qname, qtype, `@server`,
transport, timeout, tries, DNSSEC/NSID flags, address family, and cache options).
If a match exists, delve **replays that stored snapshot** instead of issuing new
DNS queries. The snapshot is kept until retention purge removes it — there is no
time-based expiry for reuse.

```text
session: 01JXXXXXXXXXXXXXXXXXXXXXXXXXX (reused snapshot from 2026-08-25T12:34:56Z)
```

Use `+fresh` to force a live trace and save a new session. `+nosave` disables both
saving and reuse.

With `+events`, reuse replays stored hop events and emits a final `complete` event
with `"reused": true`.

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

## Session explore, outline, and events

`delve session explore <id>` opens a stored trace in the **interactive tree TUI**
(no network I/O). Omit `<id>` to reopen the **default session**.

`delve session outline <id>` prints the same tree as a **one-shot indented outline**
on stdout — suitable for logs, pipes, and narrow terminals. The first line is
`session: <id>`.

`delve session events <id>` prints the explore tree as **structured JSON** on stdout
(`event: explore_tree`, including `session` and hierarchical `tree` nodes).

### `show --json` vs `events`

These are different JSON shapes for different jobs:

| Command | JSON shape | Best for |
|---------|------------|----------|
| **`session show --json`** | Flat `TraceResult`: chronological `hops` array + `final_response` | Replaying trace data, diffing sessions, tools that expect the stored snapshot |
| **`session events`** | Hierarchical explore `tree`: delegation / resolve / hop / final nodes | Tools that want the same structure as the TUI and outline views |

Both include per-query **`rtt_ms`** and **`from_cache`** in hop JSON. The explore
tree omits a separate final node when the last hop already records the
authoritative answer (same exchange as `final_response`).

Use **`--json`** for JSON output from `session show` (not `+events`; that flag is
for `delve trace` only).

```bash
delve session explore              # default session, TUI
delve session explore 01J...       # explicit id, TUI
delve session outline 01J...       # print tree once and exit
delve session events 01J...        # JSON tree on stdout
delve session show --json          # flat JSON for the default session
```

| Command | Output |
|---------|--------|
| **`session explore`** | TUI with colored tree + dig-style detail pane; session id in title bar; `?` help, `c` toggle colors, `Tab` / `Shift-Tab` cycle panes |
| **`session outline`** | `session: <id>` header + indented tree on stdout |
| **`session events`** | Structured JSON explore tree on stdout |
| **`session show --json`** | Flat JSON trace snapshot on stdout |

New traces store full DNS response sections (header flags, question, answer, authority, additional) for each hop. The explore detail pane renders these in a **dig-style** layout. Older saved sessions without section data fall back to the compact YAML-style summary.

## Data locations

| Data | Path |
|------|------|
| Config | `$XDG_CONFIG_HOME/cdt/delve.yaml` |
| Response cache | `$XDG_CACHE_HOME/cdt/delve/cache.sqlite` |
| Sessions (SQLite) | `$XDG_DATA_HOME/cdt/delve/sessions.sqlite` |
| Sessions (NDJSON fallback) | `$XDG_DATA_HOME/cdt/delve/sessions/*.json` |
| Last session pointer | `$XDG_STATE_HOME/cdt/delve/last-session` |

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
