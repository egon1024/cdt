# delve

`delve` traces the DNS delegation path for a query name — similar in spirit to `dig +trace`, but built for operators who need structured per-hop metadata (NSID, EDE, RTT), persisted trace snapshots, and machine-readable output.

## What a trace is

A **trace** walks from a starting resolver (root hints by default, or an `@server` you choose) toward the authoritative nameservers for your query. At each hop, delve issues a DNS query, records the response (rcode, flags, sections, RTT, NSID when present), and follows delegation until it reaches an answer or a terminal error.

Human progress goes to **stderr**. With `+events`, structured NDJSON events go to **stdout** so you can pipe or store them separately.

## Sessions

A **session** is a saved snapshot of one completed trace. When `+save` is enabled (the default), delve writes the full result — every hop, response section, and timing — to local storage as a versioned JSON document keyed by a ULID.

Sessions exist so you can work with a trace **after** the live queries finish, without touching the network again:

- **Inspect** a trace with `delve session show`, `outline`, or `events`.
- **Explore** it interactively in the TUI with `delve session explore`.
- **Share or diff** stable JSON (`show --json`, `events`) for automation and review.
- **Replay** the same human or NDJSON output later via session reuse (see below).

Each `delve trace` that saves creates a **new** session id. Re-running a trace does not update an existing session; it either reuses a matching snapshot or saves a fresh one.

### Default session

The **default session** is resolved in order: an explicit id on the command line, then `DELVE_SESSION` when set (non-empty after trimming) and the session still exists, then the most recently modified stored session (`updated_at`). Commands that accept an optional `[id]` (`show`, `outline`, `events`, `explore`, `branch`) use the default when you omit the id. `delve session current` prints that resolved id; `delve session list` marks it with `@` in the first column (`*` means pinned).

`DELVE_SESSION` is an override for scripts and scoped shells — delve does not set it. If it points at a removed session, delve prints a warning to stderr and falls through to the most recently modified session.

Session ids accept a full ULID or a unique short prefix (like git).

### Session reuse

When `+save` is enabled, `delve trace` first looks for an existing stored session whose **trace parameters** match the current request: qname, qtype, `@server`, transport, timeout, tries, DNSSEC/NSID flags, address family, cache options, and related flags. If a match exists, delve **replays that stored snapshot** instead of issuing new DNS queries. The snapshot stays available until retention purge removes it — there is no time-based expiry for reuse.

```text
session: 01JXXXXXXXXXXXXXXXXXXXXXXXXXX (reused snapshot from 2026-08-25T12:34:56Z)
```

Use `+fresh` to force a live trace and save a new session. `+nosave` disables both saving and reuse.

With `+events`, reuse replays stored hop events and emits a final `complete` event with `"reused": true`.

### Retention and pinning

Unpinned sessions are subject to **retention** only when you set `session.retention` in config (default **unlimited** — sessions are kept until you remove them). Purge runs when the session store is opened (any command that touches sessions). **Pinned** sessions are skipped by automatic retention and by `delve session purge` (but not by explicit `delve session rm <id>`).

Use `delve session pin <id>` to keep a session across retention. Use `delve session purge --all` to remove every unpinned session regardless of age. Use `delve session purge <id>` to remove one unpinned session regardless of age (pinned sessions are skipped).

## Response cache

Separate from sessions, delve keeps a **response cache** on disk (`cache.sqlite`). During a **live** trace, recent DNS responses can be reused within their record TTL so repeated queries to the same names are faster. The cache does not change stored sessions; clearing it does not delete sessions, and vice versa.

`delve cache stats` reports entry count, size, and cumulative hit/miss counts (persisted across runs). `delve cache purge` removes expired entries; `delve cache purge --all` clears the entire cache.

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

Installed packages also ship `man delve` (CLI synopsis) and this guide at `/usr/share/doc/cdt/docs/delve.md`.

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
| `delve session purge <id>` | Remove one unpinned session regardless of retention age |
| `delve session purge --all` | Remove all unpinned sessions |
| `delve session purge --dry-run` | Report what would be removed |
| `delve session explore [id]` | Interactive tree explorer (TUI); omit id for the default session |
| `delve session outline [id]` | Indented resolution tree on stdout; omit id for the default session |
| `delve session events [id]` | Structured JSON explore tree on stdout; omit id for the default session |
| `delve cache stats` | Response cache statistics |
| `delve cache purge` | Remove expired cache entries |
| `delve cache purge --all` | Clear the entire response cache |

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

```bash
delve trace example.com +events > trace.ndjson
```

## Configuration

delve reads an optional YAML config file:

**Linux (XDG):** `$XDG_CONFIG_HOME/cdt/delve.yaml`

Typical path: `~/.config/cdt/delve.yaml`

If the file is missing, defaults apply. If the file exists but is invalid, delve prints a warning and falls back to defaults.

### Example

```yaml
session:
  retention: 180d   # optional; default unlimited (omit or use never / unlimited / 0)
trace:
  max_parallel_queries: 8
explore:
  rtt_bar:
    green_ms: 50
    yellow_ms: 150
    orange_ms: 500
    insane_ms: 2000
    max_width: 20
```

### `explore.rtt_bar`

Colors and fixed width for the **Compare** screen latency bars (`█` characters). The bar
column is always `max_width` characters wide (default **20**). The longest RTT among
visible hops fills the full width; other hops scale proportionally. Remaining space is
blank. Each filled character is colored by the RTT it represents on that scale.

On terminals that report **256-color** or **truecolor** support (or common modern
emulators such as Kitty, WezTerm, iTerm, Windows Terminal), bars use a smooth gradient
between **step** colors. Each segment transitions only toward the next milestone:

| Range | Gradient |
|-------|----------|
| `0` → `green_ms` | green → yellow (fully yellow at `green_ms`) |
| `green_ms` → `yellow_ms` | solid yellow |
| `yellow_ms` → `orange_ms` | yellow → orange (fully orange at `orange_ms`) |
| `orange_ms` → `insane_ms` | orange → red (fully red at `insane_ms`) |

Hops that do not reach a later milestone still show a partial transition toward it.
Basic 8/16-color terminals keep stepped bands instead.

| Threshold | Bar color |
|-----------|-----------|
| `green_ms` | Green — typical fast query |
| `yellow_ms` | Yellow — a little slow |
| `orange_ms` | Orange — unusually slow |
| above `orange_ms` | Red |

`insane_ms` keeps color thresholds strictly ordered when config is normalized; it does
not cap bar length.

Override detection with `DELVE_TRUECOLOR=1` (force gradient) or `DELVE_BASIC_COLORS=1`
(force stepped bands).

Defaults: `green_ms` **50**, `yellow_ms` **150**, `orange_ms` **500**, `insane_ms`
**2000**, `max_width` **20** characters.

### Compare analytics (`session explore`)

On the **Compare** screen, delve derives timing from stored hop data (no network I/O for stats):

| Key | Action |
|-----|--------|
| `F` | Toggle fork-scoped full-path stats (fastest / slowest / average through the nearest fork to selection) |
| `B` | Toggle fork sibling hop RTT breakdown at that fork |
| `f` / `s` | Highlight fastest / slowest **answered** root-to-leaf path in the tree (overlay only; does not move selection) |
| `Esc` | Clear path highlight |
| `?` | Screen-scoped help (footer shows `Press ? for help`) |

Press **`r`** on **Browse** or **Compare** to re-query every hop with cache bypass. RTTs update **in memory** only; delve prompts to save on quit.

Whole-tree fastest, slowest, and average are always shown in the summary strip at the top. Stats include **answered** leaf paths only (failed or referral-only terminals are excluded). When the trace was budget-truncated, the strip notes that path statistics may be incomplete.

### `trace.max_parallel_queries`

Maximum number of DNS queries that `delve trace` may run concurrently when expanding a zone cut across multiple nameservers (`+expand=last` or `+expand=all`). Independent queries at the same cut share this worker pool; progress events are still emitted in stable path order. Set to `1` for fully serial execution (useful for deterministic tests). Default: **8**.

### `session.retention`

Controls how long **unpinned** stored sessions are kept before automatic purge.
Default when unset: **unlimited** (no automatic purge by age).

| Value | Meaning |
|-------|---------|
| `180d` | Calendar days |
| `6mo` | Calendar months (same day-of-month, N months earlier; end-of-month clamped) |
| `0`, `never`, or `unlimited` | Sessions are never removed by retention |

When sessions are removed, stderr shows a notice only if the count is greater than zero, for example:

```text
purged 3 sessions older than 180d
```

Manual removal: `delve session rm <id>`, `delve session purge`, `delve session purge <id>`, or `delve session purge --all` (unpinned only for purge; pinned sessions are kept unless you use `rm`).

## Session explore, outline, and events

`delve session explore <id>` opens a stored trace in the **interactive tree TUI** (no network I/O). Omit `<id>` to reopen the **default session**.

`delve session outline <id>` prints the same tree as a **one-shot indented outline** on stdout — suitable for logs, pipes, and narrow terminals. The first line is `session: <id>`.

`delve session events <id>` prints the explore tree as **structured JSON** on stdout (`event: explore_tree`, including `session` and hierarchical `tree` nodes).

### `show --json` vs `events`

These are different JSON shapes for different jobs:

| Command | JSON shape | Best for |
|---------|------------|----------|
| **`session show --json`** | Flat `TraceResult`: chronological `hops` array + `final_response` | Replaying trace data, diffing sessions, tools that expect the stored snapshot |
| **`session events`** | Hierarchical explore `tree`: delegation / resolve / hop / final nodes | Tools that want the same structure as the TUI and outline views |

Both include per-query **`rtt_ms`** and **`from_cache`** in hop JSON. The explore tree omits a separate final node when the last hop already records the authoritative answer (same exchange as `final_response`).

Use **`--json`** for JSON output from `session show` (not `+events`; that flag is for `delve trace` only).

```bash
delve session explore              # default session, TUI
delve session explore 01J...       # explicit id, TUI
delve session outline 01J...       # print tree once and exit
delve session events 01J...        # JSON tree on stdout
delve session show --json          # flat JSON for the default session
```

| Command | Output |
|---------|--------|
| **`session explore`** | TUI with Browse (tree + detail) and Compare (full tree, aligned columns, RTT bars, path-timing analytics); `Tab` cycles screens; `?` help |
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

On non-Linux platforms, the `directories` crate selects the equivalent config, cache, and data locations.

## Output shapes

With `+events`, NDJSON lines include `hop`, `message`, and `complete` events. The `complete` event carries the full `TraceResult`.

Stored sessions use a versioned JSON document (`version: 1`) containing the same `TraceResult` shape plus metadata (`id`, `created_at`, `pinned`, and the `TraceRequest` used for matching).

## See also

- [cdt](cdt.md) — bundle version and utility list
- `man delve` and `man cdt` — CLI synopsis on installed packages
