# delve — concepts

How delve models DNS delegation tracing, stored sessions, and multipath investigation.

## What a trace is

A **trace** walks from a starting resolver (root hints by default, or an `@server` you choose) toward the authoritative nameservers for your query. At each hop, delve issues a DNS query, records the response (rcode, flags, sections, RTT, NSID when present), and follows delegation until it reaches an answer or a terminal error.

Human progress goes to **stderr**. With `+events`, structured NDJSON events go to **stdout** so you can pipe or store them separately.

## Resolution tree

A stored session holds one or more **trace trees**. Each tree is a nested structure of **nodes** — one DNS exchange per node, with child nodes for the next steps (delegation, referral resolution, alias legs, or branches).

Nodes are addressed by a **path** (for example `0.1.2`): the tree index followed by child indices from that tree's root. Paths are stable for the lifetime of a session because nodes are only appended, never reordered. Live trace progress, the explore TUI, `session outline`, and `session branch --at-path` all use the same path notation.

Nodes also have a **display index** — the number `session outline` prints in brackets (`[0]`, `[1]`, …), counting nodes top to bottom. That is what `--at-hop` and `--compare-at-hop` take. Live trace progress instead labels each line `query N at-path P`, where `N` counts queries in completion order: `N` is not a display index, so pass `at-path P` to address a node you saw during a trace, or read the index from `session outline`.

## Expansion at trace time

When a zone cut lists multiple nameservers, delve can query more than the first available server. The `+expand=` trace option controls that policy:

| Value | Behavior |
|-------|----------|
| `+expand=last` (default) | At each zone cut, query nameservers until one answers; at the **final** cut before the answer, query every listed server in parallel |
| `+expand=all` | Query every nameserver at **every** zone cut (can be very wide; interactive traces prompt for confirmation unless you add `+force`) |
| `+expand=none` | First-available only at every cut — same spirit as classic `dig +trace` |

Parallel queries share the worker pool sized by `trace.max_parallel_queries` in config (default **8**). Progress events are still emitted in stable path order.

```bash
delve trace example.com +expand=all+force   # non-interactive full expansion
```

## Sessions

A **session** is a saved snapshot of one or more completed trace trees. When `+save` is enabled (the default), delve writes the full result — every hop, response section, and timing — to local storage as a versioned JSON document keyed by a ULID.

Sessions exist so you can work with a trace **after** the live queries finish, without touching the network again:

- **Inspect** a trace with `delve session show`, `outline`, or `events`.
- **Explore** it interactively in the TUI with `delve session explore`.
- **Extend** it with `delve session branch` or the **`b`** key in explore.
- **Share or diff** stable JSON (`show --json`, `events`) for automation and review.
- **Replay** the same human or NDJSON output later via session reuse (see below).

Each `delve trace` that saves creates a **new** session id. Re-running a trace does not update an existing session; it either reuses a matching snapshot or saves a fresh one.

### Default session

The **default session** is resolved in order:

1. An explicit id on the command line
2. `DELVE_SESSION` when set (non-empty after trimming) and the session still exists
3. The most recently modified stored session (`updated_at`)

Commands that accept an optional `[id]` (`show`, `outline`, `events`, `explore`, `branch`) use the default when you omit the id. `delve session current` prints that resolved id; `delve session list` marks it with `@` in the first column (`*` means pinned).

`DELVE_SESSION` is an override for scripts and scoped shells — delve does not set it. If it points at a removed session, delve prints a warning to stderr and falls through to the most recently modified session.

Session ids accept a full ULID or a unique short prefix (like git).

### Session reuse

When `+save` is enabled, `delve trace` first looks for an existing stored session whose **trace parameters** match the current request: qname, qtype, `@server`, transport, timeout, tries, DNSSEC/NSID flags, address family, cache options, expansion policy, and related flags. If a match exists, delve **replays that stored snapshot** instead of issuing new DNS queries. The snapshot stays available until retention purge removes it — there is no time-based expiry for reuse.

Sessions that have been **branched** (extended after the initial trace) do not match for reuse — only unmodified single-tree snapshots qualify.

```text
session: 01JXXXXXXXXXXXXXXXXXXXXXXXXXX (reused snapshot from 2026-08-25T12:34:56Z)
```

Use `+fresh` to force a live trace and save a new session. `+nosave` disables both saving and reuse.

With `+events`, reuse replays stored hop events and emits a final `complete` event with `"reused": true`.

### Retention and pinning

Unpinned sessions are subject to **retention** only when you set `session.retention` in config (default **unlimited** — sessions are kept until you remove them). Purge runs when the session store is opened (any command that touches sessions). **Pinned** sessions are skipped by automatic retention and by `delve session purge` (but not by explicit `delve session rm <id>`).

Use `delve session pin <id>` to keep a session across retention. Use `delve session purge --all` to remove every unpinned session regardless of age. Use `delve session purge <id>` to remove one unpinned session regardless of age (pinned sessions are skipped).

## Branching

**Branching** extends an existing stored session by issuing new live queries from a delegation hop you choose, then appending the results as sibling subtrees. The original trace is preserved; new nodes are marked with a branch origin so you can see which paths came from investigation rather than the initial trace.

Use branching when the initial trace took one path (for example `+expand=last` or `+expand=none`) and you want to explore alternate nameservers at a zone cut without re-tracing from the root.

### CLI branching

```bash
delve session branch --at-path 0.2 --expand          # every unqueried NS at the cut
delve session branch --at-hop 5 --server @203.0.113.7
delve session branch --dry-run --at-path 0.2 --expand   # plan only
```

- **`--at-path`** — stable node path (same as in live progress, `session outline`, and explore)
- **`--at-hop`** — display index from `session outline` (alternative to path)
- **`--expand`** — query every nameserver at the zone cut that was not queried on the selected path
- **`--server`** — query one named nameserver or `@address` at the cut

Every report starts by naming the cut it resolved (`node: hop 1 (at-path 0.0) zone org. …`), so you can confirm `--at-hop` landed where you meant. Under `+expand=last` the final cut is already fully queried, so `--expand` there reports `nothing to query at this cut` with a warning saying every listed nameserver was queried; branch at a cut further up (often `--at-hop 0`, the root cut) to reach unqueried servers.

Branching updates the session in place (`updated_at` changes). The branched session becomes the default session for subsequent commands.

### Branching in explore

In the Browse screen, select a delegation hop with unqueried nameservers and press **`b`**. Choose **expand cut** (all remaining servers) or enter an alternate server address. Progress appears in the footer; new nodes appear as siblings under the selected hop.

## Response cache

Separate from sessions, delve keeps a **response cache** on disk (`cache.sqlite`). During a **live** trace or branch, recent DNS responses can be reused within their record TTL so repeated queries to the same names are faster. The cache does not change stored sessions; clearing it does not delete sessions, and vice versa.

`delve cache stats` reports entry count, size, and cumulative hit/miss counts (persisted across runs). `delve cache purge` removes expired entries; `delve cache purge --all` clears the entire cache.

Each `delve trace` with `+save` creates a **new** session. Re-running a trace may use the cache for fewer queries, but it does not update an existing session.

See [storage](storage.md) for file paths.

## See also

- [delve](../delve.md) — hub and quick start
- [Reference](reference.md) — commands and trace options
- [Session explore](explore.md) — TUI and JSON views
