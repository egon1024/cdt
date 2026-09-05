# delve

`delve` traces the DNS delegation path for a query name — similar in spirit to `dig +trace`, but built for operators who need structured per-hop metadata (NSID, EDE, RTT), persisted trace snapshots, multipath expansion, and machine-readable output.

Use delve when you want to see **how** a name resolves hop by hop, keep that investigation as a **session** you can reopen without new queries, and **branch** into alternate nameserver paths when the first trace only explored one route.

## Quick start

```bash
delve trace example.com
delve trace example.com +events          # NDJSON on stdout
delve trace example.com +tcp -4 +timeout=3 -t NS @1.1.1.1
delve trace example.com +family=both     # dual-stack (skip auto probe)
delve session explore                    # TUI for the last session
```

Each live trace prints the resolved address-family policy on stderr before the
first hop (for example `address family: dual-stack (ipv6 probe ok)`). The default
is **auto**: delve probes IPv6 reachability once per process and chooses v4-only
or dual-stack accordingly.

After a trace with saving enabled (the default), stderr also includes:

```text
session: 01JXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Installed packages also ship `man delve` (CLI synopsis) and this guide at `/usr/share/doc/cdt/docs/delve.md`.

## Documentation

| Guide | Contents |
|-------|----------|
| [Concepts](delve/concepts.md) | Traces, resolution trees, sessions, expansion, branching, cache |
| [Command reference](delve/reference.md) | Commands, trace options, query types |
| [Configuration](delve/configuration.md) | `delve.yaml`, retention, parallelism, RTT bars |
| [Session explore](delve/explore.md) | TUI, outline, JSON exports, Compare analytics |
| [Session export](delve/export.md) | SVG/PNG trace diagrams (`session export`) |
| [Storage and output](delve/storage.md) | File paths, session document shapes, NDJSON |

## At a glance

- **Trace** — live delegation walk from root hints (or `@server`) to an answer; progress on stderr, optional NDJSON on stdout. Address family defaults to **auto** (IPv6 reachability probe, then v4-only or dual-stack).
- **Session (v2)** — saved snapshot of one or more trace trees with `created_at`, **`updated_at`** (bumped by branch/pin mutations, not by read-only inspect), optional **view state**, and reuse metadata. See [storage](delve/storage.md).
- **Expansion** — `+expand=last|all|none` controls how many nameservers are queried at each zone cut during a live trace. Default **`last`** expands only the terminal cut. See [concepts — expansion](delve/concepts.md#expansion-at-trace-time).
- **Branching** — `delve session branch --at-hop=N|--at-path=P [--expand|--server @ADDR] [--dry-run]` or **`b`** in explore adds sibling paths from a delegation hop without re-tracing from the root.
- **Explore** — Browse and Compare screens; `Tab` / `1` / `2` switch views. Compare analytics and fork tables also via `session outline|events --compare-at-hop|--compare-at-path`. See [explore](delve/explore.md).
- **Default session** — omit `[id]` on session commands, or set **`DELVE_SESSION`** to pin a session in your shell. See [concepts — default session](delve/concepts.md#default-session).
- **Alias queries** — `-t CNAME +follow` stops at the CNAME owner; other types follow aliases only when `+follow` is set. See [concepts](delve/concepts.md).
- **Config** — `session.retention`, `trace.max_parallel_queries`, `trace.max_queries_per_action`, `explore.persist_view_state`, `explore.rtt_bar.*`. Run `delve config dump`. See [configuration](delve/configuration.md).
- **Cache** — TTL-aware response cache speeds live queries; independent from stored sessions.

## Integration workflow

Typical multipath investigation:

```bash
delve trace tuininga.org +expand=last +save
export DELVE_SESSION=$(delve session current)
delve session branch --at-hop=0 --expand --dry-run
delve session explore          # Browse → Compare (Tab), branch (b), quit
delve session outline --compare-at-hop=0
delve session events --compare-at-hop=0
```

Verify docs against the CLI:

```bash
delve --help
delve trace --help
delve session branch --help
```

## See also

- [cdt](cdt.md) — bundle version and utility list
- `man delve` and `man cdt` — CLI synopsis on installed packages
