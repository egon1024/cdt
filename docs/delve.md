# delve

`delve` traces the DNS delegation path for a query name — similar in spirit to
`dig +trace`, but built for operators who need structured per-hop metadata (NSID,
EDE, RTT), persisted trace snapshots, multipath expansion, and machine-readable
output.

Use delve when you want to see **how** a name resolves hop by hop, keep that
investigation as a **session** you can reopen without new queries, and **branch**
into alternate nameserver paths when the first trace only explored one route.

## Quick start

```bash
delve trace example.com
delve trace example.com +events          # NDJSON on stdout
delve trace example.com +tcp -4 +timeout=3 -t NS @1.1.1.1
delve session explore                    # TUI for the last session
```

After a trace with saving enabled (the default), stderr includes:

```text
session: 01JXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Installed packages also ship `man delve` (CLI synopsis) and this guide at
`/usr/share/doc/cdt/docs/delve.md`.

## Documentation

| Guide | Contents |
|-------|----------|
| [Concepts](delve/concepts.md) | Traces, resolution trees, sessions, expansion, branching, cache |
| [Command reference](delve/reference.md) | Commands, trace options, query types |
| [Configuration](delve/configuration.md) | `delve.yaml`, retention, parallelism, RTT bars |
| [Session explore](delve/explore.md) | TUI, outline, JSON exports, Compare analytics |
| [Storage and output](delve/storage.md) | File paths, session document shapes, NDJSON |

## At a glance

- **Trace** — live delegation walk from root hints (or `@server`) to an answer;
  progress on stderr, optional NDJSON on stdout.
- **Session** — saved snapshot of one or more trace trees; inspect offline, reuse
  when parameters match, or extend with branching.
- **Expansion** — `+expand=last|all|none` controls how many nameservers are
  queried at each zone cut during a live trace.
- **Branching** — `delve session branch` or **`b`** in explore adds sibling paths
  from a delegation hop without re-tracing from the root.
- **Cache** — TTL-aware response cache speeds live queries; independent from
  stored sessions.

## See also

- [cdt](cdt.md) — bundle version and utility list
- `man delve` and `man cdt` — CLI synopsis on installed packages
