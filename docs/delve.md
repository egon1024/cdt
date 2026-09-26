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
| [Concepts](delve/concepts.md) | Traces, resolution trees, sessions, freeze, expansion, branching, cache |
| [Command reference](delve/reference.md) | Commands, trace options, query types, export/import |
| [Configuration](delve/configuration.md) | `delve.yaml`, retention, parallelism, RTT bars |
| [Session explore](delve/explore.md) | TUI, outline, JSON exports, Compare analytics |
| [Session diagram](delve/diagram.md) | SVG/PNG trace diagrams (`session diagram`) |
| [Storage and output](delve/storage.md) | File paths, session document shapes, NDJSON |
| [Release notes](release-notes/delve.md) | Operator-facing New / Changed / Removed / Fixed |

## At a glance

- **Trace** — live delegation walk from root hints (or `@server`) to an answer; progress on stderr, optional NDJSON on stdout. Address family defaults to **auto** (IPv6 reachability probe, then v4-only or dual-stack).
- **Session (v2)** — saved snapshot of one or more trace trees with `created_at`, **`updated_at`** (bumped by branch/pin/thaw mutations, not by freeze or read-only inspect), optional **view state**, optional **`frozen`**, and reuse metadata. See [storage](delve/storage.md).
- **Freeze** — `delve session freeze <id>` seals an investigation so branch and explore persist cannot change stored content; `thaw` reopens it. List marks frozen rows with `^`. See [concepts — freeze](delve/concepts.md#freeze).
- **Portable bundles** — `delve session export` writes a JSON envelope of full session documents; `delve session import` reads that envelope from a file or stdin. Diagrams use **`session diagram`**, not export. See [reference — session bundles](delve/reference.md#session-bundles).
- **Expansion** — `+expand=last|all|none` controls how many nameservers are queried at each zone cut during a live trace. Default **`last`** expands only the terminal cut. See [concepts — expansion](delve/concepts.md#expansion-at-trace-time).
- **Branching** — `delve session branch --at-hop=N|--at-path=P [--expand|--server @ADDR] [--dry-run]` or **`b`** in explore adds sibling paths from a delegation hop without re-tracing from the root. Refused on frozen sessions before any DNS.
- **Explore** — Browse and Compare screens; `Tab` / `1` / `2` switch views. Compare analytics and fork tables also via `session outline|events --compare-at-hop|--compare-at-path`. See [explore](delve/explore.md).
- **Default session** — omit `[id]` on session commands, or set **`DELVE_SESSION`** to pin a session in your shell. See [concepts — default session](delve/concepts.md#default-session).
- **Alias queries** — `-t CNAME +follow` stops at the CNAME owner; other types follow aliases only when `+follow` is set. See [concepts](delve/concepts.md).
- **Config** — `session.retention`, `trace.max_parallel_queries`, `trace.max_queries_per_action`, `explore.persist_view_state`, `explore.rtt_bar.*`, `enrichment.icmp.*`, `capture.public_ip.*`. Run `delve config dump`. See [configuration](delve/configuration.md).
- **ICMP enrichment** — off by default; enable in config or use `delve session explore … +icmp` for one-shot backfill via **`r`** refresh.
- **Cache** — TTL-aware DNS response cache (`delve cache stats|purge`) and separate enrichment ICMP cache (`delve cache enrichment …`); independent from stored sessions.

## Integration workflow

Typical multipath investigation:

```bash
delve trace example.com +expand=last +save
export DELVE_SESSION=$(delve session current)
delve session branch --at-hop=0 --expand --dry-run
delve session explore          # Browse → Compare (Tab), branch (b), quit
delve session outline --compare-at-hop=0
delve session events --compare-at-hop=0
```

Share a finished investigation (or back it up) without copying the session database:

```bash
delve session freeze "$DELVE_SESSION"          # optional: seal before handoff
delve session export "$DELVE_SESSION" -o share.json
# on another machine or clean store:
delve session import share.json                # or: delve session import < share.json
delve session explore "$DELVE_SESSION"
```

Import may print an informational **replay notice** when a session is branched or
multi-tree: those sessions are valid for explore and other session commands, but
will not be reused for automatic trace replay. That notice is not an error.

Verify docs against the CLI:

```bash
delve --help
delve trace --help
delve session diagram --help
delve session export --help
delve session import --help
delve session freeze --help
delve session thaw --help
delve session branch --help
```

## See also

- [cdt](cdt.md) — bundle version and utility list
- [Release notes](release-notes/delve.md) — what changed for operators
- `man delve` and `man cdt` — CLI synopsis on installed packages
