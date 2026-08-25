# CDT / delve roadmap

High-level delivery phases for the `delve` delegation tracer. User guides live in
[`delve.md`](delve.md); detailed Phase 3 design is in
[`specs/session-explore-design.md`](specs/session-explore-design.md).

## Phase 1 — Core trace ✅

**Status:** Complete

- `delve trace` with dig-style query options
- Iterative delegation following (`dns-resolve`)
- Per-hop metadata: zone, server, RTT, rcode, NSID, EDE, referral NS, glue
- Human progress on stderr; `+events` NDJSON on stdout
- Shared DNS primitives (`dns-core`)

## Phase 2 — Sessions & response cache ✅

**Status:** Complete (2026-08-25)

- TTL-aware global response cache (`dns-cache`, SQLite)
- Session persistence (SQLite primary, NDJSON fallback)
- `delve session list|show|rm|pin|unpin|purge`
- `delve cache stats|purge`
- Trace flags: `+cache` / `+nocache`, `+nocache=QNAME`, `+save` / `+nosave`
- Session retention config (`delve.yaml`, default `180d`), pinning, purge on store open
- Per-utility documentation (`docs/delve.md`, `docs/cdt.md`)
- Hardening: session show parity with live trace, persistent cache hit/miss counters,
  cyclic nameserver resolution detection, glue-first / alternate-NS fallback

Delivered on branch `delve_initial_dev` (PR #11).

## Phase 3 — Session explore 🚧

**Status:** Next

Interactive exploration of stored trace sessions without network I/O.

- **`delve session explore <id>`** — TUI client (default on a terminal)
- **Static outline mode** — single, visually useful tree render for logs, CI, or
  piping (`+outline`, or automatic when stdout is not a tty)
- Optional structured tree export (`+events` / NDJSON tree) for tooling

See [session explore design](specs/session-explore-design.md).

## Later (not scheduled)

- Multi-path / parallel delegation expansion during live trace
- Anomaly hints (unexpected TTL, lame delegation, etc.)
- MCP or other agent integrations
- Documentation site generation
