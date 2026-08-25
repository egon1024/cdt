# delve Design Spec

**Date:** 2026-08-25  
**Status:** Draft — pending review  
**Repo:** `cdt` (Cole's DNS Tools)  
**Binary:** `delve`

## Summary

`delve` is a DNS delegation-path tracer — `dig +trace` on steroids. It walks the delegation chain from root to a target name, optionally following multiple paths, enriching results with timing, ASN, geolocation, and EDNS metadata. It is designed for DNS operations debugging and research/education.

The tool is **structured-data-first**: every operation produces or mutates a session artifact backed by a global cache. A CLI provides batch tracing and interactive exploration; a basic MCP server in v1 exposes trace initiation and session retrieval for agent integration.

## Goals

### Primary use cases

1. **DNS operations debugging** — identify lame delegations, parent/child NS mismatches, slow or unreachable nameservers, EDE signals.
2. **Research / education** — understand delegation structure, explore resolution paths, compare behavior across nameservers.

### Non-goals (v1)

- Replacing a full recursive resolver
- Web UI (future; architecture supports it)
- Full dnsviz feature parity for DNSSEC visualization
- Rich MCP exploration API (deferred to later releases)

## Architecture

Layered workspace crates with thin interface layers:

```
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ delve (CLI)  │  │ delve-mcp    │  │ Web API      │
│              │  │ (v1 basic)   │  │ (future)     │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       └─────────────────┼─────────────────┘
                         ▼
              dns-session (graph, issues, events)
                         │
         ┌───────────────┼───────────────┐
         ▼               ▼               ▼
   dns-resolve     dns-cache       dns-enrich
   (iterative      (pluggable       (ASN, geo,
    resolver)       storage)         ICMP)
         │               │
         ▼               ▼
      dns-core      dns-dnssec (optional)
```

### Crates

| Crate | Responsibility |
|-------|----------------|
| `dns-core` | Wire format, message parsing, EDNS/EDE, shared types and errors |
| `dns-resolve` | Iterative resolver, glue/NS resolution, multi-path engine, qname minimization |
| `dns-cache` | `CacheStore` trait, index layer, flatfile and SQLite backends |
| `dns-session` | Graph model, anomaly detection, event log, session persistence |
| `dns-enrich` | ASN, geo, ICMP — lazy, on-demand |
| `dns-dnssec` | Optional DNSSEC validation (dnsviz-style checks) |
| `delve` | CLI binary (`trace`, `session`, `cache` subcommands) |
| `delve-mcp` | MCP server (v1: basic trace + get session) |

## Data Model

### Session

The session is the central artifact. CLI, MCP, and future web API all produce or consume it.

```
Session
├── id: UUID
├── created_at: timestamp
├── query: { qname, qtype, qclass }
├── config: { expand_mode, transport, timeouts, qname_min, ... }
├── graph: Graph
├── events: Event[]          # NDJSON-compatible event log
├── issues: Issue[]          # detected anomalies
└── cache_refs: CacheKey[]   # references into global cache (no response duplication)
```

Sessions are stored at `~/.cache/delve/sessions/<uuid>.json` (configurable via `--session-dir` or config file).

### Graph

```
Graph
├── nodes: Zone | Nameserver | Address
└── edges: delegates_to | resolves_to | queried_at
```

**Zone** — e.g. `com.`, `example.com.`  
Holds referral data, authoritative answers, DS/DNSKEY when collected.

**Nameserver** — hostname from an NS record  
Holds resolution provenance (glue, lookup, sub-trace).

**Address** — IP address  
Holds timing, ASN, geo (populated lazily via enrichment).

**Edge** (`queried_at`) — records the DNS query that created the relationship:
- server, qname, qtype, transport
- rtt_ms, rcode, flags
- full EDNS metadata (including EDE, NSID)
- cache_key reference

### Default trace shape

By default the trace produces a **spine** (single path from root to target zone). At the **last hop** (the delegation introducing the target zone's authoritative nameservers), the engine fans out to all NS in that set.

```
. (root)           → single path
└─ com (TLD)       → single path
   └─ example.com  → FAN OUT to all authoritative NS
```

Expansion modes (override via `+expand=`):

| Mode | Behavior |
|------|----------|
| `last-hop` (default) | Fan out only at final delegation |
| `all` | Fan out at every delegation level |
| `<zone>` | Fan out starting at named zone cut (e.g. `+expand=com`) |

### NS resolution and glue

At each delegation step:

1. Parse referral: NS records + glue (A/AAAA in additional section).
2. For each NS hostname:
   - **In-bailiwick + glue present** → use glue IPs (`resolved_via: glue`).
   - **In-bailiwick + no glue** → resolve via parent zone authoritative data.
   - **Out-of-bailiwick** → resolve via iterative lookup from root.
3. Record provenance and all resolved addresses.
4. Query selected address; record timing and full response metadata.

**Follow sub-trace** (explore REPL): `follow ns1.example.net` runs a linked sub-trace for that hostname, walking delegation from root to the zone containing it, then resolving A/AAAA. The result links back to the parent graph node via `resolved_via_trace: <sub-session-id>`.

### Anomaly detection

Issues are first-class, typed, and attached to relevant graph nodes/edges:

| Issue | Detection |
|-------|-----------|
| `lame_delegation` | NS doesn't respond, doesn't resolve, returns REFUSED/SERVFAIL, or answers non-authoritatively |
| `ns_mismatch` | Parent referral NS set ≠ child zone authoritative NS set |
| `missing_glue` | In-bailiwick NS with no glue and failed/alternate resolution |
| `inconsistent_glue` | Glue A/AAAA disagrees with authoritative data for NS name |
| `orphan_delegation` | Parent delegates to NS not listed by child zone |
| `ede` | Extended DNS Error in OPT pseudo-RR (code, RFC meaning, extra text) |

Parent/child NS comparison runs automatically at the last hop and on expansion.

### EDNS representation

Every DNS response stores structured EDNS metadata:

```json
{
  "edns": {
    "version": 0,
    "udp_payload_size": 1232,
    "flags": { "do": true },
    "options": [
      { "code": 3, "name": "NSID", "data": "a.root-servers.net" },
      { "code": 17, "name": "EDE", "info": { "code": 22, "meaning": "No Reachable Authority", "extra_text": "..." } }
    ]
  }
}
```

- **NSID (OPT 3):** requested by default; decorates results where returned.
- **EDE (OPT 17):** first-class parsing with code, meaning, extra text.
- Other OPT codes: IANA code, known name when recognized, raw payload preserved.

## Global Cache

### Design principles

- **Global, not per-session.** Sessions reference cache entries; they do not duplicate response data.
- **Default: keep forever.** TTL from response is stored but not honored unless `+respect-ttl` is set.
- **Transport included in cache key.** UDP and TCP responses are distinct entries.
- **Pluggable storage backends** behind a `CacheStore` trait.

### Cache key

```
CacheKey {
  server: IpAddr | String,   // queried server
  port: u16,                 // default 53
  qname: String,
  qtype: u16,
  qclass: u16,
  transport: Udp | Tcp,
}
```

### Cache entry

```
CacheEntry {
  fetched_at: DateTime,
  ttl: u32,                  // from response (informational by default)
  response: Vec<u8>,         // wire-format DNS message
  metadata: ParsedMetadata,  // rcode, flags, edns, etc.
  session_id: Option<Uuid>,  // trace that first populated this entry
}
```

### Storage backends

All backends implement `CacheStore`. Future backends (Redis, etc.) plug in without changing trace/explore logic.

**Flatfile + index (v1 default):** response blobs as self-contained JSON files in a nested hash directory; queryable metadata in a companion SQLite index.

```
~/.cache/delve/cache/ab/cd/abcd1234....json   # blob
~/.cache/delve/cache/index.sqlite              # index
```

Supports rich `delve cache` queries without scanning every blob. Blobs remain human-inspectable.

**SQLite (optional):** unified blob + index storage in a single file; enable via config.

### Cache index dimensions

The index supports discovery and cleanup by:

- qname / zone tree (hierarchical matching)
- server (nameserver IP or hostname)
- fetched_at / age
- ttl / expired status
- session_id
- qtype
- enrichment: ASN, geo (post-enrichment)

### TTL behavior

| Mode | Flag | Behavior |
|------|------|----------|
| Keep forever (default) | — | Entries never expire; age shown in exploration |
| Honor TTL | `+respect-ttl` | Expired entries treated as stale; re-query on next use |
| Hard expiry | `+max-cache-age=DURATION` | Entries older than duration are stale regardless of TTL |
| Bypass reads | `+no-cache` | Always query fresh; still write to cache by default |

### `delve cache` subcommands

```
delve cache stats
delve cache list [--zone ZONE] [--server ADDR] [--asn ASN]
                 [--older-than DURATION] [--ttl-expired]
                 [--session ID] [--qtype TYPE]
delve cache tree ZONE              # entries grouped by delegation level
delve cache session ID             # all entries from a trace
delve cache show KEY
delve cache rm KEY | --zone ZONE | --server ADDR | --asn ASN
delve cache prune --older-than DURATION
delve cache prune --ttl-expired
delve cache prune --session ID
```

Exploration shows cache provenance:

```
A  192.0.2.1  [cached 2h ago, TTL=3600, NOT revalidated]
→ requery                        # force fresh lookup
```

### Configuration

```toml
# ~/.config/delve/config.toml
[cache]
backend = "flatfile"   # or "sqlite"
path = "~/.cache/delve"
respect_ttl = false
```

## Trace Engine

### Iterative resolution flow

1. Query current authority for target qname / qtype.
2. Parse response: answers, authority, additional.
3. Extract NS records and glue; resolve NS hostnames.
4. Record full response metadata (rcode, flags, TTLs, EDNS, NSID, EDE).
5. Run anomaly checks (lame, NS mismatch, glue issues).
6. Select next authority(ies) per expand mode.
7. Repeat until target zone reached; fan out at last hop.
8. Issue final query for requested qtype (default: A).

### QNAME minimization

Off by default (classic `dig +trace` behavior). When `+qname-min` is set, send only the minimal qname at each step (RFC 7816/8020 style):

```
www.example.com with +qname-min:
  . ← query "com"
  com. ← query "example.com"
  example.com. ← query "www.example.com"
```

Each query records whether minimization was used.

### dig-compatible flags

`delve trace` uses dig-style flags wherever sensible:

| delve | dig | Notes |
|-------|-----|-------|
| `@server` | `@server` | Start at this server instead of root |
| `-p port` | `-p port` | Port (default 53) |
| `-4` / `-6` | `-4` / `-6` | Address family |
| `-b addr` | `-b addr` | Source/bind address |
| `+tcp` | `+tcp` | TCP transport |
| `+time=N` | `+time=N` | Per-query timeout (seconds) |
| `+tries=N` | `+tries=N` | Retry count |
| `+bufsize=N` | `+bufsize=N` | EDNS UDP payload size |
| `+dnssec` | `+dnssec` | Set DO bit; collect DNSSEC RRsets |
| `+cd` | `+cd` | Checking disabled |
| `+norecurse` | `+norecurse` | RD=0 (always for trace; available for re-queries) |
| `+nonsid` | `+nsid` | NSID requested by default; `+nonsid` disables |
| `+subnet=…` | `+subnet=…` | Client subnet (ECS) |

delve-specific flags:

| Flag | Purpose |
|------|---------|
| `+expand=MODE` | Multi-path fan-out: `last-hop` (default), `all`, or zone name |
| `+qname-min` | QNAME minimization |
| `+events` | Emit NDJSON event stream |
| `+respect-ttl` | Honor TTL on cache lookup |
| `+max-cache-age=DURATION` | Hard cache expiry |
| `+no-cache` | Bypass cache reads |

Default qtype is **A** (most common). `--qtype NS` available for explicit authoritative NS discovery.

Example:

```bash
delve trace www.example.com +dnssec +time=3 +tcp -4
```

## CLI

### Subcommands

```
delve trace <qname> [flags]       # Phase 1: initial scan with progress
delve session list|show|rm ...    # Session management
delve session <id> explore        # Phase 2: interactive exploration
delve cache ...                   # Global cache management
```

### Phase 1: trace with progress (Option C)

**Stderr (default TTY):** human-readable step summary.

```
[.] querying root for com. ... 41ms  NSID: "a.root-servers.net"
[com.] referral → 13 NS, following a.gtld-servers.net (192.5.6.30)
[com.] querying for example.com. ... 38ms
[example.com.] expanding all 4 authoritative NS ...
  ⚠ ns_mismatch: parent lists old.ns.example., child does not
  ✗ lame: ns3.example.com (SERVFAIL, EDE 22)
```

**`+events`:** parallel NDJSON stream on stdout (or `--events-file`).

```jsonl
{"event":"delegation","zone":"com.","from":".","ns_count":13,"following":1}
{"event":"ns_resolve","name":"a.gtld-servers.net","via":"glue","addrs":["192.5.6.30"]}
{"event":"query","server":"192.5.6.30","qname":"example.com","qtype":"NS","rtt_ms":41}
{"event":"issue","kind":"ns_mismatch","zone":"example.com.","only_in_parent":["old.ns.example."]}
{"event":"ede","server":"192.0.2.1","code":22,"extra":"No Reachable Authority"}
```

**Session artifact:** written to `~/.cache/delve/sessions/<uuid>.json` on completion.

### Phase 2: explore REPL

```
delve session <id> explore
```

| Command | Action |
|---------|--------|
| `show [zone\|ns\|all]` | Display graph node(s) |
| `expand <zone>` | Fan out all NS at a delegation level |
| `follow <hostname>` | Linked sub-trace for NS hostname resolution |
| `timing <ns\|addr>` | DNS + ICMP RTT details |
| `enrich <ns\|addr>` | Fetch ASN, geo (lazy) |
| `dnssec <zone>` | Validate chain of trust |
| `issues` | List all detected anomalies |
| `compare parent\|child ns` | Side-by-side NS sets for zone cut |
| `requery <target>` | Force fresh DNS lookup (bypass cache) |
| `export json\|jsonl` | Dump current session state |
| `quit` | Exit (session persisted) |

Non-interactive equivalents for scripting:

```bash
delve session <id> expand example.com.
delve session <id> follow ns1.example.net --output json
delve session <id> issues --format json
```

## Enrichment

Lazy, on-demand, separate from core trace. Results cached in the global store under enrichment key prefixes.

| Enricher | v1 source | Notes |
|----------|-----------|-------|
| ASN | Team Cymru DNS (`origin.asn.cymru.com`) | No API key required |
| Geo | MaxMind GeoLite2 (optional DB path) | Graceful skip if no DB configured |
| ICMP | Raw ping | Optional; `+noping` to skip; may require `cap_net_raw` on Linux |

Enrichment is triggered in explore (`enrich <target>`) or via `+enrich` on `show`. Results display cache age.

## DNSSEC Add-on

Optional `dns-dnssec` crate. Enabled with `+dnssec` during trace or `dnssec <zone>` in explore.

### Collection (`+dnssec`)

- DO bit set on all queries
- Gather DS, DNSKEY, RRSIG alongside answers

### Validation (explore)

| Check | Issue type |
|-------|------------|
| Chain of trust root → zone | `dnssec_bogus`, `dnssec_insecure` |
| DS ↔ DNSKEY match | `dnssec_ds_mismatch` |
| RRSIG validity (expiry, algorithm) | `dnssec_expired`, `dnssec_bad_sig` |
| Consistent DNSSEC answers across NS | `dnssec_ns_inconsistent` |

Works with `+cd` for probing without validation stopping the trace.

## MCP Server (v1 — basic)

Crate: `delve-mcp`  
Transport: stdio (local IDE / Cursor integration)  
Shares `~/.cache/delve/` cache and sessions with CLI.

### v1 tools

| Tool | Description |
|------|-------------|
| `delve_trace` | Start a trace for a qname. Returns session ID and summary (issues count, path length, timing). Accepts qname; additional options deferred to later releases. |
| `delve_session_get` | Retrieve session data by ID. Returns graph, issues, events, and cache references as JSON. Supports optional filters (e.g. issues only, specific zone). |

### v1 behavior

- `delve_trace` runs synchronously for v1 (returns when trace completes). Progress events are included in the returned session event log.
- `delve_session_get` returns the full session artifact or a filtered subset.
- MCP server reads the same config and cache as the CLI (`~/.config/delve/config.toml`).

### Deferred MCP tools (post-v1)

- `delve_session_expand`, `delve_session_follow`, `delve_session_dnssec`
- `delve_cache_search`, `delve_cache_prune`
- Streaming progress via MCP notifications
- Full flag passthrough on `delve_trace`

### Installation

```bash
cargo install delve --features mcp
# or: delve-mcp binary alongside delve CLI
```

## Error Handling

- **Timeouts / unreachable server:** record as issue on the edge; continue trace where possible.
- **Truncated UDP response:** optionally retry with TCP (configurable; dig-style `+ignore` / `+retry`).
- **Cache backend failure:** degrade gracefully — trace still works, cache writes may warn.
- **Enrichment unavailable:** skip silently; note in output that enrichment was not performed.
- **ICMP blocked:** omit ping data; do not fail trace.

## Testing Strategy

| Layer | Approach |
|-------|----------|
| `dns-core` | Unit tests with captured wire-format fixtures |
| `dns-resolve` | Integration tests against known zones; mock UDP server for controlled referrals |
| `dns-cache` | Round-trip tests per backend; index query correctness |
| `dns-session` | Graph construction, issue detection (lame, NS mismatch, EDE parsing) |
| `dns-dnssec` | Known-good and known-bogus zone fixtures |
| `delve` CLI | CLI integration tests (trace + session show) |
| `delve-mcp` | MCP tool invocation tests with fixture sessions |

## v1 Scope Summary

### In scope

- [ ] `dns-core`, `dns-resolve`, `dns-cache`, `dns-session` crates
- [ ] `delve trace` with dig-compatible flags, default qtype A
- [ ] Multi-path expansion (default: last hop)
- [ ] Glue/NS resolution with provenance
- [ ] NSID on by default; EDE and EDNS OPT storage
- [ ] Anomaly detection: lame delegation, NS mismatch, glue issues
- [ ] Global cache (flatfile + index backend)
- [ ] `delve cache` management commands
- [ ] Progress output: stderr summary + `+events` NDJSON
- [ ] `delve session explore` REPL (basic commands)
- [ ] Enrichment: ASN (Team Cymru), ICMP; geo if DB configured
- [ ] DNSSEC collection and basic validation in explore
- [ ] `delve-mcp` with `delve_trace` and `delve_session_get`

### Out of scope (v1)

- Web UI
- Rich MCP tool set
- Full dig flag parity
- Redis / remote cache backends
- Disk-persistent enrichment cache policies beyond global cache defaults

## Open Questions

None blocking v1 implementation. To revisit post-v1:

- GeoIP default source (MaxMind GeoLite2 vs IPinfo)
- TCP fallback policy on truncation
- MCP async trace with progress notifications
