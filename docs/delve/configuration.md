# delve — configuration

delve reads an optional YAML config file:

**Linux (XDG):** `$XDG_CONFIG_HOME/cdt/delve.yaml`

Typical path: `~/.config/cdt/delve.yaml`

If the file is missing, defaults apply. If the file exists but is invalid, delve prints a warning and falls back to defaults.

To see every configurable key with defaults and your active overrides:

```bash
delve config dump
```

The output begins with the resolved config file path (whether or not the file exists), then the YAML template. Commented lines show default values (not set in your config). Uncomment a line to override that default. Sections with no overrides are commented out entirely, including nested blocks such as `rtt_bar`.

## `session.retention`

Controls how long **unpinned** stored sessions are kept before automatic purge. Default when unset: **unlimited** (no automatic purge by age).

| Value | Meaning |
|-------|---------|
| `180d` | Calendar days |
| `6mo` | Calendar months (same day-of-month, N months earlier; end-of-month clamped) |
| `0`, `never`, or `unlimited` | Sessions are never removed by retention |

Retention purge runs when the session store is opened (any command that touches sessions). Pinned sessions are skipped. When sessions are removed, stderr shows a notice only if the count is greater than zero, for example:

```text
purged 3 sessions older than 180d
```

Manual removal: `delve session rm <id>`, `delve session purge`, `delve session purge <id>`, or `delve session purge --all` (unpinned only for purge; pinned sessions are kept unless you use `rm`).

**Example — purge unpinned sessions older than 180 days:**

```yaml
session:
  retention: 180d
```

**Example — keep all sessions until you remove them manually:**

```yaml
session:
  retention: never
```

## `trace`

Limits for live traces and branch jobs.

| Key | Default | Meaning |
|-----|---------|---------|
| `max_queries_per_action` | **64** | Maximum DNS queries per trace or branch action (budget cap) |
| `max_parallel_queries` | **8** | Concurrent DNS queries when expanding a zone cut (`+expand=last` or `+expand=all`) |

`max_parallel_queries` controls how many nameservers at the same cut can be queried at once. Progress events still arrive in stable path order. Set to `1` for fully serial execution (useful for deterministic tests).

**Example — lower parallelism for a slow or rate-limited resolver path:**

```yaml
trace:
  max_parallel_queries: 2
```

**Example — tighter query budget on large `+expand=all` traces:**

```yaml
trace:
  max_queries_per_action: 32
  max_parallel_queries: 4
```

## `explore`

TUI behavior for `delve session explore`.

| Key | Default | Meaning |
|-----|---------|---------|
| `persist_view_state` | **true** | Save expanded nodes, selection, and screen choice back into the session document |

When `persist_view_state` is true, reopening explore restores your place. View-state-only writes do not bump `updated_at`.

**Example — do not persist explore UI state across reopen:**

```yaml
explore:
  persist_view_state: false
```

### `explore.rtt_bar`

Colors and fixed width for the **Compare** screen latency bars (`█` characters). See [explore](explore.md#compare-screen) for how bars appear in the TUI.

The bar column is always `max_width` characters wide (default **20**). The longest RTT among visible hops fills the full width; other hops scale proportionally. Remaining space is blank. Each filled character is colored by the RTT it represents on that scale.

On terminals that report **256-color** or **truecolor** support (or common modern emulators such as Kitty, WezTerm, iTerm, Windows Terminal), bars use a smooth gradient between **step** colors. Each segment transitions only toward the next milestone:

| Range | Gradient |
|-------|----------|
| `0` → `green_ms` | solid green |
| `green_ms` → `yellow_ms` | green → yellow (fully yellow at `yellow_ms`) |
| `yellow_ms` → `orange_ms` | yellow → orange (fully orange at `orange_ms`) |
| `orange_ms` → `insane_ms` | orange → red (fully red at `insane_ms`) |

Hops that do not reach a later milestone still show a partial transition toward it. Basic 8/16-color terminals keep stepped bands instead.

| Threshold | Bar color |
|-----------|-----------|
| `green_ms` | Green — typical fast query |
| `yellow_ms` | Yellow — a little slow |
| `orange_ms` | Orange — unusually slow |
| above `orange_ms` | Red |

`insane_ms` keeps color thresholds strictly ordered when config is normalized; it does not cap bar length.

Override detection with `DELVE_TRUECOLOR=1` (force gradient) or `DELVE_BASIC_COLORS=1` (force stepped bands).

Defaults: `green_ms` **50**, `yellow_ms` **125**, `orange_ms` **250**, `insane_ms` **1000**, `max_width` **20** characters.

**Example — stricter green/yellow thresholds and a wider bar column:**

```yaml
explore:
  rtt_bar:
    green_ms: 30
    yellow_ms: 80
    orange_ms: 200
    insane_ms: 800
    max_width: 24
```

## `enrichment.icmp`

Hop ICMP snapshots (network RTT to resolver IPs) are **off by default**. When enabled, trace and branch may populate session `targets` with ICMP measurements; explore unified refresh (**`r`**) also probes when ICMP is effective.

| Key | Default | Meaning |
|-----|---------|---------|
| `enabled` | **false** | Master switch for ICMP enrichment |
| `on_trace` | **true** | Probe ICMP during live trace/branch when `enabled` is true |
| `timeout_ms` | **200** | Per-probe timeout |
| `ping_samples` | **3** | Samples for ping fallback |
| `max_parallel_probes` | **8** | Concurrent ICMP workers |

One-shot override without editing config: `delve session explore <id> +icmp` enables ICMP for that explore process (unified **`r`** refresh and compare live fallback). Stored ICMP from a prior save remains visible on reopen.

**Example — enable ICMP on trace and branch (default-on-trace behavior):**

```yaml
enrichment:
  icmp:
    enabled: true
```

**Example — enable ICMP globally but skip trace-time probing (explore `+icmp` or refresh only):**

```yaml
enrichment:
  icmp:
    enabled: true
    on_trace: false
```

**Example — slower probes with fewer parallel workers:**

```yaml
enrichment:
  icmp:
    enabled: true
    timeout_ms: 500
    ping_samples: 5
    max_parallel_probes: 2
```

## `enrichment.cache`

Separate SQLite database (`enrichment.sqlite`) caches recent ICMP probe results (default TTL **15 minutes**). Purging the DNS response cache does not clear enrichment cache rows. Administer with `delve cache enrichment stats` and `delve cache enrichment purge icmp`.

| Key | Default | Meaning |
|-----|---------|---------|
| `icmp_ttl_minutes` | **15** | ICMP cache entry lifetime |

Session `targets` on disk are independent; purging enrichment cache does not remove stored session ICMP.

**Example — shorter ICMP cache lifetime:**

```yaml
enrichment:
  cache:
    icmp_ttl_minutes: 5
```

## `capture.public_ip`

Optional session metadata recording a public egress address at trace time. **Off by default.**

| Key | Default | Meaning |
|-----|---------|---------|
| `enabled` | **false** | Store public IP in `capture_context` when tracing |
| `provider` | **static** | Discovery provider (`static` only in v1) |
| `static_address` | — | Required when `provider: static` and `enabled: true` |

**Privacy:** Non-static providers (future) may contact third-party services and reveal your egress IP to them. Use the `static` provider when you want metadata without network egress for discovery.

**Example — record a known egress address on every saved trace:**

```yaml
capture:
  public_ip:
    enabled: true
    provider: static
    static_address: 203.0.113.10
```

Verify after tracing:

```bash
delve trace example.com +save +fresh
delve session show --json | jq '.capture_context'
```

## Combined example

All sections in one file (typical lab or operator setup):

```yaml
session:
  retention: 180d

trace:
  max_queries_per_action: 64
  max_parallel_queries: 8

explore:
  persist_view_state: true
  rtt_bar:
    green_ms: 50
    yellow_ms: 125
    orange_ms: 250
    insane_ms: 1000
    max_width: 20

enrichment:
  icmp:
    enabled: false
    on_trace: true
    timeout_ms: 200
    ping_samples: 3
    max_parallel_probes: 8
  cache:
    icmp_ttl_minutes: 15

capture:
  public_ip:
    enabled: false
    provider: static
    static_address:
```

Only uncomment or set the keys you need; omitted keys keep their defaults.

## See also

- [delve](../delve.md) — hub and quick start
- [Session explore](explore.md) — Compare screen and RTT bars in the TUI
- [Concepts](concepts.md) — retention and session lifecycle
