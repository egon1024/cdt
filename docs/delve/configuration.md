# delve — configuration

delve reads an optional YAML config file:

**Linux (XDG):** `$XDG_CONFIG_HOME/cdt/delve.yaml`

Typical path: `~/.config/cdt/delve.yaml`

If the file is missing, defaults apply. If the file exists but is invalid, delve
prints a warning and falls back to defaults.

To see every configurable key with defaults and your active overrides:

```bash
delve config dump
```

The output begins with the resolved config file path (whether or not the file
exists), then the YAML template. Commented lines show default values (not set in
your config). Uncomment a line to override that default. Sections with no overrides
are commented out entirely, including nested blocks such as `rtt_bar`.

## Example

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

## `session.retention`

Controls how long **unpinned** stored sessions are kept before automatic purge.
Default when unset: **unlimited** (no automatic purge by age).

| Value | Meaning |
|-------|---------|
| `180d` | Calendar days |
| `6mo` | Calendar months (same day-of-month, N months earlier; end-of-month clamped) |
| `0`, `never`, or `unlimited` | Sessions are never removed by retention |

Retention purge runs when the session store is opened (any command that touches
sessions). Pinned sessions are skipped. When sessions are removed, stderr shows a
notice only if the count is greater than zero, for example:

```text
purged 3 sessions older than 180d
```

Manual removal: `delve session rm <id>`, `delve session purge`,
`delve session purge <id>`, or `delve session purge --all` (unpinned only for
purge; pinned sessions are kept unless you use `rm`).

## `trace.max_parallel_queries`

Maximum number of DNS queries that `delve trace` (and parallel branch jobs) may run
concurrently when expanding a zone cut across multiple nameservers (`+expand=last`
or `+expand=all`). Independent queries at the same cut share this worker pool;
progress events are still emitted in stable path order. Set to `1` for fully serial
execution (useful for deterministic tests). Default: **8**.

## `explore.rtt_bar`

Colors and fixed width for the **Compare** screen latency bars (`█` characters).
See [explore](explore.md#compare-screen) for how bars appear in the TUI.

The bar column is always `max_width` characters wide (default **20**). The longest
RTT among visible hops fills the full width; other hops scale proportionally.
Remaining space is blank. Each filled character is colored by the RTT it represents
on that scale.

On terminals that report **256-color** or **truecolor** support (or common modern
emulators such as Kitty, WezTerm, iTerm, Windows Terminal), bars use a smooth
gradient between **step** colors. Each segment transitions only toward the next
milestone:

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

`insane_ms` keeps color thresholds strictly ordered when config is normalized; it
does not cap bar length.

Override detection with `DELVE_TRUECOLOR=1` (force gradient) or
`DELVE_BASIC_COLORS=1` (force stepped bands).

Defaults: `green_ms` **50**, `yellow_ms` **150**, `orange_ms` **500**,
`insane_ms` **2000**, `max_width` **20** characters.

## See also

- [delve](../delve.md) — hub and quick start
- [Session explore](explore.md) — Compare screen and RTT bars in the TUI
- [Concepts](concepts.md) — retention and session lifecycle
