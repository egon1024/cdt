# delve — session explore

Inspect stored traces without network I/O: interactive TUI, one-shot outline, and structured JSON.

## Commands

| Command | Output |
|---------|--------|
| **`session explore`** | TUI with Browse (tree + detail) and Compare (fork-scoped sibling path table, DNS/ICMP RTT); `Tab` cycles screens; `?` help |
| **`session outline`** | `session: <id>` header + indented tree on stdout; `--compare-at-hop` / `--compare-at-path` prints a path comparison |
| **`session events`** | Structured JSON explore tree on stdout; `--compare-at-hop` / `--compare-at-path` emits `path_comparison` JSON |
| **`session show --json`** | Flat JSON trace snapshot on stdout |

```bash
delve session explore              # default session, TUI
delve session explore 01J...       # explicit id, TUI
delve session outline 01J... --compare-at-hop=3
delve session events 01J... --compare-at-hop=3
delve session show --json          # flat JSON for the default session
```

Omit `[id]` on any of these to use the [default session](concepts.md#default-session).

New traces store full DNS response sections (header flags, question, answer, authority, additional) for each hop. The explore detail pane renders these in a **dig-style** layout. Older saved sessions without section data fall back to the compact YAML-style summary.

Explore requires a **real terminal** (80×24 minimum). For headless environments, use `session outline` or `session events`.

## Browse screen

Two-pane layout: resolution tree on one side, dig-style detail for the selected hop on the other. The Details pane meta block includes an RTT line with a latency bar and millisecond label (same colors as Compare / export); the bar uses a fixed 250 ms scale.

| Key | Action |
|-----|--------|
| `j` / `k` | Move selection |
| `Space` | Expand or collapse selected node |
| `E` | Expand all |
| `C` | Collapse all |
| `Tab` | Cycle screens (Browse ↔ Compare) |
| `w` | Cycle pane focus within Browse |
| `c` | Toggle color |
| `b` | Branch from selected node — see [concepts](concepts.md#branching-in-explore) |
| `r` | Re-query every hop with cache bypass (RTTs update in memory only; save on quit) |
| `?` | Screen-scoped help |
| `q` | Quit |

**View state** (expanded nodes, selection, active screen) persists in the session document. Reopening explore restores your place; view-state-only changes do not bump `updated_at`.

## Compare screen

Sibling-path table for the focused fork: one row per alternate server, with hop count, cumulative DNS RTT, delta vs the fastest successful sibling, a latency bar column (all rows, scaled to the slowest sibling), ICMP RTT (`n/a` when probing is unavailable), outcome, and referral-set differences. Siblings that returned the same referral set leave the referral column blank. Cache-served hops are marked so they are not read as network RTT.

Compare is scoped to a fork: each row is an alternate server at the same zone cut. Explore opens on the root, which usually has only one child, so pressing `Tab`, `2`, or `m` jumps to the nearest fork in the tree and opens Compare there. The header shows `[Compare n/a]` only when the trace has no fork at all (a single linear path). In that case Tab stays on Browse and shows `this trace has a single path, so there is nothing to compare`.

`session outline --compare-at-hop=N` and `session events --compare-at-hop=N` print the same metrics as text and JSON (no DNS queries).

Whole-tree fastest, slowest, and average RTTs appear in the summary strip at the top. Stats include **answered** leaf paths only (failed or referral-only terminals are excluded). When the trace was budget-truncated, the strip notes that path statistics may be incomplete.

### Compare analytics keys

Timing is derived from stored hop data (no network I/O for stats):

| Key | Action |
|-----|--------|
| `F` | Toggle fork-scoped full-path stats (fastest / slowest / average through the nearest fork to selection) |
| `B` | Toggle fork sibling hop RTT breakdown at that fork |
| `f` / `s` | Highlight fastest / slowest **answered** root-to-leaf path in the tree (overlay only; does not move selection) |
| `Esc` | Clear path highlight |
| `?` | Screen-scoped help (footer shows `Press ? for help`) |

Press **`r`** on Browse or Compare to re-query every hop with cache bypass. RTTs update **in memory** only; delve prompts to save on quit.

RTT bar colors and width are configured under `explore.rtt_bar` — see [configuration](configuration.md#explorertt_bar).

## `show --json` vs `events`

These are different JSON shapes for different jobs:

| Command | JSON shape | Best for |
|---------|------------|----------|
| **`session show --json`** | Flat `TraceResult`: chronological `hops` array + `final_response` | Replaying trace data, diffing sessions, tools that expect the stored snapshot |
| **`session events`** | Hierarchical explore `tree`: delegation / resolve / hop / final nodes | Tools that want the same structure as the TUI and outline views |

Both include per-query **`rtt_ms`** and **`from_cache`** in hop JSON. The explore tree omits a separate final node when the last hop already records the authoritative answer (same exchange as `final_response`).

Use **`--json`** for JSON output from `session show` (not `+events`; that flag is for `delve trace` only).

## See also

- [delve](../delve.md) — hub and quick start
- [Concepts](concepts.md) — branching in explore
- [Storage and output](storage.md) — JSON document shapes
