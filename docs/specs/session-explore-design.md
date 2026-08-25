# Session explore — Phase 3 design

**Status:** Approved direction (2026-08-25)  
**Command:** `delve session explore <id>`

## Goal

Let operators **walk a stored trace** after the fact: see how delegation and
nameserver resolution branched, inspect any hop's details, without new DNS
queries. Complements `session show` (flat timeline) with a **navigable tree**.

## User-facing modes

Two output paths, same underlying tree model:

| Mode | When | Output |
|------|------|--------|
| **TUI** (default) | Interactive terminal | Full-screen tree + detail pane; keyboard navigation |
| **Outline** (static) | `+outline`, or stdout not a tty | One-shot indented tree to stdout — suitable for logs, paste, screenshots |

Optional third path for automation:

| Mode | Flag | Output |
|------|------|--------|
| **Tree JSON** | `+events` | NDJSON or single JSON tree document on stdout |

Dig-style flags keep consistency with `delve trace`:

```bash
delve session explore 01J...          # TUI when attached to a terminal
delve session explore 01J... +outline # print tree once and exit
delve session explore 01J... +events  # structured tree on stdout
delve session explore 01J... +outline < file   # non-tty → outline by default
```

**`+outline`** is the “single set of output” option: one coherent, visually
readable tree (indentation, zone labels, key hop fields on each line), not an
interactive redraw loop.

### Outline example (illustrative)

```text
tuininga.org. A
├─ [. ] ns.second-ns.com → com.          198.41.0.4  11ms  NOERROR
│  ├─ [com.] → second-ns.com.           192.41.162.30  11ms
│  │  └─ (resolve ns1.your-server.de)
│  │     ├─ [. ] → de.                  198.41.0.4  11ms
│  │     └─ [de.] → your-server.de.     194.0.0.53  39ms
│  └─ …
└─ final: 93.184.216.34 (A)
```

Exact formatting is implementation detail; the requirement is **scannable
hierarchy** in one pass.

## TUI behavior (sketch)

- **Left / main:** tree of nodes (delegation steps and NS-resolution branches)
- **Right / bottom:** detail for selected node (full hop fields, referral NS,
  glue, NSID, EDE — same richness as `session show`)
- **Keys:** up/down (move), enter (expand/collapse branch), `q` quit, `?` help
- **No network**, no cache reads

Libraries: `ratatui` + `crossterm` (standard Rust TUI stack; new dependencies
only on `delve`).

## Data model

### Problem

Today `TraceResult.hops` is a **flat list**. Sub-traces for nameserver resolution
append hops to the same list (or interleave via shared progress), which is hard to
navigate as a tree.

### Approach

**Phase 3a (explore on existing sessions):** Build an **explore tree** from the
flat hop list using heuristics:

- Root: trace `qname` / `qtype`
- Child edges: zone transitions, `qname` changes, and message boundaries implied
  by hop `zone` / `qname` / delegation targets
- NS-resolution subtrees grouped under a synthetic “resolve &lt;ns&gt;” node

Works for all Phase 2 sessions without migration.

**Phase 3b (optional follow-up):** Record an explicit `explore_tree` (or
`trace_tree`) at save time in session format **v2**, so future traces have a
canonical tree. Explore prefers v2 when present, falls back to reconstruction.

No change required to start Phase 3 implementation.

## Components

| Unit | Responsibility |
|------|----------------|
| `explore/tree.rs` | `ExploreNode`, build from `TraceResult`, iterators |
| `explore/outline.rs` | Render tree to `String` / stdout (`+outline`) |
| `explore/tui.rs` | Ratatui app: layout, input, selection state |
| `explore/json.rs` | `+events` tree serialization |
| `cli.rs` | `SessionSubcommand::Explore`, flag parsing |

## Error handling

- Session not found / ambiguous id → same as `session show`
- Corrupt session JSON → clear error, no partial TUI
- TUI on non-tty without `+outline` / `+events` → print hint and use outline
  (or require flag)

## Testing

- Unit tests: tree builder from fixture `TraceResult` snapshots
- Outline renderer: golden-line tests (stable text output)
- TUI: smoke test optional; prioritize outline + tree builder coverage
- Manual: `session explore` on real `tuininga.org` session

## Out of scope (Phase 3)

- Live trace tree (`delve trace` does not become interactive)
- Re-running queries from explore
- Multi-session diff or compare

## Success criteria

1. `delve session explore <id>` opens a usable TUI on a stored session.
2. `+outline` prints a single, readable tree without interaction.
3. No network activity during explore.
4. `make test` covers tree build and outline rendering.
