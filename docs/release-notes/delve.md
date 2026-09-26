# delve release notes

Operator-facing changes for the `delve` utility. Newest version first.

For the full guide, see [docs/delve.md](../delve.md).

## 0.1.1

### New

- **`delve trace`** walks the DNS delegation path with structured per-hop metadata
  (NSID, EDE, RTT), optional NDJSON on stdout, and configurable expansion at zone
  cuts.
- **Sessions** persist trace snapshots for reuse; **`delve session explore`** opens
  the TUI; **branch** adds alternate paths from a delegation hop without re-tracing
  from the root.
- **Address family policy** defaults to auto (IPv6 reachability probe, then v4-only
  or dual-stack); override with `+family=` and related trace flags.

## Unreleased

### New

- **`delve session export`** writes a portable JSON session bundle (envelope
  `format: "delve-sessions"`, version `1`) to stdout or `-o PATH`. Export one or
  more session ids (order preserved) or use `--all`.
- **`delve session import [PATH]`** reads that envelope from a file or stdin.
  Default policy skips colliding ids; `--replace` and `--reassign` are mutually
  exclusive; `--force`, `--pin`, `--touch`, `--frozen`, and `--json` control
  overwrite, retention, freeze-on-import, and machine-readable reports.
- **`delve session freeze <id>`** / **`delve session thaw <id>`** seal or reopen
  a session. Frozen sessions refuse content writes (branch, explore view-state
  persist) while read, explore, diagram, export, pin, and remove still work.
  List marks frozen rows with `^`; `session show` reports `frozen: yes`.

### Changed

- Trace diagram export moved from **`delve session export`** to
  **`delve session diagram`**. Flags and layouts are unchanged; see
  [docs/delve/diagram.md](../delve/diagram.md).
- Import may print an informational **replay notice** for branched or multi-tree
  sessions. Those sessions remain valid for explore and other session commands;
  they simply will not be reused for automatic trace replay.

### Removed

- **`delve session export`** no longer produces SVG/PNG diagrams. Use
  **`delve session diagram`** instead (breaking rename; no CLI alias).
