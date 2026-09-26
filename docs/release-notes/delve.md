# delve release notes

Operator-facing changes for the `delve` utility. Newest version first.

For the full guide, see [docs/delve.md](../delve.md).

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
