# delve — command reference

Command synopsis and trace options. For concepts (sessions, branching, expansion), see [concepts](concepts.md).

## Command overview

| Command | Purpose |
|---------|---------|
| `delve trace …` | Run a delegation trace |
| `delve session list` | List stored sessions (`^` frozen, `*` pinned, `@` current default) |
| `delve session current` | Print the current default session id |
| `delve session show [id]` | Show a stored session (no network); omit id for the default |
| `delve session show [id] --json` | Same session as flat JSON (`event: complete`) |
| `delve session rm <id>` | Delete one session |
| `delve session pin <id>` | Exempt from retention purge |
| `delve session unpin <id>` | Allow retention purge again |
| `delve session purge` | Apply retention policy now |
| `delve session purge <id>` | Remove one unpinned session regardless of retention age |
| `delve session purge --all` | Remove all unpinned sessions |
| `delve session purge --dry-run` | Report what would be removed |
| `delve session explore [id] [+icmp]` | Interactive tree explorer (TUI); `+icmp` enables one-shot ICMP refresh for this process |
| `delve session outline [id]` | Indented resolution tree on stdout; omit id for the default session |
| `delve session events [id]` | Structured JSON explore tree on stdout; omit id for the default session |
| `delve session diagram [id]` | Export trace tree as SVG or PNG; omit id for the default session |
| `delve session export [<id>…]` | Export session documents as a JSON bundle (`--all`, `-o PATH`) |
| `delve session import [PATH]` | Import a session bundle from a file or stdin |
| `delve session freeze <id>` | Mark a session frozen (content writes refused) |
| `delve session thaw <id>` | Unfreeze a session for branching and explore persist |
| `delve session branch [id]` | Extend a stored trace at a node (live queries) |
| `delve cache stats` | DNS response cache statistics |
| `delve cache purge` | Remove expired DNS cache entries |
| `delve cache purge --all` | Clear the entire DNS response cache |
| `delve cache enrichment stats` | Enrichment (ICMP) cache statistics |
| `delve cache enrichment purge icmp` | Clear all ICMP enrichment cache rows |
| `delve cache enrichment purge expired` | Remove TTL-expired ICMP enrichment cache rows |
| `delve config dump` | Print resolved config path and YAML template with defaults |

Session ids accept a full ULID or a unique short prefix (like git).

## Trace query options

Options follow **dig** conventions (not GNU long flags):

| Option | Default | Notes |
|--------|---------|-------|
| `+tcp` / `+notcp` | UDP | Transport |
| `+timeout=N` / `+time=N` | 5s | Both spellings; `N < 1` clamps to 1 |
| `+tries=N` | 2 | Retries per server |
| `+dnssec` / `+nodnssec` | off | Sets the DO bit |
| `+nsid` / `+nonsid` | **on** | delve requests NSID by default |
| `+events` | off | NDJSON event stream on stdout |
| `+debug` / `+nodebug` | off | Log query job, path, and thread id |
| `+cache` / `+nocache` | on | Use the global response cache for all queries |
| `+nocache=QNAME` | — | Skip cache for that exact query name (repeatable); other queries still use cache |
| `+save` / `+nosave` | on | Persist trace as a session |
| `+fresh` | off | Always run a live trace; do not reuse a stored session |
| `+follow` / `+nofollow` | off | Follow CNAME and DNAME aliases, restarting delegation from the new name |
| `+expand=last\|all\|none` | `last` | Zone-cut expansion policy; see [concepts](concepts.md#expansion-at-trace-time) |
| `+expand=all+force` | — | Skip full-expansion confirmation prompt |
| `+family=auto\|v4\|v6\|both` | `auto` | Address-family policy; see [Address family](#address-family) below |
| `-t TYPE` or `-TYPE` | `A` | Query type |
| `-x` | off | Reverse lookup: positional argument is an IP address; queries `PTR` at the corresponding `in-addr.arpa` / `ip6.arpa` name |
| `-4` / `-6` | — | Aliases for `+family=v4` / `+family=v6`; mutually exclusive |
| `@server` | root hints | Starting server (**IP literal** only today) |

### Address family

By default, delve uses **`+family=auto`**: before the first hop it probes whether
IPv6 UDP traffic can leave the host (toward the AAAA for `a.root-servers.net`).
If the kernel reports the route is unreachable, the trace runs **v4-only**; otherwise
it uses **dual-stack** (v4 and v6 root hints and glue, with v4 roots listed first).

Each live trace prints the resolved mode on stderr, for example:

```text
address family: dual-stack (ipv6 probe ok)
address family: v4-only (ipv6 unreachable)
address family: v4-only (-4)
address family: dual-stack (+family=both)
```

Explicit overrides skip the probe:

| Spelling | Effective policy |
|----------|------------------|
| (default) / `+family=auto` | Probe once per process, then v4-only or dual-stack |
| `-4` / `+family=v4` | IPv4 only |
| `-6` / `+family=v6` | IPv6 only |
| `+family=both` | Dual-stack (v4 and v6) |

In v4-only mode, nameserver resolution queries **A** records only; in v6-only mode,
**AAAA** only; in dual-stack mode, both. Family filtering also applies to glue and
referral target addresses. With `+debug`, skipped addresses may be logged.

Session reuse matches on the **resolved** family stored in session metadata
(`v4`, `v6`, or `both`), not on whether you used `-4` or `+family=auto` on the CLI.
See [concepts — session reuse](concepts.md#session-reuse).

Supported query types:

| Category | Types |
|----------|-------|
| Address / naming | `A`, `AAAA`, `CNAME`, `DNAME`, `NS`, `PTR`, `RP` |
| Mail / text / service | `MX`, `TXT`, `SRV`, `HTTPS`, `SVCB` |
| Security / DNSSEC / DANE | `CAA`, `CDNSKEY`, `CDS`, `CERT`, `CSYNC`, `DNSKEY`, `DS`, `OPENPGPKEY`, `RRSIG`, `NSEC`, `NSEC3`, `NSEC3PARAM`, `SMIMEA`, `SSHFP`, `TLSA` |
| Other | `HINFO`, `LOC`, `NAPTR`, `SOA` |

Any IANA type code also works via `TYPEnn` (for example `TYPE45` for IPSECKEY).

Truncated UDP responses (`TC=1`) are recorded as-is. Delve does **not** automatically retry over TCP when `TC` is set; use `+tcp` up front if you need TCP for the whole trace.

Human progress is written to **stderr**; with `+events`, structured events go to **stdout** so you can redirect:

```bash
delve trace example.com +events > trace.ndjson
```

Installed packages also ship `man delve` and `man delve-trace` for a CLI synopsis.

## Session diagram

Export a stored trace tree as SVG or PNG. See [diagram](diagram.md) for layouts
and formats. Diagram export is **`delve session diagram`** — not `session export`.

## Session bundles

Portable JSON envelopes move full session documents between machines without
copying the session store database.

### Export

```bash
delve session export <id> [<id> …]     # stdout; id order preserved
delve session export <id> -o path.json
delve session export --all             # every session in the store
```

`--all` and an id list are mutually exclusive. Each exported document includes
trees, view state, `frozen`, and other persisted fields.

Envelope shape:

```json
{
  "format": "delve-sessions",
  "version": 1,
  "exported_at": "2026-09-05T19:00:00Z",
  "sessions": [ /* full session documents */ ]
}
```

The envelope `version` is the **bundle** format, not the per-session document
field. See [storage — format versions](storage.md#format-versions).

### Import

```bash
delve session import path.json
delve session import < path.json       # stdin when PATH is omitted
delve session import --replace path.json
delve session import --reassign path.json
delve session import --pin --touch --frozen path.json
delve session import --json path.json  # machine-readable report
```

| Flag | Effect |
|------|--------|
| (default) | Skip sessions whose id already exists; leave the local copy unchanged; exit non-zero if any were skipped |
| `--replace` | Upsert over the same id (prompts when the local session is newer; refused for local **frozen** sessions unless `--force`) |
| `--reassign` | Mint a new id for every session in the bundle (`--replace` and `--reassign` cannot combine) |
| `--force` | With `--replace`, skip newer-local prompts and allow overwriting a frozen local session |
| `--pin` | Store imported sessions as pinned |
| `--touch` | Set `updated_at` to import time (`--pin` and `--touch` may both be set) |
| `--frozen` | Store each imported session as frozen |
| `--json` | Print a JSON report (counts, per-session outcomes, `no_replay` metadata) instead of the human summary |

Empty TTY stdin with no file path fails fast. Unsupported envelope `format` /
`version` fails before any store write. Session documents that this delve build
cannot read are reported and skipped; other sessions in the bundle continue;
exit status is non-zero. Details: [storage — format versions](storage.md#format-versions).

After import, branched or multi-tree sessions may trigger an informational
**replay notice**: they remain valid for explore and session commands, but will
not match for automatic trace replay. That is not corruption or an import error.

## Freeze and thaw

```bash
delve session freeze <id>   # seal: content writes refused; updated_at unchanged
delve session thaw <id>     # reopen: branching and explore persist allowed again
```

Frozen sessions still support pin/unpin, freeze/thaw, remove, purge, show,
outline, events, explore (read), diagram, and bundle export. Branch CLI and
explore **`b`** refuse before DNS. Explore view-state persist warns and skips
the write. See [concepts — freeze](concepts.md#freeze).

## See also

- [delve](../delve.md) — hub and quick start
- [Concepts](concepts.md) — traces, sessions, freeze, branching
- [Configuration](configuration.md) — YAML keys
- [Release notes](../release-notes/delve.md) — operator-facing changes
