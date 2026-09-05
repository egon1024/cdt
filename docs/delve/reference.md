# delve — command reference

Command synopsis and trace options. For concepts (sessions, branching, expansion), see [concepts](concepts.md).

## Command overview

| Command | Purpose |
|---------|---------|
| `delve trace …` | Run a delegation trace |
| `delve session list` | List stored sessions (`*` pinned, `@` current default) |
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
| `delve session explore [id]` | Interactive tree explorer (TUI); omit id for the default session |
| `delve session outline [id]` | Indented resolution tree on stdout; omit id for the default session |
| `delve session events [id]` | Structured JSON explore tree on stdout; omit id for the default session |
| `delve session export [id]` | Export trace tree as SVG or PNG; omit id for the default session |
| `delve session branch [id]` | Extend a stored trace at a node (live queries) |
| `delve cache stats` | Response cache statistics |
| `delve cache purge` | Remove expired cache entries |
| `delve cache purge --all` | Clear the entire response cache |
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

## Session export

Export a stored trace tree as SVG or PNG. See [export](export.md) for layouts
and formats.

## See also

- [delve](../delve.md) — hub and quick start
- [Concepts](concepts.md) — traces, sessions, branching
- [Configuration](configuration.md) — YAML keys
