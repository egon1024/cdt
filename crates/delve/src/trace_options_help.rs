/// Printed after `delve trace --help` and in `delve-trace(1)`.
pub const TRACE_OPTIONS_HELP: &str = "\
Query arguments:
  QNAME                 Name to trace (required unless only showing help)
  @SERVER               Start from this server (IP address; default: root hints)

Query type:
  -t TYPE               Query type (default: A)
  -qtype TYPE           Alias for -t
  -TYPE                 Shorthand for -t TYPE (e.g. -NS, -MX)
  -x                     Reverse lookup: argument is an IP; queries PTR

Address family:
  -4                     IPv4 only
  -6                     IPv6 only

Transport and timing:
  +tcp / +notcp          Use TCP or UDP (default: UDP)
  +timeout=N             Per-query timeout in seconds (default: 5; min 1)
  +time=N                Alias for +timeout=N
  +tries=N               Retries per server (default: 2)

DNS behavior:
  +dnssec / +nodnssec    Set or clear the DO bit (default: off)
  +nsid / +nonsid        Request EDNS NSID (default: on)
  +follow / +nofollow    Follow CNAME/DNAME alias chains (default: off)
  +expand=last|all|none  Zone-cut expansion policy (default: last)
  +expand=all+force      Skip full-expansion confirmation prompt

Output and sessions:
  +events / +noevents    Emit NDJSON events on stdout (default: off)
  +debug / +nodebug      Log query job, path, and thread id (default: off)
  +save / +nosave        Persist trace as a session (default: on)
  +fresh                 Force a live trace; do not reuse a stored session

Response cache:
  +cache / +nocache      Use the response cache (default: on)
  +nocache=QNAME         Skip cache for that qname only (repeatable)

Supported types include A, AAAA, CNAME, DNAME, NS, MX, TXT, SOA, DNSSEC types
(DNSKEY, DS, RRSIG, …), SVCB, HTTPS, TLSA, and TYPEnn for any IANA code.

Output:
  Progress and hop summaries go to stderr. With +events, structured NDJSON
  (hop, message, complete) goes to stdout for piping.

Examples:
  delve trace example.com
  delve trace example.com +events > trace.ndjson
  delve trace example.com +tcp -4 +timeout=3 -t NS @1.1.1.1
  delve trace example.com +follow +fresh
  delve trace example.com +nocache=example.com
  delve trace 192.0.2.1 -x
";
