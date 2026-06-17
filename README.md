# GoScan

A fast, reliable TCP network scanner built for **scheduled perimeter monitoring** of large
(/16) subnets. GoScan is tuned for a specific job: run on a schedule, scan an external
subnet, and produce machine-readable output that a downstream tool (or AI agent) can diff
against the previous run to detect change — new hosts, new open ports, and changed services.

## Why GoScan

`masscan` is fast but its stateless SYN approach can miss services; `nmap` is thorough but
slow across a full /16. GoScan aims for a reliable middle ground for the **change-detection**
use case: a tiered host-discovery pass narrows a sparse /16 down to live hosts, then only
those hosts get a full port scan.

> **Scope note:** GoScan uses TCP `connect()` scanning, not raw-socket SYN scanning. It is
> reliable and needs no special privileges for port scanning, but it is not a masscan-speed
> stateless scanner. It is best suited to sparse subnets scanned on a schedule.

## How it works

1. **Tiered discovery** — an ICMP echo sweep first (cheap, one packet per host, concurrency
   scaled by the discovery timing template), then a short-timeout TCP "knock" on a tight set
   of high-signal ports (443, 80, 22, 445, 3389) for hosts that don't answer ICMP (catches
   hosts with host-based firewalls that drop ping). The knock is **RST-aware**: a host that
   actively refuses a probe is recorded as up, even when none of the knocked ports are open.
2. **Targeted port scan** — only hosts found "up" in discovery get a full port scan, so empty
   address space costs only the cheap discovery probe. Because detecting a *new* host is the
   whole point, discovery still touches every address; it just makes the per-address probe
   cheap rather than skipping address space.
3. **Structured output** — JSON (default), with per-host fingerprints and rich scan metadata,
   plus `txt` and `csv` formats.
4. **Built-in diff** — compare two JSON scans and emit the changes, with a non-zero exit code
   when changes are found, so a cron wrapper can trigger a notification.

## Build

```sh
go build -o GoScan ./GoScan.go
```

## Usage

```sh
# Single host, specific ports, with service detection
GoScan -p 80,443 -sV 192.168.1.100

# /24 with aggressive timing
GoScan -p 1-10000 -T4 192.168.1.0/24

# Sparse /16: fast discovery, thorough port scan, JSON output
GoScan -Td 5 -T 4 -sV -o scan -oF json 10.0.0.0/16

# Diff two scans (flag order no longer matters)
GoScan --diff scan-2026-06-16.json scan-2026-06-20.json -oF json

# Resume an interrupted scan: skip already-completed hosts, finish the rest
GoScan -p 1-65535 -resume scan-2026-06-17.json -o scan -oF json 10.0.0.0/16
```

### Key flags

| Flag    | Meaning |
|---------|---------|
| `-p`    | Ports: `22,80,443`, `1-1000`, or `-` for all 65535 (default: top 100) |
| `-sV`   | Probe open ports for service/version banners |
| `-T`    | Timing template 0–5 (T0 Paranoid … T5 Insane), default T3 |
| `-Td`   | Discovery-phase timing override (for sparse networks) |
| `-Pn`   | Skip host discovery (treat all hosts as up) |
| `-sF`   | Report filtered (firewalled) ports in addition to open |
| `-o`    | Output file base name (date is auto-appended) |
| `-oF`   | Output format: `json` (default), `txt`, `csv` |
| `-diff` | Compare two JSON scan files |
| `-resume` | Resume from a prior JSON scan: skip already-completed hosts, merge their results |

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Success / no changes (diff mode) |
| `1`  | Error |
| `2`  | Diff mode: changes detected |

## Scheduled monitoring example

```sh
# Twice-weekly perimeter scan (cron)
GoScan -Td 5 -T 4 -sV -o /data/scans/perimeter -oF json 10.20.0.0/16
# → /data/scans/perimeter-YYYY-MM-DD.json

# Diff the two most recent scans; exit code 2 triggers notification
GoScan -oF json -o /data/diffs/diff \
  -diff /data/scans/perimeter-2026-06-16.json /data/scans/perimeter-2026-06-20.json
```

## Reliability notes

- **Atomic output:** results are written to a temp file, fsynced, and renamed into place, so a
  reader (your AI agent) never sees a half-written file, and an interrupted write leaves the
  previous good file intact.
- **Crash resistance:** each probe runs under panic recovery — one malformed response can never
  abort a multi-hour scan; the affected port is skipped and reported in the summary.
- **Interrupted scans are flagged:** on Ctrl+C/SIGTERM, partial results are saved with
  `meta.partial: true` (and a `# PARTIAL` note in text output) so a consumer knows that absent
  ports are *not* confirmed closed and should not be diffed as closures.
- **Unreachable ≠ closed:** host/network-unreachable results are counted separately
  (`meta.total_unreachable`), never silently recorded as "closed".
- **File descriptors:** a `connect()` scan uses one descriptor per in-flight probe. GoScan
  raises its soft `RLIMIT_NOFILE` to the hard limit at startup and caps worker concurrency
  under that budget. If descriptors are still exhausted mid-scan, the affected dials are
  retried (never silently counted as "closed"), and a warning reports how many events occurred.
- **Change-detection stability:** discovery gathers signal from both ICMP and a multi-port,
  RST-aware TCP knock, so a single dropped packet is unlikely to flip a live host to "down"
  and create spurious `NEW_HOST`/`CLOSED_HOST` churn in diffs.
- **Per-host adaptive timing:** each host gets its own smoothed RTT and timeout (Jacobson/Karels,
  as TCP computes its RTO) plus a congestion backoff that grows the timeout on consecutive
  losses — so a slow WAN host and a fast LAN host no longer share, and corrupt, one global
  timeout. This is what keeps results accurate on a lossy or rate-limited link.
- **Resume:** every host is tagged `complete` in JSON output; `-resume <file>` skips hosts
  already fully scanned and finishes the rest, so a /16 that dies at 90% continues cheaply
  instead of restarting from zero.
- **Diff guards:** `--diff` warns when the two scans cover different targets, or when either is
  marked partial (so a consumer never treats an interrupted scan's absences as real closures).

Argument handling is forgiving: nmap-style attached flags (`-T4`, `-Td5`, `-p-`) and
space-separated forms (`-T 4`, `-p 1-65535`) both work, and flags may appear before or after
positional arguments.

## Privileges

The ICMP discovery sweep needs raw-socket access (root / `CAP_NET_RAW`). Without it, GoScan
skips the ICMP phase and relies on the TCP knock. TCP port scanning needs no special
privileges.
