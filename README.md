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

1. **Tiered discovery** — an ICMP echo sweep first (cheap, one packet per host), then a TCP
   "knock" on a small set of common ports for hosts that don't answer ICMP (catches hosts
   with host-based firewalls that drop ping).
2. **Targeted port scan** — only hosts found "up" in discovery get a full port scan, so empty
   address space costs only the cheap discovery probe.
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

# Diff two scans (flags BEFORE the file arguments)
GoScan -oF json -diff scan-2026-06-16.json scan-2026-06-20.json
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

## Privileges

The ICMP discovery sweep needs raw-socket access (root / `CAP_NET_RAW`). Without it, GoScan
skips the ICMP phase and relies on the TCP knock. TCP port scanning needs no special
privileges.
