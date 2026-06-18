# GoScan

A fast, reliable TCP network scanner built for **scheduled perimeter monitoring** of large
(/16) subnets. GoScan runs on a schedule, scans an external subnet, and produces
machine-readable output that a downstream tool (or AI agent) can diff against the previous run
to detect change — new hosts, new open ports, and changed services.

- **Reliable middle ground** between `masscan` (fast but misses services) and `nmap` (thorough
  but slow across a full /16).
- **Built for automation:** stable JSON output, per-host fingerprints, a built-in diff mode,
  and meaningful exit codes so a cron job can trigger a notification on change.
- **Hardened for unattended runs:** atomic output, crash recovery, resume, and per-host
  adaptive timing.

> **Scope note:** GoScan uses TCP `connect()` scanning, not raw-socket SYN scanning. It is
> reliable and needs no special privileges for port scanning, but it is not a masscan-speed
> stateless scanner. It is best suited to sparse subnets scanned on a schedule. OS detection is
> intentionally **not** included (it is slow, noisy, and can destabilize fragile devices).

## Contents

- [Quick start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Command-line options](#command-line-options)
- [Output formats](#output-formats)
- [Diff mode](#diff-mode)
- [Resume](#resume)
- [Scheduled monitoring workflow](#scheduled-monitoring-workflow)
- [How it works](#how-it-works)
- [Reliability & design notes](#reliability--design-notes)
- [Privileges](#privileges)
- [Authorized use](#authorized-use)
- [License](#license)

## Quick start

```sh
# Build
go build -o GoScan .

# Scan a /24 with fast discovery, thorough port scan, and service detection
sudo ./GoScan -Td 5 -T 4 -sV -o lab-scan 192.168.10.0/24
#   → writes lab-scan-YYYY-MM-DD.json

# Scan again later and diff to see what changed (exit code 2 = changes found)
sudo ./GoScan -Td 5 -T 4 -sV -o lab-scan2 192.168.10.0/24
./GoScan --diff lab-scan-2026-06-16.json lab-scan2-2026-06-20.json
```

## Installation

### Build from source

Requires Go 1.21+.

```sh
git clone https://github.com/Arsenal-Unified-Intelligence/GoScan.git
cd GoScan
go build -o GoScan .
```

### Prebuilt binaries

Static binaries for Linux (amd64), Windows (amd64), and macOS (amd64 + arm64) are produced
with `GOOS`/`GOARCH` cross-compilation, e.g.:

```sh
GOOS=linux   GOARCH=amd64 go build -o GoScan-linux-amd64 .
GOOS=windows GOARCH=amd64 go build -o GoScan-windows-amd64.exe .
GOOS=darwin  GOARCH=amd64 go build -o GoScan-darwin-amd64 .
GOOS=darwin  GOARCH=arm64 go build -o GoScan-darwin-arm64 .
```

## Usage

```sh
# Single host, specific ports, with service/version detection
GoScan -p 80,443 -sV 192.168.1.100

# /24 with aggressive timing and all ports
GoScan -p- -T4 192.168.1.0/24

# Sparse /16: fast discovery (T5), thorough port scan (T4), JSON output
GoScan -Td 5 -T 4 -sV -o scan -oF json 10.0.0.0/16

# Skip discovery and scan every host directly (-Pn)
GoScan -Pn -p 22,3389 192.168.1.0/24

# Diff two scans (flag order does not matter)
GoScan --diff scan-2026-06-16.json scan-2026-06-20.json -oF json

# Resume an interrupted scan: skip already-completed hosts, finish the rest
GoScan -p- -resume scan-2026-06-17.json -o scan 10.0.0.0/16
```

Argument handling is forgiving: nmap-style attached flags (`-T4`, `-Td5`, `-p-`) and
space-separated forms (`-T 4`, `-p 1-65535`) both work, and flags may appear before or after
the target.

## Command-line options

| Flag       | Default | Meaning |
|------------|---------|---------|
| `-p`       | top 100 | Ports: `22,80,443`, a range `1-1000`, or `-` for all 65535 |
| `-sV`      | off     | Probe open ports for service/version banners |
| `-T`       | `3`     | Timing template 0–5 (T0 Paranoid · T1 Sneaky · T2 Polite · T3 Normal · T4 Aggressive · T5 Insane) |
| `-Td`      | = `-T`  | Discovery-phase timing override (use a fast value for sparse networks) |
| `-Pn`      | off     | Skip host discovery (treat all hosts as up) |
| `-sF`      | off     | Report filtered (firewalled) ports in addition to open |
| `-workers` | auto    | Concurrent workers (0 = derived from timing template, capped by fd limit) |
| `-timeout` | auto    | Connection timeout (0 = adaptive per-host) |
| `-retries` | auto    | Retries on failure (0 = from timing template) |
| `-o`       | none    | Output file base name (date is auto-appended) |
| `-oF`      | `json`  | Output format: `json`, `txt`, `csv` |
| `-quiet`   | auto    | Suppress progress output (auto-set when stdout is not a TTY, e.g. cron) |
| `-diff`    | —       | Compare two JSON scan files (see [Diff mode](#diff-mode)) |
| `-resume`  | —       | Resume from a prior JSON scan (see [Resume](#resume)) |

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Success / no changes (in diff mode) |
| `1`  | Error |
| `2`  | Diff mode: changes detected |

## Output formats

`json` (default) is the format intended for automated consumers. Structure:

```jsonc
{
  "meta": {
    "scan_date": "2026-06-17T23:13:04Z",  // RFC3339, UTC
    "target": "192.168.10.0/24",
    "scan_timing": "Aggressive",
    "discovery_timing": "Insane",
    "workers": 1010,
    "ports_scanned": "top100",
    "goscan_version": "1.3",
    "duration_seconds": 4,
    "hosts_discovered": 11,
    "total_open_ports": 62,
    "total_filtered_ports": 0,
    "total_unreachable": 0,
    "partial": false                       // true if the scan was interrupted
  },
  "hosts": [
    {
      "ip": "192.168.10.10",
      "discovery_method": "icmp",          // icmp | tcp | assumed | single
      "fingerprint": "13914fea9d14f8b3",   // SHA-256 of open ports+banners (change-detection)
      "complete": true,                    // false if this host wasn't fully scanned
      "ports": [
        { "port": 80, "state": "open", "service": "HTTP/1.1 200 OK | Server: nginx" }
      ]
    }
  ]
}
```

Hosts and ports are sorted deterministically (IPs numerically, ports ascending) so diffs are
stable. The `fingerprint` lets a consumer do an O(n) pass and only deep-inspect hosts whose
fingerprint changed. `txt` is human-readable; `csv` has columns
`IP,Port,State,Service,Discovery Method,Fingerprint`.

## Diff mode

```sh
GoScan --diff old.json new.json            # human-readable text
GoScan --diff old.json new.json -oF json   # machine-readable, for an agent
GoScan --diff old.json new.json -o changes # save to a file
```

Emits `NEW_HOST`, `CLOSED_HOST`, `NEW_PORT`, `CLOSED_PORT`, and `CHANGED_BANNER` records and a
summary. **Exit code 2** when any change is found (0 when clean), so a wrapper can act on it
directly. Diff warns if the two scans cover different targets, or if either is marked partial
(in which case `CLOSED_*` changes may be spurious).

## Resume

Every host is tagged `complete` in JSON output. If a scan is interrupted, re-run it with
`-resume <prior.json>`: hosts already fully scanned are skipped and merged from the prior file,
and only the unfinished hosts are rescanned. Completion is conservative — an interrupted host is
treated as incomplete and rescanned, so partial port data is never trusted.

```sh
GoScan -p- -resume scan-2026-06-17.json -o scan 10.0.0.0/16
```

## Scheduled monitoring workflow

The intended deployment: a cron job scans the perimeter on a schedule, diffs against the last
scan, and notifies on change.

```sh
# /etc/cron.d/goscan  — Monday & Friday at 02:00
0 2 * * 1,5  scanner  /opt/goscan/run-perimeter.sh
```

```sh
#!/usr/bin/env bash
# run-perimeter.sh
set -euo pipefail
SCANS=/data/scans
TODAY=$(date +%F)
PREV=$(ls -1 "$SCANS"/perimeter-*.json 2>/dev/null | tail -1)

# Scan (quiet mode auto-enables when stdout isn't a TTY)
/opt/goscan/GoScan -Td 5 -T 4 -sV -o "$SCANS/perimeter" -oF json 10.20.0.0/16

NEW="$SCANS/perimeter-$TODAY.json"
if [ -n "$PREV" ] && [ "$PREV" != "$NEW" ]; then
  if /opt/goscan/GoScan --diff "$PREV" "$NEW" -oF json -o "$SCANS/diff-$TODAY"; then
    echo "No perimeter changes."          # exit 0
  else
    notify-security-team "$SCANS/diff-$TODAY"   # exit 2 → changes found
  fi
fi
```

## How it works

1. **Tiered discovery** — an ICMP echo sweep first (cheap, one packet per host, concurrency
   scaled by the discovery timing template), then a short-timeout TCP "knock" on a tight set of
   high-signal ports (443, 80, 22, 445, 3389) for hosts that don't answer ICMP (catches hosts
   with host-based firewalls that drop ping). The knock is **RST-aware**: a host that actively
   refuses a probe is recorded as up, even when none of the knocked ports are open.
2. **Targeted port scan** — only hosts found "up" get a full port scan, so empty address space
   costs only the cheap discovery probe. Because detecting a *new* host is the whole point,
   discovery still touches every address; it just makes the per-address probe cheap rather than
   skipping address space.
3. **Structured output** — JSON (default) with per-host fingerprints and rich metadata, plus
   `txt` and `csv`.
4. **Built-in diff** — compare two JSON scans and emit changes with a non-zero exit code.

## Reliability & design notes

- **Atomic output:** results are written to a temp file, fsynced, and renamed into place, so a
  reader never sees a half-written file and an interrupted write leaves the prior good file intact.
- **Crash resistance:** each probe runs under panic recovery — one malformed response can never
  abort a long scan; the affected port is skipped and reported in the summary.
- **Interrupted scans are flagged** `meta.partial: true` (and a `# PARTIAL` note in text output)
  so a consumer knows absent ports are *not* confirmed closed.
- **Unreachable ≠ closed:** host/network-unreachable results are counted separately
  (`meta.total_unreachable`), never silently recorded as "closed".
- **File descriptors:** a `connect()` scan uses one descriptor per in-flight probe. GoScan raises
  its soft `RLIMIT_NOFILE` to the hard limit and caps concurrency under that budget; residual
  exhaustion is retried (never counted as "closed") and reported.
- **Per-host adaptive timing:** each host gets its own smoothed RTT and timeout (Jacobson/Karels,
  as TCP computes its RTO) plus a congestion backoff on consecutive losses — so a slow WAN host
  and a fast LAN host don't share, and corrupt, one global timeout.
- **Change-detection stability:** discovery gathers signal from both ICMP and a multi-port,
  RST-aware TCP knock, and banners are normalized to stable identities (volatile HTTP `Date`
  headers and the like are stripped), so unchanged hosts diff to zero changes.

## Privileges

The ICMP discovery sweep needs raw-socket access (root / `CAP_NET_RAW`). Without it, GoScan
skips the ICMP phase and relies on the TCP knock. TCP port scanning needs no special privileges.

## Authorized use

GoScan is a network scanner. Only scan networks you own or are explicitly authorized to test.
Unauthorized scanning may violate law and acceptable-use policies. You are responsible for how
you use this tool.

## License

Released under the [MIT License](LICENSE). © 2026 Arsenal Unified Intelligence.
