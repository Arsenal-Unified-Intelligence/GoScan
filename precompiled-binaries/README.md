# Precompiled binaries — GoScan v1.3

Ready-to-run builds. Download the zip for your platform, unzip, and run. Each zip contains the
binary plus the project `README.md` and `LICENSE`.

| Platform | File | Binary inside |
|----------|------|---------------|
| Linux (x86-64) | `GoScan-v1.3-linux-amd64.zip` | `GoScan` |
| Windows (x86-64) | `GoScan-v1.3-windows-amd64.zip` | `GoScan.exe` |
| macOS — Intel | `GoScan-v1.3-darwin-amd64.zip` | `GoScan` |
| macOS — Apple Silicon (M1/M2/M3) | `GoScan-v1.3-darwin-arm64.zip` | `GoScan` |

> macOS ships in two builds because an Apple Silicon binary will not run on an Intel Mac and
> vice-versa. If unsure: Apple menu → About This Mac. "Apple M…" → use `arm64`; "Intel" → use `amd64`.

The binaries are statically linked with no dependencies. They are built with
`CGO_ENABLED=0 go build -ldflags="-s -w"` (symbol tables stripped to reduce size).

## Verify integrity

```sh
sha256sum -c SHA256SUMS        # Linux
shasum -a 256 -c SHA256SUMS    # macOS
```

## Run

```sh
# Linux / macOS — unzip, make executable, run
unzip GoScan-v1.3-linux-amd64.zip
chmod +x GoScan
sudo ./GoScan -Td 5 -T 4 -sV -o scan 192.168.1.0/24
```

```powershell
# Windows (PowerShell) — Expand-Archive, then run
Expand-Archive GoScan-v1.3-windows-amd64.zip -DestinationPath GoScan
.\GoScan\GoScan.exe -Td 5 -T 4 -sV -o scan 192.168.1.0/24
```

Notes:
- The ICMP discovery sweep needs elevated privileges (`sudo` on Linux/macOS; an Administrator
  prompt on Windows). Without them, GoScan falls back to the TCP knock automatically.
- macOS Gatekeeper may block an unsigned binary on first run — clear it with
  `xattr -d com.apple.quarantine GoScan`, or right-click → Open.

See the top-level [README](../README.md) for full usage. Only scan networks you are authorized to test.
