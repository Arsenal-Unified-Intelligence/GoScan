package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const version = "1.4"

const (
	defaultTimeout = 2 * time.Second
	defaultWorkers = 100
	defaultRetries = 1
	maxWorkers     = 10000
	connectTimeout = 1500 * time.Millisecond
	readTimeout    = 500 * time.Millisecond
	pingTimeout    = 1 * time.Second
	pingRetries    = 1

	// discoveryProbeTimeout is the per-port TCP knock timeout during host
	// discovery. Kept short: on a sparse /16 the runtime is dominated by waiting
	// on dead IPs, and a host that is actually up answers well under this.
	discoveryProbeTimeout = 400 * time.Millisecond

	// maxResourceRetries bounds how many times a single dial will retry after a
	// file-descriptor exhaustion error (EMFILE/ENFILE) before giving up. These
	// errors are transient — other in-flight dials complete and free fds — so we
	// retry rather than misclassify a possibly-open port as closed.
	maxResourceRetries = 40

	// fdReserve is the number of file descriptors held back from the worker pool
	// for stdout, the ICMP socket, output files, etc.
	fdReserve = 256
)

var asciiArt = `
   ██████╗  ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔════╝ ██╔═══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██║  ███╗██║   ██║███████╗██║     ███████║██╔██╗ ██║
  ██║   ██║██║   ██║╚════██║██║     ██╔══██║██║╚██╗██║
  ╚██████╔╝╚██████╔╝███████║╚██████╗██║  ██║██║ ╚████║
   ╚═════╝  ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
`

// TimingTemplate mirrors nmap's -T0 through -T5 timing profiles.
type TimingTemplate struct {
	Name             string
	MinRTT           time.Duration
	InitialRTT       time.Duration
	MaxRTT           time.Duration
	MaxRetries       int
	HostGroupSize    int
	ScanDelay        time.Duration
	MaxScanDelay     time.Duration
	MinParallelism   int
	MaxParallelism   int
	MaxHostsParallel int
	PerHostRateLimit time.Duration
}

var timingTemplates = map[string]TimingTemplate{
	"T0": {
		Name: "Paranoid", MinRTT: 100 * time.Millisecond, InitialRTT: 5 * time.Minute, MaxRTT: 10 * time.Minute,
		MaxRetries: 1, HostGroupSize: 1, ScanDelay: 5 * time.Minute, MaxScanDelay: 10 * time.Minute,
		MinParallelism: 1, MaxParallelism: 1, MaxHostsParallel: 1, PerHostRateLimit: 5 * time.Minute,
	},
	"T1": {
		Name: "Sneaky", MinRTT: 100 * time.Millisecond, InitialRTT: 15 * time.Second, MaxRTT: 10 * time.Minute,
		MaxRetries: 1, HostGroupSize: 1, ScanDelay: 15 * time.Second, MaxScanDelay: 5 * time.Minute,
		MinParallelism: 1, MaxParallelism: 10, MaxHostsParallel: 5, PerHostRateLimit: 15 * time.Second,
	},
	"T2": {
		Name: "Polite", MinRTT: 100 * time.Millisecond, InitialRTT: 1 * time.Second, MaxRTT: 10 * time.Second,
		MaxRetries: 1, HostGroupSize: 5, ScanDelay: 400 * time.Millisecond, MaxScanDelay: 1 * time.Second,
		MinParallelism: 1, MaxParallelism: 50, MaxHostsParallel: 10, PerHostRateLimit: 400 * time.Millisecond,
	},
	"T3": {
		Name: "Normal", MinRTT: 100 * time.Millisecond, InitialRTT: 500 * time.Millisecond, MaxRTT: 5 * time.Second,
		MaxRetries: 2, HostGroupSize: 20, ScanDelay: 0, MaxScanDelay: 100 * time.Millisecond,
		MinParallelism: 10, MaxParallelism: 500, MaxHostsParallel: 50, PerHostRateLimit: 10 * time.Millisecond,
	},
	"T4": {
		Name: "Aggressive", MinRTT: 50 * time.Millisecond, InitialRTT: 250 * time.Millisecond, MaxRTT: 1250 * time.Millisecond,
		MaxRetries: 2, HostGroupSize: 50, ScanDelay: 0, MaxScanDelay: 10 * time.Millisecond,
		MinParallelism: 20, MaxParallelism: 2000, MaxHostsParallel: 100, PerHostRateLimit: 0,
	},
	"T5": {
		Name: "Insane", MinRTT: 25 * time.Millisecond, InitialRTT: 75 * time.Millisecond, MaxRTT: 300 * time.Millisecond,
		MaxRetries: 1, HostGroupSize: 100, ScanDelay: 0, MaxScanDelay: 5 * time.Millisecond,
		MinParallelism: 50, MaxParallelism: 5000, MaxHostsParallel: 256, PerHostRateLimit: 0,
	},
}

// discoveryPorts is a tight, high-signal set used only for the host-discovery
// TCP knock — web (443/80), Linux/network gear (22), and Windows (445/3389).
// Kept small deliberately: every extra port multiplies across the entire
// address space. The full port scan of live hosts covers everything else.
var discoveryPorts = []int{443, 80, 22, 445, 3389}

var top100Ports = []int{
	80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
	143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
	1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
	10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
	26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
	5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
	2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543,
	544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
	7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051,
	6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
}

// tlsPorts use TLS and need a wrapped connection for banner grabbing.
var tlsPorts = map[int]bool{443: true, 8443: true, 990: true, 993: true, 995: true, 465: true}

var serviceProbes = map[int]string{
	80:   "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
	443:  "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
	8080: "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
	8443: "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
	8000: "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
	21:   "HELP\r\n",
	25:   "EHLO goscan\r\n",
	110:  "QUIT\r\n",
	143:  "A001 CAPABILITY\r\n",
	3306: "\r\n",
	5432: "\r\n",
	1433: "\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x48\x0f\x00\x00",
	135:  "\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00\xb8\x10\xb8\x10\x00\x00\x00\x00",
	139:  "*SMBSERVER\x00",
	445:  "\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00",
	389:  "\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00",
	3389: "\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00",
	22:   "\r\n",
	53:   "\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",
}

var serviceNames = map[int]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
	53: "domain", 80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
	139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap", 443: "https",
	445: "microsoft-ds", 465: "smtps", 514: "syslog", 587: "submission",
	631: "ipp", 873: "rsync", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s",
	1723: "pptp", 2049: "nfs", 3306: "mysql", 3389: "ms-wbt-server",
	5357: "wsdapi", 5432: "postgresql", 5900: "vnc", 8000: "http-alt",
	8080: "http-proxy", 8443: "https-alt", 8888: "http-alt", 27017: "mongodb",
}

// portState values for ScanResult.
const (
	stateOpen     = "open"
	stateFiltered = "filtered"
)

type ScanResult struct {
	IP     string
	Port   int
	State  string // "open" or "filtered"
	Banner string
}

type HostInfo struct {
	IP          string
	IsUp        bool
	PingSuccess bool
	TCPSuccess  bool
	Method      string
}

type scanJob struct {
	ip   string
	port int
}

type Scanner struct {
	timeout      time.Duration
	workers      int
	retries      int
	aggressive   bool
	skipHostDisc bool
	showFiltered bool
	timing       TimingTemplate
	discTiming   TimingTemplate // separate timing for discovery phase
	target       string
	portsDesc    string
	hostnames    map[string][]string // ip -> hostnames that resolved to it (read-only after setup)

	mu             sync.Mutex
	results        []ScanResult
	hostInfo       map[string]*HostInfo
	scanned           int64
	openPorts         int64
	filteredPorts     int64
	resourceErrors    int64
	unreachableErrors int64
	probePanics       int64
	partial           int32 // set when the scan did not complete (interrupted)
	lastHostScan   sync.Map
	hostTimings    sync.Map // ip -> *hostTiming (per-host adaptive timeout)
	globalSRTT     int64    // atomic nanos; coarse EWMA for progress display only
	hostProgress   sync.Map // ip -> *int64 count of ports attempted (for resume/completion)
	totalPorts     int      // ports per host this run (for completion detection)
	resumeSkip     map[string]bool // hosts seeded from --resume; skip scanning
	progressTicker *time.Ticker
	startTime      time.Time

	// for signal handler access
	outputFile   string
	outputFormat string
	isatty       bool

	fdLimit uint64 // soft open-file limit, used to cap discovery concurrency
}

// hostTiming holds per-host adaptive timeout state: a smoothed RTT and variance
// (Jacobson/Karels, as TCP computes its RTO) plus a congestion counter that grows
// the timeout on consecutive losses. Per-host means a slow WAN host and a fast LAN
// host no longer share — and corrupt — one global timeout.
type hostTiming struct {
	mu       sync.Mutex
	srtt     time.Duration
	rttvar   time.Duration
	hasRTT   bool
	timeouts int // consecutive timeouts (congestion signal)
}

// icmpResponse / icmpRequest used by the centralized ICMP dispatcher.
type icmpResponse struct {
	sourceIP string
	success  bool
}

func isTTY() bool {
	// Use a lightweight probe: try to get terminal width via TIOCGWINSZ
	// Fall back to checking if stdout is a character device.
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// normalizeArgs rewrites nmap-style attached short flags into the space-separated
// form Go's flag package requires, so familiar invocations like "-T4", "-Td5", and
// "-p-" work as documented (Go's flag would otherwise reject them as unknown flags).
func normalizeArgs(args []string) []string {
	isPortSpec := func(s string) bool {
		if s == "" {
			return false
		}
		for _, r := range s {
			if !(r >= '0' && r <= '9') && r != ',' && r != '-' {
				return false
			}
		}
		return true
	}
	isDigits := func(s string) bool {
		if s == "" {
			return false
		}
		for _, r := range s {
			if r < '0' || r > '9' {
				return false
			}
		}
		return true
	}

	out := make([]string, 0, len(args))
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "-Td") && isDigits(a[3:]):
			out = append(out, "-Td", a[3:])
		case strings.HasPrefix(a, "-T") && isDigits(a[2:]):
			out = append(out, "-T", a[2:])
		case strings.HasPrefix(a, "-p") && len(a) > 2 && isPortSpec(a[2:]):
			out = append(out, "-p", a[2:])
		default:
			out = append(out, a)
		}
	}
	return out
}

// valueFlags are the flags that consume a following argument as their value.
// Used by reorderArgs to permute flags ahead of positionals.
var valueFlags = map[string]bool{
	"p": true, "o": true, "workers": true, "timeout": true, "retries": true,
	"T": true, "Td": true, "oF": true, "diff": true, "diff2": true, "resume": true,
	"iL": true,
}

// reorderArgs moves flags (and their values) ahead of positional arguments so that
// invocations like "--diff a.json b.json -oF json -o out" work — Go's flag package
// otherwise stops parsing at the first positional, silently dropping trailing flags.
func reorderArgs(args []string) []string {
	var flags, positionals []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" { // explicit end-of-flags: everything after is positional
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			flags = append(flags, a)
			// "-flag=value" carries its own value; bare value-flags consume the next arg.
			if !strings.Contains(a, "=") {
				name := strings.TrimLeft(a, "-")
				if valueFlags[name] && i+1 < len(args) {
					flags = append(flags, args[i+1])
					i++
				}
			}
			continue
		}
		positionals = append(positionals, a)
	}
	return append(flags, positionals...)
}

func main() {
	ports := flag.String("p", "", "Port specification (22,80,443 | 1-1000 | - for all ports, default: top 100)")
	output := flag.String("o", "", "Output file base name (date auto-appended, e.g. goscan → goscan-2026-06-17)")
	workers := flag.Int("workers", 0, "Concurrent workers (0 = auto from timing)")
	timeout := flag.Duration("timeout", 0, "Connection timeout (0 = auto from timing)")
	retries := flag.Int("retries", 0, "Retries on failure (0 = auto from timing)")
	aggressive := flag.Bool("aggressive", false, "Aggressive mode (equivalent to -T4)")
	banner := flag.Bool("sV", false, "Probe open ports for service/version info")
	skipDiscovery := flag.Bool("Pn", false, "Skip host discovery (treat all hosts as online)")
	timingStr := flag.String("T", "3", "Timing template 0-5 or T0-T5 (default: T3 Normal)")
	discTimingStr := flag.String("Td", "", "Discovery phase timing override (default: same as -T)")
	progress := flag.Bool("stats", true, "Show real-time progress statistics")
	outputFormat := flag.String("oF", "json", "Output format: txt, json, csv (default: json)")
	quiet := flag.Bool("quiet", false, "Suppress progress output (auto-set when not a TTY)")
	showFiltered := flag.Bool("sF", false, "Report filtered (firewalled) ports in addition to open")
	diffFile1 := flag.String("diff", "", "Compare two JSON scan files: --diff scan1.json scan2.json")
	diffFile2 := flag.String("diff2", "", "Second file for diff comparison")
	resumeFile := flag.String("resume", "", "Resume from a prior JSON scan: skip already-completed hosts, merge their results")
	targetFile := flag.String("iL", "", "Read targets from file (one or more per line, # comments ok, - for stdin)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "GoScan v%s - Fast & Smart Network Scanner\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <target>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Target:  Single IP (192.168.1.1) or CIDR (192.168.1.0/24); multiple targets allowed\n")
		fmt.Fprintf(os.Stderr, "         Or read them from a file: -iL targets.txt (- for stdin)\n\n")
		fmt.Fprintf(os.Stderr, "Diff:    %s --diff monday.json friday.json\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Timing:  T0=Paranoid T1=Sneaky T2=Polite T3=Normal T4=Aggressive T5=Insane\n")
		fmt.Fprintf(os.Stderr, "         Use -Td for discovery phase, -T for port scan phase (sparse networks)\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s -p 80,443 192.168.1.100\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -p 1-10000 -T4 192.168.1.0/24\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -Td 5 -T 4 -sV -o scan 10.0.0.0/16   # fast discovery, thorough scan\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --diff scan-2026-06-16.json scan-2026-06-20.json\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -resume scan-2026-06-17.json -o scan 10.0.0.0/16   # finish an interrupted scan\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -iL perimeter.txt -Td 5 -T 4 -sV -o perimeter    # targets from a file\n", os.Args[0])
	}

	flag.CommandLine.Parse(reorderArgs(normalizeArgs(os.Args[1:])))

	// Diff mode — no target required.
	if *diffFile1 != "" {
		if *diffFile2 == "" && flag.NArg() >= 1 {
			*diffFile2 = flag.Arg(0)
		}
		if *diffFile2 == "" {
			fmt.Fprintln(os.Stderr, "Error: --diff requires two JSON files. Use --diff file1.json file2.json")
			os.Exit(1)
		}
		exitCode := runDiff(*diffFile1, *diffFile2, *outputFormat, *output)
		os.Exit(exitCode)
	}

	// Targets come from -iL, positional arguments, or both.
	var targetSpecs []targetSpec
	if *targetFile != "" {
		fileSpecs, ferr := readTargetFile(*targetFile)
		if ferr != nil {
			fmt.Fprintf(os.Stderr, "[!] Error reading target file: %v\n", ferr)
			os.Exit(1)
		}
		targetSpecs = append(targetSpecs, fileSpecs...)
	}
	for _, arg := range flag.Args() {
		targetSpecs = append(targetSpecs, targetSpec{text: arg})
	}

	if len(targetSpecs) == 0 {
		fmt.Fprintln(os.Stderr, "Error: target is required (a positional target, or -iL <file>)")
		flag.Usage()
		os.Exit(1)
	}

	// Descriptor recorded in scan metadata. For a target file this stays the file
	// reference rather than the expanded host list, so the diff guard keeps matching
	// across runs of the same list even as entries are added to or removed from it —
	// which is exactly the change the diff exists to report.
	target := strings.Join(flag.Args(), " ")
	if *targetFile != "" {
		src := "list:" + *targetFile
		if *targetFile == "-" {
			src = "list:<stdin>"
		}
		if target == "" {
			target = src
		} else {
			target = src + " " + target
		}
	}

	timingKey := strings.ToUpper(*timingStr)
	if !strings.HasPrefix(timingKey, "T") {
		timingKey = "T" + timingKey
	}
	timing, ok := timingTemplates[timingKey]
	if !ok {
		fmt.Fprintf(os.Stderr, "Error: invalid timing template '%s'. Use 0-5 or T0-T5\n", *timingStr)
		os.Exit(1)
	}

	discTiming := timing
	if *discTimingStr != "" {
		dk := strings.ToUpper(*discTimingStr)
		if !strings.HasPrefix(dk, "T") {
			dk = "T" + dk
		}
		dt, ok2 := timingTemplates[dk]
		if !ok2 {
			fmt.Fprintf(os.Stderr, "Error: invalid discovery timing template '%s'\n", *discTimingStr)
			os.Exit(1)
		}
		discTiming = dt
	}

	if *aggressive {
		timing = timingTemplates["T4"]
	}

	finalWorkers := *workers
	if finalWorkers == 0 {
		finalWorkers = (timing.MinParallelism + timing.MaxParallelism) / 2
	}
	if finalWorkers > maxWorkers {
		fmt.Fprintf(os.Stderr, "Warning: workers limited to %d\n", maxWorkers)
		finalWorkers = maxWorkers
	}

	// Raise the fd limit and cap concurrency under it. A connect() scan uses one
	// descriptor per in-flight probe; exceeding the limit makes dials fail with
	// EMFILE, which must not be mistaken for a closed port.
	fdLimit := raiseFDLimit()
	if capped := capConcurrency(finalWorkers, fdLimit); capped < finalWorkers {
		fmt.Fprintf(os.Stderr, "Warning: workers limited to %d by file-descriptor limit (ulimit -n %d)\n", capped, fdLimit)
		finalWorkers = capped
	}

	finalTimeout := *timeout
	if finalTimeout == 0 {
		finalTimeout = timing.InitialRTT
	}

	finalRetries := *retries
	if finalRetries == 0 {
		finalRetries = timing.MaxRetries
	}

	tty := isTTY()
	quietMode := *quiet || !tty

	// Build ports description for metadata.
	portsDesc := *ports
	if portsDesc == "" {
		portsDesc = "top100"
	} else if portsDesc == "-" {
		portsDesc = "1-65535"
	}

	// Build timestamped output filename.
	outFile := *output
	if outFile != "" {
		date := time.Now().Format("2006-01-02")
		// Strip any extension the user added so we control it.
		ext := "." + strings.ToLower(*outputFormat)
		base := strings.TrimSuffix(outFile, ext)
		outFile = base + "-" + date + ext
	}

	scanner := &Scanner{
		timeout:      finalTimeout,
		workers:      finalWorkers,
		retries:      finalRetries,
		aggressive:   *aggressive,
		skipHostDisc: *skipDiscovery,
		showFiltered: *showFiltered,
		timing:       timing,
		discTiming:   discTiming,
		target:       target,
		portsDesc:    portsDesc,
		hostInfo:     make(map[string]*HostInfo),
		startTime:    time.Now(),
		outputFile:   outFile,
		outputFormat: *outputFormat,
		isatty:       tty,
		fdLimit:      fdLimit,
	}

	if !quietMode {
		printBanner(timing.Name, discTiming.Name, finalWorkers, finalTimeout, finalRetries)
	}

	ips, hostnames, err := parseTargetSpecs(targetSpecs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error parsing target: %v\n", err)
		os.Exit(1)
	}
	if len(ips) == 0 {
		fmt.Fprintln(os.Stderr, "[!] Error: target list expanded to zero hosts")
		os.Exit(1)
	}
	scanner.hostnames = hostnames
	if len(hostnames) > 0 && !quietMode {
		names := 0
		for _, n := range hostnames {
			names += len(n)
		}
		fmt.Printf("[>] Resolved %d hostname(s) to %d address(es)\n", names, len(hostnames))
	}

	var portList []int
	if *ports == "" {
		portList = make([]int, len(top100Ports))
		copy(portList, top100Ports)
	} else {
		portList, err = parsePorts(*ports)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error parsing ports: %v\n", err)
			os.Exit(1)
		}
	}
	scanner.totalPorts = len(portList)

	// Resume: seed already-completed hosts from a prior scan and skip them.
	if *resumeFile != "" {
		skip, rerr := scanner.loadResume(*resumeFile)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "[!] Error loading resume file %s: %v\n", *resumeFile, rerr)
			os.Exit(1)
		}
		scanner.resumeSkip = skip
		if !quietMode {
			fmt.Printf("[>] Resume: %d hosts already complete in %s — skipping their port scan\n", len(skip), *resumeFile)
		} else {
			fmt.Printf("[+] Resume: skipping %d completed hosts\n", len(skip))
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown: save partial results before exit.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Printf("\n\n[!] Scan interrupted — saving partial results...\n")
		atomic.StoreInt32(&scanner.partial, 1)
		cancel()
		if scanner.progressTicker != nil {
			scanner.progressTicker.Stop()
		}
		time.Sleep(150 * time.Millisecond)
		duration := time.Since(scanner.startTime)
		scanner.printResults(duration, quietMode)
		if scanner.outputFile != "" {
			if saveErr := scanner.saveResults(scanner.outputFile, scanner.outputFormat, duration); saveErr != nil {
				fmt.Fprintf(os.Stderr, "[!] Error saving results: %v\n", saveErr)
			} else {
				fmt.Printf("[+] Partial results saved to: %s\n", scanner.outputFile)
			}
		}
		os.Exit(0)
	}()

	// Host discovery.
	var activeHosts []string
	if len(ips) > 1 && !*skipDiscovery {
		if !quietMode {
			fmt.Printf("\n[>] Smart Host Discovery on %d potential hosts (timing: %s)\n", len(ips), discTiming.Name)
			fmt.Printf("========================================================\n")
		}
		activeHosts = scanner.discoverHosts(ctx, ips, quietMode)
		if !quietMode {
			fmt.Printf("\n[+] Host discovery complete: %d hosts up\n\n", len(activeHosts))
		} else {
			fmt.Printf("[+] Discovery complete: %d/%d hosts up\n", len(activeHosts), len(ips))
		}
	} else if *skipDiscovery {
		if !quietMode {
			fmt.Printf("\n[>] Skipping host discovery (-Pn)\n\n")
		}
		activeHosts = ips
		for _, ip := range ips {
			scanner.hostInfo[ip] = &HostInfo{IP: ip, IsUp: true, Method: "assumed"}
		}
	} else {
		activeHosts = ips
		scanner.hostInfo[ips[0]] = &HostInfo{IP: ips[0], IsUp: true, Method: "single"}
	}

	if len(activeHosts) == 0 && len(scanner.resumeSkip) == 0 {
		fmt.Printf("[!] No hosts found up. Exiting.\n")
		os.Exit(0)
	}

	totalScans := len(activeHosts) * len(portList)
	if !quietMode {
		fmt.Printf("[>] Initiating Port Scan (timing: %s)\n", timing.Name)
		fmt.Printf("========================================================\n")
		fmt.Printf("[i] Hosts:      %d\n", len(activeHosts))
		fmt.Printf("[i] Ports:      %d (%s)\n", len(portList), portsDesc)
		fmt.Printf("[i] Total jobs: %d\n", totalScans)
		fmt.Printf("[i] Workers:    %d\n\n", finalWorkers)
	} else {
		fmt.Printf("[>] Port scan: %d hosts × %d ports = %d jobs\n", len(activeHosts), len(portList), totalScans)
	}

	if *progress && !quietMode && timing.Name != "Paranoid" && timing.Name != "Sneaky" {
		scanner.progressTicker = time.NewTicker(3 * time.Second)
		go scanner.showProgress(ctx)
	}

	scanner.scan(ctx, activeHosts, portList, *banner)

	if scanner.progressTicker != nil {
		scanner.progressTicker.Stop()
	}

	duration := time.Since(scanner.startTime)
	scanner.printResults(duration, quietMode)

	if outFile != "" {
		if saveErr := scanner.saveResults(outFile, *outputFormat, duration); saveErr != nil {
			fmt.Fprintf(os.Stderr, "[!] Error saving results: %v\n", saveErr)
			os.Exit(1)
		}
		fmt.Printf("[+] Results saved to: %s\n", outFile)
	}

	os.Exit(0)
}

func (s *Scanner) discoverHosts(ctx context.Context, ips []string, quiet bool) []string {
	if !quiet {
		fmt.Printf("  [1/2] ICMP Echo ping sweep... ")
	}
	pingResults := s.pingHosts(ctx, ips, quiet)
	if !quiet {
		fmt.Printf("%d hosts responded\n", len(pingResults))
	}

	for _, ip := range pingResults {
		s.mu.Lock()
		s.hostInfo[ip] = &HostInfo{IP: ip, IsUp: true, PingSuccess: true, Method: "icmp"}
		s.mu.Unlock()
	}

	var remainingHosts []string
	for _, ip := range ips {
		s.mu.Lock()
		_, found := s.hostInfo[ip]
		s.mu.Unlock()
		if !found {
			remainingHosts = append(remainingHosts, ip)
		}
	}

	var tcpResults []string
	if len(remainingHosts) > 0 {
		if !quiet {
			fmt.Printf("  [2/2] TCP SYN discovery on %d remaining hosts... ", len(remainingHosts))
		}
		tcpResults = s.tcpDiscovery(ctx, remainingHosts)
		if !quiet {
			fmt.Printf("%d additional hosts found\n", len(tcpResults))
		}
		for _, ip := range tcpResults {
			s.mu.Lock()
			s.hostInfo[ip] = &HostInfo{IP: ip, IsUp: true, TCPSuccess: true, Method: "tcp"}
			s.mu.Unlock()
		}
	} else if !quiet {
		fmt.Printf("  [2/2] TCP discovery skipped (all hosts responded to ICMP)\n")
	}

	var activeHosts []string
	activeHosts = append(activeHosts, pingResults...)
	activeHosts = append(activeHosts, tcpResults...)
	return activeHosts
}

func (s *Scanner) pingHosts(ctx context.Context, ips []string, quiet bool) []string {
	var activeHosts []string
	var mu sync.Mutex

	connChan := make(chan *icmp.PacketConn, 1)
	errChan := make(chan error, 1)
	go func() {
		conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			errChan <- err
		} else {
			connChan <- conn
		}
	}()

	var conn *icmp.PacketConn
	select {
	case conn = <-connChan:
	case <-errChan:
		if !quiet {
			fmt.Printf("(requires root privileges, skipped)\n")
		}
		return activeHosts
	case <-time.After(2 * time.Second):
		if !quiet {
			fmt.Printf("(timeout creating ICMP socket, skipped)\n")
		}
		return activeHosts
	}
	defer conn.Close()

	totalIPs := len(ips)

	// Scale ICMP concurrency by the discovery timing template (all echoes share a
	// single socket, so this just bounds in-flight goroutines, not fds).
	pingConc := (s.discTiming.MinParallelism + s.discTiming.MaxParallelism) / 2
	if pingConc < 50 {
		pingConc = 50
	}
	if pingConc > 4096 {
		pingConc = 4096
	}

	// Derive the deadline from the actual work and concurrency so large sweeps are
	// not silently truncated. Worst case per host ≈ two ping timeouts (initial +
	// one retry) plus a little slack; one "wave" covers pingConc hosts.
	perHost := 2*pingTimeout + 200*time.Millisecond
	waves := (totalIPs + pingConc - 1) / pingConc
	pingDeadline := time.Duration(waves) * perHost * 2
	if pingDeadline < 30*time.Second {
		pingDeadline = 30 * time.Second
	}
	if pingDeadline > 15*time.Minute {
		pingDeadline = 15 * time.Minute
	}

	pingCtx, pingCancel := context.WithTimeout(ctx, pingDeadline)
	defer pingCancel()

	// Sequence tracking — ICMP seq is 16-bit, keep in [1, 65535].
	requestMap := make(map[int]chan icmpResponse)
	var requestMapMu sync.Mutex
	nextSeq := 1

	dispatcherDone := make(chan struct{})
	go func() {
		defer close(dispatcherDone)
		for {
			select {
			case <-pingCtx.Done():
				return
			default:
			}
			reply := make([]byte, 1500)
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, peer, err := conn.ReadFrom(reply)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				select {
				case <-pingCtx.Done():
					return
				default:
					continue
				}
			}
			if n > 0 {
				rm, parseErr := icmp.ParseMessage(1, reply[:n])
				if parseErr == nil && rm.Type == ipv4.ICMPTypeEchoReply {
					if echo, ok := rm.Body.(*icmp.Echo); ok {
						seq := echo.Seq
						var sourceIP string
						if ipAddr, ok := peer.(*net.IPAddr); ok {
							sourceIP = ipAddr.IP.String()
						} else {
							sourceIP = peer.String()
						}
						requestMapMu.Lock()
						if respCh, exists := requestMap[seq]; exists {
							select {
							case respCh <- icmpResponse{sourceIP: sourceIP, success: true}:
							default:
							}
						}
						requestMapMu.Unlock()
					}
				}
			}
		}
	}()

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, pingConc)
	scanned := 0

Loop:
	for _, ip := range ips {
		select {
		case <-pingCtx.Done():
			break Loop
		default:
		}
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			select {
			case <-pingCtx.Done():
				return
			case semaphore <- struct{}{}:
			}
			defer func() { <-semaphore }()

			success := false
			for attempt := 0; attempt <= pingRetries; attempt++ {
				requestMapMu.Lock()
				seq := nextSeq
				// Keep sequence in 16-bit range [1, 65535].
				nextSeq = (nextSeq % 65535) + 1
				responseCh := make(chan icmpResponse, 1)
				requestMap[seq] = responseCh
				requestMapMu.Unlock()

				if s.pingHost(pingCtx, conn, targetIP, seq, responseCh) {
					success = true
					requestMapMu.Lock()
					delete(requestMap, seq)
					close(responseCh)
					requestMapMu.Unlock()
					break
				}
				requestMapMu.Lock()
				delete(requestMap, seq)
				close(responseCh)
				requestMapMu.Unlock()
				if attempt < pingRetries {
					time.Sleep(100 * time.Millisecond)
				}
			}

			if success {
				mu.Lock()
				activeHosts = append(activeHosts, targetIP)
				mu.Unlock()
			}

			if !quiet {
				mu.Lock()
				scanned++
				if scanned%25 == 0 || scanned == totalIPs {
					fmt.Printf("\r  [1/2] ICMP ping sweep... %d/%d scanned", scanned, totalIPs)
				}
				mu.Unlock()
			}
		}(ip)
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-pingCtx.Done():
	}

	pingCancel()
	<-dispatcherDone

	if !quiet {
		fmt.Print("\r" + strings.Repeat(" ", 80) + "\r")
	}
	return activeHosts
}

func (s *Scanner) pingHost(ctx context.Context, conn *icmp.PacketConn, ip string, seq int, responseCh chan icmpResponse) bool {
	select {
	case <-ctx.Done():
		return false
	default:
	}

	dst, err := net.ResolveIPAddr("ip4", ip)
	if err != nil {
		return false
	}

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  seq,
			Data: []byte("GOSCAN"),
		},
	}
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return false
	}
	if _, err := conn.WriteTo(msgBytes, dst); err != nil {
		return false
	}

	select {
	case response := <-responseCh:
		return response.success && response.sourceIP == ip
	case <-ctx.Done():
		return false
	case <-time.After(pingTimeout):
		return false
	}
}

func (s *Scanner) tcpDiscovery(ctx context.Context, ips []string) []string {
	var activeHosts []string
	var mu sync.Mutex
	discovered := make(map[string]bool)

	// Use discovery timing for worker count, capped by the fd budget (each knock
	// is a live socket).
	discWorkers := (s.discTiming.MinParallelism + s.discTiming.MaxParallelism) / 2
	if discWorkers < 10 {
		discWorkers = 10
	}
	discWorkers = capConcurrency(discWorkers, s.fdLimit)

	var wg sync.WaitGroup
	jobs := make(chan scanJob, discWorkers*2)

	for i := 0; i < discWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case job, ok := <-jobs:
					if !ok {
						return
					}
					mu.Lock()
					alreadyFound := discovered[job.ip]
					mu.Unlock()
					if alreadyFound {
						continue
					}
					if s.tcpProbeSafe(ctx, job.ip, job.port) {
						mu.Lock()
						if !discovered[job.ip] {
							discovered[job.ip] = true
							activeHosts = append(activeHosts, job.ip)
						}
						mu.Unlock()
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, ip := range ips {
			for _, port := range discoveryPorts {
				select {
				case jobs <- scanJob{ip: ip, port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	wg.Wait()
	return activeHosts
}

// tcpProbeSafe wraps tcpProbe with panic recovery so a malformed response during
// discovery can never take down a discovery worker.
func (s *Scanner) tcpProbeSafe(ctx context.Context, ip string, port int) (up bool) {
	defer func() {
		if r := recover(); r != nil {
			atomic.AddInt64(&s.probePanics, 1)
			up = false
		}
	}()
	return s.tcpProbe(ctx, ip, port)
}

// tcpProbe knocks a single port for host discovery. It reports the host as alive
// on either a successful connect (SYN-ACK) or an actively refused connection
// (RST) — both prove the host is up; the port being closed is irrelevant. A
// timeout or unreachable error is treated as "no signal". Local fd exhaustion is
// retried rather than counted as a negative.
func (s *Scanner) tcpProbe(ctx context.Context, ip string, port int) bool {
	addr := fmt.Sprintf("%s:%d", ip, port)
	for res := 0; ; {
		select {
		case <-ctx.Done():
			return false
		default:
		}
		d := net.Dialer{Timeout: discoveryProbeTimeout}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			conn.Close()
			return true
		}
		if isRefused(err) {
			return true // RST → host is alive
		}
		if isResourceError(err) && res < maxResourceRetries {
			res++
			atomic.AddInt64(&s.resourceErrors, 1)
			time.Sleep(time.Duration(res) * 25 * time.Millisecond)
			continue
		}
		return false
	}
}

func (s *Scanner) scan(ctx context.Context, ips []string, ports []int, grabBanner bool) {
	jobs := make(chan scanJob, s.workers*2)
	var wg sync.WaitGroup

	for i := 0; i < s.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case job, ok := <-jobs:
					if !ok {
						return
					}
					s.runScanJob(ctx, job, grabBanner)
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, ip := range ips {
			if s.resumeSkip[ip] {
				continue // already fully scanned in the --resume file
			}
			for _, port := range ports {
				select {
				case jobs <- scanJob{ip: ip, port: port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	wg.Wait()
}

// runScanJob applies per-host rate limiting and scans one port, recovering from
// any panic so a single malformed response can never abort the whole scan — the
// resilience property that lets a multi-hour /16 run to completion.
func (s *Scanner) runScanJob(ctx context.Context, job scanJob, grabBanner bool) {
	defer func() {
		if r := recover(); r != nil {
			atomic.AddInt64(&s.probePanics, 1)
		}
	}()

	if s.timing.PerHostRateLimit > 0 {
		if lastScan, ok := s.lastHostScan.Load(job.ip); ok {
			if lastTime, ok := lastScan.(time.Time); ok {
				if elapsed := time.Since(lastTime); elapsed < s.timing.PerHostRateLimit {
					time.Sleep(s.timing.PerHostRateLimit - elapsed)
				}
			}
		}
	}
	s.scanPort(ctx, job.ip, job.port, grabBanner)

	// Only count the attempt if we weren't interrupted, so an interrupted host
	// stays "incomplete" and a later --resume rescans it rather than trusting
	// its partial port data.
	select {
	case <-ctx.Done():
		return
	default:
	}
	s.incHostProgress(job.ip)
	s.lastHostScan.Store(job.ip, time.Now())
	if s.timing.ScanDelay > 0 {
		time.Sleep(s.timing.ScanDelay)
	}
}

func (s *Scanner) scanPort(ctx context.Context, ip string, port int, grabBanner bool) {
	defer atomic.AddInt64(&s.scanned, 1)

	timeout := s.hostTimeout(ip)

	var conn net.Conn
	var err error
	var lastErr error

	addr := fmt.Sprintf("%s:%d", ip, port)
	resourceRetries := 0
	for attempt := 0; attempt <= s.retries; attempt++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		d := net.Dialer{Timeout: timeout}
		t0 := time.Now()
		conn, err = d.DialContext(ctx, "tcp", addr)
		rtt := time.Since(t0)

		if err == nil {
			s.recordRTT(ip, rtt)
			break
		}
		lastErr = err

		// fd exhaustion says nothing about the port — back off and retry without
		// spending the real retry budget, so an open port is never lost to EMFILE.
		if isResourceError(err) && resourceRetries < maxResourceRetries {
			resourceRetries++
			atomic.AddInt64(&s.resourceErrors, 1)
			time.Sleep(time.Duration(resourceRetries) * 25 * time.Millisecond)
			attempt--
			continue
		}

		if attempt < s.retries {
			backoff := time.Duration(100*(attempt+1)) * time.Millisecond
			if backoff > s.timing.MaxScanDelay {
				backoff = s.timing.MaxScanDelay
			}
			if !s.aggressive && backoff > 0 {
				time.Sleep(backoff)
			}
		}
	}

	if err != nil {
		switch {
		case isUnreachable(lastErr):
			// Host/network unreachable says nothing about the port — do not count
			// it as a confident "closed" (which would manufacture diff churn).
			atomic.AddInt64(&s.unreachableErrors, 1)
		case isTimeoutError(lastErr):
			// Congestion signal: grow this host's next timeout.
			s.recordTimeout(ip)
			if s.showFiltered {
				result := ScanResult{IP: ip, Port: port, State: stateFiltered}
				s.mu.Lock()
				s.results = append(s.results, result)
				s.mu.Unlock()
				atomic.AddInt64(&s.filteredPorts, 1)
			}
		}
		// Otherwise the host actively refused (RST) → genuinely closed; not stored.
		return
	}
	defer conn.Close()

	bannerStr := ""
	if grabBanner {
		bannerStr = s.grabBanner(conn, port)
	}

	result := ScanResult{
		IP:     ip,
		Port:   port,
		State:  stateOpen,
		Banner: bannerStr,
	}
	s.mu.Lock()
	s.results = append(s.results, result)
	s.mu.Unlock()
	atomic.AddInt64(&s.openPorts, 1)
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}
	return false
}

// isRefused reports whether a dial failed because the host actively refused the
// connection (TCP RST). For host discovery this is a positive signal: the host
// is alive and reachable, the probed port just happens to be closed.
func isRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

// isResourceError reports whether a dial failed due to local file-descriptor
// exhaustion rather than anything about the target. Such a result says nothing
// about whether the port is open, so it must never be classified as "closed".
func isResourceError(err error) bool {
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE)
}

// isUnreachable reports whether a dial failed because the host or network could
// not be reached (routing/connectivity), as opposed to the host actively saying
// the port is closed (RST). Unreachable says nothing about the port, so it must
// not be counted as a confident "closed".
func isUnreachable(err error) bool {
	return errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.ENETDOWN) ||
		errors.Is(err, syscall.EHOSTDOWN)
}

// writeFileAtomic writes through a temp file in the same directory, fsyncs it, and
// renames it into place. A concurrent reader (the AI agent) therefore always sees
// either the previous complete file or the new complete file — never a torn one —
// and an interrupted write leaves the prior good file intact.
func writeFileAtomic(path string, write func(io.Writer) error) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if err := write(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// raiseFDLimit best-effort raises the process open-file budget and returns it.
// A connect() scanner needs one descriptor per in-flight probe, so headroom here
// directly bounds achievable concurrency. Implemented per-platform (raiseFDLimit
// lives in fdlimit_unix.go / fdlimit_windows.go).

// capConcurrency limits a desired worker count so that concurrent dials stay
// under the available file-descriptor budget, leaving fdReserve for other use.
func capConcurrency(desired int, fdLimit uint64) int {
	budget := int(fdLimit) - fdReserve
	if fdLimit > uint64(^uint(0)>>1) { // guard against overflow on huge limits
		budget = int(^uint(0) >> 1)
	}
	if budget < 1 {
		budget = 1
	}
	if desired > budget {
		return budget
	}
	return desired
}

// displayRTT returns a coarse global smoothed RTT for the progress line only.
func (s *Scanner) displayRTT() time.Duration {
	if v := atomic.LoadInt64(&s.globalSRTT); v > 0 {
		return time.Duration(v)
	}
	return s.timing.InitialRTT
}

func (s *Scanner) htFor(ip string) *hostTiming {
	if v, ok := s.hostTimings.Load(ip); ok {
		return v.(*hostTiming)
	}
	actual, _ := s.hostTimings.LoadOrStore(ip, &hostTiming{})
	return actual.(*hostTiming)
}

// hostTimeout returns the adaptive connect timeout for a host: an RTO derived from
// its smoothed RTT (srtt + 4·rttvar), doubled per consecutive timeout as congestion
// backoff, clamped to the timing template's [MinRTT, MaxRTT]. Before any RTT sample
// exists it falls back to the base timeout (also backed off under congestion).
func (s *Scanner) hostTimeout(ip string) time.Duration {
	base := s.timeout
	if s.aggressive {
		base /= 2
	}
	ht := s.htFor(ip)
	ht.mu.Lock()
	defer ht.mu.Unlock()

	to := base
	if ht.hasRTT {
		to = ht.srtt + 4*ht.rttvar
	}
	if ht.timeouts > 0 {
		shift := ht.timeouts
		if shift > 4 {
			shift = 4
		}
		to <<= uint(shift)
	}
	if to < s.timing.MinRTT {
		to = s.timing.MinRTT
	}
	if to > s.timing.MaxRTT {
		to = s.timing.MaxRTT
	}
	if to <= 0 {
		to = base
	}
	return to
}

// recordRTT folds a successful RTT into the host's smoothed estimate (Jacobson/
// Karels) and clears its congestion counter.
func (s *Scanner) recordRTT(ip string, rtt time.Duration) {
	ht := s.htFor(ip)
	ht.mu.Lock()
	if !ht.hasRTT {
		ht.srtt = rtt
		ht.rttvar = rtt / 2
		ht.hasRTT = true
	} else {
		diff := ht.srtt - rtt
		if diff < 0 {
			diff = -diff
		}
		ht.rttvar = (3*ht.rttvar + diff) / 4
		ht.srtt = (7*ht.srtt + rtt) / 8
	}
	ht.timeouts = 0
	ht.mu.Unlock()

	// Coarse global EWMA for the progress display (approximate; display-only).
	old := atomic.LoadInt64(&s.globalSRTT)
	if old == 0 {
		atomic.StoreInt64(&s.globalSRTT, int64(rtt))
	} else {
		atomic.StoreInt64(&s.globalSRTT, (7*old+int64(rtt))/8)
	}
}

// recordTimeout signals a congestion event for a host (grows its next timeout).
func (s *Scanner) recordTimeout(ip string) {
	ht := s.htFor(ip)
	ht.mu.Lock()
	ht.timeouts++
	ht.mu.Unlock()
}

// incHostProgress records that one more port of a host has been attempted.
func (s *Scanner) incHostProgress(ip string) {
	v, _ := s.hostProgress.LoadOrStore(ip, new(int64))
	atomic.AddInt64(v.(*int64), 1)
}

// hostComplete reports whether every port of a host has been attempted this run,
// i.e. the host's results are authoritative (used for --resume and JSON output).
func (s *Scanner) hostComplete(ip string) bool {
	if s.totalPorts <= 0 {
		return false
	}
	if v, ok := s.hostProgress.Load(ip); ok {
		return atomic.LoadInt64(v.(*int64)) >= int64(s.totalPorts)
	}
	return false
}

// markHostComplete forces a host to count as fully scanned (used when seeding
// already-finished hosts from a --resume file).
func (s *Scanner) markHostComplete(ip string) {
	c := new(int64)
	*c = int64(s.totalPorts)
	s.hostProgress.Store(ip, c)
}

// loadResume seeds results from a prior scan's fully-completed hosts so they are
// skipped this run and merged into output. Hosts marked incomplete in the prior
// file are ignored (rescanned fresh). Returns the set of host IPs to skip.
func (s *Scanner) loadResume(path string) (map[string]bool, error) {
	prev, err := loadJSONScan(path)
	if err != nil {
		return nil, err
	}
	skip := make(map[string]bool)
	for _, h := range prev.Hosts {
		if !h.Complete {
			continue
		}
		s.mu.Lock()
		s.hostInfo[h.IP] = &HostInfo{IP: h.IP, IsUp: true, Method: h.Method}
		for _, p := range h.Ports {
			s.results = append(s.results, ScanResult{IP: h.IP, Port: p.Port, State: p.State, Banner: p.Service})
			if p.State == stateOpen {
				atomic.AddInt64(&s.openPorts, 1)
			}
		}
		s.mu.Unlock()
		s.markHostComplete(h.IP)
		skip[h.IP] = true
	}
	return skip, nil
}

func (s *Scanner) grabBanner(conn net.Conn, port int) string {
	var actualConn net.Conn = conn

	// Wrap TLS ports.
	if tlsPorts[port] {
		tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
		if err := tlsConn.SetDeadline(time.Now().Add(readTimeout)); err == nil {
			if err := tlsConn.Handshake(); err == nil {
				actualConn = tlsConn
			}
		}
	}

	actualConn.SetReadDeadline(time.Now().Add(readTimeout))
	buf := make([]byte, 4096)
	n, _ := actualConn.Read(buf)
	if n > 0 {
		if b := s.processBanner(buf[:n], port); b != "" {
			return b
		}
	}

	probe := "\r\n"
	if specificProbe, ok := serviceProbes[port]; ok {
		probe = specificProbe
	}

	actualConn.SetWriteDeadline(time.Now().Add(readTimeout))
	if _, err := actualConn.Write([]byte(probe)); err != nil {
		if svc, ok := serviceNames[port]; ok {
			return svc
		}
		return ""
	}

	actualConn.SetReadDeadline(time.Now().Add(readTimeout))
	n, err := actualConn.Read(buf)
	if err != nil || n == 0 {
		if svc, ok := serviceNames[port]; ok {
			return svc
		}
		return ""
	}

	if b := s.processBanner(buf[:n], port); b != "" {
		return b
	}
	if svc, ok := serviceNames[port]; ok {
		return svc
	}
	return ""
}

// sanitizeBanner strips control/non-printable bytes and collapses whitespace so a
// banner is a single clean line. It does not, by itself, remove volatile content —
// that is the job of the protocol-specific extractors below.
func sanitizeBanner(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return ' '
		}
		if r < 32 || r > 126 {
			return -1
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

// firstNonEmptyLine returns the first non-blank line of raw, line endings intact.
func firstNonEmptyLine(raw string) string {
	for _, ln := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		if t := strings.TrimSpace(ln); t != "" {
			return t
		}
	}
	return ""
}

// sshVersion extracts the SSH identification string (e.g. "SSH-2.0-OpenSSH_8.9"),
// which is stable across scans.
func sshVersion(raw string) string {
	idx := strings.Index(raw, "SSH-")
	if idx < 0 {
		return ""
	}
	rest := raw[idx:]
	if end := strings.IndexAny(rest, "\r\n "); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

// httpSummary reduces an HTTP response to a STABLE identity — the status line plus
// the Server header only. Volatile headers (Date, Set-Cookie, ETag) and the body
// are dropped so two scans of an unchanged server produce identical banners.
func httpSummary(raw string) string {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	status := ""
	for _, ln := range lines {
		if t := strings.TrimSpace(ln); strings.HasPrefix(t, "HTTP/") {
			status = t
			break
		}
	}
	if status == "" {
		status = firstNonEmptyLine(raw)
	}
	server := ""
	for _, ln := range lines {
		l := strings.TrimSpace(ln)
		if l == "" {
			continue
		}
		if strings.HasPrefix(strings.ToLower(l), "server:") {
			server = strings.TrimSpace(l[len("server:"):])
			break
		}
	}
	if server != "" {
		return status + " | Server: " + server
	}
	return status
}

// mysqlSummary extracts a stable label from a MySQL handshake or error packet,
// deliberately dropping the connecting IP that MySQL echoes in "host not allowed"
// errors (volatile across source addresses, and an information leak in output).
func mysqlSummary(raw string) string {
	if strings.Contains(raw, "is not allowed to connect") {
		return "mysql (host not allowed)"
	}
	// Protocol v10 handshake: NUL-terminated server version after a 5-byte header.
	if len(raw) > 6 {
		v := raw[5:]
		if z := strings.IndexByte(v, 0); z > 0 {
			if ver := sanitizeBanner(v[:z]); ver != "" {
				return "mysql " + ver
			}
		}
	}
	return "mysql"
}

func (s *Scanner) processBanner(data []byte, port int) string {
	raw := string(data)
	var banner string

	switch {
	case strings.Contains(raw, "SSH-"):
		banner = sshVersion(raw)
	case strings.Contains(raw, "HTTP/"):
		banner = httpSummary(raw)
	case port == 3306:
		banner = mysqlSummary(raw)
	case port == 135 || port == 139 || port == 445 || port == 3389 || port == 389:
		// Binary protocols rarely yield a clean text version over connect+read;
		// the stable, useful answer is the well-known service name.
		if svc, ok := serviceNames[port]; ok {
			return svc
		}
		banner = firstNonEmptyLine(raw)
	default:
		banner = firstNonEmptyLine(raw)
		// Some SMTP/Sendmail greetings append "; <date>" — drop it for stability.
		if strings.Contains(banner, "SMTP") || strings.Contains(banner, "ESMTP") {
			if i := strings.IndexByte(banner, ';'); i > 0 {
				banner = strings.TrimSpace(banner[:i])
			}
		}
	}

	banner = sanitizeBanner(banner)
	if banner == "" {
		if svc, ok := serviceNames[port]; ok {
			return svc
		}
	}
	if len(banner) > 120 {
		banner = banner[:120] + "..."
	}
	return banner
}

// hostFingerprint returns a stable SHA-256 hash of a host's open ports and banners.
// Used by the AI agent for O(n) change detection.
func hostFingerprint(results []ScanResult) string {
	// Sort by port for stability.
	sorted := make([]ScanResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Port < sorted[j].Port })

	var parts []string
	for _, r := range sorted {
		if r.State == stateOpen {
			parts = append(parts, fmt.Sprintf("%d:%s", r.Port, r.Banner))
		}
	}
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return fmt.Sprintf("%x", h[:8]) // 8 bytes = 16 hex chars, enough for change detection
}

// sortIPsNumerically sorts IP strings by their numeric value (not lexicographic).
func sortIPsNumerically(ips []string) {
	sort.Slice(ips, func(i, j int) bool {
		return ipToUint32(ips[i]) < ipToUint32(ips[j])
	})
}

func ipToUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func printBanner(scanTiming, discTiming string, workers int, timeout time.Duration, retries int) {
	fmt.Printf("%s\n", asciiArt)
	fmt.Printf("           Fast & Smart Network Scanner v%s\n", version)
	fmt.Printf("           https://github.com/Arsenal-Unified-Intelligence/GoScan\n")
	fmt.Printf("========================================================\n")
	fmt.Printf("[i]  Scan Timing:  %s\n", scanTiming)
	fmt.Printf("[i]  Disc Timing:  %s\n", discTiming)
	fmt.Printf("[i]  Workers:      %d\n", workers)
	fmt.Printf("[i]  Timeout:      %v\n", timeout)
	fmt.Printf("[i]  Retries:      %d\n", retries)
	fmt.Printf("========================================================\n")
}

func (s *Scanner) showProgress(ctx context.Context) {
	for {
		select {
		case <-s.progressTicker.C:
			scanned := atomic.LoadInt64(&s.scanned)
			open := atomic.LoadInt64(&s.openPorts)
			filtered := atomic.LoadInt64(&s.filteredPorts)
			elapsed := time.Since(s.startTime)
			rate := float64(scanned) / elapsed.Seconds()
			avgRTT := s.displayRTT()
			closed := scanned - open - filtered
			fmt.Printf("\r[*] Scanned: %d | Open: %d | Filtered: %d | Closed: %d | Rate: %.1f/s | RTT: %v | Elapsed: %v",
				scanned, open, filtered, closed, rate, avgRTT.Round(time.Millisecond), elapsed.Round(time.Second))
		case <-ctx.Done():
			fmt.Println()
			return
		}
	}
}

func (s *Scanner) printResults(duration time.Duration, quiet bool) {
	fmt.Print("\r" + strings.Repeat(" ", 150) + "\r")

	if !quiet {
		fmt.Printf("\n========================================================\n")
		fmt.Printf("                   SCAN RESULTS\n")
		fmt.Printf("========================================================\n\n")
	}

	// Group results by IP.
	ipMap := make(map[string][]ScanResult)
	for _, r := range s.results {
		ipMap[r.IP] = append(ipMap[r.IP], r)
	}

	s.mu.Lock()
	var ips []string
	for ip := range s.hostInfo {
		ips = append(ips, ip)
	}
	s.mu.Unlock()
	sortIPsNumerically(ips)

	for _, ip := range ips {
		results := ipMap[ip]
		sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })

		s.mu.Lock()
		hInfo := s.hostInfo[ip]
		s.mu.Unlock()

		fmt.Printf("Host: %s", ip)
		if names := s.hostnames[ip]; len(names) > 0 {
			fmt.Printf(" (%s)", strings.Join(names, ", "))
		}
		if hInfo != nil && hInfo.Method != "" && hInfo.Method != "single" {
			fmt.Printf(" [%s]", hInfo.Method)
		}
		fmt.Println()
		fmt.Printf("  %-9s %-10s %s\n", "PORT", "STATE", "SERVICE")
		fmt.Printf("  %s\n", strings.Repeat("-", 50))

		if len(results) == 0 {
			fmt.Printf("  (no open ports detected)\n")
		}
		for _, r := range results {
			svc := r.Banner
			if len(svc) > 40 {
				svc = svc[:40] + "..."
			}
			fmt.Printf("  %-9d %-10s %s\n", r.Port, r.State, svc)
		}
		fmt.Println()
	}

	s.mu.Lock()
	hostsUp := len(s.hostInfo)
	s.mu.Unlock()
	scanned := atomic.LoadInt64(&s.scanned)
	openPorts := atomic.LoadInt64(&s.openPorts)
	filteredPorts := atomic.LoadInt64(&s.filteredPorts)
	unreachable := atomic.LoadInt64(&s.unreachableErrors)
	rate := float64(scanned) / duration.Seconds()
	closed := scanned - openPorts - filteredPorts - unreachable
	if closed < 0 {
		closed = 0
	}

	fmt.Printf("========================================================\n")
	fmt.Printf("[+] GoScan v%s done: %d ports in %.2fs (%.1f/s)\n", version, scanned, duration.Seconds(), rate)
	fmt.Printf("[i] Hosts up: %d | Open: %d | Filtered: %d | Closed: %d | Unreachable: %d\n",
		hostsUp, openPorts, filteredPorts, closed, unreachable)
	if re := atomic.LoadInt64(&s.resourceErrors); re > 0 {
		fmt.Printf("[!] Recovered from %d file-descriptor exhaustion events (raise ulimit -n or lower -workers for headroom)\n", re)
	}
	if pp := atomic.LoadInt64(&s.probePanics); pp > 0 {
		fmt.Printf("[!] Recovered from %d probe panics (scan continued; affected ports skipped)\n", pp)
	}
	if atomic.LoadInt32(&s.partial) != 0 {
		fmt.Printf("[!] Scan was interrupted — results are PARTIAL (absent ports are not confirmed closed)\n")
	}
	fmt.Printf("========================================================\n")
}

// ── Output ────────────────────────────────────────────────────────────────────

func (s *Scanner) saveResults(filename string, format string, duration time.Duration) error {
	switch strings.ToLower(format) {
	case "json":
		return s.saveResultsJSON(filename, duration)
	case "csv":
		return s.saveResultsCSV(filename)
	default:
		return s.saveResultsTXT(filename)
	}
}

// JSONScanMeta holds scan-level metadata for AI agent consumption.
type JSONScanMeta struct {
	ScanDate       string `json:"scan_date"`
	Target         string `json:"target"`
	ScanTiming     string `json:"scan_timing"`
	DiscTiming     string `json:"discovery_timing"`
	Workers        int    `json:"workers"`
	PortsScanned   string `json:"ports_scanned"`
	GoScanVersion  string `json:"goscan_version"`
	DurationSecs   int64  `json:"duration_seconds"`
	HostsDiscovered int   `json:"hosts_discovered"`
	TotalOpenPorts int64  `json:"total_open_ports"`
	TotalFiltered  int64  `json:"total_filtered_ports"`
	TotalUnreachable int64 `json:"total_unreachable"`
	Partial        bool   `json:"partial"` // true if the scan was interrupted; port absences are not authoritative
}

type JSONPort struct {
	Port    int    `json:"port"`
	State   string `json:"state"`
	Service string `json:"service,omitempty"`
}

type JSONHost struct {
	IP          string     `json:"ip"`
	Hostnames   []string   `json:"hostnames,omitempty"` // names from -iL / args that resolved here
	Method      string     `json:"discovery_method,omitempty"`
	Fingerprint string     `json:"fingerprint"`
	Complete    bool       `json:"complete"` // false if this host wasn't fully scanned (interrupted); enables --resume
	Ports       []JSONPort `json:"ports"`
}

type JSONOutput struct {
	Meta  JSONScanMeta `json:"meta"`
	Hosts []JSONHost   `json:"hosts"`
}

func (s *Scanner) saveResultsJSON(filename string, duration time.Duration) error {
	ipMap := make(map[string][]ScanResult)
	for _, r := range s.results {
		ipMap[r.IP] = append(ipMap[r.IP], r)
	}

	s.mu.Lock()
	var ips []string
	for ip := range s.hostInfo {
		ips = append(ips, ip)
	}
	hostsUp := len(s.hostInfo)
	s.mu.Unlock()
	sortIPsNumerically(ips)

	var hosts []JSONHost
	for _, ip := range ips {
		results := ipMap[ip]
		sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })

		s.mu.Lock()
		hInfo := s.hostInfo[ip]
		s.mu.Unlock()

		var ports []JSONPort
		for _, r := range results {
			svc := r.Banner
			ports = append(ports, JSONPort{Port: r.Port, State: r.State, Service: svc})
		}
		if ports == nil {
			ports = []JSONPort{}
		}

		method := ""
		if hInfo != nil {
			method = hInfo.Method
		}

		hosts = append(hosts, JSONHost{
			IP:          ip,
			Hostnames:   s.hostnames[ip],
			Method:      method,
			Fingerprint: hostFingerprint(results),
			Complete:    s.hostComplete(ip),
			Ports:       ports,
		})
	}
	if hosts == nil {
		hosts = []JSONHost{}
	}

	output := JSONOutput{
		Meta: JSONScanMeta{
			ScanDate:        time.Now().UTC().Format(time.RFC3339),
			Target:          s.target,
			ScanTiming:      s.timing.Name,
			DiscTiming:      s.discTiming.Name,
			Workers:         s.workers,
			PortsScanned:    s.portsDesc,
			GoScanVersion:   version,
			DurationSecs:    int64(duration.Seconds()),
			HostsDiscovered:  hostsUp,
			TotalOpenPorts:   atomic.LoadInt64(&s.openPorts),
			TotalFiltered:    atomic.LoadInt64(&s.filteredPorts),
			TotalUnreachable: atomic.LoadInt64(&s.unreachableErrors),
			Partial:          atomic.LoadInt32(&s.partial) != 0,
		},
		Hosts: hosts,
	}

	return writeFileAtomic(filename, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(output)
	})
}

func (s *Scanner) saveResultsTXT(filename string) error {
	ipMap := make(map[string][]ScanResult)
	for _, r := range s.results {
		ipMap[r.IP] = append(ipMap[r.IP], r)
	}

	s.mu.Lock()
	var ips []string
	for ip := range s.hostInfo {
		ips = append(ips, ip)
	}
	s.mu.Unlock()
	sortIPsNumerically(ips)

	return writeFileAtomic(filename, func(f io.Writer) error {
		fmt.Fprintf(f, "# GoScan v%s Results\n", version)
		fmt.Fprintf(f, "# Target: %s\n", s.target)
		fmt.Fprintf(f, "# Scan Date: %s\n", time.Now().Format(time.RFC3339))
		if atomic.LoadInt32(&s.partial) != 0 {
			fmt.Fprintf(f, "# PARTIAL: scan was interrupted; absent ports are not confirmed closed\n")
		}
		fmt.Fprintln(f)

		for _, ip := range ips {
			results := ipMap[ip]
			sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })

			s.mu.Lock()
			hInfo := s.hostInfo[ip]
			s.mu.Unlock()

			fmt.Fprintf(f, "Host: %s", ip)
			if names := s.hostnames[ip]; len(names) > 0 {
				fmt.Fprintf(f, " (%s)", strings.Join(names, ", "))
			}
			if hInfo != nil && hInfo.Method != "" {
				fmt.Fprintf(f, " [%s]", hInfo.Method)
			}
			fmt.Fprintln(f)

			if len(results) == 0 {
				fmt.Fprintln(f, "  (no open ports detected)")
			} else {
				fmt.Fprintf(f, "  %-9s %-10s %s\n", "PORT", "STATE", "SERVICE")
				for _, r := range results {
					svc := r.Banner
					if svc == "" {
						svc = "unknown"
					}
					fmt.Fprintf(f, "  %-9d %-10s %s\n", r.Port, r.State, svc)
				}
			}
			fmt.Fprintln(f)
		}
		return nil
	})
}

func (s *Scanner) saveResultsCSV(filename string) error {
	ipMap := make(map[string][]ScanResult)
	for _, r := range s.results {
		ipMap[r.IP] = append(ipMap[r.IP], r)
	}

	s.mu.Lock()
	var ips []string
	for ip := range s.hostInfo {
		ips = append(ips, ip)
	}
	s.mu.Unlock()
	sortIPsNumerically(ips)

	return writeFileAtomic(filename, func(out io.Writer) error {
		w := csv.NewWriter(out)
		// "Hostnames" is appended last so existing column positions stay valid
		// for anything already consuming this CSV.
		if err := w.Write([]string{"IP", "Port", "State", "Service", "Discovery Method", "Fingerprint", "Hostnames"}); err != nil {
			return err
		}

		for _, ip := range ips {
			results := ipMap[ip]
			sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })

			s.mu.Lock()
			hInfo := s.hostInfo[ip]
			s.mu.Unlock()

			method := ""
			if hInfo != nil {
				method = hInfo.Method
			}
			fp := hostFingerprint(results)
			names := strings.Join(s.hostnames[ip], " ")

			if len(results) == 0 {
				if err := w.Write([]string{ip, "-", "up", "no open ports", method, fp, names}); err != nil {
					return err
				}
			} else {
				for _, r := range results {
					svc := r.Banner
					if svc == "" {
						svc = "unknown"
					}
					if err := w.Write([]string{ip, strconv.Itoa(r.Port), r.State, svc, method, fp, names}); err != nil {
						return err
					}
				}
			}
		}
		w.Flush()
		return w.Error()
	})
}

// ── Diff mode ─────────────────────────────────────────────────────────────────

type DiffChange struct {
	Type     string `json:"type"` // NEW_HOST, CLOSED_HOST, NEW_PORT, CLOSED_PORT, CHANGED_BANNER, HOSTNAME_MOVED
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"` // set on HOSTNAME_MOVED and host-level changes
	Port     int    `json:"port,omitempty"`
	State    string `json:"state,omitempty"`
	Before   string `json:"before,omitempty"`
	After    string `json:"after,omitempty"`
}

type DiffReport struct {
	File1   JSONScanMeta `json:"scan_a"`
	File2   JSONScanMeta `json:"scan_b"`
	Changes []DiffChange `json:"changes"`
	Summary struct {
		NewHosts       int `json:"new_hosts"`
		ClosedHosts    int `json:"closed_hosts"`
		NewPorts       int `json:"new_ports"`
		ClosedPorts    int `json:"closed_ports"`
		ChangedBanner  int `json:"changed_banners"`
		HostnamesMoved int `json:"hostnames_moved"`
	} `json:"summary"`
}

func hostnameSuffix(hostname string) string {
	if hostname == "" {
		return ""
	}
	return " (" + hostname + ")"
}

// hostnameIndex maps each hostname seen in a scan to the sorted set of addresses
// it resolved to, letting two scans be compared by name rather than by address.
func hostnameIndex(hosts []JSONHost) map[string][]string {
	idx := make(map[string][]string)
	for _, h := range hosts {
		for _, n := range h.Hostnames {
			idx[n] = appendUnique(idx[n], h.IP)
		}
	}
	for n := range idx {
		sortIPsNumerically(idx[n])
	}
	return idx
}

func loadJSONScan(path string) (*JSONOutput, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out JSONOutput
	if err := json.NewDecoder(f).Decode(&out); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &out, nil
}

// runDiff compares two JSON scan files and prints changes.
// Returns exit code: 0 = no changes, 2 = changes found, 1 = error.
func runDiff(file1, file2, outputFormat, outFile string) int {
	scan1, err := loadJSONScan(file1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error loading %s: %v\n", file1, err)
		return 1
	}
	scan2, err := loadJSONScan(file2)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error loading %s: %v\n", file2, err)
		return 1
	}

	// Self-consistency guards: a mismatched target or a partial scan produces
	// misleading diffs (spurious new/closed hosts and ports). Warn loudly so a
	// downstream consumer doesn't act on noise.
	if scan1.Meta.Target != "" && scan2.Meta.Target != "" && scan1.Meta.Target != scan2.Meta.Target {
		fmt.Fprintf(os.Stderr, "[!] Warning: scans cover different targets (%s vs %s) — diff may be meaningless\n",
			scan1.Meta.Target, scan2.Meta.Target)
	}
	if scan1.Meta.Partial || scan2.Meta.Partial {
		fmt.Fprintf(os.Stderr, "[!] Warning: a scan is marked partial (interrupted) — absent ports are not confirmed closed; CLOSED_* changes may be false\n")
	}

	// Index hosts by IP.
	hosts1 := make(map[string]JSONHost)
	for _, h := range scan1.Hosts {
		hosts1[h.IP] = h
	}
	hosts2 := make(map[string]JSONHost)
	for _, h := range scan2.Hosts {
		hosts2[h.IP] = h
	}

	report := DiffReport{File1: scan1.Meta, File2: scan2.Meta}
	report.Changes = []DiffChange{}

	// Find new and closed hosts, changed ports.
	var allIPs []string
	seen := make(map[string]bool)
	for ip := range hosts1 {
		allIPs = append(allIPs, ip)
		seen[ip] = true
	}
	for ip := range hosts2 {
		if !seen[ip] {
			allIPs = append(allIPs, ip)
		}
	}
	sortIPsNumerically(allIPs)

	for _, ip := range allIPs {
		h1, in1 := hosts1[ip]
		h2, in2 := hosts2[ip]

		if in2 && !in1 {
			report.Changes = append(report.Changes, DiffChange{Type: "NEW_HOST", IP: ip, Hostname: strings.Join(h2.Hostnames, " ")})
			report.Summary.NewHosts++
			for _, p := range h2.Ports {
				report.Changes = append(report.Changes, DiffChange{Type: "NEW_PORT", IP: ip, Port: p.Port, State: p.State, After: p.Service})
				report.Summary.NewPorts++
			}
			continue
		}
		if in1 && !in2 {
			report.Changes = append(report.Changes, DiffChange{Type: "CLOSED_HOST", IP: ip, Hostname: strings.Join(h1.Hostnames, " ")})
			report.Summary.ClosedHosts++
			continue
		}

		// Both scans have this host — compare fingerprints for quick skip.
		if h1.Fingerprint == h2.Fingerprint {
			continue
		}

		ports1 := make(map[int]JSONPort)
		for _, p := range h1.Ports {
			ports1[p.Port] = p
		}
		ports2 := make(map[int]JSONPort)
		for _, p := range h2.Ports {
			ports2[p.Port] = p
		}

		// Ports closed since last scan.
		for port, p1 := range ports1 {
			if p1.State != stateOpen {
				continue
			}
			p2, exists := ports2[port]
			if !exists || p2.State != stateOpen {
				report.Changes = append(report.Changes, DiffChange{Type: "CLOSED_PORT", IP: ip, Port: port, Before: p1.Service})
				report.Summary.ClosedPorts++
			}
		}

		// New ports or changed banners since last scan.
		for port, p2 := range ports2 {
			if p2.State != stateOpen {
				continue
			}
			p1, exists := ports1[port]
			if !exists || p1.State != stateOpen {
				report.Changes = append(report.Changes, DiffChange{Type: "NEW_PORT", IP: ip, Port: port, State: p2.State, After: p2.Service})
				report.Summary.NewPorts++
			} else if p1.Service != p2.Service {
				report.Changes = append(report.Changes, DiffChange{
					Type: "CHANGED_BANNER", IP: ip, Port: port,
					Before: p1.Service, After: p2.Service,
				})
				report.Summary.ChangedBanner++
			}
		}
	}

	// A hostname that now resolves elsewhere is one of the more security-relevant
	// perimeter changes there is (DNS repointing, subdomain takeover), and the
	// IP-keyed comparison above cannot see it: the old address just looks closed
	// and the new one looks new, with nothing tying the two together.
	names1 := hostnameIndex(scan1.Hosts)
	names2 := hostnameIndex(scan2.Hosts)
	var sharedNames []string
	for n := range names1 {
		if _, ok := names2[n]; ok {
			sharedNames = append(sharedNames, n)
		}
	}
	sort.Strings(sharedNames)
	for _, n := range sharedNames {
		before := strings.Join(names1[n], " ")
		after := strings.Join(names2[n], " ")
		if before == after {
			continue
		}
		report.Changes = append(report.Changes, DiffChange{
			Type: "HOSTNAME_MOVED", IP: after, Hostname: n, Before: before, After: after,
		})
		report.Summary.HostnamesMoved++
	}

	totalChanges := report.Summary.NewHosts + report.Summary.ClosedHosts +
		report.Summary.NewPorts + report.Summary.ClosedPorts + report.Summary.ChangedBanner +
		report.Summary.HostnamesMoved

	// Output.
	if strings.ToLower(outputFormat) == "json" {
		var out []byte
		out, err = json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error encoding diff: %v\n", err)
			return 1
		}
		if outFile != "" {
			writeErr := writeFileAtomic(outFile, func(w io.Writer) error {
				_, e := w.Write(out)
				return e
			})
			if writeErr != nil {
				fmt.Fprintf(os.Stderr, "[!] Error writing diff to %s: %v\n", outFile, writeErr)
				return 1
			}
			fmt.Printf("[+] Diff saved to: %s\n", outFile)
		} else {
			fmt.Println(string(out))
		}
	} else {
		// Human-readable diff.
		fmt.Printf("GoScan Diff Report\n")
		fmt.Printf("A: %s (target: %s, date: %s)\n", file1, scan1.Meta.Target, scan1.Meta.ScanDate)
		fmt.Printf("B: %s (target: %s, date: %s)\n\n", file2, scan2.Meta.Target, scan2.Meta.ScanDate)

		if totalChanges == 0 {
			fmt.Println("[=] No changes detected.")
		} else {
			for _, c := range report.Changes {
				switch c.Type {
				case "NEW_HOST":
					fmt.Printf("[+] NEW HOST     %s%s\n", c.IP, hostnameSuffix(c.Hostname))
				case "CLOSED_HOST":
					fmt.Printf("[-] CLOSED HOST  %s%s\n", c.IP, hostnameSuffix(c.Hostname))
				case "HOSTNAME_MOVED":
					fmt.Printf("[~] MOVED        %-18s %s  →  %s\n", c.Hostname, c.Before, c.After)
				case "NEW_PORT":
					fmt.Printf("[+] NEW PORT     %-18s %d/tcp   %s\n", c.IP, c.Port, c.After)
				case "CLOSED_PORT":
					fmt.Printf("[-] CLOSED PORT  %-18s %d/tcp   %s\n", c.IP, c.Port, c.Before)
				case "CHANGED_BANNER":
					fmt.Printf("[~] CHANGED      %-18s %d/tcp   %s  →  %s\n", c.IP, c.Port, c.Before, c.After)
				}
			}
			fmt.Printf("\nSummary: +%d hosts  -%d hosts  +%d ports  -%d ports  %d banner changes  %d hostnames moved\n",
				report.Summary.NewHosts, report.Summary.ClosedHosts,
				report.Summary.NewPorts, report.Summary.ClosedPorts, report.Summary.ChangedBanner,
				report.Summary.HostnamesMoved)
		}
	}

	if totalChanges > 0 {
		return 2
	}
	return 0
}

// ── Target / Port parsing ──────────────────────────────────────────────────────

func parseTarget(target string) ([]string, error) {
	if strings.Contains(target, "/") {
		return parseCIDR(target)
	}
	return []string{target}, nil
}

// targetSpec is one target exactly as the user wrote it, tagged with where it
// came from so an error can point at the offending line of a -iL file.
type targetSpec struct {
	text   string
	origin string // "file:line" for -iL entries; empty for command-line arguments
}

func (t targetSpec) errorf(format string, a ...any) error {
	msg := fmt.Sprintf(format, a...)
	if t.origin == "" {
		return errors.New(msg)
	}
	return fmt.Errorf("%s: %s", t.origin, msg)
}

type specKind int

const (
	specIP specKind = iota
	specCIDR
	specHostname
)

const (
	dnsResolveTimeout = 10 * time.Second
	dnsResolveWorkers = 16
)

// parseTargetSpecs expands target specs (IPs, CIDRs, hostnames) into one
// deduplicated IP list, plus the ip→hostnames mapping discovered on the way.
// Overlapping entries — a /24 plus a host inside it — are common in a target
// file, and scanning a host twice would double-count it in the totals and emit
// two entries in the report.
//
// Hostnames are resolved here, once, rather than being passed down to the probe
// paths as names. Dialing by name would re-resolve on every port probe, would
// scatter a round-robin name's ports across different machines, and would leave
// the host sorted as 0 by ipToUint32 — making output order nondeterministic and
// breaking the stable-output contract that diff mode depends on.
func parseTargetSpecs(specs []targetSpec) ([]string, map[string][]string, error) {
	kinds := make([]specKind, len(specs))
	var names []string
	nameSeen := make(map[string]bool)
	for i, spec := range specs {
		kind, err := classifyTargetSpec(spec.text)
		if err != nil {
			return nil, nil, spec.errorf("%s", err)
		}
		kinds[i] = kind
		if kind == specHostname && !nameSeen[spec.text] {
			nameSeen[spec.text] = true
			names = append(names, spec.text)
		}
	}

	resolved, resolveErrs := resolveHostnames(names)
	for i, spec := range specs {
		if kinds[i] == specHostname {
			if err := resolveErrs[spec.text]; err != nil {
				return nil, nil, spec.errorf("cannot resolve %q: %v", spec.text, err)
			}
		}
	}

	seen := make(map[string]bool)
	var ips []string
	hostnames := make(map[string][]string)
	add := func(ip string) {
		if !seen[ip] {
			seen[ip] = true
			ips = append(ips, ip)
		}
	}

	for i, spec := range specs {
		if kinds[i] == specHostname {
			for _, ip := range resolved[spec.text] {
				add(ip)
				hostnames[ip] = appendUnique(hostnames[ip], spec.text)
			}
			continue
		}
		expanded, err := parseTarget(spec.text)
		if err != nil {
			return nil, nil, spec.errorf("%s", err)
		}
		for _, ip := range expanded {
			add(ip)
		}
	}

	// Sorted so repeated runs emit an identical host record.
	for ip := range hostnames {
		sort.Strings(hostnames[ip])
	}
	return ips, hostnames, nil
}

func appendUnique(list []string, s string) []string {
	for _, existing := range list {
		if existing == s {
			return list
		}
	}
	return append(list, s)
}

// resolveHostnames looks up each name's IPv4 addresses concurrently, once per
// name. Errors are returned per name rather than aggregated so the caller can
// attribute a failure back to the target-file line that caused it.
func resolveHostnames(names []string) (map[string][]string, map[string]error) {
	out := make(map[string][]string, len(names))
	errs := make(map[string]error, len(names))
	if len(names) == 0 {
		return out, errs
	}

	workers := dnsResolveWorkers
	if len(names) < workers {
		workers = len(names)
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan string)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range jobs {
				ctx, cancel := context.WithTimeout(context.Background(), dnsResolveTimeout)
				addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", name)
				cancel()

				var ips []string
				for _, a := range addrs {
					if v4 := a.To4(); v4 != nil {
						ips = append(ips, v4.String())
					}
				}
				// DNS rotates round-robin answers between queries; sort so the scan
				// order and the resulting report are identical from run to run.
				sortIPsNumerically(ips)

				mu.Lock()
				switch {
				case err != nil:
					errs[name] = err
				case len(ips) == 0:
					errs[name] = errors.New("no IPv4 address")
				default:
					out[name] = ips
				}
				mu.Unlock()
			}
		}()
	}
	for _, n := range names {
		jobs <- n
	}
	close(jobs)
	wg.Wait()
	return out, errs
}

// readTargetFile reads an nmap-style target list (-iL): one or more targets per
// line, separated by whitespace or commas. Blank lines and "#" comments are
// ignored. A path of "-" reads from stdin.
//
// Each entry keeps its file:line origin so that a bad or unresolvable target is
// reported against the line that introduced it. Validation happens before the
// scan starts rather than at probe time: a typo in a list of thousands would
// otherwise become a phantom target that quietly reports as down, and the
// operator would never learn that a subnet went unscanned.
func readTargetFile(path string) ([]targetSpec, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}

	name := path
	if path == "-" {
		name = "<stdin>"
	}

	var specs []targetSpec
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for lineNo := 1; sc.Scan(); lineNo++ {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || unicode.IsSpace(r)
		})
		for _, field := range fields {
			specs = append(specs, targetSpec{
				text:   field,
				origin: fmt.Sprintf("%s:%d", name, lineNo),
			})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", name, err)
	}
	if len(specs) == 0 {
		return nil, fmt.Errorf("no targets found in %s", name)
	}
	return specs, nil
}

// classifyTargetSpec decides what a target is — an IPv4 address, an IPv4 CIDR,
// or a hostname — and rejects everything else.
//
// IPv6 is rejected explicitly: the scanner is IPv4-only throughout (ICMP echo
// via ipv4, and ipToUint32 sorting), and enumerating an IPv6 prefix would
// exhaust memory long before it produced a scannable host list.
func classifyTargetSpec(spec string) (specKind, error) {
	if spec == "" {
		return 0, errors.New("empty target")
	}
	if strings.Contains(spec, "://") {
		return 0, urlNotSupported(spec)
	}
	if strings.Contains(spec, "/") {
		ip, _, err := net.ParseCIDR(spec)
		if err != nil {
			// "example.com/status" is a URL missing its scheme, not a malformed
			// CIDR — say so rather than pointing the user at CIDR syntax. The
			// letter test keeps a genuinely bad CIDR ("10.0.0.0/33") out of this
			// branch: all-numeric labels are valid hostname syntax but nobody
			// means them as a name.
			if host := spec[:strings.IndexByte(spec, '/')]; containsLetter(host) && validateHostname(host) == nil {
				return 0, urlNotSupported(spec)
			}
			return 0, fmt.Errorf("invalid CIDR %q", spec)
		}
		if ip.To4() == nil {
			return 0, fmt.Errorf("IPv6 CIDR %q is not supported (IPv4 only)", spec)
		}
		return specCIDR, nil
	}
	if ip := net.ParseIP(spec); ip != nil {
		if ip.To4() == nil {
			return 0, fmt.Errorf("IPv6 address %q is not supported (IPv4 only)", spec)
		}
		return specIP, nil
	}
	// A spec with no letters in it is a malformed address, not a name: report
	// "10.0.0.300" as a bad IP rather than sending it to DNS and blaming the
	// resolver for the typo.
	if !containsLetter(spec) {
		return 0, fmt.Errorf("invalid IP address %q", spec)
	}
	if err := validateHostname(spec); err != nil {
		return 0, err
	}
	return specHostname, nil
}

func containsLetter(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}

// urlNotSupported reports a URL target, naming the bare hostname to use instead.
// A URL also implies a port, which would silently contradict -p; refusing is
// clearer than guessing which the operator meant.
func urlNotSupported(spec string) error {
	host := spec
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	if i := strings.LastIndexByte(host, '@'); i >= 0 { // strip user:pass@
		host = host[i+1:]
	}
	if i := strings.LastIndexByte(host, ':'); i >= 0 { // strip :8443
		host = host[:i]
	}
	if host == "" || validateHostname(host) != nil {
		return fmt.Errorf("URLs are not supported — use a bare hostname or IP instead of %q", spec)
	}
	return fmt.Errorf("URLs are not supported — use the hostname %q instead of %q", host, spec)
}

// validateHostname checks DNS name syntax (RFC 1123): dot-separated labels of
// letters, digits and hyphens, no leading or trailing hyphen, 63 bytes per
// label and 253 overall. Syntax only — resolution happens later.
func validateHostname(h string) error {
	name := strings.TrimSuffix(h, ".") // tolerate a fully-qualified trailing dot
	if name == "" {
		return fmt.Errorf("invalid target %q", h)
	}
	if len(name) > 253 {
		return fmt.Errorf("hostname %q is too long (max 253 characters)", h)
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return fmt.Errorf("invalid hostname %q (empty label)", h)
		}
		if len(label) > 63 {
			return fmt.Errorf("invalid hostname %q (label %q exceeds 63 characters)", h, label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid hostname %q (label %q starts or ends with a hyphen)", h, label)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
			default:
				return fmt.Errorf("invalid target %q", h)
			}
		}
	}
	return nil
}

func parseCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}

	ones, _ := ipnet.Mask.Size()
	switch {
	case ones == 32:
		return ips, nil
	case ones == 31:
		return ips, nil
	case len(ips) > 2:
		return ips[1 : len(ips)-1], nil
	default:
		return ips, nil
	}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func parsePorts(portStr string) ([]int, error) {
	seen := make(map[int]bool)
	var ports []int

	if portStr == "-" {
		for p := 1; p <= 65535; p++ {
			ports = append(ports, p)
		}
		return ports, nil
	}

	for _, r := range strings.Split(portStr, ",") {
		r = strings.TrimSpace(r)
		if strings.Contains(r, "-") {
			parts := strings.SplitN(r, "-", 2)
			start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("invalid port range: %s", r)
			}
			if start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range %s (must be 1-65535, start ≤ end)", r)
			}
			for p := start; p <= end; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		} else {
			p, err := strconv.Atoi(r)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", r)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("port %d out of range (1-65535)", p)
			}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}
	}
	return ports, nil
}
