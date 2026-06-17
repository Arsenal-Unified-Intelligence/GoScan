package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const version = "1.1"

const (
	defaultTimeout = 2 * time.Second
	defaultWorkers = 100
	defaultRetries = 1
	maxWorkers     = 10000
	connectTimeout = 1500 * time.Millisecond
	readTimeout    = 500 * time.Millisecond
	pingTimeout    = 2 * time.Second
	pingRetries    = 1
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

var discoveryPorts = []int{80, 443, 22, 21, 25, 3389, 8080, 8443}

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

	mu             sync.Mutex
	results        []ScanResult
	hostInfo       map[string]*HostInfo
	scanned        int64
	openPorts      int64
	filteredPorts  int64
	lastHostScan   sync.Map
	rttSamples     []time.Duration
	rttMu          sync.Mutex
	progressTicker *time.Ticker
	startTime      time.Time

	// for signal handler access
	outputFile   string
	outputFormat string
	isatty       bool
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

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "GoScan v%s - Fast & Smart Network Scanner\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <target>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Target:  Single IP (192.168.1.1) or CIDR (192.168.1.0/24)\n\n")
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
	}

	flag.Parse()

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

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: target is required\n")
		flag.Usage()
		os.Exit(1)
	}

	target := flag.Arg(0)

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
		rttSamples:   make([]time.Duration, 0, 100),
		startTime:    time.Now(),
		outputFile:   outFile,
		outputFormat: *outputFormat,
		isatty:       tty,
	}

	if !quietMode {
		printBanner(timing.Name, discTiming.Name, finalWorkers, finalTimeout, finalRetries)
	}

	ips, err := parseTarget(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error parsing target: %v\n", err)
		os.Exit(1)
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown: save partial results before exit.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Printf("\n\n[!] Scan interrupted — saving partial results...\n")
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

	if len(activeHosts) == 0 {
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
	var pingDeadline time.Duration
	switch {
	case totalIPs <= 10:
		pingDeadline = 30 * time.Second
	case totalIPs <= 64:
		pingDeadline = 45 * time.Second
	case totalIPs <= 256:
		pingDeadline = 90 * time.Second
	default:
		pingDeadline = 180 * time.Second
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
	semaphore := make(chan struct{}, 50)
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
		fmt.Printf("\r" + strings.Repeat(" ", 80) + "\r")
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

	// Use discovery timing for worker count.
	discWorkers := (s.discTiming.MinParallelism + s.discTiming.MaxParallelism) / 2
	if discWorkers < 10 {
		discWorkers = 10
	}

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
					if s.tcpProbe(ctx, job.ip, job.port) {
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

func (s *Scanner) tcpProbe(ctx context.Context, ip string, port int) bool {
	d := net.Dialer{Timeout: 1000 * time.Millisecond}
	conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return false
	}
	conn.Close()
	return true
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
					s.lastHostScan.Store(job.ip, time.Now())
					if s.timing.ScanDelay > 0 {
						time.Sleep(s.timing.ScanDelay)
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

func (s *Scanner) scanPort(ctx context.Context, ip string, port int, grabBanner bool) {
	defer atomic.AddInt64(&s.scanned, 1)

	timeout := s.timeout
	if s.aggressive {
		timeout = timeout / 2
	}

	s.rttMu.Lock()
	if len(s.rttSamples) > 10 {
		avgRTT := s.calculateAvgRTT()
		adaptive := avgRTT * 3
		if adaptive > s.timing.MinRTT && adaptive < s.timing.MaxRTT {
			timeout = adaptive
		}
	}
	s.rttMu.Unlock()

	var conn net.Conn
	var err error
	var lastErr error

	for attempt := 0; attempt <= s.retries; attempt++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		d := net.Dialer{Timeout: timeout}
		t0 := time.Now()
		conn, err = d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", ip, port))
		rtt := time.Since(t0)

		if err == nil {
			s.rttMu.Lock()
			s.rttSamples = append(s.rttSamples, rtt)
			if len(s.rttSamples) > 100 {
				s.rttSamples = s.rttSamples[1:]
			}
			s.rttMu.Unlock()
			break
		}
		lastErr = err

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
		// Distinguish filtered (timeout) from closed (connection refused).
		if s.showFiltered && isTimeoutError(lastErr) {
			result := ScanResult{IP: ip, Port: port, State: stateFiltered}
			s.mu.Lock()
			s.results = append(s.results, result)
			s.mu.Unlock()
			atomic.AddInt64(&s.filteredPorts, 1)
		}
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

func (s *Scanner) calculateAvgRTT() time.Duration {
	if len(s.rttSamples) == 0 {
		return s.timing.InitialRTT
	}
	var total time.Duration
	for _, rtt := range s.rttSamples {
		total += rtt
	}
	return total / time.Duration(len(s.rttSamples))
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

func (s *Scanner) processBanner(data []byte, port int) string {
	banner := strings.TrimSpace(string(data))
	banner = strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			if r == '\n' || r == '\r' || r == '\t' {
				return ' '
			}
			return -1
		}
		return r
	}, banner)
	banner = strings.TrimSpace(strings.ReplaceAll(banner, "  ", " "))

	if strings.Contains(banner, "SSH-") {
		if idx := strings.Index(banner, "SSH-"); idx >= 0 {
			end := strings.IndexAny(banner[idx:], "\r\n ")
			if end > 0 {
				banner = banner[idx : idx+end]
			} else {
				banner = banner[idx:]
			}
		}
	} else if strings.Contains(banner, "HTTP") {
		if idx := strings.Index(banner, "Server:"); idx >= 0 {
			line := banner[idx:]
			if end := strings.IndexAny(line, "\r\n"); end > 0 {
				banner = strings.TrimSpace(line[:end])
			}
		} else if strings.HasPrefix(banner, "HTTP/") {
			parts := strings.Fields(banner)
			if len(parts) >= 3 {
				banner = parts[0] + " " + parts[1] + " " + parts[2]
			}
		}
	} else if strings.Contains(banner, "FTP") || strings.Contains(banner, "ProFTPD") || strings.Contains(banner, "vsftpd") {
		lines := strings.Split(banner, "\n")
		if len(lines) > 0 {
			banner = strings.TrimSpace(lines[0])
		}
	} else if strings.Contains(banner, "SMTP") || strings.Contains(banner, "ESMTP") {
		lines := strings.Split(banner, "\n")
		if len(lines) > 0 {
			banner = strings.TrimSpace(lines[0])
		}
	} else if port == 135 || port == 139 || port == 445 || port == 3389 || port == 389 {
		if len(banner) < 10 || strings.Count(banner, " ") > len(banner)/2 {
			if svc, ok := serviceNames[port]; ok {
				return svc
			}
		}
	}

	if len(banner) > 100 {
		banner = banner[:100] + "..."
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
	fmt.Printf("           https://github.com/RedLogicSecurity/GoScan\n")
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
			s.rttMu.Lock()
			avgRTT := s.calculateAvgRTT()
			s.rttMu.Unlock()
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
	rate := float64(scanned) / duration.Seconds()

	fmt.Printf("========================================================\n")
	fmt.Printf("[+] GoScan v%s done: %d ports in %.2fs (%.1f/s)\n", version, scanned, duration.Seconds(), rate)
	fmt.Printf("[i] Hosts up: %d | Open: %d | Filtered: %d | Closed: %d\n",
		hostsUp, openPorts, filteredPorts, scanned-openPorts-filteredPorts)
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
}

type JSONPort struct {
	Port    int    `json:"port"`
	State   string `json:"state"`
	Service string `json:"service,omitempty"`
}

type JSONHost struct {
	IP          string     `json:"ip"`
	Method      string     `json:"discovery_method,omitempty"`
	Fingerprint string     `json:"fingerprint"`
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
			Method:      method,
			Fingerprint: hostFingerprint(results),
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
			HostsDiscovered: hostsUp,
			TotalOpenPorts:  atomic.LoadInt64(&s.openPorts),
			TotalFiltered:   atomic.LoadInt64(&s.filteredPorts),
		},
		Hosts: hosts,
	}

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func (s *Scanner) saveResultsTXT(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

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

	fmt.Fprintf(f, "# GoScan v%s Results\n", version)
	fmt.Fprintf(f, "# Target: %s\n", s.target)
	fmt.Fprintf(f, "# Scan Date: %s\n\n", time.Now().Format(time.RFC3339))

	for _, ip := range ips {
		results := ipMap[ip]
		sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })

		s.mu.Lock()
		hInfo := s.hostInfo[ip]
		s.mu.Unlock()

		fmt.Fprintf(f, "Host: %s", ip)
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
}

func (s *Scanner) saveResultsCSV(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{"IP", "Port", "State", "Service", "Discovery Method", "Fingerprint"}); err != nil {
		return err
	}

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

		method := ""
		if hInfo != nil {
			method = hInfo.Method
		}
		fp := hostFingerprint(results)

		if len(results) == 0 {
			if err := w.Write([]string{ip, "-", "up", "no open ports", method, fp}); err != nil {
				return err
			}
		} else {
			for _, r := range results {
				svc := r.Banner
				if svc == "" {
					svc = "unknown"
				}
				if err := w.Write([]string{ip, strconv.Itoa(r.Port), r.State, svc, method, fp}); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ── Diff mode ─────────────────────────────────────────────────────────────────

type DiffChange struct {
	Type    string `json:"type"`    // NEW_HOST, CLOSED_HOST, NEW_PORT, CLOSED_PORT, CHANGED_BANNER
	IP      string `json:"ip"`
	Port    int    `json:"port,omitempty"`
	State   string `json:"state,omitempty"`
	Before  string `json:"before,omitempty"`
	After   string `json:"after,omitempty"`
}

type DiffReport struct {
	File1   JSONScanMeta `json:"scan_a"`
	File2   JSONScanMeta `json:"scan_b"`
	Changes []DiffChange `json:"changes"`
	Summary struct {
		NewHosts      int `json:"new_hosts"`
		ClosedHosts   int `json:"closed_hosts"`
		NewPorts      int `json:"new_ports"`
		ClosedPorts   int `json:"closed_ports"`
		ChangedBanner int `json:"changed_banners"`
	} `json:"summary"`
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
			report.Changes = append(report.Changes, DiffChange{Type: "NEW_HOST", IP: ip})
			report.Summary.NewHosts++
			for _, p := range h2.Ports {
				report.Changes = append(report.Changes, DiffChange{Type: "NEW_PORT", IP: ip, Port: p.Port, State: p.State, After: p.Service})
				report.Summary.NewPorts++
			}
			continue
		}
		if in1 && !in2 {
			report.Changes = append(report.Changes, DiffChange{Type: "CLOSED_HOST", IP: ip})
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

	totalChanges := report.Summary.NewHosts + report.Summary.ClosedHosts +
		report.Summary.NewPorts + report.Summary.ClosedPorts + report.Summary.ChangedBanner

	// Output.
	if strings.ToLower(outputFormat) == "json" {
		var out []byte
		out, err = json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error encoding diff: %v\n", err)
			return 1
		}
		if outFile != "" {
			if writeErr := os.WriteFile(outFile, out, 0644); writeErr != nil {
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
					fmt.Printf("[+] NEW HOST     %s\n", c.IP)
				case "CLOSED_HOST":
					fmt.Printf("[-] CLOSED HOST  %s\n", c.IP)
				case "NEW_PORT":
					fmt.Printf("[+] NEW PORT     %-18s %d/tcp   %s\n", c.IP, c.Port, c.After)
				case "CLOSED_PORT":
					fmt.Printf("[-] CLOSED PORT  %-18s %d/tcp   %s\n", c.IP, c.Port, c.Before)
				case "CHANGED_BANNER":
					fmt.Printf("[~] CHANGED      %-18s %d/tcp   %s  →  %s\n", c.IP, c.Port, c.Before, c.After)
				}
			}
			fmt.Printf("\nSummary: +%d hosts  -%d hosts  +%d ports  -%d ports  %d banner changes\n",
				report.Summary.NewHosts, report.Summary.ClosedHosts,
				report.Summary.NewPorts, report.Summary.ClosedPorts, report.Summary.ChangedBanner)
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
