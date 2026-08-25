package arp

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// PHANTOMGATE PORT SCANNER v3.0 — ADVANCED PORT SCANNING
// ══════════════════════════════════════════════════════════════════════════════

type PortScanner struct {
	iface       string
	attackerIP  net.IP
	targets     []net.IP
	ports       []int
	rate        int
	timeout     time.Duration
	results     map[string]*ScanResult
	resultsMu   sync.RWMutex
	onResult    func(*ScanResult)
}

type ScanResult struct {
	Target     net.IP
	Port       int
	State      PortState
	Service    string
	Version    string
	Banner     string
	ScanTime   time.Duration
	Timestamp  time.Time
}

type PortState int

const (
	PortStateClosed PortState = iota
	PortStateOpen
	PortStateFiltered
)

type ScanMode int

const (
	ScanModeSYN ScanMode = iota
	ScanModeConnect
	ScanModeACK
	ScanModeFIN
	ScanModeXMAS
	ScanModeNULL
	ScanModeUDP
)

type ScanConfig struct {
	Mode        ScanMode
	Rate        int
	Timeout     time.Duration
	Ports       []int
	Services    bool
	BannerGrab  bool
}

var CommonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
	143, 443, 445, 993, 995, 1723, 3306, 3389,
	5432, 5900, 8080, 8443, 27017,
}

var TopPorts = []int{
	80, 443, 22, 21, 25, 53, 110, 135, 139, 143,
	445, 993, 995, 1723, 3306, 3389, 5432, 5900,
	8080, 8443, 27017, 2000, 5601, 9200, 11211,
}

var ServiceMap = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	111:   "RPCBind",
	135:   "MSRPC",
	139:   "NetBIOS",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB",
	993:   "IMAPS",
	995:   "POP3S",
	1433:  "MSSQL",
	1723:  "PPTP",
	3306:  "MySQL",
	3389:  "RDP",
	5432:  "PostgreSQL",
	5900:  "VNC",
	8080:  "HTTP-Proxy",
	8443:  "HTTPS-Alt",
	27017: "MongoDB",
	2000:  "Cisco-SCCP",
	5601:  "Kibana",
	9200:  "Elasticsearch",
	11211: "Memcached",
}

func NewPortScanner(cfg ScanConfig) *PortScanner {
	if cfg.Rate == 0 {
		cfg.Rate = 100
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 1 * time.Second
	}
	if len(cfg.Ports) == 0 {
		cfg.Ports = CommonPorts
	}

	return &PortScanner{
		ports:   cfg.Ports,
		rate:    cfg.Rate,
		timeout: cfg.Timeout,
		results: make(map[string]*ScanResult),
	}
}

func (s *PortScanner) SetTargets(targets []net.IP) {
	s.targets = targets
}

func (s *PortScanner) ScanTarget(target net.IP) []*ScanResult {
	var results []*ScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, s.rate)

	for _, port := range s.ports {
		wg.Add(1)
		sem <- struct{}{}

		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			start := time.Now()
			result := s.scanPort(target, port)
			result.ScanTime = time.Since(start)
			result.Timestamp = time.Now()

			mu.Lock()
			results = append(results, result)
			key := fmt.Sprintf("%s:%d", target, port)
			s.resultsMu.Lock()
			s.results[key] = result
			s.resultsMu.Unlock()
			mu.Unlock()

			if s.onResult != nil {
				s.onResult(result)
			}
		}(port)
	}

	wg.Wait()
	return results
}

func (s *PortScanner) ScanAll() map[string][]*ScanResult {
	allResults := make(map[string][]*ScanResult)

	for _, target := range s.targets {
		results := s.ScanTarget(target)
		allResults[target.String()] = results
	}

	return allResults
}

func (s *PortScanner) scanPort(target net.IP, port int) *ScanResult {
	result := &ScanResult{
		Target: target,
		Port:   port,
		State:  PortStateClosed,
	}

	addr := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", addr, s.timeout)
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			result.State = PortStateClosed
		} else if strings.Contains(err.Error(), "timeout") {
			result.State = PortStateFiltered
		} else {
			result.State = PortStateFiltered
		}
		return result
	}
	defer conn.Close()

	result.State = PortStateOpen
	result.Service = s.getService(port)

	return result
}

func (s *PortScanner) getService(port int) string {
	if service, ok := ServiceMap[port]; ok {
		return service
	}
	return "Unknown"
}

func (s *PortScanner) GetOpenPorts(target net.IP) []int {
	var openPorts []int

	s.resultsMu.RLock()
	defer s.resultsMu.RUnlock()

	for key, result := range s.results {
		if strings.HasPrefix(key, target.String()+":") && result.State == PortStateOpen {
			openPorts = append(openPorts, result.Port)
		}
	}

	return openPorts
}

func (s *PortScanner) GetResults() map[string]*ScanResult {
	s.resultsMu.RLock()
	defer s.resultsMu.RUnlock()

	results := make(map[string]*ScanResult)
	for k, v := range s.results {
		results[k] = v
	}
	return results
}

func (s *PortScanner) SetOnResult(fn func(*ScanResult)) {
	s.onResult = fn
}

func (s *PortScanner) PrintResults() {
	s.resultsMu.RLock()
	defer s.resultsMu.RUnlock()

	fmt.Println("\n╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                   PORT SCAN RESULTS                         ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")

	for _, result := range s.results {
		if result.State == PortStateOpen {
			fmt.Printf("║ %-16s | %-6d | %-12s | %s\n",
				result.Target, result.Port, result.Service, result.Version)
		}
	}

	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
}
