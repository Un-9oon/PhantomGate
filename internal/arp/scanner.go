package arp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// PHANTOMGATE NETWORK SCANNER v3.0 — NETWORK DISCOVERY & RECONNAISSANCE
// ══════════════════════════════════════════════════════════════════════════════

type NetworkScanner struct {
	iface       *net.Interface
	ifaceName   string
	attackerIP  net.IP
	attackerMAC net.HardwareAddr
	subnet      *net.IPNet
	fd          int
	
	// Discovered hosts
	hosts       map[string]*DiscoveredHost
	hostsMu     sync.RWMutex
	
	// Services
	services    map[string]*ARPScannerServiceInfo
	servicesMu  sync.RWMutex
	
	// Statistics
	stats       *ScanStats
	
	// Configuration
	config      *ARPScannerConfig
}

type DiscoveredHost struct {
	IP          net.IP
	MAC         net.HardwareAddr
	Hostname    string
	Vendor      string
	OS          string
	Status      ARPScannerHostStatus
	Ports       map[int]*ARPScannerPortInfo
	Services    []string
	TTL         uint8
	Speed       string
	FirstSeen   time.Time
	LastSeen    time.Time
	PingCount   int
}

type ARPScannerHostStatus int

const (
	ARPScannerHostUnknown ARPScannerHostStatus = iota
	ARPScannerHostAlive
	ARPScannerHostDead
	ARPScannerHostFirewalled
)

type ARPScannerPortInfo struct {
	Port     int
	State    ARPScannerPortState
	Service  string
	Version  string
	Banner   string
}

type ARPScannerPortState int

const (
	ARPScannerPortClosed ARPScannerPortState = iota
	ARPScannerPortOpen
	ARPScannerPortFiltered
)

type ARPScannerServiceInfo struct {
	Name     string
	Port     int
	Protocol string
	Version  string
}

type ScanStats struct {
	HostsScanned   int64
	HostsAlive     int64
	PortsScanned   int64
	PortsOpen      int64
	StartTime      time.Time
}

type ARPScannerConfig struct {
	Mode           string
	Ports          []int
	Rate           int
	Timeout        time.Duration
	PingBeforeScan bool
	OSDetection    bool
	ServiceDetect  bool
}

var DefaultPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
	443, 445, 993, 995, 1723, 3389, 5900, 8080, 8443,
}

var WellKnownServices = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
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
	8080:  "HTTP-Alt",
	8443:  "HTTPS-Alt",
	27017: "MongoDB",
}

var MACVendorPrefixes = map[string]string{
	"00:50:56": "VMware",
	"00:0C:29": "VMware",
	"00:1C:42": "Parallels",
	"08:00:27": "VirtualBox",
	"52:54:00": "QEMU/KVM",
	"00:16:3E": "Xen",
	"B8:27:EB": "Raspberry Pi",
	"DC:A6:32": "Raspberry Pi",
	"00:1A:79": "Cisco",
	"00:1B:21": "Cisco",
	"00:26:0B": "Cisco",
	"FC:FB:FB": "Apple",
	"00:17:F2": "Apple",
	"AC:BC:32": "Apple",
	"00:1D:4F": "Dell",
	"00:14:22": "Dell",
	"F8:BC:12": "Dell",
	"00:15:5D": "Hyper-V",
	"00:1D:D8": "Microsoft",
}

func NewNetworkScanner(iface string) (*NetworkScanner, error) {
	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface '%s' not found: %w", iface, err)
	}

	addrs, err := netIface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get interface addresses: %w", err)
	}

	var attackerIP net.IP
	var subnet *net.IPNet
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			attackerIP = ipNet.IP.To4()
			subnet = ipNet
			break
		}
	}
	if attackerIP == nil {
		return nil, fmt.Errorf("no IPv4 address found on interface %s", iface)
	}

	return &NetworkScanner{
		iface:       netIface,
		ifaceName:   iface,
		attackerIP:  attackerIP,
		attackerMAC: netIface.HardwareAddr,
		subnet:      subnet,
		fd:          -1,
		hosts:       make(map[string]*DiscoveredHost),
		services:    make(map[string]*ARPScannerServiceInfo),
		stats: &ScanStats{
			StartTime: time.Now(),
		},
		config: &ARPScannerConfig{
			Mode:           "quick",
			Ports:          DefaultPorts,
			Rate:           100,
			Timeout:        1 * time.Second,
			PingBeforeScan: true,
			OSDetection:    false,
			ServiceDetect:  true,
		},
	}, nil
}

func (s *NetworkScanner) SetConfig(cfg *ARPScannerConfig) {
	if cfg != nil {
		s.config = cfg
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// HOST DISCOVERY
// ══════════════════════════════════════════════════════════════════════════════

func (s *NetworkScanner) DiscoverHosts() []*DiscoveredHost {
	log.Printf("[SCANNER] Starting host discovery on %s", s.subnet)

	// ARP scan for local network
	s.arpScan()

	// Ping sweep for additional discovery
	if s.config.PingBeforeScan {
		s.pingSweep()
	}

	log.Printf("[SCANNER] Discovery complete: %d hosts found", len(s.hosts))
	return s.GetAliveHosts()
}

func (s *NetworkScanner) arpScan() {
	if s.subnet == nil {
		return
	}

	baseIP := s.subnet.IP.Mask(s.subnet.Mask).To4()
	ones, bits := s.subnet.Mask.Size()
	hostBits := bits - ones
	maxHosts := (1 << hostBits) - 2
	if maxHosts > 254 {
		maxHosts = 254
	}

	fd, err := openRawSocket(s.iface.Index)
	if err != nil {
		log.Printf("[SCANNER] Failed to open raw socket: %v", err)
		return
	}
	defer closeRawSocket(fd)

	for i := 1; i <= maxHosts; i++ {
		ip := make(net.IP, 4)
		copy(ip, baseIP)
		ip[3] = baseIP[3] + byte(i)

		if !s.subnet.Contains(ip) || ip.Equal(s.attackerIP) {
			continue
		}

		s.sendARPRequest(fd, ip)
		atomic.AddInt64(&s.stats.HostsScanned, 1)
		time.Sleep(time.Duration(1000/s.config.Rate) * time.Millisecond)
	}

	// Wait for replies
	time.Sleep(1 * time.Second)
	s.readARPTable()
}

func (s *NetworkScanner) pingSweep() {
	if s.subnet == nil {
		return
	}

	baseIP := s.subnet.IP.Mask(s.subnet.Mask).To4()
	ones, bits := s.subnet.Mask.Size()
	hostBits := bits - ones
	maxHosts := (1 << hostBits) - 2
	if maxHosts > 254 {
		maxHosts = 254
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 50) // Limit concurrency

	for i := 1; i <= maxHosts; i++ {
		ip := make(net.IP, 4)
		copy(ip, baseIP)
		ip[3] = baseIP[3] + byte(i)

		if !s.subnet.Contains(ip) || ip.Equal(s.attackerIP) {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(ip net.IP) {
			defer wg.Done()
			defer func() { <-sem }()

			if s.pingHost(ip) {
				s.addHost(ip, ARPScannerHostAlive)
			}
		}(ip)
	}

	wg.Wait()
}

func (s *NetworkScanner) pingHost(ip net.IP) bool {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", ip.String())
	return cmd.Run() == nil
}

func (s *NetworkScanner) readARPTable() {
	data, err := exec.Command("cat", "/proc/net/arp").Output()
	if err != nil {
		return
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		ip := net.ParseIP(fields[0]).To4()
		if ip == nil || ip.Equal(s.attackerIP) {
			continue
		}

		mac, err := net.ParseMAC(fields[3])
		if err != nil || mac.String() == "00:00:00:00:00:00" {
			continue
		}

		s.addHostWithMAC(ip, mac, ARPScannerHostAlive)
	}
}

func (s *NetworkScanner) addHost(ip net.IP, status ARPScannerHostStatus) {
	s.hostsMu.Lock()
	defer s.hostsMu.Unlock()

	if _, exists := s.hosts[ip.String()]; !exists {
		s.hosts[ip.String()] = &DiscoveredHost{
			IP:        ip,
			Status:    status,
			Ports:     make(map[int]*ARPScannerPortInfo),
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		atomic.AddInt64(&s.stats.HostsAlive, 1)
	} else {
		s.hosts[ip.String()].LastSeen = time.Now()
		s.hosts[ip.String()].Status = status
	}
}

func (s *NetworkScanner) addHostWithMAC(ip net.IP, mac net.HardwareAddr, status ARPScannerHostStatus) {
	s.hostsMu.Lock()
	defer s.hostsMu.Unlock()

	if _, exists := s.hosts[ip.String()]; !exists {
		vendor := s.lookupVendor(mac)
		s.hosts[ip.String()] = &DiscoveredHost{
			IP:        ip,
			MAC:       mac,
			Vendor:    vendor,
			Status:    status,
			Ports:     make(map[int]*ARPScannerPortInfo),
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
		}
		atomic.AddInt64(&s.stats.HostsAlive, 1)
	} else {
		host := s.hosts[ip.String()]
		host.LastSeen = time.Now()
		host.Status = status
		if host.MAC == nil {
			host.MAC = mac
			host.Vendor = s.lookupVendor(mac)
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// PORT SCANNING
// ══════════════════════════════════════════════════════════════════════════════

func (s *NetworkScanner) ScanHost(targetIP net.IP, ports []int) *DiscoveredHost {
	log.Printf("[SCANNER] Scanning ports on %s...", targetIP)

	if ports == nil {
		ports = s.config.Ports
	}

	host := &DiscoveredHost{
		IP:    targetIP,
		Ports:     make(map[int]*ARPScannerPortInfo),
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, s.config.Rate)

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}

		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			info := s.scanPort(targetIP, port)
			if info != nil {
				host.Ports[port] = info
				atomic.AddInt64(&s.stats.PortsOpen, 1)
			}
			atomic.AddInt64(&s.stats.PortsScanned, 1)
		}(port)
	}

	wg.Wait()

	log.Printf("[SCANNER] Scan complete: %d open ports found on %s", len(host.Ports), targetIP)
	return host
}

func (s *NetworkScanner) scanPort(ip net.IP, port int) *ARPScannerPortInfo {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, s.config.Timeout)
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			return &ARPScannerPortInfo{Port: port, State: ARPScannerPortClosed}
		}
		return &ARPScannerPortInfo{Port: port, State: ARPScannerPortFiltered}
	}
	defer conn.Close()

	info := &ARPScannerPortInfo{
		Port:    port,
		State:   ARPScannerPortOpen,
		Service: s.getServiceName(port),
	}

	// Grab banner
	if s.config.ServiceDetect {
		banner := s.grabBanner(conn)
		if banner != "" {
			info.Banner = banner
			info.Version = s.detectVersion(banner)
		}
	}

	return info
}

func (s *NetworkScanner) grabBanner(conn net.Conn) string {
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Send HTTP request for web servers
	fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", conn.RemoteAddr())

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}

	return string(buf[:n])
}

func (s *NetworkScanner) detectVersion(banner string) string {
	bannerLower := strings.ToLower(banner)

	if strings.Contains(bannerLower, "apache") {
		if idx := strings.Index(banner, "Apache/"); idx >= 0 {
			end := strings.IndexAny(banner[idx:], " \r\n")
			if end > 0 {
				return banner[idx : idx+end]
			}
			return banner[idx:]
		}
		return "Apache"
	}

	if strings.Contains(bannerLower, "nginx") {
		if idx := strings.Index(banner, "nginx/"); idx >= 0 {
			end := strings.IndexAny(banner[idx:], " \r\n")
			if end > 0 {
				return banner[idx : idx+end]
			}
			return banner[idx:]
		}
		return "nginx"
	}

	if strings.Contains(bannerLower, "openssh") {
		if idx := strings.Index(banner, "OpenSSH_"); idx >= 0 {
			end := strings.IndexAny(banner[idx:], " \r\n")
			if end > 0 {
				return banner[idx : idx+end]
			}
			return banner[idx:]
		}
		return "OpenSSH"
	}

	if strings.Contains(bannerLower, "microsoft") || strings.Contains(bannerLower, "iis") {
		return "IIS"
	}

	return ""
}

func (s *NetworkScanner) getServiceName(port int) string {
	if service, ok := WellKnownServices[port]; ok {
		return service
	}
	return "Unknown"
}

// ══════════════════════════════════════════════════════════════════════════════
// OS FINGERPRINTING
// ══════════════════════════════════════════════════════════════════════════════

func (s *NetworkScanner) DetectOS(targetIP net.IP) string {
	// TTL-based OS detection
	ttl := s.getTTL(targetIP)
	if ttl == 0 {
		return "Unknown"
	}

	// Common TTL values
	switch {
	case ttl <= 64:
		return "Linux/Unix"
	case ttl <= 128:
		return "Windows"
	case ttl <= 255:
		return "Network Device"
	default:
		return "Unknown"
	}
}

func (s *NetworkScanner) getTTL(targetIP net.IP) uint8 {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", targetIP.String())
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	// Parse TTL from ping output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "ttl=") {
			parts := strings.Fields(line)
			for _, part := range parts {
				if strings.HasPrefix(part, "ttl=") {
					var ttl uint8
					fmt.Sscanf(strings.TrimPrefix(part, "ttl="), "%d", &ttl)
					return ttl
				}
			}
		}
	}

	return 0
}

// ══════════════════════════════════════════════════════════════════════════════
// NETWORK UTILITIES
// ══════════════════════════════════════════════════════════════════════════════

func (s *NetworkScanner) sendARPRequest(fd int, targetIP net.IP) {
	packet := make([]byte, 42)
	broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	// Ethernet header
	copy(packet[0:6], broadcastMAC)
	copy(packet[6:12], s.attackerMAC)
	binary.BigEndian.PutUint16(packet[12:14], 0x0806)

	// ARP header
	binary.BigEndian.PutUint16(packet[14:16], 0x0001) // Hardware type
	binary.BigEndian.PutUint16(packet[16:18], 0x0800) // Protocol type
	packet[18] = 6                                      // Hardware size
	packet[19] = 4                                      // Protocol size
	binary.BigEndian.PutUint16(packet[20:22], 0x0001) // Request

	// ARP payload
	copy(packet[22:28], s.attackerMAC)
	copy(packet[28:32], s.attackerIP.To4())
	copy(packet[32:38], []byte{0, 0, 0, 0, 0, 0})
	copy(packet[38:42], targetIP.To4())

	sendOnSocket(fd, s.iface.Index, packet)
}

func (s *NetworkScanner) lookupVendor(mac net.HardwareAddr) string {
	prefix := mac.String()[:8]
	if vendor, ok := MACVendorPrefixes[prefix]; ok {
		return vendor
	}
	return "Unknown"
}

// ══════════════════════════════════════════════════════════════════════════════
// OUTPUT FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════

func (s *NetworkScanner) GetAliveHosts() []*DiscoveredHost {
	s.hostsMu.RLock()
	defer s.hostsMu.RUnlock()

	var alive []*DiscoveredHost
	for _, host := range s.hosts {
		if host.Status == ARPScannerHostAlive {
			alive = append(alive, host)
		}
	}

	sort.Slice(alive, func(i, j int) bool {
		return bytesToUint32(alive[i].IP.To4()) < bytesToUint32(alive[j].IP.To4())
	})

	return alive
}

func (s *NetworkScanner) GetHostsByVendor(vendor string) []*DiscoveredHost {
	s.hostsMu.RLock()
	defer s.hostsMu.RUnlock()

	var hosts []*DiscoveredHost
	for _, host := range s.hosts {
		if strings.Contains(host.Vendor, vendor) {
			hosts = append(hosts, host)
		}
	}

	return hosts
}

func (s *NetworkScanner) GetHostsByOS(os string) []*DiscoveredHost {
	s.hostsMu.RLock()
	defer s.hostsMu.RUnlock()

	var hosts []*DiscoveredHost
	for _, host := range s.hosts {
		if strings.Contains(host.OS, os) {
			hosts = append(hosts, host)
		}
	}

	return hosts
}

func (s *NetworkScanner) PrintResults() {
	hosts := s.GetAliveHosts()

	fmt.Println("\n╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                   NETWORK SCAN RESULTS                      ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║ Scan Time: %s\n", s.stats.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Printf("║ Hosts Scanned: %d | Alive: %d\n", s.stats.HostsScanned, s.stats.HostsAlive)
	fmt.Printf("║ Ports Scanned: %d | Open: %d\n", s.stats.PortsScanned, s.stats.PortsOpen)
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")

	for _, host := range hosts {
		fmt.Printf("║ IP: %-16s MAC: %-17s Vendor: %s\n",
			host.IP, host.MAC, host.Vendor)
		if len(host.Ports) > 0 {
			fmt.Print("║   Ports: ")
			first := true
			for port, info := range host.Ports {
				if info.State == ARPScannerPortOpen {
					if !first {
						fmt.Print(", ")
					}
					fmt.Printf("%d/%s", port, info.Service)
					first = false
				}
			}
			fmt.Println()
		}
	}

	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
}

func bytesToUint32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func atomic_AddInt64(ptr *int64, val int64) {
	for {
		old := *ptr
		if compareAndSwapInt64(ptr, old, old+val) {
			return
		}
	}
}

func compareAndSwapInt64(ptr *int64, old, new int64) bool {
	// This is a simplified version - in real code use sync/atomic
	*ptr = new
	return true
}
