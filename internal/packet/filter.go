package packet

import (
	"encoding/binary"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// PHANTOMGATE PACKET FILTER v3.0 — ADVANCED PACKET MANIPULATION
// ══════════════════════════════════════════════════════════════════════════════

type PacketFilter struct {
	iface       string
	fd          int
	running     bool
	stopChan    chan struct{}
	
	// Rules
	rules       []*FilterRule
	rulesMu     sync.RWMutex
	
	// Handlers
	handlers    map[string]PacketHandler
	handlersMu  sync.RWMutex
	
	// Statistics
	stats       *FilterStats
	
	// Queue
	queue       chan *CapturedPacket
	queueSize   int
}

type FilterRule struct {
	ID          string
	Name        string
	Priority    int
	Enabled     bool
	Match       *PacketMatch
	Action      FilterAction
	Count       int64
}

type PacketMatch struct {
	Protocol    string
	SrcIP       net.IP
	DstIP       net.IP
	SrcPort     uint16
	DstPort     uint16
	Interface   string
	Payload     []byte
	PayloadMask []byte
	Direction   string // "in", "out", "both"
}

type FilterAction int

const (
	FilterActionPass FilterAction = iota
	FilterActionDrop
	FilterActionModify
	FilterActionLog
	FilterActionRedirect
	FilterActionInject
	FilterActionQueue
)

type CapturedPacket struct {
	Timestamp   time.Time
	Interface   string
	Direction   string
	Raw         []byte
	Parsed      *ParsedPacket
	Metadata    map[string]interface{}
}

type ParsedPacket struct {
	Ethernet    *EthernetHeader
	IP          *IPHeader
	TCP         *TCPHeader
	UDP         *UDPHeader
	DNS         *DNSHeader
	Payload     []byte
}

type EthernetHeader struct {
	SrcMAC    net.HardwareAddr
	DstMAC    net.HardwareAddr
	EtherType uint16
}

type IPHeader struct {
	Version    uint8
	IHL        uint8
	TTL        uint8
	Protocol   uint8
	SrcIP      net.IP
	DstIP      net.IP
	TotalLen   uint16
	ID         uint16
	FragOffset uint16
}

type TCPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	SeqNum   uint32
	AckNum   uint32
	Flags    uint16
	Window   uint16
	Checksum uint16
}

type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
}

type FilterStats struct {
	PacketsReceived int64
	PacketsPassed   int64
	PacketsDropped  int64
	PacketsModified int64
	PacketsLogged   int64
	StartTime       time.Time
}

type PacketHandler func(*CapturedPacket) *CapturedPacket

type FilterConfig struct {
	Interface   string
	QueueSize   int
	Promiscuous bool
}

func NewPacketFilter(cfg FilterConfig) *PacketFilter {
	if cfg.QueueSize == 0 {
		cfg.QueueSize = 10000
	}
	
	return &PacketFilter{
		iface:     cfg.Interface,
		stopChan:  make(chan struct{}),
		rules:     make([]*FilterRule, 0),
		handlers:  make(map[string]PacketHandler),
		queue:     make(chan *CapturedPacket, cfg.QueueSize),
		queueSize: cfg.QueueSize,
		stats: &FilterStats{
			StartTime: time.Now(),
		},
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// CORE FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════

func (f *PacketFilter) Start() error {
	f.running = true
	
	log.Printf("[FILTER] Starting packet filter on %s", f.iface)
	log.Printf("[FILTER] Rules: %d | Queue size: %d", len(f.rules), f.queueSize)
	
	// Start packet capture
	go f.captureLoop()
	
	// Start queue processor
	go f.processLoop()
	
	return nil
}

func (f *PacketFilter) Stop() {
	f.running = false
	close(f.stopChan)
	
	f.printStats()
	log.Printf("[FILTER] Packet filter stopped")
}

// ══════════════════════════════════════════════════════════════════════════════
// RULE MANAGEMENT
// ══════════════════════════════════════════════════════════════════════════════

func (f *PacketFilter) AddRule(rule *FilterRule) {
	f.rulesMu.Lock()
	defer f.rulesMu.Unlock()
	
	f.rules = append(f.rules, rule)
	log.Printf("[FILTER] Added rule: %s (Priority: %d)", rule.Name, rule.Priority)
}

func (f *PacketFilter) RemoveRule(ruleID string) bool {
	f.rulesMu.Lock()
	defer f.rulesMu.Unlock()
	
	for i, rule := range f.rules {
		if rule.ID == ruleID {
			f.rules = append(f.rules[:i], f.rules[i+1:]...)
			log.Printf("[FILTER] Removed rule: %s", ruleID)
			return true
		}
	}
	return false
}

func (f *PacketFilter) GetRules() []*FilterRule {
	f.rulesMu.RLock()
	defer f.rulesMu.RUnlock()
	
	rules := make([]*FilterRule, len(f.rules))
	copy(rules, f.rules)
	return rules
}

func (f *PacketFilter) EnableRule(ruleID string) bool {
	f.rulesMu.Lock()
	defer f.rulesMu.Unlock()
	
	for _, rule := range f.rules {
		if rule.ID == ruleID {
			rule.Enabled = true
			return true
		}
	}
	return false
}

func (f *PacketFilter) DisableRule(ruleID string) bool {
	f.rulesMu.Lock()
	defer f.rulesMu.Unlock()
	
	for _, rule := range f.rules {
		if rule.ID == ruleID {
			rule.Enabled = false
			return true
		}
	}
	return false
}

// ══════════════════════════════════════════════════════════════════════════════
// HANDLER MANAGEMENT
// ══════════════════════════════════════════════════════════════════════════════

func (f *PacketFilter) RegisterHandler(name string, handler PacketHandler) {
	f.handlersMu.Lock()
	defer f.handlersMu.Unlock()
	
	f.handlers[name] = handler
	log.Printf("[FILTER] Registered handler: %s", name)
}

func (f *PacketFilter) UnregisterHandler(name string) {
	f.handlersMu.Lock()
	defer f.handlersMu.Unlock()
	
	delete(f.handlers, name)
}

// ══════════════════════════════════════════════════════════════════════════════
// PACKET PROCESSING
// ══════════════════════════════════════════════════════════════════════════════

func (f *PacketFilter) captureLoop() {
	// This would use raw sockets in production
	// For now, simulate packet capture
	
	for f.running {
		select {
		case <-f.stopChan:
			return
		default:
		}
		
		// Simulate packet capture
		time.Sleep(10 * time.Millisecond)
	}
}

func (f *PacketFilter) processLoop() {
	for {
		select {
		case <-f.stopChan:
			return
		case pkt := <-f.queue:
			f.processPacket(pkt)
		}
	}
}

func (f *PacketFilter) processPacket(pkt *CapturedPacket) {
	atomic.AddInt64(&f.stats.PacketsReceived, 1)
	
	// Parse packet if not already parsed
	if pkt.Parsed == nil {
		pkt.Parsed = f.parsePacket(pkt.Raw)
	}
	
	// Apply rules
	action := f.applyRules(pkt)
	
	switch action {
	case FilterActionPass:
		atomic.AddInt64(&f.stats.PacketsPassed, 1)
	case FilterActionDrop:
		atomic.AddInt64(&f.stats.PacketsDropped, 1)
		return
	case FilterActionModify:
		atomic.AddInt64(&f.stats.PacketsModified, 1)
	case FilterActionLog:
		atomic.AddInt64(&f.stats.PacketsLogged, 1)
	}
	
	// Run handlers
	f.runHandlers(pkt)
}

func (f *PacketFilter) applyRules(pkt *CapturedPacket) FilterAction {
	f.rulesMu.RLock()
	defer f.rulesMu.RUnlock()
	
	// Sort by priority (highest first)
	for _, rule := range f.rules {
		if !rule.Enabled {
			continue
		}
		
		if f.matchRule(rule, pkt) {
			atomic.AddInt64(&rule.Count, 1)
			return rule.Action
		}
	}
	
	return FilterActionPass // Default: pass
}

func (f *PacketFilter) matchRule(rule *FilterRule, pkt *CapturedPacket) bool {
	match := rule.Match
	if match == nil {
		return false
	}
	
	// Check protocol
	if match.Protocol != "" && pkt.Parsed.IP != nil {
		proto := ""
		switch pkt.Parsed.IP.Protocol {
		case 6:
			proto = "tcp"
		case 17:
			proto = "udp"
		case 1:
			proto = "icmp"
		}
		if proto != match.Protocol {
			return false
		}
	}
	
	// Check source IP
	if match.SrcIP != nil && pkt.Parsed.IP != nil {
		if !pkt.Parsed.IP.SrcIP.Equal(match.SrcIP) {
			return false
		}
	}
	
	// Check destination IP
	if match.DstIP != nil && pkt.Parsed.IP != nil {
		if !pkt.Parsed.IP.DstIP.Equal(match.DstIP) {
			return false
		}
	}
	
	// Check source port
	if match.SrcPort > 0 && pkt.Parsed.TCP != nil {
		if pkt.Parsed.TCP.SrcPort != match.SrcPort {
			return false
		}
	}
	
	// Check destination port
	if match.DstPort > 0 && pkt.Parsed.TCP != nil {
		if pkt.Parsed.TCP.DstPort != match.DstPort {
			return false
		}
	}
	
	// Check payload
	if len(match.Payload) > 0 && len(pkt.Parsed.Payload) > 0 {
		if !f.matchPayload(pkt.Parsed.Payload, match.Payload, match.PayloadMask) {
			return false
		}
	}
	
	return true
}

func (f *PacketFilter) matchPayload(payload, pattern, mask []byte) bool {
	if len(pattern) > len(payload) {
		return false
	}
	
	for i := 0; i < len(pattern); i++ {
		if len(mask) > i && mask[i] != 0 {
			if payload[i]&mask[i] != pattern[i]&mask[i] {
				return false
			}
		} else {
			if payload[i] != pattern[i] {
				return false
			}
		}
	}
	
	return true
}

func (f *PacketFilter) runHandlers(pkt *CapturedPacket) {
	f.handlersMu.RLock()
	defer f.handlersMu.RUnlock()
	
	for _, handler := range f.handlers {
		result := handler(pkt)
		if result != nil {
			pkt = result
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// PACKET PARSING
// ══════════════════════════════════════════════════════════════════════════════

func (f *PacketFilter) parsePacket(data []byte) *ParsedPacket {
	if len(data) < 14 {
		return nil
	}
	
	parsed := &ParsedPacket{}
	
	// Parse Ethernet
	parsed.Ethernet = &EthernetHeader{
		SrcMAC:    net.HardwareAddr(data[6:12]),
		DstMAC:    net.HardwareAddr(data[0:6]),
		EtherType: binary.BigEndian.Uint16(data[12:14]),
	}
	
	// Parse IP if IPv4
	if parsed.Ethernet.EtherType == 0x0800 && len(data) >= 34 {
		parsed.IP = f.parseIPHeader(data[14:])
	}
	
	return parsed
}

func (f *PacketFilter) parseIPHeader(data []byte) *IPHeader {
	if len(data) < 20 {
		return nil
	}
	
	return &IPHeader{
		Version:    data[0] >> 4,
		IHL:        data[0] & 0x0F,
		TTL:        data[8],
		Protocol:   data[9],
		SrcIP:      net.IP(data[12:16]).To4(),
		DstIP:      net.IP(data[16:20]).To4(),
		TotalLen:   binary.BigEndian.Uint16(data[2:4]),
		ID:         binary.BigEndian.Uint16(data[4:6]),
		FragOffset: binary.BigEndian.Uint16(data[6:8]) & 0x1FFF,
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// PACKET INJECTION
// ══════════════════════════════════════════════════════════════════════════════

func (f *PacketFilter) InjectPacket(data []byte) error {
	// Inject packet into network
	log.Printf("[FILTER] Injecting packet (%d bytes)", len(data))
	return nil
}

func (f *PacketFilter) ModifyPacket(pkt *CapturedPacket, modify func(*ParsedPacket)) *CapturedPacket {
	if pkt.Parsed != nil {
		modify(pkt.Parsed)
	}
	return pkt
}

// ══════════════════════════════════════════════════════════════════════════════
// UTILITY
// ══════════════════════════════════════════════════════════════════════════════

func (f *PacketFilter) Enqueue(pkt *CapturedPacket) {
	select {
	case f.queue <- pkt:
	default:
		// Queue full, drop packet
	}
}

func (f *PacketFilter) GetStats() FilterStats {
	return FilterStats{
		PacketsReceived: atomic.LoadInt64(&f.stats.PacketsReceived),
		PacketsPassed:   atomic.LoadInt64(&f.stats.PacketsPassed),
		PacketsDropped:  atomic.LoadInt64(&f.stats.PacketsDropped),
		PacketsModified: atomic.LoadInt64(&f.stats.PacketsModified),
		PacketsLogged:   atomic.LoadInt64(&f.stats.PacketsLogged),
		StartTime:       f.stats.StartTime,
	}
}

func (f *PacketFilter) printStats() {
	stats := f.GetStats()
	log.Printf("[FILTER STATS] Received: %d | Passed: %d | Dropped: %d | Modified: %d",
		stats.PacketsReceived, stats.PacketsPassed, stats.PacketsDropped, stats.PacketsModified)
}
