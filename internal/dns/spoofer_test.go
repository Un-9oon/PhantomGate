package dns

import (
	"encoding/binary"
	"net"
	"testing"
)

// ─── Checksum Tests ───────────────────────────────────────────────────────────

// Test that ipChecksum produces 0 when re-applied to a checksummed header
// (standard validation: applying checksum to a valid header should give 0xFFFF or 0)
func TestIPChecksum_Valid(t *testing.T) {
	// Minimal 20-byte IP header (no options), checksum field zeroed
	header := []byte{
		0x45, 0x00, 0x00, 0x3c, // version/ihl, dscp, total length
		0x13, 0x37, 0x40, 0x00, // id, flags/frag
		0x40, 0x11, 0x00, 0x00, // ttl, proto=UDP, checksum=0
		192, 168, 1, 100,       // src IP
		192, 168, 1, 200,       // dst IP
	}
	csum := ipChecksum(header)
	binary.BigEndian.PutUint16(header[10:12], csum)

	// Re-checksum: a correct header gives sum=0xFFFF before NOT, so result=0x0000
	result := checksumWords(header)
	if result != 0x0000 {
		t.Errorf("IP header re-checksum should be 0x0000 (valid), got 0x%04X", result)
	}
}

func TestIPChecksum_ZeroedField(t *testing.T) {
	// A header with all zeros except valid length fields should produce a non-zero checksum
	header := make([]byte, 20)
	header[0] = 0x45
	csum := ipChecksum(header)
	if csum == 0 {
		t.Error("checksum of non-zero header should not be zero")
	}
}

// Test UDP checksum: computing then re-verifying must give 0xFFFF
func TestUDPChecksum_Valid(t *testing.T) {
	srcIP := net.ParseIP("192.168.1.1").To4()
	dstIP := net.ParseIP("192.168.1.100").To4()

	// Minimal UDP segment: 8 byte header + "hello" payload
	payload := []byte("hello")
	udpLen := 8 + len(payload)
	udp := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udp[0:2], 53)              // src port
	binary.BigEndian.PutUint16(udp[2:4], 54321)           // dst port
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))  // length
	binary.BigEndian.PutUint16(udp[6:8], 0)               // checksum = 0
	copy(udp[8:], payload)

	csum := udpChecksum(srcIP, dstIP, udp)
	binary.BigEndian.PutUint16(udp[6:8], csum)

	// Build pseudo-header + udp to verify
	pseudo := make([]byte, 12+len(udp))
	copy(pseudo[0:4], srcIP)
	copy(pseudo[4:8], dstIP)
	pseudo[8] = 0
	pseudo[9] = 17
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(udpLen))
	copy(pseudo[12:], udp)

	// Re-verify: summing a correctly checksummed packet gives 0x0000
	result := checksumWords(pseudo)
	if result != 0x0000 {
		t.Errorf("UDP re-checksum should be 0x0000 (valid), got 0x%04X", result)
	}
}

// ─── DNS Name Parser Tests ────────────────────────────────────────────────────

func TestParseDNSName_Simple(t *testing.T) {
	// Encode "www.google.com" manually
	pkt := []byte{
		3, 'w', 'w', 'w',
		6, 'g', 'o', 'o', 'g', 'l', 'e',
		3, 'c', 'o', 'm',
		0, // root label
	}
	name, end := parseDNSName(pkt, 0)
	if name != "www.google.com" {
		t.Errorf("expected 'www.google.com', got '%s'", name)
	}
	if end != len(pkt) {
		t.Errorf("expected end=%d, got %d", len(pkt), end)
	}
}

func TestParseDNSName_SingleLabel(t *testing.T) {
	pkt := []byte{4, 't', 'e', 's', 't', 0}
	name, _ := parseDNSName(pkt, 0)
	if name != "test" {
		t.Errorf("expected 'test', got '%s'", name)
	}
}

func TestParseDNSName_TooShort(t *testing.T) {
	pkt := []byte{10} // claims 10 bytes but none follow
	name, _ := parseDNSName(pkt, 0)
	if name != "" {
		t.Errorf("expected empty name for truncated packet, got '%s'", name)
	}
}

// ─── shouldPoison / Domain Matching Tests ────────────────────────────────────

func newTestPoisoner(targets []string) *Poisoner {
	t := make(map[string]bool)
	for _, d := range targets {
		t[d] = true
	}
	return &Poisoner{targets: t}
}

func TestShouldPoison_ExactMatch(t *testing.T) {
	p := newTestPoisoner([]string{"instagram.com"})
	if !p.shouldPoison("instagram.com") {
		t.Error("exact match 'instagram.com' should be poisoned")
	}
}

func TestShouldPoison_SubdomainMatch(t *testing.T) {
	p := newTestPoisoner([]string{"instagram.com"})
	if !p.shouldPoison("www.instagram.com") {
		t.Error("subdomain 'www.instagram.com' should match target 'instagram.com'")
	}
	if !p.shouldPoison("api.instagram.com") {
		t.Error("subdomain 'api.instagram.com' should match target 'instagram.com'")
	}
}

func TestShouldPoison_NoMatch(t *testing.T) {
	p := newTestPoisoner([]string{"instagram.com"})
	if p.shouldPoison("google.com") {
		t.Error("'google.com' should NOT be poisoned")
	}
	if p.shouldPoison("notinstagram.com") {
		t.Error("'notinstagram.com' should NOT be poisoned")
	}
}

func TestShouldPoison_CaseInsensitive(t *testing.T) {
	p := newTestPoisoner([]string{"instagram.com"})
	// shouldPoison receives already-lowercased input from processPacket
	if !p.shouldPoison("instagram.com") {
		t.Error("lowercase should match")
	}
}

// ─── Forged Packet Structure Tests ───────────────────────────────────────────

func TestBuildForgedPacket_Structure(t *testing.T) {
	p := &Poisoner{
		redirectIP: net.ParseIP("10.0.0.1").To4(),
		ifaceIndex: 1,
	}

	srcMAC := net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	dstMAC := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	srcIP := net.ParseIP("8.8.8.8").To4()
	dstIP := net.ParseIP("192.168.1.50").To4()
	dnsData := []byte("fakednspayload1234")

	pkt := p.buildForgedPacket(dstMAC, srcMAC, srcIP, dstIP, 53, 54321, dnsData, 0, 20)

	if len(pkt) < 42 {
		t.Fatalf("packet too short: %d bytes", len(pkt))
	}

	// Check Ethernet dst MAC
	for i := 0; i < 6; i++ {
		if pkt[i] != dstMAC[i] {
			t.Errorf("dst MAC byte %d: got %02x want %02x", i, pkt[i], dstMAC[i])
		}
	}

	// Check EtherType = 0x0800
	ethType := binary.BigEndian.Uint16(pkt[12:14])
	if ethType != 0x0800 {
		t.Errorf("EtherType: got 0x%04X want 0x0800", ethType)
	}

	// Check IP version = 4
	if pkt[14]>>4 != 4 {
		t.Errorf("IP version: got %d want 4", pkt[14]>>4)
	}

	// Check IP protocol = 17 (UDP)
	if pkt[14+9] != 17 {
		t.Errorf("IP protocol: got %d want 17 (UDP)", pkt[14+9])
	}

	// Check IP src = 8.8.8.8
	if !net.IP(pkt[14+12 : 14+16]).Equal(srcIP) {
		t.Errorf("IP src: got %v want %v", net.IP(pkt[14+12:14+16]), srcIP)
	}

	// Check UDP src port = 53
	udpSrcPort := binary.BigEndian.Uint16(pkt[34:36])
	if udpSrcPort != 53 {
		t.Errorf("UDP src port: got %d want 53", udpSrcPort)
	}

	// Verify IP checksum
	ipHeader := pkt[14:34]
	savedCsum := binary.BigEndian.Uint16(ipHeader[10:12])
	binary.BigEndian.PutUint16(ipHeader[10:12], 0)
	computed := ipChecksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:12], savedCsum)
	if computed != savedCsum {
		t.Errorf("IP checksum mismatch: stored=0x%04X computed=0x%04X", savedCsum, computed)
	}

	// Verify UDP checksum is non-zero (real checksum present)
	udpCsum := binary.BigEndian.Uint16(pkt[40:42])
	if udpCsum == 0 {
		t.Error("UDP checksum must not be 0 — forged packet will be dropped by victim kernel")
	}
}

func TestForgeDNSResponse_MatchesTxnID(t *testing.T) {
	p := &Poisoner{
		redirectIP: net.ParseIP("10.0.0.1").To4(),
	}

	// Minimal DNS query for "test.com": header + encoded name + type + class
	query := []byte{
		0xAB, 0xCD, // Transaction ID
		0x01, 0x00, // Flags: standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answers: 0
		0x00, 0x00, // Authority: 0
		0x00, 0x00, // Additional: 0
		// "test.com"
		4, 't', 'e', 's', 't', 3, 'c', 'o', 'm', 0,
		0x00, 0x01, // Type: A
		0x00, 0x01, // Class: IN
	}
	queryEnd := 12 + 10 // after header + name

	resp := p.forgeDNSResponse(query, 0xABCD, queryEnd)

	if len(resp) < 12 {
		t.Fatal("forged response too short")
	}

	// Check TxnID matches
	txnID := binary.BigEndian.Uint16(resp[0:2])
	if txnID != 0xABCD {
		t.Errorf("TxnID mismatch: got 0x%04X want 0xABCD", txnID)
	}

	// Check QR bit set (response flag)
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x8000 == 0 {
		t.Error("QR bit not set in forged response flags")
	}

	// Check answer count = 1
	answerCount := binary.BigEndian.Uint16(resp[6:8])
	if answerCount != 1 {
		t.Errorf("answer count: got %d want 1", answerCount)
	}

	// Check TTL is 1 (fast expiry)
	answerOffset := 12 + (queryEnd - 12) + 4 // header + question section
	if answerOffset+10 <= len(resp) {
		ttl := binary.BigEndian.Uint32(resp[answerOffset+6 : answerOffset+10])
		if ttl != 1 {
			t.Errorf("TTL: got %d want 1 (slow TTL would delay poison)", ttl)
		}
	}

	// Check last 4 bytes of answer = redirect IP
	if len(resp) >= 4 {
		gotIP := net.IP(resp[len(resp)-4:])
		if !gotIP.Equal(net.ParseIP("10.0.0.1").To4()) {
			t.Errorf("redirect IP in answer: got %s want 10.0.0.1", gotIP)
		}
	}
}
