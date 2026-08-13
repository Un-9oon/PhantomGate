package dns

import (
	"encoding/binary"
	"net"
	"testing"
)

// FuzzParseDNSName fuzzes the DNS name parser with arbitrary byte slices.
// Goal: find any panic, out-of-bounds, or infinite loop.
func FuzzParseDNSName(f *testing.F) {
	// Seed corpus: valid DNS names
	f.Add([]byte{3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0}, 0)
	f.Add([]byte{0}, 0)
	f.Add([]byte{}, 0)
	f.Add([]byte{0xC0, 0x0C}, 0) // compression pointer
	f.Add([]byte{4, 't', 'e', 's', 't', 0}, 0)
	// Malformed: label says 100 bytes but only 2 follow
	f.Add([]byte{100, 'a', 'b'}, 0)
	// Deeply nested compression pointer (potential loop)
	f.Add([]byte{0xC0, 0x00}, 0)
	// Compression pointer pointing beyond packet
	f.Add([]byte{0xC0, 0xFF}, 0)

	f.Fuzz(func(t *testing.T, data []byte, offset int) {
		if offset < 0 {
			offset = 0
		}
		if offset >= len(data)+1 {
			offset = 0
		}
		// Must not panic
		name, end := parseDNSName(data, offset)
		_ = name
		_ = end
	})
}

// FuzzForgeDNSResponse fuzzes the forged DNS response builder.
// Goal: no panics on arbitrary query bytes.
func FuzzForgeDNSResponse(f *testing.F) {
	p := &Poisoner{redirectIP: net.ParseIP("10.0.0.1").To4()}

	// Valid minimal query seed
	validQuery := []byte{
		0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		4, 't', 'e', 's', 't', 0, 0x00, 0x01, 0x00, 0x01,
	}
	f.Add(validQuery, uint16(0xABCD), 18)
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, uint16(0), 12)
	f.Add([]byte{}, uint16(0), 0)

	f.Fuzz(func(t *testing.T, query []byte, txnID uint16, queryEnd int) {
		if queryEnd < 0 {
			queryEnd = 0
		}
		if queryEnd > len(query) {
			queryEnd = len(query)
		}
		// Must not panic
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("forgeDNSResponse panicked: %v", r)
			}
		}()
		resp := p.forgeDNSResponse(query, txnID, queryEnd)
		_ = resp
	})
}

// FuzzBuildForgedPacket fuzzes the full packet builder.
// Goal: no panics, valid packet structure.
func FuzzBuildForgedPacket(f *testing.F) {
	p := &Poisoner{
		redirectIP: net.ParseIP("10.0.0.1").To4(),
		ifaceIndex: 1,
	}

	f.Add(
		[]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
		[]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		[]byte{8, 8, 8, 8},
		[]byte{192, 168, 1, 100},
		uint16(53), uint16(54321),
		[]byte("dns_payload"),
	)
	f.Add(
		[]byte{0, 0, 0, 0, 0, 0},
		[]byte{0, 0, 0, 0, 0, 0},
		[]byte{0, 0, 0, 0},
		[]byte{0, 0, 0, 0},
		uint16(0), uint16(0),
		[]byte{},
	)

	f.Fuzz(func(t *testing.T, dstMAC, srcMAC, srcIPb, dstIPb []byte, srcPort, dstPort uint16, payload []byte) {
		if len(dstMAC) < 6 || len(srcMAC) < 6 || len(srcIPb) < 4 || len(dstIPb) < 4 {
			return
		}
		dstMAC = dstMAC[:6]
		srcMAC = srcMAC[:6]
		srcIP := net.IP(srcIPb[:4])
		dstIP := net.IP(dstIPb[:4])

		defer func() {
			if r := recover(); r != nil {
				t.Errorf("buildForgedPacket panicked: %v", r)
			}
		}()
		pkt := p.buildForgedPacket(dstMAC, srcMAC, srcIP, dstIP, srcPort, dstPort, payload, 0, 20)
		_ = pkt
	})
}

// FuzzIPChecksum fuzzes the IP checksum function.
func FuzzIPChecksum(f *testing.F) {
	f.Add(make([]byte, 20))
	f.Add([]byte{0x45, 0x00, 0x00, 0x3c, 0x13, 0x37, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 192, 168, 1, 1, 192, 168, 1, 2})
	f.Add([]byte{})
	f.Add([]byte{0xFF})

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ipChecksum panicked: %v", r)
			}
		}()
		_ = checksumWords(data)
	})
}

// FuzzUDPChecksum fuzzes the UDP checksum with arbitrary IPs and segments.
func FuzzUDPChecksum(f *testing.F) {
	f.Add([]byte{8, 8, 8, 8}, []byte{192, 168, 1, 1}, []byte{0, 53, 0x01, 0x02, 0, 12, 0, 0, 'h', 'i'})
	f.Add([]byte{0, 0, 0, 0}, []byte{0, 0, 0, 0}, []byte{})

	f.Fuzz(func(t *testing.T, srcIPb, dstIPb, segment []byte) {
		if len(srcIPb) < 4 || len(dstIPb) < 4 {
			return
		}
		srcIP := net.IP(srcIPb[:4])
		dstIP := net.IP(dstIPb[:4])

		defer func() {
			if r := recover(); r != nil {
				t.Errorf("udpChecksum panicked: %v", r)
			}
		}()
		_ = udpChecksum(srcIP, dstIP, segment)
	})
}

// FuzzProcessPacket fuzzes the full packet processor with arbitrary Ethernet frames.
// Goal: no panic, no crash on malformed/truncated frames.
func FuzzProcessPacket(f *testing.F) {
	p := &Poisoner{
		iface:      "lo",
		redirectIP: net.ParseIP("10.0.0.1").To4(),
		targets:    map[string]bool{"example.com": true},
		sendFD:     -1,
	}

	// Valid Ethernet + IP + UDP + DNS query for "example.com"
	validPkt := buildValidDNSQueryPacket()
	f.Add(validPkt)
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x01, 0x02})
	f.Add(make([]byte, 42))
	f.Add(make([]byte, 1500))

	f.Fuzz(func(t *testing.T, packet []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("processPacket panicked on input len=%d: %v", len(packet), r)
			}
		}()
		p.processPacket(packet)
	})
}

// buildValidDNSQueryPacket constructs a valid Ethernet+IP+UDP+DNS query frame
// for "example.com" to use as a fuzz seed.
func buildValidDNSQueryPacket() []byte {
	// DNS query payload for "example.com" type A
	dnsPayload := []byte{
		0xAB, 0xCD,             // TxnID
		0x01, 0x00,             // Flags: standard query
		0x00, 0x01,             // Questions: 1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Ans/Auth/Add = 0
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		3, 'c', 'o', 'm', 0,
		0x00, 0x01, // Type A
		0x00, 0x01, // Class IN
	}

	udpLen := 8 + len(dnsPayload)
	ipLen := 20 + udpLen
	totalLen := 14 + ipLen
	pkt := make([]byte, totalLen)

	// Ethernet header
	copy(pkt[0:6], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})   // dst
	copy(pkt[6:12], []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF})  // src
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800)                 // IPv4

	// IP header
	ip := pkt[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen))
	ip[9] = 17 // UDP
	copy(ip[12:16], []byte{192, 168, 1, 100}) // src
	copy(ip[16:20], []byte{8, 8, 8, 8})       // dst (DNS server)
	binary.BigEndian.PutUint16(ip[10:12], checksumWords(ip[:20]))

	// UDP header
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[0:2], 54321) // src port
	binary.BigEndian.PutUint16(udp[2:4], 53)    // dst port
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], dnsPayload)

	return pkt
}
