package dns

import (
	"encoding/binary"
	"net"
	"testing"
)

// ─── Benchmarks ───────────────────────────────────────────────────────────────

func BenchmarkParseDNSName(b *testing.B) {
	pkt := []byte{
		3, 'w', 'w', 'w',
		6, 'g', 'o', 'o', 'g', 'l', 'e',
		3, 'c', 'o', 'm',
		0,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		parseDNSName(pkt, 0)
	}
}

func BenchmarkIPChecksum(b *testing.B) {
	header := []byte{
		0x45, 0x00, 0x00, 0x3c, 0x13, 0x37, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00, 192, 168, 1, 1, 192, 168, 1, 2,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ipChecksum(header)
	}
}

func BenchmarkUDPChecksum(b *testing.B) {
	srcIP := net.ParseIP("192.168.1.1").To4()
	dstIP := net.ParseIP("192.168.1.100").To4()
	segment := make([]byte, 512)
	binary.BigEndian.PutUint16(segment[0:2], 53)
	binary.BigEndian.PutUint16(segment[2:4], 54321)
	binary.BigEndian.PutUint16(segment[4:6], uint16(len(segment)))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		udpChecksum(srcIP, dstIP, segment)
	}
}

func BenchmarkForgeDNSResponse(b *testing.B) {
	p := &Poisoner{redirectIP: net.ParseIP("10.0.0.1").To4()}
	query := []byte{
		0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0x00, 0x01, 0x00, 0x01,
	}
	queryEnd := 25

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.forgeDNSResponse(query, 0xABCD, queryEnd)
	}
}

func BenchmarkBuildForgedPacket(b *testing.B) {
	p := &Poisoner{
		redirectIP: net.ParseIP("10.0.0.1").To4(),
		ifaceIndex: 1,
	}
	dstMAC := net.HardwareAddr{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	srcMAC := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	srcIP := net.ParseIP("8.8.8.8").To4()
	dstIP := net.ParseIP("192.168.1.50").To4()
	dnsData := make([]byte, 64)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.buildForgedPacket(dstMAC, srcMAC, srcIP, dstIP, 53, 54321, dnsData, 0, 20)
	}
}

func BenchmarkShouldPoison_Miss(b *testing.B) {
	p := newTestPoisoner([]string{
		"instagram.com", "facebook.com", "google.com",
		"microsoft.com", "twitter.com", "linkedin.com",
	})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.shouldPoison("notinlist.example.org")
	}
}

func BenchmarkShouldPoison_SubdomainHit(b *testing.B) {
	p := newTestPoisoner([]string{
		"instagram.com", "facebook.com", "google.com",
	})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.shouldPoison("www.instagram.com")
	}
}

func BenchmarkProcessPacket(b *testing.B) {
	p := &Poisoner{
		iface:      "lo",
		redirectIP: net.ParseIP("10.0.0.1").To4(),
		targets:    map[string]bool{"example.com": true},
		sendFD:     -1, // don't actually send
	}
	pkt := buildValidDNSQueryPacket()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.processPacket(pkt)
	}
}

// BenchmarkChecksumWords measures the core checksum primitive
func BenchmarkChecksumWords(b *testing.B) {
	data := make([]byte, 1500) // MTU-sized buffer
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checksumWords(data)
	}
}
