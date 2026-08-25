package arp

import (
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"
)

// ══════════════════════════════════════════════════════════════════════════════
// PHANTOMGATE ARP SYSCALL HELPERS v3.0 — LOW-LEVEL NETWORK OPERATIONS
// ══════════════════════════════════════════════════════════════════════════════

const (
	ETH_P_ALL  = 0x0003
	ETH_P_IP   = 0x0800
	ETH_P_ARP  = 0x0806
)

// ══════════════════════════════════════════════════════════════════════════════
// RAW SOCKET OPERATIONS
// ══════════════════════════════════════════════════════════════════════════════

func openRawSocket(ifaceIndex int) (int, error) {
	fd, err := syscall.Socket(
		syscall.AF_PACKET,
		syscall.SOCK_RAW,
		int(htons(ETH_P_ALL)),
	)
	if err != nil {
		return -1, err
	}

	sa := syscall.SockaddrLinklayer{
		Protocol: htons(ETH_P_IP),
		Ifindex:  ifaceIndex,
	}

	if err := syscall.Bind(fd, &sa); err != nil {
		syscall.Close(fd)
		return -1, err
	}

	return fd, nil
}

func closeRawSocket(fd int) {
	if fd >= 0 {
		syscall.Close(fd)
	}
}

func sendOnSocket(fd, ifaceIndex int, packet []byte) error {
	addr := syscall.SockaddrLinklayer{
		Protocol: htons(ETH_P_IP),
		Ifindex:  ifaceIndex,
	}
	return syscall.Sendto(fd, packet, 0, &addr)
}

func recvFromSocket(fd int, buf []byte) (int, syscall.Sockaddr, error) {
	return syscall.Recvfrom(fd, buf, 0)
}

// ══════════════════════════════════════════════════════════════════════════════
// PACKET CONSTRUCTION
// ══════════════════════════════════════════════════════════════════════════════

func buildEthernetHeader(dstMAC, srcMAC []byte, etherType uint16) []byte {
	header := make([]byte, 14)
	copy(header[0:6], dstMAC)
	copy(header[6:12], srcMAC)
	binary.BigEndian.PutUint16(header[12:14], etherType)
	return header
}

func buildARPPacket(
	op uint16,
	senderMAC []byte,
	senderIP []byte,
	targetMAC []byte,
	targetIP []byte,
) []byte {
	packet := make([]byte, 28)

	// ARP Header
	binary.BigEndian.PutUint16(packet[0:2], 0x0001) // Hardware type (Ethernet)
	binary.BigEndian.PutUint16(packet[2:4], 0x0800) // Protocol type (IPv4)
	packet[4] = 6                                      // Hardware size (MAC)
	packet[5] = 4                                      // Protocol size (IP)
	binary.BigEndian.PutUint16(packet[6:8], op)

	// Sender
	copy(packet[8:14], senderMAC)
	copy(packet[14:18], senderIP)

	// Target
	copy(packet[18:24], targetMAC)
	copy(packet[24:28], targetIP)

	return packet
}

func buildARPRequest(senderMAC, senderIP, targetIP []byte) []byte {
	zeroMAC := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	return buildARPPacket(0x0001, senderMAC, senderIP, zeroMAC, targetIP)
}

func buildARPReply(senderMAC, senderIP, targetMAC, targetIP []byte) []byte {
	return buildARPPacket(0x0002, senderMAC, senderIP, targetMAC, targetIP)
}

func buildGratuitousARP(senderMAC, senderIP []byte) []byte {
	broadcastMAC := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	return buildARPPacket(0x0002, senderMAC, senderIP, broadcastMAC, senderIP)
}

func buildEthernetFrame(dstMAC, srcMAC []byte, payload []byte) []byte {
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], ETH_P_IP)
	copy(frame[14:], payload)
	return frame
}

// ══════════════════════════════════════════════════════════════════════════════
// PACKET PARSING
// ══════════════════════════════════════════════════════════════════════════════

type EthernetHeader struct {
	DstMAC    []byte
	SrcMAC    []byte
	EtherType uint16
}

type ARPHeader struct {
	HardwareType uint16
	ProtocolType uint16
	HardwareSize uint8
	ProtocolSize uint8
	Opcode       uint16
	SenderMAC    []byte
	SenderIP     []byte
	TargetMAC    []byte
	TargetIP     []byte
}

type IPHeader struct {
	Version    uint8
	IHL        uint8
	DSCP       uint8
	ECN        uint8
	TotalLen   uint16
	ID         uint16
	Flags      uint16
	FragOffset uint16
	TTL        uint8
	Protocol   uint8
	Checksum   uint16
	SrcIP      net.IP
	DstIP      net.IP
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
	NSCount uint16
	ARCount uint16
}

func parseEthernetHeader(data []byte) (*EthernetHeader, error) {
	if len(data) < 14 {
		return nil, ErrPacketTooShort
	}

	return &EthernetHeader{
		DstMAC:    data[0:6],
		SrcMAC:    data[6:12],
		EtherType: binary.BigEndian.Uint16(data[12:14]),
	}, nil
}

func parseARPHeader(data []byte) (*ARPHeader, error) {
	if len(data) < 28 {
		return nil, ErrPacketTooShort
	}

	return &ARPHeader{
		HardwareType: binary.BigEndian.Uint16(data[0:2]),
		ProtocolType: binary.BigEndian.Uint16(data[2:4]),
		HardwareSize: data[4],
		ProtocolSize: data[5],
		Opcode:       binary.BigEndian.Uint16(data[6:8]),
		SenderMAC:    data[8:14],
		SenderIP:     data[14:18],
		TargetMAC:    data[18:24],
		TargetIP:     data[24:28],
	}, nil
}

func parseIPHeader(data []byte) (*IPHeader, error) {
	if len(data) < 20 {
		return nil, ErrPacketTooShort
	}

	version := data[0] >> 4
	if version != 4 {
		return nil, ErrNotIPv4
	}

	ihl := int(data[0]&0x0f) * 4
	if len(data) < ihl {
		return nil, ErrPacketTooShort
	}

	return &IPHeader{
		Version:    version,
		IHL:        uint8(ihl),
		DSCP:       data[1] >> 2,
		ECN:        data[1] & 0x03,
		TotalLen:   binary.BigEndian.Uint16(data[2:4]),
		ID:         binary.BigEndian.Uint16(data[4:6]),
		Flags:      binary.BigEndian.Uint16(data[6:8]) >> 13,
		FragOffset: binary.BigEndian.Uint16(data[6:8]) & 0x1FFF,
		TTL:        data[8],
		Protocol:   data[9],
		Checksum:   binary.BigEndian.Uint16(data[10:12]),
		SrcIP:      net.IP(data[12:16]).To4(),
		DstIP:      net.IP(data[16:20]).To4(),
	}, nil
}

func parseUDPHeader(data []byte) (*UDPHeader, error) {
	if len(data) < 8 {
		return nil, ErrPacketTooShort
	}

	return &UDPHeader{
		SrcPort:  binary.BigEndian.Uint16(data[0:2]),
		DstPort:  binary.BigEndian.Uint16(data[2:4]),
		Length:   binary.BigEndian.Uint16(data[4:6]),
		Checksum: binary.BigEndian.Uint16(data[6:8]),
	}, nil
}

func parseDNSHeader(data []byte) (*DNSHeader, error) {
	if len(data) < 12 {
		return nil, ErrPacketTooShort
	}

	return &DNSHeader{
		ID:      binary.BigEndian.Uint16(data[0:2]),
		Flags:   binary.BigEndian.Uint16(data[2:4]),
		QDCount: binary.BigEndian.Uint16(data[4:6]),
		ANCount: binary.BigEndian.Uint16(data[6:8]),
		NSCount: binary.BigEndian.Uint16(data[8:10]),
		ARCount: binary.BigEndian.Uint16(data[10:12]),
	}, nil
}

// ══════════════════════════════════════════════════════════════════════════════
// CHECKSUM FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════

func calculateChecksum(data []byte) uint16 {
	var sum uint32

	// Sum all 16-bit words
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}

	// Add odd byte if present
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}

	// Fold 32-bit sum to 16 bits
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}

	return ^uint16(sum)
}

func calculateIPChecksum(header []byte) uint16 {
	// Zero out checksum field
	header[10] = 0
	header[11] = 0

	return calculateChecksum(header)
}

func calculateUDPChecksum(srcIP, dstIP net.IP, udpData []byte) uint16 {
	// Build pseudo-header
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[8] = 0
	pseudoHeader[9] = 17 // UDP protocol
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(udpData)))

	// Combine pseudo-header and UDP data
	data := append(pseudoHeader, udpData...)

	return calculateChecksum(data)
}

// ══════════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════

func htons(n int) uint16 {
	return uint16((n >> 8) | (n << 8))
}

func ntohs(n uint16) uint16 {
	return htons(int(n))
}

func macToString(mac []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func stringToMAC(s string) ([]byte, error) {
	return net.ParseMAC(s)
}

func ipToString(ip []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func stringToIP(s string) ([]byte, error) {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return nil, ErrInvalidIP
	}
	return ip, nil
}

// ══════════════════════════════════════════════════════════════════════════════
// FILE AND COMMAND OPERATIONS
// ══════════════════════════════════════════════════════════════════════════════

func exec_readFile(path string) ([]byte, error) {
	data, err := exec.Command("cat", path).Output()
	if err != nil {
		return nil, err
	}
	return data, nil
}

func exec_runCommand(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}

func exec_commandOutput(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).Output()
}

// ══════════════════════════════════════════════════════════════════════════════
// ERRORS
// ══════════════════════════════════════════════════════════════════════════════

var (
	ErrPacketTooShort = fmt.Errorf("packet too short")
	ErrNotIPv4        = fmt.Errorf("not an IPv4 packet")
	ErrInvalidIP      = fmt.Errorf("invalid IP address")
	ErrInvalidMAC     = fmt.Errorf("invalid MAC address")
	ErrSocketFailed   = fmt.Errorf("failed to create raw socket")
)

// ══════════════════════════════════════════════════════════════════════════════
// ADVANCED PACKET OPERATIONS
// ══════════════════════════════════════════════════════════════════════════════

func buildDNSResponse(
	queryID uint16,
	queryName string,
	queryType uint16,
	redirectIP []byte,
	ttl uint32,
) []byte {
	// Build DNS response
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], queryID)
	binary.BigEndian.PutUint16(header[2:4], 0x8180) // Response, Authoritative
	binary.BigEndian.PutUint16(header[4:6], 1)       // Questions
	binary.BigEndian.PutUint16(header[6:8], 1)       // Answers
	binary.BigEndian.PutUint16(header[8:10], 0)      // Authority
	binary.BigEndian.PutUint16(header[10:12], 0)     // Additional

	// Query section
	query := makeDNSQuery(queryName, queryType)

	// Answer section
	answer := make([]byte, 16)
	binary.BigEndian.PutUint16(answer[0:2], 0xC00C) // Pointer to query
	binary.BigEndian.PutUint16(answer[2:4], 1)      // Type A
	binary.BigEndian.PutUint16(answer[4:6], 1)      // Class IN
	binary.BigEndian.PutUint32(answer[6:10], ttl)
	binary.BigEndian.PutUint16(answer[10:12], 4)    // Data length
	copy(answer[12:16], redirectIP)

	// Combine all parts
	response := make([]byte, 0, 12+len(query)+16)
	response = append(response, header...)
	response = append(response, query...)
	response = append(response, answer...)

	return response
}

func makeDNSQuery(name string, queryType uint16) []byte {
	var query []byte

	// Encode domain name
	labels := strings.Split(name, ".")
	for _, label := range labels {
		query = append(query, byte(len(label)))
		query = append(query, []byte(label)...)
	}
	query = append(query, 0) // Root label

	// Query type and class
	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, queryType)
	query = append(query, typeBytes...)

	classBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(classBytes, 1) // Class IN
	query = append(query, classBytes...)

	return query
}

func parseDNSName(data []byte, offset int) (string, int) {
	var name []string
	pos := offset

	for pos < len(data) {
		length := int(data[pos])
		if length == 0 {
			pos++
			break
		}

		// Compression pointer
		if length&0xC0 == 0xC0 {
			if pos+1 >= len(data) {
				return "", -1
			}
			pointer := int(binary.BigEndian.Uint16(data[pos:pos+2])) & 0x3FFF
			return strings.Join(name, "."), pointer
		}

		pos++
		if pos+length > len(data) {
			return "", -1
		}

		name = append(name, string(data[pos:pos+length]))
		pos += length
	}

	return strings.Join(name, "."), pos
}

// ══════════════════════════════════════════════════════════════════════════════
// PACKET INJECTION
// ══════════════════════════════════════════════════════════════════════════════

func injectPacket(fd, ifaceIndex int, packet []byte) error {
	return sendOnSocket(fd, ifaceIndex, packet)
}

func injectARPReply(fd, ifaceIndex int, dstMAC, srcMAC, senderIP, targetIP []byte) error {
	ethHeader := buildEthernetHeader(dstMAC, srcMAC, ETH_P_ARP)
	arpPayload := buildARPReply(srcMAC, senderIP, dstMAC, targetIP)
	packet := append(ethHeader, arpPayload...)

	return injectPacket(fd, ifaceIndex, packet)
}

func injectARPRequest(fd, ifaceIndex int, srcMAC, srcIP, dstIP []byte) error {
	broadcastMAC := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	ethHeader := buildEthernetHeader(broadcastMAC, srcMAC, ETH_P_ARP)
	arpPayload := buildARPRequest(srcMAC, srcIP, dstIP)
	packet := append(ethHeader, arpPayload...)

	return injectPacket(fd, ifaceIndex, packet)
}

// ══════════════════════════════════════════════════════════════════════════════
// FRAGMENTATION SUPPORT
// ══════════════════════════════════════════════════════════════════════════════

func fragmentIPPacket(packet []byte, maxFragmentSize int) [][]byte {
	if len(packet) <= maxFragmentSize {
		return [][]byte{packet}
	}

	// Parse IP header
	if len(packet) < 20 {
		return nil
	}

	ihl := int(packet[0]&0x0f) * 4
	payload := packet[ihl:]

	var fragments [][]byte
	offset := 0

	for offset < len(payload) {
		fragLen := maxFragmentSize
		if offset+fragLen > len(payload) {
			fragLen = len(payload) - offset
		}

		// Build fragment
		fragHeader := make([]byte, 20)
		copy(fragHeader, packet[:20])

		// Update fragment offset and MF flag
		fragOffset := offset / 8
		flags := uint16(fragOffset) << 3
		if offset+fragLen < len(payload) {
			flags |= 0x2000 // More Fragments flag
		}
		binary.BigEndian.PutUint16(fragHeader[6:8], flags)

		// Update total length
		fragTotalLen := ihl + fragLen
		binary.BigEndian.PutUint16(fragHeader[2:4], uint16(fragTotalLen))

		// Calculate checksum
		fragHeader[10] = 0
		fragHeader[11] = 0
		checksum := calculateChecksum(fragHeader)
		binary.BigEndian.PutUint16(fragHeader[10:12], checksum)

		// Build fragment
		fragment := make([]byte, fragTotalLen)
		copy(fragment, fragHeader)
		copy(fragment[ihl:], payload[offset:offset+fragLen])

		fragments = append(fragments, fragment)
		offset += fragLen
	}

	return fragments
}
