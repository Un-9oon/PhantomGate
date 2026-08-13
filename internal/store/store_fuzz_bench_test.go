package store

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// ─── Fuzz Tests ───────────────────────────────────────────────────────────────

// FuzzAddCredential fuzzes the store with arbitrary victim IDs and credential fields.
func FuzzAddCredential(f *testing.F) {
	f.Add("victim-1", "user@example.com", "password123", "192.168.1.1")
	f.Add("", "", "", "")
	f.Add("victim-\x00\x01", "user\nname", "pass\tword", "::1")
	f.Add(string(make([]byte, 1000)), "user", "pass", "127.0.0.1")

	f.Fuzz(func(t *testing.T, victimID, username, password, sourceIP string) {
		s := NewStore("")
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("AddCredential panicked: %v", r)
			}
		}()
		s.AddCredential(CapturedCredential{
			ID:        "fuzz-cred",
			VictimID:  victimID,
			Username:  username,
			Password:  password,
			SourceIP:  sourceIP,
			Timestamp: time.Now(),
		})
		_ = s.GetAllVictims()
		_ = s.GetStats()
	})
}

// FuzzGetVictim fuzzes GetVictim with arbitrary IDs (should never panic).
func FuzzGetVictim(f *testing.F) {
	f.Add("victim-1")
	f.Add("")
	f.Add("\x00")
	f.Add(string(make([]byte, 10000)))

	s := NewStore("")
	s.AddCredential(CapturedCredential{ID: "c1", VictimID: "victim-1", Timestamp: time.Now()})

	f.Fuzz(func(t *testing.T, id string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("GetVictim panicked on %q: %v", id, r)
			}
		}()
		_, _ = s.GetVictim(id)
	})
}

// ─── Extended Unit Tests ──────────────────────────────────────────────────────

// TestVictimIDIsolation ensures different victim IDs produce separate records.
func TestVictimIDIsolation(t *testing.T) {
	s := NewStore("")
	for i := 0; i < 5; i++ {
		s.AddCredential(CapturedCredential{
			ID:        fmt.Sprintf("c%d", i),
			VictimID:  fmt.Sprintf("victim-%d", i),
			Username:  fmt.Sprintf("user%d@test.com", i),
			Timestamp: time.Now(),
		})
	}
	victims := s.GetAllVictims()
	if len(victims) != 5 {
		t.Errorf("expected 5 isolated victims, got %d", len(victims))
	}
}

// TestSameVictimMultipleSessions ensures token aggregation works correctly.
func TestSameVictimMultipleSessions(t *testing.T) {
	s := NewStore("")
	s.AddSession(CapturedSession{
		ID: "s1", VictimID: "v1",
		Cookies:   map[string]string{"TOKEN_A": "val_a"},
		Timestamp: time.Now(), IsValid: true,
	})
	s.AddSession(CapturedSession{
		ID: "s2", VictimID: "v1",
		Cookies:   map[string]string{"TOKEN_B": "val_b"},
		Timestamp: time.Now(), IsValid: true,
	})

	v, ok := s.GetVictim("v1")
	if !ok {
		t.Fatal("victim not found")
	}
	if len(v.Sessions) != 2 {
		t.Errorf("expected 2 sessions, got %d", len(v.Sessions))
	}
	if v.Tokens["TOKEN_A"] != "val_a" {
		t.Errorf("TOKEN_A not aggregated, got %q", v.Tokens["TOKEN_A"])
	}
	if v.Tokens["TOKEN_B"] != "val_b" {
		t.Errorf("TOKEN_B not aggregated, got %q", v.Tokens["TOKEN_B"])
	}
}

// TestOnNewVictimChannel tests that the notification channel fires.
func TestOnNewVictimChannel(t *testing.T) {
	s := NewStore("")
	s.AddCredential(CapturedCredential{
		ID:       "c1",
		VictimID: "new-victim",
		Timestamp: time.Now(),
	})

	select {
	case v := <-s.OnNewVictim:
		if v.ID != "new-victim" {
			t.Errorf("expected new-victim, got %q", v.ID)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("OnNewVictim channel did not fire")
	}
}

// TestOnCredentialChannel tests the credential notification channel.
func TestOnCredentialChannel(t *testing.T) {
	s := NewStore("")
	cred := CapturedCredential{
		ID:       "c1",
		VictimID: "v1",
		Username: "notified@test.com",
		Timestamp: time.Now(),
	}
	s.AddCredential(cred)

	select {
	case received := <-s.OnCredential:
		if received.Username != "notified@test.com" {
			t.Errorf("wrong credential in channel: %q", received.Username)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("OnCredential channel did not fire")
	}
}

// TestOnSessionChannel tests the session notification channel.
func TestOnSessionChannel(t *testing.T) {
	s := NewStore("")
	sess := CapturedSession{
		ID:        "s1",
		VictimID:  "v1",
		Cookies:   map[string]string{"KEY": "VALUE"},
		Timestamp: time.Now(),
		IsValid:   true,
	}
	s.AddSession(sess)

	select {
	case received := <-s.OnSession:
		if received.Cookies["KEY"] != "VALUE" {
			t.Errorf("wrong session cookie in channel: %v", received.Cookies)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("OnSession channel did not fire")
	}
}

// TestChannelNonBlocking ensures store does NOT block when channels are full.
func TestChannelNonBlocking(t *testing.T) {
	s := NewStore("")
	// Fill all channels to capacity (100 each)
	for i := 0; i < 110; i++ {
		// Must complete without blocking even when channels are full
		s.AddCredential(CapturedCredential{
			ID:        fmt.Sprintf("c%d", i),
			VictimID:  "flood-victim",
			Timestamp: time.Now(),
		})
	}
	// If we got here without hanging, the test passes
}

// TestResetClearsStats verifies stats are 0 after Reset.
func TestResetClearsStats(t *testing.T) {
	s := NewStore("")
	s.AddCredential(CapturedCredential{ID: "c1", VictimID: "v1", Timestamp: time.Now()})
	s.AddSession(CapturedSession{ID: "s1", VictimID: "v2", Cookies: map[string]string{"k": "v"}, Timestamp: time.Now()})
	s.Reset()

	stats := s.GetStats()
	if stats["total_victims"] != 0 {
		t.Errorf("expected 0 victims after reset, got %v", stats["total_victims"])
	}
	if stats["total_credentials"] != 0 {
		t.Errorf("expected 0 credentials after reset, got %v", stats["total_credentials"])
	}
}

// TestGetVictimNonexistent returns false for unknown ID.
func TestGetVictimNonexistent(t *testing.T) {
	s := NewStore("")
	_, ok := s.GetVictim("does-not-exist")
	if ok {
		t.Error("expected false for nonexistent victim")
	}
}

// TestStoreLastSeenUpdates verifies LastSeen is updated on each add.
func TestStoreLastSeenUpdates(t *testing.T) {
	s := NewStore("")
	s.AddCredential(CapturedCredential{ID: "c1", VictimID: "v1", Timestamp: time.Now()})
	v1, _ := s.GetVictim("v1")
	t1 := v1.LastSeen

	time.Sleep(5 * time.Millisecond)
	s.AddCredential(CapturedCredential{ID: "c2", VictimID: "v1", Timestamp: time.Now()})
	v2, _ := s.GetVictim("v1")

	if !v2.LastSeen.After(t1) {
		t.Error("LastSeen should be updated on second add")
	}
}

// TestHighConcurrencyMixedOps stresses mixed reads/writes under race conditions.
func TestHighConcurrencyMixedOps(t *testing.T) {
	s := NewStore("")
	const workers = 50
	var wg sync.WaitGroup
	wg.Add(workers * 3)

	// Writers: credentials
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			s.AddCredential(CapturedCredential{
				ID:        fmt.Sprintf("cred-%d", i),
				VictimID:  fmt.Sprintf("v-%d", i%10),
				Timestamp: time.Now(),
			})
		}(i)
	}
	// Writers: sessions
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			s.AddSession(CapturedSession{
				ID:        fmt.Sprintf("sess-%d", i),
				VictimID:  fmt.Sprintf("v-%d", i%10),
				Cookies:   map[string]string{fmt.Sprintf("cookie-%d", i): "val"},
				Timestamp: time.Now(),
			})
		}(i)
	}
	// Readers
	for i := 0; i < workers; i++ {
		go func(i int) {
			defer wg.Done()
			_ = s.GetAllVictims()
			_ = s.GetStats()
		}(i)
	}
	wg.Wait()
}

// ─── Benchmarks ───────────────────────────────────────────────────────────────

func BenchmarkAddCredential(b *testing.B) {
	s := NewStore("")
	cred := CapturedCredential{
		ID:        "bench-cred",
		VictimID:  "bench-victim",
		Username:  "bench@test.com",
		Password:  "benchpassword",
		Timestamp: time.Now(),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cred.ID = fmt.Sprintf("cred-%d", i)
		s.AddCredential(cred)
	}
}

func BenchmarkGetAllVictims(b *testing.B) {
	s := NewStore("")
	for i := 0; i < 1000; i++ {
		s.AddCredential(CapturedCredential{
			ID:        fmt.Sprintf("c%d", i),
			VictimID:  fmt.Sprintf("v%d", i),
			Timestamp: time.Now(),
		})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.GetAllVictims()
	}
}

func BenchmarkGetStats(b *testing.B) {
	s := NewStore("")
	for i := 0; i < 100; i++ {
		s.AddCredential(CapturedCredential{ID: fmt.Sprintf("c%d", i), VictimID: fmt.Sprintf("v%d", i%10), Timestamp: time.Now()})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.GetStats()
	}
}

func BenchmarkConcurrentReadWrite(b *testing.B) {
	s := NewStore("")
	// Pre-populate
	for i := 0; i < 50; i++ {
		s.AddCredential(CapturedCredential{ID: fmt.Sprintf("pre-%d", i), VictimID: fmt.Sprintf("v%d", i), Timestamp: time.Now()})
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if i%2 == 0 {
				s.AddCredential(CapturedCredential{ID: fmt.Sprintf("c%d", i), VictimID: "shared-victim", Timestamp: time.Now()})
			} else {
				s.GetAllVictims()
			}
			i++
		}
	})
}
