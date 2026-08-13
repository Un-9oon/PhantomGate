package capture

import (
	"bytes"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/phantomgate/phantomgate/internal/phishlet"
	"github.com/phantomgate/phantomgate/internal/store"
)

func newTestInterceptor() (*CredentialInterceptor, *store.Store) {
	s := store.NewStore("")
	p := &phishlet.Phishlet{
		Name: "test",
		Credentials: phishlet.CredentialConfig{
			Username: phishlet.CredentialField{Key: "login", Search: `"login"\s*:\s*"([^"]*)"`, Type: "json"},
			Password: phishlet.CredentialField{Key: "passwd", Search: `"passwd"\s*:\s*"([^"]*)"`, Type: "json"},
		},
	}
	return NewCredentialInterceptor(s, p), s
}

func TestFormCredentialExtraction(t *testing.T) {
	ci, s := newTestInterceptor()

	body := "login=user%40example.com&passwd=secret123"
	req, _ := http.NewRequest("POST", "https://example.com/login", io.NopCloser(bytes.NewReader([]byte(body))))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ci.InspectRequest(req, []byte(body), "victim-1")
	time.Sleep(10 * time.Millisecond)

	v, ok := s.GetVictim("victim-1")
	if !ok {
		t.Fatal("victim not found")
	}
	if len(v.Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(v.Credentials))
	}
	if v.Credentials[0].Username != "user@example.com" {
		t.Errorf("expected 'user@example.com', got %q", v.Credentials[0].Username)
	}
	if v.Credentials[0].Password != "secret123" {
		t.Errorf("expected 'secret123', got %q", v.Credentials[0].Password)
	}
}

func TestJSONCredentialExtraction(t *testing.T) {
	ci, s := newTestInterceptor()

	body := `{"login": "admin@corp.com", "passwd": "hunter2"}`
	req, _ := http.NewRequest("POST", "https://example.com/api/login", io.NopCloser(bytes.NewReader([]byte(body))))
	req.Header.Set("Content-Type", "application/json")

	ci.InspectRequest(req, []byte(body), "victim-2")
	time.Sleep(10 * time.Millisecond)

	v, ok := s.GetVictim("victim-2")
	if !ok {
		t.Fatal("victim not found")
	}
	if len(v.Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(v.Credentials))
	}
	if v.Credentials[0].Username != "admin@corp.com" {
		t.Errorf("expected 'admin@corp.com', got %q", v.Credentials[0].Username)
	}
}

func TestFallbackFieldNames(t *testing.T) {
	s := store.NewStore("")
	p := &phishlet.Phishlet{Name: "test"}
	ci := NewCredentialInterceptor(s, p)

	body := "email=test%40test.com&password=mypass"
	req, _ := http.NewRequest("POST", "https://example.com/login", io.NopCloser(bytes.NewReader([]byte(body))))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	ci.InspectRequest(req, []byte(body), "victim-3")
	time.Sleep(10 * time.Millisecond)

	v, ok := s.GetVictim("victim-3")
	if !ok {
		t.Fatal("victim not found")
	}
	if v.Credentials[0].Username != "test@test.com" {
		t.Errorf("fallback username extraction failed: got %q", v.Credentials[0].Username)
	}
	if v.Credentials[0].Password != "mypass" {
		t.Errorf("fallback password extraction failed: got %q", v.Credentials[0].Password)
	}
}

func TestGetMethodIgnored(t *testing.T) {
	ci, s := newTestInterceptor()

	req, _ := http.NewRequest("GET", "https://example.com/login?user=admin", nil)
	ci.InspectRequest(req, nil, "victim-4")
	time.Sleep(10 * time.Millisecond)

	_, ok := s.GetVictim("victim-4")
	if ok {
		t.Error("GET request should not create a victim")
	}
}

func TestMaskPassword(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ab", "***"},
		{"abc", "a*c"},
		{"password", "p******d"},
	}
	for _, tc := range tests {
		result := maskPassword(tc.input)
		if result != tc.expected {
			t.Errorf("maskPassword(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}
