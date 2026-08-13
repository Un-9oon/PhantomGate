package phishlet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── Fuzz Tests ───────────────────────────────────────────────────────────────

// FuzzLoadPhishlet fuzzes phishlet YAML parsing with arbitrary bytes.
// Goal: no panics, no crashes on malformed YAML.
func FuzzLoadPhishlet(f *testing.F) {
	f.Add([]byte(testPhishletYAML))
	f.Add([]byte(""))
	f.Add([]byte("name: test\nproxy_hosts: null"))
	f.Add([]byte("{{{not yaml at all}}}"))
	f.Add([]byte("name: " + strings.Repeat("x", 10000)))
	f.Add([]byte("\x00\x01\x02\xff"))
	f.Add([]byte("proxy_hosts:\n  - phish_sub: a\n    orig_sub: b\n    is_ssl: notabool"))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("loadPhishlet panicked: %v", r)
			}
		}()
		dir := t.TempDir()
		path := filepath.Join(dir, "fuzz.yml")
		os.WriteFile(path, data, 0644)
		p, err := loadPhishlet(path)
		_ = p
		_ = err
	})
}

// FuzzGetHostMappings fuzzes GetHostMappings with arbitrary phish domain strings.
func FuzzGetHostMappings(f *testing.F) {
	p := &Phishlet{
		ProxyHosts: []ProxyHost{
			{PhishSub: "login", OrigSub: "login.example.com"},
			{PhishSub: "cdn", OrigSub: "cdn.example.com"},
		},
	}

	f.Add("evil.com")
	f.Add("")
	f.Add(strings.Repeat("a", 1000) + ".com")
	f.Add("evil.com\x00injected")

	f.Fuzz(func(t *testing.T, domain string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("GetHostMappings panicked on %q: %v", domain, r)
			}
		}()
		mappings := p.GetHostMappings(domain)
		_ = mappings
	})
}

// ─── Extended Unit Tests ──────────────────────────────────────────────────────

// TestPhishletDefaultSSL verifies that is_ssl defaults to true when not specified.
func TestPhishletDefaultSSL(t *testing.T) {
	yaml := `
name: "NoSSLField"
proxy_hosts:
  - phish_sub: "login"
    orig_sub: "login.example.com"
    domain: "example.com"
`
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yml")
	os.WriteFile(path, []byte(yaml), 0644)

	p, err := loadPhishlet(path)
	if err != nil {
		t.Fatalf("loadPhishlet failed: %v", err)
	}
	if !p.ProxyHosts[0].IsSSL {
		t.Error("is_ssl should default to true when not specified in YAML")
	}
}

// TestPhishletExplicitSSLFalse verifies is_ssl: false is respected.
func TestPhishletExplicitSSLFalse(t *testing.T) {
	yaml := `
name: "ExplicitNoSSL"
proxy_hosts:
  - phish_sub: "insecure"
    orig_sub: "insecure.example.com"
    domain: "example.com"
    is_ssl: false
`
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yml")
	os.WriteFile(path, []byte(yaml), 0644)

	p, err := loadPhishlet(path)
	if err != nil {
		t.Fatalf("loadPhishlet failed: %v", err)
	}
	if p.ProxyHosts[0].IsSSL {
		t.Error("is_ssl: false should not be overridden to true")
	}
}

// TestPhishletInvalidYAML returns an error (no panic) for malformed YAML.
func TestPhishletInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yml")
	os.WriteFile(path, []byte(":::invalid: yaml:::"), 0644)

	_, err := loadPhishlet(path)
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

// TestPhishletMissingFile returns an error for a nonexistent path.
func TestPhishletMissingFile(t *testing.T) {
	_, err := loadPhishlet("/nonexistent/path/to/phishlet.yml")
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

// TestPhishletEmptyProxyHosts — a phishlet with no proxy_hosts is valid (no panic).
func TestPhishletEmptyProxyHosts(t *testing.T) {
	yamlContent := `
name: "Empty"
proxy_hosts: []
auth_tokens: []
`
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.yml")
	os.WriteFile(path, []byte(yamlContent), 0644)

	p, err := loadPhishlet(path)
	if err != nil {
		t.Fatalf("empty phishlet should load without error: %v", err)
	}
	if len(p.GetHostMappings("evil.com")) != 0 {
		t.Error("expected empty host mappings for empty phishlet")
	}
}

// TestManagerLoadAllFilesOnly verifies .yml and .yaml are loaded but not other extensions.
func TestManagerLoadAllFilesOnly(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.yml"), []byte(`name: "A"`), 0644)
	os.WriteFile(filepath.Join(dir, "b.yaml"), []byte(`name: "B"`), 0644)
	os.WriteFile(filepath.Join(dir, "c.txt"), []byte("should be ignored"), 0644)
	os.WriteFile(filepath.Join(dir, "README.md"), []byte("# docs"), 0644)

	pm := NewPhishletManager(dir)
	if err := pm.LoadAll(); err != nil {
		t.Fatalf("LoadAll failed: %v", err)
	}

	names := pm.List()
	if len(names) != 2 {
		t.Errorf("expected 2 phishlets (yml + yaml), got %d: %v", len(names), names)
	}
}

// TestGetSessionDomainsDedup verifies duplicate domains are deduplicated.
func TestGetSessionDomainsDedup(t *testing.T) {
	p := &Phishlet{
		AuthTokens: []AuthToken{
			{Domain: ".example.com", Keys: []string{"A"}},
			{Domain: ".example.com", Keys: []string{"B"}},
			{Domain: ".example.com", Keys: []string{"C"}},
		},
	}
	domains := p.GetSessionDomains()
	if len(domains) != 1 {
		t.Errorf("expected 1 deduplicated domain, got %d", len(domains))
	}
}

// TestGetAllAuthCookieKeysEmpty returns empty slice for phishlet with no auth tokens.
func TestGetAllAuthCookieKeysEmpty(t *testing.T) {
	p := &Phishlet{}
	keys := p.GetAllAuthCookieKeys()
	if len(keys) != 0 {
		t.Errorf("expected 0 keys for empty phishlet, got %d", len(keys))
	}
}

// TestPhishletDomainSubstitution verifies {phish_domain} placeholder in sub_filters.
func TestPhishletDomainSubstitution(t *testing.T) {
	yaml := `
name: "DomainSubst"
proxy_hosts:
  - phish_sub: "login"
    orig_sub: "login.example.com"
    domain: "example.com"
    is_ssl: true
sub_filters:
  - triggers_on: "login.example.com"
    search: "login.example.com"
    replace: "login.{phish_domain}"
    mimes: ["text/html"]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "subst.yml")
	os.WriteFile(path, []byte(yaml), 0644)

	p, err := loadPhishlet(path)
	if err != nil {
		t.Fatalf("loadPhishlet failed: %v", err)
	}
	if len(p.SubFilters) != 1 {
		t.Fatalf("expected 1 sub_filter, got %d", len(p.SubFilters))
	}
	if p.SubFilters[0].Replace != "login.{phish_domain}" {
		t.Errorf("sub_filter replace: got %q", p.SubFilters[0].Replace)
	}
}

// ─── Benchmarks ───────────────────────────────────────────────────────────────

func BenchmarkLoadPhishlet(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "bench.yml")
	os.WriteFile(path, []byte(testPhishletYAML), 0644)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p, err := loadPhishlet(path)
		if err != nil {
			b.Fatal(err)
		}
		_ = p
	}
}

func BenchmarkGetHostMappings(b *testing.B) {
	p := &Phishlet{
		ProxyHosts: []ProxyHost{
			{PhishSub: "login", OrigSub: "login.example.com"},
			{PhishSub: "cdn", OrigSub: "cdn.example.com"},
			{PhishSub: "api", OrigSub: "api.example.com"},
			{PhishSub: "auth", OrigSub: "auth.example.com"},
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.GetHostMappings("evil.test")
	}
}

func BenchmarkGetAllAuthCookieKeys(b *testing.B) {
	p := &Phishlet{
		AuthTokens: []AuthToken{
			{Domain: ".example.com", Keys: []string{"A", "B", "C", "D", "E"}},
			{Domain: ".other.com", Keys: []string{"F", "G", "H"}},
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.GetAllAuthCookieKeys()
	}
}
