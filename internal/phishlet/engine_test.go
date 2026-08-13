package phishlet

import (
	"os"
	"path/filepath"
	"testing"
)

const testPhishletYAML = `
name: "TestApp"
author: "test"
min_ver: "1.0.0"

proxy_hosts:
  - phish_sub: "login"
    orig_sub: "login.example.com"
    domain: "example.com"
    session: true
    is_ssl: true
  - phish_sub: "cdn"
    orig_sub: "cdn.example.com"
    domain: "example.com"
    session: false
    is_ssl: true

sub_filters:
  - triggers_on: "login.example.com"
    search: "login.example.com"
    replace: "login.{phish_domain}"
    mimes: ["text/html"]

credentials:
  username:
    key: "email"
    type: "post"
  password:
    key: "password"
    type: "post"

auth_tokens:
  - domain: ".example.com"
    keys: ["SESSION", "AUTH"]

landing_path:
  - "/"
  - "/login"
`

func TestLoadPhishlet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yml")
	os.WriteFile(path, []byte(testPhishletYAML), 0644)

	p, err := loadPhishlet(path)
	if err != nil {
		t.Fatalf("loadPhishlet failed: %v", err)
	}

	if p.Name != "TestApp" {
		t.Errorf("expected name 'TestApp', got %q", p.Name)
	}
	if len(p.ProxyHosts) != 2 {
		t.Fatalf("expected 2 proxy hosts, got %d", len(p.ProxyHosts))
	}
	if p.ProxyHosts[0].PhishSub != "login" {
		t.Errorf("expected phish_sub 'login', got %q", p.ProxyHosts[0].PhishSub)
	}
	if !p.ProxyHosts[0].IsSSL {
		t.Error("expected IsSSL to be true for login host")
	}
	if len(p.AuthTokens) != 1 {
		t.Fatalf("expected 1 auth token config, got %d", len(p.AuthTokens))
	}
	if len(p.AuthTokens[0].Keys) != 2 {
		t.Errorf("expected 2 auth token keys, got %d", len(p.AuthTokens[0].Keys))
	}
}

func TestPhishletManager(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "test.yml"), []byte(testPhishletYAML), 0644)

	pm := NewPhishletManager(dir)
	if err := pm.LoadAll(); err != nil {
		t.Fatalf("LoadAll failed: %v", err)
	}

	names := pm.List()
	if len(names) != 1 {
		t.Fatalf("expected 1 phishlet, got %d", len(names))
	}

	p, ok := pm.Get("TestApp")
	if !ok {
		t.Fatal("phishlet 'TestApp' not found")
	}
	if p.Author != "test" {
		t.Errorf("expected author 'test', got %q", p.Author)
	}

	_, ok = pm.Get("nonexistent")
	if ok {
		t.Error("expected nonexistent phishlet to not be found")
	}
}

func TestGetHostMappings(t *testing.T) {
	p := &Phishlet{
		ProxyHosts: []ProxyHost{
			{PhishSub: "login", OrigSub: "login.example.com"},
			{PhishSub: "cdn", OrigSub: "cdn.example.com"},
		},
	}

	mappings := p.GetHostMappings("evil.com")

	if mappings["login.evil.com"] != "login.example.com" {
		t.Errorf("expected login.evil.com -> login.example.com, got %q", mappings["login.evil.com"])
	}
	if mappings["cdn.evil.com"] != "cdn.example.com" {
		t.Errorf("expected cdn.evil.com -> cdn.example.com, got %q", mappings["cdn.evil.com"])
	}
}

func TestGetAllAuthCookieKeys(t *testing.T) {
	p := &Phishlet{
		AuthTokens: []AuthToken{
			{Domain: ".example.com", Keys: []string{"A", "B"}},
			{Domain: ".other.com", Keys: []string{"C"}},
		},
	}

	keys := p.GetAllAuthCookieKeys()
	if len(keys) != 3 {
		t.Errorf("expected 3 keys, got %d", len(keys))
	}
}

func TestGetSessionDomains(t *testing.T) {
	p := &Phishlet{
		AuthTokens: []AuthToken{
			{Domain: ".example.com", Keys: []string{"A"}},
			{Domain: ".example.com", Keys: []string{"B"}},
			{Domain: ".other.com", Keys: []string{"C"}},
		},
	}

	domains := p.GetSessionDomains()
	if len(domains) != 2 {
		t.Errorf("expected 2 unique domains, got %d", len(domains))
	}
}
