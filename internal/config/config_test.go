package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.ListenIP != "0.0.0.0" {
		t.Errorf("expected ListenIP '0.0.0.0', got %q", cfg.ListenIP)
	}
	if cfg.HTTPPort != 80 {
		t.Errorf("expected HTTPPort 80, got %d", cfg.HTTPPort)
	}
	if cfg.HTTPSPort != 443 {
		t.Errorf("expected HTTPSPort 443, got %d", cfg.HTTPSPort)
	}
	if cfg.AdminPort != 8443 {
		t.Errorf("expected AdminPort 8443, got %d", cfg.AdminPort)
	}
	if cfg.TLS.Mode != "self-signed" {
		t.Errorf("expected TLS mode 'self-signed', got %q", cfg.TLS.Mode)
	}
	if !cfg.Stealth.RemoveProxyHeaders {
		t.Error("expected RemoveProxyHeaders to be true by default")
	}
}

func TestLoadConfigFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")

	content := `
listen_ip: "10.0.0.1"
http_port: 8080
https_port: 8443
admin_port: 9443
admin_pass: "supersecret"
domain: "evil.com"
tls:
  mode: "manual"
  cert_file: "/path/to/cert.pem"
  key_file: "/path/to/key.pem"
stealth:
  remove_proxy_headers: false
  spoof_server_header: "nginx/1.24"
`
	os.WriteFile(path, []byte(content), 0644)

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.ListenIP != "10.0.0.1" {
		t.Errorf("expected ListenIP '10.0.0.1', got %q", cfg.ListenIP)
	}
	if cfg.HTTPPort != 8080 {
		t.Errorf("expected HTTPPort 8080, got %d", cfg.HTTPPort)
	}
	if cfg.Domain != "evil.com" {
		t.Errorf("expected domain 'evil.com', got %q", cfg.Domain)
	}
	if cfg.TLS.Mode != "manual" {
		t.Errorf("expected TLS mode 'manual', got %q", cfg.TLS.Mode)
	}
	if cfg.Stealth.RemoveProxyHeaders {
		t.Error("expected RemoveProxyHeaders to be false")
	}
	if cfg.Stealth.SpoofServerHeader != "nginx/1.24" {
		t.Errorf("expected SpoofServerHeader 'nginx/1.24', got %q", cfg.Stealth.SpoofServerHeader)
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	cfg, err := LoadConfig("/nonexistent/config.yml")
	if err != nil {
		t.Fatalf("expected fallback to defaults, got error: %v", err)
	}
	if cfg.HTTPPort != 80 {
		t.Errorf("expected default HTTPPort 80, got %d", cfg.HTTPPort)
	}
}

func TestSaveAndReloadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "save_test.yml")

	cfg := DefaultConfig()
	cfg.Domain = "roundtrip.com"
	cfg.AdminPass = "testpass"

	if err := SaveConfig(cfg, path); err != nil {
		t.Fatalf("SaveConfig failed: %v", err)
	}

	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig after save failed: %v", err)
	}

	if loaded.Domain != "roundtrip.com" {
		t.Errorf("expected domain 'roundtrip.com', got %q", loaded.Domain)
	}
	if loaded.AdminPass != "testpass" {
		t.Errorf("expected admin_pass 'testpass', got %q", loaded.AdminPass)
	}
}
