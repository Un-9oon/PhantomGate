package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level PhantomGate configuration
type Config struct {
	// General settings
	ListenIP   string `yaml:"listen_ip"`
	HTTPPort   int    `yaml:"http_port"`
	HTTPSPort  int    `yaml:"https_port"`
	AdminPort  int    `yaml:"admin_port"`
	AdminPass  string `yaml:"admin_pass"`
	Domain     string `yaml:"domain"`
	ExternalIP string `yaml:"external_ip"`

	// TLS settings
	TLS TLSConfig `yaml:"tls"`

	// Logging
	LogLevel string `yaml:"log_level"`

	// Stealth
	Stealth StealthConfig `yaml:"stealth"`
}

// TLSConfig controls certificate management
type TLSConfig struct {
	Mode     string `yaml:"mode"` // "auto" (Let's Encrypt), "self-signed", "manual"
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	Email    string `yaml:"acme_email"` // For Let's Encrypt
}

// StealthConfig controls anti-detection features
type StealthConfig struct {
	RemoveProxyHeaders  bool   `yaml:"remove_proxy_headers"`
	SpoofServerHeader   string `yaml:"spoof_server_header"`
	EnableFingerprinting bool  `yaml:"enable_fingerprinting"`
	RandomizeTimings    bool   `yaml:"randomize_timings"`
}

// DefaultConfig returns a sane default configuration
func DefaultConfig() *Config {
	return &Config{
		ListenIP:  "0.0.0.0",
		HTTPPort:  80,
		HTTPSPort: 443,
		AdminPort: 8443,
		AdminPass: "changeme",
		LogLevel:  "info",
		TLS: TLSConfig{
			Mode: "self-signed",
		},
		Stealth: StealthConfig{
			RemoveProxyHeaders:  true,
			SpoofServerHeader:   "Microsoft-IIS/10.0",
			EnableFingerprinting: true,
			RandomizeTimings:    true,
		},
	}
}

// LoadConfig reads configuration from a YAML file
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // Use defaults if no config file
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return cfg, nil
}

// SaveConfig writes the current config to a YAML file
func SaveConfig(cfg *Config, path string) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}
