package plugin

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"plugin"
	"sync"
	"sync/atomic"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// PHANTOMGATE PLUGIN SYSTEM v3.0 — EXTENSIBLE PLUGIN ARCHITECTURE
// ══════════════════════════════════════════════════════════════════════════════

type PluginManager struct {
	plugins     map[string]*Plugin
	pluginsMu   sync.RWMutex
	
	hooks       map[string][]HookHandler
	hooksMu     sync.RWMutex
	
	pluginDir   string
	running     bool
	stats       *PluginStats
}

type Plugin struct {
	Name        string
	Version     string
	Author      string
	Description string
	Path        string
	Enabled     bool
	Loaded      bool
	Instance    plugin.Plugin
	Module      interface{}
	LoadTime    time.Time
	Config      map[string]interface{}
}

type HookHandler func(args map[string]interface{}) interface{}

type PluginStats struct {
	PluginsLoaded   int64
	PluginsEnabled  int64
	PluginsFailed   int64
	HooksExecuted   int64
	StartTime       time.Time
}

// PluginInterface defines the interface plugins must implement
type PluginInterface interface {
	Name() string
	Version() string
	Init(config map[string]interface{}) error
	Start() error
	Stop() error
	Execute(command string, args map[string]interface{}) (interface{}, error)
}

// PluginConfig represents plugin configuration
type PluginConfig struct {
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Enabled     bool                   `json:"enabled"`
	Config      map[string]interface{} `json:"config"`
}

type PluginManifest struct {
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Author      string                 `json:"author"`
	Description string                 `json:"description"`
	Entry       string                 `json:"entry"`
	Dependencies []string              `json:"dependencies"`
	Config      map[string]interface{} `json:"config"`
}

func NewPluginManager(pluginDir string) *PluginManager {
	if pluginDir == "" {
		pluginDir = "/opt/phantomgate/plugins"
	}
	
	return &PluginManager{
		plugins:   make(map[string]*Plugin),
		hooks:     make(map[string][]HookHandler),
		pluginDir: pluginDir,
		stats: &PluginStats{
			StartTime: time.Now(),
		},
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// CORE FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════

func (m *PluginManager) Start() error {
	m.running = true
	
	log.Printf("[PLUGIN] Starting plugin manager")
	log.Printf("[PLUGIN] Plugin directory: %s", m.pluginDir)
	
	// Create plugin directory if it doesn't exist
	if err := os.MkdirAll(m.pluginDir, 0755); err != nil {
		return fmt.Errorf("failed to create plugin directory: %w", err)
	}
	
	// Load all plugins
	if err := m.LoadAllPlugins(); err != nil {
		log.Printf("[PLUGIN] Warning: Some plugins failed to load: %v", err)
	}
	
	return nil
}

func (m *PluginManager) Stop() {
	m.running = false
	
	// Stop all plugins
	m.pluginsMu.RLock()
	for _, p := range m.plugins {
		if p.Loaded && p.Enabled {
			m.stopPlugin(p)
		}
	}
	m.pluginsMu.RUnlock()
	
	log.Printf("[PLUGIN] Plugin manager stopped")
}

// ══════════════════════════════════════════════════════════════════════════════
// PLUGIN LOADING
// ══════════════════════════════════════════════════════════════════════════════

func (m *PluginManager) LoadAllPlugins() error {
	entries, err := os.ReadDir(m.pluginDir)
	if err != nil {
		return fmt.Errorf("failed to read plugin directory: %w", err)
	}
	
	var errors []error
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		
		if filepath.Ext(entry.Name()) == ".so" {
			pluginPath := filepath.Join(m.pluginDir, entry.Name())
			if err := m.LoadPlugin(pluginPath); err != nil {
				errors = append(errors, fmt.Errorf("failed to load %s: %w", entry.Name(), err))
			}
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("plugin loading errors: %v", errors)
	}
	
	return nil
}

func (m *PluginManager) LoadPlugin(path string) error {
	// Open plugin
	p, err := plugin.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open plugin: %w", err)
	}
	
	// Look for Plugin symbol
	sym, err := p.Lookup("Plugin")
	if err != nil {
		return fmt.Errorf("failed to find Plugin symbol: %w", err)
	}
	
	// Assert plugin interface
	pluginInstance, ok := sym.(PluginInterface)
	if !ok {
		return fmt.Errorf("plugin does not implement PluginInterface")
	}
	
	// Create plugin entry
	pluginEntry := &Plugin{
		Name:     pluginInstance.Name(),
		Path:     path,
		Loaded:   true,
		Instance: *p,
		Module:   pluginInstance,
		LoadTime: time.Now(),
	}
	
	// Register plugin
	m.pluginsMu.Lock()
	m.plugins[pluginEntry.Name] = pluginEntry
	m.pluginsMu.Unlock()
	
	atomic.AddInt64(&m.stats.PluginsLoaded, 1)
	log.Printf("[PLUGIN] Loaded plugin: %s", pluginEntry.Name)
	
	return nil
}

func (m *PluginManager) UnloadPlugin(name string) error {
	m.pluginsMu.Lock()
	defer m.pluginsMu.Unlock()
	
	plugin, exists := m.plugins[name]
	if !exists {
		return fmt.Errorf("plugin not found: %s", name)
	}
	
	if plugin.Loaded && plugin.Enabled {
		m.stopPlugin(plugin)
	}
	
	delete(m.plugins, name)
	log.Printf("[PLUGIN] Unloaded plugin: %s", name)
	
	return nil
}

// ══════════════════════════════════════════════════════════════════════════════
// PLUGIN MANAGEMENT
// ══════════════════════════════════════════════════════════════════════════════

func (m *PluginManager) EnablePlugin(name string) error {
	m.pluginsMu.Lock()
	defer m.pluginsMu.Unlock()
	
	plugin, exists := m.plugins[name]
	if !exists {
		return fmt.Errorf("plugin not found: %s", name)
	}
	
	if !plugin.Loaded {
		return fmt.Errorf("plugin not loaded: %s", name)
	}
	
	if err := m.startPlugin(plugin); err != nil {
		return err
	}
	
	plugin.Enabled = true
	atomic.AddInt64(&m.stats.PluginsEnabled, 1)
	log.Printf("[PLUGIN] Enabled plugin: %s", name)
	
	return nil
}

func (m *PluginManager) DisablePlugin(name string) error {
	m.pluginsMu.Lock()
	defer m.pluginsMu.Unlock()
	
	plugin, exists := m.plugins[name]
	if !exists {
		return fmt.Errorf("plugin not found: %s", name)
	}
	
	if err := m.stopPlugin(plugin); err != nil {
		return err
	}
	
	plugin.Enabled = false
	log.Printf("[PLUGIN] Disabled plugin: %s", name)
	
	return nil
}

func (m *PluginManager) startPlugin(p *Plugin) error {
	if module, ok := p.Module.(PluginInterface); ok {
		if err := module.Start(); err != nil {
			return fmt.Errorf("failed to start plugin %s: %w", p.Name, err)
		}
	}
	return nil
}

func (m *PluginManager) stopPlugin(p *Plugin) error {
	if module, ok := p.Module.(PluginInterface); ok {
		if err := module.Stop(); err != nil {
			return fmt.Errorf("failed to stop plugin %s: %w", p.Name, err)
		}
	}
	return nil
}

// ══════════════════════════════════════════════════════════════════════════════
// PLUGIN EXECUTION
// ══════════════════════════════════════════════════════════════════════════════

func (m *PluginManager) ExecutePlugin(name, command string, args map[string]interface{}) (interface{}, error) {
	m.pluginsMu.RLock()
	plugin, exists := m.plugins[name]
	m.pluginsMu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("plugin not found: %s", name)
	}
	
	if !plugin.Loaded || !plugin.Enabled {
		return nil, fmt.Errorf("plugin not enabled: %s", name)
	}
	
	if module, ok := plugin.Module.(PluginInterface); ok {
		return module.Execute(command, args)
	}
	
	return nil, fmt.Errorf("plugin does not support execution")
}

// ══════════════════════════════════════════════════════════════════════════════
// HOOK SYSTEM
// ══════════════════════════════════════════════════════════════════════════════

func (m *PluginManager) RegisterHook(name string, handler HookHandler) {
	m.hooksMu.Lock()
	defer m.hooksMu.Unlock()
	
	m.hooks[name] = append(m.hooks[name], handler)
}

func (m *PluginManager) ExecuteHook(name string, args map[string]interface{}) []interface{} {
	m.hooksMu.RLock()
	handlers, exists := m.hooks[name]
	m.hooksMu.RUnlock()
	
	if !exists {
		return nil
	}
	
	var results []interface{}
	for _, handler := range handlers {
		result := handler(args)
		results = append(results, result)
		atomic.AddInt64(&m.stats.HooksExecuted, 1)
	}
	
	return results
}

// ══════════════════════════════════════════════════════════════════════════════
// PLUGIN DISCOVERY
// ══════════════════════════════════════════════════════════════════════════════

func (m *PluginManager) ListPlugins() []*Plugin {
	m.pluginsMu.RLock()
	defer m.pluginsMu.RUnlock()
	
	plugins := make([]*Plugin, 0, len(m.plugins))
	for _, p := range m.plugins {
		plugins = append(plugins, p)
	}
	return plugins
}

func (m *PluginManager) GetPlugin(name string) *Plugin {
	m.pluginsMu.RLock()
	defer m.pluginsMu.RUnlock()
	
	return m.plugins[name]
}

func (m *PluginManager) PluginExists(name string) bool {
	m.pluginsMu.RLock()
	defer m.pluginsMu.RUnlock()
	
	_, exists := m.plugins[name]
	return exists
}

// ══════════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ══════════════════════════════════════════════════════════════════════════════

func (m *PluginManager) LoadConfig(path string) ([]PluginConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	
	var configs []PluginConfig
	if err := json.Unmarshal(data, &configs); err != nil {
		return nil, err
	}
	
	return configs, nil
}

func (m *PluginManager) SaveConfig(path string, configs []PluginConfig) error {
	data, err := json.MarshalIndent(configs, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(path, data, 0644)
}

// ══════════════════════════════════════════════════════════════════════════════
// UTILITY
// ══════════════════════════════════════════════════════════════════════════════

func (m *PluginManager) GetStats() PluginStats {
	return PluginStats{
		PluginsLoaded:  atomic.LoadInt64(&m.stats.PluginsLoaded),
		PluginsEnabled: atomic.LoadInt64(&m.stats.PluginsEnabled),
		PluginsFailed:  atomic.LoadInt64(&m.stats.PluginsFailed),
		HooksExecuted:  atomic.LoadInt64(&m.stats.HooksExecuted),
		StartTime:      m.stats.StartTime,
	}
}

func (m *PluginManager) printStats() {
	stats := m.GetStats()
	log.Printf("[PLUGIN STATS] Loaded: %d | Enabled: %d | Failed: %d | Hooks: %d",
		stats.PluginsLoaded, stats.PluginsEnabled, stats.PluginsFailed, stats.HooksExecuted)
}
