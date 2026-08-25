package arp

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// PHANTOMGATE ARP CACHE MANIPULATION v3.0 — ARP CACHE POISONING & RESTORATION
// ══════════════════════════════════════════════════════════════════════════════

type ARPCacheManager struct {
	iface       *net.Interface
	fd          int
	running     bool
	stopChan    chan struct{}
	
	// Cache manipulation
	originalARP  map[string]*ARPEntry
	cachedMutated map[string]bool
	
	// Poisoning
	poisonedIPs  map[string]*PoisonedEntry
	poisonMu     sync.RWMutex
	
	// Restoration
	restoreOnExit bool
	
	// Statistics
	stats *CacheStats
}

type ARPEntry struct {
	IP        net.IP
	MAC       net.HardwareAddr
	Interface string
	Flags     string
	State     string
}

type PoisonedEntry struct {
	TargetIP    net.IP
	RealMAC     net.HardwareAddr
	PoisonMAC   net.HardwareAddr
	PoisonedAt  time.Time
	RestoreMAC  net.HardwareAddr
}

type CacheStats struct {
	CacheReads    int64
	CacheWrites   int64
	PoisonsSent   int64
	Restorations  int64
	CacheFlushes  int64
}

func NewARPCacheManager(iface string) (*ARPCacheManager, error) {
	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface '%s' not found: %w", iface, err)
	}

	return &ARPCacheManager{
		iface:        netIface,
		fd:           -1,
		stopChan:     make(chan struct{}),
		originalARP:  make(map[string]*ARPEntry),
		cachedMutated: make(map[string]bool),
		poisonedIPs:  make(map[string]*PoisonedEntry),
		restoreOnExit: true,
		stats:        &CacheStats{},
	}, nil
}

// ══════════════════════════════════════════════════════════════════════════════
// CACHE OPERATIONS
// ══════════════════════════════════════════════════════════════════════════════

func (m *ARPCacheManager) ReadCache() map[string]*ARPEntry {
	entries := make(map[string]*ARPEntry)
	
	data, err := readFile("/proc/net/arp")
	if err != nil {
		return entries
	}
	
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		
		ip := net.ParseIP(fields[0]).To4()
		if ip == nil {
			continue
		}
		
		mac, err := net.ParseMAC(fields[3])
		if err != nil {
			continue
		}
		
		entry := &ARPEntry{
			IP:        ip,
			MAC:       mac,
			Interface: fields[5],
			Flags:     fields[2],
			State:     fields[2],
		}
		
		entries[ip.String()] = entry
	}
	
	m.originalARP = entries
	return entries
}

func (m *ARPCacheManager) FlushCache() error {
	// Clear entire ARP cache
	err := runCommand("ip", "neighbor", "flush", "all")
	if err != nil {
		return err
	}
	
	m.stats.CacheFlushes++
	log.Printf("[ARP CACHE] Flushed entire ARP cache")
	return nil
}

func (m *ARPCacheManager) FlushEntry(ip net.IP) error {
	err := runCommand("ip", "neighbor", "flush", "dev", m.iface.Name, "ip", ip.String())
	if err != nil {
		return err
	}
	
	m.stats.CacheFlushes++
	log.Printf("[ARP CACHE] Flushed entry for %s", ip)
	return nil
}

func (m *ARPCacheManager) AddEntry(ip net.IP, mac net.HardwareAddr) error {
	// Delete existing entry first
	m.FlushEntry(ip)
	
	// Add new entry
	err := runCommand("ip", "neighbor", "add", ip.String(), "lladdr", mac.String(), "dev", m.iface.Name, "nud", "permanent")
	if err != nil {
		return err
	}
	
	m.stats.CacheWrites++
	log.Printf("[ARP CACHE] Added %s → %s", ip, mac)
	return nil
}

func (m *ARPCacheManager) UpdateEntry(ip net.IP, mac net.HardwareAddr) error {
	err := runCommand("ip", "neighbor", "replace", ip.String(), "lladdr", mac.String(), "dev", m.iface.Name, "nud", "permanent")
	if err != nil {
		return err
	}
	
	m.stats.CacheWrites++
	return nil
}

func (m *ARPCacheManager) DeleteEntry(ip net.IP) error {
	err := runCommand("ip", "neighbor", "del", ip.String(), "dev", m.iface.Name)
	if err != nil {
		return err
	}
	
	return nil
}

func (m *ARPCacheManager) GetEntry(ip net.IP) (*ARPEntry, error) {
	data, err := readFile("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	
	lines := strings.Split(string(data), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		
		entryIP := net.ParseIP(fields[0]).To4()
		if entryIP == nil || !entryIP.Equal(ip) {
			continue
		}
		
		mac, err := net.ParseMAC(fields[3])
		if err != nil {
			continue
		}
		
		m.stats.CacheReads++
		
		return &ARPEntry{
			IP:        entryIP,
			MAC:       mac,
			Interface: fields[5],
			Flags:     fields[2],
			State:     fields[2],
		}, nil
	}
	
	return nil, fmt.Errorf("no ARP entry for %s", ip)
}

// ══════════════════════════════════════════════════════════════════════════════
// POISONING OPERATIONS
// ══════════════════════════════════════════════════════════════════════════════

func (m *ARPCacheManager) PoisonEntry(targetIP net.IP, realMAC, poisonMAC net.HardwareAddr) error {
	m.poisonMu.Lock()
	defer m.poisonMu.Unlock()
	
	targetIPStr := targetIP.String()
	
	// Store original for restoration
	entry, err := m.GetEntry(targetIP)
	if err == nil {
		m.originalARP[targetIPStr] = entry
	}
	
	// Poison the cache
	err = m.UpdateEntry(targetIP, poisonMAC)
	if err != nil {
		return err
	}
	
	m.poisonedIPs[targetIPStr] = &PoisonedEntry{
		TargetIP:   targetIP,
		RealMAC:    realMAC,
		PoisonMAC:  poisonMAC,
		PoisonedAt: time.Now(),
		RestoreMAC: realMAC,
	}
	
	m.stats.PoisonsSent++
	log.Printf("[ARP CACHE] Poisoned %s: %s → %s", targetIPStr, poisonMAC, realMAC)
	return nil
}

func (m *ARPCacheManager) RestoreEntry(targetIP net.IP) error {
	m.poisonMu.Lock()
	defer m.poisonMu.Unlock()
	
	targetIPStr := targetIP.String()
	
	poisoned, exists := m.poisonedIPs[targetIPStr]
	if !exists {
		return fmt.Errorf("no poisoned entry for %s", targetIP)
	}
	
	err := m.UpdateEntry(targetIP, poisoned.RestoreMAC)
	if err != nil {
		return err
	}
	
	delete(m.poisonedIPs, targetIPStr)
	m.stats.Restorations++
	log.Printf("[ARP CACHE] Restored %s → %s", targetIPStr, poisoned.RestoreMAC)
	return nil
}

func (m *ARPCacheManager) RestoreAll() {
	m.poisonMu.RLock()
	targets := make([]net.IP, 0, len(m.poisonedIPs))
	for _, poisoned := range m.poisonedIPs {
		targets = append(targets, poisoned.TargetIP)
	}
	m.poisonMu.RUnlock()
	
	for _, targetIP := range targets {
		m.RestoreEntry(targetIP)
	}
}

func (m *ARPCacheManager) IsPoisoned(ip net.IP) bool {
	m.poisonMu.RLock()
	defer m.poisonMu.RUnlock()
	
	_, exists := m.poisonedIPs[ip.String()]
	return exists
}

func (m *ARPCacheManager) GetPoisonedEntries() map[string]*PoisonedEntry {
	m.poisonMu.RLock()
	defer m.poisonMu.RUnlock()
	
	result := make(map[string]*PoisonedEntry)
	for k, v := range m.poisonedIPs {
		result[k] = v
	}
	return result
}

// ══════════════════════════════════════════════════════════════════════════════
// CACHE SNIFFING
// ══════════════════════════════════════════════════════════════════════════════

func (m *ARPCacheManager) WatchCache(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	
	var lastCache map[string]*ARPEntry
	
	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			currentCache := m.ReadCache()
			m.detectChanges(lastCache, currentCache)
			lastCache = currentCache
		}
	}
}

func (m *ARPCacheManager) detectChanges(old, new map[string]*ARPEntry) {
	if old == nil {
		return
	}
	
	for ip, newEntry := range new {
		oldEntry, exists := old[ip]
		if !exists {
			log.Printf("[ARP CACHE] New entry: %s → %s (%s)", ip, newEntry.MAC, newEntry.Interface)
			continue
		}
		
		if !bytes.Equal(oldEntry.MAC, newEntry.MAC) {
			log.Printf("[ARP CACHE] MAC changed: %s: %s → %s", ip, oldEntry.MAC, newEntry.MAC)
			
			// Detect potential poisoning
			if m.IsPoisoned(net.ParseIP(ip)) {
				log.Printf("[ARP CACHE] WARNING: Poisoned entry %s was modified!", ip)
			}
		}
	}
	
	for ip := range old {
		if _, exists := new[ip]; !exists {
			log.Printf("[ARP CACHE] Entry removed: %s", ip)
		}
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// ANTI-DETECTION
// ══════════════════════════════════════════════════════════════════════════════

func (m *ARPCacheManager) RandomizeTiming(minDelay, maxDelay time.Duration) {
	// Randomize packet timing to avoid detection
	delay := minDelay + time.Duration(float64(maxDelay-minDelay)*float64(randUint32()%1000)/1000.0)
	time.Sleep(delay)
}

func (m *ARPCacheManager) FragmentPackets(data []byte, fragmentSize int) [][]byte {
	var fragments [][]byte
	
	for i := 0; i < len(data); i += fragmentSize {
		end := i + fragmentSize
		if end > len(data) {
			end = len(data)
		}
		
		fragment := make([]byte, end-i)
		copy(fragment, data[i:end])
		fragments = append(fragments, fragment)
	}
	
	return fragments
}

// ══════════════════════════════════════════════════════════════════════════════
// CACHE ANALYSIS
// ══════════════════════════════════════════════════════════════════════════════

func (m *ARPCacheManager) AnalyzeCache() *CacheAnalysis {
	cache := m.ReadCache()
	
	analysis := &CacheAnalysis{
		TotalEntries:    len(cache),
		PoisonedEntries: len(m.poisonedIPs),
		StaticEntries:   0,
		DynamicEntries:  0,
		SuspiciousEntries: make([]*SuspiciousEntry, 0),
	}
	
	for _, entry := range cache {
		if entry.Flags == "0x2" {
			analysis.StaticEntries++
		} else {
			analysis.DynamicEntries++
		}
		
		// Check for suspicious entries
		if m.isSuspiciousEntry(entry) {
			analysis.SuspiciousEntries = append(analysis.SuspiciousEntries, &SuspiciousEntry{
				IP:        entry.IP,
				MAC:       entry.MAC,
				Reason:    "Potential poisoning",
				DetectedAt: time.Now(),
			})
		}
	}
	
	return analysis
}

type CacheAnalysis struct {
	TotalEntries       int
	PoisonedEntries    int
	StaticEntries      int
	DynamicEntries     int
	SuspiciousEntries  []*SuspiciousEntry
}

type SuspiciousEntry struct {
	IP         net.IP
	MAC        net.HardwareAddr
	Reason     string
	DetectedAt time.Time
}

func (m *ARPCacheManager) isSuspiciousEntry(entry *ARPEntry) bool {
	// Check for multiple IPs with same MAC (potential poisoning)
	data, _ := readFile("/proc/net/arp")
	lines := strings.Split(string(data), "\n")
	
	macCount := make(map[string]int)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			mac := fields[3]
			macCount[mac]++
		}
	}
	
	return macCount[entry.MAC.String()] > 1
}

// ══════════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════

func (m *ARPCacheManager) Stop() {
	close(m.stopChan)
	
	if m.restoreOnExit {
		m.RestoreAll()
	}
}

func (m *ARPCacheManager) GetStats() CacheStats {
	return CacheStats{
		CacheReads:   m.stats.CacheReads,
		CacheWrites:  m.stats.CacheWrites,
		PoisonsSent:  m.stats.PoisonsSent,
		Restorations: m.stats.Restorations,
		CacheFlushes: m.stats.CacheFlushes,
	}
}

// Helper functions that use syscall
func readFile(path string) ([]byte, error) {
	return exec_readFile(path)
}

func runCommand(name string, args ...string) error {
	return exec_runCommand(name, args...)
}

func randUint32() uint32 {
	return uint32(time.Now().UnixNano())
}
