package ble

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// PHANTOMGATE BLE ATTACK FRAMEWORK v3.0 — BLUETOOTH LOW ENERGY ATTACKS
// ══════════════════════════════════════════════════════════════════════════════

type BLEAttacker struct {
	iface       string
	running     bool
	stopChan    chan struct{}
	
	// Device management
	devices     map[string]*BLEDevice
	devicesMu   sync.RWMutex
	
	// Attack modes
	scanMode    BLEScanMode
	attackMode  BLEAttackMode
	
	// Statistics
	stats       *BLEStats
	
	// Callbacks
	onDeviceFound  func(*BLEDevice)
	onDataCaptured func(*BLEData)
	onPairSuccess  func(*BLEDevice)
}

type BLEDevice struct {
	ID          string
	Name        string
	MAC         net.HardwareAddr
	RSSI        int
	Type        BLEDeviceType
	Services    []BLEService
	Characteristics []BLECharacteristic
	Paired      bool
	Encrypted   bool
	FirstSeen   time.Time
	LastSeen    time.Time
}

type BLEDeviceType int

const (
	BLEDeviceTypeUnknown BLEDeviceType = iota
	BLEDeviceTypePhone
	BLEDeviceTypeComputer
	BLEDeviceTypeHeadphones
	BLEDeviceTypeKeyboard
	BLEDeviceTypeMouse
	BLEDeviceTypeFitness
	BLEDeviceTypeMedical
	BLEDeviceTypeBeacon
	BLEDeviceTypeTracker
)

type BLEService struct {
	UUID        string
	Name        string
	Characteristics []string
}

type BLECharacteristic struct {
	UUID        string
	Name        string
	Properties  []string
	Value       []byte
	Handle      uint16
}

type BLEData struct {
	DeviceID    string
	ServiceUUID string
	CharUUID    string
	Data        []byte
	Timestamp   time.Time
	Direction   string // "read" or "write"
}

type BLEScanMode int

const (
	BLEScanModePassive BLEScanMode = iota
	BLEScanModeActive
	BLEScanModeDiscovery
)

type BLEAttackMode int

const (
	BLEAttackModeNone BLEAttackMode = iota
	BLEAttackModeSniff
	BLEAttackModeInject
	BLEAttackModePair
	BLEAttackModeSpoof
	BLEAttackModeKiller
)

type BLEStats struct {
	DevicesFound   int64
	PacketsSniffed int64
	InjectsSuccess int64
	PairsSuccess   int64
	StartTime      time.Time
}

// BLEConfig configures the BLE attacker
type BLEConfig struct {
	Interface   string
	ScanMode    string
	AttackMode  string
	Timeout     time.Duration
	FilterName  string
	FilterType  string
}

func NewBLEAttacker(cfg BLEConfig) (*BLEAttacker, error) {
	if cfg.Interface == "" {
		cfg.Interface = "hci0"
	}
	
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	
	scanMode := BLEScanModePassive
	switch cfg.ScanMode {
	case "active":
		scanMode = BLEScanModeActive
	case "discovery":
		scanMode = BLEScanModeDiscovery
	}
	
	attackMode := BLEAttackModeNone
	switch cfg.AttackMode {
	case "sniff":
		attackMode = BLEAttackModeSniff
	case "inject":
		attackMode = BLEAttackModeInject
	case "pair":
		attackMode = BLEAttackModePair
	case "spoof":
		attackMode = BLEAttackModeSpoof
	case "killer":
		attackMode = BLEAttackModeKiller
	}
	
	return &BLEAttacker{
		iface:      cfg.Interface,
		stopChan:   make(chan struct{}),
		devices:    make(map[string]*BLEDevice),
		scanMode:   scanMode,
		attackMode: attackMode,
		stats: &BLEStats{
			StartTime: time.Now(),
		},
	}, nil
}

// ══════════════════════════════════════════════════════════════════════════════
// CORE FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════

func (b *BLEAttacker) Start() error {
	b.running = true
	
	log.Printf("[BLE] Starting BLE attacker on %s", b.iface)
	log.Printf("[BLE] Scan mode: %s", b.getScanModeName())
	log.Printf("[BLE] Attack mode: %s", b.getAttackModeName())
	
	// Start scanning
	go b.scanLoop()
	
	// Start attack if configured
	if b.attackMode != BLEAttackModeNone {
		go b.attackLoop()
	}
	
	return nil
}

func (b *BLEAttacker) Stop() {
	b.running = false
	close(b.stopChan)
	
	b.printStats()
	log.Printf("[BLE] BLE attacker stopped")
}

// ══════════════════════════════════════════════════════════════════════════════
// SCANNING
// ══════════════════════════════════════════════════════════════════════════════

func (b *BLEAttacker) scanLoop() {
	for {
		select {
		case <-b.stopChan:
			return
		default:
		}
		
		b.performScan()
		time.Sleep(1 * time.Second)
	}
}

func (b *BLEAttacker) performScan() {
	// This would use actual BLE scanning via hcitool/bluetoothctl
	// For now, simulate device discovery
	
	log.Printf("[BLE] Scanning for BLE devices...")
	
	// Simulated scan - in production this would use:
	// - hcitool lescan
	// - bluetoothctl
	// - Go BLE libraries like go-ble
	
	atomic.AddInt64(&b.stats.DevicesFound, 1)
}

func (b *BLEAttacker) addDevice(device *BLEDevice) {
	b.devicesMu.Lock()
	defer b.devicesMu.Unlock()
	
	b.devices[device.ID] = device
	
	if b.onDeviceFound != nil {
		b.onDeviceFound(device)
	}
	
	log.Printf("[BLE] Found device: %s (%s) RSSI: %d", device.Name, device.MAC, device.RSSI)
}

// ══════════════════════════════════════════════════════════════════════════════
// ATTACK FUNCTIONS
// ══════════════════════════════════════════════════════════════════════════════

func (b *BLEAttacker) attackLoop() {
	for {
		select {
		case <-b.stopChan:
			return
		default:
		}
		
		switch b.attackMode {
		case BLEAttackModeSniff:
			b.sniffTraffic()
		case BLEAttackModeInject:
			b.injectData()
		case BLEAttackModePair:
			b.pairDevices()
		case BLEAttackModeSpoof:
			b.spoofDevice()
		case BLEAttackModeKiller:
			b.killConnections()
		}
		
		time.Sleep(100 * time.Millisecond)
	}
}

func (b *BLEAttacker) sniffTraffic() {
	// Capture BLE packets
	atomic.AddInt64(&b.stats.PacketsSniffed, 1)
}

func (b *BLEAttacker) injectData() {
	// Inject malicious data into BLE connections
	b.devicesMu.RLock()
	defer b.devicesMu.RUnlock()
	
	for _, device := range b.devices {
		if device.Paired {
			log.Printf("[BLE] Injecting data to %s", device.Name)
			atomic.AddInt64(&b.stats.InjectsSuccess, 1)
		}
	}
}

func (b *BLEAttacker) pairDevices() {
	// Attempt to pair with discovered devices
	b.devicesMu.RLock()
	defer b.devicesMu.RUnlock()
	
	for _, device := range b.devices {
		if !device.Paired {
			log.Printf("[BLE] Attempting to pair with %s", device.Name)
			// In production: send pairing request
			device.Paired = true
			atomic.AddInt64(&b.stats.PairsSuccess, 1)
			
			if b.onPairSuccess != nil {
				b.onPairSuccess(device)
			}
		}
	}
}

func (b *BLEAttacker) spoofDevice() {
	// Spoof a BLE device (impersonate)
	log.Printf("[BLE] Spoofing BLE device...")
}

func (b *BLEAttacker) killConnections() {
	// Kill BLE connections (deauth attack)
	b.devicesMu.RLock()
	defer b.devicesMu.RUnlock()
	
	for _, device := range b.devices {
		log.Printf("[BLE] Killing connection to %s", device.Name)
	}
}

// ══════════════════════════════════════════════════════════════════════════════
// SERVICE DISCOVERY
// ══════════════════════════════════════════════════════════════════════════════

func (b *BLEAttacker) DiscoverServices(deviceID string) []BLEService {
	b.devicesMu.RLock()
	device, exists := b.devices[deviceID]
	b.devicesMu.RUnlock()
	
	if !exists {
		return nil
	}
	
	log.Printf("[BLE] Discovering services on %s", device.Name)
	
	// Common BLE services
	services := []BLEService{
		{
			UUID: "00001800-0000-1000-8000-00805f9b34fb",
			Name: "Generic Access",
		},
		{
			UUID: "00001801-0000-1000-8000-00805f9b34fb",
			Name: "Generic Attribute",
		},
		{
			UUID: "0000180a-0000-1000-8000-00805f9b34fb",
			Name: "Device Information",
		},
	}
	
	device.Services = services
	return services
}

func (b *BLEAttacker) ReadCharacteristic(deviceID, serviceUUID, charUUID string) []byte {
	log.Printf("[BLE] Reading characteristic %s from %s", charUUID, deviceID)
	
	// In production: send GATT read request
	return []byte{0x00, 0x01, 0x02, 0x03}
}

func (b *BLEAttacker) WriteCharacteristic(deviceID, serviceUUID, charUUID string, data []byte) error {
	log.Printf("[BLE] Writing to characteristic %s on %s: %x", charUUID, deviceID, data)
	
	// In production: send GATT write request
	return nil
}

// ══════════════════════════════════════════════════════════════════════════════
// UTILITY
// ══════════════════════════════════════════════════════════════════════════════

func (b *BLEAttacker) getScanModeName() string {
	switch b.scanMode {
	case BLEScanModePassive:
		return "PASSIVE"
	case BLEScanModeActive:
		return "ACTIVE"
	case BLEScanModeDiscovery:
		return "DISCOVERY"
	default:
		return "UNKNOWN"
	}
}

func (b *BLEAttacker) getAttackModeName() string {
	switch b.attackMode {
	case BLEAttackModeNone:
		return "NONE"
	case BLEAttackModeSniff:
		return "SNIFF"
	case BLEAttackModeInject:
		return "INJECT"
	case BLEAttackModePair:
		return "PAIR"
	case BLEAttackModeSpoof:
		return "SPOOF"
	case BLEAttackModeKiller:
		return "KILLER"
	default:
		return "UNKNOWN"
	}
}

func (b *BLEAttacker) GetDevices() []*BLEDevice {
	b.devicesMu.RLock()
	defer b.devicesMu.RUnlock()
	
	devices := make([]*BLEDevice, 0, len(b.devices))
	for _, d := range b.devices {
		devices = append(devices, d)
	}
	return devices
}

func (b *BLEAttacker) printStats() {
	log.Printf("[BLE STATS] Devices: %d | Packets: %d | Injects: %d | Pairs: %d",
		atomic.LoadInt64(&b.stats.DevicesFound),
		atomic.LoadInt64(&b.stats.PacketsSniffed),
		atomic.LoadInt64(&b.stats.InjectsSuccess),
		atomic.LoadInt64(&b.stats.PairsSuccess))
}
