package arp

import (
	"fmt"
	"log"
	"net"
	"time"
)

// ══════════════════════════════════════════════════════════════════════════════
// PHANTOMGATE NETWORK DISCOVERY v3.0 — COMPREHENSIVE NETWORK RECONNAISSANCE
// ══════════════════════════════════════════════════════════════════════════════

type NetworkDiscovery struct {
	iface       string
	attackerIP  net.IP
	gatewayIP   net.IP
	subnet      *net.IPNet
	
	// Components
	scanner     *NetworkScanner
	portScanner *PortScanner
	notifier    *Notifier
	
	// Results
	networkMap  *NetworkMap
}

type NetworkMap struct {
	Hosts       []*HostInfo
	Services    []*ServiceInfo
	Vulnerabilities []string
	Timestamp   time.Time
}

type HostInfo struct {
	IP          net.IP
	MAC         net.HardwareAddr
	Hostname    string
	Vendor      string
	OS          string
	Status      HostStatus
	Ports       []*PortInfo
	LastSeen    time.Time
}

type HostStatus int

const (
	HostStatusUnknown HostStatus = iota
	HostStatusAlive
	HostStatusDead
)

type PortInfo struct {
	Port     int
	State    string
	Service  string
	Version  string
}

type ServiceInfo struct {
	Name     string
	Port     int
	Protocol string
	Version  string
	Host     net.IP
}

func NewNetworkDiscovery(iface string, gateway string) (*NetworkDiscovery, error) {
	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface '%s' not found: %w", iface, err)
	}

	addrs, err := netIface.Addrs()
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

	gatewayIP := net.ParseIP(gateway).To4()
	if gatewayIP == nil {
		return nil, fmt.Errorf("invalid gateway IP: %s", gateway)
	}

	scanner, err := NewNetworkScanner(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to create scanner: %w", err)
	}

	return &NetworkDiscovery{
		iface:      iface,
		attackerIP: attackerIP,
		gatewayIP:  gatewayIP,
		subnet:     subnet,
		scanner:    scanner,
		portScanner: NewPortScanner(ScanConfig{
			Ports:    CommonPorts,
			Rate:     100,
			Timeout:  1 * time.Second,
		}),
		notifier: NewNotifier(),
		networkMap: &NetworkMap{
			Hosts: make([]*HostInfo, 0),
		},
	}, nil
}

func (d *NetworkDiscovery) SetNotifier(n *Notifier) {
	d.notifier = n
}

func (d *NetworkDiscovery) Discover() (*NetworkMap, error) {
	log.Printf("[DISCOVERY] Starting network discovery on %s", d.iface)
	start := time.Now()

	// Phase 1: Host Discovery
	log.Printf("[DISCOVERY] Phase 1: Host Discovery")
	hosts := d.scanner.DiscoverHosts()
	log.Printf("[DISCOVERY] Found %d live hosts", len(hosts))

	// Phase 2: Port Scanning
	log.Printf("[DISCOVERY] Phase 2: Port Scanning")
	for _, host := range hosts {
		result := d.portScanner.ScanTarget(host.IP)
		hostInfo := &HostInfo{
			IP:       host.IP,
			MAC:      host.MAC,
			Vendor:   host.Vendor,
			Status:   HostStatusAlive,
			LastSeen: time.Now(),
		}

		for _, r := range result {
			if r.State == PortStateOpen {
				hostInfo.Ports = append(hostInfo.Ports, &PortInfo{
					Port:    r.Port,
					State:   "open",
					Service: r.Service,
				})
			}
		}

		d.networkMap.Hosts = append(d.networkMap.Hosts, hostInfo)
	}

	// Phase 3: Service Enumeration
	log.Printf("[DISCOVERY] Phase 3: Service Enumeration")
	for _, host := range d.networkMap.Hosts {
		for _, port := range host.Ports {
			service := &ServiceInfo{
				Name:    port.Service,
				Port:    port.Port,
				Host:    host.IP,
				Version: port.Version,
			}
			d.networkMap.Services = append(d.networkMap.Services, service)
		}
	}

	d.networkMap.Timestamp = time.Now()
	elapsed := time.Since(start)

	log.Printf("[DISCOVERY] Scan complete in %v", elapsed)
	log.Printf("[DISCOVERY] Hosts: %d | Services: %d",
		len(d.networkMap.Hosts), len(d.networkMap.Services))

	// Send notification if configured
	if d.notifier != nil && d.notifier.enabled {
		d.notifier.SendAlert(
			AlertAttack,
			"Network Discovery Complete",
			fmt.Sprintf("Found %d hosts and %d services on %s",
				len(d.networkMap.Hosts), len(d.networkMap.Services), d.iface),
			"medium",
		)
	}

	return d.networkMap, nil
}

func (d *NetworkDiscovery) GetHosts() []*HostInfo {
	return d.networkMap.Hosts
}

func (d *NetworkDiscovery) GetServices() []*ServiceInfo {
	return d.networkMap.Services
}

func (d *NetworkDiscovery) GetHostByIP(ip net.IP) *HostInfo {
	for _, host := range d.networkMap.Hosts {
		if host.IP.Equal(ip) {
			return host
		}
	}
	return nil
}

func (d *NetworkDiscovery) GetHostsByVendor(vendor string) []*HostInfo {
	var hosts []*HostInfo
	for _, host := range d.networkMap.Hosts {
		if contains(host.Vendor, vendor) {
			hosts = append(hosts, host)
		}
	}
	return hosts
}

func (d *NetworkDiscovery) GetHostsByService(service string) []*HostInfo {
	var hosts []*HostInfo
	for _, host := range d.networkMap.Hosts {
		for _, port := range host.Ports {
			if contains(port.Service, service) {
				hosts = append(hosts, host)
				break
			}
		}
	}
	return hosts
}

func (d *NetworkDiscovery) PrintResults() {
	fmt.Println("\n╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                  NETWORK DISCOVERY RESULTS                   ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║ Scan Time: %s\n", d.networkMap.Timestamp.Format("2006-01-02 15:04:05"))
	fmt.Printf("║ Hosts Found: %d | Services Found: %d\n",
		len(d.networkMap.Hosts), len(d.networkMap.Services))
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")

	for _, host := range d.networkMap.Hosts {
		fmt.Printf("║ IP: %-16s MAC: %-17s\n", host.IP, host.MAC)
		if host.Vendor != "" {
			fmt.Printf("║   Vendor: %s\n", host.Vendor)
		}
		if len(host.Ports) > 0 {
			fmt.Print("║   Ports: ")
			for i, port := range host.Ports {
				if i > 0 {
					fmt.Print(", ")
				}
				fmt.Printf("%d/%s", port.Port, port.Service)
			}
			fmt.Println()
		}
		fmt.Println("║")
	}

	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
