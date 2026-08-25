package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/phantomgate/phantomgate/internal/certgen"
	"github.com/phantomgate/phantomgate/internal/config"
	"github.com/phantomgate/phantomgate/internal/console"
	"github.com/phantomgate/phantomgate/internal/dashboard"
	pgdns "github.com/phantomgate/phantomgate/internal/dns"
	"github.com/phantomgate/phantomgate/internal/lure"
	"github.com/phantomgate/phantomgate/internal/network"
	"github.com/phantomgate/phantomgate/internal/phishlet"
	"github.com/phantomgate/phantomgate/internal/proxy"
	"github.com/phantomgate/phantomgate/internal/store"
)

var version = "3.1.0"

func shellCompletionScript(shell string) string {
	switch shell {
	case "bash":
		return `# PhantomGate bash completion
_phantomgate() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="--domain --phishlet --phishlet-dir --config --listen --https-port --http-port --admin-port --admin-pass --cert --key --store --list --lure --intercept --wizard --iface --gateway --victim-ip --poison-domain --rogue-ap --ap-ssid --ap-pass --ap-channel --ap-iface --use-ca --captive-portal --version --generate-completions --dry-run --json-log --no-dashboard --help"
    if [[ ${cur} == -* ]]; then
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
        return 0
    fi
    case "${prev}" in
        --phishlet)
            local phishlets=$(ls /usr/share/phantomgate/phishlets/*.yml 2>/dev/null | xargs -I{} basename {} .yml | tr '\n' ' ')
            COMPREPLY=( $(compgen -W "${phishlets}" -- ${cur}) )
            return 0
            ;;
        --phishlet-dir|--config|--cert|--key|--store)
            COMPREPLY=( $(compgen -f -- ${cur}) )
            return 0
            ;;
    esac
}
complete -F _phantomgate phantomgate
`
	case "zsh":
		return `#compdef phantomgate
_phantomgate() {
    _arguments \
        '--domain[Phishing domain name]' \
        '--phishlet[Phishlet to activate]' \
        '--phishlet-dir[Phishlet YAML directory]' \
        '--config[Config file path]' \
        '--listen[Listen IP]' \
        '--https-port[HTTPS port]' \
        '--http-port[HTTP port]' \
        '--admin-port[Dashboard port]' \
        '--admin-pass[Dashboard password]' \
        '--cert[TLS cert file]' \
        '--key[TLS key file]' \
        '--store[Data store file]' \
        '--list[List phishlets]' \
        '--lure[Create lure URL]' \
        '--intercept[Enable DNS interception]' \
        '--wizard[Launch wizard]' \
        '--iface[Network interface]' \
        '--gateway[Gateway IP]' \
        '--victim-ip[Victim IPs]' \
        '--poison-domain[Domains to poison]' \
        '--rogue-ap[Create rogue AP]' \
        '--ap-ssid[AP SSID]' \
        '--ap-pass[AP password]' \
        '--ap-channel[WiFi channel]' \
        '--version[Print version]' \
        '--generate-completions[Generate completions]' \
        '--dry-run[Test config]' \
        '--json-log[JSON logging]' \
        '--help[Show help]' && return 0
}
_phantomgate "$@"
`
	case "fish":
		return `# fish completions for phantomgate
complete -c phantomgate -l domain -r -d 'Phishing domain'
complete -c phantomgate -l phishlet -r -d 'Phishlet to activate'
complete -c phantomgate -l phishlet-dir -r -F -d 'Phishlet directory'
complete -c phantomgate -l config -r -F -d 'Config file'
complete -c phantomgate -l listen -r -d 'Listen IP'
complete -c phantomgate -l https-port -r -d 'HTTPS port'
complete -c phantomgate -l http-port -r -d 'HTTP port'
complete -c phantomgate -l admin-port -r -d 'Dashboard port'
complete -c phantomgate -l admin-pass -r -d 'Dashboard password'
complete -c phantomgate -l cert -r -F -d 'TLS cert'
complete -c phantomgate -l key -r -F -d 'TLS key'
complete -c phantomgate -l store -r -F -d 'Data store'
complete -c phantomgate -l list -d 'List phishlets'
complete -c phantomgate -l lure -r -d 'Create lure'
complete -c phantomgate -l intercept -d 'DNS interception'
complete -c phantomgate -l wizard -d 'Launch wizard'
complete -c phantomgate -l iface -r -d 'Interface'
complete -c phantomgate -l gateway -r -d 'Gateway IP'
complete -c phantomgate -l victim-ip -r -d 'Victim IPs'
complete -c phantomgate -l poison-domain -r -d 'Domains to poison'
complete -c phantomgate -l rogue-ap -d 'Create rogue AP'
complete -c phantomgate -l ap-ssid -r -d 'AP SSID'
complete -c phantomgate -l ap-pass -r -d 'AP password'
complete -c phantomgate -l ap-channel -r -d 'WiFi channel'
complete -c phantomgate -l ap-iface -r -d 'WiFi interface'
complete -c phantomgate -l use-ca -d 'Dynamic CA'
complete -c phantomgate -l captive-portal -d 'Captive portal'
complete -c phantomgate -l version -d 'Print version'
complete -c phantomgate -l generate-completions -r -d 'Generate completions'
complete -c phantomgate -l dry-run -d 'Test config'
complete -c phantomgate -l json-log -d 'JSON logging'
complete -c phantomgate -l no-dashboard -d 'Disable dashboard'
`
	}
	return ""
}

func main() {
	domain := flag.String("domain", "", "Phishing domain name")
	phishletName := flag.String("phishlet", "", "Phishlet YAML filename (e.g., microsoft365.yml)")
	phishletDir := flag.String("phishlet-dir", "phishlets", "Directory containing phishlet YAML files")
	configFile := flag.String("config", "", "Path to YAML config file")
	listenIP := flag.String("listen", "", "IP address to bind listeners")
	httpsPort := flag.Int("https-port", 0, "HTTPS listener port")
	httpPort := flag.Int("http-port", 0, "HTTP redirect listener port")
	adminPort := flag.Int("admin-port", 0, "Operator dashboard port")
	adminPass := flag.String("admin-pass", "", "Operator dashboard password")
	certFile := flag.String("cert", "", "TLS certificate file (PEM format)")
	keyFile := flag.String("key", "", "TLS private key file (PEM format)")
	storePath := flag.String("store", "", "Path to data store file")
	listPhishlets := flag.Bool("list", false, "List available phishlets and exit")
	lurePhishlet := flag.String("lure", "", "Create a lure URL for the specified phishlet")
	interceptMode := flag.Bool("intercept", false, "Enable DNS interception mode")
	wizardMode := flag.Bool("wizard", false, "Launch interactive configuration wizard")
	iface := flag.String("iface", "", "Network interface for ARP/WiFi interception")
	gatewayIP := flag.String("gateway", "", "Gateway/router IP address")
	victimIPs := flag.String("victim-ip", "", "Comma-separated victim IP addresses")
	poisonDomains := flag.String("poison-domain", "", "Comma-separated domains to poison")
	rogueAP := flag.Bool("rogue-ap", false, "Create a rogue WiFi access point")
	apSSID := flag.String("ap-ssid", "FreeWiFi", "SSID for the rogue access point")
	apPassword := flag.String("ap-pass", "", "WPA2 password (empty for open network)")
	apChannel := flag.Int("ap-channel", 6, "WiFi channel for rogue AP")
	apIface := flag.String("ap-iface", "wlan0", "WiFi interface for rogue AP")
	useCA := flag.Bool("use-ca", false, "Generate dynamic TLS certificates per victim")
	showVersion := flag.Bool("version", false, "Print version and exit")
	generateCompletions := flag.String("generate-completions", "", "Generate shell completion script (bash/zsh/fish)")
	dryRun := flag.Bool("dry-run", false, "Test configuration without binding ports")
	jsonLog := flag.Bool("json-log", false, "Enable JSON structured logging")
	noDashboard := flag.Bool("no-dashboard", false, "Disable terminal dashboard")
	consoleMode := flag.Bool("console", false, "Start interactive operator console (Metasploit-style)")

	flag.Parse()

	if *generateCompletions != "" {
		script := shellCompletionScript(*generateCompletions)
		if script == "" {
			fmt.Fprintf(os.Stderr, "Unsupported shell: %s (use bash, zsh, or fish)\n", *generateCompletions)
			os.Exit(1)
		}
		fmt.Print(script)
		os.Exit(0)
	}

	if *showVersion {
		fmt.Printf("PhantomGate v%s\n", version)
		os.Exit(0)
	}

	// Interactive console mode (Metasploit-style)
	if *consoleMode {
		pm := phishlet.NewPhishletManager(*phishletDir)
		if err := pm.LoadAll(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load phishlets: %v\n", err)
			os.Exit(1)
		}

		s := store.NewStore(*storePath)
		cons, err := console.NewConsole(pm, s)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create console: %v\n", err)
			os.Exit(1)
		}
		defer cons.Stop()

		cons.Run()
		os.Exit(0)
	}

	// JSON logging
	if *jsonLog {
		log.SetFlags(0)
		log.SetOutput(&jsonWriter{})
	}

	// Create data store
	dataStore := store.NewStore(*storePath)

	// Create terminal console
	cons := dashboard.NewServer(dataStore, *adminPass)

	// Print banner
	cons.PrintBanner(version)

	// Load config file if specified
	var cfg *config.Config
	if *configFile != "" {
		var err error
		cfg, err = config.LoadConfig(*configFile)
		if err != nil {
			dashboard.PrintError("Failed to load config: %v", err)
			os.Exit(1)
		}
		dashboard.PrintSuccess("Config loaded: %s", *configFile)
	} else {
		cfg = config.DefaultConfig()
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
		dashboard.PrintError("Failed to load phishlets: %v", err)
		os.Exit(1)
	}

	// List mode
	if *listPhishlets {
		dashboard.PrintSection("Available Phishlets")
		for _, name := range pm.List() {
			p, _ := pm.Get(name)
			hosts := make([]string, 0)
			for _, h := range p.ProxyHosts {
				hosts = append(hosts, h.OrigSub)
			}
			fmt.Printf("    %-20s %s%s%s\n", name, "\033[36m", strings.Join(hosts, ", "), "\033[0m")
		}
		fmt.Println()
		os.Exit(0)
	}

	// Validate required flags
	if cfg.Domain == "" && !*wizardMode {
		dashboard.PrintError("Domain is required. Use --domain or --wizard")
		os.Exit(1)
	}

	// Wizard mode
	if *wizardMode {
		cfg = runWizard(cfg)
		if cfg.Domain == "" {
			dashboard.PrintError("Domain is required")
			os.Exit(1)
		}
	}

	// Dry run
	if *dryRun {
		printDryRun(cfg, pm)
		os.Exit(0)
	}

	// Create components
	lg := lure.NewGenerator(cfg.Domain)
	
	// Get first available phishlet for the proxy
	phishletNames := pm.List()
	if len(phishletNames) == 0 {
		dashboard.PrintError("No phishlets available")
		os.Exit(1)
	}
	
	// Create proxy with first phishlet (or specified one)
	var selectedPhishlet *phishlet.Phishlet
	if *phishletName != "" {
		p, ok := pm.Get(*phishletName)
		if !ok {
			dashboard.PrintError("Phishlet not found: %s", *phishletName)
			os.Exit(1)
		}
		selectedPhishlet = p
	} else {
		p, _ := pm.Get(phishletNames[0])
		selectedPhishlet = p
	}
	
	proxyEngine := proxy.NewPhantomProxy(cfg, selectedPhishlet, dataStore, lg)

	// Setup CA if enabled
	var ca *certgen.PhantomCA
	if *useCA {
		caManager, err := certgen.NewPhantomCA("")
		if err != nil {
			dashboard.PrintError("Failed to create CA: %v", err)
			os.Exit(1)
		}
		ca = caManager
		dashboard.PrintSuccess("Dynamic CA generated")
	}

	// Setup DNS poisoner
	if *interceptMode {
		poisoner, err := pgdns.NewPoisoner(pgdns.PoisonerConfig{
			Interface:     *iface,
			RedirectIP:    cfg.ListenIP,
			TargetDomains: strings.Split(*poisonDomains, ","),
			TTL:           300,
		})
		if err != nil {
			dashboard.PrintError("Failed to create DNS poisoner: %v", err)
			os.Exit(1)
		}
		go func() {
			dashboard.PrintInfo("DNS poisoner starting on %s", *iface)
			if err := poisoner.Start(); err != nil {
				dashboard.PrintError("DNS poisoner failed: %v", err)
			}
		}()
	}

	// Setup rogue AP
	if *rogueAP {
		ap, err := network.NewRogueAP(network.RogueAPConfig{
			Interface: *apIface,
			SSID:      *apSSID,
			Password:  *apPassword,
			Channel:   *apChannel,
		})
		if err != nil {
			dashboard.PrintError("Failed to create rogue AP: %v", err)
			os.Exit(1)
		}
		if err := ap.Start(); err != nil {
			dashboard.PrintError("Rogue AP failed: %v", err)
			os.Exit(1)
		}
		dashboard.PrintSuccess("Rogue AP started: %s on %s", *apSSID, *apIface)
		defer ap.Stop()
	}

	// Setup ARP spoofing
	if *victimIPs != "" && *gatewayIP != "" {
		spoof, err := pgdns.NewARPPoisoner(pgdns.ARPConfig{
			Interface:  *iface,
			GatewayIP:  *gatewayIP,
			TargetIPs:  strings.Split(*victimIPs, ","),
		})
		if err != nil {
			dashboard.PrintError("Failed to create ARP spoofer: %v", err)
			os.Exit(1)
		}
		if err := spoof.Start(); err != nil {
			dashboard.PrintError("ARP spoofing failed: %v", err)
			os.Exit(1)
		}
		dashboard.PrintSuccess("ARP spoofing started on %s", *iface)
		defer spoof.Stop()
	}

	// Create lure
	if *lurePhishlet != "" {
		l := lg.Create(*lurePhishlet, "", "", "")
		url := lg.GetURL(l)
		dashboard.PrintSection("Lure Created")
		fmt.Printf("    URL: %s%s%s\n", "\033[36m", url, "\033[0m")
		fmt.Printf("    ID:  %s\n", l.ID)
		fmt.Println()
		os.Exit(0)
	}

	// Setup TLS
	var tlsConfig *tls.Config
	if ca != nil {
		// Dynamic TLS per victim
		dashboard.PrintInfo("Using dynamic TLS (CA-issued certs)")
	} else if cfg.TLS.Mode == "manual" {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			dashboard.PrintError("Failed to load TLS: %v", err)
			os.Exit(1)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		dashboard.PrintSuccess("TLS: Manual certificate loaded")
	} else {
		// Generate self-signed certificate
		cert, err := certgen.GenerateSelfSigned(cfg.Domain)
		if err != nil {
			dashboard.PrintError("Failed to generate self-signed cert: %v", err)
			os.Exit(1)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		dashboard.PrintSuccess("TLS: Self-signed certificate generated")
	}

	// Start operator console
	if !*noDashboard {
		go cons.Start(fmt.Sprintf("%s:%d", cfg.ListenIP, cfg.AdminPort))
		dashboard.PrintSuccess("Operator console ready (terminal mode)")
	}

	// Build handler chain
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// All requests go through the proxy
		proxyEngine.ServeHTTP(w, r)
	})

	// Start HTTP server
	go func() {
		addr := fmt.Sprintf("%s:%d", cfg.ListenIP, cfg.HTTPPort)
		dashboard.PrintInfo("HTTP redirect server: %s", addr)
		if err := http.ListenAndServe(addr, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := fmt.Sprintf("https://%s%s", r.Host, r.URL.RequestURI())
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		})); err != nil {
			dashboard.PrintError("HTTP failed: %v", err)
		}
	}()

	// Start HTTPS server
	go func() {
		addr := fmt.Sprintf("%s:%d", cfg.ListenIP, cfg.HTTPSPort)
		dashboard.PrintInfo("HTTPS proxy server: %s", addr)
		server := &http.Server{
			Addr:      addr,
			Handler:   handler,
			TLSConfig: tlsConfig,
		}
		if err := server.ListenAndServeTLS("", ""); err != nil {
			dashboard.PrintError("HTTPS failed: %v", err)
		}
	}()

	// Print status
	fmt.Println()
	dashboard.PrintSuccess("PhantomGate is LIVE")
	dashboard.PrintInfo("Domain:     %s", cfg.Domain)
	dashboard.PrintInfo("HTTPS:      %s:%d", cfg.ListenIP, cfg.HTTPSPort)
	dashboard.PrintInfo("HTTP:       %s:%d", cfg.ListenIP, cfg.HTTPPort)
	if !*noDashboard {
		dashboard.PrintInfo("Console:    Terminal mode")
	}
	fmt.Println()

	// Wait for signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2)

	for sig := range sigCh {
		switch sig {
		case syscall.SIGINT, syscall.SIGTERM:
			dashboard.PrintInfo("Shutting down...")
			os.Exit(0)
		case syscall.SIGUSR1:
			stats := dataStore.GetStats()
			dashboard.PrintSection("Live Stats")
			for k, v := range stats {
				fmt.Printf("    %-20s %v\n", k, v)
			}
		case syscall.SIGUSR2:
			dashboard.PrintInfo("Store reload not implemented")
		}
	}
}

func printDryRun(cfg *config.Config, pm *phishlet.PhishletManager) {
	dashboard.PrintSection("DRY-RUN: Configuration")
	dashboard.PrintInfo("Domain:      %s", cfg.Domain)
	dashboard.PrintInfo("Listen IP:   %s", cfg.ListenIP)
	dashboard.PrintInfo("HTTPS Port:  %d", cfg.HTTPSPort)
	dashboard.PrintInfo("HTTP Port:   %d", cfg.HTTPPort)
	dashboard.PrintInfo("Admin Port:  %d", cfg.AdminPort)
	dashboard.PrintInfo("TLS Mode:    %s", cfg.TLS.Mode)
	fmt.Println()
	dashboard.PrintSection("Loaded Phishlets")
	for _, name := range pm.List() {
		p, _ := pm.Get(name)
		hosts := make([]string, 0)
		for _, h := range p.ProxyHosts {
			hosts = append(hosts, h.OrigSub)
		}
		fmt.Printf("    %-20s %s\n", name, strings.Join(hosts, ", "))
	}
	fmt.Println()
	dashboard.PrintSuccess("Configuration is valid. Exiting without starting.")
}

type jsonWriter struct{}

func (j *jsonWriter) Write(p []byte) (n int, err error) {
	entry := map[string]string{
		"level":   "info",
		"message": strings.TrimSpace(string(p)),
		"time":    time.Now().UTC().Format(time.RFC3339),
	}
	data, _ := json.Marshal(entry)
	fmt.Println(string(data))
	return len(p), nil
}

// Placeholder for wizard - will be replaced with full implementation
func runWizard(cfg *config.Config) *config.Config {
	dashboard.PrintSection("Interactive Wizard")
	dashboard.PrintInfo("Wizard mode requires interactive input")
	dashboard.PrintInfo("Use --domain, --phishlet, and --admin-pass flags instead")
	return cfg
}
