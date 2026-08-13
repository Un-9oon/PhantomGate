package network

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"
)

type RogueAPConfig struct {
	SSID       string
	Password   string // empty = open network
	Channel    int
	Interface  string // wireless interface for AP
	UpstreamIF string // internet-connected interface
	GatewayIP  string // AP's gateway IP (e.g., 192.168.4.1)
	Subnet     string // DHCP range subnet (e.g., 192.168.4.0/24)
	DHCPStart  string
	DHCPEnd    string
	Band       string // "2g" or "5g"
	Hidden     bool
}

type RogueAP struct {
	cfg         RogueAPConfig
	hostapdProc *os.Process
	dnsmasqProc *os.Process
	tmpDir      string
	running     bool
}

func DefaultRogueAPConfig() RogueAPConfig {
	return RogueAPConfig{
		SSID:      "Free_WiFi",
		Channel:   6,
		GatewayIP: "192.168.4.1",
		Subnet:    "192.168.4.0/24",
		DHCPStart: "192.168.4.10",
		DHCPEnd:   "192.168.4.250",
		Band:      "2g",
	}
}

var hostapdTmpl = template.Must(template.New("hostapd").Parse(`interface={{.Interface}}
driver=nl80211
ssid={{.SSID}}
hw_mode={{.HWMode}}
channel={{.Channel}}
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid={{.IgnoreBroadcast}}
{{- if .WPA}}
wpa=2
wpa_passphrase={{.Password}}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
{{- end}}
`))

var dnsmasqTmpl = template.Must(template.New("dnsmasq").Parse(`interface={{.Interface}}
bind-interfaces
dhcp-range={{.DHCPStart}},{{.DHCPEnd}},255.255.255.0,12h
dhcp-option=3,{{.GatewayIP}}
dhcp-option=6,{{.GatewayIP}}
server=8.8.8.8
log-queries
log-dhcp
no-resolv
`))

func NewRogueAP(cfg RogueAPConfig) (*RogueAP, error) {
	if cfg.Interface == "" {
		iface, err := findWirelessInterface()
		if err != nil {
			return nil, fmt.Errorf("no wireless interface found: %w", err)
		}
		cfg.Interface = iface
	}

	if cfg.UpstreamIF == "" {
		upstream, err := findUpstreamInterface(cfg.Interface)
		if err != nil {
			log.Printf("[ROGUE AP] Warning: no upstream interface found — AP will have no internet")
		} else {
			cfg.UpstreamIF = upstream
		}
	}

	tmpDir := filepath.Join(os.TempDir(), "phantomgate_ap")
	os.MkdirAll(tmpDir, 0755)

	return &RogueAP{
		cfg:    cfg,
		tmpDir: tmpDir,
	}, nil
}

func (ap *RogueAP) Start() error {
	log.Println("[ROGUE AP] Setting up access point...")

	if err := checkDependencies(); err != nil {
		return err
	}

	// Kill any conflicting processes
	killConflicting()

	// Put interface in AP mode
	if err := ap.setupInterface(); err != nil {
		return fmt.Errorf("interface setup failed: %w", err)
	}

	// Assign IP to AP interface
	if err := ap.assignIP(); err != nil {
		return fmt.Errorf("IP assignment failed: %w", err)
	}

	// Start hostapd
	if err := ap.startHostapd(); err != nil {
		return fmt.Errorf("hostapd failed: %w", err)
	}

	// Start dnsmasq for DHCP
	if err := ap.startDnsmasq(); err != nil {
		ap.stopHostapd()
		return fmt.Errorf("dnsmasq failed: %w", err)
	}

	// Set up NAT routing
	if err := ap.setupNAT(); err != nil {
		log.Printf("[ROGUE AP] NAT setup failed (no internet for victims): %v", err)
	}

	ap.running = true

	log.Printf("[ROGUE AP] Access point LIVE")
	log.Printf("[ROGUE AP]   SSID:      %s", ap.cfg.SSID)
	log.Printf("[ROGUE AP]   Channel:   %d", ap.cfg.Channel)
	log.Printf("[ROGUE AP]   Gateway:   %s", ap.cfg.GatewayIP)
	log.Printf("[ROGUE AP]   DHCP:      %s - %s", ap.cfg.DHCPStart, ap.cfg.DHCPEnd)
	log.Printf("[ROGUE AP]   Interface: %s", ap.cfg.Interface)
	if ap.cfg.UpstreamIF != "" {
		log.Printf("[ROGUE AP]   Upstream:  %s (internet)", ap.cfg.UpstreamIF)
	}
	if ap.cfg.Password != "" {
		log.Printf("[ROGUE AP]   Security:  WPA2-PSK")
	} else {
		log.Printf("[ROGUE AP]   Security:  OPEN (no password)")
	}

	return nil
}

func (ap *RogueAP) Stop() {
	if !ap.running {
		return
	}
	log.Println("[ROGUE AP] Shutting down access point...")

	ap.cleanupNAT()
	ap.stopDnsmasq()
	ap.stopHostapd()
	ap.restoreInterface()

	os.RemoveAll(ap.tmpDir)
	ap.running = false
	log.Println("[ROGUE AP] Access point stopped")
}

func (ap *RogueAP) GetGatewayIP() string {
	return ap.cfg.GatewayIP
}

func (ap *RogueAP) GetInterface() string {
	return ap.cfg.Interface
}

func (ap *RogueAP) setupInterface() error {
	cmds := [][]string{
		{"ip", "link", "set", ap.cfg.Interface, "down"},
		{"iw", "dev", ap.cfg.Interface, "set", "type", "__ap"},
		{"ip", "link", "set", ap.cfg.Interface, "up"},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			// iw set type might fail if already in AP mode or driver doesn't support it
			if args[2] != "set" {
				return fmt.Errorf("%s failed: %s: %w", strings.Join(args, " "), out, err)
			}
			log.Printf("[ROGUE AP] iw set type __ap failed (may already be in AP mode): %v", err)
			// Bring it back up anyway
			exec.Command("ip", "link", "set", ap.cfg.Interface, "up").Run()
		}
	}
	return nil
}

func (ap *RogueAP) restoreInterface() {
	exec.Command("ip", "link", "set", ap.cfg.Interface, "down").Run()
	exec.Command("iw", "dev", ap.cfg.Interface, "set", "type", "managed").Run()
	exec.Command("ip", "link", "set", ap.cfg.Interface, "up").Run()
}

func (ap *RogueAP) assignIP() error {
	exec.Command("ip", "addr", "flush", "dev", ap.cfg.Interface).Run()
	return exec.Command("ip", "addr", "add",
		ap.cfg.GatewayIP+"/24", "dev", ap.cfg.Interface).Run()
}

func (ap *RogueAP) startHostapd() error {
	confPath := filepath.Join(ap.tmpDir, "hostapd.conf")
	f, err := os.Create(confPath)
	if err != nil {
		return err
	}

	hwMode := "g"
	if ap.cfg.Band == "5g" {
		hwMode = "a"
	}

	ignoreBroadcast := 0
	if ap.cfg.Hidden {
		ignoreBroadcast = 1
	}

	data := struct {
		Interface       string
		SSID            string
		HWMode          string
		Channel         int
		IgnoreBroadcast int
		WPA             bool
		Password        string
	}{
		Interface:       ap.cfg.Interface,
		SSID:            ap.cfg.SSID,
		HWMode:          hwMode,
		Channel:         ap.cfg.Channel,
		IgnoreBroadcast: ignoreBroadcast,
		WPA:             ap.cfg.Password != "",
		Password:        ap.cfg.Password,
	}

	if err := hostapdTmpl.Execute(f, data); err != nil {
		f.Close()
		return err
	}
	f.Close()

	logFile, _ := os.Create(filepath.Join(ap.tmpDir, "hostapd.log"))
	cmd := exec.Command("hostapd", confPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("hostapd failed to start: %w", err)
	}

	ap.hostapdProc = cmd.Process
	time.Sleep(2 * time.Second)

	// Check if still running
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return fmt.Errorf("hostapd exited immediately — check %s/hostapd.log", ap.tmpDir)
	}

	log.Printf("[ROGUE AP] hostapd started (PID %d)", cmd.Process.Pid)
	return nil
}

func (ap *RogueAP) stopHostapd() {
	if ap.hostapdProc != nil {
		ap.hostapdProc.Kill()
		ap.hostapdProc.Wait()
		ap.hostapdProc = nil
	}
}

func (ap *RogueAP) startDnsmasq() error {
	confPath := filepath.Join(ap.tmpDir, "dnsmasq.conf")
	f, err := os.Create(confPath)
	if err != nil {
		return err
	}

	data := struct {
		Interface string
		DHCPStart string
		DHCPEnd   string
		GatewayIP string
	}{
		Interface: ap.cfg.Interface,
		DHCPStart: ap.cfg.DHCPStart,
		DHCPEnd:   ap.cfg.DHCPEnd,
		GatewayIP: ap.cfg.GatewayIP,
	}

	if err := dnsmasqTmpl.Execute(f, data); err != nil {
		f.Close()
		return err
	}
	f.Close()

	logFile, _ := os.Create(filepath.Join(ap.tmpDir, "dnsmasq.log"))
	cmd := exec.Command("dnsmasq", "-C", confPath, "--no-daemon", "--log-facility=-")
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("dnsmasq failed to start: %w", err)
	}

	ap.dnsmasqProc = cmd.Process
	time.Sleep(1 * time.Second)

	log.Printf("[ROGUE AP] dnsmasq started (PID %d)", cmd.Process.Pid)
	return nil
}

func (ap *RogueAP) stopDnsmasq() {
	if ap.dnsmasqProc != nil {
		ap.dnsmasqProc.Kill()
		ap.dnsmasqProc.Wait()
		ap.dnsmasqProc = nil
	}
}

func (ap *RogueAP) setupNAT() error {
	if ap.cfg.UpstreamIF == "" {
		return fmt.Errorf("no upstream interface")
	}

	os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)

	cmds := [][]string{
		{"iptables", "-t", "nat", "-A", "POSTROUTING", "-o", ap.cfg.UpstreamIF, "-j", "MASQUERADE"},
		{"iptables", "-A", "FORWARD", "-i", ap.cfg.Interface, "-o", ap.cfg.UpstreamIF, "-j", "ACCEPT"},
		{"iptables", "-A", "FORWARD", "-i", ap.cfg.UpstreamIF, "-o", ap.cfg.Interface,
			"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}

	for _, args := range cmds {
		if err := exec.Command(args[0], args[1:]...).Run(); err != nil {
			return fmt.Errorf("%s: %w", strings.Join(args, " "), err)
		}
	}

	log.Printf("[ROGUE AP] NAT routing: %s → %s (internet)", ap.cfg.Interface, ap.cfg.UpstreamIF)
	return nil
}

func (ap *RogueAP) cleanupNAT() {
	if ap.cfg.UpstreamIF == "" {
		return
	}
	exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", ap.cfg.UpstreamIF, "-j", "MASQUERADE").Run()
	exec.Command("iptables", "-D", "FORWARD", "-i", ap.cfg.Interface, "-o", ap.cfg.UpstreamIF, "-j", "ACCEPT").Run()
	exec.Command("iptables", "-D", "FORWARD", "-i", ap.cfg.UpstreamIF, "-o", ap.cfg.Interface,
		"-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()
}

func findWirelessInterface() (string, error) {
	entries, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		wirelessPath := filepath.Join("/sys/class/net", e.Name(), "wireless")
		if _, err := os.Stat(wirelessPath); err == nil {
			return e.Name(), nil
		}
	}
	return "", fmt.Errorf("no wireless interface found")
}

func findUpstreamInterface(excludeIF string) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		if iface.Name == excludeIF || iface.Name == "lo" {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil && !ipNet.IP.IsLoopback() {
				return iface.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no upstream interface found")
}

func checkDependencies() error {
	missing := []string{}
	for _, tool := range []string{"hostapd", "dnsmasq", "iw"} {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required tools: %s — install with: apt install %s",
			strings.Join(missing, ", "), strings.Join(missing, " "))
	}
	return nil
}

func killConflicting() {
	for _, proc := range []string{"hostapd", "wpa_supplicant"} {
		exec.Command("killall", proc).Run()
	}
	// Stop NetworkManager for our interface (it fights with hostapd)
	exec.Command("nmcli", "radio", "wifi", "off").Run()
	time.Sleep(500 * time.Millisecond)
}
