package dns

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// NetworkInfo holds auto-discovered network configuration
type NetworkInfo struct {
	Interface    string
	InterfaceMAC string
	LocalIP      string
	GatewayIP    string
	SubnetCIDR   string
	DNSServers   []string
	IsWireless   bool
}

// AutoDiscover detects the active network interface, gateway, local IP, and DNS servers
// Returns a fully populated NetworkInfo — no manual config needed
func AutoDiscover() (*NetworkInfo, error) {
	info := &NetworkInfo{}

	// Step 1: Find the default route to get gateway + interface
	gateway, iface, err := getDefaultGateway()
	if err != nil {
		return nil, fmt.Errorf("could not detect gateway: %w", err)
	}
	info.GatewayIP = gateway
	info.Interface = iface

	// Step 2: Check if wireless
	info.IsWireless = isWirelessInterface(iface)

	// Step 3: Get our IP and MAC on that interface
	netIface, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found: %w", iface, err)
	}
	info.InterfaceMAC = netIface.HardwareAddr.String()

	addrs, err := netIface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("could not get addresses for %s: %w", iface, err)
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() != nil {
			info.LocalIP = ipNet.IP.String()
			ones, bits := ipNet.Mask.Size()
			info.SubnetCIDR = fmt.Sprintf("%s/%d", ipNet.IP.Mask(ipNet.Mask).String(), ones)
			_ = bits
			break
		}
	}

	if info.LocalIP == "" {
		return nil, fmt.Errorf("no IPv4 address found on %s", iface)
	}

	// Step 4: Get DNS servers
	info.DNSServers = getDNSServers()

	return info, nil
}

// getDefaultGateway returns the default gateway IP and the interface used to reach it
func getDefaultGateway() (string, string, error) {
	if runtime.GOOS != "linux" {
		return "", "", fmt.Errorf("auto-discovery only supported on Linux")
	}

	// Parse /proc/net/route for the default route (destination 00000000)
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return getDefaultGatewayFallback()
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // Skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}

		// Default route has destination 00000000
		if fields[1] == "00000000" {
			iface := fields[0]
			gatewayHex := fields[2]

			// Convert hex gateway to IP (little-endian on x86)
			gw, err := hexToIP(gatewayHex)
			if err != nil {
				continue
			}

			return gw, iface, nil
		}
	}

	return getDefaultGatewayFallback()
}

// getDefaultGatewayFallback uses `ip route` command
func getDefaultGatewayFallback() (string, string, error) {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return "", "", fmt.Errorf("ip route failed: %w", err)
	}

	// Parse: "default via 192.168.1.1 dev eth0 ..."
	fields := strings.Fields(string(out))
	gateway := ""
	iface := ""

	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			gateway = fields[i+1]
		}
		if f == "dev" && i+1 < len(fields) {
			iface = fields[i+1]
		}
	}

	if gateway == "" || iface == "" {
		return "", "", fmt.Errorf("could not parse default route")
	}

	return gateway, iface, nil
}

// hexToIP converts a hex-encoded IP from /proc/net/route (little-endian) to dotted notation
func hexToIP(hexStr string) (string, error) {
	if len(hexStr) != 8 {
		return "", fmt.Errorf("invalid hex IP: %s", hexStr)
	}

	var bytes [4]byte
	for i := 0; i < 4; i++ {
		var b int
		fmt.Sscanf(hexStr[i*2:i*2+2], "%02X", &b)
		bytes[i] = byte(b)
	}

	// /proc/net/route uses little-endian on x86
	return fmt.Sprintf("%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]), nil
}

// isWirelessInterface checks if an interface is wireless
func isWirelessInterface(iface string) bool {
	_, err := os.Stat(fmt.Sprintf("/sys/class/net/%s/wireless", iface))
	return err == nil
}

// getDNSServers reads DNS servers from /etc/resolv.conf
func getDNSServers() []string {
	var servers []string

	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return servers
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				servers = append(servers, fields[1])
			}
		}
	}

	return servers
}

// ScanSubnet discovers live hosts on the local subnet using ARP
func ScanSubnet(iface string, cidr string) ([]string, error) {
	var hosts []string

	// Use arping or nmap for quick subnet scan
	// Fallback: parse ARP table after pinging broadcast
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %w", err)
	}

	// Calculate all IPs in the subnet
	var ips []net.IP
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incIP(ip) {
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		ips = append(ips, ipCopy)
	}

	// Skip network and broadcast addresses
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}

	// Quick ping sweep (parallel)
	done := make(chan string, len(ips))
	for _, ip := range ips {
		go func(target net.IP) {
			cmd := exec.Command("ping", "-c", "1", "-W", "1", target.String())
			cmd.Stdout = nil
			cmd.Stderr = nil
			if err := cmd.Run(); err == nil {
				done <- target.String()
			} else {
				done <- ""
			}
		}(ip)
	}

	for range ips {
		if host := <-done; host != "" {
			hosts = append(hosts, host)
		}
	}

	return hosts, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
