#!/bin/bash
# PhantomGate - Full Cleanup Script
# Removes ALL iptables rules, ARP cache fixes, IP forwarding, and kills stale processes
# Usage: sudo ./cleanup.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Run with sudo: sudo $0${NC}"
    exit 1
fi

echo -e "${CYAN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   PhantomGate Cleanup                         ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════╝${NC}"
echo ""

# 1. Kill PhantomGate processes
echo -e "${YELLOW}[1/6] Killing PhantomGate processes...${NC}"
pkill -f "phantomgate" 2>/dev/null && echo -e "  ${GREEN}✓ PhantomGate process killed${NC}" || echo -e "  ${GREEN}✓ No PhantomGate process running${NC}"
pkill -f "cloudflared tunnel" 2>/dev/null && echo -e "  ${GREEN}✓ cloudflared tunnel killed${NC}" || echo -e "  ${GREEN}✓ No cloudflared tunnel running${NC}"

# 2. Flush iptables
echo -e "${YELLOW}[2/6] Flushing iptables rules...${NC}"
iptables -F 2>/dev/null
iptables -X 2>/dev/null
iptables -t nat -F 2>/dev/null
iptables -t nat -X 2>/dev/null
iptables -t mangle -F 2>/dev/null
iptables -t mangle -X 2>/dev/null
iptables -P INPUT ACCEPT 2>/dev/null
iptables -P FORWARD ACCEPT 2>/dev/null
iptables -P OUTPUT ACCEPT 2>/dev/null
ip6tables -F 2>/dev/null
ip6tables -X 2>/dev/null
ip6tables -t nat -F 2>/dev/null
ip6tables -t nat -X 2>/dev/null
ip6tables -P INPUT ACCEPT 2>/dev/null
ip6tables -P FORWARD ACCEPT 2>/dev/null
ip6tables -P OUTPUT ACCEPT 2>/dev/null
echo -e "  ${GREEN}✓ All iptables/ip6tables rules flushed${NC}"

# 3. Disable IP forwarding
echo -e "${YELLOW}[3/6] Disabling IP forwarding...${NC}"
echo 0 > /proc/sys/net/ipv4/ip_forward
echo -e "  ${GREEN}✓ IP forwarding disabled${NC}"

# 4. Flush ARP cache
echo -e "${YELLOW}[4/6] Clearing ARP cache...${NC}"
ip -s -s neigh flush all 2>/dev/null
echo -e "  ${GREEN}✓ Local ARP cache flushed${NC}"
echo -e "  ${YELLOW}  (Victim ARP caches self-heal in ~30-60 seconds)${NC}"

# 5. Kill rogue AP artifacts
echo -e "${YELLOW}[5/6] Cleaning up rogue AP artifacts...${NC}"
pkill -f "hostapd" 2>/dev/null && echo -e "  ${GREEN}✓ hostapd killed${NC}" || true
pkill -f "dnsmasq" 2>/dev/null && echo -e "  ${GREEN}✓ dnsmasq killed${NC}" || true

for iface in $(iw dev 2>/dev/null | grep Interface | awk '{print $2}'); do
    if iw dev "$iface" info 2>/dev/null | grep -q "type monitor"; then
        echo -e "  ${YELLOW}  Found monitor mode on $iface — restoring managed mode${NC}"
        ip link set "$iface" down 2>/dev/null
        iw dev "$iface" set type managed 2>/dev/null
        ip link set "$iface" up 2>/dev/null
        echo -e "  ${GREEN}✓ $iface restored to managed mode${NC}"
    fi
done

# 6. Clean temp files
echo -e "${YELLOW}[6/6] Cleaning temp files...${NC}"
rm -f /tmp/phantomgate_* 2>/dev/null
rm -f /tmp/hostapd_phantomgate.conf 2>/dev/null
rm -f /tmp/dnsmasq_phantomgate.conf 2>/dev/null
echo -e "  ${GREEN}✓ Temp files cleaned${NC}"

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   ✓ Cleanup complete                          ║${NC}"
echo -e "${GREEN}║   Network is back to normal.                  ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════╝${NC}"
