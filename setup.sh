#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  PhantomGate — One-Command Setup
#  Installs dependencies, builds everything, verifies it works.
#  Run: chmod +x setup.sh && ./setup.sh
# ═══════════════════════════════════════════════════════════════

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

print_banner() {
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
    echo -e "   ${BOLD}One-Command Setup${NC}"
    echo ""
}

step() {
    echo -e "\n  ${CYAN}[$1/4]${NC} ${BOLD}$2${NC}"
}

ok() {
    echo -e "        ${GREEN}✓${NC} $1"
}

fail() {
    echo -e "        ${RED}✗${NC} $1"
    exit 1
}

warn() {
    echo -e "        ${YELLOW}!${NC} $1"
}

# ───────────────────────────────────────
cd "$(dirname "$0")"
PROJECT_DIR="$(pwd)"

print_banner

# STEP 1: Check prerequisites
step 1 "Checking prerequisites"

if command -v go &>/dev/null; then
    GO_VERSION=$(go version | awk '{print $3}')
    ok "Go installed: $GO_VERSION"
else
    fail "Go is not installed. Install it from https://go.dev/dl/"
fi

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    ok "Platform: Linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    ok "Platform: macOS"
    warn "DNS interception mode is Linux-only"
else
    ok "Platform: $OSTYPE"
    warn "DNS interception mode is Linux-only"
fi

if [ -f "go.mod" ]; then
    ok "Project root found: $PROJECT_DIR"
else
    fail "go.mod not found. Run this script from the PhantomGate directory."
fi

# STEP 2: Install dependencies
step 2 "Installing dependencies"

go mod tidy 2>&1 | while read -r line; do echo "        $line"; done
ok "Go modules synced"

# STEP 3: Build
step 3 "Building binaries"

mkdir -p bin

echo "        Building phantomgate..."
go build -ldflags "-s -w -X main.Version=1.0.0" -o bin/phantomgate ./cmd/phantomgate
ok "bin/phantomgate"

echo "        Building fake_target (test server)..."
go build -o bin/fake_target ./test/fake_target
ok "bin/fake_target"

# Cross-compile if requested
if [ "$1" = "--cross" ]; then
    echo "        Cross-compiling..."
    GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o bin/phantomgate-windows-amd64.exe ./cmd/phantomgate
    ok "bin/phantomgate-windows-amd64.exe"
    GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o bin/phantomgate-darwin-amd64 ./cmd/phantomgate
    ok "bin/phantomgate-darwin-amd64"
fi

# STEP 4: Verify
step 4 "Verifying build"

if [ -x "bin/phantomgate" ]; then
    ok "Binary is executable"
else
    fail "Binary not executable"
fi

# Quick phishlet load test
./bin/phantomgate --list --phishlet-dir phishlets 2>&1 | grep -q "Available Phishlets"
if [ $? -eq 0 ]; then
    ok "Phishlet loader works"
else
    warn "Phishlet loader check inconclusive"
fi

PHISHLETS=$(ls phishlets/*.yml 2>/dev/null | wc -l)
ok "$PHISHLETS phishlets available"

echo ""
echo -e "  ${GREEN}${BOLD}═══════════════════════════════════════════${NC}"
echo -e "  ${GREEN}${BOLD}  Setup complete!${NC}"
echo -e "  ${GREEN}${BOLD}═══════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Quick start:${NC}"
echo ""
echo -e "    ${CYAN}# Run the demo (safe, local-only):${NC}"
echo -e "    ./demo.sh"
echo ""
echo -e "    ${CYAN}# Real engagement (requires root for ports 80/443):${NC}"
echo -e "    sudo ./bin/phantomgate \\"
echo -e "      --domain your-phish-domain.com \\"
echo -e "      --phishlet microsoft365 \\"
echo -e "      --admin-pass YourPassword123"
echo ""
echo -e "    ${CYAN}# With DNS interception on LAN:${NC}"
echo -e "    sudo ./bin/phantomgate \\"
echo -e "      --domain your-phish-domain.com \\"
echo -e "      --phishlet microsoft365 \\"
echo -e "      --admin-pass YourPassword123 \\"
echo -e "      --intercept --gateway 192.168.1.1"
echo ""
echo -e "    ${CYAN}# List available phishlets:${NC}"
echo -e "    ./bin/phantomgate --list"
echo ""
